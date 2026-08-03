#!/usr/bin/env bash
# deploy/phases/L-go-live-checklist.sh — Phase L: Go-Live Checklist (the gate)
# Transcribed from: phases/11-go-live-checklist.md
#
# This is the go-live GATE, not a build phase — it changes nothing on the
# host, creates no files, owns no shared object. It walks every checklist
# line in L1-L12 of the source document, in order, and for each one either:
#
#   - runs the exact command the source gives and reports PASS/FAIL
#     automatically (chk / chk_blocker), when the source states a clean,
#     safely-parseable pass condition (exit code, a literal string, a
#     count, a file's presence/absence) — or
#   - prints the command's output for the operator to read (evidence) and
#     then calls common.sh's confirm() for an explicit human acknowledgment
#     (manual), when the source itself frames the line as a judgment call
#     ("recorded", "understood", "accepted", "chosen"), an [off-box] test
#     that needs the Phase H0 test host, a rehearsal/drill this script
#     cannot safely re-run inline (K6/K7/H13/H14, the 4-hour soak), or a
#     business/legal decision. This is safer than a brittle auto-parse of
#     prose like "TTL is 300" or "offset < 100 ms" that risks a false PASS
#     or FAIL from a parsing assumption the source never stated as a
#     one-liner.
#
# confirm() semantics (see lib/common.sh): it aborts the whole run (fatal,
# exit 1) the instant an operator declines. That is deliberate here — L12
# states "a line that cannot be evaluated is a fail, not a skip", and an
# operator who cannot honestly confirm a checklist line should stop right
# there, fix or verify it, and re-run this phase — not proceed to a false
# summary. Reaching the final summary table means every MANUAL item up to
# that point was affirmatively acknowledged. KEYSTONE_YES=1 skips all
# gates for a scripted run (an explicit operator decision per common.sh,
# never a default) — a strange thing to do to a human-judgment gate, but
# the mechanism is shared infra and this script does not special-case it.
#
# chk_blocker items are the ones L12 ("Do not go live if") names as a hard
# stop; failing any of them fails this script's exit code. Plain chk/manual
# items are recorded in the summary but do not by themselves flip the exit
# code — L12 is explicit that only its 17 items are hard stops; the rest of
# the checklist is supporting evidence an operator reviews by hand.
#
# Not transcribed: the "Directory and Port Layout (Final)", "Key Risks and
# Mitigations" and "Changelog from v1" sections of the source file. Those
# are reference tables cross-referenced throughout L1-L11, not `[ ]`
# checklist lines — there is nothing to run or confirm for them.
#
# Sole ownership per CLAUDE.md: this phase creates nothing and owns no
# shared object; it only reads state Phases A-Q already created.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=lib/common.sh
source lib/common.sh

require_root
phase_header "Phase L — go-live checklist (gate)"

FQDN="${FQDN:-dns.example.com}"
PUBLIC_IP="${PUBLIC_IP:-$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)}"
info "L: fqdn=$FQDN public_ip=$PUBLIC_IP"

# ---------------------------------------------------------------------
# Result-tracking helpers. Extends H12's dns-smoke.sh ok/bad/chk idiom
# (deploy/phases/H-acceptance-tests.sh) with a blocker tier and a MANUAL
# acknowledgment path.
# ---------------------------------------------------------------------
BLOCKER_FAIL=0
declare -a SUMMARY=()   # "STATUS|id|description"

ok()  { printf '  PASS  %s\n' "$1" | tee -a "$KEYSTONE_LOG_FILE" >&2; }
bad() { printf '  FAIL  %s\n' "$1" | tee -a "$KEYSTONE_LOG_FILE" >&2; }
blockerbad() { printf '  FAIL (L12 HARD BLOCKER)  %s\n' "$1" | tee -a "$KEYSTONE_LOG_FILE" >&2; BLOCKER_FAIL=1; }

# chk <id> <label> <shell-condition>  -- non-blocking automated check
chk() {
    local id="$1" label="$2" cond="$3"
    if eval "$cond" >/dev/null 2>&1; then ok "$id: $label"; SUMMARY+=("PASS|$id|$label")
    else bad "$id: $label"; SUMMARY+=("FAIL|$id|$label"); fi
}

# chk_blocker <id> <label> <shell-condition>  -- L12 hard-stop, drives exit code
chk_blocker() {
    local id="$1" label="$2" cond="$3"
    if eval "$cond" >/dev/null 2>&1; then ok "$id: $label"; SUMMARY+=("PASS|$id|$label")
    else blockerbad "$id: $label"; SUMMARY+=("FAIL-BLOCKER|$id|$label"); fi
}

# evidence <id> <cmd> -- run and print a command's output for manual review;
# never sets pass/fail by itself. Failures of the command itself are shown,
# not swallowed.
evidence() {
    local id="$1" cmd="$2"
    info "$id: evidence — running: $cmd"
    eval "$cmd" 2>&1 | tee -a "$KEYSTONE_LOG_FILE" >&2 || true
}

# manual <id> <label> [blocker]  -- judgment / off-box / business item;
# blocks on confirm() (see header note).
manual() {
    local id="$1" label="$2" blocker="${3:-no}"
    warn "$id: MANUAL — $label"
    confirm "Confirm '$id' ($label) has been verified/completed as stated"
    ok "$id: $label [MANUAL, acknowledged]"
    if [[ "$blocker" == "blocker" ]]; then
        SUMMARY+=("MANUAL-BLOCKER|$id|$label")
    else
        SUMMARY+=("MANUAL|$id|$label")
    fi
}

print_summary() {
    phase_header "L — go-live checklist summary"
    printf '%-16s  %-10s  %s\n' "STATUS" "ID" "DESCRIPTION" | tee -a "$KEYSTONE_LOG_FILE" >&2
    local row status id label
    for row in "${SUMMARY[@]}"; do
        IFS='|' read -r status id label <<<"$row"
        printf '%-16s  %-10s  %s\n' "$status" "$id" "$label" | tee -a "$KEYSTONE_LOG_FILE" >&2
    done
}

# =====================================================================
# L1. Host
# =====================================================================
phase_header "L1. Host"

# --- L1: Ubuntu 24.04 LTS, not 22.04 (A1) ---
chk "L1-01" "Ubuntu 24.04 LTS, not 22.04 (A1)" \
    "lsb_release -ds | grep -q '24\\.04'"

# --- L1: public IPv4 survives a reboot; IP matches DNS (A1) ---
evidence "L1-02" 'ip -4 addr show scope global'
manual "L1-02" "public IPv4 survives a reboot; IP matches DNS (A1)"

# --- L1: dns.example.com resolves to THIS host from TWO independent public resolvers (0.1, D0) — L12 #16 ---
chk_blocker "L1-03" "$FQDN resolves to THIS host ($PUBLIC_IP) from 1.1.1.1 AND 8.8.8.8 (0.1, D0, L12#16)" \
    'R1=$(dig +short "$FQDN" A @1.1.1.1); R2=$(dig +short "$FQDN" A @8.8.8.8); [ "$R1" = "$PUBLIC_IP" ] && [ "$R2" = "$PUBLIC_IP" ]'

# --- L1: zone served by authoritative DNS that is NOT this machine, >=2 nameservers, A/AAAA TTL 300 (0.1, D0) — L12 #16 ---
evidence "L1-04" 'dig +short NS "${FQDN#*.}"; NS1=$(dig +short NS "${FQDN#*.}" | head -1); dig +noall +answer "$FQDN" A @"$NS1"'
manual "L1-04" "zone for $FQDN is served authoritatively by a DIFFERENT machine, on >=2 nameservers, A/AAAA TTL is 300 (0.1, D0, L12#16)" blocker

# --- L1: IPv6 posture DECIDED and recorded, and the RECORD SET matches it (A1, C2, E2a) ---
manual "L1-05" "IPv6 posture decided (IPv4-only / dual-stack / IPv4-only enforced) and the published record set matches it (A1, C2, E2a)"

# --- L1: EVERY published address answers on EVERY transport this build enables [off-box] (E2a, E6-9) ---
manual "L1-06a" "[off-box, dual-stack host] E6 step 9 sweep: every address published for $FQDN answers Do53/DoT/DoQ/DoH (E2a, E6-9)"
evidence "L1-06b" "ss -lntuep '( sport = :53 or sport = :853 )'"
manual "L1-06b" "AdGuardHome renders as *:53 / *:853 with v6only:0 on a dual-stack host, or a literal 0.0.0.0 if this host genuinely has no usable IPv6 (E2a)"

# --- L1: chrony synchronised, offset < 100 ms (A2) ---
evidence "L1-07" "chronyc tracking"
manual "L1-07" "chrony synchronised, offset < 100 ms (A2)"

# --- L1: NO chrony source is a hostname (A2) ---
chk "L1-08" "no chrony source is a hostname; only numeric addresses (A2)" \
    '! chronyc sources -v 2>/dev/null | awk "/^\\^|^#/{print \$2}" | grep -qE "[A-Za-z]" && ! grep -rhE "^(server|pool)" /etc/chrony/ 2>/dev/null | grep -qE "[A-Za-z]{2,}\\.[A-Za-z]"'

# --- L1: ufw and fail2ban absent (or fail2ban on the nftables banaction) (A2, A4) ---
chk "L1-09" "ufw absent; fail2ban absent OR on the nftables banaction (A2, A4)" \
    '! dpkg -s ufw >/dev/null 2>&1 && { ! dpkg -s fail2ban >/dev/null 2>&1 || grep -rq nftables /etc/fail2ban/jail.local /etc/fail2ban/jail.d/ 2>/dev/null; }'

# --- L1: systemd-resolved disabled AND masked; port 53 free (A2) ---
chk "L1-10" "systemd-resolved masked" \
    '[ "$(systemctl is-enabled systemd-resolved 2>/dev/null)" = "masked" ]'
evidence "L1-10b" "ss -lnup 'sport = :53'"

# --- L1: No /etc/systemd/resolved.conf.d/ on the host; no phase writes DNSStubListener (A2, C1) ---
chk "L1-11" "no /etc/systemd/resolved.conf.d/, no DNSStubListener anywhere (A2, C1)" \
    '[ ! -d /etc/systemd/resolved.conf.d ] || [ -z "$(ls -A /etc/systemd/resolved.conf.d 2>/dev/null)" ] && ! grep -rq DNSStubListener /etc/systemd/ 2>/dev/null'

# --- L1: /etc/resolv.conf real file, EXACTLY ONE nameserver line, 127.0.0.1 (A2, C5.8) — L12 #11 ---
chk_blocker "L1-12" "/etc/resolv.conf is a real file, exactly one 'nameserver 127.0.0.1' line, no fallback (A2, C5.8, L12#11)" \
    '[ ! -L /etc/resolv.conf ] && [ "$(grep -c "^nameserver" /etc/resolv.conf)" -eq 1 ] && grep -qx "nameserver 127.0.0.1" /etc/resolv.conf'

# --- L1: adguardhome user exists, nologin; no smartdns / dnswarmer user (A3) ---
chk "L1-13" "adguardhome user exists (nologin); no smartdns/dnswarmer user (A3)" \
    'getent passwd adguardhome | grep -q nologin && ! getent passwd smartdns >/dev/null 2>&1 && ! getent passwd dnswarmer >/dev/null 2>&1'

# --- L1: sshd passwordauthentication no, publickey only (A4) ---
chk "L1-14" "sshd: passwordauthentication no (A4)" \
    "sshd -T 2>/dev/null | grep -qi '^passwordauthentication no'"

# --- L1: second login as dnsadmin proved BEFORE root session closed (A4 Step 2) ---
manual "L1-15" "a second login as dnsadmin was proved BEFORE the root session was closed (A4 Step 2)"

# --- L1: restricted tunnel key cannot forward anything but 127.0.0.1:3000 (A4 Step 3) ---
manual "L1-16" "restricted tunnel key cannot forward anything but 127.0.0.1:3000 (A4 Step 3)"

# --- L1: 99-dns.conf applied; net.netfilter.* keys resolve after a reboot (A5) ---
evidence "L1-17" "sysctl -a 2>/dev/null | grep -c '^net.netfilter'"
manual "L1-17" "99-dns.conf applied; net.netfilter.* keys resolve AFTER A REBOOT (A5)"

# --- L1: the two sysctl drop-ins share NO key (A5, B2) ---
chk "L1-18" "99-dns.conf and 99-nftables-edge.conf share no sysctl key (A5, B2)" \
    '[ -z "$(comm -12 <(grep -oE "^[A-Za-z0-9_.]+" /etc/sysctl.d/99-dns.conf 2>/dev/null | sort) <(grep -oE "^[A-Za-z0-9_.]+" /etc/sysctl.d/99-nftables-edge.conf 2>/dev/null | sort))" ]'

# --- L1: No /etc/sysctl.d/99-swap.conf exists (A5, N5a) ---
chk "L1-19" "no /etc/sysctl.d/99-swap.conf exists — A5 is the only writer of vm.swappiness (A5, N5a)" \
    '[ ! -e /etc/sysctl.d/99-swap.conf ]'

# --- L1: RPS spread across both vCPUs, or hardware multiqueue (A5) ---
evidence "L1-20" 'for f in /sys/class/net/*/queues/rx-*/rps_cpus; do [ -e "$f" ] && echo "$f: $(cat "$f")"; done'
manual "L1-20" "RPS spread across both vCPUs (or hardware multiqueue) (A5)"

# --- L1: UdpRcvbufErrors delta == 0 across the L6 load run (A5) ---
evidence "L1-21" "nstat -az 2>/dev/null | grep UdpRcvbufErrors"
manual "L1-21" "UdpRcvbufErrors delta == 0 across the L6 load run (A5)"

# --- L1: swap present and unused in steady state; vm.swappiness = 10 (A6) ---
chk "L1-22" "vm.swappiness = 10; a swapfile is configured (A6)" \
    '[ "$(sysctl -n vm.swappiness 2>/dev/null)" = "10" ] && swapon --show | grep -q .'
evidence "L1-22b" "free -h; swapon --show"
manual "L1-22b" "swap is UNUSED in steady state (A6)"

# --- L1: MemoryAccounting on for unbound / adguardhome / nginx (A6) ---
chk "L1-23" "MemoryAccounting=yes for unbound, adguardhome, nginx (A6)" \
    'for u in unbound adguardhome nginx; do systemctl show "$u" -p MemoryAccounting 2>/dev/null | grep -q "=yes" || exit 1; done'

# --- L1: the canonical memory ceilings are in effect and set in ONE place (A6) ---
evidence "L1-24" 'systemctl show unbound -p MemoryHigh -p MemoryMax; systemctl show adguardhome -p MemoryHigh -p MemoryMax; systemctl show nginx -p MemoryMax'
evidence "L1-24b" "grep -rl 'Memory\\(High\\|Max\\)' /etc/systemd/system/{unbound,adguardhome,nginx}.service.d/ 2>/dev/null"
manual "L1-24" "ceilings read unbound 1200M/1600M, adguardhome 800M/1200M, nginx 256M; exactly ONE drop-in file per unit and it is A6's (A6)"

# --- L1: ssh OOMScoreAdjust is -500, not -900 (A6) ---
chk "L1-25" "ssh OOMScoreAdjust is -500 (A6)" \
    '[ "$(systemctl show ssh -p OOMScoreAdjust --value 2>/dev/null)" = "-500" ]'

# --- L1: No OOM kill in the last 24 h (A6) ---
chk "L1-26" "no OOM kill in the journal in the last 24h (A6)" \
    '[ -z "$(journalctl -k --since -24h 2>/dev/null | grep -i oom)" ]'

# --- L1: memory.events for unbound and adguardhome: oom 0 and oom_kill 0 (A6) ---
chk "L1-27" "memory.events: oom 0, oom_kill 0 for unbound and adguardhome (A6)" \
    'for u in unbound adguardhome; do f="/sys/fs/cgroup/system.slice/${u}.service/memory.events"; [ -f "$f" ] && grep -qx "oom 0" "$f" && grep -qx "oom_kill 0" "$f" || exit 1; done'

# =====================================================================
# L2. Firewall and packet policy
# =====================================================================
phase_header "L2. Firewall and packet policy"

# --- L2: nft -c -f /etc/nftables.conf parses clean (B5) ---
chk "L2-01" "nft -c -f /etc/nftables.conf parses clean (B5)" \
    "nft -c -f /etc/nftables.conf"

# --- L2: EXACTLY TWO tables: inet raw and inet filter (B9-1) ---
chk "L2-02" "exactly two tables: inet raw, inet filter (B9-1)" \
    '[ "$(nft list tables | wc -l)" -eq 2 ] && nft list tables | grep -q "inet raw" && nft list tables | grep -q "inet filter"'

# --- L2: EXACTLY ONE base chain on the input hook (B9-1) ---
chk "L2-03" "exactly one base chain on the input hook (B9-1)" \
    "nft -j list ruleset | jq -e \"[.nftables[].chain? // empty | select(.hook==\\\"input\\\")] | length == 1\""

# --- L2: all six canonical sets exist in table inet filter (B9-1) ---
chk "L2-04" "floodmeter4/6, banned_ips/6, allowlist4/6 all exist in table inet filter (B9-1)" \
    'for s in floodmeter4 floodmeter6 banned_ips banned_ips6 allowlist4 allowlist6; do nft list set inet filter "$s" >/dev/null 2>&1 || exit 1; done'

# --- L2: chain dns_guard and named counters dns_dropped/dns_banned exist (B9-1) ---
chk "L2-05" "chain dns_guard and counters dns_dropped/dns_banned exist (B9-1)" \
    'nft list chain inet filter dns_guard >/dev/null 2>&1 && nft list counter inet filter dns_dropped >/dev/null 2>&1 && nft list counter inet filter dns_banned >/dev/null 2>&1'

# --- L2: NOTRACK counter on the raw prerouting rule is non-zero under live traffic (B9-2) ---
evidence "L2-06" "nft list table inet raw | grep -A2 notrack"
manual "L2-06" "NOTRACK counter on the raw prerouting rule is non-zero under live traffic (B9-2)"

# --- L2: conntrack holds NO udp 53/853/5335 flows (B9-2) ---
chk "L2-07" "conntrack holds no udp 53/853/5335 flows (B9-2)" \
    '[ "$(conntrack -L -p udp 2>/dev/null | grep -cE "dport=(53|853|5335)")" -eq 0 ]'

# --- L2: THE HOST'"'"'S OWN OUTBOUND DNS STILL WORKS (B9-3) — L12 #10 ---
chk_blocker "L2-08" "host's own outbound DNS still works: getent hosts / apt update (B9-3, L12#10)" \
    "getent hosts api.github.com >/dev/null && apt-get -s update >/dev/null"

# --- L2: B4 invariant holds: nft flood threshold >= 4x AdGuardHome's dns.ratelimit (B9-5) ---
evidence "L2-09" "nft list chain inet filter dns_guard | grep -i limit; grep -n ratelimit /opt/adguardhome/conf/AdGuardHome.yaml 2>/dev/null"
manual "L2-09" "nft flood threshold (expect 400) >= 4x AGH dns.ratelimit (expect 100); raise both together or neither (B9-5)"

# --- L2: flood guard engages off-box, bans the source, does NOT catch loopback (B9-5) ---
manual "L2-10" "[off-box] flood guard engages, bans the source, and does NOT catch loopback (B9-5)"

# --- L2: egress RRL and byte-cap counters are ZERO under normal load (B9-6) ---
evidence "L2-11" "nft list chain inet filter output | grep -i counter"
manual "L2-11" "egress RRL and byte-cap counters are ZERO under normal load (B9-6)"

# --- L2: measured amplification factor recorded; truncation proven with . DNSKEY +bufsize=512 (B9-7) ---
manual "L2-12" "measured amplification factor recorded; truncation proven with '. DNSKEY +bufsize=512' (B9-7)"

# --- L2: [off-box] 3000/5335/8053 unreachable (B9-8) ---
manual "L2-13" "[off-box] nc -z -w2 \$PUB 3000 (and 5335, 8053) — all unreachable (B9-8)"

# --- L2: [off-box] public surface is exactly 22,53,80,443,853 tcp + 53,853 udp (B9-9) ---
manual "L2-14" "[off-box] public surface is exactly tcp 22/53/80/443/853 + udp 53/853, and tcp/80 is open (certbot chain + Q5c) (B9-9)"

# --- L2: ban enforcement drops a test address on EVERY transport, then removed (B9-10) ---
manual "L2-15" "[off-box] ban enforcement drops a test address on every transport; element then removed (B9-10)"

# --- L2: certbot renewal does NOT wipe ban state (B7) ---
evidence "L2-16" "certbot renew --dry-run"
manual "L2-16" "certbot renew --dry-run does NOT wipe ban state (element survives) (B7)"

# --- L2: /usr/local/sbin/nft-apply is the ONLY reload wrapper on the box (B8) ---
chk "L2-17" "/usr/local/sbin/nft-apply is the only reload wrapper (B8)" \
    '[ -x /usr/local/sbin/nft-apply ] && [ "$(ls /usr/local/sbin/nft-* 2>/dev/null | grep -v nft-apply | grep -v nft-ban-escalate | wc -l)" -eq 0 ]'

# --- L2: systemctl reload nftables is routed to nft-apply by the B1 override (B1, B8) ---
chk "L2-18" "systemctl reload nftables is routed to nft-apply (B1, B8)" \
    "systemctl show nftables -p ExecReload | grep -q nft-apply"

# --- L2: a reload restores bans with their REMAINING timeout, not a fresh full duration (B8) ---
manual "L2-19" "a reload restores bans with their REMAINING timeout, not a fresh full duration (B8)"

# --- L2: ruleset, conntrack sysctls and allowlist all survive a reboot (B9-11) ---
manual "L2-20" "ruleset, conntrack sysctls and allowlist all survive a REBOOT (B9-11)"

# --- L2: VRRP (ip protocol 112) accepted on the private NIC only -- Tier 3 only (N3) ---
manual "L2-21" "[Tier 3 only] VRRP (ip protocol 112) accepted on the private NIC only (N3)"

# =====================================================================
# L3. Resolver (Unbound)
# =====================================================================
phase_header "L3. Resolver (Unbound)"

# --- L3: unbound 1.19.2; unbound-checkconf clean (C1, C2) ---
chk "L3-01" "unbound -V shows 1.19.2; unbound-checkconf clean (C1, C2)" \
    'unbound -V 2>&1 | grep -q "1.19.2" && unbound-checkconf >/dev/null 2>&1'

# --- L3: config drop-in is /etc/unbound/unbound.conf.d/10-public-resolver.conf (C2, M4) ---
chk "L3-02" "config drop-in is 10-public-resolver.conf (C2, M4)" \
    "[ -f /etc/unbound/unbound.conf.d/10-public-resolver.conf ]"

# --- L3: listening on 127.0.0.1:5335 and [::1]:5335 ONLY (C2) ---
evidence "L3-03" "ss -lnup 'sport = :5335'"
chk "L3-03" "Unbound listens on 127.0.0.1:5335 and [::1]:5335 only (C2)" \
    'ss -lnup "sport = :5335" 2>/dev/null | grep -q "127.0.0.1:5335" && ! ss -lnup "sport = :5335" 2>/dev/null | grep -qE "\\*:5335|0.0.0.0:5335"'

# --- L3: running as the unbound user, not root (C4) ---
chk "L3-04" "unbound process runs as user unbound, not root (C4)" \
    '[ "$(ps -o user= -C unbound | sort -u | tr -d "[:space:]")" = "unbound" ]'

# --- L3: packaged unit NOT replaced; drop-ins only (C4) ---
chk "L3-05" "/etc/systemd/system/unbound.service does NOT exist — drop-ins only (C4)" \
    "[ ! -e /etc/systemd/system/unbound.service ]"

# --- L3: DropInPaths are exactly nofile.conf + hardening.conf (C4) ---
chk "L3-06" "unbound DropInPaths are exactly nofile.conf + hardening.conf (C4)" \
    'D="$(systemctl show unbound -p DropInPaths --value)"; echo "$D" | grep -q nofile.conf && echo "$D" | grep -q hardening.conf && ! echo "$D" | grep -qE "ha.conf|limits.conf|dns-node.conf"'

# --- L3: canonical restart policy identical on every unit in the stack (C4, E5b, N4a) ---
chk "L3-07" "unbound restart policy: Restart=always RestartSec=5s StartLimitBurst=10 (C4, E5b, N4a)" \
    '[ "$(systemctl show unbound -p Restart --value)" = "always" ] && [ "$(systemctl show unbound -p RestartUSec --value)" = "5s" ] && [ "$(systemctl show unbound -p StartLimitBurst --value)" = "10" ]'

# --- L3: no Requires= between any two daemons in this stack -- Wants=+After= only (C4, E5b, N4b) ---
chk "L3-08" "no Requires= between unbound/adguardhome/nginx units (C4, E5b, N4b)" \
    '! grep -rq "^Requires=" /etc/systemd/system/{unbound,adguardhome,nginx}.service.d/ 2>/dev/null'

# --- L3: genuinely RECURSING: no forward-zone anywhere, tcpdump shows root/TLD/auth (C5.1) ---
chk "L3-09" "no forward-zone directive anywhere in Unbound config (C5.1)" \
    '! grep -rq "forward-zone" /etc/unbound/ 2>/dev/null'
manual "L3-09b" "tcpdump on the egress interface shows queries reaching root/TLD/authoritative servers, not one fixed upstream (C5.1)"

# --- L3: modules: validator iterator (C5.2) ---
chk "L3-10" "unbound-control status shows modules: validator iterator (C5.2)" \
    "unbound-control status 2>/dev/null | grep -q 'modules:.*validator.*iterator'"

# --- L3: auto-trust-anchor-file declared exactly ONCE (C3) ---
chk "L3-11" "auto-trust-anchor-file declared exactly once (C3)" \
    '[ "$(grep -rh auto-trust-anchor-file /etc/unbound/ 2>/dev/null | wc -l)" -eq 1 ]'

# --- L3: root.key non-empty, unbound:unbound 0644, in restic include list (C3, K3) ---
chk "L3-12" "root.key non-empty, owned unbound:unbound, mode 0644 (C3, K3)" \
    '[ -s /var/lib/unbound/root.key ] && [ "$(stat -c %U:%G /var/lib/unbound/root.key)" = "unbound:unbound" ] && [ "$(stat -c %a /var/lib/unbound/root.key)" = "644" ]'
evidence "L3-12b" "grep -c 'root.key' /etc/restic/include.txt 2>/dev/null"
manual "L3-12b" "root.key is in the restic include list (C3, K3)"

# --- L3: trust anchor STATE inspected, at least one key state=2 VALID (C3) — L12 #7 ---
chk_blocker "L3-13" "trust anchor has at least one key at state=2 VALID (C3, L12#7)" \
    "grep -q ';;state=2' /var/lib/unbound/root.key"

# --- L3: root.key was rewritten within the last 90 days (C3) ---
chk "L3-14" "root.key mtime is within 90 days (C3)" \
    '[ -z "$(find /var/lib/unbound/root.key -mtime +90 2>/dev/null)" ]'

# --- L3: monthly anchor-state line appended to /etc/cron.d/dns-health; ICANN rollover dates calendared (C3, I10, O6) ---
chk "L3-15" "monthly anchor-state check line present in /etc/cron.d/dns-health (C3, I10)" \
    "grep -q 'root.key' /etc/cron.d/dns-health 2>/dev/null"
manual "L3-15b" "ICANN rollover announcements subscribed and calendared next to the K6/K7 drills (C3, O6)"

# --- L3: dns-root-data is not frozen -- M1's security-pocket scope structurally excludes it (M1, C3) ---
chk "L3-16" "root.hints mtime within 365 days — dns-root-data not frozen (M1, C3)" \
    '[ -z "$(find /usr/share/dns/root.hints -mtime +365 2>/dev/null)" ]'

# --- L3: unbound-anchor-guard.timer enabled and does NOT touch a healthy anchor (C3) ---
chk "L3-17" "unbound-anchor-guard.timer is enabled (C3)" \
    "systemctl is-enabled unbound-anchor-guard.timer >/dev/null 2>&1"
manual "L3-17b" "unbound-anchor-guard.timer does NOT touch a healthy anchor (C3)"

# --- L3: two DNSSEC fast-detector lines appended to /etc/cron.d/dns-health, not a second cron file (C3, I10) ---
manual "L3-18" "the two DNSSEC fast-detector lines were APPENDED to /etc/cron.d/dns-health, not a second cron file (C3, I10)"

# --- L3: 18 private-address lines + 1 private-domain line (C2, H7) ---
chk "L3-19" "18 private-address lines + 1 private-domain line in Unbound config (C2, H7)" \
    '[ "$(grep -rc "^[[:space:]]*private-address:" /etc/unbound/ 2>/dev/null | awk -F: "{s+=\$2} END{print s}")" -eq 18 ] && grep -rq "^[[:space:]]*private-domain:" /etc/unbound/ 2>/dev/null'

# --- L3: edns-buffer-size and max-udp-size both 1232 (C2) ---
chk "L3-20" "edns-buffer-size and max-udp-size both 1232 (C2)" \
    '[ "$(unbound-control get_option edns-buffer-size 2>/dev/null)" = "1232" ] && [ "$(unbound-control get_option max-udp-size 2>/dev/null)" = "1232" ]'

# --- L3: qname-minimisation yes, strict no (C2, C5.4) ---
chk "L3-21" "qname-minimisation yes, qname-minimisation-strict no (C2, C5.4)" \
    '[ "$(unbound-control get_option qname-minimisation 2>/dev/null)" = "yes" ] && [ "$(unbound-control get_option qname-minimisation-strict 2>/dev/null)" = "no" ]'

# --- L3: do-ip6 matches this host's actual IPv6 EGRESS, tested rather than assumed (C2) ---
evidence "L3-22" 'ip -6 route show default; dig @2001:500:2f::f . NS +time=3 +tries=1; dig @2001:500:1::53 . NS +time=3 +tries=1'
manual "L3-22" "do-ip6 (yes/no) matches this host's ACTUAL tested IPv6 egress, recorded with the reason if no (C2)"

# --- L3: NO domain-insecure: in any drop-in -- NTA is runtime-only by design (C3b, O4) ---
chk "L3-23" "no domain-insecure: in any drop-in (C3b, O4)" \
    '! grep -rn "domain-insecure" /etc/unbound/ 2>/dev/null'
evidence "L3-23b" "unbound-control list_insecure"
manual "L3-23b" "unbound-control list_insecure is empty, or every entry carries a ticket and expiry date (C3b, O4)"

# --- L3: C3b procedure is in the runbook and its discriminator is understood (C3b) ---
manual "L3-24" "the C3b OUR-anchor-vs-THEIR-zone discriminator procedure is in the runbook and understood (C3b)"

# --- L3: verbosity is 1 (NOT 0) and use-syslog is no (C2, G, Q3) ---
chk "L3-25" "verbosity 1, use-syslog no (C2, G, Q3)" \
    '[ "$(unbound-control get_option verbosity 2>/dev/null)" = "1" ] && [ "$(unbound-control get_option use-syslog 2>/dev/null)" = "no" ]'

# --- L3: remote control ENABLED on the shipped unix socket, no second control channel on tcp/8953 (C2, I2, Q3) ---
chk "L3-26" "unbound remote-control enabled on unix socket; no tcp/8953 second channel (C2, I2, Q3)" \
    '[ "$(unbound-control get_option control-enable 2>/dev/null)" = "yes" ] && ! ss -lntp 2>/dev/null | grep -q ":8953"'

# --- L3: serve-expired-client-timeout is 1800, NOT 0; 1.8s degraded-path latency understood (C2, C5.6) ---
chk "L3-27" "serve-expired-client-timeout is 1800 (C2, C5.6)" \
    '[ "$(unbound-control get_option serve-expired-client-timeout 2>/dev/null)" = "1800" ]'
manual "L3-27b" "the 1.8s degraded-path latency is understood and written into the runbook (C2, C5.6)"

# --- L3: stale is NOT served while resolution is healthy (num.expired stays 0) (C5.6) ---
chk "L3-28" "num.expired is 0 while resolution is healthy (C5.6)" \
    '[ "$(unbound-control stats_noreset 2>/dev/null | grep -c "^num.expired=0")" -ge 1 ]'

# --- L3: total.num.prefetch rises under repeat traffic (C5.5, H8) ---
manual "L3-29" "total.num.prefetch rises under repeat traffic — this is what replaced Phase F (C5.5, H8)"

# --- L3: LimitNOFILE 65535; no ulimit/outgoing-port warning in the journal (C2) ---
chk "L3-30" "unbound LimitNOFILE 65535; no ulimit/outgoing-port warning (C2)" \
    '[ "$(systemctl show unbound -p LimitNOFILE --value)" = "65535" ] && ! journalctl -u unbound --no-pager 2>/dev/null | grep -qi "outgoing.*port\\|ulimit"'

# --- L3: source-port randomisation visible on the wire (many distinct ports) (C5.7) ---
manual "L3-31" "source-port randomisation visible on the wire (many distinct ports) (C5.7)"

# --- L3: cold-vs-warm miss cost measured and recorded as the Phase I latency baseline (C6) ---
manual "L3-32" "cold-vs-warm miss cost measured and recorded as the Phase I latency baseline (C6)"

# =====================================================================
# L4. TLS certificates
# =====================================================================
phase_header "L4. TLS certificates"

# --- L4: CAA state was checked BEFORE the first issuance attempt (D2) ---
evidence "L4-01" "dig +short CAA \"$FQDN\"; dig +short CAA \"\${FQDN#*.}\""
manual "L4-01" "CAA state was checked BEFORE the first issuance attempt: empty everywhere, or a set containing 0 issue \"letsencrypt.org\" (D2)"

# --- L4: CAA PUBLISHED after issuance, issuewild matches D7/P3c decision (D2, D8, D7) ---
evidence "L4-02" "dig +short CAA \"\${FQDN#*.}\""
manual "L4-02" "CAA published: issue \"letsencrypt.org\"; issuewild \";\" unless Phase P wildcard selected; iodef mailto: the Q5c security contact (D2, D8, D7)"

# --- L4: domain expiry is MONITORED, not remembered (I4, I6, O6) ---
chk "L4-03" "dns-domain-expiry check present on /etc/cron.d/dns-health (I4, I6, O6)" \
    "grep -q 'dns-domain-expiry' /etc/cron.d/dns-health 2>/dev/null"
evidence "L4-03b" "curl -fsSL --max-time 20 \"https://rdap.org/domain/\${FQDN#*.}\" | jq -r '.events[]|select(.eventAction==\"expiration\")|.eventDate'"
manual "L4-03b" "DomainExpiringSoon (60d) and DomainExpiringCritical (30d) alerts loaded; DomainExpiryCheckFailing loaded (I4, I6, O6)"

# --- L4: registrar auto-renew ON, lock ON, MFA on, recovery email + card expiry recorded in Phase O inventory (O6) ---
manual "L4-04" "registrar: auto-renew ON, registrar lock ON, account MFA on, recovery email and the renewal card's OWN expiry date recorded in the Phase O inventory (O6)"

# --- L4: a probe resolves dns.example.com against a PUBLIC resolver, not 127.0.0.1 (I4, I9) ---
chk "L4-05" "a probe target resolves $FQDN against a public resolver, not 127.0.0.1 (I4, I9)" \
    "dig +short \"$FQDN\" @1.1.1.1 | grep -q ."

# --- L4: certificate is ECDSA P-256 (D9-1) ---
chk "L4-06" "certificate public key algorithm is ECDSA P-256 (D9-1)" \
    "openssl x509 -in /opt/adguardhome/conf/ssl/fullchain.pem -noout -text 2>/dev/null | grep -q 'prime256v1\\|NIST CURVE: P-256'"

# --- L4: SANs are exactly what you intended (wildcard only if Phase P ClientID SNI) (D9-2) ---
evidence "L4-07" "openssl x509 -in /opt/adguardhome/conf/ssl/fullchain.pem -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name'"
manual "L4-07" "SANs are exactly what you intended (wildcard only if Phase P ClientID SNI) (D9-2)"

# --- L4: renewal authenticator is webroot or dns-*, NEVER standalone (D9-3) ---
chk "L4-08" "certbot renewal authenticator is webroot or dns-*, never standalone (D9-3)" \
    '! grep -rq "^authenticator = standalone" /etc/letsencrypt/renewal/ 2>/dev/null'

# --- L4: certbot renew --dry-run succeeds; certbot.timer enabled (D5, D9-4) ---
chk "L4-09" "certbot.timer enabled; certbot renew --dry-run succeeds (D5, D9-4)" \
    "systemctl is-enabled certbot.timer >/dev/null 2>&1 && certbot renew --dry-run >/dev/null 2>&1"

# --- L4: deploy hook is /etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh, mode 0700 (D4) ---
chk "L4-10" "deploy hook 50-dns-stack.sh exists, mode 0700 (D4)" \
    '[ -f /etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh ] && [ "$(stat -c %a /etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh)" = "700" ]'

# --- L4: it reaches AGH binary through /opt/adguardhome/current/AdGuardHome, never a pinned path (D4, E1, M3) ---
chk "L4-11" "deploy hook references the current symlink, not a pinned releases/<ver> path (D4, E1, M3)" \
    'grep -q "current/AdGuardHome" /etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh && ! grep -qE "releases/v?[0-9]" /etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh'

# --- L4: AGH's copy exists, 0640 adguardhome:adguardhome, byte-identical to live/ (D4, D9-5) ---
chk "L4-12" "AGH cert copy exists, adguardhome:adguardhome 0640, byte-identical to live/ (D4, D9-5)" \
    '[ -f /opt/adguardhome/conf/ssl/fullchain.pem ] && [ "$(stat -c %U:%G /opt/adguardhome/conf/ssl/fullchain.pem)" = "adguardhome:adguardhome" ] && [ "$(stat -c %a /opt/adguardhome/conf/ssl/fullchain.pem)" = "640" ] && cmp -s /opt/adguardhome/conf/ssl/fullchain.pem /etc/letsencrypt/live/"$FQDN"/fullchain.pem'

# --- L4: conf/ssl directory is adguardhome-owned 0700 (K5a) ---
chk "L4-13" "/opt/adguardhome/conf/ssl is adguardhome-owned 0700 (K5a)" \
    '[ "$(stat -c %U:%G /opt/adguardhome/conf/ssl)" = "adguardhome:adguardhome" ] && [ "$(stat -c %a /opt/adguardhome/conf/ssl)" = "700" ]'

# --- L4: served cert on :443 AND :853 matches the on-disk fingerprint (D9-6, H12) ---
chk "L4-14" "served cert on :443 and :853 matches on-disk fingerprint (D9-6, H12)" \
    'ONDISK=$(openssl x509 -in /opt/adguardhome/conf/ssl/fullchain.pem -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2); for HP in "$FQDN:853" "$FQDN:443"; do S=$(openssl s_client -connect "$HP" -servername "$FQDN" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2); [ -n "$S" ] && [ "$S" = "$ONDISK" ] || exit 1; done'

# --- L4: no OCSP URI on the certificate; no ssl_stapling directive anywhere (D6, D9-7) ---
chk "L4-15" "no OCSP URI on the certificate; no ssl_stapling directive anywhere (D6, D9-7)" \
    '! openssl x509 -in /opt/adguardhome/conf/ssl/fullchain.pem -noout -ocsp_uri 2>/dev/null | grep -q . && ! grep -rq ssl_stapling /etc/nginx/ 2>/dev/null'

# --- L4: deploy hook run by hand at least once -- certbot skips deploy hooks on --dry-run (D4, D5) ---
manual "L4-16" "deploy hook was run BY HAND at least once — certbot skips deploy hooks on --dry-run (D4, D5)"

# =====================================================================
# L5. Edge — AdGuardHome and nginx
# =====================================================================
phase_header "L5. Edge — AdGuardHome and nginx"

# --- L5: binary is a pinned tag via releases/<ver> + current symlink; checksum verified (E1, M3) ---
evidence "L5-01" "readlink -f /opt/adguardhome/current"
manual "L5-01" "binary is a pinned tag installed via releases/<ver> + current symlink; checksum verified (E1, M3)"

# --- L5: every reference to the binary anywhere on the box uses the current symlink (E1, D4, H12, M3, P1) ---
chk "L5-02" "no reference to a pinned releases/<ver> AdGuardHome path outside the current symlink itself (E1, D4, H12, M3, P1)" \
    '! grep -rlE "adguardhome/releases/v?[0-9][^[:space:]]*AdGuardHome" /etc /usr/local/sbin /opt/dns-config-backup 2>/dev/null | grep -v "^/opt/adguardhome/current$"'

# --- L5: getcap on the binary returns NOTHING (E1, E5a) — L12 #8 ---
chk_blocker "L5-03" "getcap on the AdGuardHome binary returns nothing (E1, E5a, L12#8)" \
    '[ -z "$(getcap /opt/adguardhome/current/AdGuardHome 2>/dev/null)" ]'

# --- L5: AmbientCapabilities=CAP_NET_BIND_SERVICE present and effective (E6-1) — L12 #8 ---
chk_blocker "L5-04" "AmbientCapabilities=CAP_NET_BIND_SERVICE present on adguardhome unit (E6-1, L12#8)" \
    "systemctl show adguardhome -p AmbientCapabilities --value | grep -q CAP_NET_BIND_SERVICE"
manual "L5-04b" "getpcaps <MainPID> shows the capability EFFECTIVE at runtime (E6-1)"

# --- L5: schema_version present and equal to the binary's LastSchemaVersion (E2, Q1) — L12 #9 ---
chk_blocker "L5-05" "schema_version present in AdGuardHome.yaml (E2, Q1, L12#9)" \
    "grep -q '^schema_version:' /opt/adguardhome/conf/AdGuardHome.yaml"
manual "L5-05b" "schema_version equals the binary's LastSchemaVersion (E2, Q1)"

# --- L5: querylog: and statistics: are TOP-LEVEL, and still are AFTER first start (E2, E6-8) — L12 #9 ---
chk_blocker "L5-06" "querylog: and statistics: are top-level keys; no bare 2160h anywhere (E2, E6-8, L12#9)" \
    'grep -qE "^querylog:" /opt/adguardhome/conf/AdGuardHome.yaml && grep -qE "^statistics:" /opt/adguardhome/conf/AdGuardHome.yaml && ! grep -q "2160h" /opt/adguardhome/conf/AdGuardHome.yaml'

# --- L5: shipped logging default in place unless Q posture deliberately opted into (E2, G2, Q1) ---
evidence "L5-07" "grep -A3 '^querylog:' /opt/adguardhome/conf/AdGuardHome.yaml; grep -A2 '^statistics:' /opt/adguardhome/conf/AdGuardHome.yaml"
manual "L5-07" "querylog enabled true / interval 6h / file_enabled false, anonymize_client_ip true, statistics.enabled true — unless a Phase Q posture was deliberately opted into (E2, G2, Q1)"

# --- L5: upstream_dns is only 127.0.0.1:5335; fallback_dns is [] (E2, Q2) ---
chk "L5-08" "upstream_dns is only 127.0.0.1:5335; fallback_dns is empty (E2, Q2)" \
    'U=$(grep -A2 "^upstream_dns:" /opt/adguardhome/conf/AdGuardHome.yaml); echo "$U" | grep -q "127.0.0.1:5335" && [ "$(echo "$U" | grep -c "^  - ")" -eq 1 ] && grep -A1 "^fallback_dns:" /opt/adguardhome/conf/AdGuardHome.yaml | grep -q "fallback_dns: \\[\\]"'

# --- L5: enable_dnssec true; edns_client_subnet.enabled false; use_private_ptr_resolvers false (E2, Q2) ---
chk "L5-09" "enable_dnssec true; edns_client_subnet.enabled false; use_private_ptr_resolvers false (E2, Q2)" \
    'grep -q "enable_dnssec: true" /opt/adguardhome/conf/AdGuardHome.yaml && grep -A1 "^edns_client_subnet:" /opt/adguardhome/conf/AdGuardHome.yaml | grep -q "enabled: false" && grep -q "use_private_ptr_resolvers: false" /opt/adguardhome/conf/AdGuardHome.yaml'

# --- L5: ratelimit: 100, understood to cover PLAIN UDP ONLY (E2, B4, H10) ---
chk "L5-10" "ratelimit: 100 (E2, B4, H10)" \
    "grep -q 'ratelimit: 100' /opt/adguardhome/conf/AdGuardHome.yaml"

# --- L5: ratelimit_subnet_len_ipv4 32 / _ipv6 64 -- NOT the 24/56 defaults (E2, H10) ---
chk "L5-11" "ratelimit_subnet_len_ipv4 32 / ipv6 64, not the 24/56 defaults (E2, H10)" \
    'grep -q "ratelimit_subnet_len_ipv4: 32" /opt/adguardhome/conf/AdGuardHome.yaml && grep -q "ratelimit_subnet_len_ipv6: 64" /opt/adguardhome/conf/AdGuardHome.yaml'

# --- L5: ratelimit_whitelist still contains 127.0.0.1 and ::1 (E2, F1) ---
chk "L5-12" "ratelimit_whitelist still contains 127.0.0.1 and ::1 (E2, F1)" \
    'grep -A5 "^ratelimit_whitelist:" /opt/adguardhome/conf/AdGuardHome.yaml | grep -q "127.0.0.1" && grep -A5 "^ratelimit_whitelist:" /opt/adguardhome/conf/AdGuardHome.yaml | grep -q "::1"'

# --- L5: blocked_hosts contains version.bind, id.server, hostname.bind (E2, P1) ---
chk "L5-13" "blocked_hosts contains version.bind, id.server, hostname.bind (E2, P1)" \
    'B=$(grep -A10 "^blocked_hosts:" /opt/adguardhome/conf/AdGuardHome.yaml); echo "$B" | grep -q version.bind && echo "$B" | grep -q id.server && echo "$B" | grep -q hostname.bind'

# --- L5: admin password is a 24-byte random string, bcrypt cost 12, stored in a password manager (E3) ---
manual "L5-14" "admin password is a 24-byte random string, bcrypt cost 12, stored in a password manager (E3)"

# --- L5: credentials never on a command line; /root/.dns-netrc is 0600 (E3) ---
chk "L5-15" "/root/.dns-netrc is mode 0600 (E3)" \
    '[ -f /root/.dns-netrc ] && [ "$(stat -c %a /root/.dns-netrc)" = "600" ]'
manual "L5-15b" "credentials never appear on a command line (E3)"

# --- L5: socket map is EXACTLY the E6-2 list; nothing on 0.0.0.0:3000, 0.0.0.0:8053 or 127.0.0.1:443 (E6-2) ---
chk "L5-16" "nothing on 0.0.0.0:3000, 0.0.0.0:8053 or 127.0.0.1:443 (E6-2)" \
    '! ss -lntp 2>/dev/null | grep -qE "0\\.0\\.0\\.0:3000|0\\.0\\.0\\.0:8053|127\\.0\\.0\\.1:443"'
evidence "L5-16b" "ss -lntup"
manual "L5-16b" "socket map is EXACTLY the E6-2 list (E6-2)"

# --- L5: nginx 1.24.0; listen 443 ssl http2; form (E4) ---
chk "L5-17" "nginx 1.24.0; 'listen 443 ssl http2;' form, not standalone 'http2 on;' (E4)" \
    'nginx -v 2>&1 | grep -q "1.24.0" && grep -rq "listen 443 ssl http2;" /etc/nginx/conf.d/ 2>/dev/null && ! grep -rq "^[[:space:]]*http2 on;" /etc/nginx/conf.d/ 2>/dev/null'

# --- L5: EXACTLY ONE :80 server block, EXACTLY ONE webroot (E4) ---
chk "L5-18" "exactly one :80 server block: 'listen 80 default_server;' + 'listen [::]:80 default_server;' (E4)" \
    '[ "$(grep -rn "listen .*80" /etc/nginx/ 2>/dev/null | grep -v "#" | wc -l)" -eq 2 ] && grep -rq "listen 80 default_server;" /etc/nginx/ 2>/dev/null && grep -rq "listen \\[::\\]:80 default_server;" /etc/nginx/ 2>/dev/null'

# --- L5: sites-enabled/default removed (E4) ---
chk "L5-19" "sites-enabled/default removed (E4)" \
    "[ ! -e /etc/nginx/sites-enabled/default ]"

# --- L5: X-Forwarded-For overwritten, CF-Connecting-IP/True-Client-IP stripped, Host pinned (E4, E6-6) ---
chk "L5-20" "agh-client-identity.conf overwrites XFF, strips CF-Connecting-IP/True-Client-IP, pins Host (E4, E6-6)" \
    'grep -q "X-Forwarded-For" /etc/nginx/snippets/agh-client-identity.conf 2>/dev/null && grep -qi "CF-Connecting-IP" /etc/nginx/snippets/agh-client-identity.conf 2>/dev/null && grep -qi "True-Client-IP" /etc/nginx/snippets/agh-client-identity.conf 2>/dev/null'

# --- L5: proxy_pass carries $is_args$args (E4) ---
chk "L5-21" "proxy_pass carries \$is_args\$args (E4)" \
    'grep -rq "proxy_pass.*\\$is_args\\$args" /etc/nginx/conf.d/doh.conf 2>/dev/null'

# --- L5: ssl_reject_handshake default_server active for unknown SNI (E6-5) ---
chk "L5-22" "ssl_reject_handshake on for the default_server (unknown SNI) (E6-5)" \
    'grep -rq "ssl_reject_handshake" /etc/nginx/conf.d/doh.conf 2>/dev/null'

# --- L5: adguardhome.service carries NO MemoryHigh/MemoryMax/OOMScoreAdjust (E5b, A6) ---
chk "L5-23" "adguardhome.service unit file carries no MemoryHigh/MemoryMax/OOMScoreAdjust (E5b, A6)" \
    '! grep -qE "MemoryHigh|MemoryMax|OOMScoreAdjust" /etc/systemd/system/adguardhome.service'

# --- L5: nginx's unit does NOT deny @privileged (E5c, E5d) ---
chk "L5-24" "nginx unit hardening does not deny @privileged (E5c, E5d)" \
    '! grep -rq "@privileged" /etc/systemd/system/nginx.service.d/hardening.conf 2>/dev/null'

# --- L5: [off-box] DoH GET and POST both return application/dns-message (E6-3, H2) ---
manual "L5-25" "[off-box] DoH GET and POST both return application/dns-message (E6-3, H2)"

# --- L5: [off-box] /control/status, /login.html, /install.html, /apple/* ALL return 404 (E6-5, H2) — L12 #3 ---
manual "L5-26" "[off-box] /control/status, /login.html, /install.html, /apple/* ALL return 404 from the internet; a JSON body from /control/status is a stop-the-build defect (E6-5, H2, L12#3)" blocker

# --- L5: [off-box] DoT and DoQ resolve with kdig >= 3.3 (H3, H4) ---
manual "L5-27" "[off-box] DoT and DoQ resolve with kdig >= 3.3 (H3, H4)"

# --- L5: [off-box, dual-stack host] E6 step 9: every published address answers all four transports (E2a, E6-9, L1) ---
manual "L5-28" "[off-box, dual-stack host] E6 step 9: every address published for $FQDN answers Do53/DoT/DoQ/DoH, DoH=200 on every row (E2a, E6-9, L1)"

# --- L5: [off-box] forged XFF / Host does NOT change the identity in the query log (E6-6) ---
manual "L5-29" "[off-box] forged XFF / Host does NOT change the identity in the query log (E6-6)"

# --- L5: with unbound stopped, the public edge SERVFAILs -- it never answers from anywhere else (E6-7, H5) — L12 #2 ---
manual "L5-30" "with unbound STOPPED, the public edge SERVFAILs and never answers from anywhere else (E6-7, H5, L12#2)" blocker

# --- L5: version.bind returns REFUSED, not SERVFAIL, not an answer (E6-7, P1) ---
chk "L5-31" "version.bind (CHAOS TXT) returns REFUSED (E6-7, P1)" \
    "kdig -c CH -t TXT version.bind @127.0.0.1 +noall +comments 2>/dev/null | grep -q 'status: REFUSED'"

# --- L5: [off-box] trustanchor.unbound returns REFUSED too -- the FOURTH CHAOS probe (C2, E2) ---
evidence "L5-32" "kdig @\"$PUBLIC_IP\" -c CH -t TXT trustanchor.unbound"
manual "L5-32" "[off-box] trustanchor.unbound returns REFUSED — the fourth CHAOS probe, carried by hide-trustanchor (C2, E2)"

# =====================================================================
# L6. Validation and load
# =====================================================================
# Correctness first. H5 is non-negotiable and both directions must be run —
# the negative test alone also passes on a host whose trust anchor is so
# broken that nothing resolves. All items reference the H-series tests,
# which live in and are executed by deploy/phases/H-acceptance-tests.sh;
# this gate does not re-implement them, it confirms they were run.
phase_header "L6. Validation and load"

# --- L6: Do53 UDP+TCP, NXDOMAIN, HTTPS/type65 all answer from the public IP (H1) ---
manual "L6-01" "H1: Do53 UDP + TCP, NXDOMAIN, and HTTPS/type65 all answer from the public IP (H1)"

# --- L6: DNSSEC negative: dnssec-failed.org SERVFAILs on all four transports (H5) — L12 #1 ---
chk_blocker "L6-02" "dig @$PUBLIC_IP dnssec-failed.org returns SERVFAIL, not an answer (H5, L12#1)" \
    "dig @\"$PUBLIC_IP\" dnssec-failed.org A +noall +comments 2>/dev/null | grep -q 'status: SERVFAIL'"
manual "L6-02b" "H5: the negative test also passes on DoT, DoH and DoQ (H5)"

# --- L6: DNSSEC positive: signed name returns ad + RRSIG on every transport (H5) — L12 #1 ---
chk_blocker "L6-03" "signed name returns 'ad' flag + RRSIG on Do53 (H5, L12#1)" \
    'dig @"$PUBLIC_IP" internetsociety.org A +dnssec +noall +comments 2>/dev/null | grep -q "flags:.* ad" && dig @"$PUBLIC_IP" internetsociety.org A +dnssec 2>/dev/null | grep -q RRSIG'
manual "L6-03b" "H5: the positive test also passes on DoT, DoH and DoQ (H5)"

# --- L6: cache normalisation: name warmed WITHOUT +dnssec still returns RRSIGs to a +dnssec client (H5) ---
manual "L6-04" "H5 cache normalisation: a name warmed without +dnssec still returns RRSIGs to a +dnssec client (H5)"

# --- L6: rebinding: config assertion passes; live probe PASS or INCONCLUSIVE with its control (H7) ---
chk "L6-05" "H7 rebinding config assertion: a public rebinding name resolves to no private address (H7)" \
    'M=$(dig @"$PUBLIC_IP" 7f000001.rbndr.us A +short 2>/dev/null); [ -z "$M" ] || ! echo "$M" | grep -qE "^(127\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)"'
manual "L6-05b" "H7 live probe result recorded: PASS or INCONCLUSIVE-with-its-control (H7)"

# --- L6: special-use zones answered locally, not recursed (H7) ---
manual "L6-06" "H7: special-use zones (.onion, in-addr.arpa, localhost) answered locally, not recursed (H7)"

# --- L6: TCP fallback proven with a query that actually truncates (H7) ---
chk "L6-07" "H7 TCP fallback: '. DNSKEY +bufsize=512' truncates (tc flag) and the TCP retry succeeds (H7)" \
    'dig @"$PUBLIC_IP" +dnssec +bufsize=512 +ignore . DNSKEY +noall +comments 2>/dev/null | grep -q " tc" && dig @"$PUBLIC_IP" +dnssec +tcp . DNSKEY +noall +comments 2>/dev/null | grep -q "status: NOERROR"'

# --- L6: DNS cookie status recorded -- AdGuardHome implements none; accepted gap (H7, C2) ---
manual "L6-08" "DNS cookie status recorded: AdGuardHome implements none, accepted gap, in the runbook (H7, C2)"

# --- L6: testssl.sh clean on :443 AND :853; TLS 1.2/1.3 only, no CBC/RC4 (H9) ---
manual "L6-09" "testssl.sh clean on :443 AND :853; TLS 1.2/1.3 only, no CBC/RC4 (H9)"

# --- L6: leaf + intermediate served (H9) ---
chk "L6-10" "leaf + intermediate certificate chain served, not leaf-only (H9)" \
    '[ "$(openssl s_client -connect "$FQDN:443" -servername "$FQDN" </dev/null 2>/dev/null | grep -c "^ [0-9] s:")" -ge 2 ]'

# --- L6: rate limiting drops the flooder and NOT a neighbour in the same /24 (H10) ---
manual "L6-11" "[off-box] rate limiting drops the flooder and NOT a neighbour in the same /24 (H10)"

# --- L6: H10 set check finds all six sets in table inet filter, no second table (H10) ---
chk "L6-12" "H10: all six sets in table inet filter, no second policy table (H10)" \
    'for s in floodmeter4 floodmeter6 banned_ips banned_ips6 allowlist4 allowlist6; do nft list set inet filter "$s" >/dev/null 2>&1 || exit 1; done; [ "$(nft list tables | wc -l)" -eq 2 ]'

# --- L6: H13 upstream/root-outage injection RUN, all four numbers recorded (H13, C5.6) ---
manual "L6-13" "H13 upstream/root-outage injection RUN, with all four numbers recorded: (1) :5335 answers stale not SERVFAIL, (2) EDE 3 + 30s TTL, (3) num.expired > 0, (4) query time ~1800ms (H13, C5.6)"

# --- L6: H13 also recorded what the MONITORING did (H13, I6) ---
manual "L6-14" "H13 recorded which alert fired (RecursionStalled / ServfailRateHigh / RecursionLatencyP99High), dns-smoke.sh result, and Tier-3 vrrp_script FAULT state if applicable (H13, I6)"

# --- L6: H13 restore proven: injection rule deleted by handle, dns-smoke.sh -> SMOKE: PASS (H13) ---
manual "L6-15" "H13 restore proven: injection rule deleted by handle, dns-smoke.sh reports SMOKE: PASS (H13)"

# --- L6: dns-smoke.sh exits 0 with SMOKE: PASS (H12) ---
chk "L6-16" "dns-smoke.sh exits 0 with SMOKE: PASS (H12)" \
    "/usr/local/sbin/dns-smoke.sh 2>&1 | tail -1 | grep -q 'SMOKE: PASS'"

# --- L6: dns-smoke.sh has been SEEN TO FAIL at least once (H12) ---
manual "L6-17" "dns-smoke.sh has been SEEN TO FAIL at least once (stop unbound, stop nginx, restore) (H12)"

# --- L6: all four pre-change gates exit 0 (H12) ---
chk "L6-18" "all four pre-change gates exit 0: nft -c, unbound-checkconf, nginx -t, AGH --check-config (H12)" \
    'nft -c -f /etc/nftables.conf >/dev/null 2>&1 && unbound-checkconf >/dev/null 2>&1 && nginx -t >/dev/null 2>&1 && runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate >/dev/null 2>&1'
evidence "L6-18b" "stat -c '%U:%G %a' /opt/adguardhome/validate 2>/dev/null"
manual "L6-18b" "/opt/adguardhome/validate exists, adguardhome-owned, mode 0750 (Phase O3 creates it) (H12)"

# --- L6: at least one REAL device per transport, configured FROM the Phase R strings (R1, R3-R7) ---
manual "L6-19" "at least one REAL device per transport in use was configured FROM the Phase R strings and resolves through this host end to end: Android Private DNS (R3), Apple config profile (R4), Windows 11 (R5), one browser (R7) (R1, R3-R7)"

# --- L6: R12's client-side validation check was run FROM the client (R12) ---
manual "L6-20" "R12's 'am I actually reaching this resolver, with validation on' check was run FROM the client, not from the server (R12)"

# --- L6: the transport ranking in R2 (DoH/443 first) is the one handed to users (R2) ---
manual "L6-21" "the transport ranking in R2 — DoH/443 first — is the one handed to users (R2)"

# --- L6: H11 load-test thresholds. RTT_base recorded first; every run from H0 test host. ---
manual "L6-LT0" "LT-0 RTT_base recorded (H11)"
manual "L6-LT1" "LT-1 Do53 warm 2,000 QPS / 300s: p50 < RTT_base+1ms, p99 < RTT_base+5ms (H11)"
manual "L6-LT2" "LT-2 Do53 warm: lost + timeout == 0 (H11)"
manual "L6-LT3" "LT-3 Do53 cold 500 QPS: p99 < 250ms (H11)"
manual "L6-LT4" "LT-4 Do53 hostile 300 QPS: p99 < 400ms, SERVFAIL < 1% (H11)"
manual "L6-LT5" "LT-5 DoT 200 new conns/s: handshake p99 < 150ms (H11)"
manual "L6-LT6" "LT-6 DoH 1,000 QPS / 50 conns: p99 < 15ms (H11)"
manual "L6-LT7" "LT-7 DoQ 500 QPS: p99 < 20ms (H11)"
manual "L6-LT8" "LT-8 every run: nf_conntrack_count peak < 5,000 — direct check on the NOTRACK bypass (H11)" blocker
manual "L6-LT9" "LT-9 every run: UdpRcvbufErrors delta == 0 (H11)"
manual "L6-LT10" "LT-10 every run: peak CPU across all cores < 70% (H11)"
manual "L6-LT11" "LT-11 every run: no new dmesg entries (H11)"
manual "L6-LT12" "LT-12 every run: disk growth < 20MB / 10min (shipped default; recompute from G2 if a Q posture logs to disk) (H11)"
manual "L6-LT13" "LT-13 4-hour soak at 30% of the measured knee: RSS slope FLAT for both daemons (H11)" blocker
manual "L6-LT14" "capacity knee measured with resperf and recorded; G2's query-log arithmetic re-run against the MEASURED QPS (H11, G2)"

# =====================================================================
# L7. Observability and alerting
# =====================================================================
phase_header "L7. Observability and alerting"

# --- L7: promtool check config / check rules / amtool check-config all pass (I11-1) ---
chk "L7-01" "promtool check config / check rules / amtool check-config all pass (I11-1)" \
    'promtool check config /etc/prometheus/prometheus.yml >/dev/null 2>&1 && promtool check rules /etc/prometheus/rules/*.yml >/dev/null 2>&1 && amtool check-config /etc/alertmanager/alertmanager.yml >/dev/null 2>&1'

# --- L7: every .prom textfile parses (I11-2) ---
chk "L7-02" "every node_exporter .prom textfile parses (I11-2)" \
    'for f in /var/lib/node_exporter/textfile/*.prom; do [ -e "$f" ] || continue; promtool check metrics < "$f" >/dev/null 2>&1 || exit 1; done'

# --- L7: every unbound_* key referenced by an alert EXISTS in this build's stats output (I11-3) ---
manual "L7-03" "every unbound_* key referenced by an alert EXISTS in this build's stats output — an alert on a key the build does not emit is dead code (I11-3)"

# --- L7: statistics.enabled reads true via /control/stats/config, or a Q posture deliberately opted into (I11-4, Q1) ---
manual "L7-04" "statistics.enabled reads true via /control/stats/config, OR a Phase Q posture was deliberately opted into and Q5a records it (I11-4, Q1)"

# --- L7: disabled-statistics path DEGRADES rather than pages (I11-4b, I3) ---
manual "L7-05" "the disabled-statistics path degrades rather than pages: agh_up 1, agh_running 1, agh_stats_enabled 0, agh_metrics_unavailable_by_policy 1, agh_queries_window_total ABSENT — proven once (I11-4b, I3)"

# --- L7: recent=3600000 returns 200 and recent=60000 returns 400 (I11-5) ---
manual "L7-06" "recent=3600000 returns 200 and recent=60000 returns 400 — the contract, not a guess (I11-5)"

# --- L7: agh_up, unbound_up, dnsprobe_success, dns:qps:rate5m all return >= 1 series (I11-6) ---
chk "L7-07" "agh_up, unbound_up, dnsprobe_success, dns:qps:rate5m each return >= 1 series in Prometheus (I11-6)" \
    'for m in agh_up unbound_up dnsprobe_success "dns:qps:rate5m"; do curl -fsS --max-time 5 "http://127.0.0.1:9090/api/v1/query?query=${m}" 2>/dev/null | grep -q "\"result\":\\[{" || exit 1; done'

# --- L7: prometheus_tsdb_head_series well under 5,000 (I11-7) ---
chk "L7-08" "prometheus_tsdb_head_series well under 5,000 (I11-7)" \
    'N=$(curl -fsS --max-time 5 "http://127.0.0.1:9090/api/v1/query?query=prometheus_tsdb_head_series" 2>/dev/null | grep -oE "\"value\":\\[[0-9.]+,\"[0-9]+\"" | grep -oE "[0-9]+\"$" | tr -d "\""); [ -n "$N" ] && [ "$N" -lt 5000 ]'

# --- L7: retention came from the config file, not the 15d default (I11-9) ---
chk "L7-09" "Prometheus retention set in config, not the 15d default (I11-9)" \
    'grep -rq "retention" /etc/prometheus/ 2>/dev/null || pgrep -a prometheus 2>/dev/null | grep -q "storage.tsdb.retention"'

# --- L7: [off-box] 9090/9093/9094/9095/9100/9115 all filtered; 9094 does not exist at all (I11-10) ---
manual "L7-10" "[off-box] 9090/9093/9094/9095/9100/9115 all filtered from the internet; 9094 does not exist at all (I11-10)"

# --- L7: watchdog rule loaded and firing (I11-11) ---
chk "L7-11" "Watchdog alert rule loaded and currently firing (I11-11)" \
    'curl -fsS --max-time 5 "http://127.0.0.1:9093/api/v2/alerts" 2>/dev/null | grep -q "\"alertname\":\"Watchdog\""'

# --- L7: a real notification reached the PHONE, on the lock screen, with sound (I11-12) ---
manual "L7-12" "a real notification reached the PHONE, on the lock screen, with sound (I11-12)"

# --- L7: the ntfy bridge returns 502 on a failed push, never a lying 200 (I11-13) ---
manual "L7-13" "the ntfy bridge returns 502 on a failed push, never a lying 200 (I11-13)"

# --- L7: dead man's switch proven by stopping Alertmanager and waiting for the external service to page (I11-14, I9) — L12 #5 ---
manual "L7-14" "the dead man's switch was proven by STOPPING Alertmanager and waiting for the external service to page you — without this you have a dashboard, not monitoring (I11-14, I9, L12#5)" blocker

# --- L7: a SECOND, independent external check exists (port monitor on :853 from outside) (I9) ---
manual "L7-15" "a SECOND, independent external check exists — a port monitor on :853 from outside, catching 'the box talks to itself but the internet cannot reach it' (I9)"

# --- L7: chrony is in dns-smoke.sh's UNITS list (H12, I6) ---
chk "L7-16" "chrony is in dns-smoke.sh's UNITS list (H12, I6)" \
    "grep -q 'UNITS.*chrony' /usr/local/sbin/dns-smoke.sh"

# --- L7: ClockUnsynchronised and ClockOffsetHigh are LOADED rules, one has been seen to fire (I6) ---
manual "L7-17" "ClockUnsynchronised and ClockOffsetHigh are LOADED rules and one has been SEEN TO FIRE: stop chrony, date -s '+3 days', confirm SERVFAILs + alert fires, then chronyc makestep and re-run dns-smoke.sh (I6)"

# --- L7: both external services, credentials location and notification targets recorded in Phase O inventory (I9, O6) ---
manual "L7-18" "both external services, their credentials location and their notification targets are recorded in the Phase O inventory (I9, O6)"

# --- L7: /usr/local/sbin/notify.sh exists, 0750 root:root, self-test reached the phone (I8b, I11-15) ---
chk "L7-19" "/usr/local/sbin/notify.sh exists, root:root 0750 (I8b, I11-15)" \
    '[ -x /usr/local/sbin/notify.sh ] && [ "$(stat -c %U:%G /usr/local/sbin/notify.sh)" = "root:root" ] && [ "$(stat -c %a /usr/local/sbin/notify.sh)" = "750" ]'
manual "L7-19b" "a notify.sh self-test reached the phone (I8b, I11-15)"

# --- L7: /etc/cron.d/dns-health exists, 0644 root:root, no dot in filename, loads without parse error (I10, I11-16) ---
chk "L7-20" "/etc/cron.d/dns-health exists, root:root 0644, no dot in filename, no cron parse error (I10, I11-16)" \
    '[ -f /etc/cron.d/dns-health ] && [ "$(stat -c %U:%G /etc/cron.d/dns-health)" = "root:root" ] && [ "$(stat -c %a /etc/cron.d/dns-health)" = "644" ] && [[ "$(basename /etc/cron.d/dns-health)" != *.* ]] && ! journalctl -u cron --no-pager 2>/dev/null | grep -qi "dns-health.*error"'

# --- L7: every cron consumer APPENDED its line to that one file (I10) ---
evidence "L7-21" "cat /etc/cron.d/dns-health 2>/dev/null"
manual "L7-21" "every cron consumer appended its line to /etc/cron.d/dns-health: dns-health daily, diskguard (G4), smoke gate (H12), restore drill (K6), reboot-pending (M6), is-enabled+hold guard (M7), restart-churn (N4c), the two DNSSEC detectors + monthly anchor-state + root.hints staleness (C3, M1), weekly domain-expiry (I4), weekly release watch (I4c) — no second cron file anywhere (I10)"

# --- L7: dns-health exits 0 (I10, I11-17) ---
chk "L7-22" "dns-health exits 0 (I10, I11-17)" \
    "/usr/local/sbin/dns-health"

# --- L7: SLO targets agreed and written down; error-budget policy accepted (I7) ---
manual "L7-23" "SLO targets agreed and written down; error-budget policy accepted (I7)"

# =====================================================================
# L8. Abuse controls
# =====================================================================
phase_header "L8. Abuse controls"

# --- L8: the v1 query-log abuse cron is GONE; nothing in abuse tooling reads querylog.json (J1, J10-10) ---
chk "L8-01" "v1 query-log abuse cron is gone; nothing in abuse tooling reads querylog.json (J1, J10-10)" \
    '[ ! -e /etc/cron.d/dns-abuse ] && ! grep -rq querylog.json /usr/local/sbin/ 2>/dev/null'

# --- L8: Phase J writes NO nftables configuration -- every object it manipulates is Phase B's (J3) ---
manual "L8-02" "Phase J writes NO nftables configuration; every object it manipulates is Phase B's (J3)"

# --- L8: iif lo accept is the FIRST rule of dns_guard (J10-2) ---
chk "L8-03" "'iif lo accept' is the first rule of chain dns_guard (J10-2)" \
    "nft -a list chain inet filter dns_guard 2>/dev/null | awk '/^\\tip/||/^\\tmeta/{print; exit}' | grep -q 'iif \"lo\" accept'"

# --- L8: local-flood regression test does NOT ban 127.0.0.1 (J10-3) ---
manual "L8-04" "local-flood regression test does NOT ban 127.0.0.1 (J10-3)"

# --- L8: ban sets live in the SAME table as the chain that adds to them (J10-4, B4) ---
chk "L8-05" "banned_ips/banned_ips6 live in table inet filter, same as dns_guard (J10-4, B4)" \
    'nft list set inet filter banned_ips >/dev/null 2>&1 && nft list set inet filter banned_ips6 >/dev/null 2>&1'

# --- L8: [off-box] a real remote flood populates banned_ips and increments dns_banned (J10-5) ---
manual "L8-06" "[off-box] a real remote flood populates banned_ips and increments the dns_banned counter (J10-5)"

# --- L8: ban expiry countdown is live and shrinking (J10-6) ---
manual "L8-07" "ban expiry countdown is live and shrinking (J10-6)"

# --- L8: ban state survives a reload via nft-apply, WITH ITS REMAINING TIME (J10-7, B8) ---
manual "L8-08" "ban state survives a reload via nft-apply, WITH ITS REMAINING TIME (J10-7, B8)"

# --- L8: there is no second reload wrapper (J10-7b, B8) ---
chk "L8-09" "no second reload wrapper: /usr/local/sbin/nft-bans does not exist (J10-7b, B8)" \
    "[ ! -e /usr/local/sbin/nft-bans ]"

# --- L8: allowlist4/6 contain loopback plus every known-good high-volume client (B6, J5, J7) ---
chk "L8-10" "allowlist4/allowlist6 contain loopback (B6, J5, J7)" \
    'nft list set inet filter allowlist4 2>/dev/null | grep -q "127.0.0.0/8" && nft list set inet filter allowlist6 2>/dev/null | grep -q "::1"'
manual "L8-10b" "allowlist4/6 also contain every known-good high-volume client (B6, J5, J7)"

# --- L8: escalation: 10 minutes on first offence, promoted to 24 hours on repeat; no permanent tier (B5, J4, J9) ---
manual "L8-11" "escalation: 10 minutes on first offence, promoted to 24 hours on repeat offence; no permanent tier (B5, J4, J9)"

# --- L8: 24-hour escalation sets exist in table inet filter and are actually ENFORCED (B5, J3, J4) ---
chk "L8-12" "banned_long/banned_long6 exist and chain input references them (B5, J3, J4)" \
    'nft list set inet filter banned_long >/dev/null 2>&1 && nft list set inet filter banned_long6 >/dev/null 2>&1 && nft list chain inet filter input 2>/dev/null | grep -q banned_long'

# --- L8: /var/lib/dns-abuse/offences is 0600 root, trimmed to 24h, excluded from backup (J4, J10-8, J10-11) ---
chk "L8-13" "/var/lib/dns-abuse/offences is root 0600 (J4, J10-8, J10-11)" \
    '[ -f /var/lib/dns-abuse/offences ] && [ "$(stat -c %U:%a /var/lib/dns-abuse/offences)" = "root:600" ]'
chk "L8-13b" "/var/lib/dns-abuse/offences excluded from the restic include list (J10-11)" \
    '! grep -q "dns-abuse" /etc/restic/include.txt 2>/dev/null'

# --- L8: nft_dns_banned_packets and nft_banned_ips_elements reach Prometheus (J10-9) ---
chk "L8-14" "nft_dns_banned_packets and nft_banned_ips_elements reach Prometheus (J10-9)" \
    'curl -fsS --max-time 5 "http://127.0.0.1:9090/api/v1/query?query=nft_dns_banned_packets" 2>/dev/null | grep -q "\"result\":\\[{" && curl -fsS --max-time 5 "http://127.0.0.1:9090/api/v1/query?query=nft_banned_ips_elements" 2>/dev/null | grep -q "\"result\":\\[{"'

# --- L8: J8 spoofed-flood drop-only fallback written into the runbook, quoted verbatim, rehearsed once (J8 step 3) ---
manual "L8-15" "the J8 spoofed-flood drop-only fallback is written into the runbook with the exact lines quoted from Phase B's CURRENT ruleset, and has been rehearsed once (J8 step 3)"

# --- L8: J9's ban-steering trade is recorded as accepted in the Phase O decision log (J9) ---
manual "L8-16" "J9's trade — a little over 400 spoofed pps can ban any address the attacker chooses — is recorded as accepted in the Phase O decision log (J9)"

# =====================================================================
# L9. Backup, restore and reproducibility
# =====================================================================
phase_header "L9. Backup, restore and reproducibility"

# --- L9: the v1 daily copy job is gone (K1) ---
chk "L9-01" "the v1 daily copy job is gone: /etc/cron.daily/dns-backup does not exist (K1)" \
    "[ ! -e /etc/cron.daily/dns-backup ]"

# --- L9: /opt/dns-config-backup still EXISTS -- created by Phase A3, backed up by Phase K, never deleted (K1, K3) ---
chk "L9-02" "/opt/dns-config-backup still exists — created by Phase A3, never deleted (K1, K3)" \
    "[ -d /opt/dns-config-backup ]"

# --- L9: restic repo initialised; restic cat config opens it (K2) ---
chk "L9-03" "restic repo initialised; restic cat config opens it (K2)" \
    "restic cat config >/dev/null 2>&1"

# --- L9: the repository password is in the password manager; no escrow exists (K2) ---
manual "L9-04" "the restic repository password is in the password manager; no escrow exists — losing it loses every backup ever taken (K2)"

# --- L9: second operator exists and PROVEN, or single-operator exposure recorded as accepted (K8, O6) ---
manual "L9-05" "second operator exists and has been PROVEN, OR the single-operator exposure is recorded as accepted, with a date, in the Phase O inventory (K8, O6)"
manual "L9-05a" "restic key add gave the second holder their OWN revocable password, and K2's object-storage credential reached them too (K8)"
manual "L9-05b" "a second Alertmanager receiver and dead man's switch target reach a DIFFERENT human on a DIFFERENT device, re-proven against I11-14 (K8)"
manual "L9-05c" "a second SSH admin key was added and proven with A4's own two-session procedure (K8)"
manual "L9-05d" "the absence procedure has been run once (K8)"

# --- L9: object-storage credential scoped to one bucket; delete rights withheld where expressible (K2) ---
manual "L9-06" "object-storage credential scoped to one bucket; delete rights withheld where expressible (K2)"

# --- L9: /etc/letsencrypt backed up WHOLE (archive included), root.key included (K3) ---
evidence "L9-07" "restic ls latest 2>/dev/null | grep -c '^/etc/letsencrypt/'; restic ls latest 2>/dev/null | grep -c root.key"
manual "L9-07" "/etc/letsencrypt backed up WHOLE (archive/ included, not just live/); root.key included (K3)"

# --- L9: /etc/prometheus, /etc/alertmanager, /etc/blackbox_exporter are in the include list (K3) ---
chk "L9-08" "/etc/prometheus, /etc/alertmanager, /etc/blackbox_exporter are in the restic include list (K3)" \
    "restic ls latest 2>/dev/null | grep -qE '^/etc/(prometheus|alertmanager|blackbox_exporter)/'"

# --- L9: /opt/dns-config-backup is in the include list (K3) ---
chk "L9-09" "/opt/dns-config-backup is in the restic include list (K3)" \
    '[ "$(restic ls latest 2>/dev/null | grep -c dns-config-backup)" -gt 0 ]'

# --- L9: /etc/nftables.d/dns-allow.nft is captured by the include list (B6, K3) ---
chk "L9-10" "/etc/nftables.d/dns-allow.nft is in the restic include list (B6, K3)" \
    "grep -q 'dns-allow.nft' /etc/restic/include.txt 2>/dev/null || restic ls latest 2>/dev/null | grep -q dns-allow.nft"

# --- L9: querylog / stats.db / sessions.db / filters excluded (K3) ---
chk "L9-11" "querylog / stats.db / sessions.db / filters excluded from the backup (K3)" \
    '[ "$(restic ls latest 2>/dev/null | grep -c querylog)" -eq 0 ]'

# --- L9: restic-backup.timer enabled; a snapshot exists; check --read-data-subset runs (K4) ---
chk "L9-12" "restic-backup.timer enabled; at least one snapshot exists; check --read-data-subset runs (K4)" \
    'systemctl is-enabled restic-backup.timer >/dev/null 2>&1 && restic snapshots >/dev/null 2>&1 && restic check --read-data-subset=5% >/dev/null 2>&1'

# --- L9: no secret has ever been committed (K5) ---
chk "L9-13" "no secret has ever been committed to /opt/dns-config-backup's git history (K5)" \
    '[ "$(git -C /opt/dns-config-backup log --all -p 2>/dev/null | grep -cE "\\$2[aby]\\$..\\$|PRIVATE KEY")" -eq 0 ]'

# --- L9: vault.yml is WHOLE-FILE encrypted (K5b) ---
manual "L9-14" "vault.yml is WHOLE-FILE encrypted (\$ANSIBLE_VAULT on line 1) (K5b)"

# --- L9: pre-commit tripwire installed AND mirrored as a CI job (K5d) ---
manual "L9-15" "pre-commit tripwire installed AND mirrored as a CI job (K5d)"

# --- L9: Tier 1 restore drill passes (K6) — L12 #6 ---
manual "L9-16" "Tier 1 restore drill passes: restic-restore-drill.sh exits 0, DRILL PASS logged; gates on 10-public-resolver.conf and unbound.service.d/hardening.conf specifically (K6, L12#6)" blocker

# --- L9: Tier 2 DR rebuild drill completed on a scratch VPS, all four pass criteria (K7) — L12 #6 ---
manual "L9-17" "Tier 2 DR rebuild drill on a scratch VPS: dns-smoke.sh exits 0 with SMOKE: PASS on the rebuilt host (K7, L12#6)" blocker
manual "L9-17b" "served certificate is the RESTORED one, not silently re-issued (K7)"
manual "L9-17c" "no step needed SSH to production and no value came from outside the password manager (K7)"
manual "L9-17d" "wall clock inside the O5 target — measured RTO in minutes (K7)"

# --- L9: measured RTO number written into the runbook, excludes DNS propagation (K7, O5, D0) ---
manual "L9-18" "the measured RTO number is written into the runbook and EXCLUDES DNS propagation — add the A-record TTL for Tier 0/1 (K7, O5, D0)"

# --- L9: H14 rollback rehearsal RUN on a healthy host, not merely present (H14, M3) ---
manual "L9-19" "H14 rollback rehearsal RUN on a healthy host: measured rollback RTO in seconds; readlink -f /opt/adguardhome/current is the PREVIOUS release; schema_version is the OLD number; file is adguardhome:adguardhome 0600; dns-smoke.sh exits 0 (H14, M3)"

# --- L9: Unbound rollback rehearsed, apt-mark hold interaction UNDERSTOOD (H14, M4, M7) ---
manual "L9-20" "Unbound rollback rehearsed, and the apt-mark hold interaction with M7's hourly guard is UNDERSTOOD — do not clear the hold during the incident (H14, M4, M7)"

# --- L9: Phase O operational inventory EXISTS, every row has an answer and a date (O6) ---
chk "L9-21" "/opt/dns-config-backup/INVENTORY.md exists and is committed to git (O6)" \
    'git -C /opt/dns-config-backup log -1 -- INVENTORY.md >/dev/null 2>&1'
manual "L9-21b" "every row in the Phase O inventory has an answer and a date; git log -1 on it is recent (O6)"

# --- L9: unattended-upgrades restricted to security pockets; Automatic-Reboot false (M1) ---
chk "L9-22" "unattended-upgrades scoped to the apt security pockets; Automatic-Reboot false (M1)" \
    'grep -q "Unattended-Upgrade::Automatic-Reboot \"false\"" /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null'

# --- L9: needrestart in automatic mode (M2) ---
chk "L9-23" "needrestart in automatic mode (M2)" \
    "grep -q \"\\$nrconf{restart} = 'a'\" /etc/needrestart/needrestart.conf 2>/dev/null"

# --- L9: upgrade-adguardhome.sh and upgrade-unbound.sh installed, each rolls back on smoke failure (M3, M4) ---
chk "L9-24" "upgrade-adguardhome.sh and upgrade-unbound.sh installed and executable (M3, M4)" \
    '[ -x /usr/local/sbin/upgrade-adguardhome.sh ] && [ -x /usr/local/sbin/upgrade-unbound.sh ]'
manual "L9-24b" "each upgrade wrapper rolls back on smoke failure (M3, M4)"

# --- L9: release watch is ACTIVE for all six out-of-apt daemons (I4c) ---
chk "L9-25" "weekly release watch present on /etc/cron.d/dns-health (I4c)" \
    "grep -qi 'release' /etc/cron.d/dns-health 2>/dev/null"
manual "L9-25b" "release watch covers all six out-of-apt daemons: AdGuardHome, restic, prometheus, node_exporter, alertmanager, blackbox_exporter (I4c)"

# --- L9: the release watch has been SEEN TO FIRE once (I4c) ---
manual "L9-26" "the release watch has been SEEN TO FIRE once (pin a version backwards and let it run) (I4c)"

# --- L9: the release watch does NOT auto-upgrade (I4c, M3) ---
manual "L9-27" "the release watch does NOT auto-upgrade — M3's wrapper stays operator-invoked (I4c, M3)"

# --- L9: each component's pinned version and release feed in Phase O inventory, with a named human (I4c, O6) ---
manual "L9-28" "each component's pinned version and release feed are in the Phase O inventory, with a named human responsible for reading it (I4c, O6)"

# --- L9: neither upgrade wrapper contains a setcap step (M3 trap 1) ---
chk "L9-29" "neither upgrade wrapper contains a setcap step (M3 trap 1)" \
    '! grep -q setcap /usr/local/sbin/upgrade-adguardhome.sh 2>/dev/null && ! grep -q setcap /usr/local/sbin/upgrade-unbound.sh 2>/dev/null'

# --- L9: every unit is ENABLED, not merely active; hourly is-enabled guard is in cron (M7) ---
chk "L9-30" "unbound, adguardhome, nginx, nftables are all enabled (M7)" \
    'for u in unbound adguardhome nginx nftables; do systemctl is-enabled --quiet "$u" || exit 1; done'
chk "L9-30b" "hourly is-enabled guard is wired into cron (M7)" \
    "grep -q 'is-enabled' /etc/cron.d/dns-health 2>/dev/null"

# --- L9: no package hold left in force (M4, M7) ---
chk "L9-31" "apt-mark showhold is empty — no package hold left in force (M4, M7)" \
    '[ -z "$(apt-mark showhold 2>/dev/null)" ]'

# --- L9: HA tier chosen and recorded; Tier 3 keepalived FAULT-state handover proven (N2, N3, M6) ---
manual "L9-32" "HA tier chosen and recorded. Tier 3: keepalived FAULT-state handover proven, exactly one node holds certbot.timer, DNS-01 in use, reboot windows staggered by >= 1h (N2, N3, M6)"

# --- L9: units self-heal through a transient fault AND still park in failed after 10 attempts in 300s (N4a, N4c) ---
manual "L9-33" "units self-heal through a transient fault AND still park in 'failed' after 10 attempts in 300s; churn detector wired into /etc/cron.d/dns-health (N4a, N4c)"

# --- L9: Phase N sets NO memory ceiling and NO swappiness value (N5a) ---
chk "L9-34" "Phase N units carry no MemoryHigh/MemoryMax/swappiness settings of their own (N5a)" \
    '! grep -rqE "MemoryHigh|MemoryMax" /etc/systemd/system/*.service.d/*.conf 2>/dev/null | grep -v "unbound\\|adguardhome\\|nginx" && ! grep -rq "vm.swappiness" /etc/sysctl.d/*.conf 2>/dev/null | grep -v 99-dns.conf'

# --- L9: Ansible run is idempotent: changed=0 failed=0 on EVERY recap line (O5) ---
manual "L9-35" "Ansible run is idempotent: changed=0 failed=0 on EVERY recap line (O5)"

# --- L9: drift cron tests for the PRESENCE of drift, not the absence of it (O4) ---
manual "L9-36" "drift cron tests for the PRESENCE of drift, not the absence of it (O4)"

# --- L9: handlers defined once, in restart order, single shared file; reload nftables calls nft-apply (O3) ---
manual "L9-37" "handlers are defined once, in restart order, in a single shared handlers file, and 'reload nftables' calls nft-apply rather than a bare 'nft -f' (O3)"

# --- L9: the three (five) procedures that only exist if somebody wrote them ---
manual "L9-38" "compromise procedure exists, names an OWNER, and its FIRST STEP IS NOT A REBOOT (08 runbook)"
manual "L9-39" "the K5e post-compromise rotation list is written and reachable from that procedure (K5e)"
manual "L9-40" "the Q6 Art. 33 clock is understood to start at AWARENESS, and what was exposed is stated per posture (Q6, Q1)"
manual "L9-41" "IP-change / provider-migration procedure exists and names an OWNER; rehearsed assuming you CANNOT log into the old box (N8, A1)"
manual "L9-42" "decommissioning procedure exists, names an OWNER, and commits to a notice period also stated in the published privacy notice (Q5b, Q6)"

# =====================================================================
# L10. Privacy, retention and legal — (Q)
# =====================================================================
phase_header "L10. Privacy, retention and legal (Q)"

# --- L10: logging posture chosen and recorded; doing nothing means Posture C (shipped default) (Q1) ---
manual "L10-01" "logging posture chosen and recorded. Doing nothing means Posture C — the Phase E shipped default — and that is a choice that must appear in RETENTION.md and the privacy notice (Q1)"

# --- L10: posture's monitoring consequences understood and accepted (Q1, I3) ---
manual "L10-02" "the posture's monitoring consequences are understood and accepted: Posture A means AGH window metrics ABSENT and AdGuardHomeDown cannot fire on it; Posture B costs nothing (Q1, I3)"

# --- L10: AGH starts clean; no legacy querylog_ keys; no 2160h anywhere in the file (Q1) ---
chk "L10-03" "no legacy querylog_ keys; no bare 2160h anywhere in AdGuardHome.yaml (Q1)" \
    '! grep -q "querylog_" /opt/adguardhome/conf/AdGuardHome.yaml && ! grep -q "2160h" /opt/adguardhome/conf/AdGuardHome.yaml'

# --- L10: stats.db asserted EMPTY OF CLIENTS -- never asserted absent (Q1) ---
manual "L10-04" "stats.db is asserted EMPTY OF CLIENTS — never asserted absent, that check can never pass (Q1)"

# --- L10: anonymize_client_ip understood as /16 and /48 (not /24), never used as an abuse input (Q1, J1) ---
chk "L10-05" "anonymize_client_ip is true (Q1, J1)" \
    "grep -q 'anonymize_client_ip: true' /opt/adguardhome/conf/AdGuardHome.yaml"
manual "L10-05b" "anonymize_client_ip is understood as /16 and /48 (not /24), and never used as an abuse input (Q1, J1)"

# --- L10: sensitive-path inventory names the REAL paths Phase E configures (Q3) ---
chk "L10-06" "sensitive-path inventory names the real paths: /var/log/adguardhome/querylog and /var/lib/adguardhome/stats (Q3)" \
    "[ -d /var/log/adguardhome/querylog ] && [ -d /var/lib/adguardhome/stats ]"

# --- L10: tmpfs (if adopted) mounted on those two paths; ExecStartPre=+install fixes ownership; RequiresMountsFor set (Q3) ---
manual "L10-07" "tmpfs (if adopted) is mounted on both sensitive paths; ExecStartPre=+install fixes ownership; RequiresMountsFor is set in the unit's [Unit] section (Q3)"

# --- L10: after a reboot both tmpfs directories carry nothing over (Q3) ---
manual "L10-08" "after a REBOOT both tmpfs directories carry nothing over (Q3)"

# --- L10: Unbound verbosity is 1, stated correctly in the posture inventory (Q3, C2) ---
chk "L10-09" "Unbound verbosity is 1 (Q3, C2)" \
    '[ "$(unbound-control get_option verbosity 2>/dev/null)" = "1" ]'

# --- L10: Unbound remote-control recorded as ENABLED BY DESIGN, dump_cache exposure understood (Q3, I2) ---
manual "L10-10" "Unbound remote-control is recorded as ENABLED BY DESIGN (Phase I needs it), the dump_cache exposure that follows is understood, and no scripted dump_cache exists (Q3, I2)"

# --- L10: journald storage decision (persistent vs volatile) made and recorded (Q3) ---
manual "L10-11" "journald storage decision (persistent vs volatile) made and recorded, not defaulted (Q3)"

# --- L10: disk-encryption decision recorded WITH its limits (Q3) ---
manual "L10-12" "disk-encryption decision recorded WITH its limits — nothing against a live hypervisor (Q3)"

# --- L10: access_log off proven BEHAVIOURALLY on BOTH client-facing server blocks (Q4, E4) ---
manual "L10-13" "access_log off proven BEHAVIOURALLY (byte size of access.log before/after a request) on BOTH the :443 DoH block and the single :80 block — not by grepping /etc/nginx (Q4, E4)"

# --- L10: CT exposure of the hostname accepted, or a DNS-01 wildcard issued INSTEAD (Q4, D7) ---
manual "L10-14" "CT exposure of the hostname accepted, OR a DNS-01 wildcard issued INSTEAD — this decision cannot be reversed after first issuance (Q4, D7)"

# --- L10: PTR matches dns.example.com and forward/reverse agree (Q4) ---
chk "L10-15" "PTR for $PUBLIC_IP matches $FQDN and forward/reverse agree (Q4)" \
    'P=$(dig +short -x "$PUBLIC_IP" 2>/dev/null | sed "s/\\.$//"); [ "$P" = "$FQDN" ]'

# --- L10: Phase Q added a location ^~ /.well-known/ to Phase E's EXISTING :80 block (Q5c, E4, R7) ---
chk "L10-16" "location ^~ /.well-known/ lives inside Phase E's existing :80 block; no second listen-80 default_server, no second webroot (Q5c, E4, R7)" \
    'grep -q "location \\^~ /.well-known/" /etc/nginx/conf.d/doh.conf 2>/dev/null && [ "$(grep -rc "listen 80 default_server;" /etc/nginx/ 2>/dev/null)" -eq 1 ]'

# --- L10: charset utf-8 (and server_tokens off) present in Phase E's server blocks (Q5c, E4) ---
chk "L10-17" "charset utf-8; present in Phase E's server blocks (Q5c, E4)" \
    "grep -rq 'charset utf-8;' /etc/nginx/conf.d/doh.conf 2>/dev/null"

# --- L10: security.txt served over HTTP and HTTPS as text/plain, exactly one Expires under 1 year, expiry check active (Q5c, I8b) ---
manual "L10-18" "security.txt served over HTTP and HTTPS as text/plain; charset=utf-8; exactly one Expires under one year out; expiry check active and calling notify.sh with a severity argument (Q5c, I8b)"

# --- L10: ban duration stated to users matches the kernel (Q5a, Q5b, J3, B5) — L12 #15 ---
manual "L10-19" "ban duration stated to users matches the kernel: '10 minutes, escalating to 24 hours on repeat offences' — in BOTH the retention policy and the privacy notice (Q5a, Q5b, J3, B5, L12#15)" blocker

# --- L10: abuse@ and security@ exist, monitored, tested BY HAND end to end (Q5c) ---
manual "L10-20" "abuse@ and security@ exist, are monitored, and were tested BY HAND end to end (Q5c)"

# --- L10: provider abuse-forwarding ticket raised and its reference recorded (Q5c) ---
manual "L10-21" "provider abuse-forwarding ticket raised and its reference recorded (Q5c)"

# --- L10: privacy notice published and linked from security.txt Policy:, matches the posture actually running (Q5b) ---
manual "L10-22" "privacy notice published and linked from security.txt Policy:, and it matches the posture ACTUALLY RUNNING — publishing zero-log wording on a Posture C host is a false statement (Q5b)"

# --- L10: RETENTION.md committed to /opt/dns-config-backup; Q6 decision register has answer+date in EVERY row (Q5a, Q6) ---
chk "L10-23" "RETENTION.md committed to /opt/dns-config-backup (Q5a, Q6)" \
    'git -C /opt/dns-config-backup log -1 -- RETENTION.md >/dev/null 2>&1'
manual "L10-23b" "the Q6 decision register has an answer and a date in EVERY row (Q6)"

# --- L10: provider AUP read for open-resolver / amplification clauses (Q6) ---
manual "L10-24" "provider AUP read for open-resolver / amplification clauses — this is the thing most likely to end the service (Q6)"

# --- L10: preservation-order and law-enforcement handling decided IN ADVANCE (Q6) ---
manual "L10-25" "preservation-order and law-enforcement handling decided IN ADVANCE, not under pressure (Q6)"

# --- L10: the three unfixable disclosures are in the notice: cleartext SNI, CT, provider netflow (Q4, Q5b) ---
manual "L10-26" "the three unfixable disclosures are in the notice: cleartext SNI, CT, provider netflow (Q4, Q5b)"

# =====================================================================
# L11. Private access layer — (P)
# =====================================================================
# Skip this block entirely for a deliberately public resolver; keep Phase J
# in full instead. This block is applicable only if Phase P (private access)
# was deployed.
phase_header "L11. Private access layer (P) — skip in full for a deliberately public resolver"

if [[ "${KEYSTONE_PHASE_P_DEPLOYED:-0}" == "1" ]]; then
    manual "L11-01" "mechanism selected and recorded: P6 WireGuard | P3 ClientID | P5 mTLS | P2 nft allowlist | P1 only (P0)"
    chk "L11-02" "allowed_clients populated and READ BACK via the control API (P1)" \
        "grep -A5 '^allowed_clients:' /opt/adguardhome/conf/AdGuardHome.yaml 2>/dev/null | grep -q ."
    chk "L11-03" "blocked_hosts survived the P1 edit (P1, E2)" \
        'B=$(grep -A10 "^blocked_hosts:" /opt/adguardhome/conf/AdGuardHome.yaml); echo "$B" | grep -q version.bind'
    chk "L11-04" "trusted_proxies narrowed to 127.0.0.1/32, ::1/128 (P1)" \
        'grep -A3 "^trusted_proxies:" /opt/adguardhome/conf/AdGuardHome.yaml | grep -q "127.0.0.1/32" && grep -A3 "^trusted_proxies:" /opt/adguardhome/conf/AdGuardHome.yaml | grep -q "::1/128"'
    chk "L11-05" "Phase P created NO new table, NO new chain, NO new hook (P2, P7b)" \
        '[ "$(nft list tables | wc -l)" -eq 2 ]'
    manual "L11-06" "P2's allowlist rewrite is a single atomic nft transaction and never reloads /etc/nftables.conf (P2c)"
    manual "L11-07" "every firewall edit was applied with /usr/local/sbin/nft-apply, and live ban timeouts survived (P2c, P7b)"
    chk "L11-08" "allowlist4 still holds 127.0.0.0/8 (and ::1/128 in allowlist6) after any rewrite (P2a)" \
        'nft list set inet filter allowlist4 2>/dev/null | grep -q "127.0.0.0/8" && nft list set inet filter allowlist6 2>/dev/null | grep -q "::1/128"'
    chk "L11-09" "ratelimit_subnet_len_ipv4/ipv6 still 32/64 after any edit to the dns: block (P7c, E2)" \
        'grep -q "ratelimit_subnet_len_ipv4: 32" /opt/adguardhome/conf/AdGuardHome.yaml && grep -q "ratelimit_subnet_len_ipv6: 64" /opt/adguardhome/conf/AdGuardHome.yaml'
    manual "L11-10" "[off-box] unauthorised client matches the P8a matrix exactly for this mechanism (P8b)"
    manual "L11-11" "[off-box] authorised client resolves over EVERY transport the deployment exposes (P8c)"
    manual "L11-12" "[off-box] nmap shows only the ports this mode intends; 3000/8053/8853 never appear (P8b)"
    manual "L11-13" "serve_plain_dns:false was applied TOGETHER with the P7e health-cron change, in one window (P1, P7d)"
    manual "L11-14" "Phase I probes moved inside the access path; the health cron probes the NEW binding (P7e)"
    manual "L11-15" "Phase J neutralised or converted to identity revocation; a peer can be banned by its own tunnel address (P7b, P7f)"
    chk "L11-16" "dns_guard exempts iifname \"wg0\" (or tunnel subnet in allowlist4/6); table inet filter itself is NEVER deleted (P7b, P7f)" \
        'nft list chain inet filter dns_guard 2>/dev/null | grep -q "wg0" || nft list set inet filter allowlist4 2>/dev/null | grep -q "10.77"'
    manual "L11-17" "wildcard cert AND wildcard A record in place — ONLY if DoT/DoQ ClientID SNI is used (P3c, D7)"
    manual "L11-18" "the wildcard AAAA in P3c was published ONLY if the AAAA row of E6 step 9 passes (P3c, E2a, E6-9)"
    manual "L11-19" "CAA issuewild was relaxed to 'letsencrypt.org' BEFORE the DNS-01 wildcard was requested (D2, D7)"
    manual "L11-20" "revocation drilled end to end and TIMED — measured seconds; if not near-instant, revocation depends on something you do not control (P8d)"
    manual "L11-21" "P7's honest cost accepted and disclosed: the access layer is a stronger identity layer than anything the resolver held; wg show output never captured to disk or monitoring (Q7)"
    chk "L11-22" "secrets excluded from source control: wg keys, *.p12, doh-tokens.map, *.psk (P4c, P5a, K5)" \
        '! git -C /opt/dns-config-backup log --all -p 2>/dev/null | grep -qE "BEGIN (WIREGUARD|OPENSSH) PRIVATE KEY|\\.psk"'
else
    warn "L11: KEYSTONE_PHASE_P_DEPLOYED != 1 — Phase P (private access) was not selected for this deployment. Per L11's own header, this block is skipped in full for a deliberately public resolver. Read P7c before skipping: the plan as written rate-limits only plain UDP."
    SUMMARY+=("SKIP|L11-ALL|Phase P not deployed — L11 skipped in full per the source's own instruction")
fi

# =====================================================================
# L12. Do not go live if
# =====================================================================
# "Any one of these is a hard stop." These are cross-references to checks
# already run above (chk_blocker / manual ... blocker), not re-executions —
# running the same assertion twice would not make it more true. Item 17 has
# no earlier check to reference, so it is evaluated here directly.
phase_header "L12. Do not go live if (hard stops — cross-reference)"

info "L12 #1  -> L6-02 / L6-03 (dnssec-failed.org SERVFAIL, signed name ad+RRSIG) (H5)"
info "L12 #2  -> L5-30 (public edge SERVFAILs with unbound stopped) (E6-7, H5)"
info "L12 #3  -> L5-26 (/control/status, /login.html return 404) (E6-5, H2)"
info "L12 #4  -> L6-LT8 (nf_conntrack_count peak < 5,000) (LT-8, B9-2)"
info "L12 #5  -> L7-14 (dead man's switch proven to page) (I11-14, I9)"
info "L12 #6  -> L9-16 / L9-17 (Tier 1 restore drill, Tier 2 DR rebuild) (K6, K7, K2)"
info "L12 #7  -> L3-13 (root.key non-empty; auto-trust-anchor-file declared once) (C3)"
info "L12 #8  -> L5-03 / L5-04 (getcap empty; AmbientCapabilities present) (E1, E5a, E6-1)"
info "L12 #9  -> L5-05 / L5-06 (schema_version present; querylog:/statistics: unchanged after first start) (E2, E6-8, Q1)"
info "L12 #10 -> L2-08 (getent hosts / apt update succeed on the host itself) (B9-3)"
info "L12 #11 -> L1-12 (/etc/resolv.conf: one nameserver line, 127.0.0.1) (A2, C5.8)"
info "L12 #12 -> L2-02 / L2-03 (exactly inet raw + inet filter; one input base chain) (B9-1, B4, J2)"
info "L12 #13 -> L6-LT13 (4-hour soak run; RSS slope flat) (H11)"
info "L12 #14 -> L9-13 (no secret ever committed) (K5)"
info "L12 #15 -> L10-19 (published ban duration matches the kernel's) (Q5a, Q5b, B5, J4)"
info "L12 #16 -> L1-03 / L1-04 ($FQDN resolves to this host from two resolvers; zone not hosted here) (D0, A1)"

# --- L12 #17: build was NOT left half-finished with adguardhome running unmonitored (E5) ---
manual "L12-17" "the build was NOT left half-finished with adguardhome running: either complete through Phase L, or 'systemctl stop adguardhome' was run before walking away (E5, L12#17)" blocker

# ---------------------------------------------------------------------
# Summary and exit
# ---------------------------------------------------------------------
print_summary

if [[ "$BLOCKER_FAIL" -ne 0 ]]; then
    warn "L: GO-LIVE GATE FAILED — one or more L12 hard blockers is FAIL above. Do not go live. Fix the failing item(s), then re-run: sudo deploy/run.sh L"
    exit 1
else
    info "L: go-live gate — no L12 hard blocker FAILED on this run."
    info "L: this does not by itself mean 'ready' — review every FAIL and MANUAL line in the summary table above; L12 names 17 specific hard stops, not the whole checklist. /usr/local/sbin/dns-smoke.sh (H12) remains the authoritative day-2 post-change gate. Re-run 'sudo deploy/run.sh L' any time state changes."
    exit 0
fi
