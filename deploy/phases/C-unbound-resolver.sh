#!/usr/bin/env bash
# deploy/phases/C-unbound-resolver.sh — Phase C: Unbound (validating recursive
# resolver): recursion, DNSSEC, QNAME minimisation, rebinding protection,
# trust-anchor lifecycle.
#
# Source: phases/03-unbound-resolver.md (Keystone DNS plan). Mechanical
# transcription — read the source file before running this on real hardware.
# Not run against real hardware; same caveat as the rest of deploy/.
#
# Single-ownership notes (CLAUDE.md hard rule 2) — this phase does NOT:
#   - set MemoryHigh/MemoryMax/swap/vm.swappiness (sole owner: Phase A6)
#   - create any nftables table/chain/set (sole owner: Phase B)
#   - create /usr/local/sbin/notify.sh or /etc/cron.d/dns-health (sole owner:
#     Phase I) — this script only APPENDS to dns-health and CALLS notify.sh
#   - create /opt/dns-config-backup (sole owner: Phase A3)
#   - touch /opt/adguardhome/validate (sole owner: Phase E)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=../lib/common.sh
source ../lib/common.sh

require_root

phase_header "Phase C — unbound resolver (recursion, DNSSEC, QNAME minimisation, rebinding protection, trust-anchor lifecycle)"

# ============================================================================
# C1. Install Unbound and de-fang the distro integration
# ============================================================================

# --- C1: install packages (version floor: unbound 1.19.2 on Ubuntu 24.04) ---
info "C1: installing unbound, unbound-anchor, dns-root-data"
apt install -y unbound unbound-anchor dns-root-data

# --- C1: mask unbound-resolvconf (would clobber A2's static /etc/resolv.conf) ---
confirm "C1: about to write /etc/default/unbound (RESOLVCONF=false) and disable+mask unbound-resolvconf.service (boot-time DNS config change)"
backup_file /etc/default/unbound
printf 'RESOLVCONF=false\n' > /etc/default/unbound
systemctl disable --now unbound-resolvconf.service
systemctl mask unbound-resolvconf.service

# --- C1: NOT scripted — smartdns user removal ---
# Source text: "Phase A3's smartdns user is now dead - remove it." No exact
# command is given in phases/03-unbound-resolver.md for this removal, and
# CLAUDE.md hard rule 4 (no invented directives) forbids guessing one
# (e.g. `userdel` flags, whether to keep the home dir). Handle by hand:
warn "C1: MANUAL STEP — remove the dead 'smartdns' service user (Phase A3 created it; no removal command is given in phases/03-unbound-resolver.md C1). Verify the correct removal form yourself before running it."

# --- C1: verify (read-only) ---
info "C1: verification (expected output noted inline)"
unbound -V | head -2                                 # expect: 1.19.2
systemctl is-enabled unbound-resolvconf.service || true   # expect: masked
# systemd-resolved is GONE (Phase A2), not merely stub-disabled.
systemctl is-active systemd-resolved 2>/dev/null || true  # expect: inactive, or unit not found
test -L /etc/resolv.conf && warn 'C1: FAIL — /etc/resolv.conf is a symlink again; Phase A2 should have replaced it with a real file'
cat /etc/resolv.conf                                 # expect: still A2's BOOTSTRAP value (provider resolver); C5.8 flips this later
ls -l /usr/share/dns/root.hints /usr/share/dns/root.key

# ============================================================================
# C2. Resolver configuration
# ============================================================================

# --- C2: DECISION pre-flight — do-ip6 egress test (run BEFORE writing the config) ---
info "C2: do-ip6 egress pre-flight test — both dig calls must return status: NOERROR inside 3s for do-ip6: yes to be safe"
ip -6 route show default || true    # an address with no default route is the common trap
dig @2001:500:2f::f . NS +time=3 +tries=1 +noall +comments || true   # f.root-servers.net
dig @2001:500:1::53 . NS +time=3 +tries=1 +noall +comments || true   # h.root-servers.net
warn "C2: if EITHER dig above timed out, edit do-ip6 to 'no' in 10-public-resolver.conf below BEFORE proceeding, and record why on the line — this script writes the plan's default (do-ip6: yes) verbatim and does not decide this for you."

# --- C2: write /etc/unbound/unbound.conf.d/10-public-resolver.conf ---
confirm "C2: about to write/overwrite /etc/unbound/unbound.conf.d/10-public-resolver.conf (main resolver config — do-ip6 defaults to 'yes' per the pre-flight test above; edit first if your egress test failed)"
backup_file /etc/unbound/unbound.conf.d/10-public-resolver.conf
cat > /etc/unbound/unbound.conf.d/10-public-resolver.conf <<'CONF'
# unbound 1.19.2 (Ubuntu 24.04 noble). Public recursive resolver, loopback-only
# listener - the public edge is AdGuardHome (Phase E), which is this daemon's
# only client.

server:
    # === LISTENERS =====================================================
    # Same address:port SmartDNS used, so Phase B's `dport 5335 drop` rule,
    # AdGuardHome's `upstream_dns: 127.0.0.1:5335` and the Phase H isolation
    # test all carry over unchanged.
    interface: 127.0.0.1@5335
    interface: ::1@5335

    # access-control is longest-prefix-match, so order does not matter.
    # It is also GLOBAL to the daemon, not per-listener: if you ever add a
    # public listener, `access-control: 0.0.0.0/0 allow` would open :5335 too.
    # Per-listener policy needs `interface-view:` + `access-control-view:`.
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow

    do-ip4: yes
    do-ip6: yes            # DECISION - run the egress test above BEFORE writing
                           # this line. Set `no` if this VPS has no working IPv6
                           # EGRESS; a dead v6 route costs a timeout per query and
                           # degrades silently. Record WHY if you set it to no.
    do-udp: yes
    do-tcp: yes

    username: "unbound"    # unbound drops privileges itself - see C4
    chroot: ""             # systemd sandboxing covers isolation and avoids the
                           # chroot path traps (root.hints, root.key, /dev/random)
    hide-identity: yes     # REFUSE id.server and hostname.bind
    hide-version: yes      # REFUSE version.bind and version.server
    hide-trustanchor: yes  # REFUSE trustanchor.unbound. Default is NO, and this is
                           # the FOURTH CHAOS-class identity probe - the one the
                           # rest of the stack does not cover. AdGuardHome's
                           # `blocked_hosts` (Phase E) matches on the question NAME
                           # and lists only the other three, and `deny-any` gates
                           # qtype ANY, not class CH. Left unset, an unauthenticated
                           # CH TXT query reads back this resolver's trust-anchor
                           # state - confirming the software is unbound after the
                           # other three were made to lie, and revealing whether an
                           # anchor is missing or mid-rollover. See C3.
    deny-any: yes          # answer qtype ANY with an empty response

    # === SIZING: 2 vCPU / 4 GB shared with AdGuardHome =================
    num-threads: 2                    # = vCPU count. More threads than cores
                                      # buys nothing and costs cache slab RAM.
    so-reuseport: yes                 # per-thread listen sockets; only useful
                                      # with num-threads > 1

    # Slab counts must be a POWER OF TWO and should equal num-threads. Too few
    # slabs serialises threads on a lock; too many wastes memory on empty slabs.
    msg-cache-slabs: 2
    rrset-cache-slabs: 2
    infra-cache-slabs: 2
    key-cache-slabs: 2

    so-rcvbuf: 4m                     # needs net.core.rmem_max >= 4m (Phase A)
    so-sndbuf: 4m
    outgoing-range: 8192              # outgoing source ports held open PER THREAD
    num-queries-per-thread: 4096      # NLnet Labs guidance: half of outgoing-range

    rrset-cache-size: 256m
    msg-cache-size: 128m              # NLnet Labs guidance: ~half of rrset-cache
    key-cache-size: 32m
    neg-cache-size: 16m
    infra-cache-numhosts: 100000      # RTT/EDNS state for authoritative servers

    # === RECURSION + DNSSEC ============================================
    # DO NOT set auto-trust-anchor-file here. The package already sets it in
    # root-auto-trust-anchor-file.conf and a second declaration is a known
    # breakage. See C3.
    root-hints: "/usr/share/dns/root.hints"   # from the dns-root-data package

    harden-dnssec-stripped: yes
    harden-glue: yes
    harden-below-nxdomain: yes
    harden-algo-downgrade: yes        # default is NO - an attacker may not pick
                                      # the weakest algorithm in a multi-alg zone
    harden-large-queries: yes         # default is NO
    harden-short-bufsize: yes
    harden-unknown-additional: yes    # unbound >= 1.17.0; default is NO
    val-clean-additional: yes         # strip unsigned/unvalidated records from
                                      # the additional section instead of
                                      # passing them through to the client
    val-log-level: 1                  # one line per bogus answer, with reason
    log-servfail: yes

    aggressive-nsec: yes              # RFC 8198. Default is YES on 1.19.2 and NO
                                      # on 1.13.1 - declared explicitly so a base
                                      # image change cannot silently revert it.
                                      # Cached NSEC/NSEC3 proves whole ranges
                                      # nonexistent without a query, which is the
                                      # main structural defence against
                                      # random-subdomain (water-torture) floods -
                                      # but SIGNED ZONES ONLY. It is inert when
                                      # the flooded victim zone is unsigned, which
                                      # is the usual case. See the rate-limiting
                                      # section below; `ratelimit` is the
                                      # complement, not an alternative.

    # === PREFETCH: this is what replaces the deleted Phase F warmer ====
    prefetch: yes                     # refresh a cache entry when a query
                                      # arrives with <10% of its TTL left, and
                                      # answer that query from cache immediately
    prefetch-key: yes                 # fetch DNSKEY early, before the DS is
                                      # needed - removes a serialised round trip
                                      # from the validation path on cache miss
    # Prefetch acts only on names your users actually query, so the hot set stays
    # warm with zero synthetic load. The v1 Python warmer generated its own query
    # traffic against a list of domains guessed in advance; it is deleted.

    # === PRIVACY TOWARD THE AUTHORITATIVE SIDE =========================
    qname-minimisation: yes           # RFC 9156. Send only the labels the next
                                      # server needs: the root learns "com.",
                                      # not "intranet.customer.example.com".
                                      # Default is yes on 1.19.2; declared
                                      # explicitly because it is load-bearing.
    qname-minimisation-strict: no     # TRADEOFF, and the safe side of it.
                                      # `no`  = minimise, but fall back to the
                                      #         full QNAME when a server answers
                                      #         a minimised query incorrectly.
                                      # `yes` = never fall back; those zones then
                                      #         fail to resolve ENTIRELY.
                                      # Non-conforming servers that return
                                      # NXDOMAIN (instead of NOERROR/NODATA) for
                                      # an empty non-terminal still exist. On a
                                      # public resolver serving strangers, strict
                                      # converts someone else's misconfiguration
                                      # into your outage. Choose `yes` only if
                                      # you are prepared to field those tickets.
    minimal-responses: yes            # omit unneeded authority/additional
                                      # sections: smaller packets, less
                                      # fragmentation, fewer cache-poisoning
                                      # surfaces
    rrset-roundrobin: yes             # rotate RRset order per response so
                                      # clients that take the first record
                                      # spread across a zone's addresses

    # === EDNS / FRAGMENTATION (DNS Flag Day 2020) ======================
    # 1232 = 1280 (minimum IPv6 MTU) - 40 (IPv6 header) - 8 (UDP header).
    # Larger UDP responses fragment; fragments are trivially spoofable and are
    # dropped outright by a meaningful share of middleboxes.
    edns-buffer-size: 1232            # what unbound advertises to authoritatives
    max-udp-size: 1232                # ceiling on responses unbound sends.
                                      # 1.19.2 default is 1232; 1.13.1's is 4096.
    # NOTE: this governs the RECURSIVE leg only. The client-facing leg is
    # AdGuardHome, which honours whatever buffer size the client advertises and
    # exposes no knob to cap it. See Phase E for that limitation and its
    # mitigations - do not try to fix it here.

    # === ANTI-SPOOF ====================================================
    unwanted-reply-threshold: 10000000 # default is 0 (disabled). After this many
                                       # unsolicited/unmatched replies, unbound
                                       # flushes its caches and logs - a blunt
                                       # but effective response to a sustained
                                       # off-path spoofing campaign. 10M is high
                                       # enough that normal noise never trips it.
    do-not-query-localhost: yes        # never treat a loopback address as an
                                       # authoritative server (default yes)
    use-caps-for-id: no                # DNS 0x20 - see the note below

    # === SERVE-STALE, RFC 8767 =========================================
    serve-expired: yes
    serve-expired-client-timeout: 1800 # THE LOAD-BEARING LINE. Unbound's default
                                       # is 0 in BOTH 1.13.1 and 1.19.2, and 0
                                       # means "answer stale immediately, do not
                                       # wait". See the RFC discussion below.
    serve-expired-ttl: 86400           # RFC 8767 maximum stale timer; the RFC
                                       # suggests 1-3 days
    serve-expired-reply-ttl: 30        # RFC 8767 s4 RECOMMENDED value; also
                                       # unbound's own default
    serve-expired-ttl-reset: no        # a stale hit must not extend the window
    ede: yes                           # RFC 8914 Extended DNS Errors; default no
    ede-serve-expired: yes             # attach EDE 3 "Stale Answer"; default no.
                                       # Both require unbound >= 1.16.0.

    cache-min-ttl: 0                   # DO NOT RAISE. Inflating a short TTL
                                       # breaks the failover the zone operator
                                       # deliberately bought with it.
    cache-max-ttl: 86400
    cache-max-negative-ttl: 3600

    # === DNS REBINDING PROTECTION ======================================
    # Unbound's documented default is that NO private addresses are enabled,
    # i.e. a public name may resolve to 127.0.0.1 and unbound will hand it to
    # the client. The v1 plan had no equivalent at all: any attacker who
    # controls a zone could point evil.example at 127.0.0.1 or 192.168.1.1 and
    # use your public resolver to aim a victim's browser at the victim's own
    # loopback or LAN. These lines strip such records from answers.
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 127.0.0.0/8
    private-address: 0.0.0.0/8
    private-address: 100.64.0.0/10
    private-address: 192.0.2.0/24
    private-address: 198.18.0.0/15
    private-address: 198.51.100.0/24
    private-address: 203.0.113.0/24
    private-address: 255.255.255.255/32
    private-address: ::1/128
    private-address: ::/128
    private-address: fd00::/8
    private-address: fe80::/10
    private-address: 2001:db8::/32
    private-address: ::ffff:0:0/96

    # Known-legitimate publisher of RFC1918 A records. VERIFIED: a lookup of
    # 192-168-1-1.<hash>.plex.direct really does return 192.168.1.1 - that is
    # how Plex gets a valid TLS certificate for a LAN address. Without this
    # exemption, Plex remote access breaks for every one of your users.
    private-domain: "plex.direct"

    # === RFC 9462 DDR: resolver.arpa ===================================
    # unbound 1.19.2 does NOT ship resolver.arpa among its locally-served
    # zones - upstream added resolver.arpa and service.arpa to the defaults
    # in January 2025, after this release. Verified against the noble
    # unbound.conf(5) default list, which has home.arpa but neither of
    # those. So `_dns.resolver.arpa` SVCB probes from Windows 11, iOS 17+
    # and macOS 14+ clients recurse out to the .arpa authoritatives.
    # This line is the DEFAULT side of a decision - read the DDR section
    # below before changing it. Delete it if you move to a base image whose
    # unbound already ships the zone (`unbound-control list_local_zones`).
    local-zone: "resolver.arpa." always_nxdomain

    # === LOGGING =======================================================
    verbosity: 1           # NOT 0. Level 1 is operational errors plus the
                           # val-log-level bogus lines - it does not log queries.
                           # This is the value Phase Q's posture inventory must
                           # report for unbound.
    use-syslog: no         # log to stderr -> journald, NOT to syslog. Phase G's
                           # component table must match this.
    logfile: ""            # -> stderr -> journald
    log-queries: no        # PUBLIC RESOLVER: do not log client queries. See
    log-replies: no        # Phase Q for the retention/legal position.
    extended-statistics: yes   # the wider counter set Phase I's collector scrapes
                               # over the unbound-control socket
CONF

# --- C2: unbound-checkconf + enable ---
unbound-checkconf            # MUST print: no errors in /etc/unbound/unbound.conf
confirm "C2: about to run 'systemctl enable --now unbound' — starts unbound as a boot service"
systemctl enable --now unbound

# --- C2: memory budget (MEASUREMENT ONLY — ceilings/swap/vm.swappiness are Phase A6's, not set here) ---
info "C2: memory budget — configured cache is 256m+128m+32m+16m = 432 MB; budget roughly 2x (~850 MB) as a planning figure, then measure"
systemctl show unbound -p MemoryCurrent          # bytes; run after a warm hour
unbound-control stats_noreset | grep -E 'mem\.cache|mem\.mod'

# --- C2: file descriptors (LimitNOFILE) ---
confirm "C2: about to write /etc/systemd/system/unbound.service.d/nofile.conf (LimitNOFILE=65535) and daemon-reload (boot-service unit drop-in)"
mkdir -p /etc/systemd/system/unbound.service.d
backup_file /etc/systemd/system/unbound.service.d/nofile.conf
printf '[Service]\nLimitNOFILE=65535\n' > /etc/systemd/system/unbound.service.d/nofile.conf
systemctl daemon-reload

# --- C2: outgoing-port-avoid (UNVERIFIED for 1.19.2 syntax — ergonomic guard only, not security) ---
# Guards against unbound grabbing ports 3000/8053 at startup before AdGuardHome
# (Phase E, started after unbound) needs to bind them.
confirm "C2: about to append optional outgoing-port-avoid lines (UNVERIFIED syntax) to 10-public-resolver.conf and reload"
backup_file /etc/unbound/unbound.conf.d/10-public-resolver.conf
cat >> /etc/unbound/unbound.conf.d/10-public-resolver.conf <<'CONF'
    # UNVERIFIED for 1.19.2 syntax on this exact build - `unbound-checkconf`
    # will reject it immediately if the directive name is wrong on your version.
    outgoing-port-avoid: "3000"
    outgoing-port-avoid: "8053"
CONF
if unbound-checkconf; then
    systemctl reload unbound || systemctl restart unbound
else
    warn "C2: unbound-checkconf rejected outgoing-port-avoid on this build — remove those two lines from /etc/unbound/unbound.conf.d/10-public-resolver.conf by hand and instead confirm at boot that AdGuardHome (Phase E) bound successfully. This is an ergonomic guard, not a security control."
fi

# --- C2: DNS 0x20 (use-caps-for-id) — advisory only, no additional action ---
# use-caps-for-id: no is already written above (unbound's own default, and the
# right setting here). Left off deliberately; see phases/03-unbound-resolver.md
# C2 "DNS 0x20" for the tradeoff if you ever reconsider.

# --- C2: DNS cookies (answer-cookie) — deliberately NOT set; no action ---
# Unbound's only client is AdGuardHome over loopback; cookies defend a public
# UDP listener, which this one is not. See source for the public-edge cookie
# gap, which is Phase E's / a security-phase's concern, not this phase's.

# --- C2: RFC 9462 DDR (_dns.resolver.arpa) — Option A (decline discovery) is already
# in the main config above via `local-zone: "resolver.arpa." always_nxdomain`.
# Option B (offer discovery) is NOT applied by this script: it requires an
# IP-SAN TLS certificate that Phase D does not currently issue (name-only cert).
# Recommended default per the plan is Option A. For reference only, Option B
# would replace the local-zone line above with (UNVERIFIED for 1.19.2 SVCB
# local-data syntax — unbound-checkconf is the gate):
#   local-zone: "resolver.arpa." static
#   local-data: '_dns.resolver.arpa. 300 IN SVCB 1 dns.example.com. alpn="dot" port=853'
#   local-data: '_dns.resolver.arpa. 300 IN SVCB 2 dns.example.com. alpn="doq" port=853'
#   local-data: '_dns.resolver.arpa. 300 IN SVCB 3 dns.example.com. alpn="h2,h3" dohpath="/dns-query{?dns}"'
# Take Option B only once Phase D has issued and renewed an IP-SAN certificate
# at least once, and record the choice in the Phase Q decision register.

# --- C2: rate limiting on the recursive leg — `ratelimit` LEFT OFF at go-live per the plan ---
# `ip-ratelimit` must NOT be set (this daemon's only source IP is 127.0.0.1 —
# it would rate-limit AdGuardHome itself). `ratelimit` (per-zone, outgoing qps)
# is the right shape for a random-subdomain flood but is left off by default;
# Phase B's ingress cap (400/s per source + global pps backstop) is the
# structural bound already in place. To enable later, at runtime (no restart,
# no cache flush, vanishes on restart):
#   unbound-control set_option ratelimit: 1000
#   unbound-control get_option ratelimit
#   unbound-control stats_noreset | grep 'num.query.ratelimited'
# To keep it across restarts, add `ratelimit: 1000` (measure your normal
# per-zone peak first) to 10-public-resolver.conf and `unbound-control reload`.
# If this box is ever the SOURCE of a flood against someone else's unsigned
# zone (Phase Q's most-likely-suspension scenario), the incident response is
# `ratelimit` plus a time-boxed `local-zone: "<victim-zone>." refuse` — this is
# Phase J's runbook entry, not scripted here.

# --- C2: cross-phase note — AdGuardHome unit dependency is Phase E's to fix, not scripted here ---
# AdGuardHome's Requires=smartdns.service (v1) must become Wants=+After= on
# unbound, never Requires=. That edit lives in Phase E's unit, not here.

# --- C2: verify ---
info "C2: verification (expected output noted inline)"
unbound-checkconf                                     # "no errors in ..."
ss -lnup 'sport = :5335'; ss -lntp 'sport = :5335'    # unbound only, loopback only
unbound-control status | grep -E 'version|threads|modules'   # modules: validator iterator
unbound-control get_option edns-buffer-size           # 1232
unbound-control get_option max-udp-size               # 1232
unbound-control get_option qname-minimisation         # yes
systemctl show unbound -p LimitNOFILE                 # 65535
journalctl -u unbound --since '5 min ago' | grep -i 'ulimit\|outgoing port' \
  || echo 'no fd warnings'

# Rebinding protection is present at the CONFIG level. This check cannot fail
# open; the live probe in C5 can.
grep -c '^ *private-address:' /etc/unbound/unbound.conf.d/10-public-resolver.conf   # 18
grep -c '^ *private-domain:'  /etc/unbound/unbound.conf.d/10-public-resolver.conf   # 1

# All FOUR CHAOS identity probes are closed, not three.
for q in id.server hostname.bind version.bind trustanchor.unbound; do
  printf '%-22s ' "$q"
  dig @127.0.0.1 -p 5335 -c CH -t TXT "$q" +noall +comments 2>/dev/null \
    | sed -n 's/.*status: \([A-Z]*\).*/\1/p'
done
#   all four: REFUSED. Repeat the trustanchor.unbound probe from OFF-BOX in
#   Phase H:  kdig @dns.example.com +tls -c CH -t TXT trustanchor.unbound

# IPv6 egress matches what do-ip6 claims.
unbound-control get_option do-ip6
ip -6 route show default || echo 'NO DEFAULT V6 ROUTE - do-ip6 must be no'

# resolver.arpa is answered locally, not recursed (the C2 DDR Option A decision)
unbound-control list_local_zones | grep '^resolver.arpa.'         # always_nxdomain
dig @127.0.0.1 -p 5335 _dns.resolver.arpa SVCB +noall +comments +stats \
  | grep -E 'status:|Query time'                                  # NXDOMAIN, ~0 ms

# ============================================================================
# C3. DNSSEC trust anchor lifecycle
# ============================================================================

# --- C3: confirm exactly one auto-trust-anchor-file declaration ---
cat /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf
grep -rhc 'auto-trust-anchor-file' /etc/unbound/ | paste -sd+ - | bc   # must print 1

# --- C3: bootstrap root.key once (before unbound first starts, per the plan) ---
confirm "C3: about to stop/start unbound to bootstrap /var/lib/unbound/root.key (DNSSEC trust anchor) — resolver briefly unavailable"
systemctl stop unbound 2>/dev/null || true
install -d -o unbound -g unbound -m 0755 /var/lib/unbound
unbound-anchor -a /var/lib/unbound/root.key -v || true
chown unbound:unbound /var/lib/unbound/root.key
chmod 0644 /var/lib/unbound/root.key
systemctl start unbound

# --- C3: check what the packaged unit already does ---
systemctl cat unbound | grep -i 'ExecStartPre' || true

# --- C3: detect-and-heal guard (NOT a timer-based unbound-anchor refresh — that races root.key) ---
confirm "C3: about to write /usr/local/sbin/unbound-anchor-guard.sh, its .service/.timer, and enable the timer (boot-service unit)"
backup_file /usr/local/sbin/unbound-anchor-guard.sh
cat > /usr/local/sbin/unbound-anchor-guard.sh <<'EOF'
#!/bin/bash
set -uo pipefail
KEY=/var/lib/unbound/root.key
ok=1
[ -s "$KEY" ] || ok=0
dig @127.0.0.1 -p 5335 . DNSKEY +dnssec +time=3 +tries=1 2>/dev/null \
  | grep -q '^;; flags:.* ad' || ok=0
[ "$ok" = 1 ] && exit 0
logger -t unbound-anchor "anchor unhealthy - re-bootstrapping"
systemctl stop unbound
unbound-anchor -a "$KEY" -r /usr/share/dns/root.hints -v || true
[ -s "$KEY" ] || { logger -t unbound-anchor "FATAL: root.key still empty"; exit 1; }
chown unbound:unbound "$KEY"; chmod 0644 "$KEY"
systemctl start unbound
EOF
chmod +x /usr/local/sbin/unbound-anchor-guard.sh

backup_file /etc/systemd/system/unbound-anchor-guard.service
cat > /etc/systemd/system/unbound-anchor-guard.service <<'EOF'
[Unit]
Description=Detect and heal a broken DNSSEC root trust anchor
After=network-online.target unbound.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/unbound-anchor-guard.sh
EOF

backup_file /etc/systemd/system/unbound-anchor-guard.timer
cat > /etc/systemd/system/unbound-anchor-guard.timer <<'EOF'
[Unit]
Description=Daily DNSSEC trust anchor health check

[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload && systemctl enable --now unbound-anchor-guard.timer

# --- C3: append fast detectors to Phase I's /etc/cron.d/dns-health (sole owner: Phase I) ---
if [[ -f /etc/cron.d/dns-health ]]; then
    backup_file /etc/cron.d/dns-health
    cat >> /etc/cron.d/dns-health <<'EOF'
*/5 * * * * root dig @127.0.0.1 -p 5335 . DNSKEY +dnssec +time=2 +tries=1 2>/dev/null | grep -q '^;; flags:.* ad' || echo "DNSSEC VALIDATION BROKEN (trust anchor?)" | logger -t dns-alert
0 6 * * * root [ -s /var/lib/unbound/root.key ] || echo "root.key EMPTY" | logger -t dns-alert
13 5 1 * * root /usr/local/sbin/anchor-state-check.sh
EOF
else
    warn "C3: /etc/cron.d/dns-health does not exist yet (sole owner: Phase I, which runs after Phase C in the canonical run.sh order). Re-run this append step after Phase I, or add the three lines from phases/03-unbound-resolver.md C3 'Detecting the state before it bites' by hand."
fi

# --- C3: anchor-state-check.sh (root KSK rollover awareness — REPORT ONLY, never heals) ---
backup_file /usr/local/sbin/anchor-state-check.sh
cat > /usr/local/sbin/anchor-state-check.sh <<'EOF'
#!/bin/bash
# REPORT ONLY. This script must never stop unbound and never call unbound-anchor.
# Re-bootstrapping mid-rollover discards the RFC 5011 tracking state the rollover
# depends on. Healing a DEAD anchor belongs to unbound-anchor-guard.sh, which
# fires only once validation has already stopped - a different fault.
set -uo pipefail
KEY=/var/lib/unbound/root.key
NEW_KSK=38696                      # KSK-2024. Update at the next announced roll.
N=/usr/local/sbin/notify.sh        # Phase I owns this; signature is
                                   # notify.sh <severity> <title> [message]

# Match the BRACKETED label, never the bare word: "VALID" can occur by chance
# inside the base64 key material and a false pass here is the exact failure this
# check exists to prevent.
V='\[ *VALID *\]'

grep -q ';;state=' "$KEY" || { "$N" critical "root.key carries no RFC 5011 state" "$KEY"; exit 1; }
grep -q "$V"       "$KEY" || { "$N" critical "no root trust anchor is VALID" "$(grep -o ';;state=[0-9] \[[^]]*\]' "$KEY")"; exit 1; }

line=$(grep "id = $NEW_KSK " "$KEY" || true)     # trailing space: exact tag match
if [ -z "$line" ]; then
  "$N" critical "root KSK-$NEW_KSK absent from root.key" \
       "This host SERVFAILs every signed name once that key signs the root alone."
elif ! printf '%s\n' "$line" | grep -q "$V"; then
  "$N" warning "root KSK-$NEW_KSK present but not yet VALID" "$line"
fi

# RFC 5011 tracking rewrites this file as it probes. A long-stale mtime means
# tracking has stopped even though the AD flag still passes. Measure your own
# box's rewrite cadence during burn-in and tighten this threshold to match.
[ -n "$(find "$KEY" -mtime +90)" ] && \
  "$N" warning "root.key not rewritten in 90 days" "RFC 5011 tracking has probably stopped"
exit 0
EOF
chmod 0750 /usr/local/sbin/anchor-state-check.sh
/usr/local/sbin/anchor-state-check.sh; echo "exit=$?"   # 0, and no notification (assuming Phase I's notify.sh exists)

info "C3: NOT scripted — subscribe to ksk-rollover@icann.org and watch IANA's root-anchors page; add /var/lib/unbound/root.key to the Phase K backup set (Phase K owns that set, no command given here); put each announced rollover date on the same calendar as the Phase K restore drill and record it in the Phase O inventory. These are human/organisational steps, not automatable."

# --- C3: verify ---
info "C3: verification (expected output noted inline)"
grep -rhc 'auto-trust-anchor-file' /etc/unbound/ | paste -sd+ - | bc   # 1
test -s /var/lib/unbound/root.key && echo ANCHOR-OK
stat -c '%U:%G %a %s' /var/lib/unbound/root.key    # unbound:unbound 644, non-zero

unbound-control get_option auto-trust-anchor-file  # /var/lib/unbound/root.key

grep ';;state=' /var/lib/unbound/root.key
#   expect at least one [  VALID  ]; during the current rollover expect BOTH
#   id = 20326 (KSK-2017) and id = 38696 (KSK-2024), and 38696 must read VALID.
grep -c '\[ *VALID *\]' /var/lib/unbound/root.key             # >= 1
grep 'id = 38696 ' /var/lib/unbound/root.key | grep -c '\[ *VALID *\]' || true   # 1
find /var/lib/unbound/root.key -mtime +90          # must print NOTHING
/usr/local/sbin/anchor-state-check.sh; echo "exit=$?"         # 0, no notification

systemctl list-timers unbound-anchor-guard.timer --all
MT=$(stat -c %Y /var/lib/unbound/root.key)
/usr/local/sbin/unbound-anchor-guard.sh; echo "exit=$?"          # 0
[ "$MT" = "$(stat -c %Y /var/lib/unbound/root.key)" ] && echo 'GUARD-DID-NOT-TOUCH-FILE'
journalctl -t unbound-anchor --since '5 min ago'                 # empty on a healthy box

# Fault injection (source marks this run-ONCE-in-a-maintenance-window, not
# part of a normal deploy — left commented, matching the source):
# systemctl stop unbound && : > /var/lib/unbound/root.key && systemctl start unbound
# dig @127.0.0.1 -p 5335 . DNSKEY +dnssec | grep ' ad'   # expect NO 'ad' - broken
# /usr/local/sbin/unbound-anchor-guard.sh
# dig @127.0.0.1 -p 5335 . DNSKEY +dnssec | grep ' ad'   # 'ad' is back

# ============================================================================
# C3b. When someone else's DNSSEC breaks
# ============================================================================
# This is an INCIDENT-RESPONSE RUNBOOK, not a deploy action: it requires a live
# operator decision (which real zone is bogus) that does not exist at deploy
# time. Per CLAUDE.md hard rule 7, this script does not fabricate an automated
# substitute for that judgment call. Reproduced here for reference — run these
# BY HAND, substituting the real broken zone for $Z, when a user reports a
# specific name failing while everything else resolves:
#
#   Z=broken.example                       # the zone the user reported
#   dig @127.0.0.1 -p 5335 "$Z" A +dnssec +noall +comments   # our verdict + EDE code
#   dig @8.8.8.8 "$Z" A +noall +comments; dig @1.1.1.1 "$Z" A +noall +comments  # second opinion
#   delv @127.0.0.1 -p 5335 +rtrace "$Z" A                    # names the exact fault
#   unbound-control lookup "$Z"                               # which authoritatives
#
#   # Negative trust anchor, scoped to the broken zone's own apex, never a TLD:
#   unbound-control insecure_add "$Z"
#   unbound-control list_insecure
#   systemd-run --on-active=24h --unit=nta-expire-"${Z//./-}" \
#     /usr/bin/unbound-control insecure_remove "$Z"
#   systemctl list-timers 'nta-expire-*' --all
#
#   # Once the zone operator has fixed their zone:
#   unbound-control insecure_remove "$Z"
#   unbound-control list_insecure
#   unbound-control flush_zone "$Z"
#   unbound-control flush_bogus
#   unbound-control flush_negative
#   dig @127.0.0.1 -p 5335 "$Z" A +dnssec +noall +comments | grep '^;; flags:'   # ' ad'
#
# Do NOT persist this as `domain-insecure:` in the config file — that is a
# permanent, invisible validation downgrade. See phases/03-unbound-resolver.md
# C3b "Do not persist it in the config file" before ever adding one.
warn "C3b: negative-trust-anchor incident procedure is documented above as a comment block, NOT auto-executed — it requires identifying a real broken third-party zone at incident time."

# --- C3b: verify steady state, and run the dry-run drill against a deliberately-bogus test zone ---
info "C3b: verification (expected output noted inline)"
unbound-control list_insecure          # EMPTY on a healthy box - this is the steady state
grep -c 'domain-insecure' /etc/unbound/unbound.conf.d/*.conf || true   # 0

confirm "C3b: about to run the dry-run DNSSEC-break drill against dnssec-failed.org (adds+removes a negative trust anchor, flushes cache for that zone) — self-reversing, uses a public test zone designed for this, but touches live validator state"
dig @127.0.0.1 -p 5335 dnssec-failed.org A +noall +comments      # SERVFAIL
unbound-control insecure_add dnssec-failed.org
unbound-control flush_zone dnssec-failed.org; unbound-control flush_bogus
dig @127.0.0.1 -p 5335 dnssec-failed.org A +noall +comments      # NOERROR, no 'ad'
unbound-control insecure_remove dnssec-failed.org
unbound-control flush_zone dnssec-failed.org; unbound-control flush_bogus
dig @127.0.0.1 -p 5335 dnssec-failed.org A +noall +comments      # SERVFAIL again
unbound-control list_insecure                                    # empty
info "C3b: last SERVFAIL above is the point of the drill — it proves the NTA was removed and validation is back on."

# ============================================================================
# C4. Hardened systemd unit
# ============================================================================

# --- C4: hardening.conf drop-in (never a full unit replacement — package unit stays authoritative) ---
mkdir -p /etc/systemd/system/unbound.service.d
confirm "C4: about to write /etc/systemd/system/unbound.service.d/hardening.conf (sandboxing + canonical restart policy) and restart unbound"
backup_file /etc/systemd/system/unbound.service.d/hardening.conf
cat > /etc/systemd/system/unbound.service.d/hardening.conf <<'EOF'
# /etc/systemd/system/unbound.service.d/hardening.conf
[Unit]
# systemd's default is to give up permanently after 5 restarts in 10s. On a
# resolver that turns a transient crash into an outage that lasts until someone
# notices. Widen the window. These four values (with Restart/RestartSec below)
# are the CANONICAL restart policy for every daemon in this stack - Phase N adds
# nothing beyond them and must not contradict them.
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Restart=always
RestartSec=5
# Accounting ONLY - no ceiling here. MemoryHigh/MemoryMax for unbound belong to
# Phase A6; this line is what makes them measurable. See the C2 memory budget.
MemoryAccounting=yes

# --- filesystem ---
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
# ProtectSystem=strict makes /run read-only, but the shipped remote-control.conf
# puts the control socket at /run/unbound.ctl and the pidfile at /run/unbound.pid
# - both directly in /run, so a narrower RuntimeDirectory= does not cover them.
# If you want /run narrowed, move both with `control-interface:` and `pidfile:`
# first, then tighten this line.
ReadWritePaths=/var/lib/unbound /run
UMask=0077

# --- kernel / namespace ---
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes

# AF_UNIX is MANDATORY - it is the unbound-control socket, and without it every
# unbound-control command in this plan fails. AF_NETLINK is needed for interface
# enumeration.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@mount @obsolete @reboot @swap @module @raw-io
# EPERM instead of the default SIGSYS termination: during burn-in a missing
# syscall becomes a logged error rather than a mystery crash-loop. Remove this
# line once the service has run clean for a week.
SystemCallErrorNumber=EPERM
EOF

# --- C4: NOT applied by default — optional CapabilityBoundingSet= (source: "most likely to brick the service") ---
# Deliberately absent: no User= line (packaged unit starts as root, unbound
# drops privilege itself via `username: "unbound"` in C2 — the distro-supported
# path). Because of that, no aggressive CapabilityBoundingSet= and no
# ~@privileged syscall filter either — an empty bounding set prevents the
# CAP_SETUID/CAP_SETGID privilege drop the packaged unit relies on. If you want
# a bounding set anyway, add this line SEPARATELY from everything else above,
# restart, and check `journalctl -u unbound` for a setuid/setgid failure before
# doing anything else:
#   CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_RESOURCE
# NoNewPrivileges=yes is likewise deliberately NOT set here (Phase E sets it on
# AdGuardHome for different reasons); on this root-start-then-drop daemon it is
# redundant with the bounding set and adds another way to break the drop.

systemctl daemon-reload
systemctl restart unbound

# --- C4: verify ---
info "C4: verification (expected output noted inline)"
systemctl is-active unbound
systemd-analyze verify unbound.service || true            # no warnings
systemd-analyze security unbound.service | tail -20
# exposure labels: <1.0 OK, >=5.0 MEDIUM, >=7.5 EXPOSED, >=9.0 UNSAFE

ps -o pid,user,comm -C unbound                    # USER must be 'unbound', not root

unbound-control status >/dev/null && echo CONTROL-OK

ls -l /etc/systemd/system/unbound.service 2>/dev/null && warn 'C4: FAIL — a full unit replacement exists; it must NOT (drop-ins only)'
systemctl cat unbound | head -3                   # first line: /usr/lib/systemd/system/unbound.service
systemctl show unbound -p DropInPaths             # nofile.conf + hardening.conf, no ha.conf

systemctl show unbound -p Restart -p RestartSec -p StartLimitIntervalUSec -p StartLimitBurst
#   Restart=always  RestartSec=5s  StartLimitIntervalUSec=5min  StartLimitBurst=10

journalctl -u unbound -p warning --since '-10min' --no-pager || true

# ============================================================================
# C5. Verification (acceptance test for the resolver layer, against 127.0.0.1:5335)
# ============================================================================
# End-to-end validation through the public edge, off-box, is Phase H's job —
# not duplicated here.

# --- C5.1: recursion is real, not forwarding ---
info "C5.1: recursion is real, not forwarding"
grep -rn '^ *forward-zone:' /etc/unbound/ && echo 'FAIL: still forwarding' || echo 'RECURSIVE-OK'

timeout 25 tcpdump -ni any -c 40 'udp port 53 and not host 127.0.0.1' > /tmp/rec.txt 2>&1 &
sleep 1; dig @127.0.0.1 -p 5335 "$(date +%s).nlnetlabs.nl" A >/dev/null 2>&1; wait
awk '{print $5}' /tmp/rec.txt | cut -d. -f1-4 | sort -u | head
#   PASS: root-server addresses (198.41.0.4 etc), TLD and authoritative servers

# --- C5.2: DNSSEC positive and negative ---
info "C5.2: DNSSEC positive and negative"
unbound-control status | grep -E 'modules|version'   # modules: validator iterator

dig @127.0.0.1 -p 5335 sigfail.verteiltesysteme.net A +dnssec +noall +comments
#   status: SERVFAIL, and a '; EDE:' line naming the validation failure
dig @127.0.0.1 -p 5335 dnssec-failed.org A +noall +comments
#   status: SERVFAIL

dig @127.0.0.1 -p 5335 sigok.verteiltesysteme.net A +dnssec +noall +comments
#   status: NOERROR, and flags must contain 'ad'
dig @127.0.0.1 -p 5335 internetsociety.org A +dnssec | grep -E '^;; flags:|RRSIG' | head

dig @127.0.0.1 -p 5335 . DNSKEY +dnssec +noall +comments | grep '^;; flags:'   # ' ad'

unbound-control stats_noreset | grep -E 'num.answer.secure|num.answer.bogus|num.answer.rcode.SERVFAIL'

# --- C5.3: rebinding protection ---
info "C5.3: rebinding protection (config-level assertion is authoritative; this is a confirming probe)"
# rbndr encodes IPs as TWO hex labels: <hexA>.<hexB>.rbndr.us
#   7f000001 = 127.0.0.1   c0a80001 = 192.168.0.1
V=7f000001.c0a80001.rbndr.us
CTRL=$(dig @8.8.8.8 "$V" A +short +time=4 +tries=1 | tr '\n' ' ')
MINE=$(dig @127.0.0.1 -p 5335 "$V" A +short +time=4 +tries=1 | tr '\n' ' ')
echo "control(8.8.8.8)='$CTRL'  ours='$MINE'"
if [ -z "$CTRL" ]; then
  echo "INCONCLUSIVE: vector is down upstream - do not score this run"
elif [ -z "$MINE" ]; then
  echo "PASS: private address stripped"
else
  echo "FAIL: resolver returned $MINE for a public name"
fi

unbound-control get_option private-domain 2>/dev/null || \
  grep -n 'private-domain' /etc/unbound/unbound.conf.d/10-public-resolver.conf

dig @127.0.0.1 -p 5335 facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion A +noall +comments  # NXDOMAIN
dig @127.0.0.1 -p 5335 1.168.192.in-addr.arpa PTR +noall +comments   # NXDOMAIN, not a recursion
dig @127.0.0.1 -p 5335 localhost A +short                            # 127.0.0.1

# --- C5.4: QNAME minimisation is observable (no unbound counter exists — must observe on the wire) ---
info "C5.4: QNAME minimisation"
unbound-control get_option qname-minimisation           # yes
unbound-control get_option qname-minimisation-strict    # no

unbound-control flush_zone nlnetlabs.nl
timeout 20 tcpdump -ni any -s0 -c 20 'udp port 53 and not host 127.0.0.1' -v 2>&1 > /tmp/qmin.txt &
sleep 1; dig @127.0.0.1 -p 5335 "www.nlnetlabs.nl" A >/dev/null 2>&1; wait
grep -o '[A-Za-z0-9.-]*\? A?' /tmp/qmin.txt | sort -u
#   PASS: early queries ask for 'nl.' / 'nlnetlabs.nl.' - the full
#         'www.nlnetlabs.nl' must NOT appear in the first query of the chain.
#   If tcpdump does not render the question name, treat as INCONCLUSIVE.

# --- C5.5: aggressive NSEC, cache and prefetch ---
info "C5.5: aggressive NSEC, cache and prefetch"
unbound-control stats_noreset | grep -E 'num.query.aggressive.NOERROR|num.query.aggressive.NXDOMAIN'

unbound-control stats_noreset | grep -E 'total.num.queries|total.num.cachehits|total.num.cachemiss|total.num.prefetch'
#   total.num.prefetch rising is the proof that prefetch has replaced the
#   deleted Phase F warmer.

unbound-control flush_zone example.com
dig @127.0.0.1 -p 5335 example.com A +noall +stats | grep 'Query time'   # cold: tens-hundreds of ms
dig @127.0.0.1 -p 5335 example.com A +noall +stats | grep 'Query time'   # warm: ~0 ms

# --- C5.6: serve-stale behaves per RFC 8767 (stale must NOT be served while resolution is healthy) ---
info "C5.6: serve-stale RFC 8767 behaviour (Ubuntu's default awk is mawk — positional fields, not \\s)"
D=whoami.akamai.net
dig @127.0.0.1 -p 5335 $D A +noall +answer
TTL=$(dig @127.0.0.1 -p 5335 $D A +noall +answer | awk '{print $2; exit}')
echo "cached TTL=$TTL"; sleep $((TTL + 5))
SERVED=$(dig @127.0.0.1 -p 5335 $D A +noall +answer | awk '{print $2; exit}')
UPSTR=$(dig @1.1.1.1            $D A +noall +answer | awk '{print $2; exit}')
echo "served=$SERVED upstream=$UPSTR"
#   PASS: served is close to upstream - a genuine fresh resolution happened
#   FAIL: served == 30 - a stale record was handed out with a healthy upstream

unbound-control stats_noreset | grep -E 'num.expired'
#   must stay 0 while resolution is healthy; rises only during an incident

dig @127.0.0.1 -p 5335 $D A +dnssec +noall +comments +answer | grep -i 'EDE' || true
#   expect (only when stale IS served, e.g. after breaking egress): '; EDE: 3 (Stale Answer)'

dig @127.0.0.1 -p 5335 $D A +noall +stats | grep 'Query time'

# --- C5.7: isolation, and unbound-control basics ---
info "C5.7: isolation and unbound-control basics"
dig @127.0.0.1 -p 5335 google.com A +short          # must resolve
# dig @<PUBLIC_IP> -p 5335 google.com A +time=3 +tries=1   # must FAIL / time out — substitute this host's public IP by hand
nft list ruleset | grep 5335                        # Phase B rule still present

unbound-control status
unbound-control stats_noreset | head -30
unbound-control list_stubs | head                   # root hints loaded
unbound-control flush_zone example.com              # operational: flush one zone
unbound-control reload                              # re-read config without dropping cache

timeout 20 tcpdump -ni any -c 30 'udp dst port 53 and not host 127.0.0.1' 2>/dev/null \
  | sed -n 's/.*\.\([0-9]*\) > .*/\1/p' | sort -u | wc -l    # must be many distinct ports

# --- C5.8: flip /etc/resolv.conf to the validated path (the ONE action in C5, last on purpose) ---
info "C5.8: flipping /etc/resolv.conf off Phase A2's bootstrap value — last action of Phase C"
test -L /etc/resolv.conf && warn 'C5.8: FAIL — /etc/resolv.conf is a symlink again; something re-took the file, fix that before writing through it'

chattr -i /etc/resolv.conf 2>/dev/null || true

confirm "C5.8: about to overwrite /etc/resolv.conf with 'nameserver 127.0.0.1' — host DNS now depends on AdGuardHome (:53, Phase E) being up, which depends on Unbound (:5335). If Phase E has not run yet, the host has NO resolver until it does."
backup_file /etc/resolv.conf
printf 'nameserver 127.0.0.1\noptions edns0 trust-ad\n' > /etc/resolv.conf

grep -c '^nameserver' /etc/resolv.conf   # 1
lsattr /etc/resolv.conf                  # no 'i' - the file stays mutable on purpose (deliberately no chattr +i)

# ============================================================================
# End of Phase C
# ============================================================================
echo
echo "Phase C complete. This phase's own acceptance surface is C5.1-C5.8 (already run above)."
echo "Key spot checks: 'unbound-control status', 'dig @127.0.0.1 -p 5335 sigok.verteiltesysteme.net A +dnssec' (expect 'ad' flag),"
echo "'dig @127.0.0.1 -p 5335 dnssec-failed.org A' (expect SERVFAIL), and 'grep -c ^nameserver /etc/resolv.conf' (expect 1, value 127.0.0.1)."
echo "End-to-end / off-box / every-protocol verification is Phase H's job, not duplicated here."
echo "See phases/03-unbound-resolver.md C5 and C6 for the full acceptance surface and the recursion cost/mitigation discussion."
