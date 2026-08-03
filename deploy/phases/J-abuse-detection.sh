#!/usr/bin/env bash
# deploy/phases/J-abuse-detection.sh — Phase J: Abuse Detection and Response
# Source: phases/07-observability-and-abuse.md, "PHASE J: Abuse Detection and
# Response" section (J1-J10 only). Phase I (Observability, Alerting and SLOs)
# is on the same source page but is a separate script — skipped here entirely.
#
# Mechanical transcription — read the source section before running this.
#
# Phase J writes NO nftables configuration. Every table/chain/set it touches
# (table inet filter: banned_ips/6, banned_long/6, allowlist4/6, floodmeter4/6,
# dns_guard, counters dns_dropped/dns_banned) is a Phase B object; this script
# only reads them or adds/removes elements in the two ban sets, exactly as the
# source's J3 ownership table specifies. If a name here ever disagrees with
# Phase B, Phase B is right and this script is stale.
#
# J2 (the four nftables correctness constraints), J3 (object ownership table),
# and J9 (the spoofable-source trade-off) are pure rationale in the source —
# no commands to transcribe — and are kept here as comments for traceability.
# J7 (operator procedures) and J8 (spoofed-flood incident response) are
# runbook material a human invokes ad hoc during an incident, not deploy
# steps; they are preserved verbatim as "NOTE, informational, not scripted"
# comment blocks rather than auto-executed, matching this repo's existing
# convention (see B-firewall.sh B6/B7).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=../lib/common.sh
source ../lib/common.sh

require_root
require_cmd nft jq awk sed python3 systemctl logger dig timeout stat

phase_header "Phase J — kernel-side abuse detection"

# =====================================================================
# J1. Why the v1 query-log cron is deleted outright
# =====================================================================
# anonymize_client_ip masks the source at ingestion (/16 v4, /48 v6), not at
# display, so the v1 query-log-tailing cron banned the wrong (network)
# address as a /32 while the real abuser kept querying. And if querylog is
# relocated (Phase E dir_path) or disabled (Phase Q zero-log posture), the v1
# script's `[ -f "$LOG" ] || exit 0` guard exits 0 forever: an abuse system
# that reports success while doing nothing. Detection therefore moves to the
# kernel, where the real source address is, regardless of every privacy
# decision Phase Q makes.

info "J1: removing the v1 query-log-based abuse-check.sh"
# --- J1: delete v1 abuse-check.sh ---
rm -f /opt/dns-warmer/abuse-check.sh

# --- J1: delete its stale line from Phase I's cron file (never rewrite it) ---
if [ -f /etc/cron.d/dns-health ]; then
    backup_file /etc/cron.d/dns-health
    confirm "J1: about to remove the stale 'abuse-check.sh' line from /etc/cron.d/dns-health (Phase I's file — this deletes one line only, never rewrites the file). Continue?"
    sed -i '/abuse-check\.sh/d' /etc/cron.d/dns-health
else
    warn "J1: /etc/cron.d/dns-health does not exist yet (Phase I has not run). Nothing to clean there now; if a stale abuse-check.sh line ever reappears after Phase I runs, remove it by hand with: sed -i '/abuse-check\\.sh/d' /etc/cron.d/dns-health"
fi

# --- J1: Phase F (retired v1 cache warmer) directory teardown ---
# /opt/dns-warmer/ was the v1 cache warmer's directory. Phase F is retired
# (Unbound's prefetch/prefetch-key does that work in-process — see Phase C),
# so remove the directory entirely once Phase F's own teardown has run.
if [ -d /opt/dns-warmer ]; then
    confirm "J1: about to remove /opt/dns-warmer/ entirely (rm -rf) — the retired v1 cache-warmer directory, superseded by Unbound's prefetch in Phase C. Continue?"
    rm -rf /opt/dns-warmer
else
    info "J1: /opt/dns-warmer already absent — nothing further to remove"
fi

# =====================================================================
# J2. The four correctness constraints the naive ruleset violates
# =====================================================================
# Phase B's ruleset, not this script, must satisfy all four. Restated here
# only so this script's dependency on Phase B's structure is explicit:
#   1. `add @set` cannot cross tables — the chain that bans and the sets it
#      bans into must be in one table (table inet filter).
#   2. A flood chain that runs before `input` bans loopback — dns_guard MUST
#      be a regular chain jumped from `chain input` below `iif lo accept`,
#      never a base chain at hook input priority -1.
#   3. A rate expression gates the RULE, not the dynset — the ban clause must
#      be a second chained dynset statement, never a standalone
#      `update @floodmeter... limit rate over ...` used alone (that bans
#      every source seen, immediately).
#   4. `update` refreshes the timeout; `add` does not — meters use `update`,
#      ban sets use `add` (re-arming a ban on every packet of an ongoing
#      flood would extend it indefinitely; J4 below handles repeat offenders
#      deliberately instead).
# J10 (this script's verification section, below) checks structurally that
# Phase B's ruleset satisfies all four.

# =====================================================================
# J3. The objects this phase depends on, and who owns them
# =====================================================================
# Phase B is the sole author of /etc/nftables.conf: table inet raw (NOTRACK
# only — the only hook where notrack is legal) and table inet filter (every
# policy object). Exactly one chain hooks input: `chain input`, priority 0.
# dns_guard is a regular chain jumped from it, not a base chain.
#
#   Object                      Kind                          What Phase J does with it
#   banned_ips / banned_ips6    dynamic timeout set, 10m       first-offence bans, written by dns_guard in-kernel; read by J4/J6/J7
#   banned_long / banned_long6  timeout set, 24h (Phase B)     repeat-offender bans, written ONLY by J4's escalator + J7 manual bans
#   allowlist4 / allowlist6     interval sets                  bypass flood detection AND banning entirely; 127.0.0.0/8 and ::1 ship by default
#   floodmeter4 / floodmeter6   dynamic timeout sets            per-source flood detection at 400/s
#   dns_guard                   regular chain, jumped from input  edited under pressure in J8 to fall back to drop-only
#   dns_dropped / dns_banned    counters                        the two numbers J6 exports and J7 reads
#
# banned_long/banned_long6 are Phase B objects (declared + drop rules), but
# Phase J owns only the escalation logic (J4) that populates them.

# =====================================================================
# J4. Expiry and escalation
# =====================================================================
# nft-ban-escalate promotes anything banned 3+ times within 24h from
# banned_ips/6 (10m) into banned_long/6 (24h). Runs entirely in userspace,
# where set references are not table-scoped (J2 constraint 1 does not apply
# to it) — but every set it names is still a Phase B object in table inet
# filter, named explicitly below rather than assumed.

info "J4: installing /usr/local/sbin/nft-ban-escalate (10m -> 24h escalation)"
# --- J4: nft-ban-escalate ---
backup_file /usr/local/sbin/nft-ban-escalate
cat > /usr/local/sbin/nft-ban-escalate <<'EOF'
#!/bin/bash
# Promote repeat offenders from the 10m ban set into the 24h ban set.
# Runs from a timer; reads only kernel state, never the query log.
set -u
STATE=/var/lib/dns-abuse/offences
THRESH=3
mkdir -p "$(dirname "$STATE")"; touch "$STATE"; chmod 0600 "$STATE"
NOW=$(date +%s); CUT=$((NOW - 86400))

elems() {   # elems <set>
  nft -j list set inet filter "$1" 2>/dev/null \
    | jq -r '.nftables[]?.set.elem[]? | if type=="object" then .elem.val else . end'
}

for SET in banned_ips banned_ips6; do
  case $SET in banned_ips) LONG=banned_long ;; *) LONG=banned_long6 ;; esac
  while read -r IP; do
    [ -n "$IP" ] || continue
    printf '%s %s\n' "$NOW" "$IP" >> "$STATE"
    N=$(awk -v c="$CUT" -v ip="$IP" '$1 >= c && $2 == ip' "$STATE" | wc -l)
    if [ "$N" -ge "$THRESH" ]; then
      nft add element inet filter "$LONG" "{ $IP timeout 24h }" 2>/dev/null \
        && logger -t dns-abuse "Escalated $IP to $LONG for 24h (${N} offences/24h)"
    fi
  done < <(elems "$SET")
done

# Trim the state file to the last 24h so it cannot grow without bound.
awk -v c="$CUT" '$1 >= c' "$STATE" > "${STATE}.tmp" && mv "${STATE}.tmp" "$STATE"
chmod 0600 "$STATE"
EOF
chmod 0755 /usr/local/sbin/nft-ban-escalate

info "J4: installing nft-ban-escalate.service / .timer (not enabled yet — enabled together with J6's timer below)"
# --- J4: nft-ban-escalate.service ---
backup_file /etc/systemd/system/nft-ban-escalate.service
cat > /etc/systemd/system/nft-ban-escalate.service <<'EOF'
[Unit]
Description=Promote repeat DNS abusers to the long ban set
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nft-ban-escalate
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/dns-abuse
EOF

# --- J4: nft-ban-escalate.timer ---
backup_file /etc/systemd/system/nft-ban-escalate.timer
cat > /etc/systemd/system/nft-ban-escalate.timer <<'EOF'
[Unit]
Description=Check for repeat DNS abusers every 5 minutes
[Timer]
OnBootSec=5m
OnUnitActiveSec=5m
AccuracySec=30s
[Install]
WantedBy=timers.target
EOF

# The offence file is personal data with a purpose (abuse mitigation) and a
# lifetime (24h, enforced by the trim in the script above). It is
# deliberately NOT in Phase K's restic include list, and must stay out of the
# config-staging git tree too:
info "J4: excluding the escalator's offence log from /opt/dns-config-backup's git tree"
if [ -d /opt/dns-config-backup ]; then
    grep -qx 'offences' /opt/dns-config-backup/.gitignore 2>/dev/null \
        || printf 'offences\n' >> /opt/dns-config-backup/.gitignore
else
    warn "J4: /opt/dns-config-backup does not exist yet (Phase A3 has not run) — cannot append 'offences' to its .gitignore yet. Re-run after Phase A3: printf 'offences\\n' >> /opt/dns-config-backup/.gitignore — J10 verification step 11 depends on this."
fi

# =====================================================================
# J5. Allowlist, and ban state across a reload
# =====================================================================
# Phase B owns /usr/local/sbin/nft-apply, the ONLY supported reload wrapper:
# it captures remaining ban timeouts before `flush ruleset` and replays them
# with time left, not a fresh full duration. This phase adds no second
# wrapper. The only supported reload procedure is:
#   /usr/local/sbin/nft-apply
#   /usr/local/sbin/dns-health
# Never run a bare `nft -f /etc/nftables.conf` on a live resolver — it is the
# one command that drops every active ban and every meter without telling
# you it did.

info "J5: reviewing current ban-set membership (read-only)"
# --- J5: review ban state ---
for S in banned_ips banned_ips6 banned_long banned_long6; do
    echo "== $S"
    nft list set inet filter "$S" 2>/dev/null | sed -n '/elements/,$p'
done

# NOTE (J5, informational, not scripted): ad-hoc allowlist edits.
#   Temporary (gone at the next nft-apply, because it is not in the file):
#     nft add element inet filter allowlist4 '{ 203.0.113.0/24 }'
#   Permanent: add it to the `elements = { ... }` list of allowlist4 in
#   /etc/nftables.d/dns-allow.nft (Phase B's file), then reload with
#   /usr/local/sbin/nft-apply.
# Phase P defines a separate *access* allowlist (who may query at all) using
# its own named sets and must not reuse allowlist4/allowlist6 — those mean
# only "bypasses flood detection and banning", not "is allowed to query".

# =====================================================================
# J6. Exporting abuse state to Phase I
# =====================================================================
# Phase I alerts on nft_dns_banned_packets and nft_banned_ips_elements. This
# exporter produces them, reading only Phase B's counters/sets.

info "J6: installing /usr/local/sbin/nft-abuse-textfile"
# --- J6: nft-abuse-textfile ---
backup_file /usr/local/sbin/nft-abuse-textfile
cat > /usr/local/sbin/nft-abuse-textfile <<'EOF'
#!/bin/bash
# nftables abuse counters -> node_exporter textfile.
set -u
OUT=/var/lib/node_exporter/textfile/nft-abuse.prom
TMP="${OUT}.tmp"
ctr() { nft -j list counter inet filter "$1" 2>/dev/null \
  | jq -r '.nftables[]?.counter.packets // 0' | head -1; }
cnt() { nft -j list set inet filter "$1" 2>/dev/null \
  | jq -r '[.nftables[]?.set.elem[]?] | length'; }
{
  echo '# TYPE nft_dns_dropped_packets counter'
  echo "nft_dns_dropped_packets $(ctr dns_dropped)"
  echo '# TYPE nft_dns_banned_packets counter'
  echo "nft_dns_banned_packets $(ctr dns_banned)"
  echo '# TYPE nft_banned_ips_elements gauge'
  for S in banned_ips banned_ips6 banned_long banned_long6; do
    printf 'nft_banned_ips_elements{set="%s"} %s\n' "$S" "$(cnt "$S")"
  done
} > "$TMP"
chmod 0644 "$TMP"; mv "$TMP" "$OUT"
EOF
chmod 0755 /usr/local/sbin/nft-abuse-textfile

info "J6: installing nft-abuse-textfile.service / .timer"
# --- J6: nft-abuse-textfile.service ---
backup_file /etc/systemd/system/nft-abuse-textfile.service
cat > /etc/systemd/system/nft-abuse-textfile.service <<'EOF'
[Unit]
Description=nftables abuse counters to node_exporter textfile
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nft-abuse-textfile
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/node_exporter/textfile
EOF

# --- J6: nft-abuse-textfile.timer ---
backup_file /etc/systemd/system/nft-abuse-textfile.timer
cat > /etc/systemd/system/nft-abuse-textfile.timer <<'EOF'
[Unit]
Description=Export nftables abuse counters every 30s
[Timer]
OnBootSec=60s
OnUnitActiveSec=30s
AccuracySec=5s
[Install]
WantedBy=timers.target
EOF

# --- J6/J4: enable both Phase J timers together (as the source does) ---
confirm "J6: about to daemon-reload and enable+start nft-abuse-textfile.timer and nft-ban-escalate.timer — two persistent boot-time timers that run as root, one of which (nft-ban-escalate) adds elements to the live banned_long/banned_long6 sets. Continue?"
systemctl daemon-reload
systemctl enable --now nft-abuse-textfile.timer nft-ban-escalate.timer

info "J6: nft_dns_dropped_packets resets to zero on every ruleset reload (flush ruleset recreates counters). rate() handles this correctly; increase() over a window containing a reload under-reports. Do not read a post-reload dip as a fix."

warn "MANUAL STEP (J6): update the Phase L go-live checklist line 'Abuse auto-ban: active' to reference 'nft list counter inet filter dns_banned' and nft_banned_ips_elements instead of the deleted cron job. This is a documentation edit in dns-server-plan.md / phases/*.md, outside what this deploy script performs. Not scripted here."

# =====================================================================
# J7. Operator procedures (runbook — informational, NOT executed by this
# script; invoke these by hand, as needed)
# =====================================================================
#
# Review what is currently banned:
#   for S in banned_ips banned_ips6 banned_long banned_long6; do
#     echo "== $S"; nft list set inet filter "$S" 2>/dev/null | sed -n '/elements/,$p'
#   done
#   nft list counter inet filter dns_banned     # times the auto-ban has fired
#   nft list counter inet filter dns_dropped    # packets dropped by ban + rate limit
#   journalctl -t dns-abuse --since '-24h'      # escalation decisions
#
# Ban an address by hand (use the long set for a deliberate human decision;
# the short set is the automation's):
#   nft add element inet filter banned_long  '{ 203.0.113.42 timeout 24h }'
#   nft add element inet filter banned_long6 '{ 2001:db8::42 timeout 24h }'
#   logger -t dns-abuse "Manual ban 203.0.113.42 24h: <reason, ticket ref>"
# Always log the reason — in three weeks the logger line is the only record
# of why an address is blocked.
#
# Unban:
#   nft delete element inet filter banned_ips  '{ 203.0.113.42 }'
#   nft delete element inet filter banned_long '{ 203.0.113.42 }'
#   # The offence history is what re-escalates it in five minutes. Clear it:
#   sed -i '/ 203\.0\.113\.42$/d' /var/lib/dns-abuse/offences
#   logger -t dns-abuse "Manual unban 203.0.113.42: <reason>"
#
# False positive — a legitimate client is being banned (symptom: a user
# reporting intermittent total DNS failure in ~10-minute blocks, correlated
# with nft_dns_banned_packets increasing):
#   1. Confirm it is actually them:
#        nft list set inet filter banned_ips | grep <their-ip>
#      Do NOT go looking in the query log; it holds a /16-masked address and
#      cannot answer this question (J1).
#   2. Unban as above.
#   3. Decide whether they are genuinely over 400 QPS sustained (a single
#      household behind CGNAT, or a corporate NAT egress, legitimately can
#      be). If so, add them permanently to allowlist4 in
#      /etc/nftables.d/dns-allow.nft (Phase B's file) and reload with
#      nft-apply. dns_guard returns early for allowlist members, exempting
#      them from flood detection AND banning entirely, for every rate —
#      accept that consciously.
#   4. If several unrelated clients are being banned in the same window, the
#      threshold is wrong for your traffic, not the clients — raise Phase
#      B's flood threshold above 400/second before adding a dozen
#      exemptions; a large allowlist is a larger hole than a slightly higher
#      threshold.
#   5. If the "client" is a spoofed source, no exemption helps and unbanning
#      is temporary — go to J8, below.
#
# A single address is being banned repeatedly and it is not yours: that is
# the system working. Let escalation take it to 24 hours. If it persists
# past that, the response is an abuse report to the network's contact
# (Phase Q's process), not this phase's.

# =====================================================================
# J8. Sustained spoofed-source flood (incident runbook — informational, NOT
# executed by this script)
# =====================================================================
#
# Symptom: dns:qps:rate5m far above normal, nft_banned_ips_elements climbing
# into the hundreds, banned addresses are unrelated networks worldwide, and
# legitimate users are being caught — you are being used as a reflector and
# the ban set is being steered at innocent third parties, potentially
# including your own users.
#
#   1. Stop the escalation from compounding the damage (24h bans on forged
#      addresses are worse than the flood):
#        systemctl stop nft-ban-escalate.timer
#   2. Confirm it is spoofed rather than a real botnet: a source distribution
#      with no correlation to your actual client base, usually a uniform
#      query name/type.
#        tcpdump -ni any -c 200 udp port 53 and 'udp[10] & 0x80 = 0'
#      Keep the capture short and delete it — raw client data under Phase Q.
#   3. Fall back to drop-only. In /etc/nftables.conf (Phase B's file), remove
#      the `add @banned_ips { ... }` / `add @banned_ips6 { ... }` CLAUSE from
#      each of the two flood rules inside dns_guard, keeping the
#      floodmeter4/floodmeter6 meter, the counter, and the drop on the same
#      line — do NOT comment the whole line out, that removes the
#      enforcement you are trying to keep. Then:
#        /usr/local/sbin/nft-apply
#      Write both rules quoted in full, before and after, into the runbook
#      from Phase B's current ruleset before doing this under pressure.
#   4. Tighten the packet layer, not the ban layer — Phase B owns the ingress
#      per-IP limits, the egress response-rate limit protecting the
#      third-party victim, refuse_any, and the NOTRACK rule. Re-read Phase B.
#   5. Shed load if the box is saturating — Phase N covers multi-node and
#      traffic-shedding options, including taking plain UDP/53 out of
#      service. That is a product decision with real user impact; Phase N
#      states the trade.
#   6. You cannot stop the spoofing — you are the reflector, not the origin.
#      BCP38 is somebody else's network's job. Everything above caps the
#      damage; nothing eliminates it.
#   7. Notify: provider abuse desk if traffic volume threatens your instance;
#      upstream network contacts for reflected-at victims if they contact
#      you. Contact addresses, security.txt, and the complaint workflow are
#      Phase Q's; this phase owns only the technical response.

# =====================================================================
# J9. The trade you are accepting
# =====================================================================
# UDP/53 source addresses are forgeable — the premise of the reflection
# attack this phase defends against, and it applies to the defence too. An
# attacker sustaining a little over 400 pps from a forged source can put ANY
# address of their choosing into banned_ips, including your own users or a
# large upstream recursive resolver. A drop-only rate limit has bounded harm;
# a ban does not. This is why the first offence bans for 10 minutes (not an
# hour), why escalation caps at 24 hours with no permanent tier, why
# allowlist4/allowlist6 exist and must be populated with known-good
# high-volume clients, and why J8 step 3 is a documented, rehearsed fallback
# rather than an emergency improvisation.
#
# Supported alternative if this trade is unacceptable: keep dns_guard exactly
# as Phase B ships it, but delete only the `add @banned_ips { ... }` /
# `add @banned_ips6 { ... }` clause from each of its two flood rules (the
# clause, not the line — it also carries the meter, the counter and the
# drop). You lose repeat-offender suppression and keep everything else.
# Record whichever choice you made, and the date, in the Phase O decision
# log — the next operator cannot infer it from the ruleset alone.
warn "DECISION POINT (J9): record in the Phase O decision log whether this host runs with banning enabled (default, this script's install) or with the ban clause removed (drop-only alternative) — the next operator cannot infer this from the ruleset alone. Not recorded automatically by this script."

# =====================================================================
# J10. Phase J verification
# =====================================================================
phase_header "Phase J verification (J10)"

info "J10.1: syntax-check the live ruleset before touching anything"
# --- J10 step 1 ---
nft -c -f /etc/nftables.conf && echo "OK: ruleset parses"

info "J10.2: reload through the ONE supported wrapper and confirm loopback exemption"
# --- J10 step 2 ---
confirm "J10 step 2: about to run /usr/local/sbin/nft-apply, reloading the live nftables ruleset (Phase B's wrapper — captures and replays remaining ban timeouts). Continue?"
/usr/local/sbin/nft-apply
nft -a list chain inet filter dns_guard | head -6   # EXPECTED: 'iif lo accept' is the FIRST rule

info "J10.3: regression test for the localhost-ban bug (a local flood must NOT put 127.0.0.1 into the ban set)"
# --- J10 step 3 ---
confirm "J10 step 3: about to send a 4-second UDP flood to 127.0.0.1:53 from this box as a regression test for the localhost-ban bug. This briefly loads the live resolver. Continue?"
timeout 5 python3 -c "
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); t=time.time()
while time.time()-t<4: s.sendto(b'\x00'*40,('127.0.0.1',53))"
nft list set inet filter banned_ips | grep -q '127\.' \
  && echo "FAIL: localhost banned - dns_guard is missing 'iif lo accept'" \
  || echo "OK: loopback exempt"
dig @127.0.0.1 example.com A +time=2 +tries=1 >/dev/null && echo "OK: local DNS still works"

info "J10.4: structure — two tables, exactly one input-hook chain, dns_guard is a regular chain"
# --- J10 step 4 ---
nft list ruleset | grep -c '^table'        # EXPECTED: 2 (inet raw + inet filter)
nft list ruleset | grep -E '^table'        # EXPECTED names: `inet raw`, `inet filter`
nft list ruleset | grep -E 'type filter hook input priority'
# EXPECTED: exactly ONE line — `chain input` at priority 0. A second
# input-hook chain means the v1 layout crept back in.
nft list chain inet filter dns_guard | grep -q 'type filter hook' \
  && echo "FAIL: dns_guard is a base chain -- see Phase B" \
  || echo "OK: dns_guard is a regular chain, not a base chain"
nft list chain inet filter input | grep -q 'jump dns_guard' \
  && echo "OK: input jumps to dns_guard" \
  || echo "FAIL: dns_guard is never entered -- the jump is missing from input"
for S in banned_ips banned_ips6 banned_long banned_long6 \
         allowlist4 allowlist6 floodmeter4 floodmeter6; do
  nft list set inet filter "$S" >/dev/null 2>&1 \
    && echo "OK: $S in table inet filter" || echo "FAIL: $S missing -- see Phase B"
done

info "J10.4b: every ban set is actually READ by a drop rule"
# --- J10 step 4b ---
for S in banned_ips banned_ips6 banned_long banned_long6; do
  nft list chain inet filter input | grep -q "@$S" \
    && echo "OK: chain input drops on @$S" \
    || echo "FAIL: nothing reads @$S -- see Phase B"
done

info "J10.4c: allowlisted sources bypass dns_guard entirely; loopback ships by default"
# --- J10 step 4c ---
nft list chain inet filter dns_guard | grep -E '@allowlist4|@allowlist6' \
  || echo "FAIL: dns_guard does not consult the allowlist -- see Phase B"
nft list set inet filter allowlist4 | grep -q '127\.0\.0\.0/8' \
  && echo "OK: 127.0.0.0/8 in allowlist4" || echo "FAIL: loopback missing from allowlist4"
nft list set inet filter allowlist6 | grep -q '::1' \
  && echo "OK: ::1 in allowlist6" || echo "FAIL: ::1 missing from allowlist6"

warn "MANUAL STEP (J10 step 5): auto-ban-fires-for-a-real-remote-source requires running 'dnsperf -s <PUBLIC_IP> -d /tmp/queries.txt -l 20 -Q 2000' FROM A SECOND HOST, then checking 'nft list set inet filter banned_ips' and 'nft list counter inet filter dns_banned' (packets must be > 0) on this server. Not scripted here — needs an off-box host."

info "J10.6: prove ban expiry is live and shrinking, without waiting for the full timeout"
# --- J10 step 6 ---
nft list set inet filter banned_ips | grep -o 'expires [0-9a-z]*' || true
sleep 30
nft list set inet filter banned_ips | grep -o 'expires [0-9a-z]*' || true   # EXPECTED: ~30s lower than above (if any elements present)

info "J10.7: ban state survives a reload WITH its remaining time, not a fresh one"
# --- J10 step 7 ---
confirm "J10 step 7: about to add a test element to the live banned_long set, sleep 60s, reload with nft-apply, and verify it survived with its remaining timeout, then delete it. Continue?"
nft add element inet filter banned_long '{ 198.51.100.7 timeout 24h }'
sleep 60
nft list set inet filter banned_long | grep -o 'expires [0-9a-z]*'   # EXPECTED: ~23h59m
/usr/local/sbin/nft-apply
nft list set inet filter banned_long | grep -q '198\.51\.100\.7' \
  && echo "OK: ban survived reload" || echo "FAIL: reload wiped ban state"
nft list set inet filter banned_long | grep -o 'expires [0-9a-z]*'
# EXPECTED: the countdown is roughly where it was. If it reset to 24h,
# nft-apply is replaying with a fresh timeout instead of the remaining one --
# see Phase B.
nft delete element inet filter banned_long '{ 198.51.100.7 }'

info "J10.7b: exactly ONE reload wrapper exists"
# --- J10 step 7b ---
test ! -e /usr/local/sbin/nft-bans && echo "OK: no second reload wrapper" \
  || echo "FAIL: nft-bans is back -- delete it, nft-apply is the only wrapper"

info "J10.8: escalation promotes only after the threshold, and trims its own state"
# --- J10 step 8 ---
/usr/local/sbin/nft-ban-escalate
journalctl -t dns-abuse --since '-5 min'
wc -l /var/lib/dns-abuse/offences
stat -c '%a %U' /var/lib/dns-abuse/offences     # EXPECTED: 600 root

info "J10.9: metrics reach Prometheus for the Phase I alerts"
# --- J10 step 9 ---
/usr/local/sbin/nft-abuse-textfile
promtool check metrics < /var/lib/node_exporter/textfile/nft-abuse.prom 2>/dev/null \
  || warn "J10 step 9: promtool not on PATH (Phase I installs it) -- textfile was still written, check it by hand: /var/lib/node_exporter/textfile/nft-abuse.prom"
curl -sf 127.0.0.1:9100/metrics 2>/dev/null | grep -E '^nft_(dns_banned_packets|banned_ips_elements)' \
  || warn "J10 step 9: node_exporter not reachable on 127.0.0.1:9100 yet (Phase I) -- re-run this check once Phase I is up"

info "J10.10: the query-log-dependent machinery is gone and stays gone"
# --- J10 step 10 ---
test ! -e /opt/dns-warmer/abuse-check.sh \
  && ! grep -qr abuse-check /etc/cron.d/ 2>/dev/null \
  && echo "OK: query-log-dependent abuse cron removed"
grep -rn 'querylog' /usr/local/sbin/nft-* /usr/local/sbin/dns-health 2>/dev/null \
  && echo "FAIL: abuse tooling still references the query log" \
  || echo "OK: no abuse tooling reads the query log"

info "J10.11: secrets and abuse state are excluded from the Phase K backup"
# --- J10 step 11 ---
grep -qx 'offences' /opt/dns-config-backup/.gitignore 2>/dev/null && echo "OK: offences ignored" \
  || echo "FAIL: 'offences' missing from /opt/dns-config-backup/.gitignore -- see J4 above"

echo
echo "Phase J done. To re-check this phase at any time, re-run the J10 block above, or by hand:"
echo "  nft -c -f /etc/nftables.conf"
echo "  nft list counter inet filter dns_banned; nft list counter inet filter dns_dropped"
echo "  for S in banned_ips banned_ips6 banned_long banned_long6; do nft list set inet filter \"\$S\"; done"
echo "  /usr/local/sbin/dns-health   # overall operator health summary (Phase I)"
