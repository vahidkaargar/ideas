#!/usr/bin/env bash
# deploy/phases/Q-privacy-compliance.sh — Phase Q: Privacy Posture, Retention
# and Compliance
# Source: phases/10-privacy-and-compliance.md, sections Q1-Q7.
#
# Mechanical transcription — read the source section before running this.
# Phase Q is the second headline deliverable of the plan and unlike most of
# it, it produces DOCUMENTS as well as configuration: the configuration is
# worthless the moment a future operator changes it without knowing why it
# was set. Run this only after Phase E (AdGuardHome) is live.
#
# This script does not choose your logging posture, your journald storage
# mode, your disk-encryption stance, or your legal answers for you — those
# are operator decisions with a source-documented menu of options, gated
# below with fatal() so nothing is silently defaulted into.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=../lib/common.sh
source ../lib/common.sh

require_root
require_cmd systemctl journalctl grep awk sed install git curl dig date findmnt stat python3 nginx

phase_header "Phase Q — privacy posture, retention and compliance"

# =====================================================================
# Operator decisions — fatal-gated. Set these as environment variables
# before running this script, e.g.:
#   KEYSTONE_Q_LOGGING_POSTURE=C KEYSTONE_Q_JOURNALD_STORAGE=persistent \
#   KEYSTONE_Q_DISK_ENCRYPTION=none KEYSTONE_Q_SECURITYTXT_EXPIRES=2027-08-01T00:00:00.000Z \
#   deploy/phases/Q-privacy-compliance.sh
# =====================================================================

# --- Logging posture (Q1). Options, verbatim from the Q1 comparison table: ---
#   A = zero logging            (querylog.enabled=false, statistics.enabled=false)
#   B = aggregate statistics only (querylog.enabled=false, statistics.enabled=true)
#   C = shipped default          (querylog.enabled=true,  statistics.enabled=true) — what Phase E already deployed
# "If you read this section and do nothing, you are running Posture C at a
# 6 h ring — that is a choice too" (Q1). There is no silent default here:
# say so explicitly with C.
KEYSTONE_Q_LOGGING_POSTURE="${KEYSTONE_Q_LOGGING_POSTURE:-}"
case "$KEYSTONE_Q_LOGGING_POSTURE" in
    A|B|C) ;;
    *) fatal "KEYSTONE_Q_LOGGING_POSTURE must be set to A, B, or C (see Q1 table in phases/10-privacy-and-compliance.md). Got: '${KEYSTONE_Q_LOGGING_POSTURE}'" ;;
esac

# --- journald storage (Q3). Options, verbatim from the Q3 "journald: volatile
# or not" subsection: ---
#   persistent = keep sshd/auth forensics and Phase I history (the source's stated
#                recommendation for most operators; this is already what Phase G
#                configured in 10-dns.conf — Storage=persistent)
#   volatile   = no durable connection record survives a reboot; writes
#                /etc/systemd/journald.conf.d/10-volatile.conf, which overrides
#                Phase G's setting for the Journal section
# DNS query content never reaches the journal either way — this is not a
# query-privacy control, it is about connection-activity durability.
KEYSTONE_Q_JOURNALD_STORAGE="${KEYSTONE_Q_JOURNALD_STORAGE:-}"
case "$KEYSTONE_Q_JOURNALD_STORAGE" in
    persistent|volatile) ;;
    *) fatal "KEYSTONE_Q_JOURNALD_STORAGE must be set to persistent or volatile (see Q3 'journald: volatile or not' in phases/10-privacy-and-compliance.md). Got: '${KEYSTONE_Q_JOURNALD_STORAGE}'" ;;
esac

# --- Disk encryption (Q3). Options, verbatim from the Q3 "Encryption,
# honestly" subsection: ---
#   luks = LUKS on the data volume, unlocked at boot over SSH via dropbear-initramfs
#          (raises the bar against offline disk imaging / a stolen drive; does
#          NOTHING against a live hypervisor or a provider console session)
#   none = skip it — the source's own recommendation when disk imaging is not in
#          your threat model: "a half-implemented encryption story ... is worse
#          than an honest unencrypted one plus rigorous minimisation"
# This script performs NO automated LUKS setup: the source gives no exact
# commands for it, only the tradeoff. This variable exists to force the
# decision to be made and recorded, not to trigger automation.
KEYSTONE_Q_DISK_ENCRYPTION="${KEYSTONE_Q_DISK_ENCRYPTION:-}"
case "$KEYSTONE_Q_DISK_ENCRYPTION" in
    luks|none) ;;
    *) fatal "KEYSTONE_Q_DISK_ENCRYPTION must be set to luks or none (see Q3 'Encryption, honestly' in phases/10-privacy-and-compliance.md). Got: '${KEYSTONE_Q_DISK_ENCRYPTION}'" ;;
esac

# --- security.txt Expires (Q5c). RFC 9116 requires exactly one Expires field,
# RFC 3339 format, "recommended under one year out". An expired security.txt
# "is worse than none — it signals an abandoned service" (Q5c). No default:
# an unconsidered expiry date is exactly the kind of drift the monthly
# check-securitytxt-expiry cron job exists to catch, but only if the first
# date was chosen deliberately.
KEYSTONE_Q_SECURITYTXT_EXPIRES="${KEYSTONE_Q_SECURITYTXT_EXPIRES:-}"
[[ -n "$KEYSTONE_Q_SECURITYTXT_EXPIRES" ]] || fatal "KEYSTONE_Q_SECURITYTXT_EXPIRES must be set to an RFC 3339 timestamp under one year out (see Q5c in phases/10-privacy-and-compliance.md), e.g. 2027-08-01T00:00:00.000Z"
date -d "$KEYSTONE_Q_SECURITYTXT_EXPIRES" >/dev/null 2>&1 || fatal "KEYSTONE_Q_SECURITYTXT_EXPIRES='$KEYSTONE_Q_SECURITYTXT_EXPIRES' does not parse as a date"

# =====================================================================
# Boilerplate substitution variables — plain placeholders, same convention
# as DOMAIN/APEX/EMAIL in deploy/phases/D-tls-certificates.sh. Edit these in
# place before running; they are not GDPR/retention-posture decisions, they
# are the deployment's own facts (hostname, contact addresses, controller
# identity). The source's own templates use "example.com" and "<name>" —
# these variables are how this script avoids shipping those literally.
# =====================================================================
DOMAIN="dns.example.com"
APEX="example.com"
ABUSE_EMAIL="abuse@example.com"
SECURITY_EMAIL="security@example.com"
POLICY_URL="https://example.com/dns-privacy"
ACKNOWLEDGMENTS_URL="https://example.com/security-thanks"
CONTROLLER_NAME="<legal name / individual>"
CONTROLLER_ADDRESS="<postal address>"
CONTROLLER_CONTACT="<contact email>"
JURISDICTION="<jurisdiction>"
PUBLIC_IP=""   # set before running Q4's forward/reverse DNS check

AGH_YAML=/opt/adguardhome/conf/AdGuardHome.yaml
RETENTION_MD=/opt/dns-config-backup/RETENTION.md
PRIVACY_NOTICE_MD=/opt/dns-config-backup/PRIVACY-NOTICE.md
DOH_CONF=/etc/nginx/conf.d/doh.conf

# =====================================================================
# Q1. Choose a logging posture
# =====================================================================
# "Phase E ships a working default, and it is not the zero-log posture."
# Everything here is a menu of opt-in DEVIATIONS from Posture C, which is
# already in place. Applying Posture A "overwrites values Phase E
# deliberately shipped" — treat it as a considered change, not part of
# initial deployment.

if [[ ! -f "$AGH_YAML" ]]; then
    warn "Q1: $AGH_YAML not found — Phase E has not run yet. Q1 requires AdGuardHome to be deployed first. Skipping Q1 config application; verification below will report missing-file failures until Phase E runs."
else
    case "$KEYSTONE_Q_LOGGING_POSTURE" in
    A)
        info "Q1: applying Posture A (zero logging) — this overwrites Phase E's shipped querylog:/statistics: blocks"

        # --- Q1: schema-version detection (the schema trap) ---
        # "Pin it to whatever LastSchemaVersion is for the binary you
        # actually installed, not blindly to 34 ... read it back from the
        # running deployment." Never hardcode the version from the source's
        # illustrative example block.
        confirm "About to restart adguardhome (boot service) to read its live schema_version from $AGH_YAML before pinning it into the Posture A block. Continue?"
        systemctl restart adguardhome
        sleep 10
        SCHEMA_VERSION=$(grep '^schema_version:' "$AGH_YAML" | awk '{print $2}')
        [[ -n "$SCHEMA_VERSION" ]] || fatal "Q1: could not read schema_version from $AGH_YAML after restart — check 'journalctl -u adguardhome -n 40' before continuing. Refusing to hardcode a version (see Q1 'schema trap')."
        info "Q1: live schema_version=$SCHEMA_VERSION — this is what gets pinned"

        # --- Q1: overwrite querylog:/statistics: blocks, pin schema_version ---
        confirm "About to overwrite the top-level querylog: and statistics: blocks in $AGH_YAML (Posture A) and restart adguardhome to apply them — a config already backed up, but this is a live production DNS service restart. Continue?"
        backup_file "$AGH_YAML"
        python3 - "$AGH_YAML" "$SCHEMA_VERSION" <<'PYEOF'
import re, sys
path, schema_version = sys.argv[1], sys.argv[2]

new_querylog = """querylog:
  enabled: false
  file_enabled: false
  interval: 24h
  size_memory: 1000
  ignored: []
  ignored_enabled: false
"""
new_statistics = """statistics:
  enabled: false
  interval: 24h
  ignored: []
  ignored_enabled: false
"""

with open(path) as f:
    text = f.read()

def replace_block(text, key, new_block):
    pattern = re.compile(r'^' + key + r':\n(?:[ \t].*\n?)*', re.MULTILINE)
    if not pattern.search(text):
        sys.stderr.write(f"ERROR: top-level key {key}: not found in {path}\n")
        sys.exit(1)
    return pattern.sub(lambda _m: new_block, text, count=1)

text = replace_block(text, "querylog", new_querylog)
text = replace_block(text, "statistics", new_statistics)

if re.search(r'^schema_version:.*$', text, re.MULTILINE):
    text = re.sub(r'^schema_version:.*$', f'schema_version: {schema_version}', text, count=1, flags=re.MULTILINE)
else:
    text = f'schema_version: {schema_version}\n' + text

with open(path, 'w') as f:
    f.write(text)
print(f"OK: querylog/statistics blocks replaced, schema_version pinned to {schema_version}")
PYEOF

        # --- Q1: remove legacy pre-schema-15 querylog_* keys under dns:, if any ---
        # "ensure no querylog_enabled, querylog_file_enabled, querylog_interval
        # or querylog_size_memory key remains under dns:"
        for legacy_key in querylog_enabled querylog_file_enabled querylog_interval querylog_size_memory; do
            if grep -qE "^\s+${legacy_key}:" "$AGH_YAML"; then
                sed -i "/^\s\+${legacy_key}:/d" "$AGH_YAML"
                info "Q1: removed legacy key ${legacy_key} from under dns: in $AGH_YAML"
            fi
        done

        # --- Q1: anonymize_client_ip must stay true under dns: — check, don't invent a fix ---
        grep -qE '^\s+anonymize_client_ip:\s*true' "$AGH_YAML" \
            && info "Q1: anonymize_client_ip: true confirmed under dns:" \
            || warn "Q1: anonymize_client_ip: true NOT found under dns: in $AGH_YAML — Phase E should have set this. Fix it there, not here."

        systemctl restart adguardhome
        sleep 10
        ;;
    B)
        # No full top-level block is given in the source for Posture B — only
        # the differing key values are given in the Q1 comparison table. Do
        # not fabricate a block; hand this to the operator per hard rule 7.
        warn "Q1: Posture B (aggregate statistics only) selected. The source gives no full YAML block for Posture B — only the Q1 comparison table's differing values (querylog.enabled=false, statistics.enabled=true, i.e. leave Phase E's statistics: block as shipped). MANUAL STEP: edit $AGH_YAML by hand — set querylog.enabled: false and querylog.file_enabled: false under the existing querylog: block (leave interval/size_memory/ignored/ignored_enabled as-is), leave statistics: untouched. Then 'systemctl restart adguardhome' and re-run the Q1 verification below."
        ;;
    C)
        info "Q1: Posture C selected — the Phase E shipped default (querylog.enabled=true, statistics.enabled=true, 6h ring). No config change needed."
        ;;
    esac
fi

# --- Q1: temporary in-memory debugging window (Posture A/B only) ---
# Defined as a function, not run automatically — this is an ad hoc operator
# action, not part of a routine deploy. "Set a calendar reminder to revert,
# and record the window in RETENTION.md."
q1_temporary_debug_window() {
    warn "Q1 temporary debug window: set querylog.enabled: true with querylog.file_enabled: false in $AGH_YAML by hand, restart adguardhome, use the admin UI over the Phase P SSH tunnel, then REVERT and record the window in $RETENTION_MD's 'Temporary logging windows' table. Under Posture A this does not restore Phase I metrics — statistics.enabled is a separate key."
}

# --- Q1: verification (run regardless of posture chosen) ---
info "Q1 verify: config accepted, posture matches RETENTION.md, on-disk artifacts match posture"
confirm "Q1 verification restarts adguardhome again to confirm it starts cleanly on the current config. Continue?"
systemctl restart adguardhome && sleep 10
systemctl is-active adguardhome
journalctl -u adguardhome -n 40 --no-pager | grep -i 'failed to parse\|migrating schema' \
  && echo "FAIL: config rejected" || echo "OK: config accepted"

grep -E '^(schema_version|querylog|statistics):' -A6 "$AGH_YAML" || true
! grep -qE '^\s+querylog_' "$AGH_YAML" && echo "OK: no legacy querylog_ keys"
! grep -q '2160h' "$AGH_YAML" && echo "OK: retention not reset to 90d"

QL=$(grep -A1 '^querylog:'   "$AGH_YAML" | awk '/enabled:/{print $2}')
ST=$(grep -A1 '^statistics:' "$AGH_YAML" | awk '/enabled:/{print $2}')
case "$QL/$ST" in
  true/true)   echo "INFO: Posture C - Phase E shipped default (6h query log + statistics)" ;;
  false/true)  echo "INFO: Posture B - statistics only, opted in" ;;
  false/false) echo "INFO: Posture A - zero logging, opted in. Phase I will report"
               echo "      'metrics unavailable by policy'; that is not an outage." ;;
  *)           echo "REVIEW: querylog=$QL statistics=$ST - unusual combination" ;;
esac
grep -i 'logging posture' "$RETENTION_MD" 2>/dev/null || warn "Q1 verify: $RETENTION_MD not present yet — run Q5a below first, then re-check that its posture line agrees with the INFO line above"

sleep 60
ls -l /var/log/adguardhome/querylog/querylog.json 2>/dev/null \
  || echo "OK: no query log on disk (expected under Posture A or B)"

test -e /var/lib/adguardhome/stats/stats.db && echo "INFO: stats.db exists (expected)"
n=$(strings /var/lib/adguardhome/stats/stats.db 2>/dev/null | grep -cE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || true)
u=$(strings /var/lib/adguardhome/stats/stats.db 2>/dev/null | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
     | grep -vcE '\.0\.0$' || true)
echo "addresses=$n unmasked=$u"
echo "Expected: active / OK: config accepted / a schema_version: line / an INFO: line naming the posture / RETENTION.md agreeing / and, for the shipped default, unmasked=0."

# =====================================================================
# Q2. Upstream exposure — verification only, no config change owned by Q
# =====================================================================
# Recursion (Phase C) and edns_client_subnet:false (Phase E) are what this
# section checks, not what it sets — both are owned by other phases.

info "Q2 verify: recursion is genuinely in use, ECS not forwarded, QNAME minimisation on"
grep -E '^\s*(forward-zone|forward-addr|forward-host)' -r /etc/unbound/ && echo "FAIL: forwarding configured" || echo "OK: recursive"
grep -A3 '^\s*upstream_dns:' "$AGH_YAML" 2>/dev/null || true   # expect only 127.0.0.1:5335
grep -A2 'fallback_dns' "$AGH_YAML" 2>/dev/null || true        # expect: []
grep -A2 'edns_client_subnet' "$AGH_YAML" 2>/dev/null || true  # expect enabled: false
unbound-checkconf -o qname-minimisation /etc/unbound/unbound.conf   # expect: yes
echo "Expected: OK: recursive / a single 127.0.0.1:5335 upstream / fallback_dns: [] / edns_client_subnet enabled: false / yes"

warn "Q2 note: ODoH is not supported by this stack (AdGuardHome dnsproxy has no oblivious transport) and would add third parties even if it were. Do not describe this resolver as 'oblivious' in the privacy notice (Q5b)."
warn "Q2 note: recursion trades a threat model that includes YOUR HOSTING PROVIDER for the worse — they now see your full cleartext resolution pattern, not four HTTPS destinations. State this trade explicitly in the privacy notice; do not present recursion as strictly superior."

# =====================================================================
# Q3. Data at rest on hardware you do not control
# =====================================================================

# --- Q3: put the AGH query-log and statistics directories in RAM ---
# "This is the highest-value change in Q3, and it is worth doing under ANY
# posture." Mounts the two directories Phase E actually configures, not the
# work directory.
info "Q3: mounting AdGuardHome query-log and stats directories on tmpfs"
FSTAB_LINE_QL='tmpfs /var/log/adguardhome/querylog tmpfs rw,nosuid,nodev,noexec,mode=0750,size=64M 0 0'
FSTAB_LINE_ST='tmpfs /var/lib/adguardhome/stats    tmpfs rw,nosuid,nodev,noexec,mode=0750,size=16M 0 0'

if grep -qF "$FSTAB_LINE_QL" /etc/fstab 2>/dev/null && grep -qF "$FSTAB_LINE_ST" /etc/fstab 2>/dev/null; then
    info "Q3: tmpfs fstab entries already present — skipping"
else
    confirm "About to append tmpfs mounts for /var/log/adguardhome/querylog (64M) and /var/lib/adguardhome/stats (16M) to /etc/fstab, edit /etc/systemd/system/adguardhome.service (Phase E-owned boot-service unit) to add ExecStartPre/RequiresMountsFor, then run 'mount -a', daemon-reload and restart adguardhome. This makes AGH statistics reset on every reboot (see Q3). Continue?"
    backup_file /etc/fstab
    grep -qF "$FSTAB_LINE_QL" /etc/fstab 2>/dev/null || echo "$FSTAB_LINE_QL" >> /etc/fstab
    grep -qF "$FSTAB_LINE_ST" /etc/fstab 2>/dev/null || echo "$FSTAB_LINE_ST" >> /etc/fstab

    AGH_UNIT=/etc/systemd/system/adguardhome.service
    if [[ -f "$AGH_UNIT" ]]; then
        backup_file "$AGH_UNIT"
        if ! grep -qF 'RequiresMountsFor=/var/log/adguardhome/querylog /var/lib/adguardhome/stats' "$AGH_UNIT"; then
            sed -i '/^\[Unit\]/a RequiresMountsFor=/var/log/adguardhome/querylog /var/lib/adguardhome/stats' "$AGH_UNIT"
        fi
        if ! grep -qF 'ExecStartPre=+/usr/bin/install -d -o adguardhome -g adguardhome -m 0750 /var/log/adguardhome/querylog' "$AGH_UNIT"; then
            sed -i '/^\[Service\]/a ExecStartPre=+/usr/bin/install -d -o adguardhome -g adguardhome -m 0750 /var/log/adguardhome/querylog\nExecStartPre=+/usr/bin/install -d -o adguardhome -g adguardhome -m 0750 /var/lib/adguardhome/stats' "$AGH_UNIT"
        fi
        systemctl daemon-reload
        mount -a
        systemctl restart adguardhome
    else
        warn "Q3: $AGH_UNIT not found — Phase E has not run yet. fstab entries written; the ExecStartPre/RequiresMountsFor unit edit and mount/restart must be done once Phase E creates the unit."
    fi
fi

warn "Q3: size the query-log tmpfs (64M) for your peak six-hour volume, not the nominal figure — a full tmpfs is a service-affecting write failure, not graceful degradation. Check with 'df -h' after a week at real traffic."
warn "Q3: AdGuardHome statistics now reset at every reboot (stats.db is RAM-backed) — Phase I's dashboards show a discontinuity, not an outage."

# --- Q3: journald storage ---
info "Q3: journald storage = $KEYSTONE_Q_JOURNALD_STORAGE (recorded decision)"
if [[ "$KEYSTONE_Q_JOURNALD_STORAGE" == "volatile" ]]; then
    confirm "About to write /etc/systemd/journald.conf.d/10-volatile.conf (Storage=volatile) and restart systemd-journald — this discards persistent journal history, including sshd/auth forensics. Continue?"
    install -d -m 0755 /etc/systemd/journald.conf.d
    backup_file /etc/systemd/journald.conf.d/10-volatile.conf
    cat > /etc/systemd/journald.conf.d/10-volatile.conf << 'EOF'
[Journal]
Storage=volatile
RuntimeMaxUse=64M
EOF
    systemctl restart systemd-journald
else
    info "Q3: journald staying persistent — this is what Phase G's 10-dns.conf already configured (Storage=persistent). No file written by Q3."
fi
warn "Q3: DNS query content never reaches the journal either way (Unbound runs at verbosity 1, AGH does not log queries to stderr) — this setting is about connection-activity durability, not query privacy. Record the choice and reasoning in RETENTION.md (Q5a)."

# --- Q3: disk encryption — decision only, no automated LUKS setup ---
info "Q3: disk encryption = $KEYSTONE_Q_DISK_ENCRYPTION (recorded decision, no commands run — source gives none)"
if [[ "$KEYSTONE_Q_DISK_ENCRYPTION" == "luks" ]]; then
    warn "MANUAL STEP (Q3 encryption): KEYSTONE_Q_DISK_ENCRYPTION=luks recorded, but LUKS-on-data-volume-with-dropbear-initramfs setup is NOT automated here — phases/10-privacy-and-compliance.md gives the tradeoff, not exact commands. Set it up by hand, then record it in RETENTION.md. Remember: it protects nothing against a live hypervisor, a provider console session, or a memory dump — the key is in RAM while the service runs."
fi

# --- Q3: unbound-control dump_cache — no automation, check nobody has scripted it ---
info "Q3 verify: remote-control reachability (expected, Phase I needs it) and no scripted cache dump"
for d in /var/log/adguardhome/querylog /var/lib/adguardhome/stats; do
  findmnt -no FSTYPE,OPTIONS "$d" || warn "Q3 verify: $d not mounted yet"
done
stat -c '%n %U:%G %a' /var/log/adguardhome/querylog /var/lib/adguardhome/stats 2>/dev/null || true
unbound-checkconf -o verbosity /etc/unbound/unbound.conf      # expect: 1
unbound-checkconf -o log-queries /etc/unbound/unbound.conf    # expect: no
unbound-control status >/dev/null 2>&1 \
  && echo "INFO: remote-control reachable (expected - Phase I) - see RETENTION.md"
grep -rl 'dump_cache' /etc/cron.* /etc/systemd/system /usr/local/sbin /opt 2>/dev/null \
  && echo "REVIEW: something is scripting a cache dump" \
  || echo "OK: no scripted dump_cache"
warn "Q3: RETENTION.md must record that 'unbound-control dump_cache' produces domain history for the whole user population, that the capability exists (remote-control is enabled by design for Phase I), and who holds the control key. Never redirect its output to a file that outlives the incident."

# =====================================================================
# Q4. Metadata that survives a perfect no-log configuration — verification
# and disclosure only. Q builds nothing here; CT, PTR, SNI, netflow are all
# structural properties owned by other phases or by the client's own path.
# =====================================================================

info "Q4: five leaks that survive a perfect no-log config — disclose, do not attempt to fix what cannot be fixed here"
warn "Q4: Certificate Transparency publishes the hostname at issuance, permanently, with no opt-out. If the hostname must stay unpublished, the only mitigation is a DNS-01 WILDCARD cert (Phase D) — this must be decided BEFORE first issuance; a CT entry cannot be unpublished."
warn "Q4: SNI is on the client's path and is server-side unfixable. DoT/DoH clients send $DOMAIN in cleartext TLS SNI absent Encrypted Client Hello — the user's own ISP learns that this user uses your resolver. Disclose this in the privacy notice."
warn "Q4: your hosting provider holds netflow (source, destination, port, size, timing) for every packet under their own retention policy, not yours. List them as a third party in the privacy notice."
warn "Q4: Phase F (the SmartDNS cache warmer) is retired — do not reintroduce a fixed-domain-set warmer. Unbound's prefetch (Phase C) is demand-shaped, not fingerprint-shaped; describe it accurately and do not claim it obscures anything."

info "Q4 verify"
curl -s "https://crt.sh/?q=%25.${APEX}&output=json" | (command -v jq >/dev/null 2>&1 && jq -r '.[].name_value' | sort -u || cat)
dig +short "$DOMAIN" A
if [[ -n "$PUBLIC_IP" ]]; then
    dig +short -x "$PUBLIC_IP"
else
    warn "Q4 verify: PUBLIC_IP is unset — set it at the top of this script to run the reverse-DNS check"
fi

for f in /etc/nginx/conf.d/*.conf; do
  [ -e "$f" ] || { echo "FAIL: no server blocks found in /etc/nginx/conf.d/"; break; }
  grep -q 'access_log off;' "$f" && echo "OK: $f" || echo "FAIL: $f missing 'access_log off;'"
done
if [[ -f "$DOH_CONF" ]]; then
    test "$(grep -c 'access_log off;' "$DOH_CONF")" -ge 2 \
      && echo "OK: both client-facing blocks disable access logging" \
      || echo "FAIL: fewer than two 'access_log off;' directives in $DOH_CONF"

    BEFORE=$(stat -c %s /var/log/nginx/access.log 2>/dev/null || echo 0)
    curl -s "http://${DOMAIN}/.well-known/security.txt" >/dev/null || true
    curl -s -H 'accept: application/dns-message' \
      "https://${DOMAIN}/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" >/dev/null || true
    sleep 1
    AFTER=$(stat -c %s /var/log/nginx/access.log 2>/dev/null || echo 0)
    [ "$BEFORE" -eq "$AFTER" ] && echo "OK: neither request produced a log line" \
                               || echo "FAIL: nginx logged a request"
else
    warn "Q4 verify: $DOH_CONF not found — Phase E has not run yet"
fi
echo "Expected: CT listing shows only intended labels; forward/reverse agree; OK: for every conf.d file; OK: both client-facing blocks disable access logging; OK: neither request produced a log line."
info "Q4 verify (SNI, manual): openssl s_client only proves the server ACCEPTS a given SNI, not what a real client sends. To see the wire value: tcpdump -ni any -s0 -A 'tcp port 853' | grep -a $DOMAIN"

# =====================================================================
# Q5. The written artifacts
# =====================================================================

# --- Q5a: data retention policy — deployed verbatim, filled in by the operator ---
# "Adapt the templates; do not ship them with example.com in place." The
# template itself carries [Posture A: ...] bracket alternatives for the
# operator to resolve by hand — that is the source's own format, so it is
# deployed as-is (verbatim), not paraphrased or pre-resolved.
info "Q5a: writing $RETENTION_MD"
# /opt/dns-config-backup is Phase A3's object (sole owner: install -d -m 0750
# + git init). Q writes files INTO it but never creates the directory itself
# — same convention as I3/J4 (see I-observability.sh, J-abuse-detection.sh).
if [[ ! -d /opt/dns-config-backup ]]; then
    fatal "Q5a: /opt/dns-config-backup does not exist — it is Phase A3's object (created there). Run Phase A first; Phase Q does not create it."
fi
if [[ -f "$RETENTION_MD" ]]; then
    confirm "About to overwrite existing $RETENTION_MD. It is backed up first, but this may hold live-edited operator content. Continue?"
    backup_file "$RETENTION_MD"
fi
cat > "$RETENTION_MD" << 'RETENTION_EOF'
# Data Retention Policy - dns.example.com
Owner: <name>   Effective: <date>   Review: annually
Logging posture: <shipped default (Q1 Posture C) | Posture B | Posture A>   Decided: <date> by <name>

## What is collected
| Data | Where | Why | Retention | Destruction |
|---|---|---|---|---|
| DNS query records (name, type, /16-masked client IP) | AdGuardHome query log, RAM-backed tmpfs | fault diagnosis | 6 h rolling ring | ring expiry; lost on reboot [Posture A: not retained - querylog.enabled=false, no log entry is ever built] |
| Client IP addresses | only inside the above, truncated to /16 at ingestion | fault diagnosis | 6 h | as above [Posture A: not retained at all] |
| Per-domain and per-client-/16 counters | AdGuardHome stats.db, RAM-backed tmpfs | monitoring (Phase I) | statistics.interval | lost on reboot [Posture A: statistics disabled; file exists but holds no client data] |
| Resolver cache (domains, no client identity) | Unbound process RAM | performance | until process restart | lost on exit; nothing written to disk |
| Edge cache | AdGuardHome process RAM | performance | until process restart | lost on exit |
| Unbound cache dump (manual only) | not produced routinely | incident diagnosis | n/a | remote-control is enabled for Phase I metrics, so `unbound-control dump_cache` is available to <key holders>; output is never written to a file |
| Banned source addresses | kernel nftables set | abuse mitigation | 10 minutes first offence, escalating to 24 hours on repeat (kernel set timeout; see Phase B/J) | automatic expiry; never written to disk |
| Aggregate packet counters | kernel counters | abuse monitoring | until reboot | no identity content |
| TLS certificate and key | /etc/letsencrypt | service operation | 90 days, auto-renewed | certbot |
| System and auth logs (sshd etc.) | journald | operator security | <N> days | journald rotation |

## What is NOT collected
No query records beyond the 6 h ring above, and none at all under Posture A.
No un-truncated client IP address is ever written: the mask is applied at ingestion.
No EDNS Client Subnet is sent upstream (dns.edns_client_subnet.enabled=false).
No web-server access log on any listener.
No per-peer VPN metadata is captured to disk (see Q7, if Phase P applies).

## Who can access
<names/roles>. Access is via SSH key only; no shared credentials.
The AdGuardHome admin UI is bound to 127.0.0.1 and reachable only via SSH port-forward (Phase P).

## Third parties that necessarily see data
- Hosting provider <name, jurisdiction>: connection metadata (netflow) for all traffic,
  under their policy, not ours.
- Authoritative DNS operators, including the root and TLD operators: query names, in
  cleartext, attributed to this server's IP address only - never to an individual client.
  QNAME minimisation limits what each level of the hierarchy learns.
- Certificate Transparency logs: the certificate and hostname, permanently and publicly.

## Deliberate deviations
- Logging posture: <as shipped by Phase E | opted in to Posture A or B on <date>, reason <...>>.
  If Posture A: the monitoring consequence has been accepted - AdGuardHome metrics are absent
  and the Phase I collector reports "metrics unavailable by policy" rather than an outage.
- Unbound remote-control is ENABLED, because Phase I collects metrics over it. Control-key
  holders: <names>. A manual `unbound-control dump_cache` would produce domain history for the
  whole user population; it is never scripted and never redirected to a file.
- security.txt is served over HTTP as well as HTTPS (see privacy notice; RFC 9116 requires https).
- journald storage: <persistent | volatile> - reason: <...>
- Disk encryption: <LUKS | none> - reason and limits: <...>

## Temporary logging windows
| Start | End | Posture | Reason | Approved by |
|---|---|---|---|---|

## Change control
Any change that causes user data to be retained requires an entry in this file, a commit,
and a corresponding update to the published privacy notice BEFORE deployment.

## Decision register (Q6)
Append to RETENTION.md and commit. Every row needs an answer and a date; "not applicable"
with a reason is a valid answer, "blank" is not.

| Decision | Why it is a decision | Recorded answer | Date |
|---|---|---|---|
| Logging posture (Q1) | Determines everything downstream. Leaving the Phase E shipped default in place is a valid answer and must be recorded as one - "we did not change it" is a decision, "nobody looked" is not | | |
| Monitoring consequence accepted (Q1) | Only if you opt in to Posture A: AdGuardHome metrics disappear and Phase I reports "metrics unavailable by policy". Record who accepted operating without them | | |
| Controller or processor | Serving the general public makes you a controller. Serving one organisation on its instructions makes you a processor and requires an Art. 28 agreement | | |
| Lawful basis, with a written Legitimate Interests Assessment | Consent is impractical for DNS - there is no interface in which to obtain it | | |
| Art. 30 record of processing | The under-250-employee carve-out does not apply to processing that is not occasional, and a resolver runs continuously. RETENTION.md is most of a ROPA already | | |
| Art. 27 EU representative | Required if you are established outside the EU and offer the service to people in the EU | | |
| DPO under Art. 37(1)(b) | A no-log resolver is very unlikely to constitute large-scale regular systematic monitoring - but record the reasoning rather than leaving it unconsidered | | |
| International transfers | Under recursion you no longer forward to named US operators, which removes the clearest transfer question. Authoritative servers worldwide still receive query names attributed to your IP - decide how you characterise that | | |
| Art. 33 breach notification, 72 hours | Record what a host compromise would actually expose. Under the shipped default: up to six hours of query records with /16-truncated client addresses, RAM-resident. Under Posture A: nothing, because no record exists - which remains the strongest single argument for opting in | | |
| Provider AUP position | Read the terms; record the clause and any written confirmation | | |
| Abuse complaint handling | Who receives, who responds, what evidence you can offer (kernel counters, not query logs - see Phase J) | | |
| Law enforcement runbook | Receipt, validity and jurisdiction checks, what you actually hold (nothing), user notification | | |
| Preservation-order plan | Decided in advance, per the paragraph above | | |
| Transparency report | Publish or not; if yes, cadence and first date | | |
| journald storage (Q3) | Persistent gives you break-in forensics; volatile removes durable connection records | | |
| Disk encryption (Q3) | LUKS or none, with the limitations written down | | |
| Hostname publication (Q4) | HTTP-01 named cert publishes the label to CT permanently; DNS-01 wildcard does not | | |
RETENTION_EOF

info "Q5a: RETENTION.md deployed VERBATIM from the source template (including its [Posture A: ...] bracket alternatives) — resolve those brackets and every <placeholder> by hand. Current fatal-gated decisions: logging posture=$KEYSTONE_Q_LOGGING_POSTURE, journald storage=$KEYSTONE_Q_JOURNALD_STORAGE, disk encryption=$KEYSTONE_Q_DISK_ENCRYPTION — use these to fill the 'Logging posture:' header line and the 'Deliberate deviations' section, and delete the bracket wording that does not apply."

if [[ -d /opt/dns-config-backup/.git ]]; then
    git -C /opt/dns-config-backup add RETENTION.md
    git -C /opt/dns-config-backup commit -m "Phase Q: deploy RETENTION.md template (posture=$KEYSTONE_Q_LOGGING_POSTURE)" --allow-empty-message -q || info "Q5a: nothing to commit (RETENTION.md unchanged)"
else
    warn "Q5a: /opt/dns-config-backup is not a git repo — Phase A3 is supposed to have initialised one. Commit RETENTION.md by hand once it is."
fi

# --- Q5b: privacy notice — deployed verbatim to a local file. The source
# names only a public URL (https://example.com/dns-privacy) and gives no
# nginx/webserver directive for serving it from this host. Publishing it at
# that URL is therefore a MANUAL STEP — hard rule 7 applies. ---
info "Q5b: writing $PRIVACY_NOTICE_MD (source content only; publishing this at $POLICY_URL is a manual step — see warn below)"
if [[ -f "$PRIVACY_NOTICE_MD" ]]; then
    confirm "About to overwrite existing $PRIVACY_NOTICE_MD. It is backed up first. Continue?"
    backup_file "$PRIVACY_NOTICE_MD"
fi
cat > "$PRIVACY_NOTICE_MD" << 'PRIVACY_EOF'
# Privacy Notice - dns.example.com public DNS resolver
Last updated: <date>

**Who we are.** <legal name / individual>, <postal address>, <contact email>.
We are the data controller for this service.

**What we do with your queries.** [DEFAULT CONFIGURATION VERSION] We resolve them. We keep a
short operational record of queries - the name asked for, the record type, and your IP address
truncated to its first two octets - for six hours, so that we can diagnose faults. It is held
in memory only and is lost whenever the service restarts. Your full IP address is never
written down: it is truncated before the record is created. After six hours the record is
gone. We do not sell, share or monetise DNS data. We do not filter, block or redirect answers.

**What we do with your queries.** [ZERO-LOG VERSION - publish this one only if you have opted
in to Q1 Posture A] We resolve them and forget them. We do not write query logs. We do not
store client IP addresses, truncated or otherwise. We do not sell, share or monetise DNS
data. We do not filter, block or redirect answers.

**What we necessarily process, transiently.** Your IP address is present in the packets we
receive and is held in memory only for as long as needed to answer, plus, if you send
abusive traffic volumes, for 10 minutes in a kernel firewall ban list - extended to 24 hours
if the abusive traffic repeats. Lawful basis: legitimate interests (Art. 6(1)(f)) in
delivering the service and preventing abuse. Our balancing assessment is available on request.

**Who else sees your queries.** We do not forward your queries to any commercial resolver.
This server resolves independently from the DNS root, which means the root operators, the
relevant top-level domain operator, and the authoritative servers for the domain you asked
about each see part or all of the name - in cleartext, and attributed to this server's IP
address, never to yours. We use QNAME minimisation, so each level of the hierarchy is told
only as much of the name as it needs. We do not send EDNS Client Subnet. Our hosting
provider, <name>, can observe connection metadata (your IP address, timing, volume) under
their own policy.

**What we cannot protect you from.** The hostname dns.example.com is sent in cleartext
(TLS SNI) when your device connects, so your network operator can see that you use this
resolver, though not what you asked. Our hostname and certificate are permanently public in
Certificate Transparency logs. We cannot see or control what your operating system or
browser does with DNS outside this service.

**Your rights.** Access, erasure, restriction, objection, and complaint to your supervisory
authority. [DEFAULT CONFIGURATION VERSION] In practice we hold very little: at most a six-hour
record in which your address appears only truncated to its first two octets, which we usually
cannot tie to you as an individual. We will explain in writing what we hold on request.
[ZERO-LOG VERSION] In practice we hold no data to give you or to erase; we will say so in
writing on request.

**Law enforcement.** We respond only to legally valid process in <jurisdiction>. [DEFAULT
CONFIGURATION VERSION] We hold at most six hours of query records in which client addresses
are truncated to /16, held in memory and lost on restart; we cannot produce a full client
address for any query, because we never record one. [ZERO-LOG VERSION] We hold no query or
client data to produce. If we are ever compelled to begin retaining more than is described
above, we will publish that change here before it takes effect, to the extent the law permits.

**Changes.** Material changes are published here with a new date.
PRIVACY_EOF

if [[ "$KEYSTONE_Q_LOGGING_POSTURE" == "A" ]]; then
    info "Q5b: current posture is A (zero-log) — publish the [ZERO-LOG VERSION] paragraphs and delete the [DEFAULT CONFIGURATION VERSION] ones. Do not ship both."
else
    info "Q5b: current posture is $KEYSTONE_Q_LOGGING_POSTURE — publish the [DEFAULT CONFIGURATION VERSION] paragraphs and delete the [ZERO-LOG VERSION] ones. Do not ship both."
fi
warn "MANUAL STEP (Q5b): the source names only a public URL ($POLICY_URL) for the privacy notice and gives no nginx/webserver directive for hosting it on this DNS host. $PRIVACY_NOTICE_MD holds the content — publishing it at a reachable URL (this host or your main website) is not automated here. 'Publishing the zero-log wording while running the Phase E shipped default is not a drafting slip; it is a false statement to data subjects' — resolve the bracketed paragraph pair above BEFORE publishing."

if [[ -d /opt/dns-config-backup/.git ]]; then
    git -C /opt/dns-config-backup add PRIVACY-NOTICE.md
    git -C /opt/dns-config-backup commit -m "Phase Q: deploy privacy notice template (posture=$KEYSTONE_Q_LOGGING_POSTURE)" -q || info "Q5b: nothing to commit (PRIVACY-NOTICE.md unchanged)"
fi

# --- Q5c: security.txt and the abuse contact ---
info "Q5c: adding the Phase Q /.well-known/ location to Phase E's doh.conf"
if [[ ! -f "$DOH_CONF" ]]; then
    warn "Q5c: $DOH_CONF not found — Phase E has not run yet. Skipping the nginx edit."
else
    if grep -qF 'location ^~ /.well-known/ { }' "$DOH_CONF" && [ "$(grep -cF 'location ^~ /.well-known/ { }' "$DOH_CONF")" -ge 2 ]; then
        info "Q5c: both /.well-known/ location blocks already present in $DOH_CONF — skipping"
    else
        confirm "About to edit $DOH_CONF (Phase E-owned production nginx config) to add root/charset/location lines to the :443 block and a location block to the :80 block, then reload nginx. Continue?"
        backup_file "$DOH_CONF"
        # Anchors are the exact lines Phase E wrote for this purpose: the
        # error_log line unique to the :443 DoH server block, and the literal
        # "PHASE Q INSERTION POINT" marker Phase E left inside the :80 block.
        awk '
          { print }
          /error_log  \/var\/log\/nginx\/doh-error\.log warn;/ && !inserted443 {
              print "";
              print "    root /var/www/acme;";
              print "    charset utf-8;";
              print "    location ^~ /.well-known/ { }";
              inserted443=1
          }
          /# >>> PHASE Q INSERTION POINT <<</ && !inserted80 {
              print "    location ^~ /.well-known/ { }";
              inserted80=1
          }
        ' "$DOH_CONF" > "${DOH_CONF}.q.tmp"
        mv "${DOH_CONF}.q.tmp" "$DOH_CONF"
        install -d -m 0755 /var/www/acme/.well-known
        nginx -t && systemctl reload nginx
    fi
fi

# --- Q5c: security.txt content, verbatim template with substituted contact/expiry ---
info "Q5c: writing /var/www/acme/.well-known/security.txt"
if [[ -f /var/www/acme/.well-known/security.txt ]]; then
    confirm "About to overwrite existing /var/www/acme/.well-known/security.txt (backed up first). Continue?"
    backup_file /var/www/acme/.well-known/security.txt
fi
install -d -m 0755 /var/www/acme/.well-known
cat > /var/www/acme/.well-known/security.txt << EOF
# Public DNS resolver operated at ${DOMAIN}
Contact: mailto:${ABUSE_EMAIL}
Contact: mailto:${SECURITY_EMAIL}
Expires: ${KEYSTONE_Q_SECURITYTXT_EXPIRES}
Preferred-Languages: en
Canonical: https://${DOMAIN}/.well-known/security.txt
Policy: ${POLICY_URL}
Acknowledgments: ${ACKNOWLEDGMENTS_URL}
EOF

# --- Q5c: the monthly expiry check script, verbatim ---
info "Q5c: installing /usr/local/sbin/check-securitytxt-expiry"
backup_file /usr/local/sbin/check-securitytxt-expiry
cat > /usr/local/sbin/check-securitytxt-expiry << 'EOF'
#!/bin/bash
set -u
F=/var/www/acme/.well-known/security.txt
EXP=$(awk -F': ' '/^Expires:/{print $2}' "$F")
[ -n "$EXP" ] || { echo "no Expires field in $F" | logger -t securitytxt -p daemon.err; exit 1; }
DAYS=$(( ( $(date -d "$EXP" +%s) - $(date +%s) ) / 86400 ))
[ "$DAYS" -lt 30 ] || exit 0
# notify.sh is the single notification entry point, defined by Phase I8b, and its
# signature is `notify.sh <severity> <title> [message]`. Severity and title are
# SEPARATE arguments: a single-argument call makes the message text the severity,
# which pages at the wrong priority and discards the message. Fall back to the
# journal only if notify.sh is not installed yet, so this check never silently
# does nothing -- notify.sh writes its own journald record when it is present.
if [ -x /usr/local/sbin/notify.sh ]; then
  /usr/local/sbin/notify.sh warning "security.txt expiring" \
    "security.txt for dns.example.com expires in $DAYS days (Expires: $EXP)"
else
  echo "security.txt expires in $DAYS days" | logger -t securitytxt
fi
EOF
chmod 0755 /usr/local/sbin/check-securitytxt-expiry

# --- Q5c: schedule from the ONE cron file (Phase I owns it, Q only appends) ---
CRON_FILE=/etc/cron.d/dns-health
CRON_LINE='41 7 1 * * root /usr/local/sbin/check-securitytxt-expiry'
if [[ ! -e "$CRON_FILE" ]]; then
    warn "$CRON_FILE does not exist — it is created by Phase I, not this phase. Run Phase I first; skipping the security.txt-expiry cron append until then."
else
    if grep -qF 'check-securitytxt-expiry' "$CRON_FILE" 2>/dev/null; then
        info "Q5c: security.txt-expiry line already present in $CRON_FILE — skipping duplicate append"
    else
        confirm "About to append a line to $CRON_FILE (Phase I-owned root cron file): '$CRON_LINE' — continue?"
        backup_file "$CRON_FILE"
        echo "$CRON_LINE" >> "$CRON_FILE"
    fi
fi

# --- Q5c: abuse mailbox, PTR, provider ticket — manual per the source itself ---
warn "MANUAL CHECKLIST ITEM (Q5c): 'Abuse mailbox test is a manual checklist item, not a script. Send a message by hand from an external account and confirm a human reply. Do not pipe mail from the server: this plan installs no MTA.' Not automated here."
warn "MANUAL STEP (Q5c): set abuse-c on your RIPE object (or the ARIN/APNIC Abuse POC), or open a ticket with your hosting provider asking them to forward resolver abuse reports to $ABUSE_EMAIL, and record the ticket reference. Not automated here."
warn "MANUAL STEP (Q4/Q5c): set the PTR record for this host's public IP to $DOMAIN via your hosting provider's control panel. Not automated here."
info "Q5c note: this phase adds Q's own go-live checklist items to Phase L's checklist file only as a reference below — writing to Phase L's script is out of scope for this Phase Q script (single-ownership; Phase L owns its own file):"
cat << 'EOF'
  [ ] Logging posture explicitly chosen and written into RETENTION.md with a date and a name
  [ ] If Posture A: Phase I confirmed to emit "metrics unavailable by policy"
  [ ] Privacy notice publishes the paragraph variant that matches the chosen posture
  [ ] AdGuardHome starts with schema_version pinned; no legacy querylog_ keys
  [ ] tmpfs mounted on querylog and stats dirs; survives a reboot with no carry-over
  [ ] abuse@ and security@ exist, monitored, tested end-to-end by hand
  [ ] security.txt reachable over HTTP and HTTPS, charset=utf-8, Expires < 1 year out
  [ ] exactly one listen-80 default_server block and one webroot (/var/www/acme)
  [ ] monthly security.txt expiry check active, appended to /etc/cron.d/dns-health
  [ ] certbot authenticator is webroot or dns-*, NOT standalone
  [ ] access_log off verified behaviourally on every client-facing nginx server block
  [ ] PTR matches dns.example.com
  [ ] provider abuse-forwarding ticket raised, reference recorded
  [ ] privacy notice published and linked from security.txt Policy:
  [ ] Q6 decision register completed and committed
EOF

# --- Q5c: verification ---
info "Q5c verify"
test -f "$RETENTION_MD" && echo "OK: retention policy present"
git -C /opt/dns-config-backup log --oneline -- RETENTION.md 2>/dev/null || true
curl -sSf "$POLICY_URL" > /dev/null 2>&1 && echo "OK: privacy notice published" || warn "Q5c verify: privacy notice not reachable at $POLICY_URL yet — see manual-publish step above"

CT=$(curl -sS -D- -o /tmp/keystone-q-securitytxt "http://${DOMAIN}/.well-known/security.txt" \
     | awk -F': ' 'tolower($1)=="content-type"{print tolower($2)}' | tr -d '\r')
echo "Content-Type: $CT"
case "$CT" in
  "text/plain; charset=utf-8") echo "OK: RFC 9116 compliant content type" ;;
  *) echo "FAIL: expected 'text/plain; charset=utf-8' - add 'charset utf-8;' to the server block" ;;
esac
grep -E '^(Contact|Expires):' /tmp/keystone-q-securitytxt || true
test "$(grep -c '^Expires:' /tmp/keystone-q-securitytxt)" -eq 1 && echo "OK: exactly one Expires field"
date -d "$(awk -F': ' '/^Expires:/{print $2}' /tmp/keystone-q-securitytxt)" +%s >/dev/null && echo "OK: RFC 3339 parses"
curl -sS "https://${DOMAIN}/.well-known/security.txt" 2>/dev/null | grep '^Policy:' || true

test -x /usr/local/sbin/check-securitytxt-expiry && echo "OK: expiry check installed"
grep -c 'check-securitytxt-expiry' "$CRON_FILE" 2>/dev/null || true   # expect: 1
test ! -e /etc/cron.monthly/check-securitytxt-expiry && echo "OK: no stray cron.monthly copy"
grep -q 'notify.sh warning "security.txt expiring"' /usr/local/sbin/check-securitytxt-expiry \
  && echo "OK: notify.sh called with severity and title as separate arguments"
/usr/local/sbin/check-securitytxt-expiry && echo "OK: expiry check runs clean"

{ grep -rh 'listen 80 default_server' /etc/nginx/ 2>/dev/null | grep -c . || true; } \
  | awk '{print "listen-80 default_server blocks:", $1, "(expect 1)"}'
grep -rhE '^\s*root\s' /etc/nginx/conf.d/*.conf 2>/dev/null | sort -u   # expect: only /var/www/acme

command -v certbot >/dev/null 2>&1 && certbot renew --dry-run || warn "Q5c verify: certbot not found — cannot dry-run renewal"
grep authenticator "/etc/letsencrypt/renewal/${DOMAIN}.conf" 2>/dev/null || true   # expect: webroot (or dns-<plugin>)
grep webroot_path "/etc/letsencrypt/renewal/${DOMAIN}.conf" 2>/dev/null || true    # expect: /var/www/acme

QL=$(grep -A1 '^querylog:' "$AGH_YAML" 2>/dev/null | awk '/enabled:/{print $2}')
if curl -sS "$POLICY_URL" 2>/dev/null | grep -qi 'we do not write query logs'; then
  [ "$QL" = "false" ] && echo "OK: zero-log claim matches config" \
                      || echo "FAIL: notice claims no logs but querylog.enabled=$QL"
else
  echo "INFO: notice does not make a zero-log claim - confirm it describes the 6 h ring"
fi
echo "Expected: OK: RFC 9116 compliant content type / exactly one Expires / OK: expiry check installed with exactly one cron.d line and no cron.monthly copy / exactly one listen-80 default_server block with only /var/www/acme as root / certbot renew --dry-run succeeding / no FAIL: from the published-claims check."

# =====================================================================
# Q6. Legal decisions to make and record — inherently manual (hard rule 7).
# "This is not legal advice." The decision register was already appended
# to RETENTION.md in Q5a above; this section only surfaces the context and
# checks that every row got an answer.
# =====================================================================

warn "MANUAL DECISIONS (Q6): read phases/10-privacy-and-compliance.md Q6 in full and fill in the Decision register appended to $RETENTION_MD. Key context, not automatable: a dynamic IP is personal data (CJEU C-582/14 Breyer); EDPS v SRB C-413/23 P helps a RECIPIENT of your aggregates, not you, since you hold the raw packets; provider AUP violations, not regulators, are the risk most likely to end this service — read your host's acceptable-use terms before launch; decide your preservation-order and transparency-reporting stance in advance, not under pressure."

info "Q6 verify: every decision-register row has an answer"
awk -F'|' '/^\|/ && NF>4 && $4 ~ /^[[:space:]]*$/ {print "UNANSWERED:", $2}' "$RETENTION_MD" || true
git -C /opt/dns-config-backup log -1 --format='%ci %an' -- RETENTION.md 2>/dev/null || true
echo "Expected: no UNANSWERED: lines, and a commit date you recognise."

# =====================================================================
# Q7. What Phase P changes — only relevant if the optional private-access
# layer is deployed. Verification only; Q7 owns no config of its own.
# =====================================================================

if command -v wg >/dev/null 2>&1 && wg show >/dev/null 2>&1; then
    info "Q7: WireGuard interface detected — Phase P appears to be in use. Amend the privacy notice for a private deployment per Q7 (do not simply shorten it)."
    warn "Q7: peer metadata (public key, tunnel address, endpoint IP, last handshake, all visible in 'wg show') is a durable, high-confidence identity mapping — stronger than anything the resolver itself held. Add it to the privacy notice. By default 'wg show' output is NOT captured to disk or monitoring, and it must stay that way."
    warn "Q7: revisit the CT decision (Q4) for a VPN-only/unadvertised resolver — publishing $DOMAIN to a public CT log on day one may defeat the intent of running privately; a DNS-01 wildcard is worth the extra setup here."

    info "Q7 verify"
    if [[ -n "$PUBLIC_IP" ]]; then
        dig "@${PUBLIC_IP}" google.com A +time=2 +tries=1 && warn "Q7 verify: resolver answered on the public address — expected a timeout for a private deployment" || echo "OK: connection timed out, as expected for a private resolver"
    else
        warn "Q7 verify: PUBLIC_IP unset — cannot run the public-reachability timeout check"
    fi
    wg show || true   # NOTE: contains peer endpoint IPs. Never redirect this to a file.
    grep -rl 'wg show' /etc/cron.* /etc/systemd/system /opt 2>/dev/null \
      && echo "REVIEW: something is capturing peer metadata" \
      || echo "OK: no scripted capture of wg show"
    echo "Expected: a timeout from the public address, a 'wg show' listing you recognise, and OK: no scripted capture of wg show."
else
    info "Q7: no WireGuard interface detected — Phase P does not appear to be in use on this host. Skipping Q7 (public-resolver privacy notice wording from Q5b stands unchanged)."
fi

# =====================================================================
echo
echo "Phase Q done. To confirm it worked, re-run (the source's own verification commands):"
echo "  systemctl restart adguardhome && sleep 10 && systemctl is-active adguardhome         # Q1: config accepted"
echo "  grep -i 'logging posture' $RETENTION_MD                                              # Q1: matches running config"
echo "  grep -E '^\\s*(forward-zone|forward-addr|forward-host)' -r /etc/unbound/               # Q2: expect nothing (recursive)"
echo "  for d in /var/log/adguardhome/querylog /var/lib/adguardhome/stats; do findmnt -no FSTYPE,OPTIONS \"\$d\"; done  # Q3: expect tmpfs"
echo "  curl -sS -D- -o /dev/null http://${DOMAIN}/.well-known/security.txt | grep -i content-type   # Q5c: text/plain; charset=utf-8"
echo "  awk -F'|' '/^\\|/ && NF>4 && \$4 ~ /^[[:space:]]*\$/ {print \$2}' $RETENTION_MD                # Q6: expect no output"
echo "  wg show   # if Phase P applies                                                        # Q7: peer metadata, never redirected to a file"
