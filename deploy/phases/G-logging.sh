#!/usr/bin/env bash
# deploy/phases/G-logging.sh — Phase G: Log Rotation and Retention
# Source: phases/06-logging-and-validation.md, "PHASE G: Log Rotation and
# Retention" section (steps G1-G4 only). Phase F on that page is retired
# (skip) and Phase H (acceptance tests) is a separate script.
#
# Mechanical transcription — read the source section before running this.
# This phase owns only the mechanics of what rotates and what stops the disk
# filling. What the retention numbers should be, and whether a per-query log
# should exist at all, is a Phase Q decision (see G2 below) — this script
# does not decide that, it wires the plumbing Phase Q's decision sits on top
# of.
#
# Writers on a v2 host, for reference (see the table in G's source section):
#   Unbound daemon log      -> journald                    (G1)
#   AdGuardHome daemon log  -> journald                    (G1)
#   AdGuardHome query log   -> querylog.json (Phase E path) (G2 — AGH self-rotates, never logrotate)
#   AdGuardHome stats.db    -> bolt DB, not a log           (G2 — never logrotate)
#   nginx error.log         -> packaged /etc/logrotate.d/nginx (G3)
#   certbot                 -> packaged /etc/logrotate.d/certbot (not this phase)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=../lib/common.sh
source ../lib/common.sh

require_root
require_cmd systemctl journalctl logrotate du df grep awk

phase_header "Phase G — log rotation and retention"

# =====================================================================
# G1. journald retention limits
# =====================================================================
# On a default Ubuntu 24.04 install SystemMaxUse is 10% of the filesystem,
# capped at 4 GB, and it self-limits quietly. Pin it.

info "G1: writing /etc/systemd/journald.conf.d/10-dns.conf"
# --- G1: journald retention limits ---
install -d -m 0755 /etc/systemd/journald.conf.d
backup_file /etc/systemd/journald.conf.d/10-dns.conf
cat > /etc/systemd/journald.conf.d/10-dns.conf << 'EOF'
[Journal]
Storage=persistent
SystemMaxUse=512M
SystemKeepFree=2G
SystemMaxFileSize=64M
SystemMaxFiles=16
RuntimeMaxUse=64M
MaxRetentionSec=14day
# Do not duplicate everything into /var/log/syslog as well.
ForwardToSyslog=no
EOF

# systemd-journald is a boot service; restarting it applies the new limits
# (and can vacuum existing journal data down to the new ceiling immediately).
confirm "About to restart systemd-journald to apply the new retention limits (SystemMaxUse=512M, MaxRetentionSec=14day) — this can vacuum existing journal data immediately. Continue?"
systemctl restart systemd-journald

# rsyslog interaction: informational only, no change scripted here — the
# source gives no unconditional action, only a conditional to check by hand.
if command -v rsyslogd >/dev/null 2>&1; then
    warn "rsyslog is present on this host. With ForwardToSyslog=no (set above) it stops receiving a second copy of journal entries. If you would rather keep syslog instead, edit ForwardToSyslog to yes in 10-dns.conf above and confirm /etc/logrotate.d/rsyslog exists — otherwise you have an unbounded second copy of the journal. MANUAL DECISION — not made by this script."
fi

warn "G1 privacy note (Phase Q owns the decision): if Unbound's log-queries/log-replies are ever turned on, the journal becomes a full query log with unmasked client IPs, retained per the limits above. Phase Q's retention statement must cover the journal, not only querylog.json. Do not enable those keys as a debugging convenience and forget them."

# --- G1: verify ---
info "G1 verify: journalctl --disk-usage should be well under 512M once trimmed"
journalctl --disk-usage
journalctl --header | grep -i 'max\|retention' || true
systemd-analyze cat-config systemd/journald.conf | grep -E 'SystemMaxUse|MaxRetentionSec|ForwardToSyslog'
journalctl -u unbound -n 5 --no-pager || warn "no unbound journal entries yet — expected if Phase C has not run / unbound is not started"
journalctl -u adguardhome -n 5 --no-pager || warn "no adguardhome journal entries yet — expected if Phase E has not run / adguardhome is not started"

# =====================================================================
# G2. The AdGuardHome query log — the real disk risk
# =====================================================================
# This is the single most likely way the service dies in week one, and
# logrotate has nothing to do with it. Three rules from the source, in order.

# --- G2(a): never point logrotate at querylog.json or stats.db ---
# AdGuardHome holds these files open and rotates/manages them itself. A
# logrotate stanza would rename the inode out from under a process that gets
# no signal from it (querylog.json), or touch a bolt DB that is not a log at
# all (stats.db).
info "G2(a): checking no /etc/logrotate.d/* stanza manages querylog.json or stats.db"
if grep -rn 'querylog\.json\|stats\.db' /etc/logrotate.d/ 2>/dev/null; then
    warn "MANUAL ACTION REQUIRED: a logrotate stanza above references querylog.json or stats.db (matches printed above). AdGuardHome self-rotates these — a logrotate rename here corrupts rotation. Edit the offending /etc/logrotate.d/* file by hand and delete those lines. The source markdown gives no exact sed/removal command for this, so it is intentionally not auto-edited here."
else
    info "OK: logrotate does not touch AGH data"
fi

# --- G2(b): bound the query log in AdGuardHome's own config, not here ---
# The querylog: keys (file_enabled, interval, size_memory, dir_path) live in
# /opt/adguardhome/conf/AdGuardHome.yaml and are Phase E's to write, including
# the two-pass procedure that stops AGH's schema migration from overwriting
# the block. This phase does not write or alter that config — it only
# verifies the plumbing below. Do not duplicate Phase E's write here.

# --- G2(c): size the interval against measured QPS, not guessed QPS ---
warn "MANUAL STEP (G2c): after the H11 load test, re-run the disk-fill arithmetic in phases/06-logging-and-validation.md G2 against your own measured QPS, and record the result in the Phase L checklist. Not automatable from this script."

# --- G2: verify ---
info "G2 verify: querylog/statistics plumbing"
grep -n -A6 -E '^(querylog|statistics):' /opt/adguardhome/conf/AdGuardHome.yaml || warn "AdGuardHome.yaml not found — expected if Phase E has not run yet"
grep -c 'querylog_' /opt/adguardhome/conf/AdGuardHome.yaml || true     # expect 0 (pre-0.107.24 keys)
grep -rn 'querylog.json\|stats.db' /etc/logrotate.d/ || echo 'OK: logrotate does not touch AGH data'

# The expected result of the next check depends on the posture in force
# (Phase Q), so read the config before scoring it - do not assume either answer:
grep -n 'file_enabled' /opt/adguardhome/conf/AdGuardHome.yaml || true

# With the shipped default (file_enabled: false) there must be no file at all:
ls -l /var/log/adguardhome/querylog/querylog.json* 2>&1 || true   # expect: No such file or directory
# If the posture in force sets file_enabled: true, the file is EXPECTED to exist -
# score it against the arithmetic above (2 x interval retained, no size cap) instead.

# stats.db exists under /var/lib/adguardhome/stats whether or not statistics
# are enabled — AdGuardHome opens it before it reads Enabled (Phase E).
# Asserting its absence is a test that can never pass, in any posture.

# Growth check under real load — the source says to run this ALONGSIDE the
# H11 warm run, not as part of a routine Phase G deploy. Defined as a
# function rather than executed inline so this script does not silently
# block for 10 minutes on every run; the exact commands are unchanged.
g2_growth_check_during_h11() {
    info "G2 growth check: sampling both AGH data directories over a 10-minute window"
    du -sb /var/log/adguardhome /var/lib/adguardhome
    sleep 600
    du -sb /var/log/adguardhome /var/lib/adguardhome
    # PASS: combined growth < 20 MB over 10 minutes at the target QPS.
    # That threshold assumes the shipped default (no query log on disk). If the
    # posture in force sets file_enabled: true, 20 MB is the wrong gate -
    # recompute the expected growth from the bytes-per-query arithmetic above
    # and score against that.
}
warn "G2 growth check is defined as the shell function g2_growth_check_during_h11 in this script but not run automatically — the source says to run it ALONGSIDE the H11 warm run. Source it and call the function during that test: 'source deploy/phases/G-logging.sh; g2_growth_check_during_h11' (or run the du/sleep/du sequence by hand)."

# =====================================================================
# G3. nginx
# =====================================================================
# nginx ships its own /etc/logrotate.d/nginx with a postrotate that sends
# USR1. Do not write a second stanza for the same files — confirm the
# packaged one is present and leave it alone.

info "G3: confirming the packaged nginx logrotate stanza is present and untouched"
# --- G3: verify (no changes made in this section, packaged stanza owns this) ---
test -f /etc/logrotate.d/nginx && echo 'OK: packaged stanza present' \
    || warn "MANUAL ACTION: /etc/logrotate.d/nginx is missing — expected if nginx (Phase E) is not installed yet. Do not write a replacement stanza yourself; reinstall/repair the nginx package instead."

grep -rn 'error_log' /etc/nginx/nginx.conf /etc/nginx/sites-enabled/ 2>/dev/null | grep -vi 'warn\|crit\|error' \
    && warn "a verbose error_log level was found above — keep it at 'warn' or stricter; 'info'/'debug' on a public :443 listener will out-write the disabled query log" \
    || echo 'OK: no verbose error_log level'

logrotate -d /etc/logrotate.d/nginx 2>&1 | tail -5 || true     # dry run, no errors

info "G3: the behavioural proof that access logging is actually off (a real request producing no log line) belongs to Phase Q, which owns that decision — not duplicated here."

# =====================================================================
# G4. Disk-pressure guard
# =====================================================================
# The guard for the unexpected writer: a debug flag left on, a core dump, an
# apt cache, a runaway backup. Logic lives in a script, not the crontab — a
# literal '%' inside a crontab command line is a command terminator, which
# silently breaks the obvious one-liner form of this check.

info "G4: installing /usr/local/sbin/dns-diskguard.sh"
backup_file /usr/local/sbin/dns-diskguard.sh
cat > /usr/local/sbin/dns-diskguard.sh << 'EOF'
#!/bin/bash
set -uo pipefail
THRESH=${THRESH:-85}
USED=$(df --output=pcent / | tr -dc '0-9')
if [ "${USED:-0}" -ge "$THRESH" ]; then
  logger -t dns-alert -p daemon.crit "DISK ${USED}% on / (threshold ${THRESH}%)"
  du -xh -d2 /var /opt 2>/dev/null | sort -rh | head -10 | logger -t dns-alert
  exit 1
fi
exit 0
EOF
chmod 750 /usr/local/sbin/dns-diskguard.sh

# /etc/cron.d/dns-health is created and owned by Phase I. This phase only
# appends a line to it and must not write its own copy of the file.
CRON_FILE=/etc/cron.d/dns-health
CRON_LINE='*/5 * * * * root /usr/local/sbin/dns-diskguard.sh'
if [[ ! -e "$CRON_FILE" ]]; then
    warn "$CRON_FILE does not exist — it is created by Phase I, not this phase. Run Phase I first; skipping the diskguard cron append until then."
else
    if grep -qF "$CRON_LINE" "$CRON_FILE" 2>/dev/null; then
        info "diskguard line already present in $CRON_FILE — skipping duplicate append"
    else
        confirm "About to append a line to $CRON_FILE (Phase I-owned root cron file, runs as root every 5 minutes): '$CRON_LINE' — continue?"
        backup_file "$CRON_FILE"
        echo "$CRON_LINE" >> "$CRON_FILE"
        info "appended diskguard line to $CRON_FILE"
    fi
fi

warn "Routing the diskguard's logger line to a human is Phase I's job, through the single notification entry point /usr/local/sbin/notify.sh that Phase I defines — a logger call nobody reads is not an alert. Not this phase's responsibility."

# --- G4: verify ---
info "G4 verify: exit=0 expected on a healthy box; forced THRESH=1 run must exit=1 and log a dns-alert"
set +e
/usr/local/sbin/dns-diskguard.sh
rc=$?
set -e
echo "exit=$rc"

set +e
THRESH=1 /usr/local/sbin/dns-diskguard.sh
rc=$?
set -e
echo "exit=$rc (expect 1)"

journalctl -t dns-alert --since -1m --no-pager || true   # the forced failure must appear
df -h /

# =====================================================================
echo
echo "Phase G done. To confirm it worked, re-run (the source's own verification commands):"
echo "  journalctl --disk-usage                                                       # G1: well under 512M once trimmed"
echo "  systemd-analyze cat-config systemd/journald.conf | grep -E 'SystemMaxUse|MaxRetentionSec|ForwardToSyslog'"
echo "  grep -n -A6 -E '^(querylog|statistics):' /opt/adguardhome/conf/AdGuardHome.yaml   # G2: plumbing matches Phase E's config"
echo "  ls -l /var/log/adguardhome/querylog/querylog.json*                            # G2: expect No such file (shipped default)"
echo "  logrotate -d /etc/logrotate.d/nginx                                           # G3: dry run, no errors"
echo "  THRESH=1 /usr/local/sbin/dns-diskguard.sh; echo \$?                            # G4: expect 1, plus a dns-alert log line"
echo "  during H11: source this script and call g2_growth_check_during_h11            # G2: combined AGH data growth < 20 MB / 10 min"
