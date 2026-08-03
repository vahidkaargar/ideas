#!/usr/bin/env bash
# deploy/phases/M-upgrade-rollback.sh — Phase M: Patching and Upgrades
# Source: phases/08-operations.md, "## PHASE M: Patching and Upgrades" (M1-M7)
# Read in full. Transcription only — no directive here has been invented;
# every command/flag/path is copied from that file. Read the source file
# before running this script.
#
# The rule for this entire phase, verbatim from the source: every upgrade —
# package, binary, kernel — ends by running the Phase H12 smoke gate
# (/usr/local/sbin/dns-smoke.sh). If it does not exit 0, the change is not
# finished; fix forward immediately or roll back using the procedure in this
# phase. "It came up" is not a completion criterion; SMOKE: PASS is.
#
# Sole ownership per CLAUDE.md: /etc/cron.d/dns-health and
# /usr/local/sbin/notify.sh (signature: notify.sh <severity> <title>
# [message]) are created by Phase I. This phase only APPENDS to the cron
# file below (M1, M6, M7) and CALLS notify.sh; it creates neither.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=lib/common.sh
source lib/common.sh

require_root
phase_header "Phase M — upgrade and rollback procedures"

require_cmd apt systemctl sed grep dig nginx ss curl jq sha256sum tar dpkg-query

# --- Phase-wide identifier, as used throughout M3's wrapper usage comment and
# verify block in the source (v0.107.78). Replace with the actual target
# AdGuardHome release before running against production. ---
AGH_VERSION="v0.107.78"

# =====================================================================
# M1. unattended-upgrades, with the restart window under control
# =====================================================================
phase_header "M1: unattended-upgrades, with the restart window under control"

info "M1: installing unattended-upgrades"
apt install -y unattended-upgrades

info "M1: writing /etc/apt/apt.conf.d/20auto-upgrades"
backup_file /etc/apt/apt.conf.d/20auto-upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

info "M1: writing /etc/apt/apt.conf.d/52-dns-node (security-only origins; no automatic reboot; single node)"
backup_file /etc/apt/apt.conf.d/52-dns-node
cat > /etc/apt/apt.conf.d/52-dns-node << 'EOF'
// APT configuration lists are ADDITIVE. A bare Allowed-Origins block here is APPENDED
// to the list already set in 50unattended-upgrades (read earlier, lexicographically) —
// it does not replace it. Clear the list first, then declare the security pocket only.
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";
};

// Single node: NEVER reboot on its own. An HA pair: see M6.
Unattended-Upgrade::Automatic-Reboot "false";

// Do not let apt hold the dpkg lock across a reboot-required state indefinitely.
Unattended-Upgrade::MinimalSteps "true";
EOF

info "M1: NOT adding adguardhome to Unattended-Upgrade::Package-Blacklist — it is not installed from any apt source, so unattended-upgrades can never touch it; a blacklist entry there is a comforting no-op. unbound and nginx ARE apt packages and WILL be restarted by their maintainer scripts during a security upgrade — that is intentional and correct, and M2 controls how."

# --- M1: the dns-root-data exception. It has never been published to a
# -security pocket, so the Allowed-Origins policy above freezes it
# permanently. Take it out of unattended-upgrades' hands and upgrade it on
# its own monthly schedule, appending to the one cron file (created by
# Phase I). No literal '%' in either line, deliberately — cron translates an
# unescaped '%' into a newline, which is why echo appears where printf would
# normally be preferred. ---
info "M1: appending the dns-root-data monthly-upgrade + staleness-alarm lines to /etc/cron.d/dns-health (created by Phase I; this phase only appends)"
cat >> /etc/cron.d/dns-health << 'EOF'
# dns-root-data ships only from -updates, never -security, so unattended-upgrades
# (M1) can never touch it. Monthly explicit upgrade + a staleness alarm. Unbound is
# NOT restarted here: root.hints is read at startup, and a stale-hints box is not an
# outage -- a surprise 04:40 restart is. The next planned restart picks it up.
40 4 1 * * root apt-get update -qq && out=$(apt-get install -y --only-upgrade dns-root-data 2>&1); if echo "$out" | grep -q '^Setting up dns-root-data'; then /usr/local/sbin/notify.sh info "dns-root-data upgraded" "now $(dpkg-query -W -f='${Version}' dns-root-data) - restart unbound at the next maintenance window to load the new root hints"; fi
50 4 1 * * root find /usr/share/dns/root.hints -mtime +400 -print -quit | grep -q . && /usr/local/sbin/notify.sh warning "root.hints is stale" "dns-root-data has not been updated in over 400 days - check that the monthly upgrade job above is actually running"
EOF

info "M1: cross-reference — Phase C3's unbound-anchor-guard.sh passes -r /usr/share/dns/root.hints when it re-bootstraps; stale hints degrade that recovery path. Hardening that guard is Phase C's job, not M1's."

# --- M1: verification ---
phase_header "M1 verification"
apt-config dump | grep -i 'Unattended-Upgrade::Allowed-Origins'
#   -> exactly the three security origins above, nothing inherited from 50unattended-upgrades
unattended-upgrade --dry-run --debug 2>&1 | tail -20
systemctl list-timers apt-daily-upgrade.timer --no-pager

# the dns-root-data exception
apt-cache policy dns-root-data
#   -> the installed version matches the -updates candidate, not the release-pocket one
stat -c '%y %n' /usr/share/dns/root.hints
grep -c 'dns-root-data' /etc/cron.d/dns-health          # -> 2 (upgrade job + staleness alarm)
dpkg -L dns-root-data | grep '^/usr/share/dns/'
#   -> root.ds, root.hints, root.hints.sig, root.key. If your unbound-anchor invocation
#      references any other file from this package, confirm it against this list first.

# =====================================================================
# M2. needrestart: stop it from prompting, and know what it will bounce
# =====================================================================
phase_header "M2: needrestart automatic mode"

info "M2: setting \$nrconf{restart} = 'a' — automatic restart of daemons (including unbound, nginx, and adguardhome if recognised) on a detected deleted-library restart need, without an interactive prompt that could stall an unattended apt run until the dpkg lock times out."
backup_file /etc/needrestart/needrestart.conf
sed -i "s/^#\?\$nrconf{restart}.*/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
grep -n 'nrconf{restart}' /etc/needrestart/needrestart.conf

warn "M2: needrestart's optional \$nrconf{blacklist_rc} exclusion regex has version-dependent semantics and is NOT verified here — check needrestart.conf(5) on this build before relying on it. Per source, the safer default is to leave automatic restart on and let N4's churn detector and the H12 smoke cron catch anything that fails to come back. Not configured here."

# --- M2: verification ---
phase_header "M2 verification"
needrestart -b   # -> prints NEEDRESTART-SVC lines (or none) and exits without prompting

# =====================================================================
# M3. AdGuardHome: upgrade and rollback
# =====================================================================
phase_header "M3: AdGuardHome upgrade and rollback"

info "M3: the ExecStart in /etc/systemd/system/adguardhome.service already points at /opt/adguardhome/current/AdGuardHome with --no-check-update (that unit is Phase E's, not written here) — this phase only manages what /opt/adguardhome/current resolves to and provides the upgrade/rollback wrapper."

# --- M3: one-time migration of a pre-versioned install into the
# releases/<VER> + current-symlink layout. Guarded on the legacy path
# existing — a host already built on the versioned layout (e.g. straight
# from Phase E) has nothing to migrate. Moves live binaries: confirm first. ---
if [ -d /opt/adguardhome/AdGuardHome ]; then
    confirm "M3: migrate existing /opt/adguardhome/AdGuardHome into /opt/adguardhome/releases/${AGH_VERSION}/ and point the 'current' symlink at it — continue?"
    install -d "/opt/adguardhome/releases/${AGH_VERSION}"
    mv /opt/adguardhome/AdGuardHome/* "/opt/adguardhome/releases/${AGH_VERSION}/"
    ln -sfn "/opt/adguardhome/releases/${AGH_VERSION}" /opt/adguardhome/current
    chown -R adguardhome:adguardhome /opt/adguardhome/releases
    info "M3: update any Phase D deploy-hook or Phase H reference that still points at the old (pre-migration) path — Phase D's deploy hook (phases/04-tls-certificates.md D4) already targets /opt/adguardhome/current, so nothing to change there if this repo's Phase D script has already run."
else
    info "M3: no legacy /opt/adguardhome/AdGuardHome path found — skipping the one-time migration (already on the versioned releases/ + current-symlink layout)"
fi

info "M3: three traps that bite on the first upgrade (see source for full explanation) — (1) there is NO setcap step: privileged-port binding comes from AmbientCapabilities=CAP_NET_BIND_SERVICE in the Phase E unit, not file capabilities, which NoNewPrivileges=yes nullifies across execve anyway; (2) the new binary migrates the AdGuardHome.yaml schema on first start, so the pre-migration copy taken below is the ONLY thing that makes a downgrade possible; (3) --check-config must run as the adguardhome user against a scratch work directory, never as root against the live tree, or CVE-2024-36586's permission-tightening leaves root-owned artifacts under the service user's tree and breaks the next real start."

# --- M3: install the upgrade/rollback wrapper. Writing the script itself is
# not destructive; backup_file protects a prior version of the wrapper. ---
info "M3: installing /usr/local/sbin/upgrade-adguardhome.sh"
backup_file /usr/local/sbin/upgrade-adguardhome.sh
cat > /usr/local/sbin/upgrade-adguardhome.sh << 'EOF'
#!/bin/bash
# usage: upgrade-adguardhome.sh v0.107.78
set -euo pipefail
VER="${1:?usage: upgrade-adguardhome.sh <vX.Y.Z>}"
BASE=/opt/adguardhome
STAGE="$BASE/releases/$VER"
PREV=$(readlink -f "$BASE/current")
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

curl -fsSLO "https://github.com/AdguardTeam/AdGuardHome/releases/download/${VER}/AdGuardHome_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/AdguardTeam/AdGuardHome/releases/download/${VER}/checksums.txt"
grep ' AdGuardHome_linux_amd64.tar.gz$' checksums.txt | sha256sum -c -    # aborts on mismatch

install -d "$STAGE"
tar -xzf AdGuardHome_linux_amd64.tar.gz -C "$STAGE" --strip-components=1
chown -R adguardhome:adguardhome "$STAGE"
# NO setcap. Privileged-port binding comes from AmbientCapabilities in the unit (Phase E);
# file capabilities are nullified by NoNewPrivileges=yes and would be a silent no-op here.

# Validate the LIVE config against the NEW binary BEFORE stopping anything, using COPIES
# in a scratch dir so the permission-tightening cannot touch the live tree.
install -d -o adguardhome -g adguardhome "$TMP/work"
install -o adguardhome -g adguardhome -m 0600 "$BASE/conf/AdGuardHome.yaml" "$TMP/check.yaml"
runuser -u adguardhome -- "$STAGE/AdGuardHome" --check-config -c "$TMP/check.yaml" -w "$TMP/work"

# The only thing that makes a downgrade possible.
cp -a "$BASE/conf/AdGuardHome.yaml" "$BASE/conf/AdGuardHome.yaml.pre-$VER"
echo "$PREV" > "$BASE/.prev-release"

systemctl stop adguardhome
ln -sfn "$STAGE" "$BASE/current"
systemctl start adguardhome
sleep 5

if ! /usr/local/sbin/dns-smoke.sh; then
  echo "SMOKE FAILED — rolling back to $PREV"
  systemctl stop adguardhome
  ln -sfn "$PREV" "$BASE/current"
  cp -a "$BASE/conf/AdGuardHome.yaml.pre-$VER" "$BASE/conf/AdGuardHome.yaml"
  chown adguardhome:adguardhome "$BASE/conf/AdGuardHome.yaml"
  chmod 0600 "$BASE/conf/AdGuardHome.yaml"
  systemctl start adguardhome
  sleep 5; /usr/local/sbin/dns-smoke.sh
  exit 1
fi
# keep the last 4 releases
ls -1dt "$BASE"/releases/* | tail -n +5 | xargs -r rm -rf
echo "UPGRADE OK: $VER (previous: $PREV)"
EOF
chmod 750 /usr/local/sbin/upgrade-adguardhome.sh

warn "M3: READ THE RELEASE NOTES before every AdGuardHome upgrade. Two config areas in this design have moved before and can move again: the top-level querylog: / statistics: sections (keys under dns: before v0.107.24 — Phase E), and the TLS/HTTPS listener keys the nginx DoH topology depends on (Phase E, canonical decision 5). A schema migration that relocates either one is silently accepted by the new binary and changes behaviour."

# --- M3: verification. This actually invokes the wrapper against
# AGH_VERSION, which stops and restarts adguardhome (a boot service) —
# gate it. Skip by declining the prompt if you only wanted the tooling
# installed and are not upgrading right now. ---
phase_header "M3 verification"
confirm "M3 verification: run /usr/local/sbin/upgrade-adguardhome.sh ${AGH_VERSION} now — this stops/restarts the adguardhome service and rolls back automatically on an H12 smoke-gate failure. Continue?"
/usr/local/sbin/upgrade-adguardhome.sh "$AGH_VERSION"
readlink -f /opt/adguardhome/current                     # -> .../releases/${AGH_VERSION}
systemctl show adguardhome -p AmbientCapabilities        # -> cap_net_bind_service
ss -ulnp | grep ':53 '                                   # -> AdGuardHome bound
grep -E '^schema_version:' /opt/adguardhome/conf/AdGuardHome.yaml
ls "/opt/adguardhome/conf/AdGuardHome.yaml.pre-${AGH_VERSION}"  # downgrade artifact exists
/usr/local/sbin/dns-smoke.sh; echo "exit=$?"             # -> SMOKE: PASS, exit=0

# =====================================================================
# M4. Unbound: distro package, with a trust-anchor and config-compatibility gate
# =====================================================================
phase_header "M4: Unbound upgrade — distro package, trust-anchor + config-compat gate"

info "M4: site config lives only in the drop-in directory the package already includes, never in the packaged file, so dpkg never prompts and never overwrites anything hand-written: /etc/unbound/unbound.conf (packaged, untouched, contains include: of the .d dir) vs /etc/unbound/unbound.conf.d/10-public-resolver.conf (Phase C content). That filename is canonical — do not rename it, the numeric prefix decides drop-in precedence when a second file appears."
info "M4: the trust anchor is what breaks after an upgrade. Validation depends on /var/lib/unbound/root.key being present, current, and readable by the unbound user; confirm on this build with 'systemctl cat unbound-anchor.service' that the oneshot exists and is not masked — if it is, the key is never refreshed and validation degrades to SERVFAIL on everything signed once the anchor rolls."

info "M4: installing /usr/local/sbin/upgrade-unbound.sh"
backup_file /usr/local/sbin/upgrade-unbound.sh
cat > /usr/local/sbin/upgrade-unbound.sh << 'EOF'
#!/bin/bash
set -euo pipefail
PREV=$(dpkg-query -W -f='${Version}' unbound)
cp -a /etc/unbound /var/backups/unbound.$(date -u +%Y%m%dT%H%M%SZ)
echo "$PREV" > /var/backups/unbound.prev-version

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef unbound

# The package restarts unbound itself. Gate on the config still being valid for the new
# binary — a removed or renamed directive is accepted by dpkg and rejected by unbound.
unbound-checkconf

# trust anchor still present, owned correctly, and non-trivial
test -s /var/lib/unbound/root.key
stat -c '%U %a' /var/lib/unbound/root.key

systemctl restart unbound
sleep 3
if ! /usr/local/sbin/dns-smoke.sh; then
  echo "SMOKE FAILED — rolling back unbound to $PREV"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "unbound=$PREV"
  apt-mark hold unbound
  systemctl restart unbound
  sleep 3; /usr/local/sbin/dns-smoke.sh
  exit 1
fi
echo "UNBOUND OK: $(dpkg-query -W -f='${Version}' unbound) (previous: $PREV)"
EOF
chmod 750 /usr/local/sbin/upgrade-unbound.sh

info "M4: the rollback pins with apt-mark hold, which stops unattended-upgrades from patching unbound again until the hold is released — intentional (an unattended re-upgrade into the same broken state at 03:00 is worse than a stale package), and also a landmine, which is why M7's standing guard checks for holds."

# --- M4: verification. Runs the wrapper, which does 'apt-get install -y
# --only-upgrade unbound' and restarts the unbound daemon (boot service) —
# gate it. ---
phase_header "M4 verification"
confirm "M4 verification: run /usr/local/sbin/upgrade-unbound.sh now — this upgrades the unbound package and restarts the unbound service, rolling back automatically on an H12 smoke-gate failure. Continue?"
/usr/local/sbin/upgrade-unbound.sh
unbound-checkconf                                  # -> "unbound-checkconf: no errors in ..."
unbound-control status | head -3                   # remote-control is enabled (Phase C; Phase I
                                                   # scrapes it for metrics), so this must work
dig +dnssec @127.0.0.1 -p 5335 dnssec-failed.org A | grep -c 'status: SERVFAIL'   # -> 1
dig +dnssec @127.0.0.1 -p 5335 cloudflare.com A | grep -c ' ad'                    # -> 1 (AD bit)
apt-mark showhold                                  # -> empty unless a rollback is in force
info "M4: the two dig lines above are the real gate — they prove the trust anchor survived the upgrade and that validation both rejects bad signatures and sets AD on good ones. A resolver that starts but no longer validates is the worst outcome of an Unbound upgrade, and nothing else in the smoke gate catches it."

# =====================================================================
# M5. nginx
# =====================================================================
phase_header "M5: nginx"

info "M5: nginx is an apt package and is upgraded by M1 automatically. Blast radius in this topology (canonical decision 5): nginx terminates public TLS and proxies only /dns-query to AdGuardHome's loopback HTTPS listener, so an nginx failure takes down DoH only — plain DNS on :53 and DoT/DoQ on :853 are served directly by AdGuardHome and are unaffected. Do not panic-restart the whole stack for an nginx problem."
info "M5: the only rule — never reload a configuration that has not been tested. 'reload' re-execs workers without dropping listening sockets; 'restart' briefly drops :443. Prefer reload for config changes and reserve restart for a binary upgrade that needs it."

# --- M5: reload is a boot-service action — gate it. ---
confirm "M5: run 'nginx -t && systemctl reload nginx && dns-smoke.sh' now — reloads the nginx boot service. Continue?"
nginx -t && systemctl reload nginx && /usr/local/sbin/dns-smoke.sh
#   -> nginx -t prints "syntax is ok" / "test is successful", and after reload the DoH
#      check in the smoke gate passes.

# =====================================================================
# M6. Kernel and reboots
# =====================================================================
phase_header "M6: kernel and reboots"

info "M6: Unattended-Upgrade::Automatic-Reboot \"false\" (M1) means kernel updates install but do not take effect. That is the right default and a debt that must be serviced by hand."

# --- M6: is a reboot pending, and for what? read-only. ---
test -f /var/run/reboot-required && cat /var/run/reboot-required.pkgs || info "M6: no reboot currently pending"

info "M6: appending the weekly reboot-pending alert line to /etc/cron.d/dns-health (created by Phase I; this phase only appends)"
cat >> /etc/cron.d/dns-health << 'EOF'
# appended to /etc/cron.d/dns-health (created by Phase I)
23 9 * * 1 root [ ! -f /var/run/reboot-required ] || logger -t dns-alert "reboot pending: $(tr '\n' ' ' < /var/run/reboot-required.pkgs)"
EOF

info "M6: HA pair note (Tier 3, Phase N) — if Automatic-Reboot \"true\" with Automatic-Reboot-Time \"03:00\" is ever set on an HA pair, stagger the two nodes by at least an hour. Two nodes rebooting into the same kernel regression at the same minute converts redundancy into a synchronised outage. Not applicable / not configured on a single node (this repo's default)."
info "M6: Ubuntu Livepatch covers kernel CVEs without a reboot (free for a small number of personal machines) and defers userspace reboots rather than eliminating them; enrolment details are provider-side and NOT verified here."

warn "MANUAL STEP (M6): there is no honest zero-downtime reboot story for a single node. Reboot in your lowest-traffic window, announce it if you have users who will notice, and expect 20-60 seconds of total unavailability. This is a human timing decision and is NOT scripted here — do not automate a reboot from this script."
warn "MANUAL STEP (M6 verify, post-reboot): after any reboot, confirm /usr/local/sbin/dns-smoke.sh exits 0 AND every unit in the M7 guard list reports 'enabled', not merely 'active'. Not scripted here — run by hand after the reboot above."

# =====================================================================
# M7. Standing guards
# =====================================================================
phase_header "M7: standing guards"

info "M7: two failure modes are invisible until the worst possible moment — a unit that is running but not enabled (dies at the next reboot), and a package pinned by an emergency rollback that never got released. Appending both guards to /etc/cron.d/dns-health (created by Phase I; this phase only appends)."
cat >> /etc/cron.d/dns-health << 'EOF'
17 * * * * root for u in unbound adguardhome nginx nftables restic-backup.timer; do systemctl is-enabled --quiet $u || logger -t dns-alert -p daemon.crit "CRITICAL: $u is DISABLED — will not survive reboot"; done
41 9 * * * root h=$(apt-mark showhold); [ -z "$h" ] || logger -t dns-alert "package hold still in force: $h"
EOF

info "M7: the completion rule, restated because it is the whole point of this phase — an upgrade is finished when /usr/local/sbin/dns-smoke.sh (Phase H12) exits 0. Not when apt returns, not when 'systemctl is-active' says active. The wrappers above (M3, M4) enforce it and roll back on failure; do the same by hand for anything not covered by a wrapper."

# =====================================================================
# Phase M — summary
# =====================================================================
phase_header "Phase M — verification summary"
echo "Phase M installs the upgrade/rollback tooling and standing guards. What 'this worked' looks like:"
echo "  /usr/local/sbin/dns-smoke.sh                              -> SMOKE: PASS, exit 0 (the phase-wide completion rule)"
echo "  apt-config dump | grep -i Allowed-Origins                 -> exactly the 3 security origins (M1)"
echo "  grep -c dns-root-data /etc/cron.d/dns-health               -> 2 (M1)"
echo "  needrestart -b                                             -> no interactive prompt (M2)"
echo "  readlink -f /opt/adguardhome/current                       -> points at the current AdGuardHome release (M3)"
echo "  dig +dnssec @127.0.0.1 -p 5335 cloudflare.com A | grep -c ' ad'  -> 1 (M4, validation survived the upgrade)"
echo "  apt-mark showhold                                          -> empty unless a rollback is in force (M4, M7)"
echo "  nginx -t                                                   -> syntax is ok / test is successful (M5)"
echo "See the MANUAL STEP warnings above (M6 reboot timing, M6 post-reboot enabled-check) for what this script deliberately does not automate."
