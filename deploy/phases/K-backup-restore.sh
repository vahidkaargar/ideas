#!/usr/bin/env bash
# deploy/phases/K-backup-restore.sh — Phase K: Backup, Restore and Secrets
# Source: phases/08-operations.md, "PHASE K: Backup, Restore and Secrets"
# section (K1-K8 only). Phases M (Patching and Upgrades), N (High
# Availability), and O (Provisioning and Reproducibility), on the same source
# page, are separate scripts — skipped here entirely.
#
# Mechanical transcription — read the source section before running this.
#
# Ownership (CLAUDE.md single-ownership table):
#   - /opt/dns-config-backup is Phase A3's object (created there). This
#     script never creates or deletes it — it only reads it (K3 include list,
#     K5e/K8 verification greps against its INVENTORY.md).
#   - /usr/local/sbin/notify.sh and /etc/cron.d/dns-health are Phase I's
#     objects (created there). This script only calls notify.sh and appends
#     one line to dns-health — it never rewrites either file.
#   - nftables tables/chains/sets are Phase B's objects. This script does not
#     touch nftables configuration.
# If a name here ever disagrees with those phases, they are right and this
# script is stale.
#
# K5e (rotation), K7 (Tier 2 full DR rebuild — runs on a scratch VPS from
# your workstation, never this node) and parts of K8 (second-operator
# onboarding, key escrow, pre-absence checklist) are runbook material a human
# invokes ad hoc — on a schedule, before an absence, or after a compromise —
# not deploy steps. They are preserved verbatim as "NOTE, informational, not
# scripted" comment blocks rather than auto-executed, matching this repo's
# existing convention (see B-firewall.sh B7/B8, J-abuse-detection.sh J7/J8).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=../lib/common.sh
source ../lib/common.sh

require_root
require_cmd curl jq openssl sha256sum bunzip2 systemctl nft runuser unbound-checkconf nginx sed awk grep stat logger mktemp

phase_header "Phase K — off-host backup and restore drill"

# =====================================================================
# K intro. Retire the v1 mechanism, not the v1 directory
# =====================================================================
# The v1 plan copied five files into a git repo on the node itself, which
# dies with the node it was protecting and omitted /etc/letsencrypt, every
# systemd unit, the renewal deploy hook, and every operational script.

info "K intro: retiring the v1 daily config-copy job; restic (below) replaces it"
if [ -f /etc/cron.daily/dns-backup ]; then
    confirm "K intro: about to remove /etc/cron.daily/dns-backup (the v1 daily config-copy job). Continue?"
    rm -f /etc/cron.daily/dns-backup      # the v1 daily copy job; restic replaces it
else
    info "K intro: /etc/cron.daily/dns-backup not present — nothing to retire"
fi

warn "K intro: do NOT rm -rf /opt/dns-config-backup. It is Phase A3's object (install -d + git init) — Phase I, Phase J and Phase Q write to it, and its .git is Phase A's own history, not a v1 leftover. Phase K only reads it (K3 include list) and ships it off-host; it never creates or deletes it. Nothing under this path is safe to delete."

# =====================================================================
# K1. Install restic (pinned upstream binary, checksum-verified)
# =====================================================================
# Ubuntu 24.04 packages restic and the packaged version is adequate; pin the
# upstream static binary anyway so a verified-checksum version is known
# ahead of the one outage where this tool's failure would be discovered.
#
# If you prefer the distro package (apt install restic) instead, change the
# ExecStart= paths in K4 below from /usr/local/bin/restic to /usr/bin/restic.

info "K1: installing pinned upstream restic binary"
# --- K1: pinned restic install ---
apt install -y jq bzip2
RESTIC_VER=$(curl -fsS https://api.github.com/repos/restic/restic/releases/latest | jq -r .tag_name | tr -d v)
TMP=$(mktemp -d); cd "$TMP"
curl -fsSLO "https://github.com/restic/restic/releases/download/v${RESTIC_VER}/restic_${RESTIC_VER}_linux_amd64.bz2"
curl -fsSLO "https://github.com/restic/restic/releases/download/v${RESTIC_VER}/SHA256SUMS"
grep "restic_${RESTIC_VER}_linux_amd64.bz2" SHA256SUMS | sha256sum -c -   # aborts on mismatch
bunzip2 -c "restic_${RESTIC_VER}_linux_amd64.bz2" > /usr/local/bin/restic
chmod 0755 /usr/local/bin/restic
cd /; rm -rf "$TMP"
restic version

# --- K1 verify ---
restic version                     # -> prints a version
restic --help >/dev/null; echo "restic --help exit=$? (0 expected)"

# =====================================================================
# K2. Repository and key handling
# =====================================================================
# The repository password is the only thing standing between the backup
# provider and the TLS private keys, and the only thing that can decrypt the
# backup. It is generated on the node and lives in the operator's password
# manager — restic has no key escrow and there is no recovery path.

info "K2: repository and key handling"
if marker_done "K2-restic-repo-init"; then
    info "K2: marker present — /etc/restic was already initialized by a previous run of this script. Skipping key generation and 'restic init' to avoid regenerating a password that would orphan the existing repository."
    [ -f /etc/restic/dns.env ] || fatal "K2: completion marker present but /etc/restic/dns.env is missing — state is inconsistent, investigate manually before continuing."
else
    install -d -m 0700 /etc/restic

    if [ -e /etc/restic/repo.pass ]; then
        fatal "K2: /etc/restic/repo.pass already exists but no K2 completion marker was found — refusing to regenerate it, which would orphan whatever repository it currently unlocks. Investigate manually (see K8 for the correct way to add a second key without discarding this one)."
    fi

    # --- K2: generate the repository password ---
    openssl rand -base64 48 > /etc/restic/repo.pass
    chmod 600 /etc/restic/repo.pass

    warn "K2: >>> COPY /etc/restic/repo.pass INTO YOUR PASSWORD MANAGER NOW, BEFORE CONTINUING. <<<"
    warn "K2: if this string only exists on this host, losing the host loses every backup taken from it. restic has no key escrow — there is no recovery path."
    confirm "K2: have you copied /etc/restic/repo.pass into your password manager? This is the ONLY copy of the repository password. Continue?"

    # --- K2: object-storage repository config (business/provider decision —
    # the values below are the plan's Backblaze B2 example, not real
    # credentials) ---
    warn "K2: MANUAL STEP — /etc/restic/dns.env below is written with PLACEHOLDER values (RESTIC_REPOSITORY, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY). Choosing the object-storage provider/bucket and obtaining application keys is a business decision this script cannot make. Edit the file with your real values before 'restic init' below can succeed."
    backup_file /etc/restic/dns.env
    cat > /etc/restic/dns.env << 'EOF'
RESTIC_REPOSITORY=s3:s3.eu-central-003.backblazeb2.com/my-dns-backups/dns1
RESTIC_PASSWORD_FILE=/etc/restic/repo.pass
AWS_ACCESS_KEY_ID=<application-key-id>
AWS_SECRET_ACCESS_KEY=<application-key>
EOF
    chmod 600 /etc/restic/dns.env

    warn "K2: scope the object-storage credential to this one bucket with write and list rights, and do NOT grant delete rights if your provider can express that separately — an attacker who can delete the backup has removed your recovery path. Where available, enable object-lock/immutability with retention slightly longer than K4's --keep-monthly window. Exact syntax is provider-specific and is NOT verified here — check your provider's documentation."

    confirm "K2: /etc/restic/dns.env has been edited with real object-storage credentials (not the placeholders above) and is ready. Proceed with 'restic init' against that repository?"

    # --- K2: restic init ---
    set -a; . /etc/restic/dns.env; set +a
    restic init

    mark_done "K2-restic-repo-init"
fi

# --- K2 verify ---
set -a; . /etc/restic/dns.env; set +a
restic cat config | jq '.version'      # -> repository format version, proves the repo opened

# =====================================================================
# K3. What is backed up, and what deliberately is not
# =====================================================================
# Every exclusion below is deliberate (query log and stats DB are personal
# data and worthless for DR; sessions.db holds live admin credentials;
# work/data/filters is regenerated on demand; repo.pass would be circular
# inside the repository it unlocks). /etc/letsencrypt must be taken whole —
# live/*.pem are symlinks into archive/. /etc/nftables.d/dns-allow.nft (Phase
# B's hand-maintained allowlist file) is listed individually because
# /etc/nftables.conf alone does not sweep it in.

info "K3: writing restic include/exclude lists"
# --- K3: include list ---
backup_file /etc/restic/include.txt
cat > /etc/restic/include.txt << 'EOF'
/etc/unbound
/etc/nginx
/etc/nftables.conf
/etc/nftables.d/dns-allow.nft
/etc/keepalived
/etc/wireguard
/etc/letsencrypt
/etc/systemd/system
/etc/cron.d
/etc/logrotate.d
/etc/prometheus
/etc/alertmanager
/etc/blackbox_exporter
/opt/adguardhome/conf
/opt/dns-config-backup
/usr/local/sbin
/var/lib/unbound/root.key
EOF

# --- K3: exclude list ---
backup_file /etc/restic/exclude.txt
cat > /etc/restic/exclude.txt << 'EOF'
/var/log/adguardhome/querylog
/var/lib/adguardhome/stats
/opt/adguardhome/work/data/sessions.db
/opt/adguardhome/work/data/filters
/etc/restic/repo.pass
EOF

# K3's own verify block runs after the first backup exists — see the "K3
# verify (post-first-backup)" block immediately after K4 below.

# =====================================================================
# K4. Backup service and timer
# =====================================================================
# Type=oneshot with multiple ExecStart= lines runs them in order, aborting
# on the first non-zero exit. `5%%` is not a typo — a literal `%` must be
# escaped as `%%` in a systemd unit file or the unit fails to load with a
# specifier error. OOMScoreAdjust=500 makes backup the first thing the
# kernel takes under memory pressure, never the resolver (Phase A6 owns the
# resolver's ceilings and negative OOM bias) — do NOT add MemoryMax here, a
# prune of a large repository legitimately needs memory.

info "K4: installing restic-backup.service and restic-backup.timer"
# --- K4: restic-backup.service ---
backup_file /etc/systemd/system/restic-backup.service
cat > /etc/systemd/system/restic-backup.service << 'EOF'
[Unit]
Description=Off-host encrypted backup of DNS node config and cert state
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/restic/dns.env
Nice=10
IOSchedulingClass=idle
# Backup is the one expendable workload on this box. If memory gets tight the kernel
# should take this, never the resolver — the resolver's ceilings and negative OOM bias
# are Phase A6's, and this positive score is the counterweight to them. Do NOT set
# MemoryMax here: a prune of a large repository legitimately needs memory, and killing
# it mid-prune leaves work to redo.
OOMScoreAdjust=500
ExecStart=/usr/local/bin/restic backup --tag dns-config --files-from /etc/restic/include.txt --exclude-file /etc/restic/exclude.txt
ExecStart=/usr/local/bin/restic forget --tag dns-config --prune --keep-daily 14 --keep-weekly 8 --keep-monthly 12
ExecStart=/usr/local/bin/restic check --read-data-subset=5%%
EOF

# --- K4: restic-backup.timer ---
backup_file /etc/systemd/system/restic-backup.timer
cat > /etc/systemd/system/restic-backup.timer << 'EOF'
[Unit]
Description=Daily off-host backup

[Timer]
OnCalendar=*-*-* 03:17:00
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Persistent=true runs a missed backup after a reboot rather than skipping
# the day. RandomizedDelaySec=900 matters on an HA pair: without it both
# nodes hammer the object store at the same instant.

confirm "K4: about to enable+start restic-backup.timer (daily 03:17 UTC +/-15min off-host encrypted backup, persistent across reboots) and immediately run the first restic-backup.service pass, which uploads the K3 include list to off-host object storage. Continue?"
# --- K4: enable timer and run the first backup ---
systemctl daemon-reload && systemctl enable --now restic-backup.timer
systemctl start restic-backup.service    # first run, foreground-ish

# --- K4 verify ---
systemctl list-timers restic-backup.timer --no-pager
#   -> NEXT column populated, LEFT non-negative
journalctl -u restic-backup.service -n 30 --no-pager | grep -E 'snapshot|Added to the repository'
set -a; . /etc/restic/dns.env; set +a; restic snapshots --tag dns-config | tail -5

# --- K3 verify (post-first-backup) ---
info "K3 verify: checking the first snapshot for expected inclusions/exclusions"
restic ls latest | grep letsencrypt/archive
restic ls latest | grep -E '^/etc/(prometheus|alertmanager|blackbox_exporter)/'
restic ls latest | grep -c dns-config-backup
restic ls latest | grep -c 'nftables.d/dns-allow.nft'
restic ls latest | grep -c querylog   # -> 0

# =====================================================================
# K5. Secrets: what never enters source control, and where it actually lives
# =====================================================================
# The rule is mechanical: anything that grants access lives in the vault or
# on the node, never in a config repo. Treat any secret that was ever
# committed as disclosed and rotate it (K5e). The never-commit table itself
# (AGH admin bcrypt hash, TLS private keys, restic repo password,
# object-storage keys, Certbot DNS-01 token, keepalived auth_pass, provider
# API token, Phase P WireGuard keys) is reference material, not shell — see
# K5 in the source for the full table.

# --- K5a: correct ownership on the live files ---
# AdGuardHome rewrites its own configuration at runtime, so its config file
# must be owned/writable by the service user, and since v0.107.53 AGH
# actively tightens permissions on files it touches (CVE-2024-36586
# hardening), so anything left root-owned inside its tree becomes a startup
# failure later. (The matching `install -d -o adguardhome -g adguardhome -m
# 0700` fix for the Phase D renewal deploy hook is Phase D's file, not
# scripted here.)
info "K5a: fixing ownership/permissions on live AdGuardHome and restic secret files"
chown adguardhome:adguardhome /opt/adguardhome/conf/AdGuardHome.yaml
chmod 0600 /opt/adguardhome/conf/AdGuardHome.yaml
chown adguardhome:adguardhome /opt/adguardhome/conf/ssl
chmod 0700 /opt/adguardhome/conf/ssl
chmod 600 /etc/restic/dns.env /etc/restic/repo.pass

# --- K5b: template the secret out of the repo ---
# Operates on the Ansible control repo (/srv/dns-infra — Phase O's layout),
# which may live on this node, the operator's workstation, or a separate
# control host. Skipped if the repo is not present here.
if [ -d /srv/dns-infra ]; then
    require_cmd ansible-vault
    if marker_done "K5b-vault-yml-created"; then
        info "K5b: marker present — group_vars/dns/vault.yml was already created by a previous run. Not re-templating over live secrets; edit it by hand (ansible-vault edit) if a value needs to change."
    else
        install -d /srv/dns-infra/group_vars/dns
        warn "K5b: MANUAL/BUSINESS STEP — every value below (agh_admin_bcrypt, restic_password, b2_key_id, b2_secret_key, cloudflare_api_token, keepalived_auth_pass, provider_api_token) is a PLACEHOLDER from the plan. Replace each with your own generated secret before encrypting."
        backup_file /srv/dns-infra/group_vars/dns/vault.yml
        cat > /srv/dns-infra/group_vars/dns/vault.yml << 'EOF'
agh_admin_bcrypt: "$2y$12$..."
restic_password: "<repo-pass>"
b2_key_id: "<application-key-id>"
b2_secret_key: "<application-key>"
cloudflare_api_token: "<Zone:DNS:Edit on one zone>"
keepalived_auth_pass: "8charmax"
provider_api_token: "<floating-IP scope only>"
EOF
        confirm "K5b: about to ansible-vault encrypt /srv/dns-infra/group_vars/dns/vault.yml in place (encrypts the WHOLE file — a partial encrypt_string leaves variable names and structure in the clear). Continue?"
        ansible-vault encrypt --vault-id prod@prompt /srv/dns-infra/group_vars/dns/vault.yml
        mark_done "K5b-vault-yml-created"
    fi

    # --- K5b: repo-level guard against re-committing a secret ---
    backup_file /srv/dns-infra/.gitignore
    cat >> /srv/dns-infra/.gitignore << 'EOF'
*.pem
*.key
*.env
AdGuardHome.yaml
!roles/adguardhome/templates/AdGuardHome.yaml.j2
repo.pass
cloudflare.ini
/etc-backup/
EOF
else
    warn "K5b: /srv/dns-infra not present on this host — skipping vault.yml/.gitignore steps. Run K5b on whichever host holds the Ansible control repo (Phase O)."
fi

# --- K5c: runtime secrets via systemd credentials (LoadCredential=,
# requires systemd >= 247; Ubuntu 24.04 ships systemd 255). The keepalived
# unit itself is Phase N3's object — this drop-in is the concrete instance
# of the LoadCredential pattern K5c describes; the consuming script under
# N3 reads "$CREDENTIALS_DIRECTORY/provider" and must run as root because
# the credential tmpfs is owned by the unit's user. ---
info "K5c: installing keepalived LoadCredential= drop-in"
confirm "K5c: about to write /etc/systemd/system/keepalived.service.d/creds.conf (adds LoadCredential=provider:/etc/keepalived/provider.token to the keepalived unit) and daemon-reload. keepalived itself is NOT restarted by this script — restart it per Phase N when ready. Continue?"
install -d /etc/systemd/system/keepalived.service.d
backup_file /etc/systemd/system/keepalived.service.d/creds.conf
cat > /etc/systemd/system/keepalived.service.d/creds.conf << 'EOF'
[Service]
LoadCredential=provider:/etc/keepalived/provider.token
EOF
systemctl daemon-reload

# --- K5d: pre-commit tripwire (per-clone, not versioned — mirror the same
# grep as a CI job so a clone without the hook still gets caught) ---
if [ -d /srv/dns-infra/.git ]; then
    info "K5d: installing pre-commit secret-pattern tripwire"
    backup_file /srv/dns-infra/.git/hooks/pre-commit
    cat > /srv/dns-infra/.git/hooks/pre-commit << 'EOF'
#!/bin/bash
if git diff --cached -U0 | grep -nE '\$2[aby]\$[0-9]{2}\$|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AWS_SECRET|api_token *[:=]'; then
  echo "REFUSED: this diff contains something that looks like a secret." >&2
  exit 1
fi
EOF
    chmod +x /srv/dns-infra/.git/hooks/pre-commit
else
    warn "K5d: /srv/dns-infra/.git not present on this host — skipping pre-commit tripwire install. Install it on whichever host holds a clone of the Ansible control repo, and mirror the same grep as a CI job."
fi

# --- K5 verify ---
info "K5 verify: ownership/permissions, adguardhome restart cleanliness, repo secret scan, credential mount"
stat -c '%U:%G %a %n' /opt/adguardhome/conf/AdGuardHome.yaml /opt/adguardhome/conf/ssl \
  /opt/adguardhome/conf/ssl/privkey.pem /etc/restic/dns.env /etc/restic/repo.pass
#   -> adguardhome:adguardhome 600 (yaml); adguardhome:adguardhome 700 (ssl dir); 600 on the rest

confirm "K5 verify: about to restart adguardhome to confirm the K5a ownership fix left no permission errors. This is a brief service restart. Continue?"
systemctl restart adguardhome && sleep 5
journalctl -u adguardhome -n 40 --no-pager | grep -iE 'permission|denied|no such file'; echo "grep exit=$? (1 = clean)"

if [ -d /srv/dns-infra/.git ]; then
    (cd /srv/dns-infra && git log --all -p | grep -cE '\$2[aby]\$[0-9]{2}\$|BEGIN (RSA |EC )?PRIVATE KEY')   # -> 0
    (cd /srv/dns-infra && git ls-files | grep -E '\.pem$|\.env$|repo\.pass|cloudflare\.ini') || true         # -> no output
    head -1 /srv/dns-infra/group_vars/dns/vault.yml | grep -q '^\$ANSIBLE_VAULT;' && echo file-is-encrypted
    ansible-vault view /srv/dns-infra/group_vars/dns/vault.yml --vault-id prod@prompt >/dev/null && echo vault-ok
fi

systemd-run -p LoadCredential=provider:/etc/keepalived/provider.token --wait --pipe \
  /bin/sh -c 'test -s "$CREDENTIALS_DIRECTORY/provider" && echo cred-ok'

# =====================================================================
# K5e. Rotation: routine and post-compromise (NOTE, informational, NOT
# executed by this script — invoke by hand, on the cadence in the table
# below or immediately on suspected compromise)
# =====================================================================
#
# Full per-secret table (where it lives, routine cadence, how to rotate, and
# blast radius if disclosed) is in phases/08-operations.md K5e — it covers
# the AdGuardHome admin password, restic repository password, object-storage
# keys, ntfy topic, healthchecks.io ping UUID, WireGuard server key, the
# keepalived auth_pass, the provider API token, the Certbot DNS-01 token,
# the SSH admin key, and Phase P's DoH tokens/client CA.
#
# Two rotations have a trap that makes an unplanned rotation actively worse
# than no rotation:
#
# 1) AdGuardHome admin password — stored TWICE (vault.yml bcrypt hash, AND
#    plaintext in /etc/prometheus/agh-credentials for Phase I's collector).
#    Rotating only in the admin UI leaves the collector authenticating with
#    the old password: agh_up drops to 0 and AdGuardHomeDown pages you for
#    what was a password change. Two steps, same session:
#      # 1. the service's own copy. Generate and PRINT the password first --
#      #    piping straight into htpasswd leaves a hash you cannot log in with.
#      NEW=$(head -c 24 /dev/urandom | base64); echo "$NEW"
#      htpasswd -bnBC 12 "" "$NEW" | tr -d ':\n'; echo   # -> bcrypt hash; put it in vault.yml
#      #    re-render AdGuardHome.yaml from the Phase O template, then:
#      systemctl restart adguardhome
#      # 2. the collector's copy -- SAME SESSION, not "later"
#      printf 'admin:%s\n' "$NEW" > /etc/prometheus/agh-credentials
#      chmod 0600 /etc/prometheus/agh-credentials; chown root:root /etc/prometheus/agh-credentials
#      systemctl restart prometheus
#      unset NEW
#    Verify: curl -su "$(cat /etc/prometheus/agh-credentials)" -o /dev/null -w '%{http_code}\n' \
#      http://127.0.0.1:3000/control/stats/config          # -> 200, never 401
#    then after 90s: curl -sG http://127.0.0.1:9090/api/v1/query \
#      --data-urlencode 'query=agh_up' | jq -r '.data.result[].value[1]'   # -> 1
#
# 2) ntfy topic — lives in /etc/alertmanager/ntfy.env AND in the ntfy app's
#    subscription list on your phone. Rotating one without the other sends
#    every future page to a topic nobody is listening to, which looks
#    exactly like "no alerts fired".
#      NEWTOPIC="dns1-alerts-$(head -c 24 /dev/urandom | base64 | tr -d '+/=' | head -c 32)"
#      # subscribe the phone to $NEWTOPIC FIRST, confirm it is live, THEN:
#      sed -i "s#^NTFY_URL=.*#NTFY_URL=https://ntfy.sh/${NEWTOPIC}#" /etc/alertmanager/ntfy.env
#      systemctl restart alertmanager-ntfy
#      /usr/local/sbin/notify.sh info "ntfy topic rotated" "confirm this arrived, then unsubscribe the old topic"
#    Re-run the Phase I11-14 dead-man's-switch proof end to end BEFORE
#    unsubscribing the old topic.
#
# Post-compromise blast-radius order (after evidence preservation, run from
# the REBUILT host or your workstation, NEVER from the suspect box):
#   1. TLS private key — revoke for real, this is not an expiry-scare reissue:
#        certbot revoke --cert-name dns.example.com --reason keycompromise --no-delete-after-revoke
#        certbot certonly --cert-name dns.example.com --key-type ecdsa --elliptic-curve secp256r1 --force-renewal
#      --reason is lowercase (keycompromise); --no-delete-after-revoke keeps
#      the renewal config and deploy hook. Confirm the new privkey.pem has a
#      different modulus/public point, do not assume --reuse-key is off.
#   2. restic repository password + object-storage keys — rotate the
#      object-storage key at the provider FIRST (cuts access), then K8's
#      `restic key add` / `restic key remove`. Before trusting any snapshot
#      as a rebuild source, audit the window:
#        restic snapshots --json | jq -r '.[] | "\(.time)  \(.id[0:8])  \(.hostname)  \(.tags|join(","))"'
#      Every snapshot in the window must be one the timer took; an
#      unexpected one is the attacker's, a MISSING one is worse (they pruned).
#   3. ntfy topic + healthchecks.io check — both were readable, both are how
#      you find out about the next incident.
#   4. SSH admin key, then the provider API token and provider console
#      password.
#   5. keepalived auth_pass on BOTH nodes, before the rebuilt node rejoins
#      the VRRP group.
#   6. WireGuard server key + every peer (Phase P6), and the Phase P client
#      CA + every token in doh-tokens.map. These end at a human with a
#      phone — start them early, expect them to run for days.
#   The AGH bcrypt hash and the DNSSEC trust anchor are explicitly NOT on
#   this list (hash rotation matters less than the plaintext exposure above;
#   the anchor is public data and self-heals via unbound-anchor).
#
# Verify (run once a year, and after any rotation):
#   grep -c '^admin:' /etc/prometheus/agh-credentials                     # -> 1
#   curl -su "$(cat /etc/prometheus/agh-credentials)" -o /dev/null -w '%{http_code}\n' \
#     http://127.0.0.1:3000/control/stats/config                          # -> 200
#   awk '/^## 1\./{s=1;next} /^## 2\./{s=0} s && /^\| *[A-Za-z]/ {n=split($0,f,"|");
#        if (f[5] ~ /TODO/ || f[5] ~ /^ *$/) print "NO ROTATION DATE:" f[2]}' \
#     /opt/dns-config-backup/INVENTORY.md          # -> no output

warn "K5e: rotation procedures (routine AGH-password two-step, ntfy-topic two-step, and the post-compromise blast-radius order) are NOT executed by this script — see the K5e comment block immediately above for the exact commands, or phases/08-operations.md K5e for the full cadence table."

# =====================================================================
# K6. Restore drill, Tier 1 — scheduled integrity drill (runs on the live
# node)
# =====================================================================
# Answers "is the repository readable and does it contain a usable node?".
# Restores into a scratch directory and touches nothing any service reads.
#
# Known limitation: unbound-checkconf and nginx -t resolve include:/include
# directives against absolute paths, which on the live node point at the
# LIVE files, not the restored copies. Gate 3 proves the restored top-level
# files are intact and this node's parsers accept them; it does not prove
# the restored tree is self-contained. That is Tier 2's (K7) job.

info "K6: installing the Tier 1 restore drill script"
# --- K6: restic-restore-drill.sh ---
backup_file /usr/local/sbin/restic-restore-drill.sh
cat > /usr/local/sbin/restic-restore-drill.sh << 'EOF'
#!/bin/bash
set -euo pipefail
set -a; . /etc/restic/dns.env; set +a
T=$(mktemp -d /var/tmp/drill.XXXXXX)
trap 'rm -rf "$T"' EXIT
SNAP=$(restic snapshots --tag dns-config --latest 1 --json | jq -r '.[0].short_id')
restic restore "$SNAP" --target "$T"

# gate 1: the files that make a rebuild possible exist and are non-empty.
# These are the canonical filenames — the Unbound drop-in is 10-public-resolver.conf (Phase C)
# and the Unbound unit drop-in is hardening.conf (Phase C hardening + Phase A6 ceilings +
# Phase N4 restart settings, one file). A drill testing for dns-node.conf or ha.conf fails on a
# correctly built host, which trains the operator to ignore the drill.
test -s "$T/opt/adguardhome/conf/AdGuardHome.yaml"
test -s "$T/etc/unbound/unbound.conf.d/10-public-resolver.conf"
test -s "$T/etc/nftables.conf"
test -s "$T/etc/systemd/system/adguardhome.service"
test -s "$T/etc/systemd/system/unbound.service.d/hardening.conf"

# gate 2: the private key resolves THROUGH the archive symlink. live/ alone is not enough,
# and the certs are ECDSA (P-256) so `openssl rsa` would wrongly fail — use `openssl pkey`.
test -L "$T/etc/letsencrypt/live/dns.example.com/privkey.pem"
openssl pkey -noout -in "$T/etc/letsencrypt/live/dns.example.com/privkey.pem"

# gate 3: the restored configs PARSE, using this node's own parsers.
nft -c -f "$T/etc/nftables.conf"
install -d -o adguardhome -g adguardhome "$T/aghwork"
chown adguardhome:adguardhome "$T/opt/adguardhome/conf/AdGuardHome.yaml"
runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
  -c "$T/opt/adguardhome/conf/AdGuardHome.yaml" -w "$T/aghwork"
unbound-checkconf "$T/etc/unbound/unbound.conf"
nginx -t -c "$T/etc/nginx/nginx.conf"

# gate 4: the schema_version we pinned is still what got backed up (see Phase E)
grep -qE '^schema_version:[[:space:]]*[0-9]+' "$T/opt/adguardhome/conf/AdGuardHome.yaml"

echo "DRILL PASS $(date -uIs) snapshot=$SNAP" | tee -a /var/log/restore-drill.log | logger -t restore-drill
EOF
chmod 750 /usr/local/sbin/restic-restore-drill.sh

# --- K6: schedule quarterly (Jan/Apr/Jul/Oct, 04:00). /etc/cron.d/dns-health
# is Phase I's file (creates it); this phase only appends a line, never
# rewrites it. ---
info "K6: scheduling the quarterly restore drill in /etc/cron.d/dns-health"
if [ -f /etc/cron.d/dns-health ]; then
    cat >> /etc/cron.d/dns-health << 'EOF'
0 4 1 */3 * root /usr/local/sbin/restic-restore-drill.sh || logger -t dns-alert -p daemon.crit "RESTORE DRILL FAILED"
EOF
else
    warn "K6: /etc/cron.d/dns-health does not exist yet (Phase I has not run). Append this line by hand once Phase I creates it: '0 4 1 */3 * root /usr/local/sbin/restic-restore-drill.sh || logger -t dns-alert -p daemon.crit \"RESTORE DRILL FAILED\"'"
fi
warn "K6: alert routing for the dns-alert syslog tag is Phase I's — a cron that only writes to syslog is not itself an alert."

# --- K6 verify ---
info "K6 verify: running the Tier 1 restore drill now"
/usr/local/sbin/restic-restore-drill.sh; echo "exit=$?"   # -> exit=0
tail -3 /var/log/restore-drill.log                        # -> DRILL PASS <timestamp> snapshot=<id>

# =====================================================================
# K7. Restore drill, Tier 2 — full DR rebuild (runs on a scratch VPS, from
# your WORKSTATION — NOT this node; NOTE, informational, NOT executed by
# this script)
# =====================================================================
#
# Answers "can I rebuild this service from source control and object
# storage, with nothing but what is in my password manager, and how long
# does it take?". Run once at build time, and again after any material
# change to Phase O, Phase D or Phase E. Budget under an hour of wall clock
# including provisioning.
#
#  1. Start from nothing but credentials: a terminal with only the Ansible
#     repo, the vault passphrase, the restic repository password and the
#     object-storage keys, all from the password manager. Do NOT SSH to the
#     production node at any point — if you need something from production,
#     the drill has already failed; note what it was and add it to K3.
#  2. Start the clock:
#       date -uIs | tee /tmp/drill-start
#  3. Provision a bare host with the Phase O cloud-init user-data (Hetzner
#     CLI shown, substitute your provider):
#       hcloud server create --name dns-dr --type cx22 --image ubuntu-24.04 \
#         --user-data-from-file cloud-init.yaml
#  4. Wait for first boot, confirm the node bootstrapped itself:
#       ssh deploy@dns-dr 'cloud-init status --wait --long; systemctl is-active nftables ssh'
#  5. Build it from source control:
#       cd /srv/dns-infra
#       ansible-playbook -i inventory/prod.yml site.yml --limit dns-dr --vault-id prod@prompt
#  6. Restore the non-regenerable state — certificates and account keys.
#     This is the only step restic is on the critical path for:
#       ssh deploy@dns-dr 'sudo install -d -m 0700 /etc/restic'
#       scp /path/from/password-manager/{repo.pass,dns.env} deploy@dns-dr:/tmp/
#       ssh deploy@dns-dr 'sudo mv /tmp/repo.pass /tmp/dns.env /etc/restic/ && sudo chmod 600 /etc/restic/*'
#       ssh deploy@dns-dr 'set -a; . /etc/restic/dns.env; set +a; \
#          sudo -E restic restore latest --target / --include /etc/letsencrypt'
#       ssh deploy@dns-dr 'sudo /etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh'
#  7. Take the address (see Phase N for which of these your tier gives you):
#       hcloud floating-ip assign dns-vip dns-dr
#  8. Run the gate:
#       ssh deploy@dns-dr sudo /usr/local/sbin/dns-smoke.sh
#  9. Stop the clock:
#       date -uIs | tee /tmp/drill-end
# 10. Destroy the scratch host and record the number:
#       hcloud server delete dns-dr
#
# Pass criterion — ALL FOUR must hold, or the drill failed:
#   - dns-smoke.sh exits 0 with SMOKE: PASS on the rebuilt host (Phase H12).
#   - The served certificate on the rebuilt host matches the on-disk
#     certificate and is the same one production was serving (restored, not
#     silently re-issued).
#   - No step required SSH access to the production node, and no step
#     required a value that was not in the password manager or the git repo.
#   - Wall clock from step 2 to step 9 is inside the Phase O6 rebuild-time
#     target.
# Write the measured wall-clock number into the runbook — that is your real
# RTO. Any RTO you did not measure this way is a guess.

warn "K7: the Tier 2 full DR rebuild drill is NOT executed by this script — it runs on a scratch VPS from your workstation, never this production node. See the K7 comment block immediately above for the exact procedure, or phases/08-operations.md K7. Run it once at build time and again after any material change to Phase O, D or E."

# =====================================================================
# K8. Second operator, and what happens when you are unavailable
# =====================================================================
# K7's pass criterion — "no step required a value that was not in the
# password manager" — certifies something nobody states out loud: nobody
# without your password manager can rebuild this service. Three single
# points converge on one human: the restic repository password (K2, no
# escrow), Alertmanager's one human receiver on one phone (Phase I8/I9), and
# SSH publickey-only with one admin key (Phase A4).
#
# This is a decision, not a fact. A single-operator hobby resolver serving
# your own household can rationally accept the risk. A resolver other
# people depend on cannot; the recommended default is ONE named second
# holder — the point is that the number is greater than zero, not that it
# is large.

# --- K8a: key escrow that is not a second copy of your own password
# (NOTE, informational, NOT executed by this script — invoke by hand when
# onboarding a second holder; requires an interactive handoff, not a build
# step) ---
#
#   set -a; . /etc/restic/dns.env; set +a
#   restic key list                          # note the current key ID; yours is marked with *
#   # they generate their own password and hand you a file; you never learn its value
#   restic key add --new-password-file /run/their-password --user "<their-name>"
#   rm -f /run/their-password                # /run is tmpfs, so this never reached the disk;
#                                            # do not stage it in /root or /tmp (Q5a: never write it)
#   restic key list                          # -> two keys, theirs tagged with their username
#   # to revoke later, from either holder's session:
#   #   restic key remove <their-key-id>
#
# Do NOT reach for `restic key passwd` when a second holder exists — it
# changes the password on the key you are currently using and tells you
# nothing about the other one. The second holder also needs the contents of
# /etc/restic/dns.env (the object-storage credentials), or they can decrypt
# a repository they cannot reach.
warn "K8a: key escrow (restic key add for a second holder) is NOT executed by this script — see the K8a comment block immediately above. Requires the second holder's own password file delivered out of band."

# --- K8b: accounts, not just the secrets (business/organizational decision,
# not scriptable) ---
warn "K8b: every account in the O6 operational inventory (registrar, hosting provider, object storage, healthchecks.io, ntfy, the ACME account) needs a stated second-holder answer — a shared vault entry, a provider-native second user, or a sealed envelope with a recovery code. This is a business decision. Check O6's second-holder column; a blank there is the finding."

# --- K8c: a second alerting destination (edits Phase I8's
# alertmanager.yml — that file is Phase I's object, follow Phase I8's own
# procedure, not duplicated here) ---
warn "K8c: add a THIRD Alertmanager receiver (Phase I8 already ships 'ntfy' and 'heartbeat', so the one you add here is the third) reaching a different human/device, and a second notification integration on the healthchecks.io check. This is Phase I's file — follow Phase I8's procedure. Then re-run the Phase I11-14 dead-man's-switch proof against the SECOND recipient's device; an untested second receiver is a comment, not a control."

# --- K8d: a second SSH admin key (Phase A4's object; use A4's own
# two-session procedure) ---
warn "K8d: add a second SSH admin key using Phase A4's own two-session procedure — open the new session before closing the old one, every time. Not scripted here; it is Phase A4's file and procedure."

# --- K8e: before any absence long enough that you would not see a page
# (NOTE, informational, NOT executed by this script — invoke by hand
# before a weekend, a flight, or leave) ---
#
#   /usr/local/sbin/dns-health                                 # exit 0
#   systemctl start restic-backup.service && restic snapshots --last 1   # a snapshot dated today
#   ls /var/run/reboot-required 2>/dev/null && echo "PENDING REBOOT - do it before you leave"  # (M6)
#   unattended-upgrade --dry-run 2>&1 | tail -3                 # nothing queued and waiting
#   git -C /opt/dns-config-backup status --porcelain            # -> empty; nothing uncommitted
#
# Then tell the covering person, in writing, which failures they are
# expected to handle (runbook restart order + smoke gate, N7's one-command
# rows, escalation steps 1-4, and the pre-authorised step 6: hand traffic to
# a public resolver) and which they are not (anything requiring an Ansible
# run or a vault passphrase, a rebuild/K7, escalation step 5, or deciding
# whether step 6's privacy trade-off is acceptable — you decided that in
# advance by pre-authorising it).
warn "K8e: the pre-absence checklist is NOT executed by this script — see the K8e comment block immediately above. Run it, in writing, before any absence long enough that you would not see a page."

# --- K8f: onboarding traps, one page (informational only — hand these to
# the second operator verbatim) ---
#   - Never `nft -f` directly — /usr/local/sbin/nft-apply only. A bare load
#     flushes every active ban and hands banned sources their access back
#     mid-incident (Phase B).
#   - Never edit AdGuardHome configuration in the admin UI. It rewrites the
#     file, Ansible overwrites it back, and the diff is lost (O3).
#   - Never restart AdGuardHome "as well, to be safe" after restarting
#     Unbound. That is a second, unnecessary outage (N4b).
#   - Never change the AdGuardHome admin password without the second step
#     in K5e.
#   - Never write a fallback `nameserver` line into /etc/resolv.conf and
#     leave it — see the runbook's first section.

# --- K8 verify (NOTE, informational, NOT executed by this script — these
# only make sense once K8a/c/d have actually been done, which is deferred
# operator action, not part of this build) ---
#   set -a; . /etc/restic/dns.env; set +a
#   restic key list                                            # -> two keys, one marked with *
#   awk '/^## 1\./{s=1;next} /^## 2\./{s=0} s && /^\| *[A-Za-z]/ {split($0,f,"|");
#        if (f[6] ~ /TODO/ || f[6] ~ /^ *$/) print "NO SECOND HOLDER:" f[2]}' \
#     /opt/dns-config-backup/INVENTORY.md                      # -> no output
#   n=$(grep -c '^  - name:' /etc/alertmanager/alertmanager.yml); echo "receivers=$n"
#   [ "$n" -ge 3 ] && echo second-receiver-present   # -> >= 3, never 2 (I8 ships 2 by default)
#   ssh-keygen -lf /home/deploy/.ssh/authorized_keys | wc -l   # -> 2
warn "K8 verify: the second-holder verification block (restic key list, O6 second-holder audit, alertmanager receiver count, authorized_keys count) is NOT executed by this script — see the K8 verify comment block immediately above. Run it after completing K8a/c/d, not at initial deploy time."

info "Phase K (automatic portion) complete."
echo
echo "Key Phase K verification commands:"
echo "  set -a; . /etc/restic/dns.env; set +a; restic snapshots --tag dns-config | tail -5"
echo "  systemctl list-timers restic-backup.timer --no-pager"
echo "  /usr/local/sbin/restic-restore-drill.sh; tail -3 /var/log/restore-drill.log   # Tier 1 (K6)"
echo
echo "Not executed by this script — operator-invoked runbook material (see the matching"
echo "comment block above each, or phases/08-operations.md for the full text):"
echo "  K5e  routine + post-compromise secret rotation"
echo "  K7   Tier 2 full DR rebuild drill (scratch VPS, from your workstation)"
echo "  K8   second-operator onboarding: key escrow, second receiver, second SSH key,"
echo "       pre-absence checklist, and the K8 second-holder verify block"
