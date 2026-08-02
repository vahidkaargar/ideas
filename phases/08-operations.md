[Plan index](../dns-server-plan.md) · [Previous: Observability and Abuse Response](./07-observability-and-abuse.md) · [Next: Private Access Layer (optional)](./09-private-access.md)

---

**On this page**

- [PHASE K: Backup, Restore and Secrets](#phase-k-backup-restore-and-secrets)
  - [K1. Install restic (pinned upstream binary, checksum-verified)](#k1-install-restic-pinned-upstream-binary-checksum-verified)
  - [K2. Repository and key handling](#k2-repository-and-key-handling)
  - [K3. What is backed up, and what deliberately is not](#k3-what-is-backed-up-and-what-deliberately-is-not)
  - [K4. Backup service and timer](#k4-backup-service-and-timer)
  - [K5. Secrets: what never enters source control, and where it actually lives](#k5-secrets-what-never-enters-source-control-and-where-it-actually-lives)
  - [K5e. Rotation: routine and post-compromise](#k5e-rotation-routine-and-post-compromise)
  - [K6. Restore drill, Tier 1 — scheduled integrity drill (runs on the live node)](#k6-restore-drill-tier-1-scheduled-integrity-drill-runs-on-the-live-node)
  - [K7. Restore drill, Tier 2 — full DR rebuild (runs on a scratch VPS)](#k7-restore-drill-tier-2-full-dr-rebuild-runs-on-a-scratch-vps)
  - [K8. Second operator, and what happens when you are unavailable](#k8-second-operator-and-what-happens-when-you-are-unavailable)
- [PHASE M: Patching and Upgrades](#phase-m-patching-and-upgrades)
  - [M1. unattended-upgrades, with the restart window under control](#m1-unattended-upgrades-with-the-restart-window-under-control)
  - [M2. needrestart: stop it from prompting, and know what it will bounce](#m2-needrestart-stop-it-from-prompting-and-know-what-it-will-bounce)
  - [M3. AdGuardHome: upgrade and rollback](#m3-adguardhome-upgrade-and-rollback)
  - [M4. Unbound: distro package, with a trust-anchor and config-compatibility gate](#m4-unbound-distro-package-with-a-trust-anchor-and-config-compatibility-gate)
  - [M5. nginx](#m5-nginx)
  - [M6. Kernel and reboots](#m6-kernel-and-reboots)
  - [M7. Standing guards](#m7-standing-guards)
- [PHASE N: High Availability and Failure Modes](#phase-n-high-availability-and-failure-modes)
  - [N1. What clients actually do when a resolver stops answering](#n1-what-clients-actually-do-when-a-resolver-stops-answering)
  - [N2. The tiers](#n2-the-tiers)
  - [N3. Tier 3: keepalived VRRP with a floating IP](#n3-tier-3-keepalived-vrrp-with-a-floating-ip)
  - [N4. systemd self-heal: the correctness fix](#n4-systemd-self-heal-the-correctness-fix)
  - [N5. Resource ceilings and the OOM killer](#n5-resource-ceilings-and-the-oom-killer)
  - [N6. Scale up or scale out](#n6-scale-up-or-scale-out)
  - [N7. Failure modes](#n7-failure-modes)
  - [N8. When the address has to change](#n8-when-the-address-has-to-change)
- [PHASE O: Provisioning and Reproducibility](#phase-o-provisioning-and-reproducibility)
  - [O1. cloud-init: bare VPS to reachable-and-firewalled on first boot](#o1-cloud-init-bare-vps-to-reachable-and-firewalled-on-first-boot)
  - [O2. Ansible layout, and where the role boundaries fall](#o2-ansible-layout-and-where-the-role-boundaries-fall)
  - [O3. The handful of tasks that are actually subtle](#o3-the-handful-of-tasks-that-are-actually-subtle)
  - [O4. Drift detection](#o4-drift-detection)
  - [O5. Rebuild-time target](#o5-rebuild-time-target)
  - [O6. The operational inventory](#o6-the-operational-inventory)
- [Operations Runbook](#operations-runbook)
  - [First: give yourself DNS](#first-give-yourself-dns)
  - [Restart order](#restart-order)
  - [The gate after every change](#the-gate-after-every-change)
  - [Failure scenarios](#failure-scenarios)
  - [Escalation path](#escalation-path)
  - [If you believe the host is compromised](#if-you-believe-the-host-is-compromised)
- [Decommissioning](#decommissioning)

---

## PHASE K: Backup, Restore and Secrets

The v1 plan put a git repo at `/opt/dns-config-backup` on the DNS node itself and copied five
files into it daily. That protects against exactly one failure — "I edited a config and want the
old one" — and against none of the failures a backup exists for. If the volume is lost, the
provider deletes the instance, or the box is compromised, the backup dies with the thing it was
protecting. It also omitted `/etc/letsencrypt`, every systemd unit, the renewal deploy hook and
every operational script, so a restore from it could not rebuild the node anyway.

Phase K replaces it with two separate mechanisms that have different jobs:

- **Configuration** is regenerated from source control by Phase O. Ansible is the source of truth
  for anything a template can produce.
- **State Ansible cannot regenerate** — chiefly `/etc/letsencrypt`, which holds account keys and
  issued certificates you do not want to re-request under Let's Encrypt rate limits during an
  outage — goes to encrypted off-host object storage via restic.

Retire the v1 *mechanism*, not the v1 *directory*. The daily copy job goes:

```bash
rm -f /etc/cron.daily/dns-backup      # the v1 daily copy job; restic replaces it
```

**Do not `rm -rf /opt/dns-config-backup`.** The directory has a live job in this design that has
nothing to do with the v1 backup scheme: it is the local config staging directory that Phase I,
Phase J and Phase Q write to. Deleting it breaks those phases. What was wrong with v1 was treating a
directory on the node as *the backup*; the fix is to make that directory an *input* to an off-host
backup, which is what K3 does by putting it in the restic include list.

**Phase A creates this directory** — `install -d` plus `git init` — because Phase I starts
committing to it long before Phase K runs; Phase K consumes it and never creates it. That also
means the `.git` inside it is **Phase A's repository, not a v1 leftover**: it holds the config
history Phase I, Phase J and Phase Q append to. Leave it alone. Nothing under this path is safe to
delete.

### K1. Install restic (pinned upstream binary, checksum-verified)

Ubuntu 24.04 packages restic, and the packaged version is adequate. Pin the upstream static
binary anyway: this is the one tool whose failure you discover only when you already have an
outage, and you want a known version with a verified checksum rather than whatever the archive
happens to carry.

```bash
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
```

If you prefer the distro package (`apt install restic`), change the `ExecStart=` paths in K4 from
`/usr/local/bin/restic` to `/usr/bin/restic`.

**Verify:** `restic version` prints a version and `restic --help` exits 0.

### K2. Repository and key handling

The repository password is the only thing standing between your backup provider and your TLS
private keys. It is also the only thing that can decrypt the backup. Both facts point the same
way: it is generated on the node, and it lives in your password manager.

```bash
install -d -m 0700 /etc/restic
openssl rand -base64 48 > /etc/restic/repo.pass
chmod 600 /etc/restic/repo.pass

#  >>> COPY /etc/restic/repo.pass INTO YOUR PASSWORD MANAGER NOW, BEFORE CONTINUING. <<<
#  If this string only exists on this host, losing the host loses every backup taken from it.
#  There is no recovery path. restic has no key escrow.

cat > /etc/restic/dns.env << 'EOF'
RESTIC_REPOSITORY=s3:s3.eu-central-003.backblazeb2.com/my-dns-backups/dns1
RESTIC_PASSWORD_FILE=/etc/restic/repo.pass
AWS_ACCESS_KEY_ID=<application-key-id>
AWS_SECRET_ACCESS_KEY=<application-key>
EOF
chmod 600 /etc/restic/dns.env

set -a; . /etc/restic/dns.env; set +a
restic init
```

Scope the object-storage credential to this one bucket with write and list rights. Do **not** give
it delete rights on the bucket if your provider can express that separately — an attacker on the
node who can delete the backup has removed your recovery path. Backblaze B2 application keys and
S3 bucket policies both support this; the exact syntax is provider-specific and is **not verified
here**, so check your provider's documentation. Where available, enable object-lock / immutability
with a retention slightly longer than the `--keep-monthly` window in K4.

**Verify:**

```bash
set -a; . /etc/restic/dns.env; set +a
restic cat config | jq '.version'      # -> repository format version, proves the repo opened
```

### K3. What is backed up, and what deliberately is not

```bash
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

cat > /etc/restic/exclude.txt << 'EOF'
/var/log/adguardhome/querylog
/var/lib/adguardhome/stats
/opt/adguardhome/work/data/sessions.db
/opt/adguardhome/work/data/filters
/etc/restic/repo.pass
EOF
```

Every exclusion is deliberate, and each one is a decision someone will otherwise reverse by
accident:

- **The query log and the statistics database** — `/var/log/adguardhome/querylog` and
  `/var/lib/adguardhome/stats`, which are the paths Phase E configures; they are *not* under
  `/opt/adguardhome/work/data/`, and an exclude list still naming the old locations excludes
  nothing. These contain client query history. Even with `anonymize_client_ip: true` the *queries
  themselves* are personal data (see Phase Q), and shipping them to third-party object storage as a
  side effect of a config backup is a data-processing decision nobody signed off on. They are also
  worthless for disaster recovery. Neither path is under an include entry either, so the exclusion
  is belt-and-braces — which is the point: it survives someone widening the include list later.
- **`sessions.db`** — admin UI session tokens. Restoring them restores live credentials.
- **`work/data/filters`** — downloaded blocklists, regenerated on demand. Excluding them keeps the
  snapshot small enough that `restic check --read-data` is cheap.
- **`/etc/restic/repo.pass`** — storing the repository password inside the repository it unlocks
  is circular. It lives in your password manager (K2).

Five inclusions that are easy to get wrong:

- **`/etc/letsencrypt` must be taken whole.** `live/*.pem` are symlinks into `archive/`. A backup
  of `live/` alone restores dangling symlinks and no private key, and you will not discover this
  until the restore.
- **`/var/lib/unbound/root.key`** is the DNSSEC trust anchor. It is regenerable with
  `unbound-anchor`, but that requires working network and a working clock at restore time;
  carrying the file costs nothing. See Phase C for how it is maintained.
- **`/etc/prometheus`, `/etc/alertmanager`, `/etc/blackbox_exporter`** — the monitoring
  configuration Phase I builds: scrape jobs, alert rules, routing and probe modules. None of it was
  backed up anywhere before this list existed. Losing it does not take DNS down, which is exactly
  why it gets rebuilt last and least well under outage pressure: you restore the resolver, declare
  victory, and discover a month later that nothing has been alerting.
- **`/opt/dns-config-backup`** — the local config staging directory Phases I, J and Q write to. It
  is not a backup, it is *state*, and it is one of the two paths on this node whose contents no
  playbook regenerates. Backing it up off-host is the entire reason it survives Phase K rather than
  being deleted by it.
- **`/etc/nftables.d/dns-allow.nft`** — the operator allowlist sets (`allowlist4` / `allowlist6`,
  Phase B6). `/etc/nftables.conf` is templated by Phase O and regenerates from source control; this
  file does **not**. It is edited on the node and reloaded with `dns-allow-reload`, so it is the
  other path here that nothing else can reproduce. It is a single file, not a directory: an include
  entry of `/etc/nftables.d` alone would sweep in nothing else today, but the file is what Phase B
  asks to be backed up and the file is what a restore needs.

**Verify:** after the first backup, `restic ls latest | grep letsencrypt/archive` returns lines,
`restic ls latest | grep -E '^/etc/(prometheus|alertmanager|blackbox_exporter)/'` returns lines,
`restic ls latest | grep -c dns-config-backup` is non-zero,
`restic ls latest | grep -c 'nftables.d/dns-allow.nft'` is non-zero, and
`restic ls latest | grep -c querylog` returns 0.

### K4. Backup service and timer

```ini
# /etc/systemd/system/restic-backup.service
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
```

`5%%` is not a typo. A literal `%` must be escaped as `%%` in a systemd unit file; written as `5%`
the unit fails to load with a specifier error. Multiple `ExecStart=` lines are legal here because
the unit is `Type=oneshot`, and they run in order, aborting the unit on the first non-zero exit.

The `check --read-data-subset=5%` line is what turns this from "files were uploaded" into "the
repository is readable": it downloads and verifies 5% of the pack files each run, so the whole
repository is statistically covered over a few weeks, and silent bit-rot or a provider-side
truncation surfaces before you need the data.

```ini
# /etc/systemd/system/restic-backup.timer
[Unit]
Description=Daily off-host backup

[Timer]
OnCalendar=*-*-* 03:17:00
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
```

`Persistent=true` runs a missed backup after a reboot rather than skipping the day.
`RandomizedDelaySec=900` matters on an HA pair: without it both nodes hammer the object store at
the same instant.

```bash
systemctl daemon-reload && systemctl enable --now restic-backup.timer
systemctl start restic-backup.service    # first run, foreground-ish
```

**Verify:**

```bash
systemctl list-timers restic-backup.timer --no-pager
#   -> NEXT column populated, LEFT non-negative
journalctl -u restic-backup.service -n 30 --no-pager | grep -E 'snapshot|Added to the repository'
set -a; . /etc/restic/dns.env; set +a; restic snapshots --tag dns-config | tail -5
```

### K5. Secrets: what never enters source control, and where it actually lives

The rule is mechanical: **anything that grants access lives in the vault or on the node, never in
a config repo.** Git history is append-only in practice — a secret that was committed once and
"removed" in a later commit is still in the object store, still in every clone, and still in every
fork and CI cache. Treat any secret that was ever committed as disclosed and rotate it.

**Never commit, under any circumstances:**

| Secret | Where it actually lives |
|---|---|
| AdGuardHome admin bcrypt hash | `group_vars/dns/vault.yml` (ansible-vault, Phase O), rendered into the config template |
| TLS private keys (`/etc/letsencrypt/**`, `/opt/adguardhome/conf/ssl/*`) | On the node; recovered from restic (K3), never from git |
| restic repository password (`/etc/restic/repo.pass`) | Password manager + vault |
| Object-storage keys (`/etc/restic/dns.env`) | Vault, rendered to the node at 0600 |
| Certbot DNS-01 API token (`/etc/letsencrypt/secrets/*.ini`) | Vault; scoped to DNS-edit on one zone only |
| keepalived `auth_pass` (`/etc/keepalived/keepalived.conf`) | Vault — the VRRP password is plaintext in that file by design |
| Provider API token for floating-IP moves | Vault, delivered via `LoadCredential=` (K5c) |
| Phase P access tokens / WireGuard private keys (`/etc/wireguard/*`) | Generated on the node, never templated from the repo; see Phase P |

**K5a) Correct ownership on the live files.** AdGuardHome rewrites its own configuration at runtime,
so the config file must be owned and writable by the service user — a root-owned 0644 file is
wrong in both directions. And since v0.107.53 AdGuardHome actively tightens permissions on files it
touches (CVE-2024-36586 hardening), so anything left root-owned inside its tree becomes a startup
failure later:

```bash
chown adguardhome:adguardhome /opt/adguardhome/conf/AdGuardHome.yaml
chmod 0600 /opt/adguardhome/conf/AdGuardHome.yaml
chown adguardhome:adguardhome /opt/adguardhome/conf/ssl
chmod 0700 /opt/adguardhome/conf/ssl
chmod 600 /etc/restic/dns.env /etc/restic/repo.pass
```

The `chown` on `conf/ssl` is not decoration. Phase D's renewal deploy hook runs as root; if it
creates that directory with a bare `mkdir -p`, the directory is `root:root`, and `chmod 0700` on a
root-owned directory removes traverse permission for the `adguardhome` user — every TLS listener
(DoT, DoQ, and the loopback HTTPS listener nginx proxies DoH to) then fails to load its certificate.
In the Phase D deploy hook, the directory must be created as:

```bash
install -d -o adguardhome -g adguardhome -m 0700 "$DST"
```

**K5b) Template the secret out of the repo.** The Ansible template holds a reference, never a value:

```yaml
# roles/adguardhome/templates/AdGuardHome.yaml.j2  (excerpt)
users:
  - name: admin
    password: "{{ agh_admin_bcrypt }}"
```

Encrypt the **whole** vars file. A file assembled with `ansible-vault encrypt_string >> vault.yml`
is plaintext YAML containing `!vault` scalars: the variable names and file structure are in the
clear, and `ansible-vault view` on it fails with "input is not vault encrypted data", which sends
operators looking for something to weaken.

```bash
cat > group_vars/dns/vault.yml << 'EOF'
agh_admin_bcrypt: "$2y$12$..."
restic_password: "<repo-pass>"
b2_key_id: "<application-key-id>"
b2_secret_key: "<application-key>"
cloudflare_api_token: "<Zone:DNS:Edit on one zone>"
keepalived_auth_pass: "8charmax"
provider_api_token: "<floating-IP scope only>"
EOF
ansible-vault encrypt --vault-id prod@prompt group_vars/dns/vault.yml
```

Plus a hard guard in the repo so this cannot recur:

```
# dns-infra/.gitignore
*.pem
*.key
*.env
AdGuardHome.yaml
!roles/adguardhome/templates/AdGuardHome.yaml.j2
repo.pass
cloudflare.ini
/etc-backup/
```

**K5c) Runtime secrets reach processes via systemd credentials, not environment files in the unit.**
`LoadCredential=` requires systemd >= 247; Ubuntu 24.04 ships systemd 255.

```ini
# /etc/systemd/system/keepalived.service.d/creds.conf
[Service]
LoadCredential=provider:/etc/keepalived/provider.token
```

The consuming script reads `"$CREDENTIALS_DIRECTORY/provider"`. The credential tmpfs is owned by the
unit's user, so the script that reads it must run as root — see N3, where keepalived's `notify_master`
is declared with an explicit `root root`.

**K5d) A pre-commit tripwire**, because policy that depends on remembering does not hold:

```bash
cat > /srv/dns-infra/.git/hooks/pre-commit << 'EOF'
#!/bin/bash
if git diff --cached -U0 | grep -nE '\$2[aby]\$[0-9]{2}\$|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AWS_SECRET|api_token *[:=]'; then
  echo "REFUSED: this diff contains something that looks like a secret." >&2
  exit 1
fi
EOF
chmod +x /srv/dns-infra/.git/hooks/pre-commit
```

Hooks are per-clone and not versioned; mirror the same grep as a CI job so a clone without the hook
still gets caught.

**Verify:**

```bash
stat -c '%U:%G %a %n' /opt/adguardhome/conf/AdGuardHome.yaml /opt/adguardhome/conf/ssl \
  /opt/adguardhome/conf/ssl/privkey.pem /etc/restic/dns.env /etc/restic/repo.pass
#   -> adguardhome:adguardhome 600 (yaml); adguardhome:adguardhome 700 (ssl dir); 600 on the rest

systemctl restart adguardhome && sleep 5
journalctl -u adguardhome -n 40 --no-pager | grep -iE 'permission|denied|no such file'; echo "grep exit=$? (1 = clean)"

cd /srv/dns-infra
git log --all -p | grep -cE '\$2[aby]\$[0-9]{2}\$|BEGIN (RSA |EC )?PRIVATE KEY'   # -> 0
git ls-files | grep -E '\.pem$|\.env$|repo\.pass|cloudflare\.ini'                 # -> no output
head -1 group_vars/dns/vault.yml | grep -q '^\$ANSIBLE_VAULT;' && echo file-is-encrypted
ansible-vault view group_vars/dns/vault.yml --vault-id prod@prompt >/dev/null && echo vault-ok

systemd-run -p LoadCredential=provider:/etc/keepalived/provider.token --wait --pipe \
  /bin/sh -c 'test -s "$CREDENTIALS_DIRECTORY/provider" && echo cred-ok'
```

### K5e. Rotation: routine and post-compromise

K5 says "treat any secret that was ever committed as disclosed and rotate it" and stops there. That
is reactive, it covers exactly one disclosure route, and it never says *how*. The only scheduled
rotation anywhere in this plan is Phase P4's 90-day DoH token cadence. Everything else — the
AdGuardHome admin password, the restic repository password, the object-storage keys, the WireGuard
server key, `auth_pass`, the provider API token, the ntfy topic, the SSH admin key — is set once at
build time and never thought about again.

Two of these have a trap that makes an unplanned rotation actively worse than no rotation, so read
the table's Notes column before you change anything.

| Secret | Lives in | Routine cadence | Rotate with | If disclosed |
|---|---|---|---|---|
| AdGuardHome admin password | `vault.yml` (bcrypt) **and plaintext in `/etc/prometheus/agh-credentials`** | 12 months, or on staff change | Two-step below — never the admin UI alone | Full control of filtering, upstreams and TLS config; the attacker can repoint your users at their own resolver |
| restic repository password | `/etc/restic/repo.pass` + password manager | Do not rotate on a clock; rotate on holder change | `restic key add` then `restic key remove` (K8) | Every backup is decryptable, including `/etc/letsencrypt` |
| Object-storage keys | `/etc/restic/dns.env`, from `vault.yml` | 12 months | New application key at the provider, re-template, re-run the backup unit | Attacker can read the (encrypted) repo and, if you granted delete, destroy your recovery path |
| ntfy topic | `/etc/alertmanager/ntfy.env` | 12 months | Below — the topic **is** the credential (Phase I8) | Attacker reads every alert and can publish convincing fake ones |
| healthchecks.io ping UUID | `/etc/cron.d/dns-health` line (Phase I9) | On account change only | New check at healthchecks.io, replace the URL, re-prove per I11-14 | Attacker can ping your dead man's switch and keep it green through a real outage |
| WireGuard server key | `/etc/wireguard/*` (generated on the node) | Not on a clock | `wg genkey` + re-enrol every peer (Phase P6) | Every peer tunnel is impersonable; re-enrolment is manual and per-device |
| keepalived `auth_pass` | `/etc/keepalived/keepalived.conf`, from `vault.yml` | 12 months | Change on **both** nodes in the same playbook run, then restart the standby first | VRRP takeover of the VIP from anywhere on the same L2 |
| Provider API token | `vault.yml`, delivered via `LoadCredential=` (K5c) | 6 months | Reissue at the provider, scoped to floating-IP moves only | Attacker moves your address, or deletes the instance |
| Certbot DNS-01 token | `/etc/letsencrypt/secrets/*.ini`, from `vault.yml` | 6 months | Reissue scoped to DNS-edit on one zone | Attacker issues certificates for your name — this is the one that survives losing the box |
| SSH admin key | `authorized_keys` (Phase A4) | On device change | Add the new key, prove it in a second session, then remove the old (A4's procedure) | Root on the node |
| Phase P DoH tokens / client CA | `/etc/nginx/doh-tokens.map` | **90 days** (already specified in P4) | Add alongside, migrate, delete, reload twice | One device's access; per-device revocation is the point of the tier |

**The AdGuardHome password is stored twice, and rotating it in the UI breaks Phase I.** Phase I3
writes the *plaintext* password into `/etc/prometheus/agh-credentials` because the `/control/stats`
collector has to authenticate. Change the password in the admin UI and nothing warns you: the
collector starts getting 401s, `agh_up` drops to 0, and `AdGuardHomeDown` pages you for what was a
password change. Rotation is therefore two steps in one session, and it is not finished after the
first:

```bash
# 1. the service's own copy. Generate and PRINT the password first -- Phase E3 explains why
#    piping $(openssl rand ...) straight into htpasswd leaves you a hash you cannot log in with.
NEW=$(head -c 24 /dev/urandom | base64); echo "$NEW"
htpasswd -bnBC 12 "" "$NEW" | tr -d ':\n'; echo   # -> bcrypt hash; put it in vault.yml
#    re-render AdGuardHome.yaml from the template (Phase O), then:
systemctl restart adguardhome

# 2. the collector's copy -- SAME SESSION, not "later"
printf 'admin:%s\n' "$NEW" > /etc/prometheus/agh-credentials
chmod 0600 /etc/prometheus/agh-credentials; chown root:root /etc/prometheus/agh-credentials
systemctl restart prometheus
unset NEW
```

**Verify:** `/usr/local/sbin/dns-health` passes, and the collector is authenticating again —

```bash
# the admin/control listener is 127.0.0.1:3000 (Phase E http.address), NOT the :8053 DoH backend
curl -su "$(cat /etc/prometheus/agh-credentials)" -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:3000/control/stats/config          # -> 200, never 401

sleep 90
curl -sG http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=agh_up' | jq -r '.data.result[].value[1]'
#   -> 1.  A 0 here means step 2 was skipped or the two password strings differ.
```

**Rotating the ntfy topic touches a device you cannot reach from the node.** The topic lives in
`/etc/alertmanager/ntfy.env`, and it also lives in the subscription list of the ntfy app on your
phone. Change one without the other and every page goes to a topic nobody is listening to — which
looks exactly like "no alerts fired", the failure mode Phase I exists to eliminate.

```bash
NEWTOPIC="dns1-alerts-$(head -c 24 /dev/urandom | base64 | tr -d '+/=' | head -c 32)"
# subscribe the phone to $NEWTOPIC FIRST, and confirm the subscription is live, then:
sed -i "s#^NTFY_URL=.*#NTFY_URL=https://ntfy.sh/${NEWTOPIC}#" /etc/alertmanager/ntfy.env
systemctl restart alertmanager-ntfy
/usr/local/sbin/notify.sh info "ntfy topic rotated" "confirm this arrived, then unsubscribe the old topic"
```

Then re-run the Phase I11-14 proof end to end before you unsubscribe the old topic. Unsubscribing
first is how you discover a typo with no path to tell you about it.

#### Post-compromise: the blast-radius list

Everything above was readable by root. On a host you believe was compromised (see the runbook
section "If you believe the host is compromised"), the question is not *which* secrets to rotate —
it is all of them — but in what order, and which ones need more than a new value.

Rotate, in this order, **after** the evidence-preservation steps and **from the rebuilt host or
your workstation, never from the suspect box**:

1. **The TLS private key, with a real revocation.** D6's guidance is "reissue and redeploy quickly",
   which is right for an expiry scare and wrong here: a key the attacker holds lets them impersonate
   `dns.example.com` to every DoT/DoQ/DoH client you have until the certificate expires. Revocation
   for `keyCompromise` is not optional.
   ```bash
   certbot revoke --cert-name dns.example.com --reason keycompromise --no-delete-after-revoke
   certbot certonly --cert-name dns.example.com --key-type ecdsa --elliptic-curve secp256r1 --force-renewal
   ```
   `--reason` is lowercase (`keycompromise`), and `certbot revoke` deletes the lineage afterwards
   unless you pass `--no-delete-after-revoke` — keeping it means the renewal config and the deploy
   hook survive. Certbot generates a fresh keypair on each issuance unless `--reuse-key` is set;
   Phase D does not set it, so confirm rather than assume: the new `privkey.pem` must have a
   different modulus/public point from the revoked one.
2. **The restic repository password and the object-storage keys.** The attacker held
   `/etc/restic/repo.pass` and `/etc/restic/dns.env`, so they could read the repository *and*
   `restic forget --prune` it. Rotate the object-storage key at the provider first — that cuts
   access — then add a new repository password and remove the old one (K8). Before you trust any
   snapshot as a rebuild source, audit what happened to the repository during the intrusion window:
   ```bash
   restic snapshots --json | jq -r '.[] | "\(.time)  \(.id[0:8])  \(.hostname)  \(.tags|join(","))"'
   #   -> every snapshot in the window must be one your timer took. An unexpected snapshot is
   #      an attacker's; a MISSING one is worse, because it means they pruned.
   ```
3. **The ntfy topic and the healthchecks.io check.** Both were readable, and both are how you find
   out about the next incident. An attacker who keeps your dead man's switch green owns your
   detection.
4. **The SSH admin key**, then the provider API token and the provider console password. The console
   is outside this plan's control and is the one path that survives a rebuild.
5. **keepalived `auth_pass`** on both nodes, before the rebuilt node rejoins the VRRP group.
6. **The WireGuard server key and every peer** (Phase P6), and **the Phase P client CA and every
   token in `doh-tokens.map`**. These are the slowest items on the list because each one ends at a
   human with a phone. Start them early and expect them to run for days.

Two things that are *not* on the list and are asked for anyway: the AdGuardHome bcrypt hash is worth
rotating but is not urgent (it was a hash, and the plaintext copy in `agh-credentials` is the actual
exposure — rotate for that reason, per the two-step above); and the DNSSEC trust anchor is not a
secret and does not rotate — it is public data, and Phase C's `unbound-anchor` path re-establishes it.

**Verify** (run once a year, and after any rotation, so a half-done rotation is visible):

```bash
# every stored copy of the AGH password agrees with the running service
grep -c '^admin:' /etc/prometheus/agh-credentials                     # -> 1
curl -su "$(cat /etc/prometheus/agh-credentials)" -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:3000/control/stats/config                          # -> 200, never 401

# every credential in the O6 inventory carries a rotation date (section 1 only)
awk '/^## 1\./{s=1;next} /^## 2\./{s=0} s && /^\| *[A-Za-z]/ {n=split($0,f,"|");
     if (f[5] ~ /TODO/ || f[5] ~ /^ *$/) print "NO ROTATION DATE:" f[2]}' \
  /opt/dns-config-backup/INVENTORY.md          # -> no output
```

### K6. Restore drill, Tier 1 — scheduled integrity drill (runs on the live node)

An untested backup is not a backup, it is a hope. There are two drills because they answer two
different questions, and conflating them produces a drill that cannot run anywhere.

Tier 1 answers *"is the repository readable and does it contain a usable node?"* It runs on the
production node quarterly, restores into a scratch directory, and touches nothing any service
reads.

```bash
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
```

`--check-config` runs as the `adguardhome` user against a scratch work directory. Running it as
root against the live tree would let AdGuardHome's permission-tightening leave root-owned artifacts
under a tree owned by the service user, which then fails at the next real start — you would have
broken production with a drill.

**Known limitation, stated so nobody over-trusts this drill:** `unbound-checkconf` and `nginx -t`
resolve `include:` / `include` directives against absolute paths. On the live node those absolute
paths point at the *live* files, not the restored copies. Gate 3 therefore proves that the restored
top-level files are intact and that this node's parsers accept them; it does not prove the restored
tree is self-contained. That is Tier 2's job.

Schedule it by appending to `/etc/cron.d/dns-health` (Jan/Apr/Jul/Oct, 04:00). That file is
**created by Phase I**, which owns it; this phase and Phase M add lines to it and never rewrite it:

```
0 4 1 */3 * root /usr/local/sbin/restic-restore-drill.sh || logger -t dns-alert -p daemon.crit "RESTORE DRILL FAILED"
```

Alert routing for that `dns-alert` tag is Phase I. A cron that only writes to syslog is not an alert.

**Verify:**

```bash
/usr/local/sbin/restic-restore-drill.sh; echo "exit=$?"   # -> exit=0
tail -3 /var/log/restore-drill.log                        # -> DRILL PASS <timestamp> snapshot=<id>
```

### K7. Restore drill, Tier 2 — full DR rebuild (runs on a scratch VPS)

Tier 2 answers the only question that matters: *"can I rebuild this service from source control
and object storage, with nothing but what is in my password manager, and how long does it take?"*
Run it once at build time, and again after any material change to Phase O, Phase D or Phase E.

Do it on a throwaway VPS. Budget under an hour of wall clock including provisioning.

**Procedure:**

1. **Start from nothing but credentials.** Open a terminal on your workstation with only: the
   Ansible repo, the vault passphrase, the restic repository password, and the object-storage
   keys — all from your password manager. Do not SSH to the production node at any point during
   this drill. If you need something from production, the drill has already failed; note what it
   was and add it to K3.

2. **Start the clock and record it.**
   ```bash
   date -uIs | tee /tmp/drill-start
   ```

3. **Provision a bare host** with the Phase O cloud-init user-data. Provider CLI shown for Hetzner;
   substitute yours.
   ```bash
   hcloud server create --name dns-dr --type cx22 --image ubuntu-24.04 \
     --user-data-from-file cloud-init.yaml
   ```

4. **Wait for first boot to complete**, then confirm the node bootstrapped itself.
   ```bash
   ssh deploy@dns-dr 'cloud-init status --wait --long; systemctl is-active nftables ssh'
   ```

5. **Build it from source control.**
   ```bash
   cd /srv/dns-infra
   ansible-playbook -i inventory/prod.yml site.yml --limit dns-dr --vault-id prod@prompt
   ```

6. **Restore the non-regenerable state** — certificates and account keys. This is the only step
   restic is on the critical path for.
   ```bash
   ssh deploy@dns-dr 'sudo install -d -m 0700 /etc/restic'
   scp /path/from/password-manager/{repo.pass,dns.env} deploy@dns-dr:/tmp/
   ssh deploy@dns-dr 'sudo mv /tmp/repo.pass /tmp/dns.env /etc/restic/ && sudo chmod 600 /etc/restic/*'
   ssh deploy@dns-dr 'set -a; . /etc/restic/dns.env; set +a; \
      sudo -E restic restore latest --target / --include /etc/letsencrypt'
   ssh deploy@dns-dr 'sudo /etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh'
   ```

7. **Take the address.** Move the floating IP (or, without one, repoint the `dns.example.com` A
   record and accept the TTL). See Phase N for which of these your tier gives you.
   ```bash
   hcloud floating-ip assign dns-vip dns-dr
   ```

8. **Run the gate.**
   ```bash
   ssh deploy@dns-dr sudo /usr/local/sbin/dns-smoke.sh
   ```

9. **Stop the clock.**
   ```bash
   date -uIs | tee /tmp/drill-end
   ```

10. **Destroy the scratch host** and record the number.
    ```bash
    hcloud server delete dns-dr
    ```

**Pass criterion — all four must hold, or the drill failed:**

- `dns-smoke.sh` exits 0 with `SMOKE: PASS` on the rebuilt host (Phase H12).
- The served certificate on the rebuilt host matches the on-disk certificate and is the same
  certificate production was serving — i.e. you restored it rather than silently re-issuing one.
- No step required SSH access to the production node, and no step required a value that was not in
  the password manager or the git repo.
- Wall clock from step 2 to step 9 is inside the rebuild-time target in Phase O6.

Write the measured wall-clock number into the runbook. That number is your real RTO. Any RTO you
did not measure this way is a guess.

### K8. Second operator, and what happens when you are unavailable

Read K7's pass criterion again: *"no step required a value that was not in the password manager"*.
That drill certifies something nobody states out loud — **nobody without your password manager can
rebuild this service.** Three single points converge on one human and no section of this plan names
the convergence:

- K2 puts the restic repository password in your personal vault and says, correctly, that there is
  no escrow and no recovery path. Phase L repeats it as a go-live gate.
- Alertmanager has exactly one human receiver: one ntfy topic on one phone (Phase I8). Phase I9's
  dead man's switch is deliberately routed to a *different topic on the same phone*, which protects
  against one channel failing and not at all against the phone being in a drawer.
- SSH is publickey-only with one admin key (Phase A4).

So: two weeks of leave with notifications muted, or one bus, and every page goes nowhere, the
backups are undecryptable by anyone, and nobody can log in. Every drill in this plan was written for
one person and passes for one person, which is exactly why this is invisible until it happens.

**This is a decision, not a fact.** A single-operator hobby resolver serving your own household can
rationally accept the risk — the cost of being wrong is that you reconfigure four devices. A
resolver other people depend on cannot. The recommended default for anything with users outside your
household is **one named second holder**, not a team and not a rota; the point is that the number is
greater than zero, not that it is large.

**a) Key escrow that is not a second copy of your own password.** restic supports multiple
independent keys for one repository. Give the second holder their own, so that removing their access
later is one command and does not force you to re-key:

```bash
set -a; . /etc/restic/dns.env; set +a
restic key list                          # note the current key ID; yours is marked with *
# they generate their own password and hand you a file; you never learn its value
restic key add --new-password-file /run/their-password --user "<their-name>"
rm -f /run/their-password                # /run is tmpfs, so this never reached the disk;
                                         # do not stage it in /root or /tmp (Q5a: never write it)
restic key list                          # -> two keys, theirs tagged with their username
# to revoke later, from either holder's session:
#   restic key remove <their-key-id>
```

Do **not** reach for `restic key passwd` when a second holder exists — it changes the password on
the key you are currently using and tells you nothing about the other one. And state the part people
miss: the repository password alone is useless. The second holder also needs the contents of
`/etc/restic/dns.env` (the object-storage credentials), or they can decrypt a repository they cannot
reach.

**b) The accounts, not just the secrets.** Every account in the O6 inventory — registrar, hosting
provider, object storage, healthchecks.io, ntfy, the ACME account — needs a stated answer to "who
else can get into this". A shared vault entry, a provider-native second user where one exists
(hosting providers and registrars usually support this; ntfy.sh on the public instance does not),
or a sealed envelope with a recovery code. O6's second-holder column exists to make the blanks
visible; a blank there is the finding.

**c) A second alerting destination on a different device.** Add a receiver to Phase I8's
Alertmanager routing that reaches a different human, and add a second notification integration to
the healthchecks.io check. I8 already defines two receivers — `ntfy` and `heartbeat` — so the one
you add here is the **third**, and counting receivers is only evidence of it once you count to three.
Then re-run the Phase I11-14 dead-man's-switch proof **against the second recipient's device** — an
untested second receiver is a comment, not a control.

**d) A second SSH admin key**, added and proven with Phase A4's own two-session procedure: open the
new session before closing the old one, every time.

**e) Before any absence long enough that you would not see a page — a weekend, a flight, leave:**

```bash
/usr/local/sbin/dns-health                                 # exit 0
systemctl start restic-backup.service && restic snapshots --last 1   # a snapshot dated today
ls /var/run/reboot-required 2>/dev/null && echo "PENDING REBOOT - do it before you leave"  # (M6)
unattended-upgrade --dry-run 2>&1 | tail -3                 # nothing queued and waiting
git -C /opt/dns-config-backup status --porcelain            # -> empty; nothing uncommitted
```

Then tell the covering person, in writing, **which failures they are expected to handle and which
they are not**. The honest division for one covering person who does not operate this stack daily:

| They handle | They do not |
|---|---|
| Runbook restart order, and the smoke gate | Anything requiring an Ansible run or a vault passphrase |
| N7's table rows with a one-command action | A rebuild (K7) — that is a multi-hour drill they have not rehearsed |
| Escalation steps 1-4 | Escalation step 5 |
| Escalation step 6 — hand traffic to a public resolver — **explicitly pre-authorised** | Deciding whether the privacy trade-off in step 6 is acceptable; you decided that in advance by pre-authorising it |

Pre-authorising step 6 is the single highest-value line in this section. It converts "the operator is
unreachable and the service is down indefinitely" into "the service is degraded to a public
resolver for a week", and it is the only outcome a covering person can reach without your vault.

**f) Onboarding, one page.** Give the second operator the runbook, the smoke gate, and the one-way
traps, which are the things that are obvious to you and invisible to them:

- Never `nft -f` directly — `/usr/local/sbin/nft-apply` only. A bare load flushes every active ban
  and hands banned sources their access back mid-incident (Phase B).
- Never edit AdGuardHome configuration in the admin UI. It rewrites the file, Ansible overwrites it
  back, and the diff is lost (O3).
- Never restart AdGuardHome "as well, to be safe" after restarting Unbound. That is a second,
  unnecessary outage (N4b).
- Never change the AdGuardHome admin password without the second step in K5e.
- Never write a fallback `nameserver` line into `/etc/resolv.conf` and leave it — see the runbook's
  first section.

**Verify:**

```bash
set -a; . /etc/restic/dns.env; set +a
restic key list                                            # -> two keys, one marked with *

# no account in the O6 inventory is missing a second holder
awk '/^## 1\./{s=1;next} /^## 2\./{s=0} s && /^\| *[A-Za-z]/ {split($0,f,"|");
     if (f[6] ~ /TODO/ || f[6] ~ /^ *$/) print "NO SECOND HOLDER:" f[2]}' \
  /opt/dns-config-backup/INVENTORY.md                      # -> no output

# Phase I8 already ships TWO receivers -- `ntfy` and `heartbeat` -- so a test for "more than
# one" passes on an untouched build and proves nothing. Two is the baseline; the second
# holder's receiver is the third.
n=$(grep -c '^  - name:' /etc/alertmanager/alertmanager.yml); echo "receivers=$n"
[ "$n" -ge 3 ] && echo second-receiver-present   # -> >= 3, never 2

ssh-keygen -lf /home/deploy/.ssh/authorized_keys | wc -l   # -> 2
```

---

## PHASE M: Patching and Upgrades

Two properties make DNS different from a generic web service here. First, a restart is a
user-visible outage: an unreachable resolver does not produce an error page, it produces a client
that hangs for seconds and then fails opaquely (see N1). Second, half this stack is not in apt —
AdGuardHome is a downloaded tarball running with `--no-check-update`, which means **it is never
patched unless a human patches it**, and its self-update is deliberately disabled so that the
binary on disk always matches what the deploy pipeline put there.

**The rule for this entire phase, without exception: every upgrade — package, binary, kernel —
ends by running the Phase H12 smoke gate (`/usr/local/sbin/dns-smoke.sh`). If it does not exit 0,
the change is not finished, and you either fix forward immediately or roll back using the
procedure in this phase. "It came up" is not a completion criterion; `SMOKE: PASS` is.**

### M1. unattended-upgrades, with the restart window under control

Security patches must land automatically — nobody applies them by hand at the cadence they are
released. What must not happen automatically is a reboot or a service restart at an arbitrary
moment.

```bash
apt install -y unattended-upgrades

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

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
```

Do **not** bother adding `adguardhome` to `Unattended-Upgrade::Package-Blacklist`. It is not
installed from any apt source, so unattended-upgrades can never touch it; a blacklist entry there
is a comforting no-op that makes the next reader believe a protection exists. `unbound` and `nginx`
*are* apt packages and *will* be restarted by their maintainer scripts during a security upgrade —
that is intentional and correct, and M2 controls how.

**The one package this policy freezes and must not freeze: `dns-root-data`.** Phase C1 installs it
for `/usr/share/dns/root.hints` (Unbound's `root-hints:`, C2) and `/usr/share/dns/root.key` (which
is 24.04's `unbound-anchor` default path, C3). It has **never been published to a `-security`
pocket**: in noble the archive holds `2023112702~willsync1` in the release pocket and
`2024071801~ubuntu0.24.04.1` in `noble-updates`, and nothing else. With the origins list above, a
host built from the noble base image sits on the January-2024 root hints permanently, and nothing in
this plan ever looks at the file's age. Root-server addresses do change; priming usually rescues you,
which is precisely why nobody notices until the day it does not, and the anchor material ages beside
it.

The obvious fix does not work: `Allowed-Origins` is a list of *origins*, not of packages, and
unattended-upgrades has no per-origin package filter — `Package-Whitelist` narrows what is allowed,
it cannot widen an origin for one package. Adding `${distro_codename}-updates` would admit every
non-security update on the box, which is the policy this section deliberately rejects. So take the
package out of unattended-upgrades' hands entirely and upgrade it on its own schedule, appending to
the one cron file (created by Phase I):

```bash
cat >> /etc/cron.d/dns-health << 'EOF'
# dns-root-data ships only from -updates, never -security, so unattended-upgrades
# (M1) can never touch it. Monthly explicit upgrade + a staleness alarm. Unbound is
# NOT restarted here: root.hints is read at startup, and a stale-hints box is not an
# outage -- a surprise 04:40 restart is. The next planned restart picks it up.
40 4 1 * * root apt-get update -qq && out=$(apt-get install -y --only-upgrade dns-root-data 2>&1); if echo "$out" | grep -q '^Setting up dns-root-data'; then /usr/local/sbin/notify.sh info "dns-root-data upgraded" "now $(dpkg-query -W -f='${Version}' dns-root-data) - restart unbound at the next maintenance window to load the new root hints"; fi
50 4 1 * * root find /usr/share/dns/root.hints -mtime +400 -print -quit | grep -q . && /usr/local/sbin/notify.sh warning "root.hints is stale" "dns-root-data has not been updated in over 400 days - check that the monthly upgrade job above is actually running"
EOF
```

**No `%` anywhere in those two lines, deliberately.** cron translates an unescaped `%` into a
newline, so the obvious `find -printf '%TY-%Tm-%Td'` staleness check — and an equally obvious
`printf '%s' "$out"` — truncate the command at the first `%` and silently never run. That is why
`echo` appears above where `printf` would normally be preferred. If you extend these lines, escape
every percent as `\%`.

400 days rather than 365: the package is republished irregularly (the noble update above landed
roughly seven months after release), so a one-year threshold produces a false alarm most years and
teaches you to ignore it.

Phase C3's `unbound-anchor-guard.sh` is the consumer that suffers most from a frozen copy — it
passes `-r /usr/share/dns/root.hints` when it re-bootstraps, so stale hints degrade the one path
that is supposed to recover you. Hardening that guard against looping is Phase C's job, not M1's.

**Verify:**

```bash
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
```

### M2. needrestart: stop it from prompting, and know what it will bounce

Ubuntu 24.04 installs `needrestart`, which detects daemons running against deleted library
versions and restarts them. In interactive mode it prompts, which can stall an unattended apt run
until the dpkg lock times out. In automatic mode it restarts services — including `unbound`,
`nginx` and, if it recognises the unit, `adguardhome` — without asking.

Pick automatic mode, and accept that a libc or OpenSSL security update will bounce the DNS
daemons. That is the correct trade: a resolver running against a deleted, vulnerable OpenSSL is
worse than a two-second restart.

```bash
sed -i "s/^#\?\$nrconf{restart}.*/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
grep -n 'nrconf{restart}' /etc/needrestart/needrestart.conf
```

If you want to exclude a unit from automatic restart, `needrestart` supports a
`$nrconf{blacklist_rc}` regex list — the exact semantics vary by version and are **not verified
here**; check `needrestart.conf(5)` on your build before relying on it. The safer pattern is to
leave automatic restart on and let the churn detector in N4 and the smoke cron in Phase H12 catch
anything that fails to come back.

**Verify:** `needrestart -b` prints `NEEDRESTART-SVC` lines (or none) and exits without prompting.

### M3. AdGuardHome: upgrade and rollback

AdGuardHome is a tarball. Give it a versioned release directory and a symlink so that "roll back"
is one `ln -sfn` rather than a re-download during an outage. In `/etc/systemd/system/adguardhome.service`
(the unit itself is Phase E):

```ini
ExecStart=/opt/adguardhome/current/AdGuardHome \
  -c /opt/adguardhome/conf/AdGuardHome.yaml \
  -w /opt/adguardhome/work \
  --no-check-update
```

Migrate an existing install once:

```bash
install -d /opt/adguardhome/releases/v0.107.78
mv /opt/adguardhome/AdGuardHome/* /opt/adguardhome/releases/v0.107.78/
ln -sfn /opt/adguardhome/releases/v0.107.78 /opt/adguardhome/current
chown -R adguardhome:adguardhome /opt/adguardhome/releases
```

Then update any Phase D deploy-hook or Phase H reference that still points at the old path.

**Three traps, all of which bite on the first upgrade:**

1. **There is no `setcap` step, and if you find one, the unit is wrong.** Phase E grants
   `:53`/`:853` binding with `AmbientCapabilities=CAP_NET_BIND_SERVICE` plus a matching
   `CapabilityBoundingSet`, precisely because `NoNewPrivileges=yes` nullifies *file* capabilities
   across `execve` — a `setcap`'d binary under `NoNewPrivileges=yes` simply cannot bind a
   privileged port and the service never starts. Ambient capabilities are a property of the unit,
   not of the inode, so a replaced binary inherits them automatically. This removes the classic
   "upgraded the binary, forgot setcap, DNS is down" failure entirely.

2. **The new binary migrates the config schema on first start.** After the upgrade,
   `AdGuardHome.yaml` has been rewritten with a higher `schema_version` and possibly a restructured
   layout. The old binary cannot read the new file. The pre-migration copy is therefore the only
   thing that makes a downgrade possible — take it before starting the new version, not after.

3. **Validate as the service user against a scratch work directory.** Since v0.107.53 AdGuardHome
   tightens the permissions of files it touches (CVE-2024-36586 hardening). A root-run
   `--check-config` against the live `conf/` and `work/` leaves root-owned artifacts in a tree
   owned by the unprivileged user, and the *next* real start fails.

```bash
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
```

**Read the release notes before every AdGuardHome upgrade.** Two config areas in this design have
moved before and can move again: the top-level `querylog:` / `statistics:` sections (which were
keys under `dns:` before v0.107.24 — see Phase E), and the TLS/HTTPS listener keys that the
nginx DoH topology depends on (Phase E, canonical decision 5). A schema migration that relocates
either one is silently accepted by the new binary and changes behaviour.

**Verify:**

```bash
/usr/local/sbin/upgrade-adguardhome.sh v0.107.78
readlink -f /opt/adguardhome/current                     # -> .../releases/v0.107.78
systemctl show adguardhome -p AmbientCapabilities        # -> cap_net_bind_service
ss -ulnp | grep ':53 '                                   # -> AdGuardHome bound
grep -E '^schema_version:' /opt/adguardhome/conf/AdGuardHome.yaml
ls /opt/adguardhome/conf/AdGuardHome.yaml.pre-v0.107.78  # downgrade artifact exists
/usr/local/sbin/dns-smoke.sh; echo "exit=$?"             # -> SMOKE: PASS, exit=0
```

### M4. Unbound: distro package, with a trust-anchor and config-compatibility gate

Unbound comes from apt, which removes the whole class of hazard the v1 out-of-apt resolver had
(no maintainer script that stops-and-disables the unit, no conffile prompt on a file you edited).
Two Unbound-specific things still need care.

**Site config never goes in the packaged file.** Keep it in the drop-in directory the package
already includes, so `dpkg` never prompts and never overwrites anything you wrote:

```
/etc/unbound/unbound.conf          <- packaged, untouched, contains include: of the .d dir
/etc/unbound/unbound.conf.d/10-public-resolver.conf   <- everything from Phase C
```

That filename is canonical and the numeric prefix is load-bearing: the packaged `include:` globs
the directory, and Unbound applies drop-ins in glob order. Renaming it — to `dns-node.conf` or
anything else — silently changes which file wins when a second drop-in appears.

**The trust anchor is the thing that breaks after an upgrade.** Validation depends on
`/var/lib/unbound/root.key` being present, current, and readable by the `unbound` user; the package
maintains it via `unbound-anchor`. Ubuntu's packaging ships a `unbound-anchor` oneshot ordered
before `unbound.service` — confirm on your build with `systemctl cat unbound-anchor.service`,
because if that unit is absent or masked the key is never refreshed and validation degrades to
SERVFAIL on everything signed once the anchor rolls. An upgrade that resets ownership on
`/var/lib/unbound` produces the same symptom.

The upgrade procedure:

```bash
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
```

The rollback pins with `apt-mark hold`, which means unattended-upgrades will stop patching unbound
until you release the hold. That is intentional — an unattended re-upgrade into the same broken
state at 03:00 is worse than a stale package — but it is also a landmine, so the standing guard in
M7 checks for holds.

**Verify:**

```bash
unbound-checkconf                                  # -> "unbound-checkconf: no errors in ..."
unbound-control status | head -3                   # remote-control is enabled (Phase C; Phase I
                                                   # scrapes it for metrics), so this must work
dig +dnssec @127.0.0.1 -p 5335 dnssec-failed.org A | grep -c 'status: SERVFAIL'   # -> 1
dig +dnssec @127.0.0.1 -p 5335 cloudflare.com A | grep -c ' ad'                    # -> 1 (AD bit)
apt-mark showhold                                  # -> empty unless a rollback is in force
```

The two `dig` lines are the real gate: they prove the trust anchor survived the upgrade and that
validation both rejects bad signatures and sets AD on good ones. A resolver that starts but no
longer validates is the worst outcome of an Unbound upgrade, and nothing else in the smoke gate
catches it.

### M5. nginx

nginx is an apt package and is upgraded by M1 automatically. It carries a smaller blast radius than
it looks: in this topology (canonical decision 5) nginx terminates public TLS and proxies only
`/dns-query` to AdGuardHome's loopback HTTPS listener, so **an nginx failure takes down DoH only** —
plain DNS on :53 and DoT/DoQ on :853 are served directly by AdGuardHome and are unaffected. Do not
panic-restart the whole stack for an nginx problem.

The only rule: never reload a configuration that has not been tested.

```bash
nginx -t && systemctl reload nginx && /usr/local/sbin/dns-smoke.sh
```

`reload` re-execs workers without dropping listening sockets; `restart` briefly drops :443. Prefer
`reload` for config changes and reserve `restart` for a binary upgrade that needs it.

**Verify:** `nginx -t` prints `syntax is ok` / `test is successful`, and after reload the DoH check
in the smoke gate passes.

### M6. Kernel and reboots

`Unattended-Upgrade::Automatic-Reboot "false"` (M1) means kernel updates install but do not take
effect. That is the right default and a debt you must service.

```bash
# Is a reboot pending, and for what?
test -f /var/run/reboot-required && cat /var/run/reboot-required.pkgs
```

Add it to the weekly review, and alert on it — a node that has been "reboot-required" for six weeks
is running a kernel with known CVEs while you tell yourself you are patched:

```
# appended to /etc/cron.d/dns-health (created by Phase I)
23 9 * * 1 root [ ! -f /var/run/reboot-required ] || logger -t dns-alert "reboot pending: $(tr '\n' ' ' < /var/run/reboot-required.pkgs)"
```

**Single node.** There is no honest zero-downtime story. Reboot in your lowest-traffic window,
announce it if you have users who will notice, and expect 20-60 seconds of total unavailability. If
you want to avoid the reboot entirely for a while, Ubuntu Livepatch covers kernel CVEs without a
reboot and is free for a small number of personal machines; it does not cover userspace, so it
defers reboots rather than eliminating them. Enrolment details are provider-side and **not verified
here**.

**HA pair.** Reboots become routine: drain the master (see the runbook drain procedure), reboot it,
verify with the smoke gate, then hand back or leave the VIP where it is. If you set
`Unattended-Upgrade::Automatic-Reboot "true"` with `Automatic-Reboot-Time "03:00"`, **stagger the
two nodes by at least an hour**. Two nodes rebooting into the same kernel regression at the same
minute converts redundancy into a synchronised outage — this is a real and common self-inflicted
failure.

**Verify:** after any reboot, `/usr/local/sbin/dns-smoke.sh` exits 0 **and** every unit reports
`enabled`, not merely `active` — see M7.

### M7. Standing guards

Two failure modes are invisible until the worst possible moment: a unit that is running but not
enabled (dies at the next reboot), and a package pinned by an emergency rollback that never got
released.

```
# appended to /etc/cron.d/dns-health (created by Phase I)
17 * * * * root for u in unbound adguardhome nginx nftables restic-backup.timer; do systemctl is-enabled --quiet $u || logger -t dns-alert -p daemon.crit "CRITICAL: $u is DISABLED — will not survive reboot"; done
41 9 * * * root h=$(apt-mark showhold); [ -z "$h" ] || logger -t dns-alert "package hold still in force: $h"
```

**The completion rule, restated because it is the whole point of this phase:** an upgrade is
finished when `/usr/local/sbin/dns-smoke.sh` (Phase H12) exits 0. Not when apt returns, not when
`systemctl is-active` says active. The upgrade wrappers in M3 and M4 enforce it and roll back on
failure; do the same by hand for anything not covered by a wrapper.

---

## PHASE N: High Availability and Failure Modes

### N1. What clients actually do when a resolver stops answering

Read this before choosing a tier, because it determines whether HA is even achievable and what
"achievable" buys.

The intuition — "I will just give clients two resolver IPs" — is close to worthless on most
stacks. Failover behaviour is per-platform, mostly undocumented, and uniformly slower than users
expect. What clients actually do:

- **glibc (`/etc/resolv.conf`)** — `resolv.conf(5)` caps you at `MAXNS` 3 nameservers, tries them
  in listed order, with a default `timeout` of 5 seconds and `attempts` 2. If the first resolver is
  **unreachable** (packets dropped, host gone), every lookup waits out that 5-second timeout before
  the second resolver is tried, on every query, forever — the resolver order is not adaptive and
  nothing is remembered between calls. The user-visible symptom is not "failover", it is "the
  internet takes five seconds per page". If the first resolver actively **refuses** (ICMP port
  unreachable, or a REFUSED/SERVFAIL response) the move to the next server is immediate, which is
  why a cleanly stopped daemon is far less damaging than a black-holed one. `options timeout:1
  attempts:1 rotate` improves this materially and almost nobody sets it.

- **systemd-resolved** — genuinely does implement failover: it tracks per-server failures, moves to
  the next configured server, and degrades feature level (EDNS0, DNSSEC) on the way. It is better
  than glibc but not transparent: the first few queries after a failure still fail or stall, the
  feature-level downgrade can persist, and recovery back to the preferred server is not immediate.
  The precise timers vary by systemd version and are **not verified here**.

- **Windows DNS Client** — sends to the preferred server, and on timeout switches to the alternate
  and *sticks with it* for a server-priority window (documented default 15 minutes) before
  re-trying the preferred one. Verify on your build. Practically: failover works, failback is
  delayed, and the first failure costs the user a visible hang of roughly one to a few seconds.

- **macOS / iOS (mDNSResponder)** — queries configured resolvers more aggressively and in parallel,
  so it degrades most gracefully of the four. The behaviour is undocumented and version-dependent;
  do not design around it.

- **Android Private DNS (DoT), and every DoT/DoQ/DoH client in this design** — this is the decisive
  case. Android Private DNS in strict mode accepts **one hostname** and has no secondary. If that
  hostname is unreachable, Android does not fall back to plaintext; it fails closed and the device
  has no DNS at all. The same single-endpoint shape applies to a DoT/DoQ client pointed at
  `dns.example.com` and to a DoH client pointed at `https://dns.example.com/dns-query`.
  Browser-level DoH (Firefox, Chrome in automatic mode) does fall back to the system resolver,
  which merely means those clients silently stop using your service.

**The conclusion that drives the whole phase:** because the encrypted transports this service exists
to provide are configured as a *single endpoint*, client-side failover is not available to you at
all. Any HA you get must move the endpoint — an IP address — between hosts. That rules out "just
publish two A records" and rules in floating IP / VRRP, which is why N2 lands where it does.

### N2. The tiers

| Tier | What it is | Failover time | Recurring cost | Complexity | Recovers from |
|---|---|---|---|---|---|
| **0. Single node, manual rebuild** | One VPS, Phase O rebuild from source control | Your measured RTO (K7) — tens of minutes at best | ~EUR 6/mo | Lowest | Host loss, provider loss |
| **1. Single node, fast recovery + hot spare image** | Tier 0 plus a pre-provisioned but stopped second host | ~5-10 min (start, restore, move IP) | ~EUR 7/mo | Low | Host loss |
| **2. Two independent nodes, two published addresses** | Two full stacks, both A records published | See N1 — seconds of client hang, and useless for DoT/DoQ/Android | ~EUR 12/mo | Low | Nothing, reliably |
| **3. Two nodes + floating IP + keepalived VRRP** | Active/standby, VIP moves on failure | 3-10 s (advert interval × 3 + provider API call) | ~EUR 13-18/mo | Medium | Host loss, daemon failure, planned maintenance |
| **4. Anycast** | Own ASN, own /24 or /48, BGP sessions at N PoPs | Sub-second, routing-layer | USD 90-150/mo for the /24 lease alone, plus compute, plus LIR fees | High, ongoing | Regional/PoP loss |

**Tier 2 deserves an explicit warning** because it looks like the cheap answer and is not. Two
published addresses give you the glibc behaviour in N1 (a five-second stall per query on the dead
address) and give DoT/DoQ/Android clients nothing at all, because those are configured with one
hostname. You will have doubled your cost and your attack surface in exchange for a worse user
experience than a single node.

**Tier 4 is not worth it here, and it is worth saying why plainly.** Anycast requires your own
Autonomous System Number, your own globally routable prefix — a /24 is the smallest IPv4 prefix
that propagates, a /48 for IPv6 — a provider willing to run a BGP session with you (Vultr does this
at no extra charge; most budget VPS providers do not), plus RPKI ROAs and IRR objects that you
maintain. Current IPv4 lease rates put a /24 in the region of **USD 90-150 per month before any
compute**, an order of magnitude above Tier 3. It also *adds* a failure mode Tier 3 does not have:
a route leak, a mis-signed ROA, or an expired IRR object blackholes you globally, and the debugging
loop involves other people's networks. Anycast is the right answer when you have PoPs on multiple
continents and a latency SLO. It is the wrong answer for one operator running a personal or
small-team resolver.

**Recommendation: Tier 3 if the service has users who will notice an outage; Tier 1 otherwise.**

Tier 3 is the cheapest thing that actually delivers failover for the encrypted transports, which
are the reason this service exists (N1). It costs roughly EUR 13-18/month all-in — two small VPS,
one floating IP, and a sub-dollar restic bucket — and it converts kernel reboots and AdGuardHome
upgrades from outages into non-events (M6, M3). Tier 1 is the honest choice if this resolver serves
only you: the money is better spent on a measured, rehearsed RTO (K7) than on a standby you will
never test.

If you choose Tier 1, skip N3 and go to N4 — the systemd fixes there matter more on a single node,
not less, because self-healing is the only redundancy you have.

### N3. Tier 3: keepalived VRRP with a floating IP

Both nodes run the identical stack, built by the same Ansible run (Phase O). Both resolvers stay
hot, so the standby's Unbound cache is warm at all times and a failover does not start from an
empty cache. Only the VIP moves.

**Script placement is a hard prerequisite, not a detail.** `enable_script_security` refuses to run
any script whose path is writable by a non-root user, and on Debian/Ubuntu `/usr/local/sbin` is
mode 2775 root:staff. Scripts in `/usr/local/sbin` are silently refused. Put keepalived's scripts
somewhere root-owned:

```bash
apt install -y keepalived
install -d -m 0755 -o root -g root /etc/keepalived/scripts
useradd -r -s /usr/sbin/nologin keepalived_script 2>/dev/null || true

cat > /etc/keepalived/scripts/vrrp-dns-check.sh << 'EOF'
#!/bin/bash
# Runs as keepalived_script. Non-zero exit => vrrp_script failure.
# Checks the resolver, not just the daemon: a hung Unbound still holds its PID.
dig +time=1 +tries=1 @127.0.0.1 -p 5335 google.com A +short 2>/dev/null | grep -qE '^[0-9]+\.'
EOF
chmod 0755 /etc/keepalived/scripts/vrrp-dns-check.sh
chown root:root /etc/keepalived/scripts/vrrp-dns-check.sh
```

Node A `/etc/keepalived/keepalived.conf` (node B differs only in `priority`, `unicast_src_ip` and
`unicast_peer`):

```
global_defs {
    enable_script_security
    script_user keepalived_script
}

vrrp_script chk_dns {
    script "/etc/keepalived/scripts/vrrp-dns-check.sh"
    interval 2
    timeout 2
    fall 3
    rise 2
    # `weight` is DELIBERATELY OMITTED. The default weight of 0 means <fall> consecutive
    # failures drive the instance into FAULT state, which stops adverts and hands the VIP
    # over. A negative weight only SUBTRACTS from priority: with 200/100 a `weight -40`
    # leaves 160 > 100 and nothing ever fails over. FAULT-state handover also still works
    # under `nopreempt`; priority-based takeover does not.
}

vrrp_instance DNS_VIP {
    state BACKUP          # both nodes BACKUP + nopreempt = no flapping when A recovers
    nopreempt
    interface enp7s0      # the PRIVATE nic carrying the heartbeat
    virtual_router_id 51
    priority 200          # node B: 100
    advert_int 1
    unicast_src_ip 10.0.0.2      # node B: 10.0.0.3
    unicast_peer {
        10.0.0.3                 # node B: 10.0.0.2
    }
    authentication {
        auth_type PASS
        auth_pass s3cr3tvr       # VRRPv2 PASS is 8 bytes; anything longer is truncated
    }
    virtual_ipaddress {
        203.0.113.10/32 dev eth0 # the floating IP, added locally on the master
    }
    track_script {
        chk_dns
    }
    # Runs as root: it must read the systemd credential (K5c), and it lives in a
    # root-owned directory so enable_script_security permits it.
    notify_master "/etc/keepalived/scripts/claim-floating-ip.sh" root root
}
```

On most clouds, adding the VIP locally is not enough — the provider must also be told to route it
here:

```bash
cat > /etc/keepalived/scripts/claim-floating-ip.sh << 'EOF'
#!/bin/bash
set -euo pipefail
HCLOUD_TOKEN=$(cat "${CREDENTIALS_DIRECTORY:-/etc/keepalived}/provider")
export HCLOUD_TOKEN
exec /usr/local/bin/hcloud floating-ip assign dns-vip "$(hostname)"
EOF
chmod 0750 /etc/keepalived/scripts/claim-floating-ip.sh
chown root:root /etc/keepalived/scripts/claim-floating-ip.sh
```

DigitalOcean's equivalent is `doctl compute reserved-ip-action assign <ip> <droplet-id>` and
Vultr's is `vultr-cli reserved-ip attach` — both **unverified**; confirm against your provider's
current CLI before relying on the exact syntax. Scope the token to floating-IP assignment only: a
full project token in a script on a public-facing box can delete your servers.

**The firewall must pass VRRP** between the two private addresses. VRRP is IP protocol 112, which
is neither TCP nor UDP and is therefore not covered by any port rule. The rule goes in `chain input`
of `table inet filter` in `/etc/nftables.conf`, which Phase B is the sole author of — `chain input`
is the only base chain hooking input in this design, so there is exactly one place this can go. It
does **not** go in `dns_guard`: that is a regular chain jumped from `input` and it exists solely for
UDP/53 flood detection, so a protocol-112 rule there is both off-topic and unreachable for anything
that never reaches the jump. Add it alongside the other `input` accepts, and do not add a table or a
chain of your own for it:

```
    # VRRP heartbeat, private network only
    iifname "enp7s0" ip saddr 10.0.0.0/24 ip protocol 112 accept
```

**Certificates must move to DNS-01 in a Tier 3 deployment, and this is mandatory.** HTTP-01
validates against the A record of `dns.example.com`, which resolves to the VIP, which lives on
exactly one node at a time — the standby can never renew and its certificate expires silently.
Switch Phase D to the DNS-01 plugin, issue on node A only, and ship `/etc/letsencrypt/{archive,live,renewal}`
to node B preserving symlinks. **Exactly one node may hold an active renewal timer**; both nodes get
certbot's twice-daily timer by default, and two independent renewals produce divergent certificates
and doubled ACME traffic:

```bash
# on the standby only
systemctl disable --now certbot.timer
```

Once HTTP-01 is gone, the `tcp dport 80 accept` rule in Phase B is no longer needed *for issuance*.
Keep it anyway — it is a standing rule, not a renewal-window rule. The single port-80 server block
(Phase E writes it and owns the listener, Phase D uses it for the ACME webroot) also serves the
Phase Q well-known files from `/var/www/acme`. There is no redirect-to-HTTPS on that block anywhere
in this design; Phase E states that deliberately. Closing port 80 on a Tier 3 pair takes the
well-known files with it.

**Verify:**

```bash
keepalived -t -f /etc/keepalived/keepalived.conf          # config parses

# prove the health script drives FAULT rather than a priority nudge:
systemctl stop unbound
sleep 8; journalctl -u keepalived -n 20 --no-pager | grep -i 'Entering FAULT STATE'
ip -4 addr show dev eth0 | grep -c 203.0.113.10           # -> 0 on the demoted node
systemctl start unbound

# prove keepalived is actually allowed to run the notify script:
journalctl -u keepalived --no-pager | grep -iE 'unsafe|SECURITY VIOLATION|Permission denied'
echo "grep exit=$? (1 = clean)"

# VRRP is reaching the peer, and the rule sits in `chain input` (not in dns_guard):
nft list chain inet filter input | grep 'ip protocol 112'
nft list chain inet filter dns_guard | grep -c 112     # -> 0
tcpdump -ni enp7s0 proto 112 -c 4

# exactly one node renews:
systemctl is-enabled certbot.timer     # enabled on node A, disabled on node B
```

### N4. systemd self-heal: the correctness fix

This applies to **every** tier, and it matters most on a single node.

**What is actually broken in the v1 units.** `Restart=on-failure` with `RestartSec=5` interacts with
systemd's defaults — `DefaultStartLimitBurst=5` over `DefaultStartLimitIntervalSec=10s` — such that
a daemon which crash-loops is *abandoned*. systemd.unit(5) is explicit: units configured for
`Restart=` that reach the start limit "are not attempted to be restarted anymore". A transient
problem lasting a minute becomes a permanent outage that persists until a human notices. On a DNS
resolver that is the single worst default in the stack.

**What is *not* broken, stated so nobody fixes the wrong thing.** `Requires=` does **not** propagate
a crash. systemd.unit(5) says the dependent unit is stopped or restarted only if the required unit
is "explicitly stopped (or restarted)". Propagation of an unexpected exit is `BindsTo=`, which this
design does not use. So AdGuardHome survives an Unbound crash today. What `Requires=` genuinely
costs is narrower but still worth fixing: (i) the runbook's `systemctl restart unbound` silently
restarts AdGuardHome underneath the operator, who then restarts it again, doubling the outage
window; (ii) at boot, `Requires=` + `After=` means an Unbound that fails to activate prevents
AdGuardHome from starting at all — so a resolver config typo takes out the public listener too.

**N4a) Give the units a restart policy that survives a transient fault.** These keys go into the
canonical unit drop-in — `/etc/systemd/system/<unit>.service.d/hardening.conf`, the same single
drop-in file that carries Phase C's Unbound hardening and Phase A6's memory ceilings. There is one
drop-in per unit in this design and it is assembled by the Ansible template (Phase O), not by a
shell `cat >` that would silently truncate the other phases' settings out of it. There is no
`ha.conf` and no `limits.conf`.

```ini
# /etc/systemd/system/unbound.service.d/hardening.conf
# (identical stanza in adguardhome.service.d/hardening.conf and nginx.service.d/hardening.conf)
[Unit]
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Restart=always
RestartSec=5
```

```bash
systemctl daemon-reload
```

These are the canonical values, shared with Phase C4 — do not set different ones here, and do not
set them a second time in a second drop-in. They change systemd's default
(`DefaultStartLimitBurst=5` over `DefaultStartLimitIntervalSec=10s`) in two ways at once: twice the
attempt budget, over a window thirty times longer. The wider window is the important half: ten
seconds is short enough that a fast crash loop burns the whole burst inside it while a slower one
lets the counter forget the episode entirely, so the default is simultaneously too easy to trip and
useless as a record of what happened. At 300 seconds the count accumulates over an entire failure
episode and becomes a signal you can act on. Ten attempts at `RestartSec=5` is roughly fifty seconds
of retrying, which covers the transient faults that matter here — an upstream blip, a slow disk at
boot, a peer that comes back — and does not cover a config typo.

It is deliberately **not** unlimited. A daemon that is genuinely broken — bad config, missing file,
corrupt binary — hits ten failures in fifty seconds and is parked in `failed`, which is the correct
outcome: an infinite restart loop against a config typo burns CPU, floods the journal, and hides the
fault behind a unit that always reports "activating". The backstop only works if somebody is told,
which is what N4c is for. Clear a parked unit with `systemctl reset-failed <unit>` after fixing the
cause.

Exponential backoff (`RestartSteps=` / `RestartMaxDelaySec=`, systemd v254+, present on Ubuntu
24.04's systemd 255 and absent on 22.04's 249) is not used: the flat five-second interval plus the
ten-in-five-minutes ceiling already bounds the spin, and a second mechanism doing the same job with
different numbers is how the two phases drifted apart in the first place.

**N4b) Loosen the dependencies so a restart upstream does not bounce the public listener.** In
`/etc/systemd/system/adguardhome.service`, replace `Requires=unbound.service` with:

```ini
Wants=unbound.service
After=unbound.service
```

and in the nginx unit's drop-in, express the DoH dependency the same way:

```ini
# /etc/systemd/system/nginx.service.d/hardening.conf   (add to the [Unit] section above)
Wants=adguardhome.service
After=adguardhome.service
```

`Wants=` still orders startup correctly at boot, eliminates the double restart, and lets
AdGuardHome come up and serve from its own cache even when Unbound is failing to start. Never use
`BindsTo=` anywhere in this stack: it is the directive that would turn one daemon's crash into a
full-stack outage.

**N4c) Make failure visible, and do not rely on `OnFailure=` alone.** With the canonical limits in
N4a a unit *can* reach the terminal `failed` state, so `OnFailure=` is live and worth wiring. It is not
sufficient. The dangerous case is the daemon that restarts nine times every five minutes forever: it
never trips the limit, never reaches `failed`, never fires `OnFailure=`, and reports `active` to
every naive check while dropping queries continuously. Alert on restart churn as well:

```bash
cat > /usr/local/sbin/check-restart-churn.sh << 'EOF'
#!/bin/bash
# NRestarts is monotonic for the lifetime of a unit start; a jump between samples
# means the unit is crash-looping even though it currently reports 'active'.
STATE=/var/lib/dns-health/nrestarts
install -d /var/lib/dns-health; touch "$STATE"
for u in unbound adguardhome nginx; do
  now=$(systemctl show "$u" -p NRestarts --value)
  was=$(awk -v u="$u" '$1==u {print $2}' "$STATE"); was=${was:-$now}
  if [ $(( now - was )) -ge 5 ]; then
    logger -t dns-alert -p daemon.crit "CRASH LOOP: $u restarted $(( now - was )) times in the last interval"
    # notify.sh <severity> <title> [message] — severity and title are SEPARATE arguments.
    # A single-argument call sends the whole sentence as the severity, which pages at the
    # wrong priority and drops the body entirely.
    /usr/local/sbin/notify.sh critical "CRASH LOOP: $u on $(hostname)" \
      "$u restarted $(( now - was )) times in the last 5 minutes and still reports active"
  fi
  sed -i "/^$u /d" "$STATE"; echo "$u $now" >> "$STATE"
done
EOF
chmod 750 /usr/local/sbin/check-restart-churn.sh
```

```
# appended to /etc/cron.d/dns-health (created by Phase I)
*/5 * * * * root /usr/local/sbin/check-restart-churn.sh
```

`/usr/local/sbin/notify.sh` is **defined by Phase I** and is the single notification entry point for
the whole stack; this phase calls it and does not define its own. Its signature is
`notify.sh <severity> <title> [message]` — three positional arguments, never one string.
`/etc/cron.d/dns-health` is also created by Phase I — this line is appended to it. A check that only
writes to syslog is not an alert.

**Verify:**

```bash
systemctl show unbound -p Restart -p RestartUSec -p StartLimitBurst -p StartLimitIntervalUSec
#   -> Restart=always  RestartUSec=5s  StartLimitBurst=10  StartLimitIntervalUSec=5min

# self-heal through a transient fault — with the stock defaults this left the unit dead:
for i in 1 2 3; do systemctl kill -s SIGKILL unbound; sleep 7; done
sleep 10; systemctl is-active unbound          # -> active

# and the deliberate backstop: exceeding the burst parks the unit rather than looping forever
for i in $(seq 1 12); do systemctl kill -s SIGKILL unbound; sleep 5; done
systemctl is-failed unbound                    # -> failed  (this is correct, not a bug)
systemctl reset-failed unbound && systemctl start unbound && systemctl is-active unbound

# explicit-stop propagation is what Requires= actually did; confirm it is gone:
systemctl stop unbound
systemctl is-active adguardhome                # -> active   (with Requires=: inactive)
systemctl start unbound

systemctl show unbound -p NRestarts --value
/usr/local/sbin/check-restart-churn.sh; journalctl -t dns-alert -n 5 --no-pager
```

### N5. Resource ceilings and the OOM killer

The v1 plan sizes the box by assertion (2 vCPU / 4 GB) and then configures an Unbound message and
RRset cache plus an AdGuardHome cache plus query logging, with no ceiling on any of it. Most VPS
images ship with **zero swap**, so when resident memory passes the limit the kernel OOM killer
picks a victim by heuristic — and the largest RSS on this box is the resolver. The OOM killer takes
out DNS, `Restart=always` restarts it into the same memory pressure, and you have a loop.

**N5a) The ceilings and the swap file belong to Phase A6. This phase sets neither.** Memory and swap
have exactly one owner in this document, and it is not High Availability. **Phase A6** provides the
swap file, `vm.swappiness` (in Phase A's `/etc/sysctl.d/99-dns.conf` — the only sysctl file in this
design that may carry that key), and the `MemoryHigh=` / `MemoryMax=` / `OOMScoreAdjust=` keys for
`unbound` and `adguardhome`. Those keys live in the same
`/etc/systemd/system/<unit>.service.d/hardening.conf` drop-ins this phase adds its restart settings
to (N4a), which is why there is one drop-in file per unit and not a `limits.conf` beside it.

Do not restate the numbers here, do not create a second swap file, and do not write a second
`vm.swappiness` sysctl in a `99-swap.conf`. Two files setting the same key is how a box silently
ends up with whichever one sorts last, and the failure is invisible until the day the OOM killer
runs.

**N5b) Why those ceilings exist, which is this phase's actual contribution.** A cgroup ceiling
converts an unbounded, box-wide failure into a bounded, single-service one: with `MemoryMax=` the
resolver's cgroup is what dies, not an arbitrary victim chosen by the kernel's heuristic, and
`MemoryHigh=` throttles and reclaims before it gets that far. The negative `OOMScoreAdjust=` on both
DNS daemons is the other half: if the box does go OOM, the kernel must take something else.

The expendable workload is `restic-backup.service`, which already carries `OOMScoreAdjust=500`
(K4). With the v1 cache warmer retired (Phase F, see below) there is no other sacrificial process on
this box, which is exactly why Phase A6's swap file is not optional — it is the shock absorber that
gives `MemoryHigh=` time to reclaim instead of the kernel killing something immediately. It is tuned
so it is never used for routine paging, because swapping a resolver destroys p99 latency; that is
what the low `vm.swappiness` is for.

**N5c) Size the cache from measurement, not from a round number.** Unbound's resident set runs
materially above the configured `msg-cache-size` + `rrset-cache-size` (allocator overhead plus
per-thread structures); budget roughly double and then measure. Phase A6's ceilings are a starting
point that must be reconciled with the actual cache sizes set in Phase C:

```bash
systemctl show unbound -p MemoryCurrent      # bytes, right now
unbound-control stats_noreset | grep -E 'mem\.cache|msg\.cache|total\.num'
```

Baseline after 48 hours of real traffic. If `MemoryCurrent` under load approaches `MemoryHigh`,
halve the cache sizes in Phase C before buying RAM — a resolver fronting a handful of clients will
never populate a huge cache, and the memory buys nothing.

### N6. Scale up or scale out

Use thresholds, not vibes:

| Signal | Action |
|---|---|
| Sustained load average > 1.5 on 2 vCPU, or `%steal` consistently > 5% | Scale **up** (more vCPU, or a less contended provider) |
| `MemoryCurrent` > 70% of RAM with cache sizes already tuned (N5c) | Scale **up** (RAM) |
| Cache hit ratio falling while cache size is at its ceiling | Scale **up** (RAM), not out — a second node halves each node's hit rate |
| You care about uptime at all | Scale **out** — a second node, now. This is not a traffic threshold |
| Clients in a second region with > 80 ms RTT | Scale **out** geographically (a floating IP per region, still not anycast) |
| Provider egress or packets-per-second cap being hit | Scale **out** |

The asymmetry that matters: scaling **up** buys throughput, scaling **out** buys availability, and
this service's realistic failure mode is availability. A 2 vCPU / 4 GB node with a warm cache will
serve well past the throughput the Phase H load test targets. You will hit "the host rebooted" long
before you hit "the host is too small".

**Cost, order-of-magnitude, for the recommended tier** (assumed, check current pricing):

- 2 × small VPS (2 vCPU / 4 GB): ~EUR 5-8/mo each
- 1 floating / reserved IP: ~EUR 1/mo
- Object storage for restic (config-only snapshots, well under 1 GB): ~USD 1/mo
- **Total ≈ EUR 13-18/mo for a genuinely redundant service**, against USD 90-150/mo for the anycast
  /24 lease alone.

**Verify:**

```bash
# these confirm what Phase A6 set; if they are empty, A6 did not run, not N5
systemctl show unbound     -p MemoryHigh -p MemoryMax -p OOMScoreAdjust
systemctl show adguardhome -p MemoryHigh -p MemoryMax -p OOMScoreAdjust
systemd-cgtop -1 -n1 --order=memory | head -15
free -h && swapon --show && sysctl vm.swappiness      # -> vm.swappiness = 10
ls /etc/sysctl.d/                                     # -> 99-dns.conf (A) and 99-nftables-edge.conf
                                                      #    (B) only; no 99-swap.conf

# nothing was OOM-killed during or after the Phase H load test:
journalctl -k --since '-1h' | grep -iE 'oom|killed process'; echo "grep exit=$? (1 = clean)"
df -h /opt /var && du -sh /var/log/adguardhome/querylog /var/lib/adguardhome/stats
```

### N7. Failure modes

Phase F (the v1 Python cache warmer) is **retired** and appears in none of these rows. Unbound's
in-process `prefetch` / `prefetch-key` does that job correctly with no extra daemon and no
self-inflicted query load; see Phase C. Any runbook row you find referencing `dns-warmer` is stale.

| Symptom | Likely cause | Immediate action | How Phase I sees it |
|---|---|---|---|
| All lookups time out from everywhere | Host down, or VIP not attached to any node | Check provider console; `hcloud floating-ip describe dns-vip`; on Tier 3 check `journalctl -u keepalived` on both nodes | External probe fails; node stops reporting |
| All lookups time out, host is up and SSH works | nftables ruleset reloaded without the UDP/53 accept for NOTRACK'd traffic (Phase B) — `ct state established,related accept` does not cover untracked packets | `nft list ruleset \| grep -A5 notrack`; restore the known-good `/etc/nftables.conf` from restic (Phase K) and apply it with `/usr/local/sbin/nft-apply` (Phase B), never a bare `nft -f` | Smoke gate: `AGH udp/53 public` FAIL, loopback OK |
| Everything resolves except DNSSEC-signed names (SERVFAIL) | Trust anchor missing, stale, or wrong ownership after an Unbound upgrade (M4); or clock skew | `test -s /var/lib/unbound/root.key`; `stat -c '%U %a' /var/lib/unbound/root.key`; `timedatectl`; then `unbound-anchor -a /var/lib/unbound/root.key && systemctl restart unbound` | AD-bit / SERVFAIL probe in Phase I |
| **Every** name SERVFAILs, signed and unsigned alike; `chronyc tracking` shows `Reference ID : 00000000` and `Leap status : Not synchronised`; SSH by IP still works | Clock skew, **not** a trust-anchor fault. DNSSEC signatures carry inception and expiration times, so a skewed clock fails every signature at once — and after C5.8 this host resolves its own NTP pool names through its own validator, so the clock cannot be fixed by the path that needs it fixed (A2) | `timedatectl` **first** — more than a few minutes out and it is this, so do not spend the row above's `unbound-anchor` and cache dump on it. Then run A2's console-recovery procedure ("Recovering a host that is already deadlocked") from the out-of-band console or an SSH session opened by IP: `systemctl stop chrony`; `date -u -s '<UTC now>'`; `systemctl start chrony`; `chronyc makestep`; `chronyc tracking`; then `systemctl restart unbound adguardhome` to clear the validation failures cached while the clock was wrong | `ClockUnsynchronised` and `ClockOffsetHigh` (Phase I6), deliberately distinct alerts from `DNSSECValidationBroken`; `chrony` is also in `dns-smoke.sh`'s `UNITS` list (H12) |
| Plain DNS fine, DoH broken, DoT/DoQ fine | nginx down or bad config — DoH is the only path through nginx (canonical decision 5) | `nginx -t && systemctl reload nginx` | Smoke gate: `DoH :443` FAIL alone |
| DoH broken and the admin login page is reachable from the internet | AdGuardHome HTTPS listener bound publicly instead of `127.0.0.1:8053` — its HTTPS listener inherits the host from `http.address` (Phase E) | Fix `http.address`/`port_https` per Phase E, restart AGH, then re-check `curl https://<PUBIP>/` | Smoke gate: `admin UI not public` FAIL |
| All TLS transports fail simultaneously after a renewal | Certificate renewed on disk but not reloaded into AdGuardHome, or `conf/ssl` is root-owned 0700 (K5a) | `stat -c '%U:%G %a' /opt/adguardhome/conf/ssl`; run the Phase D deploy hook; restart AGH | Smoke gate: served-cert fingerprint ≠ on-disk fingerprint |
| Resolver "active" but answers nothing | Unbound hung, or upstream/root reachability lost | `dig @127.0.0.1 -p 5335 . NS`; `systemctl restart unbound`; check egress ACLs | Smoke gate: `unbound 127.0.0.1:5335` FAIL; on Tier 3 keepalived enters FAULT |
| Service dies at 03:00 and stays dead | Unattended upgrade restarted a daemon into a bad config, and it exhausted the start limit (10 in 5 min, N4a) | `journalctl -u <unit> --since 02:00`; `systemctl show <unit> -p NRestarts`; roll back per M3/M4, then `systemctl reset-failed <unit>` | Churn detector (N4c) and smoke cron |
| Unit is running now, gone after reboot | Left `disabled` by a manual install or an emergency fix | `systemctl enable <unit>` | Hourly `is-enabled` guard (M7) |
| Memory climbing, then a daemon vanishes | Cache oversized for the box; OOM killer (N5; the ceilings and swap are Phase A6) | `journalctl -k \| grep -i oom`; reduce Phase C cache sizes; confirm Phase A6's swap file is on | `MemoryCurrent` trend; churn detector |
| `/opt` or `/var` filling | Query log growth (retention is Phase Q) or accumulated release directories (M3) | Check `du -sh /var/log/adguardhome/querylog /var/lib/adguardhome/stats`; prune `releases/` | Disk guard in Phase I |
| One client floods the resolver | Abuse (Phase J). **Do not look in the query log for the source** — `anonymize_client_ip: true` masks IPv4 to /16 and IPv6 to /48 on disk, so any ban derived from it targets a masked, wrong address | Use the kernel-side nftables counters from Phase J; ban with `nft add element inet filter banned_ips { <IP> timeout 10m }` — 10 minutes on first offence, escalating to 24 hours on repeat, per Phase J | nftables counter rates, Phase I |
| Failover happened but clients still hang | Expected. See N1 — glibc waits out its 5 s timeout per query against a black-holed address | Nothing to fix on the server; if it recurs, shorten client `options timeout:1 attempts:1` where you control the clients | External probe recovers while user reports persist |
| One user on a mobile carrier, conference WLAN or IPv6-only network reports "most sites fail" with no DNS error, while `dig` from everywhere else is clean | Their access network is IPv6-only behind NAT64 and its own resolver was doing DNS64. **This resolver does no DNS64 and deliberately never will** (R11): Unbound answers truthfully, so AAAA synthesis stops and RFC 7050 prefix discovery — which reads the prefix out of a synthesised `ipv4only.arpa` AAAA — stops with it. Nothing on this host is broken | Confirm from the affected device with R11's discriminator, using the network's own resolver, not the one under test: `dig @"$NETNS" ipv4only.arpa AAAA +short` returns addresses (typically in `64:ff9b::/96`) while `dig @<PUBLIC_IP> ipv4only.arpa AAAA` returns NOERROR with no answer. Tell them to keep the network-provided resolver on that network, or to reach this one through the Phase P6 WireGuard tunnel, which carries IPv4 inside. **Do not enable `module-config: "dns64 ..."` on this resolver** — synthesising AAAA into a translator you do not operate black-holes every dual-stack client on the internet (R11) | Invisible to every monitor here, and correctly so: the server is healthy and its answers are right. It arrives as a user report and nothing else |
| Both nodes rebooted at once | Unattended reboot windows not staggered (M6) | Stagger `Automatic-Reboot-Time` by ≥ 1 hour | Both nodes silent simultaneously |
| `apt`, `certbot` and `restic` all fail to resolve while you are fixing something else | `/etc/resolv.conf` points at `127.0.0.1:53`, which is **AdGuardHome** — the thing that is down (C5.8) | Re-flip `resolv.conf` to a public resolver for the duration, restore it before you close the incident — see the runbook's first section | Not visible to any monitor. This is a self-inflicted diagnostic dead end, and the errors name the tool, never the cause |

### N8. When the address has to change

The risk register calls provider AUP suspension for running an open resolver *more likely to end
this service than any regulator*, and Phase Q says suspension — not a warning — is the normal
enforcement once your IP appears in a reflection report. Both stop at "read the terms before
launch". The response to a suspension is a different provider and therefore a different address,
and Phase A1's warning that the IP is published in DNS, in client configuration and in a
Certificate Transparency log is the entire blast radius stated once and never returned to.

Read the uncomfortable half first, because it changes what you do on day one. **Every Do53 user
typed the address into a router or an OS setting by hand.** There is no mechanism to update them,
no failover, and no notification channel that reaches them. A forced IP change is a permanent
outage for that population regardless of how well you execute everything below. That is the
argument for steering users to `dns.example.com` over DoT/DoQ/DoH rather than to a literal address,
and it is an argument you can only act on before the incident.

**The one step you cannot do retroactively.** Lower the TTL on the `A`/`AAAA` records for
`dns.example.com` *before* you need to. Once the box is null-routed, a 3600-second TTL is 3600
seconds of outage you have already committed to and cannot shorten. The standing recommendation is
to keep that record at **300 seconds permanently** — the query volume on one hostname is
irrelevant, and the flexibility is the whole point.

```bash
dig +noall +answer dns.example.com A | awk '{print $2}'     # -> 300, today, not on the day
```

**Rehearse the order assuming you cannot log into the old box**, because a suspension usually
arrives with the address already unreachable. Nothing below requires the old host except the two
steps that say so.

1. **Provision and build the new node** from Phase O cloud-init plus the playbook, and restore
   `/etc/letsencrypt` from restic (K7 steps 3-6). The certificate is for the *name*, not the
   address, so it migrates unchanged — this is why K3 backs the whole lineage up.
2. **Set the PTR at the new provider** before cutover. Phase Q4 explains why: matching forward and
   reverse is what makes an abuse desk route a complaint to you instead of null-routing the address,
   and you are about to be a new IP with no reputation.
3. **Cut over the `A`/`AAAA` records.** With a 300 s TTL, encrypted clients follow within five
   minutes; Do53 clients never follow.
4. **Keep the old address answering for as long as the old provider allows.** If the suspension left
   you any window at all, run both in parallel. This is the only mitigation the Do53 population gets.
5. **The things that do not follow the `A` record** — this is the list nobody assembles at 2am:
   - **Phase P WireGuard peer configs** with a literal `Endpoint =` rather than the hostname. If any
     client has one, that client is dead until you re-issue its config.
   - **Phase B's `allowlist4`/`allowlist6` and Phase P's access controls**, which are written from
     the *clients'* side and unaffected by your address change — but any upstream ACL that named your
     old address (a corporate firewall, a partner's allowlist) is now wrong.
   - **The blackbox probe targets** in Phase I, and the external monitors: the healthchecks.io check
     and the ntfy topic survive, but any probe pointed at a literal address does not.
   - **`security.txt` and the published privacy notice** (Phase Q5), if either names the address.
   - **The provider abuse-forwarding arrangement.** Phase Q6 tells you to record its reference; that
     reference is provider-specific and does not migrate. Open a new one.
   - **The Ansible inventory and the cloud-init file**, and the O6 inventory's provider rows.
6. **Re-run the go-live gate**, not just the smoke gate. Phase L exists because a new address on the
   internet is a new exposure surface: re-check that the admin UI is not public and that nothing but
   :53, :443, :853 and :80 answers.

**Verify:**

```bash
/usr/local/sbin/dns-smoke.sh                                          # SMOKE: PASS on the new node
dig +short -x <NEW-IP>                                                # -> dns.example.com.
grep -rl '<OLD-IP>' /srv/dns-infra /etc/wireguard /etc/prometheus \
  /var/www/acme/.well-known /opt/dns-config-backup 2>/dev/null        # -> no output
```

---

## PHASE O: Provisioning and Reproducibility

The v1 plan is a runbook for a human, executed once, by hand. Nothing captures the result. That has
three production consequences: rebuilding after host loss means re-typing forty-odd commands under
outage pressure, which is exactly when people skip a `chown` and forget `systemctl enable`; a second
node drifts from the first the moment anyone edits a config on one box, and drift between DNS nodes
is invisible until failover, when it becomes an outage; and there is nowhere to test a change except
production. "However long it takes a tired human" is not an RTO.

### O1. cloud-init: bare VPS to reachable-and-firewalled on first boot

This file's only job is to make the box reachable by Ansible with a default-deny firewall already in
place. Everything real comes from the playbook.

```yaml
#cloud-config
hostname: dns1
fqdn: dns1.example.com
preserve_hostname: false
timezone: UTC
package_update: true
package_upgrade: true
packages: [python3, sudo, curl, jq, git, nftables, chrony, unattended-upgrades]
users:
  - name: deploy
    groups: [sudo]
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh_authorized_keys:
      - ssh-ed25519 AAAAC3Nza... ops@laptop
write_files:
  - path: /etc/ssh/sshd_config.d/99-hardening.conf
    permissions: '0644'
    content: |
      PermitRootLogin no
      PasswordAuthentication no
      KbdInteractiveAuthentication no
  - path: /etc/nftables.conf
    permissions: '0600'
    content: |
      #!/usr/sbin/nft -f
      flush ruleset
      table inet filter {
        chain input {
          type filter hook input priority 0; policy drop;
          iif lo accept
          ct state established,related accept
          ip protocol icmp accept
          ip6 nexthdr icmpv6 accept
          tcp dport 22 accept
        }
        chain forward { type filter hook forward priority 0; policy drop; }
        chain output  { type filter hook output  priority 0; policy accept; }
      }
runcmd:
  - [systemctl, enable, --now, nftables]
  - [systemctl, enable, --now, chrony]
  - [systemctl, restart, ssh]
```

This bootstrap ruleset is deliberately minimal and is **replaced wholesale** by Phase B's ruleset on
the first Ansible run — a single `table inet filter` carrying the input path, the NOTRACK chain for
UDP/53 (canonical decision 9), the flood meters and the ban sets. All of that is absent here on
purpose: nothing is listening on 53 yet, and a second table added at bootstrap is a second table
somebody has to notice and remove later.

Two Ubuntu 24.04 specifics:

- The stock `/etc/ssh/sshd_config` contains `Include /etc/ssh/sshd_config.d/*.conf`, which is what
  makes the drop-in above effective, and the unit is `ssh.service` (not `sshd.service`).
- 24.04 enables **socket activation** for SSH by default. Under `ssh.socket`, `Port` and
  `ListenAddress` in `sshd_config` are ignored — the socket unit owns them. The hardening keys above
  are unaffected, but if Phase A moves SSH off port 22 you must configure the socket, not the
  daemon. Check with `systemctl is-enabled ssh.socket` before assuming either way.

**Put no secrets in user-data.** On most providers it remains readable from the instance metadata
service by any local process for the life of the instance.

### O2. Ansible layout, and where the role boundaries fall

```
dns-infra/
├── ansible.cfg
├── inventory/prod.yml            # dns1, dns2 in group [dns]; dns1+dns2 also in [dns_ha]
├── group_vars/dns/vars.yml       # fqdn, upstream policy, cache sizes, VIP, peer private IPs
├── group_vars/dns/vault.yml      # ansible-vault, whole-file encrypted (Phase K5)
├── site.yml
├── handlers/main.yml             # ONE shared handlers file — see O3, ordering is load-bearing
└── roles/
    ├── base/          # Phase A: users, sysctl (99-dns.conf), swapfile + service memory ceilings
    │                  #          (A6), limits, sshd, chrony, unattended-upgrades (M1/M2)
    ├── nftables/      # Phase B: templates/nftables.conf.j2 — one table inet filter with the
    │                  #          NOTRACK chain, flood meters and ban sets; plus nft-apply and
    │                  #          sysctl 99-nftables-edge.conf
    ├── unbound/       # Phase C: unbound.conf.d/10-public-resolver.conf.j2, trust anchor,
    │                  #          unbound.service.d/hardening.conf drop-in
    ├── certs/         # Phase D: certbot (ECDSA), 50-dns-stack.sh deploy hook, cert fan-out
    ├── adguardhome/   # Phase E: versioned release dir + symlink, AdGuardHome.yaml.j2, unit
    ├── nginx/         # Phase D+E: TLS termination on :443, /dns-query -> 127.0.0.1:8053
    ├── logrotate/     # Phase G
    ├── observability/ # Phase I: notify.sh, /etc/cron.d/dns-health, smoke gate (H12) — this role
    │                  #          CREATES both; every other role appends to them
    ├── abuse/         # Phase J: ban escalation logic and operator tooling. The sets and meters
    │                  #          themselves belong to the nftables role above (Phase B)
    ├── backup/        # Phase K: restic install, repo, timer, drill script
    ├── keepalived/    # Phase N3: applied only to hosts in [dns_ha]
    └── access/        # Phase P: private access layer
```

Role boundaries follow phase boundaries deliberately: it keeps this document and the repository in
one-to-one correspondence, so a reader who finds a surprise in a role knows which phase explains it.
There is no `warmer/` role — Phase F is retired (see N7).

### O3. The handful of tasks that are actually subtle

Everything else is `template` + `service`. These five are where a naive translation of the runbook
breaks.

**1. Privileged ports come from the unit, never from `setcap`.** If you copied a
`community.general.capabilities` task out of an older plan, delete it. `NoNewPrivileges=yes`
nullifies file capabilities across `execve`, so a `setcap`'d AdGuardHome cannot bind `:53`/`:853`
and never starts (canonical decision 8). The capability is a property of the unit template:

```ini
# roles/adguardhome/templates/adguardhome.service.j2  (excerpt — full unit is Phase E)
[Service]
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

**2. The AdGuardHome config validate is a chicken-and-egg.** `validate:` runs a binary that does not
exist on a freshly provisioned node, so the very first `site.yml` against a new host fails on the
task meant to install it. Probe first, and validate against the dedicated validation work directory
`/opt/adguardhome/validate` so the permission-tightening (M3, trap 3) cannot touch the live `work/`
tree:

```yaml
- name: Check whether an AdGuardHome binary is already installed
  ansible.builtin.stat:
    path: /opt/adguardhome/current/AdGuardHome
  register: agh_bin

- name: Converge the validation work dir (created at install time by Phase E)
  ansible.builtin.file:
    path: /opt/adguardhome/validate
    state: directory
    owner: adguardhome
    group: adguardhome
    mode: '0750'

- name: Deploy AdGuardHome config
  ansible.builtin.template:
    src: AdGuardHome.yaml.j2
    dest: /opt/adguardhome/conf/AdGuardHome.yaml
    owner: adguardhome
    group: adguardhome
    mode: '0600'
    validate: "{{ '/opt/adguardhome/current/AdGuardHome --check-config -c %s -w /opt/adguardhome/validate'
                  if agh_bin.stat.exists else omit }}"
  notify: restart adguardhome
```

`/opt/adguardhome/validate` is **created by Phase E at install time**, not here. This task exists to
converge its ownership and mode — the same assertion Ansible makes about every other path it manages
— so a hand-repaired or drifted node comes back to `adguardhome:adguardhome 0750`. Do not read it as
the directory's only creator: the runbook's pre-change gates validate against this path on hosts that
Ansible may not have touched since install, and it must be there whether or not a playbook has run.
The rule that binds every `--check-config` in this plan, here and in K6 and M3, is the same one:
`runuser -u adguardhome`, never root, and never the live `work/` tree.

**3. `schema_version` is pinned in the template, and the admin UI is read-only.** The template must
carry an explicit `schema_version:` matching the installed AdGuardHome (canonical decision 7);
without it the post-v0.107.24 top-level `querylog:` / `statistics:` layout is silently
misinterpreted and retention settings are voided. But AdGuardHome also **rewrites its own config at
runtime** — every blocklist added through the web UI, every setting toggled there, is written back
to the file that Ansible owns and is destroyed on the next playbook run. Declare it: the admin UI is
for inspection; configuration changes go through the repository. If you accept a UI change, port it
into the template in the same session or you will lose it. After an AdGuardHome upgrade migrates the
schema (M3), bump `schema_version` in the template to match, or Ansible and the binary will fight
over the file on every run.

**4. Trust anchor before first start.** Unbound will not validate without
`/var/lib/unbound/root.key`, and on a fresh host it does not exist yet:

```yaml
- name: Bootstrap the DNSSEC trust anchor
  ansible.builtin.command:
    cmd: unbound-anchor -a /var/lib/unbound/root.key
    creates: /var/lib/unbound/root.key
  # exit 1 means "anchor was updated", which is success here
  register: anchor
  failed_when: anchor.rc not in [0, 1]

- name: Trust anchor ownership
  ansible.builtin.file:
    path: /var/lib/unbound/root.key
    owner: unbound
    group: unbound
    mode: '0644'
```

`unbound-anchor` exits 1 when it updated the anchor, which is a success and not a failure —
`failed_when` must allow it or every fresh build fails on this task.

**5. Certificate bootstrap ordering.** nginx and AdGuardHome both reference certificate paths that
do not exist until certbot has run, and certbot's HTTP-01 challenge (if you use it) needs port 80
open and nothing bound to it. Order `certs` before `nginx` and `adguardhome` in `site.yml`, and make
the nginx config validate conditional the same way as (2):

```yaml
- name: Deploy nginx site
  ansible.builtin.template:
    src: dns-doh.conf.j2
    dest: /etc/nginx/conf.d/dns-doh.conf
    validate: "{{ 'nginx -t -c /etc/nginx/nginx.conf' if cert_present.stat.exists else omit }}"
  notify: reload nginx
```

On an HA pair, only node A runs the `certs` issuance task (`when: inventory_hostname == groups['dns_ha'][0]`);
node B receives the certificate tree by fan-out and has its renewal timer disabled (N3).

**6. The nftables ruleset must never be installed unvalidated** — a bad ruleset locks you out of the
box you are configuring:

```yaml
- name: Deploy nftables ruleset
  ansible.builtin.template:
    src: nftables.conf.j2
    dest: /etc/nftables.conf
    owner: root
    group: root
    mode: '0600'
    validate: '/usr/sbin/nft -c -f %s'
  notify: reload nftables
```

**Handler ordering is load-bearing.** Ansible runs handlers at end-of-play **in the order they are
defined**, not the order they were notified. Define them once, in a single shared handlers file, in
the correct restart sequence:

```yaml
# handlers/main.yml — order here IS the restart order (see the runbook)
- name: reload nftables
  # nft-apply, never a bare `nft -f`: it is the single reload wrapper (Phase B), it is what
  # ExecReload calls, and it preserves the remaining timeouts on active bans (Phase J).
  ansible.builtin.command: /usr/local/sbin/nft-apply
- name: restart unbound
  ansible.builtin.service: { name: unbound, state: restarted }
- name: restart adguardhome
  ansible.builtin.service: { name: adguardhome, state: restarted }
- name: reload nginx
  ansible.builtin.service: { name: nginx, state: reloaded }
- name: restart keepalived
  ansible.builtin.service: { name: keepalived, state: restarted }
```

Get this wrong and a change touching two roles restarts AdGuardHome before its upstream is back.

### O4. Drift detection

```bash
# /etc/cron.d/ansible-drift   (on your control host, NOT on the DNS node)
30 6 * * * ops cd /srv/dns-infra && out=$(ansible-playbook -i inventory/prod.yml site.yml --check --diff 2>&1); rc=$?; if [ $rc -ne 0 ] || printf '%s' "$out" | grep -qE 'changed=[1-9]|failed=[1-9]|unreachable=[1-9]'; then printf '%s' "$out" | tail -20 | logger -t dns-alert -p daemon.crit; fi
```

The obvious version of this check — `... --check --diff | grep -q 'changed=0' || alert` — is
**inverted and silently dead**. The recap prints one line per host, so `grep -q 'changed=0'` succeeds
whenever *any* host is clean: with dns1 drifted at `changed=3` and dns2 clean at `changed=0`, the
grep matches, the `||` branch never fires, and you never hear about the drift you built the check to
catch. Test for the presence of drift, not for the absence of it, and gate on the playbook's own
exit status too.

### O5. Rebuild-time target

**Target: 20 minutes** from `server create` to `SMOKE: PASS` on a rebuilt node, excluding the time
it takes you to fetch credentials from your password manager.

Measured by the Tier 2 drill in Phase K7 — steps 2 through 9, wall clock. Nothing else counts:
a rebuild time you estimated is a rebuild time you do not have. Run the drill at build time, after
any change to `site.yml` or the cloud-init file, and at least once every six months. Record each
measurement with a date; a target that silently doubles over a year is the normal outcome and the
only way you find out is by measuring.

If the measurement exceeds the target, the usual causes in order of likelihood: `package_upgrade:
true` in cloud-init pulling a large update set on first boot (move it to Ansible where you can see
it), the certbot task waiting on DNS-01 propagation (pre-issue and restore from restic instead —
step 6 of K7), and Ansible re-downloading the AdGuardHome release (cache it in the repo or on the
control host).

**Verify:**

```bash
cd /srv/dns-infra
ansible-playbook -i inventory/prod.yml site.yml --vault-id prod@prompt
ansible-playbook -i inventory/prod.yml site.yml --vault-id prod@prompt | tail -5
#   -> changed=0  failed=0  on EVERY host. Read every recap line, not just the first.

# prove the drift cron catches a real drift:
ssh deploy@dns1 'sudo sed -i "1i # drift" /etc/nftables.conf'
ansible-playbook -i inventory/prod.yml site.yml --check --diff | grep -qE 'changed=[1-9]' && echo "drift detected OK"
ansible-playbook -i inventory/prod.yml site.yml --limit dns1     # repair

# a bare host really does build from nothing (this is K7 steps 2-9, timed):
ssh deploy@dns-dr 'cloud-init status --long; sudo nft list ruleset | head; systemctl is-active nftables ssh chrony'
```

### O6. The operational inventory

Three other sections of this plan tell you to write something "in the Phase O inventory", and until
now that artifact did not exist. Phase I4 sends the resolved `blackbox_exporter` version there
because the install is deliberately unpinned. Phase I9 sends the external monitoring services there
— *"an external dependency nobody documented is an external dependency that silently lapses"*. Phase
L gates go-live on it. `inventory/prod.yml` is not that thing: it is an Ansible host list containing
`dns1` and `dns2`, and an operator who follows the instruction literally writes an external-service
register into a YAML file of hostnames.

The file lives at `/opt/dns-config-backup/INVENTORY.md` — the same directory Phase A3 creates and
git-initialises, the same one Phase Q writes `RETENTION.md` into, and already inside Phase K3's
restic include list. It gets committed like everything else there, so changes are dated and
attributable locally as well as recoverable off-host.

**Never put a credential value in this file.** Every row names *where the secret lives*, never what
it is. The directory is 0750 root-owned and the restic repository is encrypted, but this file is the
one someone will paste into a ticket.

```bash
cat > /opt/dns-config-backup/INVENTORY.md << 'EOF'
# Operational inventory - dns.example.com
# Every row needs an answer and a date. "not applicable" with a reason is an answer;
# TODO is not. The verify in Phase O6 fails on any remaining TODO.

## 1. Accounts and who can reach them
| Account | Identifier | Credential lives in | Last rotated | Second holder (K8) |
|---|---|---|---|---|
| Registrar | | | TODO | TODO |
| Hosting provider | | | TODO | TODO |
| Object storage (restic) | | | TODO | TODO |
| healthchecks.io | | | TODO | TODO |
| ntfy | | | TODO | TODO |
| ACME / Let's Encrypt account | | /etc/letsencrypt/accounts | n/a - key, not password | TODO |

## 2. External dependencies and what happens when they lapse
| Dependency | Notifies | Expires / renews | Consequence of lapse |
|---|---|---|---|
| Domain registration | | TODO | Service name hijackable - see Decommissioning |
| healthchecks.io check UUID | | n/a | Dead man's switch stops paging (I9) |
| ntfy topic | | n/a | All alerts silent (I8) |
| Provider abuse-forwarding ticket ref | | TODO | Complaints go to a null-routed address (Q6) |
| security.txt Expires: field | | TODO | Signals an abandoned service (Q5c) |

## 3. Versions of everything not installed from apt
| Component | Version | Pinned? | Source |
|---|---|---|---|
| AdGuardHome | | yes (M3) | GitHub release |
| restic | | yes (K1) | GitHub release, SHA256-verified |
| blackbox_exporter | | NO - resolved at install (I4) | GitHub release |
| dnslookup | | NO - resolved at install (I4) | GitHub release |
| prometheus / alertmanager | | | apt or upstream - state which |

## 4. Measured numbers (not estimates)
| Measurement | Value | Date measured | Where it came from |
|---|---|---|---|
| Rebuild wall clock (real RTO) | | TODO | K7 steps 2-9, target in O5 |
| Phase P token revocation time | | TODO | P8d |
| Load-test knee (qps) | | TODO | Phase H |
| Query-log tmpfs peak usage | | TODO | df -h after a week at real traffic (Q3) |
EOF
chmod 0640 /opt/dns-config-backup/INVENTORY.md
git -C /opt/dns-config-backup add INVENTORY.md
git -C /opt/dns-config-backup commit -qm 'O6: operational inventory'
```

Section 3 doubles as the input to any release-watching you do: a version you never wrote down is a
version you cannot compare against upstream.

**Verify** — the same shape as Phase Q6's register check, because the failure mode is the same
(a file that exists and answers nothing passes a `test -f`):

```bash
grep -c 'TODO' /opt/dns-config-backup/INVENTORY.md      # -> 0
git -C /opt/dns-config-backup log -1 --format='%ci %an' -- INVENTORY.md
#   -> a date you recognise. An inventory last touched at build time is a stale inventory.

# the unpinned components actually have their resolved versions recorded (I4)
grep -A6 '^| Component' /opt/dns-config-backup/INVENTORY.md | grep -E 'blackbox_exporter|dnslookup'
#   -> both rows carry a version string
```

---

## Operations Runbook

The 3am page. Everything here is a pointer or a command, not an explanation.

### First: give yourself DNS

**This host has no working DNS while AdGuardHome is down.** Phase C5.8 set
`/etc/resolv.conf` to `nameserver 127.0.0.1`, and `resolv.conf` has no syntax for a port, so that
means 127.0.0.1:**53** — AdGuardHome, not Unbound on 5335. That is the correct posture for a
resolver appliance and it is a deliberate choice, but it means `apt`, `certbot renew`, the Phase D
deploy hook, `restic` (which must resolve your object-storage endpoint) and `ansible` all fail
during exactly the incident you are trying to fix, with errors that name the tool and never the
cause. Escalation step 2 reaches for restic. Step 5 reaches for restic. Neither works until you do
this.

```bash
grep nameserver /etc/resolv.conf
#   -> 'nameserver 127.0.0.1' AND AdGuardHome not answering = this host resolves nothing

printf 'nameserver 9.9.9.9\nnameserver 1.1.1.1\n' > /etc/resolv.conf     # while you work
```

**Restoring it is mandatory, and it is part of closing the incident, not optional tidying:**

```bash
printf 'nameserver 127.0.0.1\noptions edns0 trust-ad\n' > /etc/resolv.conf
grep -c '^nameserver' /etc/resolv.conf      # -> 1, exactly. Not 2.
```

A forgotten fallback line is precisely the silent, unvalidated resolution path C5.8 exists to
remove, and no Phase I alert will ever tell you it is there. If you would rather not re-flip this
file under pressure at all, pin your object-storage endpoint in `/etc/hosts` as a standing measure —
that keeps restic working regardless, which covers the two escalation steps that need it.

### Restart order

Always this sequence, and gate on the smoke test at each marked point:

```bash
/usr/local/sbin/nft-apply                                   # only if the ruleset changed
systemctl restart unbound     && sleep 3 && /usr/local/sbin/dns-smoke.sh
systemctl restart adguardhome && sleep 5 && /usr/local/sbin/dns-smoke.sh
nginx -t && systemctl reload nginx
/usr/local/sbin/dns-smoke.sh
```

Notes that change what you type:

- `nft-apply` (Phase B) is the only supported way to load the ruleset. It validates first and it
  preserves the remaining timeouts on active bans; a bare `nft -f /etc/nftables.conf` flushes them
  and hands every currently-banned source its access back mid-incident.
- Restarting `unbound` no longer restarts AdGuardHome underneath you (N4b). Do not restart
  AdGuardHome "as well, to be safe" — that is a second, unnecessary outage.
- `nginx` affects **DoH only**. Plain DNS and DoT/DoQ do not pass through it. Never restart the
  whole stack for a DoH problem.
- Never restart `keepalived` casually on the master — it moves the VIP. To do maintenance on the
  master, drain it deliberately (below).

**Tier 3 drain / undrain (planned maintenance on the master):**

```bash
# on the master
systemctl stop keepalived            # VIP moves to the standby within ~3 s
ip -4 addr show dev eth0 | grep -c 203.0.113.10     # -> 0
# ... do the work, then:
/usr/local/sbin/dns-smoke.sh         # must pass BEFORE taking traffic back
systemctl start keepalived           # with nopreempt, the VIP stays on the peer until it fails
```

### The gate after every change

```bash
/usr/local/sbin/dns-smoke.sh; echo "exit=$?"
```

`SMOKE: PASS` and `exit=0`, or you are not finished. This is the completion criterion for every
config edit, every package upgrade, every binary upgrade, every reboot and every restore. The
script is defined in Phase H12. The upgrade wrappers in M3 and M4 call it and roll back
automatically on failure; when you change something by hand, you are the rollback.

Pre-change gates, before you restart anything:

```bash
nft -c -f /etc/nftables.conf                                              # ruleset parses
unbound-checkconf                                                         # resolver config parses
runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
  -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate  # AGH config parses
nginx -t                                                                  # nginx config parses
keepalived -t -f /etc/keepalived/keepalived.conf                          # Tier 3 only
```

### Failure scenarios

The full table is **N7**. Do not maintain a second copy here — a duplicated runbook table is a
runbook table that is wrong. The four you will actually hit, in order:

| Symptom | First command |
|---|---|
| Nothing resolves from anywhere | `/usr/local/sbin/dns-smoke.sh` — read which line fails first, then N7 |
| DoH broken, everything else fine | `nginx -t && systemctl reload nginx` |
| SERVFAIL on signed domains only | `test -s /var/lib/unbound/root.key && timedatectl` → N7 trust-anchor row |
| Service died overnight and stayed dead | `journalctl -u <unit> --since 02:00` → M3/M4 rollback |

### Escalation path

**Before step 0: if you have any reason to think this is an intrusion rather than a fault, stop and
go to "If you believe the host is compromised" below.** Steps 1, 2 and 5 destroy the evidence you
would need, and step 5 re-imports the attacker's persistence from your own backup.

0. **Give yourself DNS.** See the first section of this runbook. If you skip this, steps 2 and 5
   fail on name resolution and you will spend twenty minutes debugging restic.

1. **Run the smoke gate.** It tells you which layer is broken and stops you restarting the wrong
   one. Everything below assumes you have its output.
2. **Roll back the last change.** If anything was upgraded or edited in the last 24 hours, undo that
   first — `/usr/local/sbin/upgrade-adguardhome.sh` and `upgrade-unbound.sh` roll back
   automatically, and `/var/backups/unbound.*` plus `/opt/adguardhome/releases/` hold the previous
   versions. Diagnose after service is restored, not before.
3. **Check the provider.** Status page, then the console. A host that is unreachable over SSH and
   over DNS simultaneously is usually not a DNS problem.
4. **Fail the address over.** Tier 3: `systemctl stop keepalived` on the sick node, confirm the VIP
   landed on the peer, confirm `dns-smoke.sh` passes there. Tier 0/1: this is the rebuild decision —
   go to step 5.
5. **Rebuild.** Phase K7 steps 3-8 against a fresh host. You have a measured RTO (O5); if you are
   past it, say so rather than continuing to debug.
   If the rebuild has to land on a **different address** — provider suspension, provider gone, IP
   reassigned — you are in **N8**, not here. It is a different and longer procedure, its first step
   (lowering the record's TTL) is the one you cannot do retroactively, and a population of your
   users cannot be migrated at all.
6. **Last resort: hand traffic away.** Repoint `dns.example.com` at a public resolver you trust and
   accept the TTL, or tell users to switch. This ends the outage for them at the cost of the privacy
   properties this service exists to provide (Phase Q) — it is a deliberate decision with a
   consequence, not a neutral fallback. Make it explicitly, tell users you made it, and undo it as
   soon as the smoke gate passes on your own node.
7. **Write it up.** Any incident that reached step 4 gets an entry: what failed, which monitor saw it
   (or did not — that is the more valuable finding), and what changed so it cannot recur silently.

### If you believe the host is compromised

This is a different procedure from the one above, and the difference is not stylistic: **the
escalation path's first instinct destroys the evidence and its last step re-installs the
compromise.** Step 2 rolls back — overwriting the artifacts. Step 5 rebuilds from restic, and Phase
K3's include list carries `/etc/systemd/system`, `/usr/local/sbin`, `/etc/cron.d` and
`/opt/dns-config-backup`, which is exactly where persistence lives. Restore a snapshot taken after
the intrusion and you get the attacker back, with a passing smoke gate to reassure you.

Triggers worth acting on: a service you did not enable, an outbound connection you cannot account
for, a file under `/usr/local/sbin` you did not write, an nftables ruleset that does not match
`/etc/nftables.conf`, an SSH login you did not make, a restic snapshot nobody's timer took, or a
provider abuse notice describing traffic you cannot explain. Suspicion is enough. The cost of
running this procedure on a false alarm is an afternoon; the cost of skipping it on a real one is
that you never find out how they got in and it happens again.

**1. Do not.** Not as a preference — these are the four moves that cost you the investigation:

- **Do not reboot.** The process table, the open sockets, and everything on tmpfs go with it. Phase
  Q3 puts the query log and the statistics database on tmpfs, so a reboot also destroys the only
  record of what was exposed — which you need for the notification decision in step 5.
- **Do not roll back**, and do not run `upgrade-adguardhome.sh` or `upgrade-unbound.sh`. Their
  rollback paths overwrite the binaries and unit files you need to look at.
- **Do not run `nft-apply`.** It flushes and reloads the ruleset, taking the live one — including
  anything the attacker added — with it.
- **Do not "clean up" anything you find.** Deleting the implant tells them you noticed and tells
  you nothing.

**2. Contain, without pulling the plug.** Two options, and the trade-off is real:

| | Provider console: detach the network | Scoped nftables policy drop |
|---|---|---|
| Stops exfiltration | Immediately and completely | Only what the ruleset covers |
| Keeps you able to work | No — console only, and you cannot copy evidence off | Yes |
| Kills your own alerting | Yes | No |
| Attacker can react | No | Yes — they see the ruleset change |

For a resolver on a VPS, **the scoped drop is usually right**: you need the network to get evidence
off the box, and detaching it leaves you typing into a console with no way to preserve anything.
Write a temporary ruleset by hand and load it directly — this is the one place in this plan where
`nft -f` is correct rather than forbidden, because preserving the live ban timeouts is no longer the
priority and you must not overwrite the evidence in `/etc/nftables.conf` by editing it:

```bash
nft list ruleset > /root/EVIDENCE-nft-ruleset.txt        # capture BEFORE you change anything
cat > /root/containment.nft << 'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input   { type filter hook input   priority 0; policy drop;
                  iif lo accept
                  ip saddr <YOUR-ADMIN-IP> tcp dport 22 accept
                  ct state established,related accept }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy drop;
                  oif lo accept
                  ct state established,related accept
                  ip daddr <YOUR-ADMIN-IP> accept
                  ip daddr <OBJECT-STORAGE-IP> tcp dport 443 accept }
}
EOF
nft -f /root/containment.nft
```

Note what this does to you: the service is now down for every user, the egress policy drop means
`notify.sh` cannot reach ntfy, and DNS resolution on this host is gone twice over. Accept all three
deliberately. Announce the outage through whatever channel Phase Q5 gave you.

**3. Preserve, off-host, in this order.** The provider snapshot first, because everything after it
runs on the suspect kernel and you should assume its output is a best effort rather than truth:

```bash
# 3a. FIRST: a provider-side volume snapshot. Console or CLI - not from the box.
#     hcloud server create-image --type snapshot --description "compromise-$(date -uI)" dns1

# 3b. Then, on the box, into one directory you will copy off:
D=/root/evidence-$(date -uIs); mkdir -m 0700 -p "$D"
journalctl -o export > "$D/journal.export"        # persistent journal is Phase Q3's decision paying off
ps auxwwf                > "$D/ps.txt"
ss -tulpanH              > "$D/sockets.txt"
lsof -nP 2>/dev/null     > "$D/lsof.txt"
nft list ruleset         > "$D/nft.txt"
systemctl list-units --all --no-pager > "$D/units.txt"
systemctl list-timers --all --no-pager > "$D/timers.txt"
crontab -l 2>/dev/null; cat /etc/cron.d/* > "$D/cron.txt" 2>/dev/null
dpkg --verify            > "$D/dpkg-verify.txt" 2>&1    # any line here is a modified packaged file
find / -xdev -newer /var/lib/unbound/root.key -type f 2>/dev/null > "$D/newer-than-anchor.txt"
cp /opt/adguardhome/conf/AdGuardHome.yaml "$D/"   # AGH rewrites this at runtime: it is a change record
sha256sum "$D"/* > "$D/SHA256SUMS"

# 3c. Copy it OFF. Never leave the only copy on the suspect disk, and never write it into
#     the restic repository the attacker's credentials could reach.
#     From your workstation:  scp -r deploy@dns1:/root/evidence-* ./
```

`find / -newer /var/lib/unbound/root.key` is a cheap, surprisingly effective first pass: that file
is written by Unbound's RFC 5011 tracking and by nothing else, so it is a reasonable "everything
after this is suspicious" waterline. It is a heuristic, not proof — an attacker who sets timestamps
defeats it.

**4. Rebuild. Do not clean.** State it flatly because operators reliably talk themselves out of it:
**you cannot clean a compromised host.** You do not know what you did not find, verifying absence is
impossible, and the effort of trying exceeds the 20-minute rebuild target in O5. The only case for
cleaning is a host you cannot rebuild, which this one is not — Phase O exists precisely so that
rebuilding is cheaper than trusting.

Rebuild per K7, with two changes:

- **On a new instance with a new address**, not a reimage of the same one. If that means a new IP,
  you are also in N8.
- **From a restic snapshot dated before the earliest suspicious timestamp in `newer-than-anchor.txt`
  and before the earliest suspicious journal entry** — not `latest`. This is the whole reason K4's
  retention keeps 14 dailies and 12 monthlies.
  ```bash
  restic snapshots --json | jq -r '.[] | "\(.time)  \(.id[0:8])"'
  restic restore <ID-from-before-the-window> --target / --include /etc/letsencrypt
  ```
  And restore *only* what you must. `/etc/letsencrypt` is the one thing Ansible cannot regenerate;
  everything else in K3's include list should come from source control on a rebuild after an
  intrusion, even if that costs you the Phase B allowlist and you have to re-enter it by hand.

**5. Rotate everything.** Every secret on that box was root-readable. The ordered list, with the
blast radius of each and the certificate revocation that is mandatory rather than optional, is
**K5e's post-compromise section**. Two items from it are time-critical and worth repeating here:
revoke the TLS certificate with `--reason keycompromise` (an attacker holding that key can
impersonate your resolver to every encrypted client until expiry), and cut the object-storage
credential before anything else, because that credential could `restic forget --prune` your only
clean snapshot while you are reading this.

**6. Tell people, and know what you are telling them.** Phase Q6's Art. 33 row puts a 72-hour clock
on breach notification, and **it starts at awareness, not at confirmation** — the moment you formed
this suspicion, not the moment you proved it. What was actually exposed is posture-dependent, and
the honest answer under this plan's shipped default is: up to six hours of query records with
IPv4 client addresses truncated to /16 and IPv6 to /48, held in RAM. Under Phase Q's Posture A there
is nothing to disclose because no record existed. Note the ugly interaction with step 1: those
records are on tmpfs, so a reboot destroys the evidence of what was exposed *and* your ability to
state what was not — which is a second, independent reason the provider snapshot in 3a comes first.

Record the incident in `RETENTION.md` and `INVENTORY.md` (O6) regardless of whether it met a
notification threshold. An intrusion nobody wrote down is an intrusion the next operator repeats.

---

## Decommissioning

This plan has a birth and no death, and the two disposal steps an operator would naturally take —
let the domain lapse, release the IP — are the two that hand an attacker a name or an address that a
real population of devices still trusts unconditionally.

Shutting this down is **not** symmetric with standing it up. Phase N1 and the risk register
establish that encrypted DNS clients have no client-side failover: Android Private DNS accepts one
hostname and **fails closed**. So "stop the service" does not mean degraded resolution for your
users, it means *no* resolution, on every phone and laptop configured against you, until a human
reconfigures each device by hand. Phase P makes it worse in the specific way that install-and-forget
artifacts always do: P3f hands out Apple `.mobileconfig` profiles that users install once and never
think about, and P6 writes `Endpoint = dns.example.com:51820` and a `DNS =` line into a WireGuard
config on every phone.

This section lands months or years in, when the operator has moved on — which is exactly when nobody
is reading the plan. Write the notice period into the published privacy notice (Phase Q5b) **now**,
while you are still paying attention, so that the commitment outlives your interest in it.

**Wind down in this order. Clients first, disposal second.**

1. **Announce, with a fixed date.** Through every channel that reaches an enrolled user: the
   `security.txt` `Contact:` address, the published privacy notice page, and — for a Phase P
   deployment, where you know who holds a profile or a peer config — directly. A resolver whose
   users you cannot name is a resolver you should not have published; that is a Phase Q decision,
   and this is where it comes due.
2. **Keep answering for the whole notice period.** Thirty days is a reasonable default for a small
   deployment and is not a long time to keep a EUR 6 VPS running. Do not shorten it because traffic
   dropped — falling traffic means people migrated, not that the remainder can cope.
3. **Then stop the service.** Not before.
4. **Revoke the certificate.** The private key is about to sit on a disk you no longer control, on
   storage a provider will reissue to someone else.
   ```bash
   certbot revoke --cert-name dns.example.com --reason cessationofoperation
   ```
5. **Do NOT let the domain lapse.** This is the single most damaging thing you can do on the way
   out. Every device still configured with `dns.example.com` will accept whoever registers it next,
   and that registrant can obtain a perfectly valid Let's Encrypt certificate for the name — the
   clients' trust decision is "does the hostname's certificate validate", and it will. Keep the
   registration, remove the `A`/`AAAA` records, and let the name resolve to nothing. Renewing a
   domain indefinitely is the cost of having published a resolver on it. If you truly will not keep
   it, hold it for at least a year past shutdown and accept that you are handing over a hijack after
   that.
6. **Do NOT release the IP while Do53 clients still point at it.** You cannot notify that
   population — they typed an address into a router — and the provider will reassign it eventually
   regardless. This is not fixable, and it is the strongest argument for a longer notice period
   rather than a shorter one.
7. **Dispose of the data, per Phase Q5a.** In the terms Q5a requires — crypto-erase, not a wipe you
   cannot perform:
   ```bash
   # The restic repository holds /etc/letsencrypt and, in a Phase P deployment, identity material.
   restic key list                              # know every key before you destroy any
   # Destroy the repository AND every copy of its password, including the second holder's (K8).
   # Then delete the bucket at the provider - deleting the repo contents alone leaves the bucket.
   ```
   Close healthchecks.io and ntfy, cancel the hosting account, and delete the local vault entries
   last, not first — you will want them during steps 4 through 7.
8. **Write the closing entry.** `RETENTION.md` gets a dated line recording the shutdown and the data
   disposal; `INVENTORY.md` (O6) gets the same. That entry is the artifact that answers a question
   arriving two years later about data you no longer hold.

**Verify:**

```bash
dig +short dns.example.com A                              # -> empty, with the domain still registered
whois example.com | grep -i 'expir'                       # -> a date in the future
curl -sS https://dns.example.com/dns-query -o /dev/null -w '%{http_code}\n' 2>&1 | tail -1
#   -> connection failure, not a 200 from somebody else's server
grep -i 'decommission' /opt/dns-config-backup/RETENTION.md   # -> a dated closing entry
```

---

[Plan index](../dns-server-plan.md) · [Previous: Observability and Abuse Response](./07-observability-and-abuse.md) · [Next: Private Access Layer (optional)](./09-private-access.md)
