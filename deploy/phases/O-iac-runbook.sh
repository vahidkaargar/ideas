#!/usr/bin/env bash
# deploy/phases/O-iac-runbook.sh — Phase O: Infrastructure-as-Code and
# Operations Runbook
# Source: phases/08-operations.md — sections "PHASE O: Provisioning and
# Reproducibility" (O1-O6) and "Operations Runbook" ONLY. Phases K
# (Backup/Restore/Secrets), M (Patching/Upgrades) and N (High Availability)
# on that same page are OUT OF SCOPE for this script — they have their own
# scripts. "Decommissioning" (the section after the runbook) is also OUT OF
# SCOPE here: it is not part of "infrastructure-as-code and the operations
# runbook", it is a wind-down procedure spanning months/years, and almost
# none of it is safe to pre-script (announcing a shutdown date, waiting out
# a notice period, business decisions). It is not transcribed anywhere by
# this script — flag that gap to whoever owns the full batch.
#
# Mechanical transcription — read the source sections before running this.
#
# THIS PHASE SPANS TWO HOSTS, unlike most other phase scripts:
#   - O1-O5 (the Ansible control-repo bootstrap and drift detection) are
#     control-host actions. The source is explicit that O4's drift cron goes
#     "on your control host, NOT on the DNS node" (see O4 below) — the same
#     is true of the IaC repo itself (/srv/dns-infra, per K5d/O4's own
#     examples) and of the rebuild-drill functions in O5, which `ssh` to the
#     DNS node rather than running commands locally.
#   - O6 (the operational inventory) and the "Operations Runbook" functions
#     (give-yourself-DNS, restart order, pre-change gates, escalation,
#     compromise response) run ON the DNS node itself.
# require_root is still called unconditionally below because nearly every
# write this script performs (/etc/cron.d, /opt/dns-config-backup,
# /etc/resolv.conf, systemctl, chown) needs root on whichever host it runs
# on. Read which section you are running before running it.
#
# Per the assignment scope: this script does NOT install or configure
# Ansible itself (that is an operator-supplied prerequisite, along with the
# git remote for the IaC repo) — it only bootstraps the repo *layout* Ansible
# will use, and never calls `ansible-playbook` outside of clearly-labelled,
# not-auto-run helper functions that mirror the source's own drill/verify
# commands.
#
# Ownership note (repo hard rule 2 — do not duplicate a shared object):
#   - nftables tables/sets: sole owner Phase B. This script never writes
#     /etc/nftables.conf and never calls nft-apply. The one exception is the
#     compromise-response containment ruleset in the runbook section below,
#     which the source itself declares is "the one place in this plan where
#     `nft -f` is correct rather than forbidden" (see that function).
#   - /opt/dns-config-backup: sole owner Phase A3 (creates it). This script
#     only writes INVENTORY.md into it and commits, exactly as O6 directs;
#     it never creates or deletes the directory or its .git.
#   - /usr/local/sbin/notify.sh, /etc/cron.d/dns-health: sole owner Phase I.
#     Not touched here.
#   - Memory ceilings / swap / vm.swappiness: sole owner Phase A6. Not
#     touched here.
#   - /opt/adguardhome/validate: sole owner Phase E (creates it). O3's
#     Ansible snippet only converges ownership/mode on a path Phase E
#     already created — this script does not create that directory either;
#     it is transcribed as an inert reference file only (see O3.2 below).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=../lib/common.sh
source ../lib/common.sh

require_root
require_cmd git grep

phase_header "Phase O — infrastructure-as-code and operations runbook"

IAC_REPO="/srv/dns-infra"          # exact path from K5d / O4's own examples
CONFIG_BACKUP_DIR="/opt/dns-config-backup"   # Phase A3's directory; append-only here

# =====================================================================
# O1. cloud-init: bare VPS to reachable-and-firewalled on first boot
# =====================================================================
# This file's only job is to make the box reachable by Ansible with a
# default-deny firewall already in place; everything real comes from the
# playbook. The bootstrap ruleset it writes is DELIBERATELY minimal and is
# replaced wholesale by Phase B's ruleset on the first Ansible run — this
# script does not touch Phase B's ruleset or its NOTRACK/flood-meter/ban-set
# objects at any point.
#
# The source gives the file's content in full but does not name the file;
# "cloud-init.yaml" below is this script's choice of filename inside the
# repo, not a directive from the source.

info "O1: writing ${IAC_REPO}/cloud-init.yaml (bare-VPS bootstrap: SSH hardening, minimal nftables, chrony/nftables enable)"
install -d -m 0755 "$IAC_REPO"
backup_file "${IAC_REPO}/cloud-init.yaml"
# --- O1: cloud-init bootstrap file ---
cat > "${IAC_REPO}/cloud-init.yaml" << 'EOF'
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
EOF

warn "O1: replace 'ssh-ed25519 AAAAC3Nza... ops@laptop' with the real operator public key before this cloud-init file is ever handed to a provider — the placeholder in the source is not a usable key. MANUAL STEP, business/identity decision, not scriptable."
warn "O1 (Ubuntu 24.04 specifics, informational — not acted on by this script): sshd_config.d/*.conf is only effective because /etc/ssh/sshd_config has 'Include /etc/ssh/sshd_config.d/*.conf'; the unit is ssh.service, not sshd.service. 24.04 enables socket activation for SSH by default — under ssh.socket, Port/ListenAddress in sshd_config are ignored. If Phase A ever moves SSH off port 22, the socket unit must be reconfigured, not the daemon. Check with: systemctl is-enabled ssh.socket"
warn "O1: put no secrets in cloud-init user-data — on most providers it remains readable from the instance metadata service by any local process for the life of the instance. Nothing in the file above is a secret; keep it that way."

# --- O1: verify ---
info "O1 verify: file exists and is valid YAML-shaped cloud-config (structural check only, not a cloud-init dry run)"
test -f "${IAC_REPO}/cloud-init.yaml" && head -1 "${IAC_REPO}/cloud-init.yaml" | grep -q '^#cloud-config$' \
    && echo "OK: ${IAC_REPO}/cloud-init.yaml present, starts with #cloud-config" \
    || fatal "${IAC_REPO}/cloud-init.yaml missing or malformed"

# =====================================================================
# O2. Ansible layout, and where the role boundaries fall
# =====================================================================
# Role boundaries follow phase boundaries deliberately. Only the directory
# skeleton is created here — the source gives file CONTENT for handlers/
# main.yml (see O3 below, handler ordering) and for the O3.2/O3.4/O3.5/O3.6
# task snippets, written to reference/ files below. It does NOT give content
# for ansible.cfg, inventory/prod.yml, group_vars/dns/vars.yml, site.yml, or
# group_vars/dns/vault.yml (vault.yml is Phase K5b's content and out of
# scope here regardless) — those are NOT fabricated; they are left for the
# operator, with an explicit warn() below rather than invented content.

info "O2: creating Ansible role-directory skeleton under ${IAC_REPO}"
# --- O2: ansible layout ---
install -d -m 0755 \
    "${IAC_REPO}/inventory" \
    "${IAC_REPO}/group_vars/dns" \
    "${IAC_REPO}/handlers" \
    "${IAC_REPO}/reference" \
    "${IAC_REPO}/roles/base" \
    "${IAC_REPO}/roles/nftables/templates" \
    "${IAC_REPO}/roles/unbound" \
    "${IAC_REPO}/roles/certs" \
    "${IAC_REPO}/roles/adguardhome/tasks" \
    "${IAC_REPO}/roles/adguardhome/templates" \
    "${IAC_REPO}/roles/nginx/tasks" \
    "${IAC_REPO}/roles/logrotate" \
    "${IAC_REPO}/roles/observability" \
    "${IAC_REPO}/roles/abuse" \
    "${IAC_REPO}/roles/backup" \
    "${IAC_REPO}/roles/keepalived" \
    "${IAC_REPO}/roles/access"

warn "O2: the following files are referenced by the source but their CONTENT is not given there, so nothing was written for them (no invented directives): ${IAC_REPO}/ansible.cfg, ${IAC_REPO}/inventory/prod.yml (dns1/dns2 in [dns]; dns1+dns2 also in [dns_ha]), ${IAC_REPO}/group_vars/dns/vars.yml (fqdn, upstream policy, cache sizes, VIP, peer private IPs), ${IAC_REPO}/site.yml. group_vars/dns/vault.yml is Phase K5b's content (out of scope for this script) — do not populate it here. Author all of these by hand from the plan's per-phase decisions before the first ansible-playbook run."

# --- O2: verify ---
info "O2 verify: role directories exist"
for d in base nftables unbound certs adguardhome nginx logrotate observability abuse backup keepalived access; do
    test -d "${IAC_REPO}/roles/${d}" || fatal "missing role directory: roles/${d}"
done
echo "OK: all 12 role directories present under ${IAC_REPO}/roles/"
echo "note: there is deliberately no roles/warmer/ — Phase F is retired (see N7 in the source, out of scope here)"

# =====================================================================
# O3. The handful of tasks that are actually subtle
# =====================================================================
# These are Ansible role-content fragments, not commands this script can run
# (running them means running ansible-playbook, which is explicitly out of
# scope). They are written verbatim into reference/ files inside the repo so
# the exact, checked wording survives into the IaC repo; integrating each
# into its real role file (main.yml / handlers/main.yml / the unit
# template) is a manual authoring step, flagged below.

# --- O3.1: privileged ports come from the unit, never from setcap (informational only — Phase E owns the full unit) ---
info "O3.1: privileged-port capability directive (excerpt; full adguardhome.service.j2 unit belongs to Phase E, not written here)"
backup_file "${IAC_REPO}/reference/O3.1-adguardhome-unit-capabilities.txt"
cat > "${IAC_REPO}/reference/O3.1-adguardhome-unit-capabilities.txt" << 'EOF'
# roles/adguardhome/templates/adguardhome.service.j2  (excerpt — full unit is Phase E)
[Service]
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
EOF
warn "O3.1: if a community.general.capabilities (setcap) task exists anywhere in the adguardhome role, delete it. NoNewPrivileges=yes nullifies file capabilities across execve, so a setcap'd AdGuardHome cannot bind :53/:853 and never starts (canonical decision 8). This is a code-review action on the real role, not something this script can detect or fix."

# --- O3.2: AdGuardHome config validate is a chicken-and-egg on a fresh host ---
info "O3.2: writing AdGuardHome config-validate Ansible task snippet (targets Phase E-created /opt/adguardhome/validate; does not create it)"
backup_file "${IAC_REPO}/reference/O3.2-adguardhome-validate-snippet.yml"
cat > "${IAC_REPO}/reference/O3.2-adguardhome-validate-snippet.yml" << 'EOF'
# Merge into roles/adguardhome/tasks/main.yml, in this order, ahead of any
# other AdGuardHome config task.
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
EOF
warn "O3.2: /opt/adguardhome/validate is created by Phase E at install time, not by this task and not by this script — the task above only converges its ownership/mode (0750, adguardhome:adguardhome) so a hand-repaired or drifted node comes back into line. The rule binding every --check-config in this plan (here, K6, M3) is: runuser -u adguardhome, never root, never the live work/ tree."

# --- O3.3: schema_version pinning and admin-UI read-only policy (no snippet given — policy statement only) ---
warn "O3.3 (policy, not a snippet): the AdGuardHome.yaml.j2 template must carry an explicit schema_version: matching the installed AdGuardHome (canonical decision 7) — without it the post-v0.107.24 top-level querylog:/statistics: layout is silently misinterpreted and retention settings are voided. AdGuardHome rewrites its own config at runtime: the admin UI is for inspection only; any change made there must be ported into the template in the same session or it is lost on the next playbook run. After an AdGuardHome upgrade migrates the schema (Phase M3, out of scope here), bump schema_version in the template to match, or Ansible and the binary fight over the file on every run. MANUAL AUTHORING STEP — nothing to script."

# --- O3.4: trust anchor before first start ---
info "O3.4: writing DNSSEC trust-anchor bootstrap Ansible task snippet (unbound role)"
backup_file "${IAC_REPO}/reference/O3.4-unbound-trust-anchor-snippet.yml"
cat > "${IAC_REPO}/reference/O3.4-unbound-trust-anchor-snippet.yml" << 'EOF'
# Merge into roles/unbound/tasks/main.yml, ahead of the first unbound start.
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
EOF
warn "O3.4: unbound-anchor exits 1 when it updated the anchor — that IS success, not failure. failed_when must allow rc in [0,1] or every fresh build fails on this task."

# --- O3.5: certificate bootstrap ordering ---
info "O3.5: writing nginx config-validate Ansible task snippet (conditional on certificate presence, same pattern as O3.2)"
backup_file "${IAC_REPO}/reference/O3.5-nginx-validate-snippet.yml"
cat > "${IAC_REPO}/reference/O3.5-nginx-validate-snippet.yml" << 'EOF'
# Merge into roles/nginx/tasks/main.yml. cert_present is presumed set by a
# preceding ansible.builtin.stat task on the certificate path, per the same
# pattern as O3.2's agh_bin — the source does not spell that stat task out
# for nginx, so it is not fabricated here.
- name: Deploy nginx site
  ansible.builtin.template:
    src: dns-doh.conf.j2
    dest: /etc/nginx/conf.d/dns-doh.conf
    validate: "{{ 'nginx -t -c /etc/nginx/nginx.conf' if cert_present.stat.exists else omit }}"
  notify: reload nginx
EOF
warn "O3.5: order the certs role before nginx and adguardhome in site.yml — both reference certificate paths that do not exist until certbot has run, and certbot's HTTP-01 challenge (if used) needs port 80 open with nothing else bound to it. On an HA pair, only node A runs the certs issuance task (when: inventory_hostname == groups['dns_ha'][0]); node B receives the certificate tree by fan-out and has its renewal timer disabled — that HA detail is Phase N3, out of scope here. site.yml task ordering itself is not written by this script (see the O2 warning above)."

# --- O3.6: the nftables ruleset must never be installed unvalidated ---
info "O3.6: writing nftables ruleset-deploy Ansible task snippet (validate-before-apply; does not touch the live ruleset)"
backup_file "${IAC_REPO}/reference/O3.6-nftables-deploy-snippet.yml"
cat > "${IAC_REPO}/reference/O3.6-nftables-deploy-snippet.yml" << 'EOF'
# Merge into roles/nftables/tasks/main.yml.
- name: Deploy nftables ruleset
  ansible.builtin.template:
    src: nftables.conf.j2
    dest: /etc/nftables.conf
    owner: root
    group: root
    mode: '0600'
    validate: '/usr/sbin/nft -c -f %s'
  notify: reload nftables
EOF
warn "O3.6: a bad ruleset locks you out of the box you are configuring — the validate: line above is why this task must never be weakened. Phase B owns /etc/nftables.conf and its tables/sets; this script does not deploy the ruleset itself, only stages the reference task content."

# --- O3: handler ordering is load-bearing ---
info "O3: writing ${IAC_REPO}/handlers/main.yml — full content given by source, restart order IS the order handlers are defined (Ansible runs handlers at end-of-play in definition order, not notification order)"
backup_file "${IAC_REPO}/handlers/main.yml"
cat > "${IAC_REPO}/handlers/main.yml" << 'EOF'
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
EOF
warn "O3: get handler ORDER wrong and a change touching two roles restarts AdGuardHome before its upstream (unbound) is back. Do not reorder handlers/main.yml without re-reading O3's rationale."

# --- O3: verify ---
info "O3 verify: reference snippets and handlers file are present"
for f in O3.1-adguardhome-unit-capabilities.txt O3.2-adguardhome-validate-snippet.yml \
         O3.4-unbound-trust-anchor-snippet.yml O3.5-nginx-validate-snippet.yml \
         O3.6-nftables-deploy-snippet.yml; do
    test -f "${IAC_REPO}/reference/${f}" || fatal "missing reference file: ${f}"
done
test -f "${IAC_REPO}/handlers/main.yml" || fatal "missing ${IAC_REPO}/handlers/main.yml"
grep -c '^- name:' "${IAC_REPO}/handlers/main.yml"   # -> 5, in the exact order printed above
echo "OK: O3 reference material staged"

# =====================================================================
# O4. Drift detection
# =====================================================================
# Runs on the CONTROL HOST, NOT on the DNS node — the source is explicit
# about this. If this script is being run on the DNS node itself, do not
# apply this section there.

if marker_done "O4-drift-cron"; then
    info "O4: drift-detection cron already installed per state marker — skipping re-install (edit /etc/cron.d/ansible-drift by hand if it needs to change)"
else
    info "O4: installing /etc/cron.d/ansible-drift (control host only)"
    warn "O4: this cron entry must be installed on your ANSIBLE CONTROL HOST, not on the DNS node — confirm which host this script is running on before continuing."
    confirm "About to write/overwrite /etc/cron.d/ansible-drift: a new root-owned cron job that runs 'ansible-playbook ... site.yml --check --diff' daily at 06:30 and pages via logger on drift or failure. Continue?"
    # --- O4: drift detection cron ---
    backup_file /etc/cron.d/ansible-drift
    cat > /etc/cron.d/ansible-drift << 'EOF'
# /etc/cron.d/ansible-drift   (on your control host, NOT on the DNS node)
30 6 * * * ops cd /srv/dns-infra && out=$(ansible-playbook -i inventory/prod.yml site.yml --check --diff 2>&1); rc=$?; if [ $rc -ne 0 ] || printf '%s' "$out" | grep -qE 'changed=[1-9]|failed=[1-9]|unreachable=[1-9]'; then printf '%s' "$out" | tail -20 | logger -t dns-alert -p daemon.crit; fi
EOF
    chmod 0644 /etc/cron.d/ansible-drift
    mark_done "O4-drift-cron"
fi

warn "O4: the obvious-looking check '... --check --diff | grep -q changed=0 || alert' is INVERTED and silently dead — the recap prints one line per host, so grep -q 'changed=0' succeeds whenever ANY host is clean, even if another host is drifted. The cron line above tests for the PRESENCE of drift (changed=[1-9]|failed=[1-9]|unreachable=[1-9]) and gates on the playbook's own exit status too. Do not simplify it back to the inverted form."

# --- O4: verify ---
info "O4 verify: cron file present with correct ownership and the non-inverted drift test"
test -f /etc/cron.d/ansible-drift && echo "OK: /etc/cron.d/ansible-drift present"
grep -c "changed=\[1-9\]" /etc/cron.d/ansible-drift   # -> 1 (the non-inverted form)
run-parts --test /etc/cron.d 2>/dev/null || true       # informational only, cron.d entries aren't run-parts scripts

# =====================================================================
# O5. Rebuild-time target
# =====================================================================
# Target: 20 minutes from `server create` to `SMOKE: PASS` on a rebuilt
# node, excluding password-manager credential-fetch time. Measured by the
# Tier 2 drill in Phase K7 steps 2-9 (K is out of scope here) — run at build
# time, after any change to site.yml or the cloud-init file, and at least
# once every six months.
#
# These are drills that apply real config to real hosts and, in the second
# function, DELIBERATELY corrupt a live host's /etc/nftables.conf to prove
# the O4 drift cron catches it. They are defined as functions and NOT
# invoked automatically by this script — an operator runs them by hand,
# each gated by its own confirm().

info "O5: defining (not running) rebuild-time-target drill functions — source it and call by hand: 'source deploy/phases/O-iac-runbook.sh; o5_apply_and_check'"

o5_apply_and_check() {
    require_root
    confirm "About to run ansible-playbook against inventory/prod.yml (${IAC_REPO}/site.yml) with --vault-id prod@prompt — this applies live configuration to every host in the inventory. Continue?"
    # --- O5: apply and verify clean recap ---
    ( cd "$IAC_REPO" && ansible-playbook -i inventory/prod.yml site.yml --vault-id prod@prompt )
    ( cd "$IAC_REPO" && ansible-playbook -i inventory/prod.yml site.yml --vault-id prod@prompt | tail -5 )
    #   -> changed=0  failed=0  on EVERY host. Read every recap line, not just the first.
}

o5_prove_drift_cron_catches_drift() {
    require_root
    warn "O5 drift-cron proof: this DELIBERATELY corrupts dns1's live /etc/nftables.conf with 'sed -i \"1i # drift\"' to prove the O4 cron detects it, then repairs it. Only run this against a host you can afford a brief nftables reload interruption on."
    confirm "About to (1) inject a harmless comment line into dns1's live /etc/nftables.conf via ssh, (2) run --check --diff to prove drift is detected, (3) run --limit dns1 to repair it. Continue?"
    # --- O5: prove the drift cron catches a real drift ---
    ssh deploy@dns1 'sudo sed -i "1i # drift" /etc/nftables.conf'
    ( cd "$IAC_REPO" && ansible-playbook -i inventory/prod.yml site.yml --check --diff | grep -qE 'changed=[1-9]' && echo "drift detected OK" )
    ( cd "$IAC_REPO" && ansible-playbook -i inventory/prod.yml site.yml --limit dns1 )     # repair
}

o5_bare_host_rebuild_check() {
    # Read-only verification against a scratch/DR host — this is K7 steps 2-9, timed.
    # --- O5: a bare host really does build from nothing ---
    ssh deploy@dns-dr 'cloud-init status --long; sudo nft list ruleset | head; systemctl is-active nftables ssh chrony'
}

warn "O5: if the 20-minute rebuild target is exceeded, the usual causes in order of likelihood: package_upgrade: true in cloud-init pulling a large first-boot update set (move it to Ansible where it's visible), the certbot task waiting on DNS-01 propagation (pre-issue and restore from restic instead — Phase K7 step 6, out of scope here), and Ansible re-downloading the AdGuardHome release on every run (cache it in the repo or on the control host). Record every measurement with a date in the O6 inventory below — an unmeasured rebuild time is a rebuild time you don't have, and a target that silently doubles over a year is the normal outcome."

# =====================================================================
# O6. The operational inventory
# =====================================================================
# Runs on the DNS node. /opt/dns-config-backup is Phase A3's directory
# (creates it, git-initialises it) — this script only writes INVENTORY.md
# into it and commits, exactly as O6 directs. It does not create the
# directory or run `git init`.

info "O6: writing ${CONFIG_BACKUP_DIR}/INVENTORY.md"

if [[ ! -d "$CONFIG_BACKUP_DIR" ]]; then
    warn "${CONFIG_BACKUP_DIR} does not exist — it is created by Phase A3, not this phase. Run Phase A first; skipping O6 until then."
elif [[ ! -d "${CONFIG_BACKUP_DIR}/.git" ]]; then
    warn "${CONFIG_BACKUP_DIR} exists but is not a git repository — Phase A3 is supposed to git-init it. Not initialising it here (not this phase's job); skipping the commit step below until that's fixed."
elif marker_done "O6-inventory-created"; then
    info "O6: ${CONFIG_BACKUP_DIR}/INVENTORY.md already created per state marker — NOT overwriting. An operator has likely filled in the TODOs by hand; re-templating would destroy that work. Edit the file directly instead."
else
    # --- O6: operational inventory ---
    backup_file "${CONFIG_BACKUP_DIR}/INVENTORY.md"
    cat > "${CONFIG_BACKUP_DIR}/INVENTORY.md" << 'EOF'
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
    chmod 0640 "${CONFIG_BACKUP_DIR}/INVENTORY.md"
    git -C "$CONFIG_BACKUP_DIR" add INVENTORY.md
    git -C "$CONFIG_BACKUP_DIR" commit -qm 'O6: operational inventory'
    mark_done "O6-inventory-created"
fi

warn "O6: never put a credential VALUE in INVENTORY.md — every row names WHERE the secret lives, never what it is. The directory is 0750 root-owned and the restic repository is encrypted, but this file is the one someone will paste into a ticket. Section 3's unpinned-component versions (blackbox_exporter, dnslookup) are Phase I4's to fill in; this script only creates the stub."

# --- O6: verify ---
if [[ -f "${CONFIG_BACKUP_DIR}/INVENTORY.md" ]]; then
    info "O6 verify"
    todo_count=$(grep -c 'TODO' "${CONFIG_BACKUP_DIR}/INVENTORY.md" || true)
    echo "TODO count: ${todo_count} (expect 0 once the operator has filled every row — a freshly templated file will show non-zero, that is expected right after this script runs)"
    git -C "$CONFIG_BACKUP_DIR" log -1 --format='%ci %an' -- INVENTORY.md
    #   -> a date you recognise. An inventory last touched at build time is a stale inventory.
    grep -A6 '^| Component' "${CONFIG_BACKUP_DIR}/INVENTORY.md" | grep -E 'blackbox_exporter|dnslookup' || true
    #   -> once Phase I4 has run, both rows carry a version string
fi

# =====================================================================
# Operations Runbook — "the 3am page"
# =====================================================================
# Everything below is a pointer or a command, not an explanation, per the
# source's own framing. These are transcribed as callable functions rather
# than auto-run steps: this is a human incident-response runbook, not a
# provisioning step, and the source itself describes it as something an
# operator reaches for under pressure, not something a deploy pass performs.
# Sourcing this script and calling the function you need is the intended
# usage, exactly as spelled out in each warn() below.

phase_header "Phase O — operations runbook functions (defined, not auto-run)"

# --- Runbook: give yourself DNS ---
# This host has no working DNS while AdGuardHome is down: /etc/resolv.conf
# is 'nameserver 127.0.0.1', which is AdGuardHome on :53, not Unbound on
# :5335 (Phase C5.8's deliberate posture). apt, certbot renew, the Phase D
# deploy hook, restic (must resolve the object-storage endpoint) and ansible
# all fail during exactly the incident you're trying to fix if you skip this.
runbook_give_yourself_dns_emergency() {
    require_root
    warn "Runbook: switching /etc/resolv.conf to public fallback resolvers (9.9.9.9, 1.1.1.1) while AdGuardHome is down. RESTORING it afterwards is mandatory, not optional tidying — call runbook_give_yourself_dns_restore when the incident is closed."
    grep nameserver /etc/resolv.conf || true
    #   -> 'nameserver 127.0.0.1' AND AdGuardHome not answering = this host resolves nothing
    backup_file /etc/resolv.conf
    printf 'nameserver 9.9.9.9\nnameserver 1.1.1.1\n' > /etc/resolv.conf
}

runbook_give_yourself_dns_restore() {
    require_root
    backup_file /etc/resolv.conf
    printf 'nameserver 127.0.0.1\noptions edns0 trust-ad\n' > /etc/resolv.conf
    grep -c '^nameserver' /etc/resolv.conf      # -> 1, exactly. Not 2.
    warn "Runbook: if grep -c above printed anything other than 1, a forgotten fallback line is now the silent, unvalidated resolution path Phase C5.8 exists to remove — no Phase I alert will ever tell you it is there. Fix it by hand."
}
warn "Runbook: if you'd rather not re-flip /etc/resolv.conf under pressure at all, pin your object-storage endpoint in /etc/hosts as a standing measure instead — that keeps restic working regardless. That is a one-time manual edit, not scripted here (no exact /etc/hosts line is given in the source)."

# --- Runbook: restart order ---
# Always this sequence, gated on the smoke test (Phase H12's dns-smoke.sh,
# out of scope here — only called by full path) at each marked point.
runbook_restart_order() {
    require_root
    local smoke=/usr/local/sbin/dns-smoke.sh
    command -v "$smoke" >/dev/null 2>&1 || warn "Runbook: ${smoke} not found — expected if Phase H has not run yet. The gates below will fail until it exists."

    if [[ -n "${NFTABLES_RULESET_CHANGED:-}" ]]; then
        confirm "About to run /usr/local/sbin/nft-apply to reload the live nftables ruleset (only because NFTABLES_RULESET_CHANGED is set). This is the ONLY supported way to load it — never a bare 'nft -f', which flushes and hands every currently-banned source its access back mid-incident. Continue?"
        /usr/local/sbin/nft-apply
    fi

    confirm "About to 'systemctl restart unbound'. Continue?"
    systemctl restart unbound && sleep 3 && "$smoke"

    confirm "About to 'systemctl restart adguardhome'. Do NOT run this 'as well, to be safe' if only unbound needed restarting — restarting unbound no longer restarts AdGuardHome underneath you (N4b, out of scope here), and this is a second, unnecessary outage if unrelated. Continue?"
    systemctl restart adguardhome && sleep 5 && "$smoke"

    nginx -t && confirm "nginx -t passed. About to 'systemctl reload nginx' — this affects DoH ONLY; plain DNS and DoT/DoQ do not pass through it. Never restart the whole stack for a DoH-only problem. Continue?" && systemctl reload nginx
    "$smoke"
}
warn "Runbook: never restart keepalived casually on the master — it moves the VIP. For planned maintenance on the master, use runbook_tier3_drain / runbook_tier3_undrain below instead of a bare systemctl restart."

# --- Runbook: Tier 3 drain / undrain (planned maintenance on the master) ---
runbook_tier3_drain() {
    require_root
    confirm "About to 'systemctl stop keepalived' on THIS node (assumed master) — the VIP moves to the standby within ~3s. Confirm this is the master and maintenance is planned. Continue?"
    systemctl stop keepalived
    ip -4 addr show dev eth0 | grep -c 203.0.113.10 || true     # -> 0
}
runbook_tier3_undrain() {
    require_root
    local smoke=/usr/local/sbin/dns-smoke.sh
    "$smoke" || fatal "dns-smoke.sh must pass BEFORE taking traffic back — aborting undrain"
    confirm "Smoke gate passed. About to 'systemctl start keepalived' on this node. With nopreempt (Phase N3, out of scope here) the VIP stays on the peer until it fails, so this alone does not move traffic back. Continue?"
    systemctl start keepalived
}

# --- Runbook: the gate after every change ---
runbook_gate() {
    local smoke=/usr/local/sbin/dns-smoke.sh
    command -v "$smoke" >/dev/null 2>&1 || { warn "Runbook: ${smoke} not found (Phase H not run yet)"; return 1; }
    set +e
    "$smoke"
    local rc=$?
    set -e
    echo "exit=${rc}"
    #   -> 'SMOKE: PASS' and exit=0, or you are not finished. This is the completion
    #      criterion for every config edit, package upgrade, binary upgrade, reboot
    #      and restore. When you change something by hand, YOU are the rollback.
    return "$rc"
}

# --- Runbook: pre-change gates (validate-only, no side effects, no confirm needed) ---
runbook_pre_change_gates() {
    info "Runbook pre-change gates: parse-checking every config before any restart"
    nft -c -f /etc/nftables.conf || warn "nftables ruleset does not parse"
    unbound-checkconf || warn "unbound config does not parse"
    if command -v runuser >/dev/null 2>&1 && [[ -x /opt/adguardhome/current/AdGuardHome ]]; then
        runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
            -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate \
            || warn "AdGuardHome config does not parse"
    else
        warn "Runbook: AdGuardHome binary or /opt/adguardhome/validate not present yet — skipping its check-config gate (expected pre-Phase-E)"
    fi
    nginx -t || warn "nginx config does not parse"
    if [[ -f /etc/keepalived/keepalived.conf ]]; then
        keepalived -t -f /etc/keepalived/keepalived.conf || warn "keepalived config does not parse (Tier 3 only)"
    fi
}

# --- Runbook: failure scenarios (pointer table only — full table is N7, out of scope here; do not duplicate it) ---
info "Runbook failure-scenario quick table (full table: Phase N7, not duplicated here per the source's own instruction not to keep a second copy):"
cat << 'EOF'
  Nothing resolves from anywhere         -> /usr/local/sbin/dns-smoke.sh, read which line fails first, then N7
  DoH broken, everything else fine       -> nginx -t && systemctl reload nginx
  SERVFAIL on signed domains only        -> test -s /var/lib/unbound/root.key && timedatectl -> N7 trust-anchor row
  Service died overnight and stayed dead -> journalctl -u <unit> --since 02:00 -> M3/M4 rollback (out of scope here)
EOF

# --- Runbook: escalation path ---
info "Runbook escalation path (decision tree — steps 1,2,5 destroy compromise evidence; see runbook_compromise_* below FIRST if intrusion is suspected):"
cat << 'EOF'
  0. Give yourself DNS first (runbook_give_yourself_dns_emergency) - steps 2 and 5 need name resolution.
  1. Run the smoke gate (runbook_gate) - tells you which layer is broken.
  2. Roll back the last change. If anything was upgraded/edited in the last 24h, undo that first -
     /usr/local/sbin/upgrade-adguardhome.sh and upgrade-unbound.sh (Phase M, out of scope here) roll
     back automatically; /var/backups/unbound.* and /opt/adguardhome/releases/ hold previous versions.
  3. Check the provider status page, then the console.
  4. Fail the address over: Tier 3 -> runbook_tier3_drain on the sick node, confirm VIP + smoke on peer.
     Tier 0/1 -> this is the rebuild decision, go to step 5.
  5. Rebuild (Phase K7 steps 3-8, out of scope here). If it has to land on a DIFFERENT address, that is
     N8 (out of scope here) - longer procedure, first step (lowering the record TTL) cannot be done
     retroactively.
  6. Last resort: repoint dns.example.com at a public resolver you trust, or tell users to switch.
     This is a deliberate privacy trade-off (Phase Q), not a neutral fallback - state it and undo it
     as soon as your own smoke gate passes.
  7. Write it up: what failed, which monitor saw it (or didn't), what changed so it can't recur silently.
EOF

# =====================================================================
# Runbook: "If you believe the host is compromised"
# =====================================================================
# A DIFFERENT procedure from escalation above. Steps 1(2) and 1(5) of the
# escalation path destroy evidence and re-import persistence respectively.
# This is not automatable end-to-end (step 4 "rebuild, do not clean" and
# step 6 "tell people" are judgment calls) — only the concrete, mechanical
# sub-steps the source gives verbatim are scripted, as functions, not run.

warn "Runbook COMPROMISE PROCEDURE — read before acting. Do NOT reboot (destroys process table, sockets, and the tmpfs query log Phase Q3 relies on for the notification decision). Do NOT roll back or run upgrade-adguardhome.sh/upgrade-unbound.sh (overwrites the binaries/units you need to inspect). Do NOT run nft-apply (flushes the live ruleset, including anything the attacker added). Do NOT 'clean up' anything you find. These are judgment calls for a human, not something this script decides for you."

# Step 2: contain, without pulling the plug. The scoped nftables drop is
# usually right for a VPS resolver (keeps you able to copy evidence off,
# vs. a provider-console network detach which kills your own alerting too).
# This is explicitly, per the source, "the one place in this plan where
# `nft -f` is correct rather than forbidden" — it bypasses nft-apply on
# purpose, because preserving live ban timeouts is no longer the priority,
# and it must NOT touch /etc/nftables.conf (that would overwrite evidence).
runbook_compromise_containment() {
    require_root
    : "${ADMIN_IP:?Set ADMIN_IP to your admin source IP before calling this function — the source marks this as a required placeholder, not a default}"
    : "${OBJECT_STORAGE_IP:?Set OBJECT_STORAGE_IP to your restic object-storage endpoint IP before calling this function}"
    warn "Runbook compromise containment: this replaces the LIVE ruleset in kernel memory with a lockdown policy (admin SSH + established + egress to object storage only) via a direct 'nft -f' — deliberately bypassing nft-apply and NOT touching /etc/nftables.conf on disk. This takes the service down for every user, breaks notify.sh's path to ntfy, and this host loses DNS resolution twice over. All three are accepted deliberately during a suspected compromise."
    confirm "About to capture the current ruleset to /root/EVIDENCE-nft-ruleset.txt and then load a lockdown ruleset that only permits SSH from ${ADMIN_IP} and egress to ${OBJECT_STORAGE_IP}:443. This is irreversible without re-running nft-apply afterwards. Continue?"
    # --- Runbook compromise: capture ruleset before changing anything ---
    nft list ruleset > /root/EVIDENCE-nft-ruleset.txt
    cat > /root/containment.nft << EOF
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input   { type filter hook input   priority 0; policy drop;
                  iif lo accept
                  ip saddr ${ADMIN_IP} tcp dport 22 accept
                  ct state established,related accept }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy drop;
                  oif lo accept
                  ct state established,related accept
                  ip daddr ${ADMIN_IP} accept
                  ip daddr ${OBJECT_STORAGE_IP} tcp dport 443 accept }
}
EOF
    nft -f /root/containment.nft
    warn "Runbook: announce the outage through whatever channel Phase Q5 gave you (out of scope here) — notify.sh cannot reach ntfy under this ruleset by design."
}

# Step 3: preserve evidence off-host, in this order — provider snapshot
# first (everything after it runs on the suspect kernel).
runbook_compromise_evidence_capture() {
    require_root
    warn "Runbook compromise evidence capture: step 3a (a PROVIDER-SIDE volume snapshot, e.g. 'hcloud server create-image ...') must be taken from the provider console/CLI, NOT from this box, and BEFORE this function runs — not automated here, provider-specific."
    confirm "About to collect local evidence (journal export, process/socket/lsof listings, nft ruleset, systemd units/timers, cron, dpkg --verify, files newer than the DNSSEC trust anchor, a copy of AdGuardHome's live config) into /root/evidence-<timestamp>/ on THIS box. This does not delete or modify anything. Continue?"
    # --- Runbook compromise: local evidence capture ---
    local D="/root/evidence-$(date -uIs)"
    mkdir -m 0700 -p "$D"
    journalctl -o export > "$D/journal.export"        # persistent journal is Phase Q3's decision paying off
    ps auxwwf                > "$D/ps.txt"
    ss -tulpanH              > "$D/sockets.txt"
    lsof -nP 2>/dev/null     > "$D/lsof.txt"
    nft list ruleset         > "$D/nft.txt"
    systemctl list-units --all --no-pager > "$D/units.txt"
    systemctl list-timers --all --no-pager > "$D/timers.txt"
    crontab -l 2>/dev/null > "$D/cron.txt" || true
    cat /etc/cron.d/* >> "$D/cron.txt" 2>/dev/null || true
    dpkg --verify            > "$D/dpkg-verify.txt" 2>&1    # any line here is a modified packaged file
    find / -xdev -newer /var/lib/unbound/root.key -type f 2>/dev/null > "$D/newer-than-anchor.txt"
    cp /opt/adguardhome/conf/AdGuardHome.yaml "$D/"   # AGH rewrites this at runtime: it is a change record
    sha256sum "$D"/* > "$D/SHA256SUMS"
    echo "Evidence directory: $D"
    warn "Runbook: copy $D OFF this box immediately — 'scp -r deploy@<this-host>:${D} ./' from your workstation. Never leave the only copy on the suspect disk, and NEVER write it into the restic repository (the attacker's credentials could reach it)."
    warn "Runbook: 'find / -newer /var/lib/unbound/root.key' is a heuristic, not proof — that file is written only by Unbound's RFC 5011 tracking, so it's a reasonable 'everything after this is suspicious' waterline, but an attacker who sets timestamps defeats it."
}

warn "Runbook compromise step 4 (REBUILD, DO NOT CLEAN): you cannot clean a compromised host — you don't know what you didn't find, verifying absence is impossible, and the effort exceeds the 20-minute O5 rebuild target. Rebuild per Phase K7 (out of scope here) on a NEW instance with a NEW address (a same-IP reimage is not enough; a new IP also puts you in N8, out of scope here), restoring from a restic snapshot dated BEFORE the earliest suspicious timestamp found above — never 'latest'. Restore ONLY /etc/letsencrypt from that old snapshot (the one thing Ansible cannot regenerate); restore everything else from source control instead, even if it costs you the Phase B allowlist and you have to re-enter it by hand. This is a judgment call requiring the evidence gathered above — not scripted further here."

warn "Runbook compromise step 5 (ROTATE EVERYTHING): the full ordered list with blast radius is Phase K5e's post-compromise section (out of scope here). Two items are time-critical and repeated here: revoke the TLS certificate with --reason keycompromise (an attacker holding that key can impersonate this resolver to every encrypted client until expiry), and cut the object-storage credential FIRST, before anything else — that credential could 'restic forget --prune' your only clean snapshot while you are still reading this. MANUAL, ordered, cross-referenced to K5e — not scripted further here."

warn "Runbook compromise step 6 (NOTIFY): Phase Q6's Art. 33 row (out of scope here) puts a 72-hour clock on breach notification that starts at AWARENESS, not confirmation — the moment you formed the suspicion. What was actually exposed is posture-dependent (Phase Q); under the shipped default, up to six hours of query records with IPv4 truncated to /16 and IPv6 to /48, held in RAM, may have been exposed — under Posture A there is nothing to disclose because no record existed. This is exactly why the provider snapshot in step 3a must come first: a reboot destroys both the evidence of what was exposed and your ability to state what was NOT. Record the incident in RETENTION.md and INVENTORY.md (O6, this script writes INVENTORY.md above) regardless of whether it met a notification threshold — a business/legal decision, not scripted further here."

# =====================================================================
# End of Phase O
# =====================================================================
info "Phase O transcription complete."
echo
echo "=== Phase O verification pointers ==="
echo "IaC repo skeleton:   ls -R ${IAC_REPO}   (expect: 12 role dirs, handlers/main.yml, reference/O3.* files, cloud-init.yaml)"
echo "Drift detection:     test -f /etc/cron.d/ansible-drift && grep -c 'changed=\\[1-9\\]' /etc/cron.d/ansible-drift   (control host only)"
echo "Rebuild-time target: source this script and run 'o5_apply_and_check' / 'o5_prove_drift_cron_catches_drift' / 'o5_bare_host_rebuild_check' by hand; the source's own target is 20 minutes wall clock, measured via Phase K7 steps 2-9 (out of scope here)."
echo "Operational inventory: grep -c TODO ${CONFIG_BACKUP_DIR}/INVENTORY.md   (expect 0 once fully filled in) ; git -C ${CONFIG_BACKUP_DIR} log -1 -- INVENTORY.md"
echo "Runbook functions:   source this script, then call runbook_give_yourself_dns_emergency / runbook_restart_order / runbook_tier3_drain / runbook_gate / runbook_pre_change_gates / runbook_compromise_containment / runbook_compromise_evidence_capture as the incident actually in front of you requires. This script does not call any of them itself."
echo
warn "NOT covered by this script (explicitly out of scope, see header): Phase K (Backup/Restore/Secrets), Phase M (Patching/Upgrades), Phase N (High Availability) — each has its own deploy script — and the 'Decommissioning' section of phases/08-operations.md, which is a human wind-down procedure this batch did not assign anywhere. Flag Decommissioning for coverage separately if it needs to exist as a script at all."
