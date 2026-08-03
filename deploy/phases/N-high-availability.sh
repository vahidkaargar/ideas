#!/usr/bin/env bash
# deploy/phases/N-high-availability.sh — Phase N: High Availability and Failure Modes
# Source: phases/08-operations.md, "## PHASE N: High Availability and Failure
# Modes" (N1-N8). Read in full. Transcription only — no directive here has
# been invented; every command/flag/path is copied from that file. Read the
# source file before running this script.
#
# SCOPE. This source file also holds PHASE K (backup/restore/secrets), PHASE M
# (patching/upgrades — already scripted separately in M-upgrade-rollback.sh)
# and PHASE O (provisioning/reproducibility). None of those are in this
# script. K (deploy/phases/K-backup-restore.sh) and O
# (deploy/phases/O-iac-runbook.sh) are scripted separately in this repo —
# see them for K5c's LoadCredential= drop-in (referenced, not duplicated,
# below) and O's Ansible layout. Phase P (private access / DNS-01 wildcard,
# referenced below) and Phase L (go-live gate, referenced in N8) are not
# scripted anywhere in this repo as of this writing; do not assume their
# objects exist.
#
# WHAT IS ALREADY DONE ELSEWHERE, deliberately not duplicated here:
#   - N4a (canonical restart policy: Restart=always, RestartSec=5,
#     StartLimitIntervalSec=300, StartLimitBurst=10) is ALREADY written into
#     unbound's hardening.conf by Phase C (C4) and into adguardhome's and
#     nginx's hardening.conf by Phase E. This script does not touch those
#     three files — see N4's "already-done" note below for the check that
#     proves it, instead of re-writing them and risking a second, drifted
#     copy (CLAUDE.md hard rule 2, single ownership per shared object).
#   - N4b (Requires= -> Wants=+After= so an Unbound restart does not bounce
#     AdGuardHome) is ALREADY in Phase E's adguardhome.service unit.
#   - N5 (memory ceilings, swap, vm.swappiness) has exactly ONE owner in this
#     whole plan: Phase A6. This script sets none of it — N5's own text says
#     so explicitly ("Phase A6 provides the swap file... Do not restate the
#     numbers here"). What this script does for N5/N6 is read the numbers
#     back and prove nothing was OOM-killed (verification only).
#
# TIER IS NOT ASSUMED. N2's own text gives a recommendation ("Tier 3 if the
# service has users who will notice an outage; Tier 1 otherwise"), not a
# default — this script REQUIRES the operator to state the tier explicitly.
# Tier 0 (do nothing beyond Phase K/O) and Tier 4 (anycast) are out of scope
# per this run's assignment ("Tier 1 through Tier 3 ... skip the other three
# phases entirely"); Tier 4 is also the source's own explicit recommendation
# AGAINST for this deployment size (N2: "Tier 4 is not worth it here").
#
# Env:
#   KEYSTONE_HA_ACTION=deploy|address-change   optional, default "deploy".
#                            "address-change" runs ONLY N8's procedure (moving
#                            the service to a new address after a provider
#                            suspension or IP loss) INSTEAD of the N2-N7 setup
#                            below — it is an incident procedure, not part of
#                            a routine phase run, and the two do not mix.
#   KEYSTONE_HA_TIER=1|2|3   REQUIRED when KEYSTONE_HA_ACTION=deploy. See N2's
#                            tier table below.
#   KEYSTONE_HA_NODE=A|B     REQUIRED only for tier 3 — which keepalived node
#                            identity to render (priority/unicast IPs differ
#                            per node, N3).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=lib/common.sh
source lib/common.sh

require_root
phase_header "Phase N — high availability (tiers 1-3) and failure modes"

require_cmd systemctl awk grep dig nft

KEYSTONE_HA_ACTION="${KEYSTONE_HA_ACTION:-deploy}"

# --- Phase-wide identifiers, exactly as used throughout the N3 example in the
# source (interface, private subnet, VIP, virtual_router_id, VRRP auth). These
# are the plan's own example values — replace with the real ones for your
# deployment before trusting this against production; see the warn() calls
# below at first use of each. ---
DOMAIN="dns.example.com"
HA_IFACE="enp7s0"            # the PRIVATE nic carrying the VRRP heartbeat (N3)
HA_PRIVATE_NET="10.0.0.0/24" # VRRP firewall rule scope (N3)
HA_VRID=51                   # virtual_router_id (N3)
HA_VIP="203.0.113.10/32"     # the floating IP, added locally on the master (N3)
HA_VIP_ADDR="203.0.113.10"
HA_VIP_DEV="eth0"
HA_AUTH_PASS="s3cr3tvr"      # VRRPv2 PASS is 8 bytes; anything longer is truncated (N3)

# =====================================================================
# N4c. Crash-loop churn detector — applies to every tier (all of 1/2/3), no
# tier-specific content. M7/M-upgrade-rollback.sh already cross-references
# this as "N4's churn detector".
# =====================================================================
n4c_churn_detector() {
    phase_header "N4c: crash-loop churn detector (applies to every tier)"
    info "N4c: NRestarts is monotonic for a unit's lifetime; a jump between samples means the unit is crash-looping even while systemd still reports 'active'. N4a/N4b (the restart policy and the Requires->Wants change this detector backs up) are already in place — see the header note above."

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

    info "N4c: /usr/local/sbin/notify.sh and /etc/cron.d/dns-health are Phase I's — this phase only appends. Confirm Phase I ran first."
    if [[ -f /etc/cron.d/dns-health ]]; then
        backup_file /etc/cron.d/dns-health
        cat >> /etc/cron.d/dns-health << 'EOF'
# appended to /etc/cron.d/dns-health (created by Phase I)
*/5 * * * * root /usr/local/sbin/check-restart-churn.sh
EOF
    else
        warn "N4c: /etc/cron.d/dns-health does not exist yet (sole owner: Phase I). Re-run this append step after Phase I, or add by hand: '*/5 * * * * root /usr/local/sbin/check-restart-churn.sh'"
    fi

    echo "N4c verification:"
    echo "  systemctl show unbound -p Restart -p RestartUSec -p StartLimitBurst -p StartLimitIntervalUSec"
    echo "    -> Restart=always  RestartUSec=5s  StartLimitBurst=10  StartLimitIntervalUSec=5min (already set by Phase C/E, confirmed here not re-set)"
    echo "  systemctl show unbound -p NRestarts --value"
    echo "  /usr/local/sbin/check-restart-churn.sh; journalctl -t dns-alert -n 5 --no-pager"
}

# =====================================================================
# N3. Tier 3: keepalived VRRP with a floating IP
# =====================================================================
n3_tier3_setup() {
    phase_header "N3: Tier 3 — keepalived VRRP with a floating IP"

    : "${KEYSTONE_HA_NODE:?KEYSTONE_HA_NODE is required for Tier 3 — set to A or B. Node A and node B differ only in priority, unicast_src_ip and unicast_peer (N3); this script will not guess which node it is running on.}"
    case "$KEYSTONE_HA_NODE" in
        A) HA_PRIORITY=200; HA_LOCAL_IP=10.0.0.2; HA_PEER_IP=10.0.0.3 ;;
        B) HA_PRIORITY=100; HA_LOCAL_IP=10.0.0.3; HA_PEER_IP=10.0.0.2 ;;
        *) fatal "N3: KEYSTONE_HA_NODE must be A or B (got '$KEYSTONE_HA_NODE')." ;;
    esac
    info "N3: rendering keepalived.conf for node $KEYSTONE_HA_NODE (priority=$HA_PRIORITY, unicast_src_ip=$HA_LOCAL_IP, unicast_peer=$HA_PEER_IP)"

    require_cmd apt
    info "N3: both HA nodes run the identical stack, built the same way. Both resolvers stay hot, so the standby's Unbound cache is warm before any failover. Only the VIP moves."

    # --- N3: script placement — enable_script_security refuses to run any
    # script whose path is writable by a non-root user; /usr/local/sbin is
    # 2775 root:staff on Debian/Ubuntu and would be silently refused. ---
    info "N3: installing keepalived, placing scripts under root-owned /etc/keepalived/scripts (enable_script_security refuses anything under /usr/local/sbin)"
    apt install -y keepalived
    install -d -m 0755 -o root -g root /etc/keepalived/scripts
    useradd -r -s /usr/sbin/nologin keepalived_script 2>/dev/null || true

    backup_file /etc/keepalived/scripts/vrrp-dns-check.sh
    cat > /etc/keepalived/scripts/vrrp-dns-check.sh << 'EOF'
#!/bin/bash
# Runs as keepalived_script. Non-zero exit => vrrp_script failure.
# Checks the resolver, not just the daemon: a hung Unbound still holds its PID.
dig +time=1 +tries=1 @127.0.0.1 -p 5335 google.com A +short 2>/dev/null | grep -qE '^[0-9]+\.'
EOF
    chmod 0755 /etc/keepalived/scripts/vrrp-dns-check.sh
    chown root:root /etc/keepalived/scripts/vrrp-dns-check.sh

    # --- N3: node-specific keepalived.conf ---
    warn "N3: keepalived.conf below uses the plan's EXAMPLE values (interface $HA_IFACE, private subnet $HA_PRIVATE_NET, VIP $HA_VIP, auth_pass '$HA_AUTH_PASS'). Replace them with your real values — the auth_pass in particular is the K5e-rotated VRRP secret (12-month cadence) and must not ship as the literal plan example in production."
    backup_file /etc/keepalived/keepalived.conf
    cat > /etc/keepalived/keepalived.conf << EOF
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
    # \`weight\` is DELIBERATELY OMITTED. The default weight of 0 means <fall> consecutive
    # failures drive the instance into FAULT state, which stops adverts and hands the VIP
    # over. A negative weight only SUBTRACTS from priority: with 200/100 a \`weight -40\`
    # leaves 160 > 100 and nothing ever fails over. FAULT-state handover also still works
    # under \`nopreempt\`; priority-based takeover does not.
}

vrrp_instance DNS_VIP {
    state BACKUP          # both nodes BACKUP + nopreempt = no flapping when A recovers
    nopreempt
    interface $HA_IFACE      # the PRIVATE nic carrying the heartbeat
    virtual_router_id $HA_VRID
    priority $HA_PRIORITY          # this is node $KEYSTONE_HA_NODE's priority (the other node uses the other value: 200/100)
    advert_int 1
    unicast_src_ip $HA_LOCAL_IP      # this node's private IP
    unicast_peer {
        $HA_PEER_IP                 # the PEER node's private IP
    }
    authentication {
        auth_type PASS
        auth_pass $HA_AUTH_PASS       # VRRPv2 PASS is 8 bytes; anything longer is truncated
    }
    virtual_ipaddress {
        $HA_VIP dev $HA_VIP_DEV # the floating IP, added locally on the master
    }
    track_script {
        chk_dns
    }
    # Runs as root: it must read the systemd credential (K5c), and it lives in a
    # root-owned directory so enable_script_security permits it.
    notify_master "/etc/keepalived/scripts/claim-floating-ip.sh" root root
}
EOF
    info "N3: this file was rendered for node $KEYSTONE_HA_NODE. Run this same script with KEYSTONE_HA_NODE=$( [[ "$KEYSTONE_HA_NODE" == "A" ]] && echo B || echo A ) on the peer host — it differs only in priority/unicast_src_ip/unicast_peer, exactly as N3 specifies."

    # --- N3: provider floating-IP claim script. It depends on the
    # LoadCredential= drop-in installed by Phase K5c (checked, not
    # duplicated, below). ---
    warn "N3: claim-floating-ip.sh below uses the Hetzner CLI (hcloud) exactly as given in the source. DigitalOcean's equivalent is 'doctl compute reserved-ip-action assign <ip> <droplet-id>' and Vultr's is 'vultr-cli reserved-ip attach' — both explicitly UNVERIFIED in the source; confirm against your provider's current CLI before relying on either."
    backup_file /etc/keepalived/scripts/claim-floating-ip.sh
    cat > /etc/keepalived/scripts/claim-floating-ip.sh << 'EOF'
#!/bin/bash
set -euo pipefail
HCLOUD_TOKEN=$(cat "${CREDENTIALS_DIRECTORY:-/etc/keepalived}/provider")
export HCLOUD_TOKEN
exec /usr/local/bin/hcloud floating-ip assign dns-vip "$(hostname)"
EOF
    chmod 0750 /etc/keepalived/scripts/claim-floating-ip.sh
    chown root:root /etc/keepalived/scripts/claim-floating-ip.sh

    # /etc/systemd/system/keepalived.service.d/creds.conf (LoadCredential=
    # provider:/etc/keepalived/provider.token) is Phase K5c's object, not
    # this phase's — K5c's own script comment names it explicitly: "The
    # keepalived unit itself is Phase N3's object — this drop-in is the
    # concrete instance of the LoadCredential pattern K5c describes." This
    # script only depends on it being there; it does not (re)create it.
    if [[ -f /etc/systemd/system/keepalived.service.d/creds.conf ]]; then
        info "N3/K5c: keepalived.service.d/creds.conf (LoadCredential=) already present — created by Phase K5c, not duplicated here."
    else
        warn "N3/K5c: /etc/systemd/system/keepalived.service.d/creds.conf does not exist yet. It is Phase K5c's object, not this phase's — run Phase K (K5c) before Tier 3, or add it by hand per phases/08-operations.md K5c: '[Service]\\nLoadCredential=provider:/etc/keepalived/provider.token', then 'systemctl daemon-reload'. Not created here to avoid a second, drifted copy of a file another phase owns."
    fi

    if [[ ! -s /etc/keepalived/provider.token ]]; then
        install -d -m 0700 /etc/keepalived
        printf 'REPLACE-WITH-YOUR-PROVIDER-API-TOKEN\n' > /etc/keepalived/provider.token
        chmod 0600 /etc/keepalived/provider.token
        chown root:root /etc/keepalived/provider.token
        warn "N3/K5c: /etc/keepalived/provider.token is a PLACEHOLDER. Replace it with a real provider API token scoped to floating-IP assignment ONLY (K5e: a full project token in a script on a public-facing box can delete your servers) before trusting failover to actually move the address. This value belongs in the vault (group_vars/dns/vault.yml, K5b), not committed anywhere."
    fi

    # --- N3: the firewall must pass VRRP (IP protocol 112, neither TCP nor
    # UDP) between the two private addresses. This is Phase B's chain input,
    # in table inet filter -- Phase B is the sole author of that table (per
    # CLAUDE.md's ownership table); this inserts one rule into it, alongside
    # the other input accepts, and never touches dns_guard (a regular chain,
    # off-topic and unreachable for protocol 112 traffic that never reaches
    # the jump). ---
    info "N3: VRRP is IP protocol 112 — not TCP or UDP, so no port rule covers it. It goes in chain input of table inet filter (Phase B's sole-owned object), never in dns_guard."
    if [[ ! -f /etc/nftables.conf ]]; then
        fatal "N3: /etc/nftables.conf not found — run Phase B before Phase N Tier 3."
    fi
    if grep -q 'ip protocol 112 accept' /etc/nftables.conf; then
        info "N3: VRRP accept rule already present in /etc/nftables.conf — skipping insertion"
    else
        NFT_ANCHOR='    ct state established,related accept'
        if ! grep -qF "$NFT_ANCHOR" /etc/nftables.conf; then
            fatal "N3: could not find the expected anchor line ('ct state established,related accept') inside chain input of /etc/nftables.conf — this build's Phase B ruleset does not match what this script expects. Add the VRRP rule by hand instead: iifname \"$HA_IFACE\" ip saddr $HA_PRIVATE_NET ip protocol 112 accept — alongside the other input accepts in table inet filter, chain input. Never inside dns_guard. See phases/08-operations.md N3."
        fi
        confirm "N3: about to insert a VRRP (ip protocol 112) accept rule into Phase B's 'chain input' in /etc/nftables.conf, for the private HA heartbeat, and reload the firewall via nft-apply (never a bare nft -f). This is a firewall ruleset change. Continue?"
        backup_file /etc/nftables.conf
        awk -v anchor="$NFT_ANCHOR" -v iface="$HA_IFACE" -v net="$HA_PRIVATE_NET" '
            { print }
            $0 == anchor && !done {
                print ""
                print "    # N3: VRRP heartbeat between HA pair nodes, private network only (Phase N)"
                print "    iifname \"" iface "\" ip saddr " net " ip protocol 112 accept"
                done = 1
            }
        ' /etc/nftables.conf > /etc/nftables.conf.new
        if ! nft -c -f /etc/nftables.conf.new; then
            rm -f /etc/nftables.conf.new
            fatal "N3: the nftables.conf with the VRRP rule inserted failed to validate — NOT installed, original file untouched (backup already taken above regardless)."
        fi
        mv /etc/nftables.conf.new /etc/nftables.conf
        if [[ -x /usr/local/sbin/nft-apply ]]; then
            /usr/local/sbin/nft-apply
        else
            fatal "N3: /usr/local/sbin/nft-apply not found (Phase B's reload wrapper) — run Phase B before Phase N Tier 3. Do not fall back to a bare 'nft -f': it flushes and hands every currently-banned source its access back."
        fi
    fi

    # --- N3: certificates MUST move to DNS-01 on a Tier 3 deployment. This is
    # NOT scripted here: Phase D's own D7 leaves this MANUAL/DEFERRED to
    # Phase P (P3c, "the wildcard requirement, and the record everyone
    # forgets"), and neither phase's script implements it as of this
    # writing. This script only gates on it and performs the one concrete
    # Tier-3-only step the source gives outside of Phase D/P: disabling the
    # standby's renewal timer. ---
    warn "N3: MANDATORY prerequisite, not scripted here — HTTP-01 validates against the A record of $DOMAIN, which resolves to the VIP, which lives on exactly one node at a time. The standby can NEVER renew over HTTP-01 and its certificate expires silently. Switch Phase D to the DNS-01 plugin (Phase D's own D7 section, deferred to Phase P3c 'the wildcard requirement, and the record everyone forgets'), issue on node A only, and ship /etc/letsencrypt/{archive,live,renewal} to node B preserving symlinks BEFORE relying on this tier. Neither Phase D's nor Phase P's script implements the DNS-01 switch as of this writing — do this by hand per the source, or wait for those scripts."
    confirm "N3: confirming operator acknowledgment — has Phase D already been switched to DNS-01 issuance for $DOMAIN, with the certificate lineage present on this node? (Tier 3 does not work correctly otherwise.) Continue only if yes."

    if [[ "$KEYSTONE_HA_NODE" == "B" ]]; then
        info "N3: node B — exactly one node may hold an active renewal timer (both nodes get certbot's twice-daily timer by default; two independent renewals produce divergent certificates and doubled ACME traffic)."
        confirm "N3: about to run 'systemctl disable --now certbot.timer' on this node (node B, the standby) — disables a boot-service timer. Continue?"
        systemctl disable --now certbot.timer
    else
        info "N3: node A keeps its certbot.timer enabled — it is the only node that renews."
    fi

    info "N3: HTTP-01's tcp dport 80 accept rule (Phase B) is no longer needed for ACME once DNS-01 is in place, but is kept regardless — it is a standing rule serving Phase Q's well-known files from /var/www/acme, not a renewal-window rule. Do not close it."

    echo
    echo "N3 verification:"
    echo "  keepalived -t -f /etc/keepalived/keepalived.conf          # config parses"
    echo "  systemctl stop unbound; sleep 8; journalctl -u keepalived -n 20 --no-pager | grep -i 'Entering FAULT STATE'"
    echo "  ip -4 addr show dev $HA_VIP_DEV | grep -c $HA_VIP_ADDR     # -> 0 on the demoted node"
    echo "  systemctl start unbound"
    echo "  journalctl -u keepalived --no-pager | grep -iE 'unsafe|SECURITY VIOLATION|Permission denied'; echo \"grep exit=\$? (1 = clean)\""
    echo "  nft list chain inet filter input | grep 'ip protocol 112'"
    echo "  nft list chain inet filter dns_guard | grep -c 112     # -> 0"
    echo "  tcpdump -ni $HA_IFACE proto 112 -c 4"
    echo "  systemctl is-enabled certbot.timer     # enabled on node A, disabled on node B"

    confirm "N3: about to 'systemctl daemon-reload && systemctl enable --now keepalived' — enables and starts a boot service that will begin advertising VRRP and may claim the VIP on this node. Continue?"
    systemctl daemon-reload
    systemctl enable --now keepalived
}

# =====================================================================
# N8. When the address has to change — an incident procedure, NOT part of a
# routine deploy. Only runs when KEYSTONE_HA_ACTION=address-change, and runs
# INSTEAD OF N2-N7 below, never alongside them.
# =====================================================================
n8_address_change() {
    phase_header "N8: when the address has to change"
    warn "N8 (READ FIRST): every Do53 user typed the address into a router or an OS setting by hand. There is no mechanism to update them, no failover, no notification channel that reaches them. A forced IP change is a PERMANENT OUTAGE for that population regardless of how well the rest of this procedure is executed."

    info "N8: checking the current TTL on $DOMAIN's A/AAAA records — this is the one step you cannot do retroactively. The standing recommendation is 300 seconds, permanently, set BEFORE you need it."
    dig +noall +answer "$DOMAIN" A | awk '{print $2}'

    warn "N8 step 1 (references Phase K7, out of scope for THIS script's assignment): provision the new node from Phase O cloud-init + the playbook (deploy/phases/O-iac-runbook.sh), and restore /etc/letsencrypt from restic per K7 steps 3-6 — K7's drill procedure lives in deploy/phases/K-backup-restore.sh, not here. The certificate is for the NAME, not the address, so it migrates unchanged."
    warn "N8 step 2 (MANUAL, provider-specific): set the PTR record at the new provider BEFORE cutover (Phase Q4) — a mismatched forward/reverse is what gets an abuse desk to null-route you instead of routing complaints to you, and you are about to be a new IP with zero reputation."
    warn "N8 step 3 (MANUAL, registrar action): cut over the A/AAAA records for $DOMAIN. With a 300s TTL, encrypted clients follow within five minutes; Do53 clients never follow."
    warn "N8 step 4 (MANUAL / provider account decision): keep the OLD address answering for as long as the old provider allows, in parallel, if the suspension left any window at all. This is the only mitigation the Do53 population gets."

    info "N8 step 5: things that do NOT follow the A record, checked here where a grep is possible — anything that pins the OLD IP literally, rather than the hostname:"
    warn "N8 step 5 detail (MANUAL, per item — none of these are auto-fixable, each is provider/registrar/document-specific): Phase P WireGuard peer configs with a literal Endpoint= (dead until re-issued); Phase B allowlist4/allowlist6 and Phase P access controls written from the CLIENT side (unaffected, but any upstream ACL naming your OLD address is now wrong); Phase I's blackbox probe targets pointed at a literal address; security.txt and the published privacy notice (Phase Q5) if either names the address; the provider abuse-forwarding reference (Phase Q6, provider-specific, does not migrate — open a new one); the Ansible inventory, the cloud-init file, and the O6 inventory's provider rows."
    echo "  grep -rl '<OLD-IP>' /srv/dns-infra /etc/wireguard /etc/prometheus /var/www/acme/.well-known /opt/dns-config-backup 2>/dev/null   # -> no output, once step 5 is actually done. Fill in <OLD-IP> yourself."

    warn "N8 step 6 (MANUAL, cross-phase): re-run the go-live gate (Phase L), not just the smoke gate — a new address on the internet is a new exposure surface. Confirm the admin UI is not public and that nothing but :53, :443, :853 and :80 answers. Phase L is not scripted in this repo as of this writing."

    echo
    echo "N8 verification:"
    echo "  /usr/local/sbin/dns-smoke.sh                                          # SMOKE: PASS on the new node"
    echo "  dig +short -x <NEW-IP>                                                # -> $DOMAIN."
}

# =====================================================================
# Action dispatch — address-change and deploy are mutually exclusive.
# =====================================================================
if [[ "$KEYSTONE_HA_ACTION" == "address-change" ]]; then
    n8_address_change
    echo
    echo "Phase N (address-change action) complete. Re-run with KEYSTONE_HA_ACTION=deploy for the routine tier setup."
    exit 0
elif [[ "$KEYSTONE_HA_ACTION" != "deploy" ]]; then
    fatal "N: KEYSTONE_HA_ACTION must be 'deploy' or 'address-change' (got '$KEYSTONE_HA_ACTION')."
fi

# =====================================================================
# N1. What clients actually do when a resolver stops answering (reference)
# =====================================================================
# No action here — N1 is the reasoning that drives N2's tier choice, not a
# step. Restated in full in phases/08-operations.md N1; the one line that
# matters for what follows: DoT/DoQ/DoH and Android Private DNS are
# configured with ONE endpoint and have no client-side failover, so any HA
# this plan buys has to move an IP address between hosts — client-side
# "just publish two A records" (Tier 2) does not deliver failover for them.
info "N1: client-side failover does not exist for DoT/DoQ/DoH/Android Private DNS (single endpoint, no fallback) — see phases/08-operations.md N1. This is why Tier 2 is not a solution and Tier 3 moves an IP instead."

# =====================================================================
# N2. The tiers — tier selection is mandatory, not assumed
# =====================================================================
phase_header "N2: tier selection"

: "${KEYSTONE_HA_TIER:?KEYSTONE_HA_TIER is required when KEYSTONE_HA_ACTION=deploy — set to 1, 2 or 3. See phases/08-operations.md N2's tier table. The source's own recommendation is Tier 3 if the service has users who will notice an outage, Tier 1 otherwise — that is a recommendation, not a default, and this script will not assume it for you.}"

case "$KEYSTONE_HA_TIER" in
    1|2|3) : ;;
    0|4)
        fatal "N2: KEYSTONE_HA_TIER=$KEYSTONE_HA_TIER is out of scope for this script. Tier 0 (manual rebuild) needs nothing beyond Phase K/O. Tier 4 (anycast) is the source's own explicit recommendation against for this deployment size (N2: 'Tier 4 is not worth it here') and is not scripted anywhere in this plan." ;;
    *)
        fatal "N2: KEYSTONE_HA_TIER must be 1, 2 or 3 (got '$KEYSTONE_HA_TIER')." ;;
esac

info "N2: selected KEYSTONE_HA_TIER=$KEYSTONE_HA_TIER"

# --- N2 dispatch — what each tier actually needs from this script ---
case "$KEYSTONE_HA_TIER" in
    1)
        phase_header "N2: Tier 1 — single node, fast recovery + hot spare image"
        info "N2 Tier 1: a pre-provisioned but STOPPED second host, built the same way as the live node (Phase O cloud-init + playbook), ready to start/restore/take-the-address in roughly 5-10 minutes. Failover time and RTO are only real if measured — Phase K7's Tier 2 DR drill IS the measurement, run against this stopped spare."
        warn "N2 Tier 1 (MANUAL / provider-specific): the source gives no concrete command for provisioning a stopped standby host — this is a provider account/billing decision, not a scriptable universal step. Provision it the same way K7's scratch VPS is provisioned (Phase O's cloud-init user-data), then leave it stopped. Not scripted here."
        n4c_churn_detector
        ;;
    2)
        phase_header "N2: Tier 2 — two independent nodes, two published addresses"
        warn "N2 Tier 2 EXPLICIT WARNING FROM THE SOURCE: this looks like the cheap answer and is not. Two published A/AAAA records give glibc clients a five-second stall per query against the dead address (N1) and give DoT/DoQ/Android clients NOTHING AT ALL, because those are configured with one hostname. You will have doubled cost and attack surface for a worse user experience than a single node. The source recommends Tier 3 (real failover) or Tier 1 (measured RTO, no standing standby) instead."
        info "N2 Tier 2 (MANUAL / registrar decision): publishing a second A/AAAA record is a DNS registrar action outside this host, not something this script performs. Not scripted here."
        n4c_churn_detector
        ;;
    3)
        n3_tier3_setup
        n4c_churn_detector
        ;;
esac

# =====================================================================
# N5/N6. Resource ceilings, the OOM killer, and scale signals
# (verification only — sole owner of the ceilings/swap is Phase A6)
# =====================================================================
phase_header "N5/N6: resource ceilings and scale-up/out signals (read-only — Phase A6 owns the ceilings)"
info "N5a: memory ceilings, the swap file and vm.swappiness have exactly one owner in this plan: Phase A6. This phase sets none of it. If any of the checks below come back empty, Phase A6 did not run — that is not this phase's job to fix."
info "N5c: size the cache from measurement, not a round number. Unbound's resident set runs materially above msg-cache-size + rrset-cache-size (allocator overhead, per-thread structures) — budget roughly double, then measure over 48h of real traffic."

echo
echo "N5/N6 verification (read-only):"
echo "  systemctl show unbound     -p MemoryHigh -p MemoryMax -p OOMScoreAdjust"
echo "  systemctl show adguardhome -p MemoryHigh -p MemoryMax -p OOMScoreAdjust"
echo "  systemctl show unbound -p MemoryCurrent      # bytes, right now"
echo "  unbound-control stats_noreset | grep -E 'mem\\.cache|msg\\.cache|total\\.num'"
echo "  systemd-cgtop -1 -n1 --order=memory | head -15"
echo "  free -h && swapon --show && sysctl vm.swappiness      # -> vm.swappiness = 10"
echo "  ls /etc/sysctl.d/                                     # -> 99-dns.conf (A) and 99-nftables-edge.conf (B) only; no 99-swap.conf"
echo "  journalctl -k --since '-1h' | grep -iE 'oom|killed process'; echo \"grep exit=\$? (1 = clean)\""
echo "  df -h /opt /var && du -sh /var/log/adguardhome/querylog /var/lib/adguardhome/stats"
info "N6 scale thresholds (act on these, not on vibes — see phases/08-operations.md N6 for the full table): load average > 1.5 sustained on 2 vCPU, or %steal > 5% -> scale UP. MemoryCurrent > 70% of RAM with cache already tuned -> scale UP. Cache hit ratio falling at ceiling -> scale UP (not out — a second node halves each node's hit rate). You care about uptime at all -> scale OUT, now, not on a traffic threshold. Clients >80ms RTT in a second region -> scale OUT geographically. Egress/pps cap hit -> scale OUT."

# =====================================================================
# N7. Failure modes — reference table only, not scripted
# =====================================================================
# The full lookup table is N7 in phases/08-operations.md, and the Operations
# Runbook section of that same file says explicitly: "The full table is N7.
# Do not maintain a second copy here — a duplicated runbook table is a
# runbook table that is wrong." Every row's "immediate action" is a command
# already defined by the owning phase (nft-apply — Phase B; dns-smoke.sh —
# Phase H12; unbound-anchor — Phase C; the notify.sh escalation — Phase I).
# This script does not restate the table. See phases/08-operations.md N7,
# or the Operations Runbook's four-row summary, when diagnosing a live
# failure.
info "N7: failure-mode table is a reference lookup, not a deploy step — see phases/08-operations.md N7. Not duplicated here (the source itself forbids a second copy)."

# ============================================================================
# End of Phase N
# ============================================================================
echo
echo "Phase N complete for KEYSTONE_HA_TIER=$KEYSTONE_HA_TIER."
echo "This phase's own acceptance surface: the N3 checks above (Tier 3 only) and the N4c/N5/N6 read-only checks above."
echo "The overall completion gate, per the Operations Runbook: /usr/local/sbin/dns-smoke.sh must print 'SMOKE: PASS' and exit 0 (Phase H12) — not merely 'systemctl is-active'."
echo "See phases/08-operations.md N1-N8 for the full text, and the Operations Runbook section of the same file for the 3am escalation path."
echo "N8 (address change) is a separate incident procedure — run this script again with KEYSTONE_HA_ACTION=address-change when it is actually needed."
