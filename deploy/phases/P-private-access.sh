#!/usr/bin/env bash
# deploy/phases/P-private-access.sh — Phase P: Private Access Layer (Optional)
# Source: phases/09-private-access.md (read in full). Transcription only — no
# directive here has been invented; every command/flag/path/config key is
# copied from that file. Read the source file before running this script.
#
# P0 is a DECISION MATRIX, not a build step: the source is explicit that the
# six mechanisms (P1-P6) are not all meant to run together, and that a normal
# deployment picks a primary (see the matrix) plus at most one secondary. This
# script does not force every option — pass the mechanism(s) you actually
# chose, using exactly the option names phases/09-private-access.md defines:
#
#   P1  AdGuardHome native ACLs                    (§P1,  weakest, near-universal)
#   P2  nftables IP allowlisting                    (§P2,  static-IP sites)
#   P3  ClientIDs for dynamic-IP clients             (§P3,  BYOD / no VPN client)
#   P4  nginx token-authenticated DoH                (§P4,  convenience tier)
#   P5  mTLS for DoT via an nginx stream front        (§P5,  high-assurance)
#   P6  WireGuard-fronted DNS                         (§P6,  recommended default)
#
# Usage:
#   sudo deploy/phases/P-private-access.sh <MECH>[,<MECH>...]
#   KEYSTONE_P_MECHANISMS=P6,P1 sudo deploy/phases/P-private-access.sh
#
# Applied in the fixed canonical order P1,P2,P3,P4,P5,P6 regardless of the
# order given on the command line — this is deliberate: P0 states the
# strongest realistic stack is "P6 (WireGuard) + P1 (allowed_clients scoped to
# the tunnel subnet)", and because every mechanism's AdGuardHome.yaml patch is
# a partial, key-level merge (see agh_yaml_patch below), applying P6 AFTER P1
# is what makes that combination converge on the tunnel-scoped allowed_clients
# the source describes, without this script needing separate combo logic.
#
# Single ownership respected (CLAUDE.md hard rule 2): this script never
# creates an nftables table/chain/set, never creates /usr/local/sbin/notify.sh
# or /etc/cron.d/dns-health, never creates /opt/dns-config-backup, and never
# creates /opt/adguardhome/validate. It edits objects Phase B, Phase I and
# Phase K created, in the ways the source markdown itself documents as Phase
# P's job (P2b/P6e edit Phase B's `chain input` DNS accepts; P7b edits Phase
# B's `dns_guard` chain; P7e edits the probe inside Phase I's
# /usr/local/sbin/dns-health; P2c/P4d append to Phase K's restic include/
# exclude lists) — never anything outside what the source assigns to Phase P.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=lib/common.sh
source lib/common.sh

require_root
phase_header "Phase P — private access (WireGuard, AdGuardHome ACLs, ClientIDs, token DoH, mTLS, IP allowlists)"

require_cmd curl jq python3 dig nft sed awk openssl

# =====================================================================
# Phase-wide identifiers, exactly as used throughout phases/09-private-access.md.
# Replace with real values before running against production (same convention
# as Phase D's DOMAIN placeholder).
# =====================================================================
DOMAIN="dns.example.com"
AGH_YAML="/opt/adguardhome/conf/AdGuardHome.yaml"          # Phase E creates; P edits in place
AGH_NETRC="/root/.dns-netrc"                                # Phase E creates; P only reads it
NFTABLES_CONF="/etc/nftables.conf"                          # Phase B owns; P edits documented deltas only
NFT_APPLY="/usr/local/sbin/nft-apply"                        # Phase B's reload wrapper — never raw `nft -f`
DNS_HEALTH_SCRIPT="/usr/local/sbin/dns-health"               # Phase I creates; P edits the probe line (P7e)
RESTIC_INCLUDE="/etc/restic/include.txt"                     # Phase K owns; P only appends
RESTIC_EXCLUDE="/etc/restic/exclude.txt"                     # Phase K owns; P only appends
STAGING_DIR="/opt/dns-config-backup"                         # Phase A3 creates; P only writes into it

# P1/P3/P5 ClientID examples, exactly as the source uses them throughout.
CLIENTS=(alice-iphone bob-laptop)
# P1/P2 office IP examples (P0: "Office with a static IP" row). REPLACE with
# your real ranges before production; kept as literal placeholders on purpose,
# matching this repo's DOMAIN-placeholder convention (see Phase D).
OFFICE_V4=(203.0.113.10 198.51.100.0/28)
OFFICE_V6=(2001:db8:abcd::/48)
# P7e: dedicated ClientID for the Phase I health probe once serve_plain_dns is
# false (P1/P3/P5). Added to allowed_clients alongside CLIENTS in those paths.
HEALTHCHECK_CLIENT="healthcheck"

# P6 WireGuard identifiers — the single peer example the source gives (P6a/b).
WG_IFACE="wg0"
WG_PORT=51820
WG_V4_SUBNET="10.77.0.0/24"
WG_V4_SERVER_IP="10.77.0.1"
WG_V6_SUBNET="fd77:d15:c0de::/64"
WG_V6_SERVER_IP="fd77:d15:c0de::1"
WG_PEER_NAME="alice"
WG_PEER_V4="10.77.0.11/32"
WG_PEER_V6="fd77:d15:c0de::11/128"

# =====================================================================
# Mechanism selection (P0) — argument or env var, exactly the P1..P6 names.
# =====================================================================
usage() {
    cat >&2 <<'USAGE'
Usage: sudo deploy/phases/P-private-access.sh <MECH>[,<MECH>...]
   or: KEYSTONE_P_MECHANISMS=<MECH>[,<MECH>...] sudo deploy/phases/P-private-access.sh

Mechanisms (P0 decision matrix, phases/09-private-access.md):
  P1  AdGuardHome native ACLs           - near-universal component
  P2  nftables IP allowlisting          - static-IP office sites
  P3  ClientIDs for dynamic-IP clients  - BYOD, no VPN client permitted
  P4  nginx token-authenticated DoH     - convenience tier, not a security tier
  P5  mTLS for DoT via nginx stream     - high-assurance / regulated fleet
  P6  WireGuard-fronted DNS             - recommended default, personal/mobile

Strongest realistic stack (P0): P6 + P1 (allowed_clients scoped to the tunnel
subnet). Second: P5 + P1 (ClientID allowlist). Read P0's full decision matrix
in the source file before choosing.
USAGE
}

RAW_MECHS="${1:-${KEYSTONE_P_MECHANISMS:-}}"
if [[ -z "$RAW_MECHS" ]]; then
    usage
    fatal "no mechanism selected — pass one or more of P1..P6"
fi

VALID_MECHS=(P1 P2 P3 P4 P5 P6)
IFS=',' read -r -a REQUESTED_MECHS <<< "$RAW_MECHS"
SELECTED_MECHS=()
for m in "${REQUESTED_MECHS[@]}"; do
    m="${m^^}"
    ok=0
    for v in "${VALID_MECHS[@]}"; do [[ "$m" == "$v" ]] && ok=1; done
    [[ "$ok" -eq 1 ]] || { usage; fatal "unknown mechanism '$m' — valid: ${VALID_MECHS[*]}"; }
    SELECTED_MECHS+=("$m")
done

is_selected() {  # is_selected <MECH>
    local x="$1" s
    for s in "${SELECTED_MECHS[@]}"; do [[ "$s" == "$x" ]] && return 0; done
    return 1
}

info "P0: selected mechanism(s): ${SELECTED_MECHS[*]} — applied in canonical order P1,P2,P3,P4,P5,P6"
info "P0 honesty note: an IP allowlist is not authentication (UDP source addresses are forgeable) — only a handshake (DoT/DoQ/mTLS/WireGuard) proves who a client is."
info "P0 honesty note: every mechanism except P6 leaves a public listener up — it answers REFUSED instead of an answer, a policy improvement, not an attack-surface improvement."

# =====================================================================
# Shared helpers
# =====================================================================

require_cmd python3
python3 -c 'import yaml' >/dev/null 2>&1 || { info "installing python3-yaml (PyYAML) — needed to patch $AGH_YAML in place without clobbering fields other phases wrote"; apt install -y python3-yaml; }
python3 -c 'import yaml' >/dev/null 2>&1 || fatal "python3's 'yaml' module is still unavailable after 'apt install python3-yaml' — required before this script can safely edit $AGH_YAML"

# agh_yaml_patch <label>: reads a YAML mapping from stdin and deep-merges it
# into $AGH_YAML. Dicts merge key-by-key recursively; a list or scalar in the
# patch REPLACES the corresponding key wholesale. This is what lets each
# mechanism below restate only the source markdown's own YAML block for that
# subsection (e.g. P3a patches only http.doh) without clobbering sibling keys
# (http.address, http.session_ttl, ...) that Phase E or an earlier mechanism
# already set — matching the source's own language of each block "replacing
# PART OF" the dns:/http:/tls: section, never the whole file.
agh_yaml_patch() {
    local label="$1" patch
    [[ -f "$AGH_YAML" ]] || fatal "$label: $AGH_YAML does not exist — run Phase E first."
    patch="$(mktemp /tmp/agh-patch.XXXXXX.yaml)"
    cat > "$patch"
    backup_file "$AGH_YAML"
    if ! python3 - "$AGH_YAML" "$patch" <<'PYEOF'
import sys
import yaml

main_path, patch_path = sys.argv[1], sys.argv[2]
with open(main_path) as f:
    main = yaml.safe_load(f) or {}
with open(patch_path) as f:
    patch = yaml.safe_load(f) or {}

def deep_merge(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            deep_merge(dst[k], v)
        else:
            dst[k] = v

deep_merge(main, patch)
with open(main_path, "w") as f:
    yaml.safe_dump(main, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
PYEOF
    then
        rm -f "$patch"
        fatal "$label: failed to patch $AGH_YAML (see error above) — file left as backed up, not modified further"
    fi
    rm -f "$patch"
    info "$label: merged into $AGH_YAML"
}

# exact_replace <file> <label>: stdin is OLD-block, a line containing exactly
# "===REPLACE-WITH===", then NEW-block. Replaces the first (and ONLY)
# verbatim occurrence of OLD in <file>. Refuses to touch the file if OLD does
# not appear exactly once — a config that has already drifted from what this
# script expects must fail loudly, not be silently corrupted. Used for the
# documented Phase-P edits into Phase B's nftables.conf and Phase E's
# doh.conf, where the exact anchor text is known and load-bearing.
exact_replace() {
    local file="$1" label="$2" old_f new_f
    old_f="$(mktemp)"; new_f="$(mktemp)"
    awk -v oldf="$old_f" -v newf="$new_f" '
        BEGIN { mode = 0 }
        /^===REPLACE-WITH===$/ { mode = 1; next }
        { print > (mode == 0 ? oldf : newf) }
    '
    backup_file "$file"
    if ! python3 - "$file" "$old_f" "$new_f" "$label" <<'PYEOF'
import sys
path, old_f, new_f, label = sys.argv[1:5]
with open(path) as f:
    content = f.read()
with open(old_f) as f:
    old = f.read()
with open(new_f) as f:
    new = f.read()
n = content.count(old)
if n != 1:
    sys.stderr.write(
        f"FATAL: {label}: expected exactly 1 occurrence of the anchor block in "
        f"{path}, found {n}. The file has drifted from what this script "
        f"expects (already edited, or Phase B/E's script changed) — stopping "
        f"WITHOUT changes so you can compare and patch by hand.\n"
    )
    sys.exit(1)
content = content.replace(old, new, 1)
with open(path, "w") as f:
    f.write(content)
PYEOF
    then
        rm -f "$old_f" "$new_f"
        fatal "$label: exact_replace failed against $file"
    fi
    rm -f "$old_f" "$new_f"
    info "$label: replaced anchor block in $file"
}

# reload_nftables <label>: syntax-check, confirm, then Phase B's reload
# wrapper — NEVER raw `nft -f`, which would flush live ban state.
reload_nftables() {
    local label="$1"
    nft -c -f "$NFTABLES_CONF" || fatal "$label: nft -c -f $NFTABLES_CONF failed syntax check — not applying"
    [[ -x "$NFT_APPLY" ]] || fatal "$label: $NFT_APPLY not found/executable — run Phase B first"
    confirm "$label: about to reload the live nftables ruleset via $NFT_APPLY (Phase B's wrapper — preserves live ban timeouts). This changes what the firewall accepts on this host. Proceed?"
    "$NFT_APPLY"
}

restic_append() {  # restic_append <include|exclude-file> <path-to-add> <label>
    local list="$1" path_to_add="$2" label="$3"
    if [[ ! -f "$list" ]]; then
        warn "$label: $list does not exist yet (Phase K has not run) — add '$path_to_add' to it by hand once Phase K creates it."
        return 0
    fi
    if grep -qxF "$path_to_add" "$list"; then
        info "$label: $path_to_add already present in $list"
        return 0
    fi
    backup_file "$list"
    confirm "$label: about to append '$path_to_add' to $list (Phase K-owned restic file list). Proceed?"
    echo "$path_to_add" >> "$list"
    info "$label: appended $path_to_add to $list"
}

# =====================================================================
# P1. AdGuardHome native ACLs
# =====================================================================
p1_apply() {
    phase_header "P1: AdGuardHome native ACLs"
    require_cmd runuser ss

    info "P1: Phase E ships allowed_clients empty on purpose and names Phase P as its owner — until this runs, the resolver answers every source address on the internet."
    info "P1: mixing IPs and ClientIDs in allowed_clients is safe — allowlist mode composes IP-check AND ClientID-check, so a plain-DNS client with no ClientID is still allowed on IP match alone."

    confirm "P1: about to overwrite dns.{bind_hosts,serve_plain_dns,allowed_clients,disallowed_clients,blocked_hosts,trusted_proxies} in $AGH_YAML and restart adguardhome (boot service). With serve_plain_dns:false, the 127.0.0.1:53 listener Phase H/I probe DISAPPEARS — apply the P7e health-cron change in this same run (this script does, in p7_deltas). Proceed?"

    # --- P1: dns: block (allowed_clients/disallowed_clients/blocked_hosts/trusted_proxies) ---
    local allowed
    allowed="$(
        for ip in "${OFFICE_V4[@]}" "${OFFICE_V6[@]}"; do printf '    - %s\n' "$ip"; done
        for c in "${CLIENTS[@]}" "$HEALTHCHECK_CLIENT"; do printf '    - %s\n' "$c"; done
    )"
    agh_yaml_patch "P1" <<YAML
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  serve_plain_dns: false
  allowed_clients:
$allowed
  disallowed_clients: []
  # Carried over verbatim from Phase E — CHAOS-class fingerprinting stays closed.
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind
  # Tighten from the 127.0.0.0/8 + ::1/128 defaults — only a proxy on this
  # exact host may rewrite the client IP via headers (see P4b).
  trusted_proxies:
    - 127.0.0.1/32
    - ::1/128
YAML

    systemctl restart adguardhome
    sleep 1
    systemctl is-active --quiet adguardhome || fatal "P1: adguardhome failed to start after the config change — check: journalctl -u adguardhome -n 50"

    # --- P1: hot-apply the same lists without a restart, via the control API ---
    # (POST /control/access/set, v0.107.0+; each list unique, allowed/disallowed
    # must not intersect or validateAccessSet returns 400). Uses Phase E's
    # netrc credential file rather than a literal password on the command line.
    [[ -f "$AGH_NETRC" ]] || warn "P1: $AGH_NETRC not found (Phase E should have created it) — skipping the /control/access/set hot-apply call; the restart above already applied the same values."
    if [[ -f "$AGH_NETRC" ]]; then
        local allowed_json
        allowed_json="$(printf '%s\n' "${OFFICE_V4[@]}" "${OFFICE_V6[@]}" "${CLIENTS[@]}" "$HEALTHCHECK_CLIENT" | jq -R . | jq -s .)"
        curl -s --netrc-file "$AGH_NETRC" -X POST \
          -H 'Content-Type: application/json' \
          --data "{\"allowed_clients\":${allowed_json},\"disallowed_clients\":[],\"blocked_hosts\":[\"version.bind\",\"id.server\",\"hostname.bind\"]}" \
          http://127.0.0.1:3000/control/access/set
    fi

    # --- P1: verify (step 0 is safe/local — run it; the rest need a real
    #     domain/vantage point and are echoed as reference, matching P8) ---
    info "P1 verify (step 0, local and safe):"
    runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
      -c "$AGH_YAML" -w /opt/adguardhome/validate; echo "exit=$? (expect 0)"
    ss -lntup | grep -E ':53\b' && echo 'FAIL: plain DNS still listening' || echo 'OK: no plain :53'
    [[ -f "$AGH_NETRC" ]] && curl -s --netrc-file "$AGH_NETRC" http://127.0.0.1:3000/control/access/list | jq .

    cat <<'VERIFYEOF'
P1 verify (reference — run from a real client against $DOMAIN once DNS/certs are live):
  kdig @dns.example.com +tls google.com A | grep -E '^;; ->>HEADER<<-'      # unauthorised -> REFUSED
  kdig @dns.example.com +tls +tls-hostname=dns.example.com google.com A +short   # authorised -> resolves
  kdig @dns.example.com +tls -c CH -t TXT version.bind | grep -E '^;; ->>HEADER<<-'  # REFUSED, not SERVFAIL
  dig @<PUBLIC_IP> google.com A +time=2 +tries=1; echo "exit=$? (expect 9)"  # UDP-drop, BEFORE flipping serve_plain_dns off
VERIFYEOF
}

# =====================================================================
# P2. nftables IP allowlisting
# =====================================================================
p2_apply() {
    phase_header "P2: nftables IP allowlisting"
    require_cmd install

    info "P2: allowlist4/allowlist6 are Phase B's own dns_guard exemption sets — putting an office range in them both admits it through chain input AND exempts it from the flood meter. That is intended for a private deployment; if you want a client admitted but still metered, use P3 instead."

    # --- P2a: the allowlist sets, repopulated as one atomic nft transaction ---
    install -d -m 0755 /etc/nftables.d
    backup_file /etc/nftables.d/dns-allow.nft
    {
        echo '#!/usr/sbin/nft -f'
        echo ''
        echo '# 1) Ensure the sets exist (idempotent — spec must match Phase B exactly).'
        echo 'table inet filter {'
        echo '  set allowlist4 { type ipv4_addr; flags interval; auto-merge; }'
        echo '  set allowlist6 { type ipv6_addr; flags interval; auto-merge; }'
        echo '}'
        echo ''
        echo '# 2) Empty them.'
        echo 'flush set inet filter allowlist4'
        echo 'flush set inet filter allowlist6'
        echo ''
        echo '# 3) Repopulate. Steps 1-3 commit as ONE kernel transaction.'
        echo 'table inet filter {'
        echo '  set allowlist4 {'
        echo '    type ipv4_addr'
        echo '    flags interval'
        echo '    auto-merge'
        echo '    elements = {'
        echo "      127.0.0.0/8,           # MANDATORY -- dns_guard's exemption (Phase B/J)"
        for ip in "${OFFICE_V4[@]}"; do echo "      $ip,"; done
        echo '    }'
        echo '  }'
        echo ''
        echo '  set allowlist6 {'
        echo '    type ipv6_addr'
        echo '    flags interval'
        echo '    auto-merge'
        echo '    elements = {'
        echo '      ::1/128,               # MANDATORY -- as above'
        for ip in "${OFFICE_V6[@]}"; do echo "      $ip,"; done
        echo '    }'
        echo '  }'
        echo '}'
    } > /etc/nftables.d/dns-allow.nft
    info "P2a: wrote /etc/nftables.d/dns-allow.nft"

    # --- P2b: wire it into Phase B's ruleset (include, then scoped accepts) ---
    if ! grep -qxF 'include "/etc/nftables.d/dns-allow.nft"' "$NFTABLES_CONF"; then
        backup_file "$NFTABLES_CONF"
        confirm "P2b: about to append 'include \"/etc/nftables.d/dns-allow.nft\"' to the END of $NFTABLES_CONF (must come after Phase B's table inet filter block). Proceed?"
        printf '\ninclude "/etc/nftables.d/dns-allow.nft"\n' >> "$NFTABLES_CONF"
    else
        info "P2b: include line already present in $NFTABLES_CONF"
    fi

    confirm "P2b: about to REPLACE Phase B's blanket DNS accepts in chain input (udp/tcp 53, tcp 443, tcp/udp 853) with @allowlist4/@allowlist6-scoped accepts in $NFTABLES_CONF, then reload the live ruleset. Non-allowlisted sources will stop resolving. Proceed?"
    exact_replace "$NFTABLES_CONF" "P2b chain input" <<'EOB'
    udp dport 53  counter accept
    tcp dport 53  counter accept
    tcp dport 443 counter accept   # DoH -- nginx terminates TLS (Phase D)
    tcp dport 853 counter accept   # DoT -- AdGuardHome dnsforward (Phase E)
    udp dport 853 counter accept   # DoQ -- RFC 9250
===REPLACE-WITH===
    # DNS only from allowlisted networks (P2b)
    ip  saddr @allowlist4 udp dport 53  accept
    ip  saddr @allowlist4 tcp dport { 53, 443, 853 } accept
    ip  saddr @allowlist4 udp dport 853 accept
    ip6 saddr @allowlist6 udp dport 53  accept
    ip6 saddr @allowlist6 tcp dport { 53, 443, 853 } accept
    ip6 saddr @allowlist6 udp dport 853 accept
EOB
    info "P2b: tcp dport 80 accept left untouched — Phase B's standing rule, HTTP-01 and Phase Q's well-known files need it unscoped."
    reload_nftables "P2b"

    # --- P2c: edit-without-outage wrapper ---
    backup_file /usr/local/sbin/dns-allow-reload
    cat > /usr/local/sbin/dns-allow-reload << 'EOF'
#!/bin/bash
# Replace ONLY allowlist4 / allowlist6, in a single atomic nft transaction.
# Leaves banned_ips, banned_ips6, floodmeter4, floodmeter6 and every chain
# untouched -- this is deliberately NOT a ruleset reload, so Phase B's
# /usr/local/sbin/nft-apply is not involved and no ban timeout is disturbed.
set -euo pipefail
F=/etc/nftables.d/dns-allow.nft
nft -c -f "$F"     # syntax check, no side effects
nft    -f "$F"     # declare + flush + repopulate, one transaction
logger -t dns-allow "allowlist reloaded: $(nft -j list set inet filter allowlist4 | wc -c) bytes v4"
EOF
    chmod 0700 /usr/local/sbin/dns-allow-reload
    info "P2c: wrote /usr/local/sbin/dns-allow-reload"

    restic_append "$RESTIC_INCLUDE" "/etc/nftables.d" "P2c"

    # --- P2 verify (safe/local run now; rest echoed for a second vantage point) ---
    nft -c -f /etc/nftables.d/dns-allow.nft && echo 'allowlist syntax OK'
    nft -c -f "$NFTABLES_CONF" && echo 'full ruleset syntax OK'
    nft list set inet filter allowlist4 | grep -q '127.0.0.0/8' \
      && echo 'PASS: loopback exempt' || echo 'FAIL: dns_guard can now ban 127.0.0.1'
    cat <<'VERIFYEOF'
P2 verify (reference — run from an allowlisted AND a non-allowlisted host):
  nft add element inet filter banned_ips { 192.0.2.66 timeout 10m }
  /usr/local/sbin/dns-allow-reload
  nft list set inet filter banned_ips | grep 192.0.2.66 && echo 'PASS: bans preserved' || echo 'FAIL: bans wiped'
  dig @<PUBLIC_IP> google.com A +time=2 +tries=1   # non-allowlisted host: expect exit 9
  dig @<PUBLIC_IP> google.com A +short             # allowlisted host: resolves
VERIFYEOF
}

# =====================================================================
# P3. ClientIDs for dynamic-IP clients
# =====================================================================
p3_apply() {
    phase_header "P3: ClientIDs for dynamic-IP clients"

    is_selected P1 || warn "P3: P1 was not selected in this run — P3a only restricts the DoH routes to the ClientID form; the ClientIDs still need to be IN dns.allowed_clients (P1) or this mechanism admits nobody. Apply P1 too, or confirm allowed_clients already lists ${CLIENTS[*]} from a previous run."

    confirm "P3a: about to restrict AdGuardHome's DoH routes to the ClientID form (http.doh.routes) in $AGH_YAML — the anonymous /dns-query endpoint stops existing — and widen Phase E's nginx location so the ClientID suffix survives the proxy hop. Proceed?"

    # --- P3a: enable ClientID routes, delete the anonymous one ---
    agh_yaml_patch "P3a" <<'YAML'
http:
  doh:
    insecure_enabled: false
    routes:
      - 'GET /dns-query/{ClientID}'
      - 'POST /dns-query/{ClientID}'
YAML

    # Widen Phase E's `location = /dns-query` in doh.conf so the ClientID
    # suffix reaches AdGuardHome. REPLACES that block in Phase E's own file —
    # does not add a second server block for the same name.
    exact_replace /etc/nginx/conf.d/doh.conf "P3a nginx location" <<'EOB'
    location = /dns-query {
        proxy_pass https://agh_doh/dns-query$is_args$args;
        proxy_ssl_server_name on;            # off by default: no SNI is sent without this
        proxy_ssl_name dns.example.com;      # must match tls.server_name, not the IP
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_ssl_verify_depth 3;
        proxy_ssl_session_reuse on;
        include /etc/nginx/snippets/agh-client-identity.conf;
        proxy_read_timeout 10s;
        proxy_connect_timeout 2s;
    }
===REPLACE-WITH===
    location ~ "^/dns-query(/[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9])?$" {
        proxy_pass https://agh_doh$request_uri;
        proxy_ssl_name        dns.example.com;
        proxy_ssl_server_name on;
        proxy_ssl_verify      on;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_ssl_verify_depth 3;
        proxy_ssl_session_reuse on;
        include /etc/nginx/snippets/agh-client-identity.conf;   # see P4b — mandatory
        proxy_read_timeout    10s;
        proxy_connect_timeout 2s;
    }
EOB
    nginx -t
    confirm "P3a: about to reload nginx to serve the widened /dns-query{/ClientID} location. Proceed?"
    systemctl reload nginx

    info "P3b: ClientID naming rule (netutil.ValidateHostnameLabel) — ASCII letters/digits/hyphens, must start/end alphanumeric, max 63 chars, case-insensitive, no dots. Names in \$CLIENTS already conform: ${CLIENTS[*]}."

    # --- P3c: MANUAL — wildcard cert (DNS-01, Phase D) + wildcard DNS record ---
    warn "P3c MANUAL STEP: the SNI form (alice-iphone.$DOMAIN — required for Android 9+ Private DNS and DoQ) needs (1) a wildcard cert via Phase D's DNS-01 issuance with '-d $DOMAIN -d *.$DOMAIN' — that is Phase D's script, not scripted here, rerun it with those -d args — and (2) a wildcard A/AAAA DNS record at your registrar/DNS provider ('*.$DOMAIN. 300 IN A <PUBLIC_IP>'), a business/access decision this script cannot make. Skip both entirely if every client uses the DoH URL-path form (P3a) only."
    info "P3c: verify the wildcard record BEFORE running certbot: dig +short alice-iphone.$DOMAIN A @1.1.1.1"

    # --- P3d: AdGuardHome tls: block ---
    confirm "P3d: about to set tls.strict_sni_check:false and tls.server_name in $AGH_YAML and restart adguardhome (boot service). Proceed?"
    agh_yaml_patch "P3d" <<YAML
tls:
  enabled: true
  server_name: $DOMAIN
  force_https: false
  port_https: 8053
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  port_dnscrypt: 0
  certificate_chain: /opt/adguardhome/conf/ssl/fullchain.pem
  private_key: /opt/adguardhome/conf/ssl/privkey.pem
  strict_sni_check: false
YAML
    systemctl restart adguardhome
    sleep 1
    systemctl is-active --quiet adguardhome || fatal "P3d: adguardhome failed to start — check: journalctl -u adguardhome -n 50"

    info "P3e: exact client strings, server_name=$DOMAIN — DoH URL-path (no wildcard needed): https://$DOMAIN/dns-query/<ClientID> ; Android Private DNS / DoT / DoQ SNI form (wildcard needed): <ClientID>.$DOMAIN"

    # --- P3f: Apple mobileconfig — generate locally, MANUAL distribution ---
    for c in "${CLIENTS[@]}"; do
        curl -s "http://127.0.0.1:3000/apple/doh.mobileconfig?host=$DOMAIN&client_id=$c" -o "/root/$c-doh.mobileconfig"
        curl -s "http://127.0.0.1:3000/apple/dot.mobileconfig?host=$DOMAIN&client_id=$c" -o "/root/$c-dot.mobileconfig"
        info "P3f: generated /root/$c-doh.mobileconfig and /root/$c-dot.mobileconfig"
    done
    warn "P3f MANUAL STEP: /apple/*.mobileconfig is loopback-only by design and is NOT published through nginx (shares the admin mux, exempt from auth). Hand the generated .mobileconfig files to each device by AirDrop or signed email — never publish them, never render the download link publicly."

    cat <<VERIFYEOF
P3 verify (reference — a real domain/device is required for most of these):
  openssl x509 -noout -text -in /etc/letsencrypt/live/$DOMAIN/cert.pem | grep -A1 'Subject Alternative Name'  # only if wildcard issued
  kdig @$DOMAIN +tls  +tls-hostname=alice-iphone.$DOMAIN example.com A     # SNI form, wildcard only
  kdig @$DOMAIN +https=/dns-query/alice-iphone example.com A              # URL-path form, always
  kdig @$DOMAIN +https=/dns-query              example.com A   # expect HTTP 404 -- anonymous route gone
  kdig @$DOMAIN +tls +tls-hostname=mallory.$DOMAIN example.com A | grep -E '^;; ->>HEADER<<-'  # unknown ID -> REFUSED
VERIFYEOF
}

# =====================================================================
# P4. nginx token-authenticated DoH
# =====================================================================
p4_apply() {
    phase_header "P4: nginx token-authenticated DoH"
    warn "P4e: a bearer token in a URL path is a convenience tier, not a security tier — it persists in client prefs/registry/profiles and in any intermediary's logs. Prefer P5 or P6 for anything sensitive."

    confirm "P4a: about to set dns.bind_hosts:[127.0.0.1], serve_plain_dns:true (loopback-only), allowed_clients:[${CLIENTS[*]}] and the DoH-only tls: block in $AGH_YAML, then restart adguardhome (boot service). Proceed?"

    # --- P4a: AdGuardHome side (DoH-only topology, ClientID-gated) ---
    local allowed
    allowed="$(for c in "${CLIENTS[@]}"; do printf '    - %s\n' "$c"; done)"
    agh_yaml_patch "P4a" <<YAML
http:
  address: 127.0.0.1:3000
  doh:
    insecure_enabled: false
    routes:
      - 'GET /dns-query/{ClientID}'
      - 'POST /dns-query/{ClientID}'
dns:
  bind_hosts: [127.0.0.1]
  serve_plain_dns: true
  allowed_clients:
$allowed
  trusted_proxies:
    - 127.0.0.1/32
    - ::1/128
  anonymize_client_ip: false
tls:
  enabled: true
  server_name: $DOMAIN
  port_https: 8053
  port_dns_over_tls: 0
  port_dns_over_quic: 0
  certificate_chain: /opt/adguardhome/conf/ssl/fullchain.pem
  private_key: /opt/adguardhome/conf/ssl/privkey.pem
YAML
    systemctl restart adguardhome
    sleep 1
    systemctl is-active --quiet adguardhome || fatal "P4a: adguardhome failed to start — check: journalctl -u adguardhome -n 50"

    # --- P4b: the client-identity header snippet — Phase E already writes this
    #     file. Do NOT recreate or fork it; every P4 location simply includes it. ---
    if [[ -f /etc/nginx/snippets/agh-client-identity.conf ]]; then
        info "P4b: /etc/nginx/snippets/agh-client-identity.conf already exists (Phase E) — reusing as-is, not rewriting."
    else
        fatal "P4b: /etc/nginx/snippets/agh-client-identity.conf missing — run Phase E first (it is the sole owner of this file)."
    fi

    # --- P4c: token map (real random tokens, generated exactly as documented) ---
    gen_doh_token() { head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '='; }
    backup_file /etc/nginx/doh-tokens.map
    {
        echo 'map $doh_token $doh_clientid {'
        echo '    default                             "";'
        for c in "${CLIENTS[@]}"; do
            printf '    "%s"  "%s";\n' "$(gen_doh_token)" "$c"
        done
        echo '}'
    } > /etc/nginx/doh-tokens.map
    chmod 0600 /etc/nginx/doh-tokens.map
    chown root:root /etc/nginx/doh-tokens.map
    warn "P4c MANUAL STEP: tokens were just generated into /etc/nginx/doh-tokens.map (mode 0600). Distribute each one to its device OUT OF BAND now — this is the only time this script prints them:"
    cat /etc/nginx/doh-tokens.map

    # --- P4d: nginx — http-level file + location inside Phase E's server block ---
    backup_file /etc/nginx/conf.d/doh-gateway.conf
    cat > /etc/nginx/conf.d/doh-gateway.conf << 'EOF'
include /etc/nginx/doh-tokens.map;
limit_req_zone $doh_token zone=dohtok:10m rate=30r/s;

log_format doh_safe '$remote_addr $ssl_protocol $status $doh_clientid $request_time';
EOF

    confirm "P4d: about to insert an access_log line and a /t/<token>/dns-query location into Phase E's $DOMAIN server block in /etc/nginx/conf.d/doh.conf, then reload nginx. Proceed?"
    exact_replace /etc/nginx/conf.d/doh.conf "P4d nginx location" <<'EOB'
    # /control/*, /login.html, /install.html, /apple/*.mobileconfig -- none of
    # it may be reachable. This is the rule that makes fact (2) above harmless.
    location / { return 404; }
}
===REPLACE-WITH===
    # Phase E sets `access_log off` for this whole server. Turning logging back
    # on for THIS location only is a deliberate trade: it is what lets you tie
    # an abusive request to a token. NEVER the default 'combined' format.
    access_log /var/log/nginx/doh.log doh_safe;

    location ~ "^/t/(?<doh_token>[A-Za-z0-9_-]{32})/dns-query$" {
        if ($doh_clientid = "") { return 404; }
        limit_req zone=dohtok burst=60 nodelay;
        limit_req_status 429;

        # $is_args$args is MANDATORY -- proxy_pass with a variable AND a URI
        # replaces the request URI wholesale otherwise, dropping ?dns=<base64>.
        proxy_pass https://agh_doh/dns-query/$doh_clientid$is_args$args;
        proxy_ssl_name        dns.example.com;
        proxy_ssl_server_name on;
        proxy_ssl_verify      on;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_ssl_verify_depth 3;
        include /etc/nginx/snippets/agh-client-identity.conf; # P4b — mandatory
    }

    # /control/*, /login.html, /install.html, /apple/*.mobileconfig -- none of
    # it may be reachable. This is the rule that makes fact (2) above harmless.
    location / { return 404; }
}
EOB
    nginx -t
    systemctl reload nginx
    info "P4d: client URL is https://$DOMAIN/t/<token>/dns-query. Rotate tokens on a 90-day cadence (add new line, reload, migrate device, delete old line, reload) and immediately on device loss."

    restic_append "$RESTIC_EXCLUDE" "/etc/nginx/doh-tokens.map" "P4d"
    restic_append "$RESTIC_EXCLUDE" "/etc/dns-mtls" "P4d"
    # STAGING_DIR (/opt/dns-config-backup) is Phase A3-owned -- P only writes
    # into it, never creates it (CLAUDE.md single-ownership table).
    if [[ -d "$STAGING_DIR" ]]; then
        sed -E 's/"[A-Za-z0-9_-]{32}"/"<REDACTED>"/' /etc/nginx/doh-tokens.map > "$STAGING_DIR/doh-tokens.map.redacted"
        chmod 0600 "$STAGING_DIR/doh-tokens.map.redacted"
        info "P4d: staged a redacted copy at $STAGING_DIR/doh-tokens.map.redacted so a restore still shows which ClientIDs existed, without the live tokens."
    else
        warn "P4d: $STAGING_DIR does not exist (Phase A3 has not run) — stage a redacted token map there by hand once it does: sed -E 's/\"[A-Za-z0-9_-]{32}\"/\"<REDACTED>\"/' /etc/nginx/doh-tokens.map > $STAGING_DIR/doh-tokens.map.redacted"
    fi

    cat <<'VERIFYEOF'
P4 verify (reference — needs a real token from the map above):
  nginx -t
  curl -si -H 'accept: application/dns-message' "https://$DOMAIN/t/<TOKEN>/dns-query?dns=<b64url-query>" | head -3   # expect 200
  curl -s -o /dev/null -w '%{http_code}\n' "https://$DOMAIN/t/00000000000000000000000000000000/dns-query"   # wrong token -> 404
  for p in /control/status /login.html /install.html /apple/doh.mobileconfig /dns-query; do
    printf '%s -> ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' "https://$DOMAIN$p"; done   # every one -> 404
  sudo grep -rl "<TOKEN>" /var/log/nginx/ /var/log/adguardhome/ ; echo "grep exit=$? (expect 1)"
VERIFYEOF
    nginx -t
}

# =====================================================================
# P5. mTLS for DoT via an nginx stream front
# =====================================================================
p5_apply() {
    phase_header "P5: mTLS for DoT via an nginx stream front"
    info "P5: AdGuardHome has no client-certificate support at all — nginx's stream module does the mTLS handshake and re-originates TLS to AdGuardHome with the ClientID as SNI, so identity survives the proxy hop without needing a wildcard cert or record."

    # --- P5a: private client CA and per-device certificates ---
    install -d -m 0700 /etc/dns-mtls
    (
        cd /etc/dns-mtls
        umask 077
        if [[ ! -f ca.key ]]; then
            openssl ecparam -name prime256v1 -genkey -noout -out ca.key
            openssl req -x509 -new -sha256 -days 3650 -key ca.key \
              -subj "/CN=$DOMAIN Client CA" -out ca.crt
        else
            info "P5a: /etc/dns-mtls/ca.key already exists — reusing existing client CA, not regenerating (regenerating would invalidate every issued client cert)."
        fi
        issue() {  # issue <clientid>
            [[ -f "$1.crt" ]] && { info "P5a: $1.crt already issued — skipping."; return 0; }
            openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"
            openssl req -new -sha256 -key "$1.key" -subj "/CN=$1" -out "$1.csr"
            openssl x509 -req -sha256 -in "$1.csr" -CA ca.crt -CAkey ca.key \
              -CAcreateserial -days 365 -out "$1.crt"
            openssl pkcs12 -export -inkey "$1.key" -in "$1.crt" -certfile ca.crt -out "$1.p12"
            rm -f "$1.csr"
        }
        for c in "${CLIENTS[@]}"; do issue "$c"; done
    )
    warn "P5a MANUAL STEP: /etc/dns-mtls is NOT in Phase K's restic include list (P4d excludes it deliberately) — it holds secrets. Ship each <id>.p12 + ca.crt to its device (iOS/macOS profile, Android cert install, PEM pair for stubby/Unbound), then delete that <id>.p12 from the server. Put ca.key somewhere deliberate — a password manager or an encrypted archive you own — losing it means reissuing every client certificate. This is a business/custody decision this script cannot make."

    confirm "P5b: about to set dns.bind_hosts:[127.0.0.1], serve_plain_dns:false, allowed_clients:[${CLIENTS[*]}], and tls.port_dns_over_tls:8853 (loopback) in $AGH_YAML, then restart adguardhome (boot service) — this moves DoT off the public interface entirely; nginx stream takes over public :853. Proceed?"

    # --- P5b: AdGuardHome listens on loopback only ---
    local allowed
    allowed="$(for c in "${CLIENTS[@]}"; do printf '    - %s\n' "$c"; done)"
    agh_yaml_patch "P5b" <<YAML
dns:
  bind_hosts: [127.0.0.1]
  serve_plain_dns: false
  allowed_clients:
$allowed
  trusted_proxies:
    - 127.0.0.1/32
    - ::1/128
  anonymize_client_ip: false
tls:
  enabled: true
  server_name: $DOMAIN
  port_https: 0
  port_dns_over_tls: 8853
  port_dns_over_quic: 0
  certificate_chain: /opt/adguardhome/conf/ssl/fullchain.pem
  private_key: /opt/adguardhome/conf/ssl/privkey.pem
  strict_sni_check: false
YAML
    systemctl restart adguardhome
    sleep 1
    systemctl is-active --quiet adguardhome || fatal "P5b: adguardhome failed to start — check: journalctl -u adguardhome -n 50"

    # --- P5c: nginx stream — verify client cert, re-originate TLS with the
    #     ClientID as SNI. Top-level block, sibling of http{}, appended once. ---
    if grep -q '^stream {' /etc/nginx/nginx.conf 2>/dev/null; then
        warn "P5c: a 'stream {' block already exists in /etc/nginx/nginx.conf — not appending a second one. Merge by hand: see phases/09-private-access.md P5c for the exact map + server block."
    else
        backup_file /etc/nginx/nginx.conf
        confirm "P5c: about to append a top-level stream{} block to /etc/nginx/nginx.conf (listens 853 ssl, ssl_verify_client on, proxies to 127.0.0.1:8853) and reload nginx. Proceed?"
        {
            echo ''
            echo 'stream {'
            echo '    # RFC 2253 subject DN -> the SNI the backend should see.'
            echo '    # The default maps to a sentinel NEVER in allowed_clients, so a'
            echo '    # revoked-but-CA-valid certificate is denied deterministically.'
            echo "    map \$ssl_client_s_dn \$dot_backend_sni {"
            echo "        default            \"revoked.$DOMAIN\";"
            for c in "${CLIENTS[@]}"; do
                printf '        "CN=%s"  "%s.%s";\n' "$c" "$c" "$DOMAIN"
            done
            echo '    }'
            echo ''
            echo '    server {'
            echo '        listen      853 ssl;'
            echo '        listen [::]:853 ssl;'
            echo ''
            echo "        ssl_certificate         /etc/letsencrypt/live/$DOMAIN/fullchain.pem;"
            echo "        ssl_certificate_key     /etc/letsencrypt/live/$DOMAIN/privkey.pem;"
            echo '        ssl_protocols           TLSv1.2 TLSv1.3;'
            echo '        ssl_session_cache       shared:dot:10m;'
            echo ''
            echo '        ssl_verify_client       on;                     # stream: nginx >= 1.11.8'
            echo '        ssl_client_certificate  /etc/dns-mtls/ca.crt;'
            echo '        ssl_verify_depth        1;                      # already the default'
            echo ''
            echo '        proxy_pass              127.0.0.1:8853;'
            echo '        proxy_ssl               on;'
            echo '        proxy_ssl_name          $dot_backend_sni;       # variables: nginx >= 1.11.3'
            echo '        proxy_ssl_server_name   on;'
            echo '        proxy_ssl_verify        off;                    # loopback leg, see P5c'
            echo '        proxy_timeout           120s;'
            echo '    }'
            echo '}'
        } >> /etc/nginx/nginx.conf
        nginx -t
        systemctl reload nginx
    fi

    # --- P5c: firewall delta, stated directly in P5c (also covered by P7b) ---
    confirm "P5c: about to REPLACE Phase B's blanket DNS accepts in chain input with the DoT-only set (keep tcp 853, drop udp 853 and tcp 443 — no DoQ path, port_https:0) and reload the ruleset. Proceed?"
    exact_replace "$NFTABLES_CONF" "P5 firewall delta" <<'EOB'
    udp dport 53  counter accept
    tcp dport 53  counter accept
    tcp dport 443 counter accept   # DoH -- nginx terminates TLS (Phase D)
    tcp dport 853 counter accept   # DoT -- AdGuardHome dnsforward (Phase E)
    udp dport 853 counter accept   # DoQ -- RFC 9250
===REPLACE-WITH===
    # P5: mTLS DoT only -- no DoQ (stream cannot terminate QUIC), no port_https
    udp dport 53  counter accept
    tcp dport 53  counter accept
    tcp dport 853 counter accept   # DoT -- nginx stream mTLS front (P5c)
EOB
    reload_nftables "P5"

    info "P5d: DoT only — stream cannot terminate DoQ or mTLS for HTTP/3. Android Private DNS cannot present a client certificate at all; confirm your fleet before committing. nginx build needs --with-stream_ssl_module (nginx-full on Ubuntu 24.04 has it)."
    info "P5: revocation — delete the CN line from the stream map's \$ssl_client_s_dn -> \$dot_backend_sni block and 'systemctl reload nginx'. Instant, no CRL/OCSP. For belt and braces also remove the ClientID from dns.allowed_clients."

    nginx -V 2>&1 | tr ' ' '\n' | grep -E 'stream' && echo 'stream module present' || warn "P5d: nginx build lacks --with-stream / --with-stream_ssl_module"
    nginx -t
    ss -lntup | grep -E ':8853|:853'

    cat <<VERIFYEOF
P5 verify (reference — needs an issued client cert from P5a):
  openssl s_client -connect $DOMAIN:853 -servername $DOMAIN </dev/null 2>&1 | grep -E 'alert|Verify return|handshake failure'
  kdig @$DOMAIN +tls example.com A; echo "exit=\$? (expect non-zero, no client cert)"
  kdig @$DOMAIN +tls +tls-hostname=$DOMAIN +tls-certfile=/etc/dns-mtls/${CLIENTS[0]}.crt +tls-keyfile=/etc/dns-mtls/${CLIENTS[0]}.key example.com A
VERIFYEOF
}

# =====================================================================
# P6. WireGuard-fronted DNS
# =====================================================================
p6_apply() {
    phase_header "P6: WireGuard-fronted DNS (recommended default for personal/mobile use)"
    info "P6: no public listener at all. Deletes work: no certificate, no wildcard, no DNS-01, Phase D becomes unnecessary in full."

    # --- P6a: server key material and interface ---
    apt install -y wireguard qrencode
    install -d -m 0700 /etc/wireguard /etc/wireguard/clients
    if [[ ! -f /etc/wireguard/server.key ]]; then
        ( umask 077
          wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub )
    else
        info "P6a: /etc/wireguard/server.key already exists — reusing, not regenerating (would break every enrolled peer)."
    fi
    if [[ ! -f "/etc/wireguard/clients/$WG_PEER_NAME.key" ]]; then
        ( umask 077
          wg genkey | tee "/etc/wireguard/clients/$WG_PEER_NAME.key" | wg pubkey > "/etc/wireguard/clients/$WG_PEER_NAME.pub"
          wg genpsk > "/etc/wireguard/clients/$WG_PEER_NAME.psk" )
    else
        info "P6a: /etc/wireguard/clients/$WG_PEER_NAME.key already exists — reusing."
    fi

    local server_priv server_pub peer_pub peer_psk
    server_priv="$(cat /etc/wireguard/server.key)"
    peer_pub="$(cat "/etc/wireguard/clients/$WG_PEER_NAME.pub")"
    peer_psk="$(cat "/etc/wireguard/clients/$WG_PEER_NAME.psk")"

    backup_file /etc/wireguard/wg0.conf
    ( umask 077
      cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address    = $WG_V4_SERVER_IP/24, $WG_V6_SERVER_IP/64
ListenPort = $WG_PORT
PrivateKey = $server_priv
# Deliberately no PostUp NAT and no ip_forward: this tunnel carries DNS only.
# Nothing is forwarded, so Phase B's chain forward policy drop stays untouched.

[Peer]
# $WG_PEER_NAME
PublicKey    = $peer_pub
PresharedKey = $peer_psk
AllowedIPs   = $WG_PEER_V4, $WG_PEER_V6
EOF
    )
    chmod 0600 /etc/wireguard/wg0.conf

    confirm "P6a: about to run 'systemctl enable --now wg-quick@wg0' — starts a new boot service (WireGuard tunnel). Proceed?"
    systemctl enable --now wg-quick@wg0

    # --- P6b: client config and QR flow ---
    server_pub="$(cat /etc/wireguard/server.pub)"
    local peer_priv
    peer_priv="$(cat "/etc/wireguard/clients/$WG_PEER_NAME.key")"
    backup_file "/etc/wireguard/clients/$WG_PEER_NAME.conf"
    ( umask 077
      cat > "/etc/wireguard/clients/$WG_PEER_NAME.conf" << EOF
[Interface]
Address    = $WG_PEER_V4, $WG_PEER_V6
PrivateKey = $peer_priv
DNS        = $WG_V4_SERVER_IP, $WG_V6_SERVER_IP
MTU        = 1280

[Peer]
PublicKey           = $server_pub
PresharedKey        = $peer_psk
Endpoint            = $DOMAIN:$WG_PORT
AllowedIPs          = $WG_V4_SUBNET, $WG_V6_SUBNET
PersistentKeepalive = 25
EOF
    )
    info "P6b: MTU = 1280 is not optional — wg-quick's default 1420 assumes a 1500-byte outer path; PPPoE/LTE/5G/hotel CPE commonly do not have it, and the failure (large answers silently hang while small ones work) is very hard to diagnose. See Phase R9 in phases/12-client-setup.md for the client-side hand-out — keep the two in sync."
    warn "P6b MANUAL STEP: scan the QR code below into the WireGuard app on the device, or transfer /etc/wireguard/clients/$WG_PEER_NAME.conf out of band. Never render the QR into a screenshot that leaves this machine — it is the private key. Once the device has its config, delete /etc/wireguard/clients/$WG_PEER_NAME.key from the server (P6b key-management note) and keep only the .pub and .psk."
    qrencode -t ansiutf8 < "/etc/wireguard/clients/$WG_PEER_NAME.conf"

    confirm "P6c: about to move AdGuardHome's dns.bind_hosts to [$WG_V4_SERVER_IP, $WG_V6_SERVER_IP] only in $AGH_YAML (moves the WHOLE service off the public interface — plain, DoT, DoH, DoQ, DNSCrypt all derive from bind_hosts). The restart that picks this up is a separate confirm below, after the P6d boot-ordering drop-in is in place. Proceed?"

    # --- P6c: AdGuardHome binds only to the tunnel ---
    agh_yaml_patch "P6c" <<YAML
dns:
  bind_hosts:
    - $WG_V4_SERVER_IP
    - $WG_V6_SERVER_IP
  port: 53
  serve_plain_dns: true
  allowed_clients:
    - $WG_V4_SUBNET
    - $WG_V6_SUBNET
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind
YAML

    # --- P6d: boot ordering drop-in (AdGuardHome exits if the tunnel address
    #     does not exist yet when it starts) ---
    install -d /etc/systemd/system/adguardhome.service.d
    cat > /etc/systemd/system/adguardhome.service.d/10-wireguard.conf <<'EOF'
[Unit]
After=wg-quick@wg0.service
Requires=wg-quick@wg0.service
EOF
    systemctl daemon-reload

    confirm "P6d: about to restart adguardhome now that it Requires=wg-quick@wg0.service and binds only $WG_V4_SERVER_IP/$WG_V6_SERVER_IP — public :53/:853/:443 stop answering after this. Proceed?"
    systemctl restart adguardhome
    sleep 1
    systemctl is-active --quiet adguardhome || fatal "P6d: adguardhome failed to start — check: journalctl -u adguardhome -n 50 (often the tunnel address not being up yet — verify 'wg show $WG_IFACE' first)"

    info "P6d: do NOT reach for net.ipv4.ip_nonlocal_bind=1 to work around a bind failure — it hides the real fault and can silently blackhole queries."

    # --- P6e: nftables delta ---
    confirm "P6e: about to REPLACE Phase B's blanket DNS accepts in chain input with WireGuard-only accepts (udp 51820 public; DNS only via iifname wg0) and reload the ruleset. Proceed?"
    exact_replace "$NFTABLES_CONF" "P6e chain input" <<EOB
    udp dport 53  counter accept
    tcp dport 53  counter accept
    tcp dport 443 counter accept   # DoH -- nginx terminates TLS (Phase D)
    tcp dport 853 counter accept   # DoT -- AdGuardHome dnsforward (Phase E)
    udp dport 853 counter accept   # DoQ -- RFC 9250
===REPLACE-WITH===
    # WireGuard handshake and data -- the ONLY new public port (P6e)
    udp dport $WG_PORT accept

    # DNS is reachable only from inside the tunnel. Explicit accepts required:
    # Phase B NOTRACKs UDP/53 in table inet raw, so ct state established,related
    # accept does not cover it.
    iifname "$WG_IFACE" udp dport 53 accept
    iifname "$WG_IFACE" tcp dport 53 accept
EOB
    info "P6e: tcp dport 80 accept left untouched — nginx still serves Phase Q's /.well-known/ files there even though certbot is gone."
    reload_nftables "P6e"

    info "P6f: unspoofable (a WireGuard session is not a forgeable claim), effectively zero attack surface (silent to unauthenticated packets, no TLS/DoQ stack exposed), roaming for free once the network lets the tunnel come up, and real revocation: 'wg set $WG_IFACE peer <PUBKEY> remove'."
    warn "P6f: on a captive portal / hostile network, UDP/$WG_PORT is often blocked and the tunnel cannot come up at all until the user logs in through the portal — P6 is then the WORST transport, not the best. See phases/12-client-setup.md R10."

    wg show "$WG_IFACE" || true
    systemctl is-active wg-quick@wg0 adguardhome
    ss -lntup | grep -E 'AdGuardHome' || true

    cat <<VERIFYEOF
P6 verify (reference — run the negative/positive tests from OFF this box):
  dig @<PUBLIC_IP> google.com A +time=2 +tries=1; echo "exit=\$? (expect 9)"
  nmap -sU -p 53,853,$WG_PORT -Pn <PUBLIC_IP>
  nmap -sT -p 53,443,853   -Pn <PUBLIC_IP>
  dig @$WG_V4_SERVER_IP google.com A +short           # from a connected peer
  wg set $WG_IFACE peer <ALICE_PUBKEY> remove          # revocation
  dig @$WG_V4_SERVER_IP +dnssec +bufsize=4096 . DNSKEY +noall +stats | grep 'MSG SIZE'   # MTU=1280 large-answer probe
  dig @$WG_V4_SERVER_IP +tcp +dnssec        . DNSKEY +noall +stats | grep 'MSG SIZE'
VERIFYEOF
}

# =====================================================================
# P7. Deltas private mode forces on the rest of the plan
# =====================================================================
p7_deltas() {
    phase_header "P7: deltas private mode forces on the rest of the plan"

    # --- P7a: Phase F is already gone in this plan; clean up a v1 remnant if present ---
    if [[ -d /opt/dns-warmer ]]; then
        confirm "P7a: found /opt/dns-warmer (retired v1 cache warmer, superseded by Unbound's prefetch/prefetch-key — Phase C). About to remove it and any dns-warmer unit. Proceed?"
        systemctl disable --now dns-warmer.service 2>/dev/null || true
        rm -rf /opt/dns-warmer
        rm -f /etc/systemd/system/dns-warmer.service
        systemctl daemon-reload
        info "P7a: removed /opt/dns-warmer and its unit."
    else
        info "P7a: /opt/dns-warmer absent — nothing to clean up (Phase F never existed in this plan)."
    fi

    # --- P7b: dns_guard tunnel exemption — the UDP/53 flood meter does NOT
    #     become a no-op under P6; a peer's own local load test can ban its
    #     tunnel address unless exempted. Only relevant when P6 is selected. ---
    if is_selected P6; then
        confirm "P7b: about to insert 'iifname \"$WG_IFACE\" accept' into Phase B's dns_guard chain, immediately after its 'iif lo accept' rule, and reload the ruleset — without this, a peer running a heavy local test can get its own tunnel address banned by dns_guard. Proceed?"
        exact_replace "$NFTABLES_CONF" "P7b dns_guard wg0 exemption" <<EOB
    iif lo accept

    # Operator allowlist. A member bypasses flood detection AND banning
===REPLACE-WITH===
    iif lo accept

    # P7b: WireGuard tunnel is neither loopback nor in allowlist4/6 by
    # default -- exempt it here or a peer's own load test can ban itself.
    iifname "$WG_IFACE" accept

    # Operator allowlist. A member bypasses flood detection AND banning
EOB
        reload_nftables "P7b"
        info "P7e (Phase J note): under P6 every client is 10.77.0.x, so floodmeter4/banned_ips would ban a tunnel address, not a person — Phase J's abuse machinery is now neutralised by design (see P7e below), not just this exemption."
    fi

    # --- P7c: rate-limit gap. ratelimit/ratelimit_subnet_len_* keys ONLY
    #     protect plain UDP (dnsproxy ratelimit.go) — with serve_plain_dns:
    #     false they protect nothing and remain documentation of intent only.
    #     Real per-transport limiting: P4 has its own (limit_req_zone $doh_token,
    #     already applied in p4_apply); P6 needs none (peers are authenticated
    #     and few); DoT/DoQ direct (P1/P3/P5) needs a kernel rule. ---
    info "P7c: dns.ratelimit / ratelimit_subnet_len_ipv4(32) / ratelimit_subnet_len_ipv6(64) / ratelimit_whitelist(127.0.0.1,::1) — leave exactly as Phase E ships them; do not restore the /24 and /56 defaults, they black-hole CGNAT clients."
    if is_selected P3 || is_selected P5; then
        confirm "P7c: about to add a kernel-side per-source rate limit for DoT/DoQ (tcp dport 853 ct state new meter dot_conn { ip saddr limit rate over 20/second } drop) to Phase B's dns_guard chain, and reload the ruleset. This is the only real rate limit for direct DoT/DoQ traffic (P1/P3/P5 have no other one). Proceed?"
        exact_replace "$NFTABLES_CONF" "P7c dot rate limit" <<'EOB'
    udp dport 53 limit rate over 5000/second burst 10000 packets counter drop
  }
===REPLACE-WITH===
    udp dport 53 limit rate over 5000/second burst 10000 packets counter drop

    # P7c: per-source rate limit for direct DoT/DoQ. TCP/853 is still
    # conntrack-tracked (only UDP is NOTRACK'd in table inet raw), so ct state
    # new is valid here.
    tcp dport 853 ct state new meter dot_conn { ip saddr limit rate over 20/second } drop
  }
EOB
        reload_nftables "P7c"
    fi

    # --- P7d: serve_plain_dns:false removes the :53 listeners entirely (info) ---
    info "P7d: serve_plain_dns:false is not a filter or ACL — AdGuardHome creates NO :53 listener at all, on any address, and refuses to start unless at least one encrypted protocol is configured. Anything talking to 127.0.0.1:53 (Phase H, Phase I) stops working the moment this is set; P7e below is that fix for Phase I's probe."

    # --- P7e: Phase I health-cron probe — edit the probe INSIDE Phase I's own
    #     script, never a second cron entry. Only the "Do53 udp" line changes;
    #     P4 (serve_plain_dns:true on loopback) needs no edit at all. ---
    if [[ -f "$DNS_HEALTH_SCRIPT" ]]; then
        if is_selected P6; then
            confirm "P7e: about to replace the 'Do53 udp' probe in $DNS_HEALTH_SCRIPT (Phase I-owned) with a probe against the WireGuard tunnel address ($WG_V4_SERVER_IP), since 127.0.0.1:53 no longer exists under P6. Proceed?"
            exact_replace "$DNS_HEALTH_SCRIPT" "P7e dns-health probe (P6)" <<EOB
chk "Do53 udp"      "dig @127.0.0.1 example.com A +time=2 +tries=1 +short"
===REPLACE-WITH===
chk "Do53 (wg0 tunnel)" "dig @$WG_V4_SERVER_IP example.com A +time=2 +tries=1 +short"
EOB
        elif is_selected P1 || is_selected P3 || is_selected P5; then
            confirm "P7e: about to replace the 'Do53 udp' probe in $DNS_HEALTH_SCRIPT (Phase I-owned) with an encrypted-transport probe using the dedicated '$HEALTHCHECK_CLIENT' ClientID, since serve_plain_dns:false removes 127.0.0.1:53. Proceed?"
            exact_replace "$DNS_HEALTH_SCRIPT" "P7e dns-health probe (encrypted)" <<EOB
chk "Do53 udp"      "dig @127.0.0.1 example.com A +time=2 +tries=1 +short"
===REPLACE-WITH===
chk "DoT ($HEALTHCHECK_CLIENT ClientID)" "kdig @$DOMAIN +tls +tls-hostname=$HEALTHCHECK_CLIENT.$DOMAIN example.com A +short"
EOB
        else
            info "P7e: P4 selected with serve_plain_dns:true on loopback — the existing 127.0.0.1:53 probe in $DNS_HEALTH_SCRIPT keeps working unchanged; no edit needed."
        fi
        warn "P7e: the Phase I blackbox/Prometheus probe targets that check the public DoH/DoT/DoQ endpoint from outside also need inverting under private mode — 'public port answers' becomes an ALERTING condition, not a health signal. The exact Prometheus target edit is operator-specific and not scripted here; see P7e in phases/09-private-access.md and Phase I's blackbox config."
    else
        warn "P7e: $DNS_HEALTH_SCRIPT not found — run Phase I first, then re-run this script's P7e delta by hand (or re-run this whole script once Phase I exists)."
    fi

    # --- P7e: Phase J abuse controls — neutralise or convert to identity revocation ---
    if is_selected P6 || is_selected P1 || is_selected P4 || is_selected P5; then
        info "P7e (Phase J): under P6 every client is 10.77.0.x (dns_guard now exempts wg0 — P7b); under P1/P4/P5 every query reaches AdGuardHome from 127.0.0.1 — Phase J's IP-based auto-ban has no useful per-client address to act on in private mode. Prefer identity revocation instead of an IP ban: revoke a ClientID via POST /control/access/set (P7e), or 'wg set $WG_IFACE peer <PUBKEY> remove'. Do NOT delete 'table inet filter' — it is the entire firewall and Phase J's escalation logic stays valid for any node you leave public."
    fi

    cat <<'CHECKLIST'
P7f: Phase L go-live checklist deltas for private mode (add/replace in Phase L):
  [ ] Private mode selected and recorded: P6 WireGuard | P3 ClientID | P5 mTLS | P2 nft allowlist
  [ ] dns.allowed_clients populated and read back via GET /control/access/list
  [ ] dns.blocked_hosts still contains version.bind / id.server / hostname.bind
  [ ] blocked_hosts verified to return REFUSED (not SERVFAIL) over DoT
  [ ] ratelimit_subnet_len_ipv4/ipv6 still 32/64 after any edit to the dns: block
  [ ] dns.trusted_proxies narrowed to 127.0.0.1/32, ::1/128 (or empty if no proxy)
  [ ] Non-allowlisted client verified: UDP times out, TCP/DoT returns REFUSED
  [ ] Firewall: only 22, standing tcp/80, plus the ONE transport this deployment uses is open
  [ ] Firewall edits applied via /usr/local/sbin/nft-apply; ban timeouts survived
  [ ] dns_guard chain removed OR iifname "wg0" exempted; allowlist4 still holds 127.0.0.0/8
  [ ] Exactly one nginx server block per listener/name -- no duplicate :443 or :80
  [ ] External scan clean: nmap -sU -sT shows no DNS ports to the public internet
  [ ] Health cron (Phase I) probes the NEW binding, not 127.0.0.1:53
  [ ] Phase I external probes inverted: "public port answers" is now an alert
  [ ] Phase J abuse auto-ban neutralised OR converted to identity revocation
  [ ] Secrets kept out of the restic snapshot (doh-tokens.map, /etc/dns-mtls); client
      private keys deleted from the server after enrolment
  [ ] Per-client revocation drilled end to end and timed
  [ ] Wildcard cert AND wildcard A record in place -- only if DoT/DoQ ClientIDs used
  [ ] Phase F confirmed absent: no /opt/dns-warmer, no dns-warmer.service
CHECKLIST
}

# =====================================================================
# P8. Validation: prove refusal and prove service (reference — needs a
# second, unauthorised vantage point; see phases/09-private-access.md P8)
# =====================================================================
p8_validate() {
    phase_header "P8: validation — prove refusal and prove service"
    warn "P8 MANUAL STEP: this needs TWO vantage points — a host that is NOT authorised (another VPS, or a phone on cellular with the profile removed) and one that is. Running the negative tests from the server itself proves nothing; loopback is exempt nearly everywhere. Not automated here."

    cat <<'MATRIX'
P8a expected result matrix:
  P1 allowed_clients | UDP/53+DNSCrypt: timeout. TCP/53,DoT,DoH,DoQ: REFUSED | authorised: NOERROR
  P2 nftables allowlist | timeout on every DNS port (kernel drop); :80 still answers | authorised: NOERROR
  P3 ClientIDs | unknown ID -> REFUSED; bare /dns-query -> 404; unknown SNI -> REFUSED | authorised: NOERROR
  P4 token DoH | wrong token -> 404; over-rate -> 429 | authorised: HTTP 200, application/dns-message
  P5 mTLS DoT | no cert/foreign CA -> handshake failure; revoked CN -> REFUSED | authorised: NOERROR
  P6 WireGuard | nothing on any DNS port; 51820 silent to unauthenticated packets | authorised (in tunnel): NOERROR
MATRIX

    cat <<VERIFYEOF
P8b negative tests (run from an UNAUTHORISED host):
  TARGET=$DOMAIN; IP=<PUBLIC_IP>
  dig @"\$IP" google.com A +time=2 +tries=1;        echo "udp exit=\$? (expect 9, or 10 under P2/P6)"
  dig @"\$IP" google.com A +tcp +time=2 +tries=1;   echo "tcp exit=\$? (expect 9/10, or REFUSED under P1)"
  kdig @"\$TARGET" +tls  google.com A | grep -E '^;; ->>HEADER<<-'
  kdig @"\$TARGET" +quic google.com A | grep -E '^;; ->>HEADER<<-'
  kdig @"\$TARGET" +https=/dns-query google.com A
  kdig @"\$TARGET" +tls -c CH -t TXT version.bind | grep -E '^;; ->>HEADER<<-'
  for p in /control/status /login.html /install.html /apple/doh.mobileconfig; do
    printf '%s -> ' "\$p"; curl -s -o /dev/null -w '%{http_code}\n' "https://\$TARGET\$p"; done
  nmap -sU -p 53,853,$WG_PORT -Pn "\$IP"
  nmap -sT -p 22,53,80,443,853,3000,8053,8853 -Pn "\$IP"
  # tcp/80 is OPEN in every mechanism, P6 included -- not a finding.
  # 3000, 8053, 8853 must NEVER appear open -- loopback-only.

P8c positive tests (run from an AUTHORISED client):
  dig @<PUBLIC_IP> example.com A +short                                            # P1/P2
  kdig @\$DOMAIN +https=/dns-query/alice-iphone example.com A +short               # P3
  kdig @\$DOMAIN +tls  +tls-hostname=alice-iphone.\$DOMAIN example.com A +short     # P3 SNI
  curl -si -H 'accept: application/dns-message' "https://\$DOMAIN/t/<TOKEN>/dns-query?dns=<b64>"  # P4
  kdig @\$DOMAIN +tls +tls-hostname=\$DOMAIN +tls-certfile=/etc/dns-mtls/alice-iphone.crt +tls-keyfile=/etc/dns-mtls/alice-iphone.key example.com A +short  # P5
  dig @$WG_V4_SERVER_IP example.com A +short                                       # P6
  dig @$WG_V4_SERVER_IP dnssec-failed.org A; echo "exit=\$? (expect SERVFAIL)"      # P6, Unbound still validates

P8d attribution and revocation drill (record the measured time in Phase L):
  curl -s --netrc-file $AGH_NETRC 'http://127.0.0.1:3000/control/querylog?limit=5' | jq -r '.data[] | "\(.client) \(.client_id) \(.question.name)"'
  time ( <revoke the one command matching your mechanism -- P7e / P4d / P5c / P6f> )
  # then re-run the matching P8c positive test from the revoked device -- it must now fail.
VERIFYEOF
}

# =====================================================================
# Main — apply selected mechanisms in canonical order, then deltas, then
# the validation reference.
# =====================================================================
for m in "${VALID_MECHS[@]}"; do
    is_selected "$m" || continue
    case "$m" in
        P1) p1_apply ;;
        P2) p2_apply ;;
        P3) p3_apply ;;
        P4) p4_apply ;;
        P5) p5_apply ;;
        P6) p6_apply ;;
    esac
done

p7_deltas
p8_validate

info "done: Phase P mechanisms ${SELECTED_MECHS[*]} applied."
echo "What 'this worked' looks like: re-run this script's echoed P8b/P8c commands from a real UNAUTHORISED and AUTHORISED vantage point (see the P8 output above), and walk the P7f checklist before marking Phase L's private-mode items complete."
