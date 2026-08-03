#!/usr/bin/env bash
# deploy/phases/E-adguardhome-edge.sh — Phase E: AdGuardHome edge (AdGuardHome.yaml,
# nginx DoH front, systemd hardening).
#
# Mechanical transcription of phases/05-adguardhome-edge.md. This script has NOT
# been run against real hardware — same caveat as the source plan. Read the
# source file and this script before running either.
#
# Depends on: Phase A (host prep, sysctl), Phase B (nftables — TCP/80 and
# TCP/443 must already be open), Phase C (Unbound on 127.0.0.1:5335), Phase D
# (Let's Encrypt cert at /etc/letsencrypt/live/<domain>/{fullchain,privkey}.pem).
#
# Placeholders carried verbatim from the source markdown, NOT filled in here —
# see the warn() calls below for exactly which ones and why:
#   dns.example.com   — the public hostname (Phase E4/E2/E6). Choosing it is a
#                        business decision the source plan explicitly leaves to
#                        the operator; this script does not invent one.
#   <PUBLIC_IP>        — the host's public address, used only in E6 verification
#                        commands that the source plan itself says must be run
#                        from a DIFFERENT host, not from this one.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=../lib/common.sh
source ../lib/common.sh

require_root
phase_header "Phase E: AdGuardHome edge (AdGuardHome.yaml, nginx DoH front, systemd hardening)"

warn "This script uses the placeholder hostname 'dns.example.com' throughout, exactly as phases/05-adguardhome-edge.md does. Domain choice is an operator business decision (see CLAUDE.md hard rule 7) — replace every occurrence with your real domain (e.g. via sed on this file) BEFORE running it. Do not run it unedited against production."

require_cmd curl tar sha256sum openssl sed awk grep

# =============================================================================
# E1. Install a pinned release with an integrity check
# =============================================================================
# --- E1: pin, download, checksum-verify, install into a versioned dir ---
AGH_VER=v0.107.78          # pin deliberately; see Phase M for the upgrade path
BASE=/opt/adguardhome
# `validate` is the SCRATCH work directory for every `--check-config` run in
# this plan (E2 here, Phase H's pre-change gate, Phase K's restore drill,
# Phase M's upgrade wrapper, Phase O's Ansible validate= hook). Phase E is its
# SOLE OWNER — created here, at install time, because those consumers all
# assume it already exists. --check-config leaves artifacts behind, so it must
# never be pointed at the live work/ tree, and it must never run as root.
install -d "$BASE"/{conf,work,releases,validate} /var/log/adguardhome
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT; cd "$TMP"

curl -fsSLO "https://github.com/AdguardTeam/AdGuardHome/releases/download/${AGH_VER}/AdGuardHome_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/AdguardTeam/AdGuardHome/releases/download/${AGH_VER}/checksums.txt"
grep ' AdGuardHome_linux_amd64.tar.gz$' checksums.txt | sha256sum -c -
# MUST print "AdGuardHome_linux_amd64.tar.gz: OK". `set -e` (from common.sh)
# already aborts the script on anything else, matching the source's "Anything
# else: stop."
info "checksum verified OK for AdGuardHome_linux_amd64.tar.gz ($AGH_VER)"

install -d "$BASE/releases/$AGH_VER"
tar -xzf AdGuardHome_linux_amd64.tar.gz -C "$BASE/releases/$AGH_VER" --strip-components=1
ln -sfn "$BASE/releases/$AGH_VER" "$BASE/current"
chown -R adguardhome:adguardhome "$BASE" /var/log/adguardhome
chmod 0750 "$BASE/conf" "$BASE/validate" /var/log/adguardhome
cd - >/dev/null

# checksums.txt is served from the same origin as the tarball: it proves the
# download was not corrupted or truncated, not that the release was not
# tampered with at source. AdGuardTeam publishes no detached signature for
# these artifacts, so there is nothing stronger to do here.

# --- E1: no setcap grant anywhere in this plan — verify the binary is clean ---
"$BASE/current/AdGuardHome" --version
CAP_OUT=$(getcap "$BASE/current/AdGuardHome" || true)
[[ -z "$CAP_OUT" ]] || warn "getcap printed '$CAP_OUT' — expected NO output on a clean install. A stale file capability from a v1-plan host will be stripped in E5a below."
ls -ld "$BASE/validate"
# expect: drwxr-x--- adguardhome adguardhome -- the scratch --check-config
# work dir. Every phase that runs a config gate assumes this exists.

# =============================================================================
# E2. AdGuardHome.yaml
# =============================================================================
# --- E2: confirm the schema number for the pinned binary before writing the file ---
SCHEMA_CHECK=$(curl -s "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/${AGH_VER}/internal/configmigrate/configmigrate.go" \
  | grep LastSchemaVersion || true)
info "upstream LastSchemaVersion for ${AGH_VER}: ${SCHEMA_CHECK:-<not found>}"
# Expected: "LastSchemaVersion uint = 34" for AGH_VER=v0.107.78 as pinned above.
# The heredoc below hardcodes schema_version: 34 to match. If AGH_VER is ever
# changed, this MUST be re-verified and the heredoc edited by hand — this
# script does not auto-rewrite schema_version, and the source plan is explicit
# that hand-editing it AFTER first start is wrong in either direction.
echo "$SCHEMA_CHECK" | grep -q '= 34' \
  || warn "LastSchemaVersion for ${AGH_VER} does not read 34 — the AdGuardHome.yaml written below assumes 34. Verify by hand before continuing."

# --- E2: write AdGuardHome.yaml (schema_version present => no legacy migration chain) ---
backup_file /opt/adguardhome/conf/AdGuardHome.yaml
cat > /opt/adguardhome/conf/AdGuardHome.yaml << 'EOF'
# Must match LastSchemaVersion of the pinned binary. Absent => migrator reads 0
# and runs 34 legacy migrations that expect legacy types. Do not hand-edit this
# number after first start; a higher value is rejected by validateVersion, a
# lower one re-runs the destructive migrations.
schema_version: 34

http:
  # Admin UI + control API. Loopback only, reached over the Phase P SSH tunnel.
  # This address ALSO fixes the host of the HTTPS listener below (web.go:
  # netip.AddrPortFrom(web.conf.BindAddr.Addr(), portHTTPS)), which is why
  # port_https can never be a public 443. See E4.
  address: 127.0.0.1:3000
  session_ttl: 4h
  pprof:
    port: 0
    enabled: false

users:
  - name: admin
    password: "$2y$12$REPLACE_WITH_BCRYPT_HASH"   # see E3

dns:
  # Plain Do53, DoT and DoQ bind here. Not the web listener. This is a WILDCARD
  # address, and a wildcard is NOT IPv4-only: Go gives you one dual-stack socket
  # per port. Read E2a before you publish -- or withhold -- an AAAA record, and
  # do NOT "add IPv6" by appending '::' here.
  bind_hosts:
    - 0.0.0.0
  port: 53

  # --- RESOLUTION: Unbound is the only resolver and the only validator ---
  upstream_dns:
    - 127.0.0.1:5335
  upstream_dns_file: ""
  bootstrap_dns:
    - 127.0.0.1:5335
  # load_balance is the only correct mode with a single validating upstream.
  # 'parallel' and 'fastest_addr' race resolvers, which makes the AD bit
  # nondeterministic. Valid values: load_balance | parallel | fastest_addr.
  upstream_mode: load_balance
  # MUST stay empty. dnsproxy reaches the fallback on a TRANSPORT error, i.e.
  # exactly when Unbound is down, restarting or OOM -- the moment you least want
  # an unvalidated third party answering in your name. (It is NOT reached on
  # SERVFAIL: a SERVFAIL rcode is a successfully exchanged message, so a
  # DNSSEC-bogus name does not silently re-resolve elsewhere.)
  fallback_dns: []

  # Sets the DO bit on EVERY upstream query, not only on queries whose client
  # already set it. This is a CACHE-NORMALISATION setting, not a validation
  # setting: AdGuardHome does not validate DNSSEC and never will here. Unbound
  # is the validator. Without it, a non-DO query stores an entry stripped of
  # RRSIGs and a later '+dnssec' client can be served that stripped entry.
  enable_dnssec: true

  # --- CACHE ---
  cache_size: 134217728      # 128 MB edge cache. See Phase A6 for the memory budget.
  cache_ttl_min: 0           # never inflate a TTL; short TTLs are load-bearing for failover
  cache_ttl_max: 3600
  cache_optimistic: false    # Unbound's prefetch owns staleness (Phase C)

  # --- RATE LIMITING (plain UDP ONLY -- read the caveat) ---
  # Verified in dnsproxy proxy/server.go:
  #   if d.Proto == ProtoUDP && p.isRatelimited(ip) { ... }
  # So this limiter covers plain UDP/53 and NOTHING else. TCP/53, DoH, DoT and
  # DoQ are completely unthrottled at the application layer. The encrypted
  # transports are covered by the nftables connection-rate ceiling in Phase B;
  # do not treat this key as protecting them.
  ratelimit: 100
  # Defaults are /24 and /56, i.e. one budget shared by 256 IPv4 hosts. Set to
  # /32 and /64 for per-host accounting: subnet aggregation black-holes CGNAT
  # and corporate-NAT clients, and against SPOOFED sources it helps not at all.
  ratelimit_subnet_len_ipv4: 32
  ratelimit_subnet_len_ipv6: 64
  # Loopback only. Harmless in this topology because the nginx-fronted DoH path
  # (which does arrive from 127.0.0.1) is not rate-limited by this key anyway.
  # If a plain-DNS proxy is ever put in front, DELETE these two lines or the
  # limiter silently whitelists 100% of traffic.
  ratelimit_whitelist:
    - 127.0.0.1
    - ::1
  refuse_any: true

  # --- CLIENT IDENTITY AND PROXY TRUST (see E4) ---
  # Default is 127.0.0.0/8 AND ::1/128. Narrowed: only nginx on this exact host
  # may rewrite the client address via X-Forwarded-For.
  trusted_proxies:
    - 127.0.0.1/32
    - ::1/128
  # Phase P owns the values. An EMPTY allowed_clients means "allow everyone";
  # a non-empty one wins outright and disallowed_clients is then ignored.
  allowed_clients: []
  disallowed_clients: []
  # AdGuardHome's own defaults, which are lost the moment you write the whole
  # file yourself. Refusing these kills trivial version fingerprinting.
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind

  # --- PRIVACY ---
  # Applied at ingestion, in place, BEFORE the address reaches the query log or
  # stats.db. Granularity: /16 for IPv4, /48 for IPv6. CONSEQUENCE: anything
  # that parses a client address out of the query log gets a network address,
  # not the abuser. Abuse detection is kernel-side -- see Phase J.
  anonymize_client_ip: true
  edns_client_subnet:
    enabled: false           # never carry client subnets to the authoritative side
  # AdGuardHome's built-in default is TRUE. A public resolver must not answer
  # PTR for RFC1918 space out of the host's own resolver stack.
  use_private_ptr_resolvers: false
  local_ptr_upstreams: []

  # --- TRANSPORT / CONCURRENCY ---
  # HTTP/3 stays OFF. nginx 1.24.0 (Ubuntu 24.04) has no HTTP/3, and AGH's own
  # HTTPS listener is loopback-only here, so 'true' would advertise
  # Alt-Svc: h3=":443" for a UDP/443 path that Phase B drops -- every
  # HTTP/3-capable client stalls into a black hole before falling back.
  # DoQ on UDP/853 is a separate listener and is unaffected.
  serve_http3: false
  use_http3_upstreams: false
  # Concurrency ceiling. AdGuardHome publishes no default for this key, so read
  # it back after first start rather than assuming one. Rough model:
  # ceiling_qps ~= max_goroutines / miss_latency_seconds.
  max_goroutines: 800
  # Phase P may set this false to refuse plain DNS entirely. It is TRUE here.
  # Note the constraint: AdGuardHome refuses to start with serve_plain_dns:false
  # unless at least one ENCRYPTED listener exists (preparePlain counts DNSCrypt,
  # HTTPS, QUIC and TLS listen addresses -- the plain-HTTP DoH handler on the
  # web mux does not count).
  serve_plain_dns: true

  # --- FILTERING: off. This is a resolver, not a blocker. ---
  filtering_enabled: false
  filters_update_interval: 0
  parental_enabled: false
  safebrowsing_enabled: false
  safesearch:
    enabled: false

tls:
  enabled: true
  server_name: dns.example.com
  force_https: false
  # 8053, NOT 443. AdGuardHome builds this listener as
  # netip.AddrPortFrom(web.conf.BindAddr.Addr(), portHTTPS) -- the HOST comes
  # from http.address. With http.address on loopback, port_https: 443 binds
  # 127.0.0.1:443 and public DoH silently never works. nginx owns public 443
  # and proxies only /dns-query here. See E4.
  port_https: 8053
  port_dns_over_tls: 853       # DoT, served by dnsforward on dns.bind_hosts
  port_dns_over_quic: 853      # DoQ (RFC 9250), UDP, also on dns.bind_hosts
  port_dnscrypt: 0
  # Phase D4's hook copies these here. Never point at /etc/letsencrypt/live --
  # the archive key is root-only 0600 and this process is unprivileged.
  certificate_chain: /opt/adguardhome/conf/ssl/fullchain.pem
  private_key: /opt/adguardhome/conf/ssl/privkey.pem
  # Leave false. When true, an SNI that is neither the apex nor an immediate
  # subdomain returns an error that becomes SERVFAIL, instead of falling through
  # to the allowlist. It buys nothing once allowed_clients is set, and it is
  # marked deprecated in the AdGuardHome changelog.
  strict_sni_check: false
  # Go crypto/tls constant names, passed straight through: a typo means the
  # listener refuses to start. There is deliberately NO min_version key --
  # internal/home/tls.go hardcodes MinVersion: tls.VersionTLS12. This list
  # exists to remove the CBC suites scanners flag, not to raise the floor.
  # TLS 1.3 suites are not configurable in Go and are always on; DoQ is
  # TLS 1.3-only, so this list is inert there.
  override_tls_ciphers:
    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305

# TOP-LEVEL. Not under dns:. The v1 layout silently voided every value here.
#
# THIS IS THE SHIPPED DEFAULT LOGGING POSTURE for the whole plan: querylog on,
# interval 6h, and every client address already masked by dns.anonymize_client_ip
# above before it reaches this ring buffer. Phase Q documents alternative
# postures -- including a zero-log one -- as explicit operator OPT-INS, each
# stated there together with what it costs you in monitoring. None of them is
# the default, and nothing outside this file changes what is written here.
querylog:
  enabled: true
  # No query log on disk by default. When true, retention is 2x `interval`:
  # after `interval` the file is RENAMED to querylog.json.1, not deleted. At
  # 1000 QPS and ~400 B/entry that is ~34.5 GB/day on a 40 GB disk.
  file_enabled: false
  # Accepted values only: 6h, 24h, 168h, 720h, 2160h.
  interval: 6h
  size_memory: 5000            # in-memory ring, survives nothing, costs no disk
  # Only consulted when file_enabled is true. Set now so enabling it later does
  # not drop the log into the work dir.
  dir_path: /var/log/adguardhome/querylog
  ignored: []
  ignored_enabled: false

# TOP-LEVEL. Phase I's metrics come from /control/stats, so this is the key the
# whole AdGuardHome half of the dashboard hangs on. TRUE is the shipped default.
# If an operator later adopts one of Phase Q's opt-in postures and turns it off,
# Phase I's collector emits its distinct "metrics unavailable by policy" signal
# and does NOT report the daemon down -- Phase I owns that degradation logic.
# Do not build a second copy of it here, and do not treat enabled:false as an
# outage anywhere in this document.
statistics:
  enabled: true
  # Duration string since v0.107.27, NOT a number of days. Must be present and
  # >= 1h even when disabled: stats.New calls validateIvl before anything else
  # and a 0 is fatal ("unsupported interval: less than an hour").
  interval: 24h
  dir_path: /var/lib/adguardhome/stats
  ignored: []
  ignored_enabled: false

log:
  file: /var/log/adguardhome/adguardhome.log
  max_backups: 5
  max_size: 100
  max_age: 7
  compress: true
  verbose: false
EOF

install -d -o adguardhome -g adguardhome -m 0750 \
  /var/log/adguardhome/querylog /var/lib/adguardhome/stats
chown adguardhome:adguardhome /opt/adguardhome/conf/AdGuardHome.yaml
chmod 0600 /opt/adguardhome/conf/AdGuardHome.yaml

# Two things about this file that are not obvious (source E2 prose):
# - stats.db exists whether or not statistics are enabled (stats.New calls
#   openDB() unconditionally). It holds a per-domain request-count table that
#   client anonymisation does NOT touch. Lives at statistics.dir_path
#   (/var/lib/adguardhome/stats) -- see Phase Q and Phase K.
# - AdGuardHome REWRITES this file at startup, not shutdown. The authoritative
#   statement of what your config means is the file AFTER first start, not the
#   file you wrote. That is why the diff below runs after E5 starts the service.

# --- E2: validate the just-written config in the E1 scratch dir, as adguardhome, never as root ---
cp -a /opt/adguardhome/conf/AdGuardHome.yaml /tmp/agh.intended
runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
  -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate; echo "exit=$?"

# =============================================================================
# E2a. Address family: 0.0.0.0 is not IPv4-only, and the AAAA is a decision
# =============================================================================
# Phase A owns the dual-stack-vs-IPv4-only decision. This phase's config above
# already matches whichever answer Phase A gave (bind_hosts: [0.0.0.0], which
# is a dual-stack wildcard on any host with a usable IPv6 stack — see E2a's
# prose for the golang/go#48723 mechanics). Nothing to script here beyond what
# E2 already wrote; the socket/loopback verification for this decision runs
# after the service starts (see the "post-start verification" section below).
info "E2a: dns.bind_hosts is [0.0.0.0] (dual-stack wildcard, not IPv4-only) per Phase A's decision. See phases/05-adguardhome-edge.md#e2a for the AAAA-publication consequences before adding any DNS record."

# =============================================================================
# E3. Admin credentials
# =============================================================================
# --- E3: admin password + bcrypt hash, cost 12 ---
apt install -y apache2-utils
require_cmd htpasswd
PW=$(openssl rand -base64 24)
printf 'STORE THIS IN YOUR PASSWORD MANAGER NOW: %s\n' "$PW"
warn "AdGuardHome admin password was just printed above. This is a manual step the plan itself calls out: store it in your password manager NOW. It will not be printed again by this script."
HASH=$(htpasswd -bnBC 12 "" "$PW" | tr -d ':\n')

# The source says: "Paste the $2y$12$... string into users[0].password in
# AdGuardHome.yaml." That paste is mechanical (the value is already computed
# above), so it is done here with sed rather than left as a manual step —
# unlike the password-manager step above, there is no operator judgement call
# involved in placing a generated hash into the placeholder E2 already wrote.
backup_file /opt/adguardhome/conf/AdGuardHome.yaml
sed -i "s|\$2y\$12\$REPLACE_WITH_BCRYPT_HASH|${HASH}|" /opt/adguardhome/conf/AdGuardHome.yaml

# --- E3: file permissions for a config the process itself must be able to rewrite ---
chown adguardhome:adguardhome /opt/adguardhome/conf/AdGuardHome.yaml
chmod 0600 /opt/adguardhome/conf/AdGuardHome.yaml
# `install -d`, not `chmod`: AdGuardHome creates work/data itself on FIRST
# START, which has not happened yet at this point in the build order -- a bare
# chmod here fails with "No such file or directory". install -d creates it
# with the right owner/mode if absent and re-applies both if it already
# exists, so this line is correct whether or not the service has ever run.
install -d -o adguardhome -g adguardhome -m 0700 /opt/adguardhome/work/data

# Never put credentials on a command line -- /proc/PID/cmdline is
# world-readable, so `curl -u admin:password` leaks to every local account for
# the life of the request. Use a netrc file for the Phase I health checks.
# NOTE: the source markdown's own example writes the literal token
# 'THE_PASSWORD' here, clearly a stand-in for the reader to replace by hand.
# This script has the real generated $PW in scope from above, so it is used
# directly -- writing the literal placeholder string into a real credential
# file on a real host would produce a netrc that cannot authenticate, which is
# a bug, not a faithful transcription.
backup_file /root/.dns-netrc
install -m 0600 /dev/null /root/.dns-netrc
printf 'machine 127.0.0.1 login admin password %s\n' "$PW" > /root/.dns-netrc
unset PW

warn "E3: AdGuardHome.yaml's bcrypt hash must NOT reach the Phase K backup in plaintext-adjacent form. See Phase K for the sanitisation filter and encryption requirement before this file (or any backup containing it) leaves this host."

# =============================================================================
# E4. nginx as the public DoH front
# =============================================================================
# --- E4: nginx is the public HTTPS edge; AdGuardHome's web listeners stay loopback-only ---
apt install -y nginx
nginx -v    # expect nginx/1.24.0 on Ubuntu 24.04

# Client identity snippet -- every proxied location must include this.
# OVERWRITE, never append: $proxy_add_x_forwarded_for appends to a
# client-supplied header and AdGuardHome takes the FIRST comma-separated
# element, which is the client-controlled one.
install -d /etc/nginx/snippets
backup_file /etc/nginx/snippets/agh-client-identity.conf
cat > /etc/nginx/snippets/agh-client-identity.conf << 'EOF'
# OVERWRITE, never append. $proxy_add_x_forwarded_for appends to a
# client-supplied header and AdGuardHome takes the FIRST element.
proxy_set_header X-Forwarded-For   $remote_addr;
proxy_set_header X-Real-IP         $remote_addr;

# Strip the two headers dnsproxy checks BEFORE X-Forwarded-For. An empty value
# means the header is not passed to the upstream at all.
proxy_set_header CF-Connecting-IP  "";
proxy_set_header True-Client-IP    "";

# Pin the Host. Belt and braces: the TLS backend already closes the
# Host-as-SNI ClientID path, but this survives someone moving the backend to
# plain HTTP later.
proxy_set_header Host              dns.example.com;

proxy_set_header X-Forwarded-Proto https;
proxy_http_version 1.1;
proxy_set_header Connection        "";
proxy_buffering off;
EOF

# If a CDN is ever put in front, trusted_proxies must list the CDN egress
# ranges and nginx must NOT strip CF-Connecting-IP -- but then the CDN, not
# you, decides who your clients are. For this design, do not.

# --- E4: the server itself -- public :443 DoH-only front, plus the permanent :80 block ---
backup_file /etc/nginx/conf.d/doh.conf
cat > /etc/nginx/conf.d/doh.conf << 'EOF'
upstream agh_doh {
    server 127.0.0.1:8053;
    # Reuse backend TLS connections; without this every client request pays a
    # loopback handshake.
    keepalive 32;
}

server {
    # nginx 1.24.0 syntax. The standalone `http2 on;` directive is nginx
    # >= 1.25.1 and fails `nginx -t` here. HTTP/3 is not available in 1.24 at
    # all, which is why dns.serve_http3 is false in E2.
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name dns.example.com;

    # Version string off every response and error page. Phase Q relies on this
    # being here rather than adding it itself. No `charset` here: Phase Q adds
    # `charset utf-8;` to THIS block when it publishes the HTTPS copy of
    # security.txt, and a second `charset` in the same context is a duplicate-
    # directive error at `nginx -t`.
    server_tokens off;

    ssl_certificate     /etc/letsencrypt/live/dns.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_ecdh_curve      X25519:prime256v1;
    ssl_session_cache   shared:doh:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    # No ssl_stapling: Let's Encrypt shut its OCSP responders down 2025-08-06
    # and issued certs carry no OCSP URI. It would be a no-op. See Phase D6.

    # No client-IP logging. This line is load-bearing for the whole privacy
    # design -- see Phase Q. error_log still records addresses on failures;
    # keep it at warn and accept that, or send it to /dev/null knowingly.
    access_log off;
    error_log  /var/log/nginx/doh-error.log warn;

    # DoH, and only DoH. GET carries ?dns=<base64url>, POST carries the wire
    # message as the body; both hit the same location.
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

    # /control/*, /login.html, /install.html, /apple/*.mobileconfig -- none of
    # it may be reachable. This is the rule that makes fact (2) above harmless.
    location / { return 404; }
}

# Anything arriving on 443 with a different (or absent) SNI gets no handshake
# and no certificate. ssl_reject_handshake is nginx >= 1.19.4.
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    ssl_reject_handshake on;
}

# ---------------------------------------------------------------------------
# THE ONE AND ONLY PORT 80 SERVER BLOCK ON THIS HOST.
#
# TCP/80 IS PERMANENTLY OPEN. Phase B carries a standing `tcp dport 80 accept`;
# there is no open-for-renewal / close-afterwards dance anywhere in this plan,
# and nothing here may be written as if the port were normally shut. nginx owns
# this listener for the life of the host.
#
# It serves two consumers out of ONE webroot, /var/www/acme:
#   - the ACME http-01 challenge (Phase D3's `certbot --webroot -w /var/www/acme`)
#   - the Phase Q well-known files (security.txt and friends)
# Phase Q does NOT add a second listen-80 server and does NOT add a second
# webroot; it adds location blocks to THIS server, at the marked point below.
#
# `default_server` is deliberate and load-bearing: it makes a second listen-80
# default_server a hard `nginx -t` failure ("duplicate default server for
# 0.0.0.0:80") instead of a silently shadowed block whose ACME challenge 404s
# for reasons nobody can see. Combined with the `rm -f sites-enabled/default`
# below, this is the whole of :80 on this machine.
#
# Deliberately no redirect to HTTPS -- a DoH endpoint has no browser flow, and
# a redirect just hands scanners a confirmed mapping.
# ---------------------------------------------------------------------------
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name dns.example.com;
    access_log off;

    # These two are shipped HERE, by Phase E, and Phase Q depends on both being
    # present in this block -- it confirms them rather than adding them:
    #   server_tokens off  - no version string on responses or error pages.
    #   charset utf-8      - RFC 9116 requires security.txt as
    #                        `text/plain; charset=utf-8`. `default_type` cannot
    #                        deliver that: mime.types already resolves .txt to
    #                        text/plain, so default_type never fires and the
    #                        charset stays off. text/plain is in nginx's default
    #                        charset_types, so this one line is sufficient. It has
    #                        no effect on DoH, which is not served from this block
    #                        and whose application/dns-message is not in
    #                        charset_types anyway.
    server_tokens off;
    charset utf-8;

    # Shared webroot for every consumer of this block. Phase D3's -w argument
    # must match this path verbatim.
    root /var/www/acme;

    location ^~ /.well-known/acme-challenge/ {
        default_type "text/plain";
    }

    # >>> PHASE Q INSERTION POINT <<<
    # Phase Q adds its /.well-known/ location blocks HERE -- inside this server,
    # served from the `root` above. Nothing else in this file changes.
    # Nothing is placed here by Phase E.

    location / { return 404; }
}
EOF

install -d -m 0755 /var/www/acme

# --- E4: remove the packaged catch-all -- it binds :80/[::]:80 and would
#         collide with the default_server block above ---
confirm "About to run: rm -f /etc/nginx/sites-enabled/default (removes the packaged nginx catch-all site so this host's single :80 default_server block above can own port 80/[::]:80). This touches nginx's boot-service site configuration. Proceed?"
rm -f /etc/nginx/sites-enabled/default
nginx -t

# Exactly one :80 server and exactly one webroot. Re-run this after Phase Q
# adds its locations, and after any later nginx change.
grep -rn 'listen .*80' /etc/nginx/ | grep -v '#'
# expect: exactly the two lines from the block above -- 80 default_server and
#         [::]:80 default_server.

# The two directives Phase Q depends on. Iterate conf.d/*.conf, NOT
# sites-enabled: every server block on this host lives in conf.d, and the
# sites-enabled removal above leaves that directory empty.
for f in /etc/nginx/conf.d/*.conf; do
  printf '%s: server_tokens=%s charset=%s\n' "$f" \
    "$(grep -c 'server_tokens off;' "$f")" "$(grep -c 'charset utf-8;' "$f")"
done
# expect for doh.conf: server_tokens=2 (the :443 and :80 blocks) charset=1
# (:80 only). Phase Q adds the second `charset utf-8;` to the :443 block when
# it publishes the HTTPS copy of security.txt.

# =============================================================================
# E5. systemd units, and the shared hardening reference
# =============================================================================

# --- E5a: why setcap cannot work here, and the one setcap in this whole plan (a removal) ---
# The v1 plan set NoNewPrivileges=yes in the unit AND ran
# `setcap 'cap_net_bind_service=+ep'` on the binary. These are mutually
# exclusive: with NoNewPrivileges, the kernel intersects the new permitted set
# with the old (empty, for User=adguardhome) at execve, so a file capability
# never survives and AdGuardHome dies with "bind: permission denied".
# AmbientCapabilities= (E5b) is applied by PID 1 BEFORE execve, so
# NoNewPrivileges does not block it -- that is the fix.
#
# Clearing a stale file capability is MANDATORY, not hygiene: the kernel does
# `if (has_fcap || id_changed) cap_clear(new->cap_ambient);`, so a leftover
# file capability CLEARS the ambient set at execve and silently defeats E5b.
#
# This is the ONLY setcap in this entire plan, and it only ever REMOVES. No
# phase grants a capability with setcap; every capability comes from
# AmbientCapabilities= in the unit. On a clean build this is a no-op.
confirm "About to run: setcap -r on /opt/adguardhome/current/AdGuardHome (strips any stale file capability left by a v1-plan install; grants nothing; no-op on a clean build). This touches the binary the adguardhome boot service execs. Proceed?"
setcap -r /opt/adguardhome/current/AdGuardHome 2>/dev/null || true
CAP_OUT2=$(getcap /opt/adguardhome/current/AdGuardHome || true)
[[ -z "$CAP_OUT2" ]] || warn "getcap still prints '$CAP_OUT2' after setcap -r — investigate before starting the service (E5a)."

# Do not reach for PrivateUsers=yes on this unit: CAP_NET_BIND_SERVICE held
# only inside a user namespace does not authorise binding ports below 1024 in
# the host network namespace, so it reintroduces the identical failure.
# Socket activation would avoid the capability entirely, but AdGuardHome does
# not implement LISTEN_FDS, so it is not available.

# --- E5b: adguardhome.service ---
backup_file /etc/systemd/system/adguardhome.service
cat > /etc/systemd/system/adguardhome.service << 'EOF'
[Unit]
Description=AdGuardHome DNS Gateway
After=network-online.target unbound.service
Wants=network-online.target
# Wants=, NOT Requires=. Requires= does not propagate a crash (that is BindsTo=),
# but it does mean `systemctl restart unbound` silently bounces the public
# listener too, and that an unbound that fails to activate at boot keeps
# AdGuardHome from starting at all. With Wants= it comes up and serves from its
# own cache. See Phase N for the crash-churn detector.
Wants=unbound.service
# Canonical restart policy, identical on every unit in this plan -- Phase C4's
# Unbound unit and Phase N's drop-in carry the same four values, and they must
# not be allowed to diverge again: Restart=always, RestartSec=5,
# StartLimitIntervalSec=300, StartLimitBurst=10.
#
# A BOUNDED start limit, not a disabled one. systemd's stock 5-starts-in-10s
# abandons a crash-looping daemon in `failed` and never retries it, so a
# transient fault becomes a permanent outage; a limit of zero overcorrects,
# because a unit that can never reach `failed` can never fire OnFailure=
# either. 10 starts per 300 s absorbs real crash-and-recover churn and still
# leaves the escape hatch open.
#
# Read it together with the exponential backoff in [Service]: once RestartSec
# has stepped up, a sustained loop spaces restarts far enough apart that the
# limit is rarely reached in practice. Do NOT treat `failed` as your outage
# signal -- alert on restart churn (see Phase I for the notifier, Phase N for
# the churn detector).
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
User=adguardhome
Group=adguardhome
ExecStart=/opt/adguardhome/current/AdGuardHome \
  -c /opt/adguardhome/conf/AdGuardHome.yaml \
  -w /opt/adguardhome/work \
  --no-check-update
Restart=always
RestartSec=5
# systemd 255 on Ubuntu 24.04 supports exponential backoff (added in v254).
RestartSteps=5
RestartMaxDelaySec=60s
LimitNOFILE=1048576

# --- Capabilities: the E5a fix ---
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
RestrictSUIDSGID=yes

# --- Filesystem ---
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
# AdGuardHome rewrites AdGuardHome.yaml at startup and on schema migration, so
# /opt/adguardhome MUST be writable. The other two are querylog and stats dirs.
ReadWritePaths=/opt/adguardhome /var/log/adguardhome /var/lib/adguardhome
UMask=0077

# --- Kernel / namespace ---
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
# NO ProcSubset=pid -- see the table below.
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes

# --- Syscalls and sockets ---
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete @mount
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
EOF

# Memory ceilings (MemoryHigh=, MemoryMax=, OOMScoreAdjust=), the swapfile and
# vm.swappiness are DELIBERATELY ABSENT from this unit and MUST NOT be added
# here: sole owner is Phase A6, which sets AdGuardHome's ceiling next to
# Unbound's and the host's swap so the sum can be checked against real RAM. If
# E2's cache_size changes, change AdGuardHome's ceiling in Phase A6's file, not
# here.

# --- E5c: nginx.service hardening drop-in (override the packaged unit, don't edit it) ---
install -d /etc/systemd/system/nginx.service.d
backup_file /etc/systemd/system/nginx.service.d/hardening.conf
cat > /etc/systemd/system/nginx.service.d/hardening.conf << 'EOF'
[Unit]
# Same canonical tuple as adguardhome.service and as Phase C4/Phase N's Unbound
# unit. See E5b for why the limit is bounded rather than disabled.
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Restart=always
RestartSec=5
# Memory ceilings are NOT set here either -- Phase A6 owns them for every
# daemon on this host.

# nginx's master starts as root and binds 80/443 BEFORE dropping to www-data,
# so it needs no AmbientCapabilities. Bound what the master may keep:
#   NET_BIND_SERVICE - the listeners
#   SETUID/SETGID - the in-process worker privilege drop
#   DAC_OVERRIDE - reading /etc/letsencrypt/live (root-only 0600 key)
#   CHOWN - only needed if you add proxy_cache_path/client_body_temp_path with
#           a user-owned directory; harmless to keep, safe to remove otherwise.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE
NoNewPrivileges=yes
RestrictSUIDSGID=yes

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ReadWritePaths=/var/log/nginx /var/lib/nginx /run
UMask=0077

ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
# Safe ONLY while `pcre_jit` stays off (the nginx default). PCRE2's JIT maps
# writable-executable pages; turning pcre_jit on with this set crashes on the
# first regex location -- and E4 uses a regex location under Phase P.
MemoryDenyWriteExecute=yes
RemoveIPC=yes

SystemCallArchitectures=native
SystemCallFilter=@system-service
# NOTE: no `~@privileged` here -- see below. Deny the specific dangerous groups.
SystemCallFilter=~@obsolete @mount @swap @reboot @module @raw-io @clock @cpu-emulation @debug
SystemCallErrorNumber=EPERM
# AF_UNIX is mandatory: nginx uses socketpair(AF_UNIX) for the master/worker
# channel and will not start without it.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
EOF

# NoNewPrivileges=yes on nginx does not conflict with anything: nginx never
# relies on file capabilities, because the master is already root when it binds.
#
# `~@privileged` is the one hardening option that must NOT be copied from the
# AdGuardHome unit to nginx: systemd's @privileged set contains setuid/setgid/
# setreuid/setresuid/setgroups and all of @chown. Harmless for a User=-style
# service (systemd changes credentials before installing the seccomp filter),
# but FATAL for nginx, whose root master drops each worker to www-data
# in-process, after the filter is live -- denying @privileged kills every
# worker at startup as a respawn loop, not a clean seccomp message.

# =============================================================================
# E5d. Activate both units -- see the shared hardening reference table in
# phases/05-adguardhome-edge.md#e5d for the full AdGuardHome/nginx/Unbound
# comparison this unit design is built from.
# =============================================================================
confirm "About to run: systemctl daemon-reload && systemctl enable --now adguardhome nginx. THIS IS THE MOMENT THIS HOST BECOMES REACHABLE FROM THE PUBLIC INTERNET FOR THE FIRST TIME IN THE ENTIRE BUILD -- nginx will bind public :80/:443 and AdGuardHome will bind public :53/:853, and Phase B's firewall already permits that traffic. Confirm Phase B (firewall), Phase C (Unbound), and Phase D (TLS certs) are already live and correct before proceeding. Proceed?"
systemctl daemon-reload
systemctl enable --now adguardhome nginx
sleep 3
systemctl is-active adguardhome nginx
systemd-analyze security adguardhome.service nginx.service unbound.service
# Exposure labels: <1.0 OK | >=5.0 MEDIUM | >=7.5 EXPOSED | >=9.0 UNSAFE.
# Treat the score as a checklist prompt, not a target: it does not know that
# ProcSubset=pid would cost you the listen backlog.
journalctl -u adguardhome -u nginx -p warning --since '-5min' --no-pager
journalctl -u adguardhome --since '-5min' --no-pager | grep -i 'receive buffer' || true
# quic-go raises the UDP receive buffer with SO_RCVBUF and, when the kernel
# ceiling blocks it, retries with SO_RCVBUFFORCE (needs CAP_NET_ADMIN, which
# this unit does not grant). Do NOT grant CAP_NET_ADMIN to fix a hit here --
# raise net.core.rmem_max in Phase A instead.

# =============================================================================
# Post-start verification deferred from E2, E2a and E3 (each requires the
# service actually running, which it now is).
# =============================================================================
require_cmd ss dig jq

# --- E2 (deferred): the config AdGuardHome rewrote at startup vs. what was written ---
diff -u /tmp/agh.intended /opt/adguardhome/conf/AdGuardHome.yaml || true
grep -n '2160h' /opt/adguardhome/conf/AdGuardHome.yaml && warn "E2: migration clobbered querylog -- interval reads 2160h, not the intended 6h. Your retention settings are not the running settings." || true

# --- E2a (deferred): what the sockets actually are ---
# ss renders an AF_INET6 wildcard socket as '*' when it is NOT v6only and as
# '[::]' when it is. If AdGuardHome reads 0.0.0.0:53 rather than *:53, this
# host has NO usable IPv6 stack -- that is a legitimate state, and it is the
# state in which an AAAA record must not exist.
ss -lntuep '( sport = :53 or sport = :853 or sport = :443 )'
# Does the v6 half serve? Loopback proves the LISTENER without a second host
# and without involving the firewall.
dig  @::1 example.com A +short || true
if command -v kdig >/dev/null 2>&1; then
  kdig @::1 +tls  +tls-sni=dns.example.com example.com A +short || true
  kdig @::1 +quic +tls-sni=dns.example.com example.com A +short || true
else
  warn "kdig not found -- install knot-dnsutils to run the E2a DoT/DoQ loopback checks."
fi

# --- E3 (deferred): the netrc credential actually authenticates against the running control API ---
curl -s --netrc-file /root/.dns-netrc http://127.0.0.1:3000/control/status | jq .

# =============================================================================
# E6. Verification
# =============================================================================
require_cmd systemctl getcap
info "E6 step 1: capability grant landed"
AGH_PID=$(systemctl show -p MainPID --value adguardhome.service)
getpcaps "$AGH_PID"
# expect cap_net_bind_service in the effective/permitted/ambient sets. Output
# formatting varies by libcap version; grep for the name, not the layout.
journalctl -u adguardhome -n 50 --no-pager | grep -i 'permission denied' \
  && warn 'E6 step 1: STILL BROKEN -- E5a fix not applied' || true

info "E6 step 2: exactly the expected sockets, and nothing else"
ss -lntup | grep -vE 'users:\(\("(systemd-resolve)"' | sort -k5
# Expected, and NOTHING beyond it (see phases/05-adguardhome-edge.md#e6 for the
# full annotated table):
#   udp/tcp  *:53           AdGuardHome  plain DNS
#   udp/tcp  *:853          AdGuardHome  DoQ/DoT
#   tcp  127.0.0.1:3000     AdGuardHome  admin UI + control API -- LOOPBACK
#   tcp  127.0.0.1:8053     AdGuardHome  DoH backend            -- LOOPBACK
#   tcp  0.0.0.0:443/[::]:443  nginx     public DoH
#   tcp  0.0.0.0:80/[::]:80    nginx     ACME + well-known
#   udp/tcp 127.0.0.1:5335  unbound      resolver -- LOOPBACK
#   tcp  0.0.0.0:22 (+ [::]:22 dual-stack)  sshd
# FAIL conditions: 3000 or 8053 on any non-loopback address, 443 on loopback,
# or 5335 on a non-loopback address. Assert the ALLOWED address rather than
# grepping for 0.0.0.0: a leaked AdGuardHome web listener appears as *:3000,
# never as 0.0.0.0:3000.
ss -lntupH | awk '{print $5}' | grep -E ':(3000|8053)$' | grep -vE '^127\.0\.0\.1:' \
  && warn 'E6 step 2: FAIL -- web listener is on the wrong address' || true
ss -lntupH | awk '{print $5}' | grep -E '^127\.0\.0\.1:443$' \
  && warn 'E6 step 2: FAIL -- 443 is on loopback (port_https was set to 443, see E4)' || true

info "E6 step 7 (local part): the query path really reaches Unbound"
unbound-control stats_noreset | grep -E 'total.num.queries|num.answer.secure|num.answer.bogus' || true
if command -v kdig >/dev/null 2>&1; then
  # Validation is visible end to end, on every transport (SERVFAIL expected):
  kdig @dns.example.com +tls   dnssec-failed.org A | grep 'status:' || true
  kdig @dns.example.com +https dnssec-failed.org A | grep 'status:' || true
  kdig @dns.example.com +quic  dnssec-failed.org A | grep 'status:' || true
  # Fingerprinting is refused (REFUSED, from serveBlockedResponse, never SERVFAIL):
  kdig @dns.example.com +tls -c CH -t TXT version.bind | grep 'status:' || true
fi

# No fallback path exists: with the validator stopped, nobody else may answer.
# This BRIEFLY interrupts live DNS resolution on this host -- it is a deliberate
# drill from the source plan, not incidental downtime.
confirm "About to run: systemctl stop unbound (briefly, to prove there is no fallback resolver — E6 step 7 drill), then systemctl start unbound. This interrupts live DNS resolution on this host for a few seconds. Proceed?"
systemctl stop unbound
dig @127.0.0.1 example.com A +noall +comments || true   # MUST be SERVFAIL, never an answer, once <PUBLIC_IP> is substituted for a real remote check
systemctl start unbound
UQ2=$(unbound-control stats_noreset | grep -E 'total.num.queries' || true)
info "unbound total.num.queries after restart: $UQ2"

info "E6 step 8: config survived first start"
grep -n '^schema_version' /opt/adguardhome/conf/AdGuardHome.yaml
awk '/^querylog:/,/^[a-z_]+:/'   /opt/adguardhome/conf/AdGuardHome.yaml
awk '/^statistics:/,/^[a-z_]+:/' /opt/adguardhome/conf/AdGuardHome.yaml
# querylog.interval must read 6h. 2160h means a migration ran and overwrote the
# block -- your retention settings are not the running settings.
curl -s --netrc-file /root/.dns-netrc 127.0.0.1:3000/control/stats/config \
  | jq '{enabled, interval}'
# enabled must read TRUE here: that is the shipped default and what Phase I's
# collector expects on a stock build. False has exactly two causes: a
# migration clobbered the block (a bug -- fix it), or an operator deliberately
# adopted one of Phase Q's opt-in postures (legitimate -- Phase I then emits
# "metrics unavailable by policy" instead of reporting the daemon down).

# --- E6 steps 3, 4, 5, 6 and 9 MUST be run from a DIFFERENT host (step 9 from
# a DUAL-STACK one) -- every DoH failure mode in E4 and every address-family
# failure in E2a passes when tested from the box itself. This script therefore
# does NOT execute them here; it prints the exact commands from
# phases/05-adguardhome-edge.md#e6 for the operator to run remotely, with
# dns.example.com and <PUBLIC_IP> exactly as the source plan leaves them.
warn "E6 steps 3, 4, 5, 6 and 9 must be run from a DIFFERENT host (step 9 from a dual-stack one). Printing the reference commands below rather than executing them here -- do not trust a pass observed from this box for any of them."
cat << 'REMOTE_VERIFICATION'

# --- 3. DoH works FROM OUTSIDE (this is the check E4 exists for) ---
Q=$(printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
     | base64 | tr '+/' '-_' | tr -d '=')
curl -si -H 'accept: application/dns-message' \
  "https://dns.example.com/dns-query?dns=$Q" | head -3
# PASS: HTTP/2 200 + content-type: application/dns-message
curl -s -o /dev/null -w 'POST -> %{http_code}\n' -X POST \
  -H 'content-type: application/dns-message' \
  --data-binary @<(printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01') \
  https://dns.example.com/dns-query
kdig @dns.example.com +https example.com A +short

# --- 4. DoT and DoQ. Ubuntu 24.04 ships knot-dnsutils 3.3.x, which HAS +quic;
#        22.04's 3.1.x does not and fails with an unknown-option error that
#        reads like a DoQ outage. Check the version before believing a failure.
kdig -V
kdig @dns.example.com +tls  example.com A +short
kdig @dns.example.com +quic example.com A +short

# --- 5. The admin UI must NOT be reachable publicly, by any route ---
for p in /control/status /control/stats /control/querylog /login.html \
         /install.html /apple/doh.mobileconfig / ; do
  printf '%-28s -> ' "$p"
  curl -s -o /dev/null -w '%{http_code}\n' "https://dns.example.com$p"
done
# Every one must be 404. A 200 or a 302 on any of them is a stop-the-build defect.
curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 http://<PUBLIC_IP>:3000/ \
  || echo 'OK: :3000 not reachable (connection refused/timed out)'
curl -sk -o /dev/null -w '%{http_code}\n' --max-time 5 https://<PUBLIC_IP>:8053/ \
  || echo 'OK: :8053 not reachable'

# Unknown SNI on 443 gets no handshake and no certificate:
openssl s_client -connect dns.example.com:443 -servername evil.example.net </dev/null 2>&1 \
  | grep -qi 'unrecognized name\|handshake failure' \
  && echo 'OK: ssl_reject_handshake active'

# --- 6. XFF and Host cannot be forged into a different identity ---
curl -s -o /dev/null \
  -H 'accept: application/dns-message' \
  -H 'X-Forwarded-For: 203.0.113.10' \
  -H 'CF-Connecting-IP: 203.0.113.10' \
  -H 'True-Client-IP: 203.0.113.10' \
  -H 'Host: mallory.dns.example.com' \
  "https://dns.example.com/dns-query?dns=$Q"
curl -s --netrc-file /root/.dns-netrc \
  'http://127.0.0.1:3000/control/querylog?limit=3' \
  | jq -r '.data[] | "\(.client) \(.client_id // "-") \(.question.name)"'
# PASS: client is your real source address, masked to /16 by
#       anonymize_client_ip (e.g. 203.0.0.0), and client_id is "-".
# FAIL: client is 203.0.113.10, or client_id is "mallory".

# --- 7 (the <PUBLIC_IP> half, run from a different host alongside 3-6/9) ---
dig @<PUBLIC_IP> example.com A +short >/dev/null
dig @<PUBLIC_IP> dnssec-failed.org A +noall +comments   # SERVFAIL
dig @<PUBLIC_IP> example.com A +noall +comments         # while unbound is briefly stopped: MUST be SERVFAIL, never an answer

# --- 9. EVERY ADVERTISED ADDRESS ANSWERS ON EVERY TRANSPORT ---
# Run from a DUAL-STACK host. The address list comes from DNS, not from a
# <PUBLIC_IP> variable, so this fails exactly when a published record has no
# listener behind it.
for A in $(dig +short dns.example.com A    @1.1.1.1) \
         $(dig +short dns.example.com AAAA @1.1.1.1); do
  case $A in *:*) H="[$A]" ;; *) H="$A" ;; esac
  printf '%-40s Do53=%-16s DoT=%-16s DoQ=%-16s DoH=%s\n' "$A" \
    "$(dig  +short +timeout=3 +tries=1 @"$A" example.com A | head -1)" \
    "$(kdig +short +timeout=3 +retry=0 +tls  +tls-sni=dns.example.com \
            @"$A" example.com A 2>/dev/null | head -1)" \
    "$(kdig +short +timeout=3 +retry=0 +quic +tls-sni=dns.example.com \
            @"$A" example.com A 2>/dev/null | head -1)" \
    "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            --resolve "dns.example.com:443:$H" \
            -H 'accept: application/dns-message' \
            "https://dns.example.com/dns-query?dns=$Q")"
done
# PASS: every column populated on every row, DoH=200. curl needs >= 7.57 for a
# bracketed IPv6 literal in --resolve; 24.04 ships 8.5.
# FAIL: a blank column anywhere -- almost always the whole AAAA row except DoH.
# Fix the listener or withdraw the AAAA. Never leave a published address that
# answers on only some transports.
REMOTE_VERIFICATION

# Phase F is retired (v1's Python cache-warmer daemon; Unbound's prefetch does
# the same job in-process). Nothing here depends on it.

info "Phase E complete. This host is now serving public DNS if you proceeded through the confirm() gates above."
echo
echo "=== How to confirm this phase actually worked ==="
echo "Local (already run above): systemd-analyze security adguardhome.service nginx.service unbound.service"
echo "Local (already run above): ss -lntup | grep -vE 'users:\\(\\(\"(systemd-resolve)\"'  -- must match the table in E6 step 2, nothing beyond it"
echo "Local (already run above): journalctl -u adguardhome -u nginx -p warning --since '-5min' --no-pager"
echo "REMOTE, from a different host (dual-stack for the AAAA sweep), run the block printed above from phases/05-adguardhome-edge.md E6 steps 3-6 and 9:"
echo "  curl -si -H 'accept: application/dns-message' \"https://dns.example.com/dns-query?dns=<Q>\"   # expect HTTP/2 200"
echo "  kdig @dns.example.com +tls example.com A +short   ;   kdig @dns.example.com +quic example.com A +short"
echo "  every path under https://dns.example.com/{control,login.html,install.html,...} must 404"
