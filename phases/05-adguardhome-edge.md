[Plan index](../dns-server-plan.md) · [Previous: TLS Certificates](./04-tls-certificates.md) · [Next: Retired Warmer, Log Rotation, Validation](./06-logging-and-validation.md)

---

**On this page**

- [PHASE E: AdGuardHome and the Public Edge](#phase-e-adguardhome-and-the-public-edge)
  - [E1. Install a pinned release with an integrity check](#e1-install-a-pinned-release-with-an-integrity-check)
  - [E2. AdGuardHome.yaml](#e2-adguardhomeyaml)
  - [E3. Admin credentials](#e3-admin-credentials)
  - [E4. nginx as the public DoH front](#e4-nginx-as-the-public-doh-front)
  - [E5. systemd units, and the shared hardening reference](#e5-systemd-units-and-the-shared-hardening-reference)
  - [E6. Verification](#e6-verification)

---

## PHASE E: AdGuardHome and the Public Edge

AdGuardHome is the client-facing DNS server. It does not resolve and it does not validate — every query goes to Unbound on 127.0.0.1:5335 (Phase C), which is the only recursor and the only DNSSEC validator in this design. AdGuardHome's job is transport termination (Do53, DoT, DoQ), per-client policy, and the edge cache.

The public HTTPS edge is nginx, not AdGuardHome. E4 explains why in detail; the short version is that AdGuardHome's HTTPS listener inherits its *bind address* from `http.address` and shares its request mux with the admin UI, so "just set `port_https: 443`" produces either a loopback-only DoH endpoint that silently never works from the internet, or a publicly exposed login page.

### E1. Install a pinned release with an integrity check

Do not resolve `releases/latest` at install time. A build you did not choose is a build you cannot roll back to, and the config schema migration on first start is version-dependent (E2). Pin an exact tag, verify the published checksum, and install into a versioned directory behind a `current` symlink so Phase M's upgrade/rollback procedure has something to move.

```bash
AGH_VER=v0.107.78          # pin deliberately; see Phase M for the upgrade path
BASE=/opt/adguardhome
# `validate` is the SCRATCH work directory for every `--check-config` run in this
# plan (E2 here, Phase H's pre-change gate, Phase K's restore drill, Phase M's
# upgrade wrapper, Phase O's Ansible validate= hook). It is created HERE, at
# install time, because those consumers all assume it already exists.
# --check-config leaves artifacts behind, so it must never be pointed at the live
# work/ tree, and it must never run as root -- root-owned artifacts under an
# adguardhome-owned tree break the next real start.
install -d "$BASE"/{conf,work,releases,validate} /var/log/adguardhome
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT; cd "$TMP"

curl -fsSLO "https://github.com/AdguardTeam/AdGuardHome/releases/download/${AGH_VER}/AdGuardHome_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/AdguardTeam/AdGuardHome/releases/download/${AGH_VER}/checksums.txt"
grep ' AdGuardHome_linux_amd64.tar.gz$' checksums.txt | sha256sum -c -
# MUST print "AdGuardHome_linux_amd64.tar.gz: OK". Anything else: stop.

install -d "$BASE/releases/$AGH_VER"
tar -xzf AdGuardHome_linux_amd64.tar.gz -C "$BASE/releases/$AGH_VER" --strip-components=1
ln -sfn "$BASE/releases/$AGH_VER" "$BASE/current"
chown -R adguardhome:adguardhome "$BASE" /var/log/adguardhome
chmod 0750 "$BASE/conf" "$BASE/validate" /var/log/adguardhome
```

`checksums.txt` is served from the same origin as the tarball, so it proves the download was not corrupted or truncated — it does not prove the release was not tampered with at source. That is the honest limit of this check; AdGuardTeam publishes no detached signature for these artifacts, so there is nothing stronger to do here.

**Do not run `setcap` on the binary.** The v1 plan did, and it cannot work under the unit in E5 — see canonical decision 8 and the explanation in E5. This is a whole-document rule, not a Phase E preference: **no phase grants a capability with `setcap`**, every capability comes from `AmbientCapabilities=` in the unit, and that includes Phase M's upgrade procedure, which must not reintroduce it when it swaps the `current` symlink. The single `setcap` invocation anywhere in this plan is the *removal* in E5a, which strips a stale file capability left behind on a host built from the v1 plan.

```bash
"$BASE/current/AdGuardHome" --version
getcap "$BASE/current/AdGuardHome"    # expect: no output
ls -ld "$BASE/validate"
# expect: drwxr-x--- adguardhome adguardhome -- the scratch --check-config work dir.
# Every phase that runs a config gate assumes this exists; if it does not, the
# gate either fails or silently validates against the live work/ tree.
```

### E2. AdGuardHome.yaml

Three structural facts drive the file below, all verified against AdGuardHome source:

1. **`schema_version` must be present and correct.** `internal/configmigrate/migrator.go` reads a missing `schema_version` as **0** and runs the entire migration chain 0 → current. The v1 plan's file has no `schema_version` and writes `dns.querylog_interval: 24h`; `internal/configmigrate/v12.go` reads that field as an *integer number of days*, so the migration aborts and **AdGuardHome refuses to start**: `failed to parse configuration file err="migrating schema 11 to 12: unexpected type of \"querylog_interval\": string"`. That is a boot failure, not a retention drift.
2. **`querylog:` and `statistics:` are top-level sections**, siblings of `dns:` and `tls:`, since v0.107.24. If you write them at the top level *without* `schema_version`, `v15.go` does `diskConf["querylog"] = qlog` **unconditionally** with `interval: "2160h"` and drops `dir_path` — your retention settings are replaced by a 90-day default. Getting `schema_version` right is what makes the modern layout survive.
3. **`anonymize_client_ip` stays under `dns:`.** It did not move with the querylog migration. It is applied at ingestion, in place, before the address reaches either the query log or the statistics database — masking to **/16 for IPv4 and /48 for IPv6** (not /24, not /112). The consequence is in E2's annotations and in Phase J: anything that reads a client address out of the query log is reading a masked, wrong address.

Confirm the schema number for the version you actually pinned before writing the file:

```bash
curl -s "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/${AGH_VER}/internal/configmigrate/configmigrate.go" \
  | grep LastSchemaVersion
# LastSchemaVersion uint = 34   -> use 34 below
```

```bash
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
  # Plain Do53, DoT and DoQ bind here. Not the web listener.
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
```

Two things about this file that are not obvious:

- **`stats.db` exists whether or not statistics are enabled.** `stats.New` calls `openDB()` unconditionally, before it looks at `Enabled`, and `Close()` writes the current unit on shutdown. Asserting its *absence* is a test that can never pass. What it holds beyond client counts is a **per-domain request-count table** — a domain-history artifact that client anonymisation does not touch. It lives at `statistics.dir_path`, i.e. **`/var/lib/adguardhome/stats`** on this build, *not* under `/opt/adguardhome/work/data` where the v1 layout left it; the query log is likewise at `/var/log/adguardhome/querylog`. Those two paths are the real sensitive-data inventory for this host — **see Phase Q**, which reasons about exactly these paths, and **see Phase K** for why neither may enter the backup repository.
- **AdGuardHome rewrites this file at startup**, not at shutdown (`internal/home/home.go` → `config.write`). So the authoritative statement of what your config means on this build is the file after first start, not the file you wrote. Diff them, and treat any change to `querylog:` or `statistics:` as a migration having run — your settings are not the running settings.

```bash
cp -a /opt/adguardhome/conf/AdGuardHome.yaml /tmp/agh.intended
# As the adguardhome user, against the E1 scratch validate directory -- NEVER as
# root and NEVER against the live work/ tree. --check-config writes artifacts;
# root-owned ones under an adguardhome-owned tree break the next real start.
# This is the same invocation shape Phase H's gate, Phase K's drill, Phase M's
# upgrade wrapper and Phase O's Ansible validate= hook use.
runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
  -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate; echo "exit=$?"
# after E5 starts the service:
diff -u /tmp/agh.intended /opt/adguardhome/conf/AdGuardHome.yaml || true
grep -n '2160h' /opt/adguardhome/conf/AdGuardHome.yaml && echo 'FAIL: migration clobbered querylog'
```

### E3. Admin credentials

The admin UI is the whole control API: `/control/*` can rewrite upstreams, disable DNSSEC, and dump the query log. It is loopback-only (E4) and reached over an SSH tunnel (**see Phase P**), so the password guards a path that already requires host access — but AdGuardHome's failed-login lockout behaviour varies by version, so size the password for **unlimited online guessing**.

```bash
apt install -y apache2-utils
PW=$(openssl rand -base64 24)
printf 'STORE THIS IN YOUR PASSWORD MANAGER NOW: %s\n' "$PW"
htpasswd -bnBC 12 "" "$PW" | tr -d ':\n'; echo
unset PW
# Paste the $2y$12$... string into users[0].password in AdGuardHome.yaml.
```

Print the password, do not pipe `$(openssl rand ...)` straight into `htpasswd` — the common one-liner consumes it in a subshell and leaves you a hash you cannot authenticate against. Cost 12 is roughly 250 ms per login attempt on 2 vCPU, which is also the throttle on guessing.

File permissions, for a config owned by an unprivileged process:

```bash
chown adguardhome:adguardhome /opt/adguardhome/conf/AdGuardHome.yaml
chmod 0600 /opt/adguardhome/conf/AdGuardHome.yaml
# `install -d`, not `chmod`: AdGuardHome creates work/data itself on FIRST START,
# which has not happened yet at this point in the build order -- a bare chmod here
# fails with "No such file or directory". install -d creates it with the right
# owner and mode if absent and re-applies both if it already exists, so this line
# is correct whether or not the service has ever run.
install -d -o adguardhome -g adguardhome -m 0700 /opt/adguardhome/work/data
```

`0600 adguardhome:adguardhome` is the tightest setting that still works: AdGuardHome rewrites this file at startup and on every config change, so it cannot be root-owned read-only. `UMask=0077` in the unit (E5) keeps everything the process creates at the same level.

Never put credentials on a command line — `/proc/PID/cmdline` is world-readable, so `curl -u admin:password` leaks to every local account for the life of the request. Use a netrc file for the Phase I health checks:

```bash
install -m 0600 /dev/null /root/.dns-netrc
printf 'machine 127.0.0.1 login admin password %s\n' 'THE_PASSWORD' > /root/.dns-netrc
curl -s --netrc-file /root/.dns-netrc http://127.0.0.1:3000/control/status | jq .
```

**The bcrypt hash must not reach the Phase K backup in plaintext.** `AdGuardHome.yaml` is the natural thing to version, and it carries `users[0].password`. A git object store keeps it forever, on whatever host the repository is mirrored to, at whatever permissions that host uses — and a 2019-era bcrypt hash is a perfectly good offline cracking target. **See Phase K** for the sanitisation filter and the encryption requirement; do not add this file to a backup that has not been through it.

### E4. nginx as the public DoH front

**Why AdGuardHome is not on 443 directly.** Two facts about AdGuardHome's web server, both verified in source, make the obvious configuration wrong in opposite directions:

1. The HTTPS listener inherits its **host** from `http.address`, not from `dns.bind_hosts`. `internal/home/home.go` sets `BindAddr: config.HTTPConfig.Address`, and `internal/home/web.go`'s `serveTLS()` computes `addr := netip.AddrPortFrom(web.conf.BindAddr.Addr(), portHTTPS)`. So `http.address: 127.0.0.1:3000` plus `tls.port_https: 443` binds **127.0.0.1:443** — the firewall has TCP/443 open for a socket that only exists on loopback, public DoH silently never works, and every DoH validation step fails while AdGuardHome reports itself healthy.
2. The admin UI and `/dns-query` **share one handler**. `internal/home/dns.go`'s `registerDoHHandlers` does `mux.Handle(route, dnsServer)` on the same mux `web.wrapMux(logger)` serves. So the naive fix — `http.address: 0.0.0.0:3000` — publishes `/control/*`, `/login.html`, `/install.html` and `/apple/*.mobileconfig` on the same listener as DoH.

nginx resolves both: it terminates public TLS, proxies **only** `/dns-query`, and returns 404 for everything else. AdGuardHome's web listeners stay on loopback. DoT (TCP/853) and DoQ (UDP/853) are served by `dnsforward` bound to `dns.bind_hosts` and are **not** affected by any of this — they go straight to AdGuardHome, no nginx involved.

Proxying to AdGuardHome's **HTTPS** backend on 127.0.0.1:8053 rather than the plain-HTTP mux on :3000 buys one concrete thing beyond defence in depth: `internal/dnsforward/clientid.go`'s `clientServerNameFromHTTP` returns `r.TLS.ServerName` when `r.TLS != nil`, and falls back to `netutil.SplitHost(r.Host)` only when it is nil. Behind a plain-HTTP proxy, a forwarded `Host:` header therefore becomes the ClientID input. With a real TLS leg to the backend, that path is closed structurally and the ClientID can only come from the URL route.

```bash
apt install -y nginx
nginx -v    # nginx/1.24.0 on Ubuntu 24.04
```

**Client identity snippet.** Every proxied location must include this. dnsproxy's `remoteAddr` (`proxy/serverhttps.go`) checks headers in the order `CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, `X-Forwarded-For`, and for XFF it takes the **first** comma-separated element — the client-controlled one. Appending with `$proxy_add_x_forwarded_for` lets a client prepend a forged address that then wins.

```bash
install -d /etc/nginx/snippets
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
```

If a CDN is ever put in front, `trusted_proxies` must list the CDN egress ranges and nginx must **not** strip `CF-Connecting-IP` — but then the CDN, not you, decides who your clients are. For this design, do not.

**The server itself.**

```bash
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
rm -f /etc/nginx/sites-enabled/default    # the packaged catch-all binds :80 and :[::]:80
nginx -t

# Exactly one :80 server and exactly one webroot. Re-run this after Phase Q adds
# its locations, and after any later nginx change: `nginx -t` rejects a second
# *default* server on :80, but a second non-default :80 block is accepted and
# then silently loses every request whose Host does not match it.
grep -rn 'listen .*80' /etc/nginx/ | grep -v '#'
# expect: exactly the two lines from the block above -- 80 default_server and
#         [::]:80 default_server. Anything else is the Phase Q merge going wrong.

# The two directives Phase Q depends on. Iterate conf.d/*.conf, NOT sites-enabled:
# every server block on this host lives in conf.d, and `rm -f sites-enabled/default`
# above leaves that directory empty -- a loop over it inspects nothing and passes
# no matter what is broken.
for f in /etc/nginx/conf.d/*.conf; do
  printf '%s: server_tokens=%s charset=%s\n' "$f" \
    "$(grep -c 'server_tokens off;' "$f")" "$(grep -c 'charset utf-8;' "$f")"
done
# expect for doh.conf: server_tokens=2 (the :443 and :80 blocks) charset=1 (:80 only).
# Phase Q adds the second `charset utf-8;` to the :443 block when it publishes the
# HTTPS copy of security.txt; shipping it here too would be a duplicate directive.
```

`proxy_pass https://agh_doh/dns-query$is_args$args;` — the `$is_args$args` suffix is mandatory. When a URI is given on `proxy_pass`, nginx replaces the original request URI wholesale, and a DoH GET's `?dns=<base64url>` is silently dropped without it. Every GET-mode client (which is most of them) breaks, and it breaks as a malformed-query error rather than a routing error, so it is slow to diagnose.

**What Phase P builds on top of this.** The `X-Forwarded-For` overwrite and the pinned `Host` are what make Phase P's IP allowlist mean anything: in allowlist mode AdGuardHome blocks only when *both* the IP check and the ClientID check block, so a forged `CF-Connecting-IP` matching an `allowed_clients` entry would admit the request on that basis alone. The `location = /dns-query` block is also the anchor Phase P replaces with a token- or ClientID-carrying regex location. **See Phase P** for those; do not add them here.

### E5. systemd units, and the shared hardening reference

#### E5a. Why `setcap` cannot work

The v1 plan set `NoNewPrivileges=yes` in the unit *and* ran `setcap 'cap_net_bind_service=+ep'` on the binary. These are mutually exclusive. `systemd.exec(5)` on `NoNewPrivileges=`: the process "can never gain new privileges through `execve()` (e.g. via setuid or setgid bits, or filesystem capabilities)". The kernel implements this in `security/commoncap.c` (`cap_bprm_creds_from_file`): with `LSM_UNSAFE_NO_NEW_PRIVS` set, the new permitted set is intersected with the old one — empty, for `User=adguardhome` — so AdGuardHome execs with no `CAP_NET_BIND_SERVICE` and dies with `listen udp :53: bind: permission denied`.

Ambient capabilities are applied by PID 1 *before* `execve`, so `no_new_privs` does not block them. That is the fix.

Clearing the stale file capability is **mandatory, not hygiene**: the same kernel function does `if (has_fcap || id_changed) cap_clear(new->cap_ambient);`, and `has_fcap` is set by `get_file_caps()` regardless of `no_new_privs`. A leftover file capability therefore *clears the ambient set at execve* and the fix silently fails.

The command below is the **only** `setcap` in this entire plan, and it only ever *removes*. No phase grants a capability with `setcap` — every capability in this design comes from `AmbientCapabilities=` in the unit (canonical decision 8), and Phase M's upgrade procedure must not reintroduce a `setcap` step when it repoints the `current` symlink at a new release. Treat it as a repair for a host built from the v1 plan; on a clean build `getcap` prints nothing and the removal is a no-op.

```bash
# REMOVAL ONLY -- this is a v1-upgrade repair, never a grant. `setcap -r` strips
# the stale file capability a host built from the v1 plan carries; it does not and
# must not give AdGuardHome any capability. Every capability in this design comes
# from AmbientCapabilities= in the unit (E5b), and nothing anywhere in this plan --
# including Phase M's upgrade procedure -- may add a `setcap <cap>=+ep` step. On a
# clean build this is a no-op.
setcap -r /opt/adguardhome/current/AdGuardHome 2>/dev/null || true
getcap /opt/adguardhome/current/AdGuardHome     # expect: no output
```

Do not reach for `PrivateUsers=yes` on this unit: `CAP_NET_BIND_SERVICE` held only inside a user namespace does not authorise binding ports below 1024 in the host network namespace, so it reintroduces the identical failure. Socket activation would avoid the capability entirely, but AdGuardHome does not implement `LISTEN_FDS`, so it is not available.

#### E5b. `adguardhome.service`

```bash
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
```

**Memory ceilings are deliberately absent from this unit, and must not be added to it.** `MemoryHigh=`, `MemoryMax=`, `OOMScoreAdjust=`, the swapfile and `vm.swappiness` have exactly one owner in this plan: **Phase A6**, which sets AdGuardHome's ceiling next to Unbound's and next to the host's swap configuration, so that the sum can be checked against the RAM the box actually has. Phase E ships no ceiling of its own, and neither does Phase N — a second drop-in with its own `MemoryMax=` is how a host ends up with two numbers, one of which is silently wrong. The reasoning for the chosen values, and the measure-then-set procedure behind them, live in Phase A6 as well; the short version of why they are chosen rather than guessed is that a guessed cgroup limit on a service with `Restart=always` converts an OOM into a cache-reloading restart loop, which costs more memory pressure than it saves. If E2's `cache_size` changes, change AdGuardHome's ceiling in **Phase A6's** file, not here.

#### E5c. `nginx.service`

Ubuntu's packaged unit is minimal. Override it rather than editing it, so a package upgrade cannot silently revert the hardening.

```bash
install -d /etc/systemd/system/nginx.service.d
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
```

`NoNewPrivileges=yes` on nginx does not conflict with anything: nginx never relies on file capabilities, because the master is already root when it binds.

**`~@privileged` is the one hardening option that must NOT be copied from the AdGuardHome unit to nginx.** systemd's `@privileged` set (`src/shared/seccomp-util.c`) contains `setuid`, `setgid`, `setreuid`, `setresuid`, `setgroups` and the whole `@chown` group. For a `User=`-style service that is harmless, because systemd changes credentials in the forked child *before* installing the seccomp filter. nginx is different: the master stays root and drops each **worker** to `www-data` with an in-process `setuid()` long after the filter is installed. Denying `@privileged` therefore kills every worker at startup, and the failure surfaces as workers respawning in a loop rather than as a seccomp message. `@resources` is also absent from the deny list here, so `worker_priority` and `worker_cpu_affinity` keep working; add it back only if you use neither.

#### E5d. Shared hardening reference

This table is the source of truth for every unit in this document, including Phase C's Unbound unit. "Go" means AdGuardHome; the same reasoning applies to any Go daemon added later.

| Option | AdGuardHome (Go) | nginx | Unbound (C) | Notes |
|---|---|---|---|---|
| `NoNewPrivileges=yes` | yes | yes | yes | **Nullifies file capabilities across `execve`.** Any `setcap` approach dies here. See E5a. |
| `AmbientCapabilities=CAP_NET_BIND_SERVICE` | **required** | not needed | not needed | AGH binds 53/853 as an unprivileged user. nginx binds as root. Unbound binds 127.0.0.1:5335 (>1024). |
| `CapabilityBoundingSet=` | `CAP_NET_BIND_SERVICE` | see E5c | empty | Must contain every ambient capability or the ambient grant is dropped. On an already-unprivileged process with `NoNewPrivileges`, this is belt-and-braces — it caps what could be *gained*, not what is held. |
| `PrivateUsers=yes` | **BREAKS** | **BREAKS** | safe | The low-port check is `ns_capable()` against the init netns user_ns; a namespaced capability does not authorise a host-netns bind below 1024. Safe on Unbound only because its port is high. |
| `ProcSubset=pid` | **BREAKS TUNING** | safe | safe | Hides `/proc/sys`. Go's `net` package reads `/proc/sys/net/core/somaxconn` to size the listen backlog and silently falls back to **128** when the read fails, discarding Phase A's `net.core.somaxconn`. Leave at the default on any Go service. |
| `ProtectProc=invisible` | yes | yes | yes | Unaffected by the above; keep it. |
| `MemoryDenyWriteExecute=yes` | yes | conditional | yes | Fine for pure Go (`CGO_ENABLED=0`; quic-go is not a JIT) and for C without text relocations. **nginx: only while `pcre_jit` is off.** Drop it for any service that gains a ctypes/libffi/JIT dependency. |
| `RestrictAddressFamilies=` | `AF_INET AF_INET6 AF_UNIX AF_NETLINK` | same | same | **AF_NETLINK** is required: Go's `net.Interfaces()` and glibc's interface enumeration use netlink. **AF_UNIX** is required by nginx's master/worker channel and by any journal/syslog handler added later; the cost of including it is nil. |
| `SystemCallFilter=@system-service` | yes | yes | yes | The recommended allow-list baseline for a system daemon. |
| `SystemCallFilter=~@privileged` | yes | **BREAKS** | yes | `@privileged` contains `setuid`/`setgid`/`setreuid`/`setresuid`/`setgroups` and all of `@chown`. Harmless for a `User=` service (systemd changes credentials before installing the filter) but **fatal for nginx**, whose root master drops each worker to `www-data` in-process, after the filter is live. Deny the specific groups instead — see E5c. |
| `SystemCallFilter=~@resources` | yes | conditional | yes | Blocks `setpriority`/`sched_setaffinity`; incompatible with nginx's `worker_priority` and `worker_cpu_affinity`. |
| `SystemCallErrorNumber=EPERM` | burn-in | burn-in | burn-in | Default action is **SIGSYS termination**. During burn-in this turns a missing syscall into a logged `EPERM` instead of a mystery crash-loop. Remove it once the service has run clean for a week. |
| `IPAddressDeny=any` + `IPAddressAllow=` | **BREAKS** | **BREAKS** | see Phase C | The filter applies to **ingress as well as egress**, so it drops inbound client connections on any public listener. Usable only on services with no public listener. |
| `ProtectSystem=strict` + `ReadWritePaths=` | yes | yes | yes | AGH **must** have `/opt/adguardhome` writable — it rewrites its own config at startup and on migration. nginx needs `/var/log/nginx`, `/var/lib/nginx`, `/run`. |
| `UMask=0077` | yes | yes | yes | Default is 0022, which makes query logs and cache files world-readable by any local account. |
| `RestrictNamespaces` / `RestrictRealtime` / `LockPersonality` / `RemoveIPC` / `ProtectClock` / `ProtectHostname` / `ProtectKernel*` / `ProtectControlGroups` / `DevicePolicy=closed` / `PrivateDevices` | yes | yes | yes | No known interaction with any service here. |
| `Restart=always` + `RestartSec=5` + `StartLimitIntervalSec=300` + `StartLimitBurst=10` | yes | yes | yes | **Canonical tuple for every unit in this plan** — Phase C4's Unbound unit and Phase N's drop-in carry exactly these four values; do not let any unit diverge. systemd's stock 5-in-10 s leaves a crash-looping unit dead forever; a *zero* limit means the unit can never reach `failed` at all. With backoff in play the limit is rarely reached anyway, so alert on restart churn rather than on `failed` (Phase I notifier, Phase N detector). |
| `MemoryHigh=` / `MemoryMax=` / `OOMScoreAdjust=` | **see Phase A6** | **see Phase A6** | **see Phase A6** | Single owner. Memory ceilings, the swapfile and `vm.swappiness` are set in one place so the total can be checked against real RAM. No unit or drop-in in Phase C, E or N carries its own ceiling. |
| `RestartSteps=` / `RestartMaxDelaySec=` | optional | optional | optional | systemd **>= 254**; Ubuntu 24.04 ships 255. Confirm with `systemctl --version` before relying on them; they are a silent no-op on older systemd. |

**What breaks QUIC specifically** (DoQ on UDP/853, and HTTP/3 if it is ever enabled): nothing in the table above, with one operational caveat. quic-go raises the UDP receive buffer with `SO_RCVBUF` and, when the kernel ceiling blocks it, retries with `SO_RCVBUFFORCE`, which needs `CAP_NET_ADMIN`. Under the bounding set here that retry fails and quic-go logs a warning about being unable to increase the receive buffer, with real packet loss under load. **Do not grant `CAP_NET_ADMIN` to fix it** — raise `net.core.rmem_max` in Phase A instead, which removes the need for the forced path. Treat the exact warning text as version-dependent; grep for `receive buffer` rather than an exact string.

```bash
systemctl daemon-reload
systemctl enable --now adguardhome nginx
sleep 3
systemctl is-active adguardhome nginx
systemd-analyze security adguardhome.service nginx.service unbound.service
# Exposure labels: <1.0 OK | >=5.0 MEDIUM | >=7.5 EXPOSED | >=9.0 UNSAFE.
# Treat the score as a checklist prompt, not a target: it does not know that
# ProcSubset=pid would cost you the listen backlog.
journalctl -u adguardhome -u nginx -p warning --since '-5min' --no-pager
journalctl -u adguardhome --since '-5min' --no-pager | grep -i 'receive buffer'
```

### E6. Verification

Steps 3 through 6 must be run **from a different host**. Every DoH failure mode described in E4 passes when tested from the box itself.

```bash
# --- 1. The capability grant actually landed ---
getpcaps $(systemctl show -p MainPID --value adguardhome.service)
# expect cap_net_bind_service in the effective/permitted/ambient sets.
# Output formatting varies by libcap version; grep for the name, not the layout.
journalctl -u adguardhome -n 50 --no-pager | grep -i 'permission denied' \
  && echo 'STILL BROKEN: E5a fix not applied'

# --- 2. Exactly the expected sockets, and nothing else ---
ss -lntup | grep -vE 'users:\(\("(systemd-resolve)"' | sort -k5
# Expected, and NOTHING beyond it:
#   udp  0.0.0.0:53     AdGuardHome     plain DNS
#   tcp  0.0.0.0:53     AdGuardHome     plain DNS
#   udp  0.0.0.0:853    AdGuardHome     DoQ  (RFC 9250)
#   tcp  0.0.0.0:853    AdGuardHome     DoT
#   tcp  127.0.0.1:3000 AdGuardHome     admin UI + control API  -- LOOPBACK
#   tcp  127.0.0.1:8053 AdGuardHome     DoH backend             -- LOOPBACK
#   tcp  0.0.0.0:443    nginx           public DoH
#   tcp  0.0.0.0:80     nginx           ACME + /.well-known
#   udp  127.0.0.1:5335 unbound         resolver                -- LOOPBACK
#   tcp  127.0.0.1:5335 unbound
#   tcp  0.0.0.0:22     sshd
# FAIL conditions: anything on 0.0.0.0:3000, anything on 0.0.0.0:8053,
# anything on 127.0.0.1:443, or 5335 on a non-loopback address.
ss -lntup | grep -E '0\.0\.0\.0:(3000|8053)|127\.0\.0\.1:443' \
  && echo 'FAIL: web listener is on the wrong address'

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

# --- 7. The query path really reaches Unbound, and nothing routes around it ---
unbound-control stats_noreset | grep -E 'total.num.queries|num.answer.secure|num.answer.bogus'
dig @<PUBLIC_IP> example.com A +short >/dev/null
unbound-control stats_noreset | grep -E 'total.num.queries'   # must have increased

# Validation is visible end to end, on every transport:
dig  @<PUBLIC_IP>            dnssec-failed.org A +noall +comments   # SERVFAIL
kdig @dns.example.com +tls   dnssec-failed.org A | grep 'status:'   # SERVFAIL
kdig @dns.example.com +https dnssec-failed.org A | grep 'status:'   # SERVFAIL
kdig @dns.example.com +quic  dnssec-failed.org A | grep 'status:'   # SERVFAIL

# No fallback path exists: with the validator stopped, nobody else may answer.
systemctl stop unbound
dig @<PUBLIC_IP> example.com A +noall +comments   # MUST be SERVFAIL, never an answer
systemctl start unbound

# Fingerprinting is refused (REFUSED on TCP/DoT/DoH/DoQ, dropped on UDP -- both
# come from serveBlockedResponse; neither is SERVFAIL):
kdig @dns.example.com +tls -c CH -t TXT version.bind | grep 'status:'   # REFUSED

# --- 8. Config survived first start ---
grep -n '^schema_version' /opt/adguardhome/conf/AdGuardHome.yaml
awk '/^querylog:/,/^[a-z_]+:/'   /opt/adguardhome/conf/AdGuardHome.yaml
awk '/^statistics:/,/^[a-z_]+:/' /opt/adguardhome/conf/AdGuardHome.yaml
# querylog.interval must read 6h. 2160h means a migration ran and overwrote the
# block -- your retention settings are not the running settings.
curl -s --netrc-file /root/.dns-netrc 127.0.0.1:3000/control/stats/config \
  | jq '{enabled, interval}'
# enabled must read TRUE here: that is the shipped default and what Phase I's
# collector expects on a stock build. False has exactly two causes, and they are
# not the same defect: a migration clobbered the block (a bug -- fix it), or an
# operator deliberately adopted one of Phase Q's opt-in postures (legitimate --
# Phase I then emits "metrics unavailable by policy" instead of reporting the
# daemon down, and nothing needs fixing).
```

---

> **Phase F is retired.** The v1 plan placed a Python cache-warmer daemon here. Unbound's `prefetch` / `prefetch-key` (Phase C) does the same job in-process, correctly, with no extra daemon, no extra systemd unit, and no self-inflicted query load. Nothing in the phases that follow depends on it; where the old plan referenced `dns-warmer.service` or `/opt/dns-warmer/`, there is now nothing to configure.

---

[Plan index](../dns-server-plan.md) · [Previous: TLS Certificates](./04-tls-certificates.md) · [Next: Retired Warmer, Log Rotation, Validation](./06-logging-and-validation.md)
