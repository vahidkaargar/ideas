[Plan index](../dns-server-plan.md) · [Previous: Backup, Patching, HA, Provisioning](./08-operations.md) · [Next: Privacy, Retention and Compliance (optional)](./10-privacy-and-compliance.md)

---

**On this page**

- [PHASE P: Private Access Layer (Optional)](#phase-p-private-access-layer-optional)
  - [P0. Decision matrix](#p0-decision-matrix)
  - [P1. AdGuardHome native ACLs](#p1-adguardhome-native-acls)
  - [P2. nftables IP allowlisting](#p2-nftables-ip-allowlisting)
  - [P3. ClientIDs for dynamic-IP clients](#p3-clientids-for-dynamic-ip-clients)
  - [P4. nginx token-authenticated DoH](#p4-nginx-token-authenticated-doh)
  - [P5. mTLS for DoT via an nginx stream front](#p5-mtls-for-dot-via-an-nginx-stream-front)
  - [P6. WireGuard-fronted DNS — recommended default for personal and mobile use](#p6-wireguard-fronted-dns-recommended-default-for-personal-and-mobile-use)
  - [P7. Deltas private mode forces on the rest of the plan](#p7-deltas-private-mode-forces-on-the-rest-of-the-plan)
  - [P8. Validation: prove refusal and prove service](#p8-validation-prove-refusal-and-prove-service)

---

## PHASE P: Private Access Layer (Optional)

Everything up to Phase O builds a resolver that answers the whole internet. That is a deliberate and defensible choice — it is also the choice that creates every obligation in Phase J (abuse controls), most of the load in Phase N (high availability), and all of the reflection/amplification risk in Phase B. This phase converts the service from "serves the whole internet" to "serves only my clients". It is optional, it is orthogonal to correctness, and it is the single highest-leverage change available if your actual user population is a family, a team, or a fleet of devices you control.

Six mechanisms are given, weakest to strongest. They are not alternatives in the usual sense — P1 (AdGuardHome ACLs) is a component of nearly every real deployment, and the stronger mechanisms mostly exist to give P1 something trustworthy to key on. Read the decision matrix, pick a primary, then read only that subsection plus P1, P7 and P8.

Two honesty notes that apply to the whole phase:

- **An IP allowlist is not authentication.** UDP source addresses are forgeable. Only a handshake — DoT, DoQ, mTLS, WireGuard — proves who a client is.
- **Every mechanism except P6 leaves a public listener up.** It answers `REFUSED` instead of an answer, which is a policy improvement, not an attack-surface improvement. The TLS stack, the QUIC stack and the certificate-transparency breadcrumb are all still there.

### P0. Decision matrix

| Your situation | Primary mechanism | Secondary (defence in depth) | Why this one |
|---|---|---|---|
| **Family / personal, a handful of devices, phones roam** | **P6 WireGuard** | P1 `allowed_clients: [10.77.0.0/24]` | No public listener at all. No certificate, no wildcard, no DNS-01, Phase D can be deleted. Works on cellular and hotel NAT. Revocation is one command. |
| **Small team (5–50), mixed BYOD, no VPN client permitted** | **P3 ClientIDs over the DoH URL path** + P1 `allowed_clients` | P4 nginx token layer if the ID must stay opaque; P2 for the office range | Native on iOS, Windows, Firefox and Chrome with zero client software installed. Per-user attribution in the query log. Revoke = delete one string. |
| **Road-warrior laptops and phones** | **P6 WireGuard** | P3 ClientIDs as a fallback profile for networks that block UDP/51820 | Dynamic IPs make every allowlist scheme meaningless. Only key- or certificate-bound identity survives roaming. |
| **Office with a static IP** | **P2 nftables allowlist** + P1 `allowed_clients` CIDR | P3 ClientIDs for the laptops that leave the building | Cheapest possible: no client configuration at all, non-clients dropped in-kernel at zero CPU. |
| **High-assurance / regulated fleet** | **P5 mTLS DoT** (or P6) | P1 ClientID allowlist, P2 for the office range | Cryptographic per-device identity that survives the reverse-proxy hop. Instant revocation via an nginx `map`. |
| **Deliberately public service** | none of P1–P6 | keep Phase J in full, and close the rate-limit gap in P7c | You have accepted the open-resolver duties. Read P7c anyway — the plan as written rate-limits only plain UDP. |

Strongest realistic stack for a private resolver: **P6 (WireGuard) + P1 (`allowed_clients` scoped to the tunnel subnet)**. Second: **P5 (mTLS DoT) + P1 (ClientID allowlist)**.

---

### P1. AdGuardHome native ACLs

AdGuardHome has a first-class access-control list. Phase E ships it empty on purpose and names Phase P as its owner — an empty `allowed_clients` means "allow everyone", so until this subsection is applied the resolver answers every source address on the internet. Three keys are involved, all direct children of `dns:` in `/opt/adguardhome/conf/AdGuardHome.yaml` (verified against `internal/dnsforward/config.go` yaml tags).

`allowed_clients`, `disallowed_clients` and `blocked_hosts` each accept bare IPs, CIDR prefixes and ClientIDs (see P3) mixed in one list — `processAccessClients` parses each entry as `netip.Addr`, then `netip.Prefix`, then `ValidateClientID`. **If `allowed_clients` is non-empty it wins outright and `disallowed_clients` is never consulted.** Do not try to use both.

One thing this subsection does **not** have to fix: `blocked_hosts`. **Phase E already ships `version.bind`, `id.server` and `hostname.bind`** in the `dns:` block it writes, so CHAOS-class software fingerprinting is closed before this phase starts. The reason the key is repeated in the config below is that the block below is a *replacement* for part of Phase E's `dns:` section — write it without those three lines and you silently delete a control Phase E put there. Keep them in sync; do not treat them as something Phase P introduces.

> **Do not apply `serve_plain_dns: false` on its own.** It removes the `127.0.0.1:53` listener that Phase H's validation tests and Phase I's health cron (`/etc/cron.d/dns-health`, defined by Phase I) both query. Apply the P7e cron change in the same maintenance window, or keep `serve_plain_dns: true` with `bind_hosts` restricted instead.

```yaml
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53

  # --- PRIVATE MODE: refuse plain DNS entirely (AGH >= v0.107.42) ---
  # AGH creates NO UDP/TCP :53 listener at all when this is false, and refuses
  # to start unless at least one encrypted protocol is enabled: preparePlain
  # counts DNSCrypt + HTTPS + QUIC + TLS listen addresses and errors with
  # "disabling plain dns requires at least one encrypted protocol" on zero.
  serve_plain_dns: false

  # --- ACCESS CONTROL ---
  # Bare IPs, CIDR prefixes and ClientIDs may be mixed in one list.
  allowed_clients:
    - 203.0.113.10          # office static IPv4
    - 198.51.100.0/28       # branch office IPv4 CIDR
    - 2001:db8:abcd::/48    # office IPv6 CIDR
    - alice-iphone          # ClientID (DoH path form / DoT+DoQ SNI form)
    - bob-laptop            # ClientID
  disallowed_clients: []

  # Carried over verbatim from Phase E, which already sets these. Repeated
  # only because this block replaces part of Phase E's dns: section; omitting
  # them here would remove working anti-fingerprinting.
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind

  # Tighten from the defaults, which are 127.0.0.0/8 AND ::1/128 — only a
  # proxy on this exact host may rewrite the client IP via headers (see P4b).
  trusted_proxies:
    - 127.0.0.1/32
    - ::1/128
```

**Mixing IPs and ClientIDs in one list is safe.** In allowlist mode the two checks compose with AND (`dnsforward.go`: `if allowlistMode && blockedByIP && blockedByClientID`), so a plain-DNS client that matches only on IP — and therefore carries no ClientID at all — is still allowed. The intuitive fear that adding one ClientID locks out every IP-only client is unfounded.

**What a non-allowed client actually receives** (verified in `internal/dnsforward/middleware.go`, `serveBlockedResponse`):

| Transport | Response |
|---|---|
| Plain UDP/53, DNSCrypt | `proxy.ErrDrop` — **no response at all**; the client times out. Deliberate, so the box cannot be used as an amplifier. |
| Plain TCP/53, DoT, DoH, DoQ | `REFUSED` (`makeResponseREFUSED`) |
| Query matching `blocked_hosts` | **The same split** — `ErrDrop` on UDP/DNSCrypt, `REFUSED` on TCP/DoT/DoH/DoQ. `isBlockedHost` routes through the identical helper. **Not SERVFAIL.** |
| Malformed or invalid ClientID, strict-SNI mismatch | `SERVFAIL` (`NewMsgSERVFAIL`) — the only SERVFAIL path in this code |

That asymmetry matters operationally: an allowlist failure over UDP looks like an outage (timeout) and over DoT/DoH looks like a policy decision (REFUSED). Tell your users which to expect before they open a ticket.

**Changing the list without a restart.** `POST /control/access/set` (v0.107.0+) takes all three lists. Each must contain only unique elements, and `allowed_clients` / `disallowed_clients` must not intersect, or `validateAccessSet` returns 400. Reach it over the Phase P-recommended SSH tunnel to 127.0.0.1:3000, never publicly.

```bash
curl -s -u admin:'YourStrongPassword' -X POST \
  -H 'Content-Type: application/json' \
  --data '{"allowed_clients":["203.0.113.10","alice-iphone"],"disallowed_clients":[],"blocked_hosts":["version.bind","id.server","hostname.bind"]}' \
  http://127.0.0.1:3000/control/access/set
```

The allowlist is snapshotted for free — Phase K's restic include list already covers `/opt/adguardhome/conf`, so every edit lands in the next off-host snapshot.

**Verify:**

```bash
# 0. Config parses BEFORE you restart anything. Canonical binary path: always
#    the version symlink, never a versioned directory (see Phase E / Phase M).
#    Run it as the adguardhome user, against the scratch validate directory
#    Phase E creates at install time -- never as root and never against the
#    live work/ tree: --check-config leaves artifacts behind, and root-owned
#    files in work/ break the next real start.
runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
  -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate; echo "exit=$?"
# expect: exit=0

# 1. With serve_plain_dns:false there must be no :53 listener at all
ss -lntup | grep -E ':53\b' && echo 'FAIL: plain DNS still listening' || echo 'OK: no plain :53'

# 2. Non-allowlisted client over TCP/DoT -> REFUSED
kdig @dns.example.com +tls google.com A | grep -E '^;; ->>HEADER<<-'
# expect: status: REFUSED

# 3. Allowlisted client -> resolves
kdig @dns.example.com +tls +tls-hostname=dns.example.com google.com A +short

# 4. Fingerprinting is still dead — i.e. Phase E's blocked_hosts survived the
#    edit above. Expect REFUSED, NOT SERVFAIL.
kdig @dns.example.com +tls -c CH -t TXT version.bind | grep -E '^;; ->>HEADER<<-'

# 5. The UDP-drop path. Only meaningful while plain DNS is still enabled —
#    run this BEFORE flipping serve_plain_dns to false.
dig @<PUBLIC_IP> google.com A +time=2 +tries=1; echo "exit=$? (expect 9 = no reply)"

# 6. Read back what AdGuardHome actually loaded
curl -s -u admin:'YourStrongPassword' http://127.0.0.1:3000/control/access/list | jq .
```

---

### P2. nftables IP allowlisting

For a site with static addresses, dropping non-clients in the kernel is strictly better than answering `REFUSED` in userspace: no TLS handshake, no CPU, no log noise, no fingerprintable response. **Phase B owns `/etc/nftables.conf` and every object in it** — the `flush ruleset` at the top, the raw-table NOTRACK for UDP/53, the single `table inet filter`, its `input` chain, the `dns_guard` chain, the meters `floodmeter4` / `floodmeter6`, the ban sets `banned_ips` / `banned_ips6` and the allowlist sets `allowlist4` / `allowlist6`. This subsection owns only the *contents* of the allowlist sets and the update procedure. It creates no new table, no new chain and no new hook.

The trap that makes a naive implementation dangerous: `/etc/nftables.conf` begins with `flush ruleset` and declares the ban sets in the same file, so a bare `nft -f /etc/nftables.conf` destroys live ban state. Phase B's `/usr/local/sbin/nft-apply` is the one wrapper that exists to stop that — it dumps the ban sets with their **remaining** timeouts, reloads, and restores them, and Phase B wires it to `ExecReload` so `systemctl reload nftables` is safe too. Use it for ruleset edits. But an allowlist edit should not need a whole-ruleset reload in the first place, and the procedure in P2c avoids one entirely.

#### P2a. The allowlist sets, repopulated as one atomic transaction

The sets are Phase B's canonical `allowlist4` / `allowlist6` in `table inet filter`. Phase P does not invent a second pair. That has one consequence you must understand before adopting P2, because it is not obvious from the set name:

**`allowlist4` / `allowlist6` are also the exemption sets Phase B's `dns_guard` chain consults** — the chain `return`s on a member before evaluation ever reaches the flood rule, so anything in them is never rate-limited and never banned (Phase J's escalation procedures manipulate the same objects). That is the whole purpose of an operator allowlist: it is a bypass, not a discount. Putting your office ranges in there therefore does two things at once: it admits them through `chain input`, and it exempts them from the flood meter. For a private deployment whose entire client population is in the allowlist that is the intended posture. If you want a client admitted but still metered, do not use P2 for it — give it a ClientID (P3) and let Phase B's `dns_guard` see it as an ordinary source.

Because the file below **flushes** those sets, it is the single source of truth for their contents. Two rules follow, and both are load-bearing:

- **Loopback stays in the list.** `127.0.0.0/8` and `::1/128` are Phase B's own entries and `dns_guard` depends on them; flushing them away arms a local load test to ban `127.0.0.1`. Phase J documents that failure in detail — it is the reason `iif lo accept` is the first rule of `dns_guard`, and this file must not undo the belt-and-braces half of it.
- **Ad-hoc `nft add element` additions do not survive.** If Phase J's operator procedures exempt a partner resolver on the fly, write it into this file too or the next reload discards it.

`/etc/nftables.d/dns-allow.nft`:

```
#!/usr/sbin/nft -f

# 1) Ensure the sets exist. Redeclaring an existing set with the SAME spec is
#    an idempotent add, so this is safe when run standalone on a cold boot and
#    when included from Phase B's /etc/nftables.conf. The type and flag list
#    below must match Phase B's declaration exactly -- a differing flag list
#    fails the load instead of merging.
table inet filter {
  set allowlist4 { type ipv4_addr; flags interval; auto-merge; }
  set allowlist6 { type ipv6_addr; flags interval; auto-merge; }
}

# 2) Empty them.
flush set inet filter allowlist4
flush set inet filter allowlist6

# 3) Repopulate. Steps 1-3 commit as ONE kernel transaction, so the allowlist
#    is never momentarily empty and no legitimate client is ever dropped.
table inet filter {
  set allowlist4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = {
      127.0.0.0/8,           # MANDATORY -- dns_guard's exemption (Phase B/J)
      203.0.113.10,          # HQ static
      198.51.100.0/28,       # branch office
    }
  }

  set allowlist6 {
    type ipv6_addr
    flags interval
    auto-merge
    elements = {
      ::1/128,               # MANDATORY -- as above
      2001:db8:abcd::/48,    # HQ v6
    }
  }
}
```

`flags interval` is what makes CIDR prefixes legal; `auto-merge` collapses overlaps instead of failing with "conflicting intervals specified". Because Phase B owns the declaration, `auto-merge` has to be present in *both* places or neither — if Phase B's canonical `allowlist4` / `allowlist6` declaration does not carry it, add it there rather than diverging here. `flags interval` cannot be combined with `flags dynamic` or `timeout`, so these sets never auto-expire — correct for a hand-curated allowlist, and the reason this file can be flushed and rewritten wholesale while `banned_ips` / `banned_ips6`, which carry live timeouts, must never be touched the same way.

#### P2b. Wire them into the Phase B ruleset

In `/etc/nftables.conf`, at the **end** of the file, after the `table inet filter { … }` block:

```
include "/etc/nftables.d/dns-allow.nft"
```

The position matters in both directions. It must come *after* the table block, because that block is where Phase B declares `allowlist4` / `allowlist6` and the flush-and-repopulate has to be the last word on their contents — put the include at the top and Phase B's own declaration re-adds its elements afterwards, so what you get is the union, not the list you wrote. It must not be *outside* the file at all, because then a cold boot brings the ruleset up with an empty allowlist.

Then, in `chain input`, replace Phase B's blanket DNS accepts with allowlist-scoped equivalents. Keep them in the same position in the chain — in particular they must stay after the `iif lo accept` rule and they must remain *explicit accepts*, because Phase B NOTRACKs UDP/53 in `table inet raw` and `ct state established,related accept` therefore does not cover DNS:

```
    # DNS only from allowlisted networks
    ip  saddr @allowlist4 udp dport 53  accept
    ip  saddr @allowlist4 tcp dport { 53, 443, 853 } accept
    ip  saddr @allowlist4 udp dport 853 accept
    ip6 saddr @allowlist6 udp dport 53  accept
    ip6 saddr @allowlist6 tcp dport { 53, 443, 853 } accept
    ip6 saddr @allowlist6 udp dport 853 accept
```

Everything else falls through to the chain's `policy drop`. Note what this does *not* change: `dns_guard` is a **regular** chain, reached by the `jump dns_guard` that Phase B places in `chain input` above these accepts — it is not a base chain and it does not hook `input` at its own priority. It therefore still runs before the accepts and still sees every packet that reaches the jump, including packets it is about to let through and `chain input` is about to drop. Sources you put in `@allowlist4` / `@allowlist6` `return` from it at its allowlist check, never touching the flood meter. That is harmless, and it is why P2 does not touch `dns_guard`.

Port 80 needs no change either — but not because it is closed. **Phase B carries a standing `tcp dport 80 accept`**: nginx owns the `:80` listener (Phase E), and it serves both Phase D's ACME webroot and the `/.well-known/` files Phase Q publishes. Leave the accept exactly as Phase B writes it. Do not scope it to `@allowlist4`: HTTP-01 validation arrives from Let's Encrypt's arbitrary and undisclosed source addresses, and Phase Q's files are meant to be readable by anyone. Adopting P3 and moving to DNS-01 removes the *reason* for HTTP-01, not the port — `:80` still has an owner.

#### P2c. Editing the allowlist without an outage and without losing ban state

`/usr/local/sbin/dns-allow-reload`:

```bash
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
```

```bash
chmod 0700 /usr/local/sbin/dns-allow-reload
```

Do **not** write this as a bare `nft flush set ...` followed by a separate `nft -f`. Those are two independent kernel transactions; between them the allowlist is empty while `chain input` is `policy drop`, so every legitimate client is dropped for the duration — a visible outage on every allowlist edit, which is exactly the failure this workflow exists to prevent. The separate `flush set` also aborts under `set -e` on a cold boot, before the set exists.

Ad-hoc entries (not persisted — add them to the file as well, and see P2a: the next reload of this file discards anything that is not in it, including exemptions added by Phase J's operator procedures):

```bash
nft add element inet filter allowlist4 { 192.0.2.0/24 }
nft delete element inet filter allowlist4 { 192.0.2.0/24 }
nft list set inet filter allowlist4
```

Add `/etc/nftables.d` to Phase K's `/etc/restic/include.txt`. Phase K's list names `/etc/nftables.conf` as a file, so the directory is not picked up implicitly and the allowlist would be absent from every snapshot.

#### P2d. What this does and does not buy

- **Does:** eliminates scanning, brute-force and casual abuse; makes the box invisible to everyone outside the allowlist; costs nothing per packet.
- **Does not stop spoofed-source floods.** A packet claiming `203.0.113.10` is accepted, processed and answered — to 203.0.113.10, not to the attacker. So the allowlist stops you being a reflector *against arbitrary victims* and shrinks the amplification target set to your own networks, but it is not client authentication.
- **Useless for dynamic IPs**, which is most of the world. Pair with P3, or replace with P6.

**Verify:**

```bash
# 1. Syntax-check before touching the live ruleset
nft -c -f /etc/nftables.d/dns-allow.nft && echo 'allowlist syntax OK'
nft -c -f /etc/nftables.conf            && echo 'full ruleset syntax OK'

# 2. Sets loaded with the expected prefixes, loopback included
nft list set inet filter allowlist4 | grep -q '127.0.0.0/8' \
  && echo 'PASS: loopback exempt' || echo 'FAIL: dns_guard can now ban 127.0.0.1'
nft list set inet filter allowlist4
nft list set inet filter allowlist6

# 3. Ban state SURVIVES an allowlist reload. 10m is the canonical first-offence
#    ban duration (Phase J owns the escalation to 24h).
nft add element inet filter banned_ips { 192.0.2.66 timeout 10m }
/usr/local/sbin/dns-allow-reload
nft list set inet filter banned_ips | grep 192.0.2.66 \
  && echo 'PASS: bans preserved' || echo 'FAIL: bans wiped'

# 4. The reload never empties the allowlist. Run the loop from an ALLOWLISTED
#    host, concurrently with a reload; expect zero DROP lines.
( for i in $(seq 1 200); do dig @<PUBLIC_IP> google.com A +time=1 +tries=1 +short >/dev/null \
    || echo DROP; done ) & /usr/local/sbin/dns-allow-reload; wait

# 5. Non-allowlisted source is dropped in-kernel (run from a non-allowlisted host)
dig @<PUBLIC_IP> google.com A +time=2 +tries=1   # expect exit 9

# 6. Allowlisted source still resolves (run from 203.0.113.10)
dig @<PUBLIC_IP> google.com A +short
```

---

### P3. ClientIDs for dynamic-IP clients

IP allowlists are useless for phones, home broadband and roaming laptops — the normal case. AdGuardHome's answer is the ClientID: a label the client carries in-band, which `allowed_clients` matches on exactly like an IP. Requires AdGuardHome **v0.107.74 or newer** for the configurable DoH routes below; on older builds the routes are fixed and the equivalent knob is `tls.allow_unencrypted_doh`.

There are two forms, with very different infrastructure costs. Read P3c before you commit.

#### P3a. Enable ClientID routes and delete the anonymous one

v0.107.74 moved DoH routing into a new `http.doh` block (schema 33 → 34). Restricting the routes to the ClientID form means the anonymous endpoint does not exist at all:

```yaml
http:
  address: 127.0.0.1:3000     # admin UI stays on loopback; SSH tunnel only
  session_ttl: 720h
  pprof:
    port: 0
    enabled: false
  doh:
    insecure_enabled: false   # true only for the plain-HTTP variant noted in P4a
    routes:
      - 'GET /dns-query/{ClientID}'
      - 'POST /dns-query/{ClientID}'
```

The literal token `{ClientID}` is mandatory: `clientIDFromDNSContextHTTPS` extracts the ID only when `strings.Contains(r.Pattern, "{ClientID}")` holds, then reads `r.PathValue("ClientID")`. Routes are handed straight to Go's `http.ServeMux.Handle`, so any Go 1.22+ pattern is legal — you may use an unguessable path prefix here as well.

In the canonical topology nginx terminates TLS on public :443 and proxies only `/dns-query` to AdGuardHome's HTTPS listener on `127.0.0.1:8053`. **Phase E owns that server block** — it is the `location = /dns-query` inside `server { … server_name dns.example.com; }` in `/etc/nginx/conf.d/doh.conf`. Widen that location in place so the ClientID suffix survives the hop. Do not add a second `server` block for the same name: nginx logs "conflicting server name" and silently serves only the first.

```nginx
# REPLACES the exact-match `location = /dns-query` block Phase E writes, in
# Phase E's own file. Backend TLS settings are Phase E's, unchanged: the
# loopback leg presents the real certificate for dns.example.com, so it is
# verifiable and stays verified.
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
```

`$request_uri` replaces Phase E's `/dns-query$is_args$args` here because the path itself is now variable; it already carries the query string, so do not append `$is_args$args` to it as well.

#### P3b. ClientID naming rules

A ClientID is a single RFC 1035 hostname label — AdGuardHome validates with `netutil.ValidateHostnameLabel`. ASCII letters, digits and hyphens; must start and end alphanumeric; **maximum 63 characters**; case-insensitive (AdGuardHome lowercases it). No dots: `a.b.dns.example.com` is rejected because AdGuardHome requires an *immediate* subdomain — exactly one extra label.

#### P3c. The wildcard requirement, and the record everyone forgets

The URL-path form `https://dns.example.com/dns-query/alice-iphone` works with the plan's existing single-name certificate and needs nothing else. The SNI form `alice-iphone.dns.example.com` is the **only** form Android 9+ Private DNS and DoQ can use, because both accept a hostname and nothing else — and it needs two things, not one:

1. A certificate valid for `*.dns.example.com`. Let's Encrypt cannot issue wildcards over HTTP-01 under any circumstances, so Phase D's issuance must switch to DNS-01. **See Phase D** for the plugin, the credentials file, the ECDSA key type and the deploy hook; the only change here is the certbot `-d` arguments:

   ```
   -d dns.example.com -d '*.dns.example.com'
   ```

   Both names are required. `*.dns.example.com` alone does not cover the apex, and AdGuardHome compares the client SNI against `tls.server_name`.

2. **A wildcard DNS record.** This is the step that is missing from almost every write-up, including AdGuardHome's own. `alice-iphone.dns.example.com` is a real hostname that the device resolves through its *current* resolver before any TLS handshake happens. Without the record the client fails with NXDOMAIN — earlier than, and looking nothing like, the certificate error you would expect. A wildcard certificate with no wildcard A record is inert.

   ```
   dns.example.com.     300  IN  A     <PUBLIC_IP>
   *.dns.example.com.   300  IN  A     <PUBLIC_IP>
   ; and, if the VPS has IPv6:
   dns.example.com.     300  IN  AAAA  <PUBLIC_IPV6>
   *.dns.example.com.   300  IN  AAAA  <PUBLIC_IPV6>
   ```

   ```bash
   # Must answer with <PUBLIC_IP> BEFORE you run certbot:
   dig +short alice-iphone.dns.example.com A @1.1.1.1
   dig +short anything-at-all.dns.example.com A @1.1.1.1
   ```

Once DNS-01 is in use, HTTP-01 is never exercised again — but nothing about the firewall changes. Phase B's `tcp dport 80 accept` is a standing rule and stays one: the `:80` server block Phase E writes is also where Phase Q publishes its `/.well-known/` files, so the port keeps an owner that has nothing to do with ACME.

Skip both steps entirely if every client uses the DoH URL-path form.

#### P3d. AdGuardHome TLS block

```yaml
tls:
  enabled: true
  server_name: dns.example.com     # apex only; ClientIDs are subdomains OF this
  force_https: false
  port_https: 8053                 # inherits 127.0.0.1 from http.address (see Phase E)
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  port_dnscrypt: 0
  certificate_chain: /opt/adguardhome/conf/ssl/fullchain.pem
  private_key: /opt/adguardhome/conf/ssl/privkey.pem
  strict_sni_check: false
```

Leave `strict_sni_check: false`. When true, an SNI that is neither the apex nor an immediate subdomain makes `clientIDFromClientServerName` return an error, which the middleware turns into `SERVFAIL` instead of falling through to the (now denying) allowlist — noisier, and no additional security once `allowed_clients` is set. It is marked **deprecated** in the AdGuardHome changelog's Unreleased section (post-v0.107.78), so do not build on it.

DoT (TCP 853) and DoQ (UDP 853) are served by `dnsforward` directly on `dns.bind_hosts` and are unaffected by the nginx DoH topology.

#### P3e. Exact client configuration strings

With `server_name: dns.example.com` and ClientID `alice-iphone`:

| Platform | What the user enters | Needs wildcard cert **and** wildcard A record? |
|---|---|---|
| iOS / macOS (profile) | install the `.mobileconfig` generated in P3f | DoH: no. DoT: **yes** |
| iOS / macOS (manual DoH) | `https://dns.example.com/dns-query/alice-iphone` | no |
| Android 9+ Private DNS | `alice-iphone.dns.example.com` | **yes** |
| Android (Intra / AdGuard app, DoH) | `https://dns.example.com/dns-query/alice-iphone` | no |
| Windows 11 (Settings → Network → DNS over HTTPS) | `https://dns.example.com/dns-query/alice-iphone` | no |
| Firefox (`network.trr.uri`) | `https://dns.example.com/dns-query/alice-iphone` | no |
| Chrome (custom DoH URI) | `https://dns.example.com/dns-query/alice-iphone` | no |
| dnscrypt-proxy / OpenWrt / OPNsense DoT | `tls://alice-iphone.dns.example.com:853` | **yes** |
| DoQ clients (AdGuard, dnsproxy) | `quic://alice-iphone.dns.example.com:853` | **yes** |

**There is no ALPN-based ClientID.** `clientServerName()` reads the DoQ identity from `pctx.QUICConnection.ConnectionState().TLS.ServerName` — SNI only. ALPN is used purely for protocol negotiation. Do not attempt to encode identity there.

#### P3f. Apple mobileconfig: generate locally, distribute out of band

AdGuardHome builds its HTTPS web listener from the IP in `http.address`, not from `dns.bind_hosts` (`web.go`: `netip.AddrPortFrom(web.conf.BindAddr.Addr(), portHTTPS)`). With `http.address: 127.0.0.1:3000`, `/apple/*.mobileconfig` is **loopback-only** and a remote iPhone cannot download it. Do not publish that path through nginx either — it shares the mux with the admin UI and is explicitly exempt from AdGuardHome's auth middleware. Generate on the box and hand the file over by AirDrop or signed email:

```bash
curl -s 'http://127.0.0.1:3000/apple/doh.mobileconfig?host=dns.example.com&client_id=alice-iphone' \
  -o /root/alice-iphone-doh.mobileconfig
curl -s 'http://127.0.0.1:3000/apple/dot.mobileconfig?host=dns.example.com&client_id=alice-iphone' \
  -o /root/alice-iphone-dot.mobileconfig
```

Then list the IDs in `dns.allowed_clients` (P1). Revoking a device is one deleted string plus `POST /control/access/set` — no certificate reissue, no client touched.

**Verify:**

```bash
# 0. Wildcard DNS record resolves (do this BEFORE certbot)
dig +short alice-iphone.dns.example.com A @1.1.1.1     # expect <PUBLIC_IP>

# 1. Wildcard SAN present on the issued cert
openssl x509 -noout -text -in /etc/letsencrypt/live/dns.example.com/cert.pem \
  | grep -A1 'Subject Alternative Name'
# expect: DNS:*.dns.example.com, DNS:dns.example.com

# 2. Server presents it for a ClientID SNI
openssl s_client -connect dns.example.com:853 -servername alice-iphone.dns.example.com </dev/null 2>&1 \
  | openssl x509 -noout -subject -ext subjectAltName

# 3. Allowlisted ClientID over DoT and DoQ -> NOERROR
kdig @dns.example.com +tls  +tls-hostname=alice-iphone.dns.example.com example.com A
kdig @dns.example.com +quic +tls-hostname=alice-iphone.dns.example.com example.com A

# 4. Unknown ClientID -> REFUSED, not NOERROR
kdig @dns.example.com +tls +tls-hostname=mallory.dns.example.com example.com A \
  | grep -E '^;; ->>HEADER<<-'

# 5. ClientID over the DoH path; the bare route must be gone
kdig @dns.example.com +https=/dns-query/alice-iphone example.com A
kdig @dns.example.com +https=/dns-query              example.com A   # expect HTTP 404

# 6. Renewal still works unattended over DNS-01
certbot renew --dry-run

# 7. AdGuardHome recorded the ClientID, not just the IP
curl -s -u admin:'YourStrongPassword' 'http://127.0.0.1:3000/control/querylog?limit=5' \
  | jq '.data[].client_id'
```

---

### P4. nginx token-authenticated DoH

For clients that cannot run a VPN and whose identity you do not want visible in a shared URL, a bearer-token DoH front is the pragmatic option. It is a convenience tier, not a security tier — read P4e before adopting it.

#### P4a. AdGuardHome side

The canonical topology written by Phase E already has nginx terminating TLS on public :443 and proxying only `/dns-query` to AdGuardHome's HTTPS listener on `127.0.0.1:8053`, through the `agh_doh` upstream. Keep it. Do not "simplify" by pointing nginx at `http://127.0.0.1:3000` — the DoH handler is registered on the **web UI mux** (`registerDoHHandlers` does `globalContext.web.conf.mux.Handle(route, ...)`), the same mux that serves `/control/*`, `/login.html` and `/install.html`, and every DoH route plus `/apple/*.mobileconfig` is exempt from the auth middleware. A bare `proxy_pass` to that port publishes your admin API.

```yaml
http:
  address: 127.0.0.1:3000
  doh:
    insecure_enabled: false     # backend leg is TLS, so no plain-HTTP DoH needed
    routes:
      - 'GET /dns-query/{ClientID}'
      - 'POST /dns-query/{ClientID}'
dns:
  bind_hosts: [127.0.0.1]
  # Keep plain DNS ON but loopback-only. It is harmless behind Phase B's
  # firewall and it keeps Phase H and Phase I probing 127.0.0.1:53 unchanged.
  serve_plain_dns: true
  allowed_clients: [alice-iphone, bob-laptop]
  trusted_proxies:            # block style, not [a, b]: an unquoted ::1/128
    - 127.0.0.1/32            # inside a flow sequence is a YAML parse error
    - ::1/128
  anonymize_client_ip: false    # see P4b; retention policy is Phase Q
tls:
  enabled: true
  server_name: dns.example.com
  port_https: 8053              # loopback, inherited from http.address
  port_dns_over_tls: 0          # DoH-only deployment
  port_dns_over_quic: 0
  certificate_chain: /opt/adguardhome/conf/ssl/fullchain.pem
  private_key: /opt/adguardhome/conf/ssl/privkey.pem
```

`allowed_clients` is ClientID-only here, and every request reaches AdGuardHome from 127.0.0.1. That works because in allowlist mode the IP and ClientID checks compose with AND — see P1.

There is a variant that uses AdGuardHome's plain-HTTP DoH on the web mux (`doh.insecure_enabled: true`, `tls.enabled: false`). Do not take it. Besides re-exposing the admin mux to a misconfigured `location`, `serve_plain_dns: false` combined with `tls.enabled: false` makes `preparePlain`'s `lenEncrypted` zero and **AdGuardHome refuses to start** — the plain-HTTP DoH handler lives on the web mux, not on a dnsproxy listener, and does not count toward that total.

#### P4b. The header snippet that makes any HTTP front safe

This is not optional and it is not cosmetic. dnsproxy resolves the "real" client IP from, in priority order, `CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, then the **first** comma-separated element of `X-Forwarded-For`. The idiomatic `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` *appends* to whatever the client sent, so an attacker who sends `X-Forwarded-For: 203.0.113.10` — or simply `CF-Connecting-IP: 203.0.113.10` — makes AdGuardHome believe the request came from your allowlisted office address. Every `allowed_clients` CIDR entry and every query-log attribution is then forgeable with one header.

**Phase E already writes this file** as `/etc/nginx/snippets/agh-client-identity.conf`. Do not create a second copy and do not fork its contents — every location Phase P adds simply `include`s it. It is restated here because the reasoning, not the file, is what makes any HTTP front safe, and because a future edit that "tidies" one of these lines silently reopens the hole:

```nginx
# OVERWRITE, never append: $proxy_add_x_forwarded_for lets the client prepend a
# forged address, and AdGuardHome takes the FIRST element.
proxy_set_header X-Forwarded-For   $remote_addr;
proxy_set_header X-Real-IP         $remote_addr;

# Strip the two headers dnsproxy checks BEFORE X-Forwarded-For.
# An empty value means the header is not passed to the upstream at all.
proxy_set_header CF-Connecting-IP  "";
proxy_set_header True-Client-IP    "";

# Pin the Host. When the backend leg is plain HTTP, r.TLS is nil and
# clientServerNameFromHTTP falls back to SplitHost(r.Host) — a forwarded $host
# then lets any client claim any ClientID. The HTTPS backend leg in P4a closes
# that path; pin it anyway so the config stays correct if the leg ever changes.
proxy_set_header Host              dns.example.com;

proxy_set_header X-Forwarded-Proto https;
proxy_http_version 1.1;
proxy_set_header Connection        "";   # required for the agh_doh keepalive pool
proxy_buffering off;
```

Pair it with the narrowed `trusted_proxies` from P1. If you ever put a CDN in front, `trusted_proxies` must instead list the CDN egress ranges and nginx must *not* strip `CF-Connecting-IP` — but then the CDN, not you, decides who your clients are. For a private resolver, do not.

Set `anonymize_client_ip: false` once any proxy is in play: with every request arriving from 127.0.0.1, an anonymised query log tells you nothing, and you have thrown away the only record of which authenticated identity did what. Retention and legal framing for that decision belong to Phase Q. (Phase P5's `stream` front carries no HTTP headers, so this snippet does not apply there.)

#### P4c. Token map, kept off the backup path (see P4d)

`/etc/nginx/doh-tokens.map`, mode 0600 root:root:

```nginx
map $doh_token $doh_clientid {
    default                             "";
    "k7Qm2yV9pR4tW8xZ0aL6nB3cH1sJ5dF7"  "alice-iphone";
    "T3vN8qL2mX9wR5yB7cK4hJ6sD1fG0zP2"  "bob-laptop";
}
```

Generate tokens with `head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '='` — 32 URL-safe characters, 192 bits.

#### P4d. nginx

Ubuntu 24.04 ships nginx 1.24.0. The standalone `http2 on;` directive is nginx 1.25.1 and will fail `nginx -t` here; Phase E already uses the `listen ... http2` form, so nothing changes on that front.

This tier adds **one file at `http` level and one location inside Phase E's existing server block**. It does not add a second `server { listen 443 … server_name dns.example.com; }` — two server blocks claiming the same listener and name make nginx warn about a conflicting server name and serve only the first, which is a failure mode that looks like a routing bug for hours.

`/etc/nginx/conf.d/doh-gateway.conf` — `http`-context objects only:

```nginx
include /etc/nginx/doh-tokens.map;
limit_req_zone $doh_token zone=dohtok:10m rate=30r/s;

log_format doh_safe '$remote_addr $ssl_protocol $status $doh_clientid $request_time';
```

Then, inside the `server { … server_name dns.example.com; }` block Phase E writes in `/etc/nginx/conf.d/doh.conf`, alongside the `/dns-query` location:

```nginx
    # Phase E sets `access_log off` for this whole server. Turning logging back
    # on for THIS location only is a deliberate trade: it is what lets you tie
    # an abusive request to a token. NEVER the default 'combined' format — the
    # token is in the path and $request would write every token to disk in
    # cleartext. $remote_addr is a client IP: read Phase Q before enabling it,
    # and keep the retention short.
    access_log /var/log/nginx/doh.log doh_safe;

    location ~ "^/t/(?<doh_token>[A-Za-z0-9_-]{32})/dns-query$" {
        if ($doh_clientid = "") { return 404; }
        limit_req zone=dohtok burst=60 nodelay;
        limit_req_status 429;

        # $is_args$args is MANDATORY. When proxy_pass contains a variable AND a
        # URI, nginx replaces the original request URI wholesale, silently
        # dropping a DoH GET's ?dns=<base64>.
        proxy_pass https://agh_doh/dns-query/$doh_clientid$is_args$args;
        proxy_ssl_name        dns.example.com;
        proxy_ssl_server_name on;
        proxy_ssl_verify      on;                             # as Phase E
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_ssl_verify_depth 3;
        include /etc/nginx/snippets/agh-client-identity.conf; # P4b — mandatory
    }
```

Phase E's `location / { return 404; }` already covers the rest of the backend mux — `/control/*`, `/login.html`, `/install.html`, `/apple/*.mobileconfig` — so nothing extra is needed to keep it unreachable. If you are running the token tier *instead of* the anonymous DoH endpoint rather than alongside it, delete Phase E's `location = /dns-query` as well.

Client URL: `https://dns.example.com/t/k7Qm2yV9pR4tW8xZ0aL6nB3cH1sJ5dF7/dns-query`.

On nginx ≥ 1.25.1 (from nginx.org's repo, or a future Ubuntu release) Phase E's `listen 443 ssl http2;` becomes `listen 443 ssl;` plus a separate `http2 on;`. That is a Phase E edit, not a Phase P one.

Rate limiting is keyed on `$doh_token`, i.e. per device rather than per source IP, which is the right unit for roaming clients behind carrier NAT. This is also the only real rate limit in a DoH deployment — see P7c.

**Rotation.** Add the new token alongside the old in the map, `nginx -t && systemctl reload nginx`, migrate the device, delete the old line, reload again. Zero downtime, per-device revocation, no AdGuardHome restart. Rotate on a 90-day cadence and immediately on device loss.

**Decide deliberately whether the tokens leave the host.** Phase K backs `/etc/nginx` up wholesale to off-host object storage with restic, so the live token map is in every snapshot unless you say otherwise. The restic repository is encrypted, which makes this a *policy* question rather than the plaintext-in-git-history catastrophe it was in v1 — but a token that has been rotated away still resolves to a working identity in every retained snapshot, and Phase K keeps 12 monthly ones.

The recommended split: exclude the real map, snapshot a redacted one from the local staging directory `/opt/dns-config-backup` (which Phase K also backs up, and which Phases I, J and Q already write to). Add to Phase K's `/etc/restic/exclude.txt`:

```
/etc/nginx/doh-tokens.map
/etc/dns-mtls
```

and stage the sanitised copy so a restore still tells you which ClientIDs existed:

```bash
sed -E 's/"[A-Za-z0-9_-]{32}"/"<REDACTED>"/' /etc/nginx/doh-tokens.map \
  > /opt/dns-config-backup/doh-tokens.map.redacted
chmod 0600 /opt/dns-config-backup/doh-tokens.map.redacted
```

Note the asymmetry with `/etc/wireguard` (P6), which Phase K's include list covers on purpose: losing WireGuard server keys means re-enrolling every peer by hand, so those belong in the encrypted repository. Tokens are cheap to reissue; keys are not.

#### P4e. Why a secret in a URL path is weaker than it looks

- **Server logs.** nginx's default `combined` format logs `$request` — the full path. Phase E sets `access_log off` on this server, so the stock plan does not leak; the moment you turn logging back on for the token location, `combined` would write every token to disk in cleartext and Phase G's logrotate would then copy it around. The `doh_safe` format above is not optional.
- **Client-side persistence.** The DoH URL is stored verbatim in Firefox prefs, Chrome policy, the Windows registry, Apple configuration profiles and Android app settings, all of which sync to cloud backups and are readable by anything with local access to the device.
- **Any intermediary.** A corporate TLS-inspecting proxy or a captive portal sees the path, and it lands in *their* access logs by default. A bearer token in a header would be seen too, but would not be logged as a matter of routine.
- **Support channels.** Users paste "the DNS address" into help-desk tickets, chats and screenshots without ever thinking of it as a credential.
- **No expiry, no binding.** Unlike P5 or P6, the token is bearer-only: whoever holds the string is you, forever, from anywhere.

Use `Authorization: Bearer` where the client supports it — but iOS, Android Private DNS, Windows and Firefox cannot set custom headers on DoH, which is precisely why the path form exists. Treat this as a low-assurance convenience tier and prefer P5 or P6 for anything sensitive.

**Verify:**

```bash
nginx -t

Q=$(printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
     | base64 | tr '+/' '-_' | tr -d '=')
T=k7Qm2yV9pR4tW8xZ0aL6nB3cH1sJ5dF7

# 0. AdGuardHome actually came up (this is what catches the serve_plain_dns trap)
systemctl is-active adguardhome || journalctl -u adguardhome -n 30 --no-pager

# 1. Valid token, GET form -> 200 application/dns-message
#    This is the step that fails if $is_args$args was omitted.
curl -si -H 'accept: application/dns-message' "https://dns.example.com/t/$T/dns-query?dns=$Q" | head -3

# 1b. POST form -> 200 as well
curl -si -X POST -H 'content-type: application/dns-message' \
  --data-binary @<(printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01') \
  "https://dns.example.com/t/$T/dns-query" | head -3

# 2. Wrong token -> 404
curl -s -o /dev/null -w '%{http_code}\n' \
  "https://dns.example.com/t/00000000000000000000000000000000/dns-query?dns=$Q"

# 3. Admin API must NOT be reachable through nginx — every line must print 404
for p in /control/status /control/stats /login.html /install.html \
         /apple/doh.mobileconfig /dns-query; do
  printf '%s -> ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' "https://dns.example.com$p"
done

# 4. Header spoofing must NOT change the recorded client
curl -s -o /dev/null -H 'accept: application/dns-message' \
  -H 'X-Forwarded-For: 203.0.113.10' -H 'CF-Connecting-IP: 203.0.113.10' \
  -H 'True-Client-IP: 203.0.113.10' -H 'Host: mallory.dns.example.com' \
  "https://dns.example.com/t/$T/dns-query?dns=$Q"
curl -s -u admin:'YourStrongPassword' 'http://127.0.0.1:3000/control/querylog?limit=1' \
  | jq -r '.data[] | "\(.client) \(.client_id)"'
# PASS: 127.0.0.1 alice-iphone.  FAIL: 203.0.113.10, or client_id "mallory".

# 5. Rate limit fires
for i in $(seq 1 200); do curl -s -o /dev/null -w '%{http_code}\n' \
  "https://dns.example.com/t/$T/dns-query?dns=$Q" & done | sort | uniq -c   # expect some 429

# 6. Token must not appear in any log, in the staging directory, or in a backup
sudo grep -rl "$T" /var/log/nginx/ /var/log/adguardhome/ ; echo "grep exit=$? (expect 1)"
sudo grep -rl "$T" /opt/dns-config-backup/ ; echo "grep exit=$? (expect 1)"
set -a; . /etc/restic/dns.env; set +a
restic ls latest | grep -c 'doh-tokens.map$'   # expect 0 (the redacted copy may appear)
```

---

### P5. mTLS for DoT via an nginx stream front

AdGuardHome has no client-certificate support of any kind — there is no `ClientAuth` reference anywhere in the codebase, and it remains an open feature request. If you want cryptographic per-device authentication on DoT without requiring a VPN client, nginx's `stream` module must do it.

The obvious workaround — terminate mTLS in nginx and forward *plain DNS* to AdGuardHome:53 — destroys the client identity: every query then arrives from 127.0.0.1, which is unattributable in the query log, invisible to `allowed_clients`, and inside `ratelimit_whitelist`. The design below keeps the identity.

#### P5a. Private client CA and per-device certificates

```bash
install -d -m 0700 /etc/dns-mtls && cd /etc/dns-mtls && umask 077

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -sha256 -days 3650 -key ca.key \
  -subj "/CN=dns.example.com Client CA" -out ca.crt

issue() {  # issue <clientid>
  openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"
  openssl req -new -sha256 -key "$1.key" -subj "/CN=$1" -out "$1.csr"
  openssl x509 -req -sha256 -in "$1.csr" -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days 365 -out "$1.crt"
  openssl pkcs12 -export -inkey "$1.key" -in "$1.crt" -certfile ca.crt -out "$1.p12"
  rm -f "$1.csr"
}
issue alice-iphone
issue bob-laptop
```

The CN **is** the ClientID — that is what makes the identity survive the proxy hop — so it must also be a valid ClientID: a single RFC 1035 label, at most 63 characters (P3b). Ship `<id>.p12` plus `ca.crt` to the device: iOS/macOS install as a profile; Android via Settings → Security → Install certificate; stubby / dnscrypt-proxy / Unbound take the PEM pair. These files are secrets. `/etc/dns-mtls` is not in Phase K's restic include list, and P4d adds it to the exclude list as belt and braces, so it is not backed up by default — delete each `<id>.p12` from the server once the device has it, and put `ca.key` somewhere deliberate (a password manager, or an encrypted archive you own) because losing it means reissuing every client certificate. Nothing from this directory belongs in `/opt/dns-config-backup`.

#### P5b. AdGuardHome listens on loopback only

```yaml
dns:
  bind_hosts: [127.0.0.1]
  serve_plain_dns: false        # legal here: TLSListenAddr is non-empty, so
                                # preparePlain's lenEncrypted check passes
  allowed_clients: [alice-iphone, bob-laptop]
  trusted_proxies:            # block style, not [a, b]: an unquoted ::1/128
    - 127.0.0.1/32            # inside a flow sequence is a YAML parse error
    - ::1/128
  anonymize_client_ip: false
tls:
  enabled: true
  server_name: dns.example.com
  port_https: 0
  port_dns_over_tls: 8853       # loopback only; nginx owns public 853
  port_dns_over_quic: 0
  certificate_chain: /opt/adguardhome/conf/ssl/fullchain.pem
  private_key: /opt/adguardhome/conf/ssl/privkey.pem
  strict_sni_check: false
```

This removes the 127.0.0.1:53 listener, so apply the P7e health-cron change in the same maintenance window.

#### P5c. nginx stream: verify the client cert, then re-originate TLS with the ClientID as SNI

At the top level of `/etc/nginx/nginx.conf` — a sibling of `http { }`, not inside it:

```nginx
stream {
    # RFC 2253 subject DN -> the SNI the backend should see.
    # The default maps to an explicit sentinel label that is NEVER in
    # allowed_clients, so a revoked-but-CA-valid certificate is denied
    # deterministically and shows up legibly in the query log.
    map $ssl_client_s_dn $dot_backend_sni {
        default            "revoked.dns.example.com";
        "CN=alice-iphone"  "alice-iphone.dns.example.com";
        "CN=bob-laptop"    "bob-laptop.dns.example.com";
    }

    server {
        listen      853 ssl;
        listen [::]:853 ssl;

        ssl_certificate         /etc/letsencrypt/live/dns.example.com/fullchain.pem;
        ssl_certificate_key     /etc/letsencrypt/live/dns.example.com/privkey.pem;
        ssl_protocols           TLSv1.2 TLSv1.3;
        ssl_session_cache       shared:dot:10m;

        ssl_verify_client       on;                     # stream: nginx >= 1.11.8
        ssl_client_certificate  /etc/dns-mtls/ca.crt;
        ssl_verify_depth        1;                      # already the default

        proxy_pass              127.0.0.1:8853;
        proxy_ssl               on;
        proxy_ssl_name          $dot_backend_sni;       # variables: nginx >= 1.11.3
        proxy_ssl_server_name   on;
        proxy_ssl_verify        off;                    # loopback leg, see below
        proxy_timeout           120s;
    }
}
```

**This is the trick, and it is why mTLS here costs less than P3:** nginx rewrites the SNI on the inner connection to `<clientid>.dns.example.com`, so AdGuardHome's ordinary SNI-based ClientID extraction fires and `allowed_clients` operates on certificate-proved identities. Because `proxy_ssl_verify off` on the loopback leg means the backend certificate is never name-checked, **you need neither a wildcard certificate nor a wildcard DNS record** — clients dial `dns.example.com:853`, and Phase D's single-name certificate is sufficient. (Go's TLS server returns its one configured certificate regardless of the SNI value, and `strict_sni_check: false` plus the immediate-subdomain rule both accept the rewritten name.)

Firewall delta, all of it in Phase B's `chain input`: keep `tcp dport 853 counter accept`; drop `udp dport 853 counter accept` (there is no DoQ path — `stream` cannot terminate QUIC) and drop `tcp dport 443 counter accept` (`port_https: 0`). Apply it with `/usr/local/sbin/nft-apply` so live ban timeouts survive the edit.

**Revocation.** Delete the line from the `map` and `systemctl reload nginx`. Instant: no CRL, no OCSP responder, no reissue. The certificate remains cryptographically valid but now maps to `revoked.dns.example.com`, which is not in `allowed_clients`, so AdGuardHome answers `REFUSED` and the query log records the attempt under a name you can read. For belt and braces, also drop the ClientID from `dns.allowed_clients`.

#### P5d. Honest limitations

- **DoT only.** `stream` cannot terminate DoQ or do mTLS for HTTP/3. DoH-over-mTLS would need the `http` block with `ssl_verify_client`, and most DoH clients cannot present a client certificate anyway.
- **Client support is the real constraint.** Android Private DNS cannot present a client certificate at all; iOS can, via a profile; desktop stub resolvers (stubby, dnscrypt-proxy, Unbound) can. Confirm your fleet before committing to this design.
- **ALPN.** `ssl_alpn` in `stream` requires nginx ≥ 1.21.4, which Ubuntu 24.04's 1.24.0 satisfies, so you may pin `ssl_alpn "dot";` on the client-facing side. Be aware that a client which offers ALPN with no matching protocol is then terminated. There is no corresponding directive to set ALPN on the upstream leg — treat that as unverified and do not assume one exists; it is not needed, because nginx sends no ALPN and Go's TLS server simply negotiates none.
- **nginx build.** `ssl_verify_client` in `stream` requires `--with-stream_ssl_module`. Ubuntu 24.04's `nginx-full` has it; check before writing config.

**Verify:**

```bash
# 0. Build must have stream + stream_ssl
nginx -V 2>&1 | tr ' ' '\n' | grep -E 'stream'   # expect --with-stream and --with-stream_ssl_module
nginx -t

# 1. Backend is loopback-only; AdGuardHome actually started
systemctl is-active adguardhome
ss -lntup | grep -E ':8853|:853'   # expect 127.0.0.1:8853 (AGH), 0.0.0.0:853 (nginx)

# 2. No client cert -> handshake rejected by nginx
openssl s_client -connect dns.example.com:853 -servername dns.example.com </dev/null 2>&1 \
  | grep -E 'alert|Verify return|handshake failure'
kdig @dns.example.com +tls example.com A; echo "exit=$? (expect non-zero)"

# 3. Valid client cert -> resolves, attributed to the right ClientID.
#    NOTE: the kdig options are +tls-certfile / +tls-keyfile.
#    There is no +tls-cert and no +tls-key.
kdig @dns.example.com +tls +tls-hostname=dns.example.com \
     +tls-certfile=/etc/dns-mtls/alice-iphone.crt \
     +tls-keyfile=/etc/dns-mtls/alice-iphone.key example.com A
curl -s -u admin:'YourStrongPassword' 'http://127.0.0.1:3000/control/querylog?limit=1' \
  | jq -r '.data[0].client_id'          # expect: alice-iphone

# 4. Certificate signed by a DIFFERENT CA -> rejected at the nginx handshake
openssl s_client -connect dns.example.com:853 -cert /tmp/rogue.crt -key /tmp/rogue.key </dev/null 2>&1 \
  | grep -i alert

# 5. Revocation by map removal takes effect on reload
sed -i '/alice-iphone/d' /etc/nginx/nginx.conf && nginx -t && systemctl reload nginx
kdig @dns.example.com +tls +tls-certfile=/etc/dns-mtls/alice-iphone.crt \
     +tls-keyfile=/etc/dns-mtls/alice-iphone.key example.com A | grep -E '^;; ->>HEADER<<-'
# expect: REFUSED
curl -s -u admin:'YourStrongPassword' 'http://127.0.0.1:3000/control/querylog?limit=1' \
  | jq -r '.data[0].client_id'          # expect: revoked
```

---

### P6. WireGuard-fronted DNS — recommended default for personal and mobile use

Every mechanism in P1–P5 still leaves AdGuardHome reachable by the whole internet; it just answers `REFUSED`. The service is still scannable, still enumerable through certificate transparency, still exposed to TLS- and QUIC-stack vulnerabilities, and every rejection still costs a handshake. For a personal, family or roaming fleet the correct answer is that the resolver has no public listener at all.

This is the recommended default for those cases. It also deletes work: no certificate, no wildcard, no DNS-01, no renewal monitoring — Phase D becomes unnecessary in full.

#### P6a. Server key material and interface

```bash
apt install -y wireguard qrencode
install -d -m 0700 /etc/wireguard /etc/wireguard/clients
umask 077
wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
wg genkey | tee /etc/wireguard/clients/alice.key | wg pubkey > /etc/wireguard/clients/alice.pub
wg genpsk > /etc/wireguard/clients/alice.psk
```

`/etc/wireguard/wg0.conf`, mode 0600 root:root:

```ini
[Interface]
Address    = 10.77.0.1/24, fd77:d15:c0de::1/64
ListenPort = 51820
PrivateKey = <CONTENTS OF /etc/wireguard/server.key>
# Deliberately no PostUp NAT and no ip_forward: this tunnel carries DNS only.
# Clients keep their normal internet path; only DNS is tunnelled. Nothing is
# forwarded, so Phase B's `chain forward policy drop` stays untouched.

[Peer]
# alice-iphone
PublicKey    = <CONTENTS OF /etc/wireguard/clients/alice.pub>
PresharedKey = <CONTENTS OF /etc/wireguard/clients/alice.psk>
AllowedIPs   = 10.77.0.11/32, fd77:d15:c0de::11/128
```

`AllowedIPs` on the server side is the cryptographic identity binding: a packet claiming source 10.77.0.11 is accepted only if it arrived inside alice's authenticated session. That is what an IP allowlist pretends to do and cannot.

```bash
systemctl enable --now wg-quick@wg0
```

#### P6b. Client config and QR flow

`/etc/wireguard/clients/alice.conf`:

```ini
[Interface]
Address    = 10.77.0.11/32, fd77:d15:c0de::11/128
PrivateKey = <CONTENTS OF /etc/wireguard/clients/alice.key>
DNS        = 10.77.0.1, fd77:d15:c0de::1
MTU        = 1280

[Peer]
PublicKey           = <CONTENTS OF /etc/wireguard/server.pub>
PresharedKey        = <CONTENTS OF /etc/wireguard/clients/alice.psk>
Endpoint            = dns.example.com:51820
AllowedIPs          = 10.77.0.0/24, fd77:d15:c0de::/64
PersistentKeepalive = 25
```

```bash
qrencode -t ansiutf8 < /etc/wireguard/clients/alice.conf   # scan in the WireGuard app
```

Split tunnel: the client's `AllowedIPs` covers only the DNS subnet, so ordinary traffic is untouched and the battery cost is negligible. `PersistentKeepalive = 25` keeps the NAT binding alive on cellular.

**`MTU = 1280` is not optional, and it is the one line whose absence is hardest to diagnose.** `wg-quick` defaults to 1420, which assumes a 1500-byte outer path. On PPPoE (1492), on LTE and 5G with GTP encapsulation, inside an outer IPv6 transition tunnel, or behind hotel CPE, the encapsulated packet exceeds the real path MTU and delivery then depends on an ICMP or ICMPv6 "packet too big" reaching the client — which mobile carriers and consumer CPE drop as a matter of routine. The result is that small answers work and large ones silently hang: the handshake completes, `wg show` reports a recent handshake, and P8c's `dig +short` probes all pass because they ask for A records, while DNSSEC-signed answers, TXT records and anything that would fall back to TCP time out. P6c serves plaintext Do53 inside the tunnel and Phase H7 records that AdGuardHome honours the client's advertised EDNS buffer verbatim with no ceiling, so answers above 1400 bytes are ordinary rather than exotic. 1280 is the IPv6 minimum link MTU and therefore survives every path in existence; it costs nothing here, because P6a runs no NAT and enables no forwarding, so the tunnel carries DNS only and there is no throughput to lose. Phase R9 in [Client Configuration](./12-client-setup.md#r9-wireguard-clients-set-the-mtu) carries the same line for the client-side hand-out — keep the two in sync.

**Key management.** The flow above generates client private keys on the server, which is convenient and means the server briefly holds every client secret. If you would rather it never did: generate the keypair *on the device* (the WireGuard app can do this), and paste only the resulting public key into `wg0.conf`. Either way `/etc/wireguard` is 0700, and note that Phase K's restic include list covers it deliberately — the server key and the peer list are exactly what a rebuild needs, and the repository is encrypted. Client *private* keys are the part that need not be there: once a device has its config, delete `/etc/wireguard/clients/<name>.key` from the server and keep only the public key and the PSK. Never render the QR into a screenshot that leaves the machine — it is the private key.

#### P6c. AdGuardHome binds only to the tunnel

```yaml
dns:
  bind_hosts:
    - 10.77.0.1
    - fd77:d15:c0de::1
  port: 53
  serve_plain_dns: true          # plain DNS is fine INSIDE the tunnel
  allowed_clients:               # defence in depth
    - 10.77.0.0/24
    - fd77:d15:c0de::/64
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind
```

Every AdGuardHome listener — plain, DoT, DoH, DoQ, DNSCrypt — is built from `dns.bind_hosts` (`internal/home/dns.go` derives `UDPListenAddrs`, `TCPListenAddrs`, `HTTPSListenAddrs`, `TLSListenAddrs`, `QUICListenAddrs` and the DNSCrypt addresses from that one list), so this single change moves the whole service off the public interface. TLS becomes optional: `tls.enabled: false` together with `serve_plain_dns: true` is legal — `preparePlain` returns early on the plain-DNS branch and never reaches the "at least one encrypted protocol" check — so Phase D and certbot become unnecessary. Port 80 is not part of that saving: Phase B's `tcp dport 80 accept` is standing, and Phase E's nginx keeps serving Phase Q's `/.well-known/` files there.

Useful side effect, though not one this plan needs: binding a specific tunnel address also sidesteps the `systemd-resolved` stub listener on 127.0.0.53:53 that commonly collides with `bind_hosts: 0.0.0.0` on stock Ubuntu server images. Phase A2 has already disabled `systemd-resolved` outright and written a static `/etc/resolv.conf`, which Phase C5 later points at 127.0.0.1, so the collision cannot arise here — the remark matters only if you lift this subsection onto an untouched image.

#### P6d. Boot ordering — the failure everyone hits

AdGuardHome exits if 10.77.0.1 does not exist when it starts. Add a drop-in rather than editing Phase E's unit:

```bash
install -d /etc/systemd/system/adguardhome.service.d
cat > /etc/systemd/system/adguardhome.service.d/10-wireguard.conf <<'EOF'
[Unit]
After=wg-quick@wg0.service
Requires=wg-quick@wg0.service
EOF
systemctl daemon-reload
```

`wg-quick@.service` is `Type=oneshot` with `RemainAfterExit=yes`, so `Requires=` plus `After=` genuinely guarantees the address exists before AdGuardHome binds. The drop-in merges cleanly with the `[Unit]` section Phase E already writes.

This `Requires=` is a deliberate exception to the rule that governs the DNS daemons themselves, where the canonical coupling is `Wants=` plus `After=` precisely so that stopping one never cascades a stop into the other (Phase N owns that rule; Phase A6 owns the resource ceilings in the same units). The exception is justified because `wg-quick@wg0` is a one-shot interface bring-up rather than a peer daemon, and because AdGuardHome genuinely cannot bind `10.77.0.1` without it — a cascade here is the correct behaviour, not an accident. Do not copy the pattern between `unbound` and `adguardhome`.

Do **not** reach for `net.ipv4.ip_nonlocal_bind=1`. It lets AdGuardHome bind an address the kernel does not own, which hides the real fault and creates a window in which queries are silently blackholed.

#### P6e. nftables delta

Phase B owns the ruleset. Under P6 the DNS accepts in its `chain input` change shape entirely:

```
    # WireGuard handshake and data — the ONLY new public port
    udp dport 51820 accept

    # DNS is reachable only from inside the tunnel. These accepts must be
    # explicit: Phase B NOTRACKs UDP/53 in `table inet raw`, so
    # `ct state established,related accept` does not cover it.
    iifname "wg0" udp dport 53 accept
    iifname "wg0" tcp dport 53 accept
```

Delete `udp dport 53 counter accept`, `tcp dport 53 counter accept`, `tcp dport 443 counter accept`, `tcp dport 853 counter accept` and `udp dport 853 counter accept`. Leave `tcp dport 80 accept` alone: it is standing in Phase B, and even under P6 — where certbot is gone entirely — nginx still serves Phase Q's `/.well-known/` files on `:80`. Apply the edit with `/usr/local/sbin/nft-apply`. See also P7b for the `dns_guard` interaction, which is not what it looks like.

#### P6f. Why this beats every IP-allowlist scheme

- **Unspoofable.** UDP source addresses are forgeable; a WireGuard session is not. An allowlist entry is a claim; a WireGuard peer is a proof.
- **Effectively zero attack surface.** WireGuard's handshake is silent to unauthenticated packets — the port does not respond to scans, so there is nothing to fingerprint, no TLS stack exposed, no DoQ amplification vector and no certificate-transparency breadcrumb.
- **Roaming for free, once the network lets you out.** Peer identity is the key, not the address, so the same device works on home Wi-Fi, cellular and hotel NAT with no reconfiguration. The claim is about identity, not reachability: a captive portal blocks udp/51820 and hijacks the lookup of `Endpoint = dns.example.com` until the user has logged in, so the tunnel cannot come up at all and the device is dark until then — P6 is the *worst* of the transports on that network, not the best. R10 in [Client Configuration](./12-client-setup.md#r10-captive-portals-and-hostile-networks) has the failure shapes and what to tell the user; the same caveat applies to P0's "Works on cellular and hotel NAT".
- **Real revocation.** Delete the `[Peer]` block and `systemctl reload wg-quick@wg0` — the unit's `ExecReload` runs `wg syncconf`, which removes peers absent from the file. That device is off instantly, with no certificate reissue and no TTL wait.
- **The abuse problem disappears.** There is no open resolver to abuse, so Phase J's ban machinery has nothing left to act on — see P7e, and note that the `dns_guard` chain stays in Phase B's ruleset unless you deliberately remove it.

**Verify:**

```bash
# 1. Tunnel up, peer handshaking
wg show wg0
systemctl is-active wg-quick@wg0 adguardhome

# 2. AdGuardHome listens ONLY on the tunnel address
ss -lntup | grep -E 'AdGuardHome'   # expect 10.77.0.1:53 and [fd77:...]:53 only

# 3. From the public internet: nothing answers (run these from OFF the box)
dig @<PUBLIC_IP> google.com A +time=2 +tries=1; echo "exit=$? (expect 9)"
nmap -sU -p 53,853,51820 -Pn <PUBLIC_IP>    # 53/853 closed|filtered, 51820 open|filtered
nmap -sT -p 53,443,853   -Pn <PUBLIC_IP>    # all closed/filtered

# 4. From a connected peer: resolves
dig @10.77.0.1 google.com A +short

# 5. Boot ordering actually holds
systemctl reboot
# after it comes back:
systemctl is-active adguardhome && journalctl -u adguardhome -b | grep -i 'bind\|address'

# 6. Revocation works
wg set wg0 peer <ALICE_PUBKEY> remove
# then, from alice's device:
dig @10.77.0.1 google.com A +time=2 +tries=1   # must fail
```

---

### P7. Deltas private mode forces on the rest of the plan

Bolting on a private access layer invalidates parts of the plan built for a public one. Two of those interactions fail silently; both are below.

#### P7a. Phase F is already gone — do not go looking for it

Phase F in the v1 plan was a Python cache warmer that queried `127.0.0.1:53` on a timer. It is **retired in this plan**: Unbound's `prefetch` and `prefetch-key` do the same job in-process, correctly, with no extra daemon and no self-inflicted query load (see Phase C). This matters here because the warmer was the single most fragile consumer of `127.0.0.1:53`, and every private-mode change in this phase would have broken it. There is no warmer to retarget. If you are porting a v1 deployment, delete `/opt/dns-warmer` and its unit as part of this change.

#### P7b. Phase B (firewall) deltas

Every one of these is an edit to Phase B's single `table inet filter`, applied through `/usr/local/sbin/nft-apply` so live ban timeouts survive:

- **P6 WireGuard:** delete `udp dport 53`, `tcp dport 53`, `tcp dport 443`, `tcp dport 853`, `udp dport 853`; add `udp dport 51820 accept` and the two `iifname "wg0"` accepts (P6e). Keep the standing `tcp dport 80 accept` — nginx and Phase Q still own `:80` after certbot goes.
- **P3 with DNS-01:** no firewall delta at all. HTTP-01 stops being used, but `tcp dport 80 accept` is standing in Phase B and Phase Q keeps publishing over `:80`.
- **P2:** replace the blanket accepts with the `@allowlist4` / `@allowlist6` rules, and read P2a on what else those sets control.
- **P5:** keep `tcp dport 853`; drop `udp dport 853` and `tcp dport 443`.

**The UDP/53 flood meter does not become a no-op under P6.** This is the counter-intuitive one. `dns_guard` is a regular chain, not a base chain: Phase B reaches it with a `jump dns_guard` placed in `chain input` (the single input-hook base chain, priority 0) above the DNS accepts, so it runs before them, and its rules match `udp dport 53` with no interface qualifier. Loopback is already handled — `iif lo accept` is the first rule of `dns_guard` (Phase J documents why: without it a local load test bans 127.0.0.1 and takes the resolver down), and `127.0.0.0/8` is in `allowlist4`, which the chain consults immediately afterwards and `return`s on. **`wg0` is neither.** Packets decrypted by WireGuard and delivered to `10.77.0.1:53` arrive on the tunnel interface, match `udp dport 53`, and are metered into `floodmeter4` like any stranger — so a peer that runs a heavy local test can be banned by its own tunnel address, which then also drops its traffic in `chain input`. Treating the chain as dead weight leaves a silent per-source throttle in the path for your own authenticated peers.

Fix it by exempting the tunnel, immediately after the existing loopback rule at the top of `dns_guard`:

```
    # in dns_guard, directly after `iif lo accept`
    iifname "wg0" accept
```

Adding `10.77.0.0/24` and `fd77:d15:c0de::/64` to `allowlist4` / `allowlist6` achieves the same thing one rule later and is the better choice if you are already running P2's reload script. Deleting `dns_guard` outright is also defensible under P6 — but delete the *chain*, never the table: `table inet filter` is the whole firewall.

#### P7c. Phase E (AdGuardHome) deltas, and the rate-limit gap

```yaml
dns:
  # TRAP: the ratelimit middleware fires only for plain UDP. Verified in
  # dnsproxy ratelimit/ratelimit.go:
  #   if dctx.Proto == proxy.ProtoUDP && m.isRatelimited(dctx.Addr.Addr())
  # DoH, DoT, DoQ and TCP/53 are NOT rate-limited — today, in the public plan
  # as written. With serve_plain_dns:false these keys protect nothing at all
  # and remain only as documentation of intent.
  ratelimit: 100
  # Per-host accounting, as Phase E sets it and Phase H gates on it. These are
  # NOT the AdGuardHome defaults (/24 and /56) — subnet aggregation shares one
  # budget across 256 IPv4 hosts and black-holes CGNAT clients. Do not "restore"
  # the defaults here.
  ratelimit_subnet_len_ipv4: 32
  ratelimit_subnet_len_ipv6: 64
  # Keep these exactly as Phase E ships them; no private-mode variant removes
  # the loopback exemption.
  ratelimit_whitelist:
    - 127.0.0.1
    - ::1

  # Under any proxy or ClientID scheme, anonymising destroys your only audit
  # trail: every request already arrives from 127.0.0.1. Retention policy and
  # the legal framing of that choice belong to Phase Q.
  anonymize_client_ip: false
```

Note that `anonymize_client_ip: true` masks to /16 for IPv4 and /48 for IPv6, not /24 — a second reason it is useless as an abuse-detection input. Query-log retention keys live in the top-level `querylog:` section, not under `dns:` — see Phase E.

Real per-client limiting for encrypted transports, pick the one that matches your mechanism:

- **DoH behind nginx:** `limit_req_zone $doh_token zone=dohtok:10m rate=30r/s;` (P4d). Per device, not per source IP.
- **DoT/DoQ direct:** kernel-side, as a rule in Phase B's `dns_guard` chain (Phase B owns every object in the ruleset), e.g. `tcp dport 853 ct state new meter dot_conn { ip saddr limit rate over 20/second } drop`. `ct state` is available here because the raw-table NOTRACK covers UDP only, so TCP/853 is still tracked.
- **WireGuard:** not needed. Peers are authenticated and few.

#### P7d. `serve_plain_dns: false` removes the :53 listeners entirely

This is the second silent failure. It is not a filter and not an ACL — AdGuardHome creates no UDP and no TCP :53 listener at all, on any address. Anything in the plan that talks to `127.0.0.1:53` stops working the moment you set it, and AdGuardHome additionally refuses to start unless at least one encrypted protocol is configured. The affected consumers are Phase H's plain-DNS validation tests and Phase I's health cron in `/etc/cron.d/dns-health`; see P7e. The same effect is produced by moving `bind_hosts` to a tunnel address under P6, without the start-up guard.

#### P7e. Phase I and Phase J deltas

**Phase I health cron.** Phase I owns `/etc/cron.d/dns-health` and `/usr/local/sbin/notify.sh`; this is an edit to the probe inside the file Phase I created, not a second cron entry. Replace the `dig @127.0.0.1 google.com A` probe with one that matches the new binding:

```bash
# P6 (WireGuard): the tunnel address is reachable from the host itself
dig @10.77.0.1 google.com A +short

# P1/P3/P5 (no plain :53): probe over the encrypted transport, using a
# dedicated ClientID that you add to dns.allowed_clients
kdig @dns.example.com +tls +tls-hostname=healthcheck.dns.example.com google.com A +short
```

Under P4 with `serve_plain_dns: true` on loopback, the existing probe keeps working unchanged — that is the reason for keeping it on.

The Phase I probes also change meaning: an external blackbox probe of the DoH/DoT endpoint is no longer possible once the endpoint is not publicly reachable. Under P6 there is nothing to probe from outside at all, and an external check that succeeds is a *failure* — it means a listener leaked back onto the public interface. Invert it: make "public port answers" an alerting condition, and move liveness checking to a probe that runs on the host or inside the tunnel. Prometheus/blackbox targets from Phase I must move accordingly.

**Phase J abuse controls.** Phase J is kernel-side by design (nftables counters, never the query log — the query log's client IP is masked by Phase E's shipped `anonymize_client_ip: true`, see P7c). That design survives, but its input disappears:

- Under **P6**, every client is 10.77.0.x. `dns_guard` and `chain input` see the tunnel interface, not the peer's public endpoint, so `floodmeter4` accounts against 10.77.0.11 and `banned_ips` would hold a tunnel address — which bans that peer and nobody else. Useless as abuse control, and actively harmful: see P7b.
- Under **P1/P4/P5**, every query reaches AdGuardHome from 127.0.0.1, so there is no per-client address to count.

**Neutralise the abuse machinery in private mode** — exempt `wg0` in `dns_guard` (P7b), or remove the chain from Phase B's ruleset — or convert the response from an IP ban to an identity revocation. What you must not do is delete `table inet filter`: it is the entire firewall, and Phase B's `dns_guard`, `banned_ips` / `banned_ips6`, `floodmeter4` / `floodmeter6` and `allowlist4` / `allowlist6` all live inside it by design (a cross-table `add @set` is illegal, which is why every one of them sits in that single filter table — the only other table in the ruleset is `table inet raw`, which carries nothing but the NOTRACK rules, because `notrack` is legal only at the raw hook). Phase J's escalation logic — 10 minutes on a first offence, 24 hours on repeat — and its operator procedures stay valid for any node you leave public.

```bash
# Revoke a ClientID instead of banning an IP
curl -s -u admin:"$AGH_PASS" -X POST -H 'Content-Type: application/json' \
  --data "$(curl -s -u admin:"$AGH_PASS" http://127.0.0.1:3000/control/access/list \
            | jq --arg id "$BAD_ID" '.allowed_clients |= map(select(. != $id))')" \
  http://127.0.0.1:3000/control/access/set

# Or revoke a WireGuard peer
wg set wg0 peer <PUBKEY> remove && wg-quick save wg0
```

Phase N (high availability) is also affected: under P6 a second node needs its own WireGuard interface and its own peer set, and clients need both endpoints — the failover story is per-peer configuration, not a floating IP. Decide that before you build the second node.

#### P7f. Phase L go-live checklist, private-mode edition

Replace the firewall and rate-limit lines in Phase L with these:

```
[ ] Private mode selected and recorded: P6 WireGuard | P3 ClientID | P5 mTLS | P2 nft allowlist
[ ] dns.allowed_clients populated and read back via GET /control/access/list
[ ] dns.blocked_hosts still contains version.bind / id.server / hostname.bind (Phase E ships them)
[ ] blocked_hosts verified to return REFUSED (not SERVFAIL) over DoT
[ ] ratelimit_subnet_len_ipv4/ipv6 still 32/64 after any edit to the dns: block
[ ] dns.trusted_proxies narrowed to 127.0.0.1/32, ::1/128 (or empty if no proxy)
[ ] Non-allowlisted client verified: UDP times out, TCP/DoT returns REFUSED
[ ] Firewall: only 22, the standing tcp/80 (nginx: ACME webroot + Phase Q well-known), plus
    the ONE transport this deployment actually uses is open
[ ] Firewall edits applied via /usr/local/sbin/nft-apply; ban timeouts survived
[ ] dns_guard chain removed OR `iifname "wg0"` exempted; allowlist4 still holds 127.0.0.0/8
[ ] Exactly one nginx server block per listener/name — no duplicate :443 or :80 for dns.example.com
[ ] External scan clean: nmap -sU -sT shows no DNS ports to the public internet
[ ] Health cron (/etc/cron.d/dns-health, Phase I) probes the NEW binding, not 127.0.0.1:53
[ ] Phase I external probes inverted: "public port answers" is now an alert
[ ] Phase J abuse auto-ban neutralised OR converted to identity revocation
[ ] Secrets kept out of the restic snapshot per P4d (doh-tokens.map, /etc/dns-mtls); client
    private keys deleted from the server after enrolment
[ ] Per-client revocation drilled end to end and timed
[ ] Wildcard cert AND wildcard A record in place — only if DoT/DoQ ClientIDs are used
[ ] Phase F confirmed absent: no /opt/dns-warmer, no dns-warmer.service
```

---

### P8. Validation: prove refusal and prove service

Run this after the mechanism is in place and before go-live. The per-subsection verifications above check that a component is configured; this section checks the property that actually matters — that an unauthorised client cannot resolve and an authorised one can, over **every** protocol the deployment exposes.

You need two vantage points: a host that is *not* authorised (any VPS, or a phone on cellular with the profile removed), and a host that is. Run the negative tests from the unauthorised one. Running them from the server itself proves nothing, because loopback is exempt nearly everywhere.

#### P8a. Expected result matrix

| Mechanism | Unauthorised client sees | Authorised client sees |
|---|---|---|
| P1 `allowed_clients` | UDP/53 and DNSCrypt: timeout. TCP/53, DoT, DoH, DoQ: `REFUSED` | NOERROR |
| P2 nftables allowlist | timeout on every DNS port (packet dropped in kernel; no TCP handshake either); `:80` still answers — it is deliberately not allowlist-scoped | NOERROR |
| P3 ClientIDs | unknown ID → `REFUSED`; bare `/dns-query` → HTTP 404; unknown SNI → `REFUSED` | NOERROR |
| P4 token DoH | wrong token → HTTP 404; over-rate → HTTP 429 | HTTP 200, `application/dns-message` |
| P5 mTLS DoT | no certificate or foreign CA → TLS handshake failure; revoked CN → `REFUSED` | NOERROR |
| P6 WireGuard | nothing on any DNS port; 51820 does not respond to unauthenticated packets | NOERROR from inside the tunnel |

#### P8b. Negative tests — run from an UNAUTHORISED host

```bash
TARGET=dns.example.com
IP=<PUBLIC_IP>

# Plain DNS, both transports
dig @"$IP" google.com A +time=2 +tries=1;        echo "udp exit=$? (expect 9, or 10 under P2/P6)"
dig @"$IP" google.com A +tcp +time=2 +tries=1;   echo "tcp exit=$? (expect 9/10, or REFUSED under P1)"

# DoT
kdig @"$TARGET" +tls  google.com A | grep -E '^;; ->>HEADER<<-'   # expect REFUSED, or connect failure

# DoQ
kdig @"$TARGET" +quic google.com A | grep -E '^;; ->>HEADER<<-'   # expect REFUSED, or connect failure

# DoH — anonymous route and, under P4, a wrong token
kdig @"$TARGET" +https=/dns-query google.com A                    # expect HTTP 404
curl -s -o /dev/null -w '%{http_code}\n' \
  "https://$TARGET/t/00000000000000000000000000000000/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

# Fingerprinting must be dead on every transport that answers at all
kdig @"$TARGET" +tls -c CH -t TXT version.bind | grep -E '^;; ->>HEADER<<-'   # expect REFUSED

# Admin surface must be unreachable
for p in /control/status /login.html /install.html /apple/doh.mobileconfig; do
  printf '%s -> ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' "https://$TARGET$p"
done   # expect 404 everywhere (or connection refused)

# Port scan: only the transports you intend should answer. udp/784 is NOT in
# this list — the legacy DoQ draft port is not part of this design at all, and
# scanning for it only teaches people to open it.
nmap -sU -p 53,853,51820 -Pn "$IP"
nmap -sT -p 22,53,80,443,853,3000,8053,8853 -Pn "$IP"
# tcp/80 is OPEN in every mechanism, P6 included — nginx serves the ACME
# webroot and Phase Q's /.well-known/ files there, and Phase B's accept for it
# is standing. Do not treat an open :80 as a finding.
# Under P6 the only other open ports are 22 and 51820 (open|filtered).
# 3000, 8053 and 8853 must NEVER appear open — they are loopback-only.
```

#### P8c. Positive tests — run from an AUTHORISED client

```bash
# P1/P2 (IP-authorised)
dig @<PUBLIC_IP> example.com A +short
dig @<PUBLIC_IP> example.com A +tcp +short

# P3 ClientID, all three forms
kdig @dns.example.com +https=/dns-query/alice-iphone example.com A +short
kdig @dns.example.com +tls  +tls-hostname=alice-iphone.dns.example.com example.com A +short
kdig @dns.example.com +quic +tls-hostname=alice-iphone.dns.example.com example.com A +short

# P4 token DoH
Q=$(printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
     | base64 | tr '+/' '-_' | tr -d '=')
curl -si -H 'accept: application/dns-message' \
  "https://dns.example.com/t/$T/dns-query?dns=$Q" | head -3    # expect 200

# P5 mTLS DoT
kdig @dns.example.com +tls +tls-hostname=dns.example.com \
     +tls-certfile=/etc/dns-mtls/alice-iphone.crt \
     +tls-keyfile=/etc/dns-mtls/alice-iphone.key example.com A +short

# P6 WireGuard, from a connected peer
dig @10.77.0.1 example.com A +short
dig @10.77.0.1 dnssec-failed.org A; echo "exit=$?"   # expect SERVFAIL: Unbound is validating

# P6 MTU. The probes above are all small A records and pass with a wrong MTU,
# so they prove nothing about P6b's `MTU = 1280`. Ask for an answer that is
# actually large, over UDP and then over TCP:
dig @10.77.0.1 +dnssec +bufsize=4096 . DNSKEY +noall +stats | grep 'MSG SIZE'
dig @10.77.0.1 +tcp +dnssec        . DNSKEY +noall +stats | grep 'MSG SIZE'
# expect: BOTH return, ~1139 bytes (Phase H7's measured root DNSKEY size).
# UDP timing out while TCP succeeds is the MTU signature exactly — add
# `MTU = 1280` to the client [Interface] block (P6b) and retest.
ip link show wg0 | grep -o 'mtu [0-9]*'   # on the client: expect mtu 1280
```

#### P8d. Attribution and revocation drill

Access control that cannot be audited or undone is not access control.

```bash
# 1. The query log names the right identity, not a forged one
curl -s -u admin:'YourStrongPassword' 'http://127.0.0.1:3000/control/querylog?limit=5' \
  | jq -r '.data[] | "\(.client) \(.client_id) \(.question.name)"'

# 2. Revoke, and time it end to end
time (
  # pick the one that matches your mechanism:
  #   wg set wg0 peer <PUBKEY> remove
  #   sed -i '/alice-iphone/d' /etc/nginx/doh-tokens.map && nginx -t && systemctl reload nginx
  #   sed -i '/alice-iphone/d' /etc/nginx/nginx.conf     && nginx -t && systemctl reload nginx
  #   curl ... /control/access/set   # see P7e
  true
)

# 3. From the revoked device, the positive test from P8c must now fail.
#    Re-run it. If it still succeeds, the revocation did not take: check that
#    you reloaded the right service and that the ID is gone from
#    dns.allowed_clients as well.
curl -s -u admin:'YourStrongPassword' http://127.0.0.1:3000/control/access/list | jq .
```

Record the measured revocation time in the Phase L checklist. If it is longer than a few seconds, you have chosen a mechanism whose revocation depends on something you do not control — certificate expiry, a CRL, or a DNS TTL — and you should reconsider.

---

[Plan index](../dns-server-plan.md) · [Previous: Backup, Patching, HA, Provisioning](./08-operations.md) · [Next: Privacy, Retention and Compliance (optional)](./10-privacy-and-compliance.md)
