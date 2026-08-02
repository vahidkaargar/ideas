[Plan index](../dns-server-plan.md) · [Previous: Unbound Recursive Resolver](./03-unbound-resolver.md) · [Next: AdGuardHome and the Public Edge](./05-adguardhome-edge.md)

---

**On this page**

- [PHASE D: TLS Certificates](#phase-d-tls-certificates)
  - [D0. Prerequisites — the name must already resolve](#d0-prerequisites-the-name-must-already-resolve)
  - [D1. Install certbot](#d1-install-certbot)
  - [D2. First issuance — HTTP-01 standalone](#d2-first-issuance-http-01-standalone)
  - [D3. Switch the renewal authenticator once nginx owns port 80](#d3-switch-the-renewal-authenticator-once-nginx-owns-port-80)
  - [D4. Deploy hook — one certificate, two consumers](#d4-deploy-hook-one-certificate-two-consumers)
  - [D5. Prove renewal actually runs unattended](#d5-prove-renewal-actually-runs-unattended)
  - [D6. Revocation, OCSP, and what not to configure](#d6-revocation-ocsp-and-what-not-to-configure)
  - [D7. The wildcard / DNS-01 path — a Phase P decision, not a Phase D one](#d7-the-wildcard-dns-01-path-a-phase-p-decision-not-a-phase-d-one)
  - [D8. Expiry monitoring, Certificate Transparency, and CAA](#d8-expiry-monitoring-certificate-transparency-and-caa)
  - [D9. Verification](#d9-verification)

---

## PHASE D: TLS Certificates

This phase issues one certificate that three consumers read: nginx (public :443, Phase E4), AdGuardHome's DoT/DoQ listeners on :853, and AdGuardHome's loopback DoH backend on 127.0.0.1:8053. nginx runs its master as root and reads `/etc/letsencrypt/live/...` directly; AdGuardHome runs unprivileged under `ProtectSystem=strict` and cannot, so it gets a copy. That asymmetry is the reason the deploy hook in D4 exists at all.

### D0. Prerequisites — the name must already resolve

This box is a recursive resolver, not an authoritative server. Nothing in this plan serves the zone that contains `dns.example.com`; that zone lives at a registrar or a DNS hosting provider, and it is the one dependency of this service the host cannot repair by itself. **See Phase 0 in the [plan index](../dns-server-plan.md)** for who must own it, the nameserver and TTL requirements, and where the account and its credentials are recorded. Phase D creates none of that; it only refuses to start until it is already true.

Certbot is the first thing in this build that talks to an external service which penalises you for getting it wrong. Let's Encrypt allows **five authorization failures per identifier, per account, per hour**, refilling one every 12 minutes, plus a separate ceiling of 1,152 consecutive failures per identifier that resets only on a success. So a mismatched record is a **STOP**, not a retry: the retry is what consumes the hour you would otherwise have spent fixing the record. Check all of the below before D1 installs anything.

```bash
# 1. This host's public address, as the world will see it.
PUB=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1); echo "$PUB"

# 2. The name, from two independent public resolvers, and from Phase C's Unbound --
#    which recurses from the root, so it answers from the zone rather than from
#    somebody else's cache.
for r in 1.1.1.1 9.9.9.9; do printf '%-9s ' "$r"; dig +short A dns.example.com @"$r"; done
dig +short A dns.example.com @127.0.0.1 -p 5335
# PASS: all three return exactly $PUB and nothing else.
```

Two independent resolvers rather than one, because a single answer cannot distinguish "the zone is correct" from "this resolver is holding a stale value". Divergence between them means the record was changed recently and the old TTL has not expired. Read the remaining TTL and wait it out — do not run certbot against a half-propagated record, and remember that the local Unbound caches too:

```bash
dig +noall +answer A dns.example.com @1.1.1.1   # field 2 is the remaining TTL, in seconds
unbound-control flush dns.example.com           # before re-checking step 2 locally
```

**Whether to publish an AAAA is a decision, and publishing one this host cannot serve is the most common first-issuance failure.** Let's Encrypt always attempts the IPv6 address first when both A and AAAA exist, and it retries over IPv4 only on a network-level failure of the *first* request — a v6 address that accepts the connection and then misbehaves is not retried at all.

- **A record only — the recommended default.** One address to get right and one validation path. The cost is IPv6-only clients, a small population for a public resolver, and it is reversible later.
- **A + AAAA.** Correct for a genuinely dual-stack service and mandatory if any client is v6-only. The cost is a second address that must stay reachable on TCP/80 and TCP/443 for the life of the host. The plan is already built for it — Phase B's ruleset is in the `inet` family so `tcp dport 80 accept` covers both address families, and Phase E4's server block carries `listen [::]:80` alongside `listen 80` — so the risk is not the plan, it is a published AAAA pointing at an address this host does not answer on.

```bash
dig +short AAAA dns.example.com @1.1.1.1
ip -6 -o addr show scope global | awk '{print $4}' | cut -d/ -f1
# PASS: identical, or BOTH empty. Anything else fails HTTP-01 even when the A record is
# perfect. Reachability itself is proved by the D2 staging dry run, not here -- nothing
# is listening on :80 until certbot binds it.
```

### D1. Install certbot

Ubuntu 24.04 ships `certbot 2.9.0`. Two things follow from the 2.x line that were not true of 22.04's 1.21:

- ECDSA is the **default** key type (changed in certbot 2.0.0), so the common failure mode of silently issuing RSA-2048 is gone. Pin it anyway — the default is a property of the certbot version, and a future `--key-type` regression or a hand-typed `certonly` on another box should not be able to change it.
- The nginx authenticator plugin is packaged and current, which matters because from Phase E onward nginx owns port 80.

```bash
apt install -y certbot python3-certbot-nginx
certbot --version    # expect: certbot 2.9.0
```

Make the key type sticky for every future issuance and renewal on this host:

```bash
cat >> /etc/letsencrypt/cli.ini << 'EOF'
key-type = ecdsa
elliptic-curve = secp256r1
EOF
```

**Why the key type is load-bearing here and not just hygiene.** An RSA-2048 private-key operation costs roughly 0.8–1.5 ms of CPU; an ECDSA P-256 signature costs roughly 40–70 µs. On 2 vCPU that is the difference between about 1,000 and about 20,000 full handshakes per second. It matters on this box specifically because **TLS is the one request path AdGuardHome's rate limiter does not cover**: dnsproxy gates its limiter on `d.Proto == ProtoUDP` (`proxy/server.go`), so DoH, DoT and DoQ are entirely unthrottled at the application layer. The `ratelimit: 100` line in Phase E2 watches idly while a few hundred full handshakes per second pin both cores. Do not trust the numbers above — measure them on the CPU you were actually given:

```bash
openssl speed -seconds 3 rsa2048 ecdsap256
```

The ECDSA chain is also roughly half the bytes of the RSA chain, which is worth a note for DoQ: RFC 9000 §8.1 caps the server's pre-validation response at 3× the client's Initial (3,600 bytes for a padded 1200-byte Initial). An RSA Let's Encrypt chain flight of ~2.5–3 KB usually still fits, so this is a *possible* extra round trip under added extensions, not a certain one.

### D2. First issuance — HTTP-01 standalone

At this point in the build order nothing is listening on port 80, so `--standalone` can bind it. Phase B leaves TCP/80 permanently open, so no firewall dance is needed at renewal time.

**Check CAA before you spend an attempt.** A CA is required to read the CAA record set for the name it is issuing for, climbing the tree and stopping at the first ancestor that has one — so a record at `example.com` governs `dns.example.com` whenever the label itself has none. A non-empty set that omits `letsencrypt.org` is a hard refusal, and the error text mentions neither DNS nor your firewall, which is why this belongs in a preflight rather than in a troubleshooting section. Domains that were ever managed by a corporate CA, a hosting control panel, or anyone working through a hardening checklist frequently carry one already.

```bash
for n in dns.example.com example.com; do
  printf '%-22s ' "$n"; dig +short CAA "$n" | tr '\n' ' '; echo
done
# PASS: both empty (any CA may issue), or the closest non-empty set contains
#       0 issue "letsencrypt.org"
# If a set exists and omits letsencrypt.org: fix the record, then wait out its TTL
# (dig +noall +answer CAA example.com) before running anything below.
```

Empty is a pass, not a good state. With no CAA anywhere, any of the roughly ninety CAs in the public trust stores may issue for this name — and here the certificate *is* the entire client-authentication story for DoT, DoQ and DoH. Android Private DNS pins nothing and has no fallback (Phase N), and D6 records that Let's Encrypt has shut its OCSP responders down, so there is no revocation signal a client will act on. One mis-issued certificate plus any traffic interception is full plaintext visibility into every query from every client, undetectable from the client side. Publish the record in the zone's own control panel, at the apex so it governs every label beneath it:

```
example.com.  300  IN  CAA  0 issue     "letsencrypt.org"
example.com.  300  IN  CAA  0 issuewild ";"
example.com.  300  IN  CAA  0 iodef     "mailto:admin@example.com"
```

`issuewild ";"` forbids wildcard issuance outright, and `iodef` should carry the abuse mailbox Phase Q defines so an unauthorised issuance attempt reports somewhere a human reads. **The ordering trap is `issuewild`:** if Phase P later selects the ClientID-as-SNI form, D7's wildcard needs that record relaxed to `0 issuewild "letsencrypt.org"` *before* certbot runs, or the DNS-01 switch fails a CAA check and you spend attempts diagnosing a certificate problem that lives in the zone.

Optionally narrow it to this host's own ACME account — the difference between "only Let's Encrypt may issue" and "only my Let's Encrypt account may issue":

```bash
jq -r .uri /etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/*/regr.json
# -> https://acme-v02.api.letsencrypt.org/acme/acct/<id>, which becomes
#    0 issue "letsencrypt.org;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<id>"
```

Do that only *after* the production issuance below has succeeded, since the account does not exist until then. The cost is that losing `/etc/letsencrypt/accounts/` now means editing DNS before you can reissue during an incident; K3 takes `/etc/letsencrypt` whole for exactly that reason. Do **not** add `validationmethods=http-01` alongside it: D3 keeps HTTP-01, but Phase P may move issuance to DNS-01, and that parameter would then have to be edited in lockstep with a phase that has no reason to know it exists.

**Then rehearse the whole thing for free.** `--dry-run` runs the entire issuance against Let's Encrypt's staging environment, which has far higher limits, and saves nothing to disk. It is the only way to exercise the real path — DNS, the firewall, the IPv6 leg, CAA — at zero cost to the production budget.

```bash
certbot certonly --standalone --dry-run \
  -d dns.example.com \
  --cert-name dns.example.com \
  --key-type ecdsa --elliptic-curve secp256r1 \
  --agree-tos --no-eff-email -m admin@example.com
# expect: "The dry run was successful."
ls /etc/letsencrypt/live/ 2>/dev/null   # on a first build, expect empty: a dry run
                                        # never creates or touches a lineage
```

Do not add `--test-cert` (or its alias `--staging`) to that command. `--dry-run` already selects the staging server, and `--test-cert` *without* `--dry-run` would install an untrusted staging certificate into the `dns.example.com` lineage, which D4's hook then copies to AdGuardHome. One caveat specific to this build: certbot picks staging for `--dry-run` **unless a `server` line exists in `/etc/letsencrypt/cli.ini`** — the same file D1 appends the key-type pins to. Never put a `server =` line there, or every future "dry run" quietly spends production budget.

Only once the dry run passes, issue for real:

```bash
certbot certonly --standalone \
  -d dns.example.com \
  --cert-name dns.example.com \
  --key-type ecdsa --elliptic-curve secp256r1 \
  --agree-tos --no-eff-email -m admin@example.com
```

If you are re-issuing over an existing RSA lineage, add `--force-renewal` — and run it **once**. Each forced re-issue consumes one of Let's Encrypt's five duplicate-certificate-per-week slots for that exact name set, and burning them leaves you unable to reissue during an incident.

```bash
openssl x509 -in /etc/letsencrypt/live/dns.example.com/cert.pem -noout -text \
  | grep -A2 'Public Key Algorithm'
# expect: Public Key Algorithm: id-ecPublicKey
#         Public-Key: (256 bit)
```

### D3. Switch the renewal authenticator once nginx owns port 80

`--standalone` opens its own listener on :80. From Phase E4 onward nginx holds :80 and :443, and a standalone renewal will fail with `Could not bind TCP port 80 because it is already in use`. Certbot records the authenticator per lineage in `/etc/letsencrypt/renewal/dns.example.com.conf`, so the fix is to re-run `certonly` once with the method you want persisted — not to edit that file by hand.

Two workable modes. Prefer **webroot**: it touches nothing but a directory, so an nginx config error cannot also break renewal.

There is exactly **one** `:80` server block on this host and exactly **one** webroot behind it, `/var/www/acme`. **Phase E4 writes both**, and Phase Q publishes its `/.well-known/` files as an additional *location* inside that same block rather than as a second listener with a second root. So the `-w` path below is not a Phase D invention: it must match Phase E4's `root` verbatim, or ACME validation 404s against a directory certbot is happily writing to.

```bash
# Run AFTER Phase E4 has nginx serving :80 with the acme-challenge location.
# install -d is idempotent; E4 creates this same directory with these same modes.
install -d -m 0755 /var/www/acme
certbot certonly --webroot -w /var/www/acme \
  -d dns.example.com --cert-name dns.example.com \
  --agree-tos --no-eff-email -m admin@example.com
grep -E '^(authenticator|webroot_path)' /etc/letsencrypt/renewal/dns.example.com.conf
# expect: authenticator = webroot   /   webroot_path = /var/www/acme,
```

The alternative is the nginx plugin, which writes a temporary `server` block, reloads nginx, validates, then reverts:

```bash
certbot certonly --nginx -d dns.example.com --cert-name dns.example.com
```

Use it only if you are comfortable with renewal mutating your nginx config unattended. Do **not** use `--pre-hook 'systemctl stop nginx'` / `--post-hook 'systemctl start nginx'` to keep `--standalone` alive: it takes the public DoH endpoint down for the duration of every renewal attempt, including failed ones, and a hook that fails mid-run leaves nginx stopped.

### D4. Deploy hook — one certificate, two consumers

The hook copies the certificate into AdGuardHome's own tree with ownership AdGuardHome can read, and reloads nginx. It must be idempotent, must tolerate either service not existing yet (it is created in Phase D but AdGuardHome's unit only appears in Phase E5), and must not act on lineages other than the one it names.

```bash
cat > /etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh << 'EOF'
#!/bin/bash
set -euo pipefail

LINEAGE=dns.example.com
SRC=/etc/letsencrypt/live/$LINEAGE
DST=/opt/adguardhome/conf/ssl

# renewal-hooks/deploy/ runs for EVERY renewed lineage. If Phase P later adds a
# wildcard lineage, this guard keeps the two from cross-installing.
[ "${RENEWED_LINEAGE:-$SRC}" = "$SRC" ] || exit 0

install -d -o adguardhome -g adguardhome -m 0750 "$DST"
install -o adguardhome -g adguardhome -m 0640 "$SRC/fullchain.pem" "$DST/fullchain.pem"
install -o adguardhome -g adguardhome -m 0640 "$SRC/privkey.pem"   "$DST/privkey.pem"

# nginx reads /etc/letsencrypt directly (master runs as root); a reload re-reads
# both cert and key with no dropped connections.
systemctl is-active --quiet nginx && systemctl reload nginx || true

# AdGuardHome >= v0.107.72 watches the cert and key files and hot-reloads TLS
# (CHANGELOG v0.107.72, 2026-02-19, issue #3962). On that version or newer, do
# NOT restart: Go's TLS session-ticket keys are process-local, so a restart
# invalidates every client's resumption ticket and converts the whole client
# base into simultaneous full handshakes -- the exact expensive operation, all
# at once, every 60 days. On older builds the restart is the only reload path.
# Always the `current` symlink (Phase E1), never a versioned release directory:
# Phase M's upgrade/rollback moves that symlink, and a pinned versioned path
# would leave this hook version-probing a binary the service no longer runs.
AGH=/opt/adguardhome/current/AdGuardHome
if ! systemctl is-active --quiet adguardhome; then
  systemctl start adguardhome || true
elif ! "$AGH" --version 2>/dev/null \
     | grep -qE 'v0\.10[89]|v0\.107\.(7[2-9]|[89][0-9])'; then
  systemctl try-restart adguardhome || true
fi
EOF
chmod 0700 /etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh

# Run once now, so Phase E5 finds the cert already in place.
/etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh
```

Ownership matters in both directions: `0640 adguardhome:adguardhome` is readable by the service user and by nobody else, and it survives `ProtectSystem=strict` because `/opt/adguardhome` is in the unit's `ReadWritePaths` (Phase E5). Do not point AdGuardHome at `/etc/letsencrypt/live/...` directly — the `archive` directory holding the real key is root-only `0600`, and loosening it to make AdGuardHome work makes the key readable by whatever else runs on the box.

```bash
ls -l /opt/adguardhome/conf/ssl/
# expect: -rw-r----- 1 adguardhome adguardhome ... fullchain.pem / privkey.pem
journalctl -u adguardhome --since -5m --no-pager | grep -i certificate
```

### D5. Prove renewal actually runs unattended

```bash
certbot renew --dry-run
systemctl list-timers snap.certbot.renew.service certbot.timer --all | head
systemctl is-enabled certbot.timer    # expect: enabled
```

The dry run exercises the authenticator but **not** the deploy hook (certbot skips deploy hooks on dry runs). Test the hook path separately by running it by hand, as D4 already does. A renewal that succeeds while the hook is broken leaves AdGuardHome serving the old certificate until it expires, and nothing else in this plan notices.

### D6. Revocation, OCSP, and what not to configure

Let's Encrypt has retired OCSP. Must-Staple issuance was blocked 2025-01-30, OCSP URLs were removed from issued certificates (and CRL URLs added) 2025-05-07, and the responders were shut down 2025-08-06. Consequences, recorded here so nobody re-adds them later:

- `ssl_stapling on;` in nginx is a no-op. It is deliberately absent from Phase E4.
- `--must-staple` fails at issuance. Do not pass it.
- Your practical revocation story is "reissue and redeploy quickly", which is an argument for keeping D5's automation healthy rather than for adding revocation machinery.

```bash
openssl x509 -noout -ocsp_uri -in /etc/letsencrypt/live/dns.example.com/cert.pem
# expect: EMPTY output. Any URI here means the cert predates 2025-05-07 -- reissue.
```

### D7. The wildcard / DNS-01 path — a Phase P decision, not a Phase D one

HTTP-01 cannot issue wildcards; Let's Encrypt's own documentation is explicit that only DNS-01 can. A wildcard is required for exactly one thing in this design: the **ClientID-as-SNI** form `<id>.dns.example.com` used by Android Private DNS, DoT and DoQ clients. The DoH URL-path form (`https://dns.example.com/dns-query/<id>`) needs neither a wildcard certificate nor a wildcard DNS record.

Do not decide this here. **See Phase P** for the access-layer decision matrix, the wildcard A/AAAA records that must exist *before* certbot runs (without them clients fail at NXDOMAIN long before any certificate error), the provider plugin selection, and the credential file handling. If Phase P does select it, D0's resolution check and D2's CAA preflight both have to be re-run for the wildcard name — in particular the `0 issuewild ";"` record D2 publishes must be relaxed first, because it is precisely a wildcard that it forbids. If Phase P selects the SNI form, the only Phase D change is the issuance command; D4's hook and D5's automation are unchanged because the lineage directory keeps the same name when `--cert-name dns.example.com` is passed. Confirm that with `ls /etc/letsencrypt/live/` after issuance rather than assuming it — certbot names a lineage after the first `-d` with the wildcard stripped when `--cert-name` is omitted.

One knock-on worth knowing now, and the limit of it: DNS-01 needs no inbound HTTP, so switching to it removes ACME as a *reason* for port 80 — but it does not close the port. **TCP/80 stays permanently open in this design regardless of the issuance method.** Phase B carries a standing `tcp dport 80 accept`, nginx owns the listener for the life of the host (Phase E4), and Phase Q publishes `security.txt` and the abuse contact as locations inside that same single `:80` server block. Closing the port would take those with it. Do not add a close-it-after-renewal step here or anywhere else.

### D8. Expiry monitoring, Certificate Transparency, and CAA

Expiry alerting is **not** written here. A cron job that only writes to syslog is not an alert, and the alerting transport, the dead-man's-switch problem, and the metric pipeline all belong together — **see Phase I**. What Phase I needs from this phase is one number:

```bash
openssl x509 -enddate -noout -in /etc/letsencrypt/live/dns.example.com/cert.pem
```

Certificate Transparency: every certificate Let's Encrypt issues is published to public CT logs, so `dns.example.com` becomes a public fact the moment D2 completes — **see Phase Q** for whether that is acceptable and what the wildcard alternative changes.

CT and the CAA record published in D2 are the two halves of one control, and it is worth naming which half does what. CT is **detection**: it tells you, after issuance and only if somebody is watching a log feed, that a certificate for this name exists. CAA is **prevention**: it is what stops most of those certificates from being issued at all. On this service the detection half is weaker than on a web server, because D6 leaves no revocation signal a client will honour — by the time CT shows you a certificate you did not ask for, there is nothing to do but reissue and hope clients reconnect. That makes the prevention half the one that carries the weight. It also makes it worth re-reading, because a zone migration silently deletes it:

```bash
dig +short CAA example.com
# expect: the D2 record set, unchanged. An empty result means the zone was rebuilt or
# moved provider and the control is gone -- nothing on this host would otherwise notice.
```

### D9. Verification

```bash
# 1. Key type and curve
openssl x509 -in /etc/letsencrypt/live/dns.example.com/cert.pem -noout -text \
  | grep -A3 'Public Key Algorithm'
# PASS: id-ecPublicKey / Public-Key: (256 bit) / NIST CURVE: P-256

# 2. Names on the certificate
openssl x509 -in /etc/letsencrypt/live/dns.example.com/cert.pem -noout -ext subjectAltName
# PASS: DNS:dns.example.com   (plus DNS:*.dns.example.com only if Phase P applies)

# 3. Renewal is configured for a method that survives nginx owning :80
grep -E '^(authenticator|installer|webroot_path|key_type)' \
  /etc/letsencrypt/renewal/dns.example.com.conf
# PASS: authenticator = webroot (or nginx). FAIL: authenticator = standalone

# 4. Unattended renewal path works end to end
certbot renew --dry-run 2>&1 | tail -5   # PASS: "simulated renewals ... succeeded"

# 5. AdGuardHome's copy exists, is current, and has the right owner
ls -l /opt/adguardhome/conf/ssl/
cmp /etc/letsencrypt/live/dns.example.com/fullchain.pem \
    /opt/adguardhome/conf/ssl/fullchain.pem && echo 'OK: copy is current'

# 6. What is actually served on the wire, on both TLS-terminating listeners
openssl s_client -connect dns.example.com:443 -servername dns.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -dates -ext subjectAltName
openssl s_client -connect dns.example.com:853 -servername dns.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -dates
# Both must show the same P-256 certificate and the same notAfter.

# 7. No OCSP dependency anywhere
openssl x509 -noout -ocsp_uri -in /etc/letsencrypt/live/dns.example.com/cert.pem
# PASS: no output

# 8. The name still points here, and CAA still constrains who may issue for it
dig +short A dns.example.com @1.1.1.1
ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1
# PASS: identical (D0)
dig +short CAA example.com
# PASS: non-empty, contains 0 issue "letsencrypt.org" (D2).
# FAIL-OPEN WARNING: empty output is not an error from certbot's point of view -- it
# means any public CA may issue for the name that authenticates every DoT/DoQ/DoH client.
```

---

[Plan index](../dns-server-plan.md) · [Previous: Unbound Recursive Resolver](./03-unbound-resolver.md) · [Next: AdGuardHome and the Public Edge](./05-adguardhome-edge.md)
