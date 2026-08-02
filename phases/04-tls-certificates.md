[Plan index](../dns-server-plan.md) · [Previous: Unbound Recursive Resolver](./03-unbound-resolver.md) · [Next: AdGuardHome and the Public Edge](./05-adguardhome-edge.md)

---

**On this page**

- [PHASE D: TLS Certificates](#phase-d-tls-certificates)
  - [D1. Install certbot](#d1-install-certbot)
  - [D2. First issuance — HTTP-01 standalone](#d2-first-issuance-http-01-standalone)
  - [D3. Switch the renewal authenticator once nginx owns port 80](#d3-switch-the-renewal-authenticator-once-nginx-owns-port-80)
  - [D4. Deploy hook — one certificate, two consumers](#d4-deploy-hook-one-certificate-two-consumers)
  - [D5. Prove renewal actually runs unattended](#d5-prove-renewal-actually-runs-unattended)
  - [D6. Revocation, OCSP, and what not to configure](#d6-revocation-ocsp-and-what-not-to-configure)
  - [D7. The wildcard / DNS-01 path — a Phase P decision, not a Phase D one](#d7-the-wildcard-dns-01-path-a-phase-p-decision-not-a-phase-d-one)
  - [D8. Expiry monitoring and Certificate Transparency](#d8-expiry-monitoring-and-certificate-transparency)
  - [D9. Verification](#d9-verification)

---

## PHASE D: TLS Certificates

This phase issues one certificate that three consumers read: nginx (public :443, Phase E4), AdGuardHome's DoT/DoQ listeners on :853, and AdGuardHome's loopback DoH backend on 127.0.0.1:8053. nginx runs its master as root and reads `/etc/letsencrypt/live/...` directly; AdGuardHome runs unprivileged under `ProtectSystem=strict` and cannot, so it gets a copy. That asymmetry is the reason the deploy hook in D4 exists at all.

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

Do not decide this here. **See Phase P** for the access-layer decision matrix, the wildcard A/AAAA records that must exist *before* certbot runs (without them clients fail at NXDOMAIN long before any certificate error), the provider plugin selection, and the credential file handling. If Phase P selects the SNI form, the only Phase D change is the issuance command; D4's hook and D5's automation are unchanged because the lineage directory keeps the same name when `--cert-name dns.example.com` is passed. Confirm that with `ls /etc/letsencrypt/live/` after issuance rather than assuming it — certbot names a lineage after the first `-d` with the wildcard stripped when `--cert-name` is omitted.

One knock-on worth knowing now, and the limit of it: DNS-01 needs no inbound HTTP, so switching to it removes ACME as a *reason* for port 80 — but it does not close the port. **TCP/80 stays permanently open in this design regardless of the issuance method.** Phase B carries a standing `tcp dport 80 accept`, nginx owns the listener for the life of the host (Phase E4), and Phase Q publishes `security.txt` and the abuse contact as locations inside that same single `:80` server block. Closing the port would take those with it. Do not add a close-it-after-renewal step here or anywhere else.

### D8. Expiry monitoring and Certificate Transparency

Expiry alerting is **not** written here. A cron job that only writes to syslog is not an alert, and the alerting transport, the dead-man's-switch problem, and the metric pipeline all belong together — **see Phase I**. What Phase I needs from this phase is one number:

```bash
openssl x509 -enddate -noout -in /etc/letsencrypt/live/dns.example.com/cert.pem
```

Certificate Transparency: every certificate Let's Encrypt issues is published to public CT logs, so `dns.example.com` becomes a public fact the moment D2 completes — **see Phase Q** for whether that is acceptable and what the wildcard alternative changes.

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
```

---

[Plan index](../dns-server-plan.md) · [Previous: Unbound Recursive Resolver](./03-unbound-resolver.md) · [Next: AdGuardHome and the Public Edge](./05-adguardhome-edge.md)
