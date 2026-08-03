#!/usr/bin/env bash
# deploy/phases/D-tls-certificates.sh — Phase D: TLS Certificates
# Source: phases/04-tls-certificates.md (read in full). Transcription only —
# no directive here has been invented; every command/flag/path is copied from
# that file. Read the source file before running this script.
#
# This phase issues one certificate that three consumers read: nginx (public
# :443, Phase E4), AdGuardHome's DoT/DoQ listeners on :853, and AdGuardHome's
# loopback DoH backend on 127.0.0.1:8053. D4's deploy hook is why: nginx runs
# as root and reads /etc/letsencrypt/live/... directly, AdGuardHome runs
# unprivileged under ProtectSystem=strict and cannot, so it gets a copy.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=lib/common.sh
source lib/common.sh

require_root
phase_header "Phase D — TLS certificates (ECDSA issuance, deploy hook feeding nginx and AdGuardHome)"

# --- Phase-wide identifiers, exactly as used throughout phases/04-tls-certificates.md.
# Replace with the real domain/email before running against production. ---
DOMAIN="dns.example.com"
APEX="example.com"
EMAIL="admin@example.com"

info "Let's Encrypt allows 5 authorization failures per identifier/account/hour (refilling one every 12 min), plus 1,152 consecutive failures per identifier that resets only on success. A mismatched record below is a STOP, not a retry."

# =====================================================================
# D0. Prerequisites — the name must already resolve
# =====================================================================
phase_header "D0: prerequisites — the name must already resolve"
info "See Phase 0 in the plan index (../dns-server-plan.md) for who owns the zone, nameserver/TTL requirements, and account credential storage. Phase D creates none of that; it only refuses to proceed until it is already true."

require_cmd dig ip

# --- D0: this host's public address, as the world will see it ---
PUB=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
echo "$PUB"

# --- D0: the name, from two independent public resolvers, and from Phase C's Unbound
#     (which recurses from the root, so it answers from the zone, not a cache) ---
for r in 1.1.1.1 9.9.9.9; do printf '%-9s ' "$r"; dig +short A "$DOMAIN" @"$r"; done
dig +short A "$DOMAIN" @127.0.0.1 -p 5335
# PASS: all three return exactly $PUB and nothing else.
warn "D0: manually confirm all three A-record lookups above equal \$PUB ($PUB) before continuing. This is a human judgement call — the plan does not script an abort here."

# --- D0: if the two public resolvers diverge, read the remaining TTL and wait it out;
#     do not run certbot against a half-propagated record. Local Unbound caches too. ---
dig +noall +answer A "$DOMAIN" @1.1.1.1   # field 2 is the remaining TTL, in seconds
command -v unbound-control >/dev/null 2>&1 && unbound-control flush "$DOMAIN" || \
    warn "D0: unbound-control not found — flush $DOMAIN in Unbound's cache by hand before re-checking."

# --- D0: whether to publish an AAAA is a decision (business/design choice), not a
#     scriptable step. See phases/04-tls-certificates.md D0 for the A-only vs A+AAAA
#     tradeoff. Let's Encrypt tries IPv6 first when both A and AAAA exist and does not
#     retry a v6 address that accepts the connection and then misbehaves. ---
warn "D0: MANUAL DECISION — publish AAAA or not? See phases/04-tls-certificates.md D0. Not scripted; a wrong AAAA fails HTTP-01 even when the A record is perfect."
dig +short AAAA "$DOMAIN" @1.1.1.1
ip -6 -o addr show scope global | awk '{print $4}' | cut -d/ -f1
# PASS: identical, or BOTH empty. Reachability itself is proved by the D2 staging dry
# run, not here — nothing is listening on :80 until certbot binds it.

# =====================================================================
# D1. Install certbot
# =====================================================================
phase_header "D1: install certbot"

apt install -y certbot python3-certbot-nginx
certbot --version    # expect: certbot 2.9.0

require_cmd certbot openssl jq

# --- D1: make the ECDSA key type sticky for every future issuance/renewal on this
#     host. Certbot 2.x already defaults to ECDSA; pin it anyway so a future
#     --key-type regression or a hand-typed certonly elsewhere on the box cannot
#     silently issue RSA-2048. Idempotency guard added so re-running this phase does
#     not duplicate the block in cli.ini — the pinned values themselves are unchanged
#     from the source. ---
if ! grep -qs '^key-type = ecdsa' /etc/letsencrypt/cli.ini; then
    cat >> /etc/letsencrypt/cli.ini << 'EOF'
key-type = ecdsa
elliptic-curve = secp256r1
EOF
    info "D1: appended ECDSA key-type pin to /etc/letsencrypt/cli.ini"
else
    info "D1: /etc/letsencrypt/cli.ini already pins key-type = ecdsa, skipping append"
fi
warn "D1: never add a 'server = ...' line to /etc/letsencrypt/cli.ini — it would make every future 'certbot ... --dry-run' quietly spend production rate-limit budget."

# --- D1: measure the RSA-2048 vs ECDSA P-256 handshake cost on the CPU actually
#     given to this host (informational; do not trust the plan's own ballpark figures) ---
openssl speed -seconds 3 rsa2048 ecdsap256

# =====================================================================
# D2. First issuance — HTTP-01 standalone
# =====================================================================
phase_header "D2: first issuance — HTTP-01 standalone"
info "D2: nothing is listening on :80 yet at this point in the build order, so --standalone can bind it. Phase B leaves TCP/80 permanently open."

# --- D2: check CAA before spending an issuance attempt. A CA must read the CAA
#     record set for the name being issued, climbing to the first ancestor that has
#     one — a record at example.com governs dns.example.com when the label itself
#     has none. ---
for n in "$DOMAIN" "$APEX"; do
  printf '%-22s ' "$n"; dig +short CAA "$n" | tr '\n' ' '; echo
done
# PASS: both empty (any CA may issue), or the closest non-empty set contains
#       0 issue "letsencrypt.org"
# If a set exists and omits letsencrypt.org: fix the record, then wait out its TTL
# (dig +noall +answer CAA example.com) before running anything below.

# --- D2: MANUAL STEP — publish the CAA record set in the zone's own control panel,
#     at the apex so it governs every label beneath it. This host does not serve the
#     zone (see D0/Phase 0) and cannot do this for you. ---
warn "D2: MANUAL STEP — publish the CAA records below in the zone's control panel at the apex. Do not proceed until 'dig +short CAA $APEX' reflects them and the TTL has elapsed. issuewild \";\" forbids wildcard issuance; iodef should carry the abuse mailbox Phase Q defines."
cat << CAAEOF
${APEX}.  300  IN  CAA  0 issue     "letsencrypt.org"
${APEX}.  300  IN  CAA  0 issuewild ";"
${APEX}.  300  IN  CAA  0 iodef     "mailto:${EMAIL}"
CAAEOF
info "D2: ordering trap — if Phase P later selects the ClientID-as-SNI wildcard form, the issuewild record above must be relaxed to '0 issuewild \"letsencrypt.org\"' BEFORE certbot runs for that lineage, or the DNS-01 switch fails CAA."

# --- D2: rehearse the whole issuance for free against Let's Encrypt staging before
#     spending a production attempt. Do NOT add --test-cert/--staging alongside
#     --dry-run, and never add a 'server =' line to cli.ini (D1) or "dry runs" will
#     quietly spend production budget. ---
certbot certonly --standalone --dry-run \
  -d "$DOMAIN" \
  --cert-name "$DOMAIN" \
  --key-type ecdsa --elliptic-curve secp256r1 \
  --agree-tos --no-eff-email -m "$EMAIL"
# expect: "The dry run was successful."
ls /etc/letsencrypt/live/ 2>/dev/null   # on a first build, expect empty: a dry run
                                        # never creates or touches a lineage

# --- D2: production issuance. --standalone binds :80 itself for this one run. ---
confirm "D2: run PRODUCTION certbot issuance (--standalone, binds :80) for $DOMAIN — consumes a real Let's Encrypt rate-limit slot. Continue?"
certbot certonly --standalone \
  -d "$DOMAIN" \
  --cert-name "$DOMAIN" \
  --key-type ecdsa --elliptic-curve secp256r1 \
  --agree-tos --no-eff-email -m "$EMAIL"
# NOTE: if re-issuing over an existing RSA lineage, add --force-renewal to the command
# above by hand and run it ONCE — each forced re-issue consumes one of Let's Encrypt's
# 5 duplicate-certificate-per-week slots for this exact name set.

openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/cert.pem" -noout -text \
  | grep -A2 'Public Key Algorithm'
# expect: Public Key Algorithm: id-ecPublicKey
#         Public-Key: (256 bit)

# --- D2: optional — narrow CAA to this host's own ACME account. Source: "Do that
#     only after the production issuance below has succeeded, since the account does
#     not exist until then." Publishing the narrowed record is itself a manual DNS
#     change; this step only surfaces the accounturi value. ---
jq -r .uri /etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/*/regr.json
warn "D2: OPTIONAL MANUAL STEP — to narrow CAA to only this ACME account, publish 0 issue \"letsencrypt.org;accounturi=<uri printed above>\" at the apex, replacing the plain 0 issue \"letsencrypt.org\" record. Do NOT add validationmethods=http-01 alongside it — Phase P may move issuance to DNS-01."

# =====================================================================
# D3. Switch the renewal authenticator once nginx owns port 80
# =====================================================================
phase_header "D3: switch the renewal authenticator once nginx owns port 80"
info "D3: --standalone opens its own :80 listener. From Phase E4 onward nginx holds :80 and :443 and a standalone renewal fails with 'Could not bind TCP port 80'."

# Source note: "Run AFTER Phase E4 has nginx serving :80 with the acme-challenge
# location." This repo's PHASE_ORDER runs D before E, so this step cannot execute
# unattended as part of Phase D — it is guarded on nginx actually being active and
# skipped (not silently faked) otherwise. Re-run this phase, or this block by hand,
# after Phase E4 has nginx serving :80 with /var/www/acme wired into it.
if systemctl is-active --quiet nginx; then
    # --- D3: webroot authenticator — touches nothing but a directory, so an nginx
    #     config error cannot also break renewal. The -w path below MUST match
    #     Phase E4's root verbatim (Phase E4 writes /var/www/acme; Phase D does not
    #     own that directory, it only reuses the same path certbot will write into). ---
    install -d -m 0755 /var/www/acme    # idempotent; E4 creates this same directory/modes
    confirm "D3: switch $DOMAIN certbot renewal authenticator to --webroot (re-issues now via /var/www/acme) — continue?"
    certbot certonly --webroot -w /var/www/acme \
      -d "$DOMAIN" --cert-name "$DOMAIN" \
      --agree-tos --no-eff-email -m "$EMAIL"
    grep -E '^(authenticator|webroot_path)' "/etc/letsencrypt/renewal/$DOMAIN.conf"
    # expect: authenticator = webroot   /   webroot_path = /var/www/acme,
else
    warn "D3: nginx is not active — skipping the webroot authenticator switch." \
         " Renewal is still on --standalone from D2 until this step is re-run after" \
         " Phase E4 stands nginx up on :80/:443."
fi

# Alternative authenticator (NOT run by default — source: "Use it only if you are
# comfortable with renewal mutating your nginx config unattended"):
#   certbot certonly --nginx -d "$DOMAIN" --cert-name "$DOMAIN"
# Do NOT use --pre-hook 'systemctl stop nginx' / --post-hook 'systemctl start nginx'
# to keep --standalone alive instead: it takes the public DoH endpoint down for the
# duration of every renewal attempt, including failed ones, and a hook that fails
# mid-run leaves nginx stopped.

# =====================================================================
# D4. Deploy hook — one certificate, two consumers
# =====================================================================
phase_header "D4: deploy hook — one certificate, two consumers"

HOOK=/etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh
backup_file "$HOOK"
install -d -m 0755 "$(dirname "$HOOK")"
cat > "$HOOK" << 'EOF'
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
chmod 0700 "$HOOK"
info "D4: wrote deploy hook: $HOOK"
info "D4: 0640 adguardhome:adguardhome survives ProtectSystem=strict because /opt/adguardhome is in the unit's ReadWritePaths (Phase E5). Never point AdGuardHome at /etc/letsencrypt/live/... directly — its archive/ directory holding the real key is root-only 0600."

# --- D4: run the hook once now, so Phase E5 finds the cert already in place. This
#     copies the key into /opt/adguardhome/conf/ssl and may reload nginx / restart
#     adguardhome — both boot services. ---
confirm "D4: run $HOOK now (copies cert+key to /opt/adguardhome/conf/ssl, reloads nginx if active, may restart adguardhome) — continue?"
"$HOOK"

# --- D4: verify ownership and that AdGuardHome picked it up ---
ls -l /opt/adguardhome/conf/ssl/
# expect: -rw-r----- 1 adguardhome adguardhome ... fullchain.pem / privkey.pem
journalctl -u adguardhome --since -5m --no-pager | grep -i certificate || true

# =====================================================================
# D5. Prove renewal actually runs unattended
# =====================================================================
phase_header "D5: prove renewal actually runs unattended"

certbot renew --dry-run
systemctl list-timers snap.certbot.renew.service certbot.timer --all | head
systemctl is-enabled certbot.timer    # expect: enabled

warn "D5: certbot skips deploy hooks on dry runs — this exercises the authenticator but NOT the D4 hook. The hook path was already tested by hand in D4. A renewal that succeeds while the hook is broken leaves AdGuardHome serving the old certificate until it expires, and nothing else in this plan notices."

# =====================================================================
# D6. Revocation, OCSP, and what not to configure
# =====================================================================
phase_header "D6: revocation, OCSP, and what not to configure"
warn "D6: Let's Encrypt has retired OCSP (Must-Staple blocked 2025-01-30, OCSP URLs removed 2025-05-07, responders shut down 2025-08-06). Do NOT add 'ssl_stapling on;' to nginx (Phase E4, deliberately absent) — it is a no-op. Do NOT pass --must-staple to certbot — it fails at issuance."

openssl x509 -noout -ocsp_uri -in "/etc/letsencrypt/live/$DOMAIN/cert.pem"
# expect: EMPTY output. Any URI here means the cert predates 2025-05-07 -- reissue.

# =====================================================================
# D7. The wildcard / DNS-01 path — a Phase P decision, not a Phase D one
# =====================================================================
phase_header "D7: the wildcard / DNS-01 path — a Phase P decision, not a Phase D one"
warn "D7: MANUAL / DEFERRED — a wildcard cert is only needed for the ClientID-as-SNI form used by Android Private DNS/DoT/DoQ. Do not action here; see Phase P for the decision matrix, wildcard A/AAAA records (must exist BEFORE certbot runs), provider plugin selection, and credential handling. If Phase P selects it, D0's resolution check and D2's CAA preflight must be re-run for the wildcard name, and D2's '0 issuewild \";\"' record must be relaxed first. Confirm the lineage name afterward with 'ls /etc/letsencrypt/live/' rather than assuming it."
warn "D7: TCP/80 stays permanently open regardless of issuance method (Phase B's standing tcp dport 80 accept, nginx owns the listener per Phase E4, Phase Q serves security.txt from the same block). Do not add a close-it-after-renewal step here or anywhere else."

# =====================================================================
# D8. Expiry monitoring, Certificate Transparency, and CAA
# =====================================================================
phase_header "D8: expiry monitoring, Certificate Transparency, and CAA"
warn "D8: expiry ALERTING is NOT implemented in this phase — a cron job that only writes to syslog is not an alert. See Phase I for the alerting transport, dead-man's-switch, and metric pipeline. This phase only surfaces the one number Phase I needs:"
openssl x509 -enddate -noout -in "/etc/letsencrypt/live/$DOMAIN/cert.pem"

warn "D8: every certificate Let's Encrypt issues is published to public CT logs — $DOMAIN becomes a public fact the moment D2 completes. See Phase Q for whether that is acceptable and what the wildcard alternative changes."

# --- D8: CT is detection, CAA (published in D2) is prevention. A zone migration can
#     silently delete the CAA control — re-check it periodically. ---
dig +short CAA "$APEX"
# expect: the D2 record set, unchanged. An empty result means the zone was rebuilt or
# moved provider and the control is gone -- nothing on this host would otherwise notice.

# =====================================================================
# D9. Verification
# =====================================================================
phase_header "D9: verification"

# 1. Key type and curve
openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/cert.pem" -noout -text \
  | grep -A3 'Public Key Algorithm'
# PASS: id-ecPublicKey / Public-Key: (256 bit) / NIST CURVE: P-256

# 2. Names on the certificate
openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/cert.pem" -noout -ext subjectAltName
# PASS: DNS:dns.example.com   (plus DNS:*.dns.example.com only if Phase P applies)

# 3. Renewal is configured for a method that survives nginx owning :80
grep -E '^(authenticator|installer|webroot_path|key_type)' \
  "/etc/letsencrypt/renewal/$DOMAIN.conf"
# PASS: authenticator = webroot (or nginx). FAIL: authenticator = standalone

# 4. Unattended renewal path works end to end
certbot renew --dry-run 2>&1 | tail -5   # PASS: "simulated renewals ... succeeded"

# 5. AdGuardHome's copy exists, is current, and has the right owner
ls -l /opt/adguardhome/conf/ssl/
cmp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" \
    /opt/adguardhome/conf/ssl/fullchain.pem && echo 'OK: copy is current'

# 6. What is actually served on the wire, on both TLS-terminating listeners
openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -dates -ext subjectAltName
openssl s_client -connect "$DOMAIN:853" -servername "$DOMAIN" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -dates
# Both must show the same P-256 certificate and the same notAfter.

# 7. No OCSP dependency anywhere
openssl x509 -noout -ocsp_uri -in "/etc/letsencrypt/live/$DOMAIN/cert.pem"
# PASS: no output

# 8. The name still points here, and CAA still constrains who may issue for it
dig +short A "$DOMAIN" @1.1.1.1
ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1
# PASS: identical (D0)
dig +short CAA "$APEX"
# PASS: non-empty, contains 0 issue "letsencrypt.org" (D2).
# FAIL-OPEN WARNING: empty output is not an error from certbot's point of view -- it
# means any public CA may issue for the name that authenticates every DoT/DoQ/DoH client.

echo
echo "Phase D done. 'Worked' means every PASS comment in the D9 block above matched" \
     " what actually printed — re-run the eight checks in D9 by hand at any time with:"
echo "  bash $(basename "${BASH_SOURCE[0]}")   # D9 runs unconditionally at the end of this script"
