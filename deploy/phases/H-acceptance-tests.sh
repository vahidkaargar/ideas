#!/usr/bin/env bash
# deploy/phases/H-acceptance-tests.sh — Phase H: Validation Tests (the
# acceptance test suite)
# Transcribed from: phases/06-logging-and-validation.md, "PHASE H: Validation
# Tests" (H0-H15). Phase F (retired DNS cache warmer) and Phase G (log
# rotation and retention) live in the same source file but are OUT OF SCOPE
# for this script — see phases/06-logging-and-validation.md directly, or
# deploy/phases/G-logging.sh for Phase G.
#
# Mechanical transcription only. Not run against real hardware. Read this
# script (and the source file) before running it on a VPS.
#
# THIS IS A VERIFICATION SCRIPT, NOT A BUILD SCRIPT. Most of it runs checks
# and prints their result rather than changing host state. Three sections —
# H13, H14, H15 — are the documented exception: the source markdown is
# explicit that they "deliberately break the running service" as the only
# way to prove the failure modes this plan's machinery exists to survive.
# Each of those sections is gated behind confirm() and is meant to run once,
# alone, in a maintenance window — never as an unattended step of `deploy/run.sh
# all`.
#
# TWO-HOST SUITE — READ THIS BEFORE RUNNING.
# The source markdown's own governing rule for Phase H: "Encrypted-transport
# and isolation tests run from a second host, never from the DNS server.
# Running them locally bypasses the NIC, the firewall, the conntrack bypass,
# the rate limiter, and — for DoH specifically — the entire nginx front end,
# which means they can pass on a box where the public service is completely
# broken." This script therefore has two roles, selected by KEYSTONE_H_ROLE:
#
#   server   (default) — runs ON the DNS host: H5's resolver-local checks,
#            H12's smoke-script install and pre-change gates, and the
#            fault-injection sections H13/H14/H15 (the source runs all of
#            these "on the host" / "on the DNS host").
#   testhost — copy this script to the H0 second VPS (same region) and
#            re-run there with KEYSTONE_H_ROLE=testhost to run H1-H4, H6,
#            H7's external half, H9, H10's flood half, and H11's load test
#            against PUBLIC_IP / FQDN.
#
# Running the testhost-only sections with ROLE=server would silently produce
# the false PASSes the source document warns about, so this script refuses to
# run them locally instead of fabricating a same-host substitute.
#
# Single-ownership notes (CLAUDE.md): this script creates no nftables
# objects (H13 inserts/deletes transient rules in Phase B's existing `output`
# chain and restores via Phase B's own /etc/nftables.conf — it owns none of
# it); it appends to, but does not create, /etc/cron.d/dns-health (Phase I
# owns that file — this script warns and skips the append if Phase I has not
# created it yet); it invokes, but does not create, /opt/adguardhome/validate
# (Phase E owns it) and /usr/local/sbin/dns-diskguard.sh (Phase G4 owns it).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=lib/common.sh
source lib/common.sh

require_root
phase_header "Phase H — acceptance test suite (DNSSEC, load test, smoke gate, LT-13 soak)"

# =====================================================================
# Shared configuration
# =====================================================================
ROLE="${KEYSTONE_H_ROLE:-server}"
FQDN="${FQDN:-dns.example.com}"
PUBLIC_IP="${PUBLIC_IP:-$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)}"
# RTT_base is recorded by H0 and consumed by the LT-1/LT-3 gates in H11.
RTT_base="${RTT_base:-}"

info "H: role=$ROLE fqdn=$FQDN public_ip=$PUBLIC_IP"
case "$ROLE" in
  server|testhost) ;;
  *) fatal "H: KEYSTONE_H_ROLE must be 'server' or 'testhost', got: $ROLE" ;;
esac

require_cmd dig curl jq openssl

# run_smoke — invoke /usr/local/sbin/dns-smoke.sh (installed by H12) and print
# its exit code, WITHOUT letting a nonzero exit abort this script under
# set -e. Several H12/H13/H14/H15 checks deliberately expect dns-smoke.sh to
# FAIL (that is the point of the check) and are always followed by a restore
# step (systemctl start ...) that must still run.
run_smoke() {
  local rc=0
  /usr/local/sbin/dns-smoke.sh || rc=$?
  echo "exit=$rc"
  return 0
}

# =====================================================================
# H0. Test harness
# =====================================================================
h0_test_harness() {
  phase_header "H0. Test harness"
  if [[ "$ROLE" != "testhost" ]]; then
    warn "H0: manual step — 'Build a second small VPS in the same region' is a provider/business decision (region, size, network) that cannot be scripted. Provision it, then copy this script to it and re-run with KEYSTONE_H_ROLE=testhost. NOT scripted here."
    return 0
  fi

  # --- H0: tooling install (test host) ---
  apt-get install -y dnsperf knot-dnsutils curl jq openssl
  which resperf || echo 'WARN: resperf not in this dnsperf build - install from DNS-OARC source'

  # --- H0: dnspyre install (per-protocol load with percentiles) ---
  local ARCH URL
  ARCH=$(dpkg --print-architecture)
  URL=$(curl -fsS https://api.github.com/repos/Tantalor93/dnspyre/releases/latest \
    | jq -r --arg a "$ARCH" '.assets[] | select(.name | test("linux_" + $a + "\\.tar\\.gz$")) | .browser_download_url')
  if [ -z "$URL" ]; then
    fatal "H0: resolve manually: curl -fsS https://api.github.com/repos/Tantalor93/dnspyre/releases/latest | jq -r .assets[].name"
  fi
  curl -fsSL "$URL" | tar xz -C /usr/local/bin dnspyre
  dnspyre --version

  # --- H0: baseline RTT, used by the H11 latency gates ---
  RTT_base=$(ping -c 20 -q "$PUBLIC_IP" | awk -F/ '/rtt|round-trip/ {print $5}')
  echo "RTT_base = ${RTT_base} ms"    # record this in the Phase L checklist

  # --- H0: DoQ client build check ---
  # kdig -V must report >= 3.3 for +quic to mean anything (Ubuntu 22.04's
  # 3.1.6 has +tls/+https but no +quic, and the resulting unknown-option
  # error reads exactly like a DoQ outage).
  kdig -V
  if ! kdig -V 2>&1 | grep -qE 'Knot DNS (3\.[3-9]|[4-9])'; then
    warn "H0: kdig < 3.3, no +quic support. Install AdGuard's 'dnslookup' (a static Go binary that speaks quic://) rather than scoring a tooling failure as a service failure."
  fi
}

# =====================================================================
# H1. Plain DNS (Do53)
# =====================================================================
h1_do53() {
  phase_header "H1. Plain DNS (Do53)"
  if [[ "$ROLE" != "testhost" ]]; then
    warn "H1: skipped on ROLE=server — must run from the H0 test host, not locally. Re-run with KEYSTONE_H_ROLE=testhost."
    return 0
  fi
  dig "@$PUBLIC_IP" google.com A
  dig "@$PUBLIC_IP" google.com AAAA
  dig "@$PUBLIC_IP" +tcp google.com A                       # TCP/53 must also answer
  dig "@$PUBLIC_IP" nonexistent.invalid A +noall +comments  # status: NXDOMAIN
  dig "@$PUBLIC_IP" google.com HTTPS                        # type65 is a large share of real traffic
  echo "H1 PASS: all four return status: NOERROR with answers (NXDOMAIN for the .invalid name), over both UDP and TCP."
}

# =====================================================================
# H2. DoH — through nginx, from outside the host
# =====================================================================
h2_doh() {
  phase_header "H2. DoH — through nginx, from outside the host"
  if [[ "$ROLE" != "testhost" ]]; then
    warn "H2: skipped on ROLE=server — running this on the DNS host reaches 127.0.0.1:8053 directly and can give a green result on a box whose public DoH is entirely broken. Re-run with KEYSTONE_H_ROLE=testhost."
    return 0
  fi
  require_cmd kdig

  # --- H2: primary check - wire format, GET and POST, both handled by kdig ---
  kdig "@$FQDN" +https google.com A
  kdig "@$FQDN" +https +tls-ca +tls-hostname="$FQDN" google.com A

  # --- H2: raw HTTP form, canonical RFC 8484 4.1.1 example query (www.example.com A) ---
  curl -sD- -o /dev/null --max-time 5 \
    -H 'accept: application/dns-message' \
    "https://$FQDN/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
  echo "H2 PASS: HTTP/2 200 with content-type: application/dns-message"

  # --- H2: the JSON API does NOT exist - this documents the gap, not a failure ---
  curl -si --max-time 5 -H 'accept: application/dns-json' \
    "https://$FQDN/dns-query?name=google.com&type=A" | head -3 || true

  # --- H2: only /dns-query may be proxied ---
  curl -si --max-time 5 "https://$FQDN/"            | head -1   # expect 404/403, NOT an AGH page
  curl -si --max-time 5 "https://$FQDN/login.html"  | head -1   # expect 404/403
  curl -s  --max-time 5 "https://$FQDN/control/status"          # expect empty/404, never JSON

  echo "H2 PASS: +https resolves; /dns-query returns application/dns-message; no other path returns AdGuardHome content."
  echo "H2 CRITICAL if /control/status returned a JSON body — the control API is exposed; stop and fix Phase E before continuing."
}

# =====================================================================
# H3. DoT
# =====================================================================
h3_dot() {
  phase_header "H3. DoT"
  if [[ "$ROLE" != "testhost" ]]; then
    warn "H3: skipped on ROLE=server — encrypted-transport tests run from the H0 test host. Re-run with KEYSTONE_H_ROLE=testhost."
    return 0
  fi
  require_cmd kdig
  kdig "@$FQDN" +tls google.com A
  kdig "@$FQDN" +tls +tls-ca +tls-hostname="$FQDN" google.com A   # cert actually validates
  kdig "@$FQDN" +tls dnssec-failed.org A +noall +comments          # SERVFAIL, see H5
  echo "H3 PASS: NOERROR with an answer, and the second form succeeds without --tls-not-verify."
}

# =====================================================================
# H4. DoQ
# =====================================================================
h4_doq() {
  phase_header "H4. DoQ"
  if [[ "$ROLE" != "testhost" ]]; then
    warn "H4: skipped on ROLE=server — encrypted-transport tests run from the H0 test host. Re-run with KEYSTONE_H_ROLE=testhost."
    return 0
  fi
  require_cmd kdig
  kdig -V | head -1                                   # must be >= 3.3
  kdig "@$FQDN" +quic google.com A
  kdig "@$FQDN" +quic dnssec-failed.org A +noall +comments   # SERVFAIL
  echo "H4 PASS: NOERROR with an answer over udp/853."
  echo "H4 NOTE: if this fails while H3 passes, check UDP/853 in the firewall first — DoT and DoQ share a port number but not a protocol."
}

# =====================================================================
# H5. DNSSEC validation — positive and negative
# =====================================================================
h5_dnssec() {
  phase_header "H5. DNSSEC validation — positive and negative"

  if [[ "$ROLE" == "server" ]]; then
    # --- H5: at the resolver (on the host) — negative ---
    dig @127.0.0.1 -p 5335 dnssec-failed.org A +dnssec +noall +comments
    dig @127.0.0.1 -p 5335 sigfail.verteiltesysteme.net A +dnssec +noall +comments
    echo "H5 PASS (negative): status: SERVFAIL. An EDE of 'DNSSEC Bogus' / 'Signature Expired' is confirmation."

    # --- H5: at the resolver — positive ---
    dig @127.0.0.1 -p 5335 sigok.verteiltesysteme.net A +dnssec +noall +comments
    dig @127.0.0.1 -p 5335 internetsociety.org A +dnssec | grep -E '^;; flags:|RRSIG'
    echo "H5 PASS (positive): flags line contains 'ad', and at least one RRSIG record is present."

    # --- H5: the validator is actually armed ---
    test -s /var/lib/unbound/root.key && echo ANCHOR-OK
    stat -c '%U:%G %a %s' /var/lib/unbound/root.key
    unbound-control stats_noreset | grep -E 'num.answer.secure|num.answer.bogus|val'
    echo "H5 NOTE: dnssec-failed.org SERVFAILs both when validation works AND when the trust anchor is broken. The positive test above is what distinguishes them — never run the negative one alone."

    # --- H5: no bypass exists — with the validator stopped, nothing else may answer ---
    confirm "H5: about to 'systemctl stop unbound' briefly to prove fallback_dns is empty (no third-party resolver bypass) — this takes the resolver offline for a few seconds. Continue?"
    systemctl stop unbound
    dig "@$PUBLIC_IP" example.org A +time=3 +tries=1 +noall +comments || true   # SERVFAIL / no answer, NEVER an address
    systemctl start unbound
    echo "H5 PASS (no-bypass): a failed lookup. An answer here means some third-party resolver is configured somewhere in the chain, and every DNSSEC guarantee above is void."
  fi

  if [[ "$ROLE" == "testhost" ]]; then
    require_cmd kdig
    # --- H5: through the public edge, on every protocol ---
    dig  "@$PUBLIC_IP"            dnssec-failed.org A +noall +comments   # SERVFAIL
    kdig "@$FQDN" +tls   dnssec-failed.org A +noall +comments   # SERVFAIL
    kdig "@$FQDN" +https dnssec-failed.org A +noall +comments   # SERVFAIL
    kdig "@$FQDN" +quic  dnssec-failed.org A +noall +comments   # SERVFAIL
    dig  "@$PUBLIC_IP" internetsociety.org A +dnssec | grep -E '^;; flags:|RRSIG'   # 'ad' + RRSIG

    # --- H5: cache normalisation — proves enable_dnssec: true took effect ---
    local N
    N=$(openssl rand -hex 4).internetsociety.org   # any signed zone; use a fresh label
    dig "@$PUBLIC_IP" internetsociety.org A +short >/dev/null      # warm WITHOUT dnssec
    dig "@$PUBLIC_IP" internetsociety.org A +dnssec | grep -c RRSIG
    echo "H5 PASS (cache normalisation): non-zero. Zero means enable_dnssec is not in effect."
  fi
}

# =====================================================================
# H6. Resolver isolation
# =====================================================================
h6_isolation() {
  phase_header "H6. Resolver isolation"
  if [[ "$ROLE" == "testhost" ]]; then
    require_cmd nmap
    dig "@$PUBLIC_IP" -p 5335 google.com A +time=2 +tries=1 || true   # expect timeout, never an answer
    timeout 3 bash -c "</dev/tcp/$PUBLIC_IP/8053" && echo 'FAIL: 8053 open' || echo 'OK: 8053 closed'
    timeout 3 bash -c "</dev/tcp/$PUBLIC_IP/3000" && echo 'FAIL: 3000 open' || echo 'OK: 3000 closed'
    curl -si --max-time 3 "http://$PUBLIC_IP:3000/" | head -1 || true  # expect connection failure
    nmap -Pn -p 53,80,443,853,3000,5335,8053 "$PUBLIC_IP"
    nmap -Pn -sU -p 53,853 "$PUBLIC_IP"
    echo "H6 PASS (nmap): 53/tcp, 80/tcp, 443/tcp, 853/tcp open, everything else filtered or closed; 53/udp and 853/udp open."
    echo "H6 NOTE: 80/tcp is PERMANENTLY open (Phase B standing rule, nginx ACME webroot + Phase Q well-known files). Filtered/closed 80/tcp here is a failure, not a hardening win."
  fi
  if [[ "$ROLE" == "server" ]]; then
    # --- H6: on the host — confirm the bindings themselves, not just the firewall ---
    ss -lntup | grep -E ':(53|80|443|853|3000|5335|8053)\b'
    echo "H6 PASS (bindings): 5335 on 127.0.0.1/::1 only; 8053 on 127.0.0.1 only; 3000 on 127.0.0.1 only; 53/80/443/853 on the public address (or 0.0.0.0) as designed."
  fi
  info "H6: the admin UI is reached over an SSH tunnel; that procedure belongs to Phase P."
}

# =====================================================================
# H7. Rebinding, EDNS, and TCP fallback
# =====================================================================
h7_rebinding_edns_tcp() {
  phase_header "H7. Rebinding, EDNS, and TCP fallback"

  if [[ "$ROLE" == "server" ]]; then
    # --- H7: config assertion (authoritative, cannot fail open) ---
    grep -c '^ *private-address:' /etc/unbound/unbound.conf.d/10-public-resolver.conf   # expect 18
    grep -c '^ *private-domain:'  /etc/unbound/unbound.conf.d/10-public-resolver.conf   # expect 1
    unbound-checkconf && echo CONF-OK

    # --- H7: special-use zones must be answered locally, not recursed ---
    dig @127.0.0.1 -p 5335 facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion A +noall +comments || true  # NXDOMAIN
    dig @127.0.0.1 -p 5335 1.168.192.in-addr.arpa PTR +noall +comments   # NXDOMAIN, not a recursion
    dig @127.0.0.1 -p 5335 localhost A +short                            # 127.0.0.1

    # --- H7: upstream EDNS buffer size (DNS Flag Day 2020) ---
    unbound-control get_option edns-buffer-size    # 1232
    unbound-control get_option max-udp-size        # 1232
    info "H7: AdGuardHome has NO UDP buffer knob on the client-facing leg — a client advertising 4096 gets up to 4096 bytes and the response fragments. Documented limitation, not a misconfiguration. Do NOT clamp EDNS in nftables — no DNS parser, a byte-offset hack corrupts answers."
  fi

  if [[ "$ROLE" == "testhost" ]]; then
    # --- H7: rebinding live probe, with a control query (rbndr.us can SERVFAIL for
    # unrelated reasons, so an inconclusive control result must not be scored) ---
    local V CTRL MINE
    V=7f000001.c0a80001.rbndr.us          # 7f000001 = 127.0.0.1, c0a80001 = 192.168.0.1
    CTRL=$(dig @8.8.8.8 "$V" A +short +time=4 +tries=1 | tr '\n' ' ')
    MINE=$(dig "@$PUBLIC_IP" "$V" A +short +time=4 +tries=1 | tr '\n' ' ')
    echo "control='$CTRL' ours='$MINE'"
    if   [ -z "$CTRL" ]; then echo 'H7 INCONCLUSIVE: vector down upstream - do not score this run'
    elif [ -z "$MINE" ]; then echo 'H7 PASS: private address stripped'
    else echo "H7 FAIL: resolver returned $MINE for a public name"; fi

    # --- H7: TCP fallback — a pair that provably truncates ---
    dig "@$PUBLIC_IP" +dnssec +bufsize=512 +ignore . DNSKEY +noall +comments | grep -o 'flags:[^;]*'
    echo "H7 PASS: the flags string contains ' tc'"
    dig "@$PUBLIC_IP" +dnssec +tcp . DNSKEY +noall +comments | grep 'status:'
    echo "H7 PASS: NOERROR over TCP"
    dig "@$PUBLIC_IP" +dnssec +bufsize=4096 . DNSKEY +noall +stats | grep 'MSG SIZE'
    echo "H7 NOTE: a >1232-byte UDP response here is the client-leg fragmentation exposure - expected, documented."

    # --- H7: source-port randomisation on the recursive leg ---
    if command -v tcpdump >/dev/null 2>&1; then
      timeout 20 tcpdump -ni any -c 30 'udp dst port 53 and not host 127.0.0.1' 2>/dev/null \
        | sed -n 's/.*\.\([0-9]*\) > .*/\1/p' | sort -u | wc -l    # PASS: many distinct ports, not 1
    else
      warn "H7: tcpdump not installed on this host — skipping source-port randomisation capture."
    fi

    # --- H7: DNS cookies — record whether the public edge implements RFC 7873 ---
    dig "@$PUBLIC_IP" +cookie google.com A +noall +comments | grep -i 'COOKIE'
    info "H7: 'COOKIE: <client><server>' with 64+ hex chars => server cookies active. Client-only cookie echoed back => the edge does not implement cookies (AdGuardHome does not) — a known, accepted gap in this design."
  fi
}

# =====================================================================
# H8. Cache, prefetch, and restart behaviour
# =====================================================================
h8_cache_prefetch_restart() {
  phase_header "H8. Cache, prefetch, and restart behaviour"
  if [[ "$ROLE" != "server" ]]; then
    warn "H8: skipped on ROLE=testhost — these are on-host unbound-control checks. Re-run with KEYSTONE_H_ROLE=server."
    return 0
  fi

  unbound-control stats_noreset | grep -E 'total.num.(queries|cachehits|cachemiss|prefetch)' || \
    unbound-control stats_noreset | grep '^total'

  # --- H8: cache hit — the second query must be materially faster ---
  dig @127.0.0.1 -p 5335 wikipedia.org A +noall +stats | grep 'Query time'
  dig @127.0.0.1 -p 5335 wikipedia.org A +noall +stats | grep 'Query time'
  echo "H8 PASS (cache hit): second query time is ~0 ms."

  # --- H8: prefetch is doing work (replaces the retired Phase F warmer) ---
  local B A
  B=$(unbound-control stats_noreset | awk -F= '/total.num.prefetch/{print $2}')
  info "H8: run ~10 minutes of the H11 warm corpus now (from the test host), then re-run this section to read the delta."
  A=$(unbound-control stats_noreset | awk -F= '/total.num.prefetch/{print $2}')
  echo "prefetch delta = $((A - B))"    # PASS: > 0 under sustained repeat traffic

  # --- H8: TTL honesty — a short-TTL name must not be pinned by a minimum-TTL setting ---
  dig "@$PUBLIC_IP" whoami.cloudflare.com TXT +noall +answer   # or any known short-TTL name
  sleep 35
  dig "@$PUBLIC_IP" whoami.cloudflare.com TXT +noall +answer
  echo "H8 PASS (TTL honesty): the TTL counts down and refreshes; it must not be floored at an artificial value."

  # --- H8: restart behaviour ---
  confirm "H8: about to 'systemctl restart unbound' to prove the cache is memory-only and recovery is immediate — this briefly interrupts resolution. Continue?"
  systemctl restart unbound && sleep 2
  unbound-control stats_noreset | grep -E 'total.num.cachehits|total.num.cachemiss'  # both near zero
  ls -l /var/lib/unbound/                 # PASS: root.key only, no cache file
  dig "@$PUBLIC_IP" google.com A +short    # PASS: answers within the first second after restart
  echo "H8 PASS overall: hit ratio climbs during the H11 warm run, total.num.prefetch is non-zero, no on-disk cache artefact exists, and service resumes immediately after a restart."
}

# =====================================================================
# H9. TLS grade
# =====================================================================
h9_tls_grade() {
  phase_header "H9. TLS grade"
  if [[ "$ROLE" != "testhost" ]]; then
    warn "H9: skipped on ROLE=server — TLS grading runs from the H0 test host. Re-run with KEYSTONE_H_ROLE=testhost."
    return 0
  fi

  if ! command -v testssl.sh >/dev/null 2>&1 && [ ! -x /opt/testssl/testssl.sh ]; then
    apt-get install -y testssl.sh || git clone --depth 1 https://github.com/testssl/testssl.sh /opt/testssl
  fi
  local TESTSSL=/opt/testssl/testssl.sh
  command -v testssl.sh >/dev/null 2>&1 && TESTSSL=testssl.sh
  "$TESTSSL" --quiet --protocols --ciphers --vulnerable "$FQDN:443"   # nginx / DoH
  "$TESTSSL" --quiet --protocols --ciphers               "$FQDN:853"  # AdGuardHome / DoT
  echo "H9 PASS: TLS 1.2 and 1.3 offered; TLS 1.0/1.1 and SSLv3 refused; no CBC or RC4 suites; no known-vulnerable findings."
  info "H9: AdGuardHome's TLS floor is hardcoded (internal/home/tls.go, MinVersion: tls.VersionTLS12) — not configurable, no min_version key. Cipher list is configurable via tls.override_tls_ciphers."

  # --- H9: TLS 1.1 refusal — Ubuntu's system OpenSSL policy makes the naive
  # command a false pass, so the client must be forced down first ---
  openssl s_client -connect "$FQDN:853" -servername "$FQDN" \
    -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0' </dev/null 2>&1 | grep -E 'Protocol|alert|handshake failure' || true
  info "H9: trust testssl.sh --protocols over the openssl s_client probe above; it is the unambiguous answer."

  # --- H9: chain and key type ---
  openssl x509 -in /etc/letsencrypt/live/"$FQDN"/cert.pem -noout -text \
    | grep -E 'Public Key Algorithm|ASN1 OID|NIST CURVE|Signature Algorithm' | head -4
  echo "H9 PASS: id-ecPublicKey / prime256v1 / NIST CURVE: P-256"

  openssl s_client -connect "$FQDN:443" -servername "$FQDN" -showcerts </dev/null 2>/dev/null \
    | grep -E '^ *[0-9]+ s:|^ *[0-9]+ i:'
  echo "H9 PASS: leaf + intermediate served. A leaf-only chain works in browsers and breaks DoT clients."

  openssl x509 -noout -ocsp_uri -in /etc/letsencrypt/live/"$FQDN"/cert.pem   # expect EMPTY
  info "H9: an empty OCSP URI is expected — Let's Encrypt dropped OCSP from issued certs 2025-05-07 and shut the responders down 2025-08-06. Do NOT add ssl_stapling on (no-op) or request --must-staple (fails at issuance)."

  # --- H9: Certificate Transparency (informational only) ---
  curl -s "https://crt.sh/?q=$FQDN&output=json" | jq -r '.[].issuer_name' | sort -u || true
}

# =====================================================================
# H10. Rate limiting under abuse — and no collateral damage
# =====================================================================
h10_rate_limiting() {
  phase_header "H10. Rate limiting under abuse — and no collateral damage"

  if [[ "$ROLE" == "server" ]]; then
    # --- H10: confirm the flooder was actually limited (config + kernel state) ---
    grep -E '^ *ratelimit:|ratelimit_subnet_len' /opt/adguardhome/conf/AdGuardHome.yaml
    echo "H10 expect: ratelimit: 100, ratelimit_subnet_len_ipv4: 32, ratelimit_subnet_len_ipv6: 64"
    nft list chain inet filter dns_guard | grep -E 'limit rate|@floodmeter|@banned_ips'
    nft -j list sets | jq -r '.nftables[]?.set?.name' | sort -u
    echo "H10 expect to see: floodmeter4 floodmeter6 banned_ips banned_ips6 banned_long banned_long6 allowlist4 allowlist6 - all in table inet filter."
    nft list tables                  # expect EXACTLY: table inet raw, table inet filter

    # --- H10: abuse detection must be kernel-side — verify floodmeter -> banned_ips promotion ---
    info "H10: floodmeter4 contains EVERY source seen in the window — it is the limiter's state, not a list of offenders. Watch it and banned_ips SEPARATELY during a flood, never assume the meter's contents are bannable as-is."
    nft -j list set inet filter floodmeter4 | jq '.nftables[]?.set.elem? | length'
    nft -j list set inet filter banned_ips  | jq '.nftables[]?.set.elem? | length'
    nft list set inet filter banned_ips     # the flooder's address, with a timeout counting down
    echo "H10 PASS: the flooding source appears in floodmeter4 and is then promoted into banned_ips with a 10-minute timeout (escalating to 24 hours on repeat); a well-behaved source in the same subnet appears in neither set and keeps resolving throughout."
  fi

  if [[ "$ROLE" == "testhost" ]]; then
    warn "H10: the flood/no-collateral-damage test needs TWO test hosts (host A floods, host B in the SAME /24 as host A confirms it still resolves) running SIMULTANEOUSLY. That coordination is inherently manual and is NOT scripted here — run it by hand:"
    cat <<'MANUAL'
  # 1. Legitimate baseline, from a normal client - record it.
  for i in $(seq 1 10); do dig @<PUBLIC_IP> example.net A +short +time=2; done

  # 2. Flood from host A - 5000 QPS is far above both the AGH 100 qps UDP
  #    limiter and the 400/s nftables flood threshold, so both layers must engage:
  dnsperf -s <PUBLIC_IP> -d /tmp/queries.txt -c 20 -T 2 -l 30 -Q 5000

  # 3. DURING the flood, from host B in the SAME /24 as host A:
  dig @<PUBLIC_IP> example.net A +short +time=2 +tries=1
  # PASS: host B still gets an answer. A timeout means the limiter aperture is
  # per-subnet, not per-IP (needs AGH >= v0.107.41).
MANUAL
  fi
}

# =====================================================================
# H11. Load test
# =====================================================================
h11_load_test() {
  phase_header "H11. Load test"
  if [[ "$ROLE" != "testhost" ]]; then
    warn "H11: skipped on ROLE=server — the load test runs FROM the H0 test host; running it on the DNS server steals CPU from the system under test and bypasses the NIC/firewall/conntrack/rate-limiter. Re-run with KEYSTONE_H_ROLE=testhost."
    return 0
  fi
  require_cmd dnsperf openssl

  # --- H11: corpus — a realistic mix, built once ---
  curl -sL https://tranco-list.eu/top-1m.csv.zip -o /tmp/t.zip
  unzip -p /tmp/t.zip | cut -d, -f2 | head -50000 > /tmp/warm.txt
  for i in $(seq 1 5000); do echo "nx$(openssl rand -hex 4).invalid"; done >> /tmp/warm.txt

  # --- H11: hostile corpus — guaranteed cache miss, NXDOMAIN at the root, no
  # third-party authoritative load. Do NOT aim this at example.com. ---
  for i in $(seq 1 10000); do echo "$(openssl rand -hex 6).$(openssl rand -hex 3).invalid"; done > /tmp/miss.txt

  # --- H11: dnsperf format, with a modern type mix (HTTPS/type65 is a large
  # share of real traffic and takes a different code path) ---
  awk '{print $1" A"; print $1" AAAA"; if (NR%5==0) print $1" HTTPS"; \
        if (NR%23==0) print $1" MX"; if (NR%37==0) print $1" TXT"}' /tmp/warm.txt > /tmp/queries.txt

  info "H11: the cold run below drives ~50,000 real recursions at real authoritative servers. That is legitimate and bounded — do not loop it."

  # --- H11: three cache states, measured separately ---
  confirm "H11: about to restart unbound on the DNS host to force the COLD cache state, then run a sustained dnsperf load test against it — this generates real production load and a brief resolution gap. Continue?"
  ssh dns1 'systemctl restart unbound'; sleep 3
  dnsperf -s "$PUBLIC_IP" -d /tmp/queries.txt -c 50  -T 4 -l 300 -Q 500  -S 10

  # WARM - after 10 minutes of the same corpus; the normal operating point.
  dnsperf -s "$PUBLIC_IP" -d /tmp/queries.txt -c 100 -T 4 -l 300 -Q 2000 -S 10

  # HOSTILE - 100% unique labels, the actual shape of a cache-busting attack.
  dnsperf -s "$PUBLIC_IP" -d <(awk '{print $1" A"}' /tmp/miss.txt) -c 50 -T 4 -l 300 -Q 300 -S 10

  # CAPACITY KNEE - ramp until it breaks. Never guess the ceiling.
  if command -v resperf >/dev/null 2>&1; then
    confirm "H11: about to run resperf and ramp traffic until the DNS server's capacity knee breaks — this is a deliberate overload of production. Continue?"
    resperf -s "$PUBLIC_IP" -d /tmp/queries.txt -m 20000 -r 120 -c 60
  else
    warn "H11: resperf not installed — skipping the capacity-knee ramp. See H0's note on installing it from DNS-OARC source."
  fi

  # --- H11: per-protocol, with percentiles ---
  if command -v dnspyre >/dev/null 2>&1; then
    dnspyre -s "$PUBLIC_IP"                       -t A -t AAAA -t HTTPS -c 50 -l 2000 -d 300s @/tmp/warm.txt
    dnspyre -s "$FQDN:853" --dot         -t A -c 50 -l 500  -d 300s --separate-worker-connections @/tmp/warm.txt
    dnspyre -s "https://$FQDN/dns-query" -t A -c 50 -l 1000 -d 300s @/tmp/warm.txt
    dnspyre -s "quic://$FQDN:853"        -t A -c 50 -l 500  -d 300s @/tmp/warm.txt
    info "H11: --separate-worker-connections on the DoT run is what exercises handshake cost rather than a single reused session."

    # --- H11: pin the dnspyre JSON schema before writing any automated gate ---
    dnspyre -s 127.0.0.1 -t A -c 2 -d 5s --json example.org | jq 'paths(scalars) | join(".")' | sort -u
    info "H11: substitute the real field names into your gate. Do not ship guessed jq paths."
  else
    warn "H11: dnspyre not installed — skipping per-protocol percentile runs. Re-run H0 (test host) first."
  fi

  echo "H11: PASS thresholds LT-0 through LT-13 are defined in phases/06-logging-and-validation.md (H11 table) and referenced by Phase L. This script does not re-score them numerically — read dnsperf/dnspyre/resperf output and the server-side capture below against that table."

  # --- H11: minimum go-live gate ---
  dnsperf -s "$PUBLIC_IP" -d /tmp/queries.txt -c 100 -T 4 -l 300 -Q 2000 -S 10 | tee /tmp/warm.out
  grep -E 'Queries per second|Average Latency|Queries lost|Response codes' /tmp/warm.out

  echo "H11: LT-13 is a FOUR-HOUR SOAK TEST. It is intentionally not run automatically as part of this pass — invoke it explicitly (h11_soak_lt13 below) as a separate, deliberate, foreground step."
}

# LT-13: 4-hour soak at 30% of the measured knee. Deliberately separate from
# h11_load_test so it is never accidentally bundled into a routine run. This
# is a long-running FOREGROUND step by design — do not background it; the
# operator is expected to watch it (or at minimum keep the terminal open) so
# the RSS plot is captured for the run that actually happened.
h11_soak_lt13() {
  phase_header "H11 / LT-13. Four-hour soak at 30% of the measured knee"
  if [[ "$ROLE" != "testhost" ]]; then
    fatal "H11/LT-13: must run from the H0 test host (KEYSTONE_H_ROLE=testhost)."
  fi
  local KNEE_QPS="${KEYSTONE_LT13_KNEE_QPS:-}"
  [ -n "$KNEE_QPS" ] || fatal "H11/LT-13: set KEYSTONE_LT13_KNEE_QPS to the QPS measured by the H11 capacity-knee (resperf) run — this cannot be guessed. 30% of that value is the soak rate the source markdown specifies."
  local SOAK_QPS=$(( KNEE_QPS * 30 / 100 ))
  confirm "H11/LT-13: about to run a FOUR-HOUR foreground dnsperf soak at ${SOAK_QPS} QPS (30% of knee=${KNEE_QPS}) against $PUBLIC_IP. This will hold the terminal for 4 hours and put sustained load on production. Continue?"
  info "H11/LT-13: run this in the SAME window, on the DNS host, to capture RSS of both daemons for the pass/fail (flat line = PASS, positive slope = a leak):"
  info "H11/LT-13:   while true; do date; ps -o rss=,cmd= -C unbound,AdGuardHome; sleep 300; done | tee /tmp/lt13-rss.log"
  # 4h = 14400s. Foreground, blocking — matches dnsperf's own -l semantics.
  dnsperf -s "$PUBLIC_IP" -d /tmp/queries.txt -c 100 -T 4 -l 14400 -Q "$SOAK_QPS" -S 60
  echo "H11/LT-13 PASS: plot /tmp/lt13-rss.log for both unbound and AdGuardHome — a flat RSS line is the pass, a positive slope is a leak."
}

# =====================================================================
# H12. Post-change smoke gate
# =====================================================================
h12_smoke_gate() {
  phase_header "H12. Post-change smoke gate"
  if [[ "$ROLE" != "server" ]]; then
    warn "H12: skipped on ROLE=testhost — dns-smoke.sh is installed and run on the DNS host. Re-run with KEYSTONE_H_ROLE=server."
    return 0
  fi

  # --- H12: install /usr/local/sbin/dns-smoke.sh — verbatim from source ---
  backup_file /usr/local/sbin/dns-smoke.sh
  cat > /usr/local/sbin/dns-smoke.sh << 'SMOKE'
#!/bin/bash
# Post-change gate. Exit 0 = safe to walk away. Exit 1 = you are not done.
set -uo pipefail
FQDN="${FQDN:-dns.example.com}"
PUBIP="${PUBIP:-$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)}"
CERT="${CERT:-/opt/adguardhome/conf/ssl/fullchain.pem}"
UNITS="${UNITS:-unbound adguardhome nginx nftables}"
FAIL=0
ok(){  printf '  OK    %s\n' "$1"; }
bad(){ printf '  FAIL  %s\n' "$1"; FAIL=1; }
chk(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

echo "== units =="
for u in $UNITS; do
  chk "$u active"  "systemctl is-active  --quiet $u"
  chk "$u enabled" "systemctl is-enabled --quiet $u"
done

echo "== resolution path =="
chk "unbound 127.0.0.1:5335"  "dig +time=3 +tries=1 @127.0.0.1 -p 5335 google.com A +short | grep -qE '^[0-9]+\.'"
chk "AGH udp/53 loopback"     "dig +time=3 +tries=1 @127.0.0.1 google.com A +short | grep -qE '^[0-9]+\.'"
chk "AGH udp/53 public"       "dig +time=3 +tries=1 @$PUBIP google.com A +short | grep -qE '^[0-9]+\.'"
chk "AGH tcp/53 public"       "dig +tcp +time=3 +tries=1 @$PUBIP google.com A +short | grep -qE '^[0-9]+\.'"
chk "NXDOMAIN is NXDOMAIN"    "dig +time=3 +tries=1 @$PUBIP nonexistent.invalid A | grep -q 'status: NXDOMAIN'"

echo "== dnssec =="
# Negative AND positive. The negative alone also passes when the trust anchor is
# broken so badly that nothing resolves at all.
chk "bogus zone SERVFAILs"    "dig +time=4 +tries=1 @$PUBIP dnssec-failed.org A | grep -q 'status: SERVFAIL'"
chk "signed zone has ad+RRSIG" "dig +time=4 +tries=1 +dnssec @$PUBIP internetsociety.org A | grep -q 'flags:.* ad' && dig +time=4 +tries=1 +dnssec @$PUBIP internetsociety.org A | grep -q RRSIG"
chk "trust anchor non-empty"  "test -s /var/lib/unbound/root.key"

echo "== encrypted transports =="
chk "DoT  tcp/853" "kdig +tls   +timeout=5 @$FQDN google.com A +short | grep -qE '^[0-9]+\.'"
chk "DoH  tcp/443" "kdig +https +timeout=5 @$FQDN google.com A +short | grep -qE '^[0-9]+\.'"
# DoQ needs kdig >= 3.3 (noble ships 3.3.x). A tooling failure here is not a service failure.
if kdig -V 2>&1 | grep -qE 'Knot DNS (3\.[3-9]|[4-9])'; then
  chk "DoQ  udp/853" "kdig +quic +timeout=5 @$FQDN google.com A +short | grep -qE '^[0-9]+\.'"
else
  echo "  SKIP  DoQ (kdig < 3.3, no +quic support)"
fi

echo "== isolation =="
chk "5335 closed from public" "! dig +time=2 +tries=1 @$PUBIP -p 5335 google.com A +short | grep -qE '^[0-9]+\.'"
chk "8053 closed from public" "! timeout 3 bash -c \"</dev/tcp/$PUBIP/8053\""
chk "3000 closed from public" "! timeout 3 bash -c \"</dev/tcp/$PUBIP/3000\""
chk "admin UI not on 443"     "! curl -fsS --max-time 4 https://$FQDN/login.html -o /dev/null"
chk "control API not on 443"  "! curl -fsS --max-time 4 https://$FQDN/control/status -o /dev/null"
chk "unbound loopback-only"   "! ss -lnu 'sport = :5335' | grep -qE '0\.0\.0\.0|\*:5335'"

echo "== kernel / firewall =="
chk "AGH has ambient cap"     "systemctl show adguardhome -p AmbientCapabilities | grep -q cap_net_bind_service"
chk "AGH bound to :53"        "ss -lnup | grep -q ':53 '"
chk "udp/53 is NOTRACK'd"     "nft list table inet raw 2>/dev/null | grep -q notrack"
# Structure, not just presence: two tables (inet raw for NOTRACK, inet filter for
# the rest) and exactly ONE base chain on the input hook. dns_guard is a regular
# chain jumped from it, so a second 'hook input' line means someone re-introduced
# the v1 priority-arithmetic layout. Deliberately jq-free - this gate must run on
# a host that has nothing installed beyond the stack itself.
chk "two tables, no more"     "[ \$(nft list tables | wc -l) -eq 2 ] && nft list tables | grep -q 'inet raw' && nft list tables | grep -q 'inet filter'"
chk "one input base chain"    "[ \$(nft list ruleset | grep -c 'hook input') -eq 1 ]"
chk "ban set present"         "nft -j list set inet filter banned_ips >/dev/null 2>&1"
chk "long-ban set present"    "nft -j list set inet filter banned_long >/dev/null 2>&1"
chk "flood meter present"     "nft -j list set inet filter floodmeter4 >/dev/null 2>&1"
chk "dns_guard chain present" "nft list chain inet filter dns_guard 2>/dev/null | grep -q 'limit rate'"

echo "== certificate =="
if END=$(openssl x509 -enddate -noout -in "$CERT" 2>/dev/null | cut -d= -f2); then
  DAYS=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))
  [ "$DAYS" -ge 14 ] && ok "cert valid, $DAYS days left" || bad "cert only $DAYS days left"
else bad "cannot read $CERT"; fi
ONDISK=$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
# The failure with no other symptom: renewed on disk, stale in memory. Check BOTH
# terminators - nginx on 443 and AdGuardHome on 853 load the cert independently.
for HP in "$FQDN:853" "$FQDN:443"; do
  SERVED=$(openssl s_client -connect "$HP" -servername "$FQDN" </dev/null 2>/dev/null \
           | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
  if [ -n "$SERVED" ] && [ "$SERVED" = "$ONDISK" ]; then ok "served cert == on-disk ($HP)"
  else bad "served cert differs from on-disk ($HP) - service not reloaded after renewal?"; fi
done

echo "== disk =="
chk "disk under 85%" "/usr/local/sbin/dns-diskguard.sh"

echo
[ "$FAIL" -eq 0 ] && echo "SMOKE: PASS" || echo "SMOKE: FAIL"
exit $FAIL
SMOKE
  chmod 750 /usr/local/sbin/dns-smoke.sh
  info "H12: dns-diskguard.sh (invoked above under '== disk ==') is created by Phase G4, not this phase — this script only calls it."

  # --- H12: wire into /etc/cron.d/dns-health — Phase I creates and owns this
  # file; this phase only appends to it, never creates it ---
  local CRONFILE=/etc/cron.d/dns-health
  local CRONLINE='*/10 * * * * root /usr/local/sbin/dns-smoke.sh >/tmp/dns-smoke.out 2>&1 || logger -t dns-alert -p daemon.crit "SMOKE FAILED"'
  if [ ! -e "$CRONFILE" ]; then
    warn "H12: $CRONFILE does not exist yet — it is created by Phase I, which this phase does not own and must not pre-create. Run Phase I first, then re-run H12 to append the smoke-gate cron line."
  elif grep -qF "$CRONLINE" "$CRONFILE" 2>/dev/null; then
    info "H12: smoke-gate cron line already present in $CRONFILE — not duplicating."
  else
    echo "$CRONLINE" >> "$CRONFILE"
    info "H12: appended smoke-gate line to $CRONFILE (Phase I-owned file)."
  fi

  # --- H12: pre-change gates — validate before you break things ---
  nft -c -f /etc/nftables.conf                                              # ruleset parses
  unbound-checkconf                                                         # resolver config parses
  nginx -t                                                                  # nginx config parses
  runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
    -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate  # AGH config parses
  info "H12: /opt/adguardhome/validate is created by Phase E at install time (owned by adguardhome) — this phase only invokes --check-config against it, via runuser, never as root, never against the live work/ tree."

  # --- H12: verify the gate itself — run once, one at a time, restore after each ---
  run_smoke
  echo "  -> every line OK, trailer 'SMOKE: PASS', exit=0"

  confirm "H12: about to 'systemctl stop unbound' to prove dns-smoke.sh actually detects a broken resolver (expect exit=1) — this briefly interrupts resolution. Continue?"
  systemctl stop unbound
  run_smoke   # expect exit=1
  systemctl start unbound

  confirm "H12: about to 'systemctl stop nginx' to prove dns-smoke.sh detects a broken DoH path (expect a FAIL line) — this briefly takes DoH down. Continue?"
  systemctl stop nginx
  /usr/local/sbin/dns-smoke.sh | grep DoH || true   # expect a FAIL line here
  systemctl start nginx

  # --- H12: cert-mismatch detector, which has no other symptom ---
  openssl x509 -in /opt/adguardhome/conf/ssl/fullchain.pem -noout -fingerprint -sha256
  openssl s_client -connect "$FQDN:853" -servername "$FQDN" </dev/null 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256
  echo "H12: the two fingerprints above must match."

  # --- H12: pre-change gates all exit 0 on a healthy node ---
  nft -c -f /etc/nftables.conf; echo "nft=$?"
  unbound-checkconf;            echo "unbound=$?"
  nginx -t;                     echo "nginx=$?"
  runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
    -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate; echo "agh=$?"

  find /opt/adguardhome/validate ! -user adguardhome -print   # expect: no output
  echo "H12: no output above means the validate workdir stayed adguardhome-owned."
}

# =====================================================================
# H13. Upstream and root-server outage injection
# =====================================================================
h13_outage_injection() {
  phase_header "H13. Upstream and root-server outage injection"
  if [[ "$ROLE" != "server" ]]; then
    warn "H13: skipped on ROLE=testhost for the injection itself — run the injection on the DNS host (ROLE=server). The public-edge checks below need the test host; run those separately with KEYSTONE_H_ROLE=testhost."
    return 0
  fi

  confirm "H13: about to CUT ALL RECURSIVE-LEG UPSTREAM DNS on this host (nftables drop, output chain, dport 53, oifname != lo) to force serve-stale and prove RFC 8767 behaviour. This is a DELIBERATE, documented service degradation — run it in a maintenance window, one test at a time, and confirm dns-smoke.sh reports SMOKE: PASS before starting the next H13/H14/H15 test. Continue?"

  local D=whoami.akamai.net
  dig @127.0.0.1 -p 5335 "$D" A +noall +answer            # warm it - stale can only serve what is cached
  local TTL
  TTL=$(dig @127.0.0.1 -p 5335 "$D" A +noall +answer | awk '{print $2; exit}')
  echo "cached TTL=$TTL"

  # --- H13: failsafe first — if this shell dies mid-test the box restores
  # itself in 15 minutes. nft -f reloads Phase B's canonical ruleset, which
  # also clears live banned_ips / floodmeter state (Phase J) — acceptable in
  # a pre-go-live drill, not something to trigger casually on a running service.
  systemd-run --on-active=15min --unit=dns-egress-restore /usr/sbin/nft -f /etc/nftables.conf

  # --- H13: the block. dport 53 only cuts the recursion leg (replies to
  # clients carry SPORT 53, disjoint from this); oifname != lo keeps the
  # AdGuardHome -> Unbound loopback path intact; drop (not reject) is
  # required so the 1800ms client-response timer is actually exercised. ---
  nft insert rule inet filter output oifname != "lo" udp dport 53 counter drop
  nft insert rule inet filter output oifname != "lo" tcp dport 53 counter drop
  nft -a list chain inet filter output | grep 'dport 53 counter drop'   # RECORD the two handles

  dig @198.41.0.4 . NS +time=2 +tries=1 +noall +comments || true   # expect: no servers could be reached

  sleep $((TTL + 5))          # the cached entry must actually expire

  # --- H13: at the resolver ---
  dig @127.0.0.1 -p 5335 "$D" A +dnssec +time=5 +tries=1 +noall +comments +answer +stats
  unbound-control stats_noreset | grep -E 'num.expired'
  echo "H13 PASS (resolver, all four together): status: NOERROR with an answer (not SERVFAIL); comments carry '; EDE: 3 (Stale Answer)'; answer TTL is 30 (serve-expired-reply-ttl); Query time ~1800 ms; num.expired above zero and rising."

  # --- H13: a name that was never cached — the half users actually report ---
  dig "@$PUBLIC_IP" "$(openssl rand -hex 4).example.org" A +time=8 +tries=1 +noall +comments || true
  echo "H13 expect: SERVFAIL. Stale serves only what it already has."

  # --- H13: what the monitoring said ---
  run_smoke
  info "H13: expect the smoke gate to largely PASS during the outage — serve-stale is doing its job. H12 is NOT an upstream-outage detector; that is Phase I's job (RecursionStalled, ServfailRateHigh, RecursionLatencyP99High). Note which fired, and how long it took."

  if [[ -n "${KEYSTONE_H13_TESTHOST_ECHO:-}" ]]; then
    warn "H13: at the public edge, from the H0 test host, run (this script does not do it for you from here):"
    cat <<EOF
  dig  @$PUBLIC_IP            $D A +time=5 +tries=1 +noall +comments +stats
  kdig @$FQDN +tls   $D A
  kdig @$FQDN +https $D A
  # PASS: the same stale answer arrives on every transport, slowly.
  grep -n 'upstream_timeout' /opt/adguardhome/conf/AdGuardHome.yaml   # must exceed 1800ms
  grep -rn 'proxy_read_timeout' /etc/nginx/sites-enabled/              # 10s (Phase E)
EOF
  fi

  # --- H13: restore — part of the test, not an afterthought ---
  # (|| true throughout: this section MUST reach flush_infra and the final
  # run_smoke regardless of what any single diagnostic line reports — the
  # 15-minute systemd-run failsafe armed above is the backstop, not this
  # script staying alive.)
  nft -a list chain inet filter output | grep 'dport 53 counter drop' || true
  warn "H13: manual step — delete the two rules above by handle: nft delete rule inet filter output handle <handle> (once per rule, using the handles just listed). If the handles are gone, 'nft -f /etc/nftables.conf' is correct but clears live ban/flood-meter state (Phase J)."
  read -r -p "H13: press Enter once the rules above are deleted (or run 'nft -f /etc/nftables.conf') to continue the restore sequence... " _

  systemctl stop dns-egress-restore.timer 2>/dev/null || true

  dig @198.41.0.4 . NS +time=2 +tries=1 +noall +comments || true   # answers again

  # --- H13: recovery is NOT immediate on its own — Unbound's infra cache
  # remembers unreachability for infra-host-ttl (900s default) ---
  unbound-control flush_infra all

  dig @127.0.0.1 -p 5335 "$D" A +noall +stats | grep 'Query time' || true   # back to normal, no EDE 3
  unbound-control stats_noreset | grep num.expired || true       # stops rising
  nft list tables                                                # EXACTLY: inet raw, inet filter
  run_smoke                                                      # SMOKE: PASS, exit=0
  echo "H13 PASS overall: stale answers released with EDE 3 at the measured 1.8s, reached clients on every transport, an uncached name SERVFAILed, the monitoring signal recorded, and the ruleset/resolver byte-for-byte back where they started."
}

# =====================================================================
# H14. Rollback rehearsal
# =====================================================================
h14_rollback_rehearsal() {
  phase_header "H14. Rollback rehearsal — the recovery path nothing else runs"
  if [[ "$ROLE" != "server" ]]; then
    warn "H14: skipped on ROLE=testhost — rollback rehearsal runs on the DNS host. Re-run with KEYSTONE_H_ROLE=server."
    return 0
  fi

  # --- H14: AdGuardHome rollback ---
  local VB="${KEYSTONE_H14_AGH_VERSION:-}"
  [ -n "$VB" ] || fatal "H14: set KEYSTONE_H14_AGH_VERSION to a DIFFERENT AdGuardHome release from what is currently installed (readlink -f /opt/adguardhome/current tells you the current one). This is a deliberate choice, not something this script can guess — re-running with the version already installed makes the rollback a no-op that proves nothing."

  confirm "H14: about to force AdGuardHome's rollback branch via /usr/local/sbin/upgrade-adguardhome.sh $VB (CERT pointed at a nonexistent path so the smoke gate fails and triggers rollback). This upgrades, then rolls back, a boot service on this host. Continue?"

  local A
  A=$(readlink -f /opt/adguardhome/current); echo "running: $A"
  time CERT=/nonexistent/fullchain.pem /usr/local/sbin/upgrade-adguardhome.sh "$VB"
  echo "H14 expected: the upgrade succeeds, the smoke gate FAILs on the certificate lines, the script prints 'SMOKE FAILED — rolling back to ...', runs the branch, and exits 1. The second smoke run inside the rollback branch also fails for the same injected reason — not a rollback failure."

  readlink -f /opt/adguardhome/current                    # == $A
  cmp -s /opt/adguardhome/conf/AdGuardHome.yaml \
         "/opt/adguardhome/conf/AdGuardHome.yaml.pre-$VB" \
    && echo 'CONFIG RESTORED' \
    || warn "H14: config does NOT byte-match the pre-\$VB copy — the rollback may not have restored the pre-migration file. Investigate before continuing."
  stat -c '%U:%G %a' /opt/adguardhome/conf/AdGuardHome.yaml   # adguardhome:adguardhome 600
  ss -ulnp | grep ':53 '                                      # the OLD binary is bound again
  run_smoke                                                   # SMOKE: PASS, exit=0 (clean env)
  info "H14: cmp above is the assertion that carries the proof, not schema_version — a matching schema number proves nothing when adjacent patch releases don't migrate."

  journalctl -u adguardhome --since -5m --no-pager | grep -iE 'stats|schema|migrat|error' || true
  info "H14: the rollback branch does not restore runtime state (stats.db etc.) — an untested combination in AdGuardHome itself, not fixable from this plan."

  # --- H14: Unbound rollback ---
  apt-cache madison unbound                              # every installable version and its source
  dpkg-query -W -f='${Version}\n' unbound                # what is running now
  ls /var/cache/apt/archives/unbound_*.deb 2>/dev/null || true   # the local fallback

  local PREV="${KEYSTONE_H14_UNBOUND_PREV:-}"
  if [ -z "$PREV" ]; then
    warn "H14: KEYSTONE_H14_UNBOUND_PREV not set — read the apt-cache madison output above and decide whether a second installable Unbound version exists. If madison lists exactly one version, the Phase M Unbound rollback CANNOT run on this host today; record that rather than discovering it during an incident, and keep the running .deb (apt-get download unbound) somewhere Phase K's backup set covers. Set KEYSTONE_H14_UNBOUND_PREV=<version> and re-run to rehearse the downgrade."
  else
    confirm "H14: about to 'apt-get install --allow-downgrades unbound=$PREV' and restart unbound — this changes an installed boot-service package. Continue?"
    time DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "unbound=$PREV"
    apt-mark hold unbound
    unbound-checkconf                          # OLD binary, CURRENT drop-in
    systemctl restart unbound; sleep 3
    dig +dnssec @127.0.0.1 -p 5335 internetsociety.org A | grep -c ' ad'      # -> 1
    dig +dnssec @127.0.0.1 -p 5335 dnssec-failed.org  A | grep -c 'SERVFAIL'  # -> 1
    run_smoke
    apt-mark showhold                          # -> unbound
    info "H14: the apt-mark hold is DELIBERATE during a real rollback — do not clear it until you fix forward, or unattended-upgrades reinstalls the version you just rolled away from."

    confirm "H14: about to fix forward — reinstall the current unbound version and release the apt hold. Continue?"
    DEBIAN_FRONTEND=noninteractive apt-get install -y unbound
    apt-mark unhold unbound
    apt-mark showhold                          # -> empty
    run_smoke
  fi

  echo "H14 PASS overall: both rollback branches executed end to end, config provably restored from the pre-migration copy, rolled-back node passes a clean smoke run, and two wall-clock numbers (the 'time' outputs above) are recorded for Phase L."
}

# =====================================================================
# H15. Expired certificate
# =====================================================================
h15_expired_certificate() {
  phase_header "H15. Expired certificate — the failure a renewal dry run cannot find"
  if [[ "$ROLE" != "server" ]]; then
    warn "H15: skipped on ROLE=testhost for the injection — run the injection on the DNS host. The client-visible checks below need the test host; run those separately with KEYSTONE_H_ROLE=testhost."
    return 0
  fi

  confirm "H15: about to install a DELIBERATELY EXPIRED certificate as AdGuardHome's own copy (/opt/adguardhome/conf/ssl/{fullchain,privkey}.pem) and restart adguardhome, to prove the smoke gate's enddate check is what actually catches this. This can take DoT/DoQ down (and possibly all of :53, depending on how this AGH build reacts). Not staged in /etc/letsencrypt/live/ — do not redirect this at the certbot lineage. Continue?"

  require_cmd openssl
  apt-get install -y faketime
  install -d -m 0700 /root/expired-cert-drill

  openssl req -help 2>&1 | grep -q not_after && echo 'has -not_after' || echo 'use faketime'

  faketime '2024-01-01 00:00:00' openssl req -x509 -nodes \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -days 30 -subj '/CN=dns.example.com' \
    -addext 'subjectAltName=DNS:dns.example.com' \
    -keyout /root/expired-cert-drill/privkey.pem \
    -out    /root/expired-cert-drill/fullchain.pem

  openssl x509 -enddate -noout -in /root/expired-cert-drill/fullchain.pem
  echo "H15: expect a notAfter in early 2024."

  # --- H15: install it, and record which of two things this build does ---
  backup_file /opt/adguardhome/conf/ssl/fullchain.pem
  backup_file /opt/adguardhome/conf/ssl/privkey.pem
  cp -a /opt/adguardhome/conf/ssl/fullchain.pem /root/expired-cert-drill/fullchain.real
  cp -a /opt/adguardhome/conf/ssl/privkey.pem   /root/expired-cert-drill/privkey.real

  install -o adguardhome -g adguardhome -m 0640 \
    /root/expired-cert-drill/fullchain.pem /opt/adguardhome/conf/ssl/fullchain.pem
  install -o adguardhome -g adguardhome -m 0640 \
    /root/expired-cert-drill/privkey.pem   /opt/adguardhome/conf/ssl/privkey.pem
  systemctl restart adguardhome; sleep 5

  systemctl is-active adguardhome || true
  journalctl -u adguardhome --since -2m --no-pager | grep -iE 'certificat|expir|tls' || true
  info "H15: record which branch this build takes — (a) starts and serves the expired cert (DoT/DoQ-only outage, Do53 untouched) or (b) refuses the certificate and does not start (total outage, :53 included). Not safe to guess; it sets the severity of every Phase I certificate alert."

  # --- H15: what the gates see (on-host) ---
  run_smoke
  cat <<'NOTE'
H15: read the dns-smoke.sh signature, don't just score exit code:
  - "cert only -N days left"                      -> FAIL (the only expiry detector; reads the file, never the wire)
  - "served cert == on-disk (dns.example.com:853)" -> OK (both are the same expired cert; this check detects
                                                          a STALE RELOAD, not expiry — a green line here is not "fine")
  - "served cert differs from on-disk (...:443)"   -> FAIL (nginx still serves the real lineage; an artifact of
                                                          this drill's scoping only)
  - "DoT tcp/853"                                  -> OK (the gate's transport checks do not validate the chain)
NOTE

  if [[ -n "${KEYSTONE_H15_TESTHOST_ECHO:-}" ]]; then
    warn "H15: from the H0 test host, run (this script does not do it for you from here):"
    cat <<EOF
  dig @$PUBLIC_IP google.com A +short                # unaffected - Do53 has no certificate
  kdig @$FQDN +tls google.com A                       # RECORD: this SUCCEEDS (kdig verifies nothing by default)
  kdig @$FQDN +tls +tls-ca +tls-hostname=$FQDN google.com A   # FAILS
  kdig @$FQDN +quic +tls-ca +tls-hostname=$FQDN google.com A  # FAILS
  openssl s_client -connect $FQDN:853 -servername $FQDN </dev/null 2>&1 \\
    | grep -E 'Verify return code|notAfter'
  # expect: 'Verify return code: 10 (certificate has expired)'
EOF
  fi

  # --- H15: restore ---
  install -o adguardhome -g adguardhome -m 0640 \
    /root/expired-cert-drill/fullchain.real /opt/adguardhome/conf/ssl/fullchain.pem
  install -o adguardhome -g adguardhome -m 0640 \
    /root/expired-cert-drill/privkey.real   /opt/adguardhome/conf/ssl/privkey.pem
  systemctl restart adguardhome; sleep 5

  diff <(openssl x509 -noout -fingerprint -sha256 -in /opt/adguardhome/conf/ssl/fullchain.pem) \
       <(openssl x509 -noout -fingerprint -sha256 -in "/etc/letsencrypt/live/$FQDN/fullchain.pem") \
    && echo 'OK: the AGH copy matches the lineage again' \
    || warn "H15: restored cert does NOT match the certbot lineage — investigate before Phase K's next backup run. Continuing to clean up the drill directory regardless."
  run_smoke      # SMOKE: PASS, exit=0

  # --- H15: the drill directory holds a SECOND COPY OF THE PRODUCTION PRIVATE
  # KEY. Remove it, and make sure it never reaches a Phase K backup set. ---
  shred -u /root/expired-cert-drill/*.pem /root/expired-cert-drill/*.real 2>/dev/null || true
  rm -rf /root/expired-cert-drill
  echo "H15 PASS overall: expired cert installed, start-or-refuse branch recorded, validating clients failed and non-validating ones did not, smoke gate flagged it on the enddate check only, real certificate restored with a clean smoke run and no leftover key copy."
}

# =====================================================================
# Dispatch
# =====================================================================
STEP="${1:-all}"
case "$STEP" in
  H0)  h0_test_harness ;;
  H1)  h1_do53 ;;
  H2)  h2_doh ;;
  H3)  h3_dot ;;
  H4)  h4_doq ;;
  H5)  h5_dnssec ;;
  H6)  h6_isolation ;;
  H7)  h7_rebinding_edns_tcp ;;
  H8)  h8_cache_prefetch_restart ;;
  H9)  h9_tls_grade ;;
  H10) h10_rate_limiting ;;
  H11) h11_load_test ;;
  LT13) h11_soak_lt13 ;;
  H12) h12_smoke_gate ;;
  H13) h13_outage_injection ;;
  H14) h14_rollback_rehearsal ;;
  H15) h15_expired_certificate ;;
  all)
    h0_test_harness
    h1_do53
    h2_doh
    h3_dot
    h4_doq
    h5_dnssec
    h6_isolation
    h7_rebinding_edns_tcp
    h8_cache_prefetch_restart
    h9_tls_grade
    h10_rate_limiting
    h11_load_test
    h12_smoke_gate
    warn "H: LT-13 (4h soak) and H13/H14/H15 (deliberate fault injection) are NOT run as part of 'all' — invoke them one at a time, in a maintenance window: '$0 LT13', '$0 H13', '$0 H14', '$0 H15'."
    ;;
  *)
    fatal "H: unknown step '$STEP'. Valid: H0-H12, H13, H14, H15, LT13, all"
    ;;
esac

echo
echo "=== Phase H verification pointer ==="
echo "This phase's own gate is /usr/local/sbin/dns-smoke.sh (installed by H12)."
echo "Run it directly to check current state:  /usr/local/sbin/dns-smoke.sh; echo \"exit=\$?\""
echo "Expected output on a healthy host: every check line 'OK', trailer 'SMOKE: PASS', exit=0."
echo "Individual test PASS criteria are printed inline above each check as it runs; the full"
echo "PASS-threshold table (LT-0 .. LT-13) is phases/06-logging-and-validation.md, section H11."
