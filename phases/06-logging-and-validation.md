[Plan index](../dns-server-plan.md) · [Previous: AdGuardHome and the Public Edge](./05-adguardhome-edge.md) · [Next: Observability and Abuse Response](./07-observability-and-abuse.md)

---

**On this page**

- [PHASE F: (Retired) DNS Cache Warmer](#phase-f-retired-dns-cache-warmer)
  - [F1. Removing the v1 warmer from an existing host](#f1-removing-the-v1-warmer-from-an-existing-host)
- [PHASE G: Log Rotation and Retention](#phase-g-log-rotation-and-retention)
  - [G1. journald retention limits](#g1-journald-retention-limits)
  - [G2. The AdGuardHome query log — the real disk risk](#g2-the-adguardhome-query-log-the-real-disk-risk)
  - [G3. nginx](#g3-nginx)
  - [G4. Disk-pressure guard](#g4-disk-pressure-guard)
- [PHASE H: Validation Tests](#phase-h-validation-tests)
  - [H0. Test harness](#h0-test-harness)
  - [H1. Plain DNS (Do53)](#h1-plain-dns-do53)
  - [H2. DoH — through nginx, from outside the host](#h2-doh-through-nginx-from-outside-the-host)
  - [H3. DoT](#h3-dot)
  - [H4. DoQ](#h4-doq)
  - [H5. DNSSEC validation — positive and negative](#h5-dnssec-validation-positive-and-negative)
  - [H6. Resolver isolation](#h6-resolver-isolation)
  - [H7. Rebinding, EDNS, and TCP fallback](#h7-rebinding-edns-and-tcp-fallback)
  - [H8. Cache, prefetch, and restart behaviour](#h8-cache-prefetch-and-restart-behaviour)
  - [H9. TLS grade](#h9-tls-grade)
  - [H10. Rate limiting under abuse — and no collateral damage](#h10-rate-limiting-under-abuse-and-no-collateral-damage)
  - [H11. Load test](#h11-load-test)
  - [H12. Post-change smoke gate](#h12-post-change-smoke-gate)
  - [H13. Upstream and root-server outage injection](#h13-upstream-and-root-server-outage-injection)
  - [H14. Rollback rehearsal — the recovery path nothing else runs](#h14-rollback-rehearsal-the-recovery-path-nothing-else-runs)
  - [H15. Expired certificate — the failure a renewal dry run cannot find](#h15-expired-certificate-the-failure-a-renewal-dry-run-cannot-find)

---

## PHASE F: (Retired) DNS Cache Warmer

Phase F no longer exists. The standalone Python cache warmer (`dns-warmer.service`, `/opt/dns-warmer/warmer.py`, the `dnswarmer` user, `/etc/dns-warmer/domains.txt`) is deleted from the design and is not replaced by a timer, a one-shot script, or anything else. The letter F is retired rather than reused, so cross-references in older notes resolve to this section instead of to some unrelated new phase.

Four reasons, in order of weight:

1. **Unbound already does it, in-process and better.** Phase C sets `prefetch: yes` and `prefetch-key: yes`. Unbound refreshes any cache entry that is queried again inside the last 10% of its TTL, and pre-fetches the DNSKEY for a zone before the validation is needed. That is demand-driven and covers the *whole* cache, not a hand-maintained list. An external warmer cannot beat it; it can only add load.
2. **It warmed the wrong cache.** The v1 warmer queried `127.0.0.1:53` — AdGuardHome — so it filled AGH's small message cache rather than the resolver's, wrote a query-log line per query, and skewed the AGH statistics that Phase I reads for monitoring.
3. **It silently stopped working past 20 domains.** `warm_domain()` was `while True:` with no exit path, and `main()` submitted one such never-returning task per domain into `ThreadPoolExecutor(max_workers=20)`. With `WORKERS = 20`, entries 21 and beyond were queued and never scheduled — no error, no log line, no metric. The shipped `domains.txt` ended with `# Add more as needed`, so this was a trap laid for the operator, not a theoretical edge. The design also cannot be scaled out of the bug: each thread sleeps up to an hour holding a slot.
4. **Its traffic is a fingerprint, not cover traffic.** A fixed set of names re-queried at `ttl * 0.75` with a few seconds of jitter is trivially subtractable from an upstream's view of your resolver, and it advertises which resolver software and which list you run. Cross-reference Phase Q for why "we generate noise" is not a privacy control.

### F1. Removing the v1 warmer from an existing host

Run this on any host built from the v1 plan. It is idempotent.

```bash
systemctl disable --now dns-warmer.service 2>/dev/null || true
rm -f  /etc/systemd/system/dns-warmer.service
rm -rf /opt/dns-warmer /etc/dns-warmer /var/log/dns-warmer
systemctl daemon-reload
systemctl reset-failed dns-warmer.service 2>/dev/null || true

# the service account and its group
userdel  dnswarmer 2>/dev/null || true
groupdel dnswarmer 2>/dev/null || true

# any cron entry that invoked it or its helper
grep -rlsE 'dns-warmer|warmer\.py|warm-once' /etc/cron.d /etc/cron.*/ /var/spool/cron 2>/dev/null
```

Then remove, by hand, the two places v1 referenced the warmer:

- the `/var/log/dns-warmer/*.log` glob in `/etc/logrotate.d/dns-services` (Phase G below already omits it);
- the "warmer log fresh" check in any local copy of the smoke script. H12 below does not contain one.

**Do not touch `ratelimit_whitelist`.** An earlier draft of this section told you to strip `127.0.0.1` / `::1` from it once the warmer was gone. That is wrong: the whitelist is not the warmer's, it is part of the canonical AdGuardHome config Phase E writes, and Phase E keeps both entries. Removing the warmer removes one loopback client; it does not remove the others, and the entries are harmless in this topology for the reasons Phase E states inline — including the caveat about what changes if a plain-DNS proxy is ever placed in front of AdGuardHome. Leave the key exactly as Phase E ships it.

**Verify**

```bash
systemctl is-enabled dns-warmer.service 2>&1     # expect: Failed to get unit file state ... No such file
id dnswarmer 2>&1                                # expect: no such user
ls /opt/dns-warmer /etc/dns-warmer 2>&1          # expect: No such file or directory
grep -rn 'dns-warmer\|dnswarmer' /etc/logrotate.d /etc/cron.d /etc/systemd/system 2>/dev/null   # expect: no output
```

If you want proof that prefetch is carrying the load instead, that is H8.

---

## PHASE G: Log Rotation and Retention

This phase owns only the *mechanics*: what writes, what rotates it, and what stops the disk filling. **What the retention numbers should be, and whether a per-query log should exist at all, is a Phase Q decision** — set the values there, wire the plumbing here.

The component set changed from v1. SmartDNS is gone, so `/var/log/smartdns/` no longer exists. The warmer is gone (Phase F), so `/var/log/dns-warmer/` no longer exists. What actually writes on a v2 host:

| Writer | Destination | Rotated by |
|---|---|---|
| Unbound | journald (`use-syslog: no` — it logs to stderr, which systemd captures; see Phase C) | journald size/time limits |
| AdGuardHome — daemon log | journald | journald size/time limits |
| AdGuardHome — query log | `querylog.json` under `querylog.dir_path` = `/var/log/adguardhome/querylog` (Phase E) — **only when `file_enabled: true`**, which is not the shipped default | **AdGuardHome itself**, never logrotate |
| AdGuardHome — statistics | `stats.db` under `statistics.dir_path` = `/var/lib/adguardhome/stats` (Phase E) | nothing — it is a bolt DB, not a log |
| nginx | `error.log` (and `access.log`, which Phase Q turns off) | the packaged `/etc/logrotate.d/nginx` |
| certbot | `/var/log/letsencrypt/` | the packaged `/etc/logrotate.d/certbot` (if present) |

Two of those rows are the ones that bite.

### G1. journald retention limits

Unbound and AdGuardHome both log to the journal. On a default Ubuntu 24.04 install `SystemMaxUse` is 10% of the filesystem, capped at 4 GB — which on a 40 GB disk means the journal alone may consume 4 GB before it self-limits, and it will do so quietly. Pin it.

```bash
install -d -m 0755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/10-dns.conf << 'EOF'
[Journal]
Storage=persistent
SystemMaxUse=512M
SystemKeepFree=2G
SystemMaxFileSize=64M
SystemMaxFiles=16
RuntimeMaxUse=64M
MaxRetentionSec=14day
# Do not duplicate everything into /var/log/syslog as well.
ForwardToSyslog=no
EOF
systemctl restart systemd-journald
```

`MaxRetentionSec` is a ceiling, not a floor: entries are also dropped when `SystemMaxUse` is hit first, which under load is what will actually happen. Both limits are needed — size bounds the disk, time bounds the privacy exposure.

If `rsyslog` is installed (it is not in the minimal noble cloud image, but some provider images add it) it receives a second copy of everything and writes `/var/log/syslog` under its own packaged logrotate stanza. With `ForwardToSyslog=no` that copy stops; if you would rather keep syslog, leave forwarding on and confirm `/etc/logrotate.d/rsyslog` exists, otherwise you have an unbounded second copy of the journal.

**Privacy interaction (Phase Q owns the decision):** Unbound's `log-queries: yes` / `log-replies: yes` turn the journal into a full query log with unmasked client IPs, retained for whatever the limits above allow. Do not enable them as a debugging convenience and forget them. Phase Q's retention statement must cover the journal, not only `querylog.json`.

**Verify**

```bash
journalctl --disk-usage                       # expect well under 512M once trimmed
journalctl --header | grep -i 'max\|retention' || true
systemd-analyze cat-config systemd/journald.conf | grep -E 'SystemMaxUse|MaxRetentionSec|ForwardToSyslog'
journalctl -u unbound -n 5 --no-pager         # unbound really is landing in the journal
journalctl -u adguardhome -n 5 --no-pager
```

### G2. The AdGuardHome query log — the real disk risk

This is the single most likely way the service dies in week one, and logrotate has nothing to do with it.

AdGuardHome writes one JSON line per query — question, timing, upstream, and a base64 `Answer` blob — at roughly 300–500 bytes. It **rotates by renaming** `querylog.json` to `querylog.json.1` every `querylog.interval`, and deletes the previous `.1` only at the *next* rotation. So the on-disk retention is up to **two intervals**, and there is **no size cap anywhere**: `size_memory` bounds the in-memory ring the admin UI reads, not the file.

At 400 bytes per query on a 40 GB disk:

| Sustained QPS | Per day | On disk at `interval: 24h` (2 intervals) | Time to fill 40 GB |
|---|---|---|---|
| 100 | ~3.5 GB | ~7 GB | ~11 days |
| 500 | ~17 GB | ~35 GB | ~2.3 days |
| 1000 | ~35 GB | ~69 GB | **under 1.2 days** |

When the disk fills, AdGuardHome's own config write fails, the Phase K backup fails, and the journal stops — you lose the evidence at the same moment you lose the service.

Three rules follow.

**(a) Never point logrotate at `querylog.json`.** AdGuardHome holds the file open and rotates it itself. A logrotate stanza would rename the inode out from under a process that receives no signal from it, and AGH would keep appending to the renamed file while `querylog.json` never reappears. The same applies to `stats.db`, which is a database, not a log. If a `/etc/logrotate.d/*` file on your host mentions either path, delete those lines.

**(b) Bound it in AdGuardHome's own config, not with an external tool.** The keys are in the top-level `querylog:` section (Phase E owns writing them, including the two-pass procedure that stops AGH's schema migration from overwriting your block):

```yaml
querylog:
  enabled: true
  file_enabled: false     # the disk-fill fix: memory ring only, nothing on disk
  interval: 6h
  size_memory: 5000
  dir_path: /var/log/adguardhome/querylog   # only consulted when file_enabled is true
```

Those are the values Phase E actually ships — quoted here so the plumbing story is readable in one place, not restated as a second source of truth. `file_enabled: false` keeps the admin UI's recent-queries view working — it reads the memory ring — and writes nothing to disk. `interval` accepts only `6h`, `24h`, `168h`, `720h` and `2160h`; `1h` is not a legal value, so "shorten the interval" is not available as a disk-pressure lever below 6h.

**This is the shipped default, and the shipped default is not zero-log.** Phase E ships `querylog.enabled: true` with `file_enabled: false` and `anonymize_client_ip: true`, and it ships `statistics.enabled: true`. A fully log-free posture is an **opt-in choice offered by Phase Q**, not the state of a freshly built node, and it is not free: turning `statistics.enabled` off blinds every AdGuardHome metric Phase I collects. Phase I owns what happens then — the collector emits a distinct "metrics unavailable by policy" signal rather than `agh_up=0`, and `AdGuardHomeDown` does not fire on a policy decision. Read Phase Q for the choice and Phase I for its consequences before changing either key here.

If the posture in force calls for a file log on disk, then it must be bounded by something other than optimism: `dir_path` on a filesystem you can quota, the shortest legal `interval` (`6h`, so at most ~12h is retained), and the disk guard in G4. Note that **abuse detection must not depend on it either way** — with `anonymize_client_ip: true` the addresses written to disk are masked to /16 (IPv4) or /48 (IPv6), so any ban derived from them targets a network, not an offender. Kernel-side counters are the input; see Phase J.

**(c) Size the interval against measured QPS, not guessed QPS.** Re-run the arithmetic with your own numbers after the H11 load test, and record the result in the Phase L checklist.

**Verify**

```bash
grep -n -A6 -E '^(querylog|statistics):' /opt/adguardhome/conf/AdGuardHome.yaml
grep -c 'querylog_' /opt/adguardhome/conf/AdGuardHome.yaml     # expect 0 (pre-0.107.24 keys)
grep -rn 'querylog.json\|stats.db' /etc/logrotate.d/ || echo 'OK: logrotate does not touch AGH data'

# The expected result of the next check depends on the posture in force (Phase Q),
# so read the config before scoring it - do not assume either answer:
grep -n 'file_enabled' /opt/adguardhome/conf/AdGuardHome.yaml

# With the shipped default (file_enabled: false) there must be no file at all:
ls -l /var/log/adguardhome/querylog/querylog.json* 2>&1   # expect: No such file or directory
# If the posture in force sets file_enabled: true, the file is EXPECTED to exist -
# score it against the arithmetic above (2 x interval retained, no size cap) instead.

# Growth check under real load - run alongside the H11 warm run. Both AGH data
# directories, since the query log and the stats DB live on different paths:
du -sb /var/log/adguardhome /var/lib/adguardhome
sleep 600
du -sb /var/log/adguardhome /var/lib/adguardhome
# PASS: combined growth < 20 MB over 10 minutes at the target QPS.
# That threshold assumes the shipped default (no query log on disk). If the posture
# in force sets file_enabled: true, 20 MB is the wrong gate - recompute the expected
# growth from the bytes-per-query arithmetic above and score against that.
```

`stats.db` exists under `/var/lib/adguardhome/stats` whether or not statistics are enabled — AdGuardHome opens it before it reads `Enabled` (Phase E). Asserting its absence is a test that can never pass, in any posture.

### G3. nginx

nginx ships its own `/etc/logrotate.d/nginx` with a `postrotate` that sends `USR1`. Do not write a second stanza for the same files — two rotators on one file produce gaps and duplicate inodes. Confirm the packaged one is present and leave it alone.

With `access_log off;` in the server block (Phase Q; it is load-bearing for the whole privacy design) only `error.log` grows, and it grows slowly. Keep it at the default `warn` level; `info` or `debug` on a public :443 listener will out-write the query log you just disabled.

**Verify**

```bash
test -f /etc/logrotate.d/nginx && echo 'OK: packaged stanza present'
grep -rn 'error_log' /etc/nginx/nginx.conf /etc/nginx/sites-enabled/ | grep -vi 'warn\|crit\|error' \
  || echo 'OK: no verbose error_log level'
logrotate -d /etc/logrotate.d/nginx 2>&1 | tail -5     # dry run, no errors
```

The behavioural proof that access logging is actually off — a real request producing no log line — belongs to Phase Q, which owns that decision; do not duplicate it here.

### G4. Disk-pressure guard

Everything above bounds the expected writers. The guard exists for the unexpected one — a debug flag left on, a core dump, an apt cache, a runaway backup.

Put the logic in a script, not in the crontab. A literal `%` inside a crontab command line is a command terminator (everything after it becomes stdin for the command), which silently breaks the obvious one-liner form of this check.

```bash
cat > /usr/local/sbin/dns-diskguard.sh << 'EOF'
#!/bin/bash
set -uo pipefail
THRESH=${THRESH:-85}
USED=$(df --output=pcent / | tr -dc '0-9')
if [ "${USED:-0}" -ge "$THRESH" ]; then
  logger -t dns-alert -p daemon.crit "DISK ${USED}% on / (threshold ${THRESH}%)"
  du -xh -d2 /var /opt 2>/dev/null | sort -rh | head -10 | logger -t dns-alert
  exit 1
fi
exit 0
EOF
chmod 750 /usr/local/sbin/dns-diskguard.sh
```

Append it to `/etc/cron.d/dns-health` — that file is **created by Phase I**, which owns it; this phase only adds a line to it and must not write its own copy:

```
*/5 * * * * root /usr/local/sbin/dns-diskguard.sh
```

Routing that `logger` line to a human is Phase I's job, through the single notification entry point `/usr/local/sbin/notify.sh` that Phase I defines — a `logger` call nobody reads is not an alert.

**Verify**

```bash
/usr/local/sbin/dns-diskguard.sh; echo "exit=$?"        # expect exit=0 on a healthy box
THRESH=1 /usr/local/sbin/dns-diskguard.sh; echo "exit=$? (expect 1)"
journalctl -t dns-alert --since -1m --no-pager          # the forced failure must appear
df -h /
```

---

## PHASE H: Validation Tests

This is the acceptance suite. Every test states what PASS looks like, and every threshold in H11 has an identifier the Phase L checklist references rather than restates.

Three rules govern the whole phase:

- **Encrypted-transport and isolation tests run from a second host**, never from the DNS server. Running them locally bypasses the NIC, the firewall, the conntrack bypass, the rate limiter, and — for DoH specifically — the entire nginx front end, which means they can pass on a box where the public service is completely broken.
- **A test that cannot fail is worse than no test.** Several v1 checks used vectors that produce the "pass" output on a totally unprotected resolver. Where that was true, the corrected vector and the reason are given inline.
- **H13, H14 and H15 deliberately break the running service.** They remove upstream reachability, force a version rollback, and install an expired certificate — the three states this plan configures machinery to survive and otherwise never produces. Each carries its restore step, and the restore is part of the test, not an afterthought. Run them one at a time in a maintenance window before go-live, and confirm `dns-smoke.sh` reports `SMOKE: PASS` before starting the next one.

### H0. Test harness

Build a second small VPS **in the same region**. Record its round-trip time to the DNS host once; H11's latency gates are stated relative to it.

```bash
apt install -y dnsperf knot-dnsutils curl jq openssl
which resperf || echo 'WARN: resperf not in this dnsperf build - install from DNS-OARC source'

# dnspyre: per-protocol load with percentiles. Resolve the asset from the API -
# the release filename embeds the version, so a hand-built URL 404s.
ARCH=$(dpkg --print-architecture)
URL=$(curl -fsS https://api.github.com/repos/Tantalor93/dnspyre/releases/latest \
  | jq -r --arg a "$ARCH" '.assets[] | select(.name | test("linux_" + $a + "\\.tar\\.gz$")) | .browser_download_url')
[ -n "$URL" ] || { echo 'resolve manually: curl -fsS https://api.github.com/repos/Tantalor93/dnspyre/releases/latest | jq -r .assets[].name'; exit 1; }
curl -fsSL "$URL" | tar xz -C /usr/local/bin dnspyre
dnspyre --version

# Baseline RTT, used by the H11 latency gates.
RTT_base=$(ping -c 20 -q <PUBLIC_IP> | awk -F/ '/rtt|round-trip/ {print $5}')
echo "RTT_base = ${RTT_base} ms"    # record this in the Phase L checklist
```

**DoQ client.** Ubuntu 24.04 ships `knot-dnsutils` 3.3.x, and DoQ (`+quic`) landed in Knot DNS 3.3.0 — so `kdig +quic` is expected to work on noble. This is the reason Ubuntu 22.04 was rejected: jammy's 3.1.6 has `+tls` and `+https` but no `+quic`, and the resulting unknown-option error reads exactly like a DoQ outage. Confirm the build before trusting any DoQ result:

```bash
kdig -V     # must report >= 3.3 for +quic to mean anything
```

If your image ships something older, install AdGuard's `dnslookup` (a static Go binary that speaks `quic://`) rather than scoring a tooling failure as a service failure.

### H1. Plain DNS (Do53)

```bash
dig @<PUBLIC_IP> google.com A
dig @<PUBLIC_IP> google.com AAAA
dig @<PUBLIC_IP> +tcp google.com A                       # TCP/53 must also answer
dig @<PUBLIC_IP> nonexistent.invalid A +noall +comments  # status: NXDOMAIN
dig @<PUBLIC_IP> google.com HTTPS                        # type65 is a large share of real traffic
```

PASS: all four return `status: NOERROR` with answers (NXDOMAIN for the `.invalid` name), from the public IP, over both UDP and TCP.

Note the UDP path is untracked by conntrack (Phase B) — the accept rule for untracked DNS is what makes this work, and H12 re-checks it after every change.

### H2. DoH — through nginx, from outside the host

DoH is the test most likely to give a false pass. nginx terminates TLS on public `:443` and proxies **only** `/dns-query` to AdGuardHome's HTTPS listener on `127.0.0.1:8053` (Phase E explains why AGH's own `port_https` cannot serve this publicly). If you run this test on the DNS host you can reach `127.0.0.1:8053` directly and get a green result on a box whose public DoH is entirely broken. **Run it from the test host.**

AdGuardHome speaks **RFC 8484 wire format only**. Its DoH server is dnsproxy's, which reads `?dns=<base64url>` on GET and requires `Content-Type: application/dns-message` on POST. There is **no** `application/dns-json` endpoint — the v1 plan's `curl -H 'accept: application/dns-json' '.../dns-query?name=...'` test cannot succeed and was never testing DoH.

```bash
# Primary check - wire format, GET and POST, both handled by kdig:
kdig @dns.example.com +https google.com A
kdig @dns.example.com +https +tls-ca +tls-hostname=dns.example.com google.com A

# Raw HTTP form, using the canonical RFC 8484 4.1.1 example query (www.example.com A):
curl -sD- -o /dev/null --max-time 5 \
  -H 'accept: application/dns-message' \
  'https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB'
# PASS: HTTP/2 200 with content-type: application/dns-message

# The JSON API does NOT exist - this documents the gap, it is not a failure:
curl -si --max-time 5 -H 'accept: application/dns-json' \
  'https://dns.example.com/dns-query?name=google.com&type=A' | head -3

# Only /dns-query may be proxied. Everything else must not reach AdGuardHome:
curl -si --max-time 5 https://dns.example.com/            | head -1   # expect 404/403, NOT an AGH page
curl -si --max-time 5 https://dns.example.com/login.html  | head -1   # expect 404/403
curl -s  --max-time 5 https://dns.example.com/control/status         # expect empty/404, never JSON
```

PASS: `+https` resolves; `/dns-query` returns `application/dns-message`; no other path returns AdGuardHome content. A JSON body from `/control/status` is a **critical** failure — the control API is exposed — stop and fix Phase E before continuing.

### H3. DoT

```bash
kdig @dns.example.com +tls google.com A
kdig @dns.example.com +tls +tls-ca +tls-hostname=dns.example.com google.com A   # cert actually validates
kdig @dns.example.com +tls dnssec-failed.org A +noall +comments                 # SERVFAIL, see H5
```

PASS: NOERROR with an answer, and the second form succeeds without `--tls-not-verify`, proving the served chain validates against the system trust store.

DoT is served directly by AdGuardHome's `dnsforward` on `dns.bind_hosts:853` — nginx is not in this path, so a DoT failure and a DoH failure have different causes. Do not debug them together.

### H4. DoQ

```bash
kdig -V | head -1                                   # must be >= 3.3
kdig @dns.example.com +quic google.com A
kdig @dns.example.com +quic dnssec-failed.org A +noall +comments   # SERVFAIL
```

PASS: NOERROR with an answer over `udp/853`. DoQ is TLS 1.3-only by construction (RFC 9250 requires QUIC), so a cipher-policy change that affects DoT will not show up here.

If this fails while H3 passes, check UDP/853 in the firewall first — DoT and DoQ share a port number but not a protocol, and a ruleset that opens only `tcp dport 853` produces exactly this asymmetry.

### H5. DNSSEC validation — positive and negative

Non-negotiable for this design. Validation happens in exactly one place, Unbound. AdGuardHome does not validate; `enable_dnssec: true` only sets the DO bit. Prove both directions, at the resolver and then through every public protocol.

**At the resolver (on the host):**

```bash
# Negative: a deliberately broken zone must SERVFAIL, and 1.19.2 should say why (EDE).
dig @127.0.0.1 -p 5335 dnssec-failed.org A +dnssec +noall +comments
dig @127.0.0.1 -p 5335 sigfail.verteiltesysteme.net A +dnssec +noall +comments
# PASS: status: SERVFAIL. An EDE of 'DNSSEC Bogus' / 'Signature Expired' is confirmation.

# Positive: a signed name must return the 'ad' flag and RRSIGs.
dig @127.0.0.1 -p 5335 sigok.verteiltesysteme.net A +dnssec +noall +comments
dig @127.0.0.1 -p 5335 internetsociety.org A +dnssec | grep -E '^;; flags:|RRSIG'
# PASS: flags line contains 'ad', and at least one RRSIG record is present.

# The validator is actually armed - a missing/empty trust anchor SERVFAILs everything,
# which looks identical to "DNSSEC works" if you only run the negative test:
test -s /var/lib/unbound/root.key && echo ANCHOR-OK
stat -c '%U:%G %a %s' /var/lib/unbound/root.key
unbound-control stats_noreset | grep -E 'num.answer.secure|num.answer.bogus|val'
```

The last block is the check most suites omit. `dnssec-failed.org` returns SERVFAIL both when validation works *and* when the trust anchor is broken so badly that nothing resolves. The positive test is what distinguishes them — never run the negative one alone.

**Through the public edge, on every protocol:**

```bash
dig  @<PUBLIC_IP>            dnssec-failed.org A +noall +comments   # SERVFAIL
kdig @dns.example.com +tls   dnssec-failed.org A +noall +comments   # SERVFAIL
kdig @dns.example.com +https dnssec-failed.org A +noall +comments   # SERVFAIL
kdig @dns.example.com +quic  dnssec-failed.org A +noall +comments   # SERVFAIL
dig  @<PUBLIC_IP> internetsociety.org A +dnssec | grep -E '^;; flags:|RRSIG'   # 'ad' + RRSIG
```

**Cache normalisation** — the check that proves `enable_dnssec: true` took effect. dnsproxy's `addDO` only *adds* DO when the client omitted it, so a client that sets `+dnssec` already gets RRSIGs regardless of the setting. What the setting changes is the cached entry: with it off, a plain query caches an answer stripped of RRSIGs and a later `+dnssec` client is served that stripped entry.

```bash
N=$(openssl rand -hex 4).internetsociety.org   # any signed zone; use a fresh label
dig @<PUBLIC_IP> internetsociety.org A +short >/dev/null      # warm WITHOUT dnssec
dig @<PUBLIC_IP> internetsociety.org A +dnssec | grep -c RRSIG
# PASS: non-zero. Zero means enable_dnssec is not in effect.
```

**No bypass exists** — with the validator stopped, nothing else may answer. This proves `fallback_dns` is empty (dnsproxy reaches a fallback on transport errors, which is precisely when Unbound is down):

```bash
systemctl stop unbound
dig @<PUBLIC_IP> example.org A +time=3 +tries=1 +noall +comments   # SERVFAIL / no answer, NEVER an address
systemctl start unbound
```

PASS: a failed lookup. An answer here means some third-party resolver is configured somewhere in the chain, and every DNSSEC guarantee above is void.

### H6. Resolver isolation

`5335` (Unbound), `8053` (AGH HTTPS listener behind nginx), and `3000` (AGH admin UI) must be reachable on loopback and nowhere else. **From the test host:**

```bash
dig @<PUBLIC_IP> -p 5335 google.com A +time=2 +tries=1   # expect timeout, never an answer
timeout 3 bash -c '</dev/tcp/<PUBLIC_IP>/8053' && echo 'FAIL: 8053 open' || echo 'OK: 8053 closed'
timeout 3 bash -c '</dev/tcp/<PUBLIC_IP>/3000' && echo 'FAIL: 3000 open' || echo 'OK: 3000 closed'
curl -si --max-time 3 http://<PUBLIC_IP>:3000/ | head -1  # expect connection failure
nmap -Pn -p 53,80,443,853,3000,5335,8053 <PUBLIC_IP>
nmap -Pn -sU -p 53,853 <PUBLIC_IP>
```

PASS from nmap: `53/tcp`, `80/tcp`, `443/tcp`, `853/tcp` open, everything else `filtered` or `closed`; `53/udp` and `853/udp` open. **`80/tcp` is permanently open** — Phase B carries a standing `tcp dport 80 accept`, nginx owns the listener (Phase E), and it serves the ACME webroot (Phase D) and the Phase Q well-known files. A filtered or closed `80/tcp` here is a failure, not a hardening win.

**On the host**, confirm the bindings themselves rather than relying on the firewall alone — a listener bound to `0.0.0.0` and protected only by nftables is one bad `nft flush` away from exposure:

```bash
ss -lntup | grep -E ':(53|80|443|853|3000|5335|8053)\b'
# PASS: 5335 on 127.0.0.1/::1 only; 8053 on 127.0.0.1 only; 3000 on 127.0.0.1 only;
#       53/80/443/853 on the public address (or 0.0.0.0) as designed - :80 is nginx
#       (Phase E), and it is expected to be listening at all times, not only during
#       a certificate renewal.
```

The admin UI is reached over an SSH tunnel; that procedure belongs to Phase P.

### H7. Rebinding, EDNS, and TCP fallback

**Rebinding.** The v1-era vectors for this test were all wrong *and* all fail-open — they produce empty output on a resolver with no protection at all, so the test certified an absent control as working. `private.dns-oarc.net` does not exist; `1.0.0.127.rbndr.us` is not rbndr's format (it uses hex labels, not reversed dotted-quad); `7f000001.rbndr.us` is missing its second label. The working form is `<hexA>.<hexB>.rbndr.us`.

The config assertion is the authoritative check, because it cannot fail open:

```bash
grep -c '^ *private-address:' /etc/unbound/unbound.conf.d/10-public-resolver.conf   # expect 18
grep -c '^ *private-domain:'  /etc/unbound/unbound.conf.d/10-public-resolver.conf   # expect 1
unbound-checkconf && echo CONF-OK
```

The live probe needs a control query, because `rbndr.us` runs a deliberately non-conforming nameserver that a validating resolver may SERVFAIL for reasons unrelated to `private-address`:

```bash
V=7f000001.c0a80001.rbndr.us          # 7f000001 = 127.0.0.1, c0a80001 = 192.168.0.1
CTRL=$(dig @8.8.8.8 "$V" A +short +time=4 +tries=1 | tr '\n' ' ')
MINE=$(dig @<PUBLIC_IP> "$V" A +short +time=4 +tries=1 | tr '\n' ' ')
echo "control='$CTRL' ours='$MINE'"
if   [ -z "$CTRL" ]; then echo 'INCONCLUSIVE: vector down upstream - do not score this run'
elif [ -z "$MINE" ]; then echo 'PASS: private address stripped'
else echo "FAIL: resolver returned $MINE for a public name"; fi
```

Special-use zones must be answered locally, not recursed:

```bash
dig @127.0.0.1 -p 5335 facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion A +noall +comments  # NXDOMAIN
dig @127.0.0.1 -p 5335 1.168.192.in-addr.arpa PTR +noall +comments   # NXDOMAIN, not a recursion
dig @127.0.0.1 -p 5335 localhost A +short                            # 127.0.0.1
```

Runbook note: `private-address` *strips* records, so some names return NODATA rather than an error. Any "site X stopped working" report should be checked against this list first and, if legitimate, exempted with `private-domain`.

**EDNS and fragmentation.** The upstream leg is configurable; the client-facing leg is not.

```bash
# Upstream: Unbound advertises 1232 to authoritatives (DNS Flag Day 2020).
unbound-control get_option edns-buffer-size    # 1232
unbound-control get_option max-udp-size        # 1232
```

AdGuardHome has **no** UDP buffer knob — dnsproxy takes the client's advertised size verbatim with no ceiling (`defaultUDPBufSize` is a compile-time constant used only as a fallback). A client advertising 4096 gets up to 4096 bytes on UDP and the response fragments. This is a documented limitation, not a misconfiguration; the mitigation is steering clients to DoT/DoH/DoQ. Do **not** try to clamp EDNS in nftables — it has no DNS parser and a byte-offset hack will corrupt answers.

**TCP fallback.** The v1 vector could not truncate. Measured response sizes with `+tcp +dnssec +bufsize=4096`: `isc.org DNSKEY` 299 B, `dnsviz.net DNSKEY` 491 B, `org DNSKEY` 895 B, `. DNSKEY` 1139 B — none exceed 1232, so `+bufsize=1232 +ignore` never sets `tc` and the check returned 0 and read as a pass. Use a pair that provably truncates:

```bash
dig @<PUBLIC_IP> +dnssec +bufsize=512 +ignore . DNSKEY +noall +comments | grep -o 'flags:[^;]*'
#   PASS: the flags string contains ' tc'
dig @<PUBLIC_IP> +dnssec +tcp . DNSKEY +noall +comments | grep 'status:'
#   PASS: NOERROR over TCP
dig @<PUBLIC_IP> +dnssec +bufsize=4096 . DNSKEY +noall +stats | grep 'MSG SIZE'
#   a >1232-byte UDP response here is the client-leg fragmentation exposure - expected, documented
```

**Source-port randomisation** on the recursive leg. `ss -unp 'dst :53'` shows nothing for Unbound (it uses unconnected UDP sockets), so watch the wire:

```bash
timeout 20 tcpdump -ni any -c 30 'udp dst port 53 and not host 127.0.0.1' 2>/dev/null \
  | sed -n 's/.*\.\([0-9]*\) > .*/\1/p' | sort -u | wc -l    # PASS: many distinct ports, not 1
```

**DNS cookies.** Check whether the public edge implements RFC 7873 at all, and record the answer rather than assuming:

```bash
dig @<PUBLIC_IP> +cookie google.com A +noall +comments | grep -i 'COOKIE'
# 'COOKIE: <client><server>' with 64+ hex chars => server cookies active
# client-only cookie echoed back      => the edge does not implement cookies (AdGuardHome does not)
```

Plain Do53 through AdGuardHome has no cookie protection. That is a known, accepted gap in this design — the answer is to steer users to the connection-oriented protocols — and it belongs in the runbook, not in a "fix later" list.

### H8. Cache, prefetch, and restart behaviour

Unbound's cache is **in memory only**. It is lost on restart, there is no cache file, and that is deliberate: the SmartDNS design wrote a `smartdns.cache` domain-history file that survived reboots and provider snapshots (see Phase Q). "Cache persistence" is therefore not a v2 requirement, and the v1 test for it no longer applies. What matters is that the cache fills, that prefetch keeps hot entries warm without a warmer, and that a restart recovers quickly.

```bash
unbound-control stats_noreset | grep -E 'total.num.(queries|cachehits|cachemiss|prefetch)'
# If your build names these differently, enumerate with:
#   unbound-control stats_noreset | grep '^total'

# Cache hit: the second query must be materially faster and must not re-recurse.
dig @127.0.0.1 -p 5335 wikipedia.org A +noall +stats | grep 'Query time'
dig @127.0.0.1 -p 5335 wikipedia.org A +noall +stats | grep 'Query time'
# PASS: second query time is ~0 ms.

# Prefetch is doing work (this replaces the retired Phase F warmer):
B=$(unbound-control stats_noreset | awk -F= '/total.num.prefetch/{print $2}')
# ... run 10 minutes of the H11 warm corpus ...
A=$(unbound-control stats_noreset | awk -F= '/total.num.prefetch/{print $2}')
echo "prefetch delta = $((A - B))"    # PASS: > 0 under sustained repeat traffic

# TTL honesty: a short-TTL name must not be pinned by a minimum-TTL setting.
dig @<PUBLIC_IP> whoami.cloudflare.com TXT +noall +answer   # or any known short-TTL name
sleep 35; dig @<PUBLIC_IP> whoami.cloudflare.com TXT +noall +answer
# PASS: the TTL counts down and refreshes; it must not be floored at an artificial value.

# Restart behaviour:
systemctl restart unbound && sleep 2
unbound-control stats_noreset | grep -E 'total.num.cachehits|total.num.cachemiss'  # both near zero
ls -l /var/lib/unbound/                 # PASS: root.key only, no cache file
dig @<PUBLIC_IP> google.com A +short    # PASS: answers within the first second after restart
```

PASS overall: hit ratio climbs during the H11 warm run, `total.num.prefetch` is non-zero, no on-disk cache artefact exists, and service resumes immediately after a restart.

### H9. TLS grade

Two listeners terminate TLS and they are configured by different components. Test both — almost nobody checks `:853`.

```bash
apt install -y testssl.sh || git clone --depth 1 https://github.com/testssl/testssl.sh /opt/testssl
/opt/testssl/testssl.sh --quiet --protocols --ciphers --vulnerable dns.example.com:443   # nginx / DoH
/opt/testssl/testssl.sh --quiet --protocols --ciphers               dns.example.com:853  # AdGuardHome / DoT
```

PASS: TLS 1.2 and 1.3 offered; TLS 1.0/1.1 and SSLv3 refused; no CBC or RC4 suites; no known-vulnerable findings.

**Protocol floor.** nginx's floor is yours to set in Phase D. AdGuardHome's is **not configurable** — `internal/home/tls.go` hardcodes `MinVersion: tls.VersionTLS12`, which is why there is no `min_version` key. What *is* configurable is the cipher list (`tls.override_tls_ciphers`, real yaml tag in `tlsConfigSettings`), whose values are Go `crypto/tls` constant names passed straight through: a typo makes the listener refuse to start, so restart and read the log rather than assuming it applied. TLS 1.3 suites are not configurable in Go and are always on, so DoQ scan results will not change when you edit the list.

**Do not test TLS 1.1 refusal with the naive command.** Ubuntu ships OpenSSL with `MinProtocol = TLSv1.2` and `@SECLEVEL=2`, so `openssl s_client -tls1_1` fails locally before a packet leaves the box — the check reports "correctly refused" no matter what the server does. Force the client down first:

```bash
openssl s_client -connect dns.example.com:853 -servername dns.example.com \
  -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0' </dev/null 2>&1 | grep -E 'Protocol|alert|handshake failure'
# Trust testssl.sh --protocols over this; it is the unambiguous answer.
```

**Chain and key type.** Certificates are ECDSA P-256 (Phase D) — RSA-2048 handshakes are roughly an order of magnitude more expensive on the one path AdGuardHome does not rate-limit.

```bash
openssl x509 -in /etc/letsencrypt/live/dns.example.com/cert.pem -noout -text \
  | grep -E 'Public Key Algorithm|ASN1 OID|NIST CURVE|Signature Algorithm' | head -4
# PASS: id-ecPublicKey / prime256v1 / NIST CURVE: P-256

openssl s_client -connect dns.example.com:443 -servername dns.example.com -showcerts </dev/null 2>/dev/null \
  | grep -E '^ *[0-9]+ s:|^ *[0-9]+ i:'
# PASS: leaf + intermediate served. A leaf-only chain works in browsers and breaks DoT clients.

openssl x509 -noout -ocsp_uri -in /etc/letsencrypt/live/dns.example.com/cert.pem   # expect EMPTY
```

That last line is expected to print nothing: Let's Encrypt dropped OCSP URLs from issued certificates on 2025-05-07 and shut the responders down on 2025-08-06. Do not add `ssl_stapling on` (a no-op) or request `--must-staple` (fails at issuance). The practical revocation story is reissue-and-redeploy, which is an argument for keeping Phase D's renewal automation healthy — and for the served-vs-on-disk fingerprint check in H12.

**Certificate Transparency** publishes the hostname at issuance. Nothing to configure; worth knowing what is public:

```bash
curl -s 'https://crt.sh/?q=dns.example.com&output=json' | jq -r '.[].issuer_name' | sort -u
```

### H10. Rate limiting under abuse — and no collateral damage

Two limiters stack, and they live in different places:

- **nftables per-source flood detection** — chain `dns_guard` in `table inet filter`, a *regular* chain jumped from `chain input`, with the meters `floodmeter4` / `floodmeter6` and the ban sets `banned_ips` / `banned_ips6` in that same table (Phase B owns the ruleset objects; Phase J owns the ban and escalation logic that manipulates them). The flood threshold is **400/s per source**, and that single flood rule is the only kernel rate-limit tier — there is no second, lower limiter below it. There is no separate rate-limit table to look in either: the ruleset is two tables — `table inet raw` for the NOTRACK rules and nothing else, `table inet filter` for everything here — with exactly one base chain on the input hook (`chain input`, at priority 0 — spelled `priority filter` in Phase B's ruleset), which `dns_guard` hangs off rather than competing with. `dns_guard` is not a base chain and is not at priority -1; that was v1's layout, and it made rule order a function of priority arithmetic.
- **AdGuardHome's application-level `ratelimit`** — **100 qps**, and it covers **plain UDP/53 only**. TCP/53, DoH, DoT and DoQ are unthrottled at the application layer by construction (Phase E documents the dnsproxy code path). Do not read a DoH result as evidence about this key.

Both **drop silently** — neither implements RRL SLIP, and an nftables `drop` definitionally cannot emit TC=1. That is a design consequence to document, not a bug to chase.

The test that matters is not "does it drop", it is "does it drop *only the abuser*". AdGuardHome's *defaults* are `ratelimit_subnet_len_ipv4: 24` / `_ipv6: 56`, which means an entire /24 shares one budget and one abusive client behind a carrier NAT takes out every legitimate client near it. Phase E therefore sets **32 / 64**, and this test is what proves those values are in effect rather than merely written down.

```bash
# 1. Legitimate baseline, from a normal client - record it.
for i in $(seq 1 10); do dig @<PUBLIC_IP> example.net A +short +time=2; done

# 2. Flood from host A - 5000 QPS is far above both the AGH 100 qps UDP limiter
#    and the 400/s nftables flood threshold, so both layers must engage:
dnsperf -s <PUBLIC_IP> -d /tmp/queries.txt -c 20 -T 2 -l 30 -Q 5000

# 3. DURING the flood, from host B in the SAME /24 as host A:
dig @<PUBLIC_IP> example.net A +short +time=2 +tries=1
# PASS: host B still gets an answer. A timeout here means the limiter aperture is
# per-subnet, not per-IP - Phase E's ratelimit_subnet_len_ipv4: 32 / _ipv6: 64 is
# not in effect (the keys need AGH >= v0.107.41).

# 4. Confirm the flooder was actually limited:
grep -E '^ *ratelimit:|ratelimit_subnet_len' /opt/adguardhome/conf/AdGuardHome.yaml
#    expect: ratelimit: 100, ratelimit_subnet_len_ipv4: 32, ratelimit_subnet_len_ipv6: 64
nft list chain inet filter dns_guard | grep -E 'limit rate|@floodmeter|@banned_ips'
nft -j list sets | jq -r '.nftables[]?.set?.name' | sort -u
#    expect to see: floodmeter4 floodmeter6 banned_ips banned_ips6 banned_long
#    banned_long6 allowlist4 allowlist6 - all in table inet filter. The only other
#    table is table inet raw, which carries the NOTRACK rules and holds no sets:
nft list tables                  # expect EXACTLY: table inet raw, table inet filter
```

**Abuse detection must be kernel-side.** With `anonymize_client_ip: true` the addresses AdGuardHome writes are masked to /16 (IPv4) and /48 (IPv6) — verified in source and empirically, where v0.107.78 wrote `"IP":"127.0.0.0"`. Anything that bans an address read from the query log bans a masked, wrong network — and under a Phase Q posture that disables the query log, it bans nothing at all while still exiting 0. Phase J's ban pipeline reads nftables state instead, which is correct in every posture. Verify that it is promoting from the **flood meter** into the **ban set**, and not simply banning the meter's contents:

```bash
# floodmeter4 contains EVERY source seen in the window - it is the limiter's state,
# not a list of offenders. Banning its contents removes your entire user base in one
# tick, which is why Phase J's promotion is gated on the rate expression rather than
# on set membership. Watch the two sets separately during the flood:
nft -j list set inet filter floodmeter4 | jq '.nftables[]?.set.elem? | length'
nft -j list set inet filter banned_ips  | jq '.nftables[]?.set.elem? | length'
nft list set inet filter banned_ips     # the flooder's address, with a timeout counting down
```

PASS: the flooding source appears in `floodmeter4` and is then promoted into `banned_ips` with a 10-minute timeout (escalating to 24 hours on repeat — Phase J owns that logic and the operator procedures); a well-behaved source in the same subnet appears in neither set and keeps resolving throughout.

### H11. Load test

The v1 load test (`echo "google.com A" > /tmp/queries.txt` plus one more name, then `dnsperf -l 30 -Q 500`) cannot detect a single failure mode in this document. Two names are 100% cache hits after the first two queries, so it benchmarks a Go map lookup. `-Q 500` caps the rate at the target, so it can never find the knee. Thirty seconds is shorter than TLS ticket rotation, cache eviction, log rotation and GC steady state. It reports throughput and a mean, not percentiles, so the tail — which is what users experience — is invisible. And it covers only Do53, leaving DoH, DoT and DoQ, the protocols with the expensive CPU path and no application rate limit, entirely untested.

Everything below runs **from the H0 test host**. A load test on the DNS server steals CPU from the system under test and bypasses the NIC, the firewall, conntrack and the rate limiter — every component this plan hardens.

**Corpus** — a realistic mix, built once:

```bash
curl -sL https://tranco-list.eu/top-1m.csv.zip -o /tmp/t.zip
unzip -p /tmp/t.zip | cut -d, -f2 | head -50000 > /tmp/warm.txt
for i in $(seq 1 5000); do echo "nx$(openssl rand -hex 4).invalid"; done >> /tmp/warm.txt

# Hostile corpus: guaranteed cache miss, NXDOMAIN at the root, and NO third-party
# authoritative load. Do NOT aim this at example.com - 300 QPS for 300 s is ~90,000
# queries at IANA's documentation domain, forwarded to real authoritatives, and the
# run stops being reproducible the moment they throttle you.
for i in $(seq 1 10000); do echo "$(openssl rand -hex 6).$(openssl rand -hex 3).invalid"; done > /tmp/miss.txt

# dnsperf format: name + type, with a modern type mix. HTTPS/type65 is a large share
# of real traffic today and takes a different code path.
awk '{print $1" A"; print $1" AAAA"; if (NR%5==0) print $1" HTTPS"; \
      if (NR%23==0) print $1" MX"; if (NR%37==0) print $1" TXT"}' /tmp/warm.txt > /tmp/queries.txt
```

Note that the cold run drives ~50,000 real recursions at real authoritative servers. That is legitimate, bounded, and the point of the test — but do not loop it.

**Three cache states, measured separately.** v1 measured only one, and it was the least interesting.

```bash
# COLD - Unbound's cache is in memory only, so a restart IS the cold state.
# (There is no cache file to delete; that was the SmartDNS design.)
ssh dns1 'systemctl restart unbound'; sleep 3
dnsperf -s <PUBLIC_IP> -d /tmp/queries.txt -c 50  -T 4 -l 300 -Q 500  -S 10

# WARM - after 10 minutes of the same corpus; the normal operating point.
dnsperf -s <PUBLIC_IP> -d /tmp/queries.txt -c 100 -T 4 -l 300 -Q 2000 -S 10

# HOSTILE - 100% unique labels, the actual shape of a cache-busting attack.
dnsperf -s <PUBLIC_IP> -d <(awk '{print $1" A"}' /tmp/miss.txt) -c 50 -T 4 -l 300 -Q 300 -S 10

# CAPACITY KNEE - ramp until it breaks. Never guess the ceiling.
# NOTE: -c means different things in the two tools.
#   dnsperf -c N = simulated clients ; resperf -c N = seconds of CONSTANT traffic after the ramp
resperf -s <PUBLIC_IP> -d /tmp/queries.txt -m 20000 -r 120 -c 60
```

**Per-protocol, with percentiles.** Their costs differ by an order of magnitude; a single aggregate number hides that entirely.

```bash
dnspyre -s <PUBLIC_IP>                       -t A -t AAAA -t HTTPS -c 50 -l 2000 -d 300s @/tmp/warm.txt
dnspyre -s dns.example.com:853 --dot         -t A -c 50 -l 500  -d 300s --separate-worker-connections @/tmp/warm.txt
dnspyre -s https://dns.example.com/dns-query -t A -c 50 -l 1000 -d 300s @/tmp/warm.txt
dnspyre -s quic://dns.example.com:853        -t A -c 50 -l 500  -d 300s @/tmp/warm.txt
```

`--separate-worker-connections` on the DoT run is what exercises handshake cost rather than a single reused session — that is the metric the ECDSA decision in Phase D exists to protect.

**Pin the dnspyre JSON schema before writing any automated gate.** `--json` exists but its schema is not documented, and a wrong `jq` path returns `null` and silently passes:

```bash
dnspyre -s 127.0.0.1 -t A -c 2 -d 5s --json example.org | jq 'paths(scalars) | join(".")' | sort -u
# Substitute the real field names into your gate. Do not ship guessed paths.
```

**Server-side instrumentation, captured during every single run.** A run without this is not a result.

```bash
# on the DNS host, for the duration of each run:
watch -n1 'cat /proc/sys/net/netfilter/nf_conntrack_count; \
           nstat -az | grep -Ei "UdpRcvbufErrors|UdpInErrors|TcpExtListenDrops"; \
           systemd-cgtop -m -n1 --order=memory | head -6'
mpstat -P ALL 1 300 > /tmp/cpu.log
```

**PASS thresholds.** These replace the v1 checklist's bare "Load test passed (500 QPS sustained)". Phase L references them by ID.

| ID | Run | Metric | PASS |
|---|---|---|---|
| LT-0 | baseline, measured first | `dig` RTT from test host to DNS host | record as `RTT_base` |
| LT-1 | Do53 warm, 2,000 QPS, 300 s | p50 / p99 | < `RTT_base` + 1 ms / < `RTT_base` + 5 ms |
| LT-2 | Do53 warm | lost + timeout | 0 |
| LT-3 | Do53 cold, 500 QPS | p99 | < 250 ms |
| LT-4 | Do53 hostile, 300 QPS | p99 / SERVFAIL rate | < 400 ms / < 1% |
| LT-5 | DoT, 200 new conns/s | handshake p99 | < 150 ms |
| LT-6 | DoH, 1,000 QPS over 50 conns | p99 | < 15 ms |
| LT-7 | DoQ, 500 QPS | p99 | < 20 ms |
| LT-8 | every run | `nf_conntrack_count` peak | < 5,000 |
| LT-9 | every run | `UdpRcvbufErrors` delta | 0 |
| LT-10 | every run | peak CPU, all cores | < 70% |
| LT-11 | every run | new `dmesg` entries | none |
| LT-12 | every run | disk growth over 10 min | < 20 MB |
| LT-13 | 4-hour soak at 30% of the measured knee | RSS slope, both daemons | flat |

LT-8 is the direct check on the Phase B conntrack bypass: if UDP/53 is genuinely NOTRACK'd, a 2,000 QPS run barely moves the counter. A number in the hundreds of thousands means the bypass is not in effect and the box will drop SSH along with DNS.

LT-12 is stated for the shipped logging default — query log in memory only, statistics on (Phase E). It is the one threshold in this table that a *policy* change can move: if the posture in force (Phase Q) puts a query log on disk, recompute the gate from the G2 arithmetic instead of failing a run against a number that no longer applies.

LT-13 is the one nothing shorter finds. Run the soak before go-live and plot RSS of `unbound` and `AdGuardHome`. A flat line is the pass; a positive slope is a leak, and a leak is the failure this stack is most likely to hit in production.

**Minimum gate before declaring go-live:**

```bash
dnsperf -s <PUBLIC_IP> -d /tmp/queries.txt -c 100 -T 4 -l 300 -Q 2000 -S 10 | tee /tmp/warm.out
grep -E 'Queries per second|Average Latency|Queries lost|Response codes' /tmp/warm.out

# On the server, immediately after every run - all four must be clean:
cat /proc/sys/net/netfilter/nf_conntrack_count
nstat -az | grep -Ei 'UdpRcvbufErrors|UdpInErrors'
dmesg -T | tail -20
df -h /
```

### H12. Post-change smoke gate

The v1 plan restarted services and then hoped. This is the gate that answers "did it come back correctly". One script, non-zero exit on any failure, called after **every** restart and **every** upgrade.

Three notes on what it does *not* contain, each of which would make it fail permanently on a correct v2 host — and a gate that always fails gets deleted, taking the working checks with it:

- **No `getcap` check.** `NoNewPrivileges=yes` nullifies file capabilities across `execve`, so this design uses `AmbientCapabilities=CAP_NET_BIND_SERVICE` (Phase E). The binary has no file capability to find; the script asserts the unit property and then proves the bind actually happened.
- **No `application/dns-json` check.** AdGuardHome has no JSON API (see H2).
- **No warmer freshness check.** Phase F is retired.

Set `UNITS` to match what your host actually runs — Phase N adds units on an HA pair. The ban and flood-meter object names are Phase B's (`banned_ips`, `banned_long`, `floodmeter4`, chain `dns_guard`, all in `table inet filter`); Phase J manipulates those same objects and creates none of its own. `dns_guard` is a regular chain jumped from `chain input`, the single base chain on the input hook — it has no hook of its own, so `nft list chain inet filter dns_guard` is the only way to see it. The one other table is `table inet raw`, which exists solely because `notrack` is legal only at the raw hook. Confirm the object names once with `nft -j list sets | jq -r '.nftables[]?.set?.name'` before trusting the ruleset checks.

```bash
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
```

**Wire it in three places.** The upgrade wrappers call it and roll back on failure (Phase M); the runbook's restart sequence gates on it instead of ending with a bare `systemctl restart`; and cron surfaces breakage nobody triggered. The cron line is **appended to `/etc/cron.d/dns-health`**, the file Phase I creates and owns — do not create a second cron file for it:

```
*/10 * * * * root /usr/local/sbin/dns-smoke.sh >/tmp/dns-smoke.out 2>&1 || logger -t dns-alert -p daemon.crit "SMOKE FAILED"
```

Routing that to a human is Phase I's, through the single notification entry point `/usr/local/sbin/notify.sh` that Phase I defines — as is the off-box probe that catches a node which has lost its default route but looks perfectly healthy to itself.

**Pre-change gates** belong next to it — validate before you break things, not after:

```bash
nft -c -f /etc/nftables.conf                                              # ruleset parses
unbound-checkconf                                                         # resolver config parses
nginx -t                                                                  # nginx config parses
runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
  -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate  # AGH config parses
```

Three details in that last command are load-bearing. The binary is reached through the **`current/` version symlink** — the same path the unit's `ExecStart` uses, so the gate validates the build that will actually run. The work directory is the **scratch validate directory `/opt/adguardhome/validate`**, never the live `work/`: `--check-config` leaves artifacts behind, and pointing it at the live tree contaminates the directory the running service owns. And it runs **as the `adguardhome` user via `runuser`**, never as root, so nothing it writes is root-owned — root-owned artifacts are exactly what AdGuardHome then cannot rewrite on the next real start. `/opt/adguardhome/validate` is created by **Phase E at install time** (owned by `adguardhome`), so this gate is runnable on a freshly built node, before any Ansible has touched it. Phase M uses the same three-part invocation in its upgrade wrappers.

**Verify the gate itself.** A gate nobody has seen fail is a gate nobody knows works. Run these once, one at a time, and restore after each:

```bash
/usr/local/sbin/dns-smoke.sh; echo "exit=$?"
#   -> every line OK, trailer 'SMOKE: PASS', exit=0

systemctl stop unbound && /usr/local/sbin/dns-smoke.sh; echo "exit=$? (expect 1)"
systemctl start unbound

systemctl stop nginx && /usr/local/sbin/dns-smoke.sh | grep DoH; echo "exit=$? (expect a FAIL line)"
systemctl start nginx

# The cert-mismatch detector, which has no other symptom:
openssl x509 -in /opt/adguardhome/conf/ssl/fullchain.pem -noout -fingerprint -sha256
openssl s_client -connect dns.example.com:853 -servername dns.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
#   -> the two fingerprints must match

# Pre-change gates all exit 0 on a healthy node:
nft -c -f /etc/nftables.conf; echo "nft=$?"
unbound-checkconf;            echo "unbound=$?"
nginx -t;                     echo "nginx=$?"
runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
  -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate; echo "agh=$?"

# And the validate workdir stays adguardhome-owned - a root-owned artifact here means
# someone ran the gate without runuser, and the next real start is the one that breaks:
find /opt/adguardhome/validate ! -user adguardhome -print   # expect: no output
```

### H13. Upstream and root-server outage injection

Phase C configures RFC 8767 serve-stale with four keys, argues the design at length, and names its price: during an upstream or authoritative incident a client waits **up to 1.8 seconds per query** before the stale answer is released. Nothing in this plan has ever produced that state. Phase C's own C5.6 gets one step away and stops — it says "warm the name, then break egress, then query" and then supplies a `dig` line that runs against a perfectly healthy resolver, so the documented `; EDE: 3 (Stale Answer)` cannot appear and an operator following it scores a pass on a check that never executed.

This test supplies the injection, the assertions, and the restore. It proves four things that are otherwise only asserted in prose: that the resolver degrades to stale rather than SERVFAIL, that the stale answer survives the timeouts between Unbound and the client, that the monitoring can tell "the internet is broken" from "this node is broken", and that recovery is actually immediate rather than gated on a cache nobody knows about.

**Injection.** Run on the DNS host, in a maintenance window, with a failsafe armed *before* the block goes in.

```bash
D=whoami.akamai.net
dig @127.0.0.1 -p 5335 $D A +noall +answer            # warm it - stale can only serve what is cached
TTL=$(dig @127.0.0.1 -p 5335 $D A +noall +answer | awk '{print $2; exit}')
echo "cached TTL=$TTL"

# Failsafe first. If this shell dies mid-test the box restores itself in 15 minutes.
# `nft -f` reloads the canonical ruleset from disk, which also clears the live
# banned_ips / floodmeter state (Phase J) - acceptable in a pre-go-live drill,
# not something to trigger casually on a running service.
systemd-run --on-active=15min --unit=dns-egress-restore /usr/sbin/nft -f /etc/nftables.conf

# The block. Three details are load-bearing:
#   dport 53 only - replies to clients carry SPORT 53, so this cuts the recursion
#     leg and leaves the service leg answering. Phase B's own egress RRL rules in
#     this chain match sport 53, so the two are disjoint.
#   oifname != lo - keeps AdGuardHome -> Unbound (127.0.0.1:5335) and the host's
#     own resolver path intact; only off-box recursion is cut.
#   drop, not reject - an ICMP error lets unbound fail fast, and the 1800 ms
#     client-response timer would never be exercised. The hang is the point.
nft insert rule inet filter output oifname != "lo" udp dport 53 counter drop
nft insert rule inet filter output oifname != "lo" tcp dport 53 counter drop
nft -a list chain inet filter output | grep 'dport 53 counter drop'   # RECORD the two handles

# Prove the cut is real before scoring anything downstream:
dig @198.41.0.4 . NS +time=2 +tries=1 +noall +comments   # expect: no servers could be reached

sleep $((TTL + 5))          # the cached entry must actually expire
```

**At the resolver.**

```bash
dig @127.0.0.1 -p 5335 $D A +dnssec +time=5 +tries=1 +noall +comments +answer +stats
unbound-control stats_noreset | grep -E 'num.expired'
```

PASS, all four together: `status: NOERROR` with an answer rather than SERVFAIL; the comments carry `; EDE: 3 (Stale Answer)`; the answer TTL is **30** (`serve-expired-reply-ttl`, Phase C); `Query time` is roughly **1800 ms**; and `num.expired` is above zero and rising. Write the measured latency down — that is Phase C's stated cost as it lands on *this* host, and it is the number to quote in the runbook when someone reports "the resolver got slow".

Two failures with distinct causes. SERVFAIL instead of an answer means serve-expired never engaged: check the name really was in cache and still inside `serve-expired-ttl: 86400`. A query time near 0 ms *with* EDE 3 means `serve-expired-client-timeout` is 0 rather than 1800 — stale-first, not RFC 8767 — which is precisely the line Phase C calls load-bearing, not in effect.

**At the public edge.** The 1.8-second wait has to survive two timeouts between Unbound and the client, and neither of them is in Phase C. From the H0 test host:

```bash
dig  @<PUBLIC_IP>            $D A +time=5 +tries=1 +noall +comments +stats
kdig @dns.example.com +tls   $D A
kdig @dns.example.com +https $D A
```

PASS: the same stale answer arrives on every transport, slowly. If any of them SERVFAILs while the resolver itself answered correctly, something between them clipped the wait — there are exactly two candidates:

```bash
grep -n 'upstream_timeout' /opt/adguardhome/conf/AdGuardHome.yaml   # must exceed 1800ms
grep -rn 'proxy_read_timeout' /etc/nginx/sites-enabled/              # 10s (Phase E)
```

Phase E sets no `upstream_timeout`, so AdGuardHome's built-in default applies — read the effective value out of the running config rather than assuming it. Tune that key below ~2 s at any point in the future and every client gets SERVFAIL during an upstream incident even though Unbound answered correctly; the entire serve-stale design is void at the edge and no other test in this suite would notice.

**A name that was never cached.** This is the half users actually report.

```bash
dig @<PUBLIC_IP> $(openssl rand -hex 4).example.org A +time=8 +tries=1 +noall +comments
# expect: SERVFAIL. Stale serves only what it already has, so during an upstream
# outage the shape of the complaint is "sites I visit work, new ones do not".
```

**What the monitoring said — record it, do not assume it.**

```bash
/usr/local/sbin/dns-smoke.sh; echo "exit=$?"
```

Expect this to be counterintuitive: for the first hours of an upstream outage the smoke gate largely **passes**, because serve-stale is doing exactly its job and every name H12 probes is already warm. Two of its lines are worth reading rather than scoring. `bogus zone SERVFAILs` passes during a total outage for the wrong reason — the same fail-open shape H5 warns about. The DoT/DoH/DoQ checks use `+timeout=5`, comfortably above 1.8 s, so they pass slowly instead of failing.

The conclusion to record is that **H12 is not an upstream-outage detector**. Detection belongs to Phase I: note which of `RecursionStalled`, `ServfailRateHigh` and `RecursionLatencyP99High` fired, and how long each took to fire. An outage that fires none of them is a Phase I gap to fix there, not an H13 failure.

On a Tier 3 pair (Phase N), record whether the keepalived health script entered FAULT. A global root or TLD failure is indistinguishable from a node fault when viewed from inside one node, and failing the VIP over hands it to a standby that is equally unable to resolve — an extra failover stacked on an outage it cannot fix. Confirm from a second network before failing anything over.

**Restore — part of the test, not an afterthought.**

```bash
nft -a list chain inet filter output | grep 'dport 53 counter drop'
nft delete rule inet filter output handle <handle>      # once per rule, using the handles above
# If the handles are gone: nft -f /etc/nftables.conf - correct, but it clears the
# live ban and flood-meter state with it (Phase J).
systemctl stop dns-egress-restore.timer 2>/dev/null || true

dig @198.41.0.4 . NS +time=2 +tries=1 +noall +comments   # answers again

# Recovery is NOT immediate on its own, and this is the step that makes an operator
# think the restore failed. Unbound caches per-server unreachability in its
# infrastructure cache for `infra-host-ttl` (900 s default; Phase C does not override
# it), so for up to 15 minutes after the block is lifted it keeps behaving as though
# the authoritatives were still down. Clear it explicitly:
unbound-control flush_infra all

dig @127.0.0.1 -p 5335 $D A +noall +stats | grep 'Query time'   # back to normal, no EDE 3
unbound-control stats_noreset | grep num.expired               # stops rising
nft list tables                                                # EXACTLY: inet raw, inet filter
/usr/local/sbin/dns-smoke.sh; echo "exit=$?"                   # SMOKE: PASS, exit=0
```

PASS overall: stale answers were released with EDE 3 at the measured 1.8 s, they reached clients on every transport, an uncached name SERVFAILed, the monitoring signal that fired is written down, and the ruleset plus the resolver are byte-for-byte back where they started.

### H14. Rollback rehearsal — the recovery path nothing else runs

Phase K's doctrine is that an untested backup is not a backup, it is a hope, and this plan holds itself to that nearly everywhere: restore is drilled twice, restart self-heal is drilled with kill tests in Phase N, the trust anchor is fault-injected in Phase C, the ban pipeline is drilled in Phase J, the dead man's switch is drilled in Phase I. Rollback is the exception. Phase M's `upgrade-adguardhome.sh` carries a rollback branch that executes **only** when `dns-smoke.sh` fails, and Phase M's verification runs the forward upgrade — so the first execution of that branch happens at 03:00, with the service already down, inside the script that is supposed to be the recovery.

Rehearse it here on a healthy host and record the wall clock. That number is your rollback RTO and it belongs in the runbook next to the Phase K7 rebuild time.

**AdGuardHome.** No script edit is needed. The branch is gated on the smoke gate's exit status, and `dns-smoke.sh` takes `CERT` from the environment, so pointing it at a path that does not exist fails the gate on the certificate block alone while every other check still runs and passes.

```bash
# 1. Starting state.
A=$(readlink -f /opt/adguardhome/current); echo "running: $A"

# 2. Force the branch. <vB> MUST be a different release from A - re-running the
#    script with the version already installed makes PREV and STAGE the same
#    directory, and the rollback degenerates into a no-op symlink move that
#    proves nothing.
time CERT=/nonexistent/fullchain.pem /usr/local/sbin/upgrade-adguardhome.sh <vB>
```

Expected: the upgrade itself succeeds, the smoke gate prints `FAIL` on the certificate lines, the script prints `SMOKE FAILED — rolling back to ...`, runs the branch, and exits 1. The second smoke run *inside* the rollback branch also fails, for the same injected reason — that is not a rollback failure, and an operator reading the transcript later needs to know it.

```bash
readlink -f /opt/adguardhome/current                    # == $A
cmp -s /opt/adguardhome/conf/AdGuardHome.yaml \
       /opt/adguardhome/conf/AdGuardHome.yaml.pre-<vB> && echo 'CONFIG RESTORED'
stat -c '%U:%G %a' /opt/adguardhome/conf/AdGuardHome.yaml   # adguardhome:adguardhome 600
ss -ulnp | grep ':53 '                                      # the OLD binary is bound again
/usr/local/sbin/dns-smoke.sh; echo "exit=$?"                # SMOKE: PASS, exit=0 (clean env)
```

`cmp` is the assertion that carries the proof, not `schema_version`. The schema number only changes when the new release actually migrates, which adjacent patch releases usually do not — so a matching `schema_version` proves nothing in either direction. A byte-identical match against the `.pre-<vB>` copy proves the pre-migration file was restored rather than the migrated one, in every case.

**What the rollback does not restore.** The branch moves the `current` symlink and the config. It does not touch AdGuardHome's runtime state — `stats.db` under `/var/lib/adguardhome/stats`, and anything else the newer binary opened and may have written in its own format. Running an older binary against forward state is an untested combination in AdGuardHome itself, not something this plan can fix; what it can do is tell you where to look when a rolled-back node starts cleanly but its statistics are wrong.

```bash
journalctl -u adguardhome --since -5m --no-pager | grep -iE 'stats|schema|migrat|error'
```

**Unbound.** Phase M's apt rollback has a precondition nothing in the plan checks: the previous version must still be *installable*. `apt-get install --allow-downgrades unbound=$PREV` succeeds while `$PREV` sits in a configured pocket or the local cache — true when the previous version is the noble base-pocket one, false when it was itself an `-updates` version that has since been superseded and evicted.

```bash
apt-cache madison unbound                              # every installable version and its source
dpkg-query -W -f='${Version}\n' unbound                # what is running now
ls /var/cache/apt/archives/unbound_*.deb 2>/dev/null   # the local fallback
```

If `madison` lists exactly one version, **the Phase M Unbound rollback cannot run on this host today** — record that rather than discovering it during an incident. The mitigation is to keep the running `.deb` (`apt-get download unbound`) somewhere the Phase K backup set covers, so a downgrade is possible offline.

When a second version is available, rehearse it:

```bash
PREV=<the older version from madison>
time DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "unbound=$PREV"
apt-mark hold unbound
unbound-checkconf                          # OLD binary, CURRENT drop-in - see below
systemctl restart unbound; sleep 3
dig +dnssec @127.0.0.1 -p 5335 internetsociety.org A | grep -c ' ad'      # -> 1
dig +dnssec @127.0.0.1 -p 5335 dnssec-failed.org  A | grep -c 'SERVFAIL'  # -> 1
/usr/local/sbin/dns-smoke.sh; echo "exit=$?"
apt-mark showhold                          # -> unbound
```

`unbound-checkconf` before the restart is the line that earns its place. A rollback runs an older binary against a drop-in written for the newer one; a directive that exists only in the newer build is accepted by dpkg and rejected at startup, which leaves you with no resolver at all — during a rollback, which is where you already were. The two `dig` lines are the same gate Phase M uses for the forward path, for the same reason: a resolver that starts but no longer validates is the worst outcome of either direction.

Then fix forward and release the hold:

```bash
DEBIAN_FRONTEND=noninteractive apt-get install -y unbound
apt-mark unhold unbound
apt-mark showhold                          # -> empty
/usr/local/sbin/dns-smoke.sh; echo "exit=$?"
```

The hold is deliberate and Phase M's standing guard flags it. During a real rollback that flag is **expected**, not an alert to clear — clearing it lets unattended-upgrades reinstall the version you just rolled away from, unattended, at 03:00. Say so in the incident notes at the time.

PASS overall: both rollback branches executed end to end on a healthy host, the config was provably restored from the pre-migration copy, the rolled-back node passes a clean smoke run, and two wall-clock numbers are recorded. Phase M's verification covers the forward path only; this test covers the branch it never runs, and Phase L should not pass without the two measured RTOs written down.

### H15. Expired certificate — the failure a renewal dry run cannot find

Phase D proves renewal *works*: `certbot renew --dry-run` exercises the authenticator, and D5 already records that a dry run skips deploy hooks entirely. What no test in this plan produces is the state all of that machinery exists to prevent — a certificate that is genuinely past its `notAfter` while the service keeps running. It fails differently from a renewal failure, it fails differently per transport, and three checks this document already ships keep returning green while it is happening. That combination is why an operator who has only ever seen a passing dry run misdiagnoses it.

Run it once, before go-live, against **AdGuardHome's copy** of the certificate. Do not stage it in `/etc/letsencrypt/live/` — that tree is the certbot lineage's state machine, and mutating it to manufacture a fake fault is a real risk taken for a pretend one. DoH through nginx fails in the same way for the same reason (the failure is in the client's clock check, not the server's), and nginx reads the lineage directly.

**Build an expired certificate.**

```bash
# `openssl req -days` accepts a POSITIVE integer only, and -not_after arrived in
# `openssl req` after the 3.0.x that noble ships. Check before reaching for it:
openssl req -help 2>&1 | grep -q not_after && echo 'has -not_after' || echo 'use faketime'

apt-get install -y faketime
install -d -m 0700 /root/expired-cert-drill
faketime '2024-01-01 00:00:00' openssl req -x509 -nodes \
  -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -days 30 -subj '/CN=dns.example.com' \
  -addext 'subjectAltName=DNS:dns.example.com' \
  -keyout /root/expired-cert-drill/privkey.pem \
  -out    /root/expired-cert-drill/fullchain.pem

openssl x509 -enddate -noout -in /root/expired-cert-drill/fullchain.pem
# expect a notAfter in early 2024. ECDSA P-256 deliberately, to match Phase D -
# an RSA test cert changes handshake cost as well as validity, and you would be
# reading two variables at once.
```

**Install it, and record which of two things your build does.**

```bash
cp -a /opt/adguardhome/conf/ssl/fullchain.pem /root/expired-cert-drill/fullchain.real
cp -a /opt/adguardhome/conf/ssl/privkey.pem   /root/expired-cert-drill/privkey.real

install -o adguardhome -g adguardhome -m 0640 \
  /root/expired-cert-drill/fullchain.pem /opt/adguardhome/conf/ssl/fullchain.pem
install -o adguardhome -g adguardhome -m 0640 \
  /root/expired-cert-drill/privkey.pem   /opt/adguardhome/conf/ssl/privkey.pem
systemctl restart adguardhome; sleep 5

systemctl is-active adguardhome
journalctl -u adguardhome --since -2m --no-pager | grep -iE 'certificat|expir|tls'
```

AdGuardHome v0.107.72 and newer watch these two files and hot-reload TLS (Phase D4), so the swap may take effect without the restart — the explicit restart is here so the *startup* path is exercised too. Which of two branches you land in is the single most valuable output of this test and it is not safe to guess:

- **AdGuardHome starts and serves the expired certificate.** The outage is DoT and DoQ only. Do53 is untouched and the box looks healthy from outside.
- **AdGuardHome refuses the certificate and does not start.** The outage is total — `:53` goes with it — and the incident is an order of magnitude larger than "TLS expired".

Record which one, with the version that produced it. It sets the severity of every certificate alert Phase I raises, and it is the difference between a partial and a total outage.

**What clients see.** From the H0 test host:

```bash
dig @<PUBLIC_IP> google.com A +short                # unaffected - Do53 has no certificate

kdig @dns.example.com +tls google.com A             # RECORD: this SUCCEEDS
kdig @dns.example.com +tls +tls-ca +tls-hostname=dns.example.com google.com A   # FAILS
kdig @dns.example.com +quic +tls-ca +tls-hostname=dns.example.com google.com A  # FAILS

openssl s_client -connect dns.example.com:853 -servername dns.example.com </dev/null 2>&1 \
  | grep -E 'Verify return code|notAfter'
# expect: 'Verify return code: 10 (certificate has expired)'
```

The finding to write down: **`kdig @host +tls name A` succeeds against an expired certificate**, because kdig performs no verification at all unless `+tls-ca` or a pin is given. Every real client validates and fails closed — Android Private DNS, the Apple encrypted-DNS profiles, `systemd-resolved` with `DNSOverTLS=yes` and a hostname, and browser DoH. A suite that runs only the bare `+tls` form certifies a certificate state that takes the entire encrypted client base offline. H3's second line exists for exactly this and must never be dropped as redundant.

**What the gates see.**

```bash
/usr/local/sbin/dns-smoke.sh; echo "exit=$?"
```

Read the signature rather than just scoring it:

- `cert only -N days left` — **FAIL**. This is the check that catches it, and it catches it from the on-disk file, never from the wire.
- `served cert == on-disk (dns.example.com:853)` — **OK**. Both are the same expired certificate, so the fingerprint comparison passes. That check detects a *stale reload* — renewed on disk, old in memory — and it is structurally incapable of detecting expiry. Do not let a green fingerprint line read as "the certificate is fine".
- `served cert differs from on-disk (dns.example.com:443)` — FAIL, because nginx is still serving the real lineage. That mismatch is an artifact of this drill's scoping and disappears at restore.
- `DoT tcp/853` — **OK**, for the same reason the bare `kdig +tls` above passes: the gate's transport checks do not validate the chain.

The rule that follows: in `dns-smoke.sh` the `openssl x509 -enddate` check is the **only** expiry detector, and it reads the file rather than the connection. If anyone ever removes it on the grounds that "the transport checks pass anyway", the gate goes blind to this failure entirely.

Phase I's `CertExpiringSoon` / `CertExpiringCritical` should have fired weeks before any host reaches this state. Use the drill to confirm the exporter reads the path the deploy hook *writes* — `/opt/adguardhome/conf/ssl/fullchain.pem` — and not only the lineage. The two diverge in exactly one scenario, a broken deploy hook, and that is the scenario D5 names: the lineage renews, the alert clears, and the served copy rots until it expires.

**Restore.**

```bash
install -o adguardhome -g adguardhome -m 0640 \
  /root/expired-cert-drill/fullchain.real /opt/adguardhome/conf/ssl/fullchain.pem
install -o adguardhome -g adguardhome -m 0640 \
  /root/expired-cert-drill/privkey.real   /opt/adguardhome/conf/ssl/privkey.pem
systemctl restart adguardhome; sleep 5

kdig @dns.example.com +tls +tls-ca +tls-hostname=dns.example.com google.com A +short
diff <(openssl x509 -noout -fingerprint -sha256 -in /opt/adguardhome/conf/ssl/fullchain.pem) \
     <(openssl x509 -noout -fingerprint -sha256 -in /etc/letsencrypt/live/dns.example.com/fullchain.pem) \
  && echo 'OK: the AGH copy matches the lineage again'
/usr/local/sbin/dns-smoke.sh; echo "exit=$?"      # SMOKE: PASS, exit=0

# The drill directory holds a SECOND COPY OF THE PRODUCTION PRIVATE KEY. Remove it,
# and make sure it never reaches a provider snapshot or the Phase K backup set:
shred -u /root/expired-cert-drill/*.pem /root/expired-cert-drill/*.real 2>/dev/null
rm -rf /root/expired-cert-drill
```

PASS overall: the expired certificate was installed, the start-or-refuse branch was recorded, validating clients failed and non-validating ones did not, the smoke gate flagged it on the enddate check and only on the enddate check, and the real certificate is back in place with a clean smoke run and no leftover copy of the key.

---

[Plan index](../dns-server-plan.md) · [Previous: AdGuardHome and the Public Edge](./05-adguardhome-edge.md) · [Next: Observability and Abuse Response](./07-observability-and-abuse.md)
