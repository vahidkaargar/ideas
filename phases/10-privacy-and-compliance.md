[Plan index](../dns-server-plan.md) · [Previous: Private Access Layer (optional)](./09-private-access.md) · [Next: Go-Live Checklist and Risk Register](./11-go-live-checklist.md)

---

**On this page**

- [PHASE Q: Privacy Posture, Retention and Compliance](#phase-q-privacy-posture-retention-and-compliance)
  - [Q1. Choose a logging posture](#q1-choose-a-logging-posture)
  - [Q2. Upstream exposure: what recursion fixed, and what it did not](#q2-upstream-exposure-what-recursion-fixed-and-what-it-did-not)
  - [Q3. Data at rest on hardware you do not control](#q3-data-at-rest-on-hardware-you-do-not-control)
  - [Q4. Metadata that survives a perfect no-log configuration](#q4-metadata-that-survives-a-perfect-no-log-configuration)
  - [Q5. The written artifacts](#q5-the-written-artifacts)
  - [Q6. Legal decisions to make and record](#q6-legal-decisions-to-make-and-record)
  - [Q7. What Phase P changes](#q7-what-phase-p-changes)

---

## PHASE Q: Privacy Posture, Retention and Compliance

Two different things get called "a private DNS server". The first is access control: who is permitted to send this resolver a query at all. That is Phase P — allowlists, WireGuard, ClientIDs, mTLS — and it is a network question. The second is what this phase covers: given that queries do arrive, does the machine accumulate a searchable record of who asked for what, and does the operator have the written artifacts to survive an abuse complaint, a legal request, or a curious regulator. A resolver can be perfectly locked down and still be a surveillance database; it can be wide open to the public and hold nothing. The two decisions are independent and must be made separately.

Phase Q owns the second. It is the second headline deliverable of this plan, and unlike most of the plan it produces documents as well as configuration — the configuration is worthless the moment a future operator changes it without knowing why it was set.

---

### Q1. Choose a logging posture

This is the single highest-leverage privacy decision on the host. Decide it before writing `AdGuardHome.yaml`, not after, because the config layout differs and getting it wrong is a boot failure rather than a warning.

**Phase E ships a working default, and it is not the zero-log posture.** The configuration that leaves this plan has `querylog.enabled: true` with `querylog.interval: 6h`, `dns.anonymize_client_ip: true`, and `statistics.enabled: true`. That is deliberate: a resolver you cannot observe is a resolver you cannot operate, and both Phase I's collector and Phase J's operator procedures assume those values on day one. Everything in Q1 is therefore a menu of **opt-in deviations** from a default that is already in place. Nothing here is applied unless the operator applies it, records the choice in `RETENTION.md` (Q5a), and accepts the monitoring consequences stated with each posture. If you read this section and do nothing, you are running Posture C at a 6 h ring — that is a choice too, and it must be reflected in the published privacy notice (Q5b).

#### The shipped default and the two opt-in deviations

| | Posture A: zero logging (opt-in) | Posture B: aggregate statistics only (opt-in) | Posture C: shipped default (Phase E) |
|---|---|---|---|
| `querylog.enabled` / `statistics.enabled` | false / false | false / true | true / true |
| Per-query records on disk | none | none | `querylog.json`, 6 h ring |
| Per-domain counters on disk | none | `stats.db` domain table | `stats.db` domain table |
| Per-client counters on disk | none | `stats.db`, masked to /16 | `stats.db`, masked to /16 |
| Admin UI dashboard | empty | populated | populated |
| Can you answer "why did this client get NXDOMAIN at 14:02" | no | no | yes, within the last 6 h |
| Can you answer "is query volume abnormal" | via kernel counters only (Phase I/J) | yes, in-product | yes |
| AdGuardHome metrics in Phase I | none — collector emits "metrics unavailable by policy" | full | full |
| Breach of the host exposes user history | structurally impossible | domain popularity only | 6 h of queries |
| Suited to | a public resolver you advertise, once you have accepted operating blind on the AGH side | a resolver for a known small group | general operation; the state the plan hands you |

**The case for opting in to Posture A**, stated honestly so that the operator is choosing rather than drifting: for a public recursive resolver the query log is a liability with limited operational upside. It cannot drive abuse response (see below — the client address is masked before the entry is built), it cannot be produced under legal process if it does not exist, and it is the only artifact on the box whose compromise harms your users rather than you. **The case against** is equally real: you give up per-query fault diagnosis entirely, and if you also disable statistics you give up the AdGuardHome half of Phase I's observability. Posture B splits the difference and is defensible when you operate for a group who know and accept it. Posture C is where the plan leaves you, and it is a legitimate resting place — it is not, as the v1 draft implied, a temporary debugging state.

Whatever you choose, choose it explicitly and write it down. An operator who inherits this host must be able to read `RETENTION.md` and know that the current logging state was decided, not defaulted into by nobody.

#### Monitoring consequences — read these before choosing

Each posture changes what Phase I can see. Phase I owns the degradation logic; this is a cross-reference, not a restatement.

- **Posture A** (`statistics.enabled: false`). AdGuardHome exposes no usable metrics. Phase I's collector detects this and emits its distinct **"metrics unavailable by policy"** signal — it does **not** emit `agh_up=0` and it does **not** fire `AdGuardHomeDown`, because a policy choice is not an outage and must not page anyone at 03:00. Liveness continues to be established by Phase I's DNS probe against the service itself, not by the metrics endpoint. Query-volume and abuse signals come from the kernel counters and nftables sets (Phase I/J), which are unaffected. Before opting in, confirm Phase I's collector on this host is the version that implements that degradation path; on an older collector, disabling statistics produces a permanent false alarm.
- **Posture B** (`statistics.enabled: true`, `querylog.enabled: false`). Phase I is fully functional: request rates, block rates, upstream timing and the `agh_up` liveness signal all continue to work, because they are derived from the statistics path and not from the query log. What you lose is per-query forensics only. This is the cheapest privacy gain in this phase and the one that costs monitoring nothing.
- **Posture C**, the shipped default. Phase I is fully functional and, in addition, a fault reported by a user in the last six hours can be reconstructed from the query log. This is the assumption every other phase was written against.

#### Posture A — the opt-in configuration

Applying this section **overwrites values Phase E deliberately shipped**. Do it as a considered change with a `RETENTION.md` entry and a commit, not as part of initial deployment.

`querylog:` and `statistics:` are **top-level** keys in `AdGuardHome.yaml` (`internal/home/config.go:140-141`), siblings of `dns:` and `tls:`. Only `anonymize_client_ip` genuinely lives under `dns:` (`config.go:230-232`). The v1 plan put four `querylog_*` keys under `dns:`, which is the pre-schema-15 layout, and wrote no `schema_version` at all.

Replace Phase E's shipped blocks at the top level of `/opt/adguardhome/conf/AdGuardHome.yaml`:

```yaml
schema_version: 34

querylog:
  enabled: false
  file_enabled: false
  interval: 24h
  size_memory: 1000
  ignored: []
  ignored_enabled: false

statistics:
  enabled: false
  interval: 24h
  ignored: []
  ignored_enabled: false
```

and ensure no `querylog_enabled`, `querylog_file_enabled`, `querylog_interval` or `querylog_size_memory` key remains under `dns:`. Keep `anonymize_client_ip: true` under `dns:` — Phase E already sets it, that key's location is correct, and its effect is real. `querylog.interval` stays at an accepted value even though it is inert while the log is disabled: the validator runs regardless (see below), and leaving a valid value in place is what lets you flip `enabled` back to `true` for a debugging window without editing two keys.

With `querylog.enabled: false`, `Add()` returns before it ever constructs a log entry (`qlog.go:230-232`); a flush is only scheduled when `fileIsEnabled` (`qlog.go:255`). Verified empirically on v0.107.78: Posture A produces no `querylog.json` in the configured query-log directory at all, not an empty one.

#### The schema trap — this is a boot failure, not a warning

The v1 layout does not silently drift to a 90-day retention. AdGuardHome v0.107.78 given the v1 Phase E2 config **refuses to start**:

```
[error] failed to parse configuration file err="migrating schema 11 to 12: unexpected type of \"querylog_interval\": string"
```

`internal/configmigrate/v12.go:29-41` reads `querylog_interval` as an integer number of days; v1 writes the string `24h`. With no `schema_version` key the migrator starts at 0 (`migrator.go:56-62`) and runs the whole 0→34 chain, dying at step 11→12. `parseConfig` returns the error and the service exits.

The 90-day clobber is a separate, real hazard with a narrow trigger: hand-editing the file to a top-level `querylog:` block **without** adding `schema_version`. `v15.go:43-58` then unconditionally executes `diskConf["querylog"] = qlog` with `"interval": "2160h"` and only afterwards moves any legacy keys in — so modernising the layout without pinning the schema silently resets retention to 90 days and re-enables the log. Pinning `schema_version` is what makes this block a control rather than a suggestion.

Pin it to whatever `LastSchemaVersion` is for the binary you actually installed, not blindly to 34. Do not run a throwaway second instance to find out — it fights the live one for :53 and :3000. AdGuardHome rewrites the config **at startup** (`internal/home/home.go:996` → `config.write`), so read it back from the running deployment, or read it from source for your tag:

```bash
systemctl restart adguardhome && sleep 10
grep '^schema_version:' /opt/adguardhome/conf/AdGuardHome.yaml

# or, before deploying:
AGH_VER=$(/opt/adguardhome/current/AdGuardHome --version | grep -oE 'v[0-9.]+')
curl -s "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/${AGH_VER}/internal/configmigrate/configmigrate.go" | grep LastSchemaVersion
```

If AdGuardHome writes back a higher number, accept it — it has already migrated the file forward from a pinned, known starting point, which is the whole objective.

#### Accepted interval values

`querylog.interval` is validated against a fixed set — `6h`, `24h`, `168h`, `720h`, `2160h` (`qlog.go:115-126`). Anything else is rejected. Phase E's shipped `6h` is the shortest value the validator accepts, which is why the default ring is six hours and not something tighter: there is no supported way to retain query records for less time while retaining them at all. If six hours is too long for your policy, the answer is Posture A or B, not a smaller number. `statistics.interval` goes through `validateIvl`, which accepts 1 h to 365 d, and it **must be present and ≥ 1h even when `statistics.enabled: false`**: `stats.New` calls `validateIvl(conf.Limit)` before it looks at `Enabled` and returns `unsupported interval: less than an hour` on 0, which is fatal.

#### What `anonymize_client_ip: true` actually does

It masks the client address **at rest**, not only in the UI. `internal/dnsforward/stats.go:32-34` is:

```go
ip := pctx.Addr.Addr().AsSlice()
s.anonymizer.Load()(ip)
ipStr := net.IP(ip).String()
```

The anonymiser mutates the slice **in place at ingestion**, before that same slice is handed to `logQuery` → `querylog.AddParams.ClientIP` → `newLogEntry` → the ring buffer → `flushLogBuffer` → `querylog.json`, and before `updateStats` writes `stats.Entry.Client`. `internal/home/dns.go:56,81,118` hands the same `*aghnet.IPMut` instance to the query log, the statistics path and `dnsforward`. Verified empirically on v0.107.78 with clients at 127.0.0.1: on-disk `querylog.json` contained `"IP":"127.0.0.0"`, and `stats.db` contained `127.0.0.0`. Never the real address.

**Granularity is /16 for IPv4 and /48 for IPv6**, not the widely repeated /24 and /112. `http.go:152-164` copies zero bytes over `ip4[2:4]` and `ip6[6:16]`.

Two consequences follow, and both matter:

1. The mask is a genuine control. Under Posture A you may state in the privacy notice that client addresses are not stored, full stop. Under the shipped default or Posture B you may not say that flatly — state it precisely: the first two octets are stored, which identifies an ISP and often a region. Since the shipped default is what most deployments will actually be running, the precise wording is the one to write first.
2. **Abuse response cannot come from the query log.** A script that reads `.IP` from `querylog.json` and bans it gets `203.0.0.0` and installs a /32 ban on an address that is not the abuser and probably does not exist. This is why abuse detection in this plan is kernel-side nftables counters and sets — see Phase J. Do not reintroduce a query-log-derived ban; it is a no-op at best and bans a bystander at worst.

#### `stats.db` behaves differently from the query log

`stats.New` calls `openDB()` unconditionally, before and regardless of `Enabled`, and `Close()` writes the current unit on shutdown. Measured with `statistics.enabled: false`: `stats.db` present at 16 KB while running, 32 KB after shutdown. **Do not write a check that asserts the file is absent — it will never pass under any posture.** Under Posture A assert instead that it contains no client addresses, which it will not, because `Update()` returns early when disabled. Under the shipped default and Posture B the file is genuinely populated, and the check that is meaningful there is that every address in it is /16-masked — see the Q1 verification block.

What `stats.db` holds that is easy to overlook: a **per-domain request-count table** (`internal/stats/unit.go`: `domains`, `blockedDomains`). That is domain history for the whole user population, and client anonymisation does nothing about it. If your privacy notice claims no domain data is retained, the shipped default and Posture B both contradict it — only Posture A supports that claim.

#### Temporary debugging without touching disk

This applies once you have opted in to Posture A or B and then need to see live queries to diagnose a fault. Set `querylog.enabled: true` with `querylog.file_enabled: false`. Entries go to the in-memory ring buffer, are visible in the admin UI (reachable only over the SSH tunnel, see Phase P), and are lost on restart. Set a calendar reminder to revert, and record the window in `RETENTION.md` (Q5) — an undeclared logging window is exactly the kind of thing a transparency report exists to prevent. Under Posture A this window also restores nothing on the monitoring side: `statistics.enabled` is a separate key, so Phase I keeps emitting "metrics unavailable by policy" throughout unless you flip that too.

#### Verification

```bash
# 1. AGH actually starts. The v1 config fails this check.
systemctl restart adguardhome && sleep 10
systemctl is-active adguardhome
journalctl -u adguardhome -n 40 --no-pager | grep -i 'failed to parse\|migrating schema' \
  && echo "FAIL: config rejected" || echo "OK: config accepted"

# 2. Schema and blocks are where they belong.
grep -E '^(schema_version|querylog|statistics):' -A6 /opt/adguardhome/conf/AdGuardHome.yaml
! grep -qE '^\s+querylog_' /opt/adguardhome/conf/AdGuardHome.yaml && echo "OK: no legacy querylog_ keys"
! grep -q '2160h' /opt/adguardhome/conf/AdGuardHome.yaml && echo "OK: retention not reset to 90d"

# 3. The running config matches the posture recorded in RETENTION.md. This is the
#    check that matters: any of the three states is correct, disagreeing with the
#    published policy is not.
QL=$(grep -A1 '^querylog:'   /opt/adguardhome/conf/AdGuardHome.yaml | awk '/enabled:/{print $2}')
ST=$(grep -A1 '^statistics:' /opt/adguardhome/conf/AdGuardHome.yaml | awk '/enabled:/{print $2}')
case "$QL/$ST" in
  true/true)   echo "INFO: Posture C - Phase E shipped default (6h query log + statistics)" ;;
  false/true)  echo "INFO: Posture B - statistics only, opted in" ;;
  false/false) echo "INFO: Posture A - zero logging, opted in. Phase I will report"
               echo "      'metrics unavailable by policy'; that is not an outage." ;;
  *)           echo "REVIEW: querylog=$QL statistics=$ST - unusual combination" ;;
esac
grep -i 'logging posture' /opt/dns-config-backup/RETENTION.md   # must agree with the above

# 4. Query log on disk. Present under the shipped default, absent under A and B.
sleep 60
ls -l /var/log/adguardhome/querylog/querylog.json 2>/dev/null \
  || echo "OK: no query log on disk (expected under Posture A or B)"

# 5. stats.db WILL exist under every posture. Assert the right thing for yours.
test -e /var/lib/adguardhome/stats/stats.db && echo "INFO: stats.db exists (expected)"
n=$(strings /var/lib/adguardhome/stats/stats.db | grep -cE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || true)
u=$(strings /var/lib/adguardhome/stats/stats.db | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
     | grep -vcE '\.0\.0$' || true)
# Posture A: n must be 0.  Shipped default / Posture B: u must be 0 (all /16-masked).
echo "addresses=$n unmasked=$u"
```

Expected: `active`, `OK: config accepted`, a `schema_version:` line at column 0, an `INFO:` line naming the posture you actually chose, a `RETENTION.md` line that agrees with it, and — for the shipped default — `unmasked=0`.

---

### Q2. Upstream exposure: what recursion fixed, and what it did not

The v1 design forwarded every query to four DoH operators concurrently. SmartDNS queries multiple upstreams simultaneously and returns the fastest answer, so each of the four saw **100 % of queries**, not 25 %. That is not reduced trust, it is four times the exposure of a single forwarder, and the operator got no privacy benefit from the plurality. On top of it, SmartDNS's default `speed-check-mode ping,tcp:80,tcp:443` made the resolver actively connect to every IP address it resolved on a user's behalf, leaking the user's intended destination to that destination from your server's IP.

Both problems are gone by construction. Unbound (Phase C) recurses from the root; there are no forwarders and no speed probes.

**What recursion hides.** No single commercial operator sees your users' aggregate query stream. Nobody outside your host can build a profile of "everything this resolver's population looks up". No third party can correlate your traffic across sessions and sell it. This is a real and substantial improvement, and it is the honest headline for the privacy notice.

**What recursion does not hide, and you must say so.**

- Authoritative servers still see queries. Every name still gets resolved by asking somebody. The root, the TLD operator and the zone's own authoritative servers each learn something.
- The transport is cleartext UDP/53 to those authorities. There is no DoT-to-authoritative deployment worth relying on. An on-path observer between your VPS and the authoritative servers sees the names in plaintext.
- Your hosting provider therefore sees more, not less, than before. Under v1 they saw four HTTPS destinations; now they see your full resolution pattern in cleartext. **For a threat model that includes the hosting provider, forwarding to an encrypted upstream was actually better.** State this trade explicitly rather than presenting recursion as strictly superior.
- Queries are attributed to *your server's* IP, never to an individual client — provided `edns_client_subnet.enabled: false` stays set under `dns:` in `AdGuardHome.yaml`. That single key is what keeps client subnets out of upstream visibility. Verify it, do not assume it.

**QNAME minimisation limits per-level learning.** Unbound sends the root only `com.`, the `.com` servers only `example.com.`, and the full `www.internal.example.com.` only to the zone that needs it. So the root and TLD operators learn which TLDs and which second-level domains your population uses, and the timing, but not the full names. The zone's own authoritative server learns the full name — it must, in order to answer. Phase C pins `qname-minimisation: yes` even though it is already the default, precisely so a package default change cannot silently weaken this.

**ODoH, honestly.** Oblivious DoH (RFC 9230) separates knowledge of the client from knowledge of the query by putting an untrusted relay between them: the relay sees your IP but only ciphertext, the target sees the query but only the relay's IP. It is the right shape for this problem and it does not help you here, for two verified reasons. First, this stack cannot speak it: AdGuardHome's `dnsproxy` upstream constructor switches on `sdns`, `udp`, `tcp`, `quic`, `tls`, `h3` and `https` only (`upstream/upstream.go:263-276`) — there is no oblivious transport, and no `odoh`/`oblivious` support in SmartDNS either. Second, the property only holds if the relay and target are operated by genuinely independent parties who do not collude, which means you would be adding two more third parties, not removing any. Public ODoH deployment remains limited to a small number of relay/target pairs, and it is a client-to-relay protocol — running your own resolver is an alternative to ODoH, not a complement to it. Do not promise it, and do not describe your resolver as "oblivious".

#### Verification

```bash
# No forwarders configured anywhere - recursion is genuinely in use.
grep -E '^\s*(forward-zone|forward-addr|forward-host)' -r /etc/unbound/ && echo "FAIL: forwarding configured" || echo "OK: recursive"
grep -A3 '^\s*upstream_dns:' /opt/adguardhome/conf/AdGuardHome.yaml   # expect only 127.0.0.1:5335
grep -A2 'fallback_dns' /opt/adguardhome/conf/AdGuardHome.yaml        # expect: []

# Client subnet is not forwarded upstream.
grep -A2 'edns_client_subnet' /opt/adguardhome/conf/AdGuardHome.yaml  # expect enabled: false

# QNAME minimisation is on in the running config.
unbound-checkconf -o qname-minimisation /etc/unbound/unbound.conf     # expect: yes
```

Expected: `OK: recursive`, a single `127.0.0.1:5335` upstream, `fallback_dns: []`, `enabled: false` under `edns_client_subnet`, and `yes`.

---

### Q3. Data at rest on hardware you do not control

A VPS is somebody else's computer. The provider can snapshot the disk, attach the volume elsewhere, open a console session on a running instance, and in principle dump guest memory. None of that leaves a trace you can see. The design goal is therefore not "protect the disk" — it is **do not write it in the first place**, and where you must, keep it in RAM.

#### The inventory: what on this host is sensitive

These are the paths Phase E actually configures. The query log and the statistics database do **not** live together under the AdGuardHome work directory — Phase E points them at `/var/log/adguardhome/querylog` and `/var/lib/adguardhome/stats` respectively, and any inventory, tmpfs mount or backup exclusion written against the old `/opt/adguardhome/work/data/` layout will silently miss both.

| Path | Contains | Shipped default (Phase E) | Under Posture A |
|---|---|---|---|
| `/var/log/adguardhome/querylog/querylog.json` | per-query records, /16-masked client IP | present, 6 h ring | absent |
| `/var/lib/adguardhome/stats/stats.db` | per-domain counts, /16-masked client counts | present and populated | exists, empty of clients (see Q1) |
| AGH work dir, `sessions.db` | admin UI session tokens | present | present |
| AGH work dir, `filters/` | downloaded filter lists | empty while `filtering_enabled: false` | same |
| `/var/log/nginx/access.log` | client IPs and, for DoH GET, the encoded query — see Q4 | must stay 0 bytes | must stay 0 bytes |
| journald | sshd/auth records; no DNS query content | operator decision, below | operator decision, below |
| `/etc/letsencrypt/` | private key | must persist; not user data | same |
| Unbound cache | resolved domains, no client identity | process RAM only | process RAM only |

**Unbound writes no cache to disk.** This is a structural improvement over v1's SmartDNS `cache-persist yes`, which serialised up to half a million domains to `/var/lib/smartdns/smartdns.cache` on clean exit and reloaded it at boot — an unmanaged, unrotated, indefinitely retained answer to "what do this server's users look up", captured by every provider snapshot. Unbound has no equivalent automatic behaviour: nothing in the running configuration ever writes the cache out.

**But the manual route is open on this host, and you must plan for it.** `unbound-control dump_cache` serialises the entire cache to stdout, and it requires `remote-control: enable: yes` — which **is** enabled here. Phase I needs the control channel to collect Unbound metrics, so it is on by design and is not something to switch off for privacy. The consequence is that any operator who can reach the control socket with the control key can produce a complete domain-history dump on demand. Two obligations follow, and neither is optional:

- `RETENTION.md` must carry a line stating that a manual cache dump is domain history for the whole user population, that the capability exists, and who holds the control key.
- Never redirect `dump_cache` output into a file that outlives the incident. Pipe it, read it, discard it. A dump left in `/root` or in `/opt/dns-config-backup` is precisely the durable artifact this whole phase exists to prevent, and it will be picked up by Phase K's off-host backup.

#### Put the AdGuardHome query-log and statistics directories in RAM

This is the highest-value change in Q3, and it is worth doing under **any** posture. Under Posture A it makes "we do not retain query data" structurally true rather than configuration-dependent — a future operator who flips `querylog.enabled` back to `true` without reading this file still writes nothing durable. Under the shipped default it converts a six-hour disk-backed ring into a six-hour RAM-backed one, so a provider snapshot or a recovered disk yields nothing, while Phase I keeps every metric it had.

Mount the two directories Phase E configures, not the work directory. `/etc/fstab`:

```
tmpfs /var/log/adguardhome/querylog tmpfs rw,nosuid,nodev,noexec,mode=0750,size=64M 0 0
tmpfs /var/lib/adguardhome/stats    tmpfs rw,nosuid,nodev,noexec,mode=0750,size=16M 0 0
```

A tmpfs is created empty and root-owned at every boot, so the service must fix ownership before it starts. In the AdGuardHome unit, under `[Service]` — the leading `+` runs these commands as root, bypassing the unit's own sandbox, which is required because `ProtectSystem=strict` is in effect:

```
ExecStartPre=+/usr/bin/install -d -o adguardhome -g adguardhome -m 0750 /var/log/adguardhome/querylog
ExecStartPre=+/usr/bin/install -d -o adguardhome -g adguardhome -m 0750 /var/lib/adguardhome/stats
```

and under `[Unit]`:

```
RequiresMountsFor=/var/log/adguardhome/querylog /var/lib/adguardhome/stats
```

Three consequences to record in the runbook so nobody is surprised.

- **Statistics reset at every reboot**, because `stats.db` is now in RAM. Phase I's dashboards show a discontinuity, not an outage: `statistics.enabled` is still `true`, so the collector keeps returning real metrics and the "metrics unavailable by policy" path is not involved. Do not let a counter reset be mistaken for a fault.
- **Size the query-log tmpfs for your peak six-hour volume, not for a nominal figure.** 64 M is generous for a small deployment and thin for a busy public resolver; a full tmpfs means AdGuardHome cannot write the ring, which is a service-affecting failure and not a graceful degradation. Check actual usage with `df -h` after a week at real traffic before you trust the number.
- Admin UI logins are unaffected, because `sessions.db` stays in the AdGuardHome work directory on persistent disk. If you want those in RAM too, that is a third mount and a separate decision — record it.

Filter lists also stay on persistent disk under the work directory, so the old warning about `filtering_enabled` exhausting a 64 M data-directory tmpfs no longer applies to these mounts.

#### journald: volatile or not

`/etc/systemd/journald.conf.d/10-volatile.conf`:

```
[Journal]
Storage=volatile
RuntimeMaxUse=64M
```

Be clear about what this is and is not. **DNS query content never reaches the journal** — Unbound runs at `verbosity: 1` and AdGuardHome does not log queries to stderr — so this is not a query-privacy control. It is about whether any durable record of connection activity exists at all.

Verbosity 1 is worth understanding rather than assuming, because the number looks alarming next to a no-log claim and it is the level Phase C actually sets. Level 1 emits operational events: startup, configuration, trust-anchor state, and errors. Per-query logging in Unbound requires `log-queries: yes` or verbosity 3 and above, neither of which is configured here. So the journal tells you that the resolver is healthy without telling you what anybody asked. Verbosity 0 would suppress the operational events too, which costs you fault diagnosis for no privacy gain, and it is not what Phase C ships. If you ever raise verbosity to 3 for debugging, you have created a temporary logging window in the sense of Q1 — declare it in `RETENTION.md` and revert it.

The cost is real and falls on you: you also lose persistent `sshd`/auth logs, which are your own break-in forensics, and the Phase I observability history. For most operators the better answer is **keep journald persistent** — you need to be able to investigate a compromise of your own server — and rely on tmpfs plus no-log for *user* data. Make it a documented decision in `RETENTION.md`, not a default that nobody chose.

#### Encryption, honestly

LUKS on the data volume, unlocked at boot over SSH via `dropbear-initramfs`, meaningfully raises the bar against offline disk imaging, a stolen or decommissioned drive, and casual snapshot exfiltration. It does **nothing** against a live hypervisor, a provider console session on a running instance, or a memory dump — the key is necessarily in RAM while the service runs. Write that limitation down, because a privacy notice that says "encrypted at rest" without it overclaims.

If your threat model does not actually include disk imaging, skip LUKS. A half-implemented encryption story that the operator half-believes is worse than an honest unencrypted one plus rigorous minimisation.

#### Secure deletion does not work here

`shred` is not an answer on SSD or on virtualised block storage. Copy-on-write, TRIM and wear levelling mean overwriting a file's logical blocks does not overwrite the physical cells, and on a network-backed volume you are not addressing physical cells at all. There are exactly two reliable strategies: **never write it** (tmpfs, no-log), or **encrypt it and destroy the key** (crypto-erase). Phrase the destruction column of your retention policy in those terms; do not promise a wipe you cannot perform.

#### Verification

```bash
for d in /var/log/adguardhome/querylog /var/lib/adguardhome/stats; do
  findmnt -no FSTYPE,OPTIONS "$d"   # expect: tmpfs  rw,nosuid,nodev,noexec,...
done
systemctl restart adguardhome && sleep 5
stat -c '%n %U:%G %a' /var/log/adguardhome/querylog /var/lib/adguardhome/stats
                                          # expect: adguardhome:adguardhome 750 on both

# Unbound logs operational events, not queries.
unbound-checkconf -o verbosity /etc/unbound/unbound.conf    # expect: 1
unbound-checkconf -o log-queries /etc/unbound/unbound.conf  # expect: no

# Remote control is ENABLED by design - Phase I collects metrics over it. The check
# is not whether it is on, but whether anyone has scripted a cache dump to disk.
unbound-control status >/dev/null 2>&1 \
  && echo "INFO: remote-control reachable (expected - Phase I) - see RETENTION.md"
grep -rl 'dump_cache' /etc/cron.* /etc/systemd/system /usr/local/sbin /opt 2>/dev/null \
  && echo "REVIEW: something is scripting a cache dump" \
  || echo "OK: no scripted dump_cache"

# Service-affecting, schedule it: after a reboot the tmpfs dirs must be empty of carry-over
ls -la /var/log/adguardhome/querylog /var/lib/adguardhome/stats
```

Expected: `tmpfs` with the listed options on both mounts, `adguardhome:adguardhome 750` on both, `verbosity: 1`, `log-queries: no`, `INFO: remote-control reachable`, `OK: no scripted dump_cache`, and after a reboot a freshly created `stats.db` plus — under the shipped default — a query log that starts from empty rather than carrying the previous boot's six hours forward.

---

### Q4. Metadata that survives a perfect no-log configuration

Five leaks remain after everything above. None is a bug; all must be disclosed or decided.

**Certificate Transparency publishes the hostname at issuance.** Let's Encrypt submits every certificate it issues to public CT logs — this is required by browser root programme policy and there is no opt-out. The moment Phase D runs, `dns.example.com` is enumerable at `crt.sh` by anyone monitoring your apex domain: before you have announced the service, configured abuse handling, or decided whether it is public at all. If the hostname must stay unpublished, the only mitigation is a DNS-01 **wildcard** certificate, which places `*.example.com` in the log rather than the specific label. Phase D owns the certbot mechanics and Phase P owns the related ClientID decision; the point here is that this is a privacy decision with a deadline — it must be made *before* first issuance, because you cannot unpublish a CT entry. If a public hostname is acceptable, which it usually is for a service you intend to advertise, keep HTTP-01 and record in the privacy notice that the hostname is public.

**Reverse DNS is public either way.** Left at the provider default, the PTR advertises your hosting provider and that this is a generic VPS. Set to `dns.example.com`, it publicly binds the service to the IP. Choose deliberately. A matching forward and reverse record is what makes an abuse desk route a complaint to you rather than null-routing the address, so for a resolver you intend to run properly, setting it is usually right — see Q6.

**SNI is on the client's path and you cannot fix it.** DoT and DoH clients send `dns.example.com` in cleartext TLS SNI on every connection, absent Encrypted Client Hello. The user's own ISP therefore learns *that this user uses your resolver*, even though it cannot read the queries. This is server-side unfixable and it is the single most commonly misunderstood property of encrypted DNS — users switching to a private resolver routinely assume the fact of the switch is hidden. It must be disclosed.

**The hosting provider holds netflow.** Source, destination, port, size and timing for every packet, regardless of encryption, retained under their policy and not yours. They hold a de facto connection log of everyone who uses your resolver. This is a data recipient you did not choose and it belongs in the privacy notice's list of third parties.

**nginx will silently recreate the client-IP log you just deleted — and on the DoH vhost it is worse than an IP log.** Debian and Ubuntu nginx log every request to `/var/log/nginx/access.log` with the client IP by default. Because RFC 8484 defines a GET form in which the DNS message is base64url-encoded into the `?dns=` query string, and `$request` in the default `combined` log format includes the query string, an access log on the DoH server block stores **the client's IP address next to the encoded DNS query**. That is a more complete record than AdGuardHome's query log, written by a component nobody thinks of as a DNS logger. `access_log off;` is not hygiene here — it is load-bearing for the entire privacy design, and it is required on **both** the public :443 DoH server block and the single port-80 server block. Phase E writes both of those blocks; Q5 adds a `location` to the port-80 one rather than creating another. So this is a property to verify in Phase E's file, not to re-declare in a file of Q's own.

Do not check this with `grep -R access_log /etc/nginx/ | grep -v off`. That produces a false failure on every stock Ubuntu box, because `/etc/nginx/nginx.conf` ships an http-level `access_log /var/log/nginx/access.log;` that is correctly overridden by the server-level `access_log off;`. Measured on Ubuntu / nginx 1.18.0 and unchanged in 24.04's 1.24. An operator following a grep-based runbook after a package upgrade sees a failure that is not one, and the natural reaction — deleting the http-level line — is unnecessary churn. Check behaviourally instead.

**Phase F is retired.** The v1 plan's Python cache warmer queried 12 fixed domains at `ttl*0.75` plus `random.randint(0,30)` jitter. To an upstream that is a near-periodic heartbeat from your IP: it marks the host as a resolver running a warmer, it is trivially separable from user traffic because the set is small and constant, and during low-traffic hours its known volume lets an observer estimate your real user count by subtraction. It was never cover traffic; it was a latency optimisation with a mild negative privacy effect. Unbound's `prefetch` / `prefetch-key` (Phase C) replaces it and is better on this axis too: it refreshes only names your users actually asked for, in proportion to real demand, so it adds no fixed signature and no constant baseline to subtract. It is not zero — prefetch does emit a refresh query to an authoritative server near TTL expiry for popular names, slightly extending the window in which that authority sees activity from you — but it is demand-shaped rather than fingerprint-shaped. Describe it accurately in the privacy notice and do not claim it obscures anything.

#### Verification

```bash
# See exactly what you have already published to CT for your domain.
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u

# Forward and reverse must match.
dig +short dns.example.com A
dig +short -x <PUBLIC_IP>

# Every nginx file that defines a client-facing server block disables access
# logging. Iterate /etc/nginx/conf.d/*.conf, NOT sites-enabled: Phase E writes
# both blocks into /etc/nginx/conf.d/doh.conf and removes sites-enabled/default,
# so a loop over sites-enabled/* expands to a non-existent path, inspects
# nothing, and can never fail — a check that always passes is not a check.
for f in /etc/nginx/conf.d/*.conf; do
  [ -e "$f" ] || { echo "FAIL: no server blocks found in /etc/nginx/conf.d/"; break; }
  grep -q 'access_log off;' "$f" && echo "OK: $f" || echo "FAIL: $f missing 'access_log off;'"
done
# Phase E ships exactly two client-facing blocks in doh.conf — the :443 DoH block
# and the single :80 block — and both must carry the directive.
test "$(grep -c 'access_log off;' /etc/nginx/conf.d/doh.conf)" -ge 2 \
  && echo "OK: both client-facing blocks disable access logging" \
  || echo "FAIL: fewer than two 'access_log off;' directives in doh.conf"

# Behavioural proof - the only check that survives a package upgrade.
BEFORE=$(stat -c %s /var/log/nginx/access.log 2>/dev/null || echo 0)
curl -s http://dns.example.com/.well-known/security.txt >/dev/null
curl -s -H 'accept: application/dns-message' \
  'https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB' >/dev/null
sleep 1
AFTER=$(stat -c %s /var/log/nginx/access.log 2>/dev/null || echo 0)
[ "$BEFORE" -eq "$AFTER" ] && echo "OK: neither request produced a log line" \
                           || echo "FAIL: nginx logged a request"
```

Expected: the CT listing shows only labels you intended to publish; forward and reverse agree; `OK:` for every file in `conf.d/` plus `OK: both client-facing blocks disable access logging`; `OK: neither request produced a log line`.

Note on SNI: `openssl s_client -connect host:853 -servername host` confirms the server *accepts* a handshake with that SNI — it does not display what a real client transmits. To see that on the wire, capture the ClientHello: `tcpdump -ni any -s0 -A 'tcp port 853' | grep -a dns.example.com`.

---

### Q5. The written artifacts

Every control above is a setting a future operator can change in thirty seconds with no record of why it was set. These three documents are what make the configuration a policy. Adapt the templates; do not ship them with `example.com` in place.

#### Q5a. Data retention policy

`/opt/dns-config-backup/RETENTION.md`. That directory is the local config staging area — it survives, it is the same place Phases I and J write to, and Phase K's job is to back it up off-host with restic, encrypted, not to delete it. Keep a git repo in it and commit every change, so that edits to the policy are dated and attributable locally as well as recoverable remotely.

Fill in the posture you actually chose in Q1. The table below is written for the shipped default; the bracketed alternative on each affected row is the Posture A wording. Do not ship both.

```markdown
# Data Retention Policy - dns.example.com
Owner: <name>   Effective: <date>   Review: annually
Logging posture: <shipped default (Q1 Posture C) | Posture B | Posture A>   Decided: <date> by <name>

## What is collected
| Data | Where | Why | Retention | Destruction |
|---|---|---|---|---|
| DNS query records (name, type, /16-masked client IP) | AdGuardHome query log, RAM-backed tmpfs | fault diagnosis | 6 h rolling ring | ring expiry; lost on reboot [Posture A: not retained - querylog.enabled=false, no log entry is ever built] |
| Client IP addresses | only inside the above, truncated to /16 at ingestion | fault diagnosis | 6 h | as above [Posture A: not retained at all] |
| Per-domain and per-client-/16 counters | AdGuardHome stats.db, RAM-backed tmpfs | monitoring (Phase I) | statistics.interval | lost on reboot [Posture A: statistics disabled; file exists but holds no client data] |
| Resolver cache (domains, no client identity) | Unbound process RAM | performance | until process restart | lost on exit; nothing written to disk |
| Edge cache | AdGuardHome process RAM | performance | until process restart | lost on exit |
| Unbound cache dump (manual only) | not produced routinely | incident diagnosis | n/a | remote-control is enabled for Phase I metrics, so `unbound-control dump_cache` is available to <key holders>; output is never written to a file |
| Banned source addresses | kernel nftables set | abuse mitigation | 10 minutes first offence, escalating to 24 hours on repeat (kernel set timeout; see Phase B/J) | automatic expiry; never written to disk |
| Aggregate packet counters | kernel counters | abuse monitoring | until reboot | no identity content |
| TLS certificate and key | /etc/letsencrypt | service operation | 90 days, auto-renewed | certbot |
| System and auth logs (sshd etc.) | journald | operator security | <N> days | journald rotation |

## What is NOT collected
No query records beyond the 6 h ring above, and none at all under Posture A.
No un-truncated client IP address is ever written: the mask is applied at ingestion.
No EDNS Client Subnet is sent upstream (dns.edns_client_subnet.enabled=false).
No web-server access log on any listener.
No per-peer VPN metadata is captured to disk (see Q7, if Phase P applies).

## Who can access
<names/roles>. Access is via SSH key only; no shared credentials.
The AdGuardHome admin UI is bound to 127.0.0.1 and reachable only via SSH port-forward (Phase P).

## Third parties that necessarily see data
- Hosting provider <name, jurisdiction>: connection metadata (netflow) for all traffic,
  under their policy, not ours.
- Authoritative DNS operators, including the root and TLD operators: query names, in
  cleartext, attributed to this server's IP address only - never to an individual client.
  QNAME minimisation limits what each level of the hierarchy learns.
- Certificate Transparency logs: the certificate and hostname, permanently and publicly.

## Deliberate deviations
- Logging posture: <as shipped by Phase E | opted in to Posture A or B on <date>, reason <...>>.
  If Posture A: the monitoring consequence has been accepted - AdGuardHome metrics are absent
  and the Phase I collector reports "metrics unavailable by policy" rather than an outage.
- Unbound remote-control is ENABLED, because Phase I collects metrics over it. Control-key
  holders: <names>. A manual `unbound-control dump_cache` would produce domain history for the
  whole user population; it is never scripted and never redirected to a file.
- security.txt is served over HTTP as well as HTTPS (see privacy notice; RFC 9116 requires https).
- journald storage: <persistent | volatile> - reason: <...>
- Disk encryption: <LUKS | none> - reason and limits: <...>

## Temporary logging windows
| Start | End | Posture | Reason | Approved by |
|---|---|---|---|---|

## Change control
Any change that causes user data to be retained requires an entry in this file, a commit,
and a corresponding update to the published privacy notice BEFORE deployment.
```

#### Q5b. Privacy notice

Publish at `https://example.com/dns-privacy` and reference it from the `Policy:` field of `security.txt`.

**The "what we do with your queries" paragraph has two versions and you must publish the one that matches Q1.** Publishing the zero-log wording while running the Phase E shipped default is not a drafting slip; it is a false statement to data subjects about a system that demonstrably contradicts it, and it is the single most likely way this plan produces a compliance problem. The default version is given first because it is the one most deployments need.

```markdown
# Privacy Notice - dns.example.com public DNS resolver
Last updated: <date>

**Who we are.** <legal name / individual>, <postal address>, <contact email>.
We are the data controller for this service.

**What we do with your queries.** [DEFAULT CONFIGURATION VERSION] We resolve them. We keep a
short operational record of queries - the name asked for, the record type, and your IP address
truncated to its first two octets - for six hours, so that we can diagnose faults. It is held
in memory only and is lost whenever the service restarts. Your full IP address is never
written down: it is truncated before the record is created. After six hours the record is
gone. We do not sell, share or monetise DNS data. We do not filter, block or redirect answers.

**What we do with your queries.** [ZERO-LOG VERSION - publish this one only if you have opted
in to Q1 Posture A] We resolve them and forget them. We do not write query logs. We do not
store client IP addresses, truncated or otherwise. We do not sell, share or monetise DNS
data. We do not filter, block or redirect answers.

**What we necessarily process, transiently.** Your IP address is present in the packets we
receive and is held in memory only for as long as needed to answer, plus, if you send
abusive traffic volumes, for 10 minutes in a kernel firewall ban list - extended to 24 hours
if the abusive traffic repeats. Lawful basis: legitimate interests (Art. 6(1)(f)) in
delivering the service and preventing abuse. Our balancing assessment is available on request.

**Who else sees your queries.** We do not forward your queries to any commercial resolver.
This server resolves independently from the DNS root, which means the root operators, the
relevant top-level domain operator, and the authoritative servers for the domain you asked
about each see part or all of the name - in cleartext, and attributed to this server's IP
address, never to yours. We use QNAME minimisation, so each level of the hierarchy is told
only as much of the name as it needs. We do not send EDNS Client Subnet. Our hosting
provider, <name>, can observe connection metadata (your IP address, timing, volume) under
their own policy.

**What we cannot protect you from.** The hostname dns.example.com is sent in cleartext
(TLS SNI) when your device connects, so your network operator can see that you use this
resolver, though not what you asked. Our hostname and certificate are permanently public in
Certificate Transparency logs. We cannot see or control what your operating system or
browser does with DNS outside this service.

**Your rights.** Access, erasure, restriction, objection, and complaint to your supervisory
authority. [DEFAULT CONFIGURATION VERSION] In practice we hold very little: at most a six-hour
record in which your address appears only truncated to its first two octets, which we usually
cannot tie to you as an individual. We will explain in writing what we hold on request.
[ZERO-LOG VERSION] In practice we hold no data to give you or to erase; we will say so in
writing on request.

**Law enforcement.** We respond only to legally valid process in <jurisdiction>. [DEFAULT
CONFIGURATION VERSION] We hold at most six hours of query records in which client addresses
are truncated to /16, held in memory and lost on restart; we cannot produce a full client
address for any query, because we never record one. [ZERO-LOG VERSION] We hold no query or
client data to produce. If we are ever compelled to begin retaining more than is described
above, we will publish that change here before it takes effect, to the extent the law permits.

**Changes.** Material changes are published here with a new date.
```

#### Q5c. security.txt and the abuse contact

RFC 9116 requires the file at `/.well-known/security.txt`, requires `Contact` and `Expires` (exactly one `Expires`, RFC 3339 format, recommended under one year out), and requires it be served as `text/plain` **with `charset=utf-8`**. All other fields are optional; OpenPGP signing is recommended, not required.

Port 80 is the natural home, and it already exists — **Q does not build it**. Phase E writes the one and only port-80 server block on this host, with the one and only webroot at `/var/www/acme`, and Phase D's ACME challenge is served out of that same webroot. Q adds a single `location` to that existing block. It does **not** create a second `listen 80 default_server` (nginx refuses to start with a duplicate `default_server` on the same address and port), it does **not** create a second webroot (that is how the ACME challenge and the well-known files end up in different directories with only one of them reachable), and it does **not** install a second web server.

Add to Phase E's port-80 server block:

```nginx
    # Phase Q: security.txt and friends, served from the same webroot as the
    # Phase D ACME challenge. One block, one root - see Phase E.
    location ^~ /.well-known/ { }
```

Three properties of that block are load-bearing for Q, and all three belong to Phase E's file — Phase E ships all three in the port-80 block, so this is a confirmation, not a change. Confirm they are present; if any is missing on the host in front of you, add it **there**, not in a block of your own:

- `access_log off;` — see Q4. Without it the port-80 block logs client IPs.
- `server_tokens off;`
- `charset utf-8;` — RFC 9116 requires `text/plain; charset=utf-8`. `default_type` does **not** achieve this: `security.txt` has a `.txt` extension, so `mime.types` already resolves `text/plain` and `default_type` never fires, leaving the charset off. Measured on nginx 1.18.0: `default_type` gives `text/plain` (NON-CONFORMANT); `charset utf-8;` gives `text/plain; charset=utf-8` (conformant). `text/plain` is in nginx's default `charset_types`, so the one line is sufficient.

```bash
install -d -m 0755 /var/www/acme/.well-known
nginx -t && systemctl reload nginx
```

Because nginx — not AdGuardHome — owns :443 on this host under the v2 topology, you can satisfy the RFC's `https` requirement locally rather than deviating from it. Add these three lines to the Phase E public :443 server block, pointing at the same single webroot:

```nginx
    root /var/www/acme;
    charset utf-8;
    location ^~ /.well-known/ { }
```

`charset utf-8;` has no effect on the DoH responses proxied from `/dns-query`, because `application/dns-message` is not in nginx's default `charset_types`. If you would rather host the canonical copy on your main website, do that and point `Canonical:` there; either way, keep a copy reachable from the resolver hostname, since a researcher who scanned you may have nothing but the hostname.

`/var/www/acme/.well-known/security.txt`:

```
# Public DNS resolver operated at dns.example.com
Contact: mailto:abuse@example.com
Contact: mailto:security@example.com
Expires: 2027-08-01T00:00:00.000Z
Preferred-Languages: en
Canonical: https://dns.example.com/.well-known/security.txt
Policy: https://example.com/dns-privacy
Acknowledgments: https://example.com/security-thanks
```

An expired `security.txt` is worse than none — it signals an abandoned service. Install the check as a script and schedule it from the one cron file:

```bash
cat > /usr/local/sbin/check-securitytxt-expiry <<'EOF'
#!/bin/bash
set -u
F=/var/www/acme/.well-known/security.txt
EXP=$(awk -F': ' '/^Expires:/{print $2}' "$F")
[ -n "$EXP" ] || { echo "no Expires field in $F" | logger -t securitytxt -p daemon.err; exit 1; }
DAYS=$(( ( $(date -d "$EXP" +%s) - $(date +%s) ) / 86400 ))
[ "$DAYS" -lt 30 ] || exit 0
# notify.sh is the single notification entry point, defined by Phase I8b, and its
# signature is `notify.sh <severity> <title> [message]`. Severity and title are
# SEPARATE arguments: a single-argument call makes the message text the severity,
# which pages at the wrong priority and discards the message. Fall back to the
# journal only if notify.sh is not installed yet, so this check never silently
# does nothing -- notify.sh writes its own journald record when it is present.
if [ -x /usr/local/sbin/notify.sh ]; then
  /usr/local/sbin/notify.sh warning "security.txt expiring" \
    "security.txt for dns.example.com expires in $DAYS days (Expires: $EXP)"
else
  echo "security.txt expires in $DAYS days" | logger -t securitytxt
fi
EOF
chmod 0755 /usr/local/sbin/check-securitytxt-expiry
```

Schedule it by **appending to `/etc/cron.d/dns-health`** — the file Phase I creates and every other phase appends to. Do not add a `cron.monthly` file or a second `cron.d` file for it; one schedule file is what keeps the cron inventory auditable and stops one phase silently deleting another's entry.

```
# appended to /etc/cron.d/dns-health (created by Phase I)
41 7 1 * * root /usr/local/sbin/check-securitytxt-expiry
```

**Make the mailbox real and route it.** A contact address that nobody reads is a liability, not a control.

- Set `abuse-c` on your RIPE object, or the Abuse POC on your ARIN/APNIC record, if you hold the address space. If the IP belongs to the hosting provider, open a ticket asking them to forward resolver abuse reports to your address, and **record the ticket reference** — it is your evidence of diligence if they later act unilaterally.
- Set the PTR to `dns.example.com` so a complainant can find you (Q4).
- Publish the resolver's purpose and contact at the `Policy:` URL, so a researcher who scanned you can tell an intentional public resolver from a misconfiguration.

**Q imposes no new dependency on Phase D — it inherits one.** nginx owns port 80 from Phase E onward, so certbot cannot use `--standalone`; Phase D already uses the `webroot` authenticator against `/var/www/acme`, or DNS-01. Because Q's `location` sits under that same webroot and adds no new listener, adding the well-known files changes nothing about certificate issuance or renewal, and nothing needs to be re-cut. Verify it anyway (below), because a wrong authenticator is silent until renewal day.

The one case that still needs care is a **migration** from an older host where the lineage was issued with `--standalone`. `certbot certonly` against an existing lineage prompts interactively for (K)eep/(R)enew and aborts under `-n`, so switching authenticators on an existing lineage needs `--force-renewal` or `--keep-until-expiring`. `--force-renewal` consumes one of Let's Encrypt's five-duplicate-certificates-per-week allowance; fine as a one-off, never in a loop.

#### Verification

```bash
# Artifacts exist, are versioned, and are reachable.
test -f /opt/dns-config-backup/RETENTION.md && echo "OK: retention policy present"
git -C /opt/dns-config-backup log --oneline -- RETENTION.md
curl -sSf https://example.com/dns-privacy > /dev/null && echo "OK: privacy notice published"

# security.txt is served with the RFC-required media type AND charset.
CT=$(curl -sS -D- -o /tmp/st http://dns.example.com/.well-known/security.txt \
     | awk -F': ' 'tolower($1)=="content-type"{print tolower($2)}' | tr -d '\r')
echo "Content-Type: $CT"
case "$CT" in
  "text/plain; charset=utf-8") echo "OK: RFC 9116 compliant content type" ;;
  *) echo "FAIL: expected 'text/plain; charset=utf-8' - add 'charset utf-8;' to the server block" ;;
esac

grep -E '^(Contact|Expires):' /tmp/st
test "$(grep -c '^Expires:' /tmp/st)" -eq 1 && echo "OK: exactly one Expires field"
date -d "$(awk -F': ' '/^Expires:/{print $2}' /tmp/st)" +%s >/dev/null && echo "OK: RFC 3339 parses"
curl -sS https://dns.example.com/.well-known/security.txt | grep '^Policy:'

# The expiry check is installed and scheduled from the ONE cron file (Phase I),
# not from a cron.monthly drop-in, and it calls notify.sh with severity and title
# as separate arguments.
test -x /usr/local/sbin/check-securitytxt-expiry && echo "OK: expiry check installed"
grep -c 'check-securitytxt-expiry' /etc/cron.d/dns-health   # expect: 1
test ! -e /etc/cron.monthly/check-securitytxt-expiry && echo "OK: no stray cron.monthly copy"
grep -q 'notify.sh warning "security.txt expiring"' /usr/local/sbin/check-securitytxt-expiry \
  && echo "OK: notify.sh called with severity and title as separate arguments"
# End-to-end run. NOTE: if Expires is genuinely under 30 days out this sends a real
# notification - that is the check working, not a false alarm. Exits 0 whether or not
# it notified; exit 1 means the Expires field is missing or unparseable.
/usr/local/sbin/check-securitytxt-expiry && echo "OK: expiry check runs clean"

# Exactly one port-80 server block and one webroot on this host. Q added a location
# to Phase E's block; if this prints anything other than 1, someone created a second.
# Search all of /etc/nginx — Phase E's blocks live in conf.d/doh.conf, and a
# second block someone added could be anywhere. Do NOT scope this to
# sites-enabled/, which Phase E empties: it would report 0 and never fail.
grep -rh 'listen 80 default_server' /etc/nginx/ 2>/dev/null | grep -c . \
  | awk '{print "listen-80 default_server blocks:", $1, "(expect 1)"}'
grep -rhE '^\s*root\s' /etc/nginx/conf.d/*.conf | sort -u   # expect: only /var/www/acme

# Certificate renewal still works with nginx owning :80.
certbot renew --dry-run
grep authenticator /etc/letsencrypt/renewal/dns.example.com.conf   # expect: webroot (or dns-<plugin>)
grep webroot_path /etc/letsencrypt/renewal/dns.example.com.conf    # expect: /var/www/acme

# The PUBLISHED claims match the running system. This is the check that catches a
# privacy notice left on the zero-log wording while the shipped default is running.
# Re-run at every annual review and after any Q1 change.
QL=$(grep -A1 '^querylog:' /opt/adguardhome/conf/AdGuardHome.yaml | awk '/enabled:/{print $2}')
if curl -sS https://example.com/dns-privacy | grep -qi 'we do not write query logs'; then
  [ "$QL" = "false" ] && echo "OK: zero-log claim matches config" \
                      || echo "FAIL: notice claims no logs but querylog.enabled=$QL"
else
  echo "INFO: notice does not make a zero-log claim - confirm it describes the 6 h ring"
fi
grep -A2 'edns_client_subnet' /opt/adguardhome/conf/AdGuardHome.yaml   # expect enabled: false
```

Expected: both files present and committed, `OK: RFC 9116 compliant content type`, exactly one `Expires`, `OK: expiry check installed` with exactly one `check-securitytxt-expiry` line in `/etc/cron.d/dns-health` and no `cron.monthly` copy, exactly one listen-80 `default_server` block with `/var/www/acme` as the only root, `certbot renew --dry-run` succeeding with a non-standalone authenticator, and no `FAIL:` from the published-claims check.

**Abuse mailbox test is a manual checklist item, not a script.** Send a message by hand from an external account and confirm a human reply. Do not pipe mail from the server: this plan installs no MTA, and sending mail on the operator's behalf from a verification script is the wrong shape for a check.

Add to the Phase L go-live checklist:

```
[ ] Logging posture explicitly chosen - shipped default or a recorded opt-in - and written
    into RETENTION.md with a date and a name; running config matches it
[ ] If Posture A: Phase I confirmed to emit "metrics unavailable by policy" and NOT to fire
    AdGuardHomeDown or report agh_up=0
[ ] Privacy notice publishes the paragraph variant that matches the chosen posture
[ ] AdGuardHome starts with schema_version pinned; no legacy querylog_ keys
[ ] tmpfs mounted on /var/log/adguardhome/querylog and /var/lib/adguardhome/stats;
    survives a reboot with no carry-over
[ ] abuse@ and security@ exist, monitored, tested end-to-end by hand
[ ] security.txt reachable over HTTP and HTTPS, charset=utf-8, Expires < 1 year out
[ ] exactly one listen-80 default_server block and one webroot (/var/www/acme); Q added a
    location to Phase E's block, not a block of its own
[ ] monthly security.txt expiry check active - /usr/local/sbin/check-securitytxt-expiry
    installed and its cron line APPENDED to /etc/cron.d/dns-health (Phase I's file),
    with no cron.monthly drop-in; it calls notify.sh with severity AND title
[ ] certbot authenticator is webroot against /var/www/acme, or dns-* (NOT standalone)
[ ] access_log off verified behaviourally on every client-facing nginx server block
[ ] PTR matches dns.example.com
[ ] provider abuse-forwarding ticket raised, reference recorded
[ ] privacy notice published and linked from security.txt Policy:
[ ] Q6 decision register completed and committed
```

---

### Q6. Legal decisions to make and record

**This is not legal advice.** What follows is a list of decisions the operator must make, with enough context to make them, and a register to record them in. Where a decision has legal consequence in your jurisdiction, take advice. Recording the reasoning is worth as much as the answer: a documented decision that later turns out to be wrong is a very different position from having never considered it.

**Why any of this applies.** A dynamic IP address is personal data in the hands of a service provider who has legal means to identify the subscriber — CJEU C-582/14 *Breyer*, 19 October 2016 — and GDPR Recital 30 names online identifiers explicitly. A resolver receives IP addresses by necessity, so it processes personal data even under Posture A. In *EDPS v SRB*, C-413/23 P, 4 September 2025, the CJEU adopted a contextual, relative test: sufficiently strongly pseudonymised data may not be personal data in the hands of a recipient who cannot reidentify, assessed on all the means reasonably likely to be used. That decision helps a *recipient* of your aggregates. It does not help you, because as the party holding the raw packets you retain the means. Do not read it as permission to keep /16-truncated logs and call them anonymous — and note that under the Phase E shipped default you are keeping exactly that, for six hours. The truncation is a strong mitigation and a good argument in a balancing assessment. It is not a get-out from the regime.

**Provider AUP is the risk that actually bites.** Read your hosting provider's acceptable use terms for open-resolver, amplification and DDoS-source clauses *before* launch. Several providers restrict or forbid running a public recursive resolver outright, and suspension — not a warning — is the normal enforcement when your IP appears in a reflection attack report. This is far more likely to end your service than any regulator. If the terms are ambiguous, ask in writing and keep the answer.

**Preservation orders are the decision that most affects your users.** A legally valid order can compel you to begin retaining data prospectively. Under the shipped default you hold six hours of /16-truncated records today and could be ordered to hold more, for longer, un-truncated; under Posture A you hold nothing today, but you can still be told to hold something tomorrow. The order of magnitude differs, the decision does not. Decide now: who receives such a request, how its validity and jurisdiction are checked, whether you will seek advice before complying, whether and when you notify affected users, and whether the fact of compelled logging is publishable. Deciding this under pressure, at the moment it happens, is how operators end up logging ad hoc and telling users nothing.

**Transparency reporting over warrant canaries.** Publish periodic counts of requests received, complied with, and rejected. Prefer this to a warrant canary: canaries have contested legal effect, require disciplined scheduled updates, and a missed update is ambiguous rather than informative — readers cannot distinguish compulsion from the operator being on holiday. If you publish one anyway, fix the cadence in writing and automate the reminder.

#### Decision register

Append to `RETENTION.md` and commit. Every row needs an answer and a date; "not applicable" with a reason is a valid answer, "blank" is not.

| Decision | Why it is a decision | Recorded answer | Date |
|---|---|---|---|
| Logging posture (Q1) | Determines everything downstream. Leaving the Phase E shipped default in place is a valid answer and must be recorded as one — "we did not change it" is a decision, "nobody looked" is not | | |
| Monitoring consequence accepted (Q1) | Only if you opt in to Posture A: AdGuardHome metrics disappear and Phase I reports "metrics unavailable by policy". Record who accepted operating without them | | |
| Controller or processor | Serving the general public makes you a controller. Serving one organisation on its instructions makes you a processor and requires an Art. 28 agreement | | |
| Lawful basis, with a written Legitimate Interests Assessment | Consent is impractical for DNS — there is no interface in which to obtain it | | |
| Art. 30 record of processing | The under-250-employee carve-out does not apply to processing that is not occasional, and a resolver runs continuously. `RETENTION.md` is most of a ROPA already | | |
| Art. 27 EU representative | Required if you are established outside the EU and offer the service to people in the EU | | |
| DPO under Art. 37(1)(b) | A no-log resolver is very unlikely to constitute large-scale regular systematic monitoring — but record the reasoning rather than leaving it unconsidered | | |
| International transfers | Under recursion you no longer forward to named US operators, which removes the clearest transfer question. Authoritative servers worldwide still receive query names attributed to your IP — decide how you characterise that | | |
| Art. 33 breach notification, 72 hours | Record what a host compromise would actually expose. Under the shipped default: up to six hours of query records with /16-truncated client addresses, RAM-resident. Under Posture A: nothing, because no record exists — which remains the strongest single argument for opting in | | |
| Provider AUP position | Read the terms; record the clause and any written confirmation | | |
| Abuse complaint handling | Who receives, who responds, what evidence you can offer (kernel counters, not query logs — see Phase J) | | |
| Law enforcement runbook | Receipt, validity and jurisdiction checks, what you actually hold (nothing), user notification | | |
| Preservation-order plan | Decided in advance, per the paragraph above | | |
| Transparency report | Publish or not; if yes, cadence and first date | | |
| journald storage (Q3) | Persistent gives you break-in forensics; volatile removes durable connection records | | |
| Disk encryption (Q3) | LUKS or none, with the limitations written down | | |
| Hostname publication (Q4) | HTTP-01 named cert publishes the label to CT permanently; DNS-01 wildcard does not | | |

#### Verification

```bash
# Every row has an answer. This is a human read, but catch the empty ones mechanically.
awk -F'|' '/^\|/ && NF>4 && $4 ~ /^[[:space:]]*$/ {print "UNANSWERED:", $2}' \
  /opt/dns-config-backup/RETENTION.md
git -C /opt/dns-config-backup log -1 --format='%ci %an' -- RETENTION.md
```

Expected: no `UNANSWERED:` lines, and a commit date you recognise.

---

### Q7. What Phase P changes

Restricting the resolver to a WireGuard peer group, an nftables allowlist, or mTLS clients shifts your exposure. It does not eliminate it, and in one specific respect it makes things worse. Amend the privacy notice for a private deployment; do not simply shorten it.

**What disappears.** Open-resolver amplification abuse: you are no longer a reflector, so reflection complaints, the associated provider-AUP risk, and most of the DDoS surface go away. The Phase J auto-ban machinery becomes near-decorative — keep it, but it should never fire. You stop processing data about the general public entirely, which shrinks the population whose rights you must consider from "anyone on the internet" to "people you enrolled". The lawful basis gets cleaner: contract, or a narrow and easily justified legitimate interest, rather than a balancing test against unknown data subjects. And a scan of your IP no longer reveals a resolver at all.

**What remains unchanged.** Authoritative servers, the root and the TLD operators still see the aggregate query stream attributed to your IP. The hosting provider still holds netflow. The Certificate Transparency entry is still public and still permanent. Client SNI is still cleartext on the user's path — and if the client reaches you over the tunnel, the tunnel endpoint is what the ISP sees instead, which is a different disclosure, not an absent one. GDPR still applies.

**What gets worse, and operators consistently miss this.** The access layer is itself a new identity layer, and a stronger one than anything the resolver held. WireGuard associates each peer's public key with its current real endpoint IP address and a last-handshake timestamp, all visible in `wg show`. Peers are named, enrolled and few — so unlike a masked /16 in a query log, this is a durable, high-confidence mapping from a specific human to a specific address at a specific time. An nftables allowlist is a written list of your users' home IP addresses. A ClientID scheme puts a per-user label in the DoT/DoQ SNI, in cleartext, on the user's path. mTLS gives you a certificate per user.

The net position is better — sharply lower abuse volume, smaller legal exposure, fewer data subjects — but your ability to identify an individual user goes **up**, not down. That trade is usually worth making. It has to be disclosed.

Concretely, for a Phase P deployment:

- Add to the privacy notice: which peer metadata exists (public key, assigned tunnel address, endpoint IP, last handshake), that it is visible to the operator, and how long it persists.
- Decide and record whether `wg show` output is ever captured to disk or into monitoring. **By default it is not, and it should stay that way.** A monitoring check that graphs per-peer handshake age creates the durable identity log the resolver was designed not to have. If you need liveness monitoring, monitor the interface in aggregate.
- Remove the public-resolver abuse language from the notice; it no longer describes the service.
- Revisit the CT decision (Q4). A VPN-only or unadvertised resolver is exactly the case where publishing `dns.example.com` to a public log on day one defeats the intent, and where a DNS-01 wildcard is worth the extra setup.
- If the resolver serves one organisation on its instructions, revisit the controller/processor row in Q6 — that is the fact pattern that makes you a processor.

#### Verification

```bash
# If private: confirm the resolver is genuinely not publicly reachable.
dig @<PUBLIC_IP> google.com A +time=2 +tries=1     # expect: connection timed out

# Peer metadata exists and is NOT being persisted anywhere.
wg show   # NOTE: this output contains peer endpoint IPs. Never redirect it to a file.
grep -rl 'wg show' /etc/cron.* /etc/systemd/system /opt 2>/dev/null \
  && echo "REVIEW: something is capturing peer metadata" \
  || echo "OK: no scripted capture of wg show"
```

Expected: a timeout from the public address, a `wg show` listing you recognise, and `OK: no scripted capture of wg show`.

---

[Plan index](../dns-server-plan.md) · [Previous: Private Access Layer (optional)](./09-private-access.md) · [Next: Go-Live Checklist and Risk Register](./11-go-live-checklist.md)
