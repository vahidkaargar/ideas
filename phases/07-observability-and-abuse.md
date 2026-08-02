[Plan index](../dns-server-plan.md) · [Previous: Retired Warmer, Log Rotation, Validation](./06-logging-and-validation.md) · [Next: Backup, Patching, HA, Provisioning](./08-operations.md)

---

**On this page**

- [PHASE I: Observability, Alerting and SLOs](#phase-i-observability-alerting-and-slos)
  - [I0. Hard constraints, stated before you build anything](#i0-hard-constraints-stated-before-you-build-anything)
  - [I1. Prometheus and node_exporter](#i1-prometheus-and-node-exporter)
  - [I2. Unbound metrics — the preferred signal](#i2-unbound-metrics-the-preferred-signal)
  - [I3. AdGuard Home metrics via /control/stats](#i3-adguard-home-metrics-via-controlstats)
  - [I4. Synthetic probes: blackbox_exporter, and the DoQ gap](#i4-synthetic-probes-blackbox-exporter-and-the-doq-gap)
  - [I5. Abuse counters](#i5-abuse-counters)
  - [I6. Alert rules](#i6-alert-rules)
  - [I7. Recording rules, SLIs and SLOs](#i7-recording-rules-slis-and-slos)
  - [I8. Alertmanager and the path to a phone](#i8-alertmanager-and-the-path-to-a-phone)
  - [I8b. `notify.sh` — the one notification entry point](#i8b-notifysh-the-one-notification-entry-point)
  - [I9. The off-box dead man's switch — required, not optional](#i9-the-off-box-dead-mans-switch-required-not-optional)
  - [I10. `dns-health` — the single operator script](#i10-dns-health-the-single-operator-script)
  - [I11. Phase I verification](#i11-phase-i-verification)
- [PHASE J: Abuse Detection and Response](#phase-j-abuse-detection-and-response)
  - [J1. Why the v1 query-log cron is deleted outright](#j1-why-the-v1-query-log-cron-is-deleted-outright)
  - [J2. The four correctness constraints the naive ruleset violates](#j2-the-four-correctness-constraints-the-naive-ruleset-violates)
  - [J3. The objects this phase depends on, and who owns them](#j3-the-objects-this-phase-depends-on-and-who-owns-them)
  - [J4. Expiry and escalation](#j4-expiry-and-escalation)
  - [J5. Allowlist, and ban state across a reload](#j5-allowlist-and-ban-state-across-a-reload)
  - [J6. Exporting abuse state to Phase I](#j6-exporting-abuse-state-to-phase-i)
  - [J7. Operator procedures](#j7-operator-procedures)
  - [J8. Sustained spoofed-source flood](#j8-sustained-spoofed-source-flood)
  - [J9. The trade you are accepting](#j9-the-trade-you-are-accepting)
  - [J10. Phase J verification](#j10-phase-j-verification)

---

## PHASE I: Observability, Alerting and SLOs

The v1 plan's Phase I was two cron lines piping `dig` failures into `logger -t dns-alert`, i.e. journald on the box being monitored. There is no notifier, no history, no threshold evaluation, no acknowledgement, and — decisively — no way for the machine to report its own death. This phase replaces it with a real metrics pipeline, real alert rules, and one external dependency that exists solely so that a dead VPS still reaches your phone.

### I0. Hard constraints, stated before you build anything

Four facts shape every decision below. Read them first; they explain why this phase is not the obvious Prometheus install.

1. **AdGuard Home has no native Prometheus endpoint.** PR #7937 is open and unmerged as of v0.107.78. Anything claiming a `/metrics` on AGH is wrong. AGH metrics come from `/control/stats`, over HTTP Basic auth, on the loopback admin listener (`http.address: 127.0.0.1:3000` — see Phase E).
2. **`/control/stats` is a rolling-window gauge, not a monotonic counter.** It returns totals accumulated over `statistics.interval` (default 24h). `rate(agh_queries[5m])` on such a series is meaningless: it is off by orders of magnitude and lags by hours. The window is controlled by the `recent` query parameter, and AGH's own OpenAPI spec constrains it: *"The lookback period for statistics in milliseconds. The interval must be a multiple of one hour and must not be greater than the value of `statistics.interval`."* Anything else returns HTTP 400. **One hour is the floor.** Treat AGH numbers as a one-hour trailing average suitable for accounting and slow drift, and never as a fast signal.
3. **Unbound is the opposite, and is therefore the preferred source.** `unbound-control stats_noreset` emits genuinely cumulative counters, at whatever resolution you scrape, including rcode breakdowns, cache hit/miss, validation failures and a recursion-time histogram. Every alert that *can* be sourced from Unbound is sourced from Unbound below. Only blocking/filtering statistics, which Unbound does not perform, come from AGH.
4. **Every monitor in this phase runs on the box it monitors.** That is unavoidable on a single VPS and it means the whole stack is blind to exactly the failures that matter most: kernel panic, OOM, provider network outage, disk full, nftables lockout, VPS terminated for abuse. Section I9 is the answer, and it is not optional.

One dependency crosses phases: Phase I reads `/control/stats`, which is populated only if `statistics.enabled: true` survives AGH's config migration. That is the shipped default — Phase E ships `querylog.enabled: true` with a 6 h interval and `anonymize_client_ip: true`, and `statistics.enabled: true` — so on a stock build of this plan every AGH panel has data. Phase E must write the top-level `querylog:`/`statistics:` sections **in two passes**: a config with no `schema_version` is read as version 0, and `internal/configmigrate/v15.go` / `v16.go` execute `diskConf["querylog"] = qlog` and `diskConf["statistics"] = stats` unconditionally, destroying hand-written blocks and reverting `interval` to `2160h` with `dir_path` dropped. See Phase E for the procedure; verify the outcome here (I11 step 4).

Statistics can also be off **on purpose**. Phase Q offers a zero-log posture as an opt-in operator choice, and if it is taken, `statistics.enabled` is false and `/control/stats` has nothing to give. A policy decision is not an outage, and this phase must not page as though it were. **Phase I owns that logic**: the collector in I3 detects the disabled state, keeps `agh_up` at 1 while the control API answers, and emits a distinct "metrics unavailable by policy" signal instead of a fake death; the alert rules in I6 treat that signal as informational and `AdGuardHomeDown` cannot fire because of it. Phase Q states the consequences of each posture and cross-references this section rather than restating it. The one thing the collector genuinely cannot distinguish from the API alone is *policy-off* from *migration-accident-off* — both read `enabled: false` — which is exactly what I11 step 4 is for.

### I1. Prometheus and node_exporter

Install both from pinned upstream tarballs. Ubuntu's packaged Prometheus lags by years and its unit files are not hardened.

```bash
PROM_VER=3.13.2   # verified: prometheus CHANGELOG "3.13.2 / 2026-07-29"
NODE_VER=1.12.1   # verified: node_exporter CHANGELOG "1.12.1 / 2026-07-14"
cd /tmp
wget "https://github.com/prometheus/prometheus/releases/download/v${PROM_VER}/prometheus-${PROM_VER}.linux-amd64.tar.gz"
wget "https://github.com/prometheus/node_exporter/releases/download/v${NODE_VER}/node_exporter-${NODE_VER}.linux-amd64.tar.gz"
tar -xzf "prometheus-${PROM_VER}.linux-amd64.tar.gz"
tar -xzf "node_exporter-${NODE_VER}.linux-amd64.tar.gz"
install -m0755 "prometheus-${PROM_VER}.linux-amd64/prometheus"       /usr/local/bin/prometheus
install -m0755 "prometheus-${PROM_VER}.linux-amd64/promtool"         /usr/local/bin/promtool
install -m0755 "node_exporter-${NODE_VER}.linux-amd64/node_exporter" /usr/local/bin/node_exporter

useradd -r -s /usr/sbin/nologin -d /var/lib/prometheus     prometheus
useradd -r -s /usr/sbin/nologin -d /var/lib/node_exporter  nodeexp
mkdir -p /etc/prometheus/rules /var/lib/prometheus /var/lib/node_exporter/textfile
chown prometheus:prometheus /var/lib/prometheus
chown nodeexp:nodeexp /var/lib/node_exporter/textfile
chmod 0755 /var/lib/node_exporter/textfile   # root-run collector scripts write here; root bypasses mode bits
```

`/etc/prometheus/prometheus.yml` — retention lives in the config file, not on the command line. The `--storage.tsdb.retention.*` flags are marked `[DEPRECATED]` in v3.13.2 (`cmd/prometheus/main.go`: *"use the storage.tsdb.retention.time field in the config file instead"*); they still function but earn a startup warning.

```yaml
global:
  scrape_interval: 15s
  scrape_timeout: 10s
  evaluation_interval: 15s
  external_labels:
    host: dns1

storage:
  tsdb:
    retention:
      time: 90d
      size: 6GB

rule_files:
  - /etc/prometheus/rules/*.yml

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['127.0.0.1:9093']

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['127.0.0.1:9090']

  - job_name: node
    static_configs:
      - targets: ['127.0.0.1:9100']
```

The blackbox jobs are appended in I4. Keep everything in this one file.

```ini
# /etc/systemd/system/prometheus.service
[Unit]
Description=Prometheus
After=network-online.target
Wants=network-online.target

[Service]
User=prometheus
Group=prometheus
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus \
  --web.listen-address=127.0.0.1:9090 \
  --web.enable-lifecycle
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
# Hard ceiling so Prometheus can never starve Unbound's message and RRset caches.
MemoryHigh=512M
MemoryMax=768M
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/prometheus

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/node_exporter.service
[Unit]
Description=Prometheus node exporter
After=network-online.target

[Service]
User=nodeexp
Group=nodeexp
ExecStart=/usr/local/bin/node_exporter \
  --web.listen-address=127.0.0.1:9100 \
  --collector.systemd \
  --collector.textfile.directory=/var/lib/node_exporter/textfile \
  --no-collector.nfs --no-collector.nfsd --no-collector.zfs \
  --no-collector.infiniband --no-collector.mdadm
Restart=on-failure
RestartSec=5
MemoryMax=128M
# ProtectSystem=strict is CORRECT here and must not be downgraded to `full`.
# node_exporter's systemd collector connects to the D-Bus SYSTEM bus
# (collector/systemd_linux.go: newSystemdDbusConn -> dbus.NewWithContext); the
# root-only private socket is used only with the hidden --collector.systemd.private.
# A read-only /run does not block connect(2) on a unix socket: the kernel's
# sb_permission() returns -EROFS only for S_ISREG/S_ISDIR/S_ISLNK, not S_ISSOCK.
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now node_exporter prometheus
```

**Retention sizing for the 40 GB disk, worked rather than guessed.**

| Source | Active series (after drops) |
|---|---|
| Prometheus self-metrics | ~700 |
| node_exporter (systemd + textfile, trimmed collectors) | ~1,000 |
| blackbox probes (7 targets x ~10 series) | ~70 |
| unbound textfile (incl. recursion histogram) | ~180 |
| agh textfile | ~10 |
| nftables abuse textfile (Phase J) | ~10 |
| **Total** | **~2,000** |

At a 15 s scrape interval that is `2000 / 15 = 133` samples/s. Prometheus TSDB costs roughly 1.5–2 bytes per sample after compression; use 2 to be safe: `133 x 2 = 266 B/s` = **~23 MB/day** = ~700 MB/month. Ninety days is therefore **~2.1 GB**, and the 6 GB size cap gives roughly 3x headroom for WAL and compaction churn while bounding the blast radius.

Full 40 GB budget: OS and packages ~6 GB, Unbound caches are RAM-only, AGH query log ~4 GB as a ceiling — retention is 2x Phase E's shipped `querylog.interval` of 6 h, so the realistic figure is far smaller, and it is zero only if the operator opts in to Phase Q's zero-log posture — AGH `stats.db` ~0.2 GB, journald 1 GB capped in Phase G, Prometheus 6 GB, service logs 1 GB — **~19 GB committed, more than half the disk free**. That headroom is what makes the `predict_linear` disk alert in I6 meaningful rather than permanently firing.

### I2. Unbound metrics — the preferred signal

Unbound must be told to keep cumulative counters and to expose the extended breakdown. Add a second drop-in rather than editing Phase C's `/etc/unbound/unbound.conf.d/10-public-resolver.conf`, so that a Phase C change and a monitoring change never collide in the same file:

```
# /etc/unbound/unbound.conf.d/99-stats.conf
server:
    extended-statistics: yes
    # Counters accumulate forever instead of resetting on read. Without this,
    # any operator who types `unbound-control stats` (which DOES reset) zeroes
    # every counter and puts a false negative spike into every rate() below.
    statistics-cumulative: yes
    # Do not also dump stats to the log on a timer; that is a second reset path
    # and it duplicates data Prometheus already has.
    statistics-interval: 0

remote-control:
    control-enable: yes
    control-interface: /run/unbound.ctl
    control-use-cert: no
```

A unix-socket control interface with `control-use-cert: no` avoids the TLS keypair that `unbound-control-setup` would otherwise require, and keeps the control channel off the network entirely. The scraper runs as root, so socket ownership does not need widening.

Unbound's remote control is therefore **enabled**, deliberately and permanently, because it is the only source of the cumulative counters this phase depends on. It is a root-owned unix socket in `/run` with no network listener and no TLS material, which is why enabling it is defensible; any phase that describes the resolver's attack surface must describe it that way rather than claiming the control channel is off.

`/usr/local/sbin/unbound-textfile` — a **generic** mapper. It invents no metric names: every `key.path value` line from `stats_noreset` becomes `unbound_<key with dots replaced by underscores>`. This deliberately departs from Prometheus naming convention (no `_total` suffix) so that every series maps 1:1 onto a key documented in `unbound.conf(5)`, and so that a key your build does not emit simply produces no series rather than a wrong one.

```python
#!/usr/bin/env python3
"""unbound-control stats_noreset -> node_exporter textfile metrics.

Naming: unbound's own key, dots -> underscores, prefixed `unbound_`.
  total.num.queries          -> unbound_total_num_queries
  num.answer.rcode.SERVFAIL  -> unbound_num_answer_rcode_SERVFAIL
Nothing is renamed or invented. A key absent on your build yields no series
(and any alert that depends on it silently never fires -- see I11 step 3,
which prints the exact key list your unbound emits).

`histogram.*` keys are handled separately and turned into a real Prometheus
histogram. Keys whose shape does not parse are skipped, never guessed.
"""
import os, re, subprocess, sys, time

OUT   = "/var/lib/node_exporter/textfile/unbound.prom"
CTL   = ["/usr/sbin/unbound-control", "stats_noreset"]
# Cumulative counters; everything else is reported as a gauge.
CTR   = ("num.", "total.num.", "unwanted.", "total.requestlist.overwritten",
         "total.requestlist.exceeded")
HIST  = re.compile(r"^histogram\.(\d+)\.(\d+)\.to\.(\d+)\.(\d+)$")

lines, seen, buckets, ok = [], set(), [], 1

def emit(name, mtype, value, labels=""):
    if name not in seen:
        lines.append("# TYPE %s %s" % (name, mtype))
        seen.add(name)
    lines.append("%s%s %s" % (name, labels, value))

try:
    raw = subprocess.run(CTL, capture_output=True, text=True, timeout=10,
                         check=True).stdout
    for line in raw.splitlines():
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if not key or not val:
            continue
        m = HIST.match(key)
        if m:
            hi = int(m.group(3)) + int(m.group(4)) / 1e6
            buckets.append((hi, float(val)))
            continue
        emit("unbound_" + key.replace(".", "_"),
             "counter" if key.startswith(CTR) else "gauge", val)
    emit("unbound_up", "gauge", 1)
except Exception as exc:                      # noqa: BLE001
    lines, seen, buckets, ok = [], set(), [], 0
    emit("unbound_up", "gauge", 0)
    print("unbound-textfile: %s" % exc, file=sys.stderr)

if buckets:
    buckets.sort()
    run = 0.0
    lines.append("# TYPE unbound_recursion_time_seconds histogram")
    seen.add("unbound_recursion_time_seconds_bucket")
    for hi, n in buckets:
        run += n
        lines.append('unbound_recursion_time_seconds_bucket{le="%g"} %g' % (hi, run))
    lines.append('unbound_recursion_time_seconds_bucket{le="+Inf"} %g' % run)
    lines.append("unbound_recursion_time_seconds_count %g" % run)

emit("unbound_textfile_last_success_seconds", "gauge", int(time.time()) if ok else 0)

tmp = OUT + ".tmp"                            # atomic: never expose a half file
with open(tmp, "w") as fh:
    fh.write("\n".join(lines) + "\n")
os.chmod(tmp, 0o644)
os.replace(tmp, OUT)
```

```ini
# /etc/systemd/system/unbound-textfile.service
[Unit]
Description=Unbound stats to node_exporter textfile
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/unbound-textfile
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/node_exporter/textfile
```

```ini
# /etc/systemd/system/unbound-textfile.timer
[Unit]
Description=Scrape Unbound stats every 30s
[Timer]
OnBootSec=60s
OnUnitActiveSec=30s
AccuracySec=5s
[Install]
WantedBy=timers.target
```

The histogram emitted here has no `_sum`, because unbound does not publish a total recursion time in a form that can be summed reliably. `histogram_quantile()` needs only `_bucket`, so the quantile alerts work; `rate(..._sum)/rate(..._count)` does not exist and must not be written. `unbound_total_recursion_time_avg` is available as a gauge if you want a mean.

**Packaged alternative.** `kumina/unbound_exporter` and its forks expose the same counters over `/metrics`. The plan does not pin one because no current maintained release was verified during research; if you adopt one, pin the exact tag, and note it replaces this script rather than supplementing it — running both doubles the control-socket load for no extra signal.

### I3. AdGuard Home metrics via /control/stats

Credentials first. The `/control/` API requires HTTP Basic auth (AGH's `openapi.yaml` sets `security: [basicAuth]` at the root), and the YAML holds only a bcrypt hash, so the scraper needs the plaintext.

```bash
install -m0600 -o root -g root /dev/null /etc/prometheus/agh-credentials
printf 'admin:YourStrongPassword\n' > /etc/prometheus/agh-credentials

# /opt/dns-config-backup is the local config STAGING directory. It survives:
# Phases I, J and Q all write to it, and Phase K's job is to back it up
# off-host with restic, not to delete it. .gitignore patterns there are
# repo-relative; a leading '/' anchors to the repo root and would match
# nothing, because files are staged FLAT. Use basenames:
printf 'agh-credentials\nntfy.env\n' >> /opt/dns-config-backup/.gitignore
```

Two different protections, and they are not the same protection. The `.gitignore` keeps plaintext secrets out of the *staging* directory, which is a plain git working tree on local disk. The off-host copy is Phase K's encrypted restic repository, whose include list covers `/etc/prometheus`, `/etc/alertmanager` and `/etc/blackbox_exporter` — so `agh-credentials` and `ntfy.env` **are** backed up, encrypted, which is what you want when you have to rebuild this box. Keep Phase K's include list an explicit allowlist; never turn it into `cp -r`.

`/usr/local/sbin/agh-textfile`:

```python
#!/usr/bin/env python3
"""AdGuard Home /control/stats -> node_exporter textfile metrics.

Why this and not a packaged exporter:
  * /control/stats totals are scoped to statistics.interval (default 24h).
    The `recent` query parameter (added in AGH v0.107.72) lets us ask for a
    bounded window so QPS is at least computable.
  * Packaged exporters emit top_queried_domains / top_clients as labelled
    series. On a PUBLIC resolver those label values churn every scrape --
    an unbounded-cardinality bomb that OOMs Prometheus on a 4 GB box in days.

HARD CONSTRAINT on `recent`, per AGH openapi.yaml:
    "The lookback period for statistics in milliseconds.  The interval must
     be a multiple of one hour and must not be greater than the value of
     `statistics.interval`."
  Anything else returns HTTP 400.  3600000 (1h) is the smallest legal value.

POLICY vs OUTAGE.  statistics.enabled may be false because the operator chose
Phase Q's opt-in zero-log posture.  That is a decision, not a death, and it
must never look like one:
  * agh_up stays 1 whenever the control API answers.  It is a reachability
    signal, not a data-availability signal.
  * agh_stats_enabled 0 and agh_metrics_unavailable_by_policy 1 are the
    distinct signal.  The window metrics are then ABSENT, not zero -- an
    absent series cannot be mistaken for "no traffic", a zero can.
  * No alert in I6 fires critical on this path.  See the posture table in I3.
"""
import base64, json, os, sys, time, urllib.request

BASE     = "http://127.0.0.1:3000"
HOUR_MS  = 3600000
WINDOW   = int(os.environ.get("AGH_WINDOW_MS", str(HOUR_MS)))
OUT      = "/var/lib/node_exporter/textfile/adguard.prom"

# Fail loudly at config time rather than emitting agh_up=0 forever.
if WINDOW < HOUR_MS or WINDOW % HOUR_MS != 0:
    sys.exit("AGH_WINDOW_MS must be a positive multiple of %d (1h); got %d"
             % (HOUR_MS, WINDOW))

def _auth_header():
    with open("/etc/prometheus/agh-credentials") as fh:
        user, _, pw = fh.read().strip().partition(":")
    return "Basic " + base64.b64encode((user + ":" + pw).encode()).decode()

def _get(path):
    req = urllib.request.Request(BASE + path)
    req.add_header("Authorization", _auth_header())
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.load(resp)

lines, seen = [], set()

def emit(name, mtype, help_text, value, labels=""):
    if name not in seen:                 # HELP/TYPE exactly once per metric name
        lines.append("# HELP %s %s" % (name, help_text))
        lines.append("# TYPE %s %s" % (name, mtype))
        seen.add(name)
    lines.append("%s%s %s" % (name, labels, value))

ok = 1
try:
    status = _get("/control/status")
    emit("agh_up", "gauge",
         "AdGuard Home control API reachable (NOT a data-availability signal).", 1)
    emit("agh_running", "gauge", "AdGuard Home reports itself running.",
         int(bool(status.get("running"))))
    emit("agh_protection_enabled", "gauge", "DNS protection enabled.",
         int(bool(status.get("protection_enabled"))))

    # Ask whether statistics are collected at all BEFORE asking for them.
    # An older build that lacks this endpoint, or omits the key, is treated as
    # enabled -- the /control/stats call below is then the real test.
    scfg    = _get("/control/stats/config")
    enabled = bool(scfg.get("enabled", True))
    emit("agh_stats_enabled", "gauge",
         "statistics.enabled as AdGuard Home reports it.", int(enabled))
    emit("agh_metrics_unavailable_by_policy", "gauge",
         "1 = statistics are switched off, so AGH window metrics are absent "
         "by configuration rather than by failure.", 0 if enabled else 1)

    if enabled:
        stats = _get("/control/stats?recent=%d" % WINDOW)
        emit("agh_query_window_seconds", "gauge",
             "Width of the stats window these totals cover.", WINDOW / 1000.0)
        emit("agh_queries_window_total", "gauge",
             "DNS queries within agh_query_window_seconds.",
             int(stats.get("num_dns_queries") or 0))
        emit("agh_blocked_filtering_window_total", "gauge",
             "Queries blocked by filtering within the window.",
             int(stats.get("num_blocked_filtering") or 0))
        emit("agh_avg_processing_time_seconds", "gauge",
             "Mean query processing time over the window.",
             float(stats.get("avg_processing_time") or 0.0))
        # top_upstreams_* are bounded by maxItems:100 in the AGH schema, and
        # this box has exactly one upstream (127.0.0.1:5335). Safe to label.
        for entry in (stats.get("top_upstreams_avg_time") or []):
            for host, secs in entry.items():
                emit("agh_upstream_avg_time_seconds", "gauge",
                     "Mean response time per upstream.", float(secs),
                     '{upstream="%s"}' % host.replace('"', ""))
        for entry in (stats.get("top_upstreams_responses") or []):
            for host, n in entry.items():
                emit("agh_upstream_responses_window_total", "gauge",
                     "Responses per upstream within the window.", int(n),
                     '{upstream="%s"}' % host.replace('"', ""))
    else:
        # Deliberately emit NOTHING further. Absent beats zero: a zero here
        # would be indistinguishable from a resolver answering no queries,
        # which is the exact confusion this branch exists to prevent.
        print("agh-textfile: statistics disabled; window metrics omitted "
              "by policy (see Phase Q posture, Phase I3)", file=sys.stderr)
except Exception as exc:                     # noqa: BLE001
    # Reached only when the control API itself fails. Disabled statistics do
    # NOT come through here -- they are a policy branch, not an exception.
    ok, lines, seen = 0, [], set()
    emit("agh_up", "gauge",
         "AdGuard Home control API reachable (NOT a data-availability signal).", 0)
    print("agh-textfile: %s" % exc, file=sys.stderr)

emit("agh_textfile_last_success_seconds", "gauge",
     "Unix time of the last successful AGH scrape.", int(time.time()) if ok else 0)

tmp = OUT + ".tmp"                            # atomic: never expose a half file
with open(tmp, "w") as fh:
    fh.write("\n".join(lines) + "\n")
os.chmod(tmp, 0o644)
os.replace(tmp, OUT)
```

```ini
# /etc/systemd/system/agh-textfile.service
[Unit]
Description=AdGuard Home stats to node_exporter textfile
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/agh-textfile
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/node_exporter/textfile
```

```ini
# /etc/systemd/system/agh-textfile.timer
[Unit]
Description=Scrape AdGuard Home stats every 60s
[Timer]
OnBootSec=90s
OnUnitActiveSec=60s
AccuracySec=5s
[Install]
WantedBy=timers.target
```

**What each logging posture does to the metrics.** Phase Q offers the operator a set of postures; this table is the monitoring half of that decision, and it lives here because Phase I owns the degradation behaviour. Phase Q cross-references it rather than duplicating it.

| Posture | Config state | Metric effect | Alerting effect |
|---|---|---|---|
| **Shipped default** (Phase E) | `querylog.enabled: true`, `interval: 6h`, `anonymize_client_ip: true`, `statistics.enabled: true` | every `agh_*` series present | full set, nothing suppressed |
| Query log off, statistics on (opt-in) | `querylog.enabled: false`, `statistics.enabled: true` | `agh_*` all present and correct; `dns_dir_bytes{dir="/var/log/adguardhome"}` goes to ~0 | `QueryLogGrowing` can never fire. No loss: nothing in this phase reads the query log, and J1 explains why nothing should |
| Statistics off (opt-in) | `statistics.enabled: false` | `agh_queries_window_total`, `agh_blocked_filtering_window_total`, `agh_avg_processing_time_seconds`, `agh_upstream_*`, `agh_query_window_seconds` **absent**. `agh_up` stays 1, `agh_running` and `agh_protection_enabled` stay valid, `agh_stats_enabled` 0, `agh_metrics_unavailable_by_policy` 1 | `AdGuardHomeDown` **cannot** fire on this path. `AdGuardMetricsDisabledByPolicy` fires once at `info` and is not routed as a page |
| Both off (opt-in) | union of the two above | union of the two above | union of the two above |

The reason this degradation costs so little is I0's third constraint: no alert rule in I6 depends on an AGH window metric. Blocking counts are the only thing Unbound cannot supply, and nothing pages on blocking counts. Every availability, correctness, latency and capacity alert is sourced from Unbound, blackbox, `dnslookup` or node_exporter, all of which are indifferent to every posture above.

**How to use these numbers correctly.** `agh_queries_window_total / 3600` is a one-hour trailing average. It is fine for accounting and for spotting slow drift; it is useless for flood detection, and `recent=60000` is not a smaller window — it is an HTTP 400. Do not attempt it. For fast QPS signal use `rate(unbound_total_num_queries[5m])` (I2), corroborated by `rate(node_network_receive_packets_total{device!="lo"}[2m])`, which node_exporter already provides at scrape resolution and which is an excellent proxy on a box that does nothing but DNS.

**If you insist on a packaged exporter.** The maintained project is `henrywhitaker3/adguard-exporter` (`ghcr.io/henrywhitaker3/adguard-exporter:latest`; env `ADGUARD_SERVERS`, `ADGUARD_USERNAMES`, `ADGUARD_PASSWORDS`, `INTERVAL` default `30s`, `BIND_ADDR` default `:9618`). It is Docker-only, meaning a container runtime on this box. If you do it, the cardinality drops are **mandatory** — but keep the upstream series, which AGH bounds at `maxItems: 100`:

```yaml
  - job_name: adguard
    scrape_interval: 30s
    static_configs:
      - targets: ['127.0.0.1:9618']
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'adguard_top_(queried_domains|blocked_domains|clients)'
        action: drop
      - source_labels: [__name__]
        regex: 'adguard_queries_details.*'
        action: drop
```

The older `ebrianne/adguard-exporter` — referenced by most blog posts and by Grafana dashboard 13330 — is unmaintained. Do not deploy it.

### I4. Synthetic probes: blackbox_exporter, and the DoQ gap

This is the most important part of the phase. The encrypted endpoints break **silently**: a certificate rotation that does not reach AGH, an nginx reload that drops the `/dns-query` location, a DoQ listener that fails to rebind after restart — none of these move a single counter. Plain UDP/53 keeps working, the dashboards stay green, and every DoT/DoH/DoQ client on the internet fails. Only an end-to-end probe catches that class of failure.

Division of labour, because one tool cannot cover all four protocols:

| Protocol | Prober | Why |
|---|---|---|
| Do53 UDP / TCP | blackbox `dns` | native, cheap, includes rcode validation |
| DoH | blackbox `http` | RFC 8484 GET with a fixed wire-format query |
| TLS expiry on :443 and :853 | blackbox `tcp` with `tls: true` | `probe_ssl_earliest_cert_expiry` is the cert as clients see it |
| DoT resolution | `dnslookup` (I4b) | blackbox's DoT support is version-dependent |
| DoQ resolution | `dnslookup` (I4b) | **blackbox has no QUIC prober at all** |

Install blackbox_exporter. Research did not verify a current release tag, so resolve it at install time and **record the resolved version in the Phase O inventory** — an unpinned install is acceptable only if the actual version is written down afterwards:

```bash
BB_VER=$(curl -fsS https://api.github.com/repos/prometheus/blackbox_exporter/releases/latest | jq -r .tag_name | tr -d v)
echo "blackbox_exporter resolved to ${BB_VER} on $(date -u +%F)"   # record this
cd /tmp
wget "https://github.com/prometheus/blackbox_exporter/releases/download/v${BB_VER}/blackbox_exporter-${BB_VER}.linux-amd64.tar.gz"
tar -xzf "blackbox_exporter-${BB_VER}.linux-amd64.tar.gz"
install -m0755 "blackbox_exporter-${BB_VER}.linux-amd64/blackbox_exporter" /usr/local/bin/blackbox_exporter
useradd -r -s /usr/sbin/nologin blackbox
mkdir -p /etc/blackbox_exporter
```

`/etc/blackbox_exporter/blackbox.yml`. The DoH query string is the RFC 8484 §4.1 example: base64url of a wire-format query for `www.example.com A` with message ID 0.

```yaml
modules:
  # Warm name: should be served from Unbound's cache. Measures the fast path.
  dns_udp_warm:
    prober: dns
    timeout: 3s
    dns:
      query_name: example.com
      query_type: A
      transport_protocol: udp
      preferred_ip_protocol: ip4
      ip_protocol_fallback: false
      valid_rcodes: [NOERROR]

  dns_tcp_warm:
    prober: dns
    timeout: 5s
    dns:
      query_name: example.com
      query_type: A
      transport_protocol: tcp
      preferred_ip_protocol: ip4
      ip_protocol_fallback: false
      valid_rcodes: [NOERROR]

  # DNSSEC positive control: a signed name that must validate.
  dns_dnssec_ok:
    prober: dns
    timeout: 5s
    dns:
      query_name: sigok.verteiltesysteme.net
      query_type: A
      transport_protocol: udp
      preferred_ip_protocol: ip4
      valid_rcodes: [NOERROR]

  # DNSSEC negative control: a deliberately broken signature.
  # A validating resolver MUST return SERVFAIL. NOERROR here means validation
  # is off or has been routed around -- see Phase C.
  dns_dnssec_fail:
    prober: dns
    timeout: 5s
    dns:
      query_name: sigfail.verteiltesysteme.net
      query_type: A
      transport_protocol: udp
      preferred_ip_protocol: ip4
      valid_rcodes: [SERVFAIL]

  doh_get:
    prober: http
    timeout: 5s
    http:
      method: GET
      valid_status_codes: [200]
      preferred_ip_protocol: ip4
      ip_protocol_fallback: false
      fail_if_header_not_matches:
        - header: Content-Type
          regexp: application/dns-message

  # Connectivity + certificate only. This does NOT prove DNS resolution over
  # TLS; I4b does that. Its job is probe_ssl_earliest_cert_expiry.
  tls_connect:
    prober: tcp
    timeout: 5s
    tcp:
      tls: true
      preferred_ip_protocol: ip4
      ip_protocol_fallback: false
```

Two honest caveats. First, `sigok`/`sigfail.verteiltesysteme.net` are third-party test zones; if either is retired the corresponding alert fires spuriously. Confirm the zone by hand before believing a DNSSEC alert. Second, blackbox rejects an unknown configuration key **fatally at startup**, so a version that does not support one of the fields above will refuse to start rather than silently ignoring it — that is the check, and it is why there is no separate "does this key exist" step.

```ini
# /etc/systemd/system/blackbox_exporter.service
[Unit]
Description=Prometheus blackbox exporter
After=network-online.target

[Service]
User=blackbox
Group=blackbox
ExecStart=/usr/local/bin/blackbox_exporter \
  --config.file=/etc/blackbox_exporter/blackbox.yml \
  --web.listen-address=127.0.0.1:9115
Restart=on-failure
RestartSec=5
MemoryMax=128M
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Append the scrape jobs to `/etc/prometheus/prometheus.yml`. Replace `dns.example.com` throughout with your hostname.

```yaml
  - job_name: blackbox-dns
    metrics_path: /probe
    scrape_interval: 30s
    params:
      module: [dns_udp_warm]
    static_configs:
      - targets: ['127.0.0.1:53']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115

  - job_name: blackbox-dns-tcp
    metrics_path: /probe
    scrape_interval: 60s
    params:
      module: [dns_tcp_warm]
    static_configs:
      - targets: ['127.0.0.1:53']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115

  - job_name: blackbox-dnssec
    metrics_path: /probe
    scrape_interval: 5m
    params:
      module: [dns_dnssec_ok]
    static_configs:
      - targets: ['127.0.0.1:53']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115

  - job_name: blackbox-dnssec-fail
    metrics_path: /probe
    scrape_interval: 5m
    params:
      module: [dns_dnssec_fail]
    static_configs:
      - targets: ['127.0.0.1:53']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115

  - job_name: blackbox-doh
    metrics_path: /probe
    scrape_interval: 60s
    params:
      module: [doh_get]
    static_configs:
      - targets:
          - 'https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB'
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115

  - job_name: blackbox-tls
    metrics_path: /probe
    scrape_interval: 5m
    params:
      module: [tls_connect]
    static_configs:
      - targets:
          - 'dns.example.com:443'
          - 'dns.example.com:853'
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115
```

**The caveat that makes these probes weaker than they look.** Every probe above originates on the box. A packet addressed to your own public IP is routed over `lo`, so it hits Phase B's `iif lo accept` and never traverses the public input chain. These probes prove the *daemon and its TLS material* are healthy; they do **not** prove the service is reachable from the internet. Only an off-box check does that — see I9, which is why I9 exists in addition to, not instead of, this section.

#### I4b. DoT and DoQ resolution probes

`dnslookup` (AdGuardTeam) speaks `tls://`, `quic://` and `https://` and returns a non-zero exit status on failure, which is all the probe needs. Install it and record the resolved version alongside blackbox_exporter's:

```bash
DL_VER=$(curl -fsS https://api.github.com/repos/ameshkov/dnslookup/releases/latest | jq -r .tag_name | tr -d v)
echo "dnslookup resolved to ${DL_VER} on $(date -u +%F)"   # record this
cd /tmp
wget "https://github.com/ameshkov/dnslookup/releases/download/v${DL_VER}/dnslookup-linux-amd64-${DL_VER}.tar.gz"
tar -xzf "dnslookup-linux-amd64-${DL_VER}.tar.gz"
install -m0755 linux-amd64/dnslookup /usr/local/bin/dnslookup
# Confirm the invocation by hand ONCE before trusting the probe:
dnslookup example.com tls://dns.example.com && echo DOT_OK
dnslookup example.com quic://dns.example.com && echo DOQ_OK
```

`/usr/local/sbin/dns-probe-textfile`:

```bash
#!/bin/bash
# Encrypted-transport probes + directory sizes -> node_exporter textfile.
# Deliberately shell, not Python: the whole point is to exercise the real client
# binary, and a non-zero exit is the entire signal.
set -u
OUT=/var/lib/node_exporter/textfile/dnsprobe.prom
TMP="${OUT}.tmp"
HOST=dns.example.com
: > "$TMP"

echo '# TYPE dnsprobe_success gauge'          >> "$TMP"
echo '# TYPE dnsprobe_duration_seconds gauge' >> "$TMP"

probe() {   # probe <label> <server-uri>
  local proto="$1" uri="$2" t0 t1 rc
  t0=$(date +%s.%N)
  timeout 8 dnslookup example.com "$uri" >/dev/null 2>&1; rc=$?
  t1=$(date +%s.%N)
  printf 'dnsprobe_success{proto="%s"} %d\n' "$proto" "$([ $rc -eq 0 ] && echo 1 || echo 0)" >> "$TMP"
  printf 'dnsprobe_duration_seconds{proto="%s"} %s\n' "$proto" \
    "$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.4f", b-a}')" >> "$TMP"
}

probe dot  "tls://${HOST}"
probe doq  "quic://${HOST}"
probe doh  "https://${HOST}/dns-query"

# Directory sizes: the query log and the TSDB are the two things that grow.
echo '# TYPE dns_dir_bytes gauge' >> "$TMP"
for d in /var/log/adguardhome /var/lib/prometheus /var/lib/adguardhome; do
  [ -d "$d" ] || continue
  printf 'dns_dir_bytes{dir="%s"} %s\n' "$d" "$(du -sb "$d" 2>/dev/null | cut -f1)" >> "$TMP"
done

chmod 0644 "$TMP"; mv "$TMP" "$OUT"
```

```ini
# /etc/systemd/system/dns-probe-textfile.service
[Unit]
Description=Encrypted DNS transport probes to node_exporter textfile
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dns-probe-textfile
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/node_exporter/textfile
```

```ini
# /etc/systemd/system/dns-probe-textfile.timer
[Unit]
Description=Run encrypted DNS probes every 60s
[Timer]
OnBootSec=120s
OnUnitActiveSec=60s
AccuracySec=10s
[Install]
WantedBy=timers.target
```

```bash
chmod 0755 /usr/local/sbin/unbound-textfile /usr/local/sbin/agh-textfile /usr/local/sbin/dns-probe-textfile
systemctl daemon-reload
systemctl enable --now blackbox_exporter \
  unbound-textfile.timer agh-textfile.timer dns-probe-textfile.timer
```

If Phase P puts the resolver behind WireGuard or an nftables allowlist, these probes must run **inside** the access path or they will report a permanent outage. That is a Phase P delta, not a Phase I one.

### I5. Abuse counters

Phase B defines the nftables ban sets, meters and counters — `banned_ips`, `banned_ips6`, `banned_long`, `banned_long6`, `floodmeter4`, `floodmeter6`, `dns_dropped`, `dns_banned`, all inside `table inet filter`. Phase J ships `/usr/local/sbin/nft-abuse-textfile`, which reads those objects and writes `nft_dns_dropped_packets`, `nft_dns_banned_packets` and `nft_banned_ips_elements` into the same textfile directory. Phase I only consumes them (I6 alerts, I7 SLO corroboration). Do not duplicate the exporter here.

### I6. Alert rules

Write the whole file. Do not append fragments — a bare `- alert:` with no `groups:`/`rules:` wrapper makes Prometheus refuse to load the entire file, which silently disables every rule including the Watchdog.

Thresholds below assume a small public resolver doing tens to low hundreds of QPS. Re-derive the two QPS bounds and the disk predictor against your own first fortnight of data before treating them as ground truth; everything else is scale-independent.

```yaml
# /etc/prometheus/rules/dns.yml
groups:
  # ---------------------------------------------------------------- pipeline
  - name: pipeline
    rules:
      # The dead man's switch. Always firing, routed off-box. Its ABSENCE is
      # the signal; see I9. Never add an `for:` or an inhibit rule to it.
      - alert: Watchdog
        expr: vector(1)
        labels:
          severity: none
        annotations:
          summary: "Alerting pipeline is alive. Absence of this alert means the pipeline is broken."

      # A stale textfile means a collector timer died. Without this, a dead
      # collector looks exactly like a healthy service with flat counters.
      - alert: CollectorStale
        expr: time() - node_textfile_mtime_seconds > 300
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Textfile collector {{ $labels.file }} is stale"
          description: "No update for >5 minutes. Metrics derived from it are frozen, not zero."

      - alert: TextfileScrapeError
        expr: node_textfile_scrape_error != 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "node_exporter cannot parse a textfile"
          description: "A collector is writing malformed exposition; its metrics are absent."

      - alert: PrometheusTargetDown
        expr: up == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Scrape target {{ $labels.job }} is down"

  # ---------------------------------------------------------------- resolver
  - name: resolver
    rules:
      # The inhibit rule in I8 keys off this exact alertname. Do not rename it.
      - alert: DNSResolverDown
        expr: probe_success{job="blackbox-dns"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Do53 is not answering on 127.0.0.1:53"
          description: "AdGuardHome or Unbound is down, or the answer rcode is not NOERROR."

      - alert: UnboundDown
        expr: unbound_up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "unbound-control is unreachable"
          description: "Unbound is down or the control socket is gone. Every cache miss now fails."

      # agh_up is a REACHABILITY signal only. The collector (I3) keeps it at 1
      # whenever the control API answers, including when statistics are
      # switched off, so this alert cannot fire because of a logging policy.
      - alert: AdGuardHomeDown
        expr: agh_up == 0 or agh_running == 0
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: "AdGuard Home control API is down or not running"
          description: "The API is unreachable or AGH reports itself stopped. Statistics being disabled does NOT reach this rule -- that is AdGuardMetricsDisabledByPolicy."

      - alert: AdGuardMetricsDisabledByPolicy
        expr: agh_metrics_unavailable_by_policy == 1
        for: 15m
        labels:
          severity: info
        annotations:
          summary: "AdGuard Home statistics are off; AGH window metrics are absent by policy"
          description: >-
            Informational, deliberately not a page. agh_queries_window_total and
            its siblings are absent rather than zero, and every Unbound-sourced
            alert is unaffected -- see the posture table in I3. Confirm this is
            the Phase Q posture you chose and not a Phase E config-migration
            regression; I11 step 4 is what distinguishes the two.

      - alert: EncryptedTransportDown
        expr: dnsprobe_success == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.proto | toUpper }} is not resolving"
          description: >-
            Plain DNS can be perfectly healthy while this is broken. Usual causes:
            a certificate that renewed but was never copied to AGH (Phase D),
            an nginx reload that lost the /dns-query location (Phase E), or a
            DoQ listener that did not rebind after restart.

      - alert: DoHDown
        expr: probe_success{job="blackbox-doh"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "DoH endpoint is not returning application/dns-message"

      - alert: DNSSECValidationBroken
        expr: probe_success{job="blackbox-dnssec-fail"} == 0
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "A deliberately-bogus name did NOT return SERVFAIL"
          description: >-
            Validation is off or something is routing around Unbound. Check
            Phase C's trust anchor and Phase E's fallback_dns (must be empty).
            Confirm the test zone still exists before acting.

      - alert: DNSSECPositiveControlFailing
        expr: probe_success{job="blackbox-dnssec"} == 0
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "A correctly-signed name is not resolving"
          description: "Stale or empty root.key SERVFAILs everything. See Phase C."

      - alert: ServfailRateHigh
        expr: >-
          rate(unbound_num_answer_rcode_SERVFAIL[10m])
            / clamp_min(rate(unbound_total_num_queries[10m]), 0.001) > 0.05
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "SERVFAIL ratio above 5% for 15 minutes"
          description: "Value {{ $value | humanizePercentage }}. Upstream reachability, trust anchor, or a broken zone under heavy query."

      - alert: ValidationFailuresRising
        expr: rate(unbound_num_rrset_bogus[15m]) > 0.05
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Unbound is rejecting bogus RRsets at >3/minute"
          description: "Either a genuinely broken signed zone, or someone is attempting cache poisoning. Working as designed; worth looking at."

      - alert: RecursionStalled
        expr: >-
          rate(unbound_total_num_queries[15m]) > 0.1
            and rate(unbound_total_num_recursivereplies[15m]) == 0
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "Queries arriving but no recursive replies completing"
          description: "Root/TLD reachability is gone (egress blocked, upstream network fault). Cache will drain and the service dies gradually."

      - alert: RequestListExceeded
        expr: rate(unbound_total_requestlist_exceeded[10m]) > 0.1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Unbound is dropping queries because its request list is full"
          description: "Recursion is slower than arrival rate. See Phase C for num-queries-per-thread / outgoing-range."

      - alert: CacheHitRatioCollapsed
        expr: >-
          (rate(unbound_total_num_cachehits[30m])
            / clamp_min(rate(unbound_total_num_queries[30m]), 0.001)) < 0.5
            and rate(unbound_total_num_queries[30m]) > 1
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Cache hit ratio below 50% for 30 minutes"
          description: >-
            Value {{ $value | humanizePercentage }}. Either the cache was
            flushed/restarted, prefetch is off (Phase C), or you are being used
            as a random-subdomain (water-torture) amplifier -- correlate with
            nft_dns_dropped_packets and Phase J.

  # --------------------------------------------------------------- traffic
  - name: traffic
    rules:
      - alert: QPSSpike
        expr: dns:qps:rate5m > 2000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Query rate {{ $value | printf \"%.0f\" }}/s, far above normal"
          description: "Flood, reflection attempt, or a client in a retry loop. See Phase J before widening any limit."

      - alert: QPSCollapsed
        expr: >-
          dns:qps:rate5m < 0.2 * dns:qps:rate1d
            and dns:qps:rate1d > 1
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Query rate fell to under 20% of its daily average"
          description: >-
            The dangerous direction: the box is up, the probes pass, and real
            clients have stopped arriving. Firewall change, provider null-route,
            DNS delegation problem, or an accidental Phase P allowlist.

      - alert: RecursionLatencyP99High
        expr: >-
          histogram_quantile(0.99,
            sum by (le) (rate(unbound_recursion_time_seconds_bucket[10m]))) > 1
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "p99 recursion time above 1s"
          description: "Value {{ $value | printf \"%.2f\" }}s. Cache misses are slow; upstream network or root reachability."

      - alert: CachedLatencyP99High
        expr: >-
          quantile_over_time(0.99,
            probe_duration_seconds{job="blackbox-dns"}[30m]) > 0.05
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "p99 cached-answer latency above 50ms"
          description: "A cache hit should be sub-millisecond. This is CPU starvation, swap, or a stalled event loop."

  # ------------------------------------------------------------------- tls
  - name: tls
    rules:
      - alert: CertExpiringSoon
        expr: (probe_ssl_earliest_cert_expiry - time()) / 86400 < 14
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.instance }} certificate expires in {{ $value | printf \"%.1f\" }} days"
          description: "Renewal should have happened at 30 days. Check the Phase D deploy hook -- renewal succeeding while the copy-to-AGH step fails is the common failure."

      - alert: CertExpiringCritical
        expr: (probe_ssl_earliest_cert_expiry - time()) / 86400 < 5
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.instance }} certificate expires in under 5 days"
          description: "Every DoT/DoH/DoQ client fails hard at expiry. Fix now, do not wait for the next renewal window."

  # ------------------------------------------------------------- host/capacity
  - name: host
    rules:
      - alert: DiskWillFill
        expr: >-
          predict_linear(node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay"}[6h], 72*3600) < 0
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Root filesystem projected full within 72 hours"
          description: "Usual suspects: AGH query log, Prometheus TSDB, journald. Check dns_dir_bytes."

      - alert: DiskLow
        expr: >-
          node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay"}
            / node_filesystem_size_bytes{mountpoint="/",fstype!~"tmpfs|overlay"} < 0.15
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "Less than 15% of root filesystem free"

      - alert: InodesLow
        expr: >-
          node_filesystem_files_free{mountpoint="/",fstype!~"tmpfs|overlay"}
            / node_filesystem_files{mountpoint="/",fstype!~"tmpfs|overlay"} < 0.15
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Less than 15% of inodes free"
          description: "A disk with free bytes and no inodes fails writes in ways that read as corruption."

      - alert: QueryLogGrowing
        expr: dns_dir_bytes{dir="/var/log/adguardhome"} > 4e9
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "AdGuard Home query log exceeds 4 GB"
          description: >-
            Retention is 2x querylog.interval -- the file is RENAMED to
            querylog.json.1, not deleted. At Phase E's shipped 6h interval this
            should never fire, so if it does, check that the interval actually
            survived the config migration before blaming traffic. Phase Q's
            retention decision changes the expected size, not this threshold.

      - alert: MemoryLow
        expr: node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes < 0.10
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Less than 10% memory available"
          description: "Unbound's caches plus Prometheus. The unbound and AdGuard Home memory ceilings live in Phase A6 and nowhere else; check them there before raising any cache size."

      - alert: OOMKillOccurred
        # Present when the kernel exposes oom_kill in /proc/vmstat (it does on
        # the 6.8 kernel Ubuntu 24.04 ships). Absent kernels yield no series.
        expr: increase(node_vmstat_oom_kill[15m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "The kernel OOM-killed a process in the last 15 minutes"
          description: "Find out which one before assuming the service recovered."

      - alert: ServiceInactive
        expr: >-
          node_systemd_unit_state{name=~"unbound.service|adguardhome.service|nginx.service",state="active"} == 0
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.name }} is not active"

      - alert: ServiceFlapping
        expr: >-
          changes(node_systemd_unit_state{name=~"unbound.service|adguardhome.service|nginx.service",state="active"}[1h]) > 5
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.name }} restarted more than 5 times in an hour"
          description: "Restart=always with a StartLimitBurst of 10 is masking a real fault: the unit keeps coming back and the service keeps failing. See Phase N for the restart policy and Phase C for the unit itself."

      - alert: ConntrackFilling
        expr: node_nf_conntrack_entries / node_nf_conntrack_entries_limit > 0.7
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "conntrack table above 70%"
          description: >-
            UDP/53 is NOTRACK'd by Phase B's rule in `table inet raw` -- the
            only place `notrack` is legal, because it is valid solely at the
            raw hook -- so this should stay low. A rise means the notrack
            rule is gone or a reload dropped it. The conntrack sysctls
            themselves are Phase A's. When this table fills, SSH dies with DNS.

  # ------------------------------------------------------------------ abuse
  - name: abuse
    rules:
      - alert: AbuseBansActive
        expr: increase(nft_dns_banned_packets[10m]) > 0
        labels:
          severity: info
        annotations:
          summary: "The auto-ban fired in the last 10 minutes"
          description: "Informational. See Phase J for review and false-positive handling."

      - alert: BanSetLarge
        expr: nft_banned_ips_elements > 50
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "{{ $value }} addresses currently banned"
          description: >-
            Either a distributed flood or a spoofed-source run steering the ban
            set at your own users. Read Phase J8 before widening anything.
```

### I7. Recording rules, SLIs and SLOs

Recording rules define each ratio once, keep the alert expressions readable, and make the 30-day SLO queries cheap enough to run interactively.

```yaml
# /etc/prometheus/rules/slo.yml
groups:
  - name: sli
    interval: 30s
    rules:
      - record: dns:qps:rate5m
        expr: rate(unbound_total_num_queries[5m])

      - record: dns:qps:rate1d
        expr: avg_over_time(dns:qps:rate5m[1d])

      - record: dns:cache_hit_ratio:rate30m
        expr: >-
          rate(unbound_total_num_cachehits[30m])
            / clamp_min(rate(unbound_total_num_queries[30m]), 0.001)

      - record: dns:servfail_ratio:rate10m
        expr: >-
          rate(unbound_num_answer_rcode_SERVFAIL[10m])
            / clamp_min(rate(unbound_total_num_queries[10m]), 0.001)

      # Availability SLI, per protocol, as a 0/1 series that can be averaged
      # over any window. Do53 comes from blackbox, DoT/DoQ/DoH from I4b.
      - record: dns:availability:do53
        expr: min without (job, module) (probe_success{job="blackbox-dns"})

      - record: dns:availability:encrypted
        expr: min without (proto) (dnsprobe_success)
```

| SLI | Definition | How measured | SLO target | Error budget |
|---|---|---|---|---|
| Do53 availability | fraction of 30 s probes returning NOERROR | `avg_over_time(dns:availability:do53[30d])` | **99.9%** | 43m 12s / 30d |
| Encrypted-transport availability | fraction of 60 s probes where **all** of DoT/DoQ/DoH succeed | `avg_over_time(dns:availability:encrypted[30d])` | **99.5%** | 3h 36m / 30d |
| Cached-answer latency | p99 of the warm blackbox probe | `quantile_over_time(0.99, probe_duration_seconds{job="blackbox-dns"}[30d])` | **< 20 ms** | n/a (threshold SLO) |
| Cache-miss latency | p99 of Unbound recursion time | `histogram_quantile(0.99, sum by (le) (rate(unbound_recursion_time_seconds_bucket[30d])))` | **< 500 ms** | n/a |
| Correctness | fraction of 5 min DNSSEC negative probes returning SERVFAIL | `avg_over_time(probe_success{job="blackbox-dnssec-fail"}[30d])` | **100%** | zero — any failure is an incident |
| Error rate | SERVFAIL as a share of all answers | `avg_over_time(dns:servfail_ratio:rate10m[30d])` | **< 0.5%** | n/a |
| Cache effectiveness | cache hits as a share of queries | `avg_over_time(dns:cache_hit_ratio:rate30m[30d])` | **> 80%** | n/a (capacity signal, not user-facing) |

Two honest limits on these numbers. The availability SLIs are measured **on the box**, so they exclude every failure mode where the box is fine and the network is not; the true availability number is the on-box figure ANDed with the external checker's uptime from I9, and the external checker is the binding one. And the encrypted-transport SLO is deliberately looser than Do53 because it depends on certificate lifecycle, which has a scheduled failure mode that Do53 does not.

The error-budget rule that makes these worth writing down: **if the 30-day Do53 budget is more than half consumed, no non-security change ships** until the budget recovers — no filter-list churn, no cache tuning, no version bumps beyond the security ones from Phase M.

### I8. Alertmanager and the path to a phone

```bash
AM_VER=0.33.1   # verified: prometheus/alertmanager CHANGELOG.md, "0.33.1 / 2026-07-04"
cd /tmp
wget "https://github.com/prometheus/alertmanager/releases/download/v${AM_VER}/alertmanager-${AM_VER}.linux-amd64.tar.gz"
tar -xzf "alertmanager-${AM_VER}.linux-amd64.tar.gz"
install -m0755 "alertmanager-${AM_VER}.linux-amd64/alertmanager" /usr/local/bin/alertmanager
install -m0755 "alertmanager-${AM_VER}.linux-amd64/amtool"       /usr/local/bin/amtool
useradd -r -s /usr/sbin/nologin -d /var/lib/alertmanager alertmanager
mkdir -p /etc/alertmanager /var/lib/alertmanager
chown alertmanager:alertmanager /var/lib/alertmanager
```

`/etc/alertmanager/alertmanager.yml` — every key verified against `docs/configuration.md` at tag v0.33.1:

```yaml
global:
  resolve_timeout: 5m

route:
  receiver: ntfy
  group_by: ['alertname', 'instance']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    # Dead man's switch: leaves the box every 2 minutes, forever.
    # First match wins, so Watchdog never reaches the phone receiver.
    - receiver: heartbeat
      matchers:
        - alertname = "Watchdog"
      group_wait: 0s
      group_interval: 2m
      repeat_interval: 2m
    # Criticals re-nag every 30m instead of every 4h.
    - receiver: ntfy
      matchers:
        - severity = "critical"
      repeat_interval: 30m

inhibit_rules:
  # If the resolver is down, do not also page about latency and cache ratio.
  - source_matchers: [ 'alertname = "DNSResolverDown"' ]
    target_matchers: [ 'severity =~ "warning|info"' ]
    equal: ['instance']

receivers:
  - name: ntfy
    webhook_configs:
      - url: http://127.0.0.1:9095/
        send_resolved: true
        max_alerts: 20

  - name: heartbeat
    webhook_configs:
      # See I9. Set the check period to 2m and the grace period to 15m.
      - url: https://hc-ping.com/REPLACE-WITH-YOUR-UUID
        send_resolved: false
```

Alertmanager's webhook payload is raw JSON, and ntfy renders the POST body as the message text, so a bridge is needed to get a readable push. `/usr/local/sbin/alertmanager-ntfy`, Python stdlib only, no Docker and no Go toolchain. **The bridge must return non-2xx when the push fails**: Alertmanager treats 2xx as delivered and never retries, so a 200 on a failed push turns a transient ntfy outage into a permanently dropped page — precisely the silent failure this whole phase exists to eliminate.

```python
#!/usr/bin/env python3
"""Alertmanager webhook -> ntfy bridge. Python stdlib only."""
import json, os, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NTFY  = os.environ.get("NTFY_URL", "https://ntfy.sh/CHANGE-ME-to-a-long-random-topic")
TOKEN = os.environ.get("NTFY_TOKEN", "")
PRIO  = {"critical": "urgent", "warning": "high", "info": "default"}
TAGS  = {"critical": "rotating_light", "warning": "warning", "info": "information_source"}

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._reply(400, b"bad json"); return

        failed = 0
        for a in payload.get("alerts", []):
            lbl, ann = a.get("labels", {}), a.get("annotations", {})
            sev, status = lbl.get("severity", "info"), a.get("status", "firing")
            title = "[%s] %s (%s)" % (status.upper(),
                                      lbl.get("alertname", "alert"),
                                      lbl.get("instance") or lbl.get("host") or "-")
            body = ann.get("description") or ann.get("summary") or json.dumps(lbl)
            req = urllib.request.Request(NTFY, data=body.encode(), method="POST")
            req.add_header("Title", title)
            req.add_header("Priority",
                           "min" if status == "resolved" else PRIO.get(sev, "default"))
            req.add_header("Tags",
                           "white_check_mark" if status == "resolved"
                           else TAGS.get(sev, "bell"))
            if TOKEN:
                req.add_header("Authorization", "Bearer " + TOKEN)
            try:
                urllib.request.urlopen(req, timeout=10).read()
            except Exception as exc:                       # noqa: BLE001
                failed += 1
                print("ntfy push failed: %s" % exc, flush=True)

        # Non-2xx makes Alertmanager retry. Never claim success on a failed push.
        if failed:
            self._reply(502, b"ntfy push failed")
        else:
            self._reply(200, b"ok")

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 9095), Handler).serve_forever()
```

```bash
chmod 0755 /usr/local/sbin/alertmanager-ntfy
```

`--cluster.listen-address=` is **required, not cosmetic**: Alertmanager's default is `0.0.0.0:9094` (TCP and UDP) for HA gossip. On a single-node install that is pointless listener surface on the public interface, saved only by Phase B's default-drop policy.

```ini
# /etc/systemd/system/alertmanager.service
[Unit]
Description=Prometheus Alertmanager
After=network-online.target
Wants=network-online.target

[Service]
User=alertmanager
Group=alertmanager
ExecStart=/usr/local/bin/alertmanager \
  --config.file=/etc/alertmanager/alertmanager.yml \
  --storage.path=/var/lib/alertmanager \
  --web.listen-address=127.0.0.1:9093 \
  --cluster.listen-address=
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
MemoryMax=128M
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/alertmanager

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/alertmanager-ntfy.service
[Unit]
Description=Alertmanager to ntfy bridge
After=network-online.target

[Service]
User=nobody
Group=nogroup
EnvironmentFile=-/etc/alertmanager/ntfy.env
ExecStart=/usr/local/sbin/alertmanager-ntfy
Restart=on-failure
RestartSec=5
MemoryMax=64M
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```bash
# /etc/alertmanager/ntfy.env -- 0600 root:root. It holds the topic, which IS
# the credential, so it must never be copied into the /opt/dns-config-backup
# staging tree (that is what the .gitignore in I3 is for). It IS inside Phase
# K's encrypted restic set, because /etc/alertmanager is in K's include list --
# encrypted off-host is where this file belongs when you rebuild the box.
install -m0600 /dev/null /etc/alertmanager/ntfy.env
cat > /etc/alertmanager/ntfy.env <<'EOF'
NTFY_URL=https://ntfy.sh/dns1-alerts-REPLACE-WITH-32-RANDOM-CHARS
NTFY_TOKEN=
EOF
systemctl daemon-reload
systemctl enable --now alertmanager alertmanager-ntfy
```

The ntfy topic name **is** the credential on the public `ntfy.sh` instance — anyone who knows it can read your alerts and publish fake ones. Use at least 32 random characters, or self-host ntfy with authentication and set `NTFY_TOKEN`. Install the ntfy app on the phone and subscribe to the topic; that is the whole notification path.

No firewall change is required, but only because 9090/9093/9095/9100/9115 bind to loopback and `--cluster.listen-address=` removes the 9094 listener entirely. Phase B's `iif lo accept` plus the default-drop input policy covers the rest. Reach the Alertmanager and Prometheus UIs over the Phase P SSH tunnel: `ssh -L 9090:127.0.0.1:9090 -L 9093:127.0.0.1:9093 dns1`.

### I8b. `notify.sh` — the one notification entry point

Alertmanager handles *conditions*: things that are true for a while, that group, that inhibit each other, and that resolve. It is the wrong tool for *events*: a backup that failed at 03:10, a certificate that deployed, an upgrade that rolled back, a health check that a cron job just ran. Those have no duration to group over, and — decisively — several of them need to reach a human precisely when Prometheus or Alertmanager is the broken thing.

So there is one script, defined here, that every other phase calls instead of writing its own `curl` to ntfy. Phase D calls it from the certificate deploy hook, Phase K from the backup job, Phase L from the verification run, Phase M from the upgrade procedure. **Phase I defines it; other phases call it and say so.** One script means one credential, one topic, one place to change the transport, and one audit trail in journald under a single tag.

**The signature is canonical and every caller in every phase must match it exactly:**

```
notify.sh <severity> <title> [message]
```

Three positional arguments in that order: severity first (`info` | `warning` | `critical`), title second, message optional and third. This matters because the script cannot detect a caller that gets it wrong. A single-argument call — `notify.sh "backup failed"` — parses that string as the *severity*, falls through the `case` to the `info` default, then takes `dns1` as the title and the title as the message: the real message is lost and the page arrives at the wrong priority, silently, on the day it mattered. A message with spaces needs quoting; anything after the title is joined into the body.

```bash
cat > /usr/local/sbin/notify.sh <<'EOF'
#!/bin/bash
# notify.sh <severity> <title> [message...]
#   severity: info | warning | critical   (anything else is treated as info)
#
# The single notification entry point for the whole DNS stack. Do not write a
# second one. Callers: Phase D (cert deploy), Phase I (cron health gate),
# Phase K (backup), Phase L (verification), Phase M (upgrades).
#
# Exit codes, which callers MUST NOT conflate with their own success:
#   0  logged and pushed
#   3  logged only -- no NTFY_URL configured
#   4  logged, push FAILED
set -u
SEV="${1:-info}";   shift || true
TITLE="${1:-dns1}"; shift || true
MSG="${*:-$TITLE}"

# Same credentials as the Alertmanager bridge in I8: one topic, one secret.
# shellcheck source=/dev/null
[ -r /etc/alertmanager/ntfy.env ] && . /etc/alertmanager/ntfy.env
NTFY_URL="${NTFY_URL:-}"
NTFY_TOKEN="${NTFY_TOKEN:-}"

case "$SEV" in
  critical) PRIO=urgent;  TAGS=rotating_light;       SYSLOG=err ;;
  warning)  PRIO=high;    TAGS=warning;              SYSLOG=warning ;;
  *)        SEV=info; PRIO=default; TAGS=information_source; SYSLOG=info ;;
esac

# journald FIRST and unconditionally. The local record has to exist even when
# the push fails, because the push is the part that depends on the network
# being up -- which is exactly what tends to be wrong. `journalctl -t
# dns-notify` is the notification history Phase O expects to find.
logger -t dns-notify -p "daemon.$SYSLOG" -- "[$SEV] $TITLE: $MSG"

[ -n "$NTFY_URL" ] || { echo "notify.sh: NTFY_URL unset; logged only" >&2; exit 3; }

if curl -fsS --max-time 10 \
     -H "Title: $TITLE" -H "Priority: $PRIO" -H "Tags: $TAGS" \
     ${NTFY_TOKEN:+-H "Authorization: Bearer $NTFY_TOKEN"} \
     -d "$MSG" "$NTFY_URL" >/dev/null
then
  exit 0
else
  logger -t dns-notify -p daemon.err -- "push FAILED for: $TITLE"
  exit 4
fi
EOF
chmod 0750 /usr/local/sbin/notify.sh
```

Mode `0750`, root-owned, because it reads `ntfy.env` (0600 root) — an unprivileged caller would get exit 3 and a journal line, not a silent no-op.

Two rules for callers. **Do not call it on a timer.** It has no deduplication and no rate limiting by design; a job that runs every minute and notifies every minute produces a channel nobody reads. Notify on state *changes* and on failures, and let Alertmanager own anything with a duration. **Do not treat a non-zero exit as your own failure.** A backup that succeeded and could not be announced is still a backup that succeeded; log the notify failure and keep your own exit status honest.

### I9. The off-box dead man's switch — required, not optional

Everything above runs on the VPS. When the VPS dies, the alerting dies with it, and a hard-down resolver produces exactly zero pages. This is the structural defect in every single-host monitoring stack and it cannot be fixed from inside the host.

The Watchdog rule inverts the logic. It fires permanently, Alertmanager routes it to an external endpoint every 2 minutes, and the **external** service alerts you when the pings stop. One mechanism covers VPS termination, kernel panic, network partition, disk-full, Prometheus OOM and Alertmanager crash.

Concrete implementation, end to end, on the free tier:

1. Create an account at healthchecks.io (free tier: 20 checks). Create one check named `dns1-watchdog`. Set **Period: 2 minutes**, **Grace: 15 minutes**. Copy its ping URL.
2. Paste that URL into the `heartbeat` receiver in I8 and `systemctl reload alertmanager`.
3. In the healthchecks project settings, add an integration for the notification channel that reaches your phone: either the ntfy integration pointed at a **different** topic than the one in I8 (a shared topic means one outage silences both paths), or email plus SMS. Send a test notification from their UI and confirm it arrives on the phone, on the lock screen, with sound.
4. Add a second, independent external check that does not depend on your box's software at all: UptimeRobot's free tier with a **Port** monitor on `dns.example.com:853`, 5-minute interval. Healthchecks catches "the box stopped talking"; UptimeRobot catches "the box talks to itself but the internet cannot reach it" — the case every probe in I4 is blind to.

Equivalent substitutions, in preference order if you already own a second host: self-hosted `healthchecks`, or Uptime Kuma (which does both the push heartbeat and the external port check in one tool). What is **not** acceptable is running the checker on the same VPS, on the same provider's network in the same region, or skipping it because it needs an external account. Without it, the monitoring stack's single point of failure is the thing being monitored.

Record both external services, their credentials location, and the phone numbers/emails they notify in the Phase O inventory. An external dependency nobody documented is an external dependency that silently lapses.

### I10. `dns-health` — the single operator script

One command, run by a human before and after every change, and by the Phase L checklist. It reports; it does not fix. Exit status 0 means everything passed.

```bash
cat > /usr/local/sbin/dns-health <<'EOF'
#!/bin/bash
# Read-only health summary. Exit 0 = all green.
FAIL=0
HOST=dns.example.com
say()  { printf '%-42s %s\n' "$1" "$2"; }
ok()   { say "$1" "OK   $2"; }
bad()  { say "$1" "FAIL $2"; FAIL=1; }
chk()  { if eval "$2" >/dev/null 2>&1; then ok "$1" "${3:-}"; else bad "$1" "${3:-}"; fi; }

echo "== units =="
for u in unbound adguardhome nginx prometheus alertmanager alertmanager-ntfy \
         node_exporter blackbox_exporter nftables; do
  chk "$u" "systemctl is-active --quiet $u"
done
for t in unbound-textfile.timer agh-textfile.timer dns-probe-textfile.timer; do
  chk "$t" "systemctl is-active --quiet $t"
done

echo "== resolution =="
chk "Do53 udp"      "dig @127.0.0.1 example.com A +time=2 +tries=1 +short"
chk "Do53 tcp"      "dig +tcp @127.0.0.1 example.com A +time=2 +tries=1 +short"
chk "Unbound direct" "dig @127.0.0.1 -p 5335 example.com A +time=2 +tries=1 +short"
chk "DoT"           "timeout 8 dnslookup example.com tls://$HOST"
chk "DoQ"           "timeout 8 dnslookup example.com quic://$HOST"
chk "DoH"           "timeout 8 dnslookup example.com https://$HOST/dns-query"

echo "== correctness =="
if dig @127.0.0.1 sigok.verteiltesysteme.net A +dnssec +time=3 | grep -q '^;;.*flags:.* ad'; then
  ok "DNSSEC AD bit on signed name"
else
  bad "DNSSEC AD bit on signed name" "validation is not happening"
fi
if [ "$(dig @127.0.0.1 sigfail.verteiltesysteme.net A +time=3 +tries=1 \
        | awk '/^;; ->>HEADER<<-/{print $6}')" = "SERVFAIL" ]; then
  ok "DNSSEC bogus name SERVFAILs"
else
  bad "DNSSEC bogus name SERVFAILs" "validation bypassed -- see Phase C/E"
fi

echo "== exposure =="
if ss -lntup | grep -qE '(0\.0\.0\.0|\*|\[::\]):(3000|5335|9090|9093|9094|9095|9100|9115)\b'; then
  bad "loopback-only services" "something is bound to a public address"
else
  ok "loopback-only services"
fi

echo "== capacity =="
df -h / | awk 'NR==2{printf "%-42s %s used, %s free\n","disk /",$5,$4}'
df -i / | awk 'NR==2{printf "%-42s %s inodes used\n","inodes /",$5}'
free -m | awk '/^Mem:/{printf "%-42s %s MB available\n","memory",$7}'
printf '%-42s %s\n' "banned addresses" \
  "$(nft list set inet filter banned_ips 2>/dev/null | grep -c 'timeout')"

echo "== monitoring =="
chk "prometheus healthy"  "curl -sf 127.0.0.1:9090/-/healthy"
chk "alertmanager healthy" "curl -sf 127.0.0.1:9093/-/healthy"
DOWN=$(curl -sf --get 127.0.0.1:9090/api/v1/query \
  --data-urlencode 'query=up==0' | jq -r '.data.result | length')
[ "${DOWN:-1}" = "0" ] && ok "all scrape targets up" || bad "scrape targets" "$DOWN down"
FIRING=$(curl -sf 127.0.0.1:9093/api/v2/alerts \
  | jq -r '[.[] | select(.labels.alertname!="Watchdog")] | length')
printf '%-42s %s\n' "alerts firing (excl. Watchdog)" "${FIRING:-?}"
chk "watchdog rule loaded" "curl -sf 127.0.0.1:9090/api/v1/rules | grep -q Watchdog"

echo "== tls =="
for p in 443 853; do
  END=$(echo | openssl s_client -connect "$HOST:$p" -servername "$HOST" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  if [ -n "$END" ]; then
    DAYS=$(( ($(date -d "$END" +%s) - $(date +%s)) / 86400 ))
    [ "$DAYS" -gt 14 ] && ok "cert :$p" "${DAYS}d left" || bad "cert :$p" "${DAYS}d left"
  else
    bad "cert :$p" "no certificate returned"
  fi
done

echo
[ $FAIL -eq 0 ] && echo "ALL CHECKS PASSED" || echo "FAILURES PRESENT -- see above"
exit $FAIL
EOF
chmod 0755 /usr/local/sbin/dns-health
```

`dns-health` is the pre-flight and post-flight gate, not a monitor: it runs when a human runs it. The alert rules are the monitor. Phase H owns the deeper one-time validation suite; do not duplicate it here.

**`/etc/cron.d/dns-health` — created here, appended to by others.** One scheduled run a day exists for a narrow reason: `dns-health` checks a handful of things the Prometheus rules deliberately do not, such as the DNSSEC AD bit and the loopback-only bind audit, and a daily pass means a regression in those is caught within 24 hours instead of at the next change. It is not a substitute for the alert rules and must never grow into one.

**Phase I creates this file. Other phases append their own lines to it and say so** — Phase D for certificate checks, Phase K for the backup job, Phase M for upgrade checks. Nobody rewrites it wholesale; a phase that replaces the file silently deletes the other phases' schedules.

```bash
cat > /etc/cron.d/dns-health <<'EOF'
# Scheduled jobs for the DNS stack. CREATED BY PHASE I.
# Other phases APPEND lines below and note it in their own section; never
# rewrite this file. The filename must contain no dot -- cron silently ignores
# files in /etc/cron.d whose names look like they carry an extension.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=""

# Daily health gate. Only a FAILURE notifies: a message that arrives every
# morning whether or not anything is wrong is a message that stops being read.
17 6 * * * root /usr/local/sbin/dns-health > /var/log/dns-health.last 2>&1 || /usr/local/sbin/notify.sh critical "dns-health FAILED on dns1" "$(grep FAIL /var/log/dns-health.last | head -20)"
EOF
chmod 0644 /etc/cron.d/dns-health
chown root:root /etc/cron.d/dns-health
```

`MAILTO=""` is deliberate: without it cron mails output to root on a box with no MTA, and the failure path becomes a mail spool nobody opens. The notification path is `notify.sh` (I8b) and nothing else. Cron picks up changes to `/etc/cron.d` without a restart; a syntax error in a line, however, is only visible in `journalctl -u cron`, so check it after appending.

### I11. Phase I verification

```bash
# 1. Everything parses BEFORE anything restarts.
promtool check config /etc/prometheus/prometheus.yml
promtool check rules  /etc/prometheus/rules/*.yml
amtool check-config   /etc/alertmanager/alertmanager.yml

# 2. Collectors produce valid exposition.
/usr/local/sbin/unbound-textfile && /usr/local/sbin/agh-textfile && /usr/local/sbin/dns-probe-textfile
for f in /var/lib/node_exporter/textfile/*.prom; do
  echo "--- $f"; promtool check metrics < "$f" && echo "PARSE OK"
done

# 3. Which unbound keys does THIS build actually emit? Any alert referencing a
#    key absent from this list is dead code that will never fire.
unbound-control stats_noreset | cut -d= -f1 | sort
grep -o 'unbound_[a-zA-Z0-9_]*' /etc/prometheus/rules/*.yml | sort -u
# Cross-check the two lists by hand. In particular confirm:
#   num.answer.rcode.SERVFAIL, num.rrset.bogus, total.num.recursivereplies,
#   total.requestlist.exceeded, and at least one histogram.* key.
# If histogram.* is missing, extended-statistics is not on -- fix 99-stats.conf.

# 4. AGH statistics survived the Phase E config migration. Phase E ships
#    enabled:true, so `false` here means one of exactly two things, and you
#    must know which: either the operator opted in to Phase Q's zero-log
#    posture, or the config migration ate the block. The API cannot tell them
#    apart -- you can, by checking whether anyone chose it.
AUTH=$(cat /etc/prometheus/agh-credentials)
curl -s -u "$AUTH" 127.0.0.1:3000/control/stats/config | jq '{enabled, interval, ignored_enabled}'

# 4b. Prove the disabled-statistics path DEGRADES instead of paging. Worth
#     running once even if you never intend to use the posture, because the
#     failure mode it prevents is a permanent false critical.
#     Set `statistics.enabled: false` in AdGuardHome.yaml, restart AGH, then:
/usr/local/sbin/agh-textfile
grep -E '^agh_(up|running|stats_enabled|metrics_unavailable_by_policy) ' \
  /var/lib/node_exporter/textfile/adguard.prom
# EXPECTED: agh_up 1, agh_running 1, agh_stats_enabled 0,
#           agh_metrics_unavailable_by_policy 1.
# agh_up MUST NOT be 0. A policy choice is not an outage.
grep -c '^agh_queries_window_total' /var/lib/node_exporter/textfile/adguard.prom
# EXPECTED: 0 -- absent, not zero. Then restore the setting and restart AGH.

# 5. Confirm the `recent` contract rather than guessing. Check the STATUS code:
#    a 400 body piped to jq prints "null", which looks like "no data".
for ms in 3600000 60000; do
  printf 'recent=%-8s -> HTTP %s\n' "$ms" \
    "$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" \
       "127.0.0.1:3000/control/stats?recent=$ms")"
done
# EXPECTED: 3600000 -> 200, 60000 -> 400. A 400 for 3600000 means
# statistics.interval is shorter than 1h; fix that first.

# 6. Metrics actually reach Prometheus.
curl -sf 127.0.0.1:9100/metrics | grep -E '^(agh_up|unbound_up|dnsprobe_success)'
for q in agh_up unbound_up 'dns:qps:rate5m' 'probe_success'; do
  printf '%-22s %s\n' "$q" "$(curl -sf --get 127.0.0.1:9090/api/v1/query \
    --data-urlencode "query=$q" | jq -c '.data.result | length')"
done   # each must be >= 1

# 7. Cardinality guard -- must stay well under ~5000 on this box.
curl -sf --get 127.0.0.1:9090/api/v1/query \
  --data-urlencode 'query=prometheus_tsdb_head_series' | jq -r '.data.result[0].value[1]'

# 8. systemd collector works under ProtectSystem=strict (expect > 0).
curl -sf 127.0.0.1:9100/metrics | grep -c '^node_systemd_unit_state'

# 9. Retention came from the config file, not the 15d default.
curl -sf 127.0.0.1:9090/api/v1/status/config | grep -o 'retention[^,}]*'

# 10. The 9094 gossip listener must be GONE, and nothing new is public.
ss -lntup | grep -E ':(9090|9093|9094|9095|9100|9115)\b'
# Expect 127.0.0.1 on every line and NO line for 9094 at all.
# Scanning your own public IP FROM THIS BOX routes over lo and hits Phase B's
# `iif lo accept`, so it proves nothing. Run this from a DIFFERENT host:
#   nmap -Pn -p 9090,9093,9094,9095,9100,9115 <PUBLIC_IP>   # all filtered

# 11. Watchdog is loaded and firing, not merely present on disk.
curl -sf 127.0.0.1:9090/api/v1/rules | grep -c '"name":"Watchdog"'   # must be 1
amtool --alertmanager.url=http://127.0.0.1:9093 alert query alertname=Watchdog

# 12. A real notification reaches the phone (fires, then auto-resolves).
amtool --alertmanager.url=http://127.0.0.1:9093 alert add \
  alertname=PipelineTest severity=critical instance=dns1 \
  --annotation=description='End-to-end notification test - ignore.' \
  --end="$(date -u -d '+2 min' +%Y-%m-%dT%H:%M:%SZ)"

# 13. The bridge reports failures instead of swallowing them.
NTFY_URL=http://127.0.0.1:1 curl -s -o /dev/null -w '%{http_code}\n' \
  -XPOST 127.0.0.1:9095/ -d '{"alerts":[{"status":"firing","labels":{}}]}'
# With a reachable ntfy this returns 200; with an unreachable one it MUST be 502.

# 14. THE ONE THAT MATTERS. Prove the dead man's switch. Stop Alertmanager and
#     confirm the EXTERNAL service pages your phone within its grace period.
#     If it does not, you have no monitoring -- only a dashboard.
#     Run the restore detached so an interrupted shell cannot leave AM stopped.
systemctl stop alertmanager
systemd-run --on-active=900 --unit=am-restore systemctl start alertmanager
# Do not use `journalctl -u alertmanager | grep hc-ping` to confirm the heartbeat:
# Alertmanager does not log successful notifications at the default level. The
# authoritative check is the last-ping timestamp in the external service's UI.

# 15. The shared notification entry point works, before any other phase
#     depends on it. This must reach the phone.
/usr/local/sbin/notify.sh info "notify.sh self-test" \
  "If this arrived, every phase's notifications work."; echo "exit=$?"
# exit 0 = pushed. exit 3 = NTFY_URL unset (fix ntfy.env). exit 4 = push failed.
journalctl -t dns-notify -n 5 --no-pager     # the local record must exist too

# 16. The cron file other phases append to exists and is actually loadable.
stat -c '%a %U:%G %n' /usr/local/sbin/notify.sh /etc/cron.d/dns-health
# EXPECT 0750 root:root and 0644 root:root. A cron.d filename containing a dot
# is silently ignored by cron, so confirm the name is exactly `dns-health`.
grep -c '^[0-9*]' /etc/cron.d/dns-health     # >= 1 scheduled line
journalctl -u cron --since '-5 min' | grep -i 'dns-health' || true   # no parse errors

# 17. The operator script agrees.
/usr/local/sbin/dns-health; echo "exit=$?"
```

---

## PHASE J: Abuse Detection and Response

### J1. Why the v1 query-log cron is deleted outright

The v1 Phase J2 shipped `abuse-check.sh`: tail AGH's `querylog.json`, count `.IP` values, ban anything over a threshold. It does not work, for two independent reasons, and no amount of tuning fixes either.

**It bans the wrong address.** `anonymize_client_ip: true` — which Phase E ships enabled by default, so this applies to every stock build of this plan, not only to a hardened one — masks at ingestion, not at display. `internal/dnsforward/stats.go` does `ip := pctx.Addr.Addr().AsSlice(); s.anonymizer.Load()(ip)` — mutating the slice **in place, before** it is handed to `logQuery` → `querylog.AddParams.ClientIP` → the ring buffer → `querylog.json`. Verified empirically on v0.107.78: a query from `127.0.0.1` is written to disk as `"IP":"127.0.0.0"`. The granularity is **/16 for IPv4 and /48 for IPv6** (`http.go` copies 10 zero bytes over `ip4[2:4]` and `ip6[6:16]`) — not the widely repeated /24 and /112. So the cron reads a network address, bans it as a `/32`, and the actual abuser keeps querying while the Phase L line "Abuse auto-ban: active" passes with the mechanism inert.

**The log may not exist at all.** Phase E moves the query log to `querylog.dir_path`, which breaks the hardcoded path; and if the operator opts in to Phase Q's zero-log posture, `querylog.enabled` is false, in which case AGH's `Add()` returns before it builds an entry and no file is ever written. Either way the script's `[ -f "$LOG" ] || exit 0` guard makes it exit **0, silently, forever**: an abuse-detection system that reports success while doing nothing.

Both problems have the same root: **the query log is a privacy-processed application artefact, and abuse detection needs the raw packet source.** Detection therefore moves to the kernel, where the real source address is, and where it stays correct regardless of every privacy decision Phase Q makes.

```bash
rm -f /opt/dns-warmer/abuse-check.sh
# /etc/cron.d/dns-health is created by Phase I and appended to by several
# phases. Delete the one stale line; never rewrite the file.
sed -i '/abuse-check\.sh/d' /etc/cron.d/dns-health
```

Note that `/opt/dns-warmer/` was the v1 cache warmer's directory. **Phase F is retired** — Unbound's `prefetch`/`prefetch-key` does that work in-process (see Phase C) — so remove the directory entirely once Phase F's own teardown has run.

### J2. The four correctness constraints the naive ruleset violates

Phase B writes the ruleset; these four are the constraints it has to satisfy, and they are stated here because this phase is where the consequences of getting them wrong show up. Each was confirmed by loading and flooding a real ruleset, not by reading documentation. Every one of them silently produces a ruleset that loads cleanly and does the wrong thing.

**1. `add @set` cannot cross tables.** A rule in a separate rate-limiting table that says `add @banned_ips` where `banned_ips` lives in `table inet filter` fails at load with `Error: No such file or directory; did you mean set 'banned_ips' in table inet 'filter'?`. In-kernel set references are table-scoped. **Consequence: the chain that bans and the sets it bans into must be in one table.** This is why Phase B's ruleset is a single `table inet filter` containing the meters, the flood detection and the ban sets together, reached through one input-path chain, rather than a second table dedicated to rate limiting. Userspace `nft` commands can reference any table freely; only the in-kernel statement is scoped, which is why the escalator in J4 can do from userspace what a rule cannot do in kernel.

**2. A flood chain that runs before `input` bans loopback, which is why `dns_guard` is not one.** v1 put the limiter in a base chain at `hook input priority -1`, while `iif lo accept` lived in `input` at priority 0 — which runs *afterwards* and was never reached. A 4-second flood of `127.0.0.1:53` put **127.0.0.1 into `banned_ips` for the full ban duration**, with `dns_banned` counter 1 and `dns_dropped` at 4,129,140 packets. On this plan that is triggered by Phase H's own load tests (`for i in $(seq 1 200); do dig ... & done` and `dnsperf -Q 500`), both documented as run from the server, and by the Phase I probes if their rate ever rises. Once loopback is banned there is a total local DNS outage until the ban expires, and the health checks that would tell you go down with it. The fix has two halves, and Phase B ships both: **`dns_guard` is a regular chain, jumped from `chain input` at priority 0 from a point below `iif lo accept`** — it is not a base chain and it does not hook `input` at any priority — and **`iif lo accept` is also the first rule of `dns_guard` itself**, so the exemption holds even if the jump is ever moved. Ordering that is read top to bottom in one chain cannot be got wrong by priority arithmetic.

**3. A rate expression gates the rule, not the dynset.** `update @floodmeter4 { ip saddr limit rate over 400/second }` used as a standalone statement inserts an element for **every packet**, because the rate expression only decides whether the *rule* matched — the dynset statement has already run. Written that way, `floodmeter4` accumulates one element per source IP seen, and any promotion step bans the entire client base on its first run. The correct construction is **two chained dynset statements**: the first carries the rate expression and terminates rule evaluation when the rate is not exceeded, so the second only executes for genuine offenders.

**4. `update` refreshes the timeout; `add` does not.** Measured on 30 s-timeout sets, re-hit at t+10 s: the `add` set showed `expires 19s896ms` (not refreshed), the `update` set showed `expires 29s875ms` (refreshed). `nft_dynset_eval()` refreshes expiration only for `NFT_DYNSET_OP_UPDATE`. With `add`, a sustained attacker's rate meter ages out mid-attack and the limit resets. Use `update` for every meter. Use `add` only for the ban sets, where re-arming on every packet of an ongoing flood would extend the ban indefinitely — the escalation in J4 handles repeat offenders deliberately instead.

### J3. The objects this phase depends on, and who owns them

Phase B is the sole author of `/etc/nftables.conf`. It contains exactly two tables: `table inet raw`, which holds the NOTRACK rules and nothing else because `notrack` is legal only at the raw hook, and `table inet filter`, which holds everything else. All the policy lives in the second one. That is not a stylistic preference, it is forced by constraint 1 above — the chain that bans and the sets it bans into must live in the same table — so the meters, the flood detection and the ban sets are all Phase B objects inside `table inet filter`. Exactly one chain there hooks `input`: `chain input` at priority 0. `dns_guard` is a **regular chain jumped from it**, not a base chain and not at priority -1 (constraint 2). **This phase writes no nftables configuration at all.** It reads and manipulates the objects Phase B creates, and everything below is stated in Phase B's names.

| Object | Kind | What this phase does with it |
|---|---|---|
| `banned_ips` / `banned_ips6` | dynamic timeout sets, 10 minutes | first-offence bans, added in-kernel by `dns_guard`; read by J4, J6, J7 |
| `banned_long` / `banned_long6` | timeout sets, 24 hours, **declared by Phase B** in `table inet filter`, with their own drop rules in `chain input` | repeat-offender bans, populated from userspace by J4's escalator and by manual bans in J7 |
| `allowlist4` / `allowlist6` | interval sets | membership bypasses flood detection **and** banning entirely — `dns_guard` consults them first and returns early; `127.0.0.0/8` and `::1` ship in them by default. J7's false-positive procedure adds to these |
| `floodmeter4` / `floodmeter6` | dynamic timeout sets | per-source flood detection at 400/s — the meter whose overflow triggers a ban, and the only kernel rate-limit tier there is |
| `dns_guard` | **regular chain**, jumped from `chain input` (priority 0); not a base chain | the chain J8 edits under pressure to fall back to drop-only |
| `dns_dropped` / `dns_banned` | counters | the two numbers J6 exports and J7 reads |

If a name here disagrees with Phase B, Phase B is right and this table is stale — fix it here, do not add an alias.

`banned_long` and `banned_long6` are **Phase B objects, not Phase J ones**: Phase B declares both in `table inet filter` with a 24-hour timeout and ships the matching drop rules in `chain input`, alongside the `banned_ips` / `banned_ips6` drops. Both halves are load-bearing — a set with no drop rule reading it is a list of addresses that are not actually banned, and the advertised 24-hour tier would drop nothing. **Phase J owns only the escalation logic that populates them.** They need only `flags timeout`, not `dynamic`: nothing in the kernel adds to them. Only J4's userspace escalator and the manual bans in J7 do, and `dynamic` is required only for in-kernel set statements.

Four properties of Phase B's ruleset that the procedures in J4 to J10 depend on. They are stated here so that a change on either side is visibly a change to a contract, not a local edit:

1. **`iif lo accept` is the first rule of `dns_guard`**, as well as of `input`, and the `jump dns_guard` sits below `input`'s own loopback exemption (constraint 2). Every local load test, every Phase H flood and every Phase I probe depends on it, and the failure mode is a total local DNS outage with the health checks down alongside.
2. **There is exactly one kernel rate-limit tier**: 400/s per source, in the single flood rule inside `dns_guard`, which meters, bans and drops in one statement. There is no second, lower per-source limiter beneath it — a second tier anywhere near Phase E's `dns.ratelimit` of 100 recreates the v1 stacking bug, and an ordinary limiter placed below the flood rule would end in a terminating `drop` that nothing above its threshold ever got past, leaving the meter unreachable. The only other limit in the chain is the global 5000/s UDP/53 backstop, which drops without banning because under spoofing the source is meaningless.
3. **The first offence bans for 10 minutes, not an hour.** Ten minutes still ends a reflection run; an hour turns one spoofed burst into an hour of collateral damage against whoever the attacker chose to impersonate. Read J9 before arguing for longer. This number is also user-facing: Phase Q's privacy notice and retention policy state "10 minutes, escalating to 24 hours on repeat offences", and the two must move together or the published policy becomes false.
4. **Bans apply to TCP as well as UDP.** `dns_guard`'s flood rules are UDP-only, matching AdGuard Home's own `dns.ratelimit` of 100, which is also UDP-only. The ban sets are additionally checked in the `input` chain so that a banned source cannot simply switch to TCP/53, DoT, DoH or DoQ. J7's unban procedure therefore restores all transports at once, and J8's drop-only fallback removes the ban for all of them at once too.

### J4. Expiry and escalation

Short bans expire by themselves; that is the point of the timeout. What must not happen is an attacker who is banned, waits 10 minutes, and resumes indefinitely at exactly the same cost. **This phase owns the escalation logic that moves an address from the 10-minute first offence to the 24-hour repeat ban, and nothing else**; Phase B owns the two pairs of sets it moves addresses between and the `chain input` drop rules that make membership of either pair actually block traffic.

`/usr/local/sbin/nft-ban-escalate` records every address that enters `banned_ips`, and promotes anything banned three or more times within 24 hours into `banned_long` (24 hours). It runs entirely in userspace, where set references are not table-scoped, so the cross-table constraint from J2 does not apply to it — but every set it names is still a Phase B object in `table inet filter`, and the commands say so explicitly rather than relying on a default.

```bash
cat > /usr/local/sbin/nft-ban-escalate <<'EOF'
#!/bin/bash
# Promote repeat offenders from the 10m ban set into the 24h ban set.
# Runs from a timer; reads only kernel state, never the query log.
set -u
STATE=/var/lib/dns-abuse/offences
THRESH=3
mkdir -p "$(dirname "$STATE")"; touch "$STATE"; chmod 0600 "$STATE"
NOW=$(date +%s); CUT=$((NOW - 86400))

elems() {   # elems <set>
  nft -j list set inet filter "$1" 2>/dev/null \
    | jq -r '.nftables[]?.set.elem[]? | if type=="object" then .elem.val else . end'
}

for SET in banned_ips banned_ips6; do
  case $SET in banned_ips) LONG=banned_long ;; *) LONG=banned_long6 ;; esac
  while read -r IP; do
    [ -n "$IP" ] || continue
    printf '%s %s\n' "$NOW" "$IP" >> "$STATE"
    N=$(awk -v c="$CUT" -v ip="$IP" '$1 >= c && $2 == ip' "$STATE" | wc -l)
    if [ "$N" -ge "$THRESH" ]; then
      nft add element inet filter "$LONG" "{ $IP timeout 24h }" 2>/dev/null \
        && logger -t dns-abuse "Escalated $IP to $LONG for 24h (${N} offences/24h)"
    fi
  done < <(elems "$SET")
done

# Trim the state file to the last 24h so it cannot grow without bound.
awk -v c="$CUT" '$1 >= c' "$STATE" > "${STATE}.tmp" && mv "${STATE}.tmp" "$STATE"
chmod 0600 "$STATE"
EOF
chmod 0755 /usr/local/sbin/nft-ban-escalate
```

```ini
# /etc/systemd/system/nft-ban-escalate.service
[Unit]
Description=Promote repeat DNS abusers to the long ban set
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nft-ban-escalate
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/dns-abuse
```

```ini
# /etc/systemd/system/nft-ban-escalate.timer
[Unit]
Description=Check for repeat DNS abusers every 5 minutes
[Timer]
OnBootSec=5m
OnUnitActiveSec=5m
AccuracySec=30s
[Install]
WantedBy=timers.target
```

The offence file records addresses, and under Phase Q's retention rules that is personal data with a purpose and a lifetime: purpose is abuse mitigation, lifetime is 24 hours, enforced by the trim at the end of every run. Mode 0600, root-owned. `/var/lib/dns-abuse/` is deliberately **not** in Phase K's restic include list — a 24-hour retention promise is worthless if the file is copied off-host and kept for the life of the backup repository. Keep `offences` in `/opt/dns-config-backup/.gitignore` as well, so that a stray copy into the config staging directory is never committed.

Escalation deliberately stops at 24 hours. There is no permanent ban tier, because with spoofable sources (J9) a permanent ban is a permanent, attacker-chosen outage for a third party. Permanent blocks are a human decision, made in the inverse of `allowlist4` — a manually maintained deny list you review — not an automated one.

### J5. Allowlist, and ban state across a reload

`/etc/nftables.conf` starts with `flush ruleset`. A naive reload therefore **destroys every dynamic set**, releasing all active bans and clearing all meters — during exactly the incident that made you edit the firewall in the first place.

That problem is solved once, in Phase B, by `/usr/local/sbin/nft-apply`: it syntax-checks the file, captures the current ban sets with their **remaining** timeouts, loads the new ruleset and replays the bans with the time they had left rather than a fresh full duration. It is wired to the nftables unit's `ExecReload`, so `systemctl reload nftables` runs it too. **This phase adds no second wrapper.** Two save/restore implementations racing over the same sets is how ban state gets silently lost, and a restore that re-arms every ban to its full duration turns a routine reload into an extension of every active ban — including the ones that were about to expire and the ones that were wrong.

Reload procedure, and the only supported one:

```bash
/usr/local/sbin/nft-apply         # check, capture remaining timeouts, load, replay
/usr/local/sbin/dns-health
```

Never run a bare `nft -f /etc/nftables.conf` on a live resolver. It is the one command that drops every active ban and every meter without telling you it did.

Reviewing ban state needs no wrapper at all — the sets are readable directly, and reading them is the honest way to know what is banned right now:

```bash
for S in banned_ips banned_ips6 banned_long banned_long6; do
  echo "== $S"
  nft list set inet filter "$S" 2>/dev/null | sed -n '/elements/,$p'
done
```

Allowlist entries live in the ruleset, so a temporary one lasts only until the next reload:

```bash
# Temporary (gone at the next nft-apply, because it is not in the file):
nft add element inet filter allowlist4 '{ 203.0.113.0/24 }'

# Permanent: add it to the `elements = { ... }` list of allowlist4 in
# /etc/nftables.d/dns-allow.nft -- Phase B's file, included by
# /etc/nftables.conf -- then reload with nft-apply.
```

Phase P defines the *access* allowlist — who may query the resolver at all — using its own named sets, and it must not reuse these names. `allowlist4`/`allowlist6` here say only "this source bypasses flood detection and banning entirely": `dns_guard` consults them before it meters anything and returns early for a member, which is the whole purpose of an operator allowlist. They say nothing about whether that address is allowed to query. Do not merge the two: an address can be entitled to query and still deserve flood detection.

### J6. Exporting abuse state to Phase I

Phase I alerts on `nft_dns_banned_packets` and `nft_banned_ips_elements`. This is the exporter that produces them. Every object it names — the `dns_dropped` and `dns_banned` counters, the four ban sets — is a Phase B object in `table inet filter`; this script only reads them.

```bash
cat > /usr/local/sbin/nft-abuse-textfile <<'EOF'
#!/bin/bash
# nftables abuse counters -> node_exporter textfile.
set -u
OUT=/var/lib/node_exporter/textfile/nft-abuse.prom
TMP="${OUT}.tmp"
ctr() { nft -j list counter inet filter "$1" 2>/dev/null \
  | jq -r '.nftables[]?.counter.packets // 0' | head -1; }
cnt() { nft -j list set inet filter "$1" 2>/dev/null \
  | jq -r '[.nftables[]?.set.elem[]?] | length'; }
{
  echo '# TYPE nft_dns_dropped_packets counter'
  echo "nft_dns_dropped_packets $(ctr dns_dropped)"
  echo '# TYPE nft_dns_banned_packets counter'
  echo "nft_dns_banned_packets $(ctr dns_banned)"
  echo '# TYPE nft_banned_ips_elements gauge'
  for S in banned_ips banned_ips6 banned_long banned_long6; do
    printf 'nft_banned_ips_elements{set="%s"} %s\n' "$S" "$(cnt "$S")"
  done
} > "$TMP"
chmod 0644 "$TMP"; mv "$TMP" "$OUT"
EOF
chmod 0755 /usr/local/sbin/nft-abuse-textfile
```

```ini
# /etc/systemd/system/nft-abuse-textfile.service
[Unit]
Description=nftables abuse counters to node_exporter textfile
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nft-abuse-textfile
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/node_exporter/textfile
```

```ini
# /etc/systemd/system/nft-abuse-textfile.timer
[Unit]
Description=Export nftables abuse counters every 30s
[Timer]
OnBootSec=60s
OnUnitActiveSec=30s
AccuracySec=5s
[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now nft-abuse-textfile.timer nft-ban-escalate.timer
```

Note that `nft_dns_dropped_packets` resets to zero whenever the ruleset is reloaded, because `flush ruleset` recreates the counters. `nft-apply` preserves ban *elements* across a reload; it does not preserve counter *values*, and nothing sensibly could. `rate()` handles a counter reset correctly; `increase()` over a window containing a reload will under-report. Do not read a dip as a fix.

Update the Phase L checklist line "Abuse auto-ban: active" to reference `nft list counter inet filter dns_banned` and `nft_banned_ips_elements` rather than the deleted cron job.

### J7. Operator procedures

**Review what is currently banned.**

```bash
for S in banned_ips banned_ips6 banned_long banned_long6; do
  echo "== $S"; nft list set inet filter "$S" 2>/dev/null | sed -n '/elements/,$p'
done
nft list counter inet filter dns_banned     # times the auto-ban has fired
nft list counter inet filter dns_dropped    # packets dropped by ban + rate limit
journalctl -t dns-abuse --since '-24h'      # escalation decisions
```

**Ban an address by hand.** Use the long set for a deliberate human decision; the short set is the automation's.

```bash
nft add element inet filter banned_long  '{ 203.0.113.42 timeout 24h }'
nft add element inet filter banned_long6 '{ 2001:db8::42 timeout 24h }'
logger -t dns-abuse "Manual ban 203.0.113.42 24h: <reason, ticket ref>"
```

Always log the reason. In three weeks the only record of why an address is blocked will be that line.

**Unban.**

```bash
nft delete element inet filter banned_ips  '{ 203.0.113.42 }'
nft delete element inet filter banned_long '{ 203.0.113.42 }'
# The offence history is what re-escalates it in five minutes. Clear it too:
sed -i '/ 203\.0\.113\.42$/d' /var/lib/dns-abuse/offences
logger -t dns-abuse "Manual unban 203.0.113.42: <reason>"
```

**False positive — a legitimate client is being banned.** The symptom is a user reporting intermittent total DNS failure in ~10-minute blocks, correlated with `nft_dns_banned_packets` increasing.

1. Confirm it is actually them: `nft list set inet filter banned_ips | grep <their-ip>`. Do **not** go looking in the query log; it holds a /16-masked address and cannot answer this question (J1).
2. Unban as above.
3. Decide whether they are genuinely over 400 QPS sustained. A single household behind CGNAT, or a corporate NAT egress, legitimately can be. If so, add them permanently to `allowlist4` — declared in `/etc/nftables.d/dns-allow.nft`, which is Phase B's file — and reload with `nft-apply`. `dns_guard` returns early for allowlist members, so that exempts them from flood detection *and* from banning, entirely and for every rate; accept that consciously.
4. If several unrelated clients are being banned in the same window, the threshold is wrong for your traffic, not the clients. Ask Phase B to raise the flood threshold above 400/second before you add a dozen exemptions; a large allowlist is a larger hole than a slightly higher threshold.
5. If the "client" is a *spoofed* source, no exemption helps and unbanning is temporary. Go to J8.

**A single address is being banned repeatedly and it is not yours.** That is the system working. Let escalation take it to 24 hours. If it persists past that, the response is an abuse report to the network's contact, which is Phase Q's process, not this phase's.

### J8. Sustained spoofed-source flood

The scenario: `dns:qps:rate5m` is far above normal, `nft_banned_ips_elements` is climbing into the hundreds, the banned addresses are unrelated networks all over the world, and legitimate users are being caught. You are being used as a reflector and the ban set is being steered at innocent third parties — including, potentially, your own users.

1. **Stop the escalation from compounding the damage.** `systemctl stop nft-ban-escalate.timer`. Twenty-four-hour bans on forged addresses are worse than the flood.
2. **Confirm it is spoofed** rather than a real botnet: spoofed floods show a source distribution with no correlation to your actual client base and, usually, a uniform query name and type. `tcpdump -ni any -c 200 udp port 53 and 'udp[10] & 0x80 = 0'` on the inbound side gives you the query names quickly. Keep the capture short and delete it — it is raw client data under Phase Q.
3. **Fall back to drop-only.** In `/etc/nftables.conf` — Phase B's file — remove the `add @banned_ips { ... }` and `add @banned_ips6 { ... }` **clause** from each of the two flood rules inside `dns_guard`, keeping the `floodmeter4`/`floodmeter6` meter, the counter and the `drop` on the same line, then reload with `/usr/local/sbin/nft-apply`. Do **not** comment the whole line out: each flood rule carries the meter, the ban clause, the counter and the drop in one statement, so commenting it removes the enforcement you are trying to keep. Dropping still stops the amplification; it just stops persisting state that an attacker can aim. This is the correct posture for the duration of a spoofed flood and it is a two-line edit made under pressure — write it into the runbook with both rules quoted in full, before and after, from Phase B's current ruleset rather than from memory.
4. **Tighten the packet layer, not the ban layer.** Phase B owns the whole ruleset: the ingress per-IP limits, the egress response-rate limit that protects the third-party victim even when the source is forged, `refuse_any`, and the NOTRACK rule that stops conntrack from filling. Those are the controls that actually cap what an attacker can extract from you. Re-read Phase B before touching anything here.
5. **Shed load if the box is saturating.** Phase N covers the multi-node and traffic-shedding options, including taking plain UDP/53 out of service and leaving only the authenticated/encrypted transports up. That is a product decision with real user impact — Phase N states the trade.
6. **You cannot stop the spoofing.** You are the reflector, not the origin. BCP38 is somebody else's network's job. Everything above caps the damage; nothing eliminates it. Write that in the runbook so the next person does not spend a night hunting the spoofer.
7. **Notify.** Provider abuse desk if the traffic volume threatens your instance; upstream network contacts for the reflected-at victims if they contact you. The contact addresses, the `security.txt`, and the complaint-handling workflow are Phase Q's — this phase owns the technical response only.

### J9. The trade you are accepting

UDP/53 source addresses are **forgeable**. That is the premise of the reflection attack this phase defends against, and it applies to the defence as well as the attack. An attacker who sustains a little over 400 packets per second from a forged source — one burst allowance beyond Phase B's flood threshold — can put **any address of their choosing** into `banned_ips`, including your own users or a large upstream recursive resolver. A drop-only rate limit has bounded harm; a ban does not.

This is why the first offence bans for 10 minutes rather than an hour, why escalation caps at 24 hours with no permanent tier, why `allowlist4`/`allowlist6` exist and must be populated with your known-good high-volume clients, and why J8 step 3 is a documented, rehearsed fallback rather than an emergency improvisation.

If that trade is unacceptable for your users, the supported alternative is to keep Phase B's `dns_guard` chain exactly as it stands and delete only the `add @banned_ips { ... }` / `add @banned_ips6 { ... }` clause from each of its two flood rules — the clause, not the line, which also carries the meter, the counter and the drop. You lose repeat-offender suppression and keep everything else. Record whichever choice you made, and the date, in the Phase O decision log — the next operator cannot infer it from the ruleset alone.

### J10. Phase J verification

```bash
# 1. Syntax-check BEFORE loading. Never skip this on a live resolver.
nft -c -f /etc/nftables.conf && echo "OK: ruleset parses"

# 2. Load through the ONE supported wrapper (Phase B's), and confirm the
#    loopback exemption is rule #1 of dns_guard.
/usr/local/sbin/nft-apply
nft -a list chain inet filter dns_guard | head -6   # 'iif lo accept' MUST be first

# 3. Regression test for the localhost-ban bug. Run ON the server.
#    A local flood must NOT put 127.0.0.1 into the ban set.
timeout 5 python3 -c "
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); t=time.time()
while time.time()-t<4: s.sendto(b'\x00'*40,('127.0.0.1',53))"
nft list set inet filter banned_ips | grep -q '127\.' \
  && echo "FAIL: localhost banned - dns_guard is missing 'iif lo accept'" \
  || echo "OK: loopback exempt"
dig @127.0.0.1 example.com A +time=2 +tries=1 >/dev/null && echo "OK: local DNS still works"

# 4. Structure. TWO tables -- `inet raw` for the NOTRACK rules, which is the
#    only hook where `notrack` is legal, and `inet filter` for everything else
#    -- and exactly ONE base chain hooking input. The cross-table constraint is
#    real, so the ban sets must live in the same table as the chain that writes
#    them, and nobody may re-introduce a second input-path chain.
nft list ruleset | grep -c '^table'        # must be 2: inet raw + inet filter
nft list ruleset | grep -E '^table'        # names must be `inet raw`, `inet filter`
nft list ruleset | grep -E 'type filter hook input priority'
#   EXPECT exactly ONE line: `chain input` at priority filter (0). A second
#   input-hook chain means the v1 layout crept back in.
#   dns_guard is a REGULAR chain jumped from input -- it must NOT appear above.
nft list chain inet filter dns_guard | grep -q 'type filter hook' \
  && echo "FAIL: dns_guard is a base chain -- see Phase B" \
  || echo "OK: dns_guard is a regular chain, not a base chain"
nft list chain inet filter input | grep -q 'jump dns_guard' \
  && echo "OK: input jumps to dns_guard" \
  || echo "FAIL: dns_guard is never entered -- the jump is missing from input"
for S in banned_ips banned_ips6 banned_long banned_long6 \
         allowlist4 allowlist6 floodmeter4 floodmeter6; do
  nft list set inet filter "$S" >/dev/null 2>&1 \
    && echo "OK: $S in table inet filter" || echo "FAIL: $S missing -- see Phase B"
done

# 4b. Every ban set is actually READ by a drop rule. A declared set with no rule
#     referencing it bans nobody, which would make J4's 24-hour tier -- and the
#     retention policy Phase Q publishes about it -- advertising for a control
#     that does not exist.
for S in banned_ips banned_ips6 banned_long banned_long6; do
  nft list chain inet filter input | grep -q "@$S" \
    && echo "OK: chain input drops on @$S" \
    || echo "FAIL: nothing reads @$S -- see Phase B"
done

# 4c. Allowlisted sources bypass dns_guard entirely, and loopback ships in the
#     sets by default.
nft list chain inet filter dns_guard | grep -E '@allowlist4|@allowlist6' \
  || echo "FAIL: dns_guard does not consult the allowlist -- see Phase B"
nft list set inet filter allowlist4 | grep -q '127\.0\.0\.0/8' \
  && echo "OK: 127.0.0.0/8 in allowlist4" || echo "FAIL: loopback missing from allowlist4"
nft list set inet filter allowlist6 | grep -q '::1' \
  && echo "OK: ::1 in allowlist6" || echo "FAIL: ::1 missing from allowlist6"

# 5. Auto-ban fires for a real remote source. Run FROM A SECOND HOST:
#      dnsperf -s <PUBLIC_IP> -d /tmp/queries.txt -l 20 -Q 2000
#    then, on the server:
nft list set inet filter banned_ips
nft list counter inet filter dns_banned    # packets must be > 0

# 6. Prove expiry WITHOUT waiting: the countdown must be live and shrinking.
nft list set inet filter banned_ips | grep -o 'expires [0-9a-z]*'
sleep 30
nft list set inet filter banned_ips | grep -o 'expires [0-9a-z]*'   # ~30s lower

# 7. Ban state survives a reload WITH ITS REMAINING TIME, not a fresh one.
nft add element inet filter banned_long '{ 198.51.100.7 timeout 24h }'
sleep 60
nft list set inet filter banned_long | grep -o 'expires [0-9a-z]*'   # ~23h59m
/usr/local/sbin/nft-apply
nft list set inet filter banned_long | grep -q '198\.51\.100\.7' \
  && echo "OK: ban survived reload" || echo "FAIL: reload wiped ban state"
nft list set inet filter banned_long | grep -o 'expires [0-9a-z]*'
# The countdown must be roughly where it was. If it reset to 24h, nft-apply is
# replaying with a fresh timeout instead of the remaining one -- see Phase B.
nft delete element inet filter banned_long '{ 198.51.100.7 }'

# 7b. There is exactly ONE reload wrapper. A resurrected save/restore script
#     races nft-apply over the same sets and loses bans silently.
test ! -e /usr/local/sbin/nft-bans && echo "OK: no second reload wrapper" \
  || echo "FAIL: nft-bans is back -- delete it, nft-apply is the only wrapper"

# 8. Escalation promotes only after the threshold, and trims its own state.
/usr/local/sbin/nft-ban-escalate
journalctl -t dns-abuse --since '-5 min'
wc -l /var/lib/dns-abuse/offences
stat -c '%a %U' /var/lib/dns-abuse/offences     # must be 600 root

# 9. Metrics reach Prometheus for the Phase I alerts.
/usr/local/sbin/nft-abuse-textfile
promtool check metrics < /var/lib/node_exporter/textfile/nft-abuse.prom
curl -sf 127.0.0.1:9100/metrics | grep -E '^nft_(dns_banned_packets|banned_ips_elements)'

# 10. The query-log-dependent machinery is gone and stays gone.
test ! -e /opt/dns-warmer/abuse-check.sh \
  && ! grep -qr abuse-check /etc/cron.d/ 2>/dev/null \
  && echo "OK: query-log-dependent abuse cron removed"
grep -rn 'querylog' /usr/local/sbin/nft-* /usr/local/sbin/dns-health 2>/dev/null \
  && echo "FAIL: abuse tooling still references the query log" \
  || echo "OK: no abuse tooling reads the query log"

# 11. Secrets and abuse state are excluded from the Phase K backup.
grep -qx 'offences' /opt/dns-config-backup/.gitignore && echo "OK: offences ignored"
```

---

[Plan index](../dns-server-plan.md) · [Previous: Retired Warmer, Log Rotation, Validation](./06-logging-and-validation.md) · [Next: Backup, Patching, HA, Provisioning](./08-operations.md)
