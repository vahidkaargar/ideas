#!/usr/bin/env bash
# deploy/phases/I-observability.sh — Phase I: Observability, Alerting and SLOs
# Source: phases/07-observability-and-abuse.md, section "PHASE I" (I0-I11).
# Mechanical transcription only — see phases/07-observability-and-abuse.md for
# the prose rationale behind every step. Phase J (Abuse Detection) is a
# SEPARATE phase script (deploy/phases/J-abuse-detection.sh) and is not
# generated here.
#
# Ownership (see CLAUDE.md single-ownership table): this phase is the SOLE
# owner of /usr/local/sbin/notify.sh and /etc/cron.d/dns-health — both are
# created in full below (I8b, I10). Every other phase must only append to
# them, never rewrite.
#
# NOT YET RUN ON REAL HARDWARE. Read this whole file before running it.

set -euo pipefail

# --- sourcing pattern -------------------------------------------------------
# Same mechanism run.sh uses (cd to this script's own directory, then source
# common.sh by relative path) adjusted for this script living one directory
# deeper than run.sh (deploy/phases/ vs deploy/). run.sh's literal two lines
# (`cd "$(dirname "${BASH_SOURCE[0]}")"; source lib/common.sh`) cannot be
# copied verbatim from here — deploy/phases/lib/common.sh does not exist —
# so the relative path is adjusted to ../lib/common.sh. This is flagged in
# the generation summary as a judgment call, not silently changed.
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=../lib/common.sh
source ../lib/common.sh

require_root

# --- placeholders that MUST be edited before this script is trusted --------
# The source document (I3, I4, I4b, I4c, I8, I9) uses these literal
# placeholders throughout and says to replace them. This script preserves
# the placeholders verbatim rather than inventing a parameterization scheme;
# edit them in this file (or in the config files it writes) before relying
# on any alert firing correctly.
#   dns.example.com                 -> your actual public hostname (I4, I4b)
#   example.com (DOMAIN= in I4c)    -> your actual REGISTERED domain
#   admin:YourStrongPassword        -> the real AdGuard Home admin password (I3)
#   NTFY_URL=...CHANGE-ME...        -> a real, secret ntfy.sh topic (I8)
#   NTFY_URL=...dns1-alerts-...     -> a real, secret ntfy.sh topic (I8 env file)
#   https://hc-ping.com/REPLACE...  -> your healthchecks.io ping URL (I9)
warn "Phase I placeholders (dns.example.com, example.com, ntfy topics, healthchecks.io URL) must be edited before this script's output is trustworthy — see I3/I4/I4b/I4c/I8/I9."

phase_header "Phase I — Observability, Alerting and SLOs"

# =============================================================================
# I1. Prometheus and node_exporter
# =============================================================================
phase_header "I1: Prometheus and node_exporter"

if ! marker_done "I1-binaries"; then
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
    mark_done "I1-binaries"
else
    info "I1: prometheus/node_exporter binaries already installed (marker present); skipping download"
fi

useradd -r -s /usr/sbin/nologin -d /var/lib/prometheus     prometheus 2>/dev/null || info "I1: user prometheus already exists"
useradd -r -s /usr/sbin/nologin -d /var/lib/node_exporter  nodeexp    2>/dev/null || info "I1: user nodeexp already exists"
mkdir -p /etc/prometheus/rules /var/lib/prometheus /var/lib/node_exporter/textfile
chown prometheus:prometheus /var/lib/prometheus
chown nodeexp:nodeexp /var/lib/node_exporter/textfile
chmod 0755 /var/lib/node_exporter/textfile   # root-run collector scripts write here; root bypasses mode bits

# --- I1: /etc/prometheus/prometheus.yml -------------------------------------
# Retention lives in the config file, not the CLI flags (--storage.tsdb.retention.*
# are [DEPRECATED] in v3.13.2 per cmd/prometheus/main.go). The blackbox jobs are
# appended to THIS SAME FILE in I4 below — keep everything in one file, per source.
backup_file /etc/prometheus/prometheus.yml
cat > /etc/prometheus/prometheus.yml <<'EOF'
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
EOF

backup_file /etc/systemd/system/prometheus.service
cat > /etc/systemd/system/prometheus.service <<'EOF'
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
EOF

backup_file /etc/systemd/system/node_exporter.service
cat > /etc/systemd/system/node_exporter.service <<'EOF'
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
EOF

# --- I1: retention sizing note (informational, no command) ------------------
# ~2,000 active series at 15s scrape -> ~23 MB/day -> ~2.1 GB over 90 days;
# the 6 GB size cap gives ~3x headroom. See I1 table for the full worked
# breakdown across every collector. Nothing to run for this.

confirm "I1: enable and start prometheus + node_exporter as boot services (systemd units just written) — proceed?"
systemctl daemon-reload
systemctl enable --now node_exporter prometheus

# =============================================================================
# I2. Unbound metrics — the preferred signal
# =============================================================================
phase_header "I2: Unbound metrics (99-stats.conf, unbound-textfile)"

# A SECOND drop-in, deliberately separate from Phase C's
# 10-public-resolver.conf, so a Phase C change and a monitoring change never
# collide in the same file.
backup_file /etc/unbound/unbound.conf.d/99-stats.conf
cat > /etc/unbound/unbound.conf.d/99-stats.conf <<'EOF'
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
EOF
warn "I2: 99-stats.conf written but Unbound must reload/restart to pick it up. No reload command is given in the source for this step (Phase C owns the unbound.service unit) — restart it by hand (or via Phase C's own procedure) before I11 step 3 will show any unbound_* series."

# --- I2: /usr/local/sbin/unbound-textfile ------------------------------------
# Generic mapper. Invents no metric names: every "key.path value" line from
# stats_noreset becomes unbound_<key with dots replaced by underscores>.
cat > /usr/local/sbin/unbound-textfile <<'EOF'
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
EOF

backup_file /etc/systemd/system/unbound-textfile.service
cat > /etc/systemd/system/unbound-textfile.service <<'EOF'
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
EOF

backup_file /etc/systemd/system/unbound-textfile.timer
cat > /etc/systemd/system/unbound-textfile.timer <<'EOF'
[Unit]
Description=Scrape Unbound stats every 30s
[Timer]
OnBootSec=60s
OnUnitActiveSec=30s
AccuracySec=5s
[Install]
WantedBy=timers.target
EOF

# NOTE (I2, "Packaged alternative"): kumina/unbound_exporter and forks expose
# the same counters over /metrics. The source does NOT pin one ("no current
# maintained release was verified during research") and explicitly says: if
# adopted, it REPLACES this script, never supplements it (doubles control-
# socket load for no extra signal otherwise). Not installed here — the chosen
# path is the script above.

# =============================================================================
# I3. AdGuard Home metrics via /control/stats
# =============================================================================
phase_header "I3: AdGuard Home metrics (agh-credentials, agh-textfile)"

backup_file /etc/prometheus/agh-credentials
install -m0600 -o root -g root /dev/null /etc/prometheus/agh-credentials
printf 'admin:YourStrongPassword\n' > /etc/prometheus/agh-credentials
warn "I3: /etc/prometheus/agh-credentials contains the LITERAL placeholder 'admin:YourStrongPassword' from the source. Replace it with the real AdGuard Home admin credentials before I11 verification."

# /opt/dns-config-backup is Phase A3's object (sole owner) -- this phase only
# APPENDS to its .gitignore, never creates or deletes the directory itself.
if [ -d /opt/dns-config-backup ]; then
    printf 'agh-credentials\nntfy.env\n' >> /opt/dns-config-backup/.gitignore
else
    warn "I3: /opt/dns-config-backup does not exist yet (Phase A3 owns it) -- .gitignore entries for agh-credentials/ntfy.env were NOT written. Run Phase A first, or append these two lines by hand afterward."
fi

cat > /usr/local/sbin/agh-textfile <<'EOF'
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
EOF

backup_file /etc/systemd/system/agh-textfile.service
cat > /etc/systemd/system/agh-textfile.service <<'EOF'
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
EOF

backup_file /etc/systemd/system/agh-textfile.timer
cat > /etc/systemd/system/agh-textfile.timer <<'EOF'
[Unit]
Description=Scrape AdGuard Home stats every 60s
[Timer]
OnBootSec=90s
OnUnitActiveSec=60s
AccuracySec=5s
[Install]
WantedBy=timers.target
EOF

# I3 posture table and "how to use these numbers correctly" are prose
# reference material (no commands) -- see phases/07-observability-and-abuse.md
# I3 for the full table if a QPS-alert threshold needs re-deriving.

# NOTE (I3, "If you insist on a packaged exporter") -- OPTIONAL ALTERNATIVE,
# NOT installed by default. henrywhitaker3/adguard-exporter
# (ghcr.io/henrywhitaker3/adguard-exporter:latest) is Docker-only and requires
# the cardinality-drop relabel_configs below if adopted. Given only for
# reference; the chosen path is the agh-textfile.py script above, and running
# both would be redundant. The older ebrianne/adguard-exporter is unmaintained
# -- the source says explicitly: do not deploy it.
#   - job_name: adguard
#     scrape_interval: 30s
#     static_configs:
#       - targets: ['127.0.0.1:9618']
#     metric_relabel_configs:
#       - source_labels: [__name__]
#         regex: 'adguard_top_(queried_domains|blocked_domains|clients)'
#         action: drop
#       - source_labels: [__name__]
#         regex: 'adguard_queries_details.*'
#         action: drop

# =============================================================================
# I4. Synthetic probes: blackbox_exporter, and the DoQ gap
# =============================================================================
phase_header "I4: blackbox_exporter"

if ! marker_done "I4-blackbox-binary"; then
    BB_VER=$(curl -fsS https://api.github.com/repos/prometheus/blackbox_exporter/releases/latest | jq -r .tag_name | tr -d v)
    echo "blackbox_exporter resolved to ${BB_VER} on $(date -u +%F)"   # record this in Phase O inventory
    cd /tmp
    wget "https://github.com/prometheus/blackbox_exporter/releases/download/v${BB_VER}/blackbox_exporter-${BB_VER}.linux-amd64.tar.gz"
    tar -xzf "blackbox_exporter-${BB_VER}.linux-amd64.tar.gz"
    install -m0755 "blackbox_exporter-${BB_VER}.linux-amd64/blackbox_exporter" /usr/local/bin/blackbox_exporter
    mark_done "I4-blackbox-binary"
else
    info "I4: blackbox_exporter binary already installed (marker present); skipping download"
fi
useradd -r -s /usr/sbin/nologin blackbox 2>/dev/null || info "I4: user blackbox already exists"
mkdir -p /etc/blackbox_exporter

# --- I4: /etc/blackbox_exporter/blackbox.yml --------------------------------
# The DoH query string is the RFC 8484 s4.1 example: base64url of a wire-format
# query for www.example.com A with message ID 0.
backup_file /etc/blackbox_exporter/blackbox.yml
cat > /etc/blackbox_exporter/blackbox.yml <<'EOF'
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

  # The resolver's OWN name, asked of somebody else. Every other dns module
  # here targets 127.0.0.1 and therefore cannot see the one dependency that
  # takes every encrypted transport down at once: the authoritative DNS for
  # dns.example.com is hosted by a third party, and if that delegation breaks
  # or the registration lapses, DoT/DoH/DoQ clients cannot resolve the name
  # they are configured with while this box stays entirely green. See I4c.
  dns_own_name_public:
    prober: dns
    timeout: 5s
    dns:
      query_name: dns.example.com
      query_type: A
      transport_protocol: udp
      preferred_ip_protocol: ip4
      ip_protocol_fallback: false
      valid_rcodes: [NOERROR]

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
EOF
warn "I4: blackbox.yml has query_name: dns.example.com and target dns.example.com:443/:853 hardcoded (dns_own_name_public module, and the scrape jobs below). Replace with your real hostname throughout, per the source's own instruction at I4."

backup_file /etc/systemd/system/blackbox_exporter.service
cat > /etc/systemd/system/blackbox_exporter.service <<'EOF'
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
EOF

# --- I4: append the blackbox scrape jobs to prometheus.yml -------------------
# Same file I1 wrote. This is an append to an already-live config file, so
# back it up first even though the append itself is additive, not destructive.
backup_file /etc/prometheus/prometheus.yml
cat >> /etc/prometheus/prometheus.yml <<'EOF'

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

  # Two independent public resolvers, so one provider's outage is a warning
  # and not a page. The TARGET here is the resolver being asked; the name
  # being asked for lives in the module. Neither address is your own, which
  # is the entire point.
  - job_name: blackbox-delegation
    metrics_path: /probe
    scrape_interval: 5m
    params:
      module: [dns_own_name_public]
    static_configs:
      - targets:
          - '1.1.1.1:53'
          - '9.9.9.9:53'
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
EOF
warn "I4: appended blackbox scrape jobs to /etc/prometheus/prometheus.yml, but the source gives no explicit 'reload prometheus' command anywhere in Phase I. Prometheus was already started in I1 with --web.enable-lifecycle; you must reload it yourself (e.g. via that lifecycle endpoint, or restart the unit) before these jobs are scraped. Flagged, not invented, per CLAUDE.md hard rule 4."

# Caveat (I4, informational, no command): every probe above originates on the
# box and is routed over lo, hitting Phase B's `iif lo accept` -- these probes
# prove the daemon/TLS material are healthy, NOT that the service is reachable
# from the internet. blackbox-delegation is the sole exception (packets leave
# the box for a third-party resolver) but still doesn't prove inbound
# reachability. See I9 for the off-box check that does.

# --- I4b. DoT and DoQ resolution probes --------------------------------------
phase_header "I4b: dnslookup (DoT/DoQ probes)"

if ! marker_done "I4b-dnslookup-binary"; then
    DL_VER=$(curl -fsS https://api.github.com/repos/ameshkov/dnslookup/releases/latest | jq -r .tag_name | tr -d v)
    echo "dnslookup resolved to ${DL_VER} on $(date -u +%F)"   # record this in Phase O inventory
    cd /tmp
    wget "https://github.com/ameshkov/dnslookup/releases/download/v${DL_VER}/dnslookup-linux-amd64-${DL_VER}.tar.gz"
    tar -xzf "dnslookup-linux-amd64-${DL_VER}.tar.gz"
    install -m0755 linux-amd64/dnslookup /usr/local/bin/dnslookup
    mark_done "I4b-dnslookup-binary"
else
    info "I4b: dnslookup binary already installed (marker present); skipping download"
fi

# Confirm the invocation by hand ONCE before trusting the probe (source's own
# instruction). Non-fatal: this is a one-time sanity check, not a build step.
info "I4b: confirming dnslookup invocation against dns.example.com (edit hostname first if not already done)"
dnslookup example.com tls://dns.example.com && echo DOT_OK || warn "I4b: DoT confirmation failed -- check the hostname placeholder and that Phase D/E's TLS listeners are up before trusting EncryptedTransportDown."
dnslookup example.com quic://dns.example.com && echo DOQ_OK || warn "I4b: DoQ confirmation failed -- check the hostname placeholder and that AGH's DoQ listener is up before trusting EncryptedTransportDown."

cat > /usr/local/sbin/dns-probe-textfile <<'EOF'
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
EOF
warn "I4b: dns-probe-textfile has HOST=dns.example.com hardcoded (per source). Edit before running against your real host."

backup_file /etc/systemd/system/dns-probe-textfile.service
cat > /etc/systemd/system/dns-probe-textfile.service <<'EOF'
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
EOF

backup_file /etc/systemd/system/dns-probe-textfile.timer
cat > /etc/systemd/system/dns-probe-textfile.timer <<'EOF'
[Unit]
Description=Run encrypted DNS probes every 60s
[Timer]
OnBootSec=120s
OnUnitActiveSec=60s
AccuracySec=10s
[Install]
WantedBy=timers.target
EOF

chmod 0755 /usr/local/sbin/unbound-textfile /usr/local/sbin/agh-textfile /usr/local/sbin/dns-probe-textfile

confirm "I4/I4b: enable and start blackbox_exporter (boot service) plus unbound-textfile.timer, agh-textfile.timer, dns-probe-textfile.timer — proceed?"
systemctl daemon-reload
systemctl enable --now blackbox_exporter \
  unbound-textfile.timer agh-textfile.timer dns-probe-textfile.timer

info "I4: if Phase P puts the resolver behind WireGuard or an nftables allowlist, these probes must run INSIDE the access path or they will report a permanent outage (a Phase P delta, not a Phase I one)."

# --- I4c. Slow external checks: domain registration and upstream releases ---
phase_header "I4c: dns-domain-expiry and dns-release-check"

cat > /usr/local/sbin/dns-domain-expiry <<'EOF'
#!/bin/bash
# Registry expiry date for the service domain -> node_exporter textfile.
# RDAP, not whois: whois output is unparseable per-registry free text, while
# RDAP is JSON with a defined `expiration` event (RFC 9083 s4.5).
set -u
DOMAIN=example.com          # the REGISTERED domain, not the dns.* hostname
OUT=/var/lib/node_exporter/textfile/dns_domain.prom
TMP="${OUT}.tmp"

# -L is mandatory. rdap.org is the IANA bootstrap redirector: it answers 302
# to the responsible registry (e.g. rdap.verisign.com for .com). Without -L
# curl returns an empty body and this reports a permanent, silent failure.
EXP=$(curl -fsSL --max-time 20 "https://rdap.org/domain/${DOMAIN}" 2>/dev/null \
      | jq -r '.events[]? | select(.eventAction=="expiration") | .eventDate' | head -1)

{
  echo '# TYPE dns_domain_rdap_up gauge'
  echo '# TYPE dns_domain_expiry_seconds gauge'
  if [ -n "$EXP" ] && EPOCH=$(date -d "$EXP" +%s 2>/dev/null); then
    printf 'dns_domain_rdap_up{domain="%s"} 1\n' "$DOMAIN"
    printf 'dns_domain_expiry_seconds{domain="%s"} %s\n' "$DOMAIN" "$EPOCH"
  else
    # Emit up=0 and NO expiry sample. A stale expiry that keeps counting down
    # from a cached value is worse than an absent one: it would clear itself.
    printf 'dns_domain_rdap_up{domain="%s"} 0\n' "$DOMAIN"
  fi
} > "$TMP"

chmod 0644 "$TMP"; mv "$TMP" "$OUT"
EOF
chmod 0750 /usr/local/sbin/dns-domain-expiry
warn "I4c: dns-domain-expiry has DOMAIN=example.com hardcoded (per source, the REGISTERED domain, distinct from the dns.* hostname). Edit before relying on DomainExpiringSoon/DomainExpiringCritical."

# Confirm the RDAP shape for YOUR TLD before trusting it (informational check).
info "I4c: checking RDAP shape for example.com -- expect a line beginning 'expiration=', e.g. expiration=2026-08-13T04:00:00Z. Re-run against your real domain after editing the placeholder."
curl -fsSL https://rdap.org/domain/example.com | jq -r '.events[] | "\(.eventAction)=\(.eventDate)"' || warn "I4c: RDAP check failed or returned unexpected shape -- confirm your TLD's registry publishes an 'expiration' event before trusting DomainExpiringSoon/Critical."

cat > /usr/local/sbin/dns-release-check <<'EOF'
#!/bin/bash
# Installed vs upstream version for every component apt does not patch.
# Reports only; never downloads, never upgrades. See Phase M for the upgrade.
set -u
OUT=/var/lib/node_exporter/textfile/dns_releases.prom
TMP="${OUT}.tmp"
FAILED=0

latest() {   # latest <owner/repo> -> tag with any leading v stripped
  curl -fsS --max-time 20 "https://api.github.com/repos/$1/releases/latest" \
    | jq -r '.tag_name // empty' | sed 's/^v//'
}

{
  echo '# TYPE dns_component_update_available gauge'
  echo '# TYPE dns_release_check_up gauge'

  emit() {   # emit <component> <installed> <repo>
    local comp="$1" have="$2" repo="$3" want
    want=$(latest "$repo") || true
    if [ -z "$have" ] || [ -z "$want" ]; then FAILED=1; return; fi
    # Only emit the series when there IS drift. An absent series means "up to
    # date", which keeps this at zero cost in the cardinality budget (I1) for
    # the years between releases.
    [ "$have" = "$want" ] && return
    printf 'dns_component_update_available{component="%s",installed="%s",latest="%s"} 1\n' \
      "$comp" "$have" "$want"
  }

  # AdGuardHome: read the symlink Phase E installs, not --version. The symlink
  # is what Phase M moves, so it is the truth about what would roll back.
  emit adguardhome \
    "$(basename "$(readlink -f /opt/adguardhome/current)" | sed 's/^v//')" \
    AdguardTeam/AdGuardHome

  # Prometheus-family binaries print `<name>, version X.Y.Z (...)` on STDERR.
  emit prometheus        "$(prometheus --version 2>&1        | awk 'NR==1{print $3}')" prometheus/prometheus
  emit node_exporter     "$(node_exporter --version 2>&1     | awk 'NR==1{print $3}')" prometheus/node_exporter
  emit alertmanager      "$(alertmanager --version 2>&1      | awk 'NR==1{print $3}')" prometheus/alertmanager
  emit blackbox_exporter "$(blackbox_exporter --version 2>&1 | awk 'NR==1{print $3}')" prometheus/blackbox_exporter
  # restic prints `restic X.Y.Z compiled with ...` on stdout.
  emit restic            "$(restic version 2>/dev/null       | awk 'NR==1{print $2}')" restic/restic

  echo "dns_release_check_up $((1 - FAILED))"
} > "$TMP"

chmod 0644 "$TMP"; mv "$TMP" "$OUT"
EOF
chmod 0750 /usr/local/sbin/dns-release-check

# Six unauthenticated GitHub API calls a week sits far inside the 60/hour
# anonymous limit; do NOT run this hourly. Verify each version parse by hand
# once (informational, matches source's own instruction):
info "I4c: verifying dns-release-check version parsing once by hand"
/usr/local/sbin/dns-release-check && cat /var/lib/node_exporter/textfile/dns_releases.prom
# EXPECTED on a freshly built host: `dns_release_check_up 1` and no
# dns_component_update_available lines at all. Any line here means either a
# genuine new release or a broken version parse -- check which before filing it.
prometheus --version 2>&1 | head -1     # confirm field 3 is the bare version
restic version 2>/dev/null | head -1    || warn "I4c: restic not installed yet (Phase K owns it) -- version-parse line cannot be confirmed until Phase K runs"

# =============================================================================
# I5. Abuse counters (no commands here -- Phase J's exporter, Phase I only
# consumes nft_dns_dropped_packets / nft_dns_banned_packets / nft_banned_ips_elements
# in I6's alert rules and I7's SLO corroboration. Do not duplicate the
# exporter in this phase.)
# =============================================================================
info "I5: abuse counters (nft_dns_dropped_packets etc.) are written by Phase J's nft-abuse-textfile -- nothing to install here."

# =============================================================================
# I10 (moved ahead of I4c's cron append -- see note below): /etc/cron.d/dns-health
# =============================================================================
# ORDERING NOTE: the source presents I4c's `cat >> /etc/cron.d/dns-health`
# (two lines: dns-domain-expiry, dns-release-check) textually BEFORE I10's
# `cat > /etc/cron.d/dns-health` (the daily dns-health gate line). I10's own
# text says the file is "created in I10" and uses `>` (truncate), which would
# silently destroy the I4c lines if executed in literal document order. This
# script creates the base file first (I10's content) and appends the I4c
# lines after, to match the source's own stated ownership ("Phase I creates
# this file... Other phases append") without losing either block's content.
# Flagged in the generation summary as a judgment call.
phase_header "I10: dns-health (operator script) and /etc/cron.d/dns-health (create)"

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
# chrony is in this list for the same reason it is in ServiceInactive: a dead
# clock SERVFAILs every signed zone, and node_timex_sync_status takes about
# nine hours to notice. `is-active` notices immediately.
for u in unbound adguardhome nginx prometheus alertmanager alertmanager-ntfy \
         node_exporter blackbox_exporter nftables chrony; do
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

echo "== clock =="
# Cheap, and it is the discriminator for the outage that looks like a broken
# trust anchor. `timedatectl show` is machine-readable; the pretty output is not.
if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ]; then
  ok "clock synchronised" "$(chronyc tracking 2>/dev/null | awk -F': *' '/System time/{print $2}')"
else
  bad "clock synchronised" "signed zones will SERVFAIL -- this is NOT Phase C"
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

echo "== dependencies =="
# Read I4c's textfile rather than calling RDAP: this script must stay fast and
# must not depend on a third party being up to report a green box.
DOMEXP=$(awk '/^dns_domain_expiry_seconds/{print $2}' \
  /var/lib/node_exporter/textfile/dns_domain.prom 2>/dev/null)
if [ -n "${DOMEXP:-}" ]; then
  DDAYS=$(( (${DOMEXP%.*} - $(date +%s)) / 86400 ))
  [ "$DDAYS" -gt 30 ] && ok "domain registration" "${DDAYS}d left" \
                      || bad "domain registration" "${DDAYS}d left -- renew NOW"
else
  bad "domain registration" "no expiry metric -- see I4c"
fi
# awk, not `grep -c ... || echo 0`: grep exits 1 when it matches nothing, so
# the fallback fires IN ADDITION to grep's own "0" and prints "0 0" on exactly
# the healthy path. awk always exits 0 and always prints one number.
PEND=$(awk '/^dns_component_update_available/{n++} END{print n+0}' \
  /var/lib/node_exporter/textfile/dns_releases.prom 2>/dev/null)
printf '%-42s %s\n' "upstream releases pending" "${PEND:-0} (see Phase M to apply)"

echo
[ $FAIL -eq 0 ] && echo "ALL CHECKS PASSED" || echo "FAILURES PRESENT -- see above"
exit $FAIL
EOF
chmod 0755 /usr/local/sbin/dns-health
warn "I10/I4b: dns-health has HOST=dns.example.com hardcoded (per source). Edit before trusting its DoT/DoQ/DoH/TLS checks."

# Phase I creates /etc/cron.d/dns-health. Other phases append (Phase D, K, M)
# and say so in their own sections; nobody else rewrites it wholesale.
backup_file /etc/cron.d/dns-health
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

# --- I4c (continued): append the two slow-collector cron lines --------------
# Append, never rewrite (per I4c and I10's own wording). Offset from 06:17 so
# a 20s curl timeout cannot delay the daily health gate.
cat >> /etc/cron.d/dns-health <<'EOF'

# I4c: slow external dependencies. Both write node_exporter textfiles and
# notify nobody -- I6 owns the alerting, so that Alertmanager can dedupe a
# condition that stays true for weeks. Offset from the 06:17 health gate so a
# 20s curl timeout cannot delay it.
41 4 * * *   root /usr/local/sbin/dns-domain-expiry
53 4 * * 1   root /usr/local/sbin/dns-release-check
EOF

info "I10: MAILTO=\"\" is deliberate (no MTA on this box); the only notification path is notify.sh (I8b). Cron picks up /etc/cron.d changes without a restart, but a syntax error in a line is only visible in journalctl -u cron."

# =============================================================================
# I6. Alert rules
# =============================================================================
phase_header "I6: /etc/prometheus/rules/dns.yml"
# Thresholds below assume a small public resolver doing tens to low hundreds
# of QPS. Re-derive the two QPS bounds and the disk predictor against your own
# first fortnight of data before treating them as ground truth.

backup_file /etc/prometheus/rules/dns.yml
cat > /etc/prometheus/rules/dns.yml <<'EOF'
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
      # The I4c files are written daily and weekly, not every minute, so they
      # are excluded here and covered by SlowCollectorStale below. Adding a
      # slow collector without adding it to BOTH matchers gives you a rule
      # that fires forever, which is how a whole alerting stack gets muted.
      - alert: CollectorStale
        expr: >-
          time() - node_textfile_mtime_seconds{file!~"dns_domain.prom|dns_releases.prom"} > 300
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Textfile collector {{ $labels.file }} is stale"
          description: "No update for >5 minutes. Metrics derived from it are frozen, not zero."

      # The I4c calendar collectors, at their own timescale: 36h for the daily
      # domain check, 8d for the weekly release check. The `file` label is the
      # BASENAME, not the path.
      - alert: SlowCollectorStale
        expr: >-
          time() - node_textfile_mtime_seconds{file="dns_domain.prom"} > 129600
            or time() - node_textfile_mtime_seconds{file="dns_releases.prom"} > 691200
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Slow collector {{ $labels.file }} has not run"
          description: >-
            Its cron line in /etc/cron.d/dns-health did not run, or the file was
            never created. The dependency it watches is now unmonitored, and the
            expiry it watches keeps counting down regardless. See I4c.

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

      # Deliberately adjacent to the two DNSSEC rules, because a dead clock
      # presents as exactly the same outage and the entire Phase C trust-anchor
      # diagnostic path comes back clean. `node_timex_*` needs no collector
      # work: the timex collector is default-enabled on Linux and reads
      # adjtimex(2), so ProtectSystem=strict in I1 does not touch it.
      - alert: ClockUnsynchronised
        expr: node_timex_sync_status == 0
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "System clock is not disciplined by chrony"
          description: >-
            RRSIG inception and expiration are absolute timestamps, so Unbound
            starts SERVFAILing every signed zone once drift crosses the validity
            window -- long before the wrongness is visible to a human, and
            indistinguishable from a broken trust anchor. Discriminator:
            `timedatectl` reports "System clock synchronized: no", while
            `test -s /var/lib/unbound/root.key` PASSES and will mislead you.
            Fix with `systemctl start chrony && chronyc makestep`, not with
            anything in Phase C. See Phase A for the chrony install.

      - alert: ClockOffsetHigh
        expr: abs(node_timex_offset_seconds) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Clock offset {{ $value | printf \"%.2f\" }}s"
          description: "Leading indicator for ClockUnsynchronised. chrony is running but not converging: check `chronyc sources -v` for reachable peers, and Phase B for egress on UDP/123."

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

      # chrony belongs here, and this is the rule that actually catches it.
      # ClockUnsynchronised cannot: when chronyd dies the kernel does not clear
      # STA_UNSYNC immediately. `second_overflow()` in kernel/time/ntp.c grows
      # time_maxerror by MAXFREQ/NSEC_PER_USEC = 500 us per second and only sets
      # STA_UNSYNC once it passes NTP_PHASE_LIMIT = 16 s, i.e. after roughly
      # 16000000/500 = 32000 s, about NINE HOURS of undetected free-running
      # drift. This rule notices in three minutes. Confirm the unit name on
      # your build with `systemctl list-units 'chron*'` -- it is chrony.service
      # on Ubuntu 24.04, chronyd.service on the RPM family.
      - alert: ServiceInactive
        expr: >-
          node_systemd_unit_state{name=~"unbound.service|adguardhome.service|nginx.service|chrony.service",state="active"} == 0
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.name }} is not active"

      - alert: ServiceFlapping
        expr: >-
          changes(node_systemd_unit_state{name=~"unbound.service|adguardhome.service|nginx.service|chrony.service",state="active"}[1h]) > 5
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

  # ----------------------------------------------------------- dependencies
  # Calendar failures, from the I4c collectors. Thresholds are in DAYS because
  # that is the unit the fix is measured in -- a registrar billing problem is
  # not resolved in an afternoon.
  - name: dependencies
    rules:
      - alert: DomainExpiringSoon
        expr: (dns_domain_expiry_seconds - time()) / 86400 < 60
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.domain }} registration expires in {{ $value | printf \"%.0f\" }} days"
          description: >-
            Renew now. This is NOT the certificate alert and CertExpiringSoon
            will not save you: certbot cannot issue for a domain you no longer
            control. The usual root cause is an expired card on the registrar
            account, which takes longer to fix than it sounds.

      - alert: DomainExpiringCritical
        expr: (dns_domain_expiry_seconds - time()) / 86400 < 30
        for: 1h
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.domain }} registration expires in under 30 days"
          description: >-
            At expiry every transport fails closed at once -- Do53 by hostname,
            DoT and DoQ SNI, the DoH URL, and Phase P's WireGuard endpoint --
            and no client has a fallback. After the redemption window the name
            can be re-registered by anyone, who can then obtain a valid
            certificate for it and receive your users' queries.

      - alert: DomainExpiryCheckFailing
        expr: dns_domain_rdap_up == 0
        for: 6h
        labels:
          severity: warning
        annotations:
          summary: "RDAP lookup for {{ $labels.domain }} is failing"
          description: >-
            The expiry countdown is now ABSENT, not zero, so the two rules above
            cannot fire. Registry RDAP outage, an egress block, or a TLD with no
            `expiration` event -- see I4c. Until it returns, the renewal date is
            whatever your calendar says.

      - alert: DelegationUnresolvable
        expr: probe_success{job="blackbox-delegation"} == 0
        for: 30m
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.instance }} cannot resolve this resolver's own hostname"
          description: >-
            Authoritative DNS for the service name is broken, or the
            registration lapsed. Every encrypted client fails while this box
            reports itself perfectly healthy. If BOTH public resolvers fail
            simultaneously, suspect your own egress first and correlate with
            RecursionStalled. The long `for` is deliberate: public resolvers
            cache, so brief single-target blips are noise.

      - alert: ComponentUpdateAvailable
        expr: dns_component_update_available == 1
        for: 24h
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.component }} {{ $labels.installed }} -> {{ $labels.latest }} available"
          description: >-
            unattended-upgrades (Phase M) covers the apt pockets and therefore
            cannot cover this binary. AdGuardHome and nginx are the two
            processes that parse hostile input from the whole internet, so an
            AdGuardHome release is the one to read the notes for first. Upgrade
            via Phase M's procedure -- this alert deliberately does not
            auto-upgrade anything. Silence it if you have chosen to stay on the
            pinned version; do not delete the rule.

      - alert: ReleaseCheckFailing
        expr: dns_release_check_up == 0
        for: 24h
        labels:
          severity: warning
        annotations:
          summary: "The upstream release check could not complete"
          description: >-
            A version parse broke, a binary is missing, or the GitHub API is
            unreachable or rate-limiting. Every out-of-apt component is
            unwatched until this clears. Run /usr/local/sbin/dns-release-check
            by hand and read its output.
EOF

# =============================================================================
# I7. Recording rules, SLIs and SLOs
# =============================================================================
phase_header "I7: /etc/prometheus/rules/slo.yml"

backup_file /etc/prometheus/rules/slo.yml
cat > /etc/prometheus/rules/slo.yml <<'EOF'
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
EOF

warn "I6/I7: rule files written to /etc/prometheus/rules/, but no reload/restart command for prometheus is given anywhere in the Phase I source for either I6 or I7. Same gap as I4's scrape-config append. Reload prometheus (it already runs with --web.enable-lifecycle from I1) before expecting these rules or recording rules to be active."

# I7's SLI/SLO table (Do53 99.9%, encrypted-transport 99.5%, etc.) and the
# error-budget policy ("if the 30-day Do53 budget is more than half consumed,
# no non-security change ships") are prose/policy, not commands -- see I7 in
# the source for the full table.

# =============================================================================
# I8. Alertmanager and the path to a phone
# =============================================================================
phase_header "I8: Alertmanager + ntfy bridge"

if ! marker_done "I8-alertmanager-binary"; then
    AM_VER=0.33.1   # verified: prometheus/alertmanager CHANGELOG.md, "0.33.1 / 2026-07-04"
    cd /tmp
    wget "https://github.com/prometheus/alertmanager/releases/download/v${AM_VER}/alertmanager-${AM_VER}.linux-amd64.tar.gz"
    tar -xzf "alertmanager-${AM_VER}.linux-amd64.tar.gz"
    install -m0755 "alertmanager-${AM_VER}.linux-amd64/alertmanager" /usr/local/bin/alertmanager
    install -m0755 "alertmanager-${AM_VER}.linux-amd64/amtool"       /usr/local/bin/amtool
    mark_done "I8-alertmanager-binary"
else
    info "I8: alertmanager binary already installed (marker present); skipping download"
fi
useradd -r -s /usr/sbin/nologin -d /var/lib/alertmanager alertmanager 2>/dev/null || info "I8: user alertmanager already exists"
mkdir -p /etc/alertmanager /var/lib/alertmanager
chown alertmanager:alertmanager /var/lib/alertmanager

# --- I8: /etc/alertmanager/alertmanager.yml ---------------------------------
# Every key verified against docs/configuration.md at tag v0.33.1 (per source).
backup_file /etc/alertmanager/alertmanager.yml
cat > /etc/alertmanager/alertmanager.yml <<'EOF'
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
EOF
warn "I8: alertmanager.yml's heartbeat receiver still has the literal placeholder https://hc-ping.com/REPLACE-WITH-YOUR-UUID. This MUST be replaced with a real healthchecks.io ping URL per I9 (manual, human account-creation step) before the dead man's switch does anything."

cat > /usr/local/sbin/alertmanager-ntfy <<'EOF'
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
EOF
chmod 0755 /usr/local/sbin/alertmanager-ntfy

# --cluster.listen-address= is REQUIRED, not cosmetic (source's own wording):
# Alertmanager's default is 0.0.0.0:9094 (TCP+UDP) for HA gossip. Saved only
# by Phase B's default-drop policy otherwise.
backup_file /etc/systemd/system/alertmanager.service
cat > /etc/systemd/system/alertmanager.service <<'EOF'
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
EOF

backup_file /etc/systemd/system/alertmanager-ntfy.service
cat > /etc/systemd/system/alertmanager-ntfy.service <<'EOF'
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
EOF

# /etc/alertmanager/ntfy.env -- 0600 root:root. Holds the topic, which IS the
# credential, so it must never be copied into /opt/dns-config-backup's
# staging tree (that is what I3's .gitignore is for). It IS inside Phase K's
# encrypted restic set (/etc/alertmanager is in K's include list).
backup_file /etc/alertmanager/ntfy.env
install -m0600 /dev/null /etc/alertmanager/ntfy.env
cat > /etc/alertmanager/ntfy.env <<'EOF'
NTFY_URL=https://ntfy.sh/dns1-alerts-REPLACE-WITH-32-RANDOM-CHARS
NTFY_TOKEN=
EOF
warn "I8: /etc/alertmanager/ntfy.env has the literal placeholder topic 'dns1-alerts-REPLACE-WITH-32-RANDOM-CHARS'. The ntfy topic name IS the credential on public ntfy.sh -- replace with >=32 random characters (or self-host ntfy with NTFY_TOKEN) before this is safe to leave running. Install the ntfy app and subscribe to the real topic; that is the whole notification path."

confirm "I8: enable and start alertmanager + alertmanager-ntfy (boot services) — proceed?"
systemctl daemon-reload
systemctl enable --now alertmanager alertmanager-ntfy

info "I8: no firewall change required -- 9090/9093/9095/9100/9115 bind to loopback and --cluster.listen-address= removes the 9094 listener entirely. Phase B's iif lo accept + default-drop covers the rest. Reach the UIs via: ssh -L 9090:127.0.0.1:9090 -L 9093:127.0.0.1:9093 dns1 (Phase P tunnel)."

# =============================================================================
# I8b. notify.sh -- the one notification entry point (Phase I SOLE OWNER)
# =============================================================================
phase_header "I8b: notify.sh (sole owner: Phase I)"
# Signature is canonical, every caller in every phase must match it exactly:
#   notify.sh <severity> <title> [message]
# Callers: Phase D (cert deploy), Phase I (cron health gate), Phase K
# (backup), Phase L (verification), Phase M (upgrades). Phase I defines it;
# other phases call it and say so -- they must never write a second one.

backup_file /usr/local/sbin/notify.sh
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

info "I8b: rules for callers -- do NOT call notify.sh on a timer (no dedup/rate-limiting by design), and do NOT treat a non-zero exit as your own failure (log it, keep your own exit status honest)."

# =============================================================================
# I9. The off-box dead man's switch -- required, not optional
# =============================================================================
phase_header "I9: off-box dead man's switch (MANUAL -- external accounts)"

# ---- MANUAL STEPS: no automated substitute is scripted for these. ----------
warn "I9 step 1 (MANUAL): create an account at healthchecks.io (free tier: 20 checks). Create one check named 'dns1-watchdog'. Set Period: 2 minutes, Grace: 15 minutes. Copy its ping URL. This is an out-of-band account-creation step and is not scripted here."
warn "I9 step 3 (MANUAL): in the healthchecks project settings, add an integration for the notification channel that reaches your phone -- either the ntfy integration pointed at a DIFFERENT topic than I8's (a shared topic means one outage silences both paths), or email plus SMS. Send a test notification from their UI and confirm it arrives on the phone, on the lock screen, with sound. Not scripted here -- requires a human looking at their phone."
warn "I9 step 4 (MANUAL): add a second, independent external check that does not depend on this box's software at all -- UptimeRobot's free tier with a Port monitor on dns.example.com:853, 5-minute interval (or self-hosted healthchecks / Uptime Kuma, in that preference order, if you already own a second host). Do NOT run the checker on this VPS, on the same provider, or in the same region -- that recreates the single point of failure this section exists to remove."

# I9 step 2: once the human has copied the healthchecks.io ping URL and
# pasted it into alertmanager.yml's heartbeat receiver (I8, above -- replacing
# REPLACE-WITH-YOUR-UUID by hand), reload alertmanager to pick it up.
confirm "I9 step 2: reload alertmanager (only meaningful after you have manually pasted the real healthchecks.io URL into /etc/alertmanager/alertmanager.yml's heartbeat receiver) — proceed?"
systemctl reload alertmanager

info "I9: record both external services (healthchecks.io, UptimeRobot/equivalent), their credentials location, and the phone numbers/emails they notify in the Phase O inventory. Also record in that inventory: the domain registrar, account identity, who else can log in, auto-renew status, registrar lock status, and the card that pays for it -- and the authoritative DNS hosting for the name, which may be a different company. Recommended default: recovery address on an UNRELATED domain, registrar lock + auto-renew enabled, registrar account behind its own MFA. None of this is scriptable; it is operator record-keeping."

# =============================================================================
# I11. Phase I verification
# =============================================================================
phase_header "I11: Phase I verification"

# 1. Everything parses BEFORE anything else restarts.
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

# 4. AGH statistics survived the Phase E config migration.
AUTH=$(cat /etc/prometheus/agh-credentials)
curl -s -u "$AUTH" 127.0.0.1:3000/control/stats/config | jq '{enabled, interval, ignored_enabled}'

# 4b. Prove the disabled-statistics path DEGRADES instead of paging (manual:
#     set statistics.enabled: false in AdGuardHome.yaml, restart AGH, then run
#     the two checks below; restore the setting and restart AGH afterward).
warn "I11 step 4b is a manual toggle-and-observe test against AdGuardHome.yaml (Phase E's file) -- not automated here. Set statistics.enabled: false, restart AGH, run: /usr/local/sbin/agh-textfile && grep -E '^agh_(up|running|stats_enabled|metrics_unavailable_by_policy) ' /var/lib/node_exporter/textfile/adguard.prom -- EXPECTED: agh_up 1, agh_running 1, agh_stats_enabled 0, agh_metrics_unavailable_by_policy 1, and 'grep -c ^agh_queries_window_total ...' EXPECTED 0 (absent, not zero). Then restore the setting and restart AGH."

# 5. Confirm the `recent` contract rather than guessing (status code, not body).
for ms in 3600000 60000; do
  printf 'recent=%-8s -> HTTP %s\n' "$ms" \
    "$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" \
       "127.0.0.1:3000/control/stats?recent=$ms")"
done
# EXPECTED: 3600000 -> 200, 60000 -> 400.

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
# Scanning your own public IP FROM THIS BOX routes over lo and proves nothing;
# run this from a DIFFERENT host instead:
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
#     Run the restore detached so an interrupted shell cannot leave AM stopped.
confirm "I11 step 14: stop alertmanager (a boot service) to prove the off-box dead man's switch fires -- this is the test the source calls 'THE ONE THAT MATTERS'. It will auto-restart via systemd-run in 900s. Proceed?"
systemctl stop alertmanager
systemd-run --on-active=900 --unit=am-restore systemctl start alertmanager
info "I11 step 14: do NOT use 'journalctl -u alertmanager | grep hc-ping' to confirm the heartbeat -- Alertmanager does not log successful notifications at the default level. The authoritative check is the last-ping timestamp in the external service's UI."

# 15. The shared notification entry point works, before any other phase
#     depends on it. This must reach the phone.
/usr/local/sbin/notify.sh info "notify.sh self-test" \
  "If this arrived, every phase's notifications work."; echo "exit=$?"
# exit 0 = pushed. exit 3 = NTFY_URL unset (fix ntfy.env). exit 4 = push failed.
journalctl -t dns-notify -n 5 --no-pager     # the local record must exist too

# 16. The cron file other phases append to exists and is actually loadable.
stat -c '%a %U:%G %n' /usr/local/sbin/notify.sh /etc/cron.d/dns-health
# EXPECT 0750 root:root and 0644 root:root.
grep -c '^[0-9*]' /etc/cron.d/dns-health     # >= 1 scheduled line
journalctl -u cron --since '-5 min' | grep -i 'dns-health' || true   # no parse errors

# 17. The operator script agrees.
/usr/local/sbin/dns-health; echo "exit=$?"

# 18. The clock is actually monitored. Both series must EXIST.
curl -s 127.0.0.1:9100/metrics | grep -E '^node_timex_(sync_status|offset_seconds) '
# EXPECTED: node_timex_sync_status 1, and an offset within a few milliseconds.
curl -s 127.0.0.1:9100/metrics | grep 'node_systemd_unit_state.*chrony'
# EXPECTED: a chrony.service line with state="active" value 1. If the unit is
# named chronyd.service on your build, fix the regex in ServiceInactive to
# match, or the rule silently covers nothing.

# 19. Prove the chrony alert path end to end, cheaply and reversibly. This is
#     the DETECTION test only; the full clock-skew rehearsal belongs to
#     Phase H's validation suite, not here. Restore detached so an
#     interrupted shell cannot leave the clock adrift.
confirm "I11 step 19: stop chrony (a boot service) to prove ServiceInactive fires -- it auto-restarts via a backgrounded subshell in 300s. Proceed?"
systemctl stop chrony
( sleep 300; systemctl start chrony; chronyc makestep ) >/dev/null 2>&1 &
sleep 240; curl -s 127.0.0.1:9093/api/v2/alerts | jq -r '.[].labels.alertname' | grep ServiceInactive
# EXPECTED: ServiceInactive fires within ~3 minutes. ClockUnsynchronised will
# NOT have fired and that is correct (see I6's comment on ServiceInactive).
timedatectl show -p NTPSynchronized --value    # confirm `yes` again afterwards

# 20. The domain expiry countdown exists and is sane.
/usr/local/sbin/dns-domain-expiry && cat /var/lib/node_exporter/textfile/dns_domain.prom
# EXPECTED: dns_domain_rdap_up 1 and an epoch. Sanity-check against the
# registrar's control panel -- they must agree:
awk '/^dns_domain_expiry_seconds/{print $2}' \
  /var/lib/node_exporter/textfile/dns_domain.prom | xargs -I{} date -d @{}
curl -sf --get 127.0.0.1:9090/api/v1/query \
  --data-urlencode 'query=(dns_domain_expiry_seconds - time()) / 86400' | jq -r '.data.result[].value[1]'
# EXPECTED: days remaining, matching the registrar. A NEGATIVE number means the
# domain has already expired and every encrypted transport is living on cache.

# 21. The release check is honest about both outcomes.
/usr/local/sbin/dns-release-check && cat /var/lib/node_exporter/textfile/dns_releases.prom
# EXPECTED on a freshly built host: `dns_release_check_up 1` and NO
# dns_component_update_available lines. `up 0` means a version parse broke.

# 22. The slow collectors do not poison CollectorStale. Run this the day AFTER
#     the collectors first wrote, i.e. once both files are older than 5 minutes.
curl -sf --get 127.0.0.1:9090/api/v1/query \
  --data-urlencode 'query=ALERTS{alertname="CollectorStale"}' | jq -r '.data.result | length'
# EXPECTED: 0. Anything else means the file!~ exclusion in I6 does not match
# the real basenames -- compare against:
curl -s 127.0.0.1:9100/metrics | grep '^node_textfile_mtime_seconds'

# 23. All rules loaded, and every new one is present rather than silently
#     dropped by a YAML error higher up the file.
curl -sf 127.0.0.1:9090/api/v1/rules | jq -r '.data.groups[].rules[].name' | sort > /tmp/loaded
for a in ClockUnsynchronised ClockOffsetHigh SlowCollectorStale DomainExpiringSoon \
         DomainExpiringCritical DomainExpiryCheckFailing DelegationUnresolvable \
         ComponentUpdateAvailable ReleaseCheckFailing; do
  grep -qx "$a" /tmp/loaded && echo "ok   $a" || echo "MISSING $a"
done
# EXPECTED: `ok` on all nine.

echo
echo "=== Phase I done. What 'this worked' looks like: ==="
echo "  - I11 step 1  : promtool/amtool checks above printed no errors"
echo "  - I11 step 11 : Watchdog rule count == 1 and amtool shows it firing"
echo "  - I11 step 14 : the healthchecks.io UI shows a missed-ping alert while"
echo "                  alertmanager was stopped, and it clears once restored"
echo "                  (systemd-run am-restore fires automatically at +900s)"
echo "  - I11 step 15 : the notify.sh self-test push arrived on your phone"
echo "  - I11 step 23 : every alert name below printed 'ok', not 'MISSING'"
echo "  - dns-health  : 'sudo /usr/local/sbin/dns-health' prints ALL CHECKS PASSED"
echo "See phases/07-observability-and-abuse.md I11 for the full 23-step list and expected outputs."
