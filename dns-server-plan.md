# Public Recursive DNS Service — Full Agent Execution Plan

---

## PHASE A: Host Preparation

### A1. Provision VPS
- Min specs: 2 vCPU, 4 GB RAM, 40 GB SSD, static IPv4, Ubuntu 22.04 LTS
- Optional: static IPv6
- Provider: any with low-latency routing (Hetzner, Vultr, DigitalOcean, etc.)

### A2. Initial OS Setup
```bash
apt update && apt full-upgrade -y
hostnamectl set-hostname dns1
timedatectl set-timezone UTC
apt install -y curl wget jq git unzip logrotate ufw nftables fail2ban chrony
systemctl enable --now chrony
```

### A3. Create Service Users (least privilege)
```bash
useradd -r -s /usr/sbin/nologin -d /opt/adguardhome adguardhome
useradd -r -s /usr/sbin/nologin -d /opt/smartdns smartdns
useradd -r -s /usr/sbin/nologin -d /opt/dns-warmer dnswarmer
```

### A4. Secure SSH
```bash
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
Port 22  # change to non-standard if desired
systemctl restart sshd
```

### A5. Kernel / System Tuning
```bash
cat >> /etc/sysctl.d/99-dns.conf << 'EOF'
fs.file-max = 1000000
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.udp_mem = 65536 131072 262144
EOF
sysctl --system
```

```bash
# /etc/security/limits.d/dns.conf
*    soft nofile 1000000
*    hard nofile 1000000
```

---

## PHASE B: Firewall (nftables)

### B1. Full nftables Ruleset
```bash
cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  # Dynamic ban set (populated by abuse response)
  set banned_ips {
    type ipv4_addr
    flags dynamic, timeout
    timeout 1h
  }

  chain input {
    type filter hook input priority 0; policy drop;

    # Loopback always allowed
    iif lo accept

    # Drop banned IPs
    ip saddr @banned_ips drop

    # Established/related
    ct state established,related accept

    # ICMP
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    # SSH (rate-limited)
    tcp dport 22 ct state new limit rate 10/minute accept

    # Public DNS protocols
    udp dport 53 accept
    tcp dport 53 accept
    tcp dport 443 accept   # DoH
    tcp dport 853 accept   # DoT
    udp dport 784 accept   # DoQ

    # BLOCK SmartDNS port from non-loopback (defense in depth)
    tcp dport 5335 drop
    udp dport 5335 drop
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}

# Per-IP UDP rate limiting for DNS (anti-reflection)
table inet dns_ratelimit {
  meter dns_udp_meter {
    type ipv4_addr
    size 65536
  }

  chain dns_udp_limit {
    type filter hook input priority -1;
    udp dport 53 meter dns_udp_meter { ip saddr limit rate over 100/second burst 200 packets } drop
  }
}
EOF

systemctl enable --now nftables
nft -f /etc/nftables.conf
```

---

## PHASE C: SmartDNS (Resolver Layer)

### C1. Install SmartDNS
```bash
# Get latest release from https://github.com/pymumu/smartdns/releases
SMARTDNS_VER=$(curl -s https://api.github.com/repos/pymumu/smartdns/releases/latest | jq -r .tag_name)
wget "https://github.com/pymumu/smartdns/releases/download/${SMARTDNS_VER}/smartdns.1.$(uname -m).tar.gz" -O /tmp/smartdns.tar.gz
tar -xzf /tmp/smartdns.tar.gz -C /tmp/
bash /tmp/smartdns/install
```

### C2. Directory Setup
```bash
mkdir -p /opt/smartdns /etc/smartdns /var/lib/smartdns /var/log/smartdns
chown smartdns:smartdns /opt/smartdns /var/lib/smartdns /var/log/smartdns
```

### C3. SmartDNS Configuration
```bash
cat > /etc/smartdns/smartdns.conf << 'EOF'
# === BIND: localhost ONLY ===
bind 127.0.0.1:5335
bind [::1]:5335

# === CACHE ===
cache-size 500000
cache-persist yes
cache-file /var/lib/smartdns/smartdns.cache
prefetch-domain yes
serve-expired yes
serve-expired-ttl 86400
serve-expired-reply-ttl 5
rr-ttl-min 60
rr-ttl-max 86400
rr-ttl-reply-max 3600

# === NEGATIVE CACHE ===
negative-ttl 300

# === UPSTREAM GROUPS ===
# Group: neutral (Cloudflare, Google)
server-https https://1.1.1.1/dns-query -group neutral -exclude-default-group
server-https https://1.0.0.1/dns-query -group neutral -exclude-default-group
server-https https://8.8.8.8/dns-query  -group neutral -exclude-default-group
server-https https://8.8.4.4/dns-query  -group neutral -exclude-default-group

# Group: security-aware (Quad9)
server-https https://9.9.9.9/dns-query  -group security -exclude-default-group
server-https https://149.112.112.112/dns-query -group security -exclude-default-group

# Group: regional (Adguard DNS — neutral mode)
server-https https://94.140.14.140/dns-query -group regional -exclude-default-group
server-https https://94.140.14.141/dns-query -group regional -exclude-default-group

# Default group: all upstreams race
server-https https://1.1.1.1/dns-query
server-https https://8.8.8.8/dns-query
server-https https://9.9.9.9/dns-query
server-https https://94.140.14.140/dns-query

# === PARALLEL RESOLUTION ===
# First valid answer wins
dualstack-ip-selection yes

# === LOGGING ===
log-level info
log-file /var/log/smartdns/smartdns.log
log-size 50m
log-num 5

# === PERFORMANCE ===
tcp-idle-time 120
max-query-limit 1000
EOF
```

### C4. SmartDNS systemd Service
```bash
cat > /etc/systemd/system/smartdns.service << 'EOF'
[Unit]
Description=SmartDNS Resolver
After=network-online.target
Wants=network-online.target

[Service]
User=smartdns
Group=smartdns
ExecStart=/usr/sbin/smartdns -f -c /etc/smartdns/smartdns.conf
Restart=on-failure
RestartSec=5
LimitNOFILE=1000000
# Systemd sandboxing
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/smartdns /var/log/smartdns

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now smartdns
systemctl status smartdns
```

### C5. Verify SmartDNS (localhost only)
```bash
dig @127.0.0.1 -p 5335 google.com A    # must resolve
dig @<PUBLIC_IP> -p 5335 google.com A  # must FAIL / timeout
```

---

## PHASE D: TLS Certificate

### D1. Install Certbot
```bash
apt install -y certbot
```

### D2. Obtain Certificate (standalone — port 80 must be open temporarily)
```bash
# Temporarily allow port 80
nft add rule inet filter input tcp dport 80 accept

certbot certonly --standalone -d dns.example.com \
  --agree-tos --no-eff-email -m admin@example.com

# Remove port 80 rule after cert obtained
nft delete rule inet filter input handle $(nft -a list chain inet filter input | grep "dport 80" | awk '{print $NF}')
```

### D3. Auto-Renewal Hook (reload AdGuardHome on renew)
```bash
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-adguard.sh << 'EOF'
#!/bin/bash
systemctl reload-or-restart adguardhome
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-adguard.sh
```

### D4. Test Auto-Renewal
```bash
certbot renew --dry-run
```

### D5. Cert Expiry Monitoring
```bash
cat > /etc/cron.daily/check-cert-expiry << 'EOF'
#!/bin/bash
EXPIRY=$(openssl x509 -enddate -noout -in /etc/letsencrypt/live/dns.example.com/cert.pem | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
if [ $DAYS_LEFT -lt 14 ]; then
  echo "CERT EXPIRY WARNING: $DAYS_LEFT days left" | logger -t cert-monitor
fi
EOF
chmod +x /etc/cron.daily/check-cert-expiry
```

---

## PHASE E: AdGuardHome (Public Gateway)

### E1. Install AdGuardHome
```bash
mkdir -p /opt/adguardhome/work /opt/adguardhome/conf
cd /tmp
AGH_VER=$(curl -s https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest | jq -r .tag_name)
wget "https://github.com/AdguardTeam/AdGuardHome/releases/download/${AGH_VER}/AdGuardHome_linux_amd64.tar.gz"
tar -xzf AdGuardHome_linux_amd64.tar.gz -C /opt/adguardhome/
chown -R adguardhome:adguardhome /opt/adguardhome
```

### E2. AdGuardHome Configuration
```bash
cat > /opt/adguardhome/conf/AdGuardHome.yaml << 'EOF'
http:
  pprof:
    port: 0
    enabled: false
  address: 127.0.0.1:3000   # Admin UI: localhost only
  session_ttl: 720h

users:
  - name: admin
    password: "$2y$10$REPLACE_WITH_BCRYPT_HASH"  # generate: htpasswd -bnBC 10 "" 'StrongPass' | tr -d ':\n'

dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  # Upstream: SmartDNS ONLY
  upstream_dns:
    - 127.0.0.1:5335
  upstream_dns_file: ""
  bootstrap_dns:
    - 127.0.0.1:5335
  fallback_dns: []
  # Cache: conservative (SmartDNS is primary cache)
  cache_size: 10000000       # 10 MB edge cache
  cache_ttl_min: 0
  cache_ttl_max: 3600
  cache_optimistic: false    # SmartDNS handles stale
  # Rate limiting
  ratelimit: 100             # per-client QPS
  ratelimit_whitelist: []
  # Refuse malformed
  refuse_any: true
  # EDNS
  edns_client_subnet:
    enabled: false           # privacy: no ECS forwarding
  # DNSSEC
  enable_dnssec: false       # SmartDNS handles upstream; set true if Unbound added
  # Filtering: minimal for public resolver
  filtering_enabled: false
  filters_update_interval: 0
  parental_enabled: false
  safesearch:
    enabled: false
  safebrowsing_enabled: false
  # Logging
  querylog_enabled: true
  querylog_file_enabled: true
  querylog_interval: 24h     # keep only 24h of query logs
  querylog_size_memory: 1000
  anonymize_client_ip: true  # privacy

tls:
  enabled: true
  server_name: dns.example.com
  force_https: false
  port_https: 443            # DoH
  port_dns_over_tls: 853     # DoT
  port_dns_over_quic: 784    # DoQ
  port_dnscrypt: 0
  certificate_chain: /etc/letsencrypt/live/dns.example.com/fullchain.pem
  private_key: /etc/letsencrypt/live/dns.example.com/privkey.pem
  strict_sni_check: false

log:
  file: /var/log/adguardhome/adguardhome.log
  max_backups: 5
  max_size: 100
  max_age: 7
  compress: true
  verbose: false
EOF
```

### E3. Generate Admin Password Hash
```bash
apt install -y apache2-utils
htpasswd -bnBC 10 "" 'YourStrongPassword' | tr -d ':\n'
# Paste output into AdGuardHome.yaml users[0].password
```

### E4. AdGuardHome systemd Service
```bash
cat > /etc/systemd/system/adguardhome.service << 'EOF'
[Unit]
Description=AdGuardHome DNS Gateway
After=network-online.target smartdns.service
Wants=network-online.target
Requires=smartdns.service

[Service]
User=adguardhome
Group=adguardhome
ExecStart=/opt/adguardhome/AdGuardHome/AdGuardHome \
  -c /opt/adguardhome/conf/AdGuardHome.yaml \
  -w /opt/adguardhome/work \
  --no-check-update
Restart=on-failure
RestartSec=5
LimitNOFILE=1000000
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/opt/adguardhome /var/log/adguardhome

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /var/log/adguardhome
chown adguardhome:adguardhome /var/log/adguardhome
# Allow binding to port 53 (privileged)
setcap 'cap_net_bind_service=+ep' /opt/adguardhome/AdGuardHome/AdGuardHome
systemctl daemon-reload
systemctl enable --now adguardhome
systemctl status adguardhome
```

---

## PHASE F: DNS Cache Warmer

### F1. Directory and Files
```bash
mkdir -p /opt/dns-warmer
chown dnswarmer:dnswarmer /opt/dns-warmer
```

### F2. Warmer Script (`/opt/dns-warmer/warmer.py`)
```python
#!/usr/bin/env python3
"""
DNS Cache Warmer
- Queries AdGuardHome on localhost:53
- TTL-aware scheduling with jitter
- Worker pool, rate limiting, exponential backoff
"""
import dns.resolver
import time, random, logging, os, threading
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

# --- Config ---
TARGET_HOST   = "127.0.0.1"
TARGET_PORT   = 53
DOMAINS_FILE  = "/etc/dns-warmer/domains.txt"
WORKERS       = 20
GLOBAL_QPS    = 50# max queries/sec total
REFRESH_RATIO = 0.75        # refresh at 75% of TTL
MIN_INTERVAL  = 60          # seconds
MAX_INTERVAL  = 3600        # seconds
MAX_BACKOFF   = 300         # seconds

logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("/var/log/dns-warmer/warmer.log"),
        logging.StreamHandler()
    ])
log = logging.getLogger("warmer")

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = [TARGET_HOST]
resolver.port = TARGET_PORT
resolver.timeout = 3
resolver.lifetime = 5

rate_lock = threading.Semaphore(GLOBAL_QPS)
stats = defaultdict(int)

def query_domain(domain: str, qtype: str = "A") -> int:
    """Returns TTL on success, -1 on failure."""
    try:
        ans = resolver.resolve(domain, qtype, raise_on_no_answer=False)
        ttl = ans.rrset.ttl if ans.rrset else MIN_INTERVAL
        stats["success"] += 1
        return ttl
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        stats["nxdomain"] += 1
        return MIN_INTERVAL
    except Exception as e:
        stats["failure"] += 1
        log.warning(f"FAIL {domain} {qtype}: {e}")
        return -1

def warm_domain(domain: str):
    backoff = 5
    while True:
        with rate_lock:
            ttl_a    = query_domain(domain, "A")
            ttl_aaaa = query_domain(domain, "AAAA")

        if ttl_a == -1 and ttl_aaaa == -1:
            log.error(f"Backoff {domain}: {backoff}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF)
            continue

        backoff = 5
        ttl = max(ttl_a, ttl_aaaa, MIN_INTERVAL)
        sleep = max(MIN_INTERVAL,    min(int(ttl * REFRESH_RATIO) + random.randint(0, 30),
                        MAX_INTERVAL))
        log.debug(f"Warmed {domain}, next in {sleep}s")
        time.sleep(sleep)

def load_domains():
    with open(DOMAINS_FILE) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def main():
    domains = load_domains()
    log.info(f"Warming {len(domains)} domains with {WORKERS} workers")
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(warm_domain, d) for d in domains]
        for f in futures:
            f.result()

if __name__ == "__main__":
    main()
```

### F3. Domain List
```bash
mkdir -p /etc/dns-warmer
cat > /etc/dns-warmer/domains.txt << 'EOF'
# Top domains to keep warm
google.com
youtube.com
facebook.com
twitter.com
instagram.com
wikipedia.org
reddit.com
amazon.com
apple.com
microsoft.com
cloudflare.com
github.com
# Add more as needed
EOF
chown -R dnswarmer:dnswarmer /etc/dns-warmer
```

### F4. Install Python Dependencies
```bash
apt install -y python3 python3-pip
pip3 install dnspython
```

### F5. Warmer systemd Service
```bash
cat > /etc/systemd/system/dns-warmer.service << 'EOF'
[Unit]
Description=DNS Cache Warmer
After=network-online.target adguardhome.service
Wants=network-online.target
Requires=adguardhome.service

[Service]
User=dnswarmer
Group=dnswarmer
ExecStart=/usr/bin/python3 /opt/dns-warmer/warmer.py
Restart=on-failure
RestartSec=10
LimitNOFILE=65535
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=/var/log/dns-warmer

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /var/log/dns-warmer
chown dnswarmer:dnswarmer /var/log/dns-warmer
chown dnswarmer:dnswarmer /opt/dns-warmer/warmer.py
chmod +x /opt/dns-warmer/warmer.py
systemctl daemon-reload
systemctl enable --now dns-warmer
```

---

## PHASE G: Log Rotation

```bash
cat > /etc/logrotate.d/dns-services << 'EOF'
/var/log/adguardhome/*.log
/var/log/smartdns/*.log
/var/log/dns-warmer/*.log
{
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        systemctl reload adguardhome 2>/dev/null || true
        systemctl reload smartdns 2>/dev/null || true
    endscript
}
EOF
```

---

## PHASE H: Validation Tests

### H1. Plain DNS
```bash
dig @<PUBLIC_IP> google.com A
dig @<PUBLIC_IP> google.com AAAA
dig @<PUBLIC_IP> nonexistent.invalid A   # expect NXDOMAIN
```

### H2. DoH
```bash
curl -s "https://dns.example.com/dns-query?dns=$(echo -n '...' | base64)" \
  -H "accept: application/dns-message"
# Or use kdig:
kdig @dns.example.com +https google.com A
```

### H3. DoT
```bash
kdig @dns.example.com +tls google.com A
```

### H4. DoQ
```bash
kdig @dns.example.com +quic google.com A
```

### H5. SmartDNS Isolation Check
```bash
# Must fail:
dig @<PUBLIC_IP> -p 5335 google.com A
# Must succeed:
dig @127.0.0.1 -p 5335 google.com A
```

### H6. Cache Persistence Test
```bash
systemctl restart smartdns
sleep 5
dig @127.0.0.1 -p 5335 google.com A   # must answer from cache
```

### H7. TLS Certificate Check
```bash
openssl s_client -connect dns.example.com:853 -servername dns.example.com < /dev/null 2>&1 | grep -E "subject|issuer|notAfter"
```

### H8. Rate Limit Test
```bash
# Send >100 UDP queries/sec from one IP, verify drops
for i in $(seq 1 200); do dig @<PUBLIC_IP> google.com A & done
wait
```

### H9. Load Test
```bash
apt install -y dnsperf
# Create query file
echo "google.com A" > /tmp/queries.txt
echo "youtube.com A" >> /tmp/queries.txt
dnsperf -s <PUBLIC_IP> -d /tmp/queries.txt -l 30 -Q 500
```

---

## PHASE I: Observability Setup

### I1. Metrics to Monitor (minimum)
| Metric | Source |
|---|---|
| QPS by protocol | AdGuardHome stats API (`/control/stats`) |
| Cache hit ratio | AdGuardHome + SmartDNS logs |
| Upstream latency | SmartDNS logs |
| NXDOMAIN ratio | AdGuardHome stats |
| Active connections | `ss -s` |
| Cert expiry days | cron script (Phase D5) |
| Warmer success/fail | `/var/log/dns-warmer/warmer.log` |

### I2. AdGuardHome Stats API
```bash
# Poll every 60s from localhost
curl -s -u admin:password http://127.0.0.1:3000/control/stats | jq .
```

### I3. Basic Alerting (cron-based minimum)
```bash
cat > /etc/cron.d/dns-health << 'EOF'
*/5 * * * * root dig @127.0.0.1 -p 5335 google.com A +time=2 +tries=1 > /dev/null 2>&1 || echo "SmartDNS DOWN" | logger -t dns-alert
*/5 * * * * root dig @127.0.0.1 google.com A +time=2 +tries=1 > /dev/null 2>&1 || echo "AdGuardHome DOWN" | logger -t dns-alert
EOF
```

---

## PHASE J: Abuse Controls

### J1. Automatic IP Ban (nftables dynamic set)
```bash
# Ban an IP for 1 hour:
nft add element inet filter banned_ips { <ABUSER_IP> timeout 1h }

# View current bans:
nft list set inet filter banned_ips
```

### J2. Abuse Detection Cron
```bash
cat > /opt/dns-warmer/abuse-check.sh << 'EOF'
#!/bin/bash
# Flag IPs with >1000 queries in last 5 min from AGH query log
# Adjust path to actual query log location
LOG=/opt/adguardhome/work/data/querylog.json
if [ -f "$LOG" ]; thenABUSERS=$(tail -n 10000 "$LOG" | jq -r '.IP' 2>/dev/null | sort | uniq -c | sort -rn | awk '$1 > 1000 {print $2}')
  for IP in $ABUSERS; do
    nft add element inet filter banned_ips { "$IP" timeout 1h }
    logger -t dns-abuse "Auto-banned $IP"
  done
fi
EOF
chmod +x /opt/dns-warmer/abuse-check.sh

echo "*/5 * * * * root /opt/dns-warmer/abuse-check.sh" >> /etc/cron.d/dns-health
```

---

## PHASE K: Backup & Config Management

```bash
# Initialize git repo for configs
mkdir -p /opt/dns-config-backup
cd /opt/dns-config-backup
git init

# Daily backup script
cat > /etc/cron.daily/dns-backup << 'EOF'
#!/bin/bash
DEST=/opt/dns-config-backup
cp /etc/smartdns/smartdns.conf         $DEST/
cp /opt/adguardhome/conf/AdGuardHome.yaml $DEST/
cp /etc/nftables.conf                  $DEST/
cp /etc/dns-warmer/domains.txt         $DEST/
cp /opt/dns-warmer/warmer.py           $DEST/
cd $DEST
git add -A
git commit -m "backup $(date -u +%Y-%m-%dT%H:%M:%SZ)" --allow-empty
EOF
chmod +x /etc/cron.daily/dns-backup
```

---

## PHASE L: Go-Live Checklist

[ ] VPS: static IP, Ubuntu 22.04, time synced (chrony)
[ ] DNS A record: dns.example.com → <PUBLIC_IP>
[ ] TLS cert: valid, auto-renew tested
[ ] SmartDNS: running, localhost:5335 only, cache persistent
[ ] AdGuardHome: running, upstream = 127.0.0.1:5335 only
[ ] Warmer: running, querying 127.0.0.1:53 only
[ ] Firewall: default-deny, only 22/53/443/853/784 open
[ ] SmartDNS port 5335 blocked from public
[ ] Admin UI: 127.0.0.1:3000 only, strong password
[ ] Rate limiting: active (100 QPS/IP UDP)
[ ] Log rotation: configured
[ ] Health cron: active
[ ] Cert expiry cron: active
[ ] Abuse auto-ban: active
[ ] Config backup: git initialized, cron active
[ ] All protocol tests passed (H1–H9)
[ ] Load test passed (500 QPS sustained)


---

## Operations Runbook

### Restart Order (always follow this sequence)
```bash
systemctl restart smartdns
sleep 3
systemctl restart adguardhome
sleep 3
systemctl restart dns-warmer
```

### Failure Scenarios

| Scenario | Action |
|---|---|
| SmartDNS down | `systemctl restart smartdns` → verify `dig @127.0.0.1 -p 5335` |
| AdGuardHome down | `systemctl restart adguardhome` → check cert paths, port 53 cap |
| TLS expired | `certbot renew --force-renewal` → `systemctl restart adguardhome` |
| Upstream outage | Comment out bad upstream in `smartdns.conf` → `systemctl reload smartdns` |
| Abuse event | `nft add element inet filter banned_ips { <IP> timeout 1h }` |
| Cache corruption | `rm /var/lib/smartdns/smartdns.cache` → `systemctl restart smartdns` |

---

## Directory Layout (Final)

/opt/adguardhome/
  AdGuardHome/AdGuardHome   ← binary
  conf/AdGuardHome.yaml
  work/                     ← runtime data

/opt/smartdns/              ← (binary installed to /usr/sbin/smartdns)
/etc/smartdns/smartdns.conf
/var/lib/smartdns/smartdns.cache

/opt/dns-warmer/warmer.py
/etc/dns-warmer/domains.txt
/var/log/dns-warmer/warmer.log

/etc/nftables.conf
/etc/letsencrypt/live/dns.example.com/
/opt/dns-config-backup/     ← git repo


---

## Key Risks & Mitigations (Agent Must Verify)

| Risk | Mitigation | Verify |
|---|---|---|
| Open resolver abuse | Rate limit + auto-ban | H8 test passes |
| SmartDNS exposed | Firewall + bind localhost | H5 test passes |
| Cert expiry | Auto-renew + cron alert | D4 dry-run passes |
| Cache corruption | Graceful rebuild on bad file | H6 after corrupt test |
| Admin UI exposed | Bind 127.0.0.