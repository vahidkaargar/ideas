#!/usr/bin/env bash
# deploy/phases/A-host-preparation.sh — Phase A: Host Preparation
# Transcribed from: phases/01-host-preparation.md
#
# Mechanical transcription only. Not run against real hardware. Read this
# script (and the source file) before running it on a VPS.
#
# Sole ownership per CLAUDE.md: this phase is the sole owner of
# /opt/dns-config-backup (created at A3) and of memory ceilings / swap /
# vm.swappiness (set at A5/A6). Do not add a second swapfile, a second
# vm.swappiness value, or a second MemoryMax for unbound/adguardhome/nginx/
# ssh anywhere else.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=lib/common.sh
source lib/common.sh

require_root
phase_header "Phase A — host preparation (sizing, SSH hardening, sysctl, memory ceilings, swap)"

# =====================================================================
# A1. Provision the VPS, and know what will break first
# =====================================================================
#
# --- A1: pre-provisioning checks (manual / operator judgment) ---
# The six pre-purchase checks (AUP permits a public recursive resolver,
# outbound UDP/53 unfiltered, self-service PTR, movable floating IP object,
# static address across reboot/rebuild, out-of-band console) are business
# and provider-contract decisions that cannot be scripted. So is the
# second-instance provisioning for Phase B9 off-box verification, and the
# IPv4-only vs dual-stack decision recorded in the Phase Q6 decision register.
warn "A1: manual step — verify the six pre-purchase provider checks (AUP, unfiltered outbound UDP/53, self-service PTR, movable floating IP, static address across reboot/rebuild, out-of-band console) and record answers in the Phase Q6 decision register. NOT scripted."
warn "A1: manual step — provision a SECOND instance in the same region for Phase B9 off-box verification (built out fully in Phase H0); needed from Phase B9 onward. NOT scripted."
warn "A1: manual step — decide IPv4-only vs dual-stack (service family) and record in Q6; this also determines whether AAAA is published (Phase E/L) and whether nginx listens on [::]:443/[::]:80 (Phase E). NOT scripted."

# --- A1 VERIFY: baseline host facts ---
info "A1: running baseline host verification commands"
lsb_release -ds                       # expect: Ubuntu 24.04... LTS
nproc; free -g; df -h /
ip -4 addr show scope global; ip -6 addr show scope global

# --- A1 VERIFY: recursion from the root is possible (provider check 2) ---
dig +norecurse @198.41.0.4 . NS +noall +comments +answer
#   expect: flags include `aa` and NOT `ra`; the answer is the root NS set.
dig +norecurse @198.41.0.4 hostname.bind CH TXT +short
#   expect: a root-server site identifier.
dig +norecurse @198.41.0.4 . DNSKEY +bufsize=1232 +noall +comments +stats
#   expect: ~1 KB of answer, no `tc` flag (a `tc` flag here is only
#   legitimate during a root KSK rollover).
dig +norecurse @198.41.0.4 . NS +noall +comments | grep -E 'flags:'   # `aa`, no `ra`

warn "A1: manual step — the do-ip6 egress decision belongs to Phase C2 (ip -6 route show default plus queries to two root letters over IPv6); run it now on this host and carry the answer into Q6. NOT duplicated here."
echo "recursion egress family: do-ip6 ____ (per the C2 egress test)"
echo "service family decision: ____ (IPv4-only = publish no AAAA)"

warn "A1: manual step — the off-box test host built in Phase H0 must exist before Phase B; confirm it is reachable: ssh <TEST_HOST_IP> 'lsb_release -ds && echo TEST_HOST_REACHABLE'. NOT scripted (requires the second instance's address)."

warn "A1: manual step — 'reboot then reconnect and re-check ip -4 addr' to confirm the address survives reboot is an operator action requiring a new connection; not automated in this unattended script."

# =====================================================================
# A2. Base OS setup
# =====================================================================

# --- A2: package install and hostname/timezone ---
apt update && apt full-upgrade -y
hostnamectl set-hostname dns1
timedatectl set-timezone UTC

apt install -y \
  nftables chrony logrotate \
  curl wget jq git unzip ca-certificates \
  bind9-dnsutils knot-dnsutils \
  ethtool sysstat conntrack

systemctl enable --now chrony

# --- A2: break the chrony/DNSSEC deadlock now (IP-literal NTP sources) ---
install -d -m 0755 /etc/chrony/conf.d
backup_file /etc/chrony/conf.d/10-ip-literal.conf
cat > /etc/chrony/conf.d/10-ip-literal.conf <<'EOF'
# The time path MUST NOT depend on the DNS path. After Phase C5 this host
# resolves only through its own validator, and a validator with a skewed clock
# SERVFAILs every name - including the NTP pool names chrony needs to fix the
# clock. Every source here is an IP literal for that reason. Never add a
# hostname to this file.
#
# PREFER your provider's own NTP addresses if it publishes them: on-net, lower
# latency, and not subject to a third party's routing. The Cloudflare anycast
# literals below are the documented fallback
# (https://developers.cloudflare.com/time-services/ntp/usage/), but Cloudflare
# states the addresses may change - re-verify them at each Phase M review.
server 162.159.200.1   iburst
server 162.159.200.123 iburst

# Step the clock whenever it is more than 1 s out, not only during the first
# three updates after start. chrony.conf(5) on the second argument: "A negative
# value disables the limit." Without this, a host that skews WHILE RUNNING -
# resumed VM, drifting emulated RTC - slews instead of stepping and takes days
# to close an hours-wide gap, SERVFAILing every signed zone throughout.
makestep 1.0 -1
EOF

# --- A2: determine which makestep directive actually wins ---
info "A2: checking merged chrony config for effective makestep directive"
chronyd -p | grep -nE 'makestep|^server|^pool'
# The LAST makestep printed is the effective one. If that is `makestep 1 3`
# rather than `makestep 1.0 -1`, comment out the stock line in
# /etc/chrony/chrony.conf and re-run this command.
warn "A2: manual step — if 'chronyd -p' shows 'makestep 1 3' as the LAST occurrence (not 'makestep 1.0 -1'), comment out the stock makestep line in /etc/chrony/chrony.conf yourself, then re-run the chronyd -p check. NOT auto-edited by this script (requires reading which stock line is present)."

systemctl restart chrony
chronyc sources -v

# --- A2: free port 53 from systemd-resolved ---
confirm "A2: about to disable+mask systemd-resolved and replace /etc/resolv.conf (host DNS path change) — continue?"
systemctl disable --now systemd-resolved
systemctl mask systemd-resolved      # an apt upgrade of systemd happily re-enables units
                                     # it ships; masking is what makes the removal stick

backup_file /etc/resolv.conf
rm -f /etc/resolv.conf               # on a stock image this is a SYMLINK into
                                     # /run/systemd/resolve - replace it, never write
                                     # through it, or your content lands in a file that
                                     # something else owns and regenerates
cat > /etc/resolv.conf <<'EOF'
# BOOTSTRAP ONLY - this is the host's resolver until its own resolver exists.
# Unbound is not installed until Phase C and AdGuardHome not until Phase E, so
# right now the host has to resolve through somebody else's recursive resolver
# or apt, certbot and restic cannot run at all.
# Prefer your VPS provider's own resolver (address is in the image's cloud-init
# network config, or the provider's docs); the public addresses below are a
# stand-in for providers that do not publish one.
# Phase C5 replaces this file - see the note below. Nothing here is a value the
# finished system runs on.
nameserver 9.9.9.9
nameserver 1.1.1.1
options timeout:2 attempts:2
EOF

# --- A2 VERIFY ---
info "A2: running verification commands"
lsb_release -ds                        # Ubuntu 24.04.x LTS
apt list --installed 2>/dev/null | grep -E '^(ufw|fail2ban)/' # expect no output
chronyc tracking | grep -E 'Leap status|System time'          # Normal, offset < 100 ms

# The time path does not depend on the DNS path. Check the merged CONFIG, not
# `chronyc sources` - chronyc reverse-resolves what it displays.
chronyd -p | grep -cE '^[[:space:]]*server[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
#   expect >= 2 IP-literal server lines
chronyd -p | grep -E 'makestep' | tail -1      # expect: makestep 1.0 -1

# The real proof: chrony still syncs with name resolution taken away entirely.
confirm "A2: about to move /etc/resolv.conf aside and restart chrony to prove IP-literal-only sync — continue?"
mv /etc/resolv.conf /etc/resolv.conf.off; systemctl restart chrony; sleep 20
chronyc tracking | head -2; mv /etc/resolv.conf.off /etc/resolv.conf
# Reference ID must name one of the IP literals. `00000000` means the box would
# not have recovered from a clock excursion after Phase C5 - fix it here, now.

systemctl is-active systemd-resolved   # expect: inactive
systemctl is-enabled systemd-resolved  # expect: masked
ss -lnup 'sport = :53'                 # expect no output - port 53 is free
dig +short deb.debian.org @9.9.9.9 >/dev/null && echo HOST_RESOLUTION_OK
test -e /etc/systemd/resolved.conf.d && echo 'STALE: resolved drop-in on a host with no resolved'

warn "A2: manual step — 'reboot' then, after reconnecting, verify /etc/resolv.conf came back exactly as written (test -L /etc/resolv.conf must be false; grep -c '^nameserver' /etc/resolv.conf must match the count written above). Requires a new connection after reboot; NOT scripted here."

# =====================================================================
# A3. Service users
# =====================================================================
# NOTE: do NOT create an 'unbound' user by hand — Phase C's package install
# creates it. Creating one here would collide with package ownership.

# --- A3: adguardhome service user ---
useradd -r -s /usr/sbin/nologin -d /opt/adguardhome -M adguardhome
install -d -m 0750 -o adguardhome -g adguardhome /opt/adguardhome

# --- A3: /opt/dns-config-backup — SOLE OWNER: Phase A3 (creates it).
# Phase I, J, P4c, Q5a append/commit to it; Phase K backs it up off-host;
# none of those phases create or delete it. Do not duplicate this creation
# in another phase script. ---
install -d -m 0750 -o root -g root /opt/dns-config-backup
git init -q -b main /opt/dns-config-backup
git -C /opt/dns-config-backup config user.email 'root@dns1'
git -C /opt/dns-config-backup config user.name  'dns-config-backup'

warn "A3: note — the human administrator account 'dnsadmin' is created in A4, BEFORE SSH is hardened. Do not reorder A3/A4 steps when running phases out of order."

# --- A3 VERIFY ---
info "A3: running verification commands"
id adguardhome                              # uid=... shell=/usr/sbin/nologin
getent passwd adguardhome | cut -d: -f7     # /usr/sbin/nologin
ls -ld /opt/adguardhome                     # drwxr-x--- adguardhome adguardhome
id smartdns 2>&1; id dnswarmer 2>&1         # both: "no such user" - correct

ls -ld /opt/dns-config-backup                                    # drwxr-x--- root root
git -C /opt/dns-config-backup rev-parse --is-inside-work-tree    # true
git -C /opt/dns-config-backup config user.email                  # non-empty

# =====================================================================
# A4. SSH hardening
# =====================================================================

# --- A4 Step 0: create the admin account FIRST. Do not skip. ---
warn "A4 Step 0: manual step — the authorized_keys public key below is a placeholder ('ssh-ed25519 AAAAC3Nza... admin@laptop'). Replace it with the real operator public key before running this block. NOT auto-generated."
useradd -m -s /bin/bash -G sudo dnsadmin
install -d -m 0700 -o dnsadmin -g dnsadmin /home/dnsadmin/.ssh
install -m 0600 -o dnsadmin -g dnsadmin /dev/stdin /home/dnsadmin/.ssh/authorized_keys <<'EOF'
ssh-ed25519 AAAAC3Nza... admin@laptop
EOF
passwd -l dnsadmin                                  # key only; no password to guess
su - dnsadmin -c 'sudo -n true' && echo SUDO_OK
# Do not continue until SUDO_OK printed above.

# --- A4 Step 1: write the drop-in, but do NOT reload yet ---
backup_file /etc/ssh/sshd_config.d/00-hardening.conf
cat > /etc/ssh/sshd_config.d/00-hardening.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers dnsadmin
MaxAuthTries 6
MaxSessions 4
MaxStartups 10:30:60
LoginGraceTime 45
AllowTcpForwarding yes
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
EOF
sshd -t && echo CONFIG_OK
ls /etc/ssh/sshd_config.d/     # nothing may sort before 00-hardening.conf

# Socket activation caveat — verify on this image before ever changing Port/ListenAddress:
systemctl is-enabled ssh.socket 2>/dev/null || true   # 'enabled' means socket activation is in use

# --- A4 Step 2: reload, then prove a second login before closing the first ---
confirm "A4 Step 2: about to reload sshd with hardened config (PasswordAuthentication no, PermitRootLogin no, AllowUsers dnsadmin) — this can lock you out if misconfigured. Confirm you will verify a NEW login before closing this session. Continue?"
systemctl reload ssh
sshd -T | grep -Ei '^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication|authenticationmethods|allowusers|maxauthtries|logingracetime)'
# Expected output includes `passwordauthentication no`.

warn "A4 Step 2: manual step — in a NEW terminal, with the existing root session still open, run: ssh dnsadmin@<PUBLIC_IP> 'id && sudo -n true && echo LOGIN_OK'. Only after LOGIN_OK may you close the root session. NOT scripted (requires a second, independent connection)."

# --- A4 Step 3: a restricted key for the admin-UI tunnel ---
warn "A4 Step 3: manual step — add a SECOND authorized_keys line for the tunnel-only key, alongside the unrestricted key: 'restrict,port-forwarding,permitopen=\"127.0.0.1:3000\" ssh-ed25519 AAAAC3Nza... tunnel@laptop'. Replace the placeholder key. NOT auto-appended by this script to avoid overwriting the operator's real authorized_keys file unattended."

# --- A4 Step 4: the admin-UI access procedure (reference only, not executed) ---
# ssh -N -L 3000:127.0.0.1:3000 dnsadmin@dns.example.com
# then browse to http://127.0.0.1:3000 on your own machine.
# Port 3000 is never opened in the Phase B firewall; AGH's http.address stays
# 127.0.0.1:3000 (decision 5). There is no other supported path to the admin UI.
info "A4 Step 4: admin-UI is reached only via: ssh -N -L 3000:127.0.0.1:3000 dnsadmin@dns.example.com (see script comment). This is documented, not executed, here."

# --- A4: fail2ban, if you keep it (optional, not installed by A2's package set) ---
if command -v fail2ban-client >/dev/null 2>&1; then
    warn "A4: fail2ban detected on host. Its default banaction (iptables-multiport) builds a parallel iptables ruleset invisible to 'nft list ruleset'. Writing nftables banaction override."
    install -d -m 0755 /etc/fail2ban/jail.d
    backup_file /etc/fail2ban/jail.d/00-nftables.conf
    cat > /etc/fail2ban/jail.d/00-nftables.conf <<'EOF'
# /etc/fail2ban/jail.d/00-nftables.conf
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
EOF
fi

# --- A4 VERIFY ---
info "A4: running verification commands"
sshd -T | grep -Ei '^(passwordauthentication|permitrootlogin|authenticationmethods|allowusers)'
# passwordauthentication MUST print 'no'

warn "A4 VERIFY: manual steps — the following checks require an external client and are not run from this script: 'ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no dnsadmin@<PUBLIC_IP>' (expect Permission denied (publickey)); the SSH tunnel curl check to http://127.0.0.1:3000/ (expect 200 or 302); the restricted-key forwarding-refusal check; 'nmap -Pn -p 3000 <PUBLIC_IP>' (expect filtered)."

# =====================================================================
# A5. sysctl and limits — the corrected set
# =====================================================================

# --- A5: interactive-shell nofile limit (NOT the daemon limit — see note) ---
install -d -m 0755 /etc/security/limits.d
backup_file /etc/security/limits.d/dns.conf
cat > /etc/security/limits.d/dns.conf <<'EOF'
# INTERACTIVE SHELLS ONLY. pam_limits does not apply to systemd services -
# the daemon limit is LimitNOFILE= in each unit file (Phases C, D, E).
*    soft nofile 1000000
*    hard nofile 1000000
EOF

# --- A5: /etc/sysctl.d/99-dns.conf — OWNER: Phase A. Companion file
# /etc/sysctl.d/99-nftables-edge.conf is Phase B's; disjoint key sets,
# no key may appear in both. vm.swappiness is set here and ONLY here
# (sole owner: Phase A6/A5 per the plan's ownership note). ---
backup_file /etc/sysctl.d/99-dns.conf
cat > /etc/sysctl.d/99-dns.conf <<'EOF'
# OWNER: Phase A. Companion file: /etc/sysctl.d/99-nftables-edge.conf (Phase B,
# edge hardening). No key may appear in both - sysctl.d applies in lexical
# order and the later file wins with no warning.

# ---- file descriptors ----
fs.file-max = 1000000

# ---- socket buffers ----
# rmem_max/wmem_max are CEILINGS. Only quic-go (AGH DoQ + HTTP/3) uses them:
# it targets ~7 MB via setsockopt and warns in the log if capped. 25 MB is
# comfortably above quic-go's documented 7.5 MB recommendation.
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400

# rmem_default is the default sk_rcvbuf for every socket that does NOT call
# setsockopt - which is believed to include AGH's plain UDP:53 listener.
# VERIFY BEFORE TRUSTING: run load, then check `nstat -az | grep UdpRcvbufErrors`.
# Only raise this above the 212992 default if that counter is non-zero.
# Note this is a system-wide default, not a DNS-specific one.
net.core.rmem_default = 8388608
net.core.wmem_default = 4194304

# Per-socket floor that survives global memory pressure.
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# NOTE: net.ipv4.udp_mem is in PAGES (4 KiB), not bytes. The kernel's
# auto-computed default on 4 GB is ~384/512/768 MiB, which brackets the
# v1 value rather than being uniformly larger. Deliberately omitted.
#   sysctl net.ipv4.udp_mem   (multiply by 4096 for bytes)

# ---- backlogs / softirq ----
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000
net.ipv4.tcp_max_syn_backlog = 65535
# net.ipv4.tcp_syncookies is deliberately NOT set here. It is an edge-hardening
# knob and Phase B sets it in 99-nftables-edge.conf, which sorts later and would
# win anyway. Verified there, not here.

# ---- outbound (Unbound -> authoritatives on TCP fallback; ACME; apt) ----
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# ---- allocator headroom for softirq under flood ----
# Read the pre-change default first: sysctl vm.min_free_kbytes
# init_per_zone_wmark_min() gives roughly 8-16 MB on a 4 GB host, so 64 MB is
# already 4-8x the default. Only go to 128 MB if you actually observe order-0
# allocation failures in dmesg - it is permanently reserved RAM.
vm.min_free_kbytes = 65536

# The ONE swappiness setting in this plan. It pairs with the swapfile in A6,
# which owns swap and memory policy end to end. No other phase writes a
# swappiness value and no /etc/sysctl.d/99-swap.conf exists - if one is on the
# host it is stale, it sorts later, and it is silently overriding this line.
vm.swappiness = 10

# ---- conntrack ----
# These are Phase A's (see the ownership note above), even though the firewall
# is Phase B's. udp/53 is NOTRACK'd in a raw table (decision 9, Phase B), so
# they govern TCP/53, 443, 853 and your SSH session - not the bulk DNS path.
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
net.netfilter.nf_conntrack_udp_timeout = 10
net.netfilter.nf_conntrack_udp_timeout_stream = 60
EOF

# --- A5: nf_conntrack keys don't exist until the module is loaded ---
echo nf_conntrack > /etc/modules-load.d/conntrack.conf
modprobe nf_conntrack
sysctl --system

# --- A5: RPS tuning script and unit (spread receive softirq across vCPUs) ---
cat > /usr/local/sbin/rps-tune.sh <<'EOF'
#!/bin/bash
set -euo pipefail
IF=$(ip -o -4 route show default | awk '{print $5}' | head -1)
[ -n "$IF" ] || { echo "no default route interface" >&2; exit 1; }

# If the NIC has real hardware queues, use them and skip RPS entirely.
if ethtool -l "$IF" 2>/dev/null | awk '/^Combined:/{print $2; exit}' | grep -qvx 1; then
  ethtool -L "$IF" combined 2 || true
  echo "hardware multiqueue on $IF; skipping RPS"
  exit 0
fi

NQ=$(ls -d /sys/class/net/"$IF"/queues/rx-* | wc -l)
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries
for q in /sys/class/net/"$IF"/queues/rx-*; do
  echo 3 > "$q/rps_cpus"                    # bitmask for CPUs 0+1 on a 2 vCPU box
  echo $((32768 / NQ)) > "$q/rps_flow_cnt"  # must be rps_sock_flow_entries / num queues
done
echo "RPS enabled on $IF ($NQ rx queue(s))"
EOF
chmod +x /usr/local/sbin/rps-tune.sh

cat > /etc/systemd/system/rps-tune.service <<'EOF'
[Unit]
Description=Enable RPS on the primary NIC
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/rps-tune.sh

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now rps-tune.service

# --- A5 VERIFY ---
info "A5: running verification commands"
sysctl net.core.rmem_default net.ipv4.udp_rmem_min net.core.netdev_budget vm.min_free_kbytes
sysctl net.ipv4.udp_mem                # informational; multiply by 4096 for bytes
sysctl net.netfilter.nf_conntrack_max  # must return a value, not an error
sysctl vm.swappiness                   # 10, and set by this file alone

# The ownership split holds - no key is written by both drop-ins. Re-run this
# after Phase B, which is when the second file appears:
test -f /etc/sysctl.d/99-nftables-edge.conf && \
  comm -12 <(grep -oE '^[a-z0-9_.]+' /etc/sysctl.d/99-dns.conf | sort -u) \
           <(grep -oE '^[a-z0-9_.]+' /etc/sysctl.d/99-nftables-edge.conf | sort -u)
# expect no output; anything printed is a key the later file silently wins
ls /etc/sysctl.d/99-swap.conf 2>/dev/null && echo 'STALE: delete it, A5 owns vm.swappiness' || true

systemctl status rps-tune.service --no-pager | tail -3   # must show the script's echo line
IF=$(ip -o -4 route show default | awk '{print $5}' | head -1)
cat /sys/class/net/"$IF"/queues/rx-*/rps_cpus              # expect 3 (unless multiqueue)
ethtool -l "$IF"

# quic-go is no longer complaining - this is the proof rmem_max is load-bearing:
journalctl -u adguardhome --since -10m | grep -i 'receive buffer size' || true   # must be empty

warn "A5 VERIFY: manual step — 'nstat -az | grep -Ei UdpRcvbufErrors|UdpInErrors|UdpNoPorts' PASS criterion (UdpRcvbufErrors delta == 0) requires reading before AND after a Phase H load run; not a single-point check."
mpstat -P ALL 1 5      # %soft spread across CPUs, not pinned to CPU0

# =====================================================================
# A6. Memory safety
# =====================================================================
# SOLE OWNER of memory ceilings, swap, and vm.swappiness for the DNS stack
# (unbound, adguardhome, nginx, sshd) per CLAUDE.md's single-ownership table.
# vm.swappiness itself is set in A5's 99-dns.conf; this section owns the
# swapfile and every MemoryHigh/MemoryMax/OOMScoreAdjust drop-in below.
# Phase N sets restart policy / start-limit guards on these same units —
# a different control — and must not duplicate a memory ceiling.

# --- A6: 2 GB swapfile — shock absorber, not a paging path ---
confirm "A6: about to create and enable a 2G swapfile at /swapfile and add it to /etc/fstab — continue?"
# fallocate produces an unusable swapfile on Btrfs and can trigger
# "swapon: /swapfile: skipping - it appears to have holes" elsewhere.
fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
backup_file /etc/fstab
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# --- A6: per-unit memory ceilings — the canonical set ---
# unbound
confirm "A6: about to write a systemd override for unbound (MemoryHigh=1200M, MemoryMax=1600M, OOMScoreAdjust=-300) — this changes a boot-service unit. Continue?"
install -d -m 0755 /etc/systemd/system/unbound.service.d
backup_file /etc/systemd/system/unbound.service.d/override.conf
cat > /etc/systemd/system/unbound.service.d/override.conf <<'EOF'
[Service]
MemoryAccounting=yes
MemoryHigh=1200M
MemoryMax=1600M
OOMScoreAdjust=-300
EOF

# adguardhome
confirm "A6: about to write a systemd override for adguardhome (MemoryHigh=800M, MemoryMax=1200M, OOMScoreAdjust=-500) — this changes a boot-service unit. Continue?"
install -d -m 0755 /etc/systemd/system/adguardhome.service.d
backup_file /etc/systemd/system/adguardhome.service.d/override.conf
cat > /etc/systemd/system/adguardhome.service.d/override.conf <<'EOF'
[Service]
MemoryAccounting=yes
MemoryHigh=800M
MemoryMax=1200M
# AGH is the public front door: make it the LAST thing the kernel picks.
OOMScoreAdjust=-500
EOF

# nginx
confirm "A6: about to write a systemd override for nginx (MemoryMax=256M, OOMScoreAdjust=-200) — this changes a boot-service unit. Continue?"
install -d -m 0755 /etc/systemd/system/nginx.service.d
backup_file /etc/systemd/system/nginx.service.d/override.conf
cat > /etc/systemd/system/nginx.service.d/override.conf <<'EOF'
[Service]
MemoryAccounting=yes
MemoryMax=256M
OOMScoreAdjust=-200
EOF

# ssh
confirm "A6: about to write a systemd override for ssh (OOMScoreAdjust=-500) — this changes the boot-service unit for the SSH listener. Continue?"
install -d -m 0755 /etc/systemd/system/ssh.service.d
backup_file /etc/systemd/system/ssh.service.d/override.conf
cat > /etc/systemd/system/ssh.service.d/override.conf <<'EOF'
[Service]
# -500, NOT -900. oom_score_adj is inherited across fork(), so this value
# applies to every login session and everything a user launches from it.
# At -900 a runaway process in an SSH session becomes nearly immune to the
# OOM killer, on a host that has no memory headroom by design.
OOMScoreAdjust=-500
EOF

warn "A6: optional variant — if you want the sshd listener protected at -900 without protecting user sessions, set -900 in ssh.service.d/override.conf above and add a matching OOMScoreAdjust=0 drop-in on user@.service yourself. NOT applied by default here (the plan's default is -500)."

# --- A6: apply the ceilings ---
confirm "A6: about to daemon-reload and restart unbound, adguardhome, nginx to apply the new memory ceilings — this restarts boot services. Continue?"
systemctl daemon-reload
systemctl restart unbound adguardhome nginx

# --- A6 VERIFY ---
info "A6: running verification commands"
systemctl show unbound     -p MemoryAccounting -p MemoryHigh -p MemoryMax -p MemoryCurrent -p OOMScoreAdjust
#   expect MemoryHigh=1258291200 (1200M) / MemoryMax=1677721600 (1600M) / -300
systemctl show adguardhome -p MemoryHigh -p MemoryMax -p MemoryCurrent -p OOMScoreAdjust
#   expect MemoryHigh=838860800 (800M) / MemoryMax=1258291200 (1200M) / -500
systemctl show nginx       -p MemoryMax -p OOMScoreAdjust        # 268435456 (256M) / -200
systemctl show ssh         -p OOMScoreAdjust    # must be -500, not -900

# Nobody set a second ceiling behind this section's back.
ls /etc/systemd/system/{unbound,adguardhome,nginx}.service.d/
grep -rl 'Memory\(High\|Max\)' \
     /etc/systemd/system/{unbound,adguardhome,nginx}.service.d/ 2>/dev/null || true
# exactly one file per unit, and it is the one this section wrote.

free -h && swapon --show && sysctl vm.swappiness   # 10; Used stays at 0 in steady state

warn "A6 VERIFY: manual step — 'systemd-cgtop -m --order=memory -n 5' live budget check is meant to be read during a Phase H load run, not standalone."

grep -E '^(oom|oom_kill|max|high) ' /sys/fs/cgroup/system.slice/unbound.service/memory.events
grep -E '^(oom|oom_kill|max|high) ' /sys/fs/cgroup/system.slice/adguardhome.service/memory.events
# PASS: oom 0 and oom_kill 0. A non-zero `high` is EXPECTED (MemoryHigh doing
# its job); a rising `max` means MemoryMax is too low.

journalctl -k --since -24h | grep -iE 'out of memory|oom-kill' || true    # must be empty

systemctl restart unbound && sleep 3 && dig @127.0.0.1 -p 5335 example.com A +short

info "Phase A complete."
echo
echo "=== Phase A verification summary ==="
echo "Re-run these to confirm Phase A held:"
echo "  lsb_release -ds && chronyc tracking && sysctl vm.swappiness"
echo "  systemctl show unbound adguardhome nginx -p MemoryHigh -p MemoryMax -p OOMScoreAdjust"
echo "  free -h && swapon --show"
echo "  grep -E '^(oom|oom_kill) ' /sys/fs/cgroup/system.slice/{unbound,adguardhome}.service/memory.events"
echo "  journalctl -k --since -24h | grep -iE 'out of memory|oom-kill'   # must be empty"
echo "See phases/01-host-preparation.md A1-A6 VERIFY blocks for the full set,"
echo "including the manual steps flagged with warn() above (provider checks,"
echo "second-instance provisioning, dnsadmin key installation, second-login proof)."
