[Plan index](../dns-server-plan.md) · [Next: Firewall and Edge Packet Policy](./02-firewall.md)

---

**On this page**

- [PHASE A: Host Preparation](#phase-a-host-preparation)
  - [A1. Provision the VPS, and know what will break first](#a1-provision-the-vps-and-know-what-will-break-first)
  - [A2. Base OS setup](#a2-base-os-setup)
  - [A3. Service users](#a3-service-users)
  - [A4. SSH hardening](#a4-ssh-hardening)
  - [A5. sysctl and limits — the corrected set](#a5-sysctl-and-limits-the-corrected-set)
  - [A6. Memory safety](#a6-memory-safety)

---

## PHASE A: Host Preparation

### A1. Provision the VPS, and know what will break first

**Baseline spec: 2 vCPU, 4 GB RAM, 40 GB SSD, static IPv4, Ubuntu 24.04 LTS.** Optional
static IPv6. Any provider with low-latency transit and a stable IP (Hetzner, Vultr,
DigitalOcean and equivalents are all fine). Do not accept a provider that reassigns the IP
on reboot — the IP is published in DNS records, in client configuration, and in a
Certificate Transparency log.

The v1 plan asserted this size without a model behind it. Here is the model. **Cache RAM
is not the constraint on this box and never appears in the list of things that fail.**

**Steady-state memory budget.** Unbound with the Phase C cache sizes runs a few hundred MB
including slab overhead; AdGuardHome's Go heap plus its in-memory query-log ring runs
150–400 MB under load; nginx with a handful of workers is tens of MB. Total is roughly
0.8–1.4 GB of 4 GB. There is no warmer daemon (decision 3), so nothing is budgeted for it.
The problem is not the steady state, it is behaviour under pressure — see A6.

**Throughput, per path.** These are planning estimates for 2 vCPU / 4 GB. Replace them
with the measured numbers from the Phase H benchmark; do not quote them as results.

| Path | Estimated sustained QPS | Limited by |
|---|---|---|
| Do53/UDP, AGH cache hit, file query log **off** | ~8,000–15,000 | AGH CPU and RX softirq (see the RPS note in A5) |
| Do53/UDP, AGH cache hit, file query log **on** | ~2,000–4,000 | JSON encode + synchronous disk write |
| Do53/UDP, AGH miss, Unbound cache hit | ~4,000–7,000 | two processes, two loopback round trips, two parses |
| Do53/UDP, cold name, full recursion from root | ~300–800 | `max_goroutines` divided by miss latency; recursion is 2–5 network round trips for a name whose delegation chain is cold |
| **TCP/53** | unbounded until CPU | **nothing** — the Phase B nftables meter matches `udp dport 53` only, and dnsproxy gates its own limiter on `d.Proto == ProtoUDP` |
| **DoH / DoT / DoQ** | unbounded until CPU | **nothing at the application layer** — same `ProtoUDP` gate. TLS handshake cost is the practical brake |
| DoT/DoQ/DoH new handshakes, ECDSA P-256 | not the binding constraint | — (with RSA-2048 it would be ~1,000–2,000/s and would be the constraint; see decision 10) |

**Binding constraints, in the order they actually bite.**

1. **The AdGuardHome query log on disk.** At 500 QPS sustained, 500 × 86400 = 43.2 M
   entries per day; AGH's JSON query-log lines run a couple of hundred bytes each, so this
   is gigabytes of writes per day on a 40 GB volume. What stops that from filling the disk
   is the retention interval, not the write rate: Phase E ships the shipped-default
   `querylog` retention, which bounds the on-disk set to a fraction of a day's traffic.
   Lengthen that interval — which is exactly what someone does the first time they want
   longer-range statistics — and this becomes the single most likely thing to take the
   service down first. Phase E owns the shipped retention default and Phase Q offers the
   stricter opt-in postures; Phase G rotates; Phase I alarms on disk.
2. **The conntrack table**, *for the transports that are still tracked.* `nf_conntrack_max`
   is 65536 on a 4 GB host (kernel `nf_conntrack_init_start()` uses `max_factor = 1` when
   hashsize is unset), which with default UDP timeouts is a ceiling near **2,185 aggregate
   accepted QPS** — note *accepted*: packets the rate limiter drops never reach the table.
   Decision 9 removes udp/53 from this by NOTRACK'ing it in a raw table (Phase B), which
   is why the constraint has moved down this list rather than off it. TCP/53, 443, 853 and
   your SSH session still consume entries, and when the table fills you lose SSH too.
3. **TLS handshake CPU**, only if you let a certificate be RSA. Decision 10 makes it ECDSA
   P-256, which removes this from the list. It returns the moment someone reissues with
   defaults.
4. **The AGH-miss round trip.** Every query AGH does not answer from its own cache costs a
   full serialize / socket / parse cycle through a second process. On 2 vCPU that is a
   large fraction of per-query CPU. The cheapest throughput lever on this box is making
   AGH's cache large enough that most queries never reach Unbound — Phase E.
5. **UDP receive-buffer drops during Go GC pauses**, governed by `net.core.rmem_default`.
   Silent: the counter is `UdpRcvbufErrors`, not a log line. See A5.

**Concurrency ceiling.** AdGuardHome's `dns.max_goroutines` is "the max number of parallel
goroutines for processing incoming requests" (verified at `internal/dnsforward/config.go`).
The official AGH configuration reference publishes **no default value**, so do not compute
a ceiling from a number you read on a wiki. Let AGH write its config once, read back what
it chose, and compute from that plus your measured miss latency:

```bash
grep -n 'max_goroutines' /opt/adguardhome/conf/AdGuardHome.yaml
# ceiling_qps ~= max_goroutines / miss_latency_seconds
```

Phase E sets it explicitly rather than inheriting an undocumented default.

**When to scale up versus out.** Use thresholds, not intuition.

| Signal | Action |
|---|---|
| Sustained load average > 1.5 on 2 vCPU, or `%steal` consistently > 5% | Scale **up** (more vCPU, or a provider with quieter neighbours) |
| `MemoryCurrent` > 70% of RAM with Unbound's cache sizes already tuned | Scale **up** (RAM) |
| Cache hit ratio falling while the cache is already at its ceiling | Scale **up** (RAM), not out — a second node halves each node's hit rate |
| You care about uptime at all | Scale **out** — a second node, now. This is not a traffic threshold. See Phase N |
| Clients in a second region with > 80 ms RTT | Scale **out** geographically (floating IP per region, not anycast) |
| Provider egress or packets-per-second cap being hit | Scale **out** |

The asymmetry that matters: scaling **up** buys throughput, scaling **out** buys
availability, and this service's realistic failure mode is availability. A 2 vCPU / 4 GB
box with a warm cache will serve well past the load the Phase H benchmark targets. You
will hit "the host rebooted" long before you hit "the host is too small".

**Cost, order of magnitude — ASSUMED, check current pricing before quoting it.**
Two small VPS instances (2 vCPU / 4 GB) at roughly EUR 5–8/month each, one floating or
reserved IP at ~EUR 1/month, and object storage for the Phase K restic repository at
~USD 1/month (config-only snapshots are well under 1 GB) comes to roughly **EUR 15–18 per
month for a genuinely redundant service**. For comparison, anycast starts at a /24 lease —
current market is nearer USD 90–150/month — plus ASN administration plus multiple PoPs.
That is an order-of-magnitude cost increase for capability this service does not need. See
Phase N for the redundancy design that the EUR 15–18 actually buys.

**VERIFY**

```bash
lsb_release -ds                       # expect: Ubuntu 24.04... LTS
nproc; free -g; df -h /
ip -4 addr show scope global; ip -6 addr show scope global
# the IP must survive a reboot:
reboot   # then reconnect and re-check `ip -4 addr`
```

---

### A2. Base OS setup

Ubuntu 24.04 LTS. Not 22.04 — decision 1. The package set below is deliberately smaller
than v1's; two packages were removed on purpose.

**Removed: `ufw`.** ufw is a front end that owns and rewrites its own tables. Running it
alongside the hand-written `/etc/nftables.conf` from Phase B gives you two rulesets, two
sources of truth, and precedence that depends on hook priorities nobody is tracking. The
plan uses raw nftables (and needs a `raw` table for decision 9, which ufw does not model).
Pick one. This plan picks nftables.

**Removed by default: `fail2ban`.** After A4 the host accepts `AuthenticationMethods
publickey` only — there is no credential to brute-force, so the sshd jail is log hygiene,
not a security control. If you keep it for the log hygiene, you **must** change its ban
action, because Debian/Ubuntu's default `banaction` is `iptables-multiport`, which builds
a parallel iptables ruleset that `nft list ruleset` will not show you — see A4.

**Kept, with justification:** `nftables` (Phase B), `chrony` (below), `logrotate`
(Phase G), `curl`/`wget`/`jq` (health checks and the Phase I metrics scraping),
`git` (Phase K config repo), `ca-certificates` (ACME and any HTTPS blocklist fetch).
**Added:** `bind9-dnsutils` for `dig`, `knot-dnsutils` for `kdig` (the only convenient way
to test DoT and DoQ in Phase H), `ethtool` for the A5 NIC-queue check, `sysstat` for
`mpstat` in the A5 verification, `conntrack` to inspect the table referenced in A1 and
Phase B. `libcap2-bin` is **not** needed — decision 8 means there is no `setcap` step.

`chrony` is not optional on this host. DNSSEC signatures carry inception and expiration
timestamps; a clock that drifts far enough makes Unbound SERVFAIL every signed zone, which
presents as a total outage with no obvious cause.

```bash
apt update && apt full-upgrade -y
hostnamectl set-hostname dns1
timedatectl set-timezone UTC

apt install -y \
  nftables chrony logrotate \
  curl wget jq git unzip ca-certificates \
  bind9-dnsutils knot-dnsutils \
  ethtool sysstat conntrack

systemctl enable --now chrony
```

Automatic security updates are **not** configured here — that is Phase M, together with
the upgrade and rollback procedure for the two daemons that live outside apt.

**Free port 53 from systemd-resolved.** Ubuntu Server runs `systemd-resolved` with a stub
listener on `127.0.0.53:53`. AdGuardHome binds `0.0.0.0:53` in Phase E, which covers that
address, so the bind fails and AGH will not start. On a host whose entire job is DNS, the
least surprising outcome is to remove resolved from the picture and manage `/etc/resolv.conf`
directly.

Remove it **entirely** — disabled and masked — rather than merely turning off its stub
listener with a `DNSStubListener=no` drop-in. Two reasons. A resolver box does not need a
second resolver on it, and every remaining resolved feature (its own cache, its own
search-domain handling, its own idea of which upstream to use) is a way for host lookups to
take a path that is not the validating one this plan builds. And once the unit is gone,
`resolved.conf.d` is dead configuration: **no phase in this plan writes a `DNSStubListener`
setting**, because there is no resolved left to read it. If you find such a drop-in on the
host, it is stale.

```bash
systemctl disable --now systemd-resolved
systemctl mask systemd-resolved      # an apt upgrade of systemd happily re-enables units
                                     # it ships; masking is what makes the removal stick
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
```

**Why this file gets written twice, and why the second write keeps no fallback.** Phase C5,
once Unbound has been proved to validate, replaces the whole file with a single
`nameserver 127.0.0.1` line and **no external entry**. Do not be tempted to leave one public
resolver behind "just in case". glibc walks the `nameserver` list on timeout without saying
so anywhere, which means a fallback entry silently routes the host's own lookups around the
validating path — and it does so precisely when the validating path is broken, i.e. the one
moment you needed to find out. Accept the consequence instead: while AdGuardHome is down the
host cannot resolve, and `apt`, `certbot renew` and restic fail loudly rather than quietly
resolving through an unvalidated third party. Phase C owns the flip; the Phase L go-live
checklist verifies it actually happened and that exactly one nameserver line remains.

Some cloud images regenerate `/etc/resolv.conf` from cloud-init on boot. The verification
below is a reboot check for exactly that; if the file comes back changed, disable
cloud-init's `resolv_conf` module rather than fighting it with `chattr`.

**VERIFY**

```bash
lsb_release -ds                        # Ubuntu 24.04.x LTS
apt list --installed 2>/dev/null | grep -E '^(ufw|fail2ban)/' # expect no output
chronyc tracking | grep -E 'Leap status|System time'          # Normal, offset < 100 ms
systemctl is-active systemd-resolved   # expect: inactive
systemctl is-enabled systemd-resolved  # expect: masked
ss -lnup 'sport = :53'                 # expect no output - port 53 is free
dig +short deb.debian.org @9.9.9.9 >/dev/null && echo HOST_RESOLUTION_OK
test -e /etc/systemd/resolved.conf.d && echo 'STALE: resolved drop-in on a host with no resolved'
reboot
# after reconnecting - the bootstrap file must come back exactly as written:
test -L /etc/resolv.conf && echo 'FAIL: cloud-init restored the symlink'
grep -c '^nameserver' /etc/resolv.conf # expect the count you wrote above (2 with both
                                       # stand-ins, 1 with a single provider resolver)
```

This is still the bootstrap value at this point in the build. The final state of this file —
`nameserver 127.0.0.1`, one line, no fallback — is set by Phase C5 and checked by Phase L.

---

### A3. Service users

Unbound is installed from the Ubuntu archive in Phase C, and its package creates the
`unbound` system user, `/var/lib/unbound`, and the trust-anchor file. **Do not create an
unbound user by hand** — you will end up with a UID that does not own the package's
directories and Unbound will fail to write `root.key`.

That leaves exactly one service account to create here. There is no `smartdns` user
(decision 2) and no `dnswarmer` user (decision 3). `nginx` is created by its own package
in Phase D.

```bash
useradd -r -s /usr/sbin/nologin -d /opt/adguardhome -M adguardhome
install -d -m 0750 -o adguardhome -g adguardhome /opt/adguardhome
```

`-M` avoids creating a home directory before the install path exists; the `install -d`
line then creates it with the mode the Phase E config file needs (the config contains the
admin password hash, so `0750` on the directory and `0640` on the file are load-bearing —
Phase E sets the file mode).

**The config staging repository, created here because Phase I writes into it first.**
`/opt/dns-config-backup` is the local config staging directory that Phase I3 (which appends
to its `.gitignore`), Phase J, Phase P4c and Phase Q5a (which commits `RETENTION.md` into it)
all write to. The first of those writes happens long before Phase K runs, so the directory and
its git repository are created **here**, root-owned. Phase K's job is to back this directory up
off-host with restic; Phase K does not create it, and does not delete it.

```bash
install -d -m 0750 -o root -g root /opt/dns-config-backup
git init -q -b main /opt/dns-config-backup
git -C /opt/dns-config-backup config user.email 'root@dns1'
git -C /opt/dns-config-backup config user.name  'dns-config-backup'
```

`git` comes from the A2 package set, so this step must follow A2. `git init` on a directory
that already holds a repository is a no-op, so re-running it is safe. The identity is set
repo-locally on purpose: the jobs that commit here run as root from cron with no global git
identity, and `git commit` refuses to run without one — which would otherwise present as a
staging directory that silently never gains a commit. Files are staged **flat** in this
repository (see the `.gitignore` note in I3).

The human administrator account, `dnsadmin`, is created in A4 **before** SSH is hardened.
Do not reorder those two steps.

**VERIFY**

```bash
id adguardhome                              # uid=... shell=/usr/sbin/nologin
getent passwd adguardhome | cut -d: -f7     # /usr/sbin/nologin
ls -ld /opt/adguardhome                     # drwxr-x--- adguardhome adguardhome
id smartdns 2>&1; id dnswarmer 2>&1         # both: "no such user" - correct

# the config staging repo exists and can be committed to before Phase I runs:
ls -ld /opt/dns-config-backup                                    # drwxr-x--- root root
git -C /opt/dns-config-backup rev-parse --is-inside-work-tree    # true
git -C /opt/dns-config-backup config user.email                  # non-empty
```

---

### A4. SSH hardening

Two things make v1's four-line SSH section worse than useless. First, Ubuntu's
`/etc/ssh/sshd_config` begins with `Include /etc/ssh/sshd_config.d/*.conf`, and sshd uses
**first-obtained-value-wins** semantics — so a directive appended to the bottom of the main
file loses to anything in an included drop-in. Cloud images ship
`/etc/ssh/sshd_config.d/50-cloud-init.conf` containing `PasswordAuthentication yes`. v1's
appended `PasswordAuthentication no` therefore did nothing, and password authentication
stayed enabled on a host this plan deliberately advertises to the entire internet. Second,
v1 never told the operator how to reach the loopback-only admin UI, which is the single
most likely reason someone eventually opens port 3000 "just for a minute".

The fix is a drop-in named so that `glob()` sorts it first, applied in an order that
cannot lock you out.

#### Step 0 — create the admin account FIRST. Do not skip this.

A3 creates only `adguardhome`, with `/usr/sbin/nologin`, and every command in this plan
runs as root. Applying `AllowUsers dnsadmin` together with `PermitRootLogin no` and
`AuthenticationMethods publickey` without this step leaves **zero** accounts able to log
in, and Phase B's `policy drop` means there is no second way in. On a remote VPS that is a
rebuild.

```bash
useradd -m -s /bin/bash -G sudo dnsadmin
install -d -m 0700 -o dnsadmin -g dnsadmin /home/dnsadmin/.ssh
install -m 0600 -o dnsadmin -g dnsadmin /dev/stdin /home/dnsadmin/.ssh/authorized_keys <<'EOF'
ssh-ed25519 AAAAC3Nza... admin@laptop
EOF
passwd -l dnsadmin                                  # key only; no password to guess
su - dnsadmin -c 'sudo -n true' && echo SUDO_OK
```

Do not continue until `SUDO_OK` prints.

#### Step 1 — write the drop-in, but do NOT reload yet

```bash
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
```

Notes on the specific values, because several differ from the obvious choices:

- `00-` sorts before `50-cloud-init.conf`, and because the `Include` sits at the *top* of
  `sshd_config` with first-obtained-value-wins semantics, this file wins. That is the
  entire point of the name. Check the `ls` output: if the image ships something that sorts
  earlier, rename this file lower.
- `ChallengeResponseAuthentication` is deliberately **absent**. It is still a live alias
  for `KbdInteractiveAuthentication` in current OpenSSH, so it parses, but it is redundant
  with the line above it and redundant directives in a security config invite doubt.
- `MaxAuthTries 6`, not 3. `ssh` offers identities one at a time; an agent holding several
  keys burns attempts before reaching the right one, and you get "Too many authentication
  failures" from your own hardening. If you want 3, pair it with `IdentitiesOnly=yes` in
  your **client** config.
- `LoginGraceTime 45`, not 20. This host is expected to be under exactly the kind of load
  the rest of this plan defends against; an aggressive grace period turns a busy moment
  into a lockout.
- `AllowTcpForwarding yes` is required — the admin UI tunnel below depends on it.
- All listed algorithms exist in the OpenSSH that 24.04 ships (`sntrup761x25519-sha512@
  openssh.com` landed in 8.5). The newer `mlkem768x25519-sha256` is not in this release;
  do not add it. Confirm with `ssh -Q kex` before editing the list.

**Socket activation caveat (verify on your image, unverified across all 24.04 variants):**
if `ssh.socket` is enabled, `Port`/`ListenAddress` in `sshd_config` are ignored and the
listener is defined by the socket unit instead. This plan does not change the port, so it
does not matter here — but check before you ever do:

```bash
systemctl is-enabled ssh.socket 2>/dev/null   # 'enabled' means socket activation is in use
```

#### Step 2 — reload, then prove a second login before closing the first

```bash
systemctl reload ssh
sshd -T | grep -Ei '^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication|authenticationmethods|allowusers|maxauthtries|logingracetime)'
```

Expected output includes `passwordauthentication no` — that is the whole point of this
step, and it is the line v1 believed it had set. Then, **in a new terminal, with the
existing root session still open**:

```bash
ssh dnsadmin@<PUBLIC_IP> 'id && sudo -n true && echo LOGIN_OK'
```

Only after `LOGIN_OK` may you close the root session.

#### Step 3 — a restricted key for the admin-UI tunnel

Add this as a **second** key in `/home/dnsadmin/.ssh/authorized_keys`, alongside your
unrestricted administration key. Keep the unrestricted key or you cannot administer the box.

```
restrict,port-forwarding,permitopen="127.0.0.1:3000" ssh-ed25519 AAAAC3Nza... tunnel@laptop
```

`restrict` disables agent forwarding, X11, PTY allocation and user-rc; `port-forwarding`
plus `permitopen` then re-enable exactly one destination. A stolen tunnel key reaches the
AdGuardHome login page and nothing else — no shell, no other port.

#### Step 4 — the admin-UI access procedure

This is the command the rest of this document means whenever it says "over the SSH tunnel".
Put it in the Phase K runbook.

```bash
ssh -N -L 3000:127.0.0.1:3000 dnsadmin@dns.example.com
# then browse to http://127.0.0.1:3000 on your own machine
```

Port 3000 is never opened in the Phase B firewall and AGH's `http.address` stays
`127.0.0.1:3000` (decision 5). There is no other supported path to the admin UI.

#### fail2ban, if you keep it

With `AuthenticationMethods publickey` there is no credential to brute-force, so the sshd
jail buys log hygiene, not security. If you install it anyway, change the ban action —
otherwise it builds a parallel iptables ruleset that `nft list ruleset` will not show you,
and your firewall stops being auditable from one command:

```ini
# /etc/fail2ban/jail.d/00-nftables.conf
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
```

**VERIFY**

```bash
sshd -T | grep -Ei '^(passwordauthentication|permitrootlogin|authenticationmethods|allowusers)'
# passwordauthentication MUST print 'no'

# password auth is genuinely refused, not just configured off:
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no dnsadmin@<PUBLIC_IP>
# expect: Permission denied (publickey).

# the tunnel works:
ssh -N -L 3000:127.0.0.1:3000 dnsadmin@<PUBLIC_IP> &
sleep 2; curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/   # 200 or 302

# the restricted key cannot forward anything else:
ssh -i ~/.ssh/tunnel_key -N -L 9999:127.0.0.1:22 dnsadmin@<PUBLIC_IP>
# expect: channel setup failed / administratively prohibited

nmap -Pn -p 3000 <PUBLIC_IP>          # filtered
```

---

### A5. sysctl and limits — the corrected set

v1's sysctl block was mostly decorative. Four of its seven lines were no-ops, wrong-unit,
or ceilings with nothing calling `setsockopt`, and the values that actually decide whether
this host drops queries were absent. Deletions first, with the reason for each, because
"why is that line gone" is the question a reader will have.

**Deleted: `net.ipv4.udp_mem = 65536 131072 262144`.** This sysctl is in **pages**, not
bytes, so the line reads 256 / 512 / 1024 MiB. The kernel's own `udp_init()` computes
`limit = nr_free_buffer_pages() / 8` and then `[min, pressure, max] = [limit/4*3, limit,
limit/4*3*2]`, which on a 4 GB host is roughly **384 / 512 / 768 MiB**. So the plan's line
*lowers* the min threshold, leaves pressure identical, and *raises* the max. It is a wash
at best, and it is emphatically not what the numbers look like they do. Let the kernel
size it.

**Deleted as a daemon control: `/etc/security/limits.d/dns.conf`.** `pam_limits` applies
to PAM login sessions. systemd services do not go through PAM's limits stack, so this file
has never affected AdGuardHome, Unbound or nginx. The `LimitNOFILE=` line in each unit is
the real setting. Keep the file if you want the limit for interactive shells, but comment
it so nobody mistakes it for the daemon limit:

```bash
cat > /etc/security/limits.d/dns.conf <<'EOF'
# INTERACTIVE SHELLS ONLY. pam_limits does not apply to systemd services -
# the daemon limit is LimitNOFILE= in each unit file (Phases C, D, E).
*    soft nofile 1000000
*    hard nofile 1000000
EOF
```

**Kept, but reframed: `net.core.rmem_max` / `wmem_max`.** These are ceilings. They do
nothing unless a process calls `setsockopt(SO_RCVBUF)`. Exactly one thing in this stack
does: quic-go inside AdGuardHome, for DoQ and HTTP/3, which targets around 7 MB and logs
`failed to sufficiently increase receive buffer size` if it cannot get it. So 25 MB is
correct and load-bearing — but only for QUIC.

Now the replacement file. Write it whole; do not append to v1's.

**Which sysctl file owns what.** There are exactly two sysctl drop-ins in this plan and they
have disjoint key sets. `/etc/sysctl.d/99-dns.conf` is Phase A's, written here, and it owns
file descriptors, socket buffers, backlogs, the outbound port range, the allocator watermark,
`vm.swappiness` and **all** the conntrack keys. `/etc/sysctl.d/99-nftables-edge.conf` is
Phase B's, and it owns the edge-hardening keys — SYN cookies, `tcp_synack_retries`, ICMP
redirect and source-route handling. A key must appear in exactly one of the two. This is not
tidiness: `sysctl.d` files apply in lexical order and the later file wins **silently**, so
`99-nftables-edge.conf` beats `99-dns.conf` on any key both set, and you would be running a
value you can read in one file and not the other. If you find a `net.netfilter.*` key in
Phase B's file, delete it there — it sorts later and would override the values below.

```bash
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
```

The `net.netfilter.*` keys **do not exist until `nf_conntrack` is loaded**. On a fresh boot
`sysctl --system` runs before anything has pulled the module in, and you get errors and
unset values. Load it explicitly:

```bash
echo nf_conntrack > /etc/modules-load.d/conntrack.conf
modprobe nf_conntrack
sysctl --system
```

**Spread receive softirq across both vCPUs (RPS).** A VPS virtio NIC commonly presents a
single RX queue, so all receive-side softirq processing lands on one vCPU while the second
core idles — you cap out at roughly half the box's capability and the symptom is one core
pinned at 100% in `mpstat`.

This matters here specifically because of where the parallelism knobs are. Unbound does
expose `num-threads` and `so-reuseport` (configured in Phase C, not restated here), but
**AdGuardHome exposes no listener-count or reuseport option at all** — there is no such
field in its dnsforward config struct. AGH is the front door for every client query, so
kernel-side RX distribution is the only parallelism available on the client-facing leg.

Put the logic in a script rather than in `ExecStart=`. systemd performs its own `$VAR`
expansion on `Exec*` lines before handing the string to a shell — `systemd.service(5)`
says "To pass a literal dollar sign, use `$$`" — so an inline `for q in .../rx-*; do echo
3 > $q/...` is silently emptied. Combined with `RemainAfterExit=yes`, the unit reports
success while having done nothing, which is the worst possible failure shape for a tuning
knob.

```bash
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
```

`rps_cpus = 3` is the bitmask for cores 0 and 1. On a box with more vCPUs, widen it.
`rps_flow_cnt` must be `rps_sock_flow_entries` divided by the number of RX queues, which
is why the script computes it rather than hard-coding a number.

**VERIFY**

```bash
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
ls /etc/sysctl.d/99-swap.conf 2>/dev/null && echo 'STALE: delete it, A5 owns vm.swappiness'

systemctl status rps-tune.service --no-pager | tail -3   # must show the script's echo line
IF=$(ip -o -4 route show default | awk '{print $5}' | head -1)
cat /sys/class/net/$IF/queues/rx-*/rps_cpus              # expect 3 (unless multiqueue)
ethtool -l $IF

# quic-go is no longer complaining - this is the proof rmem_max is load-bearing:
journalctl -u adguardhome --since -10m | grep -i 'receive buffer size'   # must be empty

# THE acceptance metric. Read, run load (Phase H), read again.
nstat -az | grep -Ei 'UdpRcvbufErrors|UdpInErrors|UdpNoPorts'
# PASS: UdpRcvbufErrors delta == 0 across a 5-minute run at target QPS

# Softirq is landing on both cores, not one:
mpstat -P ALL 1 5      # %soft spread across CPUs, not pinned to CPU0
```

---

### A6. Memory safety

> **This section is the single owner of memory and swap policy for the DNS stack.** Swap,
> `vm.swappiness` (the sysctl line itself lives in A5's `99-dns.conf`, which is Phase A's
> file) and the `MemoryHigh=` / `MemoryMax=` / `OOMScoreAdjust=` values for **unbound,
> AdGuardHome, nginx and sshd** are set here and nowhere else. Phase E does not set a ceiling
> for AdGuardHome, Phase N does not set ceilings for any of them, and neither ships a second
> swapfile or a second swappiness value — both cross-reference this section instead. Phase N
> keeps the restart policy and start-limit guards, a different control that interacts with
> these ceilings (see the end of this section). If you find a `MemoryMax=` for one of those
> four units anywhere else in this document, it is stale. The monitoring units Phase I
> installs are outside this boundary and carry their own ceilings, set in Phase I.

The steady-state budget from A1 fits comfortably. The failure is not the budget, it is
what happens when something exceeds it. None of the units in v1 set `MemoryMax`,
`MemoryHigh` or `MemoryAccounting`, so a single leak or one mis-sized cache consumes the
whole host including sshd. Most VPS images ship with zero swap, so the kernel OOM killer
fires with no warning and picks its victim by RSS — meaning it kills the resolver, which
is the largest process on a DNS box. `Restart=always` then restarts it into the same
pressure and you get a loop that looks like a crash bug.

**systemd-oomd does not save you here.** Ubuntu ships it, but by default it manages user
slices, not `system.slice`. It will happily watch AdGuardHome die. Per-unit `MemoryMax`
is the control that actually applies to these services, and cgroup v2 (the default unified
hierarchy on 24.04) is what makes it enforced rather than advisory.

#### Swap as a shock absorber, not a paging path

With `vm.swappiness = 10` from A5 already applied, this is a safety net: pressure degrades
into slowness you can alert on, instead of an instant kill. Swapping a resolver destroys
p99 latency, so it must never be part of the steady state.

One 2 GB swapfile, created here, is the whole of this plan's swap configuration. The value
is 10 rather than 1 or 0 on purpose: this box's memory is dominated by *anonymous* pages —
Unbound's slab caches and AGH's Go heap are in-process, not page cache — so at swappiness 1
the kernel reclaims page cache it barely has, leaves the swapfile essentially unused, and
you arrive at the OOM kill the swapfile was bought to prevent. At 10, genuinely idle
anonymous pages move out under pressure and the hot cache stays resident.

```bash
# fallocate produces an unusable swapfile on Btrfs and can trigger
# "swapon: /swapfile: skipping - it appears to have holes" elsewhere.
fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

#### Per-unit ceilings — the canonical set

Use drop-in overrides so the unit files from Phases C, D and E stay as written and the
limits survive a package reinstall. The drop-ins below are the complete set of memory
ceilings and OOM priorities in this plan; ship them as written. Phase E and Phase N
reference these numbers rather than carrying their own.

They are ceilings, not reservations. Their sum (1600 + 1200 + 256 MB) deliberately exceeds
the 0.8–1.4 GB steady state from A1, so a spike in one daemon is absorbed instead of clipped,
and stays far enough under 4 GB that all three sitting at their ceiling at once still leaves
the kernel and sshd room to work.

The `MemoryHigh` line ahead of each `MemoryMax` is what makes this safe to ship. A bare
`MemoryMax` under `Restart=always` converts a slow leak into a restart loop — the same outage
the kernel OOM killer would have caused, just relocated into the cgroup. `MemoryHigh` is a
throttle rather than a kill: the cgroup is held under reclaim pressure and gets slow, which
is a symptom Phase I can alert on well before `MemoryMax` kills anything. The other half of
that guard is the start limit in Phase N, which bounds the loop if a kill does happen.
Neither half is optional.

```bash
systemctl edit unbound
```
```ini
[Service]
MemoryAccounting=yes
MemoryHigh=1200M
MemoryMax=1600M
OOMScoreAdjust=-300
```

Unbound's `msg-cache-size` / `rrset-cache-size` (Phase C) are what set its peak, and the two
numbers above are the arithmetic for the Phase C cache sizes *as written*. If you change
those cache sizes, re-derive rather than re-guess: run a 4-hour soak with real traffic, read
`MemoryCurrent` at peak, and keep `MemoryHigh` at roughly 1.3x and `MemoryMax` at roughly
1.6x that peak. Changing one without the other is how a cache-size tweak becomes an outage.

```bash
systemctl edit adguardhome
```
```ini
[Service]
MemoryAccounting=yes
MemoryHigh=800M
MemoryMax=1200M
# AGH is the public front door: make it the LAST thing the kernel picks.
OOMScoreAdjust=-500
```

```bash
systemctl edit nginx
```
```ini
[Service]
MemoryAccounting=yes
MemoryMax=256M
OOMScoreAdjust=-200
```

```bash
systemctl edit ssh
```
```ini
[Service]
# -500, NOT -900. oom_score_adj is inherited across fork(), so this value
# applies to every login session and everything a user launches from it.
# At -900 a runaway process in an SSH session becomes nearly immune to the
# OOM killer, on a host that has no memory headroom by design.
OOMScoreAdjust=-500
```

If you want the sshd listener protected at -900 without protecting user sessions, set
-900 here and add a matching `OOMScoreAdjust=0` drop-in on `user@.service`.

There is no `dns-warmer` drop-in. Phase F is retired (decision 3); nothing on this host is
expendable enough to be the designated OOM victim, which is another reason the ceilings
above matter.

Restart policy, start-limit guards and the restart-churn detector belong to **Phase N**, and
that is the *only* thing Phase N sets on these units — the memory side of every drop-in above
is settled here. The two controls interact in both directions (a cgroup OOM under
`Restart=always` is an unbounded loop without a start limit; a start limit with no ceiling
above it never gets the chance to fire, because the kernel picked a different victim), which
is precisely why each is written down exactly once. Phase N's restart values must also agree
with the hardened unit in **Phase C4** — one canonical set of restart directives across the
stack, not one per phase.

```bash
systemctl daemon-reload
systemctl restart unbound adguardhome nginx
```

**VERIFY**

```bash
# Limits are in effect, not merely written to a file:
systemctl show unbound     -p MemoryAccounting -p MemoryHigh -p MemoryMax -p MemoryCurrent -p OOMScoreAdjust
#   expect MemoryHigh=1258291200 (1200M) / MemoryMax=1677721600 (1600M) / -300
systemctl show adguardhome -p MemoryHigh -p MemoryMax -p MemoryCurrent -p OOMScoreAdjust
#   expect MemoryHigh=838860800 (800M) / MemoryMax=1258291200 (1200M) / -500
systemctl show nginx       -p MemoryMax -p OOMScoreAdjust        # 268435456 (256M) / -200
systemctl show ssh         -p OOMScoreAdjust    # must be -500, not -900

# Nobody set a second ceiling behind this section's back. `systemctl show` merges
# drop-ins, so a duplicate from another phase is invisible there - look at the files:
ls /etc/systemd/system/{unbound,adguardhome,nginx}.service.d/
grep -rl 'Memory\(High\|Max\)' \
     /etc/systemd/system/{unbound,adguardhome,nginx}.service.d/ 2>/dev/null
# exactly one file per unit, and it is the one this section wrote. Phase I's
# monitoring units have their own ceilings and are deliberately not in this list.

# Swap present and idle, and swappiness is A5's value:
free -h && swapon --show && sysctl vm.swappiness   # 10; Used stays at 0 in steady state

# Live budget during the Phase H load run:
systemd-cgtop -m --order=memory -n 5

# The cgroup gate. PASS: oom 0 and oom_kill 0. A non-zero `high` is EXPECTED and
# means MemoryHigh is doing its job; a rising `max` means MemoryMax is too low.
grep -E '^(oom|oom_kill|max|high) ' /sys/fs/cgroup/system.slice/unbound.service/memory.events
grep -E '^(oom|oom_kill|max|high) ' /sys/fs/cgroup/system.slice/adguardhome.service/memory.events

# Nothing was ever killed by the kernel:
journalctl -k --since -24h | grep -iE 'out of memory|oom-kill'    # must be empty

# Clean restart still answers:
systemctl restart unbound && sleep 3 && dig @127.0.0.1 -p 5335 example.com A +short
```

Cross-references: patching and daemon upgrades are **Phase M**; the second node, restart
policy and failover are **Phase N**; reproducible provisioning of everything in this phase
is **Phase O**.

---

[Plan index](../dns-server-plan.md) · [Next: Firewall and Edge Packet Policy](./02-firewall.md)
