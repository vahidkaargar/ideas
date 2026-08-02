[Plan index](../dns-server-plan.md) · [Previous: Privacy, Retention and Compliance (optional)](./10-privacy-and-compliance.md) · [Next: Client Configuration](./12-client-setup.md)

---

**On this page**

- [PHASE L: Go-Live Checklist](#phase-l-go-live-checklist)
  - [L1. Host](#l1-host)
  - [L2. Firewall and packet policy](#l2-firewall-and-packet-policy)
  - [L3. Resolver (Unbound)](#l3-resolver-unbound)
  - [L4. TLS certificates](#l4-tls-certificates)
  - [L5. Edge — AdGuardHome and nginx](#l5-edge-adguardhome-and-nginx)
  - [L6. Validation and load](#l6-validation-and-load)
  - [L7. Observability and alerting](#l7-observability-and-alerting)
  - [L8. Abuse controls](#l8-abuse-controls)
  - [L9. Backup, restore and reproducibility](#l9-backup-restore-and-reproducibility)
  - [L10. Privacy, retention and legal — `(Q)`](#l10-privacy-retention-and-legal-q)
  - [L11. Private access layer — `(P)`](#l11-private-access-layer-p)
  - [L12. Do not go live if](#l12-do-not-go-live-if)
- [Directory and Port Layout (Final)](#directory-and-port-layout-final)
  - [Listening sockets — base build](#listening-sockets-base-build)
  - [Listening sockets — conditional additions](#listening-sockets-conditional-additions)
  - [nftables objects — the single ruleset](#nftables-objects-the-single-ruleset)
  - [File and directory layout](#file-and-directory-layout)
- [Key Risks and Mitigations](#key-risks-and-mitigations)
- [Changelog from v1](#changelog-from-v1)

---

## PHASE L: Go-Live Checklist

This is a gate, not a summary. Every line is an assertion with a command that proves it, and every
command already exists earlier in this document — the reference in parentheses tells you where the
step, its expected output and its failure modes are explained. Nothing here re-derives a threshold.

Rules for running it:

- **Run it on the actual host, in one sitting, and record the output.** A checklist ticked from
  memory across three weeks certifies nothing.
- **Items marked `[off-box]` must be run from the Phase H0 test host.** Every isolation and
  encrypted-transport check passes on a completely broken box when run locally: loopback bypasses
  the NIC, the firewall, the conntrack bypass, the rate limiter and — for DoH — nginx entirely.
- **Items marked `(P)` or `(Q)` are conditional** on a Phase P access mode or a Phase Q posture
  having been selected. A plain public resolver skips the `(P)` block in full; the `(Q)` block
  always applies, because "the shipped default" is itself a posture that has to be recorded.
- A line that cannot be evaluated is a **fail**, not a skip. "Inconclusive" is only an acceptable
  result where the step itself defines it (C5.3, H7 rebinding).

> **Consistency note.** An earlier revision of this section carried a table of cross-phase conflicts
> that had to be settled before the gate could run — two rate-limiting tables, two reload wrappers,
> two ban durations, two memory owners, two `:80` server blocks, two names for the Unbound drop-in.
> The document has since been consistency-audited and those conflicts have been resolved in the
> phases themselves: there is one nftables ruleset with one policy table, one reload wrapper, one
> ban-duration schedule, one owner for memory and swap, one `:80` server block and one canonical
> filename for every artifact. Each canonical value now appears in exactly one phase and is
> cross-referenced from the others. **If you find two phases giving different values for the same
> object, that is a defect to report, not a decision to make** — this checklist assumes the single
> value and will fail against a host built from a divergent copy.

---

### L1. Host

```
[ ] Ubuntu 24.04 LTS, not 22.04                      lsb_release -ds                        (A1)
[ ] Public IPv4 survives a reboot; IP matches DNS    ip -4 addr show scope global            (A1)
[ ] dns.example.com resolves to THIS host from TWO independent public resolvers               (0.1, D0)
       dig +short dns.example.com A @1.1.1.1 ; dig +short dns.example.com A @8.8.8.8
       -- both must return the address on the line above. One resolver proves nothing: it can
          be serving a cached answer from a previous holder of the name. A mismatch here is a
          stop, not a retry -- each failed HTTP-01 burns one of Let's Encrypt's five failed
          validations per hostname per hour, and D2 is where you discover that.
[ ] The zone for that name is served by authoritative DNS that is NOT this machine, on at
    least two nameservers, and the A/AAAA TTL is 300                                          (0.1, D0)
       dig +noall +answer dns.example.com A @$(dig +short NS example.com | head -1)
       -- read the TTL from an AUTHORITATIVE answer; a cached one is counting down and lies.
          This box is authoritative for nothing -- Unbound refuses 0.0.0.0/0 on :5335 and no
          phase writes an auth-zone -- so hosting the zone here makes the name die with the
          host, taking every DoT/DoQ/DoH client, both I9 external monitors and the N8 cutover
          with it. 300 s is what K7 step 7 and escalation step 6 each spend repointing the
          record: it has to be low ALREADY, because lowering it during the incident is too late.
[ ] IPv6 posture DECIDED and recorded, and the RECORD SET matches it            (A1, C2, E2a)
       -- the listener is not the variable. `dns.bind_hosts: [0.0.0.0]` is a WILDCARD, and Go
          resolves a wildcard listen address to an AF_INET6 socket with `IPV6_V6ONLY=0` set
          explicitly (`net/ipsock_posix.go`, `net/sockopt_linux.go`), so Do53, DoT and DoQ
          ALREADY answer over both families on the file exactly as Phase E ships it. E4's
          nginx is the opposite shape on purpose and binds `0.0.0.0` and `[::]` separately;
          Phase B's `inet` ruleset accepts both. What the posture decides is therefore which
          RECORDS to publish -- and, separately, whether Phase C's `do-ip6` EGRESS works.
          Three postures are coherent:
            (a) IPv4-only  -- publish NO AAAA for dns.example.com anywhere, including the one
                P3c adds "if the VPS has IPv6". The wildcard socket still accepts v6 from
                anyone who learns the address another way; that is not a leak on a
                deliberately public resolver, but it does keep Phase B's v6 ban path
                load-bearing.
            (b) dual-stack -- publish the AAAA, and prove it with the next line.
            (c) IPv4-only ENFORCED at the socket -- `bind_hosts: [<PUBLIC_IPV4>]`. A literal
                is not a wildcard, so this is the ONLY setting that yields a genuine AF_INET
                socket. Read Phase N before choosing it: AdGuardHome then refuses to start
                whenever that address is not yet on an interface, which is exactly the state
                a floating-IP standby is in.
          Do NOT "add IPv6" by writing `bind_hosts: [0.0.0.0, '::']`. dnsproxy sets
          SO_REUSEADDR and SO_REUSEPORT on every listener, so that binds `[::]:53` a second
          time, succeeds silently, and buys nothing. It is not the dual-stack fix (E2a).
[ ] EVERY published address answers on EVERY transport this build enables          (E2a, E6-9)
       run E6 step 9 from a DUAL-STACK host -- see the L5 [off-box] line, which is where it
       is executed. It derives its address list from `dig +short dns.example.com A/AAAA`
       rather than from a $PUB variable, precisely so that it fails on a record that no
       listener owns. If it reports a blank column, fix the listener or withdraw the record.
       ss -lntuep '( sport = :53 or sport = :853 )'                                    (E2a)
       -> AdGuardHome renders as `*:53` / `*:853` with `v6only:0` on a dual-stack host. A
          literal `0.0.0.0:53` means Go could not open an AF_INET6 socket at all, i.e. this
          host has NO usable IPv6 stack -- which is a legitimate state, and the one in which
          an AAAA must not exist.
[ ] chrony synchronised, offset < 100 ms             chronyc tracking                        (A2)
       -- clock skew SERVFAILs every signed zone and presents as a total outage
[ ] NO chrony source is a hostname -- the time path must not depend on the DNS path           (A2)
       chronyc sources -v                         -> numeric addresses only
       grep -rhE '^(server|pool)' /etc/chrony/     -> nothing that requires resolution
       -- after C5.8 the host resolves through its own validator, and a validator with a skewed
          clock SERVFAILs the NTP pool's own name. IP-literal sources plus `makestep` are the
          only things that stop the deadlock forming; once it has formed the exit is a console
          `date -s`, which is why that recovery row exists in the runbook.
[ ] ufw and fail2ban absent (or fail2ban on the nftables banaction)                          (A2, A4)
[ ] systemd-resolved disabled AND masked; port 53 free   ss -lnup 'sport = :53'              (A2)
[ ] No /etc/systemd/resolved.conf.d/ on the host -- no phase writes DNSStubListener          (A2, C1)
[ ] /etc/resolv.conf is a real file (not a symlink) with EXACTLY ONE nameserver line,
    and it is 127.0.0.1 -- no external fallback entry of any kind                            (A2, C5.8)
       -- A2 wrote the provider's resolver as a labelled BOOTSTRAP value; C5.8 flipped it
          after Unbound proved it validates. If a second nameserver is present, glibc will
          silently route the host's own lookups around the validating path.
[ ] adguardhome user exists, nologin; no smartdns / dnswarmer user                           (A3)
[ ] sshd: passwordauthentication no, publickey only  sshd -T | grep -i passwordauth          (A4)
[ ] A second login as dnsadmin proved BEFORE the root session was closed                     (A4 Step 2)
[ ] Restricted tunnel key cannot forward anything but 127.0.0.1:3000                         (A4 Step 3)
[ ] 99-dns.conf applied; net.netfilter.* keys resolve after a reboot                         (A5)
[ ] The two sysctl drop-ins share NO key                                                     (A5, B2)
       comm -12 <(keys of 99-dns.conf) <(keys of 99-nftables-edge.conf)  -> empty
       -- conntrack, ip_local_port_range, tcp_syncookies and vm.swappiness are Phase A's;
          Phase B owns only the edge-hardening keys. sysctl.d applies in lexical order and
          the later file wins with no warning.
[ ] No /etc/sysctl.d/99-swap.conf exists -- A5 is the only writer of vm.swappiness           (A5, N5a)
[ ] RPS spread across both vCPUs (or hardware multiqueue)  cat .../rx-*/rps_cpus             (A5)
[ ] UdpRcvbufErrors delta == 0 across the L6 load run   nstat -az | grep UdpRcvbufErrors     (A5)
[ ] Swap present and unused in steady state; vm.swappiness = 10   free -h; swapon --show     (A6)
[ ] MemoryAccounting on for unbound / adguardhome / nginx                                    (A6)
[ ] The canonical ceilings are in effect and set in ONE place                                (A6)
       systemctl show unbound     -p MemoryHigh -p MemoryMax   -> 1200M / 1600M
       systemctl show adguardhome -p MemoryHigh -p MemoryMax   ->  800M / 1200M
       systemctl show nginx       -p MemoryMax                 ->  256M
       grep -rl 'Memory\(High\|Max\)' /etc/systemd/system/{unbound,adguardhome,nginx}.service.d/
         -> exactly ONE file per unit, and it is A6's. Phase E and Phase N ship no ceilings.
[ ] ssh OOMScoreAdjust is -500, not -900             systemctl show ssh -p OOMScoreAdjust    (A6)
[ ] No OOM kill in the last 24 h                     journalctl -k --since -24h | grep -i oom (A6)
[ ] memory.events for unbound and adguardhome: oom 0 and oom_kill 0                          (A6)
```

### L2. Firewall and packet policy

```
[ ] nft -c -f /etc/nftables.conf parses clean                                                (B5)
[ ] EXACTLY TWO tables: inet raw and inet filter     nft list tables                         (B9-1)
       -- `inet raw` exists only because `notrack` is legal only at the raw hook (decision 9).
          Anything else -- and dns_ratelimit or dns_rrl in particular -- is a v1 ruleset or a
          phase that re-added a table of its own, and it breaks the in-datapath `add @banned_ips`,
          which is table-scoped.
[ ] EXACTLY ONE base chain on the input hook                                                 (B9-1)
       nft -j list ruleset | jq '[.nftables[].chain? | select(.hook=="input")] | length'  -> 1
       -- dns_guard is a JUMP TARGET inside `input`, not a second base chain and not a chain
          at its own hook priority.
[ ] All six canonical sets exist in table inet filter                                        (B9-1)
       floodmeter4  floodmeter6  banned_ips  banned_ips6  allowlist4  allowlist6
[ ] Chain dns_guard and the named counters dns_dropped / dns_banned exist                    (B9-1)
[ ] NOTRACK counter on the raw prerouting rule is non-zero under live traffic                (B9-2)
[ ] conntrack holds NO udp 53/853/5335 flows        conntrack -L -p udp | grep -c dport=53   (B9-2)
[ ] THE HOST'S OWN OUTBOUND DNS STILL WORKS         getent hosts api.github.com; apt update  (B9-3)
       -- server-direction-only notrack; get this wrong and apt/certbot/ACME die silently
[ ] The B4 invariant holds: nft flood threshold >= 4x AdGuardHome's dns.ratelimit            (B9-5)
       expect nft=400 agh=100. Raise both together or neither.
[ ] Flood guard engages off-box, bans the source, and does NOT catch loopback                (B9-5)
[ ] Egress RRL and byte-cap counters are ZERO under normal load                              (B9-6)
[ ] Measured amplification factor recorded; truncation proven with . DNSKEY +bufsize=512     (B9-7)
[ ] [off-box] 3000 / 5335 / 8053 unreachable        nc -z -w2 $PUB 3000                      (B9-8)
[ ] [off-box] Public surface is exactly 22, 53, 80, 443, 853 tcp + 53, 853 udp               (B9-9)
       -- tcp/80 is permanently open on this build, and there is no alternative: Phase B5's
          `certbot` chain holds a standing `tcp dport 80 counter accept` (B7) and Phase E4
          writes the `:80` server block that serves the ACME webroot and the Phase Q
          well-known files. No renewal hook may open or close it. A filtered or closed 80
          fails this check.
[ ] Ban enforcement drops a test address on EVERY transport, then the element is removed     (B9-10)
[ ] Certbot renewal does NOT wipe ban state         (element survives certbot renew --dry-run) (B7)
[ ] /usr/local/sbin/nft-apply is the ONLY reload wrapper on the box                          (B8)
       ls /usr/local/sbin/nft-*   -> no second ban save/restore tool
[ ] `systemctl reload nftables` is routed to nft-apply by the B1 override                    (B1, B8)
[ ] A reload restores bans with their REMAINING timeout, not a fresh full duration           (B8)
[ ] Ruleset, conntrack sysctls and allowlist all survive a reboot                            (B9-11)
[ ] VRRP (ip protocol 112) accepted on the private NIC only          -- Tier 3 only          (N3)
```

### L3. Resolver (Unbound)

```
[ ] unbound 1.19.2; unbound-checkconf clean          unbound -V; unbound-checkconf            (C1, C2)
[ ] The config drop-in is /etc/unbound/unbound.conf.d/10-public-resolver.conf                 (C2, M4)
       -- that exact name. The numeric prefix decides which drop-in wins when a second one
          appears, and the K6 restore drill gates on it.
[ ] Listening on 127.0.0.1:5335 and [::1]:5335 ONLY  ss -lnup 'sport = :5335'                 (C2)
[ ] Running as the unbound user, not root            ps -o user -C unbound                    (C4)
[ ] Packaged unit NOT replaced; drop-ins only        ls -l /etc/systemd/system/unbound.service (C4)
       -- that path must NOT exist
[ ] DropInPaths are exactly nofile.conf + hardening.conf                                      (C4)
       systemctl show unbound -p DropInPaths   -- no ha.conf, no limits.conf, no dns-node.conf
[ ] Canonical restart policy in effect, identical on every unit in the stack                  (C4, E5b, N4a)
       Restart=always  RestartSec=5s  StartLimitIntervalUSec=5min  StartLimitBurst=10
[ ] No Requires= between any two daemons in this stack -- Wants= + After= only                (C4, E5b, N4b)
[ ] It is genuinely RECURSING: no forward-zone anywhere, and tcpdump shows root/TLD/auth      (C5.1)
[ ] modules: validator iterator                      unbound-control status                   (C5.2)
[ ] auto-trust-anchor-file declared exactly ONCE     grep -rhc ... | paste -sd+ - | bc  -> 1  (C3)
[ ] root.key non-empty, unbound:unbound 0644, in the restic include list                      (C3, K3)
[ ] Trust anchor STATE inspected, not merely its size                                         (C3)
       grep ';;state=' /var/lib/unbound/root.key
       -> at least one key at `;;state=2 [  VALID  ]`. 1 = ADDPEND (seen, not yet through its
          30-day hold-down), 3 = MISSING, 4 = REVOKED, 5 = REMOVED.
       -- `test -s root.key` and an AD flag on `. DNSKEY` BOTH pass for the whole of an RFC 5011
          rollover, including on a host that will SERVFAIL every signed name the day ICANN
          revokes the old KSK. During a roll the new key must reach VALID BEFORE the old one is
          revoked; a box powered off for longer than the hold-down never sees it and has to be
          re-bootstrapped by hand. This is the one service-killing event on this stack that
          arrives with a published calendar date.
[ ] root.key was rewritten within the last 90 days                                            (C3)
       find /var/lib/unbound/root.key -mtime +90    -> no output
       -- RFC 5011 tracking rewrites the file routinely, so a stale mtime means tracking has
          stopped while every other anchor check still passes.
[ ] The monthly anchor-state line was APPENDED to /etc/cron.d/dns-health, and the ICANN
    rollover announcements are subscribed and calendared next to the K6/K7 drills             (C3, I10, O6)
[ ] dns-root-data is not frozen -- M1's security-pocket scope structurally excludes it         (M1, C3)
       find /usr/share/dns/root.hints -mtime +365   -> no output
       -- it carries root.hints and the ICANN bundle the C3 heal path validates against, so a
          frozen copy degrades priming and the heal path together, silently.
[ ] unbound-anchor-guard.timer enabled and does NOT touch a healthy anchor                    (C3)
[ ] The two DNSSEC fast-detector lines were APPENDED to /etc/cron.d/dns-health,
    not dropped into a second cron file                                                       (C3, I10)
[ ] 18 private-address lines + 1 private-domain line                                          (C2, H7)
[ ] edns-buffer-size and max-udp-size both 1232      unbound-control get_option ...           (C2)
[ ] qname-minimisation yes, strict no                unbound-control get_option ...           (C2, C5.4)
[ ] do-ip6 matches this host's actual IPv6 EGRESS, tested rather than assumed                 (C2)
       ip -6 route show default
       dig @2001:500:2f::f . NS +time=3 +tries=1 ; dig @2001:500:1::53 . NS +time=3 +tries=1
       -> both root letters answer inside 3 s -> `do-ip6: yes`. Either times out -> `do-ip6: no`,
          recorded WITH the reason, because someone will "fix" it back later.
       -- a global v6 address with dead transit is the common provider trap, and `ip -6 addr`
          passes on exactly that host. The cost is a timeout per query to every v6-reachable
          authoritative on every cache miss: degradation, not failure, so it survives launch and
          surfaces months later as an unattributed RecursionLatencyP99High.
[ ] NO `domain-insecure:` in any drop-in -- a negative trust anchor is RUNTIME-ONLY by design  (C3b, O4)
       grep -rn 'domain-insecure' /etc/unbound/    -> no output
       unbound-control list_insecure               -> empty, or every entry carries a ticket
                                                      and an expiry date recorded against it
       -- a persisted NTA disables validation for that zone forever and silently, which voids
          the single property this build exists to provide.
[ ] The C3b procedure is in the runbook and its discriminator is understood                    (C3b)
       -- OUR anchor broken = EVERY signed zone SERVFAILs. THEIR zone broken = ONE zone
          SERVFAILs, with EDE 6/7/8/9/10 on the answer. Matching the second case against the
          first sends the operator to `unbound-anchor` plus a cache-dumping restart for a fault
          neither one can fix.
[ ] verbosity is 1 (NOT 0) and use-syslog is no -- unbound logs to journald                   (C2, G, Q3)
[ ] Remote control is ENABLED on the shipped unix socket, and no second control channel
    was added on tcp/8953                                                                     (C2, I2, Q3)
       -- Phase I scrapes `unbound-control stats_noreset` over /run/unbound.ctl. Disabling
          remote control blinds Phase I; declaring a second `remote-control:` block ADDS a
          channel rather than replacing one.
[ ] serve-expired-client-timeout is 1800, NOT 0 -- and the 1.8 s degraded-path latency is
    understood and written into the runbook                                                   (C2, C5.6)
[ ] Stale is NOT served while resolution is healthy  (num.expired stays 0)                    (C5.6)
[ ] total.num.prefetch rises under repeat traffic -- this is what replaced Phase F            (C5.5, H8)
[ ] LimitNOFILE 65535; no ulimit/outgoing-port warning in the journal                         (C2)
[ ] Source-port randomisation visible on the wire (many distinct ports)                       (C5.7)
[ ] Cold-vs-warm miss cost measured and recorded as the Phase I latency baseline              (C6)
```

### L4. TLS certificates

```
[ ] CAA state was checked BEFORE the first issuance attempt                                   (D2)
       dig +short CAA dns.example.com ; dig +short CAA example.com
       -> empty everywhere, or a set containing `0 issue "letsencrypt.org"`.
       -- a CA climbs to the first ancestor that HAS a record and stops, so the apex governs
          whenever the label carries none. A non-empty set that omits letsencrypt.org is a hard
          refusal whose error text mentions neither DNS nor the firewall, and it spends one of
          the five attempts per hostname per hour finding that out.
[ ] CAA PUBLISHED after issuance, and issuewild matches the D7 / P3c decision          (D2, D8, D7)
       example.com.  300  IN  CAA  0 issue     "letsencrypt.org"
       example.com.  300  IN  CAA  0 issuewild ";"        <- relax to "letsencrypt.org" ONLY
                                                             if Phase P selected the wildcard
       example.com.  300  IN  CAA  0 iodef     "mailto:<the Q5c security contact>"
       -- empty is a pass at the gate but not a good state: with no CAA, any of roughly ninety
          public CAs may issue for the one name that is the ENTIRE client authentication of
          DoT, DoQ and DoH. Android Private DNS pins nothing, and D6 records that Let's Encrypt
          shut its OCSP responders down on 2025-08-06 -- so a mis-issued certificate has no
          revocation any client will act on. CT detects mis-issuance afterwards; CAA prevents it.
       -- ordering trap: relaxing issuewild must happen BEFORE certbot runs the DNS-01 switch.
[ ] Domain expiry is MONITORED, not remembered                                        (I4, I6, O6)
       dns-domain-expiry on /etc/cron.d/dns-health; DomainExpiringSoon (60 d) and
       DomainExpiringCritical (30 d) loaded; DomainExpiryCheckFailing loaded too
       curl -fsSL --max-time 20 https://rdap.org/domain/example.com \
         | jq -r '.events[]|select(.eventAction=="expiration")|.eventDate'
       -- `-L` is not optional: rdap.org is the bootstrap redirector and answers 302 to the
          responsible registry. This is the only expiry in the design nothing else covers --
          CertExpiringSoon fires on a name you no longer own with no fixable cause, and after
          the redemption window anyone may re-register it, obtain a valid certificate, and
          receive the queries of every device still configured to trust it.
[ ] Registrar: auto-renew ON, registrar lock ON, account MFA on, recovery email and the
    renewal card's OWN expiry date recorded in the Phase O inventory                          (O6)
       -- a lapsed payment card is the usual root cause, and it fails silently.
[ ] A probe resolves dns.example.com against a PUBLIC resolver, not 127.0.0.1                 (I4, I9)
       -- every other DNS probe in I4 targets 127.0.0.1:53 and therefore cannot see a failure
          of the third-party authoritative DNS that serves this name. When that zone goes down,
          the box, dns-smoke.sh and every on-box probe stay green while every client fails.
[ ] Certificate is ECDSA P-256                       openssl x509 ... Public Key Algorithm    (D9-1)
[ ] SANs are exactly what you intended (wildcard only if Phase P uses ClientID SNI)           (D9-2)
[ ] Renewal authenticator is webroot or dns-*, NEVER standalone                               (D9-3)
       -- nginx owns :80 from E4 onward, so a standalone renewal fails with "Could not bind
          TCP port 80". The webroot path is /var/www/acme and it must match E4's `root`.
[ ] certbot renew --dry-run succeeds; certbot.timer enabled                                   (D5, D9-4)
[ ] The deploy hook is /etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh, mode 0700       (D4)
[ ] It reaches the AGH binary through /opt/adguardhome/current/AdGuardHome (the version
    symlink), never a pinned releases/<ver> path                                              (D4, E1, M3)
[ ] AGH's copy exists, 0640 adguardhome:adguardhome, and is byte-identical to live/           (D4, D9-5)
[ ] conf/ssl directory is adguardhome-owned 0700 -- a root-owned 0700 kills every TLS
    listener with no obvious cause                                                            (K5a)
[ ] Served cert on :443 AND on :853 matches the on-disk fingerprint                           (D9-6, H12)
[ ] No OCSP URI on the certificate; no ssl_stapling directive anywhere                        (D6, D9-7)
[ ] Deploy hook run by hand at least once -- certbot skips deploy hooks on --dry-run          (D4, D5)
```

### L5. Edge — AdGuardHome and nginx

```
[ ] Binary is a pinned tag installed via releases/<ver> + current symlink; checksum verified   (E1, M3)
[ ] Every reference to the binary anywhere on the box uses the `current` symlink               (E1, D4, H12, M3, P1)
[ ] getcap on the binary returns NOTHING                                                       (E1, E5a)
       -- the only setcap in this entire plan is the REMOVAL in E5a. No phase, including
          Phase M's upgrade procedure, grants a capability with setcap.
[ ] AmbientCapabilities=CAP_NET_BIND_SERVICE present and effective    getpcaps <MainPID>       (E6-1)
[ ] schema_version present and equal to the binary's LastSchemaVersion                         (E2, Q1)
[ ] querylog: and statistics: are TOP-LEVEL, and still are AFTER first start                   (E2, E6-8)
       -- 2160h anywhere in the file means a migration overwrote your block
[ ] Shipped logging default is in place unless a Phase Q posture was deliberately opted into:
    querylog.enabled true / interval 6h / file_enabled false, anonymize_client_ip true,
    statistics.enabled TRUE                                                                    (E2, G2, Q1)
[ ] upstream_dns is only 127.0.0.1:5335; fallback_dns is []                                    (E2, Q2)
[ ] enable_dnssec true; edns_client_subnet.enabled false; use_private_ptr_resolvers false      (E2, Q2)
[ ] ratelimit: 100, and it is understood to cover PLAIN UDP ONLY                               (E2, B4, H10)
[ ] ratelimit_subnet_len_ipv4 32 / _ipv6 64 -- NOT the 24/56 defaults                          (E2, H10)
[ ] ratelimit_whitelist still contains 127.0.0.1 and ::1                                       (E2, F1)
       -- Phase E keeps it. Only the dnsdist escalation in B4 removes it, and you have not
          adopted that. No phase instructs you to strip it.
[ ] blocked_hosts contains version.bind, id.server, hostname.bind                               (E2, P1)
[ ] Admin password is a 24-byte random string, bcrypt cost 12, stored in a password manager     (E3)
[ ] Credentials never on a command line; /root/.dns-netrc is 0600                               (E3)
[ ] Socket map is EXACTLY the E6-2 list; nothing on 0.0.0.0:3000, 0.0.0.0:8053 or 127.0.0.1:443 (E6-2)
[ ] nginx 1.24.0; `listen 443 ssl http2;` form (the standalone `http2 on;` is >= 1.25.1)        (E4)
[ ] EXACTLY ONE `:80` server block on the host, with EXACTLY ONE webroot                        (E4)
       grep -rn 'listen .*80' /etc/nginx/ | grep -v '#'
       -> exactly two lines: `listen 80 default_server;` and `listen [::]:80 default_server;`
       -- `default_server` is load-bearing: it makes a second listen-80 default_server a hard
          `nginx -t` failure instead of a silently shadowed block. Phase D3's `-w` argument and
          Phase Q5c's `location ^~ /.well-known/` both live inside THIS block, on THIS root.
[ ] sites-enabled/default removed (the packaged catch-all also binds :80)                       (E4)
[ ] X-Forwarded-For is OVERWRITTEN, CF-Connecting-IP and True-Client-IP stripped, Host pinned   (E4, E6-6)
[ ] proxy_pass carries $is_args$args -- without it every DoH GET client breaks                  (E4)
[ ] ssl_reject_handshake default_server active for unknown SNI                                  (E6-5)
[ ] adguardhome.service carries NO MemoryHigh/MemoryMax/OOMScoreAdjust -- those are A6's         (E5b, A6)
[ ] nginx's unit does NOT deny @privileged (it kills every worker at startup)                    (E5c, E5d)
[ ] [off-box] DoH GET and POST both return application/dns-message                              (E6-3, H2)
[ ] [off-box] /control/status, /login.html, /install.html, /apple/* ALL return 404              (E6-5, H2)
       -- a JSON body from /control/status is a stop-the-build defect
[ ] [off-box] DoT and DoQ resolve with kdig >= 3.3                                              (H3, H4)
[ ] [off-box, DUAL-STACK host] E6 step 9: every address published for dns.example.com
    answers Do53, DoT, DoQ and DoH                                             (E2a, E6-9, L1)
       -- this is the only dual-stack sweep in the plan; the H-series transport tests have no
          v6 variants and none are needed, because step 9 already runs all four transports
          against every advertised address. It reads that address list out of DNS instead of
          a $PUB variable, so it fails exactly when a record has been published that no
          listener owns. PASS is every column populated on every row, DoH=200. A blank column
          is a FAIL, not a partial pass: an RFC 6724 client prefers the AAAA, pays a connect
          timeout per attempt, and a v6-only client is hard-broken. The usual shape is the
          whole AAAA row blank except DoH -- nginx binds `[::]:443` explicitly while the
          Do53/DoT/DoQ wildcard socket lost its v6 half, which means the HOST's v6 stack is
          gone, not that `bind_hosts` is v4-only. Fix the listener or withdraw the record.
[ ] [off-box] Forged XFF / Host does NOT change the identity in the query log                   (E6-6)
[ ] With unbound stopped, the public edge SERVFAILs -- it never answers from anywhere else      (E6-7, H5)
[ ] version.bind returns REFUSED (not SERVFAIL, not an answer)                                  (E6-7, P1)
[ ] [off-box] trustanchor.unbound returns REFUSED too -- it is the FOURTH CHAOS probe           (C2, E2)
       kdig @<PUBLIC_IP> -c CH -t TXT trustanchor.unbound
       -- `hide-trustanchor` defaults to NO and the name is not in AdGuardHome's blocked_hosts,
          so without C2's line the resolver hands out its anchor state after the other three
          probes were made to lie. The guarantee is carried by `hide-trustanchor` and nothing
          else: the Phase P rewrite of the dns: block is exactly where blocked_hosts entries
          get lost.
```

### L6. Validation and load

Correctness first. **H5 is non-negotiable and both directions must be run** — the negative test
alone also passes on a host whose trust anchor is so broken that nothing resolves.

```
[ ] Do53 UDP + TCP, NXDOMAIN, and HTTPS/type65 all answer from the public IP                   (H1)
[ ] DNSSEC negative: dnssec-failed.org and sigfail... SERVFAIL on Do53, DoT, DoH and DoQ       (H5)
[ ] DNSSEC positive: signed name returns 'ad' + RRSIG on every transport                       (H5)
[ ] Cache normalisation: a name warmed WITHOUT +dnssec still returns RRSIGs to a +dnssec client (H5)
[ ] Rebinding: config assertion passes; live probe PASS or INCONCLUSIVE with its control        (H7)
[ ] Special-use zones answered locally, not recursed (.onion, in-addr.arpa, localhost)          (H7)
[ ] TCP fallback proven with a query that actually truncates (. DNSKEY +bufsize=512)            (H7)
[ ] DNS cookie status recorded -- AdGuardHome implements none; accepted gap, in the runbook     (H7, C2)
[ ] testssl.sh clean on :443 AND :853; TLS 1.2/1.3 only, no CBC/RC4                             (H9)
[ ] Leaf + intermediate served (a leaf-only chain works in browsers and breaks DoT clients)     (H9)
[ ] Rate limiting drops the flooder and NOT a neighbour in the same /24                         (H10)
[ ] The H10 set check finds all six sets in table inet filter and no second table               (H10)
[ ] H13 upstream/root-outage injection RUN, with all four numbers recorded                      (H13, C5.6)
       -- serve-expired is the plan's only graceful-degradation mechanism, and it is otherwise
          configured, costed in prose and never made to fire. Record: (1) :5335 still ANSWERS
          from stale rather than SERVFAILing; (2) the answer carries `; EDE: 3 (Stale Answer)`
          and a 30 s TTL; (3) num.expired has risen above zero; (4) Query time is roughly
          1800 ms -- the serve-expired-client-timeout cost measured on THIS host, not quoted.
[ ] H13 also recorded what the MONITORING did                                                   (H13, I6)
       which of RecursionStalled / ServfailRateHigh / RecursionLatencyP99High fired, whether
       dns-smoke.sh passed, and on Tier 3 whether the vrrp_script entered FAULT
[ ] H13 restore proven: injection rule deleted by handle, dns-smoke.sh -> SMOKE: PASS           (H13)
[ ] dns-smoke.sh exits 0 with SMOKE: PASS                                                       (H12)
[ ] dns-smoke.sh has been SEEN TO FAIL at least once (stop unbound, stop nginx, restore)        (H12)
[ ] All four pre-change gates exit 0                                                            (H12)
       nft -c -f /etc/nftables.conf ; unbound-checkconf ; nginx -t ;
       runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
         -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate
       -- the binary via the `current` symlink (the build the unit will actually run) and the
          SCRATCH validate work directory, never the live work/ tree: --check-config leaves
          artifacts, and root-owned artifacts under an adguardhome-owned tree break the next
          real start. Confirm /opt/adguardhome/validate exists and is adguardhome-owned 0750
          before relying on this gate (Phase O3 creates it).
[ ] At least one REAL device per transport in use was configured FROM the Phase R strings and
    resolves through this host end to end                                                       (R1, R3-R7)
       Android Private DNS (R3 — DoT/853, hostname only, fails closed, no fallback) · an Apple
       configuration profile (R4 — there is no system-wide UI) · Windows 11 (R5 — the resolver
       IP and the DoH template are registered as a PAIR) · one browser (R7)
       -- kdig passing is not evidence that any of these work. Each platform accepts a different
          subset of the four endpoint forms, several accept none without a profile, and a
          browser's own DoH silently discards whatever the OS was just told. A service that
          passes every test above and that nobody can onboard has not shipped.
[ ] R12's "am I actually reaching this resolver, with validation on" check was run FROM the
    client, not from the server                                                                 (R12)
[ ] The transport ranking in R2 is the one handed to users -- DoH/443 first, because DoT and
    DoQ on 853 are blocked outright on much of the hostile-network surface                      (R2)
```

**H11 load-test thresholds.** Every run is executed from the H0 test host with the server-side
instrumentation running. Record `RTT_base` first; LT-1 is stated relative to it.

```
[ ] LT-0   RTT_base recorded                                          ______ ms
[ ] LT-1   Do53 warm 2,000 QPS / 300 s : p50 < RTT_base+1ms, p99 < RTT_base+5ms
[ ] LT-2   Do53 warm                    : lost + timeout == 0
[ ] LT-3   Do53 cold 500 QPS            : p99 < 250 ms
[ ] LT-4   Do53 hostile 300 QPS         : p99 < 400 ms, SERVFAIL < 1%
[ ] LT-5   DoT 200 new conns/s          : handshake p99 < 150 ms
[ ] LT-6   DoH 1,000 QPS / 50 conns     : p99 < 15 ms
[ ] LT-7   DoQ 500 QPS                  : p99 < 20 ms
[ ] LT-8   every run: nf_conntrack_count peak < 5,000
             -- this is the direct check on the Phase B NOTRACK bypass. Hundreds of thousands
                here means the bypass is not in effect and the box will drop SSH with DNS.
[ ] LT-9   every run: UdpRcvbufErrors delta == 0
[ ] LT-10  every run: peak CPU across all cores < 70%
[ ] LT-11  every run: no new dmesg entries
[ ] LT-12  every run: disk growth < 20 MB / 10 min
             -- stated for the SHIPPED default (query log in memory only, statistics on). If a
                Phase Q posture puts a file log on disk, recompute the gate from G2's arithmetic
                rather than failing a run against a number that no longer applies.
[ ] LT-13  4-hour soak at 30% of the measured knee: RSS slope FLAT for both daemons
             -- nothing shorter finds a leak, and a leak is this stack's most likely
                production failure. Run it before go-live, not after.
[ ] Capacity knee measured with resperf and recorded; G2's query-log arithmetic re-run
    against the MEASURED QPS, not the guessed one                                              (H11, G2)
```

### L7. Observability and alerting

```
[ ] promtool check config / check rules / amtool check-config all pass                          (I11-1)
[ ] Every .prom textfile parses    promtool check metrics < ...                                 (I11-2)
[ ] Every unbound_* key referenced by an alert EXISTS in this build's stats output              (I11-3)
       -- an alert on a key your build does not emit is dead code that never fires
[ ] statistics.enabled reads true via /control/stats/config, OR a Phase Q posture was
    deliberately opted into and Q5a records it                                                  (I11-4, Q1)
[ ] The disabled-statistics path DEGRADES rather than pages: agh_up 1, agh_running 1,
    agh_stats_enabled 0, agh_metrics_unavailable_by_policy 1, and agh_queries_window_total
    ABSENT (not zero). Proven once, whether or not you intend to use the posture.                (I11-4b, I3)
       -- Phase I owns this logic. AdGuardHomeDown cannot fire on a policy choice.
[ ] recent=3600000 returns 200 and recent=60000 returns 400 -- the contract, not a guess         (I11-5)
[ ] agh_up, unbound_up, dnsprobe_success and dns:qps:rate5m all return >= 1 series                (I11-6)
[ ] prometheus_tsdb_head_series well under 5,000                                                 (I11-7)
[ ] Retention came from the config file, not the 15d default                                     (I11-9)
[ ] [off-box] 9090/9093/9094/9095/9100/9115 all filtered; 9094 does not exist at all              (I11-10)
[ ] Watchdog rule loaded and firing                                                               (I11-11)
[ ] A real notification reached the PHONE, on the lock screen, with sound                          (I11-12)
[ ] The ntfy bridge returns 502 on a failed push (never a lying 200)                               (I11-13)
[ ] **The dead man's switch was proven by stopping Alertmanager and waiting for the external
    service to page you.** Without this you have a dashboard, not monitoring.                      (I11-14, I9)
[ ] A SECOND, independent external check exists (port monitor on :853 from outside)                (I9)
       -- catches "the box talks to itself but the internet cannot reach it"
[ ] chrony is in dns-smoke.sh's UNITS list, so is-active/is-enabled are checked on every
    restart, upgrade, reboot and restore                                                           (H12, I6)
       -- chrony left disabled after a manual fix is exactly the M7 failure class the plan
          already guards for the other four units.
[ ] ClockUnsynchronised and ClockOffsetHigh are LOADED rules, and one has been seen to fire       (I6)
       systemctl stop chrony && date -s '+3 days'   -> every signed name SERVFAILs while
       root.key is intact and the alert fires; then systemctl start chrony && chronyc makestep,
       then re-run dns-smoke.sh
       -- a dead clock and a dead trust anchor produce the SAME symptom. Without these two rules
          the runbook's trust-anchor row sends the operator to `unbound-anchor` and a
          cache-dumping restart for a fault neither one can fix.
[ ] Both external services, their credentials location and their notification targets are
    recorded in the Phase O inventory                                                              (I9, O6)
[ ] /usr/local/sbin/notify.sh exists, is 0750 root:root, and a self-test reached the phone          (I8b, I11-15)
       -- this is the SINGLE notification entry point. Phase D, G, H, K, L, M, N and Q all call
          it; no phase ships a second one. Exit 3 = NTFY_URL unset, exit 4 = push failed, and a
          caller must not conflate either with its own failure.
[ ] /etc/cron.d/dns-health exists, is 0644 root:root, has no dot in its filename, and loads
    without a parse error in `journalctl -u cron`                                                   (I10, I11-16)
[ ] Every cron consumer APPENDED its line to that one file -- nobody rewrote it and nobody
    created a second cron file beside it                                                            (I10)
       expected lines: dns-health daily gate (I10), diskguard (G4), smoke gate (H12),
       restore drill (K6), reboot-pending (M6), is-enabled guard + hold guard (M7),
       restart-churn detector (N4c), the two DNSSEC detectors (C3), the monthly anchor-state
       and root.hints staleness checks (C3, M1), the weekly domain-expiry check (I4), and the
       weekly release watch (I4c)
[ ] dns-health exits 0                                                                              (I10, I11-17)
[ ] SLO targets agreed and written down; error-budget policy accepted                               (I7)
```

### L8. Abuse controls

```
[ ] The v1 query-log abuse cron is GONE and nothing in the abuse tooling reads querylog.json      (J1, J10-10)
[ ] Phase J writes NO nftables configuration -- every object it manipulates is Phase B's          (J3)
[ ] `iif lo accept` is the FIRST rule of dns_guard    nft -a list chain inet filter dns_guard     (J10-2)
[ ] Local-flood regression test does NOT ban 127.0.0.1                                            (J10-3)
[ ] Ban sets live in the SAME table as the chain that adds to them (`table inet filter`)           (J10-4, B4)
[ ] [off-box] A real remote flood populates banned_ips and increments dns_banned                   (J10-5)
[ ] Ban expiry countdown is live and shrinking                                                      (J10-6)
[ ] Ban state survives a reload via nft-apply, WITH ITS REMAINING TIME                               (J10-7, B8)
[ ] There is no second reload wrapper                 test ! -e /usr/local/sbin/nft-bans            (J10-7b, B8)
[ ] allowlist4 / allowlist6 contain loopback plus every known-good high-volume client                (B6, J5, J7)
       -- an allowlisted source bypasses flood detection AND banning entirely: `dns_guard`
          consults `@allowlist4` / `@allowlist6` and returns early for members (B5). Loopback
          ships in the sets, which is what keeps an on-box load test (H11) from banning 127.0.0.1.
[ ] Escalation: 10 minutes on first offence, promoted to 24 hours on repeat; no permanent tier      (B5, J4, J9)
[ ] The 24-hour escalation sets exist in `table inet filter` and are actually ENFORCED
    (i.e. `chain input` drops on them, not only `banned_ips`/`banned_ips6`)                          (B5, J3, J4)
       -- verify before go-live: `nft list set inet filter banned_long` must succeed and
          `nft list chain inet filter input` must reference it. If either fails, escalation
          promotes addresses into a set nothing consults and the 24-hour tier is inert.
[ ] /var/lib/dns-abuse/offences is 0600 root, trimmed to 24 h, and excluded from backup              (J4, J10-8, J10-11)
[ ] nft_dns_banned_packets and nft_banned_ips_elements reach Prometheus                               (J10-9)
[ ] The J8 spoofed-flood fallback (drop-only: remove the `add @banned_ips` clause from the two
    dns_guard flood rules, keep the meters and the drop) is written into the runbook with the
    exact lines QUOTED FROM PHASE B's CURRENT RULESET, and has been rehearsed once                    (J8 step 3)
[ ] J9's trade -- that a little over 400 spoofed pps can ban any address the attacker chooses --
    is recorded as accepted in the Phase O decision log                                               (J9)
```

### L9. Backup, restore and reproducibility

```
[ ] The v1 daily copy job is gone       rm -f /etc/cron.daily/dns-backup                             (K1)
[ ] **/opt/dns-config-backup still EXISTS.** It is the local config staging directory that
    Phases I, J and Q write to; Phase K backs it up off-host rather than deleting it.                (K1, K3)
       -- **Phase A3 creates it** (`install -d` plus `git init`), because Phase I3 appends to
          its .gitignore and Phase Q5a commits RETENTION.md into it, both long before Phase K
          runs. Phase K backs it up; Phase K neither creates nor deletes it.
[ ] restic repo initialised; `restic cat config` opens it                                            (K2)
[ ] **The repository password is in the password manager.** No escrow exists. Losing it loses
    every backup ever taken.                                                                          (K2)
[ ] Second operator exists and has been PROVEN, or the single-operator exposure is recorded as
    accepted, with a date, in the Phase O inventory                                                   (K8, O6)
       [ ] `restic key add` gave the second holder their OWN password (revocable with
           `restic key remove`), and K2's object-storage credential reached them too -- without
           it the key opens nothing
       [ ] a second Alertmanager receiver and a second dead man's switch target reach a
           DIFFERENT human on a DIFFERENT device, and I11-14 was re-proven against it
       [ ] a second SSH admin key was added and proven with A4's own two-session procedure
       [ ] the absence procedure has been run once
       -- as shipped, K2 has no escrow, K7's pass criterion is literally "no value came from
          outside the password manager", and Alertmanager has one topic on one phone. Every
          drill in this plan is written for one person and passes for one person, which is
          exactly why this failure is invisible until the person is unavailable.
[ ] Object-storage credential scoped to one bucket; delete rights withheld where expressible          (K2)
[ ] /etc/letsencrypt backed up WHOLE (archive included), root.key included                            (K3)
[ ] /etc/prometheus, /etc/alertmanager and /etc/blackbox_exporter are in the include list             (K3)
       restic ls latest | grep -E '^/etc/(prometheus|alertmanager|blackbox_exporter)/'  -> lines
       -- previously unbacked-up. Losing them does not take DNS down, which is exactly why they
          get rebuilt last and worst under outage pressure.
[ ] /opt/dns-config-backup is in the include list      restic ls latest | grep -c dns-config-backup   (K3)
[ ] /etc/nftables.d/dns-allow.nft is captured by the include list (add it if it is not --
    B6 requires it and the allowlist is not regenerated by anything else)                              (B6, K3)
[ ] querylog / stats.db / sessions.db / filters excluded   restic ls latest | grep -c querylog -> 0    (K3)
       -- the exclude paths are /var/log/adguardhome/querylog and /var/lib/adguardhome/stats,
          NOT the old /opt/adguardhome/work/data/ locations
[ ] restic-backup.timer enabled; a snapshot exists; check --read-data-subset runs                     (K4)
[ ] No secret has ever been committed   git log --all -p | grep -cE '\$2[aby]\$..\$|PRIVATE KEY' -> 0 (K5)
[ ] vault.yml is WHOLE-FILE encrypted ($ANSIBLE_VAULT on line 1)                                       (K5b)
[ ] Pre-commit tripwire installed AND mirrored as a CI job                                             (K5d)
[ ] **Tier 1 restore drill passes**  restic-restore-drill.sh -> exit 0, DRILL PASS logged              (K6)
       -- its gates name the canonical filenames: 10-public-resolver.conf and
          unbound.service.d/hardening.conf. A drill testing for dns-node.conf or ha.conf would
          fail on a correctly built host and train you to ignore the drill.
[ ] **Tier 2 DR rebuild drill completed on a scratch VPS**, with all four pass criteria:               (K7)
       [ ] dns-smoke.sh exits 0 with SMOKE: PASS on the rebuilt host
       [ ] served certificate is the RESTORED one, not a silently re-issued one
       [ ] no step needed SSH to production and no value came from outside the password manager
       [ ] wall clock inside the O5 target                     measured: ______ minutes
[ ] That measured number is written into the runbook as the real RTO -- and it EXCLUDES DNS
    propagation, so for Tier 0/1 add the A-record TTL to it                                             (K7, O5, D0)
[ ] **H14 rollback rehearsal RUN on a healthy host**, not merely present in the script          (H14, M3)
       measured: ______ seconds  -- that number is the rollback RTO and belongs in the runbook
       next to K7's. Assert after: `readlink -f /opt/adguardhome/current` is the PREVIOUS
       release; `schema_version` in AdGuardHome.yaml is the OLD number, proving the
       pre-migration copy was restored and not the migrated one; the file is
       adguardhome:adguardhome 0600; dns-smoke.sh exits 0 against the rolled-back version.
       -- rollback is the only automated recovery mechanism in this plan that nothing else
          exercises. Its branch runs for the first time at 03:00 with the service already down,
          and if it fails there the operator is in an unplanned K7 rebuild.
[ ] Unbound rollback rehearsed, and the apt-mark hold interaction is UNDERSTOOD                 (H14, M4, M7)
       -- a rollback pins with `apt-mark hold`, which M7's hourly guard then flags as a defect.
          Do not clear the hold during the incident. Confirm the held version actually starts
          against the drop-in on disk, and record how the hold is released once you fix forward.
[ ] The Phase O operational inventory EXISTS and every row has an answer and a date              (O6)
       /opt/dns-config-backup/INVENTORY.md, committed; the unanswered-row check is clean and
       `git log -1` on it is recent
       -- I4, I9, J9 and L7 all say "record it in the Phase O inventory". This is the file they
          mean. Sections: accounts and who ELSE can reach them; external dependencies with their
          notification target and renewal date; the installed version of every out-of-apt binary
          (which is also the release-watch input); and the measured numbers the plan asks for
          and otherwise leaves loose -- the K7 rebuild clock, the H14 rollback clock, the P8d
          revocation time, the H11 capacity knee.
[ ] unattended-upgrades restricted to the security pockets; Automatic-Reboot false (single node)        (M1)
[ ] needrestart in automatic mode; it will bounce unbound/nginx on a libc or OpenSSL update             (M2)
[ ] upgrade-adguardhome.sh and upgrade-unbound.sh installed, and each rolls back on smoke failure       (M3, M4)
[ ] Release watch is ACTIVE for all six out-of-apt daemons                                             (I4c)
       AdGuardHome, restic, prometheus, node_exporter, alertmanager, blackbox_exporter
       -- Phase M ends at M7 and ships no release watch; I4c owns it, alongside the RDAP
          domain-expiry check, because both are slow external calendars rather than host state.
          unattended-upgrades (M1) is scoped to the three apt security pockets and
          STRUCTURALLY cannot cover any of these. M3 says "read the release notes before every
          upgrade", which presumes you already know an upgrade exists; AdGuardHome runs with
          `--no-check-update`. The weekly comparison on /etc/cron.d/dns-health is the only thing
          between this plan and an unpatched daemon that parses hostile DNS, HTTP/2 and QUIC
          from the entire internet.
[ ] The release watch has been SEEN TO FIRE once (pin a version backwards and let it run)              (I4c)
[ ] The release watch does NOT auto-upgrade -- M3's wrapper stays operator-invoked                     (I4c, M3)
[ ] Each component's pinned version and release feed are in the Phase O inventory, with a
    named human responsible for reading it                                                             (I4c, O6)
[ ] Neither upgrade wrapper contains a setcap step                                                      (M3 trap 1)
[ ] Every unit is ENABLED, not merely active; the hourly is-enabled guard is in cron                    (M7)
[ ] No package hold left in force   apt-mark showhold -> empty                                          (M4, M7)
[ ] HA tier chosen and recorded. Tier 3: keepalived FAULT-state handover proven, exactly one node
    holds certbot.timer, DNS-01 in use, reboot windows staggered by >= 1 h                              (N2, N3, M6)
[ ] Units self-heal through a transient fault AND still park in `failed` after 10 attempts in
    300 s; the churn detector is wired into /etc/cron.d/dns-health                                       (N4a, N4c)
       -- a StartLimit of ZERO would be wrong: a unit that can never reach `failed` can never
          fire OnFailure= either.
[ ] Phase N sets NO memory ceiling and NO swappiness value -- those are A6's                             (N5a)
[ ] Ansible run is idempotent: changed=0 failed=0 on EVERY recap line                                     (O5)
[ ] Drift cron tests for the PRESENCE of drift, not the absence of it                                      (O4)
[ ] Handlers are defined once, in restart order, in a single shared handlers file, and
    `reload nftables` calls nft-apply rather than a bare `nft -f`                                          (O3)
```

**The three procedures that only exist if somebody wrote them.** Each of these is a decision the
operator must make and record, not a value the plan can supply: every one of them names a human,
and a procedure with no owner is a paragraph. Read them before go-live, not during the event.

```
[ ] Compromise procedure exists, names an OWNER, and its first step is NOT a reboot     (08 runbook)
       -- the availability escalation path's first two steps destroy the evidence: a reboot
          loses the process table and, under Q3, the whole tmpfs query log; a rollback
          overwrites the artifacts. It must also state that K3's include list carries
          /etc/systemd/system, /usr/local/sbin and /etc/cron.d, so restoring a snapshot taken
          AFTER the intrusion reinstalls it -- restore from before the earliest suspicious
          timestamp, and rebuild rather than clean.
[ ] The K5e post-compromise rotation list is written and reachable from that procedure      (K5e)
[ ] The Q6 Art. 33 clock is understood to start at AWARENESS, and what was exposed is stated
    per posture -- under the shipped default, up to 6 h of /16-truncated records that were
    RAM-resident and vanish the moment you reboot                                          (Q6, Q1)
[ ] IP-change / provider-migration procedure exists and names an OWNER                     (N8, A1)
       -- rehearse it assuming you CANNOT log into the old box: a suspension normally arrives
          with the old address already unreachable. The TTL step is the one that cannot be done
          retroactively, which is why the A/AAAA TTL is held at 300 permanently (L1). Do53
          clients that configured a literal address cannot be migrated at all -- that is the
          argument for steering users to the hostname transports in Phase R.
[ ] Decommissioning procedure exists, names an OWNER, and commits to a notice period that is
    also stated in the published privacy notice                                        (Q5b, Q6)
       -- the two prohibitions are the substance: do NOT let the domain lapse (a lapsed name
          plus a fresh Let's Encrypt certificate is a working hijack of every device still
          configured to trust it), and do NOT release the IP while Do53 clients still point at
          it. Certificate revoked at shutdown, restic repository and key destroyed deliberately,
          disposal date closing RETENTION.md.
```

### L10. Privacy, retention and legal — `(Q)`

```
[ ] Logging posture chosen and recorded. Doing nothing means Posture C — the Phase E shipped
    default — and that is a choice that must appear in RETENTION.md and the privacy notice.            (Q1)
[ ] The posture's monitoring consequences are understood and accepted                                  (Q1, I3)
       Posture A (statistics off): AGH window metrics ABSENT; Phase I emits "metrics unavailable
       by policy"; AdGuardHomeDown cannot fire on it. Posture B: monitoring costs nothing.
[ ] AGH starts clean; no legacy querylog_ keys; no 2160h anywhere in the file                          (Q1)
[ ] stats.db asserted EMPTY OF CLIENTS -- never asserted absent, that check can never pass             (Q1)
[ ] anonymize_client_ip understood as /16 and /48 (not /24), and never used as an abuse input          (Q1, J1)
[ ] The sensitive-path inventory names the REAL paths Phase E configures                               (Q3)
       /var/log/adguardhome/querylog and /var/lib/adguardhome/stats -- not /opt/adguardhome/work/data
[ ] tmpfs (if adopted) is mounted on those two paths; ExecStartPre=+install fixes ownership;
    RequiresMountsFor is set in the unit's [Unit] section                                              (Q3)
[ ] After a reboot both tmpfs directories carry nothing over                                            (Q3)
[ ] Unbound verbosity is 1 and this is stated correctly in the posture inventory -- level 1 logs
    operational events, not queries; verbosity 0 costs diagnosis for no privacy gain                    (Q3, C2)
[ ] Unbound remote-control is recorded as ENABLED BY DESIGN (Phase I needs it), with the
    dump_cache exposure that follows, and no scripted dump_cache exists                                 (Q3, I2)
[ ] journald storage decision (persistent vs volatile) made and recorded, not defaulted                 (Q3)
[ ] Disk-encryption decision recorded WITH its limits (nothing against a live hypervisor)               (Q3)
[ ] access_log off proven BEHAVIOURALLY on BOTH client-facing server blocks -- the :443 DoH block
    and the single :80 block. A DoH GET access log stores the client IP next to the encoded query,
    which is worse than a query log.                                                                    (Q4, E4)
       -- check behaviourally (byte size of access.log before/after a request), not by grepping
          /etc/nginx: the http-level access_log in nginx.conf is correctly overridden and a
          grep-based check produces a false failure on every stock box. Note also that Phase E
          writes both blocks into /etc/nginx/conf.d/doh.conf, so a loop over sites-enabled/*
          inspects nothing.
[ ] CT exposure of the hostname accepted, or a DNS-01 wildcard issued INSTEAD -- this decision
    cannot be reversed after first issuance                                                              (Q4, D7)
[ ] PTR matches dns.example.com and forward/reverse agree                                                (Q4)
[ ] Phase Q added a `location ^~ /.well-known/` to Phase E's EXISTING :80 block. It did NOT create
    a second listen-80 default_server and did NOT create a second webroot.                               (Q5c, E4, R7)
[ ] `charset utf-8;` (and, if you want it, `server_tokens off;`) are present in Phase E's server
    blocks -- Q5c depends on them and Phase E does not ship them by default                              (Q5c, E4)
[ ] security.txt served over HTTP and HTTPS as text/plain; charset=utf-8; exactly one Expires,
    under one year out; expiry check active and calling notify.sh with a severity argument               (Q5c, I8b)
[ ] Ban duration stated to users matches the kernel: "10 minutes, escalating to 24 hours on
    repeat offences" -- in BOTH the retention policy and the privacy notice                              (Q5a, Q5b, J3, B5)
[ ] abuse@ and security@ exist, are monitored, and were tested BY HAND end to end                        (Q5c)
[ ] Provider abuse-forwarding ticket raised and its reference recorded                                    (Q5c)
[ ] Privacy notice published and linked from security.txt Policy:, and it matches the posture
    actually running -- publishing zero-log wording on a Posture C host is a false statement              (Q5b)
[ ] RETENTION.md committed to /opt/dns-config-backup; the Q6 decision register has an answer and
    a date in EVERY row                                                                                   (Q5a, Q6)
[ ] **Provider AUP read for open-resolver / amplification clauses.** This is the thing most likely
    to end the service, and suspension is the normal enforcement.                                          (Q6)
[ ] Preservation-order and law-enforcement handling decided IN ADVANCE, not under pressure                 (Q6)
[ ] The three unfixable disclosures are in the notice: cleartext SNI, CT, provider netflow                 (Q4, Q5b)
```

### L11. Private access layer — `(P)`

Skip this block entirely for a deliberately public resolver; keep Phase J in full instead and read
P7c, because the plan as written rate-limits only plain UDP.

```
[ ] Mechanism selected and recorded: P6 WireGuard | P3 ClientID | P5 mTLS | P2 nft allowlist | P1 only  (P0)
[ ] allowed_clients populated and READ BACK via the control API                                          (P1)
[ ] blocked_hosts survived the P1 edit (it replaces part of Phase E's dns: block)                        (P1, E2)
[ ] trusted_proxies narrowed to 127.0.0.1/32, ::1/128                                                    (P1)
[ ] Phase P created NO new table, NO new chain and NO new hook -- it edits Phase B's objects             (P2, P7b)
[ ] P2's allowlist rewrite is a single atomic nft transaction and never reloads /etc/nftables.conf       (P2c)
[ ] Every firewall edit was applied with /usr/local/sbin/nft-apply, and live ban timeouts survived        (P2c, P7b)
[ ] allowlist4 still holds 127.0.0.0/8 (and ::1/128 in allowlist6) after any rewrite                      (P2a)
[ ] ratelimit_subnet_len_ipv4/ipv6 still 32/64 after any edit to the dns: block                           (P7c, E2)
[ ] [off-box] Unauthorised client matches the P8a matrix exactly for this mechanism                       (P8b)
[ ] [off-box] Authorised client resolves over EVERY transport the deployment exposes                      (P8c)
[ ] [off-box] nmap shows only the ports this mode intends; 3000/8053/8853 never appear                    (P8b)
[ ] serve_plain_dns:false was applied TOGETHER with the P7e health-cron change, in one window             (P1, P7d)
[ ] Phase I probes moved inside the access path; the health cron probes the NEW binding                   (P7e)
[ ] Phase J neutralised or converted to identity revocation -- IP bans are meaningless behind a
    tunnel, and a peer can be banned by its own tunnel address                                            (P7b, P7f)
[ ] dns_guard exempts `iifname "wg0"` (or the tunnel subnet is in allowlist4/6, or the chain was
    deliberately removed). **`table inet filter` itself is NEVER deleted -- it is the whole firewall.**   (P7b, P7f)
[ ] Wildcard cert AND wildcard A record in place -- ONLY if DoT/DoQ ClientID SNI is used                   (P3c, D7)
[ ] The wildcard AAAA in P3c was published ONLY if the AAAA row of E6 step 9 passes         (P3c, E2a, E6-9)
       -- P3c exists to serve Android Private DNS and DoQ, i.e. exactly the clients that dial
          `[v6]:853` first. The shipped wildcard `bind_hosts` already serves both families, so
          what has to be proven is that this HOST's v6 path works end to end, not that the
          list contains `'::'`. Adding it binds `[::]:853` twice and proves nothing. Under P6 the
          listener moves to the two tunnel literals, `10.77.0.1` and `fd77:d15:c0de::1` — one
          AF_INET socket and one AF_INET6 socket, so P6 is still dual-stack, just unreachable
          from outside the tunnel. Publish no AAAA for the tunnel address because it is a ULA
          that is never published, not because the socket cannot serve it. See the L1 posture gate.
[ ] CAA `issuewild` was relaxed to "letsencrypt.org" BEFORE the DNS-01 wildcard was requested          (D2, D7)
[ ] Revocation drilled end to end and TIMED     measured: ______ seconds                                   (P8d)
       -- if it is not near-instant, revocation depends on something you do not control
[ ] P7's honest cost accepted and disclosed: the access layer is a stronger identity layer than
    anything the resolver held. wg show output is never captured to disk or into monitoring.               (Q7)
[ ] Secrets excluded from source control: wg keys, *.p12, doh-tokens.map, *.psk                             (P4c, P5a, K5)
```

### L12. Do not go live if

Any one of these is a hard stop. They are not "fix it next week" items — each one either voids the
whole design or produces a silent, unattributable failure in production.

1. **`dig @<PUBLIC_IP> dnssec-failed.org` returns an answer instead of SERVFAIL**, or the positive
   test does not produce the `ad` flag. Validation is the product. (H5)
2. **The service still answers with `unbound` stopped.** Something is routing around the validator;
   every DNSSEC guarantee in this document is void. (E6-7, H5)
3. **`/control/status` or `/login.html` returns anything but 404 from the internet.** The control
   API rewrites upstreams and dumps the query log. (E6-5, H2)
4. **`nf_conntrack_count` climbs into the tens of thousands under the L6 load run.** The NOTRACK
   bypass is not in effect, and the first real flood takes SSH down with DNS. (LT-8, B9-2)
5. **The dead man's switch has never been proven to page you.** You cannot operate a single-VPS
   service whose monitoring dies with it. (I11-14, I9)
6. **The Tier 2 restore drill has not been run to a `SMOKE: PASS`,** or the restic password exists
   only on the host. You have no recovery path, only a belief in one. (K6, K7, K2)
7. **`root.key` is empty, or `auto-trust-anchor-file` is declared more than once.** This presents as
   a total outage with no obvious cause. (C3)
8. **`getcap` shows a file capability on the AdGuardHome binary,** or `AmbientCapabilities` is
   absent. One of the two configurations cannot bind :53 at all. (E1, E5a, E6-1)
9. **The AdGuardHome config on disk after first start differs from what you wrote** in `querylog:`
   or `statistics:`, or has no `schema_version`. Your retention settings are not the running
   settings — and the v1 layout is a boot failure, not a warning. (E2, E6-8, Q1)
10. **`getent hosts` / `apt update` fail on the host itself.** The notrack rule is pointing the
    wrong way and certbot renewal will fail silently at 03:00. (B9-3)
11. **`/etc/resolv.conf` has more than one `nameserver` line, or the one it has is not 127.0.0.1.**
    A fallback entry silently reintroduces an unvalidated resolution path at exactly the moment the
    validating one breaks. (A2, C5.8)
12. **`nft list tables` shows anything other than `inet raw` and `inet filter`,** or more than one
    base chain on the input hook. A cross-table `add @set` is illegal, so a second policy table
    means the in-datapath ban silently never fires. (B9-1, B4, J2)
13. **LT-13's four-hour soak was skipped,** or RSS slopes upward. A leak found in production is an
    outage; a leak found here is a config change. (H11)
14. **A secret has been committed to the config repo at any point in its history.** Treat it as
    disclosed and rotate before launch, not after. (K5)
15. **The published ban duration and the kernel's ban duration disagree.** Q5a and Q5b state a
    number to your users; B5 and J4 implement one. If they diverge, the published policy is false.
    (Q5a, Q5b, B5, J4)
16. **`dns.example.com` does not resolve to this host from two independent public resolvers, or
    its zone is served by this machine.** This box is authoritative for nothing, so a zone hosted
    here disappears the instant the host does — taking every DoT, DoQ and DoH client, both
    external monitors and the Phase N8 cutover with it, at exactly the moment they are needed.
    Certbot cannot issue against a name that does not resolve either, and each attempt spends one
    of five per hour. (D0, A1)
17. **The build was left half-finished with `adguardhome` running.** From E5 onwards the host
    answers the public internet on udp/53, tcp/53 and 853 — with Phase B's limits in force but
    validation unproven, no monitoring, and Phase J's ban escalation absent. Scanner traffic
    arrives within hours of the first bind. Finish through L, or `systemctl stop adguardhome`
    before you walk away. (E5)

---

## Directory and Port Layout (Final)

This is the authoritative map. Anything listening that is not in the first table, or any file
outside the second, is either a Phase P/N addition or a defect. **Phase R adds neither** — it is
client-side documentation and introduces no listener, no file, no unit and no cron line on this
host, which is why it is the one phase with nothing in either table.

### Listening sockets — base build

The **Family** column is load-bearing and is the thing most often assumed rather than read — and
what is assumed is usually that `0.0.0.0` means IPv4. It does not. A wildcard listen address
resolves to an AF_INET6 socket with `IPV6_V6ONLY=0` (`net/ipsock_posix.go`), so AdGuardHome's
Do53, DoT and DoQ each serve **both** families from a single socket on the shipped
`dns.bind_hosts: [0.0.0.0]`. nginx is the opposite shape on purpose: `listen [::]:443` defaults to
`ipv6only=on`, so E4 ships a `[::]` line beside every `0.0.0.0` line. Phase B's `inet` ruleset
accepts both families throughout. Two consequences: appending `'::'` to `bind_hosts` binds the
same socket twice and is never the fix, and the only entry below that is genuinely single-family
is one bound to a literal address. Whether to publish an AAAA is the L1 posture gate, proven by
the L5 [off-box] E6 step 9 sweep; whether Unbound *recurses* over IPv6 is `do-ip6` in Phase C — a
separate question with a separate answer (E2a, C2).

| Proto/Port | Bound to | Family | Owner | Exposure | Phase |
|---|---|---|---|---|---|
| tcp/22 | `0.0.0.0` | v4 + v6 as sshd ships — no `ListenAddress` is set | sshd | **public**, 10 new/min | A4, B5 |
| udp/53 | `0.0.0.0` | **v4 + v6 — one wildcard socket, `v6only:0`** | AdGuardHome | **public**, NOTRACK'd, explicit accept (load-bearing) | E2a, B5 |
| tcp/53 | `0.0.0.0` | **v4 + v6 — one wildcard socket, `v6only:0`** | AdGuardHome | **public**, conntracked, app limiter does NOT cover it | E2a, B5 |
| tcp/80 | `0.0.0.0` + `[::]` | v4 + v6 | nginx | **public**, permanently: one server block, one webroot `/var/www/acme`, serving the ACME challenge and `/.well-known/`; everything else 404 | E4, D3, Q5c, B7 v2 |
| tcp/443 | `0.0.0.0` + `[::]` | v4 + v6 | nginx | **public**: TLS terminator; only `= /dns-query` is proxied | E4 |
| udp/443 | — | — | — | **closed**. nginx 1.24.0 has no HTTP/3 and `serve_http3: false` | E2, B5 |
| tcp/853 | `0.0.0.0` | **v4 + v6 — one wildcard socket, `v6only:0`** | AdGuardHome `dnsforward` | **public** DoT — nginx is NOT in this path | E2a |
| udp/853 | `0.0.0.0` | **v4 + v6 — one wildcard socket, `v6only:0`** | AdGuardHome `dnsforward` | **public** DoQ (RFC 9250), NOTRACK'd | E2a, B5 |
| tcp/3000 | `127.0.0.1` | v4 loopback | AdGuardHome | **loopback** — admin UI + `/control/*`, SSH tunnel only | E2, A4 |
| tcp/8053 | `127.0.0.1` | v4 loopback | AdGuardHome | **loopback** — HTTPS DoH backend behind nginx | E2, E4 |
| udp+tcp/5335 | `127.0.0.1`, `[::1]` | v4 + v6 loopback | Unbound | **loopback** — the only recursor and validator | C2 |
| tcp/9090 | `127.0.0.1` | v4 loopback | Prometheus | **loopback** | I1 |
| tcp/9093 | `127.0.0.1` | v4 loopback | Alertmanager | **loopback**; 9094 gossip removed via `--cluster.listen-address=` | I8 |
| tcp/9095 | `127.0.0.1` | v4 loopback | alertmanager-ntfy bridge | **loopback** | I8 |
| tcp/9100 | `127.0.0.1` | v4 loopback | node_exporter | **loopback** | I1 |
| tcp/9115 | `127.0.0.1` | v4 loopback | blackbox_exporter | **loopback** | I4 |
| unix | `/run/unbound.ctl` | — | Unbound | **local socket**, root-owned; remote control is ON by design | C2, I2 |

Ports that must NOT appear: **udp/784** (v1's DoQ draft port — RFC 9250 is udp/853 and 784 is gone
from this design entirely), **tcp/8953** (an unnecessary second `unbound-control` channel — the
shipped unix socket is the only control interface), **udp/9094** (Alertmanager gossip), anything on
**0.0.0.0:3000** or **0.0.0.0:8053**, and anything on **127.0.0.1:443** (the symptom of the
decision-5 topology bug).

### Listening sockets — conditional additions

| Proto/Port | Bound to | Owner | Condition |
|---|---|---|---|
| udp/51820 | `0.0.0.0` | WireGuard `wg0` | Phase P6; the only public port besides 22 in that mode |
| udp+tcp/53 | `10.77.0.1` | AdGuardHome | Phase P6 — replaces the `0.0.0.0` binding |
| tcp/853 | `0.0.0.0` | nginx `stream` | Phase P5 mTLS front |
| tcp/8853 | `127.0.0.1` | AdGuardHome | Phase P5 — AGH's DoT moves to loopback behind nginx |
| ip proto 112 | private NIC | keepalived VRRP | Phase N3 Tier 3 — neither TCP nor UDP, needs its own accept |

The same address-family rule governs the conditional set, and this is where the literal-address
exception bites. P3c's `*.dns.example.com` AAAA is correct only if this host's IPv6 stack actually
works behind the wildcard socket — which E6 step 9 measures and nothing else does; P3c is
precisely the ClientID-SNI path, whose whole purpose is the DoT and DoQ clients that dial
`[v6]:853` first. Phase P6 is a different case: rebinding AdGuardHome to the two tunnel literals
`10.77.0.1` and `fd77:d15:c0de::1` gives one AF_INET socket and one AF_INET6 socket, so a P6
deployment is still dual-stack at the listener — it is simply unreachable from outside the tunnel.
No AAAA belongs on the tunnel address because `fd77:d15:c0de::1` is a ULA that is never published,
not because the socket cannot serve it.

### nftables objects — the single ruleset

There is exactly one policy table. `table inet raw` exists only because `notrack` is legal only at
the raw hook, and it contains no policy.

| Object | Kind | Declared in | Manipulated by |
|---|---|---|---|
| `table inet raw` / `chain prerouting`, `chain output` | NOTRACK for udp 53, 443, 853 (server direction) and loopback udp/5335 | B5 | nobody |
| `table inet filter` / `chain input` | the only base chain on the input hook, `policy drop` | B5 | P2b (allowlist-scoped accepts), N3 (VRRP accept) |
| `chain dns_guard` | **regular chain, jumped from `input`** — flood detection + in-datapath ban | B5 | J8 step 3 (drop-only fallback), P7b (tunnel exemption) |
| `chain certbot` | ACME port-80 window | B5 | B7 hooks |
| `chain output` | egress RRL per destination + absolute byte cap | B5 | — |
| `floodmeter4` / `floodmeter6` | dynamic timeout sets, 400/s per source | B5 | read-only (J6, H10) |
| `banned_ips` / `banned_ips6` | dynamic timeout sets, **10 minutes** | B5 | J4, J7, B8 |
| `banned_long` / `banned_long6` | timeout sets, **24 hours** (repeat offenders) | B5 (see L8) | J4 escalator, J7 manual bans, B8 |
| `allowlist4` / `allowlist6` | interval sets, `auto-merge` | B5 include → `/etc/nftables.d/dns-allow.nft` | B6, P2a |
| `rrl4` / `rrl6` | dynamic timeout sets, egress RRL state | B5 | — |
| `dns_dropped` / `dns_banned` | named counters | B5 | read by J6, alerted on by I6 |

Canonical thresholds: AdGuardHome `dns.ratelimit: 100` (UDP only) · nftables per-source flood
threshold **400/s** · global backstop 5,000 pps · egress RRL 25/s per destination · absolute egress
cap 4 mbytes/s. The invariant `nft >= 4 × AGH ratelimit` is checked mechanically in B9-5.

### File and directory layout

| Path | Owner / mode | Contents |
|---|---|---|
| `/etc/unbound/unbound.conf.d/10-public-resolver.conf` | root 0644 | **the** Phase C resolver config. This filename is canonical; `dns-node.conf` is stale |
| `/etc/unbound/unbound.conf.d/99-stats.conf` | root 0644 | cumulative statistics + the control socket Phase I scrapes |
| `/etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf` | packaged | the ONLY place `auto-trust-anchor-file` may be declared |
| `/var/lib/unbound/root.key` | `unbound:unbound` 0644 | DNSSEC trust anchor; backed up; RFC 5011 tracked in place |
| `/etc/systemd/system/unbound.service.d/nofile.conf` | root 0644 | `LimitNOFILE=65535` only (C2) |
| `/etc/systemd/system/unbound.service.d/hardening.conf` | root 0644 | **the** Unbound unit drop-in: C4's sandboxing, the canonical restart policy, A6's memory ceilings, N4's start limits. One file. There is no `ha.conf`, no `limits.conf`, no `dns-node.conf` |
| `/etc/systemd/system/adguardhome.service` | root 0644 | full unit (Phase E owns it); ceilings are in the A6 drop-in, not here |
| `/etc/systemd/system/nginx.service.d/hardening.conf` | root 0644 | nginx hardening + the same canonical restart tuple |
| `/etc/sysctl.d/99-dns.conf` | root 0644 | **Phase A's**: fds, socket buffers, backlogs, port range, `vm.swappiness`, **all** conntrack keys |
| `/etc/sysctl.d/99-nftables-edge.conf` | root 0644 | **Phase B's**: SYN cookies, `tcp_synack_retries`, redirects, source routing. Disjoint key set from the above |
| `/etc/modprobe.d/nf_conntrack.conf` | root 0644 | `hashsize=65536` (module parameter, Phase B) |
| `/etc/modules-load.d/conntrack.conf` | root 0644 | Phase A5 — without it the `net.netfilter.*` sysctls are silently skipped at boot |
| `/etc/nftables.conf` | root 0600 | begins `flush ruleset`; boot-time only, never `systemctl restart` |
| `/etc/nftables.d/dns-allow.nft` | root 0644 | allowlist sets, applied as one atomic transaction |
| `/opt/adguardhome/releases/<ver>/` | `adguardhome` | versioned binaries |
| `/opt/adguardhome/current` | symlink | **the** path every phase uses to reach the binary; Phase M's rollback lever |
| `/opt/adguardhome/conf/AdGuardHome.yaml` | `adguardhome:adguardhome` **0600** | holds the bcrypt hash; AGH rewrites it at startup |
| `/opt/adguardhome/conf/ssl/{fullchain,privkey}.pem` | `adguardhome:adguardhome` 0640, dir 0700 **adguardhome-owned** | the deploy-hook copy; never point AGH at `/etc/letsencrypt/live` |
| `/opt/adguardhome/work/` | `adguardhome` 0750 | the live work dir (`sessions.db`, `filters`); excluded from backup |
| `/opt/adguardhome/validate/` | `adguardhome` 0750 | **scratch** work dir for `--check-config` only. Never validate against `work/` |
| `/var/log/adguardhome/querylog/` | `adguardhome` 0750 | `querylog.dir_path`; empty while `file_enabled: false`; **tmpfs under Q3** |
| `/var/lib/adguardhome/stats/` | `adguardhome` 0750 | `statistics.dir_path`; `stats.db` exists in every posture; **tmpfs under Q3** |
| `/etc/nginx/conf.d/doh.conf` | root 0644 | the `:443` DoH server, the reject-handshake default, and **the one `:80` block** |
| `/etc/nginx/snippets/agh-client-identity.conf` | root 0644 | XFF overwrite + header stripping; every proxied location must include it |
| `/etc/letsencrypt/{live,archive,renewal}` | root 0600 (archive) | ECDSA P-256 lineage; backed up **whole** — `live/` alone restores dangling symlinks |
| `/etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh` | root 0700 | copies to AGH, reloads nginx, guards on `RENEWED_LINEAGE` |
| `/var/www/acme` | root 0755 | **the one webroot**: ACME challenge (D3) + `/.well-known/security.txt` (Q5c) |
| `/etc/prometheus/{prometheus.yml,rules/*.yml}` | root 0644 | scrape config and alert rules; **in the restic include list** |
| `/etc/prometheus/agh-credentials` | root **0600** | plaintext AGH admin password for the scraper |
| `/etc/alertmanager/{alertmanager.yml,ntfy.env}` | root 0644 / **0600** | the ntfy topic IS the credential; **in the restic include list** |
| `/etc/blackbox_exporter/blackbox.yml` | root 0644 | probe modules; an unknown key is fatal at startup; **in the restic include list** |
| `/var/lib/node_exporter/textfile/*.prom` | 0644 | `unbound.prom`, `adguard.prom`, `dnsprobe.prom`, `nft-abuse.prom` |
| `/var/lib/prometheus` | `prometheus` | TSDB, 90d / 6 GB |
| `/var/lib/dns-abuse/offences` | root **0600** | ban history; trimmed to 24 h; **deliberately never backed up** |
| `/var/lib/dns-health/nrestarts` | root | churn-detector state |
| `/opt/dns-config-backup` | root | **local config staging**: `.gitignore` (I3), `RETENTION.md` + git history (Q5a), the redacted token map (P4c). **Survives Phase K; Phase K backs it up off-host, encrypted** |
| `/etc/restic/{repo.pass,dns.env}` | root **0600**, dir 0700 | repo password (also in the password manager) and object-store keys |
| `/etc/restic/{include.txt,exclude.txt}` | root 0644 | explicit allowlist — never turn this into `cp -r` |
| `/root/.dns-netrc` | root 0600 | credentials for the loopback health checks |
| `/etc/cron.d/dns-health` | root 0644 | **created by Phase I**; every other phase APPENDS. Filename carries no dot |
| `/usr/local/sbin/notify.sh` | root **0750** | **the** notification entry point. `notify.sh <severity> <title> [message]` |
| `/usr/local/sbin/nft-apply` | root 0700 | **the** reload wrapper, wired to `ExecReload`; preserves remaining ban timeouts |
| `/usr/local/sbin/` (rest) | root 0700–0755 | `dns-smoke.sh`, `dns-health`, `dns-diskguard.sh`, `dns-allow-reload`, `nft-ban-escalate`, `nft-abuse-textfile`, `unbound-anchor-guard.sh`, `rps-tune.sh`, `upgrade-adguardhome.sh`, `upgrade-unbound.sh`, `restic-restore-drill.sh`, `check-restart-churn.sh`, `alertmanager-ntfy`, and the three textfile collectors |
| `/etc/keepalived/scripts/` | **root:root 0755** | Tier 3 only. `enable_script_security` refuses anything under `/usr/local/sbin` (mode 2775 root:staff) |
| `/etc/wireguard/` | root 0700 | Phase P6 keys; generated on the node, never templated from the repo |
| `/srv/dns-infra` | on the **control host**, not the resolver | Ansible source of truth; `group_vars/dns/vault.yml` whole-file encrypted |

Deleted by this plan and expected absent: `/etc/smartdns`, `/var/lib/smartdns`, `/var/log/smartdns`,
`/opt/dns-warmer`, `/etc/dns-warmer`, `/var/log/dns-warmer`, the `smartdns` and `dnswarmer` users,
`dns-warmer.service`, `/etc/cron.daily/dns-backup`, `/usr/local/sbin/nft-bans`,
`/etc/sysctl.d/99-swap.conf`, and any `/etc/systemd/resolved.conf.d/`.

---

## Key Risks and Mitigations

| Risk | Mitigation | Where it is implemented | How it is verified |
|---|---|---|---|
| Query log fills the 40 GB disk in ~1 day at 1,000 QPS; AGH's own config write, the backup and the journal all fail together | `file_enabled: false` (memory ring only) as the shipped default; `interval: 6h`, the shortest legal value; disk-pressure guard and `predict_linear` alert | E2, G2, G4, I6 `DiskWillFill`/`QueryLogGrowing`, Q1 | G2 growth check, LT-12, `dns_dir_bytes` |
| conntrack table (65,536 default on 4 GB) fills at ~2,200 accepted QPS and the kernel drops *new* flows — including your SSH session | UDP/53, 443 and 853 NOTRACK'd in `table inet raw`, with explicit accepts because `ct state established,related` no longer covers them; `nf_conntrack_max` raised (Phase A) and `hashsize` pinned (Phase B) | B5 `table inet raw`, B2, A5 | B9-2, B9-4, **LT-8**, I6 `ConntrackFilling` |
| Reflection/amplification — a recursive resolver will fetch an attacker's own 4 KB TXT record; measured factor up to ~63x | Egress RRL per destination + absolute byte cap in `chain output` (these protect the victim even when the source is forged); per-source meter with a global backstop in `chain dns_guard`; `refuse_any` / `deny-any` | B5 `chain output`, B5 `chain dns_guard`, E2, C2 | B9-6, B9-7, H10 |
| **Accepted residual:** spoofing cannot be stopped from here. You are the reflector, not the origin; BCP38 is another network's job | Cap the damage, do not hunt the spoofer; provider scrubbing and Phase N are the escalation | B3, J8 step 6 | stated in the runbook |
| The per-source dynset **fails open** when full — a spoofed flood mints a fresh key per packet and `NFT_BREAK` aborts the rule | The global backstop rule placed *after* the per-source rules is the real floor, and it deliberately does not ban | B4, B5 `chain dns_guard` | B9-5 counters, `set is full` check |
| Ban-set steering: a little over 400 spoofed pps put any address the attacker chooses into `banned_ips`, including your own users | 10-minute first offence (not an hour), escalation capped at 24 h with no permanent tier, `allowlist4`/`allowlist6` for known-good high-volume clients, rehearsed drop-only fallback | B5, J4, J9, J8 step 3 | J10-5/6, I6 `BanSetLarge` |
| **Accepted residual:** the ban mechanism is inherently attacker-steerable. The alternative is removing the `add @banned_ips` clause and losing repeat-offender suppression | recorded as a decision, either way | J9, Phase O decision log | decision log entry |
| Abuse tooling bans a masked, wrong network — `anonymize_client_ip` masks to /16 and /48 **at ingestion**, before the query log is written | Detection is kernel-side nftables counters and sets; nothing in the abuse path reads the query log, in any Phase Q posture | J1, J3, J6 | J10-10, empirical `"IP":"127.0.0.0"` |
| A cross-table `add @set` is illegal, so a split ruleset silently never bans | **One policy table, one input-path chain.** The meters, the flood rules and the ban sets are all in `table inet filter`; `dns_guard` is a jump target, not a second base chain | B4, B5, J2 constraint 1 | **B9-1** (two tables, one input base chain), J10-4 |
| Public DoH silently never works: AGH's HTTPS listener inherits its host from `http.address`, so `port_https: 443` binds loopback while the firewall shows 443 open | nginx terminates public TLS and proxies only `= /dns-query` to `127.0.0.1:8053`; AGH web listeners stay on loopback | E4, decision 5 | E6-2/3, **[off-box]** H2, `blackbox-doh` probe + `DoHDown` |
| Admin UI published alongside DoH — `/dns-query` and `/control/*` share one mux | `location / { return 404; }`; `http.address` on loopback; SSH tunnel with a `permitopen`-restricted key | E4, A4 Step 3 | E6-5, H2, H12 isolation block |
| Two `:80` server blocks, or two webroots — the ACME challenge and the well-known files end up in different directories with only one reachable | **One `listen 80 default_server` block, one webroot `/var/www/acme`**, written by Phase E4. `default_server` makes a duplicate a hard `nginx -t` failure. Phase Q adds a `location`, not a server | E4, D3, Q5c | E4's `grep -rn 'listen .*80'`, Q5c content-type check |
| Retention settings silently voided, or a hard boot failure, from the `querylog:`/`statistics:` schema migration | Explicit `schema_version` matching the binary; post-v0.107.24 top-level layout; diff the file **after** first start | E2, Q1, decision 7 | E6-8, I11-4, K6 gate 4 |
| A logging-policy choice pages the operator as though it were an outage | Phase I owns the degradation: `agh_up` stays 1, `agh_metrics_unavailable_by_policy` is the distinct signal, window metrics are **absent rather than zero**, and `AdGuardHomeDown` cannot fire on that path | I0, I3, I6, Q1 | **I11-4b** |
| AdGuardHome cannot bind :53/:853 and never starts — `NoNewPrivileges=yes` nullifies file capabilities across `execve` | `AmbientCapabilities` + matching `CapabilityBoundingSet`; stale file capability actively cleared; **no phase, including Phase M, ever runs `setcap` to grant** | E5a/E5b, M3 trap 1, O3, decision 8 | E6-1 `getpcaps`, `getcap` empty, H12 |
| Trust anchor corrupted, stale across a KSK roll, or restored from an old snapshot → **every signed zone SERVFAILs**, presenting as a total outage with no cause | Detect-and-heal guard keyed on the symptom (no AD flag), never a refresh timer racing unbound's own RFC 5011 writer; `root.key` in the backup set | C3, K3 | C3 fault injection, `blackbox-dnssec`/`-fail`, H5 |
| The anchor is intact today and dead on a published date: `test -s root.key` and an AD flag on `. DNSKEY` both pass for the **entire** RFC 5011 hold-down while the incoming KSK sits in ADDPEND, so a host mid-rollover scores green and is thirty days from total SERVFAIL | Read the key **states**, not the file size; alert when no key is at state 2 or the file has not been rewritten in 90 days; keep `dns-root-data` current so the heal path has a valid ICANN bundle; put ICANN's announced rollover dates in the same calendar as the K6/K7 drills | C3, M1, O6 | **L3 anchor-state block**, monthly line on `/etc/cron.d/dns-health` |
| A skewed clock SERVFAILs every signed zone, and after C5.8 the host resolves its NTP pool through its own validator — so the clock cannot be fixed by the path that needs it fixed, and the symptom is indistinguishable from a dead trust anchor | IP-literal chrony sources plus `makestep`, so the deadlock cannot form; `ClockUnsynchronised`/`ClockOffsetHigh` as **distinct** alerts next to `DNSSECValidationBroken`; chrony in dns-smoke.sh's `UNITS`; a console `date -s` recovery row in the runbook | A2, I6, H12, 08 runbook | L1 `chronyc sources -v`, the L7 deliberate-skew rehearsal |
| Any of roughly ninety public CAs may issue for the one name that is the entire authentication of every DoT, DoQ and DoH client — and no client will honour a revocation, because Let's Encrypt shut its OCSP responders down | **CAA** pinning issuance to the CA in use, with `issuewild ";"` unless Phase P needs the wildcard and `iodef` pointing at the Q5c mailbox. CT detects mis-issuance after the fact; CAA is the control that prevents it | D2, D8 | L4 CAA block, `dig +short CAA example.com` |
| The domain registration and the third-party zone that serves `dns.example.com` are the only dependency in this design with no owner and no monitor. Lapse fails every encrypted transport **closed**, and after redemption anyone may re-register the name, obtain a valid certificate and receive the queries of every device still trusting it | RDAP expiry check weekly at 60 and 30 days; registrar auto-renew, lock and MFA with the card's own expiry recorded; CAA as the re-registration backstop; a probe that resolves the name against a **public** resolver, since every I4 probe targets 127.0.0.1 and cannot see a zone failure | D0, I4, I6, O6 | L4 domain block, `DomainExpiringSoon`/`Critical`, N7 zone-down row |
| unattended-upgrades is scoped to the apt security pockets and structurally cannot reach the six out-of-apt binaries — AdGuardHome above all, the one process that parses hostile DNS, HTTP/2 and QUIC from the whole internet — so they are patched only when a human happens to look at GitHub | Weekly release watch on `/etc/cron.d/dns-health` comparing each pinned version against upstream and calling `notify.sh`; versions and feeds live in the Phase O inventory with a named reader; the check never auto-upgrades, because M3's operator-invoked wrapper is the only upgrade path | I4c, M1, O6 | L9 release-watch lines, one forced firing |
| The availability escalation path's first two steps — reboot, roll back — destroy the process table, the tmpfs query log and the upgrade artifacts, so the first response to a suspected intrusion is also the end of the investigation | A separate compromise branch that contains before it preserves, snapshots the volume before anything touches the disk, always rebuilds rather than cleans, and restores from a snapshot dated **before** the earliest suspicious timestamp — K3 backs up `/etc/systemd/system`, `/usr/local/sbin` and `/etc/cron.d`, so a later snapshot reinstalls the intrusion | 08 runbook, K5e, K3, Q6 | L9 procedure gate with a named owner |
| Certificate renews on disk but the running process keeps the old one — every DoT/DoQ/DoH client fails hard at expiry, with no other symptom | Deploy hook copies + reloads, reaching the binary through the `current` symlink; served-vs-on-disk fingerprint comparison on **both** terminators | D4, H12 cert block | H12, I6 `CertExpiringSoon`/`Critical` |
| Monitoring dies with the host: kernel panic, OOM, provider termination, null-route — a hard-down resolver produces zero pages | Always-firing Watchdog routed to an **external** dead man's switch, plus a second, independent external port monitor | I6, I8, I9 | **I11-14** (the only proof that counts) |
| Alerts and event notifications drift into per-phase `curl` calls nobody maintains | One entry point, `notify.sh`, defined by Phase I and called by D, G, H, K, L, M, N and Q; one cron file, `/etc/cron.d/dns-health`, created by Phase I and appended to by the rest | I8b, I10 | I11-15/16, L7 cron inventory |
| Encrypted transports are entirely unthrottled at the application layer — dnsproxy gates its limiter on `d.Proto == ProtoUDP` | ECDSA P-256 makes handshakes ~20x cheaper, which is the practical brake; nftables connection-rate ceilings; per-device limiting only under Phase P | D1, decision 10, P7c | LT-5/6/7, `openssl speed` |
| **Accepted residual:** in the public build, TCP/53, DoT, DoQ and DoH have no per-client application limit. `ratelimit: 100` covers plain UDP and nothing else | documented, not fixed; Phase P closes it per-identity | A1 throughput table, B3, B4, P7c | stated in the runbook |
| **Accepted residual:** no DNS cookies at the public edge — AdGuardHome implements none (issue #7183). Unbound's `answer-cookie` is unreachable behind loopback | Steer users to the connection-oriented transports | C2, H7 | H7 cookie probe, recorded |
| **Accepted residual:** the client-facing leg honours a 4096-byte EDNS buffer with no knob to cap it; responses fragment. Phase C's `max-udp-size: 1232` governs the recursion leg only | Steer to DoT/DoQ/DoH; do not attempt to clamp EDNS in nftables | B3, H7 | H7 `MSG SIZE` measurement |
| DNS rebinding: a public name resolving to `127.0.0.1` or `192.168.1.1`, aimed at a victim's own LAN | 18 `private-address` prefixes; `private-domain: plex.direct` for the one known legitimate publisher | C2 | H7 config assertion (cannot fail open) + controlled live probe |
| Answers rewritten by our own software — the reason SmartDNS was removed (AAAA suppression, RRset reordering and truncation by latency probe) | Unbound never reorders or filters an RRset; `rrset-roundrobin` is the only rotation and it preserves the set | C intro, decision 2 | C5.2 `modules: validator iterator`, C5.1 wire capture |
| A single leak or an oversized cache OOMs the box; the kernel picks the resolver by RSS and `Restart=always` turns it into a loop | **One owner for memory and swap: Phase A6.** `MemoryHigh` throttles before `MemoryMax` kills; negative `OOMScoreAdjust` on both daemons; a swapfile as shock absorber; `restic-backup` at +500 as the designated victim | A6, N5b, K4 | A6 `memory.events`, LT-13, I6 `OOMKillOccurred` |
| Two drop-ins, two swappiness values, two ceilings — the later file wins silently and you run a number you can read in the other one | One drop-in per unit (`hardening.conf`), one `vm.swappiness` (A5's `99-dns.conf`), disjoint sysctl key sets, and an explicit "no ceilings here" statement in Phase E and Phase N | A5, A6, E5b, N5a | L1 `grep -rl Memory` and `comm -12` key check |
| A crash-looping daemon is abandoned forever by systemd's stock 5-in-10s limit; or, over-corrected, never reaches `failed` and never fires `OnFailure=` | One canonical tuple everywhere: `Restart=always`, `RestartSec=5`, `StartLimitIntervalSec=300`, `StartLimitBurst=10` — bounded, not disabled — plus a churn detector, because ten restarts every five minutes never trips the limit | C4, E5b, N4a, N4c | N4 kill drills, I6 `ServiceFlapping` |
| `systemctl restart unbound` silently bounces the public listener, and an Unbound that fails at boot keeps AdGuardHome from starting at all | `Wants=` + `After=`, never `Requires=` and never `BindsTo=`, between any two daemons in this stack | C2 cross-phase note, C4, E5b, N4b | N4 propagation test |
| Local load tests or health probes ban `127.0.0.1` and take the whole resolver down for the ban duration | `iif lo accept` as the **first** rule of `dns_guard`, and the jump placed after `input`'s own loopback accept | B5, J2 constraint 2 | **J10-3** regression test, B9-5 loopback check |
| A ruleset reload releases every live abuser mid-incident — `/etc/nftables.conf` begins `flush ruleset`, and so does the stock `ExecReload` | **One wrapper, `nft-apply`**, restoring **remaining** timeouts; `ExecReload` redirected at it; chain-scoped certbot hooks that never touch the sets; no second save/restore tool anywhere | B1, B7, B8, J5 | B7 and B8 verification, J10-7 and J10-7b |
| `/opt/dns-config-backup` deleted as "the v1 backup", taking the staging directory Phases I, J and Q write to with it | The v1 *mechanism* is retired, the *directory* survives and becomes an input to the off-host restic set | K1, K3 | `restic ls latest \| grep -c dns-config-backup` |
| The monitoring configuration is never backed up, so it is rebuilt last and worst after an outage | `/etc/prometheus`, `/etc/alertmanager` and `/etc/blackbox_exporter` are explicit entries in the restic include list | K3 | K3 verification grep |
| Single failure domain: until Phase N, "the resolver" and "the host" are the same thing, and encrypted clients have **no** client-side failover (Android Private DNS accepts one hostname and fails closed) | Tier 3 floating IP + VRRP, or Tier 1 with a measured, rehearsed RTO | N1, N2, N3, K7 | K7 wall clock, N3 FAULT-state drill |
| **Accepted residual (Tier 0/1):** a reboot is an outage of tens of seconds and host loss is an RTO-length outage | chosen deliberately over the cost of a second node | N2, M6 | measured RTO in the runbook |
| The hosting provider now sees the **full** resolution pattern in cleartext — under v1's forwarding they saw four HTTPS destinations | Not mitigable. Disclosed as a genuine regression on that one axis | Q2 | privacy notice text |
| **Accepted residual:** cleartext TLS SNI tells the user's ISP that they use this resolver, and Certificate Transparency publishes the hostname permanently | Disclosed; DNS-01 wildcard is the only CT mitigation and must be chosen before first issuance | Q4, D7 | `crt.sh` query, Q4 verification |
| The published ban duration and the implemented one diverge, making the privacy notice false | One schedule — 10 minutes, escalating to 24 hours — stated in B5/J4 and quoted verbatim in Q5a and Q5b | B5, J3 property 3, J4, Q5a, Q5b | L12 item 15 |
| nginx recreates a client-IP log that is *worse* than a query log: the DoH GET form puts the encoded DNS message in the query string, and `$request` logs it next to the IP | `access_log off;` on **both** client-facing server blocks, verified behaviourally rather than by grep | E4, Q4 | Q4 byte-size test |
| Secrets leak into source control — git history is append-only in practice | Vault-encrypted whole file, explicit backup allowlist, pre-commit tripwire mirrored as CI, `.gitignore` in the staging directory | K5, I3 | `git log --all -p` grep, K5 verification |
| Provider AUP suspension for running an open resolver — more likely to end the service than any regulator | Read the terms before launch; PTR, `security.txt` and a monitored abuse mailbox so complaints route to you rather than to a null-route | Q5c, Q6 | Q6 decision register, ticket reference |
| Recursion is slower on a cold cache and depends on root/TLD reachability *from this VPS specifically* | `prefetch`/`prefetch-key` keep the demand-shaped hot set warm; `aggressive-nsec` answers a whole class of misses with no query; generous cache sizing | C2, C6 | C5.5, LT-3/LT-4, I6 `RecursionStalled` |
| **Accepted residual:** `serve-expired-client-timeout: 1800` makes clients wait up to 1.8 s per query during a real upstream incident | That is the RFC 8767 behaviour and the correct trade for a correctness-first resolver; `ede-serve-expired` makes it visible rather than mysterious | C2, C5.6 | measured in C5.6, expected shape in the runbook |

---

## Changelog from v1

| Area | v1 | v2 | Why |
|---|---|---|---|
| Base OS | Ubuntu 22.04 LTS | **Ubuntu 24.04 LTS** | 22.04 ships unbound 1.13.1: no `answer-cookie`, no EDE, `aggressive-nsec` off by default, `max-udp-size` 4096. 24.04 also ships certbot 2.x, which issues ECDSA by default. The Phase C config does not parse on 22.04. |
| Resolver | SmartDNS on `127.0.0.1:5335`, forwarding over DoH to four public operators and racing them | **Unbound 1.19.2 on the same `127.0.0.1:5335`**, full recursion from the root, no forwarders | SmartDNS has no DNSSEC directive of any kind, and racing N unvalidated forwarders makes the effective trust set their *union*. Its defaults also rewrite answers (`dualstack-ip-selection`, `speed-check-mode` RRset reordering/filtering), which makes signature validation impossible in principle. The port is unchanged so every firewall rule, health check and `dig -p 5335` test carries over verbatim. |
| DNSSEC | validated nowhere in the chain; `dnssec-failed.org` SERVFAILed only because the upstreams happened to validate | validated in **exactly one place, Unbound**; `fallback_dns` empty; `enable_dnssec` documented as DO-bit-only cache normalisation | The verdict is now computed, not borrowed. The old exposure was not "bogus names resolve" — it was that you could not check, could not disagree, and could not detect a compromised or compelled upstream. |
| `/etc/resolv.conf` | written once, ambiguously, with a public resolver left in place | **two deliberate writes**: A2's labelled bootstrap value, then C5.8's flip to `nameserver 127.0.0.1` and nothing else, verified by Phase L | glibc walks the nameserver list on timeout without saying so, so a fallback entry silently routes the host's own lookups around the validating path at exactly the moment it breaks. systemd-resolved is removed entirely rather than stub-disabled, so no phase writes `DNSStubListener`. |
| Phase F cache warmer | Python daemon, `dnswarmer` user, 12 fixed domains, `ThreadPoolExecutor(max_workers=20)` | **retired; the letter F is not reused** | Unbound's `prefetch`/`prefetch-key` does it in-process on real demand. The warmer also warmed the *wrong* cache (AGH, not the resolver), silently stopped working past 20 domains (`while True:` tasks holding every worker slot), skewed the Phase I statistics, and was a fingerprint rather than cover traffic. Note what did **not** change with it: `ratelimit_whitelist` stays exactly as Phase E ships it. |
| DoH topology | AdGuardHome `port_https: 443` with `http.address` on loopback | **nginx terminates public :443 and proxies only `= /dns-query` to `127.0.0.1:8053`** | AGH's HTTPS listener inherits its host from `http.address` (`web.go`), so v1 bound **127.0.0.1:443** and public DoH silently never worked. The naive fix (`http.address: 0.0.0.0:3000`) publishes the login page, because `/dns-query` and `/control/*` share one mux. |
| Port 80 | ad hoc: a firewall dance around each renewal, and a second server block for the well-known files | **one `listen 80 default_server` block, one webroot `/var/www/acme`**, written by Phase E and shared by the ACME challenge and Phase Q's `/.well-known/` | Two blocks or two roots produce a challenge that 404s for reasons nobody can see. `default_server` turns a duplicate into a hard `nginx -t` failure instead of a silently shadowed block. |
| `AdGuardHome.yaml` | no `schema_version`; `querylog_*` keys under `dns:`; `querylog_interval: 24h` as a string | **explicit `schema_version`; `querylog:` and `statistics:` as top-level sections** | The migrator reads a missing `schema_version` as 0 and runs the whole chain; `v12.go` expects `querylog_interval` as an integer number of days, so v1's file is a **boot failure**, not a retention drift. Modernising the layout *without* pinning the schema is the separate 90-day clobber (`v15.go` writes `interval: "2160h"` unconditionally). |
| Logging posture | implied, never stated; retention drifted to whatever the migrator wrote | **one shipped default** (querylog on, 6 h, anonymised, statistics **on**) with Phase Q offering explicit **opt-in** deviations, each stating its monitoring cost inline | "Zero-log" was presented as both the default and an aspiration, so no host could be scored against it. Phase I now owns graceful degradation: statistics off is a policy signal, never `agh_up=0` and never an `AdGuardHomeDown` page. |
| Privileged ports | `setcap cap_net_bind_service` **and** `NoNewPrivileges=yes` | **`AmbientCapabilities=CAP_NET_BIND_SERVICE` + matching `CapabilityBoundingSet`**; the file capability is actively cleared; no phase ever grants with `setcap` | Mutually exclusive: `no_new_privs` intersects the new permitted set with the old one at `execve`. v1's AdGuardHome could not bind :53 and never started. A leftover fcap additionally *clears* the ambient set, so the fix fails silently if you skip `setcap -r`. Phase M's upgrade path is explicitly barred from reintroducing it. |
| conntrack | every DNS packet tracked; `nf_conntrack_max` left at the 65,536 default | **UDP/53, 443 and 853 NOTRACK'd in a `raw` table, with explicit accepts**; conntrack sysctls owned solely by Phase A, `hashsize` solely by Phase B | Twenty-two well-behaved clients at their full 100 q/s allowance exceed the table. When it fills the kernel refuses all new flows — SSH, ACME and every TLS handshake die together. Note the consequence: `ct state established,related accept` no longer covers DNS, so those accepts are load-bearing, not defence in depth. |
| nftables structure | four tables — `inet filter`, `inet raw`, `inet dns_ratelimit`, `inet dns_rrl` — with two chains competing on the input hook | **two tables: `inet raw` (NOTRACK only) and `inet filter` (everything else), with one input base chain and `dns_guard` as a jump target** | A cross-table `add @set` is illegal in the kernel, so the flood rules could never have banned into `banned_ips` from a separate table. Collapsing to one table also removes the hook-priority arithmetic that made rule order a puzzle — and that let the limiter run *before* `iif lo accept`, which is how an on-box load test banned 127.0.0.1. |
| Abuse detection | cron tailing `querylog.json`, counting `.IP`, banning the top talker | **kernel-side nftables meters, counters and ban sets; nothing reads the query log**; 10-minute first offence escalating to 24 hours | `anonymize_client_ip: true` masks **at ingestion**, to /16 and /48 (not /24) — verified in source and empirically. The cron banned a masked network address as a /32 while the real abuser kept querying, and its `[ -f "$LOG" ] || exit 0` guard made it exit 0 forever once the log moved or was disabled. The kernel-side design is correct in every Phase Q posture. |
| Firewall reloads | certbot open/close dance reloading the whole ruleset twice a month; a second ban save/restore tool | **dedicated `certbot` chain; `/usr/local/sbin/nft-apply` as the single wrapper, wired to `ExecReload`, restoring REMAINING timeouts** | `/etc/nftables.conf` starts with `flush ruleset`, and so does the stock `ExecReload`. v1 unbanned every live abuser on each renewal. Two wrappers means two implementations of the timeout arithmetic, and a restore that re-arms every ban to full duration also corrupts the offence count that drives escalation. |
| Rate-limit thresholds | nft per-source 100/s alongside AGH `ratelimit: 100` | **AGH `ratelimit: 100` (UDP only) and a single kernel meter at 400/s**, with a global backstop after the per-source rules and `ratelimit_subnet_len` 32/64 | Stacked equal limits meant the kernel pre-empted userspace at random. The per-source dynset also *fails open* when full (`NFT_BREAK` aborts the rule, not the chain) — which is why the backstop after it is the real floor. `update`, not `add`, or a sustained abuser's meter resets mid-attack. The 24/56 subnet defaults black-hole an entire /24 for one CGNAT abuser. |
| Memory and swap | no ceilings anywhere; no swap; the OOM killer picked the resolver by RSS | **one owner, Phase A6**: swapfile, `vm.swappiness=10`, and the `MemoryHigh`/`MemoryMax`/`OOMScoreAdjust` for all four units, in one drop-in per unit | Ceilings scattered across three phases produce two numbers, one of which is silently wrong, and two `vm.swappiness` files where the later one wins without a warning. Phase E and Phase N now ship no ceilings at all and cross-reference A6; Phase N keeps only the restart policy, which must agree with Phase C4. |
| SSH hardening | `PasswordAuthentication no` appended to the bottom of `sshd_config` | **`/etc/ssh/sshd_config.d/00-hardening.conf`**, plus an admin account created *first* and a `permitopen`-restricted tunnel key | `Include` sits at the top of `sshd_config` and sshd is first-obtained-value-wins, so the cloud-init drop-in's `PasswordAuthentication yes` beat v1's appended line. Password auth was enabled on a host advertised to the whole internet. |
| sysctl | 7 lines, 4 of them no-ops (`udp_mem` in pages, `limits.d` for systemd services) | measured set with a **stated owner per file**: `99-dns.conf` (Phase A) and `99-nftables-edge.conf` (Phase B), disjoint key sets; plus **RPS** across both vCPUs | `pam_limits` never applied to these daemons; `LimitNOFILE=` in the unit is the real setting. `rmem_max` is load-bearing for exactly one thing — quic-go's DoQ/HTTP-3 buffer. `sysctl.d` applies in lexical order and the later file wins silently, so a duplicated key is a divergence between the file you read and the kernel you run. |
| Load test | two domains, `-Q 500`, 30 s, mean latency, Do53 only | **13 identified PASS thresholds (LT-0…LT-13)** across cold/warm/hostile/knee and all four transports, with a 4-hour soak | Two names are 100% cache hits, `-Q 500` caps at the target so it can never find the knee, and 30 s is shorter than TLS ticket rotation and GC steady state. It benchmarked a Go map lookup. |
| Post-change gate | "restart and hope" | **`dns-smoke.sh`** — one script, non-zero exit, wired into the upgrade wrappers, the runbook and cron; validating against the `current` symlink and a scratch work directory | An upgrade is finished when `SMOKE: PASS` prints, not when apt returns. Validating as root against the live `work/` tree leaves root-owned artifacts that break the next real start. |
| Observability | two cron lines piping `dig` failures into `logger` on the box being monitored | **Prometheus + node_exporter + blackbox + Alertmanager + an off-box dead man's switch**, plus `notify.sh` and `/etc/cron.d/dns-health` as the single notification and scheduling entry points | A `logger` call nobody reads is not an alert, and a monitoring stack that dies with the host produces zero pages for the failure that matters most. AGH has no `/metrics`; its `/control/stats` is a rolling gauge with a one-hour floor, so Unbound is the fast signal. One notifier and one cron file means one credential, one audit tag, and no phase silently deleting another's schedule. |
| Backup | on-box git repo, five files, no certificates, no units, no monitoring config | **restic to encrypted off-host object storage**, plus config regenerated from Ansible; two-tier restore drill; `/opt/dns-config-backup` retained as staging *input* | A backup on the volume it protects is not a backup, and v1's file list could not rebuild the node anyway. `/etc/letsencrypt` must be taken whole or `live/` restores dangling symlinks. `/etc/prometheus`, `/etc/alertmanager` and `/etc/blackbox_exporter` were previously unbacked-up entirely. |
| Filenames | `dns-node.conf`, `ha.conf`, `reload-adguard.sh`, a pinned `AdGuardHome` binary path | **one canonical name each**: `10-public-resolver.conf`, `unbound.service.d/hardening.conf`, `50-dns-stack.sh`, `/opt/adguardhome/current/AdGuardHome` | A restore drill that gates on a name no phase writes fails on a correctly built host and trains the operator to ignore the drill. A pinned binary path leaves the deploy hook version-probing a build the service no longer runs. |
| Phases | A–L only | **+M patching, +N high availability, +O provisioning/IaC, +P private access layer, +Q privacy/retention/legal**; F retired | AdGuardHome runs with `--no-check-update` and is never patched unless a human does it; a single-node resolver with no rebuild path is a demo; and the two headline properties of this service — who may use it, and what it remembers — were undocumented decisions in v1. |

---

[Plan index](../dns-server-plan.md) · [Previous: Privacy, Retention and Compliance (optional)](./10-privacy-and-compliance.md) · [Next: Client Configuration](./12-client-setup.md)
