# Public Recursive, DNSSEC-Validating DNS Resolver — Production Execution Plan (v2)

Target platform: a single Ubuntu 24.04 LTS VPS, 2 vCPU / 4 GB / 40 GB SSD, static IPv4
(optional IPv6). Every command in this document is written to be executed verbatim, in
order, by a sysadmin with root on a freshly provisioned host. What that sysadmin is
assumed to already know, and the domain, records and accounts that must exist before the
first command runs, are Phase 0.

This is a rewrite, not an edit, of the v1 plan. The resolver layer changed vendor, one
whole phase was deleted, and the base OS moved a release. Read the Architecture Decisions
table before executing anything — it is the part of this document that explains why v1's
instructions must not be reused.

---

## What this builds

A public resolver that answers Do53, DoT, DoQ and DoH, filters with AdGuardHome, and
resolves names itself — from the root zone down — with DNSSEC validation. There is no
upstream provider. Nothing in the answer path rewrites, reorders, or suppresses records.

```
                                   clients
                                      |
       Do53 udp/53 + tcp/53 ..........|.......... DoH https/443
       DoT tcp/853, DoQ udp/853       |
                                      v
 ========================= VPS (Ubuntu 24.04 LTS) ==========================

   nftables: inet filter (Phase B)  +  raw table NOTRACK on udp/53 (decision 9)
                                      |
          +---------------------------+-----------------------------+
          |                                                         |
     tcp/443 public                                        udp/53, tcp/53,
          |                                                tcp/853, udp/853
          v                                                          |
     nginx  --  TLS termination, ECDSA P-256 (Phase D)               |
       location = /dns-query   ---proxy_pass--->                     |
       everything else         ---> 404                              |
          |                                                          |
          |  127.0.0.1:8053  (AGH HTTPS listener, loopback only)     |
          +------------------------------+                           |
                                         v                           v
                    +--------------------------------------------------------+
                    |  AdGuardHome  (Phase E)                                |
                    |  filtering, blocklists, per-client rules, query log    |
                    |  admin UI 127.0.0.1:3000 -- SSH tunnel only (A4)       |
                    |  upstream_dns: 127.0.0.1:5335   fallback_dns: (empty)  |
                    +--------------------------------------------------------+
                                         |
                                         v
                    +--------------------------------------------------------+
                    |  Unbound  127.0.0.1:5335  (Phase C)                    |
                    |  recursive - DNSSEC VALIDATING - QNAME minimisation    |
                    |  RFC 8198 aggressive-nsec - prefetch / prefetch-key    |
                    +--------------------------------------------------------+
                                         |
                          full recursion, no forwarders
                                         v
                    root (.)  ->  TLD (com.)  ->  authoritative server
```

Two processes serve queries. One terminates TLS. Nothing else listens.

---

## Architecture Decisions

These are binding. Every phase in this document assumes all ten. Changing one changes
others — the Consequence column says which.

| # | Decision | Rationale | Consequence |
|---|---|---|---|
| 1 | **Ubuntu 24.04 LTS, not 22.04.** | 24.04 ships unbound 1.19.2; 22.04 ships 1.13.1, which has no `answer-cookie`, no EDE (RFC 8914), does not default `aggressive-nsec` on, and defaults `max-udp-size` to 4096. 24.04 also ships certbot 2.x, which can issue ECDSA. | Every version-specific claim in this plan is checked against 24.04 package versions. On 22.04 the Phase C config will fail to parse and the Phase D cert will be RSA. Do not substitute the OS. |
| 2 | **SmartDNS is removed entirely. Unbound replaces it**, listening on 127.0.0.1:5335. | SmartDNS cannot validate DNSSEC at all, and its defaults actively rewrite answers: AAAA suppression via `dualstack-ip-selection`, and RRset filtering/reordering driven by `speed-check-mode` probes. A public resolver that reorders A records by its own latency probes is not returning the zone's answer. | Port 5335 is deliberately unchanged, so the Phase B firewall rules, the health checks and every `dig -p 5335` test from v1 still apply verbatim. The resolver user is now `unbound`, created by the distro package — see A3. |
| 3 | **Phase F (the Python cache warmer) is retired.** No warmer daemon exists in this design. | Unbound's `prefetch` and `prefetch-key` refresh popular entries in-process, before expiry, on the real query stream. A separate warmer duplicated that work, generated self-inflicted query load, and — as written in v1 — silently warmed only the first 20 domains of its list. It is also a client fingerprint, not cover traffic. | The letter F is not reused. Where v1 referenced Phase F, the answer is now "Unbound prefetch, Phase C". No `dnswarmer` user, no `dns-warmer.service`, no memory or CPU budget for it. |
| 4 | **DNSSEC validation happens in exactly one place: Unbound.** | Validation must sit where the recursion happens. AdGuardHome's `enable_dnssec: true` only sets the DO bit on outgoing queries and surfaces the AD bit — it does not validate. Two validators would be redundant; zero is the v1 bug. | `fallback_dns` stays empty and `upstream_dns` contains only `127.0.0.1:5335`. Any config that lets a query reach the internet without traversing Unbound is a downgrade path and is prohibited. The trust anchor lifecycle (`/var/lib/unbound/root.key`) becomes a monitored asset — see Phase C and Phase I. |
| 5 | **DoH topology: nginx terminates TLS on public :443 and proxies only `/dns-query` to AdGuardHome's HTTPS listener on 127.0.0.1:8053.** | Verified in AGH source (`internal/home/web.go`): the HTTPS listener inherits its host from `http.address`, so `http.address: 127.0.0.1:3000` plus `port_https: 443` binds 443 on **loopback only** and public DoH silently never works. Worse, the admin UI shares the same HTTP mux as `/dns-query`, so publishing that listener publishes the login page. | The admin UI stays on 127.0.0.1:3000 and is reached over an SSH tunnel (A4). nginx must overwrite `X-Forwarded-For` and pin `Host`, or every AGH client control is bypassable — see Phase P. DoT (tcp/853) and DoQ (udp/853) are served directly by AGH's `dnsforward` on `dns.bind_hosts` and are unaffected by this. |
| 6 | **`anonymize_client_ip: true` masks the client IP on disk. Abuse detection must be kernel-side (nftables counters), never query-log-derived.** | Verified in AGH source and empirically on v0.107.78, which wrote `"IP":"127.0.0.0"` to the query log. Granularity is /16 for IPv4 and /48 for IPv6 — not /24. | Any script that greps `querylog.json` for a heavy hitter bans a masked network address, i.e. the wrong target, potentially a /16 of innocent clients. Phase J is built on nftables counters and sets. Phase Q owns the retention decision. |
| 7 | **`AdGuardHome.yaml` carries an explicit `schema_version` and uses the post-v0.107.24 layout: `querylog:` and `statistics:` are TOP-LEVEL sections, not keys under `dns:`.** | v1 placed them under `dns:`, where AGH ignores them and then rewrites the file with its own defaults. Retention silently becomes the default, not what you wrote. | Phase E writes the file in the new layout. Phase I's monitoring and Phase Q's retention posture both depend on those keys actually being read. Verify by reading the file back **after** the first AGH start, not before. |
| 8 | **`AmbientCapabilities=CAP_NET_BIND_SERVICE` + a matching `CapabilityBoundingSet`, not `setcap`.** | `NoNewPrivileges=yes` nullifies file capabilities across `execve`. v1 set both, so AdGuardHome could not bind :53 or :853 and never started. | The binary needs no `setcap` at all; `libcap2-bin` is not a required package. If you ever remove `NoNewPrivileges=yes`, do not "fix" it by re-adding `setcap` — the ambient-capability form is correct in both cases. |
| 9 | **UDP/53 is NOTRACK'd in an nftables `raw` table, and untracked DNS is then accepted explicitly.** | Conntrack tracks every DNS packet; `nf_conntrack_max` is 65536 on a 4 GB host, which is a hard ceiling around 2,200 accepted QPS with the default UDP timeout. When the table fills, the kernel drops new flows — including your SSH session. | `ct state established,related accept` no longer covers DNS, because untracked packets are in state `untracked`. Phase B must accept udp/53 unconditionally. The conntrack sysctls in A5 remain relevant for TCP/53, 443, 853 and SSH. |
| 10 | **Certificates are ECDSA (P-256). A wildcard cert — hence DNS-01 rather than HTTP-01 — is required only if the DoT/DoQ ClientID form `<id>.dns.example.com` is used.** | ECDSA P-256 signing is roughly an order of magnitude cheaper than RSA-2048 on the TLS handshake path, which is the one path AGH does not rate-limit. Wildcard issuance is a real operational cost (DNS provider credentials on the box) and should be paid only when ClientID actually requires it. | Phase D issues a single-name ECDSA cert by default. If Phase P selects per-client ClientIDs over DoT/DoQ, Phase D must be re-run with a DNS-01 wildcard — decide that **before** Phase D, not after. OCSP stapling is not configured: Let's Encrypt shut down its OCSP responders in 2025. |

---

## Phase 0 — Before you start

Nothing in Phase A creates a domain, a DNS record, a mailbox or an external account, and
several phases stop dead without one. Do this section before you provision the VPS. Three
of the items below have lead time measured in days, and two of those are hard Phase L
blockers — none of them can be compressed at the gate.

Throughout this document `dns.example.com` is the resolver's public name and `example.com`
is the apex domain you own. Replace both, everywhere.

### 0.1. The domain, and the authoritative DNS that must not be this box

This host is a **recursive** resolver. It is authoritative for nothing: Unbound serves no
zone (Phase C sets `access-control: 0.0.0.0/0 refuse` and declares no `auth-zone`), and
AdGuardHome forwards rather than answering from a zone file. The name `dns.example.com`
must therefore be served by authoritative DNS somewhere else — your registrar's DNS, a
hosted DNS provider, any authoritative service you do not run on this machine — and it
must keep resolving while this host is down.

**Do not host `example.com` on this box.** It is the one mistake in this build that is
unrecoverable rather than merely wrong, and it is attractive precisely because the box is
a DNS server. The dependency is circular in four places at once:

- When the host is down, the name that names it stops resolving. Every client configured
  with `dns.example.com` for DoT, DoQ or DoH loses the endpoint at exactly the moment it
  needs to reach something else.
- Phase N's failover on Tiers 0 and 1 *is* "repoint the A record". There is nothing to
  repoint if the record lived on the host that died.
- Phase I's blackbox probes and Phase I9's external checks resolve the name from outside.
  With the zone on the box they report "name does not exist" for every failure mode, which
  is the least diagnostic signal available.
- Certificate renewal (Phase D) and the runbook's last-resort hand-off (Phase N) both
  resolve the name. After C5.8 the host resolves through `127.0.0.1`, so a self-hosted zone
  plus a stopped resolver means you cannot resolve your own hostname from the console while
  debugging why it stopped.

It is also a port conflict — an authoritative server needs :53, which AdGuardHome owns from
Phase E5 — and serving recursion and authority from one address is the class of
configuration this plan exists to avoid.

**What to arrange:** own `example.com`; confirm which nameservers are authoritative for it
and that you can edit records there; obtain an API credential for that zone. The credential
is not deferrable forever — Phase N Tier 3 makes DNS-01 issuance mandatory, and Phase P's
ClientID form requires a wildcard. Decide whether you will need either **before Phase D**,
because changing the issuance method afterwards means reissuing (decision 10).

```bash
# From your workstation. Both must agree, and none of them may be this host.
dig +short NS example.com @1.1.1.1
dig +short NS example.com @9.9.9.9
# expect: your DNS provider's nameservers, identical from both,
#         and dns.example.com is not among them
```

### 0.2. The A record, its TTL, and why Phase N depends on the number

Phase D2 runs `certbot certonly --standalone -d dns.example.com` — the first command in
this plan that touches the outside world. HTTP-01 resolves that name and connects back to
it. If the record does not exist, points elsewhere, or has not propagated, the challenge
fails, and Let's Encrypt permits **five authorization failures per identifier, per account,
per hour**. A retry loop therefore locks you out of issuance for the rest of the hour,
during a build you believe is going correctly. Publish the record now, verify it from two
independent resolvers, and treat a mismatch as a stop rather than a retry.

Publish, with a 300-second TTL:

```
dns.example.com.    300    IN    A    <YOUR_PUBLIC_IPV4>
```

```bash
# From your workstation, not the VPS.
dig +short dns.example.com A @1.1.1.1
dig +short dns.example.com A @9.9.9.9
# expect: your VPS's public IPv4 from both, and nothing else

# A recursive resolver reports the TTL counting down, not the one you configured.
# Ask the zone's own nameserver for the authoritative value.
dig +norecurse +noall +answer dns.example.com A @"$(dig +short NS example.com | head -1)"
# expect: dns.example.com.   300   IN   A   <YOUR_PUBLIC_IPV4>
```

**The 300 is a Phase N parameter, not a formality.** On Tiers 0 and 1 there is no floating
IP, so both the documented failover and the runbook's last-resort hand-off are "repoint the
A record and accept the TTL". The TTL is the floor on how long that recovery takes — on an
86400-second record it is a day. You cannot fix this during the incident: raising a TTL
takes effect almost immediately, but *lowering* one only becomes visible after the old
value has aged out of every cache holding it. Set it low on day one, when it costs nothing,
and you keep an option you will otherwise need at the worst possible moment. 300 is short
enough for a five-minute repoint and long enough that authoritative query volume stays
trivial. Tier 3 moves a floating IP instead and does not depend on the TTL — but a forced
provider migration still does.

**Whether to publish an AAAA is a decision about records, not about listeners.** The
listener is already dual-stack. `dns.bind_hosts: [0.0.0.0]` is a *wildcard* address, and Go
resolves a wildcard listen address to an `AF_INET6` socket with `IPV6_V6ONLY=0`
(`net/ipsock_posix.go`), so AdGuardHome's Do53, DoT and DoQ answer over **both** families on
any host with a usable IPv6 stack — as do nginx, which binds each family explicitly, and the
Phase B ruleset. Phase E's E2a documents the mechanism and owns its consequences. Do not
"add IPv6" by appending `"::"` to `bind_hosts`: that binds `[::]:53` a second time under
`SO_REUSEADDR`/`SO_REUSEPORT`, succeeds silently, and buys nothing.

Two real questions sit behind the record set, and neither of them is a `bind_hosts` edit:

- **Does this host have working IPv6 at all?** An assigned address is not routed transit,
  and if Go's probe could not open an `AF_INET6` socket the wildcard falls back to `AF_INET`.
  In either case a published AAAA advertises an endpoint that answers nothing, and the
  failure presents as intermittent because happy-eyeballs picks a family per connection.
  This is Phase A's service-family decision — make it before you provision.
- **Does recursion leave over IPv6?** That is `do-ip6` in Phase C2, a separate decision with
  its own pre-flight egress test. A resolver can serve v6 clients while recursing only over
  v4, and can recurse over v6 while serving only v4 clients. Do not let one settle the other.

| Option | Cost | When it is right |
|---|---|---|
| **Publish A only** (default) | IPv6-only clients reach an A record only through their access network's NAT64, which means using that network's DNS64 resolver rather than this one (R11) | Every base build. It is the posture the plan verifies end to end. |
| Publish A and AAAA | The provider's IPv6 must be routed and survive a reboot; Phase B's `floodmeter6`, `banned_ips6` and `rrl6` stop being decoration and start carrying real traffic on a /64 key; and E6 step 9 must show every advertised address answering on every transport | You have IPv6-only clients and are prepared to own dual-stack as a maintained property, not a checkbox |

Publish the AAAA only after E6 step 9 — the dual-stack sweep that derives its address list
from DNS — shows all four transports answering on it. Adding it later is a one-record
change; removing it after clients have cached it is an outage for them. If you need ingress
to be genuinely IPv4-only rather than merely unadvertised, the only way is to bind the
literal, `dns.bind_hosts: [<PUBLIC_IPV4>]` — read E2a first, because a literal address also
means AdGuardHome refuses to start whenever that address is not yet on an interface, which
is exactly the state a Phase N floating-IP standby is in.

### 0.3. Acquire before Phase A

Each row names the phase that consumes it. The three with real lead time — the mailbox, the
provider AUP confirmation, and the provider abuse ticket — depend on someone else's queue.
Start them on day one and build while they run.

| Acquire | Consumed by | Lead time |
|---|---|---|
| Apex domain, registered, with editable authoritative DNS you do not run (0.1) | D2, and every transport | Minutes to register; up to 48 h if you are moving nameservers |
| An API credential for that zone | N3 (Tier 3 mandates DNS-01), P3c (wildcard) | Minutes — but the *decision* is due before Phase D |
| `dns.example.com` A record at TTL 300, verified from two resolvers (0.2) | D2 | Publish now, verify before D2 |
| An email address for the ACME account | D2 | — |
| Working mail on the apex: `abuse@` and `security@`, read by a human | Q5c, L10 | **Days.** Needs MX, hosting and a person. This plan installs no MTA, so the mailbox lives elsewhere and Q5c tests it by hand |
| A VPS whose acceptable-use policy permits a **public recursive resolver** | Phase A | **Hours to days** — a support ticket. Ask before you pay; some providers forbid it outright |
| The provider's abuse-forwarding contact, and a ticket raised with them | L10 | Someone else's queue |
| Object-storage bucket, plus a credential scoped to that bucket with write and list rights only | K2 | Minutes |
| An external dead-man's-switch account, **plus** a second independent external check on a different service | I9 | Minutes to create — but L12 blocker 5 requires a *proven* page, so budget time with the phone in hand |
| An ntfy topic of at least 32 random characters (or self-hosted ntfy), with the app installed on that phone | I8 | Minutes |
| A second small VPS in the same region — the test host | Provisioned in H0, but Phase B's verification already needs it | Minutes |
| An Ansible control host you already trust, and a git remote for the config repo | O2 | Hours, if you do not have one |
| Two SSH keypairs on your workstation: one unrestricted admin key, one restricted tunnel key | A4 Steps 0 and 3 | Minutes |

### 0.4. Who this is for, and where the assumed skill level changes

The base build — A through H, plus K and L — assumes a sysadmin who is comfortable writing
systemd units and drop-ins, reading `journalctl`, hand-editing an nftables ruleset, and
editing a YAML file that its own daemon will rewrite underneath them. It assumes no DNS
protocol expertise beyond what each phase explains where it is needed.

Three phases assume more than that, and none of them says so where it starts:

- **Phase I** additionally assumes you can write and debug PromQL — recording rules,
  `predict_linear`, and the rate-versus-gauge reasoning I0 opens with — plus an Alertmanager
  routing tree and a small Python webhook bridge. If that is not you, do **I9 first and in
  full**. It is the one part of Phase I that cannot be substituted, it requires no Prometheus
  knowledge, and it is what L12 blocker 5 actually gates on. Build the rest of I incrementally
  afterwards, against a resolver that is already answering.
- **Phase O** assumes working Ansible including Vault, cloud-init, and a control host you
  already trust. Without those, the honest fallback is Phase K7's restore drill run and timed
  by hand, and Phase O recorded as *deferred* — written down, in the Phase O inventory. A
  deferral you wrote down is a decision; one you did not is a gap you rediscover during an
  incident.
- **Phase N Tier 3** additionally assumes keepalived/VRRP and your provider's floating-IP
  API. Tier 1 needs neither, and N2 states the trade-off.

---

## How to use this plan

Execute in letter order. Do not skip forward — later phases assume earlier ones.

- **Phases A–L are the base build.** A host, B firewall, C resolver (Unbound), D TLS,
  E AdGuardHome, G logrotate, H validation, I observability, J abuse controls, K backup,
  L go-live checklist. **Phase F is retired** (decision 3) and the letter is not reused.
- **Phases M–O are production operations.** M patching and upgrades, N high availability
  and the second node, O provisioning / infrastructure-as-code. A single-node resolver
  with no patching story and no rebuild path is a demo, not a service. Do these.
- **Phases P and Q are optional layers.** P is the private access layer (WireGuard,
  ClientIDs, token-authenticated DoH, mTLS, IP allowlists); Q is the privacy, retention
  and legal posture (retention policy, privacy notice, `security.txt`, abuse contact).
  They are optional in the sense that a plain public resolver works without them — but
  **read both before Phase L**, because P changes the Phase B, D, E and J configuration
  and Q changes what Phase E writes to disk. Retrofitting either after go-live means
  reissuing certificates or deleting data you already collected.
- **Phase L is the gate, and it is printed last.** It keeps its letter because every
  other phase cites it (L1, L8, L12…), but it appears at the end of this document rather
  than between K and M, because it gates on M–Q as well as on A–K. Nothing is "live"
  until every line of it passes on the actual host. Several items exist specifically to
  catch the v1 bugs listed in the decisions table, which all fail silently.

Every step that can be checked ends with an exact verification command and its expected
output. If a verification does not produce the expected output, stop and fix it there;
almost every failure in this stack is silent downstream.

### How long this takes, and when the host becomes publicly reachable

The **Time** column in the phase table below is a first-build estimate — a host you have
never built before, verification commands included. The second build is roughly half.
Budget **two to three working days for A through L**, plus about a day for M through O.
This is not an evening's work, and the reason that matters is not scheduling.

**From Phase E5 this host answers the whole internet.** AdGuardHome binds udp/53, tcp/53,
tcp/853 and udp/853 the first time its unit starts, and stays bound for the rest of the
build. It is not undefended at that point: Phase B's rate limiting, NOTRACK bypass and
egress response-rate limiting are already in force, and Unbound is already validating. What
it is not, at that moment, is *proven or watched*. Phase H has not yet demonstrated that
validation actually rejects a bad signature (L12 blocker 1), Phase I has no monitoring,
Phase J4's ban escalation does not exist, and Phase K has no backup. The hostname is also
enumerable from Certificate Transparency the moment Phase D issues (Q4), so scanners find
the encrypted transports by name and the plain ones by address. Expect probe traffic within
hours of the first bind.

Two acceptable ways to handle that window. Finish through Phase L in one run — or
`systemctl stop adguardhome` before you walk away and start it again when you sit back
down. If the build will span days, a third option is to use Phase B6's source-allowlist
machinery as a build-time shield, admitting only the H0 test host until Phase H passes;
just remember that opening it again is then a go-live step, not an afterthought.

### A staged route, if you cannot execute all of A–O

The default instruction stands, and M–O are not decoration. But a reader who has a weekend,
or who wants a correct resolver before committing to Prometheus and Ansible, is better
served by a staged build recorded as such than by improvising — and this stack's failure
modes are specifically the silent ones. Three stages, each ending somewhere defensible:

| Stage | Phases | What you have at the end |
|---|---|---|
| **1 — correct, not yet operable** | A, B, C, D, E, H | A host that recurses from the root and validates, proven by H5. Not announced, not given to anyone, not left running unattended. |
| **2 — safe to hand to users** | G, **I9**, J, K including K7, then the L12 blockers | A resolver that will not fill its own disk, bans abusers in the kernel, can be rebuilt from source control, and whose death pages you. |
| **3 — a service** | The rest of I, M, N, O, then all of L | Metrics you can query, a patching story, failover, and a rebuild path you have measured rather than assumed. |

Stage 2 turns on **I9 specifically, not all of Phase I**. The off-box dead man's switch is
what makes an unattended single node defensible; the Prometheus stack above it is what makes
it diagnosable. Those are different requirements and only one of them is a hard blocker.

Two things must be read before the phase they change, at any stage:

- **Read Phase Q before you apply Phase E.** Q decides what the query log writes to disk,
  and it starts writing on the first query. You cannot retroactively not have collected
  something.
- **Read Phase P before Phase D** if there is any chance you will want per-client ClientIDs.
  It changes the certificate from a single name to a wildcard, which means reissuing
  (decision 10).

For every deferral, write down what stops being true — not as paperwork, but as the sentence
you will need when something breaks:

- Defer **G**: the AdGuardHome query log and journald grow with no ceiling. Disk exhaustion
  is the failure mode, and G4 is the guard you skipped.
- Defer **I9**: the threat model's answer to "loss of administrative access", and its
  admission of a single failure domain, become claims with no detector behind them.
- Defer **J**: Phase B counts abuse and nothing acts on it. The threat model's reflection and
  amplification answer is half-built.
- Defer **K7**: you have a belief in a recovery path, not a recovery path. That is L12
  blocker 6, in the plan's own words.
- Defer **M**: an unpatched public listener on :53, :443 and :853.
- Defer **N**: a reboot is an outage. The threat model already says so; deferring N makes
  that permanent rather than temporary.
- Defer **O**: your RTO is a guess. O5's 20-minute target belongs to a host built by Ansible
  and is not yours until you have measured your own.

### When a verification command surprises you

"Stop and fix it there" covers the case where the output is simply wrong. It does not cover
the third outcome: the command errors, the binary is not there, the output names a version
this plan does not, or this check passes while a neighbouring one that passed an hour ago
now fails. For that:

1. **Do not run the next step.** Every phase after this one assumes the object you just
   failed to verify exists and behaves. Stacking a second change onto an unverified first is
   what turns a ten-minute problem into a bisect.
2. **Find the owner, then read only that.** The directory and port layout tables in
   [11-go-live-checklist.md](phases/11-go-live-checklist.md) name exactly one owning phase per
   path and per listener. Go there instead of searching the whole document — two phases
   touching one file is a bug in this plan, not something to resolve by guessing.
3. **Re-run the parse gate, not the service.** These four are read-only, have no side
   effects, and are safe at any point in the build. They separate "my config does not parse"
   from "my config parses and the daemon does something else":

```bash
nft -c -f /etc/nftables.conf
unbound-checkconf
runuser -u adguardhome -- /opt/adguardhome/current/AdGuardHome --check-config \
  -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/validate
nginx -t
```

4. **Undo only the step you just ran**, using that phase's own text, and re-verify before
   moving on.
5. **Treat an unlisted version, package or path as a scope violation.** Every version-specific
   claim in this document is checked against Ubuntu 24.04 package versions and nothing else
   (decision 1). If `unbound -V`, `AdGuardHome --version` or `nginx -v` prints something this
   plan does not mention, find out why the version differs — do not adapt the config until the
   command stops complaining.

The Operations Runbook in [08-operations.md](phases/08-operations.md) is not a substitute
during the build. Its escalation path opens by running the smoke gate, which Phase H12
creates, and its second step is "roll back the last change", which presupposes a host that
worked yesterday. Use the runbook after Phase L; use the five steps above before it.

---

## Migrating from v1

**There is no in-place upgrade path, and the reason is the base OS.** v1 was built on Ubuntu
22.04. Decision 1 pins 24.04 and says do not substitute it, because the Phase C configuration
does not parse on unbound 1.13.1 and 22.04's certbot cannot issue ECDSA. The supported
migration is therefore a parallel build on a new 24.04 host, cut over by moving the address.
`do-release-upgrade` on a live public resolver is not a migration plan.

The in-place repair steps in this document are not a migration route and must not be read as
one. Phase F1's warmer removal, Phase C's SmartDNS deletion list and Phase E5a's `setcap -r`
exist for a host already on 24.04, or for one you inherited mid-migration. Running them on a
live 22.04 v1 box leaves you with a deleted resolver, an AdGuardHome that will not start at
all until Phase E is applied (Phase C says so explicitly), and no working configuration to
return to.

The cutover:

1. **Build the new host through Phase L**, on its own IP, with `dns.example.com` still
   pointing at v1. Nothing about the new host is published yet.
2. **Test the new host by address**, from the Phase H0 test host — the name still resolves to
   v1, so every check has to carry the hostname separately for SNI and certificate validation:

```bash
dig @<NEW_IP> +dnssec dnssec-failed.org A                                    # expect: SERVFAIL
dig @<NEW_IP> +dnssec example.com A | grep -q 'flags:.* ad'  && echo AD-OK   # expect: AD-OK
kdig @<NEW_IP> +tls +tls-ca +tls-hostname=dns.example.com example.com A
curl -sS --resolve dns.example.com:443:<NEW_IP> -o /dev/null \
  -w '%{http_code} %{content_type}\n' \
  'https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB'
# expect: 200 application/dns-message
```

3. **Confirm the published TTL is already 300** (0.2) and has been for at least one *old* TTL
   window. If v1 published 3600 or 86400, lower it and wait that long before touching anything
   else. This is the step people skip and then spend a day regretting.
4. **Move the record** — or the floating IP, on Phase N Tier 3 — and watch the query rate on
   both hosts. The old host's rate should decay over roughly one TTL while the new host's rises
   to meet it. If it does not, the record did not move where you think it did.
5. **Leave v1 running and answering** for at least one further old-TTL window, preferably a
   day. The rollback for this entire migration is moving the record back, and it exists only
   while v1 is still alive. Decommissioning early converts a five-minute rollback into a
   rebuild.
6. **Decommission v1** only after seven days of clean Phase I metrics on the new host, and only
   after K7 has restored the *new* host's backups — not the old host's.

Two things do not roll back. The ECDSA issuance consumes one of Let's Encrypt's five
duplicate-certificate slots per exact name set per seven days (D2), so a migration attempted
three times can leave you unable to reissue during an incident. And any client whose owner
pinned v1's IP address by hand rather than using the name must be reconfigured by that owner —
moving the record does not reach them. Find those clients before the cutover, not after.

The full v1-to-v2 changelog is in [11-go-live-checklist.md](phases/11-go-live-checklist.md).

---

## Threat model and scope

**What this resolver defends against.** Cache poisoning and off-path spoofing, via DNSSEC
validation in Unbound (decision 4), source-port and 0x20 randomisation, DNS cookies on the
outbound leg, and RFC 8198 aggressive negative caching that reduces the query surface.
On-path observation and tampering between the client and the resolver, via DoT, DoQ and
DoH (Phase D/E). Answer manipulation by the operator's own software — the reason SmartDNS
was removed (decision 2). Reflection and amplification abuse of the open UDP listener, via
per-source rate limiting, response-size limits and TC=1 truncation (Phase B, J). Resource
exhaustion of the host itself, via cgroup memory ceilings, conntrack bypass and kernel
tuning (A5, A6, Phase B). Loss of administrative access, via key-only SSH with a loopback-
only admin UI (A4, decision 5).

**What it does not defend against.** It is not a privacy service: the operator can see
every query, and Phase Q is about deciding and documenting what is retained, not about
making the operator blind. It provides no protection against a compromise of the VPS
provider, the hypervisor, or the provider's console. It gives clients no anonymity — the
resolver's own recursion exposes the client's query pattern to root, TLD and authoritative
servers from a single, stable source IP, which is a fingerprint of *this resolver*, not of
any one client. It is not resistant to a volumetric DDoS that saturates the provider's
uplink; nothing on the host can defend a full pipe, and the mitigation is Phase N plus the
provider's own scrubbing. Blocklist-based filtering (Phase E) is content policy, not a
security control — it stops known advertising and tracking hosts, not targeted attacks.
DNSSEC validates that an answer came from the zone's owner; it does not mean the zone's
owner is honest, and most of the internet is still unsigned. **It does no DNS64, and is
therefore not a drop-in resolver on an IPv6-only access network that reaches IPv4 through
NAT64** — mobile carriers, conference and campus WLANs, IPv6-mostly enterprises. Unbound
returns the zone's answer, so an IPv4-only destination yields a truthful NODATA for AAAA:
address synthesis stops and RFC 7050 prefix discovery via `ipv4only.arpa` stops with it,
which presents as most of the web failing with no DNS error to show for it (R11 in
[12-client-setup.md](phases/12-client-setup.md) has the one-command discriminator). Adding
DNS64 here is the wrong fix — the synthesised AAAAs would point into a translator you do not
run. Finally, a single node has a single failure domain: until Phase N is done, "the
resolver" and "the host" are the same thing, and a reboot is an outage.

---

## The phases

Each phase group is its own file under [`phases/`](phases/). Citations inside the
documents use phase letters and step numbers (`Phase B5`, `(H12)`, `L12`); the table
maps each letter to the file that contains it.

| File | Phases | Time (first build) | Covers |
|---|---|---|---|
| [01-host-preparation.md](phases/01-host-preparation.md) | A | ~1 h, including a reboot | VPS sizing and the honest capacity model, Ubuntu 24.04 base, SSH hardening, corrected sysctl set, memory ceilings and swap. |
| [02-firewall.md](phases/02-firewall.md) | B | ~1 h | The authoritative nftables ruleset: conntrack bypass for UDP/53, dual-stack ban and allowlist sets, flood detection, amplification analysis. |
| [03-unbound-resolver.md](phases/03-unbound-resolver.md) | C | ~1–2 h | True recursion and DNSSEC validation, QNAME minimisation, rebinding protection, trust-anchor lifecycle. Replaces SmartDNS entirely. |
| [04-tls-certificates.md](phases/04-tls-certificates.md) | D | ~30 min | ECDSA issuance, the deploy hook that feeds both nginx and AdGuardHome, renewal that cannot wipe firewall state. |
| [05-adguardhome-edge.md](phases/05-adguardhome-edge.md) | E | ~2 h — **the host becomes publicly reachable at E5** | The corrected AdGuardHome.yaml (schema_version, top-level querylog/statistics), nginx DoH front, systemd hardening reference table. |
| [06-logging-and-validation.md](phases/06-logging-and-validation.md) | F, G, H | G ~30 min; H ~3 h plus LT-13's four-hour soak | Phase F retirement notes, log rotation and retention, and the full acceptance suite including DNSSEC tests, load test and smoke gate. |
| [07-observability-and-abuse.md](phases/07-observability-and-abuse.md) | I, J | I ~3–4 h (I9 alone ~30 min); J ~2 h | Metrics pipeline, blackbox probes, alert rules, SLOs, the off-box dead-man's switch, and kernel-side abuse detection. |
| [08-operations.md](phases/08-operations.md) | K, M, N, O | K ~2 h plus K7's own under-an-hour drill; M ~2 h; N ~30 min at Tier 1, ~4 h at Tier 3; O ~1 day | Off-host encrypted backup with a restore drill, upgrade and rollback procedures, high-availability tiers, IaC, and the operations runbook. |
| [09-private-access.md](phases/09-private-access.md) | P | ~2–4 h, depending on which rows of P0 you select | Restricting who may query: WireGuard-fronted DNS, AdGuardHome ACLs, ClientIDs, token-authenticated DoH, mTLS, IP allowlists. |
| [10-privacy-and-compliance.md](phases/10-privacy-and-compliance.md) | Q | ~2 h — but read it before Phase E | Logging postures, upstream privacy, data at rest, metadata leakage, retention policy and privacy notice templates, GDPR decisions. |
| [11-go-live-checklist.md](phases/11-go-live-checklist.md) | L | ~2 h | The gate: grouped checklist with citations, hard blockers, authoritative port and path layout, risk register, v1 to v2 changelog. |
| [12-client-setup.md](phases/12-client-setup.md) | R | ~1 h, plus one real device per transport | What a user actually types where: the four endpoint strings and the per-platform constraints on them — Android, Apple, Windows, Linux, browsers, routers — captive portals, NAT64, and the check that proves a client is reaching *this* resolver with validation on. Client-side only; changes nothing on the host. |
