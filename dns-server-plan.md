# Public Recursive, DNSSEC-Validating DNS Resolver — Production Execution Plan (v2)

Target platform: a single Ubuntu 24.04 LTS VPS, 2 vCPU / 4 GB / 40 GB SSD, static IPv4
(optional IPv6). Every command in this document is written to be executed verbatim, in
order, by a sysadmin with root on a freshly provisioned host.

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
owner is honest, and most of the internet is still unsigned. Finally, a single node has a
single failure domain: until Phase N is done, "the resolver" and "the host" are the same
thing, and a reboot is an outage.

---

## The phases

Each phase group is its own file under [`phases/`](phases/). Citations inside the
documents use phase letters and step numbers (`Phase B5`, `(H12)`, `L12`); the table
maps each letter to the file that contains it.

| File | Phases | Covers |
|---|---|---|
| [01-host-preparation.md](phases/01-host-preparation.md) | A | VPS sizing and the honest capacity model, Ubuntu 24.04 base, SSH hardening, corrected sysctl set, memory ceilings and swap. |
| [02-firewall.md](phases/02-firewall.md) | B | The authoritative nftables ruleset: conntrack bypass for UDP/53, dual-stack ban and allowlist sets, flood detection, amplification analysis. |
| [03-unbound-resolver.md](phases/03-unbound-resolver.md) | C | True recursion and DNSSEC validation, QNAME minimisation, rebinding protection, trust-anchor lifecycle. Replaces SmartDNS entirely. |
| [04-tls-certificates.md](phases/04-tls-certificates.md) | D | ECDSA issuance, the deploy hook that feeds both nginx and AdGuardHome, renewal that cannot wipe firewall state. |
| [05-adguardhome-edge.md](phases/05-adguardhome-edge.md) | E | The corrected AdGuardHome.yaml (schema_version, top-level querylog/statistics), nginx DoH front, systemd hardening reference table. |
| [06-logging-and-validation.md](phases/06-logging-and-validation.md) | F, G, H | Phase F retirement notes, log rotation and retention, and the full acceptance suite including DNSSEC tests, load test and smoke gate. |
| [07-observability-and-abuse.md](phases/07-observability-and-abuse.md) | I, J | Metrics pipeline, blackbox probes, alert rules, SLOs, the off-box dead-man's switch, and kernel-side abuse detection. |
| [08-operations.md](phases/08-operations.md) | K, M, N, O | Off-host encrypted backup with a restore drill, upgrade and rollback procedures, high-availability tiers, IaC, and the operations runbook. |
| [09-private-access.md](phases/09-private-access.md) | P | Restricting who may query: WireGuard-fronted DNS, AdGuardHome ACLs, ClientIDs, token-authenticated DoH, mTLS, IP allowlists. |
| [10-privacy-and-compliance.md](phases/10-privacy-and-compliance.md) | Q | Logging postures, upstream privacy, data at rest, metadata leakage, retention policy and privacy notice templates, GDPR decisions. |
| [11-go-live-checklist.md](phases/11-go-live-checklist.md) | L | The gate: grouped checklist with citations, hard blockers, authoritative port and path layout, risk register, v1 to v2 changelog. |
