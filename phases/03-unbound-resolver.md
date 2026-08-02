[Plan index](../dns-server-plan.md) · [Previous: Firewall and Edge Packet Policy](./02-firewall.md) · [Next: TLS Certificates](./04-tls-certificates.md)

---

**On this page**

- [PHASE C: Unbound (Validating Recursive Resolver)](#phase-c-unbound-validating-recursive-resolver)
  - [C1. Install Unbound and de-fang the distro integration](#c1-install-unbound-and-de-fang-the-distro-integration)
  - [C2. Resolver configuration](#c2-resolver-configuration)
  - [C3. DNSSEC trust anchor lifecycle](#c3-dnssec-trust-anchor-lifecycle)
  - [C4. Hardened systemd unit](#c4-hardened-systemd-unit)
  - [C5. Verification](#c5-verification)
  - [C6. What recursion costs, and what pays for it](#c6-what-recursion-costs-and-what-pays-for-it)

---

## PHASE C: Unbound (Validating Recursive Resolver)

**This phase replaces v1's C1-C5 in full. SmartDNS is gone from the design.**

If you executed the v1 plan, the resolver layer was SmartDNS on `127.0.0.1:5335` forwarding every query over DoH to four public operators (Cloudflare, Google, Quad9, AdGuard) and taking the first usable answer. Three things were wrong with that, and they are why it is being removed rather than tuned:

1. **The verdict was borrowed, not computed.** SmartDNS has no DNSSEC directive of any kind — not in the configuration reference, not in the per-server flag list, not in the shipped `smartdns.conf`. AdGuardHome does not validate either; its `enable_dnssec` only sets the DO bit on upstream queries. Nothing in the v1 chain checked a signature. Note carefully what this did *not* mean: all four configured upstreams validate, so `dnssec-failed.org` already returned SERVFAIL through the v1 stack. The exposure was never "bogus names resolve" — it was that you could not check, could not disagree, and could not detect an upstream that had been BGP-hijacked with a valid certificate, legally compelled, or simply misconfigured.
2. **The race selected the most permissive answer.** SmartDNS's default group raced four operators for the first usable reply. If three returned SERVFAIL for a bogus name and one returned NOERROR, NOERROR won. Racing N unvalidated forwarders makes your effective trust set the *union* of them, and the union's security is that of its weakest member. (This is not an on-path-attacker story — the upstream leg was DoH over TLS and is not spoofable off-path. It is a trust-aggregation story.)
3. **SmartDNS mutates answers by design.** Documented defaults: `speed-check-mode ping,tcp:80,tcp:443`, `response-mode first-ping`, `dualstack-ip-selection yes`, `max-reply-ip-num 8`. It probes the addresses it resolves, reorders and filters the resulting RRset, truncates RRsets above 8 records, and suppresses AAAA when the v4 path measures faster. An RRset that has been filtered or reordered no longer verifies against its RRSIG, so DNSSEC validation could never be layered on top of it even in principle.

Unbound recurses from the root, validates every answer against the root trust anchor, and never rewrites an RRset. It listens on the **same** `127.0.0.1:5335`, so the Phase B firewall rule, AdGuardHome's `upstream_dns`, the Phase I health cron and the Phase H isolation test all carry over verbatim.

**Also retired here: Phase F.** The v1 plan ran a Python cache warmer as a separate daemon to keep hot names alive. Unbound's `prefetch` and `prefetch-key` do that in-process, on the names your users actually ask for, with no extra daemon, no extra service account, and no self-inflicted query load. The warmer is deleted; see C2's prefetch block for what replaces it.

Delete along with SmartDNS: the `smartdns` service user (Phase A3), `/etc/smartdns`, `/var/lib/smartdns`, `/var/log/smartdns`, the SmartDNS logrotate stanza and `systemctl reload smartdns` (Phase G), the `cp /etc/smartdns/smartdns.conf` line in the backup script (Phase K — it will fail the script), and every SmartDNS row in the runbook restart order, failure table and Phase L checklist.

---

### C1. Install Unbound and de-fang the distro integration

**Version floor: unbound 1.19.2, which is what Ubuntu 24.04 (noble) ships.** This is the reason Phase A1 specifies 24.04 rather than 22.04. Ubuntu 22.04 ships 1.13.1, where:

- `aggressive-nsec` defaults to **no** (RFC 8198 off — no NXDOMAIN synthesis from cached NSEC/NSEC3),
- `max-udp-size` defaults to **4096** (fragmentation exposure on the recursive leg),
- `ede` / `ede-serve-expired` **do not exist** (no RFC 8914 Extended DNS Errors, so a SERVFAIL is indistinguishable from a validation failure to the client),
- `answer-cookie` / `cookie-secret` / `ip-ratelimit-cookie` **do not exist** (RFC 7873 cookies arrived in 1.18.0),
- `harden-unknown-additional` **does not exist** (arrived in 1.17.0).

On 24.04, `aggressive-nsec` and `max-udp-size` already default correctly and the rest are available. Building unbound from source on 22.04 to close that gap is a strictly worse maintenance position than moving the base image, which is why the base image moved.

```bash
apt install -y unbound unbound-anchor dns-root-data
```

All three packages exist in noble. `dns-root-data` supplies `/usr/share/dns/root.hints` and `/usr/share/dns/root.key`.

Now disable the one piece of distro integration that will otherwise fight this design.

The piece you might expect to find here — releasing systemd-resolved's stub listener so AdGuardHome can bind `0.0.0.0:53` (Phase E) — is **not** this phase's problem and is not done with `DNSStubListener`. **Phase A2 disables and removes systemd-resolved entirely**, so there is no stub listener to release, no `/etc/systemd/resolved.conf.d/` to write into, and no `resolvectl` to consult. No phase in this plan sets `DNSStubListener`; if you find yourself reaching for that knob, A2 did not run.

```bash
# unbound-resolvconf registers unbound in /etc/resolv.conf via resolvconf, which
# would clobber the static file Phase A2 wrote (and the one C5.8 writes over it).
# With systemd-resolved gone it is the only remaining automatic writer of that
# file, so mask it rather than trusting it to keep losing races (Launchpad
# #2085778, Debian #1106186). RESOLVCONF=false is the maintainer-sanctioned switch.
printf 'RESOLVCONF=false\n' > /etc/default/unbound
systemctl disable --now unbound-resolvconf.service
systemctl mask unbound-resolvconf.service
```

**The host's own resolver, and why it does not change here.** `/etc/resolv.conf` on a stock Ubuntu 24.04 box is a **symlink** to `../run/systemd/resolve/stub-resolv.conf`. Redirecting into it with `>` writes *through* the symlink into a file systemd-resolved owns and rewrites on its next reload — the change silently reverts, usually within hours, and you find out when `certbot renew` fails at 03:00. The symlink must be replaced, never written through.

**Phase A2 has already done that.** It removed systemd-resolved, replaced the symlink with a real file, and wrote a static `nameserver` line pointing at the provider's resolver — a value A2 labels explicitly as bootstrap-only, because at that point in the build Unbound does not exist yet and there is nothing else on the box that can answer.

Leave that file alone in C1. The bootstrap value is what makes the `apt install` above work at all, and it has to keep working until Unbound has proved it resolves *and* validates. The flip to `127.0.0.1` is **C5.8**, at the close of this phase's acceptance tests — see there for the flip itself, and for why it carries no fallback entry.

Do **not** create a `unbound` service user by hand; the package creates it. Phase A3's `smartdns` user is now dead — remove it.

**Verify C1**

```bash
unbound -V | head -2                                 # 1.19.2
systemctl is-enabled unbound-resolvconf.service      # masked

# systemd-resolved is GONE (Phase A2), not merely stub-disabled. There is no
# resolvectl to query and no DNSStubListener setting anywhere in this plan.
systemctl is-active systemd-resolved 2>/dev/null     # inactive, or unit not found
test -L /etc/resolv.conf && echo 'FAIL: symlink is back - A2 replaced it with a real file'
cat /etc/resolv.conf                                 # still A2's BOOTSTRAP value (the
                                                     # provider's resolver). C5.8 flips
                                                     # this to 127.0.0.1 - not yet.
ls -l /usr/share/dns/root.hints /usr/share/dns/root.key
```

---

### C2. Resolver configuration

The distro's `/etc/unbound/unbound.conf` ends with `include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"`, so everything below goes in one drop-in file. **Drop-ins load lexicographically.** `10-public-resolver.conf` parses *before* the two files the package ships — `remote-control.conf` and `root-auto-trust-anchor-file.conf` — and you must not redeclare what those set:

- `remote-control.conf` already sets `control-enable: yes` and `control-interface: /run/unbound.ctl`. **Unbound's remote control is therefore ENABLED on this box, and it stays enabled** — that is a deliberate part of the design, not an oversight. Every `unbound-control` command in this plan runs over that shipped unix socket, and Phase I's metrics collector reads `unbound-control stats_noreset` through it; disabling remote control blinds Phase I. What you must not do is *redeclare* it. `control-interface` is a **list**, so a second declaration *adds* a channel rather than replacing one. The v1-era instinct to add a `remote-control:` block on TCP 127.0.0.1:8953 gives you a redundant second control channel and forces `unbound-control-setup` certificates that the unix socket does not need. Every `unbound-control` command in this plan works over the shipped socket unchanged. **Do not add a `remote-control:` block.**
- `root-auto-trust-anchor-file.conf` already sets `auto-trust-anchor-file: "/var/lib/unbound/root.key"`. Declaring it twice is a known breakage. See C3.

Write `/etc/unbound/unbound.conf.d/10-public-resolver.conf`:

```conf
# unbound 1.19.2 (Ubuntu 24.04 noble). Public recursive resolver, loopback-only
# listener - the public edge is AdGuardHome (Phase E), which is this daemon's
# only client.

server:
    # === LISTENERS =====================================================
    # Same address:port SmartDNS used, so Phase B's `dport 5335 drop` rule,
    # AdGuardHome's `upstream_dns: 127.0.0.1:5335` and the Phase H isolation
    # test all carry over unchanged.
    interface: 127.0.0.1@5335
    interface: ::1@5335

    # access-control is longest-prefix-match, so order does not matter.
    # It is also GLOBAL to the daemon, not per-listener: if you ever add a
    # public listener, `access-control: 0.0.0.0/0 allow` would open :5335 too.
    # Per-listener policy needs `interface-view:` + `access-control-view:`.
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow

    do-ip4: yes
    do-ip6: yes            # set to `no` if the VPS has no working IPv6 EGRESS.
                           # A broken v6 route here costs a timeout per query.
    do-udp: yes
    do-tcp: yes

    username: "unbound"    # unbound drops privileges itself - see C4
    chroot: ""             # systemd sandboxing covers isolation and avoids the
                           # chroot path traps (root.hints, root.key, /dev/random)
    hide-identity: yes
    hide-version: yes
    deny-any: yes          # answer qtype ANY with an empty response

    # === SIZING: 2 vCPU / 4 GB shared with AdGuardHome =================
    num-threads: 2                    # = vCPU count. More threads than cores
                                      # buys nothing and costs cache slab RAM.
    so-reuseport: yes                 # per-thread listen sockets; only useful
                                      # with num-threads > 1

    # Slab counts must be a POWER OF TWO and should equal num-threads. Too few
    # slabs serialises threads on a lock; too many wastes memory on empty slabs.
    msg-cache-slabs: 2
    rrset-cache-slabs: 2
    infra-cache-slabs: 2
    key-cache-slabs: 2

    so-rcvbuf: 4m                     # needs net.core.rmem_max >= 4m (Phase A)
    so-sndbuf: 4m
    outgoing-range: 8192              # outgoing source ports held open PER THREAD
    num-queries-per-thread: 4096      # NLnet Labs guidance: half of outgoing-range

    rrset-cache-size: 256m
    msg-cache-size: 128m              # NLnet Labs guidance: ~half of rrset-cache
    key-cache-size: 32m
    neg-cache-size: 16m
    infra-cache-numhosts: 100000      # RTT/EDNS state for authoritative servers

    # === RECURSION + DNSSEC ============================================
    # DO NOT set auto-trust-anchor-file here. The package already sets it in
    # root-auto-trust-anchor-file.conf and a second declaration is a known
    # breakage. See C3.
    root-hints: "/usr/share/dns/root.hints"   # from the dns-root-data package

    harden-dnssec-stripped: yes
    harden-glue: yes
    harden-below-nxdomain: yes
    harden-algo-downgrade: yes        # default is NO - an attacker may not pick
                                      # the weakest algorithm in a multi-alg zone
    harden-large-queries: yes         # default is NO
    harden-short-bufsize: yes
    harden-unknown-additional: yes    # unbound >= 1.17.0; default is NO
    val-clean-additional: yes         # strip unsigned/unvalidated records from
                                      # the additional section instead of
                                      # passing them through to the client
    val-log-level: 1                  # one line per bogus answer, with reason
    log-servfail: yes

    aggressive-nsec: yes              # RFC 8198. Default is YES on 1.19.2 and NO
                                      # on 1.13.1 - declared explicitly so a base
                                      # image change cannot silently revert it.
                                      # This is the main structural defence
                                      # against random-subdomain (water-torture)
                                      # floods: cached NSEC/NSEC3 proves whole
                                      # ranges nonexistent without a query.

    # === PREFETCH: this is what replaces the deleted Phase F warmer ====
    prefetch: yes                     # refresh a cache entry when a query
                                      # arrives with <10% of its TTL left, and
                                      # answer that query from cache immediately
    prefetch-key: yes                 # fetch DNSKEY early, before the DS is
                                      # needed - removes a serialised round trip
                                      # from the validation path on cache miss
    # Prefetch acts only on names your users actually query, so the hot set stays
    # warm with zero synthetic load. The v1 Python warmer generated its own query
    # traffic against a list of domains guessed in advance; it is deleted.

    # === PRIVACY TOWARD THE AUTHORITATIVE SIDE =========================
    qname-minimisation: yes           # RFC 9156. Send only the labels the next
                                      # server needs: the root learns "com.",
                                      # not "intranet.customer.example.com".
                                      # Default is yes on 1.19.2; declared
                                      # explicitly because it is load-bearing.
    qname-minimisation-strict: no     # TRADEOFF, and the safe side of it.
                                      # `no`  = minimise, but fall back to the
                                      #         full QNAME when a server answers
                                      #         a minimised query incorrectly.
                                      # `yes` = never fall back; those zones then
                                      #         fail to resolve ENTIRELY.
                                      # Non-conforming servers that return
                                      # NXDOMAIN (instead of NOERROR/NODATA) for
                                      # an empty non-terminal still exist. On a
                                      # public resolver serving strangers, strict
                                      # converts someone else's misconfiguration
                                      # into your outage. Choose `yes` only if
                                      # you are prepared to field those tickets.
    minimal-responses: yes            # omit unneeded authority/additional
                                      # sections: smaller packets, less
                                      # fragmentation, fewer cache-poisoning
                                      # surfaces
    rrset-roundrobin: yes             # rotate RRset order per response so
                                      # clients that take the first record
                                      # spread across a zone's addresses

    # === EDNS / FRAGMENTATION (DNS Flag Day 2020) ======================
    # 1232 = 1280 (minimum IPv6 MTU) - 40 (IPv6 header) - 8 (UDP header).
    # Larger UDP responses fragment; fragments are trivially spoofable and are
    # dropped outright by a meaningful share of middleboxes.
    edns-buffer-size: 1232            # what unbound advertises to authoritatives
    max-udp-size: 1232                # ceiling on responses unbound sends.
                                      # 1.19.2 default is 1232; 1.13.1's is 4096.
    # NOTE: this governs the RECURSIVE leg only. The client-facing leg is
    # AdGuardHome, which honours whatever buffer size the client advertises and
    # exposes no knob to cap it. See Phase E for that limitation and its
    # mitigations - do not try to fix it here.

    # === ANTI-SPOOF ====================================================
    unwanted-reply-threshold: 10000000 # default is 0 (disabled). After this many
                                       # unsolicited/unmatched replies, unbound
                                       # flushes its caches and logs - a blunt
                                       # but effective response to a sustained
                                       # off-path spoofing campaign. 10M is high
                                       # enough that normal noise never trips it.
    do-not-query-localhost: yes        # never treat a loopback address as an
                                       # authoritative server (default yes)
    use-caps-for-id: no                # DNS 0x20 - see the note below

    # === SERVE-STALE, RFC 8767 =========================================
    serve-expired: yes
    serve-expired-client-timeout: 1800 # THE LOAD-BEARING LINE. Unbound's default
                                       # is 0 in BOTH 1.13.1 and 1.19.2, and 0
                                       # means "answer stale immediately, do not
                                       # wait". See the RFC discussion below.
    serve-expired-ttl: 86400           # RFC 8767 maximum stale timer; the RFC
                                       # suggests 1-3 days
    serve-expired-reply-ttl: 30        # RFC 8767 s4 RECOMMENDED value; also
                                       # unbound's own default
    serve-expired-ttl-reset: no        # a stale hit must not extend the window
    ede: yes                           # RFC 8914 Extended DNS Errors; default no
    ede-serve-expired: yes             # attach EDE 3 "Stale Answer"; default no.
                                       # Both require unbound >= 1.16.0.

    cache-min-ttl: 0                   # DO NOT RAISE. Inflating a short TTL
                                       # breaks the failover the zone operator
                                       # deliberately bought with it.
    cache-max-ttl: 86400
    cache-max-negative-ttl: 3600

    # === DNS REBINDING PROTECTION ======================================
    # Unbound's documented default is that NO private addresses are enabled,
    # i.e. a public name may resolve to 127.0.0.1 and unbound will hand it to
    # the client. The v1 plan had no equivalent at all: any attacker who
    # controls a zone could point evil.example at 127.0.0.1 or 192.168.1.1 and
    # use your public resolver to aim a victim's browser at the victim's own
    # loopback or LAN. These lines strip such records from answers.
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 127.0.0.0/8
    private-address: 0.0.0.0/8
    private-address: 100.64.0.0/10
    private-address: 192.0.2.0/24
    private-address: 198.18.0.0/15
    private-address: 198.51.100.0/24
    private-address: 203.0.113.0/24
    private-address: 255.255.255.255/32
    private-address: ::1/128
    private-address: ::/128
    private-address: fd00::/8
    private-address: fe80::/10
    private-address: 2001:db8::/32
    private-address: ::ffff:0:0/96

    # Known-legitimate publisher of RFC1918 A records. VERIFIED: a lookup of
    # 192-168-1-1.<hash>.plex.direct really does return 192.168.1.1 - that is
    # how Plex gets a valid TLS certificate for a LAN address. Without this
    # exemption, Plex remote access breaks for every one of your users.
    private-domain: "plex.direct"

    # === LOGGING =======================================================
    verbosity: 1           # NOT 0. Level 1 is operational errors plus the
                           # val-log-level bogus lines - it does not log queries.
                           # This is the value Phase Q's posture inventory must
                           # report for unbound.
    use-syslog: no         # log to stderr -> journald, NOT to syslog. Phase G's
                           # component table must match this.
    logfile: ""            # -> stderr -> journald
    log-queries: no        # PUBLIC RESOLVER: do not log client queries. See
    log-replies: no        # Phase Q for the retention/legal position.
    extended-statistics: yes   # the wider counter set Phase I's collector scrapes
                               # over the unbound-control socket
```

Then:

```bash
unbound-checkconf            # MUST print: no errors in /etc/unbound/unbound.conf
systemctl enable --now unbound
```

#### Memory budget

Configured cache is `256m + 128m + 32m + 16m = 432 MB`. Unbound's resident set runs materially above the configured cache totals — allocator slack, per-thread structures, the infra cache and the outgoing port pool are all on top. **Budget roughly 2x configured cache (~850 MB) as a planning figure and then measure**; do not treat the multiplier as exact. On a 4 GB box sharing with AdGuardHome that leaves comfortable headroom, but it is a number to verify, not assume:

```bash
systemctl show unbound -p MemoryCurrent          # bytes; run after a warm hour
unbound-control stats_noreset | grep -E 'mem\.cache|mem\.mod'
```

**Memory ceilings and swap have exactly one owner: Phase A6.** Unbound's `MemoryHigh` / `MemoryMax` are set there — not here, and not in Phase E or Phase N — along with the swapfile and the `vm.swappiness` value that back them. See Phase A6 for the canonical numbers. This section sizes the *cache* and gives you the measurement A6's numbers are calibrated against; it deliberately sets no ceiling of its own. All C4 contributes is `MemoryAccounting=yes`, which is what makes the `MemoryCurrent` reading above available in the first place.

#### File descriptors

`outgoing-range: 8192` x `num-threads: 2` needs roughly 16k descriptors for the outgoing port pool alone. Unbound does **not** fail when it cannot get them; it logs a warning about increasing ulimit or decreasing threads/ports and **silently shrinks the port pool**, which is a direct reduction in spoofing resistance and in concurrent-query capacity. Give it room:

```bash
mkdir -p /etc/systemd/system/unbound.service.d
printf '[Service]\nLimitNOFILE=65535\n' > /etc/systemd/system/unbound.service.d/nofile.conf
systemctl daemon-reload
```

#### Outgoing port randomisation

Unbound randomises the source port of every outgoing query across the full range by default; the only port it avoids out of the box is port 0. There is nothing to enable. What you must protect is the *size* of the pool — that is the `LimitNOFILE` item above — because a shrunken pool is a smaller keyspace for an off-path attacker to guess.

One ordering hazard worth knowing: unbound claims its outgoing ports at startup, and Phase E starts AdGuardHome *after* unbound. If unbound happens to grab a port AdGuardHome later needs to bind (3000 for the admin UI, 8053 for the loopback HTTPS listener), AdGuardHome fails to bind and the failure looks unrelated. The guard is `outgoing-port-avoid`, which excludes ports from the outgoing pool:

```conf
    # UNVERIFIED for 1.19.2 syntax on this exact build - `unbound-checkconf`
    # will reject it immediately if the directive name is wrong on your version.
    outgoing-port-avoid: "3000"
    outgoing-port-avoid: "8053"
```

This is an ergonomic guard against a rare startup collision, not a security control. If `unbound-checkconf` rejects it, drop the lines and instead confirm at boot that AdGuardHome bound successfully (Phase E's verification already does).

#### serve-expired and RFC 8767

RFC 8767 section 7 states the rule plainly: stale data is used **only when refreshing has failed**. Serving stale on the happy path is a wrong answer produced with nothing broken anywhere.

Unbound's `serve-expired: yes` on its own does *not* implement RFC 8767. Its manpage describes it as serving old responses "without waiting for resolution completion" — that is stale-first. The section that turns it into RFC 8767 behaviour is `serve-expired-client-timeout`, documented as enabling "the serve-stale behavior as specified in RFC 8767 that first tries to resolve before immediately responding with expired data". **Its default is 0 in both 1.13.1 and 1.19.2, so it must be set explicitly.** 1800 ms is the RFC's recommended client response timer — "just under a common timeout value of 2 seconds".

The v1 plan's SmartDNS equivalent (`serve-expired-ttl 86400`, `serve-expired-reply-ttl 5`) violated this twice: it served stale immediately with no refresh attempt, and it advertised a 5-second reply TTL where RFC 8767 s4 recommends 30. SmartDNS has no client-response-timer equivalent at all, which is independently sufficient reason to be off it.

> **Name the cost.** This is a tradeoff, not a free win. Before: a client whose entry has expired gets an instant, possibly stale answer. After: during an upstream or authoritative incident, that client waits **up to 1.8 seconds per query** before the stale answer is released. That is what the RFC specifies and it is the correct default for a resolver whose whole value proposition is answer correctness, but it *will* be visible during any degradation. Budget for it in the Phase H load test, and be ready to explain it in the runbook — "the resolver got slow" during an incident is the expected shape of this setting working.

`ede-serve-expired: yes` makes that visible to the client as `EDE: 3 (Stale Answer)` rather than as an unexplained slow response.

#### DNS 0x20 (`use-caps-for-id`)

`use-caps-for-id: no` is unbound's default and the right setting here. 0x20 randomises the case of the QNAME in outgoing queries and requires the answer to echo it back, adding entropy against off-path spoofing. Two reasons to leave it off:

- With DNSSEC validation active, signed zones already get far stronger protection from the signature check than 0x20's handful of extra bits provide.
- It breaks against authoritative servers that do not preserve query case. Such servers still exist. Unbound falls back for a name it detects as broken, but the fallback costs a retry and the detection is not free.

An honest note on how often it breaks: **quantified breakage rates are not something this plan verified**, and published figures vary widely by measurement vintage. Treat "it breaks a small but nonzero set of zones, and you will not know which until a user complains" as the operational summary. If you enable it, do so in a maintenance window and watch `unbound-control stats_noreset | grep num.query.tcp` and the SERVFAIL counter for a step change.

#### DNS cookies (`answer-cookie`) — deliberately not set

RFC 7873/9018 cookies are available on 1.19.2 (`answer-cookie`, default no; `cookie-secret`; `ip-ratelimit-cookie`, default 0). **Enabling them on this listener buys nothing.** Unbound's only client is AdGuardHome, over loopback, on a socket no off-path attacker can reach. Cookies defend a *public* UDP listener, and this one is not public.

The real cookie gap is at the public edge: AdGuardHome implements no DNS cookies, so plain Do53 to your service has no cookie protection. That is a Phase E / security-phase matter, not something Unbound can fix from behind the gateway. Record it in the runbook as a known limitation and steer users to DoT/DoH/DoQ, which are connection-oriented and not spoofable. Do not try to close it by moving Unbound to the public edge — `access-control` is global rather than per-listener (see the comment in the config), and moving plain Do53 off AdGuardHome would blind the Phase J abuse pipeline for exactly the traffic class that gets abused.

#### Rate limiting on the recursive leg

Two knobs exist and only one of them is appropriate:

- **`ip-ratelimit` — do not set it.** It is per-source-IP, and this daemon's only source IP is `127.0.0.1`. Setting it rate-limits your own gateway.
- **`ratelimit`** is per-zone, capping queries unbound sends to a given zone's authoritative servers. That *is* the right shape for blunting a random-subdomain flood that gets past AdGuardHome's limiter. Default is 0 (off). If you enable it, understand that too low a value produces SERVFAILs for large legitimate zones:

```conf
    # ratelimit: 1000    # per-zone outgoing qps. Measure your normal per-zone
                         # peak before enabling; start well above it.
```

Leave it off at go-live. `aggressive-nsec` is the primary structural defence against random-subdomain floods and is already on; add `ratelimit` only if Phase I observability shows a zone-directed flood actually reaching the recursive leg.

#### One cross-phase edit this section forces

AdGuardHome's unit in the v1 plan carries `Requires=smartdns.service` and `After=network-online.target smartdns.service`. systemd **fails the job** when a `Requires=` unit cannot be loaded, so once SmartDNS is deleted AdGuardHome will not start at all. The corrected unit is Phase E's to own — see Phase E — and it expresses the resolver dependency as `Wants=` plus `After=`, never `Requires=`, per the canonical restart policy in C4: a `Requires=` between the gateway and the resolver propagates a stop and turns a single-daemon restart into a stack-wide outage. If you are executing phases in order, note that Phase E must be applied before AdGuardHome will come up again.

The firewall needs no change: Phase B's `tcp/udp dport 5335 drop` sits after `iif lo accept`, and AdGuardHome's `upstream_dns: 127.0.0.1:5335` is unchanged.

**Verify C2**

```bash
unbound-checkconf                                     # "no errors in ..."
ss -lnup 'sport = :5335'; ss -lntp 'sport = :5335'    # unbound only, loopback only
unbound-control status | grep -E 'version|threads|modules'   # modules: validator iterator
unbound-control get_option edns-buffer-size           # 1232
unbound-control get_option max-udp-size               # 1232
unbound-control get_option qname-minimisation         # yes
systemctl show unbound -p LimitNOFILE                 # 65535
journalctl -u unbound --since '5 min ago' | grep -i 'ulimit\|outgoing port' \
  || echo 'no fd warnings'

# Rebinding protection is present at the CONFIG level. This check cannot fail
# open; the live probe in C5 can.
grep -c '^ *private-address:' /etc/unbound/unbound.conf.d/10-public-resolver.conf   # 18
grep -c '^ *private-domain:'  /etc/unbound/unbound.conf.d/10-public-resolver.conf   # 1
```

---

### C3. DNSSEC trust anchor lifecycle

Everything in C2 rests on one 400-byte file: `/var/lib/unbound/root.key`. If it is empty, truncated or stale, unbound does not fail loudly — it **SERVFAILs every lookup on the box**, and because Phase B blocks external access to :5335 the symptom presents as "the whole service is down" with no obvious cause. Debian bug #989959 exists with exactly the title "unbound: Corrupt/empty trust anchor file is not healed upon start": unbound does not repair the file on its own.

Three ways it goes wrong:

1. An interrupted write (power loss, OOM kill, snapshot taken mid-write) leaves the file zero-length.
2. The box is off or the daemon is stopped across a root KSK rollover, so RFC 5011 tracking misses the window and the stored anchor no longer matches the root.
3. A VM snapshot is restored from before a rollover.

#### Do not declare `auto-trust-anchor-file` yourself

The package already sets it. A second declaration is a known breakage. Confirm there is exactly one — noting that `grep -rc` prints a **per-file** count and never a total, so the obvious command cannot express the assertion:

```bash
cat /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf
# server:
#     auto-trust-anchor-file: "/var/lib/unbound/root.key"

grep -rhc 'auto-trust-anchor-file' /etc/unbound/ | paste -sd+ - | bc   # must print 1
```

#### Bootstrap once, before unbound first starts

```bash
systemctl stop unbound 2>/dev/null || true
install -d -o unbound -g unbound -m 0755 /var/lib/unbound
unbound-anchor -a /var/lib/unbound/root.key -v || true
chown unbound:unbound /var/lib/unbound/root.key
chmod 0644 /var/lib/unbound/root.key
systemctl start unbound
```

Two traps in that block:

- **Pass `-a` explicitly.** The default anchor path is not portable across the base-image change this plan makes: 22.04's `unbound-anchor` defaults to `/var/lib/unbound/root.key`, **24.04's defaults to `/usr/share/dns/root.key`**. Relying on the default writes the wrong file on noble.
- **Never gate a script on `unbound-anchor`'s exit code.** Its manpage is counter-intuitive and exact: it exits **1** if the anchor was updated from the certificate or the built-in anchor was used, and **0** if no update was necessary, if RFC 5011 tracking sufficed, **or if an error occurred**. Success and failure share exit 0. Check the file instead — that is why the `|| true` is there and why `-s` appears in every check below.

Also check what the packaged unit already does for you:

```bash
systemctl cat unbound | grep -i 'ExecStartPre'
```

Ubuntu ships `/usr/libexec/unbound-helper`, and the packaged unit typically invokes it with a `root_trust_anchor_update` argument before start. **Read the actual output on your box rather than assuming** — if such a line is present, bootstrap-at-start is already covered and the guard below covers the running-daemon case only.

#### Do NOT run `unbound-anchor` on a timer against a live server

This is the trap that a naive "refresh it weekly" cron walks straight into. Once `auto-trust-anchor-file` is set, **unbound performs RFC 5011 tracking itself and rewrites `/var/lib/unbound/root.key` in place**. A weekly `unbound-anchor` run puts a *second concurrent writer* on the very file you are trying to protect from interrupted writes. `unbound-anchor(8)` says to run it "Before you start the unbound(8) DNS server" — it is a bootstrap tool, not a maintenance tool.

Replace the refresh timer with a **detect-and-heal** unit that acts only when validation has actually stopped working.

`/usr/local/sbin/unbound-anchor-guard.sh`:

```bash
#!/bin/bash
set -uo pipefail
KEY=/var/lib/unbound/root.key
ok=1
[ -s "$KEY" ] || ok=0
dig @127.0.0.1 -p 5335 . DNSKEY +dnssec +time=3 +tries=1 2>/dev/null \
  | grep -q '^;; flags:.* ad' || ok=0
[ "$ok" = 1 ] && exit 0
logger -t unbound-anchor "anchor unhealthy - re-bootstrapping"
systemctl stop unbound
unbound-anchor -a "$KEY" -r /usr/share/dns/root.hints -v || true
[ -s "$KEY" ] || { logger -t unbound-anchor "FATAL: root.key still empty"; exit 1; }
chown unbound:unbound "$KEY"; chmod 0644 "$KEY"
systemctl start unbound
```

`/etc/systemd/system/unbound-anchor-guard.service`:

```ini
[Unit]
Description=Detect and heal a broken DNSSEC root trust anchor
After=network-online.target unbound.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/unbound-anchor-guard.sh
```

`/etc/systemd/system/unbound-anchor-guard.timer`:

```ini
[Unit]
Description=Daily DNSSEC trust anchor health check

[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
chmod +x /usr/local/sbin/unbound-anchor-guard.sh
systemctl daemon-reload && systemctl enable --now unbound-anchor-guard.timer
```

This covers all three failure modes, heals instead of racing, and keys off the *symptom* (validation stopped producing the AD flag) rather than assuming a calendar refresh is sufficient.

#### Detecting the state before it bites

The daily guard is the backstop. The fast detector belongs in `/etc/cron.d/dns-health`, which **Phase I creates** — append these two lines to that file rather than dropping a second cron file beside it, and let Phase I's `/usr/local/sbin/notify.sh` own the escalation off the box; `logger` here is the local audit trail, not the pager. **Use the root zone, not a third-party test zone** — a five-minute check against a university-run domain fires 288 queries a day at someone else's infrastructure and pages you whenever *their* zone or its network path is down:

```bash
*/5 * * * * root dig @127.0.0.1 -p 5335 . DNSKEY +dnssec +time=2 +tries=1 2>/dev/null | grep -q '^;; flags:.* ad' || echo "DNSSEC VALIDATION BROKEN (trust anchor?)" | logger -t dns-alert
0 6 * * * root [ -s /var/lib/unbound/root.key ] || echo "root.key EMPTY" | logger -t dns-alert
```

Add `/var/lib/unbound/root.key` to the Phase K backup set.

**Verify C3**

```bash
grep -rhc 'auto-trust-anchor-file' /etc/unbound/ | paste -sd+ - | bc   # 1
test -s /var/lib/unbound/root.key && echo ANCHOR-OK
stat -c '%U:%G %a %s' /var/lib/unbound/root.key    # unbound:unbound 644, non-zero

# `unbound-control status` does NOT report trust-anchor state - it prints
# version, threads, modules, uptime. Use get_option:
unbound-control get_option auto-trust-anchor-file  # /var/lib/unbound/root.key

# The guard must NOT touch a healthy anchor
systemctl list-timers unbound-anchor-guard.timer --all
MT=$(stat -c %Y /var/lib/unbound/root.key)
/usr/local/sbin/unbound-anchor-guard.sh; echo "exit=$?"          # 0
[ "$MT" = "$(stat -c %Y /var/lib/unbound/root.key)" ] && echo 'GUARD-DID-NOT-TOUCH-FILE'
journalctl -t unbound-anchor --since '5 min ago'                 # empty on a healthy box

# Fault injection - run ONCE, in a maintenance window, to prove it heals
# systemctl stop unbound && : > /var/lib/unbound/root.key && systemctl start unbound
# dig @127.0.0.1 -p 5335 . DNSKEY +dnssec | grep ' ad'   # expect NO 'ad' - broken
# /usr/local/sbin/unbound-anchor-guard.sh
# dig @127.0.0.1 -p 5335 . DNSKEY +dnssec | grep ' ad'   # 'ad' is back
```

---

### C4. Hardened systemd unit

**Phase E owns the shared rationale for systemd sandboxing** — which options are safe, which brick a service, and why `CapabilityBoundingSet=` is belt-and-braces rather than a door being closed. Read that first; this section covers only what is specific to Unbound and where it *deviates* from the AdGuardHome unit.

#### Override with a drop-in, never a replacement file

The v1 plan wrote `/etc/systemd/system/smartdns.service` as a full replacement for the unit the `.deb` installed, and that is exactly the trap the ops review found: an upstream package upgrade that changes `ExecStart` or adds a required `ExecStartPre` gets masked by your stale copy, and the service either stops working or silently stops being upgraded at all.

Unbound is a distro package with a maintained unit at `/usr/lib/systemd/system/unbound.service` that includes `ExecStartPre` helpers and `Type=notify`. **Do not copy it. Do not replace it.** Add drop-ins under `/etc/systemd/system/unbound.service.d/`, which merge on top and let package updates through:

```bash
mkdir -p /etc/systemd/system/unbound.service.d
```

You already created `nofile.conf` there in C2 for the descriptor limit alone. Everything else goes in `hardening.conf`, and that filename is canonical for this stack: `/etc/systemd/system/unbound.service.d/hardening.conf` is *the* Unbound unit drop-in for sandboxing and restart policy, and **Phase N's restart/StartLimit settings go into this same file**. There is no `ha.conf` and no `dns-node.conf`; any reference to either is stale and should be read as meaning this file.

```ini
# /etc/systemd/system/unbound.service.d/hardening.conf
[Unit]
# systemd's default is to give up permanently after 5 restarts in 10s. On a
# resolver that turns a transient crash into an outage that lasts until someone
# notices. Widen the window. These four values (with Restart/RestartSec below)
# are the CANONICAL restart policy for every daemon in this stack - Phase N adds
# nothing beyond them and must not contradict them.
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Restart=always
RestartSec=5
# Accounting ONLY - no ceiling here. MemoryHigh/MemoryMax for unbound belong to
# Phase A6; this line is what makes them measurable. See the C2 memory budget.
MemoryAccounting=yes

# --- filesystem ---
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
# ProtectSystem=strict makes /run read-only, but the shipped remote-control.conf
# puts the control socket at /run/unbound.ctl and the pidfile at /run/unbound.pid
# - both directly in /run, so a narrower RuntimeDirectory= does not cover them.
# If you want /run narrowed, move both with `control-interface:` and `pidfile:`
# first, then tighten this line.
ReadWritePaths=/var/lib/unbound /run
UMask=0077

# --- kernel / namespace ---
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes

# AF_UNIX is MANDATORY - it is the unbound-control socket, and without it every
# unbound-control command in this plan fails. AF_NETLINK is needed for interface
# enumeration.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@mount @obsolete @reboot @swap @module @raw-io
# EPERM instead of the default SIGSYS termination: during burn-in a missing
# syscall becomes a logged error rather than a mystery crash-loop. Remove this
# line once the service has run clean for a week.
SystemCallErrorNumber=EPERM
```

Note what is deliberately **absent** from `[Unit]`: any `Requires=` naming another daemon in this stack. A `Requires=` between the resolver and the gateway propagates a stop in the direction you did not intend, so restarting one takes the other down with it. Where ordering genuinely matters it is expressed as `Wants=` plus `After=` — see the cross-phase note at the end of C2, and Phase E's AdGuardHome unit, which follows the same rule.

#### The two deviations from Phase E's AdGuardHome unit, and why

**1. No `User=` line.** The packaged unit starts unbound as root and unbound drops to the `unbound` account itself via the `username: "unbound"` directive in C2. That is the distro-supported path, the `ExecStartPre` helpers expect it, and within milliseconds of start the process is unprivileged anyway. Forcing `User=unbound` here means also setting `username: ""` in the config and hoping the `ExecStartPre` helpers still work — extra moving parts for no meaningful gain. Confirm the drop actually happened (C5).

**2. No aggressive `CapabilityBoundingSet=`, and no `~@privileged` in the syscall filter.** This is the direct consequence of deviation 1. A root-start-then-drop daemon needs `CAP_SETUID`/`CAP_SETGID` to perform the drop; an empty bounding set — which *is* correct for a daemon started directly as an unprivileged user — prevents it. If you want a bounding set anyway:

```ini
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_RESOURCE
```

> **This is the single line in this unit most likely to brick the service.** Add it separately from everything else, restart, and check `journalctl -u unbound` for a setuid/setgid failure. If unbound will not start or stays running as root, delete this line first before debugging anything else. `CAP_NET_BIND_SERVICE` is listed for symmetry only — unbound binds 5335, above 1024, and does not need it. If anyone ever moves this listener below port 1024, that changes.

Likewise, `SystemCallFilter=~@privileged` is deliberately absent: it risks the privilege-drop path for a defence that `NoNewPrivileges` and the non-root steady state already provide. `~@resources` is absent because unbound legitimately calls `setrlimit` at start.

`NoNewPrivileges=yes` is **not** set here. Phase E sets it on AdGuardHome and explains why it interacts fatally with file capabilities; on a root-start-then-drop daemon it is redundant with the bounding set and adds another way to break the drop. If your local policy requires it, add it and verify the drop in C5 before believing it worked.

```bash
systemctl daemon-reload
systemctl restart unbound
```

**Verify C4**

```bash
systemctl is-active unbound
systemd-analyze verify unbound.service            # no warnings
systemd-analyze security unbound.service | tail -20
# exposure labels: <1.0 OK, >=5.0 MEDIUM, >=7.5 EXPOSED, >=9.0 UNSAFE

# The privilege drop actually happened - this is the check people skip
ps -o pid,user,comm -C unbound                    # USER must be 'unbound', not root

# The control socket survived RestrictAddressFamilies
unbound-control status >/dev/null && echo CONTROL-OK

# The drop-in did not replace the packaged unit
ls -l /etc/systemd/system/unbound.service         # must NOT exist
systemctl cat unbound | head -3                   # first line: /usr/lib/systemd/system/unbound.service
systemctl show unbound -p DropInPaths             # nofile.conf + hardening.conf, no ha.conf

# The canonical restart policy is what actually took effect
systemctl show unbound -p Restart -p RestartSec -p StartLimitIntervalUSec -p StartLimitBurst
#   Restart=always  RestartSec=5s  StartLimitIntervalUSec=5min  StartLimitBurst=10

journalctl -u unbound -p warning --since '-10min' --no-pager
```

---

### C5. Verification

This is the acceptance test for the resolver layer, run against `127.0.0.1:5335`. End-to-end validation through the public edge — every protocol, from off-box — belongs to Phase H; do not duplicate it here.

C5.1 through C5.7 are checks. **C5.8 is the one *action* in this section** — the `/etc/resolv.conf` flip off Phase A2's bootstrap value — and it is gated on those checks passing.

#### C5.1 Recursion is real, not forwarding

`dig @127.0.0.1 -p 5335 . NS` proves **nothing**: a forwarder answers `. NS` identically. Two checks that actually distinguish the designs:

```bash
# Config-level: no forward-zone anywhere
grep -rn '^ *forward-zone:' /etc/unbound/ && echo 'FAIL: still forwarding' || echo 'RECURSIVE-OK'

# Wire-level: we must be talking to roots, TLDs and authoritatives ourselves
timeout 25 tcpdump -ni any -c 40 'udp port 53 and not host 127.0.0.1' > /tmp/rec.txt 2>&1 &
sleep 1; dig @127.0.0.1 -p 5335 "$(date +%s).nlnetlabs.nl" A >/dev/null 2>&1; wait
awk '{print $5}' /tmp/rec.txt | cut -d. -f1-4 | sort -u | head
#   PASS: root-server addresses (198.41.0.4 etc), TLD and authoritative servers
#   Under the v1 SmartDNS design this captured nothing at all - it spoke DoH on
#   tcp/443 only.
```

#### C5.2 DNSSEC positive and negative

```bash
# The verdict is OURS, not borrowed
unbound-control status | grep -E 'modules|version'   # modules: validator iterator

# Negative: a bogus signature must SERVFAIL, with an Extended DNS Error
dig @127.0.0.1 -p 5335 sigfail.verteiltesysteme.net A +dnssec +noall +comments
#   status: SERVFAIL, and a '; EDE:' line naming the validation failure
dig @127.0.0.1 -p 5335 dnssec-failed.org A +noall +comments
#   status: SERVFAIL

# Positive: a signed name must carry the 'ad' flag
dig @127.0.0.1 -p 5335 sigok.verteiltesysteme.net A +dnssec +noall +comments
#   status: NOERROR, and flags must contain 'ad'
dig @127.0.0.1 -p 5335 internetsociety.org A +dnssec | grep -E '^;; flags:|RRSIG' | head

# The root zone itself validates - no third-party dependency
dig @127.0.0.1 -p 5335 . DNSKEY +dnssec +noall +comments | grep '^;; flags:'   # ' ad'

# Counters agree with what you just saw
unbound-control stats_noreset | grep -E 'num.answer.secure|num.answer.bogus|num.answer.rcode.SERVFAIL'
```

> A SERVFAIL for `dnssec-failed.org` alone is **not** proof that this change landed. The v1 SmartDNS stack also returned SERVFAIL for it, because all four of its upstreams validate. The distinguishing checks are C5.1 and the `modules: validator iterator` line above.

#### C5.3 Rebinding protection

The config-level assertion in C2 is the authoritative one; it cannot fail open. The live probe below is a useful confirmation but is ambiguous on its own, so it carries a control query.

```bash
# rbndr encodes IPs as TWO hex labels: <hexA>.<hexB>.rbndr.us
#   7f000001 = 127.0.0.1   c0a80001 = 192.168.0.1
V=7f000001.c0a80001.rbndr.us
CTRL=$(dig @8.8.8.8 "$V" A +short +time=4 +tries=1 | tr '\n' ' ')
MINE=$(dig @127.0.0.1 -p 5335 "$V" A +short +time=4 +tries=1 | tr '\n' ' ')
echo "control(8.8.8.8)='$CTRL'  ours='$MINE'"
if [ -z "$CTRL" ]; then
  echo "INCONCLUSIVE: vector is down upstream - do not score this run"
elif [ -z "$MINE" ]; then
  echo "PASS: private address stripped"
else
  echo "FAIL: resolver returned $MINE for a public name"
fi
# CAVEAT: rbndr.us runs a deliberately non-conforming nameserver, and a
# validating resolver may SERVFAIL it for reasons unrelated to private-address.
# Hence the mandatory control query. Do not use `private.dns-oarc.net`,
# `1.0.0.127.rbndr.us` or the single-label `7f000001.rbndr.us` - all three
# NXDOMAIN or SERVFAIL, produce empty output, and therefore "pass" identically
# on a resolver with no rebinding protection at all.

# The plex.direct exemption: assert the config, not a lookup. Valid plex names
# are <dashed-ip>.<hash>.plex.direct, so a bare `test.plex.direct` also fails open.
unbound-control get_option private-domain 2>/dev/null || \
  grep -n 'private-domain' /etc/unbound/unbound.conf.d/10-public-resolver.conf

# Built-in special-use zones (RFC 6303/6761/7686/8375) answer locally.
# Do NOT add local-zone overrides for these - unbound already ships them.
dig @127.0.0.1 -p 5335 facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion A +noall +comments  # NXDOMAIN
dig @127.0.0.1 -p 5335 1.168.192.in-addr.arpa PTR +noall +comments   # NXDOMAIN, not a recursion
dig @127.0.0.1 -p 5335 localhost A +short                            # 127.0.0.1
```

#### C5.4 QNAME minimisation is observable

There is **no statistics counter for QNAME minimisation** in unbound — do not go looking for `num.query.qname_min`, it does not exist. Observe it on the wire instead: query a deep name and confirm the query sent to the root carries only the TLD label, not the full name.

```bash
unbound-control get_option qname-minimisation           # yes
unbound-control get_option qname-minimisation-strict    # no

unbound-control flush_zone nlnetlabs.nl
timeout 20 tcpdump -ni any -s0 -c 20 'udp port 53 and not host 127.0.0.1' -v 2>&1 > /tmp/qmin.txt &
sleep 1; dig @127.0.0.1 -p 5335 "www.nlnetlabs.nl" A >/dev/null 2>&1; wait
grep -o '[A-Za-z0-9.-]*\? A?' /tmp/qmin.txt | sort -u
#   PASS: early queries ask for 'nl.' / 'nlnetlabs.nl.' - progressively longer
#         labels. The full 'www.nlnetlabs.nl' must NOT appear in the first
#         query of the chain.
#   If tcpdump does not render the question name at your verbosity, treat this
#   as INCONCLUSIVE rather than a failure and fall back to the get_option checks.
```

#### C5.5 Aggressive NSEC, cache and prefetch

```bash
# RFC 8198: these are the real counters. Both should rise as the NSEC cache warms.
unbound-control stats_noreset | grep -E 'num.query.aggressive.NOERROR|num.query.aggressive.NXDOMAIN'

# Cache hit ratio, after an hour of real traffic
unbound-control stats_noreset | grep -E 'total.num.queries|total.num.cachehits|total.num.cachemiss|total.num.prefetch'
#   total.num.prefetch rising is the proof that prefetch has replaced the
#   deleted Phase F warmer. If it stays at 0 with steady traffic, prefetch is
#   not firing - re-check `prefetch: yes` parsed.

# Cold vs warm on the same name
unbound-control flush_zone example.com
dig @127.0.0.1 -p 5335 example.com A +noall +stats | grep 'Query time'   # cold: tens-hundreds of ms
dig @127.0.0.1 -p 5335 example.com A +noall +stats | grep 'Query time'   # warm: ~0 ms
```

#### C5.6 Serve-stale behaves per RFC 8767

Stale must **not** be served while resolution is healthy. Note: Ubuntu's default `awk` is **mawk**, which does not support the `\s` shorthand — use positional fields.

```bash
D=whoami.akamai.net
dig @127.0.0.1 -p 5335 $D A +noall +answer
TTL=$(dig @127.0.0.1 -p 5335 $D A +noall +answer | awk '{print $2; exit}')
echo "cached TTL=$TTL"; sleep $((TTL + 5))
SERVED=$(dig @127.0.0.1 -p 5335 $D A +noall +answer | awk '{print $2; exit}')
UPSTR=$(dig @1.1.1.1            $D A +noall +answer | awk '{print $2; exit}')
echo "served=$SERVED upstream=$UPSTR"
#   PASS: served is close to upstream - a genuine fresh resolution happened
#   FAIL: served == 30 - a stale record was handed out with a healthy upstream

unbound-control stats_noreset | grep -E 'num.expired'
#   must stay 0 while resolution is healthy; rises only during an incident

# EDE 3 when stale IS served: warm the name, then break egress, then query.
# `+ednsflags` is a VALUE option that SETS EDNS header flags - it does not
# display Extended DNS Errors and does not belong here. dig prints EDE in the
# comments section automatically.
dig @127.0.0.1 -p 5335 $D A +dnssec +noall +comments +answer | grep -i 'EDE'
#   expect: '; EDE: 3 (Stale Answer)'

# The latency cost of serve-expired-client-timeout: 1800 is real - measure it
dig @127.0.0.1 -p 5335 $D A +noall +stats | grep 'Query time'
```

#### C5.7 Isolation, and `unbound-control` basics

```bash
dig @127.0.0.1 -p 5335 google.com A +short          # must resolve
dig @<PUBLIC_IP> -p 5335 google.com A +time=3 +tries=1   # must FAIL / time out
nft list ruleset | grep 5335                        # Phase B rule still present

unbound-control status
unbound-control stats_noreset | head -30
unbound-control list_stubs | head                   # root hints loaded
unbound-control flush_zone example.com              # operational: flush one zone
unbound-control reload                              # re-read config without dropping cache
```

Source-port randomisation on the recursive leg cannot be checked with `ss -unp 'dst :53'` — unbound sends from unconnected UDP sockets and that filter returns nothing. Watch the wire:

```bash
timeout 20 tcpdump -ni any -c 30 'udp dst port 53 and not host 127.0.0.1' 2>/dev/null \
  | sed -n 's/.*\.\([0-9]*\) > .*/\1/p' | sort -u | wc -l    # must be many distinct ports
```

#### C5.8 Flip `/etc/resolv.conf` to the validated path

This is the last action of Phase C, and it is last on purpose.

Phase A2 wrote a **static** `/etc/resolv.conf` pointing at the provider's resolver and labelled that value bootstrap-only — it existed because Unbound did not, and it is by definition an unvalidated path. C5.1 through C5.7 have now established that this box recurses from the root, validates for itself, strips private answers and serves stale only per RFC 8767. The bootstrap value has done its job and is retired here. Flipping it any earlier would have left the host with no working resolver during the very tests that qualify the replacement.

```bash
# A2 replaced the symlink with a real file. If it is a symlink again, something
# re-took the file and this write will silently revert - fix that first.
test -L /etc/resolv.conf && echo 'FAIL: symlink is back - do not write through it'

# Clear an immutable bit only if some earlier operator set one. This plan never
# sets it - see the note below.
chattr -i /etc/resolv.conf 2>/dev/null || true
printf 'nameserver 127.0.0.1\noptions edns0 trust-ad\n' > /etc/resolv.conf

grep -c '^nameserver' /etc/resolv.conf   # 1
lsattr /etc/resolv.conf                  # no 'i' - the file stays mutable on purpose
```

**No `chattr +i`, deliberately.** The immutable bit is what you reach for when something keeps re-taking this file, and on this host nothing does: Phase A2 masked `systemd-resolved`, C1 masked `unbound-resolvconf` and set `RESOLVCONF=false`, NetworkManager is not installed on an Ubuntu Server image, and A2's post-reboot check is precisely the test for a cloud image regenerating the file — with A2's own instruction being to disable cloud-init's `resolv_conf` module if it does, rather than to fight it with `chattr`. Locking the file after every writer has already been removed buys nothing and costs something real: an immutable `/etc/resolv.conf` makes the next *legitimate* edit — a Phase K restore, a deliberate re-flip to a bootstrap value while AdGuardHome is down, an emergency change at 03:00 — fail with a bare `Operation not permitted` on a file that looks perfectly writable to root, and the person hitting that will not be you. If the `chattr -i` above actually clears a bit, something outside this plan set it; find out what before continuing.

**`127.0.0.1`, and nothing else.** No second `nameserver` line, no public resolver "just in case", no `options rotate` across two entries. glibc treats every additional nameserver as a silent fallback: the moment the local path hiccups, resolution leaves the box on an unvalidated path and *nothing tells you it happened*. A fallback entry does not buy availability here, it buys an invisible failure mode — the exact property this whole phase exists to remove. **Phase L verifies that this file contains exactly one `nameserver` and that it is `127.0.0.1`.**

> **Consequence to accept explicitly, plus an ordering hazard.** `resolv.conf` has no syntax for a port, so `nameserver 127.0.0.1` means 127.0.0.1:**53** — that is **AdGuardHome**, not Unbound on 5335. The host now eats its own dog food: `apt`, `certbot renew` (Phase D) and the Phase D deploy hook all resolve through AdGuardHome, which resolves through Unbound, and all of them fail while AdGuardHome is down. That is the correct posture for a resolver appliance — the operator's own lookups are validated and filtered exactly like a user's — but note the sequencing. AdGuardHome is **Phase E**, which has not run yet. Between this flip and Phase E's go-live the host has no resolver at all. If you are executing phases strictly in order and need working host DNS in that window, bring Phase E's AdGuardHome listener up first and then come back and run this flip. Do **not** paper over the gap with a fallback `nameserver` line.

---

### C6. What recursion costs, and what pays for it

Be honest with yourself about the trade before go-live, because the first complaint will be about latency.

**What you give up versus the v1 forwarding design:**

1. **Cold-cache latency.** A forwarder hitting a warm Cloudflare or Google cache answers in roughly 5-15 ms. Recursion from cold costs one to four round trips — root, TLD, authoritative, sometimes a CNAME chase — typically **40-300 ms**, more for distant authoritatives. Every genuinely novel name your users ask for pays this. Under DNSSEC the chain also needs DS and DNSKEY lookups, though `prefetch-key` removes one serialised hop from that.
2. **A dependency on root and TLD reachability.** Previously the only thing that had to work was a TLS connection to one of four large anycast networks. Now your service degrades if the root servers or a specific TLD's authoritatives are unreachable *from your VPS specifically* — a provider routing problem, a transit incident, or an over-eager upstream ACL will show up as partial resolution failures rather than as a clean outage. Phase I's observability and Phase N's multi-node story exist partly for this.
3. **More outbound state.** 16k outgoing ports, UDP and TCP to arbitrary internet hosts on port 53. That is a wider egress profile than four DoH endpoints, and it is why an `IPAddressAllow` egress allowlist is not an option for this daemon.

**What pays for it:**

- **`prefetch: yes` is the main mitigation and it is well matched to real traffic.** A resolver's query distribution is extremely long-tailed: a small hot set accounts for most queries, and prefetch refreshes exactly that set before expiry, so the hot set effectively never pays the cold-recursion cost. Unlike the deleted Phase F warmer, it learns the hot set from your users rather than from a list guessed in advance, and it generates no query traffic of its own.
- **`prefetch-key: yes`** removes a serialised DNSKEY fetch from the validation path on the misses that remain.
- **Cache sizing** (256m RRset / 128m msg) is deliberately generous for a 2 vCPU box. The dominant cost of recursion is the cache miss; the cheapest way to buy it back is to make misses rarer. This memory is the single highest-return line in C2.
- **`aggressive-nsec: yes`** answers a whole class of misses — nonexistent names under a signed zone — from cached NSEC/NSEC3 records with no query at all. Against random-subdomain floods this is the difference between a flood costing you one recursion per query and costing you nothing.
- **`serve-expired` with the RFC 8767 client timeout** bounds the worst case: when recursion genuinely stalls, a client waits 1.8 seconds and then gets a stale-but-labelled answer rather than a SERVFAIL.

Measure the miss cost on your own box rather than trusting the ranges above — `dig +stats` after `unbound-control flush_zone`, per C5.5 — and record the number. It is the baseline that Phase H's load test and Phase I's latency alerting are calibrated against.

---

[Plan index](../dns-server-plan.md) · [Previous: Firewall and Edge Packet Policy](./02-firewall.md) · [Next: TLS Certificates](./04-tls-certificates.md)
