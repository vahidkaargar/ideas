[Plan index](../dns-server-plan.md) · [Previous: Host Preparation](./01-host-preparation.md) · [Next: Unbound Recursive Resolver](./03-unbound-resolver.md)

---

**On this page**

- [PHASE B: Firewall and Edge Packet Policy](#phase-b-firewall-and-edge-packet-policy)
  - [B1. Remove ufw, and neutralise the reload trap](#b1-remove-ufw-and-neutralise-the-reload-trap)
  - [B2. Kernel packet-layer knobs](#b2-kernel-packet-layer-knobs)
  - [B3. What amplification this resolver actually offers, honestly](#b3-what-amplification-this-resolver-actually-offers-honestly)
  - [B4. Rate limiting that degrades correctly](#b4-rate-limiting-that-degrades-correctly)
  - [B5. The authoritative /etc/nftables.conf](#b5-the-authoritative-etcnftablesconf)
  - [B6. Optional source allowlist (machinery here, policy in Phase P)](#b6-optional-source-allowlist-machinery-here-policy-in-phase-p)
  - [B7. Certbot: a dedicated chain, never a reload](#b7-certbot-a-dedicated-chain-never-a-reload)
  - [B8. Reloading without losing ban state](#b8-reloading-without-losing-ban-state)
  - [B9. Verification](#b9-verification)

---

## PHASE B: Firewall and Edge Packet Policy

This phase owns everything the kernel does to a packet before a daemon sees it: the
nftables ruleset, conntrack sizing, ingress and egress rate limiting, and the ban-set
lifecycle. Three properties matter more than the rule list itself, and all three were
broken in v1:

1. **UDP/53 must not be conntracked.** Tracking it is what makes a modest flood take
   SSH down with it.
2. **Once it is not conntracked, `ct state established,related accept` no longer covers
   it.** The explicit DNS accepts become load-bearing, not defence in depth.
3. **A ruleset reload must not wipe the Phase J ban sets.** `/etc/nftables.conf` starts
   with `flush ruleset`; `nftables.service`'s own `ExecReload` is exactly that command.
   v1's certbot open/close dance therefore unbanned every live abuser twice a month.

Target: Ubuntu 24.04 LTS, nftables 1.0.9, kernel 6.8. Directive spellings below were
checked against noble's `nft(8)`; the places where I am not certain a form parses on your
build are marked UNVERIFIED with the check that settles it. `nft -c -f
/etc/nftables.conf` settles all of them at once and is mandatory before every apply
regardless.

---

### B1. Remove ufw, and neutralise the reload trap

v1's Phase A installed `ufw` alongside `nftables`. Both want to own the ruleset. `ufw`
on noble writes its own tables through the iptables-nft shim, and `flush ruleset` in
`/etc/nftables.conf` deletes them silently — you get a firewall whose contents depend on
service start order. Pick one; for a hand-written ruleset this dense, `ufw` is not it.

```bash
systemctl disable --now ufw 2>/dev/null || true
apt purge -y ufw
apt install -y nftables conntrack jq
systemctl enable nftables
```

`conntrack` (the CLI) is not installed by default and every verification step in B9
needs it. `jq` is needed by the reload script in B8.

Next, make `systemctl reload nftables` safe. Stock `nftables.service` has
`ExecReload=/usr/sbin/nft -f /etc/nftables.conf`, which flushes the ruleset and takes
the ban sets with it. Redirect it at the state-preserving wrapper built in B8:

```bash
install -d -m 0755 /etc/systemd/system/nftables.service.d
cat > /etc/systemd/system/nftables.service.d/override.conf << 'EOF'
[Service]
# Stock ExecReload is `nft -f /etc/nftables.conf`, which begins `flush ruleset`
# and destroys banned_ips/banned_ips6. Route reloads through the wrapper.
ExecReload=
ExecReload=/usr/local/sbin/nft-apply
EOF
systemctl daemon-reload
```

`systemctl restart nftables` is still destructive (`ExecStop` flushes, then the fresh
`ExecStart` reloads from file). Treat restart as a cold-boot-equivalent operation and
never use it for edits.

If Phase J's fail2ban is in play, pin it to the nftables backend
(`banaction = nftables[type=multiport]` in `jail.local`) so you do not end up with
fail2ban rules in an iptables-nft table that this file's `flush ruleset` erases without
fail2ban noticing. See Phase J.

Verification:

```bash
dpkg -l ufw 2>/dev/null | grep -q '^ii' && echo 'FAIL: ufw still installed' || echo 'PASS: ufw gone'
systemctl cat nftables | grep -A2 '^ExecReload'   # must show the override, not `nft -f`
```

---

### B2. Kernel packet-layer knobs

Two facts drive this block.

**nf_conntrack sizing.** `nf_conntrack_init_start()` picks `htable_size = 65536` for
1 GB < RAM <= 4 GB and, when the operator has not set `hashsize`, `max_factor = 1` —
so the stock `nf_conntrack_max` on a 4 GB VPS is **65536**, not the 262144 people
assume. Setting `hashsize` at all flips `max_factor` to 8, so specifying the kernel's
own default bucket count and then pinning `nf_conntrack_max` by sysctl gives an average
hash chain length of 4 rather than 8. The bucket count is a **module parameter** and is
set here; `nf_conntrack_max` and every other `net.netfilter.*` key is a **sysctl** and
belongs to Phase A5 — see the ownership note in the block below.

**The table is filled by traffic that is entirely within policy.** This is the point
v1 missed, and it is not an abuse scenario. With the per-source limiter at 100 q/s,
twenty-two well-behaved clients at their full allowance, multiplied by the 30 s
`nf_conntrack_udp_timeout`, is 66,000 entries — over the real ceiling. Once full the
kernel logs `nf_conntrack: table full, dropping packet` and refuses *new* flows
indiscriminately: your SSH session, certbot's ACME connection, and every DoT/DoH
handshake die together, and you have no way back in. Only NOTRACK fixes that.

A related claim from the v1-era analysis is wrong and should not be repeated: dropping a
packet anywhere on the input path — v1's limiter sat at `hook input priority -1` — does
**not** leak a conntrack slot. `nf_conntrack_in()` at PREROUTING allocates an *unconfirmed*
entry which is only inserted into the hash table by `nf_conntrack_confirm()` at LOCAL_IN
with priority `INT_MAX`, i.e. after every filter chain. A dropped packet's unconfirmed
entry dies with the skb. The limiter's position is therefore not a conntrack question at
all, and with NOTRACK in place there is no CPU argument for hoisting it to `raw` either.
That frees the placement to be decided on the grounds that do matter — legibility and
rule ordering — which is why B5 makes it a jump target inside the input chain rather than
a base chain of its own.

```bash
# Bucket count only. `hashsize` is a MODULE PARAMETER, not a sysctl, so it is
# Phase B's to own and it cannot collide with Phase A's sysctl file. Keeping
# the kernel's own default value while setting it explicitly flips
# max_factor 1 -> 8; Phase A5's net.netfilter.nf_conntrack_max = 262144 then
# pins max, giving an average chain length of 4 rather than 8.
echo 'options nf_conntrack hashsize=65536' > /etc/modprobe.d/nf_conntrack.conf

cat > /etc/sysctl.d/99-nftables-edge.conf << 'EOF'
# Firewall-layer knobs ONLY.
#
# OWNERSHIP: Phase A owns /etc/sysctl.d/99-dns.conf and is the sole writer of
# every net.netfilter.nf_conntrack_* key and of net.ipv4.ip_local_port_range.
# See Phase A5 for those values and the reasoning behind them. THIS file owns
# the edge knobs, net.ipv4.tcp_syncookies among them -- Phase A does not set
# it, so if it is missing here it is missing everywhere. Nothing in this file
# may name a key that appears there: sysctl.d applies in lexical order, last
# wins, so a duplicated key is a silent divergence between the file you are
# reading and the kernel you are running.
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF

sysctl --system
```

Do **not** add a `modules-load.d` entry for `nf_conntrack` here. Phase A5 already ships
`/etc/modules-load.d/conntrack.conf` and runs `modprobe nf_conntrack`, for exactly the
reason that matters to this phase: the `net.netfilter.*` keys do not exist until the
module is loaded, so on a cold boot `sysctl --system` silently skips them and you run on
defaults you believe you replaced. Two modules-load files naming the same module is
harmless but it hides which phase is responsible when one of them is deleted.

`net.ipv4.conf.all.rp_filter` is deliberately **not** set. The effective value is
`max(all, <iface>)`, so writing `all` forces *strict* reverse-path filtering on every
interface. That is correct on a single-homed VPS and breaks the day someone attaches a
floating IP or a second uplink. If you want it, set it per-interface.

Verification (must survive a reboot — that is the whole point of Phase A's modules-load
file). The conntrack values are read here, not written here: if they are wrong the fix is
in Phase A5, and a wrong `nf_conntrack_buckets` is the fix in this section.

```bash
# Written by this phase:
sysctl net.netfilter.nf_conntrack_buckets  # 65536, from /etc/modprobe.d/nf_conntrack.conf
sysctl net.ipv4.tcp_syncookies net.ipv4.tcp_synack_retries \
       net.ipv4.conf.all.accept_redirects                          # 1 / 2 / 0

# Written by Phase A5, depended on by B3/B4. Read-only check:
sysctl net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_udp_timeout
# expected after: 262144 / 10   (before Phase A's change: 65536 / 30)

# No key may be written twice across the two files:
grep -h '^[a-z]' /etc/sysctl.d/99-dns.conf /etc/sysctl.d/99-nftables-edge.conf \
  | cut -d= -f1 | tr -d ' ' | sort | uniq -d
#   must print nothing. Any output is an ownership violation -- delete the copy
#   in whichever file does not own the key.

reboot
sysctl net.netfilter.nf_conntrack_max      # must still read 262144
```

---

### B3. What amplification this resolver actually offers, honestly

An open recursive resolver is a reflector. You cannot stop source spoofing — you are not
the origin, BCP38 is somebody else's router's job. Everything below caps what an attacker
can *extract* from you and keeps your own uplink and kernel alive while it happens. Put
that sentence in the runbook so nobody spends a day hunting the spoofer.

**The factor.** A query is ~65 bytes on the wire (20 IP + 8 UDP + 12 DNS header +
~10 QNAME + 4 QTYPE/QCLASS + 11 OPT). Measured response sizes, `+dnssec`, EDNS buffer
4096:

| Query | DNS message | On wire | Factor |
|---|---|---|---|
| `isc.org DNSKEY` | 299 B | 327 B | ~5x |
| `dnsviz.net DNSKEY` | 491 B | 519 B | ~8x |
| `org DNSKEY` | 895 B | 923 B | ~14x |
| `. DNSKEY` | 1139 B | 1167 B | ~18x |
| attacker-hosted 4 KB TXT | 4096 B | 4124 B | **~63x** |
| US-CERT TA13-088A canonical | 3223 B | — | ~50x |

At 500 QPS of forged queries against the last row you emit ~16 Mbit/s at a third party
and your provider null-routes you.

**`refuse_any: true` is near-worthless here, and you should set it anyway.** It kills the
classic ANY vector, which is why you set it (Phase E). It does not reduce the factor,
because a *recursive* resolver will happily fetch whatever the attacker asks for: he
registers a domain, publishes a 4 KB TXT record in a zone he controls, and queries that.
No configuration on your side prevents recursion from doing its job.

**Phase C's `max-udp-size: 1232` does not cap this.** That setting bounds Unbound's
responses, and Unbound's only client is AdGuardHome over loopback. AdGuardHome exposes no
UDP buffer knob at all, so the client-facing leg still honours a 4096-byte EDNS request
and re-serialises the full answer to the public client. The 1232 cap is a fragmentation
fix on the recursion leg; it is not an amplification control. Do not let the presence of
that line in Phase C convince anyone this is handled.

**Neither daemon implements RRL.** AdGuardHome's `ratelimit` counts and drops; it has no
SLIP and no truncation. AdGuardHome issue #7183 ("AGH is non-compliant with RFC 7873 and
RFC 9018 DNS Cookies") is open, so there are no DNS cookies at the edge either. Unbound
1.19.2 *does* have `answer-cookie`, `ip-ratelimit` and `ip-ratelimit-cookie` — and all
three are unreachable in this architecture, because Unbound sits behind AdGuardHome on
loopback and every client it sees is 127.0.0.1. The one Unbound knob that still earns its
place is `ratelimit` (per-zone, on the outgoing recursion path), which blunts
random-subdomain floods; that is a Phase C setting, see Phase C.

**What this phase actually configures, in order of what it buys you:**

| Control | Where | Buys |
|---|---|---|
| NOTRACK on UDP/53 + 853 | B5, `table inet raw` | Survivability. The box stays reachable under flood. |
| Egress RRL per destination | B5, `inet filter` / `chain output` | Caps what any single victim receives, even when the source is forged. This is the closest thing to real RRL available without new software. |
| Absolute egress byte cap | B5, `inet filter` / `chain output` | Protects your uplink and your provider relationship. Blunt, but it never fails open. |
| Ingress per-source flood meter + in-datapath ban + global backstop | B5, `inet filter` / `chain dns_guard` | Bounds non-spoofed abuse, bans the offender for the Phase J duration, and caps total UDP/53 pps. Fails open against spoofing — see B4. |
| Source allowlist | B6 (optional) | Shrinks the reachable victim set to your own networks, and exempts its members from flood detection and banning entirely. Not authentication. |

**What this phase names but does not configure:**

- **dnsdist in front of AdGuardHome**, the only way to get genuine RRL with TC=1 in this
  software set. Sketch and its cost are in B4. It is an escalation, not the plan.
- **Withdrawing public plain DNS** (`dns.bind_hosts: [127.0.0.1, ::1]` plus deleting the
  `udp dport 53 accept` rule). DoT and DoH are TCP, and DoQ has RFC 9000 §8.1 address
  validation with a hard 3x ceiling, so this takes amplification surface to zero. It is
  also a product decision that invalidates the Phase H plain-DNS tests and the Phase L
  "53 open" line — decide it in Phase P, do not land it as a config edit here.

---

### B4. Rate limiting that degrades correctly

**A silent drop is the wrong failure mode, and it is the only one nftables can produce.**
`drop` is a verdict; there is no way to make the kernel emit a truncated DNS response.
A legitimate client behind CGNAT that trips the limit is indistinguishable at the packet
layer from an attacker, and it experiences the limiter as unattributable packet loss —
it retries, which puts it further over the limit. The correct degradation is TC=1: a
~40-byte response with the truncate bit set, which costs the attacker his amplification
(factor drops to roughly 1.2x) and costs the legitimate client one round trip as it
retries over TCP. Only dnsdist can do that here.

Given that, the design rule for the kernel limiter is: **it must sit clearly above the
userspace limiter, so it only fires on volumes that are unambiguously abusive.** v1 set
the nft per-IP limit to 100/s while Phase E's `dns.ratelimit` was also 100 — so the two
stacked, the kernel pre-empted userspace at random, and traffic you intended to have
rate-limited in userspace was silently dropped in the kernel instead.

**Invariant, stated once and referenced everywhere else in this plan:**

> `nft per-source flood threshold >= 4 x AdGuardHome dns.ratelimit`.
> Canonical values: AdGuardHome `dns.ratelimit: 100` (Phase E), nftables per-source flood
> threshold **400/s** (B5, `chain dns_guard`). If Phase E raises `dns.ratelimit`, raise
> B5's number in the same change or the two limiters stack again. B9 has a command that
> checks it mechanically.

There is exactly **one** kernel per-source meter, `floodmeter4`/`floodmeter6` at 400/s.
Do not add a second, lower kernel meter alongside it: anything at or near Phase E's 100
q/s reproduces the v1 stacking bug in a new place.

Two properties of AdGuardHome's limiter shape what the kernel one has to cover:

- **It is UDP-only.** `dns.ratelimit` does not apply to TCP/53, DoT, DoH or DoQ. The
  kernel meter is likewise UDP/53-only — metering a TCP or QUIC handshake by packet rate
  drops connections rather than queries. Abuse over those transports is handled by the
  ban sets, which `chain input` applies to every protocol, not by rate.
- **It counts per prefix, not per address.** Phase E sets
  `ratelimit_subnet_len_ipv4: 32` and `ratelimit_subnet_len_ipv6: 64`. The v4 kernel
  meter keys on the full address, which is the same thing as /32, so the two agree
  without further work. For v6 they only agree if the kernel meter is keyed on the /64 —
  see the masked-key form below.

**The per-source meter fails open under spoofing, by design of the datapath.** In
`net/netfilter/nft_dynset.c`, `nft_dynset_eval()` ends with
`if (!priv->invert) regs->verdict.code = NFT_BREAK;` when `set->ops->update()` returns
NULL because the set is full. `NFT_BREAK` aborts *that rule* — evaluation continues to
the next rule. A spoofed flood mints a fresh key per packet and fills a 262144-entry set
in well under a second, after which the per-source rules match nothing. Two consequences:

- Raising `size` buys seconds, not safety. 262144 is chosen as a reasonable ceiling for
  the memory cost, not because it is enough.
- Because `NFT_BREAK` continues evaluation, a **global backstop rule placed after the
  per-source rules still runs.** That backstop is the real floor, and it is the reason
  the rule order in B5 is not arbitrary.

**Use `update`, not `add`.** `nft_dynset_eval()` refreshes an element's expiration only
for `NFT_DYNSET_OP_UPDATE`. With v1's `add`, a sustained abuser's meter expires
mid-attack and his budget resets.

**IPv6 per-address metering is structurally weak.** An attacker with a routed /64 has
2^64 keys and fills `floodmeter6` at will. The fix is to key the meter on the /64 prefix
rather than the address — which is also the length Phase E already uses for
`ratelimit_subnet_len_ipv6`, so this is the form that makes the two limiters agree:

```nft
    # UNVERIFIED on nftables 1.0.9: masked payload as a dynset key.
    # Gate it on `nft -c -f /etc/nftables.conf` before adopting.
    set floodmeter6 { typeof ip6 saddr and ffff:ffff:ffff:ffff:: ; flags dynamic, timeout; timeout 10m; size 262144; }
```

If that does not parse on your build, keep the plain `type ipv6_addr` set from B5 and
accept that IPv6 is covered only by the global backstop, the ban sets and the egress RRL.
Do not ship a form you have not `nft -c`'d.

**Metering and banning must be one rule, in one table.** The flood rule does not just
drop; it also adds the offender to `banned_ips` so that the ban applies to every
subsequent packet on every protocol, not only to the UDP flood. That in-datapath
`add @banned_ips` is legal **only because the meter and the set are in the same table** —
`add @set` is table-scoped in the kernel, and a rule in one table referencing a set in
another fails at load. This is why B5 has a single `table inet filter` and no separate
rate-limiting table; see Phase J, which reached the same conclusion from the abuse side
and owns the ban duration and escalation logic.

A related trap, worth stating because the wrong form looks identical: in
`update @floodmeter4 { ip saddr limit rate over 400/second }`, the rate expression gates
the **rule**, not the dynset. An element is created for every source seen — that is what
a meter is for — and only the *rule* stops early when the rate is not exceeded. So the
`add @banned_ips` and the `drop` chained after it run for offenders only. What you must
not do is treat the meter set itself as a list of offenders and promote its contents:
that bans your entire client base on its first run. Read `banned_ips`, never
`floodmeter4`.

**Egress RRL also drops silently, so its threshold must be above real traffic.** 25
responses/second to a single destination IP is comfortably above a home router NAT's
sustained rate and below anything that looks like reflection, but a busy office NAT can
exceed it during a page-load burst — which is what `burst 50 packets` absorbs. Tune it
with evidence, not intuition: B9 shows how to read the rule counter and set occupancy.

**The escalation, stated in full so nobody adopts it half-way.** dnsdist in front of
AdGuardHome gives you real RRL with truncation:

```lua
-- /etc/dnsdist/dnsdist.conf  -- ESCALATION ONLY, not part of the base build
setLocal("0.0.0.0:53"); setLocal("[::]:53")
newServer({address="127.0.0.1:5353", name="adguardhome"})
addAction(AndRule({TCPRule(false), MaxQPSIPRule(30, 32, 64)}), TCAction())
addAction(MaxQPSIPRule(200, 32, 64), DropAction())
addAction(QTypeRule(DNSQType.ANY), RCodeAction(DNSRCode.REFUSED))
```

`TCPRule(false)` is the documented signature (`TCPRule(tcp)`); `NotRule(TCPRule())` is
not a documented form and may not parse. The guard is redundant from dnsdist 1.7.0
onward in any case — the docs state TCAction was applied over TCP only *before* 1.7.0,
and 24.04 ships a later release. Mandatory companion edits if you adopt it, because every
query now reaches AdGuardHome from 127.0.0.1:

- Delete `ratelimit_whitelist: [127.0.0.1, ::1]` from Phase E, or it whitelists 100% of
  traffic and AdGuardHome's limiter becomes a no-op. **This applies only if you adopt
  dnsdist.** In the base build Phase E keeps `ratelimit_whitelist` and it is correct
  there, because AdGuardHome's clients are real public addresses and the entry exists to
  exempt the host's own loopback probes. No phase should instruct the reader to remove it
  outside this escalation.
- Move AdGuardHome's plain-DNS listener to `127.0.0.1:5353` and re-point the B5 accepts.
- Phase J's abuse detection is already required to be kernel-side (see Phase J); this
  change makes any query-log-derived alternative permanently impossible, which is worth
  stating in the decision record rather than discovering later.

---

### B5. The authoritative /etc/nftables.conf

One file, applied at boot by `nftables.service`, and this phase is its sole author: every
other phase that needs an object in the ruleset gets it from here rather than shipping a
table of its own. Every number in it is justified in B3 and B4. Ports follow the canonical
topology: nginx owns TCP/80 and TCP/443 and terminates TLS (Phase D; the server block is
Phase E's). TCP/80 is **permanently open** — it serves the ACME HTTP-01 webroot (Phase D)
and the Phase Q well-known files, and this phase carries the standing accept for it in
`chain certbot` (B7). AdGuardHome owns 53 and 853 (Phase E); 3000 (admin UI), 5335
(Unbound) and 8053 (AdGuardHome's HTTPS listener behind nginx) are loopback-only and are
dropped explicitly on the public path. UDP/784 — v1's
legacy DoQ draft port — is gone; RFC 9250 DoQ is UDP/853 and nothing current uses 784.

**Two tables, and the second one is forced.** All policy — ban sets, flood meters, the
allowlist, the input path, the egress RRL — lives in one `table inet filter`. The only
other table is `table inet raw`, and it exists because `notrack` is legal only at the raw
hook, which no chain in `filter` can occupy. v1 had four tables; the ingress limiter sat
in `table inet dns_ratelimit` and the egress limiter in `table inet dns_rrl`. Both are
gone, for two different reasons given at the head of each block below. Do not reintroduce
either, and do not add a second base chain on the input hook.

```bash
install -d -m 0755 /etc/nftables.d
cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f
# DNS resolver edge policy. Ubuntu 24.04 / nftables 1.0.9.
#
# APPLIED AT BOOT ONLY. This file begins with `flush ruleset`, which destroys
# banned_ips / banned_ips6 and every flood meter. For any change after boot use
# /usr/local/sbin/nft-apply (Phase B8) -- it is the only reload wrapper in this
# plan, and every other phase calls it rather than reloading this file itself.
# Never `systemctl restart nftables`.

flush ruleset

# Source allowlist (Phase B6). This include is MANDATORY, not optional:
# dns_guard references allowlist4/allowlist6 unconditionally, so the file must
# exist even when you are allowlisting nothing beyond the loopback defaults it
# ships with.
include "/etc/nftables.d/dns-allow.nft"

# ---------------------------------------------------------------------------
# raw -- NOTRACK for the DNS SERVER direction only.
#
# `notrack` is legal only in a prerouting or output chain at priority raw
# (-300) or lower, which is what puts it ahead of conntrack's -200 hooks.
#
# The server direction is `prerouting dport` + `output sport`. Do NOT add
# `prerouting sport 53` or `output dport 53`: those are the CLIENT direction,
# i.e. this host's own outbound resolution. Untracking them makes the replies
# arrive untracked, so they no longer match `ct state established,related` and
# die on `policy drop` -- apt, certbot's ACME lookups and every outbound HTTPS
# name resolution break at once, with no obvious cause.
# ---------------------------------------------------------------------------
table inet raw {
  chain prerouting {
    type filter hook prerouting priority raw; policy accept;
    # 443 is inert unless Phase D enables HTTP/3; listing it costs nothing.
    udp dport { 53, 443, 853 } counter notrack
  }

  chain output {
    type filter hook output priority raw; policy accept;
    udp sport { 53, 443, 853 } counter notrack

    # AdGuardHome -> Unbound (Phase C) and the reply. Every cache miss is one
    # loopback UDP flow with a 30 s conntrack entry, which is a real consumer
    # at production miss rates.
    #
    # This pair works ONLY at the output raw hook. By the time a loopback
    # packet reaches prerouting it already carries the ct attached on the way
    # out, and nft_notrack_eval() returns early ("Previously seen (loopback or
    # untracked)? Ignore."). Listing 5335 in the prerouting chain above would
    # be a genuine no-op; here it is not. Prove it with the conntrack check in
    # B9 before and after.
    udp dport 5335 counter notrack
    udp sport 5335 counter notrack
  }
}

# ---------------------------------------------------------------------------
# filter -- the ONLY policy table.
#
# Why one table: `add @set` is TABLE-SCOPED in the kernel. A rule that says
# `add @banned_ips` from a table where `banned_ips` does not live fails at load
# with "No such file or directory; did you mean set 'banned_ips' in table
# inet 'filter'?". The flood rules in `dns_guard` ban in the datapath, so the
# meters, the ban sets and the chain that joins them CANNOT be split across
# tables. That is what killed v1's `table inet dns_ratelimit`.
#
# Why one input-path chain: v1 had `input` at priority filter and a limiter
# chain at priority -1, so the order in which the ban drops, `iif lo accept`
# and the meters ran was a function of priority arithmetic rather than of
# reading the file top to bottom -- and the limiter ran BEFORE `iif lo accept`,
# which is how an on-box load test can ban 127.0.0.1 and take local DNS out
# with it. `dns_guard` is a jump target, not a base chain.
# ---------------------------------------------------------------------------
table inet filter {
  # --- ban sets -----------------------------------------------------------
  # Phase J owns who goes in, for how long, and the escalation LOGIC; this
  # phase owns every object those procedures manipulate, the escalation sets
  # included. Four sets, two tiers:
  #
  #   banned_ips  / banned_ips6   10m  first offence; written from the datapath
  #                                    by dns_guard and by Phase J
  #   banned_long / banned_long6  24h  escalation tier; written ONLY by Phase J
  #
  # All four are declared HERE, in `table inet filter`, never in a table of
  # their own (`add @set` is table-scoped), and all four are dropped in
  # `chain input` below. A declared set that no rule reads bans nobody, which
  # is exactly how an advertised 24-hour tier ends up dropping nothing.
  #
  # `dynamic` is required, not decorative: dns_guard writes these sets from the
  # datapath.
  set banned_ips   { type ipv4_addr; flags dynamic, timeout; timeout 10m; size 65536; }
  set banned_ips6  { type ipv6_addr; flags dynamic, timeout; timeout 10m; size 65536; }
  set banned_long  { type ipv4_addr; flags dynamic, timeout; timeout 24h; size 65536; }
  set banned_long6 { type ipv6_addr; flags dynamic, timeout; timeout 24h; size 65536; }

  # --- per-source flood meters --------------------------------------------
  # 400/s per source, which is 4x Phase E's dns.ratelimit -- the B4 invariant.
  # There is deliberately only ONE kernel meter tier; a second one anywhere
  # near Phase E's 100 q/s recreates the v1 stacking bug.
  #
  # The set-level timeout only governs how long an idle source's meter state
  # lingers. It is 10m to match the ban duration, so a source that comes back
  # inside its own ban window is metered against a warm bucket rather than a
  # fresh allowance.
  set floodmeter4 { type ipv4_addr; flags dynamic, timeout; timeout 10m; size 262144; }
  set floodmeter6 { type ipv6_addr; flags dynamic, timeout; timeout 10m; size 262144; }

  # --- source allowlist ---------------------------------------------------
  # allowlist4 / allowlist6 are declared in /etc/nftables.d/dns-allow.nft,
  # included at the top of this file so they exist before any rule references
  # them. They are separate sets rather than a mode of the ones above because
  # `flags interval` cannot be combined with `flags dynamic`. See B6.
  #
  # dns_guard returns early for members, so an allowlisted source is exempt
  # from flood detection and from in-datapath banning entirely. The stub ships
  # 127.0.0.0/8 and ::1, so these sets are never empty.

  # --- egress RRL meters --------------------------------------------------
  set rrl4 { type ipv4_addr; flags dynamic, timeout; timeout 10s; size 262144; }
  set rrl6 { type ipv6_addr; flags dynamic, timeout; timeout 10s; size 262144; }

  # --- named counters -----------------------------------------------------
  # Phase J's textfile exporter reads `nft list counter inet filter dns_dropped`
  # and `... dns_banned`, and Phase I alerts on the metrics derived from them.
  # Declaring the objects here is what makes those names exist; the rules below
  # reference them with `counter name`. Without these two declarations the
  # whole file fails to load, so the failure is loud rather than a silently
  # missing metric.
  #
  # UNVERIFIED on nftables 1.0.9: the empty-brace declaration form. If `nft -c`
  # rejects it, use the dump form `counter dns_dropped { packets 0 bytes 0 }`.
  counter dns_dropped { }
  counter dns_banned  { }

  # The public HTTP surface, in one named place. TCP/80 is PERMANENTLY open:
  # nginx owns the listener (Phase E) and serves the ACME HTTP-01 webroot
  # (Phase D) and the Phase Q well-known files from it. There is no open/close
  # dance -- that was v1's bug, and it reloaded the whole file around each
  # renewal, unbanning every live abuser twice a month. Any future ACME rule
  # belongs in this chain, where `nft add rule` / `nft flush chain` are
  # surgical and leave the sets above intact. See B7.
  chain certbot {
    tcp dport 80 counter accept
  }

  chain input {
    type filter hook input priority filter; policy drop;

    iif lo accept

    # Bans apply to EVERY protocol, not only the UDP/53 flood that earns them:
    # a source banned for flooding must not still reach DoT, DoH or DoQ. These
    # sit above everything except the loopback exemption, so nothing added
    # later can accidentally rank above them.
    #
    # BOTH tiers drop here. The 24-hour escalation sets are useless unless
    # something reads them, and Phase J only writes them -- these two lines are
    # what make the escalation an actual ban rather than a bookkeeping entry.
    ip  saddr @banned_ips   counter name "dns_dropped" drop
    ip6 saddr @banned_ips6  counter name "dns_dropped" drop
    ip  saddr @banned_long  counter name "dns_dropped" drop
    ip6 saddr @banned_long6 counter name "dns_dropped" drop

    ct state invalid counter drop
    # Safe alongside notrack: nft_notrack_eval() calls
    # nf_ct_set(skb, NULL, IP_CT_UNTRACKED), so untracked packets report
    # `ct state untracked`, never `invalid`.

    # ICMP. There is deliberately NO blanket `ip protocol icmp accept` -- with
    # one present, every over-rate echo falls through to it and these limits
    # are dead code. They also sit after the ban drops, so a banned source gets
    # no ICMP either.
    ip protocol icmp icmp type echo-request limit rate 10/second burst 20 packets accept
    ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
    ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
    ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 10/second burst 20 packets accept
    # packet-too-big stays unconditional: rate-limiting it black-holes PMTUD
    # and breaks DoT/DoH/DoQ for v6 clients behind tunnels.

    # Backend ports that must never be reachable off-box:
    #   3000  AdGuardHome admin UI          (SSH tunnel only -- Phase P)
    #   5335  Unbound                       (Phase C)
    #   8053  AdGuardHome HTTPS/DoH backend (nginx proxies /dns-query -- Phase D)
    # Redundant against `policy drop` as written. Their value is position: they
    # sit above every accept, so a careless rule added later cannot override
    # them, and the counters are the evidence that nothing external got in.
    # None of these numbers falls inside net.ipv4.ip_local_port_range, which
    # Phase A5 widens to 10240-65535 -- all three are below 10240, so this
    # cannot collide with a return packet. If Phase A ever lowers the bottom of
    # that range below 8054, revisit this rule before it starts eating replies.
    tcp dport { 3000, 5335, 8053 } counter drop
    udp dport { 3000, 5335, 8053 } counter drop

    ct state established,related accept

    # SSH. This bucket is GLOBAL, not per-IP; per-IP abuse is fail2ban's job.
    tcp dport 22 ct state new limit rate 10/minute counter accept

    # The public HTTP surface. Carries the standing `tcp dport 80 accept` --
    # permanently open, never opened and closed around renewals. See B7.
    jump certbot

    # Flood detection and in-datapath banning. Placed here, after `iif lo
    # accept` and after the ban drops, and before the DNS accepts below: a
    # packet that survives dns_guard falls through to them, one that does not
    # was dropped inside it.
    jump dns_guard

    # Public DNS.
    #
    # UDP/53 and UDP/853 are NOTRACK'd in `table inet raw` above, so they no
    # longer match `ct state established,related accept`. These two accepts are
    # now LOAD-BEARING. Delete either one and plain DNS / DoQ stops working
    # with no log line anywhere to explain it.
    udp dport 53  counter accept
    tcp dport 53  counter accept
    tcp dport 443 counter accept   # DoH -- nginx terminates TLS (Phase D)
    tcp dport 853 counter accept   # DoT -- AdGuardHome dnsforward (Phase E)
    udp dport 853 counter accept   # DoQ -- RFC 9250
    # udp dport 443 counter accept # uncomment ONLY if Phase D enables HTTP/3
  }

  # -------------------------------------------------------------------------
  # dns_guard -- ingress flood detection. A REGULAR chain, jumped from `input`.
  #
  # It is not a base chain, and that is the whole point: with NOTRACK in place
  # there is no conntrack cost to save by hooking it earlier, and being a jump
  # target means its position relative to the loopback exemption and the ban
  # drops is stated in one place instead of inferred from hook priorities.
  # -------------------------------------------------------------------------
  chain dns_guard {
    # Redundant given where the jump sits, and kept anyway: it makes the chain
    # safe if it is ever jumped from somewhere earlier, and Phase J's abuse
    # analysis requires this to be the first rule. Without it, an on-box load
    # test or health probe that exceeds 400/s puts 127.0.0.1 into banned_ips
    # and takes local DNS down for the ban duration -- along with the health
    # checks that would have told you.
    iif lo accept

    # Operator allowlist. A member bypasses flood detection AND banning
    # entirely -- that is what an operator allowlist is for. `return` leaves
    # dns_guard and resumes `input` at the rule after the jump, so an
    # allowlisted source is never metered and can never be entered into
    # banned_ips by the datapath. 127.0.0.0/8 and ::1 ship in these sets by
    # default (B6), a second belt alongside `iif lo accept` above for anything
    # that reaches the host over a non-lo path with a loopback source.
    #
    # A compromised allowlisted host is handled by REMOVING it from the
    # allowlist (`dns-allow-reload`, B6), not by leaving it metered.
    ip  saddr @allowlist4 return
    ip6 saddr @allowlist6 return

    # `update`, not `add`, for the meter: nft_dynset_eval() refreshes an
    # element's expiration only for NFT_DYNSET_OP_UPDATE. With `add`, a
    # sustained abuser's meter expires mid-attack and his budget resets.
    #
    # 400/s is 4x Phase E's dns.ratelimit -- the B4 invariant. The kernel
    # limiter must stay clearly above the userspace one or the two stack and
    # you get silent kernel drops where you intended a userspace limit. Raise
    # both together or neither.
    #
    # The rate expression gates the RULE, not the dynset: every source gets a
    # floodmeter element (that is what a meter is), but the chained
    # `add @banned_ips` and the `drop` run only for sources actually over the
    # rate. Read banned_ips to find offenders, never floodmeter4.
    #
    # `add @banned_ips` is legal here only because the set is in this same
    # table. Ban duration and escalation belong to Phase J; 10m is the
    # first-offence value it defines.
    udp dport 53 update @floodmeter4 { ip  saddr timeout 10m limit rate over 400/second burst 800 packets } add @banned_ips  { ip  saddr timeout 10m } counter name "dns_banned" drop
    udp dport 53 update @floodmeter6 { ip6 saddr timeout 10m limit rate over 400/second burst 800 packets } add @banned_ips6 { ip6 saddr timeout 10m } counter name "dns_banned" drop

    # Global backstop. Under a spoofed flood the two rules above fail open --
    # a full dynset makes nft_dynset_eval() set NFT_BREAK, which aborts THAT
    # RULE only. Evaluation continues, so this rule still runs. It is the real
    # floor on total inbound UDP/53. It deliberately does NOT ban: under
    # spoofing the source address is meaningless and banning it would jail
    # innocents. Size it above your measured peak: 5000 pps is ~10x a 500 QPS
    # service.
    udp dport 53 limit rate over 5000/second burst 10000 packets counter drop
  }

  chain forward { type filter hook forward priority filter; policy drop; }

  # -------------------------------------------------------------------------
  # output -- egress response rate limiting, then accept.
  #
  # Limiting responses PER DESTINATION is what RRL actually does, and unlike
  # ingress limiting it protects the third-party victim and your uplink even
  # when the source address is forged.
  #
  # v1 put these rules in a separate `table inet dns_rrl` at hook priority -5,
  # purely so their ordering against this chain was deterministic instead of
  # registration-order dependent. Inside one table that problem does not exist:
  # the rules simply come first in the chain and the order you read is the
  # order the kernel runs. One less table, one less priority to reason about.
  #
  # Only sport 53. DoQ (853) is not included: QUIC already has RFC 9000 8.1
  # address validation with a hard 3x ceiling, and dropping QUIC packets breaks
  # handshakes far more destructively than it caps anything.
  # -------------------------------------------------------------------------
  chain output {
    type filter hook output priority filter; policy accept;

    udp sport 53 ip  daddr != 127.0.0.0/8 update @rrl4 { ip  daddr timeout 10s limit rate over 25/second burst 50 packets } counter drop
    udp sport 53 ip6 daddr != ::1         update @rrl6 { ip6 daddr timeout 10s limit rate over 25/second burst 50 packets } counter drop

    # Absolute reflected-bandwidth cap. Blunt, but it cannot fail open the way
    # a dynset can. 4 mbytes/second = 32 Mbit/s, roughly what 500 QPS of
    # maximal EDNS answers costs (B3). This number MUST exceed your real peak
    # egress or you throttle yourself; measure with the counter in B9 before
    # raising it, and do not copy 30 mbytes/second (240 Mbit/s) onto a small
    # VPS just because it appears in reference configs.
    udp sport 53 limit rate over 4 mbytes/second counter drop
  }
}
EOF
```

Ship the stub allowlist file so the `include` resolves even when you are not allowlisting
any operator network. It is not empty: the loopback ranges ship in it by default, because
`dns_guard` consults these sets on every UDP/53 packet and an on-box probe must never be
metered or banned.

```bash
cat > /etc/nftables.d/dns-allow.nft << 'EOF'
#!/usr/sbin/nft -f
# Stub. Replace with the populated version from B6 if you adopt allowlisting.
# These sets belong to `table inet filter` like everything else in this plan;
# they live in their own FILE only so B6 can rewrite them atomically without
# touching /etc/nftables.conf.
#
# 127.0.0.0/8 and ::1 are DEFAULTS, not examples. dns_guard returns early for
# allowlist members, so these entries guarantee that on-box traffic is never
# flood-metered and never lands in banned_ips. Do not delete them when you
# populate the file with your own networks.
table inet filter {
  set allowlist4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { 127.0.0.0/8 }
  }
  set allowlist6 {
    type ipv6_addr
    flags interval
    auto-merge
    elements = { ::1 }
  }
}
EOF
```

Apply:

```bash
nft -c -f /etc/nftables.conf && nft -f /etc/nftables.conf
systemctl enable --now nftables
```

`nft -c` parses and validates without touching the live ruleset. Run it before every
`nft -f`, always — a syntax error partway through a file that begins with
`flush ruleset` leaves you with a policy-drop chain and no accepts.

---

### B6. Optional source allowlist (machinery here, policy in Phase P)

For a deployment whose clients all have static addresses, dropping non-allowlisted
traffic in the kernel is strictly better than answering REFUSED in userspace: no TLS
handshake, no CPU, no log noise. Whether that is the right access model — versus
ClientIDs, a token-authenticated DoH path, or WireGuard — is a Phase P decision. The
firewall machinery is here because it belongs at this layer.

What is optional is the *policy*: putting operator networks in the sets and restricting
the DNS accepts to them. The sets themselves are not optional. B5's `dns_guard` references
them on every UDP/53 packet and they ship carrying 127.0.0.0/8 and ::1, so the file always
exists and is never empty.

**Set declaration.** `flags interval` is what makes CIDR prefixes legal; `auto-merge`
collapses overlaps instead of failing with "conflicting intervals specified". `flags
interval` cannot be combined with `dynamic`, which is exactly why `allowlist4` /
`allowlist6` are separate *sets* from the ban sets and the flood meters. They are still
in the same `table inet filter`; only the file is separate, so that the rewrite below is
atomic and never touches `/etc/nftables.conf`.

The file below is written as a **single atomic transaction**: declare (idempotent),
flush, repopulate. All three commit together, so the allowlist is never momentarily
empty. That matters because `chain input` is `policy drop` — a two-command
flush-then-reload has a window in which every legitimate client is dropped.

```bash
cat > /etc/nftables.d/dns-allow.nft << 'EOF'
#!/usr/sbin/nft -f

# 1) Ensure the sets exist. Idempotent, so this is safe on a cold boot.
table inet filter {
  set allowlist4 { type ipv4_addr; flags interval; auto-merge; }
  set allowlist6 { type ipv6_addr; flags interval; auto-merge; }
}

# 2) Empty them.
flush set inet filter allowlist4
flush set inet filter allowlist6

# 3) Repopulate. Steps 1-3 commit as ONE kernel transaction.
table inet filter {
  set allowlist4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = {
      127.0.0.0/8,           # DEFAULT -- keep. On-box probes must never be metered.
      203.0.113.10,          # HQ static
      198.51.100.0/28,       # branch office
    }
  }

  set allowlist6 {
    type ipv6_addr
    flags interval
    auto-merge
    elements = {
      ::1,                   # DEFAULT -- keep.
      2001:db8:abcd::/48,    # HQ v6
    }
  }
}
EOF
```

**Wire it into the input chain.** Replace the five blanket DNS accepts in B5 with:

```nft
    # DNS only from allowlisted networks
    ip  saddr @allowlist4 udp dport 53  counter accept
    ip  saddr @allowlist4 tcp dport { 53, 443, 853 } counter accept
    ip  saddr @allowlist4 udp dport 853 counter accept
    ip6 saddr @allowlist6 udp dport 53  counter accept
    ip6 saddr @allowlist6 tcp dport { 53, 443, 853 } counter accept
    ip6 saddr @allowlist6 udp dport 853 counter accept
```

Leave the `jump dns_guard` where it is, above these. Being on the allowlist is not a
weaker form of access: `dns_guard`'s first rules after `iif lo accept` are
`ip saddr @allowlist4 return` / `ip6 saddr @allowlist6 return`, so an allowlisted source
bypasses flood detection and in-datapath banning entirely and falls straight through to
the accepts below. That is the point of an operator allowlist — the operator's own
networks must not be able to lock themselves out of their own resolver during a load
test, a cache-warming run or a burst of legitimate traffic. If an allowlisted host is
compromised, remove it from the allowlist with `dns-allow-reload`; do not try to contain
it with a meter that, by design, no longer applies to it.

Everything else hits `policy drop`. Leave the certbot chain unrestricted — Let's Encrypt
validates from arbitrary and undisclosed source addresses (see B7).

**Editing the allowlist without a reload and without an outage:**

```bash
cat > /usr/local/sbin/dns-allow-reload << 'EOF'
#!/bin/bash
# Replace ONLY the allowlist sets, in a single atomic nft transaction.
# banned_ips / banned_ips6 / floodmeter4 / floodmeter6 are untouched, and
# /etc/nftables.conf is never reloaded -- so this is not a substitute for
# nft-apply (B8) and must never grow into one.
set -euo pipefail
F=/etc/nftables.d/dns-allow.nft
nft -c -f "$F"     # syntax check, no side effects
nft    -f "$F"     # declare + flush + repopulate, one transaction
logger -t dns-allow "allowlist reloaded: $(nft -j list set inet filter allowlist4 | wc -c) bytes v4"
EOF
chmod 0700 /usr/local/sbin/dns-allow-reload
```

Do **not** use a bare `nft flush set ...` followed by a separate `nft -f`. Those are two
kernel transactions with a drop window between them, and the standalone `flush set`
aborts under `set -e` on a cold boot when the set does not yet exist.

Ad-hoc entries (runtime only — add them to the file too, or they vanish at boot):

```bash
nft add element inet filter allowlist4 { 192.0.2.0/24 }
nft delete element inet filter allowlist4 { 192.0.2.0/24 }
nft list set inet filter allowlist4
```

Add `/etc/nftables.d/dns-allow.nft` to the Phase K backup include list. Nothing else
regenerates this file: it is hand-maintained, it is the only place the allowlist contents
exist, and `/etc/nftables.conf` fails to load without it.

**What it does and does not buy.** It eliminates scanning, brute force and casual abuse,
and makes the box invisible outside the allowlist, at zero per-packet cost. It does
**not** stop spoofed-source floods: a packet claiming `203.0.113.10` is accepted,
processed and answered — to 203.0.113.10, not to the attacker. So it prevents you being
used as a reflector against *arbitrary* victims and shrinks the target set to your own
networks, but it is not client authentication. Only a handshake (DoT/DoQ/WireGuard)
authenticates. And it is useless for dynamic addresses, which is most of the world.

---

### B7. Certbot: a dedicated chain, never a reload

**Port 80 is permanently open in this build.** nginx owns the listener (Phase E) and
serves both the ACME HTTP-01 webroot (Phase D) and the well-known files Phase Q publishes
there. There is no open/close dance, no renewal hook that edits the firewall, and
therefore nothing to fail at 03:00 on renewal night.

The `certbot` chain in B5 exists to hold that standing accept in one named place, so the
chain itself documents *why* 80 is open and any future ACME-related rule has an obvious
home that is not `/etc/nftables.conf`. `nft add rule` and `nft flush chain` on it are
surgical: they change one chain and leave every set intact. That is the correction to v1,
whose renewal hook reloaded the whole ruleset and therefore unbanned every live abuser on
each renewal — v1's mechanism was the bug, and closing the port between renewals would
not have fixed it.

```nft
  chain certbot {
    # PERMANENTLY open. nginx listener (Phase E), ACME HTTP-01 webroot
    # (Phase D), Phase Q well-known files. Do not "close it between renewals".
    tcp dport 80 counter accept
  }
```

Do **not** install `pre`/`post` renewal hooks that add and remove this rule. A port that
is open only inside a renewal window breaks the webroot challenge Phase D actually uses —
the challenge is served by the already-running nginx, not by a standalone listener certbot
brings up — and it breaks every Phase Q well-known URL for the rest of the month.

Certificates are ECDSA P-256. Validation is HTTP-01 unless Phase P adopts the
`<id>.dns.example.com` ClientID form, which forces a wildcard and therefore DNS-01. The
port stays open either way: under DNS-01 ACME stops needing it, but the Phase Q
well-known files are served from it regardless, so DNS-01 is not a reason to close it.

Verification:

```bash
nft list chain inet filter certbot | grep -q 'tcp dport 80' \
  && echo 'PASS: standing port 80 accept present' \
  || echo 'FAIL: 80 not accepted -- ACME webroot and Phase Q well-known files are dead'

# No renewal hook may touch the firewall. Empty output from the grep is the pass.
grep -rl 'nft' /etc/letsencrypt/renewal-hooks/ 2>/dev/null \
  && echo 'FAIL: a renewal hook edits the firewall; delete it' \
  || echo 'PASS: no firewall-editing renewal hooks'

# A renewal must not disturb ban state -- this is the v1 regression test:
nft add element inet filter banned_ips { 192.0.2.66 timeout 10m }
certbot renew --dry-run
nft list set inet filter banned_ips | grep -q 192.0.2.66 \
  && echo 'PASS: renewal preserved ban state' || echo 'FAIL: bans wiped by renewal'
nft delete element inet filter banned_ips { 192.0.2.66 }
nft list chain inet filter certbot   # still exactly one rule: the standing accept

# off-box: 80 answers rather than refusing the connection.
#   curl -sS -o /dev/null -w '%{http_code}\n' http://<domain>/.well-known/
```

---

### B8. Reloading without losing ban state

Any change to `/etc/nftables.conf` itself needs a full reload, and a full reload starts
with `flush ruleset`. The wrapper below dumps the ban sets with their **remaining**
lifetime, reloads, and restores them.

`/usr/local/sbin/nft-apply` is the **only** reload wrapper in this plan. There is no
companion ban save/restore tool, and no phase should ship one: a second utility that
serialises `banned_ips` is a second implementation of the timeout arithmetic below, and
the two will disagree the first time one of them is edited. Phase J's ban and escalation
procedures call `nft-apply` when they need the ruleset reloaded; between reloads they
manipulate elements directly with `nft add element` / `nft delete element`, which needs
no wrapper at all.

**"Remaining", not "as configured", is the whole point.** A ban restored with a fresh
full-duration timeout is a ban that never expires as long as you keep editing the
ruleset — and with Phase J's escalation reading how often an address is re-banned, a
reload that resets timeouts would also corrupt the offence count that drives promotion to
the 24-hour tier. The dump below therefore reads each element's `expires` field, not its
`timeout` field.

```bash
cat > /usr/local/sbin/nft-apply << 'EOF'
#!/bin/bash
# Apply /etc/nftables.conf without losing ban state.
#
# THE ONLY RELOAD WRAPPER. Every phase that needs the ruleset reloaded calls
# this; nothing else serialises the ban sets.
#
# /etc/nftables.conf begins with `flush ruleset`, so a bare `nft -f` -- and the
# stock `systemctl reload nftables`, whose ExecReload is that exact command --
# destroys banned_ips / banned_ips6 and every flood meter. Flood meters are
# ephemeral and are allowed to die; bans are not.
set -euo pipefail

RESTORE=$(mktemp /run/nft-ban-restore.XXXXXX)
trap 'rm -f "$RESTORE"' EXIT

# nft JSON renders a timed element as
#   {"elem": {"val": "1.2.3.4", "timeout": 600, "expires": 540}}
# on nftables 1.0.9 (noble). Confirm once on your box with
#   nft -j list set inet filter banned_ips | jq .
# and adjust the field names below if your build differs.
#
# `.expires` is the REMAINING lifetime and is what gets restored. The fallback
# is 600s, the first-offence ban duration, and it is only reached if a build
# omits the field entirely -- in which case fix the jq rather than living with
# every ban silently reset to 10 minutes, including 24h escalated ones.
dump_set() {
  local s=$1
  nft -j list set inet filter "$s" 2>/dev/null | jq -r --arg s "$s" '
    [ .nftables[]? | .set? | select(. != null and .name == $s) | .elem[]? ]
    | map(if type == "object" then (.elem // .) else {val: .} end)
    | map(select(.val != null))
    | map("\(.val) timeout \(((.expires // 600) | floor))s")
    | if length == 0 then empty
      else "add element inet filter \($s) { " + join(", ") + " }" end' || true
}

# Every persistent ban set in `table inet filter`. The first two are declared
# in B5; the escalation sets are Phase J's and are listed here because a set
# that nobody dumps is a set that a reload silently empties. dump_set is a
# no-op for a set that does not exist, so this list is safe whether or not the
# escalation is adopted -- but if Phase J ever adds another set, add it here in
# the same change.
{ dump_set banned_ips
  dump_set banned_ips6
  dump_set banned_long
  dump_set banned_long6
} > "$RESTORE"

nft -c -f /etc/nftables.conf     # syntax check, no side effects
nft    -f /etc/nftables.conf     # flush + full reload, one transaction

if [ -s "$RESTORE" ]; then
  nft -f "$RESTORE"
fi

# fail2ban's table lives in the same ruleset and went out with the flush.
if systemctl is-active --quiet fail2ban; then
  systemctl restart fail2ban
fi

logger -t nft-apply "ruleset reloaded; restored $(wc -l < "$RESTORE") ban element line(s)"
EOF
chmod 0700 /usr/local/sbin/nft-apply
```

**Which procedure for which change** — this table is the operational contract:

| Change | Command | Ban state |
|---|---|---|
| Allowlist entries (B6) | `dns-allow-reload` | preserved (never reloads the main file) |
| ACME port 80 window (B7) | certbot hooks | preserved (chain-scoped) |
| Add/remove a ban | `nft add element` / `nft delete element` | n/a |
| Phase J ban / escalation actions | `nft add element`, or `nft-apply` if the file changed | preserved |
| Edit `/etc/nftables.conf` | `nft-apply` | dumped and restored, with remaining timeouts |
| `systemctl reload nftables` | routed to `nft-apply` by the B1 override | preserved |
| `systemctl restart nftables` | **do not** | lost, plus an open window |

Nothing else belongs in this table. If a phase needs a reload path that is not one of
these rows, the answer is to call `nft-apply`, not to add a sixth mechanism.

Verification:

```bash
# 10m is the canonical first-offence duration from B5; sleep first so that a
# restored timeout is measurably shorter than a freshly applied one.
nft add element inet filter banned_ips  { 192.0.2.66 timeout 10m }
nft add element inet filter banned_ips6 { 2001:db8::66 timeout 10m }
sleep 30
/usr/local/sbin/nft-apply
nft list set inet filter banned_ips  | grep -q 192.0.2.66   && echo 'PASS v4' || echo 'FAIL v4'
nft list set inet filter banned_ips6 | grep -q '2001:db8::66' && echo 'PASS v6' || echo 'FAIL v6'
# the restored timeout must be the REMAINING time, not a fresh 10m:
nft -j list set inet filter banned_ips | jq -r '.. | .expires? // empty'   # < 600, ~570
systemctl reload nftables
nft list set inet filter banned_ips | grep -q 192.0.2.66 && echo 'PASS reload' || echo 'FAIL reload'
nft delete element inet filter banned_ips  { 192.0.2.66 }
nft delete element inet filter banned_ips6 { 2001:db8::66 }

# There must be exactly one reload wrapper on the box. Phase J's abuse helpers
# (escalation, the textfile exporter) are fine -- a second ban save/restore
# tool is not.
ls /usr/local/sbin/nft-* 2>/dev/null
test -e /usr/local/sbin/nft-bans \
  && echo 'FAIL: second ban save/restore path present; nft-apply is the only wrapper' \
  || echo 'PASS: single reload wrapper'
```

---

### B9. Verification

Everything below runs on the box unless marked *off-box*. Two shell variables to set
first: `PUB=<public IPv4>` and, if you have one, `PUB6=<public IPv6>`.

**1. The ruleset is what you think it is.**

```bash
nft -c -f /etc/nftables.conf && echo 'syntax OK'
nft list ruleset | head -40

nft list tables            # expect EXACTLY: inet raw, inet filter
#   Anything else -- and dns_ratelimit or dns_rrl in particular -- means a v1
#   ruleset is still in place or a phase has re-added a table of its own. Both
#   break the in-datapath `add @banned_ips`, which is table-scoped.

# The six canonical sets, the guard chain and the named counters all exist,
# and there is only one base chain on the input hook:
for s in floodmeter4 floodmeter6 banned_ips banned_ips6 allowlist4 allowlist6; do
  nft list set inet filter "$s" >/dev/null 2>&1 && echo "PASS set $s" || echo "FAIL set $s"
done
nft list chain inet filter dns_guard >/dev/null && echo 'PASS chain dns_guard'
nft list counter inet filter dns_dropped >/dev/null && echo 'PASS counter dns_dropped'
nft list counter inet filter dns_banned  >/dev/null && echo 'PASS counter dns_banned'
nft -j list ruleset | jq '[.nftables[].chain? | select(.hook == "input")] | length'
#   must print 1. `dns_guard` is a jump target, not a second base chain.
```

**2. NOTRACK is active and pointing the right way.** The counters on the notrack rules
are the proof; a zero counter on `prerouting` under live traffic means the rule is not
matching.

```bash
nft list table inet raw
dig @127.0.0.1 google.com A +short >/dev/null
nft list table inet raw | grep -A2 'hook prerouting'   # counter packets must be > 0

# No DNS flows in the conntrack table at all.
# grep -c exits 1 on a zero count -- do not let that abort a set -e wrapper.
conntrack -L -p udp 2>/dev/null | grep -cE 'dport=(53|853|5335)' || true   # must print 0
```

**3. The host's own outbound DNS still works.** This is the regression that the
server-direction-only notrack exists to avoid, and it is the single most important check
in this phase — get it wrong and apt, certbot and every outbound HTTPS call break with
no useful error.

```bash
getent hosts api.github.com
curl -sI https://acme-v02.api.letsencrypt.org/directory | head -1   # HTTP/2 200
apt-get -qq update
```

**4. Conntrack is not filling.** Run the load generator from *off-box*; `conntrack -C`
on-box before and after.

```bash
sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max
conntrack -C
# off-box: dnsperf -s $PUB -d queries.txt -l 20 -Q 1000
conntrack -C                          # delta ~0, not ~20000
journalctl -k --no-pager | grep -i 'conntrack: table full'   # must stay empty
```

`nf_conntrack_count` includes transient unconfirmed entries, so a small non-zero reading
*during* a flood is expected. The pass criterion is that it does not grow monotonically.

**5. The flood guard engages, bans the offender, and the invariant against Phase E
holds.** Run the load generator from a host you are willing to have banned for ten
minutes — this test ends with the source in `banned_ips`, which is the pass condition,
not a side effect.

```bash
# off-box, deliberately over 400/s:
#   dnsperf -s $PUB -d queries.txt -l 20 -Q 2000
nft list chain inet filter dns_guard               # per-source rule counters > 0
nft list counter inet filter dns_banned            # incremented
nft list set  inet filter floodmeter4 | head -20
nft -j list set inet filter floodmeter4 | jq '[.. | .elem? // empty] | length'
nft list set  inet filter banned_ips               # the load generator's address, timeout 10m
journalctl -k --no-pager | grep -i 'set is full'   # occupancy warning; must stay empty

# The ban must NOT have caught loopback. If it did, `iif lo accept` is missing
# from the top of dns_guard or the jump has been moved above it in `input`.
nft list set inet filter banned_ips | grep -E '127\.0\.0\.1|::1' \
  && echo 'FAIL: loopback banned' || echo 'PASS: loopback exempt'

# Invariant from B4: kernel flood threshold >= 4 x AdGuardHome's dns.ratelimit.
NFT=$(nft -j list chain inet filter dns_guard \
      | jq -r 'first(.. | select(type=="object" and has("rate")) | .rate)')
AGH=$(awk '/^  ratelimit:/{print $2; exit}' /opt/adguardhome/conf/AdGuardHome.yaml)
echo "nft=$NFT agh=$AGH"          # expect nft=400 agh=100
[ "$NFT" -ge $(( AGH * 4 )) ] && echo 'PASS invariant' || echo 'FAIL invariant'

# Clean up before moving on, or the next test runs from a banned source:
# nft delete element inet filter banned_ips { <LOAD_GENERATOR_IP> }
```

**6. The egress RRL and the byte cap are sized correctly.** Read the drop counters under
*normal* load first — if either is non-zero without an attack, you are throttling your
own users and the threshold is wrong.

```bash
nft list chain inet filter output
# per-destination rule: counter should be 0 under normal load
# byte-cap rule:        counter should be 0 under normal load
nft -j list set inet filter rrl4 | jq '[.. | .elem? // empty] | length'   # live destinations
```

To size the byte cap from evidence rather than guesswork, raise it temporarily to a value
you know is above peak, run a week, then read the rule's byte counter and set the cap
above the observed peak rate.

**7. Measure your real amplification factor.** From *off-box*:

```bash
dig +notcp +bufsize=4096 @$PUB . DNSKEY | grep 'MSG SIZE'      # ~1139 -> ~18x
dig +notcp +bufsize=4096 @$PUB org DNSKEY | grep 'MSG SIZE'    # ~895  -> ~14x
dig +notcp +bufsize=512 +ignore @$PUB . DNSKEY +noall +comments | grep -o 'flags:[^;]*'
#   must contain ' tc' -- this is the control that proves truncation happens at all.
#   Do NOT use isc.org/dnsviz.net DNSKEY as a truncation probe: at 299 B and 491 B
#   they never exceed a 1232-byte buffer, so the check silently reads as a pass.
```

**8. Loopback-only ports are unreachable from outside.** Both halves matter: the bind
addresses on-box, and an actual probe from off-box.

```bash
# on-box: nothing may be listening on 0.0.0.0/:: for these
ss -lntup | grep -E ':(3000|5335|8053)\b'
#   expect 127.0.0.1:3000 (AdGuardHome UI), 127.0.0.1:5335 + [::1]:5335 (Unbound),
#   127.0.0.1:8053 (AdGuardHome HTTPS backend). Any 0.0.0.0 or :: is a Phase C/D/E bug,
#   not a firewall bug -- fix it there; the firewall is the second line, not the first.

# off-box:
nc -z -w2 $PUB 3000 && echo 'FAIL: 3000 reachable' || echo 'PASS: 3000 closed'
nc -z -w2 $PUB 8053 && echo 'FAIL: 8053 reachable' || echo 'PASS: 8053 closed'
dig @$PUB -p 5335 google.com A +time=2 +tries=1 ; echo "exit=$? (expect 9)"
[ -n "${PUB6:-}" ] && { nc -6 -z -w2 $PUB6 3000 && echo 'FAIL v6' || echo 'PASS v6'; }

# on-box, the counters prove nothing external ever got past the guard rules:
nft list chain inet filter input | grep -A1 '3000, 5335, 8053'
```

**9. The public surface is exactly the intended set.** From *off-box*:

```bash
nmap -Pn -p 22,53,80,443,853,3000,5335,8053 $PUB
nmap -Pn -sU -p 53,443,853,5335 $PUB
# open:   tcp 22, 53, 80, 443, 853  |  udp 53, 853
# closed: tcp 3000, 5335, 8053  |  udp 5335
#   tcp 80 is permanently open (B7). A closed or filtered 80 is a FAILURE here,
#   not a hardening win: it kills the ACME webroot and every Phase Q well-known URL.
# udp 443 open only if Phase D enabled HTTP/3 and you uncommented the rule.
```

**10. Ban enforcement actually drops.** From *off-box*, with the on-box commands run in
between:

```bash
# on-box:
nft add element inet filter banned_ips { <YOUR_TEST_CLIENT_IP> timeout 2m }
# off-box -- the ban must cover every transport, not just the UDP path that
# would have earned it:
dig      @$PUB google.com A +time=2 +tries=1 ; echo "exit=$? (expect 9)"
dig +tcp @$PUB google.com A +time=2 +tries=1 ; echo "exit=$? (expect 9)"
kdig +tls @$PUB google.com A +timeout=2      ; echo "exit=$? (expect non-zero)"
# on-box:
nft list chain inet filter input | grep -A1 'banned_ips'   # counter incremented
nft list counter inet filter dns_dropped                   # incremented
nft delete element inet filter banned_ips { <YOUR_TEST_CLIENT_IP> }
```

**11. Survives a reboot.** The firewall is only as good as its cold-boot path, and three
separate things are boot-order sensitive here: Phase A5's modules-load file (without it
the `net.netfilter.*` sysctls this phase depends on are silently skipped), the allowlist
include, and `nftables.service` being enabled.

```bash
reboot
nft list tables                                # inet raw, inet filter -- nothing else
sysctl net.netfilter.nf_conntrack_max          # 262144, not 65536 (Phase A5 writes it)
sysctl net.netfilter.nf_conntrack_buckets      # 65536 (this phase's modprobe.d file)
nft list set inet filter allowlist4            # allowlist repopulated from the file
nft list chain inet filter dns_guard           # guard chain present and empty of counters
systemctl is-enabled nftables                  # enabled
dig @127.0.0.1 google.com A +short
```

---

[Plan index](../dns-server-plan.md) · [Previous: Host Preparation](./01-host-preparation.md) · [Next: Unbound Recursive Resolver](./03-unbound-resolver.md)
