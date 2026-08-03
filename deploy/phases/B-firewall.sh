#!/usr/bin/env bash
# deploy/phases/B-firewall.sh — Phase B: Firewall and Edge Packet Policy
# Source: phases/02-firewall.md
#
# Mechanical transcription. Read the source file before running this script.
# This phase is the SOLE owner of every nftables table/chain/set it creates
# below (table inet raw, table inet filter, banned_ips/6, banned_long/6,
# floodmeter4/6, allowlist4/6, rrl4/6, dns_dropped, dns_banned). No other
# phase script may create or redefine these objects (Phase J only manipulates
# elements in banned_ips/6 and banned_long/6 at runtime).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=lib/common.sh
source lib/common.sh

require_root
phase_header "Phase B — firewall (nftables ruleset)"

require_cmd apt systemctl nft

# --- B1: remove ufw, install nftables/conntrack/jq -------------------------
info "B1: removing ufw, installing nftables + conntrack + jq"
systemctl disable --now ufw 2>/dev/null || true
apt purge -y ufw
apt install -y nftables conntrack jq
systemctl enable nftables

# --- B1: neutralise the reload trap (ExecReload -> nft-apply) --------------
# The stock ExecReload is `nft -f /etc/nftables.conf`, which begins with
# `flush ruleset` and destroys banned_ips/banned_ips6. Route reloads through
# the state-preserving wrapper built in B8.
info "B1: installing nftables.service override to route reload through nft-apply"
install -d -m 0755 /etc/systemd/system/nftables.service.d
cat > /etc/systemd/system/nftables.service.d/override.conf << 'EOF'
[Service]
# Stock ExecReload is `nft -f /etc/nftables.conf`, which begins `flush ruleset`
# and destroys banned_ips/banned_ips6. Route reloads through the wrapper.
ExecReload=
ExecReload=/usr/local/sbin/nft-apply
EOF
systemctl daemon-reload

# --- B1: verification -------------------------------------------------------
info "B1 verification"
dpkg -l ufw 2>/dev/null | grep -q '^ii' && echo 'FAIL: ufw still installed' || echo 'PASS: ufw gone'
systemctl cat nftables | grep -A2 '^ExecReload'   # must show the override, not `nft -f`

# --- B2: kernel packet-layer knobs ------------------------------------------
# hashsize is a MODULE PARAMETER (Phase B owns it), distinct from the
# net.netfilter.* sysctls which Phase A5 owns. Do not duplicate keys across
# the two sysctl.d files (checked below).
info "B2: nf_conntrack hashsize module parameter"
echo 'options nf_conntrack hashsize=65536' > /etc/modprobe.d/nf_conntrack.conf

info "B2: edge-layer sysctls (99-nftables-edge.conf)"
backup_file /etc/sysctl.d/99-nftables-edge.conf
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

# NOTE: no modules-load.d entry added here for nf_conntrack — Phase A5 owns
# /etc/modules-load.d/conntrack.conf and modprobes nf_conntrack. Do not
# duplicate it here.

# NOTE: net.ipv4.conf.all.rp_filter is deliberately NOT set (per source: the
# effective value is max(all, <iface>), so "all" forces strict RPF on every
# interface — correct only for a single-homed VPS).

# --- B2: verification --------------------------------------------------------
info "B2 verification"
# Written by this phase:
sysctl net.netfilter.nf_conntrack_buckets  # expected: 65536, from /etc/modprobe.d/nf_conntrack.conf
sysctl net.ipv4.tcp_syncookies net.ipv4.tcp_synack_retries \
       net.ipv4.conf.all.accept_redirects                          # expected: 1 / 2 / 0

# Written by Phase A5, depended on by B3/B4. Read-only check:
sysctl net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_udp_timeout
# expected after Phase A5's change: 262144 / 10   (before: 65536 / 30)

# No key may be written twice across the two files:
grep -h '^[a-z]' /etc/sysctl.d/99-dns.conf /etc/sysctl.d/99-nftables-edge.conf \
  | cut -d= -f1 | tr -d ' ' | sort | uniq -d
#   must print nothing. Any output is an ownership violation -- delete the copy
#   in whichever file does not own the key.

# NOTE (manual, per B2): the source verification block ends with `reboot` and
# a post-reboot check that nf_conntrack_max still reads 262144. Rebooting is
# out of scope for an unattended script step here.
warn "MANUAL STEP (B2 verification): reboot the host, then confirm 'sysctl net.netfilter.nf_conntrack_max' still reads 262144 -- this proves the Phase A5 modules-load file survives a cold boot. Not scripted here."

# --- B5: ship /etc/nftables.conf, the authoritative ruleset ----------------
# Sole owner of table inet raw and table inet filter (all sets, chains,
# counters within). Phase J only manipulates elements of banned_ips/6 and
# banned_long/6 at runtime; it creates none of these objects.
info "B5: writing the authoritative /etc/nftables.conf"
install -d -m 0755 /etc/nftables.d
backup_file /etc/nftables.conf
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

# --- B5: ship the stub allowlist file so the include resolves --------------
# Not empty: the loopback ranges ship by default because dns_guard consults
# these sets on every UDP/53 packet.
info "B5: writing stub /etc/nftables.d/dns-allow.nft (loopback defaults only)"
backup_file /etc/nftables.d/dns-allow.nft
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

# --- B5: apply -- destructive, requires confirmation ------------------------
# `nft -f /etc/nftables.conf` begins with `flush ruleset`: it replaces the
# entire live firewall policy on this host. Gate it per the operator's
# standing policy on firewall changes.
confirm "About to load the Phase B nftables ruleset (nft -c -f /etc/nftables.conf && nft -f /etc/nftables.conf), which begins with 'flush ruleset' and replaces the entire live firewall policy on this host. Proceed?"
info "B5: validating and applying /etc/nftables.conf"
nft -c -f /etc/nftables.conf && nft -f /etc/nftables.conf

confirm "About to enable and start the nftables systemd unit (systemctl enable --now nftables), a boot service. Proceed?"
systemctl enable --now nftables

# --- B6: source allowlist (machinery only; policy is a Phase P decision) ---
# The stub above already ships the mandatory sets with loopback defaults.
# Populating operator networks (the 203.0.113.10 / 198.51.100.0/28 /
# 2001:db8:abcd::/48 example entries and rewiring the input-chain DNS accepts
# to require allowlist membership) is a Phase P policy decision, not scripted
# here -- see B6 in the source for the populated example and the input-chain
# replacement rules.
warn "MANUAL / POLICY STEP (B6): populating the allowlist with real operator networks and restricting the DNS accepts in 'chain input' to allowlist members is a Phase P decision, not part of the base build. Not scripted here -- see phases/02-firewall.md B6 if you adopt it."

# --- B6: install dns-allow-reload (safe to install regardless of B6 adoption)
# Atomic single-transaction reload of ONLY the allowlist sets. Does not touch
# /etc/nftables.conf and does not use nft-apply.
info "B6: installing /usr/local/sbin/dns-allow-reload"
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

# NOTE (B6, informational, not scripted): ad-hoc runtime-only allowlist edits
# use `nft add element inet filter allowlist4 { ... }` /
# `nft delete element inet filter allowlist4 { ... }` / `nft list set inet
# filter allowlist4` -- add any such entries to dns-allow.nft too, or they do
# not survive a reboot.

warn "REMINDER (B6): add /etc/nftables.d/dns-allow.nft to the Phase K backup include list -- it is hand-maintained and is the only place allowlist contents exist."

# --- B7: certbot chain is already shipped as part of B5's nftables.conf ----
# The standing `tcp dport 80 accept` lives in `chain certbot` above. Per B7,
# do NOT install certbot pre/post renewal hooks that add/remove firewall
# rules -- that was v1's bug. Nothing to script here beyond the verification
# below.
info "B7: certbot chain verification (standing port 80 accept, no firewall-editing renewal hooks)"
nft list chain inet filter certbot | grep -q 'tcp dport 80' \
  && echo 'PASS: standing port 80 accept present' \
  || echo 'FAIL: 80 not accepted -- ACME webroot and Phase Q well-known files are dead'

grep -rl 'nft' /etc/letsencrypt/renewal-hooks/ 2>/dev/null \
  && echo 'FAIL: a renewal hook edits the firewall; delete it' \
  || echo 'PASS: no firewall-editing renewal hooks'

# NOTE (B7 regression test): the source includes an on-box ban-survives-renewal
# test (`nft add element ... banned_ips { 192.0.2.66 timeout 10m }`, then
# `certbot renew --dry-run`, then check the element survived). This depends on
# certbot already being installed and configured (Phase D) and is a
# destructive-adjacent test against live ban state; not run automatically
# here. Run by hand after Phase D if you want to validate it:
warn "MANUAL STEP (B7 regression test): after Phase D installs certbot, validate that 'certbot renew --dry-run' does not disturb ban state. See B7 verification block in phases/02-firewall.md for the exact commands."

# --- B8: install nft-apply, the only reload wrapper -------------------------
# Overwrites a config file (if present from a prior run) that may already be
# in active use as the systemd ExecReload target -- back it up first.
info "B8: installing /usr/local/sbin/nft-apply"
backup_file /usr/local/sbin/nft-apply
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

# NOTE (B8 verification): the source's ban-restore-timing test
# (add a ban, sleep 30, run nft-apply, confirm restored `.expires` < 600 and
# `systemctl reload nftables` also preserves it) is a multi-minute, stateful
# test against live ban sets. Not run automatically here; run by hand per the
# B8 verification block in phases/02-firewall.md if you want to validate the
# wrapper end to end.
warn "MANUAL STEP (B8 verification): the ban-restore timing test (add a test ban, sleep 30s, run nft-apply, confirm the restored timeout is the REMAINING time not a fresh 10m) is not scripted here. See B8 verification block in phases/02-firewall.md."

info "B8: checking for a stray second ban save/restore tool"
ls /usr/local/sbin/nft-* 2>/dev/null || true
test -e /usr/local/sbin/nft-bans \
  && echo 'FAIL: second ban save/restore path present; nft-apply is the only wrapper' \
  || echo 'PASS: single reload wrapper'

# --- B9: verification --------------------------------------------------------
# On-box checks only. Steps 4, 5, 7, 8, 9, 10 in the source are off-box
# (require a second VPS with dnsperf/knot-dnsutils/nmap) and step 2's own
# reboot-survival check (step 11) requires an actual reboot -- flagged below,
# not scripted.
phase_header "Phase B — verification (B9)"

info "B9 step 1: ruleset shape"
nft -c -f /etc/nftables.conf && echo 'syntax OK'
nft list ruleset | head -40

nft list tables            # expect EXACTLY: inet raw, inet filter

for s in floodmeter4 floodmeter6 banned_ips banned_ips6 allowlist4 allowlist6; do
  nft list set inet filter "$s" >/dev/null 2>&1 && echo "PASS set $s" || echo "FAIL set $s"
done
nft list chain inet filter dns_guard >/dev/null && echo 'PASS chain dns_guard'
nft list counter inet filter dns_dropped >/dev/null && echo 'PASS counter dns_dropped'
nft list counter inet filter dns_banned  >/dev/null && echo 'PASS counter dns_banned'
nft -j list ruleset | jq '[.nftables[].chain? | select(.hook == "input")] | length'
#   must print 1. dns_guard is a jump target, not a second base chain.

info "B9 step 2: NOTRACK is active and pointing the right way"
nft list table inet raw
dig @127.0.0.1 google.com A +short >/dev/null || warn "on-box dig against 127.0.0.1 failed -- expected once Phase E/AdGuardHome is listening; harmless before that phase runs"
nft list table inet raw | grep -A2 'hook prerouting'   # counter packets must be > 0 under live traffic

# grep -c exits 1 on a zero count -- do not let that abort this script.
conntrack -L -p udp 2>/dev/null | grep -cE 'dport=(53|853|5335)' || true   # must print 0

info "B9 step 3: host's own outbound DNS still works (the notrack direction regression test)"
getent hosts api.github.com
curl -sI https://acme-v02.api.letsencrypt.org/directory | head -1   # expected: HTTP/2 200
apt-get -qq update

info "B9 steps 4,5,7,9,10: off-box tests, not scripted"
warn "MANUAL STEP (B9 step 4): conntrack-not-filling load test requires an off-box dnsperf run (dnsperf -s \$PUB -d queries.txt -l 20 -Q 1000) against a second VPS. Not scripted here."
warn "MANUAL STEP (B9 step 5): flood-guard-engages test requires an off-box dnsperf run deliberately over 400/s from a host you are willing to have banned for 10 minutes, plus the B4 invariant check (nft rate == 4x AdGuardHome's dns.ratelimit) which needs AdGuardHome installed (Phase E). Not scripted here."
warn "MANUAL STEP (B9 step 7): measuring the real amplification factor requires off-box dig queries against the public IP (\$PUB). Not scripted here."
warn "MANUAL STEP (B9 step 9): the nmap public-surface-exactness scan is off-box and requires nmap on the test host. Not scripted here."
warn "MANUAL STEP (B9 step 10): ban-enforcement-drops-all-transports test requires an off-box dig/kdig run against \$PUB with an on-box test ban added first. Not scripted here."

info "B9 step 6: egress RRL and byte cap sizing (read counters under current load)"
nft list chain inet filter output
nft -j list set inet filter rrl4 | jq '[.. | .elem? // empty] | length'   # live destinations

info "B9 step 8: loopback-only ports are unreachable from outside (on-box half)"
# on-box: nothing may be listening on 0.0.0.0/:: for these
ss -lntup | grep -E ':(3000|5335|8053)\b' || true
#   expect 127.0.0.1:3000 (AdGuardHome UI), 127.0.0.1:5335 + [::1]:5335 (Unbound),
#   127.0.0.1:8053 (AdGuardHome HTTPS backend). Any 0.0.0.0 or :: is a Phase C/D/E bug.
nft list chain inet filter input | grep -A1 '3000, 5335, 8053'
warn "MANUAL STEP (B9 step 8, off-box half): nc/dig probes against \$PUB and \$PUB6 for ports 3000/8053/5335 from off-box are not scripted here."

warn "MANUAL STEP (B9 step 11): reboot-survival check requires an actual reboot, then re-running: nft list tables; sysctl net.netfilter.nf_conntrack_max; sysctl net.netfilter.nf_conntrack_buckets; nft list set inet filter allowlist4; nft list chain inet filter dns_guard; systemctl is-enabled nftables; dig @127.0.0.1 google.com A +short. Not scripted here."

echo
echo "Phase B verification commands that were run above (on-box, B9 steps 1-3, 6, 8-onbox) are the immediate pass/fail signal."
echo "For the full pass condition, also complete the MANUAL STEPs flagged above (B2 reboot check, B7 certbot renewal regression test, B8 ban-restore timing test, and B9 steps 4/5/7/9/10/11 which require a second off-box VPS and/or a reboot) -- see phases/02-firewall.md B9 for exact commands and expected output."
