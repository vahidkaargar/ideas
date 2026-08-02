[Plan index](../dns-server-plan.md) · [Previous: Go-Live Checklist and Risk Register](./11-go-live-checklist.md)

---

**On this page**

- [PHASE R: Client Configuration](#phase-r-client-configuration)
  - [R1. The four endpoint strings](#r1-the-four-endpoint-strings)
  - [R2. Transport reachability — which string to hand out first](#r2-transport-reachability-which-string-to-hand-out-first)
  - [R3. Android 9+ — Private DNS](#r3-android-9-private-dns)
  - [R4. iOS, iPadOS and macOS — a configuration profile or nothing](#r4-ios-ipados-and-macos-a-configuration-profile-or-nothing)
  - [R5. Windows 11 — the IP and the template are registered as a pair](#r5-windows-11-the-ip-and-the-template-are-registered-as-a-pair)
  - [R6. Linux](#r6-linux)
  - [R7. Browsers — the setting that silently overrides everything above](#r7-browsers-the-setting-that-silently-overrides-everything-above)
  - [R8. Routers and DHCP handoff — the pattern that looks right and is not](#r8-routers-and-dhcp-handoff-the-pattern-that-looks-right-and-is-not)
  - [R9. WireGuard clients — set the MTU](#r9-wireguard-clients-set-the-mtu)
  - [R10. Captive portals and hostile networks](#r10-captive-portals-and-hostile-networks)
  - [R11. IPv6-only and NAT64 access networks — this resolver does no DNS64](#r11-ipv6-only-and-nat64-access-networks-this-resolver-does-no-dns64)
  - [R12. Verify a client is actually reaching this resolver, with validation on](#r12-verify-a-client-is-actually-reaching-this-resolver-with-validation-on)

---

## PHASE R: Client Configuration

Phases A–L build a resolver and prove it answers. They never say what a user types where. That
is not a cosmetic omission: the per-platform constraints are severe enough that several of the
obvious answers are impossible, and an operator who does not know them will field tickets for
failures this plan otherwise does not describe. Android accepts a hostname and speaks DoT on 853
and nothing else. Apple platforms have no system-wide DoH or DoT user interface at all and need a
configuration profile. Windows 11 will not use a DoH template it has not been given alongside the
resolver's IP. Browsers run their own resolver and quietly discard whatever the operating system
was just told. And the two transports that are easiest to describe — DoT and DoQ on 853 — are
blocked outright on a large fraction of the corporate, hotel and airline networks your users will
actually be sitting on.

This phase is client-side only. It changes nothing on the host and can be read at any point after
Phase E5, when the service becomes publicly reachable. It assumes the base build: no Phase P
access mode selected. If you have selected one, **Phase P** owns the endpoint strings — every one
of them gains a ClientID label or moves inside a tunnel — and P3e is the table to use instead of
R1. R9 is the exception: it applies to the Phase P6 tunnel and belongs here because it is a client
setting.

Two placeholders throughout: `dns.example.com` is the name from Phase 0.1, and `<PUBLIC_IP>` is
the host's public address from Phase 0.2. `<PUBLIC_IPV6>` appears only where the deployment is
dual-stack.

---

### R1. The four endpoint strings

There are exactly four, and every platform section below is one of them wearing local clothes.
Publish all four; users do not get to pick their platform's constraints.

| Transport | What the user enters | Port | Notes |
|---|---|---|---|
| DoH | `https://dns.example.com/dns-query` | tcp/443 | RFC 8484 wire format only — there is no JSON endpoint (Phase H2) |
| DoT | `dns.example.com` | tcp/853 | hostname, no scheme, no port; the certificate name must match |
| DoQ | `quic://dns.example.com:853` | udp/853 | RFC 9250; the scheme form is what DoQ clients expect |
| Do53 | `<PUBLIC_IP>` (and `<PUBLIC_IPV6>`) | udp+tcp/53 | unencrypted, last resort — see R2 |

**The DoH path is exact.** Phase E writes `location = /dns-query`, an exact-match location. A
trailing label — `https://dns.example.com/dns-query/alice` — does not match it and returns the
`location / { return 404; }` fallback. That form exists only under Phase P, which replaces the
exact location with a regex one. Do not publish it from a base build.

**Nothing is auto-discoverable.** This plan publishes no DDR (RFC 9462) SVCB records at
`_dns.dns.example.com`, so no client will upgrade a plaintext configuration to an encrypted one on
its own, and no client will discover the DoH endpoint from the DoT one. Every string above has to
be entered by hand or pushed by a profile.

---

### R2. Transport reachability — which string to hand out first

The four transports are not interchangeable, and the ranking that matters to a user is not the
one that matters to a protocol designer.

1. **DoH on tcp/443 traverses almost everything.** It is indistinguishable from ordinary HTTPS at
   the packet layer and 443 is open on every network that has a web browser on it. This is the
   travel transport and the one to lead with.
2. **DoT on tcp/853** is blocked on a meaningful fraction of corporate, hotel, airline and school
   networks — 853 is a distinctive port with one purpose, and network operators who want to see
   DNS block it deliberately. It is nonetheless the *only* option on Android (R3), so it is not
   optional to publish.
3. **DoQ on udp/853** adds every reason DoT fails plus every network that rate-limits or drops
   non-443 UDP wholesale. Treat it as a fast path where it works, never as a user's only
   configuration.
4. **Do53** works everywhere and protects nothing. It is also the only transport AdGuardHome's
   application rate limiter covers — `ratelimit: 100` applies to plain UDP/53 and to nothing else
   (Phase E, Phase H10) — and the only one an ISP can transparently redirect without the client
   noticing (R12). Publish it for tooling and for clients that genuinely cannot do better.

The practical consequence for support: when a user says "it stopped working when I got to the
hotel", the first question is which transport they configured, and the first remedy is DoH.

---

### R3. Android 9+ — Private DNS

Settings → Network & internet → Private DNS → **Private DNS provider hostname**:

```
dns.example.com
```

**What this platform cannot do.** The field accepts a hostname and nothing else: no scheme, no
port, no URL. It always means DoT on tcp/853. Entering an IP address fails, because DoT
authenticates the certificate against the name. There is no way to enter a DoH template here on
any Android version — Android's DoH support upgrades a *known* resolver or one that advertises a
designated resolver, and this plan publishes neither (R1).

**It is strict by construction.** Naming a hostname turns off plaintext fallback. If the TLS
connection to `dns.example.com:853` cannot be made, nothing resolves at all — the device does not
quietly fall back, which is the point of the setting and the cause of R10.

Verification on Android without a shell is R12's operator-side check. If the user has Termux,
`pkg install knot-utils` gives them `kdig` and the client-side checks work verbatim.

---

### R4. iOS, iPadOS and macOS — a configuration profile or nothing

Apple platforms have no user-facing setting for DoH or DoT. The only supported mechanism is a
configuration profile carrying a `com.apple.dnsSettings.managed` payload, supported from iOS 14
and macOS 11. Everything else — an app that installs a fake VPN, a `/etc/resolv.conf` edit on
macOS — is either a third-party tunnel or is overwritten by the system on the next network change.

Phase P3f generates a profile from AdGuardHome's own `/apple/*.mobileconfig` endpoint, but that
path is loopback-only and its output carries a ClientID. For the base build, write the profile
yourself — it is twenty lines and it is auditable, which a downloaded binary blob is not.

`dns-example-doh.mobileconfig`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key>            <string>Configuration</string>
  <key>PayloadVersion</key>         <integer>1</integer>
  <key>PayloadIdentifier</key>      <string>com.example.dns.doh</string>
  <key>PayloadUUID</key>            <string>REPLACE-WITH-uuidgen</string>
  <key>PayloadDisplayName</key>     <string>example.com encrypted DNS (DoH)</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>        <string>com.apple.dnsSettings.managed</string>
      <key>PayloadVersion</key>     <integer>1</integer>
      <key>PayloadIdentifier</key>  <string>com.example.dns.doh.payload</string>
      <key>PayloadUUID</key>        <string>REPLACE-WITH-uuidgen</string>
      <key>PayloadDisplayName</key> <string>DNS over HTTPS</string>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key>      <string>HTTPS</string>
        <key>ServerURL</key>        <string>https://dns.example.com/dns-query</string>
        <key>ServerAddresses</key>
        <array>
          <string>&lt;PUBLIC_IP&gt;</string>
        </array>
      </dict>
    </dict>
  </array>
</dict>
</plist>
```

`&lt;PUBLIC_IP&gt;` is the plan's `<PUBLIC_IP>` placeholder, XML-escaped because angle brackets
cannot appear literally in a plist. Substitute the address, not the escapes.

`DNSProtocol` takes `HTTPS` or `TLS`. `ServerURL` is required for `HTTPS` and is meaningless for
`TLS`; `ServerName` (the bare hostname, `dns.example.com`) is required for `TLS` and is
meaningless for `HTTPS`. Do not set both.

**`ServerAddresses` is the part worth understanding.** It is optional — without it the system
resolves the hostname in `ServerURL` through whatever resolver the network handed out, which is
the bootstrap dependency R10 is about. Supplying `<PUBLIC_IP>` removes that lookup entirely: the
system connects straight to the address and still validates the certificate against the name in
the URL. On a captive-portal network that NXDOMAINs everything, this is the difference between a
profile that works after login and one that cannot come up at all.

Generate the UUIDs and install:

```bash
uuidgen            # run twice; paste into the two PayloadUUID fields
```

Distribute out of band — AirDrop, signed email, or an MDM. An unsigned profile installs with an
"Unverified" warning, which is accurate and which users should be told to expect. On iOS:
Settings → General → VPN, DNS & Device Management → the downloaded profile → Install, then
Settings → General → VPN, DNS & Device Management → DNS → select it. On macOS: System Settings →
General → Device Management.

Leave `ProhibitDisablement` unset. It only takes effect on supervised devices, and on a personal
device the ability to turn the profile off is what gets the user through a hotel login (R10).

Safari, Chrome and Edge on Apple platforms use the system resolver, so this profile covers them.
Firefox does not — see R7.

---

### R5. Windows 11 — the IP and the template are registered as a pair

Windows 11 supports DoH and does not support DoT. The trap is that it does not accept a DoH URL on
its own: the resolver's IP address is what the network stack is configured with, and the DoH
template is a property Windows looks up *for that IP*. Pasting the template somewhere without
registering it against the address silently does nothing, and Windows keeps sending plaintext.

The Settings path only offers a "Manual template" box on builds that have it, and only after the
address is entered. `netsh` works on every Windows 11 build and is the form to publish. Run in an
elevated prompt:

```
netsh dns add encryption server=<PUBLIC_IP> dohtemplate=https://dns.example.com/dns-query autoupgrade=yes udpfallback=no
netsh dns show encryption server=<PUBLIC_IP>
```

Expected from the second command: one entry, with the template above, `autoupgrade` yes and
`udpfallback` no. `udpfallback=no` is the strict setting — it is what makes a failed DoH
connection an error rather than a silent downgrade to Do53, and it is the Windows equivalent of
Android's strict mode, with the same consequence in R10.

Then set the adapter to use it: Settings → Network & internet → Wi-Fi or Ethernet → Hardware
properties → DNS server assignment → Edit → Manual → IPv4 On → Preferred DNS `<PUBLIC_IP>` → DNS
over HTTPS: **Encrypted only (no fallback)**.

For a dual-stack deployment repeat the `netsh` line with `<PUBLIC_IPV6>` and set Preferred DNS
under IPv6 as well; Windows treats the two families as independent registrations.

---

### R6. Linux

**systemd-resolved** is the no-extra-package answer on Ubuntu and Fedora desktops. Note this is
the *client* — Phase A2 disables `systemd-resolved` on the resolver host itself and writes a
static `/etc/resolv.conf`. Do not carry that instruction onto a workstation.

```bash
install -d /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/90-example-dot.conf <<'EOF'
[Resolve]
DNS=<PUBLIC_IP>#dns.example.com
DNSOverTLS=yes
DNSSEC=no
Domains=~.
EOF
systemctl restart systemd-resolved
```

The `#dns.example.com` suffix is load-bearing: it is what tells resolved which name to expect in
the certificate and what it puts in SNI. Without it resolved validates the certificate against the
IP address and the connection fails. `DNSOverTLS=yes` is strict; `opportunistic` cannot
authenticate the server at all and is worth nothing here. `Domains=~.` makes this the route for
every name rather than one candidate among the DHCP-supplied servers.

`DNSSEC=no` is deliberate and is not a weakening. Validation happens in exactly one place in this
design — Unbound, Phase C — and the DoT channel authenticates the resolver that did it. Turning
resolved's own validator on duplicates the work over an already-authenticated channel and is a
well-known source of spurious `SERVFAIL` on zones that validate correctly upstream. What the
client should check is the `ad` bit (R12), not re-derive it.

**Verify:**

```bash
resolvectl status | grep -E 'Current DNS Server|DNS Servers|DNSOverTLS'
resolvectl query example.com
```

Expected: `+DNSOverTLS` in the protocol line and `<PUBLIC_IP>#dns.example.com` as the current
server.

**stubby** is the alternative where systemd-resolved is not in use, and it authenticates strictly.
`/etc/stubby/stubby.yml`:

```yaml
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
listen_addresses:
  - 127.0.0.1@53000
upstream_recursive_servers:
  - address_data: <PUBLIC_IP>
    tls_auth_name: "dns.example.com"
```

`GETDNS_AUTHENTICATION_REQUIRED` is strict privacy mode and demands `tls_auth_name` (or a pinset)
on every upstream; without one, stubby refuses to start rather than connecting unauthenticated.
Point the system stub at `127.0.0.1#53000`.

**dnscrypt-proxy** speaks DNSCrypt and DoH — not DoT. If you publish a dnscrypt-proxy recipe, it
is the DoH endpoint, configured as a static server with a DNS stamp; do not publish a `tls://`
string for it.

---

### R7. Browsers — the setting that silently overrides everything above

A user configures Android Private DNS or a Windows template, opens their browser, and most of the
DNS they care about goes somewhere else. The two engines behave differently and the difference
determines what you tell people.

**Chrome and Edge delegate.** Their "Secure DNS" *Automatic* mode uses the servers the operating
system is already configured with, and upgrades to DoH only if that server appears in Chrome's
built-in provider map. This resolver is not in that map, so Automatic leaves Chrome using the OS
stub — which, if R3/R4/R5/R6 were followed, is already encrypted. Chrome is therefore covered by
an OS-level configuration, and pointing it at the endpoint explicitly is an optimisation, not a
fix:

Settings → Privacy and security → Security → Use secure DNS → With: **Custom** →
`https://dns.example.com/dns-query`.
Confirm at `chrome://net-internals/#dns` — the secure DNS block reports the configured mode and
template.

**Firefox does not delegate.** It runs its own trusted recursive resolver against its own default
provider in the regions where DoH is enabled by default, and an OS-level setting has no effect on
it. Left alone, the browsing of every Firefox user of this service goes to a third party: your
filtering does not apply, your Phase Q logging posture does not apply, and Unbound's validation
does not apply — while every check in the Phase L gate passes.

Two remedies, and users need to be told to pick one:

- Point it here: Settings → Privacy & Security → DNS over HTTPS → **Max Protection** (or Increased
  Protection) → Choose provider → **Custom** → `https://dns.example.com/dns-query`.
  The `about:config` equivalents are `network.trr.mode` = `3` (only) or `2` (first, native
  fallback), with `network.trr.uri` and `network.trr.custom_uri` both set to the URL — the
  Settings UI writes both, and setting only `network.trr.uri` can be overwritten the next time the
  UI runs.
- Or turn it off so it falls through to the system resolver: DNS over HTTPS → **Off**, which is
  `network.trr.mode` = `5` ("off by choice", as distinct from `0`).

Confirm at `about:networking#dns`: the TRR column reads `true` for names resolved through the
configured provider.

#### R7a. The Firefox canary domain — an operator decision, currently made by accident

Firefox resolves `use-application-dns.net` through the *operating system's* resolver before
enabling its default-on DoH. Any response code other than NOERROR — NXDOMAIN in practice — is read
as "this network does not want application DoH", and Firefox turns it off. The check does not
apply to a user who chose DoH deliberately, so it never overrides the explicit configuration
above; it governs the default-on population.

The base build has no blocklists at all — Phase E ships `filtering_enabled: false` — so this
resolver answers the canary normally and Firefox's default DoH stays on. The moment an operator
enables filtering and subscribes to a blocklist, whether that stays true is decided by whichever
list they happened to pick. That is a behaviour change for every Firefox client of the resolver,
chosen by nobody.

Make it a decision and record it wherever Phase E's filtering choices are recorded:

- **Answer it normally (recommended default).** Firefox's default-on users keep Firefox's
  provider; you tell them to configure the endpoint explicitly. This is the honest position for a
  public resolver: the canary is a tool for an operator who controls the *network*, and asserting
  it from a resolver a user chose is a policy signal you are sending to clients whose networks you
  do not run — which sits badly against Phase C's promise that nothing here rewrites, reorders or
  suppresses records.
- **NXDOMAIN it.** Firefox's default-on users fall through to the system resolver, which for your
  users is you: filtering, validation and the Phase Q posture then apply to their browsing. The
  cost is that you have started answering one name untruthfully, and you do it for every client
  including those whose OS resolver is somebody else entirely.

Whichever you choose, check what you are actually doing rather than assuming:

```bash
dig @<PUBLIC_IP> use-application-dns.net A +noall +comments
```

Expected in the base build: `status: NOERROR`. A `status: NXDOMAIN` means a blocklist has made the
decision for you. Note that a filter which returns NOERROR with `0.0.0.0` — AdGuardHome's default
blocking mode for adblock-style rules — does **not** trip the canary, so "it is on my blocklist"
and "Firefox sees it as blocked" are not the same statement.

---

### R8. Routers and DHCP handoff — the pattern that looks right and is not

The commonest way a person "uses" a public resolver is to type its IP into their router's DHCP
settings. It is also the one pattern that discards everything this plan built.

**Why not.** Every device on the LAN then speaks plaintext Do53 across the open internet. The DoT,
DoQ and DoH design is unused; the user's ISP sees every query in full; the Phase Q privacy posture
protects data at rest on a host while the queries reaching it were public the whole way. And the
whole site arrives at the resolver as one source address.

**The rate-limit consequence, which has no diagnostic path.** Phase E sets `ratelimit: 100` with
`ratelimit_subnet_len_ipv4: 32` and `_ipv6: 64` — per-host accounting, deliberately, so that one
abuser behind a carrier NAT cannot take out the /24 around them. A NAT'd site is one host by that
accounting: a household, an office, or a CGNAT egress shares a single 100 q/s budget no matter how
many devices sit behind it. A household rarely sustains that; a CGNAT egress or a mid-size office
routinely does.

What makes it hard to find is that the failure is silent at every layer:

- The limiter drops. It cannot set TC=1 and implements no RRL SLIP (Phase H10), so the client sees
  packet loss, retries, and puts itself further over the limit.
- 100 q/s never reaches Phase B's 400/s flood meter, so no ban is issued, `nft_dns_banned_packets`
  never moves, and Phase J7's false-positive procedure — which keys on exactly that counter — does
  not fire. A flat ban counter does not exonerate the rate limiters.
- The limiter covers plain UDP/53 only. The same site on DoT, DoQ or DoH is not gated by it at all.

So the symptom is "intermittent slow page loads at one site, nothing wrong on the server". The
remedies, in order: move the site to a connection-oriented transport, which the limiter does not
touch; or add that address to `ratelimit_whitelist` (Phase E owns the key). Do not reach for a
higher `dns.ratelimit` — Phase B's 400/s flood threshold is stated relative to it, and raising one
without the other is how a legitimate site ends up banned instead of throttled.

**The right pattern is a forwarding router** — the router speaks DoT or DoH to this resolver and
plain DNS to the LAN, so exactly one encrypted connection crosses the internet and the LAN
addresses never leave the house.

*OpenWrt, DoT via stubby:*

```sh
opkg update && opkg install stubby
uci set stubby.global.tls_authentication='1'
uci add_list stubby.global.dns_transport='GETDNS_TRANSPORT_TLS'
uci -q delete stubby.@resolver[0]
uci add stubby resolver
uci set stubby.@resolver[-1].address='<PUBLIC_IP>'
uci set stubby.@resolver[-1].tls_auth_name='dns.example.com'
uci -q delete dhcp.@dnsmasq[0].server
uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5453'
uci set dhcp.@dnsmasq[0].noresolv='1'
uci commit && reload_config
```

`127.0.0.1#5453` is stubby's default listener on OpenWrt, and `noresolv=1` is what stops dnsmasq
also using the WAN-supplied servers — without it you have added an encrypted path and kept the
plaintext one alongside it.

*OpenWrt, DoH:* `opkg install https-dns-proxy luci-app-https-dns-proxy`, set the resolver URL to
`https://dns.example.com/dns-query`, and point dnsmasq at its listener the same way.

*OPNsense / pfSense:* Services → Unbound DNS → DNS over TLS → add server `<PUBLIC_IP>`, port
`853`, Verify CN `dns.example.com`. Supplying the IP with the name as the verification target is
the same trick as the Apple `ServerAddresses` key — no bootstrap lookup, full certificate
validation.

*MikroTik RouterOS 7:*

```
/tool fetch url="https://letsencrypt.org/certs/isrgrootx1.pem"
/certificate import file-name=isrgrootx1.pem passphrase=""
/ip dns set servers=<PUBLIC_IP> use-doh-server=https://dns.example.com/dns-query verify-doh-cert=yes
```

RouterOS ships with no root certificate store, so `verify-doh-cert=yes` fails until the CA is
imported — and importing it is not optional, because `verify-doh-cert=no` means the router will
accept any certificate for the endpoint, which is the whole guarantee gone. Note `servers=` is
still set: RouterOS needs a plain resolver to look up `dns.example.com` before it can use the DoH
URL. That is the bootstrap dependency of R10, standing.

---

### R9. WireGuard clients — set the MTU

Phase P6 is the recommended default for personal and mobile use, and its client `[Interface]`
block sets no MTU. Add one:

```ini
[Interface]
Address    = 10.77.0.11/32, fd77:d15:c0de::11/128
PrivateKey = <CONTENTS OF /etc/wireguard/clients/alice.key>
DNS        = 10.77.0.1, fd77:d15:c0de::1
MTU        = 1280
```

`wg-quick` defaults to 1420, which assumes a 1500-byte outer path. On PPPoE (1492), on LTE and 5G
with GTP encapsulation, inside an outer IPv6 transition tunnel, or behind hotel CPE, the
encapsulated packet exceeds the real path MTU, and delivery then depends on an ICMP or ICMPv6
"packet too big" reaching the client — which mobile carriers and consumer CPE drop as a matter of
routine. 1280 is the IPv6 minimum link MTU and therefore survives every path in existence. It
costs nothing here: the tunnel carries DNS only (P6a runs no NAT and does not enable forwarding),
so there is no throughput to lose.

**The failure signature, because it is the hardest report in this document to diagnose.** Small
answers work and large ones hang. The handshake completes, `wg show` reports a recent handshake,
the peer looks healthy, and P8c's `dig +short` probes all pass — they ask for A records, which fit
in a couple of hundred bytes. DNSSEC-signed responses, TXT records and anything that would fall
back to TCP are what break, and the user reports "DNS works but some sites don't". P6c serves
plaintext Do53 inside the tunnel, and per Phase H7 AdGuardHome honours the client's advertised
EDNS buffer verbatim with no ceiling, so answers above 1400 bytes are ordinary rather than exotic.

**Probe it with an answer that is actually large.** From the client, with the tunnel up:

```bash
dig @10.77.0.1 +dnssec +bufsize=4096 . DNSKEY +noall +stats | grep 'MSG SIZE'
dig @10.77.0.1 +tcp +dnssec . DNSKEY +noall +stats | grep 'MSG SIZE'
```

Expected: both return, with `MSG SIZE rcvd:` around 1139 bytes (Phase H7's measured size for the
root DNSKEY set). A timeout on the first with the second succeeding is the MTU signature exactly —
UDP large answers lost, TCP fine because it segments.

Phase P owns P6b. The `MTU = 1280` line belongs in that `[Interface]` block too, not only here.

---

### R10. Captive portals and hostile networks

A hotel, airport, conference or train network intercepts DNS until the user has logged in. Every
strict client configuration in this phase breaks against that, in three different shapes, and the
user experience is not "DNS is slow" but "I have no internet".

1. **DoT or DoQ, strict (Android Private DNS, Windows with `udpfallback=no`, resolved with
   `DNSOverTLS=yes`).** The device refuses plaintext fallback by design. Nothing resolves, so the
   portal page never loads, so there is nothing to log in to. The user is stuck until they find
   the setting and turn it off — and the setting is several menus deep on a device that currently
   cannot load a help page.
2. **DoH.** One step removed but the same shape: `dns.example.com` must itself be resolved, by the
   portal's hijacking resolver, before the first DoH connection can be opened. A portal that
   NXDOMAINs everything makes the endpoint unbootstrappable. This is Phase P3c's insight — a
   hostname is resolved through the client's *current* resolver before any TLS handshake happens —
   generalised to every client of this service.
3. **WireGuard (Phase P6).** The worst case, and it is the recommended default. `Endpoint =
   dns.example.com:51820` needs a name lookup, and udp/51820 is blocked before login regardless.
   The tunnel cannot come up and the device is dark.

**What to tell users.** Expect to turn Private DNS or the DoH profile off at check-in, complete
the portal login, and turn it back on. Prefer DoH/443 as the travel transport (R2). Where the
platform lets you pin the endpoint's address — Apple's `ServerAddresses`, Windows' IP-plus-template
registration, stubby's and OPNsense's IP-with-verification-name form — do it, because it removes
failure shape 2 entirely: the connection no longer needs a lookup the portal can break, only a
route the portal will open after login. And leave the profile disableable: this is why
`ProhibitDisablement` stays unset in R4.

**What to tell the operator.** "Your DNS killed my hotel wifi" is not a server-side incident.
Nothing is wrong with the host, no check will fail, and no metric will move. The answer is the
paragraph above.

Note also that Phase P0's "Works on cellular and hotel NAT" and P6f's "Roaming for free" are true
*after* portal login, not unconditionally — the peer identity really does roam, but the tunnel
cannot be established through a portal that has not been satisfied yet.

---

### R11. IPv6-only and NAT64 access networks — this resolver does no DNS64

Unbound recurses from the root and returns the zone's answer. That is the product (Phase C), and
it means this resolver synthesises nothing: a name with only an A record returns NODATA for AAAA,
truthfully, every time.

On an IPv6-only access network that reaches the IPv4 internet through NAT64 — some mobile
carriers, many conference and campus WLANs, IPv6-mostly enterprise networks — the
network-provided resolver is doing DNS64, and truthfulness is the wrong answer. Pointing such a
client at this resolver breaks two things, not one:

1. **AAAA synthesis stops.** IPv4-only destinations return an A record the host has no stack to
   use. Roughly a third of the web stops loading, with no DNS error anywhere to show for it.
2. **NAT64 prefix discovery stops.** RFC 7050 discovery works by asking the network's DNS64
   resolver for the AAAA of `ipv4only.arpa` and reading the synthesised prefix out of the answer.
   Against this resolver that query returns NODATA, so a client relying on it never learns the
   prefix and its local translation — a CLAT, or API-level synthesis — does not come up either.
   Clients survive only where the network advertises PREF64 in Router Advertisements (RFC 8781)
   *and* the OS does its own translation. Do not assume any particular device does; the platforms
   differ and the network half is not yours.

**The one-command discriminator**, run on the affected device, is worth publishing because it
settles the question in seconds:

```bash
# The network's own resolver, whatever it handed out - not the one just configured.
NETNS=$(resolvectl status 2>/dev/null | awk '/Current DNS Server/{print $4; exit}')
dig @"$NETNS"      ipv4only.arpa AAAA +short
dig @<PUBLIC_IP>   ipv4only.arpa AAAA +noall +comments
```

If the first returns addresses (typically in `64:ff9b::/96`) and the second returns NOERROR with
no answer, the network is DNS64 and this resolver is not a drop-in replacement on it. That is not
a fault in either. If the device has already been switched over, read the network's resolver off
the DHCP lease or the Wi-Fi settings screen instead — asking the resolver under test what the
network would have said is the one way to get this backwards.

**What such a client should do.** Keep the network-provided resolver on that network, or reach
this one through the Phase P6 WireGuard tunnel, which carries IPv4 inside and sidesteps the
problem completely.

**The operator decision: do not add DNS64 to this resolver.** Unbound can do it —
`module-config: "dns64 validator iterator"` with `dns64-prefix: 64:ff9b::/96` — and it is the
wrong place for it. DNS64 is a property of an access network, paired with a NAT64 that someone
operates; synthesising AAAA records that point into a translator you do not run hands every
dual-stack client on the internet an address that black-holes. The correct owner is whoever runs
the NAT64. If you genuinely serve an IPv6-only estate, run a second instance on a separate
address with the prefix of a translator you actually operate, and leave the public listener
alone.

**Runbook shape:** a mobile user reports most sites failing while `dig` from everywhere else is
fine. Check whether their access network is IPv6-only with NAT64 before touching the server.

---

### R12. Verify a client is actually reaching this resolver, with validation on

Every validation proof elsewhere in this plan is operator-side and runs against `127.0.0.1:5335`
or from the Phase H0 test host. None of it tells a user anything, and the failure it would catch
is one only a client can see: an ISP transparently redirecting UDP/53, or a browser that quietly
kept its own provider. In both cases the answers are entirely plausible and nothing looks wrong.

Phase E blocks `version.bind`, `id.server` and `hostname.bind`, and Phase L gates on
`version.bind` returning REFUSED. That is correct anti-fingerprinting and it is also why the
canonical "which resolver am I on?" query has no answer here. The check below gets one anyway,
without reopening anything.

Install `kdig`: `apt install knot-dnsutils` on Debian and Ubuntu, `dnf install knot-utils` on
Fedora, `brew install knot` on macOS. Windows has no `kdig` — use WSL, or fall back to the
operator-side check.

**Run all three, over the transport the client is actually configured for.** A bare `dig` with no
`@` uses whatever the OS stub picked and proves nothing about a browser or a profile.

```bash
# 1. Validation is on, negative direction: a deliberately broken zone must fail.
kdig @dns.example.com +tls dnssec-failed.org A +noall +comments
#    PASS: status: SERVFAIL

# 2. Validation is on, positive direction: a signed name must carry the 'ad' flag.
kdig @dns.example.com +tls +dnssec internetsociety.org A +noall +comments
#    PASS: the flags line contains 'ad'

# 3. It is this resolver: the egress address the answer was recursed from.
kdig @dns.example.com +tls whoami.akamai.net A +short
#    PASS: the host's egress address (see below)
```

Check 1 alone is not evidence. A broken or empty trust anchor SERVFAILs everything, which looks
identical to "DNSSEC works" from the outside — this is Phase H5's point, restated where a user can
act on it. Run 1 and 2 together or neither.

Check 3 needs a published expected value. `whoami.akamai.net` returns the address the recursive
resolver queried the authoritative server *from*, which on a standard single-homed VPS is
`<PUBLIC_IP>` but need not be — a NAT'd instance, or a dual-stack host whose outbound preference
is IPv6, answers with something else. Establish it once on the host and publish that string
alongside the endpoints:

```bash
dig @127.0.0.1 -p 5335 whoami.akamai.net A +short
```

Same three checks on the other transports:

```bash
kdig @dns.example.com +https dnssec-failed.org A +noall +comments
kdig @dns.example.com +https +dnssec internetsociety.org A +noall +comments
kdig @dns.example.com +https whoami.akamai.net A +short

kdig @dns.example.com +quic dnssec-failed.org A +noall +comments
kdig @dns.example.com +quic whoami.akamai.net A +short

dig  @<PUBLIC_IP> dnssec-failed.org A +noall +comments
dig  @<PUBLIC_IP> whoami.akamai.net A +short
```

Add `+tls-ca +tls-hostname=dns.example.com` to any `+tls` or `+quic` form to make the certificate
actually validate rather than merely be presented — the same distinction Phase H3 draws.

**On a device with no shell** — an iPhone, a stock Android — the check is operator-side. Have the
user look up a name nobody else will, then find it in the query log:

```bash
# User, on the device, in a browser address bar. The page will not load; the lookup is the point.
#   http://$(openssl rand -hex 6).internetsociety.org/

# Operator, on the host:
curl -s -u admin:'YourStrongPassword' 'http://127.0.0.1:3000/control/querylog?limit=200' \
  | jq -r '.data[] | select(.question.name | test("<the-random-label>")) | [.time, .client, .question.name] | @tsv'
```

Phase Q's `anonymize_client_ip: true` masks the address to a /16, so this confirms that the query
arrived over this resolver — not which device sent it. Under Posture A, where the query log is
off, this check does not exist and the transport checks above are the only evidence available.

**Browsers report their own state** and should be checked separately from the OS: Firefox at
`about:networking#dns` (the TRR column reads `true`), Chrome and Edge at
`chrome://net-internals/#dns`. A user whose OS check passes and whose Firefox TRR column is
`false` is exactly the R7 case.

#### R12a. The identifier decision

Check 3 works by inference — it reads the resolver's egress address off a third party — and that
is the recommended default, because it costs nothing and reopens nothing. The alternative is a
first-party answer: configure an NSID, or publish a marker name in a zone you control, so "am I on
the right resolver" has a direct reply. The trade is that either one puts an identifier in
responses that Phase E's `blocked_hosts` deliberately removed, and gives a scanner a stable label
for this host.

Recommendation: keep `blocked_hosts` as Phase E ships it, publish the expected `whoami` value with
the endpoint strings, and note that the inference breaks if the host's egress address ever changes
without the published value being updated. Phase E owns `blocked_hosts` and Phase L owns the gate
that asserts it; this is a decision to record, not a config to change here.

---

[Plan index](../dns-server-plan.md) · [Previous: Go-Live Checklist and Risk Register](./11-go-live-checklist.md)
