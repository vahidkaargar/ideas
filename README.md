# Keystone DNS

DNSSEC validation is anchored on the root zone's Key Signing Key — the "keystone" of the
whole trust chain, and the piece this design is built around rather than delegating away.

## DNS server plan

[`dns-server-plan.md`](dns-server-plan.md) — production execution plan for a public,
DNSSEC-validating recursive DNS resolver (nginx + AdGuardHome + Unbound + nftables on
Ubuntu 24.04). Split into phase files under [`phases/`](phases/); see [`CLAUDE.md`](CLAUDE.md)
for the rules that govern editing it.

Nothing in the plan has been executed on real hardware yet — it is verified against
upstream docs/source and internally consistency-checked, not field-tested.
