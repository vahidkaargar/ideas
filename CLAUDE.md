# CLAUDE.md — project rules for this repo

## What this repo is

A documentation-only repository. It contains one production execution plan for a
public, DNSSEC-validating recursive DNS resolver (nginx + AdGuardHome + Unbound + nftables
on Ubuntu 24.04), split across:

- [`dns-server-plan.md`](dns-server-plan.md) — index: architecture decisions, how to use
  the plan, threat model, phase table.
- [`phases/*.md`](phases/) — one file per phase group (A–R).

There is no build, no test suite, no runtime, and no code that executes from this repo.
The audience is a human operator who will run commands from these files, by hand, on a
VPS that does not exist yet. Do not treat this like an application codebase.

The binding technical facts (why SmartDNS was replaced with Unbound, why the OS is 24.04,
why DoH is fronted by nginx, etc.) live in the **Architecture Decisions** table in
`dns-server-plan.md` — that table is the source of truth for domain facts. This file is
about how to *edit* the repo correctly, not what the DNS design says.

## Rule types

Two tiers, matching this user's global convention (STRICT / PREFER / OPTIONAL in
`~/.claude/AGENT_RULES.md`):

- **Hard (MUST)** — violating these breaks the document: reintroduces a bug three audit
  rounds already fixed, or makes a claim nobody checked.
- **Soft (SHOULD)** — strong defaults. Deviate with a stated reason, not silently.

## Hard rules

1. **Read the Architecture Decisions table before touching any phase file.** Do not
   contradict a binding decision without updating the table itself and every phase it
   touches. A decision changed in isolation is a decision quietly broken elsewhere.

2. **Single ownership per shared object is load-bearing — do not duplicate it.** This
   list has drifted and been fixed multiple times; treat any violation as a defect, not a
   style choice:

   | Object | Sole owner | Others |
   |---|---|---|
   | Memory ceilings, swap, `vm.swappiness` | Phase A6 | cross-reference only |
   | nftables tables/chains/sets (`inet raw`, `inet filter`, `dns_guard`, `floodmeter4/6`, `banned_ips/6`, `banned_long/6`, `allowlist4/6`) | Phase B | Phase J manipulates B's objects, creates none |
   | `/usr/local/sbin/notify.sh` (signature: `notify.sh <severity> <title> [message]`) and `/etc/cron.d/dns-health` | Phase I (creates both) | every other phase appends |
   | `/opt/dns-config-backup` | Phase A3 (creates) | Phase K backs it up, never creates/deletes |
   | `/opt/adguardhome/validate` (the `--check-config` workdir) | Phase E (creates) | invoked via `runuser -u adguardhome`, never as root, never against the live `work/` tree |
   | `do-ip6` egress test | Phase C2 | Phase A cross-references, does not duplicate |

3. **Canonical filenames do not drift.** `/etc/unbound/unbound.conf.d/10-public-resolver.conf`,
   `/etc/systemd/system/unbound.service.d/hardening.conf`,
   `/etc/letsencrypt/renewal-hooks/deploy/50-dns-stack.sh`,
   `/opt/adguardhome/current/AdGuardHome` (a version symlink, never a hardcoded release path).
   If a step needs a new persistent path, name it once and grep the whole repo before reusing
   a name that means something else elsewhere.

4. **No invented directives.** Every config key, CLI flag, or software behavior claimed in
   this document must be checked against a primary source (official docs, source code, an
   RFC) before being written — not recalled from training data. Use Context7 MCP for
   library/API-shaped lookups; WebFetch/WebSearch otherwise. State what was checked.

5. **Verified vs. Assumed, stated inline.** This document already does this throughout
   ("verified in AGH source, `internal/home/web.go`..."). Match that standard for new
   content — a claim with no source is either checked or flagged unverified, never silent.

6. **Run the verifier after every edit.** `python3 scripts/verify_plan.py` (or the
   `verify-dns-plan` skill) must pass before an edit is reported done. It checks fence and
   heredoc balance, embedded YAML/Python/bash syntax, and cross-file link resolution. A
   change that breaks any of these is not complete — this is how the last several rounds of
   errors were actually caught, not by re-reading prose.

7. **Phase letters are permanent.** A–L is the base build, M–O is operations, P/Q are
   optional layers, R is client setup. Do not renumber or reuse a retired letter (F was
   retired, not reused) without grepping that letter across every file first — citations
   like `(H12)`, `L12`, `Phase B5` are load-bearing cross-references, not decoration.

8. **A multi-file edit touching a shared invariant needs a consistency pass before it's
   done.** Every time this document has been edited in parallel across files (which is most
   of its history), something drifted — a citation to a step that moved, a fact restated
   two ways, a name spelled two ways. Don't skip the re-check because the individual edits
   each looked correct in isolation.

## Soft rules

1. Match house style: `### X1. Title` step headings, prose explaining *why* before a config
   block, then an exact verification command with its expected output.
2. Prefer cross-referencing another phase by name over restating its content. Duplication
   is the primary way this document has drifted out of sync with itself.
3. Density over length. No padding, no marketing language, no emoji.
4. For a nontrivial addition (a new phase, a new binding decision), consider an adversarial
   verification pass — a second read whose job is to find what's wrong, not confirm what's
   right — before treating it as final. This is how the document reached its current
   reliability; it did not get there from a single confident pass.
5. Keep `phases/` as the source of truth; regenerate `dns-server-plan.md`'s phase table and
   nav links deliberately when adding or renaming a phase file, rather than letting the two
   drift apart.

## Tooling

- **`scripts/verify_plan.py`** — the one piece of tooling this repo needs. Structural and
  cross-reference checks only (see hard rule 6). No dependencies beyond Python 3's stdlib;
  install `pyyaml` (`pip install pyyaml`) to enable the YAML-syntax check, or it degrades to
  a warning and skips that one check.
- **Skill: `verify-dns-plan`** (`.claude/skills/verify-dns-plan/`) — wraps the script for
  invocation via the Skill tool.
- **No MCP servers are required for this repo.** It has no live API, database, or running
  service to integrate with — the deliverable is a document. (Context7 is used ad hoc for
  researching the *content* of the plan — AdGuardHome/Unbound/nftables/systemd behavior —
  not as project infrastructure; it needs no project-level configuration here.) When the
  plan is actually executed on a VPS, that host's own tooling — Prometheus, Alertmanager,
  the `notify.sh` bridge — is Phase I's concern and lives on that machine, not in this repo.
- **No CI, no linter, no build step is configured**, deliberately. This is a markdown
  document, not a package; a general-purpose markdown linter (e.g. `markdownlint-cli2`)
  would catch prose-style nits at the cost of one more tool to maintain, for a repo whose
  actual failure modes (broken cross-references, invalid embedded config, invented
  directives) are exactly what `verify_plan.py` targets and a style linter would not catch.
  Add one only if a real recurring problem shows up that this script doesn't cover.
