---
name: edit-dns-plan
description: Use when about to add, rewrite, or otherwise edit dns-server-plan.md or any file under phases/ in this repo — before touching the content, not after. Covers the pre-edit and cross-file discipline CLAUDE.md's hard rules require (Architecture Decisions table, single-ownership table, canonical filenames, sourced claims, phase-letter permanence) that no script checks. Use alongside verify-dns-plan, which covers the mechanical post-edit checks this skill does not.
---

# Edit DNS Plan

This repo's `dns-server-plan.md` + `phases/*.md` have drifted out of sync with themselves
many times — not from prose errors, but from skipping a pre-edit check CLAUDE.md already
documents. `verify-dns-plan` catches syntax and link breakage after the fact; this skill is
the checklist for what to do before and during the edit, which no script can check.

## Before touching any phase file

1. **Read the Architecture Decisions table** in `dns-server-plan.md`. Don't contradict a
   binding decision without updating the table itself and every phase it touches (Hard Rule 1).
2. **Check the single-ownership table** in `CLAUDE.md` for every shared object (nftables
   objects, `notify.sh`, memory ceilings, `/opt/dns-config-backup`, the AGH validate workdir)
   you're about to touch or reference. Edit only from the sole-owner phase; other phases may
   cross-reference, never duplicate (Hard Rule 2).
3. **Grep before naming anything persistent.** A new path, filename, or table/chain name must
   not collide with something that already means something else elsewhere (Hard Rule 3).
4. **Grep the phase letter and any citation you're about to touch** (e.g. `(H12)`, `L12`,
   `Phase B5`) across the whole repo before renaming, moving, or retiring it — these are
   load-bearing cross-references, not decoration (Hard Rule 7).

## While writing content

- Every config key, CLI flag, or software behavior claimed must be checked against a primary
  source (official docs, source code, RFC) — Context7 MCP for library/API-shaped lookups,
  WebFetch/WebSearch otherwise — not recalled from training data. State inline what was
  checked, as Verified/Assumed (Hard Rules 4, 5).
- Prefer cross-referencing another phase by name over restating its content (Soft Rule 2).

## After a multi-file edit

Hard Rule 8: a multi-file edit touching a shared invariant needs a consistency pass before
it's done — re-check every place the touched fact, name, or citation appears, not just the
file you were editing. This is what has drifted every time it was skipped, even when each
individual file's edit looked correct in isolation.

Then run `verify-dns-plan` before reporting the edit done — it now also fires automatically
via the PostToolUse hook in `.claude/settings.json`, but the skill is still the right way to
invoke it manually or to understand a failure it reports.

## Rationalizations that have caused drift before

| Thought | Reality |
|---|---|
| "This edit only touches one file" | The ownership table, citations, and Architecture Decisions table are shared state — check them regardless of how many files you're editing. |
| "The prose reads correctly on review" | Re-reading prose is exactly what has failed to catch drift historically in this repo. Only the mechanical checks and the ownership/citation grep catch it. |
| "I'll skip the primary-source check, I already know this" | Hard Rule 4 exists because recalled-from-training claims have been wrong before in this document. Check anyway. |
| "This phase letter/citation isn't used elsewhere" | Grep first, don't assume. Citations like `(H12)` are load-bearing (Hard Rule 7). |

## Related

- `CLAUDE.md` — the full hard/soft rule set this checklist operationalizes.
- `verify-dns-plan` skill — the mechanical post-edit check (fences, embedded config syntax,
  link resolution), now also triggered automatically by `.claude/hooks/verify-dns-plan.sh`.
