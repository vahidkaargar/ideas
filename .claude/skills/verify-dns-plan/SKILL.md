---
name: verify-dns-plan
description: Run the structural verifier for this repo's DNS server production plan (dns-server-plan.md + phases/*.md) — checks fenced-code-block balance, embedded YAML/Python/bash syntax, and cross-file markdown link resolution. Use this ALWAYS after editing dns-server-plan.md or any file under phases/, after adding, renaming, or removing a phase file, and after any multi-file consistency pass across those files — even if the edit looked small or the prose read correctly on review. Also use it before telling the user a plan edit is complete or before committing changes to this repo, per CLAUDE.md hard rule 6. Do not skip this because a change "only touched prose" — the checks it runs (fence balance, embedded config syntax, link resolution) have caught real breakage from edits that looked correct on read-through, repeatedly, in this repo's history.
---

# Verify DNS Plan

Wraps `scripts/verify_plan.py`, the one piece of verification tooling this repo has. Run
it, read its output, and act on it — do not summarize away the specific `file:line` errors
it prints, since those are exactly what needs fixing.

## Why this exists

This document has been rewritten and cross-edited across many files, many times. Every
time an edit touched more than one file, something drifted that a careful re-read of the
prose did not catch: an unclosed code fence, an embedded config that no longer parses, a
cross-reference to a file that got renamed. The script exists because re-reading prose does
not reliably catch these — running the actual parser does.

## How to run it

From the repo root:

```bash
python3 scripts/verify_plan.py
```

It exits 0 and prints `PASS` when everything checks out, or exits non-zero and prints
`FAIL` with a numbered list of `file:line` errors. There is no flag to silence individual
checks — if something fails, it is meant to be looked at, not suppressed.

## Reading the output

Each error category means a different kind of fix:

- **`odd number of ``` fence markers` — an unclosed code block.** Something in the edit
  added or removed a fence marker without its pair. Re-read the diff around that line; the
  fix is almost always restoring the missing ` ``` `.
- **`yaml block fails to parse` / `python block fails to parse`.** The embedded
  configuration itself is broken, not the check. Fix the YAML or Python in the document —
  do not touch the script to make the error go away.
- **`bash block fails 'bash -n'`.** Same principle: a real shell syntax error in a command
  block. If the block genuinely uses a documentation placeholder like `<PUBLIC_IP>` or
  `<the older version from madison>`, the script already skips syntax-checking that block
  (placeholders read as shell redirection to `bash -n`, which is a false positive, not a
  real error) — so if this fires on a block with a placeholder, look for a *second*, real
  syntax problem the placeholder skip didn't hide.
- **`links to phases/X, which does not exist` / `nav link to ./X, which does not exist`.**
  A phase file was renamed, moved, or deleted without updating every place that references
  it. Grep the old filename across the whole repo (`grep -rn "old-name.md"`), not just the
  file you were editing — cross-references live in the index, in sibling phase files' nav
  headers, and sometimes in prose citations.

A `PyYAML not installed` warning is not a failure — it means the YAML-syntax check was
skipped for this run. `pip install pyyaml` to enable it; the rest of the checks are
unaffected either way.

## What this deliberately does NOT do

- **It is not a general markdown linter.** It has no opinion on prose style, heading
  levels, line length, or wording. Don't reach for it to fix writing quality — that's a
  human judgment call, or a separate tool if one is ever added (see CLAUDE.md's Tooling
  section for why one isn't, by default).
- **It does not blacklist specific strings** (`setcap`, `DNSStubListener`, stale table
  names, and similar). An earlier version tried exactly this and produced roughly 70 false
  positives on an otherwise-correct document, because this plan *correctly discusses* those
  terms at length in explanatory prose — sentences like "no phase grants a capability with
  `setcap`" and "there is no `DNSStubListener` setting" are the document doing its job, not
  a regression. A bare grep cannot distinguish a live mistake from the sentence that
  prevents one. If you need to check for a specific regression, grep for it deliberately
  and read the surrounding context by hand — don't encode a one-off concern as a permanent
  blanket check here.
- **It does not check whether the DNS/systems content is technically correct** — whether a
  config key really exists in AdGuardHome, whether an RFC is cited accurately, whether a
  command does what the prose says it does. That is a research and verification task for
  the agent doing the edit (see CLAUDE.md hard rules 4 and 5), not something a syntax
  checker can determine.

## Related

- `CLAUDE.md` in the repo root — hard rule 6 requires this check to pass before an edit to
  `dns-server-plan.md` or `phases/*.md` is reported done.
- `scripts/verify_plan.py` — the script itself, with fuller inline documentation of exactly
  what each check does and why the string-blacklist approach was rejected.
