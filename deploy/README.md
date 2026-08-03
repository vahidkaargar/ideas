# deploy/ — generated automation for the Keystone DNS plan

Scripts in `phases/` are a mechanical transcription of the phase documents
(`../dns-server-plan.md`, `../phases/*.md`) into runnable bash. They exist so an
operator does not have to hand-copy every command out of the markdown — they
are **not** a substitute for reading the phase before running it, and they
have **not** been executed against real hardware, same caveat as the source
plan (`../README.md`).

## Scope

Covers every lettered phase that changes state on the host: A–E (build), G–H
(logging and acceptance tests), I–J (observability and abuse detection), K/M/N/O
(operations), P/Q (optional layers), and L (the go-live checklist, run last as
a gate — it's a checker, not a build step).

Phase R (`../phases/12-client-setup.md`) has no script here: it is explicitly
client-side only and "changes nothing on the host."

## Use

```bash
sudo deploy/run.sh list          # show phases
sudo deploy/run.sh A             # run one phase
sudo deploy/run.sh A,B,C         # run several (executed in canonical order)
sudo deploy/run.sh all           # run everything, in order, ending at L
```

Each phase script can also be run standalone: `sudo bash deploy/phases/B-firewall.sh`.

`KEYSTONE_YES=1` skips the interactive `confirm()` gate that phase scripts use
before a destructive or hard-to-reverse step (firewall reload, systemd unit
replace, sudo-owned boot service restart). Leave it unset for a first run —
read each prompt before answering yes. Setting it is an explicit choice made
by the person running the script, not a default this tooling encourages.

## What the shared helpers do (`lib/common.sh`)

- `info` / `warn` / `fatal` — timestamped logging to stdout and
  `/var/log/keystone-deploy.log` (override with `KEYSTONE_LOG_FILE`)
- `require_root` — refuses to continue if not run as root
- `confirm "<prompt>"` — interactive y/N gate; see `KEYSTONE_YES` above
- `backup_file <path>` — copies a file to `<path>.bak.<UTC timestamp>` before
  an in-place edit
- `require_cmd <name...>` — fails fast with a clear message if a dependency
  is missing, instead of a raw "command not found" mid-script
- `marker_done <name>` / `mark_done <name>` — simple idempotency markers under
  `/var/lib/keystone-deploy/state/` (override with `KEYSTONE_STATE_DIR`)

## Traceability

Every step in a phase script is commented with its source step ID (e.g.
`# --- B5: dns_guard set ---`) so it can be checked against the corresponding
phase file. If a script and its source phase file ever disagree, the phase
file is authoritative — file an update against the script, not the plan.

## What this does not do

- Does not provision a VPS, register a domain, or acquire any of the
  prerequisites listed in `../dns-server-plan.md` §0.3 — those are manual,
  one-time, and mostly outside the host itself.
- Does not replace Phase L's own checklist review — `L-go-live-checklist.sh`
  runs the automatable verification commands, but blockers that require human
  judgment (documented in phases/11-go-live-checklist.md) still need a human.
- Phase O (`O-iac-runbook.sh`) covers the runbook-shaped parts of Phase O;
  where the source plan itself calls for setting up Ansible against a config
  repo (see dns-server-plan.md §0.3, "Acquire before Phase A"), that Ansible
  control host is intentionally out of scope here — it's infrastructure you
  bring, not something this repo can stand up on your behalf.
