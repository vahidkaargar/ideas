#!/usr/bin/env bash
# PostToolUse hook (matcher: Edit|Write) — mechanizes CLAUDE.md Hard Rule 6.
#
# Whenever Edit or Write touches dns-server-plan.md or a file under phases/, run
# scripts/verify_plan.py and, on failure, feed its exact output back to Claude via
# stderr + exit 2 so the errors are seen immediately instead of relying on Claude
# to remember to run the check before reporting an edit done.
#
# Silent on success and on any file this repo's verifier doesn't cover.
set -uo pipefail

input="$(cat)"
file_path="$(printf '%s' "$input" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
print(d.get("tool_input", {}).get("file_path", ""))
' 2>/dev/null)"

case "$file_path" in
  *dns-server-plan.md|*/phases/*.md)
    ;;
  *)
    exit 0
    ;;
esac

root="${CLAUDE_PROJECT_DIR:-}"
if [ -z "$root" ]; then
  root="$(cd "$(dirname "$0")/../.." && pwd)"
fi

output="$(cd "$root" && python3 scripts/verify_plan.py 2>&1)"
status=$?

if [ "$status" -ne 0 ]; then
  echo "$output" >&2
  echo "" >&2
  echo "verify_plan.py FAILED after this edit to $file_path — fix the errors above before treating the edit as done (CLAUDE.md hard rule 6)." >&2
  exit 2
fi

exit 0
