#!/usr/bin/env bash
# deploy/lib/common.sh — shared helpers for Keystone DNS deploy scripts.
# Sourced by every deploy/phases/<LETTER>-*.sh script. Not meant to be run directly.
#
# These scripts are a mechanical transcription of dns-server-plan.md / phases/*.md
# into runnable form. They have NOT been run against real hardware — same caveat
# as the source plan (see README.md). Read a phase script before running it.

set -euo pipefail

KEYSTONE_LOG_FILE="${KEYSTONE_LOG_FILE:-/var/log/keystone-deploy.log}"
KEYSTONE_YES="${KEYSTONE_YES:-0}"

_ts() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

_log() {
    local level="$1" msg="$2"
    printf '%s [%s] %s\n' "$(_ts)" "$level" "$msg" | tee -a "$KEYSTONE_LOG_FILE" >&2
}
info()  { _log INFO  "$*"; }
warn()  { _log WARN  "$*"; }
fatal() { _log FATAL "$*"; exit 1; }

phase_header() {
    printf '\n=== %s ===\n' "$1" | tee -a "$KEYSTONE_LOG_FILE" >&2
}

require_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || fatal "must run as root (sudo). current uid=${EUID:-$(id -u)}"
}

# confirm <prompt> — interactive gate before a destructive / hard-to-reverse step
# (firewall rule load, systemd unit replace, sudo-owned boot service restart).
# Set KEYSTONE_YES=1 to skip all gates for a scripted/CI run — that is an
# operator decision, not a default; scripts must not set it themselves.
confirm() {
    local prompt="$1"
    [[ "$KEYSTONE_YES" == "1" ]] && { info "auto-confirmed (KEYSTONE_YES=1): $prompt"; return 0; }
    local reply
    read -r -p "$prompt [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || fatal "aborted by operator at: $prompt"
}

# backup_file <path> — copy to <path>.bak.<UTC timestamp> before an in-place edit.
# No-op if the file does not exist yet (nothing to protect).
backup_file() {
    local f="$1"
    [[ -e "$f" ]] || return 0
    local bak="${f}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    cp -a "$f" "$bak"
    info "backed up $f -> $bak"
}

# require_cmd <name> [<name>...] — fail fast with a clear message instead of a
# raw "command not found" mid-script.
require_cmd() {
    local missing=()
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || missing+=("$c")
    done
    [[ ${#missing[@]} -eq 0 ]] || fatal "missing required command(s): ${missing[*]}"
}

# marker_done <name> — has this idempotent step already been recorded as applied?
STATE_DIR="${KEYSTONE_STATE_DIR:-/var/lib/keystone-deploy/state}"
marker_done() { [[ -e "${STATE_DIR}/$1" ]]; }
mark_done() { mkdir -p "$STATE_DIR"; touch "${STATE_DIR}/$1"; }
