#!/usr/bin/env bash
# deploy/run.sh — Keystone DNS orchestrator.
#
# Runs the generated phase scripts (deploy/phases/<LETTER>-*.sh) in order.
# Each script is a mechanical transcription of one lettered phase from
# dns-server-plan.md / phases/*.md — read a phase before running it, this
# orchestrator does not review it for you.
#
# Usage:
#   sudo deploy/run.sh <PHASE>[,<PHASE>...]   run one or more phases, in the
#                                              canonical order below regardless
#                                              of the order given
#   sudo deploy/run.sh all                    run every phase in order
#   sudo deploy/run.sh list                   print phases and exit
#
# Env:
#   KEYSTONE_YES=1   skip interactive confirm() gates inside phase scripts
#                    (destructive-step prompts) — an explicit operator choice,
#                    not a default.
#
# Phase L (go-live checklist) is a gate, not a build step: run it last, after
# every phase you intend to deploy, before calling the host live.
# Phase R (client-setup, phases/12-client-setup.md) has no host script — it
# changes nothing on the server; see that file directly.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
source lib/common.sh

# Canonical order: build (A–E), validation (G–H), observability/abuse (I–J),
# operations (K, M, N, O), optional layers (P, Q), then the go-live gate (L).
PHASE_ORDER=(A B C D E G H I J K M N O P Q L)

declare -A SCRIPT_FOR=(
    [A]="phases/A-host-preparation.sh"
    [B]="phases/B-firewall.sh"
    [C]="phases/C-unbound-resolver.sh"
    [D]="phases/D-tls-certificates.sh"
    [E]="phases/E-adguardhome-edge.sh"
    [G]="phases/G-logging.sh"
    [H]="phases/H-acceptance-tests.sh"
    [I]="phases/I-observability.sh"
    [J]="phases/J-abuse-detection.sh"
    [K]="phases/K-backup-restore.sh"
    [M]="phases/M-upgrade-rollback.sh"
    [N]="phases/N-high-availability.sh"
    [O]="phases/O-iac-runbook.sh"
    [P]="phases/P-private-access.sh"
    [Q]="phases/Q-privacy-compliance.sh"
    [L]="phases/L-go-live-checklist.sh"
)

declare -A DESC_FOR=(
    [A]="host preparation (sizing, SSH hardening, sysctl, swap)"
    [B]="firewall (nftables ruleset)"
    [C]="unbound resolver (recursion, DNSSEC)"
    [D]="TLS certificates (ECDSA issuance, deploy hook)"
    [E]="AdGuardHome edge (public reachability at E5)"
    [G]="log rotation and retention"
    [H]="acceptance test suite"
    [I]="observability (metrics, alerting, dead-man's switch)"
    [J]="kernel-side abuse detection"
    [K]="off-host backup and restore drill"
    [M]="upgrade and rollback procedures"
    [N]="high-availability tiers"
    [O]="infrastructure-as-code and ops runbook"
    [P]="private access (WireGuard, ACLs, mTLS)"
    [Q]="privacy and compliance"
    [L]="go-live checklist (gate)"
)

usage() {
    echo "Usage: $0 <PHASE>[,<PHASE>...]|all|list"
    echo
    printf '  %-2s  %s\n' "letter" "phase"
    for p in "${PHASE_ORDER[@]}"; do
        printf '  %-2s  %s\n' "$p" "${DESC_FOR[$p]}"
    done
}

[[ $# -eq 1 ]] || { usage; exit 1; }

case "$1" in
    list)
        usage
        exit 0
        ;;
    all)
        to_run=("${PHASE_ORDER[@]}")
        ;;
    *)
        IFS=',' read -r -a requested <<< "$1"
        to_run=()
        for p in "${PHASE_ORDER[@]}"; do
            for r in "${requested[@]}"; do
                [[ "$p" == "$r" ]] && to_run+=("$p")
            done
        done
        [[ ${#to_run[@]} -gt 0 ]] || fatal "no valid phase letters in: $1"
        ;;
esac

require_root

for p in "${to_run[@]}"; do
    script="${SCRIPT_FOR[$p]:-}"
    [[ -n "$script" ]] || fatal "no script registered for phase $p"
    [[ -f "$script" ]] || fatal "phase $p script missing on disk: $script"
    phase_header "Phase $p — ${DESC_FOR[$p]}"
    bash "$script"
done

info "done: ${to_run[*]}"
