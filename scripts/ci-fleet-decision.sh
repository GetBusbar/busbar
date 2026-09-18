#!/usr/bin/env bash
# Decide whether the self-hosted CI runner floor should be UP or DOWN — READ ONLY.
#
#   ./scripts/ci-fleet-decision.sh            # prints a summary to stderr, `up`/`down` to stdout
#
# This script makes ONLY `gh api` GET calls (org runners, repo workflow runs, run jobs). It never
# touches AWS and never mutates anything, so it is safe to run at any time — including while the
# fleet is busy — to see what the fleet-control workflow WOULD decide. The actual bring-up/teardown,
# and the "two consecutive empty reads" debounce that guards a teardown, live in
# .github/workflows/fleet-control.yml; this script answers a single question at a single instant:
# "is there, right now, any self-hosted CI work queued or running?"
#
# CONSERVATIVE BY CONSTRUCTION. It answers `up` if EITHER
#   (a) any org self-hosted runner is currently busy (a job is executing), OR
#   (b) any active (queued/in_progress/waiting/requested/pending) workflow run has a job whose
#       runner labels target our fleet (busbar-xl / self-hosted / latchkey-*).
# It answers `down` only when BOTH are empty. Every ambiguous case errs toward `up`.
set -uo pipefail

ORG="${ORG:-GetBusbar}"
REPO="${REPO:-GetBusbar/busbar}"

# Labels that route a job to OUR self-hosted EC2 fleet. Everything else — ubuntu-latest,
# ubuntu-24.04, ubuntu-24.04-arm, windows-latest, macos-* — is GitHub-hosted and irrelevant to the
# floor. `latchkey-*` matches every size (small/large/xlarge); `self-hosted` and `busbar-xl` are the
# legacy composite label set (see .github/workflows/ci.yml).
self_hosted_label() {
  case "$1" in
    busbar-xl | self-hosted | latchkey-*) return 0 ;;
    *) return 1 ;;
  esac
}

log() { printf '%s\n' "$*" >&2; }

command -v gh >/dev/null || { log "ERROR: gh CLI is required"; echo up; exit 0; }

# ── Signal A: self-hosted runners currently executing a job ─────────────────────────────────────
busy=0
busy_names="$(gh api --paginate "/orgs/${ORG}/actions/runners?per_page=100" \
  --jq '.runners[] | select(.busy==true) | .name' 2>/dev/null | sort -u)"
[ -n "$busy_names" ] && busy="$(printf '%s\n' "$busy_names" | grep -c .)"
log "signal A — self-hosted runners busy: $busy"
[ "$busy" -gt 0 ] && log "  busy: $(printf '%s' "$busy_names" | tr '\n' ' ')"

# ── Signal B: queued / in-progress jobs targeting the fleet ─────────────────────────────────────
# GitHub has no org-wide "list queued jobs" endpoint, so walk the ACTIVE runs of this repo and look
# at each run's jobs. A queued run does list its jobs with their labels, so a job that has not been
# handed to a runner yet is still visible here.
active_runs="$(
  for st in queued in_progress waiting requested pending; do
    gh api --paginate "/repos/${REPO}/actions/runs?per_page=100&status=${st}" \
      --jq '.workflow_runs[].id' 2>/dev/null
  done | sort -u
)"
n_runs=0
[ -n "$active_runs" ] && n_runs="$(printf '%s\n' "$active_runs" | grep -c .)"
log "signal B — active workflow runs to inspect: $n_runs"

pending_jobs=0
declare -a hits=()
for rid in $active_runs; do
  # shellcheck disable=SC2016  # the '$l' in the jq program below is a jq variable, not shell
  while IFS=$'\t' read -r jstatus jname label; do
    [ -n "${label:-}" ] || continue
    case "$jstatus" in
      queued | in_progress | waiting | requested | pending) ;;
      *) continue ;;
    esac
    if self_hosted_label "$label"; then
      pending_jobs=$((pending_jobs + 1))
      hits+=("run ${rid}: ${jname} [${jstatus}] -> ${label}")
      break   # one self-hosted label is enough to count this job
    fi
  done < <(gh api --paginate "/repos/${REPO}/actions/runs/${rid}/jobs?per_page=100" \
    --jq '.jobs[] | select(.status != "completed") | .labels[] as $l | [.status, .name, $l] | @tsv' 2>/dev/null)
done
log "signal B — queued/in-progress self-hosted jobs: $pending_jobs"
for h in "${hits[@]:-}"; do [ -n "$h" ] && log "  $h"; done

# ── Verdict ─────────────────────────────────────────────────────────────────────────────────────
if [ "$busy" -gt 0 ] || [ "$pending_jobs" -gt 0 ]; then
  log "VERDICT: up — self-hosted work is present (busy=$busy, pending=$pending_jobs)"
  echo up
else
  log "VERDICT: down — no self-hosted runner busy and no self-hosted job queued/in-progress"
  echo down
fi
