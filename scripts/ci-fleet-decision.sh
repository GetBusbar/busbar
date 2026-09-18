#!/usr/bin/env bash
# Size the self-hosted CI runner fleet TO ITS LOAD — READ ONLY.
#
#   ./scripts/ci-fleet-decision.sh            # prints the utilization math to stderr,
#                                             # one KEY=VALUE decision line to stdout
#
# This script makes ONLY `gh api` GET calls (org runners, repo workflow runs, run jobs). It never
# touches AWS and never mutates anything, so it is safe to run at any time — including while the
# fleet is busy — to see what the fleet-control workflow WOULD decide. The actual bring-up/drain/
# teardown, and the debounce that guards a teardown, live in .github/workflows/fleet-control.yml;
# this script answers a single question at a single instant: "given the work queued/running right
# now and the capacity online right now, how many boxes SHOULD be up?"
#
# THE OWNER RULE. "Increase EC2 to whatever number, but it MUST be ~90%+ utilized — never pay for a
# box sitting at 10%." So we do not run a fixed floor of boxes on a timer; we size capacity to the
# actual backlog:
#
#   DESIRED SLOTS  = pending self-hosted jobs           (1 runner slot per pending job -> ~100% util)
#   DESIRED BOXES  = ceil(desired_slots / AGENTS_PER_BOX)      clamped to [0, MAX_BOXES]
#
# and then compare to what is online:
#
#   pending == 0                  -> down-all   (tear the fleet fully to ZERO; NO idle floor)
#   desired_boxes  >  cur_boxes   -> up         (top the fleet up toward desired_boxes)
#   desired_boxes  <  cur_boxes   -> down-to    (shed the OVER-PROVISIONED excess, idle boxes only)
#   desired_boxes ==  cur_boxes   -> hold       (steady state: online_slots ~= pending, util high)
#
# CONSERVATIVE BY CONSTRUCTION. Every ambiguous read errs toward keeping capacity: if the runners
# API is unreadable we report cur_boxes=unknown(0) so the verdict can only be `up` or `down-all`,
# never a downscale we cannot justify. The teardown/drain debounce (two consecutive reads) is the
# workflow's job — a single empty read here never terminates anything on its own.
#
# STDOUT CONTRACT (one line, space-separated KEY=VALUE, consumed by the workflow):
#   action=<up|down-all|down-to|hold> pending=<n> cur_boxes=<n> desired_boxes=<n> target_boxes=<n> \
#     up_spot_count=<n> slots=<n> busy=<n> util_pct=<n> runners_visible=<0|1>
set -uo pipefail

ORG="${ORG:-GetBusbar}"
REPO="${REPO:-GetBusbar/busbar}"

# Fleet geometry. Kept in sync with scripts/ci-runners-lib.sh (AGENTS, FLOOR) and the workflow var.
AGENTS_PER_BOX="${CI_RUNNER_AGENTS:-4}"        # runner agents (= job slots) per EC2 box
ONDEMAND_FLOOR="${CI_RUNNER_ONDEMAND_FLOOR:-2}" # on-demand boxes up.sh always launches first
MAX_BOXES="${FLEET_MAX_BOXES:-16}"             # hard cap: "increase to whatever number" up to here

# Workflows whose heavy jobs run on OUR fleet. Used ONLY as a fallback when a queued job has not yet
# been assigned labels (GitHub leaves `.labels` empty on a not-yet-dispatched job in some states,
# and a per-job label filter then silently counts it as 0 — the bug that undercounted demand to
# zero in testing). When a job's labels ARE present we trust them; when they are empty we fall back
# to "is this a self-hosted workflow?" rather than dropping the job.
SELF_HOSTED_WORKFLOWS="${FLEET_SELF_HOSTED_WORKFLOWS:-CI gate-mutants keep-proof}"

# Labels that route a job to OUR self-hosted EC2 fleet. `latchkey-*` matches every size
# (small/large/xlarge); `self-hosted` and `busbar-xl` are the legacy composite label set.
self_hosted_label() {
  case "$1" in
    busbar-xl | self-hosted | latchkey-*) return 0 ;;
    *) return 1 ;;
  esac
}
labels_are_self_hosted() { # $1 = comma/pipe-joined label string
  local l
  IFS='|,' read -ra _labs <<<"$1"
  for l in "${_labs[@]:-}"; do
    [ -n "$l" ] || continue
    self_hosted_label "$l" && return 0
  done
  return 1
}
is_self_hosted_workflow() { # $1 = workflow/run name
  local w
  for w in $SELF_HOSTED_WORKFLOWS; do [ "$1" = "$w" ] && return 0; done
  return 1
}

log() { printf '%s\n' "$*" >&2; }

# ceil(a / b) for non-negative integers
ceil_div() { echo $(( ($1 + $2 - 1) / $2 )); }
clamp() { local v="$1" lo="$2" hi="$3"; [ "$v" -lt "$lo" ] && v="$lo"; [ "$v" -gt "$hi" ] && v="$hi"; echo "$v"; }

command -v gh >/dev/null || { log "ERROR: gh CLI is required"; echo "action=up pending=1 cur_boxes=0 desired_boxes=1 target_boxes=1 up_spot_count=0 slots=0 busy=0 util_pct=0 runners_visible=0"; exit 0; }

# ── CAPACITY: online runner slots, how many are busy, and how many BOXES they belong to ──────────
# One org runner registration == one job slot. A box runs AGENTS_PER_BOX of them, named
# `ec2-<instance-id-minus-i->-<agent>`, so the distinct instance-id prefixes are the box count.
runners_visible=1
runners_json="$(gh api --paginate "/orgs/${ORG}/actions/runners?per_page=100" \
  --jq '.runners[] | select(.status=="online") | [.name, .busy] | @tsv' 2>/dev/null)"
if ! gh api "/orgs/${ORG}/actions/runners?per_page=1" >/dev/null 2>&1; then
  runners_visible=0
  log "capacity: org runners API not readable (no admin:org token) — cur_boxes treated as unknown/0"
fi

slots=0; busy=0
declare -A box_seen=()
while IFS=$'\t' read -r rname rbusy; do
  [ -n "${rname:-}" ] || continue
  slots=$((slots + 1))
  [ "$rbusy" = "true" ] && busy=$((busy + 1))
  case "$rname" in
    ec2-*-*) box_seen["i-$(printf '%s' "$rname" | sed -E 's/^ec2-(.+)-[0-9]+$/\1/')"]=1 ;;
  esac
done <<RUNNERS
$runners_json
RUNNERS
cur_boxes="${#box_seen[@]}"
util_pct=0
[ "$slots" -gt 0 ] && util_pct=$(( busy * 100 / slots ))
log "capacity — online slots: $slots, busy: $busy, boxes: $cur_boxes, current util: ${util_pct}%"

# ── DEMAND: queued + in_progress jobs targeting the fleet, across active repo runs ───────────────
active_runs="$(
  for st in queued in_progress waiting requested pending; do
    gh api --paginate "/repos/${REPO}/actions/runs?per_page=100&status=${st}" \
      --jq '.workflow_runs[] | [.id, .name] | @tsv' 2>/dev/null
  done | sort -u
)"
n_runs=0
[ -n "$active_runs" ] && n_runs="$(printf '%s\n' "$active_runs" | grep -c .)"
log "demand — active workflow runs to inspect: $n_runs"

pending=0
declare -a hits=()
while IFS=$'\t' read -r rid rname; do
  [ -n "${rid:-}" ] || continue
  while IFS=$'\t' read -r jstatus jname jlabels; do
    case "$jstatus" in queued | in_progress | waiting | requested | pending) ;; *) continue ;; esac
    if [ -n "${jlabels:-}" ]; then
      labels_are_self_hosted "$jlabels" || continue
    else
      # No labels yet on this job — count it only if the whole run is a self-hosted workflow.
      is_self_hosted_workflow "$rname" || continue
    fi
    pending=$((pending + 1))
    [ "${#hits[@]}" -lt 6 ] && hits+=("run ${rid} (${rname}): ${jname} [${jstatus}] labels='${jlabels:-<none>}'")
  done < <(gh api --paginate "/repos/${REPO}/actions/runs/${rid}/jobs?per_page=100" \
    --jq '.jobs[] | select(.status != "completed") | [.status, .name, (.labels | join("|"))] | @tsv' 2>/dev/null)
done <<RUNS
$active_runs
RUNS
log "demand — queued/in-progress self-hosted jobs (pending): $pending"
for h in "${hits[@]:-}"; do [ -n "$h" ] && log "  $h"; done
[ "$pending" -gt 6 ] 2>/dev/null && log "  ... (+$((pending - 6)) more)"

# ── SIZE TO LOAD ────────────────────────────────────────────────────────────────────────────────
desired_slots="$pending"
if [ "$pending" -le 0 ]; then
  desired_boxes=0
else
  desired_boxes="$(clamp "$(ceil_div "$desired_slots" "$AGENTS_PER_BOX")" 0 "$MAX_BOXES")"
fi

# Projected utilization AT the desired sizing (what the owner rule is really about): with
# desired_boxes online, how full are they? Capped-out backlog -> 100%.
proj_slots=$(( desired_boxes * AGENTS_PER_BOX ))
proj_util=0
if [ "$proj_slots" -gt 0 ]; then
  fill=$pending; [ "$fill" -gt "$proj_slots" ] && fill=$proj_slots
  proj_util=$(( fill * 100 / proj_slots ))
fi

# ── VERDICT ─────────────────────────────────────────────────────────────────────────────────────
action=hold; target_boxes="$cur_boxes"; up_spot_count=0
if [ "$pending" -le 0 ]; then
  # No work at all. The floor is only justified WHILE work exists, so with an empty queue the
  # target is ZERO boxes — floor included. (The workflow debounces this before acting.)
  action=down-all; target_boxes=0
elif [ "$desired_boxes" -gt "$cur_boxes" ]; then
  action=up; target_boxes="$desired_boxes"
  up_spot_count=$(( target_boxes - ONDEMAND_FLOOR )); [ "$up_spot_count" -lt 0 ] && up_spot_count=0
elif [ "$desired_boxes" -lt "$cur_boxes" ]; then
  # Over-provisioned: more boxes online than the backlog needs -> utilization would sit below the
  # target. Shed the excess. Keep the on-demand floor while work exists (demand > 0 here); the
  # drain (idle-boxes-only) is done in ci-runners-down.sh --to-boxes.
  target_boxes="$desired_boxes"; [ "$target_boxes" -lt "$ONDEMAND_FLOOR" ] && target_boxes="$ONDEMAND_FLOOR"
  if [ "$target_boxes" -lt "$cur_boxes" ]; then action=down-to; else action=hold; fi
fi

# ── THE UTILIZATION MATH, PRINTED EVERY RUN ─────────────────────────────────────────────────────
log "────────────────────────────────────────────────────────────────────────"
log "UTILIZATION MATH"
log "  pending (self-hosted jobs queued+in_progress) : $pending"
log "  online slots / busy / idle                    : $slots / $busy / $(( slots - busy ))"
log "  current boxes  (slots/box=$AGENTS_PER_BOX)                     : $cur_boxes"
log "  current utilization (busy/slots)              : ${util_pct}%"
log "  desired slots  (= pending)                    : $desired_slots"
log "  desired boxes  (ceil(pending/$AGENTS_PER_BOX), cap $MAX_BOXES)        : $desired_boxes"
log "  projected utilization at desired sizing       : ${proj_util}%"
log "  ACTION                                        : $action -> target_boxes=$target_boxes${up_spot_count:+ (up_spot_count=$up_spot_count)}"
log "────────────────────────────────────────────────────────────────────────"

printf 'action=%s pending=%s cur_boxes=%s desired_boxes=%s target_boxes=%s up_spot_count=%s slots=%s busy=%s util_pct=%s proj_util=%s runners_visible=%s\n' \
  "$action" "$pending" "$cur_boxes" "$desired_boxes" "$target_boxes" "$up_spot_count" "$slots" "$busy" "$util_pct" "$proj_util" "$runners_visible"
