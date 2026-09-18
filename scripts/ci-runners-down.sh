#!/usr/bin/env bash
# Take the busbar self-hosted runner fleet DOWN and leave no ghosts behind.
#
#   ./scripts/ci-runners-down.sh             # the SPOT boxes; the on-demand floor SURVIVES
#   ./scripts/ci-runners-down.sh --all       # everything, floor included
#   ./scripts/ci-runners-down.sh --to-boxes N  # DRAIN down to N total boxes, idle spot boxes only
#   CI_RUNNER_DRY_RUN=1 ./scripts/ci-runners-down.sh
#
# THE FLOOR SURVIVES A PLAIN `down`, AND THAT IS THE POINT OF IT. `down` is what an operator runs
# to stop paying for a burst, to get a clean slate after a disk-full box, or at the end of a long
# session — and every one of those is a moment when the next agent's push must still land. So the
# default takes the SPOT capacity down and leaves CI_RUNNER_ONDEMAND_FLOOR boxes standing. Only
# `--all` is a fleet-to-zero command, and it says so in its name.
#
# `--to-boxes N` is the UTILIZATION-AWARE DOWNSCALE the fleet-control workflow uses when the backlog
# shrinks below the capacity online: it sheds the excess SPOT boxes so online_slots tracks the queue
# (~90%+ utilization) instead of leaving 32-vCPU boxes idling. It NEVER kills a box mid-job — it
# terminates only boxes whose agents are ALL idle (see idle_spot_boxes) — and it never drops below
# the on-demand floor, because a downscale only happens while work still exists and the floor is the
# guaranteed capacity underneath it. If there is no fully-idle spot box to shed, it does nothing and
# says so: waiting one cycle beats interrupting a running job.
#
# Two halves, and the ORDER MATTERS. Terminating the boxes first would leave the org's runner list
# full of entries GitHub still believes are available: a job routed to a dead runner sits in
# `queued` until the 24h timeout with no error anywhere. So: remove the registrations FIRST (the
# boxes are still alive to be told), then terminate. Any registration that outlives its box is
# swept by the offline pass at the end regardless.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci-runners-lib.sh
. "$HERE/ci-runners-lib.sh"

ALL=0
MODE=spot          # spot | all | to
TO_BOXES=""
case "${1:-}" in
  --all)      ALL=1; MODE=all ;;
  --to-boxes) MODE=to; TO_BOXES="${2:-}"
              [ -n "$TO_BOXES" ] || die "--to-boxes needs a target box count (e.g. --to-boxes 6)"
              case "$TO_BOXES" in *[!0-9]*) die "--to-boxes wants a non-negative integer, got '$TO_BOXES'" ;; esac ;;
  "")         ;;
  *)          die "unknown argument '$1' (expected --all or --to-boxes N)" ;;
esac

require_aws
if [ "$MODE" = all ]; then
  IDS="$(fleet_instance_ids)"
  log "--all: taking the WHOLE fleet down, on-demand floor included"
elif [ "$MODE" = to ]; then
  # DRAIN to N boxes: shed the over-provisioned SPOT excess, and ONLY boxes that are fully idle.
  cur_total="$(n_of "$(fleet_instance_ids)")"
  excess=$(( cur_total - TO_BOXES ))
  log "drain to $TO_BOXES box(es): $cur_total up now, excess $excess (never below the floor, idle spot only)"
  if [ "$excess" -le 0 ]; then
    log "already at or below target ($cur_total <= $TO_BOXES); nothing to drain"
    write_fleet_file
    exit 0
  fi
  _idle=()
  while IFS= read -r _b; do [ -n "$_b" ] && _idle+=("$_b"); done < <(idle_spot_boxes)
  if [ "${#_idle[@]}" -eq 0 ]; then
    log "over-provisioned by $excess, but NO fully-idle spot box to drain — every spot box is busy"
    log "or still bootstrapping. Leaving the fleet as-is: never terminate a box mid-job."
    write_fleet_file
    exit 0
  fi
  # Take at most `excess` of the idle spot boxes.
  take=$excess; [ "$take" -gt "${#_idle[@]}" ] && take="${#_idle[@]}"
  IDS="$(printf '%s\n' "${_idle[@]:0:take}" | tr '\n' ' ' | sed 's/ $//')"
  log "draining $take idle spot box(es) (of ${#_idle[@]} idle, excess $excess): $IDS"
else
  IDS="$(fleet_spot_ids | tr '\n' ' ' | sed 's/ $//')"
  KEEP="$(fleet_ondemand_ids | tr '\n' ' ' | sed 's/ $//')"
  log "spot down, floor kept: keeping $(n_of "$(fleet_ondemand_ids)") on-demand box(es)${KEEP:+ — $KEEP}"
fi

if [ -n "$IDS" ]; then
  log "removing runner registrations on: $IDS"
  ONLINE="$(ssm_online "$IDS")"
  if [ -n "$ONLINE" ]; then
    # A DRY RUN MUST NOT MINT A CREDENTIAL, AND MUST NOT PRINT ONE. `aws_w` prints the argv it was
    # handed, and the argv here CONTAINS the remove-token — so the first dry run of this script
    # echoed a live 60-minute org credential into a terminal and a log file. The token is not needed
    # to describe the intent, so under CI_RUNNER_DRY_RUN it is never requested at all: nothing to
    # leak beats redacting something that was fetched anyway.
    if dry; then
      log "[dry-run] would mint an org remove-token (NOT printed) and SSM-dispatch to: $ONLINE"
      log "[dry-run]   for d in /opt/runner-*; svc.sh stop/uninstall; config.sh remove --token <redacted>"
    else
      TOKEN="$(gh api -X POST "/orgs/${ORG}/actions/runners/remove-token" --jq .token 2>/dev/null)"
      if [ -n "${TOKEN:-}" ]; then
        # shellcheck disable=SC2086  # $ONLINE is a whitespace-separated id list and must word-split
        aws ssm send-command --instance-ids $ONLINE --document-name AWS-RunShellScript \
          --comment "deregister busbar CI runners" \
          --parameters "commands=[\"for d in /opt/runner-*; do (cd \\\$d && ./svc.sh stop; ./svc.sh uninstall; sudo -u ubuntu env HOME=/home/ubuntu ./config.sh remove --token '$TOKEN'); done\"]" \
          --query 'Command.CommandId' --output text >/dev/null && log "deregistration dispatched"
        unset TOKEN
        sleep 25
      else
        log "could not mint a remove-token; relying on the offline sweep below"
      fi
    fi
  fi
  log "terminating $IDS"
  # shellcheck disable=SC2086  # $IDS is a whitespace-separated id list and must word-split
  aws_w ec2 terminate-instances --instance-ids $IDS >/dev/null
else
  log "nothing to terminate"
fi

# THE SWEEP. Whatever happened above — a spot reclaim that never got a shutdown, an SSM timeout,
# a box that died mid-job — an OFFLINE org runner is a routing black hole. Delete every one.
#
# TWO SWEEPS, BECAUSE `--all` AND A PARTIAL DOWN ARE DIFFERENT FACTS. Under `--all` there is no
# fleet left, so "offline" and "dead" are the same word and the blanket delete is correct. Without
# it the floor is still standing, and a floor box whose agents are mid-restart is offline and very
# much alive — deleting its registration would make a real box unreachable. So the partial path
# uses the existence-checked sweep (shared with ci-runners-reconcile.sh), which only removes a
# registration whose INSTANCE EC2 no longer lists.
if [ "$ALL" = 1 ]; then
  log "sweeping every offline org runner"
  gh api --paginate "/orgs/${ORG}/actions/runners?per_page=100" --jq \
    '.runners[] | select(.status=="offline") | "\(.id) \(.name)"' 2>/dev/null \
  | while read -r rid rname; do
      log "  removing offline runner $rname"
      if dry; then
        printf '[dry-run] gh api -X DELETE /orgs/%s/actions/runners/%s\n' "$ORG" "$rid"
      else
        gh api -X DELETE "/orgs/${ORG}/actions/runners/${rid}" >/dev/null 2>&1 \
          || log "  (delete failed for $rname)"
      fi
    done
else
  sweep_ghost_runners
  log "swept $SWEPT_GHOSTS ghost registration(s) whose instance no longer exists"
fi
write_fleet_file

log "done. The launch template, security group, IAM role and the sccache bucket are LEFT IN PLACE"
log "(they cost nothing while idle and ci-runners-up.sh reuses them; the bucket expires at 14d)."
