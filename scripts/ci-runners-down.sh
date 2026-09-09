#!/usr/bin/env bash
# Take the busbar self-hosted runner fleet DOWN and leave no ghosts behind.
#
#   ./scripts/ci-runners-down.sh
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

require_aws
IDS="$(fleet_instance_ids)"

if [ -n "$IDS" ]; then
  log "removing runner registrations on: $IDS"
  ONLINE="$(aws ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=$(echo "$IDS" | tr -s ' \t' ',,' | sed 's/,$//')" \
    --query 'InstanceInformationList[?PingStatus==`Online`].InstanceId' --output text)"
  if [ -n "$ONLINE" ]; then
    TOKEN="$(gh api -X POST "/orgs/${ORG}/actions/runners/remove-token" --jq .token 2>/dev/null)"
    if [ -n "${TOKEN:-}" ]; then
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
  log "terminating $IDS"
  aws ec2 terminate-instances --instance-ids $IDS >/dev/null
else
  log "no running instances tagged Name=$FLEET"
fi

# THE SWEEP. Whatever happened above — a spot reclaim that never got a shutdown, an SSM timeout,
# a box that died mid-job — an OFFLINE org runner is a routing black hole. Delete every one.
log "sweeping offline org runners"
gh api "/orgs/${ORG}/actions/runners" --jq \
  '.runners[] | select(.status=="offline") | "\(.id) \(.name)"' 2>/dev/null \
| while read -r rid rname; do
    log "  removing offline runner $rname"
    gh api -X DELETE "/orgs/${ORG}/actions/runners/${rid}" >/dev/null 2>&1 \
      || log "  (delete failed for $rname)"
  done

log "done. The launch template, security group, IAM role and the sccache bucket are LEFT IN PLACE"
log "(they cost nothing while idle and ci-runners-up.sh reuses them; the bucket expires at 14d)."
