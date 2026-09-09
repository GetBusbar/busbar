#!/usr/bin/env bash
# Register every prepared agent on every fleet box with the GetBusbar ORG runner pool.
#
#   ./scripts/ci-runners-register.sh
#
# ORG level, not repo level, on purpose: one pool serves busbar and every sibling repo, and a box
# that finishes a keep-proof run is immediately available to ci.yml instead of sitting idle behind
# a repo boundary.
#
# THE TOKEN IS MINTED HERE AND ONLY HERE. `gh api -X POST .../registration-token` returns a
# ~60-minute credential; it travels to the boxes over SSM SendCommand (encrypted in transit,
# never written to a file, never placed in user-data where any CI job could read it back out of
# the metadata service) and is used within seconds. Nothing on the box persists it: after
# `config.sh` runs, the box holds a per-runner .credentials issued by GitHub, not this token.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci-runners-lib.sh
. "$HERE/ci-runners-lib.sh"

require_aws
command -v gh >/dev/null || die "gh is required"

IDS="$(fleet_instance_ids)"
[ -n "$IDS" ] || die "no running instances tagged Name=$FLEET — run ./scripts/ci-runners-up.sh first"
log "fleet: $IDS"

# Only boxes SSM can actually reach. A box still in bootstrap has no SSM agent answering yet, and
# SendCommand to it would fail the whole batch.
ONLINE="$(aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=$(echo "$IDS" | tr -s ' \t' ',,' | sed 's/,$//')" \
  --query 'InstanceInformationList[?PingStatus==`Online`].InstanceId' --output text)"
[ -n "$ONLINE" ] || die "no fleet instance is reachable over SSM yet — wait for bootstrap and retry"
log "SSM-online: $ONLINE"

# One call, one token, used immediately. If this 403s the org API limit is exhausted; wait for the
# reset rather than retrying in a loop (a retry loop is what exhausts it).
TOKEN="$(gh api -X POST "/orgs/${ORG}/actions/runners/registration-token" --jq .token)" \
  || die "could not mint a registration token (rate limit? scope? needs admin:org)"
[ -n "$TOKEN" ] || die "empty registration token"
log "minted a registration token (not printed, expires in ~60 min)"

CMD_ID="$(aws ssm send-command \
  --instance-ids $ONLINE \
  --document-name AWS-RunShellScript \
  --comment "register busbar CI runners" \
  --parameters "commands=[\"/usr/local/bin/busbar-runner-register '$TOKEN' '$ORG' '$RUNNER_LABELS'\"]" \
  --query 'Command.CommandId' --output text)" || die "send-command failed"
unset TOKEN
log "ssm command $CMD_ID dispatched; polling"

for _ in $(seq 1 60); do
  sleep 10
  st="$(aws ssm list-command-invocations --command-id "$CMD_ID" \
        --query 'CommandInvocations[].Status' --output text)"
  log "  $st"
  case "$st" in
    *Pending*|*InProgress*|*Delayed*) continue ;;
    *) break ;;
  esac
done

log "org runners now registered:"
gh api "/orgs/${ORG}/actions/runners" \
  --jq '.runners[] | "  \(.name)  \(.status)  busy=\(.busy)  [\([.labels[].name] | join(","))]"' \
  || log "(could not list runners — check the API limit)"
