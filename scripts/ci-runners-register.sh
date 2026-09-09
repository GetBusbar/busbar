#!/usr/bin/env bash
# Register every prepared agent on every fleet box with the GetBusbar ORG runner pool.
#
#   ./scripts/ci-runners-register.sh                    # every SSM-reachable box
#   ./scripts/ci-runners-register.sh i-0abc i-0def       # only these boxes
#   CI_RUNNER_DRY_RUN=1 ./scripts/ci-runners-register.sh # print the calls, mint nothing
#
# THE ARGUMENT FORM EXISTS FOR ci-runners-reconcile.sh. On a 15-minute timer, registering all eight
# boxes to fix one new box is eight SSM round-trips and a registration token minted for seven boxes
# that already hold GitHub-issued credentials. Reconcile works out which boxes are actually short of
# agents and names them.
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

if [ "$#" -gt 0 ]; then
  IDS="$*"
else
  IDS="$(fleet_instance_ids)"
fi
[ -n "$IDS" ] || die "no running instances tagged Name=$FLEET — run ./scripts/ci-runners-up.sh first"
log "fleet: $IDS"

# Only boxes SSM can actually reach. A box still in bootstrap has no SSM agent answering yet, and
# SendCommand to it would fail the whole batch.
ONLINE="$(ssm_online "$IDS")"
[ -n "$ONLINE" ] || die "no named fleet instance is reachable over SSM yet — wait for bootstrap and retry"
log "SSM-online: $ONLINE"

if dry; then
  log "[dry-run] would mint one org registration token and SSM-dispatch"
  log "[dry-run]   /usr/local/bin/busbar-runner-register <token> $ORG $RUNNER_LABELS"
  log "[dry-run] to: $ONLINE"
  exit 0
fi

# One call, one token, used immediately. If this 403s the org API limit is exhausted; wait for the
# reset rather than retrying in a loop (a retry loop is what exhausts it).
TOKEN="$(gh api -X POST "/orgs/${ORG}/actions/runners/registration-token" --jq .token)" \
  || die "could not mint a registration token (rate limit? scope? needs admin:org)"
[ -n "$TOKEN" ] || die "empty registration token"
log "minted a registration token (not printed, expires in ~60 min)"

# shellcheck disable=SC2086  # $ONLINE is a whitespace-separated id list and must word-split
CMD_ID="$(aws ssm send-command \
  --instance-ids $ONLINE \
  --document-name AWS-RunShellScript \
  --comment "register busbar CI runners" \
  --parameters "commands=[\"/usr/local/bin/busbar-runner-register '$TOKEN' '$ORG' '$RUNNER_LABELS'\"]" \
  --query 'Command.CommandId' --output text)" || die "send-command failed"
unset TOKEN
log "ssm command $CMD_ID dispatched; polling"

log "ssm: $(ssm_wait "$CMD_ID" 60 10)"

log "org runners now registered:"
gh api "/orgs/${ORG}/actions/runners" \
  --jq '.runners[] | "  \(.name)  \(.status)  busy=\(.busy)  [\([.labels[].name] | join(","))]"' \
  || log "(could not list runners — check the API limit)"
