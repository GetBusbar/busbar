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
# THE TOKEN IS MINTED IN ONE PLACE: register_agents in scripts/ci-runners-lib.sh, which this
# script and ci-runners-reconcile.sh both call. `gh api -X POST .../registration-token` returns a
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

# THE MINT AND THE DISPATCH LIVE IN ci-runners-lib.sh (register_agents), not here. This script is
# the operator's entry point to them; ci-runners-reconcile.sh calls the same function directly
# rather than shelling out to this file — see the long comment above register_agents for the hour
# of dead fleet that bought that rule.
# shellcheck disable=SC2086  # a whitespace-separated id list and must word-split
register_agents $ONLINE || die "registration failed (see above)"
dry && exit 0

log "org runners now registered:"
gh api "/orgs/${ORG}/actions/runners" \
  --jq '.runners[] | "  \(.name)  \(.status)  busy=\(.busy)  [\([.labels[].name] | join(","))]"' \
  || log "(could not list runners — check the API limit)"
