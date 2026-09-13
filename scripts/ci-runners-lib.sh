#!/usr/bin/env bash
# Shared names and helpers for the self-hosted GitHub Actions runner fleet.
#
# WHY A SEPARATE FLEET AND NOT GITHUB-HOSTED RUNNERS. The org is on the GitHub Team plan: 60
# concurrent hosted jobs, shared by every workflow in every repo. A keep-proof run is ~12 jobs
# (fmt/clippy/build, five test shards, the shard-total, the gate leg, design-bindings, the oracle,
# the construction gate, the verdict), so five concurrent hand-backs saturate the entire org
# allowance and the sixth agent's push sits in `queued` behind work it has nothing to do with.
# With 25-50 agents pushing, the queue — not the compiler — is the wall clock.
#
# The shape here deliberately mirrors scripts/run-mutants-ec2.sh, the EC2 pattern this repo already
# uses: default VPC, an SSM-managed Ubuntu 24.04 AMI id, one security group, spot capacity, and the
# instance Name tag carrying the fleet name so `aws ec2 describe-instances` stays legible when
# mutant boxes and runner boxes are up at once.
#
# SHELLCHECK: this file is SOURCED, never executed, so every name it defines is "unused" here and
# consumed by the five scripts that source it. SC2034 is off file-wide for that reason alone.
# shellcheck disable=SC2034
set -uo pipefail

: "${AWS_REGION:=us-east-1}"
: "${AWS_DEFAULT_REGION:=$AWS_REGION}"
export AWS_REGION AWS_DEFAULT_REGION

# ── Fleet identity ──────────────────────────────────────────────────────────────────────────────
FLEET="${FLEET:-busbar-ci-runner}"          # Name tag AND the tag every script filters on
ORG="${ORG:-GetBusbar}"
RUNNER_LABELS="${RUNNER_LABELS:-busbar-xl}" # `self-hosted,linux,x64` are added by the runner itself
SG_NAME="${SG_NAME:-busbar-ci-runner-sg}"
ROLE_NAME="${ROLE_NAME:-busbar-ci-runner-role}"
PROFILE_NAME="${PROFILE_NAME:-busbar-ci-runner}"
LT_NAME="${LT_NAME:-busbar-ci-runner-lt}"
SCCACHE_BUCKET="${SCCACHE_BUCKET:-busbar-ci-sccache-us-east-1}"
# `local` (the default) or `s3`. See the SCCACHE_BACKEND block in ci-runner-bootstrap.sh: the S3
# bucket and its IAM policy are provisioned either way, so switching is one variable and a relaunch.
SCCACHE_BACKEND="${CI_RUNNER_SCCACHE:-local}"
# OFF by default. See the long comment in ci-runner-bootstrap.sh: on, it terminated the whole fleet
# at 02:00 PT and left 32 offline registrations routing jobs into nothing until someone noticed.
NIGHTLY_STOP="${CI_RUNNER_NIGHTLY_STOP:-0}"

# ── Fleet size ──────────────────────────────────────────────────────────────────────────────────
# See docs/ci/self-hosted-runners.md for the arithmetic these two defaults come from.
ITYPE="${CI_RUNNER_ITYPE:-c7a.8xlarge}"     # 32 vCPU x86-64 (AMD Genoa), compute-optimised
COUNT="${CI_RUNNER_COUNT:-4}"               # instances
AGENTS="${CI_RUNNER_AGENTS:-4}"             # runner agents per instance -> 8 vCPU per concurrent job
DISK_GB="${CI_RUNNER_DISK_GB:-300}"         # AGENTS separate _work trees, each with its own target/

# Ubuntu 24.04 amd64, resolved from Canonical's SSM parameter exactly as run-mutants-ec2.sh does
# (that script's parameter path ends in .../arm64/... because its boxes are Graviton; the runners
# are x86-64 because the `x64` runner label and the release artefacts both mean x86-64).
AMI_SSM="/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require_aws() {
  aws sts get-caller-identity >/dev/null 2>&1 \
    || die "no AWS credentials (need a profile/role with ec2, iam, s3 and ssm rights in $AWS_REGION)"
}

fleet_instance_ids() {
  aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=$FLEET" \
              "Name=instance-state-name,Values=pending,running" \
    --query 'Reservations[].Instances[].InstanceId' --output text
}

# ── The on-demand floor ─────────────────────────────────────────────────────────────────────────
# THE FLEET WENT TO ZERO TWICE IN ONE DAY. Once from the nightly stop (removed), and once from
# `instance-terminated-no-capacity` taking all eight c7a.8xlarge at the same instant — because all
# eight were spot, all eight were c7a.8xlarge, and all eight were in us-east-1a. That is not eight
# machines, it is one machine with eight names: a single AZ's single capacity pool.
#
# The floor is the answer to "keep those EC2 boxes up, I don't want us pushing builds and them not
# landing". FLOOR boxes are ON-DEMAND — the same AMI, the same bootstrap, the same labels,
# indistinguishable to a job — and they are counted separately from the spot boxes, topped up
# separately, and NOT taken down by ci-runners-down.sh unless it is given --all. A spot pool can
# vanish; on-demand capacity in a region this size does not, so the worst spot day now degrades
# throughput to FLOOR instead of to zero.
FLOOR="${CI_RUNNER_ONDEMAND_FLOOR:-2}"

# ── Spot diversification ────────────────────────────────────────────────────────────────────────
# One type in one AZ is one pool. Four 32-vCPU x86-64 types across every AZ the region offers them
# in is ~20 pools, and `instance-terminated-no-capacity` is a statement about ONE of them.
# All four are 32 vCPU and x86-64, so CARGO_BUILD_JOBS=32/AGENTS (the load-bearing pin, see the doc)
# holds unchanged whichever one a box turns out to be.
ITYPES="${CI_RUNNER_ITYPES:-c7a.8xlarge m7a.8xlarge c6a.8xlarge c7i.8xlarge}"

# ── Dry run ─────────────────────────────────────────────────────────────────────────────────────
# CI_RUNNER_DRY_RUN=1 prints every MUTATING AWS/gh call instead of making it. Read-only describes
# still run, because a dry run that cannot see the fleet cannot tell you what it would do to it.
DRY_RUN="${CI_RUNNER_DRY_RUN:-0}"
dry() { [ "$DRY_RUN" = 1 ]; }
# A mutating call whose output nobody reads. The launch calls are guarded explicitly instead,
# because their callers consume the instance ids they print.
aws_w() {
  if dry; then printf '[dry-run] aws %s\n' "$*" >&2; return 0; fi
  aws "$@"
}

# Count the whitespace-separated tokens of a possibly-empty string — instance ids and runner names,
# never anything with a space in it. WHITESPACE, not newlines: `aws --output text` returns a list on
# ONE TAB-SEPARATED LINE while `awk '{print $1}'` returns one per line, and the line-counting
# version of this reported "1 host" for an eight-box fleet. `wc -w` is not this either: it needs the
# `[ -z "$x" ]` guard that was being written at four call sites.
n_of() { printf '%s' "${1:-}" | tr -s '[:space:]' '\n' | grep -c . || true; }

# id / lifecycle / az / type, one instance per line. `InstanceLifecycle` is ABSENT on an on-demand
# instance (the CLI renders that as `None`), and that is the discriminator used everywhere below —
# EC2's own answer rather than a tag we might have failed to write.
fleet_instances_tsv() {
  aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=$FLEET" \
              "Name=instance-state-name,Values=pending,running" \
    --query 'Reservations[].Instances[].[InstanceId,InstanceLifecycle,Placement.AvailabilityZone,InstanceType]' \
    --output text
}
fleet_spot_ids()     { fleet_instances_tsv | awk '$2=="spot" {print $1}'; }
fleet_ondemand_ids() { fleet_instances_tsv | awk '$2!="spot" {print $1}'; }

fleet_vpc_id() {
  aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text
}

# One subnet per AZ: the default subnet, which is what run-mutants-ec2.sh and every earlier version
# of this fleet already launch into. `<subnet-id> <az>` per line.
fleet_subnets() {
  aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$1" "Name=default-for-az,Values=true" \
    --query 'Subnets[].[SubnetId,AvailabilityZone]' --output text | sort -k2
}

# `<subnet-id> <az> <instance-type>` for every pair EC2 ACTUALLY OFFERS.
# WHY THE OFFERINGS CALL AND NOT A CROSS PRODUCT: us-east-1e offers almost nothing modern, so a
# cross product spends a quarter of its overrides on guaranteed `Unsupported` errors and produces a
# request that only LOOKS diversified. Ask EC2 which pools exist before asking it for capacity.
capacity_matrix() { # $1 = vpc id
  local vpc="$1" t azs subs sub az
  subs="$(fleet_subnets "$vpc")"
  for t in $ITYPES; do
    azs="$(aws ec2 describe-instance-type-offerings --location-type availability-zone \
             --filters "Name=instance-type,Values=$t" \
             --query 'InstanceTypeOfferings[].Location' --output text | tr '\t' '\n')"
    while read -r sub az; do
      [ -n "$sub" ] || continue
      printf '%s\n' "$azs" | grep -qx "$az" && printf '%s %s %s\n' "$sub" "$az" "$t"
    done <<SUBNETS
$subs
SUBNETS
  done
}

# The floor's preference order: ITYPE across every AZ that has it (so two floor boxes are two AZs,
# never two names for one AZ), then the alternates as a fallback for a bad capacity day.
ondemand_candidates() { # $1 = vpc id
  capacity_matrix "$1" \
    | awk -v primary="$ITYPE" '{ print ($3 == primary ? 0 : 1) " " $0 }' \
    | sort -s -k1,1n | cut -d' ' -f2-
}

# ── Launching ───────────────────────────────────────────────────────────────────────────────────
# Both launchers print the instance ids they created on STDOUT and everything else on STDERR, so a
# caller can write `ids="$(launch_spot 3)"` and still see the log.

launch_ondemand() { # $1 = how many. Echoes the ids launched (possibly fewer than asked for).
  local want="${1:-0}" vpc rows sub az t ids launched="" progressed
  [ "$want" -gt 0 ] 2>/dev/null || return 0
  vpc="$(fleet_vpc_id)"
  rows="$(ondemand_candidates "$vpc")"
  if [ -z "$rows" ]; then
    log "on-demand floor: no subnet in $vpc offers any of: $ITYPES" >&2
    return 1
  fi
  while [ "$want" -gt 0 ]; do
    progressed=0
    while read -r sub az t; do
      [ "$want" -gt 0 ] || break
      [ -n "$sub" ] || continue
      if dry; then
        # shellcheck disable=SC2016  # `$Latest` is the literal launch-template version alias
        printf '[dry-run] aws ec2 run-instances --launch-template LaunchTemplateName=%s,Version=$Latest --count 1 --instance-type %s --subnet-id %s  # ON-DEMAND floor in %s\n' \
          "$LT_NAME" "$t" "$sub" "$az" >&2
        launched="$launched i-dryrun-od-${az}-${t}"
        want=$(( want - 1 )); progressed=1; continue
      fi
      ids="$(aws ec2 run-instances --launch-template "LaunchTemplateName=$LT_NAME,Version=\$Latest" \
        --count 1 --instance-type "$t" --subnet-id "$sub" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$FLEET},{Key=busbar-ci,Value=runner},{Key=busbar-ci-capacity,Value=ondemand}]" \
        --query 'Instances[].InstanceId' --output text 2>/tmp/busbar-od.err)"
      if [ -n "$ids" ]; then
        log "on-demand $t in $az -> $ids" >&2
        launched="$launched $ids"; want=$(( want - 1 )); progressed=1
      else
        log "on-demand $t in $az refused: $(tail -1 /tmp/busbar-od.err 2>/dev/null)" >&2
      fi
    done <<ROWS
$rows
ROWS
    [ "$progressed" = 1 ] || { log "on-demand floor short by $want: no capacity in any pool" >&2; break; }
  done
  printf '%s\n' "${launched# }"
}

launch_spot() { # $1 = how many. Echoes the ids launched (possibly fewer than asked for).
  local want="${1:-0}" vpc rows ov cfg out ids launched="" got sub az t progressed
  [ "$want" -gt 0 ] 2>/dev/null || return 0
  vpc="$(fleet_vpc_id)"
  rows="$(capacity_matrix "$vpc")"
  if [ -z "$rows" ]; then
    log "spot: no subnet in $vpc offers any of: $ITYPES" >&2
    return 1
  fi
  # ── EC2 Fleet, type=instant ───────────────────────────────────────────────────────────────────
  # ONE request naming EVERY pool, and `price-capacity-optimized` picks the pools with the deepest
  # capacity at the best price rather than the cheapest pool outright — which is the setting that
  # actually spreads the boxes. `instant` because this is a script an operator (or a 15-minute
  # reconcile) runs: it returns the instance ids synchronously and leaves NO durable fleet object
  # behind to drift, double-provision, or need deleting.
  ov="$(printf '%s\n' "$rows" | awk '{ printf "%s{\"InstanceType\":\"%s\",\"SubnetId\":\"%s\"}", (NR>1?",":""), $3, $1 }')"
  cfg="$(mktemp)"
  cat > "$cfg" <<JSON
{
  "Type": "instant",
  "LaunchTemplateConfigs": [{
    "LaunchTemplateSpecification": {"LaunchTemplateName": "$LT_NAME", "Version": "\$Latest"},
    "Overrides": [$ov]
  }],
  "TargetCapacitySpecification": {
    "TotalTargetCapacity": $want,
    "DefaultTargetCapacityType": "spot"
  },
  "SpotOptions": {"AllocationStrategy": "price-capacity-optimized"}
}
JSON
  if dry; then
    printf '[dry-run] aws ec2 create-fleet --cli-input-json  # %s pool(s), target %s spot\n' \
      "$(n_of "$rows")" "$want" >&2
    sed 's/^/[dry-run]   /' "$cfg" >&2
    printf '%s\n' "$rows" | sed 's/^/[dry-run]   pool /' >&2
    rm -f "$cfg"
    seq 1 "$want" | sed 's/^/i-dryrun-spot-/' | tr '\n' ' '
    printf '\n'
    return 0
  fi
  out="$(aws ec2 create-fleet --cli-input-json "file://$cfg" --output json 2>/tmp/busbar-spot.err)"
  rm -f "$cfg"
  if [ -n "$out" ]; then
    launched="$(printf '%s' "$out" | jq -r '[.Instances[]?.InstanceIds[]?] | join(" ")' 2>/dev/null)"
    printf '%s' "$out" \
      | jq -r '.Errors[]? | "  pool refused: \(.LaunchTemplateAndOverrides.Overrides.InstanceType // "?") \(.LaunchTemplateAndOverrides.Overrides.SubnetId // "?") \(.ErrorCode // "?")"' \
        2>/dev/null >&2
  else
    log "create-fleet failed: $(tail -1 /tmp/busbar-spot.err 2>/dev/null)" >&2
  fi
  got="$(n_of "$(printf '%s\n' "$launched" | tr ' ' '\n')")"
  [ "$got" -gt 0 ] && log "EC2 Fleet returned $got/$want spot instance(s): $launched" >&2

  # ── Per-AZ RunInstances, for whatever the fleet request could not fill ─────────────────────────
  # CreateFleet can be unavailable (a missing AWSServiceRoleForEC2Spot on a fresh account) or simply
  # short. Walking the same pool list one instance at a time is slower and always available, so the
  # fallback is a different MECHANISM against the same matrix rather than a retry of the one that
  # has just declined.
  want=$(( want - got ))
  while [ "$want" -gt 0 ]; do
    progressed=0
    while read -r sub az t; do
      [ "$want" -gt 0 ] || break
      [ -n "$sub" ] || continue
      ids="$(aws ec2 run-instances --launch-template "LaunchTemplateName=$LT_NAME,Version=\$Latest" \
        --count 1 --instance-type "$t" --subnet-id "$sub" \
        --instance-market-options 'MarketType=spot,SpotOptions={SpotInstanceType=one-time,InstanceInterruptionBehavior=terminate}' \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$FLEET},{Key=busbar-ci,Value=runner},{Key=busbar-ci-capacity,Value=spot}]" \
        --query 'Instances[].InstanceId' --output text 2>/tmp/busbar-spot.err)"
      if [ -n "$ids" ]; then
        log "spot fallback $t in $az -> $ids" >&2
        launched="$launched $ids"; want=$(( want - 1 )); progressed=1
      fi
    done <<ROWS
$rows
ROWS
    [ "$progressed" = 1 ] || { log "spot short by $want across $(n_of "$rows") pool(s)" >&2; break; }
  done
  printf '%s\n' "${launched# }"
}

# ── Ghost registrations ─────────────────────────────────────────────────────────────────────────
# An OFFLINE org runner whose box no longer exists is a routing black hole: GitHub hands it a job,
# the job never runs, and it sits `queued` until the 24h timeout with no error anywhere. That is
# what the nightly stop left behind — 32 of them — and it is what every spot reclaim leaves behind
# in miniature.
#
# THE CHECK IS EXISTENCE, NOT OFFLINE-NESS. ci-runners-down.sh's blanket "delete every offline
# runner" is right when the fleet is being torn down and WRONG on a 15-minute timer: a box eight
# minutes into its bootstrap, or one whose agents are mid-restart, is offline and alive, and
# deleting its registration makes a real box unreachable. So: map the runner name back to the
# instance id the bootstrap minted it from (`ec2-<id-minus-i->-<agent>`) and sweep only the ones
# whose instance EC2 no longer lists in ANY state.
#
# Sets SWEPT_GHOSTS. Names that do not match the fleet's pattern belong to something else and are
# left strictly alone.
SWEPT_GHOSTS=0
sweep_ghost_runners() {
  local live offline rid rname iid
  SWEPT_GHOSTS=0
  live="$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=$FLEET" \
              "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down" \
    --query 'Reservations[].Instances[].InstanceId' --output text | tr '\t' '\n')"
  offline="$(gh api --paginate "/orgs/${ORG}/actions/runners?per_page=100" \
    --jq '.runners[] | select(.status=="offline") | "\(.id) \(.name)"' 2>/dev/null)"
  [ -n "$offline" ] || return 0
  while read -r rid rname; do
    [ -n "$rid" ] || continue
    case "$rname" in
      ec2-*-*) iid="i-$(printf '%s' "$rname" | sed -E 's/^ec2-(.+)-[0-9]+$/\1/')" ;;
      *) continue ;;
    esac
    printf '%s\n' "$live" | grep -qx "$iid" && continue   # the box exists; offline is transient
    if dry; then
      printf '[dry-run] gh api -X DELETE /orgs/%s/actions/runners/%s  # ghost %s (%s is gone)\n' \
        "$ORG" "$rid" "$rname" "$iid" >&2
    else
      gh api -X DELETE "/orgs/${ORG}/actions/runners/${rid}" >/dev/null 2>&1 \
        || { log "  (could not delete ghost $rname)" >&2; continue; }
    fi
    SWEPT_GHOSTS=$(( SWEPT_GHOSTS + 1 ))
  done <<OFFLINE
$offline
OFFLINE
  return 0
}

# ── SSM plumbing shared by register / reconcile / ssh ───────────────────────────────────────────
ssm_online() { # $1 = whitespace-separated instance ids
  [ -n "${1:-}" ] || return 0
  # shellcheck disable=SC2016  # JMESPath backticks are a literal, not a command substitution
  aws ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=$(printf '%s' "$1" | tr -s ' \t\n' ',,,' | sed -e 's/^,//' -e 's/,$//')" \
    --query 'InstanceInformationList[?PingStatus==`Online`].InstanceId' --output text 2>/dev/null
}

ssm_wait() { # $1 = command id, $2 = polls, $3 = seconds between. Echoes the final status.
  local cid="$1" polls="${2:-60}" nap="${3:-10}" st
  for _ in $(seq 1 "$polls"); do
    sleep "$nap"
    st="$(aws ssm list-command-invocations --command-id "$cid" \
          --query 'CommandInvocations[].Status' --output text 2>/dev/null)"
    case "$st" in *Pending*|*InProgress*|*Delayed*) continue ;; *) printf '%s\n' "$st"; return 0 ;; esac
  done
  printf 'TimedOut\n'
}

# ── Registration: the mint and the dispatch, IN THE LIBRARY ─────────────────────────────────────
# THIS LIVED IN ci-runners-register.sh AND THE FLEET SAT AT 8 AGENTS OF 40 FOR AN HOUR BECAUSE OF
# IT. ci-runners-reconcile.sh registered by SHELLING OUT to its sibling — `"$HERE/ci-runners-
# register.sh" $REACHABLE >/dev/null 2>&1 || true` — and on 2026-09-10 the reconcile was being run
# from a copied scripts directory that did not contain that sibling. Every pass printed
# `registering: <eight boxes>` and then, truthfully but uselessly, "still no agents online on those
# boxes — bootstrap is not finished": the exec had failed 127 into /dev/null, the `|| true` ate it,
# and the summary line was indistinguishable from a fleet that was merely still booting. Eight
# fully-bootstrapped 32-vCPU boxes idled with their runner tarballs unpacked and no credentials.
#
# So registration is a FUNCTION OF THE LIBRARY that every caller sources. A scripts directory that
# can run the reconcile at all can register, because the reconcile cannot start without this file —
# `. "$HERE/ci-runners-lib.sh"` is fatal when it is missing, where a missing sibling was silent.
#
# THE TOKEN IS MINTED HERE AND ONLY HERE. `gh api -X POST .../registration-token` returns a
# ~60-minute credential; it travels to the boxes over SSM SendCommand (encrypted in transit, never
# written to a file, never placed in user-data where any CI job could read it back out of the
# metadata service) and is used within seconds. Nothing on the box persists it: after `config.sh`
# runs the box holds a per-runner .credentials issued by GitHub, not this token.
#
# Returns 0 only when the dispatch actually succeeded on every named box. A caller that ignores the
# status is re-introducing the defect above.
register_agents() { # $@ = SSM-reachable instance ids. Echoes nothing; the log goes to stderr.
  local ids="$*" token cid st
  [ -n "$ids" ] || return 0
  if dry; then
    log "[dry-run] gh api -X POST /orgs/$ORG/actions/runners/registration-token" >&2
    log "[dry-run] aws ssm send-command --instance-ids $ids  # busbar-runner-register <token> $ORG $RUNNER_LABELS" >&2
    return 0
  fi
  # One call, one token, used immediately. If this 403s the org API limit is exhausted; wait for the
  # reset rather than retrying in a loop (a retry loop is what exhausts it).
  token="$(gh api -X POST "/orgs/${ORG}/actions/runners/registration-token" --jq .token 2>/dev/null)"
  if [ -z "$token" ]; then
    log "REGISTRATION FAILED: could not mint a token (rate limit? scope? needs admin:org)" >&2
    return 1
  fi
  log "minted a registration token (not printed, expires in ~60 min)" >&2
  # shellcheck disable=SC2086  # a whitespace-separated id list, one argv entry per instance
  cid="$(aws ssm send-command \
    --instance-ids $ids \
    --document-name AWS-RunShellScript \
    --comment "register busbar CI runners" \
    --parameters "commands=[\"/usr/local/bin/busbar-runner-register '$token' '$ORG' '$RUNNER_LABELS'\"]" \
    --query 'Command.CommandId' --output text 2>/dev/null)"
  unset token
  if [ -z "$cid" ]; then
    log "REGISTRATION FAILED: send-command was not accepted" >&2
    return 1
  fi
  st="$(ssm_wait "$cid" 60 10)"
  log "ssm $cid: $st" >&2
  case "$st" in
    *Failed*|*TimedOut*|*Cancelled*|*Undeliverable*|*Terminated*)
      log "REGISTRATION FAILED on at least one box: $st" >&2; return 1 ;;
  esac
  return 0
}

# The host list every remote entry point reads. Written here rather than only in ci-runners-ssh.sh
# because it goes STALE the moment a spot box is reclaimed, and a stale entry makes the round-robin
# allocator in ci-remote-lib.sh hand an agent a host that no longer exists.
write_fleet_file() {
  local f="${BUSBAR_FLEET_FILE:-$HOME/.busbar-fleet}"
  if dry; then printf '[dry-run] would rewrite %s from the live fleet\n' "$f" >&2; return 0; fi
  {
    echo "# busbar CI fleet — written by scripts/ci-runners-*.sh at $(date -u +%FT%TZ)"
    echo "# <instance-id> <az> <private-ip>   (ssh reaches these over SSM; there is no public port)"
    aws ec2 describe-instances \
      --filters "Name=tag:Name,Values=$FLEET" "Name=instance-state-name,Values=running" \
      --query 'Reservations[].Instances[].[InstanceId,Placement.AvailabilityZone,PrivateIpAddress]' \
      --output text
  } > "$f"
}
