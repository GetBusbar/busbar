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
