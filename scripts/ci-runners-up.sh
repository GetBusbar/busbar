#!/usr/bin/env bash
# Bring the busbar self-hosted GitHub Actions runner fleet UP.
#
#   ./scripts/ci-runners-up.sh                 # 2 on-demand + 4 spot, 4 agents each
#   CI_RUNNER_COUNT=8 ./scripts/ci-runners-up.sh              # 2 on-demand + 8 spot
#   CI_RUNNER_ONDEMAND_FLOOR=0 ./scripts/ci-runners-up.sh     # spot only (the pre-2026-09-09 shape)
#   CI_RUNNER_DRY_RUN=1 ./scripts/ci-runners-up.sh            # print the AWS calls, make none
#   CI_RUNNER_ITYPE=c7a.16xlarge CI_RUNNER_AGENTS=8 ./scripts/ci-runners-up.sh
#
# Idempotent: the IAM role, the sccache bucket, the security group and the launch template are
# created only if absent, so this is also the "scale up" command — it tops the fleet up to
# CI_RUNNER_COUNT and leaves boxes that are already running alone.
#
# TWO KINDS OF CAPACITY, LAUNCHED IN THIS ORDER.
#
#   1. CI_RUNNER_ONDEMAND_FLOOR (default 2) ON-DEMAND boxes, launched FIRST and spread across AZs.
#   2. CI_RUNNER_COUNT SPOT boxes, requested across every (AZ, instance-type) pool the region
#      offers, so no single pool's reclaim can take the fleet to zero.
#
# The floor goes FIRST deliberately: if the account is at an instance limit, or the launch template
# is wrong, the thing that fails is the spot top-up and the guaranteed capacity is already up. The
# reverse order gets you eight spot boxes and no floor on exactly the day the floor is the point.
#
# Spot is still where the throughput comes from — CI is interruption-tolerant by construction (a
# reclaimed box loses at most the jobs in flight, and `concurrency: cancel-in-progress` would have
# killed them on a re-push anyway) and it is ~60% off on-demand. What changed is that "spot" no
# longer means "one instance type in one AZ": on 2026-09-09 `instance-terminated-no-capacity` took
# all eight c7a.8xlarge in us-east-1a in one moment and the fleet was at zero with nothing to bring
# it back. See scripts/ci-runners-reconcile.sh, which is what brings it back now.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci-runners-lib.sh
. "$HERE/ci-runners-lib.sh"

require_aws
command -v gh >/dev/null || die "gh is required (registration tokens are minted with it)"

RUST_CHANNEL="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$HERE/../rust-toolchain.toml" | head -1)"
[ -n "$RUST_CHANNEL" ] || die "could not read the channel out of rust-toolchain.toml"
VCPU_PER_AGENT="${CI_RUNNER_VCPU_PER_AGENT:-}"
if [ -z "$VCPU_PER_AGENT" ]; then
  total_vcpu="$(aws ec2 describe-instance-types --instance-types "$ITYPE" \
                 --query 'InstanceTypes[0].VCpuInfo.DefaultVCpus' --output text)"
  VCPU_PER_AGENT=$(( total_vcpu / AGENTS ))
fi
log "fleet=$FLEET type=$ITYPE spot=$COUNT on-demand-floor=$FLOOR agents/box=$AGENTS jobs=$(( (COUNT + FLOOR) * AGENTS )) rust=$RUST_CHANNEL region=$AWS_REGION"
log "spot pools: $ITYPES x every AZ of the default VPC that offers them"
dry && log "DRY RUN: read-only describes still run; nothing will be created, launched or tagged"

# ── 1. sccache bucket (same region as the fleet, 14-day lifecycle) ──────────────────────────────
if ! aws s3api head-bucket --bucket "$SCCACHE_BUCKET" >/dev/null 2>&1; then
  log "creating s3://$SCCACHE_BUCKET"
  if [ "$AWS_REGION" = "us-east-1" ]; then
    aws_w s3api create-bucket --bucket "$SCCACHE_BUCKET" >/dev/null
  else
    aws_w s3api create-bucket --bucket "$SCCACHE_BUCKET" \
      --create-bucket-configuration "LocationConstraint=$AWS_REGION" >/dev/null
  fi
  aws_w s3api put-public-access-block --bucket "$SCCACHE_BUCKET" \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null
fi
# A compiler cache with no expiry is a bucket that grows forever and is never read past its first
# fortnight. 14 days spans a toolchain bump plus a long-lived integration branch.
aws_w s3api put-bucket-lifecycle-configuration --bucket "$SCCACHE_BUCKET" --lifecycle-configuration '{
  "Rules": [{"ID":"expire-14d","Status":"Enabled","Filter":{"Prefix":""},
             "Expiration":{"Days":14},
             "AbortIncompleteMultipartUpload":{"DaysAfterInitiation":1}}]}' >/dev/null

# ── 2. IAM role: SSM (how registration and admin reach the box) + the sccache bucket ────────────
if ! aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  log "creating IAM role $ROLE_NAME"
  aws_w iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},
                  "Action":"sts:AssumeRole"}]}' >/dev/null
fi
# SSM Session Manager, NOT an inbound SSH rule: the security group below opens nothing at all, so
# the fleet has no listening attack surface, and there is no private key to distribute or rotate.
aws_w iam attach-role-policy --role-name "$ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore >/dev/null 2>&1
aws_w iam put-role-policy --role-name "$ROLE_NAME" --policy-name sccache-s3 --policy-document "{
  \"Version\":\"2012-10-17\",
  \"Statement\":[{\"Effect\":\"Allow\",
    \"Action\":[\"s3:GetObject\",\"s3:PutObject\",\"s3:DeleteObject\",\"s3:ListBucket\",\"s3:GetBucketLocation\"],
    \"Resource\":[\"arn:aws:s3:::$SCCACHE_BUCKET\",\"arn:aws:s3:::$SCCACHE_BUCKET/*\"]}]}" >/dev/null
if ! aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null 2>&1; then
  aws_w iam create-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null
  aws_w iam add-role-to-instance-profile --instance-profile-name "$PROFILE_NAME" \
    --role-name "$ROLE_NAME" >/dev/null
  dry || sleep 10   # instance-profile propagation; RunInstances 400s on a profile it cannot see yet
fi

# ── 3. Security group: egress only ─────────────────────────────────────────────────────────────
# A GitHub Actions runner DIALS OUT to github.com and holds the connection; nothing ever connects
# IN. Unlike gateway-bench-sg (which opens 22 because run-mutants-ec2.sh drives its box over SSH),
# this group has no ingress rule at all — admin goes through SSM.
VPC_ID="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
SG_ID="$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" \
          --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)"
if [ -z "$SG_ID" ] || [ "$SG_ID" = "None" ]; then
  log "creating security group $SG_NAME (egress only)"
  if dry; then
    printf '[dry-run] aws ec2 create-security-group --group-name %s --vpc-id %s\n' "$SG_NAME" "$VPC_ID" >&2
    SG_ID="sg-dryrun"
  else
    SG_ID="$(aws ec2 create-security-group --group-name "$SG_NAME" --vpc-id "$VPC_ID" \
      --description "busbar self-hosted CI runners: egress only, admin over SSM" \
      --query GroupId --output text)"
  fi
  aws_w ec2 revoke-security-group-ingress --group-id "$SG_ID" --protocol -1 --port -1 \
    --cidr 0.0.0.0/0 >/dev/null 2>&1
fi
log "sg $SG_ID in $VPC_ID"

# ── 4. Launch template ─────────────────────────────────────────────────────────────────────────
AMI="$(aws ssm get-parameter --name "$AMI_SSM" --query Parameter.Value --output text)"
log "ubuntu 24.04 amd64 ami $AMI"
UD="$(mktemp)"
sed -e "s|__AGENTS__|$AGENTS|g" \
    -e "s|__SCCACHE_BUCKET__|$SCCACHE_BUCKET|g" \
    -e "s|__SCCACHE_REGION__|$AWS_REGION|g" \
    -e "s|__SCCACHE_BACKEND__|$SCCACHE_BACKEND|g" \
    -e "s|__NIGHTLY_STOP__|$NIGHTLY_STOP|g" \
    -e "s|__RUNNER_LABELS__|$RUNNER_LABELS|g" \
    -e "s|__ORG__|$ORG|g" \
    -e "s|__RUST_CHANNEL__|$RUST_CHANNEL|g" \
    -e "s|__VCPU_PER_AGENT__|$VCPU_PER_AGENT|g" \
    "$HERE/ci-runner-bootstrap.sh" > "$UD"
# GZIPPED, BECAUSE USER-DATA IS CAPPED AT 16384 BYTES AND THIS SCRIPT SAYS WHY IT DOES THINGS.
# EC2 refuses `CreateLaunchTemplateVersion` outright with `InvalidUserData.Malformed: User data is
# limited to 16384 bytes` — and it refuses the NEW VERSION while happily leaving the OLD one as
# default, so a scale-up "succeeds" and quietly launches boxes from a stale template. That happened
# once: four new instances came up without the GitHub CLI, without python3-venv and without the
# per-agent cargo homes, because the version carrying them had been rejected minutes earlier.
#
# cloud-init sniffs the gzip magic number and decompresses before executing, so compressing costs
# nothing and buys roughly 4x the room. The comments in ci-runner-bootstrap.sh are the reason the
# fleet is intelligible; they should not be the reason a scale-up silently regresses.
UD_B64="$(gzip -9 -c < "$UD" | base64 | tr -d '\n')"
ud_bytes=$(( ${#UD_B64} * 3 / 4 ))
log "user-data: $(wc -c <"$UD") bytes raw, ${ud_bytes} gzipped (EC2 cap 16384)"
[ "$ud_bytes" -lt 16384 ] || die "user-data is ${ud_bytes} bytes gzipped, over EC2's 16384 cap"
LT_DATA="$(mktemp)"
cat > "$LT_DATA" <<JSON
{
  "ImageId": "$AMI",
  "InstanceType": "$ITYPE",
  "IamInstanceProfile": {"Name": "$PROFILE_NAME"},
  "SecurityGroupIds": ["$SG_ID"],
  "UserData": "$UD_B64",
  "InstanceInitiatedShutdownBehavior": "terminate",
  "BlockDeviceMappings": [
    {"DeviceName": "/dev/sda1",
     "Ebs": {"VolumeSize": $DISK_GB, "VolumeType": "gp3", "Iops": 6000, "Throughput": 500,
             "DeleteOnTermination": true}}
  ],
  "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 2},
  "TagSpecifications": [
    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "$FLEET"},
                                          {"Key": "busbar-ci", "Value": "runner"}]},
    {"ResourceType": "volume",   "Tags": [{"Key": "Name", "Value": "$FLEET"}]}
  ]
}
JSON
if aws ec2 describe-launch-templates --launch-template-names "$LT_NAME" >/dev/null 2>&1; then
  log "new launch template version for $LT_NAME"
  # A REFUSED VERSION MUST STOP THE SCALE-UP. Without this the command prints its error, the script
  # carries on, and `run-instances --version $Latest` launches from the previous default — boxes
  # that look right in `describe-instances` and are missing whatever the new version was adding.
  # shellcheck disable=SC2016  # `$Latest` is EC2's literal version alias, not a shell variable
  aws_w ec2 create-launch-template-version --launch-template-name "$LT_NAME" \
    --source-version '$Latest' --launch-template-data "file://$LT_DATA" \
    --query 'LaunchTemplateVersion.VersionNumber' --output text \
    || die "the launch template version was REFUSED; not launching from a stale one"
  # shellcheck disable=SC2016  # ditto
  aws_w ec2 modify-launch-template --launch-template-name "$LT_NAME" \
    --default-version '$Latest' >/dev/null
else
  log "creating launch template $LT_NAME"
  aws_w ec2 create-launch-template --launch-template-name "$LT_NAME" \
    --launch-template-data "file://$LT_DATA" >/dev/null
fi

# ── 5. Top the fleet up: the ON-DEMAND FLOOR first, then the SPOT capacity ──────────────────
# The two are counted SEPARATELY, off `InstanceLifecycle`, because "the fleet has 8 boxes" is not
# the fact that matters after a reclaim — "the fleet has 0 boxes that cannot be reclaimed" is.
# REGISTERED, not awake: a stopped box still counts toward the floor (see ci-runners-lib.sh) — the
# awake-only query would launch a replacement for every box the idle stopper just put to sleep.
have_od="$(n_of "$(fleet_registered_ondemand_ids)")"
have_spot="$(n_of "$(fleet_registered_spot_ids)")"
log "have: on-demand $have_od/$FLOOR, spot $have_spot/$COUNT registered"

want_od=$(( FLOOR - have_od ))
if [ "$want_od" -gt 0 ]; then
  log "launching $want_od on-demand floor instance(s)"
  od_ids="$(launch_ondemand "$want_od")"
  log "on-demand launched: ${od_ids:-none}"
else
  log "on-demand floor already satisfied"
fi

want_spot=$(( COUNT - have_spot ))
if [ "$want_spot" -gt 0 ]; then
  log "launching $want_spot spot instance(s), diversified over the pool matrix"
  spot_ids="$(launch_spot "$want_spot")"
  log "spot launched: ${spot_ids:-none}"
else
  log "spot capacity already at $have_spot; nothing to launch"
fi

log "instances now (id / lifecycle / az / type):"
fleet_instances_tsv | sed 's/^/  /'
log "bootstrap takes ~8-12 min (apt, rustup, runner, and a full pre-warm build)."
log "next: ./scripts/ci-runners-reconcile.sh   # sweeps ghosts, registers, refreshes ~/.busbar-fleet"
