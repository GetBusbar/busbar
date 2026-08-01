#!/usr/bin/env bash
# Run cargo-mutants for busbarAI core on ONE big EC2 box and bring the report home. Mirrors
# ~/Developer/busbarAI/benchmarking/run-mutants-ec2.sh (same rationale: mutation testing is
# embarrassingly parallel and stateless, so a big short-lived box beats pinning a laptop hard
# enough to reboot it) but targets THIS repo (GetBusbar/busbar) instead of benchmarking/engine.
#
# Matthew runs several of these concurrently for different repos/crates — the instance Name tag
# below is deliberately specific (not a generic "mutants" name) so `aws ec2 describe-instances`
# stays legible with multiple boxes up at once. Pass MUTANT_LABEL to make it even more specific
# (e.g. "round8-11-fixes").
#
# The box is terminated on every exit path, including failure and Ctrl-C.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="${BENCH_STATE_DIR:-$HOME/.cache/gateway-bench}"
KEYNAME="gateway-bench-key"; KEYFILE="$STATE/${KEYNAME}.pem"
SGNAME="gateway-bench-sg"
ITYPE="${MUTANT_ITYPE:-c7g.8xlarge}"          # 32 vCPU Graviton, compute-optimized
JOBS="${MUTANT_JOBS:-12}"                      # test processes in flight; see note by cargo mutants below
LABEL="${MUTANT_LABEL:-$(git -C "$HERE" branch --show-current 2>/dev/null || echo adhoc)}"
NAME_TAG="mutants-busbarai-core-${LABEL}"
SSM="/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"
SSHOPT="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -i $KEYFILE"
OUT="$HERE/mutants-report/${LABEL}"
# Scope: a glob/path list passed to `cargo mutants --file`. Whole-workspace is not viable (the
# sibling benchmarking run clocked 2,318 mutants x ~60s at 38h serial for a SMALLER crate) —
# always scope to the files a fix round actually touched. Space-separated globs, e.g.:
#   MUTANT_FILES="crates/busbar/src/admin/v1/service.rs crates/busbar/src/governance/*.rs" ./scripts/run-mutants-ec2.sh
FILES="${MUTANT_FILES:-}"
SKIP_TESTS="${MUTANT_SKIP_TESTS:-declared_error_set_is_exactly_what_the_handlers_emit}"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

if [[ -z "$FILES" ]]; then
  echo "MUTANT_FILES is unset — refusing to run mutants over the whole workspace (see script comment)." >&2
  exit 1
fi

SHA="$(git -C "$HERE" rev-parse HEAD)"
if ! git -C "$HERE" branch -r --contains "$SHA" >/dev/null 2>&1; then
  echo "PREFLIGHT: $SHA is not pushed; the box fetches by SHA and would fail." >&2; exit 1
fi
[[ -s "$KEYFILE" ]] || { echo "no key at $KEYFILE" >&2; exit 1; }

SG="$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SGNAME" \
      --query 'SecurityGroups[].GroupId' --output text 2>/dev/null)"
[[ -n "$SG" && "$SG" != "None" ]] || { echo "no security group $SGNAME" >&2; exit 1; }
AMI="$(aws ssm get-parameter --name "$SSM" --query Parameter.Value --output text)"

IID=""
cleanup() {
  if [[ -n "$IID" ]]; then
    log "terminating $IID ($NAME_TAG)"
    aws ec2 terminate-instances --instance-ids "$IID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

log "launching $ITYPE for mutants @ $SHA, tag=$NAME_TAG, files=[$FILES]"
IID="$(aws ec2 run-instances --image-id "$AMI" --instance-type "$ITYPE" --key-name "$KEYNAME" \
  --security-group-ids "$SG" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=60,VolumeType=gp3}' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME_TAG}]" \
  --query 'Instances[0].InstanceId' --output text)" || exit 1
log "instance $IID"
aws ec2 wait instance-running --instance-ids "$IID"
IP="$(aws ec2 describe-instances --instance-ids "$IID" \
      --query 'Reservations[].Instances[].PublicIpAddress' --output text)"
log "ip $IP - waiting for ssh"
for _ in $(seq 1 40); do
  ssh $SSHOPT "ubuntu@$IP" true 2>/dev/null && break; sleep 10
done

log "provisioning (rust + cargo-mutants); this compiles cargo-mutants once, a few minutes"
ssh $SSHOPT "ubuntu@$IP" bash -s <<'REMOTE'
set -e
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential pkg-config libssl-dev git >/dev/null
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
. "$HOME/.cargo/env"
cargo install cargo-mutants --locked >/dev/null 2>&1 || cargo install cargo-mutants --locked
echo "rustc $(rustc --version) / $(cargo mutants --version)"
REMOTE

log "cloning @ $SHA"
ssh $SSHOPT "ubuntu@$IP" "git clone -q https://github.com/GetBusbar/busbar.git bench && git -C bench checkout -q $SHA && echo cloned"

# --jobs, not --test-threads: cargo-mutants runs whole `cargo test` invocations in parallel.
# --file scopes to the fix round's touched files only (see FILES above).
FILE_ARGS=""
for f in $FILES; do FILE_ARGS="$FILE_ARGS --file $f"; done
log "running mutants (-j $JOBS) over: $FILES - this is the long part"
ssh $SSHOPT "ubuntu@$IP" bash -s <<REMOTE
. "\$HOME/.cargo/env"
cd ~/bench
nohup cargo mutants --jobs $JOBS --timeout 300 $FILE_ARGS -- -- --skip $SKIP_TESTS > ~/mutants.log 2>&1 &
echo started
REMOTE

log "waiting for completion (polling every 5m)"
while :; do
  sleep 300
  # `pgrep -c` prints the match count to stdout REGARDLESS of whether it's 0, and only its exit
  # code signals no-match -- so `pgrep -c X || echo 0` was printing TWO lines ("0" from pgrep
  # itself, then another "0" from the fallback) whenever nothing matched, making running_now
  # literally "0\n0" instead of "0" and permanently defeating the `== "0"` check below. No
  # fallback needed: pgrep -c's own stdout is already the right value on every path.
  running_now="$(ssh $SSHOPT "ubuntu@$IP" 'pgrep -c cargo-mutants' 2>/dev/null)"
  running_now="${running_now:-0}"
  tail_now="$(ssh $SSHOPT "ubuntu@$IP" 'tail -1 ~/mutants.log 2>/dev/null' 2>/dev/null || true)"
  log "mutants running=$running_now | $tail_now"
  [[ "$running_now" == "0" ]] && break
done

log "pulling report"
mkdir -p "$OUT"
rsync -az -e "ssh $SSHOPT" "ubuntu@$IP:~/bench/mutants.out/" "$OUT/" 2>/dev/null || true
rsync -az -e "ssh $SSHOPT" "ubuntu@$IP:~/mutants.log" "$OUT/mutants.log" 2>/dev/null || true
log "report in $OUT"
ls -la "$OUT" | head
