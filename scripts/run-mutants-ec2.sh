#!/usr/bin/env bash
# Run cargo-mutants for busbar core on ONE big EC2 box and bring the report home. Mutation testing
# is embarrassingly parallel and stateless, so a big short-lived box beats pinning a laptop hard
# enough to reboot it.
#
# The instance Name tag below is deliberately specific (not a generic "mutants" name) so
# `aws ec2 describe-instances` stays legible when several boxes are up at once. Pass MUTANT_LABEL
# to make it more specific still.
#
# The box is terminated on every exit path, including failure and Ctrl-C.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="${BENCH_STATE_DIR:-$HOME/.cache/gateway-bench}"
KEYNAME="gateway-bench-key"; KEYFILE="$STATE/${KEYNAME}.pem"
SGNAME="gateway-bench-sg"
ITYPE="${MUTANT_ITYPE:-c7g.8xlarge}"          # 32 vCPU Graviton, compute-optimized
JOBS="${MUTANT_JOBS:-12}"                      # test processes in flight; see note by cargo mutants below
DISK_GB="${MUTANT_DISK_GB:-120}"               # each of JOBS parallel workers gets its own build
                                                # copy under mutants.out; 60G was observed to run out
                                                # mid-run (shard7-of-12, ERROR write message to log:
                                                # No space left on device) at -j 12 on a multi-file
                                                # shard, aborting the run with real work lost
LABEL="${MUTANT_LABEL:-$(git -C "$HERE" branch --show-current 2>/dev/null || echo adhoc)}"
NAME_TAG="mutants-busbarai-core-${LABEL}"
SSM="/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"
SSHOPT="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -i $KEYFILE"
OUT="$HERE/mutants-report/${LABEL}"
# Scope: a glob/path list passed to `cargo mutants --file`. Whole-workspace is not viable (a smaller
# crate alone clocked 2,318 mutants x ~60s, 38h serial) — always scope to the files the change
# actually touched. Space-separated globs, e.g.:
#   MUTANT_FILES="crates/busbar-core/src/admin/v1/service.rs crates/busbar-core/src/governance/*.rs" ./scripts/run-mutants-ec2.sh
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
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$DISK_GB,VolumeType=gp3}" \
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
#
# --features openapi-schema (NOT --all-features): without SOME feature enablement, code behind a
# non-default feature (e.g. busbar's `openapi-schema`, CI-only, gates openapi_doc()/
# openapi_operation_id()/capitalize() AND their own golden/drift test) is invisible to both the
# mutator's build AND that feature's own real test suite — a mutant injected into a cfg'd-out
# block compiles trivially (rustc never even type-checks stripped cfg arms) and no test can catch
# it, so cargo-mutants reports it MISSED even though the real, feature-enabled test suite genuinely
# catches the equivalent hand-applied mutation (confirmed by hand: shard1-of-12's 11
# openapi_doc/operation_id/capitalize "MISSED" mutants were entirely this artifact, not real gaps).
#
# `--all-features` (tried first) is WRONG here and burned 6 EC2 boxes on an instant baseline-build
# failure: `txn-fence-red` gates admin/v1/json/tests/txn_fence.rs, a NEGATIVE compile-fence test
# that is REQUIRED to fail to type-check (its own Cargo.toml comment: "a successful build under
# this feature is the test failing") — enabling it via --all-features makes cargo build itself fail
# before a single mutant runs. `loom-model` is also special-purpose (scripts/loom.sh's own
# exhaustive-interleaving harness). openapi-schema is the one feature actually worth mutating
# under; name it explicitly instead of reaching for --all-features again.
FILE_ARGS=""
for f in $FILES; do FILE_ARGS="$FILE_ARGS --file $f"; done
log "running mutants (-j $JOBS) over: $FILES - this is the long part"
ssh $SSHOPT "ubuntu@$IP" bash -s <<REMOTE
. "\$HOME/.cargo/env"
cd ~/bench
nohup cargo mutants --jobs $JOBS --timeout 300 --features openapi-schema $FILE_ARGS -- -- --skip $SKIP_TESTS > ~/mutants.log 2>&1 &
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
  #
  # BUT: ssh itself can fail (a transient connectivity blip over a multi-hour polling loop), and
  # that is NOT the same thing as "confirmed zero cargo-mutants processes" -- collapsing both into
  # "0" via a bare `${running_now:-0}` fallback (an earlier version of this fix did exactly that)
  # made a single dropped SSH connection look identical to job completion, causing the `cleanup`
  # trap to terminate the box and pull whatever partial report existed while cargo-mutants was
  # still mid-run mid-run: the exact silent-data-loss failure mode the rsync-retry fix below this
  # loop exists to prevent, just moved one step earlier. ssh's own exit code distinguishes the two:
  # 255 is ssh's OWN connection-failure signal (never returned by a remote command, which can use
  # any code 0-254); capture it separately and treat ONLY a real ssh failure as "unknown", not "0".
  ssh_out="$(ssh $SSHOPT "ubuntu@$IP" 'pgrep -c cargo-mutants' 2>/dev/null)"
  ssh_status=$?
  if [[ "$ssh_status" -eq 255 ]]; then
    running_now="?"
  else
    running_now="${ssh_out:-0}"
  fi
  tail_now="$(ssh $SSHOPT "ubuntu@$IP" 'tail -1 ~/mutants.log 2>/dev/null' 2>/dev/null || true)"
  log "mutants running=$running_now | $tail_now"
  [[ "$running_now" == "0" ]] && break
done

log "pulling report"
mkdir -p "$OUT"
# RETRY, don't silently swallow: a bare `|| true` here previously meant a transient SSH/rsync
# failure (e.g. several shards' boxes finishing within the same minute and contending for this
# laptop's network) left the local report dir EMPTY while the box still got torn down by the
# `cleanup` trap below — the mutation-testing work was done remotely but never came home, and
# nothing said so. Retry a few times; if it still fails, DO NOT terminate the box (skip cleanup)
# so the report can be pulled by hand from a still-live instance instead of being lost for good.
pull_ok=0
for _ in 1 2 3 4 5; do
  if rsync -az -e "ssh $SSHOPT" "ubuntu@$IP:~/bench/mutants.out/" "$OUT/" \
     && rsync -az -e "ssh $SSHOPT" "ubuntu@$IP:~/mutants.log" "$OUT/mutants.log"; then
    pull_ok=1
    break
  fi
  log "rsync pull failed, retrying in 15s"
  sleep 15
done
# `$OUT/mutants.log` is a near-useless completion signal on its own: bash creates it on the
# remote box the instant `nohup cargo mutants ... > ~/mutants.log 2>&1 &` runs, whether
# cargo-mutants ever produced real output or died instantly (bad build, wrong branch, a
# provisioning heredoc failure this script also never checks the exit status of) — so `&& !-e
# mutants.log` was true almost every time `pull_ok=1`, collapsing this whole check to just
# `pull_ok != 1` and letting a genuinely broken/incomplete remote run print "report in $OUT" as
# if it succeeded. `missed.txt`/`outcomes.json` are cargo-mutants' own real output files —
# require one of THOSE, not the log.
if [[ "$pull_ok" != "1" ]] || [[ ! -e "$OUT/missed.txt" && ! -e "$OUT/outcomes.json" ]]; then
  log "FAILED to pull a non-empty report from $IP after retries — leaving $IID RUNNING (not \
terminating) so the report can be recovered by hand: rsync -az -e \"ssh $SSHOPT\" \
\"ubuntu@$IP:~/bench/mutants.out/\" \"$OUT/\""
  trap - EXIT INT TERM
  exit 1
fi
log "report in $OUT"
ls -la "$OUT" | head
