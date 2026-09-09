#!/usr/bin/env bash
# The transport half of `scripts/land.sh --remote`. Never invoked directly; land.sh execs it.
#
#   scripts/land.sh --remote i-0abc… --batch target/gate/batch-17.txt
#   LAND_REMOTE=auto scripts/land.sh --batch target/gate/batch-17.txt      # round-robin a host
#
# WHAT IT IS RESPONSIBLE FOR, AND WHAT IT REFUSES TO BE RESPONSIBLE FOR. It moves a tree and a
# batch file to a fleet box, runs THE SAME scripts/land.sh there with THE SAME arguments minus
# --remote, streams the log to this terminal as it happens, brings <batch>.result back to the path
# the local queue runner reads, and exits with the remote's status. It makes no judgement of its
# own: there is no "the transport worked so the landing is green" path, because that is the exact
# failure mode where a proof harness reports success for successfully proving nothing.
#
# THE PICKS ARE PUSHED SEPARATELY FROM THE TIP. A batch line names commits that live in an agent's
# worktree; they are objects in this repository but they are NOT reachable from HEAD, so a plain
# `push HEAD` leaves the box with a batch it cannot cherry-pick. Every hash the batch mentions is
# pushed under refs/proof/<ref>/<hash>, which both transfers the object and keeps it alive against
# the box's gc.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/ci-remote-lib.sh
. "$HERE/ci-remote-lib.sh"

HOST=""
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --host)   HOST="$2"; shift 2 ;;
    --remote) shift 2 ;;                 # already consumed by land.sh; must not reach the box
    *) ARGS+=("$1"); shift ;;
  esac
done
case "$HOST" in ''|auto|1|true|yes) HOST="" ;; esac
remote_wrapper
[ -n "$HOST" ] || HOST="$(fleet_pick_host)"

# The batch file, if this is a batch. Its path on the box mirrors its path here, so the log the box
# prints names paths the operator recognises.
BATCH=""
i=0
while [ $i -lt ${#ARGS[@]} ]; do
  [ "${ARGS[$i]}" = "--batch" ] && BATCH="${ARGS[$((i+1))]}"
  i=$((i+1))
done

REF="land-$(date -u +%Y%m%d-%H%M%S)-$$"
HASHES=""
if [ -n "$BATCH" ]; then
  [ -f "$BATCH" ] || rdie "--batch: no such file: $BATCH"
  # Every token that resolves to a commit in THIS repository. A token that does not resolve is not
  # this script's problem to diagnose — land.sh on the box will say so, in its own words.
  for tok in $(tr -s ' \t' '\n\n' < "$BATCH" | grep -Eo '^[0-9a-f]{7,40}$' | sort -u); do
    git -C "$REPO" rev-parse -q --verify "$tok^{commit}" >/dev/null 2>&1 && HASHES="$HASHES $tok"
  done
else
  for tok in "${ARGS[@]}"; do
    case "$tok" in
      -*) continue ;;
      *) git -C "$REPO" rev-parse -q --verify "$tok^{commit}" >/dev/null 2>&1 && HASHES="$HASHES $tok" ;;
    esac
  done
fi

rlog "host $HOST   ref $REF   picks:${HASHES:- <none>}"
# shellcheck disable=SC2086
remote_push_tree "$HOST" "$REPO" "$REF" $HASHES

RBATCH=""
if [ -n "$BATCH" ]; then
  RBATCH="busbar-prove/${BATCH#./}"
  rsh "$HOST" mkdir -p "$(dirname "$RBATCH")"
  rcp_to "$HOST" "$BATCH" "$RBATCH" || rdie "could not copy $BATCH to $HOST"
fi

# The remote argv is this one with the batch path rewritten to the box's copy.
RARGS=()
for a in "${ARGS[@]}"; do
  if [ -n "$BATCH" ] && [ "$a" = "$BATCH" ]; then RARGS+=("${BATCH#./}"); else RARGS+=("$a"); fi
done

START=$(date +%s)
set +e
rsh_script "$HOST" "$REF" "${RARGS[@]}" <<'RUN'
set -uo pipefail
REF="$1"; shift
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TERM_COLOR=always CARGO_INCREMENTAL=0
export RUSTC_WRAPPER=sccache SCCACHE_DIR=/var/cache/sccache SCCACHE_CACHE_SIZE=60G
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
# LAND_REMOTE_INNER is the loop-breaker: this copy of land.sh must run the engine, not delegate.
export LAND_REMOTE_INNER=1
# The box may be running four proofs at once; the recorder's fixed port block would collide.
export LAND_ORACLE_PORT_BASE=$(( 40000 + ( $$ % 40 ) * 200 ))
cd "$HOME/busbar-prove" || { echo "no ~/busbar-prove — ./scripts/prove-remote.sh --setup $(hostname)"; exit 2; }
git fetch -q prove "+refs/heads/$REF:refs/heads/$REF" "+refs/proof/$REF/*:refs/proof/$REF/*" || exit 2
git checkout -q -f "$REF" || exit 2
git clean -qffdx -e target -e .cargo -e node_modules
echo "remote tree: $(git rev-parse --short HEAD)  on $(hostname)"
exec ./scripts/land.sh "$@"
RUN
RC=$?
set -e
END=$(date +%s)

# THE RESULT FILE COMES BACK TO THE PATH THE LOCAL RUNNER ALREADY READS. target/gate/landq3.sh reads
# <batch>.result and nothing else; if it is not here, the queue runner reads a landing that never
# reported, which is worse than a red.
if [ -n "$BATCH" ]; then
  if rcp_back "$HOST" "$RBATCH.result" "$BATCH.result"; then
    rlog "per-line outcomes: $BATCH.result"
    sed 's/^/  /' "$BATCH.result" >&2
  else
    rlog "WARNING: no $RBATCH.result on $HOST — the batch did not reach its reporting stage"
  fi
fi
rlog "host $HOST   exit $RC   wall $(( END - START ))s"
exit "$RC"
