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
  if [ "${ARGS[$i]}" = "--batch" ]; then
    BATCH="${ARGS[$((i+1))]}"
    # THE BOX SEES A REPO-RELATIVE PATH. The queue runner hands land.sh an absolute path under the
    # tree; the box's checkout is at a different absolute path, so the batch travels by its path
    # RELATIVE TO THE REPO and the remote argv carries that. A path outside the repo is refused:
    # there is nowhere on the box to put it that land.sh there would find.
    case "$BATCH" in
      "$REPO"/*) BATCH="${BATCH#"$REPO"/}"; ARGS[$((i+1))]="$BATCH" ;;
      /*) rdie "--batch: $BATCH is outside the repository $REPO" ;;
    esac
  fi
  i=$((i+1))
done

REF="land-$(date -u +%Y%m%d-%H%M%S)-$$"
HASHES=""
if [ -n "$BATCH" ]; then
  [ -f "$REPO/$BATCH" ] || rdie "--batch: no such file: $REPO/$BATCH"
  # Every token that resolves to a commit in THIS repository. A token that does not resolve is not
  # this script's problem to diagnose — land.sh on the box will say so, in its own words.
  for tok in $(tr -s ' \t' '\n\n' < "$REPO/$BATCH" | grep -Eo '^[0-9a-f]{7,40}$' | sort -u); do
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
  rcp_to "$HOST" "$REPO/$BATCH" "$RBATCH" || rdie "could not copy $REPO/$BATCH to $HOST"
fi
# THE ENGINE THE BOX RUNS IS THE ONE THE RUNNER CHOSE. The tree's own scripts/land.sh at the pushed
# HEAD is whatever landed last; the runner may be carrying a fixed land.sh that is itself in the
# queue (the local runner already runs a copy of it, `land.run.sh`). Running the tree's copy on the
# box meant a landing was judged by an engine older than the one on the laptop, and the first fleet
# batch was bisected by a self-test the fix in the batch had already cured. So the runner's land.sh
# — this script's sibling — travels to the box and is what runs there.
rsh "$HOST" mkdir -p busbar-prove/target/gate
ENGINE="$HERE/land.sh"; [ -f "$HERE/land.run.sh" ] && ENGINE="$HERE/land.run.sh"   # the runner's copy is named land.run.sh
rcp_to "$HOST" "$ENGINE" "busbar-prove/target/gate/land.run.sh" || rdie "could not copy the runner's land.sh ($ENGINE) to $HOST"

# The remote argv is this one with the batch path rewritten to the box's copy.
RARGS=()
for a in "${ARGS[@]}"; do
  if [ -n "$BATCH" ] && [ "$a" = "$BATCH" ]; then RARGS+=("${BATCH#./}"); else RARGS+=("$a"); fi
done

START=$(date +%s)
set +e
# DETACHED ON THE BOX, POLLED FROM HERE. The SSM-tunnelled ssh session dies after roughly 3000
# seconds whatever ServerAlive says (observed: every landing longer than that ended in a dead
# session and a proof with no verdict). So the box runs land.sh under setsid with its log and its
# exit status on disk, this side polls with SHORT sessions, and no proof is ever bounded by how long
# one ssh connection survives. The verdict is the .rc file: absent = still running, present =
# land.sh's own exit status. There is no "the session ended so it must have finished" path.
RLOG="busbar-prove/target/land-remote-$REF.log"
RRC="busbar-prove/target/land-remote-$REF.rc"
# THE RUNNER'S CEILING TRAVELS WITH THE JOB. The block below is a quoted heredoc, so a
# `${XTASK_GATE_CEILING_SECS:-1800}` inside it is expanded on the BOX, where nothing sets it: the
# runner's 3600 never arrived and the box judged with 1800 (seen: a green tree reported "hung").
# It goes across as a positional, the one channel this script already owns.
# THE INTEGRATION BASE TRAVELS TOO. The construction gate's ceiling rows diff every ceiling against
# `ceilings::base_ref`, which is the merge-base with `origin/integration/oracle-phase0` — and falls back
# to HEAD~1 when that ref does not resolve. The box's checkout has no `origin` remote (it was renamed
# `prove` at setup), so on a box the ref never resolved: with three picks on the tree, HEAD~1 is the
# second pick, every earlier pick's rise was invisible to `ceiling-rose`, and a raise declared by the
# first pick and measured by the third read as stale. The runner's tip — the base the picks go onto,
# which is exactly what the laptop's own ref points at when the queue is caught up — is pinned under
# that name in the box's checkout before land.sh runs, verified with `rev-parse --verify`, and printed
# into the landing log so a reader of the log can see what the ceilings were judged against.
LAND_BASE_REF="${LAND_BASE_REF:-refs/remotes/origin/integration/oracle-phase0}"
rsh_script "$HOST" "$REF" "${XTASK_GATE_CEILING_SECS:-3600}" "$LAND_BASE_REF" "${RARGS[@]}" <<'RUN'
set -uo pipefail
REF="$1"; CEIL="$2"; BASEREF="$3"; shift 3
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0
export RUSTC_WRAPPER=sccache SCCACHE_DIR=/var/cache/sccache SCCACHE_CACHE_SIZE=60G
# A SERVER PORT OF ITS OWN. sccache's server is addressed by a TCP port that defaults to
# 4226 for every process on the box; the four runner agents each hold one of their own, and
# joining theirs would mean a neighbour's `sccache --stop-server` killing this proof
# mid-compile — seen once, as `Connection reset by peer` inside rustc.
export SCCACHE_SERVER_PORT="${SCCACHE_SERVER_PORT:-4300}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-16}"
export XTASK_GATE_CEILING_SECS="$CEIL"
# LAND_REMOTE_INNER is the loop-breaker: this copy of land.sh must run the engine, not delegate.
export LAND_REMOTE_INNER=1
# The box may be running four proofs at once; the recorder's fixed port block would collide.
export LAND_ORACLE_PORT_BASE=$(( 40000 + ( $$ % 40 ) * 200 ))
cd "$HOME/busbar-prove" || { echo "no ~/busbar-prove — ./scripts/prove-remote.sh --setup $(hostname)"; exit 2; }
git fetch -q prove "+refs/heads/$REF:refs/heads/$REF" "+refs/proof/$REF/*:refs/proof/$REF/*" "+refs/audit-pins/*:refs/audit-pins/*" || exit 2
git checkout -q -f "$REF" || exit 2
git clean -qffdx -e target -e .cargo -e node_modules
mkdir -p target
LOG="target/land-remote-$REF.log"; RC="target/land-remote-$REF.rc"
rm -f "$RC"
echo "remote tree: $(git rev-parse --short HEAD)  on $(hostname)" >"$LOG"
git update-ref "$BASEREF" "$(git rev-parse "refs/heads/$REF")" || exit 2
BASE_SHA="$(git rev-parse --verify --quiet "$BASEREF")" || { echo "integration base $BASEREF does not resolve on $(hostname) — the ceiling rows would judge against HEAD~1" | tee -a "$LOG"; exit 2; }
echo "integration base: $BASEREF = $BASE_SHA (the runner's tip; ceilings are diffed against it)" >>"$LOG"
# The landed tip is published to the bare repo under refs/heads/<ref>-landed the moment land.sh
# returns, whatever its status: a partially green batch has a tip too, and the local side
# fast-forwards to exactly what the box proved.
# The runner's engine, with its tree root pointed at this checkout.
sed "s|^here=.*|here=\"$HOME/busbar-prove\"|" target/gate/land.run.sh >target/gate/land.run.local.sh
setsid nohup bash -c '
  bash target/gate/land.run.local.sh "$@" >>"'"$LOG"'" 2>&1; rc=$?
  git push -q --force prove "HEAD:refs/heads/'"$REF"'-landed" >>"'"$LOG"'" 2>&1
  echo $rc >"'"$RC"'"
' _ "$@" >/dev/null 2>&1 </dev/null &
echo "detached: $LOG"
RUN
[ $? -eq 0 ] || { rlog "could not start the landing on $HOST"; exit 2; }

# POLL. Every 60 s: the .rc file (the verdict), then the log's new bytes (the operator's view).
RC=""; SEEN=0; QUIET=0
while :; do
  sleep 60
  out="$(rsh "$HOST" bash -c "cat $RRC 2>/dev/null; echo ::; wc -c <$RLOG 2>/dev/null" </dev/null 2>/dev/null)"
  if [ -z "$out" ]; then
    QUIET=$((QUIET + 1))
    [ "$QUIET" -ge 10 ] && { rlog "ERROR: $HOST unreachable for 10 polls — no verdict"; RC=2; break; }
    continue
  fi
  QUIET=0
  rc_now="${out%%::*}"; rc_now="$(printf '%s' "$rc_now" | tr -d '[:space:]')"
  size="${out##*::}"; size="$(printf '%s' "$size" | tr -d '[:space:]')"
  case "$size" in ''|*[!0-9]*) size=0 ;; esac
  if [ "$size" -gt "$SEEN" ]; then
    rsh "$HOST" tail -c +"$((SEEN + 1))" "$RLOG" </dev/null 2>/dev/null | sed 's/^/  | /' >&2
    SEEN="$size"
  fi
  if [ -n "$rc_now" ]; then RC="$rc_now"; break; fi
done
set -e
END=$(date +%s)

# THE RESULT FILE COMES BACK TO THE PATH THE LOCAL RUNNER ALREADY READS. target/gate/landq3.sh reads
# <batch>.result and nothing else; if it is not here, the queue runner reads a landing that never
# reported, which is worse than a red.
if [ -n "$BATCH" ]; then
  if rcp_back "$HOST" "$RBATCH.result" "$REPO/$BATCH.result"; then
    rlog "per-line outcomes: $REPO/$BATCH.result"
    sed 's/^/  /' "$REPO/$BATCH.result" >&2
  else
    rlog "WARNING: no $RBATCH.result on $HOST — the batch did not reach its reporting stage"
  fi
  # land.sh on the box appended its rows to the box's land-done.txt; they belong in ours.
  rcp_back "$HOST" "busbar-prove/target/gate/land-done.txt" "$REPO/$BATCH.remote-done" 2>/dev/null \
    && { grep -F -v -x -f "$REPO/target/gate/land-done.txt" "$REPO/$BATCH.remote-done" >>"$REPO/target/gate/land-done.txt" 2>/dev/null || true; rm -f "$REPO/$BATCH.remote-done"; }
fi

# THE LANDED TIP COMES BACK TOO. What the box proved is what this tree must now be at: the local
# HEAD was the base the box started from, so a fast-forward is the only honest move — anything
# else means the tree here and the tree proved there have diverged, and that is a refusal.
if GIT_SSH_COMMAND="$SSH_WRAP" git -C "$REPO" fetch -q "ssh://$REMOTE_USER@$HOST/~/$REMOTE_BARE" "+refs/heads/$REF-landed:refs/remotes/landed/$REF" 2>/dev/null; then
  landed="$(git -C "$REPO" rev-parse "refs/remotes/landed/$REF")"
  if [ "$landed" != "$(git -C "$REPO" rev-parse HEAD)" ]; then
    if git -C "$REPO" merge -q --ff-only "$landed" 2>/dev/null; then
      rlog "tree fast-forwarded to the landed tip $(git -C "$REPO" rev-parse --short HEAD)"
    else
      rlog "ERROR: the landed tip $(echo "$landed" | cut -c1-9) is not a fast-forward of this tree — refusing"; RC=2
    fi
  fi
  git -C "$REPO" update-ref -d "refs/remotes/landed/$REF" 2>/dev/null || true
else
  rlog "WARNING: no landed tip came back from $HOST (refs/heads/$REF-landed)"
  [ "$RC" = 0 ] && RC=2
fi
rlog "host $HOST   exit $RC   wall $(( END - START ))s"
exit "$RC"
