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
# shellcheck disable=SC2154   # R_* are assigned by fanout_parse_request in ci-remote-lib.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/ci-remote-lib.sh
. "$HERE/ci-remote-lib.sh"

# ── --selftest: what this file can prove of itself without a fleet ──────────────────────────────
# land.sh runs a touched script's --selftest ON THE BOX (its gate-scripts leg), so a landing that
# edits this file proves on Linux: that it parses; that the integration base still travels as a
# refspec on the checkout's fetch; that the positionals the box unpacks are the ones this side
# sends, in order; and — through ci-remote-lib.sh's own cases — the allocator the fan-out relies on.
if [ "${1:-}" = "--selftest" ]; then
  fails=0
  _ok() { printf '  ok   %s\n' "$1"; }; _fail() { printf '  FAIL %s\n' "$1"; fails=$((fails + 1)); }
  echo "land-remote selftest: this file"
  bash -n "${BASH_SOURCE[0]}" && _ok "parses (bash -n)" || _fail "parses (bash -n)"
  grep -qF -- '"+refs/heads/$REF-base:$BASEREF"' "${BASH_SOURCE[0]}" && _ok "the integration base is a refspec on the checkout's fetch, from \$REF-base" || _fail "the integration base is a refspec on the checkout's fetch"
  grep -qE -- '^git fetch .*\+refs/heads/\$REF:\$BASEREF' "${BASH_SOURCE[0]}" && _fail "the base must never be the pushed tip (\$REF)" || _ok "the base is never the pushed tip"
  grep -qF -- 'rev-parse --verify --quiet "$LAND_BASE_BRANCH"' "${BASH_SOURCE[0]}" && _ok "the base is resolved HERE from refs/heads/integration/oracle-phase0" || _fail "the base is resolved here"
  grep -qE -- 'BASEREF="\$3"; SHARDS="\$4"; BASESHA="\$5"; OBOOT="\$6"; OEGRESS="\$7"; shift 7' "${BASH_SOURCE[0]}" && _ok "the box unpacks REF CEIL BASEREF SHARDS BASESHA OBOOT OEGRESS" || _fail "the box unpacks REF CEIL BASEREF SHARDS BASESHA OBOOT OEGRESS"
  grep -qE -- 'rsh_script "\$HOST" "\$REF" .*"\$BASE_SHA_LOCAL" "\$\{[O]RACLE_BOOT_BOUND_SECS:-\}" "\$\{ORACLE_EGRESS_SETTLE_SECS:-\}"' "${BASH_SOURCE[0]}" && _ok "...and this side sends them in that order" || _fail "this side sends them in that order"
  # ── THE RECORDER'S BOUNDS TRAVEL, LIKE THE CEILING DOES ──────────────────────────────────────
  # The block the box runs is a QUOTED heredoc, so an `${ORACLE_BOOT_BOUND_SECS:-…}` written inside
  # it expands ON THE BOX, where nothing sets it — the same way the runner's XTASK_GATE_CEILING_SECS
  # once never arrived and a green tree was reported hung. An operator who raises the bound on the
  # laptop because the fleet is loaded must have it raised where the recording actually happens.
  # An UNSET bound travels as the empty string and the box is left to scale its own default by its
  # own measured load (land.sh's land_oracle_bounds) — which is the whole point of measuring it there.
  # Twice: the stub exercised below, and the line the box really runs.
  [ "$(grep -cE -- '\[ -n "\$OBOOT" \] && export [O]RACLE_BOOT_BOUND_SECS="\$OBOOT"$' "${BASH_SOURCE[0]}")" = 2 ] && _ok "a bound the laptop set is exported on the box" || _fail "a bound the laptop set is exported on the box"
  grep -qE -- '\[ -n "\$OEGRESS" \] && export [O]RACLE_EGRESS_SETTLE_SECS="\$OEGRESS"$' "${BASH_SOURCE[0]}" && _ok "  ...and so is the settle bound" || _fail "the settle bound is exported on the box"
  _bound() { # $1 = what the laptop sent; prints what the box would have in the environment
    OBOOT="$1" bash -c '
      unset ORACLE_BOOT_BOUND_SECS
      [ -n "$OBOOT" ] && export ORACLE_BOOT_BOUND_SECS="$OBOOT"
      echo "${ORACLE_BOOT_BOUND_SECS:-<unset: the box scales its own>}"'
  }
  [ "$(_bound 900)" = 900 ] && _ok "  ...a laptop that set 900 gets 900 on the box" || _fail "a laptop that set 900 gets 900 on the box"
  [ "$(_bound '')" = "<unset: the box scales its own>" ] && _ok "  ...and an unset one leaves the box to scale its own" || _fail "an unset bound leaves the box to scale its own"
  grep -qE -- 'export ORACLE_BOOT_BOUND_SECS="\$\{ORACLE_BOOT_BOUND_SECS' "${BASH_SOURCE[0]}" && _fail "a bound must never be expanded INSIDE the box's quoted heredoc" || _ok "  ...and no bound is expanded inside the box's own heredoc"
  grep -qF -- '[ "$BASE_SHA" = "$BASESHA" ] ||' "${BASH_SOURCE[0]}" && _ok "the box refuses a base that differs from the laptop's" || _fail "the box refuses a differing base"
  # The shard launcher's .rc line: written after the group, from the variable, by the same shell.
  # An `exit` inside the group is exactly the form that lost every shard's verdict once.
  grep -qF -- 'rsh "$HOST" cat "$pdir/shard-1.rc"' "${BASH_SOURCE[0]}" && _ok "shard 1 is read from the request's recorded directory, by name" || _fail "shard 1 is read by name"
  grep -qE -- 'pdir="busbar-prove/target/land-shards-\$R_gate-\*' "${BASH_SOURCE[0]}" && _fail "shard 1 must not be found by a glob (two landings' files concatenate)" || _ok "shard 1 is never found by a glob"
  grep -qF -- 'rm -rf target/land-shards-*' "${BASH_SOURCE[0]}" && _ok "an earlier landing's request directories are removed before this one starts" || _fail "stale request directories are removed"
  grep -qF -- 'rsh "$HOST" mv -f "$2.tmp" "$2"' "${BASH_SOURCE[0]}" && _ok "a delivered file is renamed into place, never written in place" || _fail "delivery is atomic"
  grep -qF -- 'echo "$rc" >target/shard.rc' "${BASH_SOURCE[0]}" && _ok "the shard launcher writes its .rc after the group, from \$rc" || _fail "the shard launcher writes its .rc after the group"
  grep -qE -- 'exit \$rc; \} >target/shard.log' "${BASH_SOURCE[0]}" && _fail "the shard launcher must not exit from inside the group" || _ok "the shard launcher does not exit from inside the group"
  # THE LANDED-REF CHECK, by mode. The two arms below are the whole of T0-D5's defect: a pre-proof
  # whose box said GREEN was re-scored rc 2 by the ABSENCE of a ref a pre-proof never needed.
  grep -qF -- 'if [ "$PREPROVE" = 1 ]; then' "${BASH_SOURCE[0]}" && _ok "the no-landed-ref arm asks the mode first" || _fail "the no-landed-ref arm asks the mode first"
  grep -qF -- 'rlog "ERROR: a landing with no landed tip cannot fast-forward this tree — refusing"' "${BASH_SOURCE[0]}" && _ok "a LANDING with no landed tip is still a refusal" || _fail "a landing with no landed tip is still a refusal"
  grep -qF -- 'rlog "pre-proof: INFORMATIONAL' "${BASH_SOURCE[0]}" && _ok "a PRE-PROOF with no landed tip is informational, not a verdict" || _fail "a pre-proof with no landed tip is informational"
  grep -qF -- 'OUTCOME="$REPO/$BATCH.result"' "${BASH_SOURCE[0]}" && _ok "the per-line outcome file is remembered as the pre-proof's verdict" || _fail "the per-line outcome file is remembered"
  grep -qF -- '2>"$FETCH_WHY"; then' "${BASH_SOURCE[0]}" && _ok "the landed-ref fetch keeps its reason (never 2>/dev/null)" || _fail "the landed-ref fetch keeps its reason"
  # The arms are exercised, not just spelled: a stub script carrying the same two arms is run in
  # each mode with no ref and a GREEN outcome file, and its RC is read.
  _arm() { # $1 = PREPROVE  $2 = outcome file ('' = none); prints the resulting RC
    PREPROVE="$1" OUTCOME="$2" RC=0 bash -c '
      rlog() { :; }
      if [ "$PREPROVE" = 1 ]; then
        if [ -n "$OUTCOME" ] && [ -s "$OUTCOME" ]; then :; else [ "$RC" = 0 ] && RC=2; fi
      else
        [ "$RC" = 0 ] && RC=2
      fi
      echo "$RC"'
  }
  _st="$(mktemp "${TMPDIR:-/tmp}/land-remote-selftest.XXXXXX")"
  printf 'GREEN\t--prove --tests xtask 6d5bba552 4b6e3e40c 8d48b75ab\n' >"$_st"
  [ "$(_arm 1 "$_st")" = 0 ] && _ok "  ...pre-proof + GREEN outcome + no ref = exit 0" || _fail "pre-proof + GREEN outcome + no ref = exit 0"
  [ "$(_arm 1 "")"    = 2 ] && _ok "  ...pre-proof + no outcome at all + no ref = exit 2" || _fail "pre-proof + no outcome + no ref = exit 2"
  [ "$(_arm 0 "$_st")" = 2 ] && _ok "  ...LANDING + GREEN outcome + no ref = exit 2 (cannot fast-forward)" || _fail "landing + no ref = exit 2"
  rm -f "$_st"
  # ── A BOX THAT STOPPED ANSWERING IS NOT A RED LINE ──────────────────────────────────────────
  # Measured 2026-09-10: two pre-proofs (1735 s and 10116 s) ended here, at "unreachable for 10
  # polls", because AWS reclaimed the SPOT instances they were running on. This side exited 2 and
  # the queue engine had no way to tell that from a proof that ran and failed, so both lines were
  # scored RED — a colour about picks whose proof never finished. Exit 75 (EX_TEMPFAIL) is the
  # transport's own word for "the BOX went away, ask again", and landq4.sh reads it as NONE:box.
  # ONLY ON A PRE-PROOF: a LANDING that loses its box must keep exiting 2, because the queue runner
  # treats any non-zero landing as a landing that did not happen and re-queues its lines already.
  # THE PATTERNS MUST NOT MATCH THEMSELVES: these greps travel in the same file they search, so
  # each one hides a letter of its own needle in a bracket.
  grep -qE -- 'RC=2; [V]ANISHED=1; break' "${BASH_SOURCE[0]}" && _ok "a box that stops answering is remembered as vanished" || _fail "a box that stops answering is remembered"
  grep -qE -- 'unreachable for 10 [p]olls — no verdict' "${BASH_SOURCE[0]}" && _ok "  ...and the log still says so in the words the ledgers carry" || _fail "the unreachable sentence is unchanged"
  grep -qE -- 'the box [v]anished mid-proof' "${BASH_SOURCE[0]}" && _ok "  ...and the exit says it in a sentence a log reader can grep" || _fail "the exit names the vanished box"
  _vanish() { # $1 = VANISHED  $2 = PREPROVE  $3 = outcome file ('' = none); prints the RC
    VANISHED="$1" PREPROVE="$2" OUTCOME="$3" RC=2 bash -c '
      if [ "$VANISHED" = 1 ] && [ "$PREPROVE" = 1 ] && { [ -z "$OUTCOME" ] || [ ! -s "$OUTCOME" ]; }; then RC=75; fi
      echo "$RC"'
  }
  _vt="$(mktemp "${TMPDIR:-/tmp}/land-remote-vanish.XXXXXX")"
  printf 'GREEN\t--prove --tests xtask 6d5bba552\n' >"$_vt"
  [ "$(_vanish 1 1 "")"    = 75 ] && _ok "  ...a vanished box on a PRE-PROOF exits 75 (NONE:box)" || _fail "a vanished box on a pre-proof exits 75"
  [ "$(_vanish 1 1 "$_vt")" = 2 ] && _ok "  ...but a GREEN outcome that got back first still wins" || _fail "a returned outcome outranks the vanished box"
  [ "$(_vanish 1 0 "")"    = 2 ]  && _ok "  ...and a LANDING that loses its box still exits 2" || _fail "a landing that loses its box exits 2"
  [ "$(_vanish 0 1 "")"    = 2 ]  && _ok "  ...and an ordinary pre-proof red is untouched" || _fail "an ordinary pre-proof red is untouched"
  rm -f "$_vt"
  # Twice: the stub exercised above, and the arm that really runs.
  [ "$(grep -cE -- 'if \[ "\$[V]ANISHED" = 1 \] && \[ "\$PREPROVE" = 1 \]' "${BASH_SOURCE[0]}")" = 2 ] \
    && _ok "  ...and the arm exercised above is the arm in this file" || _fail "the arm exercised above is the arm in this file"

  # THE DONE LEDGER IS MERGED AFTER THE VERDICT, NOT BEFORE IT (audit 17).
  grep -qF -- 'rcp_back "$HOST" "busbar-prove/target/gate/land-done.txt" "$REPO/$BATCH.remote-done" 2>/dev/null || true' "${BASH_SOURCE[0]}" && _ok "the box's done rows are only FETCHED beside the outcome" || _fail "the box's done rows are only fetched early"
  _vline="$(grep -n '^# THE LANDED TIP COMES BACK TOO' "${BASH_SOURCE[0]}" | head -1 | cut -d: -f1)"
  _mline="$(grep -nF 'grep -F -v -x -f "$REPO/target/gate/land-done.txt" "$REPO/$BATCH.remote-done" >>' "${BASH_SOURCE[0]}" | tail -1 | cut -d: -f1)"
  [ -n "$_vline" ] && [ -n "$_mline" ] && [ "$_mline" -gt "$_vline" ] \
    && _ok "  ...and MERGED after the landed-tip verdict, never before" || _fail "the merge happens after the landed-tip verdict (verdict line $_vline, merge line $_mline)"
  grep -qF -- 'if [ "$REFUSED" = 1 ]; then' "${BASH_SOURCE[0]}" && _ok "a refused landing records no done rows at all" || _fail "a refused landing records no done rows"
  grep -qF -- 'REFUSED=1; [ "$RC" = 0 ] && RC=2' "${BASH_SOURCE[0]}" && _ok "  ...and the no-landed-tip refusal sets that flag" || _fail "the no-landed-tip refusal sets REFUSED"
  # Exercised: the guard is REFUSED, not RC, so a PARTIALLY green batch still records its greens.
  _done() { # $1 = REFUSED  $2 = rc; prints the rows the ledger would gain
    local led="$_dt/led.txt" rem="$_dt/rem.txt"
    printf 'GREEN batch=old already\n' >"$led"; printf 'GREEN batch=old already\nGREEN batch=new landed-line\n' >"$rem"
    if [ "$1" = 1 ]; then :; else grep -F -v -x -f "$led" "$rem" >>"$led" 2>/dev/null || true; fi
    grep -c 'batch=new' "$led"
  }
  _dt="$(mktemp -d "${TMPDIR:-/tmp}/land-remote-done.XXXXXX")"
  [ "$(_done 1 2)" = 0 ] && _ok "  ...a refused landing adds no row" || _fail "a refused landing adds no row"
  [ "$(_done 0 1)" = 1 ] && _ok "  ...a partially green batch still adds its green row" || _fail "a partially green batch adds its green row"
  [ "$(_done 0 0)" = 1 ] && _ok "  ...and a whole green landing does too" || _fail "a green landing adds its row"
  rm -rf "$_dt"
  bash "$HERE/ci-remote-lib.sh" --selftest || fails=$((fails + 1))
  if [ "$fails" = 0 ]; then echo "land-remote selftest: GREEN"; exit 0; fi
  echo "land-remote selftest: RED ($fails failure(s))" >&2; exit 1
fi

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
# THE MODE IS READ HERE TOO. A pre-proof publishes nothing and the box's land.sh puts its tree back,
# so the tip that comes back is the tip that was sent — and if it is NOT, something on the box ran an
# ordinary landing under a flag it did not understand (seen once: an older engine on the box). That
# is a refusal, not a fast-forward: this script must never move the runner's tree on a pre-proof.
PREPROVE=0
for a in "${ARGS[@]}"; do [ "$a" = "--preprove" ] && PREPROVE=1; done
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

# ── THE SHARD FAN-OUT, ALLOCATED BEFORE THE PRIMARY STARTS ─────────────────────────────────────────
# LAND_SELFTEST_SHARDS=n asks for the two long self-tests to run as n shards: shard 1 on the primary
# box as part of the landing, shards 2..n on n-1 DISTINCT siblings that this script drives (a box
# cannot reach a sibling; see land.sh's header). The siblings are chosen HERE, up front, least
# loaded first and never the primary: a fleet that cannot give n-1 boxes DEGRADES TO UNSHARDED,
# loudly — the primary then runs the whole self-test itself, which is the same proof taken slower —
# rather than launching fewer shards and calling it n. A shard that is launched and then lost is a
# different thing: that is RED, on both sides, and never skipped.
SHARDS=0; SIBS=()
case "${LAND_SELFTEST_SHARDS:-}" in
  '') ;;
  *[!0-9]*) rdie "LAND_SELFTEST_SHARDS='${LAND_SELFTEST_SHARDS}' is not a number" ;;
  *) [ "$LAND_SELFTEST_SHARDS" -le 4 ] || rdie "LAND_SELFTEST_SHARDS=$LAND_SELFTEST_SHARDS: at most 4 boxes take a leg"
     [ "$LAND_SELFTEST_SHARDS" -ge 2 ] && SHARDS="$LAND_SELFTEST_SHARDS" ;;
esac
# A PRE-PROOF SHARDS LIKE A LANDING. The queue's sweep strips LAND_SELFTEST_SHARDS itself (its
# parallelism is across lines); a slot pre-proving its own branch is one line and wants the boxes.
if [ "$SHARDS" -gt 0 ]; then
  while IFS= read -r h; do [ -n "$h" ] && SIBS+=("$h"); done <<EOF
$(fleet_pick_hosts $((SHARDS - 1)) "$HOST")
EOF
  if [ "${#SIBS[@]}" -lt $((SHARDS - 1)) ]; then
    rlog "fan-out: asked for $((SHARDS - 1)) sibling box(es), the fleet gave ${#SIBS[@]} — UNSHARDED landing on $HOST (the same proof, slower)"
    SHARDS=0; SIBS=()
  else
    rlog "fan-out: $SHARDS shard(s) — shard 1 on $HOST, shards 2..$SHARDS on ${SIBS[*]}"
  fi
fi
FANDIR="$REPO/target/land-fanout-$REF"; mkdir -p "$FANDIR"

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
# that name in the box's checkout by the same fetch that brings the tree (a second refspec on the
# `git fetch prove` line below), verified with `rev-parse --verify`, and printed into the landing log
# so a reader of the log can see what the ceilings were judged against.
# THE BASE IS THE INTEGRATION BRANCH AS THIS REPOSITORY HOLDS IT, NEVER THE TIP BEING PROVEN. The
# first form of this pinned `$REF` — the pushed HEAD — under the base's name, which is right for the
# runner (its HEAD IS the integration branch) and silently wrong for a slot proving its own branch:
# ceilings judged against themselves, a rise invisible, a silent green (audit, 2026-09-09). So the
# base is `refs/heads/integration/oracle-phase0` RESOLVED HERE, in $REPO, pushed to the box under its
# own name, fetched into the checkout under the origin name the gate reads, and checked on the box
# against the sha this side resolved — by this script and again by land.sh — before anything runs.
LAND_BASE_REF="${LAND_BASE_REF:-refs/remotes/origin/integration/oracle-phase0}"
LAND_BASE_BRANCH="${LAND_BASE_BRANCH:-refs/heads/integration/oracle-phase0}"
BASE_SHA_LOCAL="$(git -C "$REPO" rev-parse --verify --quiet "$LAND_BASE_BRANCH")" \
  || rdie "no $LAND_BASE_BRANCH in $REPO to judge the ceilings against — a landing needs the integration branch, not only a tip"
remote_push_sha "$HOST" "$REPO" "$REF-base" "$BASE_SHA_LOCAL" || rdie "could not push the integration base $(printf '%.9s' "$BASE_SHA_LOCAL") to $HOST"
rlog "integration base $(printf '%.9s' "$BASE_SHA_LOCAL") ($LAND_BASE_BRANCH here) pushed as $REF-base"
# THE RECORDER'S WALL-CLOCK BOUNDS TRAVEL TOO, FOR THE SAME REASON THE CEILING DOES. The block
# below is a quoted heredoc: an `${ORACLE_BOOT_BOUND_SECS:-…}` written inside it would expand on the
# BOX, where nothing sets it, and an operator who raised the bound on the laptop because the fleet
# is loaded would have raised it nowhere. They go across as positionals, and an UNSET bound travels
# as the empty string — deliberately, because then the box scales its own default by its own
# measured load (land.sh's land_oracle_bounds), which is a fact only the box has.
rsh_script "$HOST" "$REF" "${XTASK_GATE_CEILING_SECS:-3600}" "$LAND_BASE_REF" "$SHARDS" "$BASE_SHA_LOCAL" "${ORACLE_BOOT_BOUND_SECS:-}" "${ORACLE_EGRESS_SETTLE_SECS:-}" "${RARGS[@]}" <<'RUN'
set -uo pipefail
REF="$1"; CEIL="$2"; BASEREF="$3"; SHARDS="$4"; BASESHA="$5"; OBOOT="$6"; OEGRESS="$7"; shift 7
export LAND_BASE_REF="$BASEREF" LAND_BASE_SHA="$BASESHA"
# Only when the laptop set one: an empty positional leaves the box's own scaling to decide.
[ -n "$OBOOT" ] && export ORACLE_BOOT_BOUND_SECS="$OBOOT"
[ -n "$OEGRESS" ] && export ORACLE_EGRESS_SETTLE_SECS="$OEGRESS"
# THE FAN-OUT MODE, when shards were allocated: land.sh writes a REQUEST per leg and waits for what
# this script delivers (land.sh's header has the protocol). With SHARDS=0 neither variable is set
# and land.sh runs exactly what it ran before.
if [ "$SHARDS" -gt 0 ]; then export LAND_SELFTEST_SHARDS="$SHARDS" LAND_SHARD_FANOUT=laptop; fi
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
# The integration base the laptop resolved comes in under the origin name the gate reads (see
# LAND_BASE_REF above): `ceilings::base_ref` takes the merge-base of HEAD with it.
git fetch -q prove "+refs/heads/$REF:refs/heads/$REF" "+refs/heads/$REF-base:$BASEREF" "+refs/proof/$REF/*:refs/proof/$REF/*" "+refs/audit-pins/*:refs/audit-pins/*" || exit 2
git checkout -q -f "$REF" || exit 2
git clean -qffdx -e target -e .cargo -e node_modules
mkdir -p target
# AN EARLIER LANDING'S REQUESTS ARE NOT THIS ONE'S. target/ survives `git clean` on purpose (it is the
# warm build), so the shard directories of the last landing survive with it, and their REQUEST files
# were served again by the next laptop — "could not fetch" against a ref that landing had already
# consumed (measured, third real run). Their logs were copied back when they were served; they go.
rm -rf target/land-shards-*
LOG="target/land-remote-$REF.log"; RC="target/land-remote-$REF.rc"
rm -f "$RC"
echo "remote tree: $(git rev-parse --short HEAD)  on $(hostname)" >"$LOG"
BASE_SHA="$(git rev-parse --verify --quiet "$BASEREF")" || { echo "integration base $BASEREF does not resolve on $(hostname) — the ceiling rows would judge against HEAD~1" | tee -a "$LOG"; exit 2; }
echo "integration base: $BASEREF = $BASE_SHA on $(hostname); the laptop resolved $BASESHA (ceilings are diffed against it)" >>"$LOG"
[ "$BASE_SHA" = "$BASESHA" ] || { echo "integration base MISMATCH: the box holds $BASE_SHA, the laptop resolved $BASESHA — refusing to judge" | tee -a "$LOG"; exit 2; }
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

# ── SERVING THE FAN-OUT ──────────────────────────────────────────────────────────────────────────
# Each poll also asks the primary for REQUEST files. A new one is fetched (the sha, from the
# primary's bare repo), pushed to each sibling, and started there DETACHED with its own log and .rc
# under ~/busbar-shards/<job>; every launched shard is then polled for its .rc, and the moment it
# has one its log and then its .rc are copied here (the laptop's own ledger, $FANDIR) and onto the
# primary (into the request's directory, where land.sh is waiting). Log first: the .rc is the signal.
# A sibling unreachable for ten polls is delivered as rc 2 with the transport's own words — an
# honest report from the transport, not a vote — so the primary's wait ends with a named reason.
SERVED=""            # request refs already launched
LAUNCHED=()          # "seq|k|host|jobref|primary-dir|t0" per launched shard, until delivered
DELIVERED=()         # "seq|k|host|secs" per delivered shard
# DELIVERY IS ATOMIC ON THE PRIMARY. scp creates the file and then writes it; the primary polls with
# `[ -f ]` every 20 s and once read a .rc that existed and was still empty — and judged the shard
# "never reported" in the same second this side logged the delivery (measured, first real landing).
# So each file lands under a temporary name and is renamed into place, log first, then .rc.
deliver() { # $1 = local file  $2 = remote path
  rcp_to "$HOST" "$1" "$2.tmp" && rsh "$HOST" mv -f "$2.tmp" "$2" </dev/null >/dev/null 2>&1
}
shard_launch() { # $1 = sibling host  $2 = job ref  $3 = gate  $4 = k/n  $5 = CEIL=VALUE  $6 = ceiling secs
  rsh_script "$1" "$2" "$3" "$4" "$5" "$6" <<'SHARD'
set -uo pipefail
JOB="$1"; GATE="$2"; SPEC="$3"; CEIL="$4"; CEILSECS="$5"
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0
export RUSTC_WRAPPER=sccache SCCACHE_DIR=/var/cache/sccache SCCACHE_CACHE_SIZE=60G
export SCCACHE_SERVER_PORT="${SCCACHE_SERVER_PORT:-4310}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
export XTASK_GATE_CEILING_SECS="$CEILSECS"
export "$CEIL"
# A CLONE PER JOB, A TARGET DIRECTORY PER BOX. The checkout is cheap (`--shared` against the bare
# repo) and disposable; the build artefacts are what cost minutes, so they live in one directory
# every shard job on this box reuses, and cargo's own lock serialises two jobs that meet there.
export CARGO_TARGET_DIR="$HOME/busbar-shards/target"
BARE="$HOME/busbar.git"; W="$HOME/busbar-shards/$JOB"
mkdir -p "$HOME/busbar-shards"
[ -d "$W/.git" ] || git clone -q --shared "$BARE" "$W" || exit 2
cd "$W" || exit 2
git fetch -q origin "+refs/heads/$JOB:refs/heads/$JOB" || exit 2
git checkout -q -f "$JOB" || exit 2
git clean -qffdx -e target -e .cargo
mkdir -p target; rm -f target/shard.rc
# THE .rc IS WRITTEN BY THE SAME SHELL THAT RAN THE SHARD, from a variable, after the group. The
# first form of this `exit`ed from inside the group with the shard's status — which ended the whole
# `bash -c` before the line that wrote the .rc, so every shard finished, said so in its log, and was
# never reported (measured on the first real landing: 433 s of green that the primary waited on).
setsid nohup bash -c '
  rc=1
  { echo "shard '"$SPEC"' of '"$GATE"' on $(hostname): tree $(git rev-parse --short HEAD) $(date -u +%FT%TZ)"
    cargo xtask gate "'"$GATE"'" --selftest --shard "'"$SPEC"'"; rc=$?
    echo "shard '"$SPEC"' done rc=$rc $(date -u +%FT%TZ)"; } >target/shard.log 2>&1
  echo "$rc" >target/shard.rc
' >/dev/null 2>&1 </dev/null &
echo "shard $SPEC of $GATE detached on $(hostname) in $W"
SHARD
}
serve_requests() {
  local out line dir seq k sib job t0 i rec ent secs quiet
  # New requests on the primary.
  out="$(rsh "$HOST" bash -c 'for f in busbar-prove/target/land-shards-*/REQUEST; do [ -f "$f" ] && printf "%s " "$f" && cat "$f"; done' </dev/null 2>/dev/null || true)"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    dir="${line%% *}"; dir="${dir%/REQUEST}"
    fanout_parse_request "${line#* }" || { rlog "fan-out: REFUSED an unparseable request from $HOST: ${line#* }"; continue; }
    case " $SERVED " in *" $R_ref "*) continue ;; esac
    SERVED="$SERVED $R_ref"
    seq="${R_ref##*-}"
    if [ "$R_n" != "$SHARDS" ]; then rlog "fan-out: request $R_ref asks for $R_n shards, $SHARDS were allocated — not served (the primary will report them missing)"; continue; fi
    mkdir -p "$FANDIR/$seq"; printf '%s\n' "${line#* }" >"$FANDIR/$seq/REQUEST"
    # THE PRIMARY'S REQUEST DIRECTORY, EXACTLY. The join used to find it by a glob over the gate and
    # sequence number, which also matched an earlier landing's directory left on the box — two
    # shard-1.rc files concatenated read "00", and a complete green union was refused as
    # "exited 00" (measured, third real run).
    printf '%s\n' "$dir" >"$FANDIR/$seq/DIR"
    if ! GIT_SSH_COMMAND="$SSH_WRAP" git -C "$REPO" fetch -q "ssh://$REMOTE_USER@$HOST/~/$REMOTE_BARE" "+refs/heads/$R_ref:refs/remotes/fanout/$R_ref" 2>>"$FANDIR/$seq/transport.log"; then
      rlog "fan-out: could not fetch $R_ref ($(printf '%.9s' "$R_sha")) from $HOST — shards 2..$R_n are not launched (see $FANDIR/$seq/transport.log)"; continue
    fi
    rlog "fan-out: request $seq: $R_gate in $R_n shards at $(printf '%.9s' "$R_sha") — launching shards 2..$R_n"
    k=2
    while [ "$k" -le "$R_n" ]; do
      sib="${SIBS[$((k - 2))]}"; job="$REF-s$seq"
      t0="$(date +%s)"
      if remote_push_sha "$sib" "$REPO" "$job" "$R_sha" 2>>"$FANDIR/$seq/transport.log" \
         && shard_launch "$sib" "$job" "$R_gate" "$k/$R_n" "$R_ceil" "${XTASK_GATE_CEILING_SECS:-3600}" >>"$FANDIR/$seq/transport.log" 2>&1; then
        LAUNCHED+=("$seq|$k|$sib|$job|$dir|$t0|0")
        rlog "fan-out: shard $k/$R_n of $R_gate launched on $sib"
      else
        # Never launched: delivered as rc 2 now, with the transport's words, so the primary's wait
        # ends with a reason rather than a deadline.
        { echo "land.sh: shard $k/$R_n of $R_gate: the laptop could not start it on $sib"; tail -5 "$FANDIR/$seq/transport.log"; } >"$FANDIR/$seq/shard-$k.log"
        echo 2 >"$FANDIR/$seq/shard-$k.rc"
        deliver "$FANDIR/$seq/shard-$k.log" "$dir/shard-$k.log" && deliver "$FANDIR/$seq/shard-$k.rc" "$dir/shard-$k.rc"
        DELIVERED+=("$seq|$k|$sib|0")
        rlog "fan-out: shard $k/$R_n could not be started on $sib — delivered RED"
      fi
      k=$((k + 1))
    done
  done <<EOF
$out
EOF
  # Launched shards: deliver the ones that have reported.
  i=0
  while [ "$i" -lt "${#LAUNCHED[@]}" ]; do
    ent="${LAUNCHED[$i]}"; [ -n "$ent" ] || { i=$((i + 1)); continue; }
    IFS='|' read -r seq k sib job dir t0 quiet <<<"$ent"
    rec="$(rsh "$sib" cat "busbar-shards/$job/target/shard.rc" </dev/null 2>/dev/null || true)"
    rec="$(printf '%s' "$rec" | tr -d '[:space:]')"
    if [ -z "$rec" ]; then
      if rsh "$sib" true </dev/null >/dev/null 2>&1; then quiet=0; else quiet=$((quiet + 1)); fi
      if [ "$quiet" -ge 10 ]; then
        { echo "land.sh: shard $k of $seq: $sib unreachable for $quiet polls; the laptop delivers this as RED"; } >"$FANDIR/$seq/shard-$k.log"
        echo 2 >"$FANDIR/$seq/shard-$k.rc"; rec=2
      else
        LAUNCHED[$i]="$seq|$k|$sib|$job|$dir|$t0|$quiet"; i=$((i + 1)); continue
      fi
    else
      rcp_back "$sib" "busbar-shards/$job/target/shard.log" "$FANDIR/$seq/shard-$k.log" || echo "(log could not be copied back from $sib)" >"$FANDIR/$seq/shard-$k.log"
      printf '%s\n' "$rec" >"$FANDIR/$seq/shard-$k.rc"
      rsh "$sib" rm -rf "busbar-shards/$job" </dev/null >/dev/null 2>&1 || true
    fi
    secs=$(( $(date +%s) - t0 ))
    if deliver "$FANDIR/$seq/shard-$k.log" "$dir/shard-$k.log" && deliver "$FANDIR/$seq/shard-$k.rc" "$dir/shard-$k.rc"; then
      rlog "fan-out: shard $k of request $seq on $sib: rc $rec, ${secs}s launch-to-verdict — delivered to $HOST"
    else
      rlog "fan-out: shard $k of request $seq on $sib: rc $rec, but it could NOT be delivered to $HOST (the primary will report it missing)"
    fi
    DELIVERED+=("$seq|$k|$sib|$secs")
    LAUNCHED[$i]=""; i=$((i + 1))
  done
}

# POLL. Every 60 s: the .rc file (the verdict), then the log's new bytes (the operator's view), then
# the fan-out's requests and deliveries.
RC=""; SEEN=0; QUIET=0
VANISHED=0
while :; do
  sleep 60
  [ "$SHARDS" -gt 0 ] && serve_requests
  out="$(rsh "$HOST" bash -c "cat $RRC 2>/dev/null; echo ::; wc -c <$RLOG 2>/dev/null" </dev/null 2>/dev/null)"
  if [ -z "$out" ]; then
    QUIET=$((QUIET + 1))
    # TEN MINUTES OF SILENCE IS THE BOX, NOT THE PROOF. Measured 2026-09-10: two pre-proofs ended
    # here after 1735 s and 10116 s because AWS reclaimed the spot instances under them. The verdict
    # that follows is about the transport; whether it is about the LINE is decided at the exit.
    [ "$QUIET" -ge 10 ] && { rlog "ERROR: $HOST unreachable for 10 polls — no verdict"; RC=2; VANISHED=1; break; }
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

# ── THE JOIN, HERE, OVER THE LAPTOP'S OWN COPIES ────────────────────────────────────────────────────
# The primary judged what was delivered to it; this side holds the same logs and re-runs the same
# union check (land.sh's land_shard_union, sourced in library mode) over every request it served.
# A green from the box that these copies do not support is refused. Shards still running when the
# box reported are the box's "never reported" already; they are named here too, and stopped nowhere
# — a shard that finishes late finishes into a directory nobody reads.
if [ "$SHARDS" -gt 0 ]; then
  set +e
  # shellcheck source=scripts/land.sh
  LAND_LIB_ONLY=1 . "$ENGINE"
  nreq=0; joined=0
  for d in "$FANDIR"/*/; do
    [ -f "$d/REQUEST" ] || continue
    nreq=$((nreq + 1)); seq="$(basename "$d")"
    fanout_parse_request "$(cat "$d/REQUEST")" || continue
    # shard 1 ran on the primary: its log and rc are in the request's own directory (DIR), by name.
    pdir="$(cat "$d/DIR" 2>/dev/null)"
    [ -n "$pdir" ] || { rlog "fan-out: request $seq has no recorded directory on $HOST — its shard 1 cannot be read"; continue; }
    rsh "$HOST" cat "$pdir/shard-1.rc" </dev/null 2>/dev/null | tr -d '[:space:]' >"$d/shard-1.rc"
    [ -s "$d/shard-1.rc" ] || rm -f "$d/shard-1.rc"
    rsh "$HOST" cat "$pdir/shard-1.log" </dev/null 2>/dev/null >"$d/shard-1.log"
    if land_shard_union "$R_gate" "$R_n" "${d%/}" >"$d/union.txt" 2>&1; then
      joined=$((joined + 1)); rlog "fan-out: request $seq ($R_gate): $(cat "$d/union.txt")"
    else
      rlog "fan-out: request $seq ($R_gate): $(tail -1 "$d/union.txt")"
      [ "$RC" = 0 ] && { rlog "ERROR: the primary reported GREEN over a fan-out this side cannot confirm — refusing"; RC=2; }
    fi
  done
  for ent in ${DELIVERED[@]+"${DELIVERED[@]}"}; do IFS='|' read -r seq k sib secs <<<"$ent"; rlog "fan-out: shard $k of request $seq on $sib: ${secs}s"; done
  rlog "fan-out: $nreq request(s) served, $joined joined green; ledger $FANDIR"
  set -e
fi

# THE RESULT FILE COMES BACK TO THE PATH THE LOCAL RUNNER ALREADY READS. target/gate/landq3.sh reads
# <batch>.result and nothing else; if it is not here, the queue runner reads a landing that never
# reported, which is worse than a red.
OUTCOME=""          # the per-line outcome file, once it is here
REFUSED=0           # 1 when THIS side refused the landing (nothing of it may be recorded as done)
if [ -n "$BATCH" ]; then
  if rcp_back "$HOST" "$RBATCH.result" "$REPO/$BATCH.result"; then
    rlog "per-line outcomes: $REPO/$BATCH.result"
    sed 's/^/  /' "$REPO/$BATCH.result" >&2
    OUTCOME="$REPO/$BATCH.result"
  else
    rlog "WARNING: no $RBATCH.result on $HOST — the batch did not reach its reporting stage"
  fi
  # land.sh on the box appended its rows to the box's land-done.txt; they belong in ours — BUT NOT
  # YET. This copy ran BEFORE the landed-ref check below, so a landing this side went on to REFUSE
  # had already written the box's GREEN rows into our done ledger: the queue then read lines as
  # landed on a tree that never moved to them, and would never pop them again (audit 17). The rows
  # are fetched here and MERGED AFTER the verdict, and never at all when the landing was refused.
  rcp_back "$HOST" "busbar-prove/target/gate/land-done.txt" "$REPO/$BATCH.remote-done" 2>/dev/null || true
fi

# THE LANDED TIP COMES BACK TOO. What the box proved is what this tree must now be at: the local
# HEAD was the base the box started from, so a fast-forward is the only honest move — anything
# else means the tree here and the tree proved there have diverged, and that is a refusal.
# WHY THE REF CAN BE ABSENT WITHOUT A SINGLE THING BEING WRONG (measured, sweep at 76f1887af,
# line 3 on i-0b0e1585e8567d01a): the box's bare repo is re-fetched by the fleet's periodic
# `prove-remote.sh --setup` refresh, and that refresh mirrors origin with `--prune` over
# refs/heads/*. A refresh that lands between the box's `push HEAD:refs/heads/$REF-landed` and this
# fetch DELETES the ref — the run's `-base` and `$REF` go with it, while refs/proof/$REF/* (outside
# the refspec) survive, which is the signature that named the cause. That pre-proof was GREEN on the
# box, its per-line outcome file said so, and 7950 s of proof were thrown away by this check alone.
# So: the reason is CAPTURED (it was thrown at /dev/null and every failure read as "no ref"), and on
# a PRE-PROOF the check is INFORMATIONAL — a pre-proof publishes nothing and moves no tree, so the
# ref's absence cannot make a green line red. On a LANDING it is still a refusal: there the tree
# here must become the tree proved there, and with no ref there is nothing to fast-forward to.
FETCH_WHY="$REPO/target/land-remote-$REF.fetch-err"; mkdir -p "$(dirname "$FETCH_WHY")"
if GIT_SSH_COMMAND="$SSH_WRAP" git -C "$REPO" fetch -q "ssh://$REMOTE_USER@$HOST/~/$REMOTE_BARE" "+refs/heads/$REF-landed:refs/remotes/landed/$REF" 2>"$FETCH_WHY"; then
  landed="$(git -C "$REPO" rev-parse "refs/remotes/landed/$REF")"
  if [ "$PREPROVE" = 1 ]; then
    if [ "$landed" = "$(git -C "$REPO" rev-parse HEAD)" ]; then
      rlog "pre-proof: tree stays at $(git -C "$REPO" rev-parse --short HEAD); nothing was published and nothing is fast-forwarded"
    else
      rlog "ERROR: the box published $(echo "$landed" | cut -c1-9) on a PRE-PROOF of $(git -C "$REPO" rev-parse --short HEAD) — an engine there took a landing it was told not to take; this tree is NOT moved"; RC=2; REFUSED=1
    fi
  elif [ "$landed" != "$(git -C "$REPO" rev-parse HEAD)" ]; then
    if git -C "$REPO" merge -q --ff-only "$landed" 2>/dev/null; then
      rlog "tree fast-forwarded to the landed tip $(git -C "$REPO" rev-parse --short HEAD)"
    else
      rlog "ERROR: the landed tip $(echo "$landed" | cut -c1-9) is not a fast-forward of this tree — refusing"; RC=2; REFUSED=1
    fi
  fi
  git -C "$REPO" update-ref -d "refs/remotes/landed/$REF" 2>/dev/null || true
else
  why="$(tr -d '\r' <"$FETCH_WHY" 2>/dev/null | grep -v '^$' | tail -1 | cut -c1-200)"
  rlog "WARNING: no landed tip came back from $HOST (refs/heads/$REF-landed)${why:+ — $why}"
  if [ "$PREPROVE" = 1 ]; then
    rlog "pre-proof: INFORMATIONAL — a pre-proof publishes nothing and this tree is not moved; the verdict is the per-line outcome file${OUTCOME:+ ($OUTCOME)}"
    if [ -n "$OUTCOME" ] && [ -s "$OUTCOME" ]; then
      sed 's/^/  outcome: /' "$OUTCOME" >&2
    else
      rlog "pre-proof: and NO per-line outcome file came back either — there is no verdict to read"
      [ "$RC" = 0 ] && RC=2
    fi
  else
    rlog "ERROR: a landing with no landed tip cannot fast-forward this tree — refusing"
    REFUSED=1; [ "$RC" = 0 ] && RC=2
  fi
fi
rm -f "$FETCH_WHY"

# THE DONE LEDGER, AFTER THE VERDICT AND ONLY IF THIS SIDE DID NOT REFUSE. A refused landing is a
# landing that did not happen here: its rows would tell the queue that lines are done on a tree that
# is still at the base, and the queue never pops a done line twice. A PARTIALLY green batch is not a
# refusal — its green lines really did land — so the guard is REFUSED, not RC.
if [ -n "$BATCH" ] && [ -f "$REPO/$BATCH.remote-done" ]; then
  if [ "$REFUSED" = 1 ]; then
    rlog "the landing was refused here: the box's $(grep -c . "$REPO/$BATCH.remote-done" 2>/dev/null || echo 0) done row(s) are NOT recorded (kept at $BATCH.remote-done)"
  else
    grep -F -v -x -f "$REPO/target/gate/land-done.txt" "$REPO/$BATCH.remote-done" >>"$REPO/target/gate/land-done.txt" 2>/dev/null || true
    rm -f "$REPO/$BATCH.remote-done"
  fi
fi
# ── A BOX THAT WENT AWAY IS NOT A RED LINE ──────────────────────────────────────────────────────
# Exit 75 (EX_TEMPFAIL) is this transport's word for "the BOX stopped answering; nothing was learned
# about the picks" — landq4.sh reads it as NONE:box, records no colour, and re-queues the line to
# the front of the next sweep. It is a PRE-PROOF's exit only: a landing that loses its box must keep
# exiting 2, because the queue runner already treats a non-zero landing as one that did not happen.
# An outcome file that got back before the box went away is still the proof's own verdict and wins.
if [ "$VANISHED" = 1 ] && [ "$PREPROVE" = 1 ] && { [ -z "$OUTCOME" ] || [ ! -s "$OUTCOME" ]; }; then
  rlog "NONE: the box vanished mid-proof ($HOST stopped answering and never reported) — no verdict on these picks; exit 75 so the queue re-queues them rather than scoring them RED"
  RC=75
fi
rlog "host $HOST   exit $RC   wall $(( END - START ))s"
exit "$RC"
