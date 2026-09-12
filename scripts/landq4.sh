#!/usr/bin/env bash
# BATCHED landing queue with a PRE-PROVE STAGE, and the reason it exists is arithmetic.
#
# The serial runner proves one batch on one box. `kind-isolation --selftest` is 1642 s on a fleet
# box and `construction --selftest` is another 400 s, and both run on EVERY landing by design — so
# a batch costs the better part of forty minutes whatever is in it, while seven boxes idle. A red
# batch then bisects SERIALLY, at the same price per half.
#
# THE PRE-PROVE STAGE SPENDS THE IDLE BOXES. Before the runner pops anything, the next up-to-six
# queue lines whose FILE SETS ARE DISJOINT are each handed to a box of their own and proven against
# the CURRENT TIP with `land.sh --preprove --remote <host> --batch <line>`: the box picks,
# proves, reports, and puts its tree back. Nothing is published and this tree never moves. The
# verdicts land in target/gate/preproved.txt, one row per line, WITH THE TIP THEY WERE PROVEN
# AGAINST.
#
# WHAT A PRE-PROOF IS AND IS NOT:
#
#   * It is not a landing, and NOTHING LANDS ON ONE. The serial runner still applies the picks and
#     runs the FULL proof over the union it popped. A green pre-proof changes the ORDER of the
#     queue, never its verdict — it says "this line was green on this tip an hour ago", which is a
#     good reason to try it first and no reason at all to skip proving it.
#   * A pre-proof is only evidence about the TIP IT WAS TAKEN ON. Every row carries that sha and is
#     ignored the moment the tip moves. A stale green is not a weaker green; it is not a green.
#   * A line pre-proven RED is parked `#RED-preproof` with the path to its log, at the head of the
#     queue, unchanged but for the marker — exactly as a red landing is parked. It is not deleted
#     and it is not skipped silently.
#   * A line with NO record is still poppable. The pre-prove stage is an accelerator, not a gate:
#     if the fleet is unreachable the queue runs exactly as it ran before, one batch at a time.
#
# WHY DISJOINT FILE SETS. Two lines that touch the same files are two lines whose proofs interact:
# proving each alone against the tip says nothing about the union, and the union is what the runner
# will actually pop. Disjointness (by `git diff --name-only` over each line's picks) is the cheap,
# checkable condition under which "each was green alone" is worth anything at all.
#
#   scripts/landq4.sh                 # run the queue
#   scripts/landq4.sh --selftest      # prove this script's own decisions, RED first
#   scripts/landq4.sh --preprove-once # one pre-prove sweep, then exit (what an operator runs by hand)
set -uo pipefail

W="${LANDQ_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
Q="${LANDQ_QUEUE:-$W/target/gate/land-queue.txt}"
D="${LANDQ_DONE:-$W/target/gate/land-done.txt}"
L="${LANDQ_LOG:-$W/target/gate/landq.out}"
PP="${LANDQ_PREPROVED:-$W/target/gate/preproved.txt}"
QLOCK="${LANDQ_QUEUE_LOCK:-$W/target/gate/land-queue.lock}"
# THE INBOX (see lq_inbox_fold). The one file an integrator appends to; land-queue.txt itself is
# only ever written by the runner, under the lock, at a moment of its own choosing.
INBOX="${LANDQ_INBOX:-$W/target/gate/land-queue.inbox.txt}"
# THE LINES THE FLEET OWES AN ANSWER TO. A line whose box was reclaimed mid-proof, or whose proof
# died of a harness failure, learned NOTHING about itself — and it has already spent an hour or
# three waiting for that nothing. It goes back to the FRONT of the next sweep's list rather than to
# the back of a queue of a hundred and twenty.
FRONT="${LANDQ_PREPROVE_FRONT:-$W/target/gate/preprove-front.txt}"
# THE ORACLE ROWS THAT ARE RED AT THE TIP ITSELF, keyed by the tip, one row per cell id.
BASERED="${LANDQ_BASE_RED:-$W/target/gate/oracle-base-red.txt}"
# THE FAULT LEDGER (see lq_fault_record). One row per CLASS — how many times in a row this class of
# infrastructure failure has stopped a batch, and when it last did — and a ring of the last faults
# with their text. Both are read by the status file and by the backoff.
FAULTS="${LANDQ_FAULTS:-$W/target/gate/landq4.faults.txt}"
FAULTRING="${LANDQ_FAULT_RING:-$W/target/gate/landq4.faultring.txt}"
# HOW MANY OF THE LAST FAULTS THE STATUS FILE CARRIES.
FAULT_RING_KEEP="${LANDQ_FAULT_RING_KEEP:-5}"
REPO="${LANDQ_GH_REPO:-GetBusbar/busbar}"
BR="${LANDQ_BRANCH:-integration/oracle-phase0}"
SCRIPTS="${LAND_SH_SRC:-$W/scripts}"
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# SCRATCH GOES UNDER $LAND_TMP, AND NEVER UNDER /tmp (owner rule, 2026-09-11)
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# /tmp is wiped — by the OS on a laptop, by systemd-tmpfiles on a fleet box — and it took a running
# engine's staged scripts, a sweep's slot directories and a lock's spill file with it. `${TMPDIR}`
# is no better: on macOS it is a per-session /var/folders directory that goes when the session does.
# So every scratch path this engine writes is rooted here, one directory the operator owns and
# nothing sweeps, and the only way to move it is to say so.
LAND_TMP="${LAND_TMP:-$HOME/Developer/tmp}"
mkdir -p "$LAND_TMP" 2>/dev/null || true

# HOW MANY BOXES THE PRE-PROVE STAGE MAY HOLD AT ONCE. Six leaves the fleet room for the serial
# runner's own box and for whatever an operator is doing by hand.
PREPROVE_LINES="${LANDQ_PREPROVE_LINES:-6}"
# HOW MANY OF THOSE BOXES THE HEAD OF THE LIVE QUEUE IS GUARANTEED (see lq_sweep_order). The chain
# preference below can otherwise spend the whole budget on holds three deep in the queue while the
# two lines the runner is about to POP go unproven — measured 2026-09-10 on a sweep of twelve.
PREPROVE_HEAD="${LANDQ_PREPROVE_HEAD:-2}"

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# WHICH MACHINE A SWEEP'S PRE-PROOF RUNS ON: `BUSBAR_PROVE_BACKEND=fleet|latchkey`
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# The owner's goal is 100% off EC2. The two workloads leave the fleet in order, and this variable is
# the seam for the FIRST of them: the sweep's pre-proofs. `fleet` is the default and is exactly what
# this engine has always done — `land.run.sh --preprove --remote <box>`. `latchkey` routes the same
# leg through scripts/prove-latchkey.sh, which rents a 16-vCPU runner per line and gives it back.
#
# THE LANDING ITSELF STAYS ON THE FLEET IN THIS PHASE, deliberately. A pre-proof that is wrong costs
# the queue an order; a landing that is wrong publishes. The pre-proof is where a new transport is
# allowed to be measured in anger, and the landing moves when this one has a week of green behind it.
#
# TWELVE, NOT TWENTY. The workspace's runner cap is 20 CONCURRENT and CI shares it — measured, and
# measured the hard way: `latchkey run` answered `Job creation blocked: concurrency_limit` on seven
# consecutive submissions while LK-1's CI push held the account. A sweep that took all twenty would
# stop the CI it is meant to replace. So the sweep takes twelve and the rest of a sweep's lines go
# to boxes; the two backends coexist until the cap is raised.
#
# AND THE OVERFLOW IS A FLEET BOX, NOT A QUEUE. A line whose job cannot be created is a line nobody
# is proving; prove-latchkey.sh answers `exit 75` — "no verdict, prove this again" — for exactly
# that case, and the dispatcher below reads a 75 as "take a box and do it the old way" rather than
# as a red. Nothing about the tree has been learned when the account is full.
LANDQ_PROVE_BACKEND="${BUSBAR_PROVE_BACKEND:-fleet}"
LATCHKEY_MAX_JOBS="${LATCHKEY_MAX_JOBS:-12}"

lq_validate_backend() { # $1 = the value; the engine refuses a backend it does not have
  case "${1:-}" in fleet|latchkey) return 0 ;; esac
  lq_log "pre-prove: BUSBAR_PROVE_BACKEND='${1:-}' is not a backend this engine has (fleet | latchkey) — using fleet"
  return 1
}
lq_preprove_backend() { lq_validate_backend "$LANDQ_PROVE_BACKEND" && printf '%s
' "$LANDQ_PROVE_BACKEND" || printf 'fleet
'; }

# HOW MANY LATCHKEY JOBS THIS ENGINE HAS IN FLIGHT. Counted from the processes, not from a file: a
# counter file survives a killed sweep and then refuses every line in the next one, which is the
# failure mode a lock file has whenever the thing it counts can be SIGKILLed.
lq_latchkey_inflight() {
  pgrep -f 'prove-latchkey\.sh .*--preprove' 2>/dev/null | grep -c . || true
}
lq_latchkey_slot_free() {
  local n; n="$(lq_latchkey_inflight)"
  [ "${n:-0}" -lt "$LATCHKEY_MAX_JOBS" ]
}

# ONE DISPATCH, TWO BACKENDS, AND THE FLEET IS THE FALLBACK OF BOTH. Every pre-proof in this file
# goes through here — the live lines, the chained holds and the base replay — so a backend cannot be
# half-adopted by a sweep that forgot one of its three loops.
#
# `$2` is the box the allocator handed this line, or the empty string when the sweep did not take
# one because the backend does not need it. A latchkey dispatch that cannot create a job and has no
# box to fall back to is the honest 75 the caller already knows how to read.
# A BOX IS ONLY TAKEN WHEN A BOX IS WHAT WILL BE USED. On the latchkey backend a line that has a
# free runner slot needs NO fleet box, and taking one anyway would bound the sweep by the very
# resource the backend exists to stop using — six boxes' worth of lines out of a queue of a hundred
# and twenty, on a backend with twelve slots. The empty string means "no box", and the dispatcher
# reads it as "there is nothing to fall back to".
lq_preprove_needs_box() { # $1 = tree (default $W)
  [ "$(lq_preprove_backend)" = latchkey ] \
    && lq_latchkey_slot_free \
    && [ -n "$(lq_latchkey_script "${1:-$W}")" ] \
    && return 1
  return 0
}
# WHERE THE LATCHKEY TRANSPORT LIVES: the STAGED copy, whose REPO is this tree (lq_stage_engine),
# and never `$tree/scripts` — the tree is what a proof is ABOUT, and an unlanded script is not in it.
lq_latchkey_script() { # $1 = tree; prints the staged transport, or nothing when this home has none
  local f="${1:-$W}/target/gate/prove-latchkey.run.sh"
  [ -f "$f" ] && printf '%s\n' "$f"
}

lq_dispatch_preprove() { # $1 = tree, $2 = host ('' = none), $3 = batch file; returns the leg's rc
  local tree="$1" host="$2" bf="$3" rc=0 lkscript
  if [ "$(lq_preprove_backend)" = latchkey ] && lq_latchkey_slot_free; then
    lkscript="$(lq_latchkey_script "$tree")"
    if [ -z "$lkscript" ]; then
      # NOT A RED, AND NOT A 127. The shell's "No such file or directory" is exit 127, and 127 is
      # what the live sweep recorded as a pre-proof RED on every line it touched. A transport this
      # engine home does not carry has measured NOTHING about anybody's picks.
      lq_log "pre-prove: this engine home carries no latchkey transport (no target/gate/prove-latchkey.run.sh) — nothing was proven on it"
    else
      env -u LAND_SELFTEST_SHARDS bash "$lkscript" --preprove --batch "$bf" </dev/null
      rc=$?
      [ "$rc" != 75 ] && return "$rc"
      lq_log "pre-prove: latchkey created no job for $(basename "$bf") (the workspace cap is shared with CI) — falling back to a box"
    fi
  fi
  [ -n "$host" ] || { lq_log "pre-prove: no box to fall back to for $(basename "$bf") — no verdict, and no red either"; return 75; }
  env -u LAND_SELFTEST_SHARDS bash "$tree/target/gate/land.run.sh" --preprove --remote "$host" --batch "$bf" </dev/null
}

export LAND_ORACLE_SHARDS="${LAND_ORACLE_SHARDS:-3}"
export LAND_ORACLE_PORT_BASE="${LAND_ORACLE_PORT_BASE:-50100}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
export XTASK_GATE_CEILING_SECS="${XTASK_GATE_CEILING_SECS:-900}"
# THE RECORDER'S WALL-CLOCK BOUNDS ARE FORWARDED, NEVER INVENTED HERE. A number this runner picked
# would be a laptop's guess about how fast a fleet box is; the box measures its own load and scales
# its own default (land.sh's land_oracle_bounds, land-remote.sh carries an operator's override
# across as a positional). What this file owes is the channel, and only when there is something in it.
[ -n "${ORACLE_BOOT_BOUND_SECS:-}" ] && export ORACLE_BOOT_BOUND_SECS
[ -n "${ORACLE_EGRESS_SETTLE_SECS:-}" ] && export ORACLE_EGRESS_SETTLE_SECS
true

TAB="$(printf '\t')"
NL="$(printf '\n.')"; NL="${NL%.}"

lq_log() { printf '%s\n' "$*" >>"$L"; }

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE DECISIONS, as functions, so the self-test can ask them directly
# ──────────────────────────────────────────────────────────────────────────────────────────────────

# Every hash a queue line names, in order. The same token shape land-remote.sh reads.
lq_line_hashes() { # $1 = queue line
  printf '%s\n' "$1" | tr -s ' \t' '\n\n' | grep -Eo '^[0-9a-f]{7,40}$' || true
}

# THE FILES A QUEUE LINE WOULD CHANGE — the union over its picks, sorted and unique.
#
# A line whose picks cannot be resolved in this repository has an UNKNOWN file set, and unknown is
# not empty: an empty set is disjoint from everything, so treating it as empty would put exactly
# the lines nobody can analyse onto boxes together. It prints the sentinel `?` and never joins a
# disjoint set.
lq_line_files() { # $1 = queue line, in the repo at $2 (default $W)
  local line="$1" repo="${2:-$W}" h out="" any=0
  for h in $(lq_line_hashes "$line"); do
    any=1
    git -C "$repo" rev-parse -q --verify "$h^{commit}" >/dev/null 2>&1 || { printf '?\n'; return 0; }
    out="$out$(git -C "$repo" diff --name-only "$h^" "$h" 2>/dev/null)
"
  done
  [ "$any" = 1 ] || { printf '?\n'; return 0; }
  printf '%s\n' "$out" | grep -v '^$' | sort -u
}

# THE NEXT UP-TO-N LIVE LINES WITH PAIRWISE DISJOINT FILE SETS, in queue order.
#
# Queue order is kept: the first live line is always taken (it is the one the serial runner would
# pop next), and each later line joins only if it touches nothing already claimed. A line that
# overlaps is left where it is — it is not reordered, and it is not dropped; the next sweep, on a
# tip where the overlapping line has landed, will see it disjoint.
#
# A LINE ALREADY PRE-PROVEN GREEN AT THIS TIP IS NOT SWEPT AGAIN, and its files are CLAIMED before the
# walk starts. Without the first, a second sweep at the same tip re-proved the same six lines and the
# ledger never reached the eight distinct greens the larger batch waits for; without the second, the
# second sweep's lines were disjoint among themselves but not from the first sweep's, and the popper
# would have joined two lines that touch one file. $4 is the tip; empty means "no ledger consulted".
# $5 IS THE BATCH THAT IS PROVING RIGHT NOW (the overlapped sweep, see lq_predict_tip). Its lines
# are not in the queue any more, but its FILES are about to change under every line behind it, and a
# line pre-proven against a prediction it overlaps is a pre-proof of something nobody will land: the
# prediction is only sound where the two file sets do not meet. Those files are claimed BEFORE the
# walk, exactly as the already-green lines' files are.
lq_disjoint_lines() { # $1 = max, $2 = queue file, $3 = repo (default $W), $4 = tip (optional), $5 = batch file already claimed (optional)
  # qa/*.toml IS SHARED OVER FIGURE-ONLY DIFFS here too (see lq_line_qa_rows): a sweep that never
  # let two figure-only lines share a box never reached the eight greens the larger batch waits for.
  local max="$1" qf="$2" repo="${3:-$W}" tip="${4:-}" inflight="${5:-}" line files claimed="" n=0 clash f crows=0 myrows
  if [ -n "$inflight" ] && [ -f "$inflight" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in ''|'#'*) continue ;; esac
      files="$(lq_line_files "$line" "$repo")"
      case "$files" in '?'|'') continue ;; esac
      [ "$(lq_line_qa_rows "$line" "$repo")" = 0 ] || crows=1
      while IFS= read -r f; do [ -n "$f" ] && claimed="$claimed$f$TAB"; done <<EOF
$files
EOF
    done <"$inflight"
  fi
  if [ -n "$tip" ] && [ -f "$PP" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      files="$(lq_line_files "$line" "$repo")"
      case "$files" in '?'|'') continue ;; esac
      [ "$(lq_line_qa_rows "$line" "$repo")" = 0 ] || crows=1
      while IFS= read -r f; do [ -n "$f" ] && claimed="$claimed$f$TAB"; done <<EOF
$files
EOF
    done <<EOF
$(awk -F"$TAB" -v tip="$tip" '$1 == "GREEN" && $2 == tip {print $4}' "$PP" | sort -u)
EOF
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; --*) ;; *) continue ;; esac
    [ "$n" -lt "$max" ] || break
    if [ -n "$tip" ] && [ "$(lq_preproved_status "$tip" "$line")" = GREEN ]; then continue; fi
    files="$(lq_line_files "$line" "$repo")"
    case "$files" in '?'|'') continue ;; esac
    myrows="$(lq_line_qa_rows "$line" "$repo")"; case "$myrows" in ''|'?') myrows=1 ;; esac
    clash=0
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      case "$TAB$claimed" in *"$TAB$f$TAB"*)
        case "$f" in qa/*.toml) [ "$myrows" = 0 ] && [ "$crows" = 0 ] && continue ;; esac
        clash=1; break ;;
      esac
    done <<EOF
$files
EOF
    [ "$clash" = 0 ] || continue
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      claimed="$claimed$f$TAB"
    done <<EOF
$files
EOF
    [ "$myrows" = 0 ] || crows=1
    printf '%s\n' "$line"
    n=$((n + 1))
  done <"$qf"
}

# WHAT THE PRE-PROVE LEDGER SAYS ABOUT ONE LINE AT ONE TIP: GREEN, RED or NONE.
#
# The tip is half the key. A row recorded against a different tip is not consulted at all — see the
# header: a pre-proof is evidence about the tree it ran on and about no other tree.
lq_preproved_status() { # $1 = tip sha, $2 = queue line, $3 = ledger (default $PP)
  local tip="$1" line="$2" pp="${3:-$PP}" st t rest
  [ -f "$pp" ] || { echo NONE; return 0; }
  local ans=NONE
  while IFS="$TAB" read -r st t rest; do
    [ -n "$st" ] || continue
    [ "$t" = "$tip" ] || continue
    # The log path is the third column; the line text is everything after it.
    local text="${rest#*"$TAB"}"
    [ "$text" = "$line" ] || continue
    ans="$st"
  done <"$pp"
  echo "$ans"
}

# ── WHAT THE UNION MAY INHERIT: THE MEMBERS' OWN PRE-PROOF LOGS, AND WHAT EACH OF THEM TOUCHED ────
# MEASURED 2026-09-10: every line lands proven TWICE — alone at pre-proof, and again in the batch
# union, where land.sh re-runs build, tests, gates and oracle in full (68 min serial). land.sh can
# now decline the legs a member already paid for at this exact tip (its land_preproof_inherits), and
# what it needs to do that is this index: one row per member whose pre-proof was GREEN AT THIS TIP,
# `<the proof's log>TAB<the files that member's picks touch>`.
#
# GREEN ONLY, AND AT THIS TIP ONLY. A RED or a NONE proved nothing to inherit, and a row keyed to
# another tip is evidence about another tree — the same rule the whole ledger is built on. The FILES
# are measured here, from the repo, rather than read out of the pre-proof's log: land.sh recomputes
# the member's owing set from them with the same function it uses on the union, so neither side is
# taking the other's word for what was owed.
lq_preproof_index() { # $1 = batch file, $2 = tip, $3 = repo (default $W), $4 = ledger (default $PP); writes <batch>.preproofs, prints the rows
  local bf="$1" tip="$2" repo="${3:-$W}" pp="${4:-$PP}" out="$1.preproofs" line lg files n=0
  : >"$out"
  [ -f "$bf" ] && [ -n "$tip" ] && [ -f "$pp" ] || { printf '0\n'; return 0; }
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    case "$line" in '#'*) continue ;; esac
    lg="$(LQ_AWK_T="$line" awk -F"$TAB" -v tip="$tip" \
            '$1 == "GREEN" && $2 == tip && $4 == ENVIRON["LQ_AWK_T"] { l = $3 } END { if (l != "") print l }' "$pp")"
    [ -n "$lg" ] || continue
    files="$(lq_line_files "$(lq_line_payload "$line")" "$repo" | grep -v '^$' | sort -u | tr '\n' ' ')"
    files="${files% }"
    [ -n "$files" ] || continue
    printf '%s%s%s\n' "$lg" "$TAB" "$files" >>"$out"
    n=$((n + 1))
  done <"$bf"
  printf '%s\n' "$n"
}

# THE BATCH SIZE. THE DEFAULT becomes eight when eight lines have already been proven green against
# THIS tip on boxes of their own; four otherwise.
#
# The larger batch is not a bet: those eight lines have each been through the whole engine against
# this exact tip, so the union is far likelier to be green in one pass than eight arbitrary lines
# would be — and a batch that goes green in one pass is the only thing that makes a bigger batch
# cheaper rather than dearer, because a red one bisects.
#
# `LAND_BATCH` IS A CEILING, NOT A COMMAND. An operator who writes LAND_BATCH=8 is saying "take eight
# when eight are ready", not "take eight arbitrary lines": a batch above four that has NOT been
# pre-proven is the bisect-at-the-same-price-per-half case the header describes, and this file does
# not take it whatever the environment says. So a LAND_BATCH of four or fewer is honoured as written
# (smaller is always allowed), and one above four is honoured only when at least that many DISTINCT
# lines are green at THIS tip — otherwise four. Ruled by the 2026-09-09 audit: eight only after eight.
lq_batch_size() { # $1 = tip sha, $2 = ledger (default $PP)
  local tip="$1" pp="${2:-$PP}" n=0 want="${LAND_BATCH:-8}"
  case "$want" in ''|*[!0-9]*) want=8 ;; esac
  [ "$want" -gt 4 ] || { echo "$want"; return 0; }
  if [ -f "$pp" ]; then
    # A CHAINED GREEN COUNTS. Its row keys by `<tip>@<predecessor picks>` and it was proven on
    # THIS tip with those picks beneath it — which is the whole of what "eight lines each through the
    # engine against this exact tip" asks for. Counting only the bare-tip rows would cap a batch of
    # eight chained greens at four for want of eight LIVE ones, which is the arithmetic this engine
    # exists to beat.
    n="$(awk -F"$TAB" -v tip="$tip" '$1 == "GREEN" && ($2 == tip || index($2, tip "@") == 1) {print $4}' "$pp" | sort -u | grep -c . || true)"
  fi
  case "$n" in ''|*[!0-9]*) n=0 ;; esac
  if [ "$n" -ge "$want" ]; then echo "$want"; else echo 4; fi
}

# ── WHAT MAY SHARE A BATCH ──────────────────────────────────────────────────────────────────────────
# A batch is proven as a UNION, and a red union bisects at the full price per half. Three shapes of
# line are known — measured over tonight's queue — to make a union red for a reason that is not the
# union's, and each is refused a neighbour rather than left to the bisect:
#
#   * TWO LINES THAT TOUCH ONE FILE. Their picks interact (a conflict, or a green-alone/red-together
#     pair), and a union that contains both says nothing about either. They never share a batch;
#     the later one waits for a batch the earlier one is not in. A line whose picks cannot be
#     resolved has an UNKNOWN file set (see lq_line_files), and unknown is not empty: it shares
#     with nobody.
#   * TWO LINES THAT TOUCH xtask/src/gates/**. A gate edit changes the JUDGE; two judge edits in one
#     union make a red row attributable to neither. At most one per batch.
#   * A LINE THAT HAS GONE RED ONCE. The land-done ledger remembers it; it lands ALONE, so its
#     second red — or its green — is its own and not a bisect over its neighbours.
#   * A DECLARED RAISE AND A LOWERING OF THE SAME CEILING. The box proves one tree against one base:
#     a line that declares `[gate.ceiling_raises."K"]` (from A to B) beside a line that lowers K's
#     figure nets the rise below the declaration, and `ceiling-rose` refuses the declaration as
#     STALE — a red that belongs to neither line. They never share a batch (2026-09-09 audit).
#
# ── AND WHAT THE RULES ARE ABOUT: UNITS, NOT LINES ────────────────────────────────────────────────
# MEASURED, 09-10 (T0-D6, on the live queue): chained pre-proofs make a held line provable early, and
# the batch count went 51 → 50. One rule ate the whole win: a dependent line touches its predecessor's
# files — that overlap is WHY the line is held — so "never two lines on one file" refused the very
# join chaining exists to make, and every chained green waited for the next batch anyway.
#
# The rules above are not wrong; they are stated at the wrong grain. Every one of them exists so that
# a RED batch bisects cleanly: halving a batch must not separate a dependent from its predecessor,
# and every line must come out of the bisect with its own attributed verdict. A CHAIN — a live root
# and its chained-green dependents, in queue order, at most LAND_CHAIN_DEPTH deep — satisfies both
# when it is admitted, bisected and judged AS ONE UNIT:
#
#   * INSIDE a unit, file overlap is EXPECTED and allowed, and so is a second gate line and a
#     ceiling raise beside a lowering: the unit is proven as a prefix ladder (root; root+1; root+2 …)
#     by land.sh's unit bisect, so the first line that turns the prefix red is the culprit, every
#     line before it is green with a proof of its own, and every line after it goes back to HELD.
#     Attribution survives; nothing is inferred.
#   * BETWEEN units, every rule above stands exactly as written, with the unit's FILE SET being the
#     UNION of its lines' files, and a unit counting once for the one-gate-line rule and once for
#     the ceiling-move rule. Two units never share a file; a red batch of units bisects BY UNIT, so
#     no half ever separates a dependent from its predecessor.
#   * A BASE FIX IS NEVER INSIDE A UNIT. It re-pins what every line in the batch is judged against
#     (lq_line_is_base_fix, and lq_chain_of refuses a chain containing one at either end); it is its
#     own unit of one and it pops alone.
#   * THE CEILING COUNTS LINES, NOT UNITS. LAND_BATCH is a bound on how much is proven in one union,
#     and a unit of three is three lines of proving. A unit that does not fit whole is admitted as
#     far as it fits: the prefix that is admitted is a chain in its own right, and its tail keeps its
#     hold and rides the next batch.
lq_line_touches_gates() { # $1 = queue line, $2 = repo
  local f
  while IFS= read -r f; do
    case "$f" in xtask/src/gates/*) return 0 ;; esac
  done <<EOF
$(lq_line_files "$1" "$2")
EOF
  return 1
}
# THE CEILING MOVES A LINE MAKES, over qa/construction.toml and qa/kind-isolation.toml. Two kinds:
#   raise <file>:<path>   the line ADDS a declared raise entry `[gate.ceiling_raises."<path>"]`
#                         (keyed as ceilings::raises keys it: the entry's `file`, default
#                         qa/construction.toml, then the dotted path);
#   lower <file>:<path>   the line LOWERS the integer at <path> in <file>.
# A line that cannot be resolved prints `?`. Integers are read whether written bare or quoted, as the
# gate reads them.
lq_toml_ints() { # $1 = repo  $2 = rev  $3 = file; prints "<path>\t<int>" per integer, and "raise\t<key>" per declared raise
  git -C "$1" show "$2:$3" 2>/dev/null | awk '
    /^\[/ { sec = $0; sub(/^\[+/, "", sec); sub(/\]+.*$/, "", sec)
             if (index(sec, "gate.ceiling_raises.") == 1) { k = substr(sec, 21); gsub(/"/, "", k); print "raise\t" k }
             next }
    /^[A-Za-z0-9_.-]+[ \t]*=[ \t]*"?[0-9]+"?[ \t]*(#.*)?$/ {
             key = $0; sub(/[ \t]*=.*$/, "", key); v = $0; sub(/^[^=]*=[ \t]*"?/, "", v); sub(/"?[ \t]*(#.*)?$/, "", v)
             print (sec == "" ? key : sec "." key) "\t" v }'
}
lq_line_ceiling_moves() { # $1 = queue line, $2 = repo; prints "raise <file>:<path>" / "lower <file>:<path>" / "?"
  local line="$1" repo="$2" h f any=0
  for h in $(lq_line_hashes "$line"); do
    any=1
    git -C "$repo" rev-parse -q --verify "$h^{commit}" >/dev/null 2>&1 || { printf '?\n'; return 0; }
    for f in qa/construction.toml qa/kind-isolation.toml; do
      git -C "$repo" diff --quiet "$h^" "$h" -- "$f" 2>/dev/null && continue
      # Raise entries added by this pick. The entry's own `file` field decides the key's file.
      awk -F'\t' -v f="$f" 'FNR == NR { if ($1 == "raise") before[$2] = 1; next }
                             $1 == "raise" && !($2 in before) { print "raise-entry\t" $2 }' \
        <(lq_toml_ints "$repo" "$h^" "$f") <(lq_toml_ints "$repo" "$h" "$f") \
      | while IFS="$TAB" read -r _ k; do
          local ef; ef="$(git -C "$repo" show "$h:$f" | awk -v k="$k" '
            /^\[gate\.ceiling_raises\./ { s = $0; gsub(/"/, "", s); on = index(s, "gate.ceiling_raises." k "]") > 0; next }
            /^\[/ { on = 0 } on && /^file[ \t]*=/ { v = $0; sub(/^file[ \t]*=[ \t]*"/, "", v); sub(/".*$/, "", v); print v; exit }')"
          printf 'raise %s:%s\n' "${ef:-qa/construction.toml}" "$k"
        done
      # Integers lowered by this pick.
      awk -F'\t' -v f="$f" 'FNR == NR { if ($1 != "raise") before[$1] = $2; next }
                             $1 != "raise" && ($1 in before) && ($2 + 0 < before[$1] + 0) { print "lower " f ":" $1 }' \
        <(lq_toml_ints "$repo" "$h^" "$f") <(lq_toml_ints "$repo" "$h" "$f")
    done
  done
  [ "$any" = 1 ] || printf '?\n'
}
lq_line_was_red() { # $1 = queue line, $2 = done ledger (default $D); rows are `ST batch=.. log=.. <text>`
  local line="$1" d="${2:-$D}"
  [ -f "$d" ] || return 1
  awk -v want="$line" 'index($1, "RED") == 1 { t = $0; sub(/^[^ ]+ batch=[^ ]+ log=[^ ]+ /, "", t); if (t == want) { found = 1; exit } } END { exit !found }' "$d"
}
# THE ROWS A LINE ADDS OR REMOVES IN qa/*.toml. A figure-only diff (an integer re-pinned by
# measurement — what K1 does) is what two lines may share a ceiling file over; a diff that adds or
# removes a ROW — a declared raise, a minted kind, a rename, a transitional, a retired census entry —
# is a change to what the gate judges, and two of those never share. Prints the count, `?` when a
# pick does not resolve.
LQ_QA_ROW_RE='^\[\[(gate\.ceiling_raises|minted|minted_kind|renamed|transitional|gate\.census_retired)\]\]|^\[gate\.ceiling_raises\.'
lq_line_qa_rows() { # $1 = queue line, $2 = repo
  local h n=0 c
  for h in $(lq_line_hashes "$1"); do
    git -C "$2" rev-parse -q --verify "$h^{commit}" >/dev/null 2>&1 || { printf '?\n'; return 0; }
    c="$(git -C "$2" diff "$h^" "$h" -- 'qa/*.toml' 2>/dev/null | grep -E '^[-+][^-+]' | sed 's/^[-+][[:space:]]*//' | grep -Ec "$LQ_QA_ROW_RE" || true)"
    n=$((n + c))
  done
  printf '%s\n' "$n"
}
# THE FILE SET OF A UNIT: the union of the files of the lines already in it. The ancestor payloads
# come in as one multi-line argument, exactly as lq_chain_of prints them. TAB-joined, TAB-terminated,
# so a caller can test membership with the same `case` the claimed set uses. An unresolvable member
# prints nothing for itself — it cannot be a member of anything, because lq_chain_of refuses a chain
# whose lines do not resolve.
lq_unit_files() { # $1 = the unit's lines (payloads, one per line), $2 = repo; prints "<f>TAB<f>TAB…"
  local repo="${2:-$W}" l f out=""
  while IFS= read -r l || [ -n "$l" ]; do
    [ -n "$l" ] || continue
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      case "$TAB$out" in *"$TAB$f$TAB"*) continue ;; esac
      out="$out$f$TAB"
    done <<EOF
$(lq_line_files "$l" "$repo")
EOF
  done <<EOF
$1
EOF
  printf '%s' "$out"
}
# ── HOW A UNIT BOUNDARY TRAVELS ───────────────────────────────────────────────────────────────────
# IN BAND, IN THE BATCH FILE. land.sh reads a batch line by line and has always skipped every `#`
# line, so `#UNIT <k>` — "the next landing line belongs to the unit rooted at the k-th landing line
# of this file" — needs no second file, no new argument, and no change to scripts/land-remote.sh,
# which copies the batch to the box byte for byte and scans it only for hashes. A landing line with
# no marker is a unit of one rooted at itself, because land.sh's default unit for the i-th landing
# line is i — which is exactly the number the root of a chain is given.
lq_batch_index() { # $1 = batch file, $2 = payload text; prints the 1-based LANDING-LINE index, or nothing
  [ -f "$1" ] || return 0
  LQ_AWK_T="$2" awk '/^[[:space:]]*(#|$)/ { next } { n = n + 1 } $0 == ENVIRON["LQ_AWK_T"] { print n; exit }' "$1"
}
# THE LANDING LINES OF A BATCH FILE — what land.sh will prove, markers and comments dropped. The
# runner counts THESE against the per-line outcome file, never the raw line count of the file.
lq_batch_lines() { # $1 = batch file
  [ -f "$1" ] || return 0
  grep -vE '^[[:space:]]*(#|$)' "$1" 2>/dev/null || true
}
# THE JOIN DECISION for one candidate against the batch so far. Prints nothing; the exit status is the
# answer, and the caller extends the claimed set only on a yes.
#   $1 = line  $2 = repo  $3 = lines in batch so far  $4 = claimed files (TAB-joined)  $5 = gates already taken (0|1)
#   $6 = batch holds a was-red line (0|1)  $7 = ceiling moves claimed so far ("raise K" / "lower K", TAB-joined)
#   $8 = batch holds a line with qa row diffs (0|1)  $9 = batch holds a base fix (0|1)
#   ${10} = THE UNIT THIS CANDIDATE IS JOINING — the file set of the chain it rides (lq_unit_files),
#           empty when the candidate opens a unit of its own. Every rule below is a rule BETWEEN
#           units (see the note above): a file already claimed BY THIS UNIT is not a clash, and the
#           one-gate-line, ceiling-move and qa-row rules are not consulted for a line that is joining
#           the unit that already holds them. What is left — a red-once line, a base fix, an
#           unresolvable file set — refuses inside a unit exactly as it refuses beside one.
lq_may_join() {
  local line="$1" repo="$2" nb="$3" claimed="$4" gates="$5" alone="$6" moves="${7:-}" brows="${8:-0}" bfix="${9:-0}" unit="${10:-}" files f m kind key myrows
  [ "$alone" = 0 ] || return 1                         # a red-once line took the whole batch
  [ "$bfix" = 0 ] || return 1                          # a base fix took the whole batch
  if lq_line_was_red "$line"; then [ "$nb" = 0 ] || return 1; fi
  # A BASE FIX JOINS NOBODY (see lq_line_is_base_fix): a line that touches only qa/*.toml re-pins
  # what every other line in the batch would be judged against, and lands alone — and it is never
  # INSIDE a unit either, whatever a `#HOLD-after-<sha>` tag on it may claim (rule 2g).
  if lq_line_is_base_fix "$line" "$repo"; then [ "$nb" = 0 ] && [ -z "$unit" ] || return 1; fi
  files="$(lq_line_files "$line" "$repo")"
  case "$files" in '?'|'') [ "$nb" = 0 ] || return 1 ;; esac   # unknown shares with nobody
  myrows="$(lq_line_qa_rows "$line" "$repo")"; case "$myrows" in ''|'?') myrows=1 ;; esac
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # ITS OWN UNIT'S FILES ARE NOT A CLASH. They are the predecessor's, and that overlap is the
    # reason the line was held; the unit is bisected by prefix, so the attribution survives it.
    case "$TAB$unit" in *"$TAB$f$TAB"*) continue ;; esac
    case "$TAB$claimed" in *"$TAB$f$TAB"*)
      # qa/*.toml IS SHARED when the diffs on both sides are figure-only (see lq_line_qa_rows).
      case "$f" in qa/*.toml) [ "$myrows" = 0 ] && [ "$brows" = 0 ] && continue ;; esac
      return 1 ;;
    esac
  done <<EOF
$files
EOF
  if [ -n "$unit" ]; then return 0; fi                 # the rest are rules BETWEEN units
  if [ "$gates" = 1 ] && lq_line_touches_gates "$line" "$repo"; then return 1; fi
  while IFS= read -r m; do
    [ -n "$m" ] || continue
    kind="${m%% *}"; key="${m#* }"
    case "$kind" in
      raise) case "$TAB$moves" in *"${TAB}lower $key$TAB"*) return 1 ;; esac ;;
      lower) case "$TAB$moves" in *"${TAB}raise $key$TAB"*) return 1 ;; esac ;;
    esac
  done <<EOF
$(lq_line_ceiling_moves "$line" "$repo")
EOF
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# ONE ENGINE IN THE TREE. Before every sweep and every pop, a census: every process whose cwd is
# this tree, or whose command names land.sh / land.run.sh / land-remote.sh / `xtask gate|selftest`
# under this tree, must descend from the lock holder. Anything else is a stranger — a slot's
# landing, a hand-run proof, a previous runner's orphan — and two engines in one tree is how a
# batch is judged on a HEAD the other one moved. A stranger is killed and logged; then the tree
# itself must be settled (HEAD is the last landed tip, nothing modified) or the batch is refused.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
LQ_ENGINE_RE='land\.sh|land\.run(\.local)?\.sh|land-remote\.sh|landq4\.sh|xtask (gate|selftest)'
lq_ps() { ps -eo pid=,ppid=,args= 2>/dev/null; }
lq_pid_cwd() { # $1 = pid; prints its cwd where the host can say (Linux /proc, else lsof), else nothing
  if [ -r "/proc/$1/cwd" ]; then readlink "/proc/$1/cwd" 2>/dev/null || true
  elif command -v lsof >/dev/null 2>&1; then lsof -a -d cwd -p "$1" -Fn 2>/dev/null | sed -n 's/^n//p' | head -n1
  fi
}
lq_pid_touches() { # $1 = pid, $2 = tree; 0 when one of its OPEN FILES (lsof, or /proc/<pid>/fd) is under the tree
  if command -v lsof >/dev/null 2>&1; then lsof -p "$1" 2>/dev/null | grep -q -- "$2"
  elif [ -d "/proc/$1/fd" ]; then
    local fd
    for fd in /proc/"$1"/fd/*; do case "$(readlink "$fd" 2>/dev/null)" in *"$2"*) return 0 ;; esac; done
    return 1
  else return 1
  fi
}
lq_cwd_pids() { # $1 = tree; prints every pid whose CWD is the tree or under it (the mutator's own mark)
  local d p n phys
  # BOTH FORMS OF THE PATH. `/tmp` is a symlink to `/private/tmp` on the laptop and `/var` to
  # `/private/var`; lsof and /proc/<pid>/cwd both answer with the PHYSICAL path. Compared only
  # against the name the runner uses, a process sitting in /tmp/land-fanout-<sha> — which is where
  # the runner's tree actually is — would never match.
  phys="$(cd "$1" 2>/dev/null && pwd -P)"; [ -n "$phys" ] || phys="$1"
  if [ -r /proc/self/cwd ]; then
    for d in /proc/[0-9]*; do
      case "$(readlink "$d/cwd" 2>/dev/null)" in
        "$1"|"$1"/*|"$phys"|"$phys"/*) printf '%s\n' "${d#/proc/}" ;;
      esac
    done
  elif command -v lsof >/dev/null 2>&1; then
    # ASKED BY ITS PHYSICAL NAME. lsof answers nothing at all for a path it cannot resolve — a
    # `$TMPDIR` that ends in a slash yields `…/T//tree`, and the whole sweep came back empty.
    lsof -a -d cwd -Fpn -- "$phys" 2>/dev/null | while IFS= read -r n; do
      case "$n" in
        p*) p="${n#p}" ;;
        n*) case "${n#n}" in "$1"|"$1"/*|"$phys"|"$phys"/*) printf '%s\n' "$p" ;; esac ;;
      esac
    done
  fi
}
lq_ancestry() { # $1 = pid, $2 = listing; prints $1 and every ancestor of it up to init
  local p="$1" list="$2" i=0
  while [ -n "$p" ] && [ "$p" != 0 ] && [ "$i" -lt 64 ]; do
    printf '%s\n' "$p"
    [ "$p" = 1 ] && break
    p="$(printf '%s\n' "$list" | awk -v p="$p" '$1 == p {print $2; exit}')"; i=$((i + 1))
  done
}
# WHAT A SHELL IS ACTUALLY RUNNING. `ps` flattens argv, so `/bin/zsh -c 'tail -f <W>/…/landq.out'`
# reads as a command line that NAMES THE TREE — which is how the census came to kill the
# integrator's monitor at 03:27. The string after a single `-c`/`-lc` is unwrapped once and judged
# on its own merits; nothing deeper is unwrapped, because a shell that builds another shell's
# command line is not something to be clever about.
lq_shell_payload() { # $1 = args; prints the command a `-c`/`-lc` shell will run, else the args unchanged
  local a="$1" s head
  case "$a" in
    *" -lc "*) s="${a#*" -lc "}" ;;
    *" -c "*)  s="${a#*" -c "}" ;;
    *) s="$a" ;;
  esac
  s="${s#\'}"; s="${s#\"}"
  # THE HARNESS'S OWN PROLOGUE. Every shell this agent fleet runs is
  #   /bin/zsh -c 'source ~/.claude/shell-snapshots/snapshot-zsh-<n>.sh 2>/dev/null; <cmd>'
  # and the `;` and the `>` in that prologue made EVERY such shell a stranger — which is precisely
  # the string the census killed at 03:24. A leading `source <file>`/`. <file>` with nothing on it
  # but redirections is dropped, and the command after it is judged exactly as before. Only that
  # shape: a prologue carrying `&&`, a pipe, or a second word is not a prologue and is not stripped,
  # so `sh -c 'source x && rm -rf <W>'` is still read for what it is.
  while : ; do
    case "$s" in 'source '*|'. '*) ;; *) break ;; esac
    head="${s%%;*}"
    [ "$head" != "$s" ] || break
    printf '%s' "$head" | grep -qE '^(source|\.) +[^ ;|&]+( +[0-9]?>[^ ;|&]+| +[0-9]?>&[0-9])* *$' || break
    s="${s#*;}"
    while : ; do case "$s" in ' '*) s="${s# }" ;; *) break ;; esac; done
  done
  printf '%s' "$s"
}
# THE ONE EXEMPTION THAT IS NOT ANCESTRY: A READER. Not "anything behind a -c string" — a mutator
# invoked as `bash -c 'cd <W> && git reset --hard'` is EXACTLY the 22:50 mis-launch this census
# exists to kill, and it hides behind a -c string just as well as a monitor does. So the payload
# must be read-only on its face: every stage of it a command out of the reading list, no write
# redirection, no second command, no substitution. `sed` counts only as `sed -n` (a `sed -i` edits
# the tree); `tee`, `cp`, `git`, `cargo`, `rm` are not on the list and never will be.
LQ_READER_CMDS='tail|head|cat|less|more|grep|egrep|fgrep|zgrep|rg|ls|wc|awk|cut|sort|uniq|tr|od|xxd|file|stat|find'
lq_is_reader() { # $1 = args; 0 when this process can only READ the tree
  local c seg w
  c="$(lq_shell_payload "$1")"
  case "$c" in *'>'*|*';'*|*'&&'*|*'`'*|*'$('*|*'&'*) return 1 ;; esac
  while [ -n "$c" ]; do
    case "$c" in *'|'*) seg="${c%%|*}"; c="${c#*|}" ;; *) seg="$c"; c="" ;; esac
    while : ; do case "$seg" in ' '*|'	'*) seg="${seg# }"; seg="${seg#	}" ;; *) break ;; esac; done
    w="${seg%% *}"; w="${w##*/}"
    [ -n "$w" ] || return 1
    case "$w" in
      sed) case " $seg " in *" -n "*) ;; *) return 1 ;; esac ;;
      *) printf '%s' "$w" | grep -qxE "$LQ_READER_CMDS" || return 1 ;;
    esac
  done
  return 0
}
lq_descends() { # $1 = pid, $2 = ancestor pid, $3 = listing (pid ppid args); 0 when $1 is $2 or a descendant
  local p="$1" a="$2" list="$3" i=0
  while [ -n "$p" ] && [ "$p" != 0 ] && [ "$p" != 1 ] && [ "$i" -lt 64 ]; do
    [ "$p" = "$a" ] && return 0
    p="$(printf '%s\n' "$list" | awk -v p="$p" '$1 == p {print $2; exit}')"; i=$((i + 1))
  done
  return 1
}
# WHAT COUNTS AS TOUCHING THE TREE — not cwd first: the engine mutates the tree by `git -C`, so its
# cwd is wherever it was started. A process is in the census when its COMMAND LINE names the tree,
# or (for a command that names an engine) one of its OPEN FILES is under the tree, or (for an
# `xtask gate|selftest`, which a slot runs from inside the tree) its cwd IS the tree. Every process
# found is printed — "own pid N (...)" for the runner's chain, "stranger pid N killed (...)" for an
# outsider, which is killed unless LANDQ_CENSUS_DRY=1 — and an EMPTY census is BROKEN (rc 1): the
# runner's own chain (this pid, its subshell, land-remote.sh, its re-exec) must be visible, or the
# census is not looking at the host it thinks it is.
lq_census() { # $1 = holder pid, $2 = tree, $3 = listing (default: live ps); rc 1 when nothing at all was found
  local holder="$1" tree="$2" list="${3:-$(lq_ps)}" pid _ppid args hit found=0 anc cwdpids=""
  # THE RUNNER'S OWN CHAIN, UPWARD (03:27). lq_descends walks DOWN from the holder, so the shell
  # that LAUNCHED the runner — `/bin/zsh -c 'source …snapshot…; … bash landq4.sh'`, whose command
  # string names the tree because the tree is in the snapshot path — was neither a descendant nor a
  # reader, and the census killed it, orphaning its own landing. An ancestor is never a stranger:
  # killing one kills the census taking the decision. The walk is from the holder to init.
  anc="$(lq_ancestry "$holder" "$list")"
  # CWD IS A MUTATOR'S MARK whatever the process is called: `sleep`, `vim`, an editor's helper. It
  # is asked once, of the host, and only when the listing is the live one.
  [ -n "${3:-}" ] || cwdpids="$(lq_cwd_pids "$tree")"
  while read -r pid _ppid args; do
    [ -n "$pid" ] || continue
    # THE RUNNER'S OWN CHAIN IS KNOWN BY PID, NEVER BY ARGV (F1d). MEASURED 2026-09-11 under the
    # supervisor: `bash landq-supervisor.sh` → `bash <engine home>/scripts/landq4.sh`, started from
    # ~/Developer/tmp, names the tree NOWHERE — not in argv, not in cwd — so the census found
    # nothing at all, called itself broken, and refused every batch at every loop top. The
    # hand-started runner only ever passed because the integrator's shell wrapper happened to carry
    # the tree in its command text. A lock this process holds is a fact about identity that no
    # string can be; the holder and everything below it are SELF, whatever they are called.
    if lq_descends "$pid" "$holder" "$list"; then
      found=$((found + 1))
      printf 'own pid %s (%s)\n' "$pid" "$(printf '%.100s' "$args")"
      continue
    fi
    hit=0
    case "$args" in *"$tree"*) hit=1 ;; esac
    if [ "$hit" = 0 ] && printf '%s' "$args" | grep -qE "$LQ_ENGINE_RE"; then
      if [ -n "${3:-}" ]; then :   # a fabricated listing has no live files to ask about
      elif lq_pid_touches "$pid" "$tree"; then hit=1
      elif printf '%s' "$args" | grep -qE 'xtask (gate|selftest)' && [ "$(lq_pid_cwd "$pid")" = "$tree" ]; then hit=1
      fi
    fi
    if [ "$hit" = 0 ] && [ -n "$cwdpids" ]; then
      case "
$cwdpids
" in *"
$pid
"*) hit=1 ;; esac
    fi
    [ "$hit" = 1 ] || continue
    found=$((found + 1))
    case "
$anc
" in *"
$pid
"*) printf 'ancestor pid %s (kept) (%s)\n' "$pid" "$(printf '%.100s' "$args")"; continue ;; esac
    # A READER is the one outsider that may touch the tree: listed, kept — whether it is a bare
    # `tail -f` or a monitor's `zsh -c 'tail -f <W>/target/gate/landq.out'`. See lq_is_reader for
    # why the exemption is the payload's READ-ONLY shape and not the `-c` string itself.
    if lq_is_reader "$args"; then
      printf 'reader pid %s (kept) (%s)\n' "$pid" "$(printf '%.100s' "$args")"; continue
    fi
    [ "${LANDQ_CENSUS_DRY:-}" = 1 ] || kill "$pid" 2>/dev/null
    printf 'stranger pid %s killed (%s)\n' "$pid" "$(printf '%.100s' "$args")"
  done <<EOF
$list
EOF
  [ "$found" -gt 0 ]
}
lq_tree_settled() { # $1 = tree, $2 = last-landed-tip file; 0 = HEAD is that tip and nothing tracked is modified
  local head last dirty
  head="$(git -C "$1" rev-parse HEAD 2>/dev/null)"
  last="$(cat "$2" 2>/dev/null | tr -d '[:space:]')"
  [ -n "$last" ] || { printf '%s\n' "$head" >"$2"; last="$head"; }   # first run: the tip as found
  dirty="$(git -C "$1" status --porcelain 2>/dev/null | grep -vE '^\?\?' || true)"
  [ "$head" = "$last" ] && [ -z "$dirty" ]
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# A BASE FIX POPS ALONE. A head line whose picks touch only qa/*.toml is a re-pin of the ceilings
# the whole queue is judged against; every line behind it would be pre-proven against a base the
# head is about to replace, and `ceiling-rose` would red them for figures the head repairs. So: no
# sweep, the head alone, nothing pre-proven behind it. A sweep is also skipped when fewer than two
# live lines exist — a sweep of one line is the serial runner plus a box.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE QUEUE IS A SHARED FILE, AND THE RUNNER IS NOT ITS ONLY WRITER
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# The runner rewrote land-queue.txt IN FULL from its own snapshot on every loop — after every pop
# attempt, on the HALT requeue, on the red park — unlocked and unchecked. So an integrator's edit
# made inside the read→rewrite window was silently REVERTED: no error, no log line, the runner
# simply idled on a queue that no longer said what its owner had just told it to say. (Audit 14.)
#
# Three rules, and only the third of them needs the clock:
#
#   * REWRITE ONLY WHAT CHANGED. A loop that popped nothing, parked nothing and released nothing
#     produces a `keep` file byte-identical to the queue; writing it back is a no-op that can only
#     ever lose somebody else's edit. Compared with cmp, so "did the runner change anything" is a
#     measurement rather than a flag somebody has to remember to set.
#   * ONE WRITER. `$W/target/gate/land-queue.lock` is a mkdir-lock (atomic on every filesystem the
#     fleet has, unlike flock, which is not on macOS's coreutils path) holding the writer's pid; a
#     lock whose holder is dead is taken over, because a runner killed mid-rewrite must not stop
#     the queue forever.
#   * THE FILE MUST BE THE ONE THAT WAS READ. A stamp is taken when the queue is read and checked
#     again before the rewrite; different means somebody edited it, and the runner then DROPS ITS
#     OWN LOOP — the hand edit stands, the pop is taken again next loop against what the file now
#     says. The stamp is mtime AND size AND cksum, because mtime alone has one-second granularity
#     and the window this exists to close is usually shorter than that.
lq_qstamp() { # prints a stamp of the queue file as it is right now
  # THE TWO `stat`s ARE NOT THE SAME PROGRAM, and neither fails on the other's flags in a way a
  # fallback chain can read: GNU's `-f` is "file SYSTEM status" and prints a block of free-block
  # counts that CHANGE between two calls a millisecond apart, so `stat -f %m || stat -c %Y` gave a
  # Linux box a stamp that never matched itself and refused every rewrite it was asked for. Found
  # by the fleet box, not by the laptop, which is why it is asked the way `date` is asked above.
  local m
  if stat --version >/dev/null 2>&1; then m="$(stat -c %Y "$Q" 2>/dev/null || echo 0)"
  else m="$(stat -f %m "$Q" 2>/dev/null || echo 0)"; fi
  printf '%s:%s\n' "$m" "$(cksum <"$Q" 2>/dev/null || echo 0)"
}
lq_qlock() { # $1 = seconds to wait (default 30); 0 when this shell holds the queue lock
  local wait="${1:-30}" i=0 owner ostart
  while ! mkdir "$QLOCK" 2>/dev/null; do
    owner="$(cat "$QLOCK/pid" 2>/dev/null || true)"
    ostart="$(cat "$QLOCK/start" 2>/dev/null || true)"
    # A CORPSE DOES NOT HOLD A QUEUE — and neither does a process that merely inherited the number
    # (see lq_lock_stale). Both are `lock-stale`, and the queue is taken back rather than waited on
    # until somebody notices.
    if [ -n "$owner" ] && [ "$owner" != "$$" ] && lq_lock_stale "$owner" "$ostart"; then
      lq_fault_record lock-stale "$QLOCK held by pid $owner, which is dead or is no longer the process that took it" >/dev/null
      rm -rf "$QLOCK"
    fi
    i=$((i + 1)); [ "$i" -lt "$wait" ] || return 1
    sleep 1
  done
  printf '%s\n' "$$" >"$QLOCK/pid"
  lq_pid_start "$$" >"$QLOCK/start"
  return 0
}
lq_qunlock() { rm -rf "$QLOCK"; }
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE INBOX: WHERE A HAND-BACK GOES WHILE THE RUNNER IS MID-LOOP
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# MEASURED 2026-09-10: lq_queue_rewrite REFUSED twice in one day, both times because the integrator
# appended a hand-back line to land-queue.txt while the runner was inside its read -> sweep -> pop
# -> rewrite window. A sweep is six to ten minutes, so that window is very nearly the whole loop:
# the refusal is not a rare race, it is the ordinary outcome of typing. And the refusal is RIGHT —
# an edit must never be silently overwritten — so the cost lands on the other side: the loop's whole
# pop is thrown away and taken again, and a queue of 120 lines goes nowhere for twenty minutes
# because two lines were handed back.
#
# THE FIX IS A SECOND DOOR, NOT A WEAKER GUARD. The integrator only ever APPENDS to
# target/gate/land-queue.inbox.txt and never touches land-queue.txt; nobody reads the inbox but the
# runner, at the top of its loop, UNDER THE QUEUE LOCK, BEFORE the stamp is taken. Every line moves
# to the TAIL of the queue in the order it was written — comments, `#HOLD-*` lines and blanks
# included, because a hand-back is usually a comment above a hold and an inbox that dropped either
# would be a queue the integrator has to repair — the inbox is truncated, and only then is the
# stamp taken. An append made at any point after that moment lands in the inbox rather than in the
# file the stamp describes, so the rewrite at the end of the loop still matches, the pop stands, and
# the line joins the queue at the next loop top a minute later.
#
# THE REFUSAL GUARD IS UNTOUCHED. A direct edit of land-queue.txt is refused exactly as it was; this
# is an easier door, not an open one.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE INBOX IS A COMMAND FILE, AND THE RUNNER IS THE ONLY WRITER OF THE QUEUE (F3)
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# T0-D13's inbox fixed APPENDS: a hand-back written while the runner was mid-loop went to the inbox
# instead of into the read -> sweep -> pop -> rewrite window, and the pop stopped being thrown away
# for it. But everything else an integrator does to the queue — a park, an un-park, a supersede, a
# re-tag, a line moved to the front — still needed a DIRECT EDIT of land-queue.txt, and a direct
# edit inside that window is refused by the stamp guard and costs the whole loop's pop. Measured
# 09-09..09-11: five refused rewrites, five dropped pops.
#
# SO THE INBOX CARRIES COMMANDS, and there is nothing left that needs a direct edit:
#
#     ADD <line>                  put <line> at the tail of the queue
#     PARK <sha> <reason>         tag the line naming <sha> `#PARK-<reason>`; it stops being live
#     UNPARK <sha>                take every park tag off it; it is live again
#     SUPERSEDE <old-sha> <line>  replace the line naming <old-sha> with <line>
#     RETAG <sha> <tags...>       replace its leading tags; no tags at all means "go live"
#     FRONT <sha>                 move it to the head of the queue
#
# A BARE LINE IS AN `ADD`. That is T0-D13's form and every integrator's fingers already know it;
# comments, `#HOLD-*` lines and blanks fold to the tail exactly as they did, because a hand-back is
# usually a comment above a hold and an inbox that dropped either would be a queue somebody has to
# repair. A command that cannot be carried out — a verb with no sha, a sha no queue line names, a
# SUPERSEDE with nothing to supersede with — is LOGGED WITH ITS TEXT AND SKIPPED. Never fatal:
# one mistyped line must not stop a queue of a hundred and twenty.
#
# scripts/landq-ctl.sh is the only tool that writes this file, and it appends one line per command.
lq_slug() { # $1 = free text; prints it as one queue-tag token
  printf '%s' "${1:-by-hand}" | tr -c '[:alnum:]._-' '-' | sed 's/-\{1,\}/-/g; s/^-//; s/-$//'
}
# A QUEUE WHOSE LAST BYTE IS NOT A NEWLINE would take the next line onto the end of its own last
# line and produce one payload nobody wrote. `$(tail -c1)` is empty exactly when that byte IS a
# newline (the substitution strips it), which is the cheap way to ask.
lq_queue_append() { # $1 = queue file, $2 = the line
  local qf="$1"
  [ -f "$qf" ] || : >"$qf"
  if [ -s "$qf" ] && [ -n "$(tail -c1 "$qf" 2>/dev/null)" ]; then printf '\n' >>"$qf"; fi
  printf '%s\n' "$2" >>"$qf"
}
lq_cmd_verb() { # $1 = an inbox line; prints its verb when it is a command, else nothing
  case "${1%% *}" in
    ADD|PARK|UNPARK|SUPERSEDE|RETAG|FRONT) printf '%s\n' "${1%% *}" ;;
  esac
}
# THE PARK TAGS COME OFF, AND THE LOG PATH WITH THEM. A pre-proof park is written
# `#RED-preproof <log> <payload>` — the log is not a `#` token, so a blind "drop leading # tokens"
# would leave the path behind as the head of the payload and hand a box a line that is not a line.
lq_line_unpark() { # $1 = a queue line; prints it with every park tag (and their arguments) removed
  local rest="$1" tok
  while : ; do
    tok="${rest%% *}"
    case "$tok" in
      '#RED-preproof'|'#PARK-preproof')
        case "$rest" in *' '*) rest="${rest#* }" ;; *) rest="" ;; esac   # the tag
        case "$rest" in *' '*) rest="${rest#* }" ;; *) rest="" ;; esac ;; # the log path
      '#RED'|'#RED-'*|'#PARK'|'#PARK-'*)
        case "$rest" in *' '*) rest="${rest#* }" ;; *) rest="" ;; esac ;;
      *) break ;;
    esac
  done
  printf '%s\n' "$rest"
}
# ONE COMMAND, APPLIED TO THE QUEUE FILE IN PLACE. rc 0 = applied, 1 = malformed (logged, skipped).
lq_inbox_apply() { # $1 = queue file, $2 = the command line
  local qf="$1" cmd="$2" verb rest sha arg line rep front=0
  verb="$(lq_cmd_verb "$cmd")"
  rest="${cmd#* }"; [ "$rest" = "$cmd" ] && rest=""
  if [ -z "$verb" ] || [ "$verb" = ADD ]; then
    if [ -z "$verb" ]; then lq_queue_append "$qf" "$cmd"; return 0; fi
    [ -n "$rest" ] || { lq_log "inbox: MALFORMED, skipped: [$cmd] — ADD with nothing to add"; return 1; }
    lq_queue_append "$qf" "$rest"; return 0
  fi
  sha="${rest%% *}"
  arg="${rest#* }"; [ "$arg" = "$rest" ] && arg=""
  [ -n "$sha" ] || { lq_log "inbox: MALFORMED, skipped: [$cmd] — $verb with no sha"; return 1; }
  line="$(lq_line_naming "$sha" "$qf" 2>/dev/null || true)"
  [ -n "$line" ] || { lq_log "inbox: MALFORMED, skipped: [$cmd] — no queue line names $sha"; return 1; }
  case "$verb" in
    PARK)       rep="#PARK-$(lq_slug "$arg") $line" ;;
    UNPARK)     rep="$(lq_line_unpark "$line")"
                [ -n "$rep" ] || { lq_log "inbox: MALFORMED, skipped: [$cmd] — un-parking leaves no line"; return 1; } ;;
    SUPERSEDE)  [ -n "$arg" ] || { lq_log "inbox: MALFORMED, skipped: [$cmd] — SUPERSEDE with no replacement line"; return 1; }
                rep="$arg" ;;
    RETAG)      local t bad=0
                for t in $arg; do case "$t" in '#'*) ;; *) bad=1 ;; esac; done
                [ "$bad" = 0 ] || { lq_log "inbox: MALFORMED, skipped: [$cmd] — a tag must begin with #"; return 1; }
                if [ -n "$arg" ]; then rep="$arg $(lq_line_payload "$line")"
                else rep="$(lq_line_payload "$line")"; fi ;;
    FRONT)      rep="$line"; front=1 ;;
  esac
  LQ_AWK_OLD="$line" LQ_AWK_NEW="$rep" LQ_AWK_FRONT="$front" \
  awk 'BEGIN { old = ENVIRON["LQ_AWK_OLD"]; new = ENVIRON["LQ_AWK_NEW"]; fr = ENVIRON["LQ_AWK_FRONT"]
               if (fr == "1") print new }
       { if (!done && $0 == old) { done = 1; if (fr != "1") print new; next }
         print }' "$qf" >"$qf.cmd.tmp" && mv "$qf.cmd.tmp" "$qf"
  lq_log "inbox: $verb $sha applied — $(printf '%.100s' "$rep")"
  return 0
}
# EVERY COMMAND IN THE FILE, IN THE ORDER IT WAS WRITTEN, UNDER THE QUEUE LOCK, at the loop top and
# BEFORE the stamp is taken: an append made from that moment on lands in the inbox rather than in
# the file the stamp describes, so the rewrite at the end of the loop still matches and the pop
# stands. Prints how many commands were applied; a malformed one is counted by nobody and stops
# nothing.
lq_inbox_fold() { # $1 = queue file (default $Q), $2 = inbox (default $INBOX); prints how many applied
  local qf="${1:-$Q}" ib="${2:-$INBOX}" n=0 cmd
  if [ -z "$ib" ] || [ ! -s "$ib" ]; then printf '0\n'; return 0; fi
  [ -f "$qf" ] || : >"$qf"
  while IFS= read -r cmd || [ -n "$cmd" ]; do
    lq_inbox_apply "$qf" "$cmd" && n=$((n + 1))
  done <"$ib"
  : >"$ib"
  printf '%s\n' "$n"
  return 0
}
lq_queue_rewrite() { # $1 = candidate file, $2 = stamp taken at the read
  # rc 0 = rewritten, 1 = nothing to write (identical), 2 = REFUSED, the file moved under us
  local now
  if cmp -s "$1" "$Q" 2>/dev/null; then rm -f "$1"; return 1; fi
  now="$(lq_qstamp)"
  if [ "$now" != "$2" ]; then
    printf 'queue: REFUSED to rewrite land-queue.txt — it changed under the runner since it was read (%s -> %s). The edit stands; this loop is dropped and the pop is taken again next loop.\n' "$2" "$now"
    rm -f "$1"; return 2
  fi
  mv "$1" "$Q"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE STAMP GUARD IS A TRIPWIRE NOW, NOT A TRAPDOOR (F3)
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# The refusal is RIGHT — an edit must never be silently overwritten — but its COST was wrong: the
# whole loop's pop was thrown away, so a queue of a hundred and twenty lines went nowhere for
# twenty minutes because somebody typed two lines. Measured 09-09..09-11: five refusals, five
# dropped pops. With landq-ctl there is no longer any reason to edit land-queue.txt by hand, so a
# direct edit is an ERROR and not a routine: it is LOGGED with the word DIRECT EDIT, it raises a
# page in the status file — and then the runner RE-READS the queue as it now stands and takes the
# popped lines out of THAT, so the edit stands and the pop stands too. Nothing is lost on either
# side, which is the whole rule.
PAGE="${LANDQ_PAGE:-$W/target/gate/landq4.page.txt}"
lq_page() { # $1 = kind, $2 = text
  mkdir -p "$(dirname "$PAGE")" 2>/dev/null || true
  printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$1" "$2" >>"$PAGE"
  lq_log "PAGE [$1]: $2"
}
lq_page_clear() { rm -f "$PAGE"; }
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE EXIT-CODE CONTRACT (F1) — WHAT THIS RUNNER'S EXIT STATUS MEANS TO THE SUPERVISOR
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# scripts/landq-supervisor.sh decides what to do next by reading nothing but the number this
# process exits with, so the number is a CONTRACT and not an accident. Four codes, and they are
# the only ways out of the loop:
#
#   0   the STOP marker was seen at the loop top (an integrator asked for a boundary), or
#       --preprove-once/--selftest finished. THE SUPERVISOR EXITS TOO: a stop is a stop.
#   1   HALT head-conflict-twice — the first queue line would not apply twice in a row. A FACT
#       ABOUT THE TREE: it needs re-picking by hand. The supervisor PAGES and waits.
#   2   another runner already holds the host lock. Not a fault and not a HALT: somebody else is
#       landing on this host. The supervisor exits without paging — restarting would only race.
#   3   HALT tree-moved — HEAD has not been the last landed tip (or the tree has been modified)
#       for LANDQ_TREE_MOVED_HALT_AFTER loops in a row. The other tree fact; pages and waits.
#
# ANY OTHER STATUS IS INFRASTRUCTURE — a crash, a kill, a signal, a driver that escaped its own
# taxonomy — and infrastructure is never a HALT (see THE FAULT TAXONOMY). The supervisor restarts
# on the 60/120/240/480/900 s ladder and counts it in the status file. No infrastructure failure
# inside the loop exits at all: it is classed, counted, backed off and retried.
LQ_EXIT_STOP=0; LQ_EXIT_HALT_HEAD=1; LQ_EXIT_LOCKED=2; LQ_EXIT_HALT_TREE_MOVED=3
export LQ_EXIT_STOP LQ_EXIT_HALT_HEAD LQ_EXIT_LOCKED LQ_EXIT_HALT_TREE_MOVED
# HOW MANY TREE-MOVED REFUSALS IN A ROW ARE A FACT ABOUT THE TREE rather than a stray process the
# census is about to kill. Four backoffs (1+2+4+8 min) pass before the fifth, so a tree that is
# still moved a quarter of an hour later is moved because somebody moved it.
LQ_TREE_MOVED_HALT_AFTER="${LANDQ_TREE_MOVED_HALT_AFTER:-5}"
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE BOUNDARY SIGNAL (F1) — THE ONE FILE THAT SAYS "A BATCH JUST ENDED, AT THIS TIP"
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# The supervisor adopts a new engine AT A BOUNDARY and never in the middle of a batch: a batch is
# an hour of a fleet box's time and killing it wastes exactly that. So the runner SIGNALS its
# boundaries — one line, `<epoch> <tip>`, rewritten temp+mv at the end of every batch and on the
# way out through the STOP marker — and the supervisor watches that file rather than the log.
# It is a signal and not a queue: only the newest boundary matters, and a reader that misses one
# reads the next.
BOUNDARY="${LANDQ_BOUNDARY:-$W/target/gate/landq.boundary}"
lq_boundary() { # $1 = the tip the tree is at now
  local tip="${1:-}"
  mkdir -p "$(dirname "$BOUNDARY")" 2>/dev/null || true
  printf '%s %s\n' "$(date +%s)" "$tip" >"$BOUNDARY.tmp" && mv "$BOUNDARY.tmp" "$BOUNDARY"
}
# THE POPPED LINES, OUT OF THE QUEUE AS IT NOW READS. The batch file carries the payload of every
# landing line it took, and the chain map carries the HELD line each chained payload was popped
# from; both forms are removed, and everything else in the file — including whatever was just
# edited into it — is kept exactly where it is. Prints how many lines were removed.
lq_queue_reconcile() { # $1 = batch file, $2 = queue file (default $Q)
  local bf="$1" qf="${2:-$Q}" before after
  [ -f "$bf" ] && [ -f "$qf" ] || { printf '0\n'; return 1; }
  before="$(grep -c '' "$qf" 2>/dev/null || true)"; case "$before" in ''|*[!0-9]*) before=0 ;; esac
  awk -F"$TAB" -v cf="$bf.chain" '
      BEGIN { while ((getline l < cf) > 0) { k = split(l, a, "\t"); if (k >= 2) { drop[a[1]] = 1; drop[a[2]] = 1 } } }
      FILENAME == ARGV[1] { if ($0 !~ /^[[:space:]]*(#|$)/) drop[$0] = 1; next }
      { if ($0 in drop && !($0 ~ /^[[:space:]]*$/)) { n++; next } print }
      END { }' "$bf" "$qf" >"$qf.rec.tmp" && mv "$qf.rec.tmp" "$qf"
  after="$(grep -c '' "$qf" 2>/dev/null || true)"; case "$after" in ''|*[!0-9]*) after=0 ;; esac
  printf '%s\n' "$((before - after))"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# A HOLD THAT NAMES A SHA RELEASES ITSELF
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# A line held behind another line is tagged `#HOLD-after-<thing>` and is a comment until somebody
# edits the file. When <thing> is a WORD — `#HOLD-after-strike`, `#HOLD-after-K3-and-A1` — only the
# integrator knows what it means and only the integrator can un-hold it. When <thing> is a SHA, the
# tree itself knows: the hold is over the moment that commit is an ancestor of HEAD, and an engine
# that can read `git merge-base --is-ancestor` should not be making its integrator get up to type
# two characters. So at pop time, and only there, every `#HOLD-after-<7-40 hex>` on the queue is
# tested against the tree; the ones that landed lose their tag, in place, with a log line.
#
# THE TAG IS DROPPED, NOT THE PREFIX. A line may carry several — `#HOLD-after-<sha> #K5-L3 --prove
# …` — and dropping the one that is satisfied leaves the others holding it: the line goes live only
# when nothing is left in front of the `--`. A tag that is not a sha, and a sha the tree has never
# heard of (merge-base fails), are both left exactly as they were found.
# WHAT "LANDED" MEANS ON A TREE THAT LANDS BY CHERRY-PICK. `merge-base --is-ancestor <sha> HEAD`
# is the obvious question and it is almost always the WRONG one here: land.sh lands with
# `cherry-pick -x`, so every landed commit is a NEW sha and the sha the queue names is an ancestor
# of nothing. Audit 15 measured it — 30 of 30 commits on the tip carry `(cherry picked from commit
# <40-hex>)` and 0 of the batch's picks are ancestors of HEAD — which means the first form of this
# rule could never have released a single line.
#
# So EITHER answer lands it: the sha is an ancestor (it was merged, or the tree is the one it was
# written on), OR some commit since the last landed tip carries its cherry-pick trailer. The queue
# writes short shas and the trailer is 40 hex, so the trailer is matched by prefix.
lq_landed_range() { # $1 = tree; prints the rev range to search for cherry-pick trailers
  local tipf="${LANDQ_TIPFILE:-$1/target/gate/landq4.tip}" t
  t="$(tr -d '[:space:]' <"$tipf" 2>/dev/null || true)"
  if [ -n "$t" ] && git -C "$1" rev-parse -q --verify "$t^{commit}" >/dev/null 2>&1 \
     && [ "$(git -C "$1" rev-parse "$t")" != "$(git -C "$1" rev-parse HEAD)" ]; then
    printf '%s..HEAD\n' "$t"; return 0
  fi
  # No usable last-tip — and the usual case is that it IS HEAD, because it is written after every
  # batch. Then the range is the whole of this branch since the integration base, and failing that
  # (a scratch repo, a detached tree) the whole log.
  if git -C "$1" rev-parse -q --verify "origin/$BR^{commit}" >/dev/null 2>&1; then
    printf 'origin/%s..HEAD\n' "$BR"
  else printf 'HEAD\n'; fi
}
lq_landed_here() { # $1 = tree, $2 = sha; 0 when that commit is on this tree, as itself or as a pick
  git -C "$1" merge-base --is-ancestor "$2" HEAD 2>/dev/null && return 0
  # NOT A PIPELINE. `git log … | grep -q` hands git a SIGPIPE the moment grep has its answer, and
  # under `set -o pipefail` the whole thing then reports 141 — a "yes" that reads as an error.
  local body
  body="$(git -C "$1" log --format=%b $(lq_landed_range "$1") 2>/dev/null || true)"
  grep -qE "cherry picked from commit $2[0-9a-f]*\)" <<<"$body"
}
lq_release_holds() { # $1 = tree; rewrites $Q in place, printing one line per release
  local line rest tok out sha tmp released=0 stamp log=""
  [ -f "$Q" ] || return 0
  stamp="$(lq_qstamp)"           # the same read→rewrite window the popper has, and the same guard
  tmp="$Q.release.$$"; : >"$tmp"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      '#'*) case "$line" in *'#HOLD-after-'*) ;; *) printf '%s\n' "$line" >>"$tmp"; continue ;; esac ;;
      *) printf '%s\n' "$line" >>"$tmp"; continue ;;
    esac
    out=""; rest="$line"
    while : ; do
      case "$rest" in '#'*) ;; *) break ;; esac
      tok="${rest%% *}"
      case "$rest" in *' '*) rest="${rest#* }" ;; *) rest="" ;; esac
      sha=""
      case "$tok" in '#HOLD-after-'*) sha="${tok#\#HOLD-after-}" ;; esac
      if [ -n "$sha" ] && printf '%s' "$sha" | grep -qxE '[0-9a-f]{7,40}' \
         && lq_landed_here "$1" "$sha"; then
        log="$log""released $tok: landed
"; released=$((released + 1))
      else
        out="$out$tok "
      fi
    done
    printf '%s%s\n' "$out" "$rest" >>"$tmp"
  done <"$Q"
  # THE RELEASES ARE ANNOUNCED ONLY IF THEY HAPPENED. Held back until the rewrite is taken, so a
  # refusal (the file moved under us) never leaves "released …" in the log for a queue that still
  # holds the line.
  if [ "$released" -gt 0 ]; then
    if lq_queue_rewrite "$tmp" "$stamp"; then printf '%s' "$log"; fi
  else rm -f "$tmp"; fi
  return 0
}
lq_live_lines() { grep -cE '^--' "$1" 2>/dev/null || true; }
lq_head_line()  { grep -E '^--' "$1" 2>/dev/null | head -n1; }
lq_line_is_base_fix() { # $1 = queue line, $2 = repo; 0 when every file the line touches is qa/*.toml
  local files f
  files="$(lq_line_files "$1" "$2")"
  case "$files" in ''|'?') return 1 ;; esac
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in qa/*.toml) ;; *) return 1 ;; esac
  done <<EOF
$files
EOF
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# CHAINED PRE-PROOFS — the arithmetic that made 121 of 123 queue lines invisible to the fleet
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# MEASURED, 09-10: 123 queue lines, of which 2 are live and 121 are `#HOLD-after-<sha>` behind a line
# that has not landed. The sweep pre-proves LIVE lines only, and the popper takes only lines
# pre-proven at the exact tip — so every batch carries one or two lines, and each landing releases
# ONE link of a chain fourteen deep at roughly three hours a cycle. The fleet is idle and the queue
# is a linked list being walked one node per cycle.
#
# THE HOLD IS NOT A REASON NOT TO PROVE IT. `#HOLD-after-<sha>` says "this line's picks need <sha>'s
# picks beneath them" — and <sha> is a pick of a line that is IN THE QUEUE. So the tree that line
# will be judged on is knowable NOW: it is the tip, plus the predecessor line's picks, plus its own,
# applied by the same `cherry-pick -x` path land.sh lands by. A box can prove exactly that tree
# today. That is a CHAINED PRE-PROOF, and its verdict is evidence about one tree and no other:
#
#   * THE KEY IS (tip, the predecessor picks, the line itself). The ledger row's tip column carries
#     `<tip>@<pred hash>+<pred hash>…` instead of a bare tip; a green is consulted only when the tip
#     is unchanged AND the predecessor chain is the same picks in the same order. A tip move drops
#     it exactly as it drops every other row (the prune matches the `<tip>@` prefix too), and a
#     predecessor that is re-picked changes the key, so its dependent's green is simply never found.
#   * THE ROOT IS A LIVE LINE. A chain is walked backwards from the held line to the first line that
#     is live; a `#HOLD-<word>` tag (S2's `#HOLD-dialect-kind-mint`, R6's, F1's multi-dependency
#     tags) is NOT a sha and is never chained — it names a thing this engine cannot resolve to picks.
#   * DEPTH IS BOUNDED (`LAND_CHAIN_DEPTH`, default 4, counting the live root). Depth is what stops
#     a fourteen-deep chain being proven as a fourteen-line union nobody would land in one batch,
#     and what stops a `#HOLD-after-<sha>` cycle walking forever.
#   * A BASE FIX IS NEVER IN A CHAIN (rule 2g). It re-pins what every other line is judged against
#     and pops alone; a chain that contains one is refused outright, at both ends.
#   * NOTHING IS UN-HELD BY THIS. The tag stays on the line (rule (c) strikes it when the sha
#     lands); admission into a batch is a POP-TIME decision, taken beside the predecessor, and a
#     dependent whose predecessor does not go into this batch stays exactly where it is.
LAND_CHAIN_DEPTH="${LAND_CHAIN_DEPTH:-4}"
case "$LAND_CHAIN_DEPTH" in ''|*[!0-9]*) LAND_CHAIN_DEPTH=4 ;; esac

# THE LANDING LINE BEHIND THE TAGS. Every leading `#…` token is stripped; what is left is what
# land.sh would be handed, and it is what a batch file and a ledger row carry.
lq_line_payload() { # $1 = queue line
  local rest="$1"
  while : ; do
    case "$rest" in '#'*) ;; *) break ;; esac
    case "$rest" in *' '*) rest="${rest#* }" ;; *) rest="" ;; esac
  done
  printf '%s\n' "$rest"
}
# THE ONE SHA A HELD LINE WAITS FOR — and nothing else. The line must carry EXACTLY ONE `#HOLD-`
# tag (a line waiting on two things, such as `#HOLD-after-K3-and-A1`, names no single predecessor
# and is the integrator's to un-hold), that tag must be `#HOLD-after-`, and its remainder must be a
# sha and not a word (rule (6)). Anything else prints nothing, which is "not chainable".
#
# A TAG THAT IS NOT A HOLD IS A LABEL, AND A LABEL IS NOT A DEPENDENCY. 36 of the queue's held
# lines are written `#HOLD-after-f7a44be23 #T0-B2-seam --prove …`: the second token names the SLOT
# the line came from, and refusing to chain over it would have left the largest group in the queue
# out of the change for no reason at all. Only `#HOLD-` tags are counted; the rest are skipped, and
# the payload is what is left after every leading `#` token.
lq_hold_after_sha() { # $1 = queue line
  local rest="$1" tok sha="" holds=0
  while : ; do
    case "$rest" in '#'*) ;; *) break ;; esac
    tok="${rest%% *}"
    case "$rest" in *' '*) rest="${rest#* }" ;; *) rest="" ;; esac
    case "$tok" in
      '#HOLD-after-'*) holds=$((holds + 1)); sha="${tok#\#HOLD-after-}" ;;
      '#HOLD'*)        holds=$((holds + 1)); sha="" ;;
    esac
  done
  [ "$holds" = 1 ] && [ -n "$sha" ] || return 0
  printf '%s' "$sha" | grep -qxE '[0-9a-f]{7,40}' || return 0
  case "$rest" in '--'*) ;; *) return 0 ;; esac
  printf '%s\n' "$sha"
}
# THE QUEUE LINE WHOSE PICKS INCLUDE THAT SHA. The queue writes short shas and a tag may be shorter
# or longer than the pick it names, so the match is a prefix in either direction.
lq_line_naming() { # $1 = sha, $2 = queue file; prints the FIRST queue line whose payload names it
  local sha="$1" qf="$2" line pay h
  [ -n "$sha" ] && [ -f "$qf" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '') continue ;; '# '*) continue ;; '#'*) ;; '--'*) ;; *) continue ;; esac
    pay="$(lq_line_payload "$line")"
    case "$pay" in '--'*) ;; *) continue ;; esac
    for h in $(lq_line_hashes "$pay"); do
      case "$h" in "$sha"*) printf '%s\n' "$line"; return 0 ;; esac
      case "$sha" in "$h"*) printf '%s\n' "$line"; return 0 ;; esac
    done
  done <"$qf"
  return 1
}
# THE CHAIN A HELD LINE STANDS ON: the payloads, ROOT FIRST, ending with the line itself. Prints
# nothing and fails when the line is not chainable — no sha tag, a word tag, a predecessor that is
# not in the queue, a pick that does not resolve, a base fix anywhere in it, or a chain longer than
# the depth (which also bounds a `#HOLD-after-` cycle).
lq_chain_of() { # $1 = held queue line, $2 = queue file, $3 = repo (default $W), $4 = depth
  local line="$1" qf="$2" repo="${3:-$W}" depth="${4:-$LAND_CHAIN_DEPTH}"
  local cur="$line" chain="" sha pred p n=0
  case "$line" in '#'*) ;; *) return 1 ;; esac
  case "$depth" in ''|*[!0-9]*) depth=4 ;; esac
  while : ; do
    n=$((n + 1)); [ "$n" -le "$depth" ] || return 1
    p="$(lq_line_payload "$cur")"
    case "$p" in '--'*) ;; *) return 1 ;; esac
    case "$(lq_line_files "$p" "$repo")" in '?'|'') return 1 ;; esac
    lq_line_is_base_fix "$p" "$repo" && return 1
    chain="$p
$chain"
    case "$cur" in '--'*) break ;; esac
    sha="$(lq_hold_after_sha "$cur")"
    [ -n "$sha" ] || return 1
    pred="$(lq_line_naming "$sha" "$qf")" || return 1
    [ -n "$pred" ] && [ "$pred" != "$cur" ] || return 1
    cur="$pred"
  done
  printf '%s' "$chain"
}
# THE LEDGER KEY FOR A CHAINED VERDICT: the tip, then the picks that must be beneath the line, in
# order. The ancestor payloads come in on stdin. A bare tip (no ancestors) is never written by this
# path — an unchained row keys by the tip alone, and the two can never collide.
lq_chain_key() { # $1 = tip; ancestor payload lines on stdin
  local tip="$1" line h k=""
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    for h in $(lq_line_hashes "$line"); do k="$k$h+"; done
  done
  printf '%s@%s\n' "$tip" "${k%+}"
}

lq_pop_head_alone() { # $1 = batch file out, $2 = keep file out; the head live line alone, all else kept in order; prints the count
  local line first=1
  : >"$1"; : >"$2"; : >"$1.chain"    # no chain rides a base fix; and no stale map is left behind
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in --*) if [ "$first" = 1 ]; then printf '%s\n' "$line" >>"$1"; first=0; continue; fi ;; esac
    printf '%s\n' "$line" >>"$2"
  done <"$Q"
  echo $((1 - first))
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# WHICH ORACLE ROWS ARE RED AT THE TIP — SO A LINE IS NEVER RED FOR THE BASE'S REDS (rule 2c, for
# the oracle the way lq_base_state_red already does it for the construction gate's ceilings)
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# Measured 2026-09-10: line 12 (a base probe) and line 8 of the sweep were parked RED on
# `boot.refusal|BOOT-P29|validate`, `boot.refusal|BOOT-P30|validate` and
# `neutrality|routes|admin-openapi-paths` — rows that are RED AT THE BASE, on the tip, with no picks
# on the tree at all. The engine wrote RED, not NONE:base, because its base-state predicate only
# knows the construction gate's own words for a figure that rose ("at the base", "ROSE since the
# base"); a shadow-oracle row says no such thing, it just FAILs. So the engine keeps the SET.
#
# A LINE'S OWN RED IS A ROW THAT WAS PASS AT THE BASE. That is the whole rule, and it is why the
# set has to be MEASURED rather than declared: a standing list would have to be edited by hand
# every time the tip moved, and the rows that go red at a tip are exactly the rows the queue is
# there to repair.
#
# TWO WAYS A TIP GETS MEASURED, and neither is a guess:
#   * THE LAST LANDED PROOF. A batch that landed green at a new tip proved the oracle families it
#     names ON THAT TIP; its own log is the measurement, read as the tree moves.
#   * A BASE-ONLY REPLAY (lq_base_red_replay), when the tip moved and no such proof exists: one box
#     is handed a batch line with NO HASHES — `--prove --families <the sweep's union>` — which is
#     the tip itself, proven. It takes a box only after every line in the sweep has one.
# Until a tip is measured, NOTHING is laundered: an unmeasured tip scores an oracle red RED.
# A FAIL ROW IS NOT JUST A ROW NAME. The report writes `<cell id>  FAIL  <class list>  <first
# divergence>` (xtask/src/ledger.rs, Row::tsv), and the last two columns are the whole of WHY the
# row is red: which classes diverged, and the first one spelled out. The base-red set is keyed on
# all three, because a row that is red at the base for reason A and red under a line for reason B
# is the LINE'S red — see lq_line_red_is_base_oracle.
lq_oracle_fail_detail() { # $1 = a proof log; prints `<id>TAB<classes>TAB<detail>` per FAIL row, deduped by id
  [ -n "${1:-}" ] && [ -f "$1" ] || return 0
  sed -n "s/^\( *| \)\{0,1\}\([^$TAB]*\)${TAB}FAIL${TAB}\(.*\)/\2${TAB}\3/p" "$1" \
    | awk -F"$TAB" '!seen[$1]++'
}
lq_oracle_fail_rows() { # $1 = a proof log; prints the cell ids of its FAIL rows, in order, deduped
  lq_oracle_fail_detail "${1:-}" | cut -f1
}
# THE ORACLE LEG REPORTED — green or red. A proof that died before it (a failed build, a lost box)
# measures nothing, and recording "measured, no red rows" from it would launder every base red at
# that tip. This is the precondition on every learn.
lq_oracle_leg_ran() { # $1 = log
  [ -n "${1:-}" ] && [ -f "$1" ] || return 1
  grep -qE 'land[.]sh: (oracle green on:|RED — oracle (families|shard))' "$1" 2>/dev/null
}
lq_base_red_known() { # $1 = tip; 0 when this tip has been measured
  [ -s "$BASERED" ] || return 1
  awk -F"$TAB" -v tp="$1" '$1 == tp && $2 == "#measured" { f = 1 } END { exit !f }' "$BASERED"
}
lq_base_red_rows() { # $1 = tip; prints the cell ids red at it
  [ -s "$BASERED" ] || return 0
  awk -F"$TAB" -v tp="$1" '$1 == tp && $2 != "#measured" { print $2 }' "$BASERED"
}
# WHAT THAT ROW'S RED WAS, as the report said it: `<class list>TAB<first divergence>`. Nothing at
# all for a row a set written before this existed recorded without one — which is not "the same
# detail" but NO measurement, and is scored as the line's own red rather than laundered.
lq_base_red_detail() { # $1 = tip, $2 = cell id
  [ -s "$BASERED" ] || return 0
  awk -F"$TAB" -v tp="$1" -v r="$2" '$1 == tp && $2 == r { if (NF >= 4) printf "%s\t%s\n", $3, $4; else if (NF == 3) printf "%s\t\n", $3; exit }' "$BASERED"
}
lq_base_red_learn() { # $1 = tip, $2 = the log of a proof taken AT that tip
  local tip="$1" log="$2" r
  [ -n "$tip" ] || return 1
  lq_oracle_leg_ran "$log" || return 1
  lq_base_red_known "$tip" && return 0
  mkdir -p "$(dirname "$BASERED")"
  printf '%s%s#measured\n' "$tip" "$TAB" >>"$BASERED"
  # `$r` is already the row's three columns — id, classes, first divergence — so the set is keyed
  # on the RED, not on the row name.
  while IFS= read -r r; do [ -n "$r" ] && printf '%s%s%s\n' "$tip" "$TAB" "$r" >>"$BASERED"; done <<EOF
$(lq_oracle_fail_detail "$log")
EOF
  lq_log "base state: $(printf '%.9s' "$tip") measured — $(lq_base_red_rows "$tip" | grep -c . || true) oracle row(s) red at the tip itself"
}
# WHAT THE MEASUREMENT WAS, WRITTEN DOWN BESIDE THE LOG IT CAME FROM. A tip is measured one of two
# ways — the last wholly-green landed batch, or the base-only replay below — and the comparison is
# only as good as what those two record. Both write the SAME result: one line per red row at the
# tip, `<cell id>TAB<class list>TAB<first divergence>`, which is exactly the three columns
# lq_line_red_is_base_oracle compares a line's reds against. It is also the answer to the first
# question an operator asks about a NONE:base ("what was the base's red on that row?") without
# opening a proof log on a fleet box's copy-back.
lq_base_red_result() { # $1 = tip, $2 = the log that measured it, $3 = where the result goes
  local tip="${1:-}" log="${2:-}" out="${3:-}" r
  [ -n "$tip" ] && [ -n "$out" ] || return 1
  mkdir -p "$(dirname "$out")" 2>/dev/null || true
  lq_oracle_fail_detail "$log" >"$out" || { : >"$out"; return 1; }
  lq_log "base state: $(printf '%.9s' "$tip") measured — $(grep -c . "$out" || true) red row(s) at the tip itself, with the divergence each carries (result: $out)"
  while IFS= read -r r || [ -n "$r" ]; do
    [ -n "$r" ] || continue
    lq_log "base state:   $(printf '%s' "$r" | tr "$TAB" ' ')"
  done <"$out"
  return 0
}
lq_base_red_prune() { # $1 = the tip to keep; every other tip's rows go
  [ -s "$BASERED" ] || return 0
  awk -F"$TAB" -v tp="$1" '$1 == tp' "$BASERED" >"$BASERED.tmp" && mv -f "$BASERED.tmp" "$BASERED"
}
# THE LINE'S RED IS THE BASE'S when the tip is measured, the log's reds are the ORACLE's alone, it
# has at least one failing row, and EVERY failing row was already red at the tip WITH THE SAME
# DIVERGENCE. One row that was PASS at the base is the line's own red; so is one that was red at
# the base for a different reason.
#
# WHY THE DETAIL AND NOT THE ROW NAME (pass-22 RED-24). Keyed on row identity alone, a line that
# broke an already-base-red row FURTHER had its only red row in the set and was recorded
# NONE:base — no colour, no park, still live. The rows in that set are exactly the rows the queue
# exists to REPAIR, with a repair line already queued against them, so the second breakage stayed
# invisible until the repairing line made the row green and found a fault it did not cause. That is
# the expensive way to learn it. The report has carried the answer all along: the FAIL row's class
# list and its first divergence.
lq_line_red_is_base_oracle() { # $1 = tip, $2 = log
  local tip="${1:-}" log="${2:-}" row r d bd n=0
  [ -n "$tip" ] && [ -n "$log" ] && [ -f "$log" ] || return 1
  lq_base_red_known "$tip" || return 1
  # Every red this proof declared must be an oracle red: a test, a clippy or a gate red at the same
  # time is the line's, whatever the oracle rows say.
  grep -E 'land[.]sh: RED — ' "$log" 2>/dev/null | grep -qvE 'land[.]sh: RED — oracle' && return 1
  while IFS= read -r row; do
    [ -n "$row" ] || continue
    n=$((n + 1))
    r="${row%%$TAB*}"; d="${row#*$TAB}"
    lq_base_red_rows "$tip" | grep -qxF -- "$r" || return 1
    bd="$(lq_base_red_detail "$tip" "$r")"
    if [ "$d" != "$bd" ]; then
      # BOTH DETAILS GO IN THE LOG, because the next question anybody asks is "different how".
      lq_log "base state: $r is red at the tip and red here, but NOT the same divergence — this is the line's OWN red"
      lq_log "base state:   base: $(printf '%s' "$bd" | tr "$TAB" ' ')"
      lq_log "base state:   line: $(printf '%s' "$d" | tr "$TAB" ' ')"
      return 1
    fi
  done <<EOF
$(lq_oracle_fail_detail "$log")
EOF
  [ "$n" -gt 0 ]
}
# The families a sweep's lines ask the oracle for — the set a base replay has to measure, and no
# more: a replay of every family would cost the box a full recording to answer a question nobody
# in this sweep asked.
# AN ORACLE RED AT A TIP NOBODY MEASURED IS NOT EVIDENCE ABOUT THE LINE. lq_line_red_is_base_oracle
# can only say "these rows are the base's" when the base HAS been measured; at an unmeasured tip it
# says nothing and the red used to fall straight through to a #RED park — a line parked for three
# hours with no evidence about itself, which is exactly what the owner rule forbids. MEASURED 09-11:
# the sweep took every box, the base replay got none, and a line parked #RED on rows nobody had
# measured at the tip. So: an oracle red at an unmeasured tip is NONE:base-unmeasured, the line goes
# back live and to the FRONT of the next sweep, and the tip is measured before it is judged again.
lq_red_is_unmeasured_oracle() { # $1 = tip, $2 = log; 0 when the red is the ORACLE's at a tip nobody measured
  local tip="${1:-}" lg="${2:-}"
  [ -n "$lg" ] && [ -f "$lg" ] || return 1
  lq_oracle_leg_ran "$lg" || return 1
  [ -n "$(lq_oracle_fail_rows "$lg")" ] || return 1
  lq_base_red_known "$tip" && return 1
  return 0
}
lq_line_families() { # $1 = queue line; prints its --families value, unquoted
  local l="${1:-}" v
  v="$(printf '%s' "$l" | sed -n "s/.*--families[[:space:]]*'\([^']*\)'.*/\1/p" | head -1)"
  [ -n "$v" ] || v="$(printf '%s' "$l" | sed -n 's/.*--families[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$v" ] || v="$(printf '%s\n' "$l" | awk '{for (i = 1; i <= NF; i++) if ($i == "--families") { print $(i + 1); exit }}')"
  printf '%s\n' "$v"
}
# ONE BOX, NO PICKS, THE TIP ITSELF. The batch line carries `--prove` and `--families` and NO
# HASHES, which land.sh accepts (a line with no hashes AND no --prove is the one it refuses) and
# which proves exactly the tree the sweep's lines are being judged against. It takes its box AFTER
# every line in the sweep has one, so measuring the base never costs a line its proof.
# THE BASE REPLAY'S BOX IS RESERVED BEFORE THE LINES ARE DISPATCHED, NOT PICKED UP AFTER THEM.
# MEASURED 09-11: "base state: no free box for the base replay at <tip> — the tip stays unmeasured,
# and an oracle red stays RED". The sweep had taken every box, so the batch's oracle red could not
# be judged against the base and a line was parked #RED with NO EVIDENCE about itself. The replay is
# not a luxury the sweep spends its leftovers on — it is what makes every other verdict in the sweep
# readable — so it takes its slot first, and the lines share what is left.
lq_base_replay_reserve() { # $1 = tip key, $2 = the sweep's lines; prints the reserved host, or nothing
  local key="$1" fams
  [ "${LANDQ_BASE_REPLAY:-1}" = 1 ] || return 1
  lq_base_red_known "$key" && return 1
  fams="$(printf '%s\n' "$2" | lq_families_union)"
  [ -n "$fams" ] || return 1
  local h; h="$( fleet_pick_host )" || h=""
  [ -n "$h" ] || return 1
  printf '%s\n' "$h"
}
lq_base_red_replay() { # $1 = tree, $2 = the sweep's directory, $3 = tip key, $4 = the sweep's lines, $5 = the RESERVED host
  local tree="$1" dir="$2" key="$3" h="$5" fams
  fams="$(printf '%s\n' "$4" | lq_families_union)"
  [ -n "$fams" ] || { lq_log "base state: no line in this sweep asks the oracle for a family; there is nothing to measure at $(printf '%.9s' "$key")"; return 1; }
  [ -n "$h" ] || { lq_log "base state: no box was reserved for the base replay at $(printf '%.9s' "$key") — the tip stays unmeasured, and an oracle red is NONE:base-unmeasured, never a park"; return 1; }
  printf -- '--prove --families %s\n' "'"'"'$fams'"'"'" >"$dir/base.batch"
  lq_log "base state: measuring the tip itself on $h — a batch with NO picks, families $fams"
  (
    lq_dispatch_preprove "$tree" "$h" "$dir/base.batch" \
      >"$dir/base.log" 2>&1
    echo $? >"$dir/base.rc"
  ) &
  return 0
}
lq_families_union() { # lines on stdin; prints their families joined by |, deduped, or nothing
  local l f out=""
  while IFS= read -r l || [ -n "$l" ]; do
    [ -n "$l" ] || continue
    f="$(lq_line_families "$l")"; [ -n "$f" ] || continue
    case "|$out|" in *"|$f|"*) continue ;; esac
    out="${out:+$out|}$f"
  done
  printf '%s\n' "$out"
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE FRONT OF THE PRE-PROOF LIST: the lines the FLEET failed, not the lines that failed
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# The sweep hands boxes to the first N disjoint live lines in queue order. A line whose box was
# reclaimed by AWS mid-proof is live and unproven exactly as it was before — and it is at whatever
# depth in the queue it always was, so on a queue of 120 lines the next sweep is overwhelmingly
# likely to hand its box to somebody else and the three hours are simply lost. These two functions
# are the whole of the re-queue: a name is remembered, and the next sweep reads a queue with those
# names moved to the top. NOTHING ELSE CHANGES — the disjointness rule, the claim check, the chain
# preference and the ceiling all run over the reordered queue exactly as they ran over the queue.
#
# A LINE ON THIS LIST THAT IS NO LONGER LIVE IS NOT OFFERED. The list is matched against the queue
# by whole-line equality every time it is read, so a line that landed, was parked or was edited
# simply falls out of it; the file is never a second queue.
lq_front_add() { # $1 = the queue line the fleet owes an answer to
  [ -n "${1:-}" ] || return 0
  mkdir -p "$(dirname "$FRONT")"
  grep -qxF -- "$1" "$FRONT" 2>/dev/null || printf '%s\n' "$1" >>"$FRONT"
}
lq_front_drop() { # $1 = a line that has now had a real verdict
  [ -n "${1:-}" ] && [ -s "$FRONT" ] || return 0
  grep -vxF -- "$1" "$FRONT" >"$FRONT.tmp" 2>/dev/null || : >"$FRONT.tmp"
  mv -f "$FRONT.tmp" "$FRONT"
}
lq_front_queue() { # $1 = queue file; prints that queue with the owed lines first
  local qf="$1" l
  [ -s "${FRONT:-}" ] || { cat "$qf"; return 0; }
  while IFS= read -r l || [ -n "$l" ]; do
    [ -n "$l" ] || continue
    grep -qxF -- "$l" "$qf" 2>/dev/null && printf '%s\n' "$l"
  done <"$FRONT"
  grep -vxF -f "$FRONT" -- "$qf" || true
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# WHAT A PRE-PROOF'S EXIT MEANS. GREEN and RED are the colours the ledger records. Two reds are NOT
# a verdict on the line and are recorded as nothing (NONE — "not pre-proven"), so the popper neither
# parks nor prefers them: a red whose log names the BASE ("at the base", "ROSE since the base") is
# `ceiling-rose` judging against a base the head line is about to repair; a red the tree-moved
# guard raised is a race with the tip, and the line is simply queued again.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# BASE-STATE: A RED THAT IS THE BASE'S, NOT THE LINE'S (rule 2c). The log must SAY the figures it
# refused are the base's — "at the base", "ROSE since the base", or the construction gate's own
# words for rows that are red without being on the standing list.
#
# ONE PREDICATE, AND BOTH READERS USE IT (audit 17). There were two: the popper called
# lq_base_state_red, which ALSO demanded the tip carry raise headers (`[gate.ceiling_raises.…]` in
# qa/), and the sweep's lq_preproof_verdict matched the bare phrase. On the current tip the strike
# removed every raise, so the precondition is false tree-wide — and the two readers of the same log
# disagree by construction: the sweep records NONE and the line stays live, then the batch proves,
# reds identically, and the POPPER parks it as #RED. A line cannot be both. The raises precondition
# is the half that goes: it was there to stop the phrase laundering any red, but the phrase is
# already land.sh's own words about the base's figures, and a tip with no raises pending is exactly
# the tip on which a base-state red is most real — nothing in the queue is going to repair it.
LQ_BASE_STATE_RE='at the base|ROSE since the base|construction gate rows red that the standing list does not name'
lq_tip_has_raises() { # $1 = tree; 0 when the tip carries ceiling-raise headers (reported, never gating)
  grep -rqE '^\[gate\.ceiling_raises\.' "$1"/qa 2>/dev/null
}
lq_base_state_red() { # $1 = log path, $2 = tree (unused, kept for the callers); 0 when this RED is the base's
  [ -n "${1:-}" ] && [ -f "$1" ] || return 1
  grep -qiE "$LQ_BASE_STATE_RE" "$1" 2>/dev/null
}
# THE BOX'S OWN PER-LINE OUTCOME OUTRANKS THE TRANSPORT'S EXIT STATUS. land.sh writes one row per
# line — `GREEN<TAB><the line>` or `RED<TAB><the line>` — and land-remote.sh copies that file back
# beside the line's log as `line-N.batch.result`. It is the proof's verdict; rc is the TRANSPORT's,
# and the transport has its own ways to fail after the proof is over. Measured (sweep at 76f1887af,
# line 3): 7950 s, `GREEN --prove --tests xtask 6d5bba552 4b6e3e40c 8d48b75ab` in the outcome file,
# and rc 2 from a landed-ref that the fleet's own bare-repo refresh had pruned out from under the
# fetch — a log naming no tree-moved guard, so this function scored RED and parked a valid green.
# It never happens again in either direction: an outcome file that is not wholly GREEN cannot make
# a red green, and an absent one leaves the rc rules exactly as they were.
lq_outcome_green() { # $1 = per-line outcome file; 0 when it exists, has rows, and EVERY row is GREEN
  local f="${1:-}" rows bad
  [ -n "$f" ] && [ -s "$f" ] || return 1
  rows="$(grep -cE '^GREEN[[:space:]]' "$f" 2>/dev/null || true)"
  [ "${rows:-0}" -ge 1 ] || return 1
  bad="$(grep -vE '^[[:space:]]*$' "$f" 2>/dev/null | grep -cvE '^GREEN[[:space:]]' || true)"
  [ "${bad:-1}" = 0 ]
}

# THE BOX WENT AWAY. Measured 2026-09-10: two of twelve pre-proofs ended `exit 2` "unreachable for
# 10 polls — no verdict" / "scp: Connection closed" after 1735 s and 10116 s, because the spot
# instances under them were reclaimed by AWS mid-proof ("Service initiated"). Nothing about the
# LINE was learned, so RED is a lie about it and a park is three hours thrown after three hours.
# Two signals, either of which is enough: the transport's own exit status (land-remote.sh exits 75,
# EX_TEMPFAIL, when the box it was polling stopped answering) and its own sentence in the log, for
# a log copied back by an older transport.
LQ_BOX_GONE_RE='unreachable for [0-9]+ polls — no verdict|the box vanished mid-proof'
# THE HARNESS GAVE UP, AND THE LINE IS AS UNPROVEN AS IT WAS. T0-D10's contract: a driver that
# cannot do its job marks the capture `effects.harness_error`/`effects.error`, prints
# `harness give-up: <why>` and exits 70; the recorder refuses the cell and the recording goes RED
# about a busy port or a mock that never came up on THAT BOX. Measured 2026-09-10: three of twelve
# pre-proofs were parked RED on `documented|changelog|admin-restart` with `/put_settings_body … ->
# ""` — the driver's second boot did not come up inside ORACLE_BOOT_BOUND_SECS on a loaded box —
# while a base-only proof had that row byte-identical at the same tip.
#
# THE SENTENCE IS land.sh's, NOT THE DRIVER'S, AND THAT IS THE WHOLE PRECISION OF IT. land.sh reads
# the evidence out of the RECORDING (land_oracle_harness_evidence) and says it in one line. Matching
# the driver's own words instead would score every landing that TOUCHES a driver NONE:harness: the
# gate-files leg runs those drivers' --selftests on the box, and one of them plants a busy port on
# purpose and prints `harness give-up:` as a passing row.
LQ_HARNESS_RE='land[.]sh: RED — oracle: (a HARNESS failure, not a divergence|the driver exited 70)'
lq_harness_gave_up() { # $1 = log; 0 when the oracle leg's red was the harness's, not the picks'
  [ -n "${1:-}" ] && [ -f "$1" ] || return 1
  grep -qE "$LQ_HARNESS_RE" "$1" 2>/dev/null
}
lq_box_gone() { # $1 = rc, $2 = log; 0 when the BOX went away rather than the proof failing
  [ "${1:-}" = 75 ] && return 0
  [ -n "${2:-}" ] && [ -f "$2" ] || return 1
  grep -qE "$LQ_BOX_GONE_RE" "$2" 2>/dev/null
}

# ── AN EXIT CODE THAT CANNOT BE A VERDICT ───────────────────────────────────────────────────────
# MEASURED, LIVE (2026-09-11 18:09): the sweep's dispatcher could not find the script it was told to
# run, the shell exited 127, and every line in that sweep was recorded `RED <tip>@…` in preproved.txt
# and parked `#RED-preproof`. Nothing had been built, nothing had been picked, nothing had been
# judged — the engine parked real work over its own missing file.
#
# THE ENGINE'S PROVERS SAY 0, 1 OR 2. These three say something else entirely, and none of them can
# be reached BY a proof:
#   126  the file is there and the shell cannot execute it
#   127  the shell could not find it at all — an unlanded transport, a bad LAND_SH_SRC
#    70  EX_SOFTWARE, the code a driver uses when it gives up (already matched in the log by
#        lq_harness_gave_up, and now also when the log never got far enough to say it)
# 75 is deliberately NOT on this list: lq_box_gone already reads it, it is already a NONE, and it is
# already never a park — moving it would relabel every reclaimed box in the ledger.
lq_rc_is_harness() { # $1 = rc; 0 when the code is the harness's, never a tree's
  case "${1:-}" in 126|127|70) return 0 ;; esac
  return 1
}

lq_preproof_verdict() { # $1 = rc ('' = never reported), $2 = log, $3 = per-line outcome file (optional), $4 = the tip the proof was taken at (optional)
  [ -n "$1" ] || { echo "NONE:never-reported"; return 0; }
  [ "$1" = 0 ] && { echo GREEN; return 0; }
  if lq_outcome_green "${3:-}"; then echo GREEN; return 0; fi
  # BEFORE EVERY OTHER RULE, because the others all read a log a harness failure never wrote.
  if lq_rc_is_harness "$1"; then echo "NONE:harness"; return 0; fi
  # …and only then the box: a proof that finished and reported GREEN before the box was reclaimed
  # is a green proof, and the outcome file is the proof's own word.
  if lq_box_gone "$1" "$2"; then echo "NONE:box"; return 0; fi
  if lq_harness_gave_up "$2"; then echo "NONE:harness"; return 0; fi
  if lq_base_state_red "$2"; then echo "NONE:base"; return 0; fi
  # …and the same rule for the oracle's rows, which have no sentence of their own to say it with.
  if lq_line_red_is_base_oracle "${4:-}" "$2"; then echo "NONE:base"; return 0; fi
  if grep -qE 'not a fast-forward of this tree|this tree is NOT moved|tip (has )?moved' "$2" 2>/dev/null; then echo "NONE:moved"; return 0; fi
  echo RED
}
# ONE LINE'S OWN ROW OUT OF A UNION'S OUTCOME FILE. A chained pre-proof hands the box the WHOLE
# chain — the predecessor's picks are the tree the dependent is judged on — so the batch's rc and
# lq_outcome_green (which demands every row green) both speak for the union. The verdict wanted here
# is the DEPENDENT's, which land.sh's own bisect already attributed per line.
lq_outcome_row() { # $1 = per-line outcome file, $2 = the line text; prints that line's outcome, or nothing
  local f="${1:-}" want="$2"
  [ -n "$f" ] && [ -s "$f" ] || return 0
  # THE LINE COMES IN THROUGH THE ENVIRONMENT, NEVER THROUGH `awk -v`. `-v x=…` runs the value
  # through awk's escape processing, so a queue line carrying `--families '…route\.failover…'`
  # arrives inside awk as `route.failover` and matches nothing — 44 of the queue's lines are that
  # shape. ENVIRON is the raw bytes.
  LQ_AWK_T="$want" awk -F"$TAB" '$2 == ENVIRON["LQ_AWK_T"] { st = $1 } END { if (st != "") print st }' "$f"
}
# A CHAINED PRE-PROOF'S VERDICT. The dependent's own row first; a base-state red is still the base's
# and is recorded NONE (rule 2g), never parked; and with no row at all the transport's rules stand
# exactly as they do for an unchained sweep — with NO whole-file outcome, because a union that is
# red in the predecessor says nothing about the dependent either way.
lq_chain_preproof_verdict() { # $1 = rc, $2 = log, $3 = per-line outcome file, $4 = the CHAINED line's own text, $5 = the tip (optional)
  local own; own="$(lq_outcome_row "${3:-}" "$4")"
  case "$own" in
    GREEN) echo GREEN; return 0 ;;
    # …and a RED row is the dependent's OWN red only when the proof really ran and really judged
    # it: a box reclaimed mid-proof and a harness that gave up are no more a verdict on a chained
    # line than on a single one (the bisect attributes rows it never got to judge to nobody).
    RED|RED-*) if lq_rc_is_harness "$1"; then echo "NONE:harness"
               elif lq_box_gone "$1" "$2"; then echo "NONE:box"
               elif lq_harness_gave_up "$2"; then echo "NONE:harness"
               elif lq_base_state_red "$2"; then echo "NONE:base"
               elif lq_line_red_is_base_oracle "${5:-}" "$2"; then echo "NONE:base"
               else echo RED; fi; return 0 ;;
    # HELD is land.sh's word for "a line BEFORE this one in the unit was the culprit, so this line
    # was never proven": its picks went back out with its predecessor's and nothing was judged. It
    # is not a red — the line is exactly as unproven as it was before the box ran — so it is
    # recorded as nothing at all, and the next sweep may hand it a box again.
    HELD) echo "NONE:held"; return 0 ;;
  esac
  lq_preproof_verdict "$1" "$2" "" "${5:-}"
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE FAULT TAXONOMY — AN INFRASTRUCTURE FAILURE IS NEVER A HALT AND NEVER A RED
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# MEASURED on the running engine's log, 09-09 to 09-11: fifteen HALTs. Five of them were
# `land.sh --batch left 0 of N per-line outcomes (rc 2|126)` — a box that stopped answering, an scp
# that closed, the base push failing — and one was `no prepared, reachable on-demand box among the
# 0` during a fleet resize. Not one of them was a fact about the tree. Each cost the queue every
# minute between the fault and the moment an integrator noticed, restarted the runner by hand and
# re-typed a twelve-variable env line.
#
# THE RULE. Every failure whose cause is the INFRASTRUCTURE — a box, the transport, the fleet
# table, the lock, the harness — is a CLASS. A class produces the verdict `NONE:<class>`, which is
# the engine's existing word for "nothing was learned about this line": the line stays LIVE, the
# batch is requeued exactly as it was popped, and the loop is taken again after a backoff of
# 1, 2, 4, 8 then 15 minutes (doubling, capped), counted per class and reset the moment a batch
# comes back with outcomes in it. Nothing is parked, nothing is marked red, nothing needs a human.
#
# HALT SURVIVES FOR TWO FACTS ABOUT THE TREE, and they are the only two: a head line that will not
# apply twice in a row (`head-conflict-twice`), and a tree that has moved under the runner
# (`tree-moved` — which does not exit even now: it refuses the batch and retries, because a tree
# that moved is usually a stray process the census is about to kill, and a runner that exits loses
# more than it protects. It is a class here so that it is COUNTED and PAGED rather than silent.)
#
# THE CLASSES, and the sentence each is read from:
#   box-unreachable  ssh/scp/rsync closed, the poller's "unreachable for N polls", rc 75 from
#                    land-remote, and the default for a batch that came back with no outcomes at
#                    all: whatever else the log says, nothing was learned about the lines.
#   base-push-failed the integration base could not be pushed to the box (land-remote rdie).
#   box-stopped      the box is STOPPED, not broken — FLEET-2's cost posture puts an idle box to
#                    sleep after fifteen minutes, and SSM then answers `TargetNotConnected` for it.
#                    The disposition is NOT NONE:box and a shrug: the engine ASKS ci-fleet-power to
#                    start what the next attempt needs, and then retries on the backoff.
#   probe-empty      "no prepared, reachable on-demand box among the N" — after FLEET-2's re-ask of
#                    an all-silent round there is still nobody home. The fleet is resizing; wait.
#   spot-reclaimed   AWS took the instance back mid-proof ("Service initiated").
#   lock-stale       a lock file whose holder is dead, or whose recorded start time is not the
#                    start time of the process now wearing that pid (see lq_lock_acquire).
#   harness          the existing NONE:harness — a driver that could not do its job.
#   census-empty     the census saw nothing at all, not even this runner: the census is broken.
#   tree-moved       HEAD is not the last landed tip, or something tracked is modified.
# A STOPPED BOX IS NOT AN UNREACHABLE ONE, and the difference is the whole of FLEET-2's posture:
# an idle box is STOPPED after fifteen minutes to stop paying for it, and SSM answers
# `TargetNotConnected` for a stopped instance while EC2 answers `IncorrectInstanceState` for an
# order sent to one. Scored as box-unreachable these would back off and wait for a box that is
# never going to answer by itself; scored as box-stopped they make the engine START one.
LQ_BOX_STOPPED_RE='TargetNotConnected|InvalidInstanceId|IncorrectInstanceState|the fleet is all asleep|no running box|box\(es\) are stopped'
LQ_PROBE_EMPTY_RE='no prepared, reachable on-demand box among the'
LQ_BASE_PUSH_RE='could not push the integration base|could not push [^ ]+ to |remote rejected|failed to push some refs'
LQ_SPOT_RE='Service initiated|instance-action|spot (instance|interruption)|marked for (termination|retirement)'
LQ_UNREACH_RE='Connection closed by|Connection closed$|ssh: connect to host|ssh_exchange_identification|^scp: |scp: Connection|rsync: |Connection timed out|Connection refused|Broken pipe|No route to host|Host key verification failed|unreachable for [0-9]+ polls|the box vanished mid-proof|Permission denied \(publickey'

# WHICH CLASS THIS LOG IS, IF IT IS ONE AT ALL. Prints nothing when the failure is not the
# infrastructure's — a line that was really judged and really went red must still go red.
lq_fault_class() { # $1 = rc, $2 = log (optional); prints the class, or nothing
  local rc="${1:-}" lg="${2:-}"
  if [ -n "$lg" ] && [ -f "$lg" ]; then
    grep -qE "$LQ_BOX_STOPPED_RE"  "$lg" 2>/dev/null && { printf 'box-stopped\n'; return 0; }
    grep -qE "$LQ_PROBE_EMPTY_RE" "$lg" 2>/dev/null && { printf 'probe-empty\n'; return 0; }
    grep -qE "$LQ_BASE_PUSH_RE"   "$lg" 2>/dev/null && { printf 'base-push-failed\n'; return 0; }
    grep -qE "$LQ_SPOT_RE"        "$lg" 2>/dev/null && { printf 'spot-reclaimed\n'; return 0; }
    grep -qE "$LQ_HARNESS_RE"     "$lg" 2>/dev/null && { printf 'harness\n'; return 0; }
    grep -qE "$LQ_UNREACH_RE"     "$lg" 2>/dev/null && { printf 'box-unreachable\n'; return 0; }
  fi
  [ "$rc" = 75 ] && { printf 'box-unreachable\n'; return 0; }
  return 0
}
# A BATCH THAT CAME BACK WITH NO PER-LINE OUTCOMES always has a class, and box-unreachable is the
# floor: land.sh writes one outcome row per landing line before it writes anything else about the
# verdict, so an empty result file means the proof never reported — which is a statement about the
# transport and never about the picks.
lq_batch_fault_class() { # $1 = rc, $2 = log (optional); always prints a class
  local c; c="$(lq_fault_class "${1:-}" "${2:-}")"
  [ -n "$c" ] || c=box-unreachable
  printf '%s\n' "$c"
}
# THE BACKOFF: 1, 2, 4, 8, 15 minutes and 15 from then on. The first retry is quick because most of
# these faults are a single box and the next loop simply picks another one; the cap is the owner's,
# and it is a cap and not a give-up — the engine never stops asking.
LQ_BACKOFF_CAP="${LANDQ_BACKOFF_CAP_SECS:-900}"
lq_backoff_secs() { # $1 = how many times in a row this class has fired (1-based)
  local n="${1:-1}" s=60
  case "$n" in ''|*[!0-9]*) n=1 ;; esac
  [ "$n" -ge 1 ] || n=1
  while [ "$n" -gt 1 ]; do
    s=$((s * 2)); n=$((n - 1))
    [ "$s" -ge "$LQ_BACKOFF_CAP" ] && break
  done
  [ "$s" -gt "$LQ_BACKOFF_CAP" ] && s="$LQ_BACKOFF_CAP"
  printf '%s\n' "$s"
}
lq_fault_count() { # $1 = class, $2 = ledger (default $FAULTS); prints how many times in a row
  local c="$1" f="${2:-$FAULTS}"
  [ -f "$f" ] || { printf '0\n'; return 0; }
  LQ_AWK_C="$c" awk -F"$TAB" '$1 == ENVIRON["LQ_AWK_C"] { n = $2 } END { print (n == "" ? 0 : n) }' "$f"
}
# RECORDED, COUNTED AND RUNG. Temp+mv, because the status renderer reads this file and a half-written
# ledger is a status line that lies. Prints the NEW consecutive count, which is what the backoff wants.
lq_fault_record() { # $1 = class, $2 = text, $3 = ledger (default $FAULTS), $4 = ring (default $FAULTRING)
  local c="$1" text="${2:-}" f="${3:-$FAULTS}" r="${4:-$FAULTRING}" n
  n="$(lq_fault_count "$c" "$f")"; n=$((n + 1))
  mkdir -p "$(dirname "$f")" 2>/dev/null || true
  { [ -f "$f" ] && LQ_AWK_C="$c" awk -F"$TAB" '$1 != ENVIRON["LQ_AWK_C"]' "$f"
    printf '%s\t%s\t%s\t%s\n' "$c" "$n" "$(date +%s)" "$text"; } >"$f.tmp" && mv "$f.tmp" "$f"
  { [ -f "$r" ] && tail -n "$((FAULT_RING_KEEP - 1))" "$r"
    printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$c" "$text"; } >"$r.tmp" && mv "$r.tmp" "$r"
  printf '%s\n' "$n"
}
# CLEARED BY A BATCH THAT CAME BACK. The backoff is about a run of faults, not about a total: one
# batch with outcomes in it is proof that the transport works, and the next fault starts at a minute
# again. With no class named, every class is cleared.
lq_fault_clear() { # $1 = class (default: all), $2 = ledger (default $FAULTS)
  local c="${1:-}" f="${2:-$FAULTS}"
  [ -f "$f" ] || return 0
  if [ -z "$c" ]; then : >"$f.tmp" && mv "$f.tmp" "$f"; return 0; fi
  LQ_AWK_C="$c" awk -F"$TAB" '$1 != ENVIRON["LQ_AWK_C"]' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
  return 0
}
# THE ONE THING A FAULT IS ALLOWED TO DO TO A LINE: say that nothing was learned about it.
lq_fault_verdict() { # $1 = class
  printf 'NONE:%s\n' "$1"
}
# THE TWO CLASSES THE ENGINE CAN FIX BY ITSELF. A stopped fleet and an empty probe round are both
# "there is no box awake", and the engine owns the switch: ci-fleet-power.sh --ensure-slots starts
# exactly as many boxes as the slots it is short of, at BUSBAR_PROVE_PER_BOX slots each, and never
# more. Best-effort by construction — no power script staged, or no credentials, and the backoff
# alone carries the retry, exactly as it did before.
lq_fault_wake() { # $1 = slots the next attempt needs (default 1), $2 = tree (default $W)
  local want="${1:-1}" tree="${2:-$W}" pw="${2:-$W}/target/gate/ci-fleet-power.sh"
  [ -x "$pw" ] || { lq_log "fleet: no staged power script at $pw; the backoff alone carries this retry"; return 1; }
  lq_log "fleet: asking for $want proof slot(s) to be awake before the next attempt"
  bash "$pw" --ensure-slots "$want" >>"$L" 2>&1 \
    || lq_log "fleet: --ensure-slots $want did not report success; the backoff still carries the retry"
  return 0
}

# A PROCESS'S START TIME, as a string that is stable for the life of that process and different for
# the next process to wear its pid. `ps -o lstart=` says it on both BSD and procps.
lq_pid_start() { # $1 = pid; prints the start time, or nothing
  local p="${1:-}"
  case "$p" in ''|*[!0-9]*) return 0 ;; esac
  ps -o lstart= -p "$p" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/^ *//; s/ *$//'
}
# IS THIS LOCK A CORPSE? Two ways, and the second is the one that cost a night: the pid is dead, OR
# the pid is alive and is SOMEBODY ELSE — the recorded start time is not the start time of the
# process now wearing that number. A laptop recycles pids in hours and a rebooted box recycles them
# in seconds, and a lock held by an unrelated process stops the queue forever with no error at all.
# A lock file written by an older engine carries no start time; then the pid's liveness is all there
# is to go on and the lock is respected exactly as it was.
lq_lock_stale() { # $1 = the pid in the lock, $2 = the start time recorded beside it; 0 = stale, take it
  local pid="${1:-}" rec="${2:-}" now
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  kill -0 "$pid" 2>/dev/null || return 0
  [ -n "$rec" ] || return 1
  now="$(lq_pid_start "$pid")"
  [ -n "$now" ] || return 1
  [ "$rec" = "$now" ] && return 1
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE PREDICTED TIP — WHAT THE TREE WILL BE WHEN THE BATCH THAT IS PROVING RIGHT NOW LANDS
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# Every tip move DROPS the pre-prove ledger (every row is keyed by the tip it was taken on), so the
# sweep that feeds the next batch could not begin until the current batch had landed: one serial
# sweep per batch, and audit 16 measured 38 batches over the 103 must-land lines at 54 minutes of
# sweep apiece. The sweep and the proof are the same fleet doing the same work at different times.
#
# They need not be. The tree the batch will produce is KNOWN BEFORE THE BATCH RETURNS: it is this
# tip with the batch's picks applied, and land.sh applies them with `cherry-pick -x`, which makes a
# NEW COMMIT (new sha, new date, a `(cherry picked from commit …)` trailer) over the SAME TREE. So
# the runner builds that tree here, in a scratch worktree of its own repository, while the box is
# still proving, and sweeps the next disjoint lines against it — keyed by the PREDICTED sha.
#
# WHAT IS PREDICTED AND WHAT IS NOT. The prediction is a tree, and it is checked against the landed
# tree (lq_preproof_rekey) before a single row of it is believed. A pick that does not apply cleanly
# yields NO prediction at all: nothing is guessed, the overlap is skipped, and the queue runs exactly
# as it ran before. A line whose files meet the batch's is never swept against the prediction
# (lq_disjoint_lines $5) — the prediction says what the tree will be, not what a pick onto it does.
LQ_PREDICT="${LANDQ_PREDICT_TREE:-$W/target/gate/predict}"
lq_predict_tip() { # $1 = tree, $2 = batch file, $3 = scratch worktree (default $LQ_PREDICT); prints "<sha> <tree-sha>", or nothing
  local tree="${1:-$W}" bf="$2" wt="${3:-$LQ_PREDICT}" tip h line
  [ -f "$bf" ] || return 1
  tip="$(git -C "$tree" rev-parse -q --verify HEAD 2>/dev/null)" || return 1
  [ -n "$tip" ] || return 1
  git -C "$tree" worktree prune >/dev/null 2>&1
  if [ ! -e "$wt/.git" ]; then
    mkdir -p "$(dirname "$wt")"
    git -C "$tree" worktree add -q --detach "$wt" "$tip" >/dev/null 2>&1 || return 1
  fi
  git -C "$wt" cherry-pick --abort >/dev/null 2>&1
  git -C "$wt" checkout -q --detach "$tip" >/dev/null 2>&1 || return 1
  git -C "$wt" reset -q --hard "$tip" >/dev/null 2>&1 || return 1
  # THE PICKS, IN THE ORDER THE BATCH NAMES THEM, exactly as land.sh applies them.
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    for h in $(lq_line_hashes "$line"); do
      git -C "$wt" cherry-pick -x "$h" >/dev/null 2>&1 || {
        git -C "$wt" cherry-pick --abort >/dev/null 2>&1
        git -C "$wt" reset -q --hard "$tip" >/dev/null 2>&1
        return 1; }
    done
  done <"$bf"
  printf '%s %s\n' "$(git -C "$wt" rev-parse HEAD)" "$(git -C "$wt" rev-parse 'HEAD^{tree}')"
}

# THE PREDICTION IS CHECKED AGAINST THE TREE, NEVER AGAINST THE SHA. `cherry-pick -x` writes a new
# commit, so the landed sha is never the predicted sha; the landed TREE is the predicted tree exactly
# when the batch landed whole and nothing else moved the tip. Equal: the rows taken against the
# prediction are rows about THIS tree and are re-keyed to the landed sha, and the next pop takes them
# with no second sweep. Not equal (a red batch that bisected, a hand landing, a partial batch): they
# are dropped, which is what every stale row has always been.
lq_preproof_rekey() { # $1 = predicted sha, $2 = predicted tree, $3 = landed sha, $4 = tree (default $W), $5 = ledger (default $PP); 0 = valid, 1 = dropped
  local psha="$1" ptree="$2" landed="$3" tree="${4:-$W}" pp="${5:-$PP}" ltree
  [ -n "$psha" ] && [ -f "$pp" ] || return 1
  ltree="$(git -C "$tree" rev-parse -q --verify "$landed^{tree}" 2>/dev/null)"
  if [ -n "$ltree" ] && [ "$ltree" = "$ptree" ]; then
    awk -F"$TAB" -v OFS="$TAB" -v p="$psha" -v l="$landed" \
      '$2 == p { $2 = l; print; next } index($2, p "@") == 1 { $2 = l substr($2, length(p) + 1) } { print }' "$pp" >"$pp.tmp" \
      && mv "$pp.tmp" "$pp"
    return 0
  fi
  awk -F"$TAB" -v p="$psha" '!($2 == p || index($2, p "@") == 1)' "$pp" >"$pp.tmp" && mv "$pp.tmp" "$pp"
  return 1
}

# A CHAINED GREEN BECOMES AN ORDINARY GREEN THE MOMENT ITS CHAIN LANDS — AND THAT IS THE WHOLE WIN.
#
# `<tip>@<pick>+<pick>…` is not a private key; it is a NAME FOR A TREE: "this tip with these picks
# on it". When a batch of exactly those picks lands whole, the tree it produced IS that tree, and
# the new tip is another name for it. Without this the row would be pruned as stale by the tip move
# — and the line it speaks for would go back onto the fleet for a 54-minute sweep to re-learn what
# a box already proved an hour ago, which is the cost this change exists to remove.
#
# EXACTLY THOSE PICKS, IN THAT ORDER, AND EVERY LINE GREEN. A prefix is not the tree (the batch
# landed more than the row's chain); a red or a red-conflict means land.sh backed picks out and the
# landed tree is not the sum of the batch file. Anything short of the exact match falls through to
# the prune, which is where every stale row has always gone.
lq_chain_rekey() { # $1 = old tip, $2 = new tip, $3 = batch file, $4 = per-line result file, $5 = ledger (default $PP); prints how many moved
  local old="$1" new="$2" bf="$3" res="$4" pp="${5:-$PP}" line h k="" n=0
  [ -n "$old" ] && [ -n "$new" ] && [ -f "$bf" ] && [ -f "$pp" ] || { echo 0; return 0; }
  lq_outcome_green "$res" || { echo 0; return 0; }
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    for h in $(lq_line_hashes "$line"); do k="$k$h+"; done
  done <"$bf"
  [ -n "$k" ] || { echo 0; return 0; }
  k="$old@${k%+}"
  n="$(LQ_AWK_K="$k" awk -F"$TAB" '$2 == ENVIRON["LQ_AWK_K"]' "$pp" 2>/dev/null | grep -c . || true)"
  case "$n" in ''|*[!0-9]*) n=0 ;; esac
  [ "$n" -gt 0 ] || { echo 0; return 0; }
  LQ_AWK_K="$k" awk -F"$TAB" -v OFS="$TAB" -v nt="$new" \
    '$2 == ENVIRON["LQ_AWK_K"] { $2 = nt } { print }' "$pp" >"$pp.tmp" 2>/dev/null && mv "$pp.tmp" "$pp"
  echo "$n"
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE ENGINE THE RUNNER RUNS, staged under target/gate with its roots pointed at THIS tree.
#
# `$SCRIPTS` (LAND_SH_SRC) is a scratch copy of scripts/ — usually inside another worktree — so that a
# landing can change land.sh without changing the copy that is landing it. land.sh derives `here`
# from its own path and execs the land-remote.sh BESIDE it, whose REPO is likewise derived. Run from
# `$SCRIPTS` directly, both resolve to the SCRATCH tree: land-remote.sh refuses the batch file as
# "outside the repository", and had it not, the tip it pushed would have been the scratch worktree's
# HEAD while the ledger keyed the verdict by this tree's. The sweep did exactly that in its first
# form. So the three files are rewritten here, once per iteration, and EVERYTHING the runner launches
# — the sweep and the batch alike — runs the staged copies.
# $1 IS THE TREE THE STAGED ENGINE IS ROOTED IN, and it is not always the runner's: the overlapped
# sweep proves from the PREDICTION worktree, whose HEAD is the tip the batch is about to make, and an
# engine rooted in the runner's tree would push the runner's HEAD instead.
lq_stage_engine() { # $1 = tree (default $W)
  local t="${1:-$W}"
  mkdir -p "$t/target/gate"
  sed "s|^here=.*|here=\"$t\"|" "$SCRIPTS/land.sh" >"$t/target/gate/land.run.sh"
  sed "s|^REPO=.*|REPO=\"$t\"|" "$SCRIPTS/land-remote.sh" >"$t/target/gate/land-remote.sh"
  cp "$SCRIPTS/ci-remote-lib.sh" "$t/target/gate/ci-remote-lib.sh"
  # THE LATCHKEY TRANSPORT IS STAGED EXACTLY LIKE THE FLEET ONE, AND FOR THE SAME REASON TWICE OVER.
  #
  # MEASURED, LIVE (2026-09-11 18:09, first sweep on BUSBAR_PROVE_BACKEND=latchkey): the dispatcher
  # ran `bash "$tree/scripts/prove-latchkey.sh"` and the runner tree is the checkout at the LANDED
  # tip — which does not carry this script, because this script has not landed yet. Every line in
  # that sweep came back `bash: …/scripts/prove-latchkey.sh: No such file or directory`, exit 127.
  # The engine's own scripts come from the ENGINE HOME ($SCRIPTS / LAND_SH_SRC, which the supervisor
  # archives), never from the tree being proven — the tree is the SUBJECT of a proof, not its tooling.
  #
  # AND IT IS REWRITTEN, NOT COPIED, for the reason in this function's header: prove-latchkey.sh
  # derives its REPO from its own path, so a copy run out of $SCRIPTS would pack the SCRATCH
  # worktree — the wrong tree, proven confidently. `REPO=` is pinned to $t exactly as
  # land-remote.sh's is.
  #
  # AN ENGINE HOME WITHOUT IT IS NOT AN ERROR HERE. A home archived before this landed simply has
  # no latchkey transport; the dispatcher finds no staged copy and says so, which is an honest
  # NONE. Failing the staging would take the FLEET down with it, over a backend nobody asked for.
  if [ -f "$SCRIPTS/prove-latchkey.sh" ]; then
    sed "s|^REPO=.*|REPO=\"$t\"|" "$SCRIPTS/prove-latchkey.sh" >"$t/target/gate/prove-latchkey.run.sh"
    chmod +x "$t/target/gate/prove-latchkey.run.sh"
  else
    rm -f "$t/target/gate/prove-latchkey.run.sh"
  fi
  # THE FLEET'S POWER SWITCH TRAVELS WITH THE ENGINE, for the same reason the transport does: the
  # sweep runs out of the staged tree, and a sweep that could not start a stopped box would quietly
  # dispatch to whatever happened to be awake and call the rest "out of free boxes".
  [ -f "$SCRIPTS/ci-fleet-power.sh" ] && cp "$SCRIPTS/ci-fleet-power.sh" "$t/target/gate/ci-fleet-power.sh"
  chmod +x "$t/target/gate/land.run.sh" "$t/target/gate/land-remote.sh"
  [ -f "$t/target/gate/ci-fleet-power.sh" ] && chmod +x "$t/target/gate/ci-fleet-power.sh"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE LOCK: ONLY THE RUNNER LANDS. A host-wide file naming this process; land.sh refuses a
# `--remote` landing that is not a pre-proof while a live pid is in it (a slot proves its own branch
# with --preprove). A second runner refuses to start over a live holder; a dead pid is stale and is
# taken over. Everything this runner launches inherits LANDQ_RUNNER_PID and is exempt.
#
# RAIL 13 — WHAT A SLOT OWES, AND WHAT IT DOES NOT. A slot CODES: it writes the change, runs
# `cargo check` and `cargo clippy` on its own tree, pushes its branch, and hands back a queue line.
# It does NOT prove the gates and it does NOT land — the FLEET proves and the runner lands, and a
# slot that spends an hour running `kind-isolation --selftest` on a laptop is an hour of a box's
# work done at a tenth the speed on the one machine every other slot is waiting for. The reason
# that division is affordable is directly above and below this line: the sweep, and the CHAINED
# sweep, put every queue line on a box of its own — a held line included, on the tree its
# predecessor will make — so "the fleet proves it" is not a promise about a later hour, it is
# something that has already happened by the time the line reaches the head of the queue.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
LOCK="${LANDQ_LOCK:-$HOME/.busbar-landq4.lock}"
# THE LOCK CARRIES THE HOLDER'S START TIME, and that is what makes "is it alive?" a question worth
# asking (see lq_lock_stale). `kill -0` alone answers about a NUMBER, not about a process: the third
# line of this file is the holder's start time as `ps` said it, and a pid whose process started at a
# different moment is a recycled number, not a runner. Such a lock is STALE and is taken, with the
# fault recorded as `lock-stale` so the status file says it happened.
lq_lock_acquire() { # $1 = my pid; 0 = held by me now, 1 = a live runner holds it (its pid on stdout)
  local me="$1" pid rec
  if [ -f "$LOCK" ]; then
    pid="$(head -n1 "$LOCK" 2>/dev/null | tr -d '[:space:]')"
    case "$pid" in ''|*[!0-9]*) pid="" ;; esac
    rec="$(sed -n 3p "$LOCK" 2>/dev/null)"
    if [ -n "$pid" ] && [ "$pid" != "$me" ]; then
      if lq_lock_stale "$pid" "$rec"; then
        lq_fault_record lock-stale "$LOCK held by pid $pid, which is dead or is no longer the process that took it" >/dev/null
      else
        printf '%s\n' "$pid"; return 1
      fi
    fi
  fi
  printf '%s\n%s\n%s\n' "$me" "$W" "$(lq_pid_start "$me")" >"$LOCK"
  export LANDQ_RUNNER_PID="$me"
  return 0
}
lq_lock_release() { # $1 = my pid
  [ -f "$LOCK" ] && [ "$(head -n1 "$LOCK" 2>/dev/null | tr -d '[:space:]')" = "$1" ] && rm -f "$LOCK"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE PRE-PROVE SWEEP
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# One box per line, in parallel, each against the CURRENT tip and each publishing nothing. The
# runner's own tree is never touched: `--preprove` makes land.sh reset the box's tree to the base
# it started from, so the tip land-remote.sh brings back is the tip it sent and the fast-forward is
# a no-op. That is the whole safety argument, and it is proven by land.sh's own self-test
# ("pre: the tree did NOT move").
# THE HELD LINES WORTH A BOX, after the live ones have had theirs (see the chained pre-proof note).
# In queue order, at most $1 of them, each one whose chain resolves and whose OWN files are free.
#
# ITS OWN FILES, LESS THE CHAIN'S. A dependent overlapping its predecessor is the ordinary case —
# that overlap is usually WHY it is held — and those files are in its own batch by construction, so
# they are not a clash. Overlapping anything ELSE the sweep is holding is a clash exactly as it is
# for a live line: two boxes proving trees that will not both survive.
lq_chain_candidates() { # $1 = max, $2 = queue file, $3 = repo, $4 = tip key, $5 = file of lines whose files are claimed, $6 = this sweep's red-root list
  local max="$1" qf="$2" repo="${3:-$W}" tip="$4" claimf="${5:-}" redroots="${6:-}" line chain dep anc ancset claimed="" f n=0 clash
  case "$max" in ''|*[!0-9]*) return 0 ;; esac
  [ "$max" -gt 0 ] || return 0
  if [ -n "$claimf" ] && [ -f "$claimf" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      while IFS= read -r f; do [ -n "$f" ] && claimed="$claimed$f$TAB"; done <<EOF
$(lq_line_files "$(lq_line_payload "$line")" "$repo")
EOF
    done <"$claimf"
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    [ "$n" -lt "$max" ] || break
    case "$line" in '#HOLD-after-'*) ;; *) continue ;; esac
    chain="$(lq_chain_of "$line" "$qf" "$repo" "$LAND_CHAIN_DEPTH")" || continue
    [ -n "$chain" ] || continue
    dep="$(printf '%s' "$chain" | tail -n1)"
    anc="$(printf '%s' "$chain" | sed '$d')"
    [ -n "$anc" ] || continue
    [ "$(lq_preproved_status "$(printf '%s\n' "$anc" | lq_chain_key "$tip")" "$dep")" = GREEN ] && continue
    # A CHAIN WHOSE ROOT IS ALREADY RED AT THIS TIP HAS NO GREEN RUNG (see lq_chain_root_red). Not
    # dispatched at all, rather than dispatched and then cancelled: a box taken for three seconds is
    # a box the next candidate in this very loop is refused.
    lq_chain_root_red "$(printf '%s\n' "$chain" | head -n1)" "$tip" "$PP" "$redroots" && continue
    ancset="$TAB"
    while IFS= read -r f; do [ -n "$f" ] && ancset="$ancset$f$TAB"; done <<EOF
$(printf '%s\n' "$anc" | while IFS= read -r l; do [ -n "$l" ] && lq_line_files "$l" "$repo"; done)
EOF
    clash=0
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      case "$ancset" in *"$TAB$f$TAB"*) continue ;; esac
      case "$TAB$claimed" in *"$TAB$f$TAB"*) clash=1; break ;; esac
    done <<EOF
$(lq_line_files "$dep" "$repo")
EOF
    [ "$clash" = 0 ] || continue
    while IFS= read -r f; do [ -n "$f" ] && claimed="$claimed$f$TAB"; done <<EOF
$(lq_line_files "$dep" "$repo")
EOF
    printf '%s\n' "$line"
    n=$((n + 1))
  done <"$qf"
}

# ── WHICH LIVE LINES ROOT A CHAIN, AND WHY THEY GO FIRST ─────────────────────────────────────────
# A box spent on a live single buys ONE line in the next batch. A box spent on a live line that
# roots a chain buys that line AND makes every chained hold behind it provable — and those land in
# the SAME batch as one unit, on files no other unit may touch. Measured in lines per proof, a chain
# is worth its whole depth and a single is worth one. So when the sweep has more lines than free
# boxes, the live lines that root a chain take their boxes first, the chained holds take theirs
# next, and the live lines that root nothing take what is left.
#
# ROOTING IS READ FROM THE TAGS, NOT FROM GIT: a held line whose `#HOLD-after-<sha>` names one of
# this line's picks is a chain that begins here. That is a string compare over the queue, so the
# preference costs nothing on a queue of 120 lines — lq_chain_candidates then does the resolving
# work, once, for the lines that actually get boxes.
lq_line_roots_a_hold() { # $1 = live payload, $2 = queue file; 0 when a #HOLD-after-<sha> names one of its picks
  local pay="$1" qf="$2" line sha h
  [ -n "$pay" ] && [ -f "$qf" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '#HOLD-after-'*) ;; *) continue ;; esac
    sha="$(lq_hold_after_sha "$line")"
    [ -n "$sha" ] || continue
    for h in $(lq_line_hashes "$pay"); do
      case "$h" in "$sha"*) return 0 ;; esac
      case "$sha" in "$h"*) return 0 ;; esac
    done
  done <"$qf"
  return 1
}
lq_chain_roots_first() { # $1 = the live picks, $2 = queue file, $3 = repo; prints them, chain roots first, order kept
  local lines="$1" qf="$2" l
  while IFS= read -r l || [ -n "$l" ]; do
    [ -n "$l" ] || continue
    lq_line_roots_a_hold "$l" "$qf" && printf '%s\n' "$l"
  done <<EOF
$lines
EOF
  while IFS= read -r l || [ -n "$l" ]; do
    [ -n "$l" ] || continue
    lq_line_roots_a_hold "$l" "$qf" || printf '%s\n' "$l"
  done <<EOF
$lines
EOF
}

# ── THE HEAD OF THE LIVE QUEUE IS RESERVED BEFORE THE CHAINS FILL THE REST ────────────────────────
# lq_chain_roots_first says WHICH live lines are worth a box; this says HOW MANY of them the chains
# may take. MEASURED 2026-09-10: the sweep of twelve logged "9 chained holds + 3 live lines, 3 of
# the live lines root a chain" — every box went to a chain or to a chain's root, and the two lines
# at the HEAD of the queue (the ones the runner pops NEXT) were left with no pre-proof at all. The
# integrator wrote them into preprove-front.txt by hand, which is the operator doing the sweep's
# arithmetic for it.
#
# A chain is worth its depth and a single is worth one — that is still true, and it is not the only
# thing that is true. A pre-proof is only worth anything to the line that is ABOUT TO BE POPPED: a
# green three lines down the queue chooses an order the runner will not reach for an hour, while an
# unproven head line is a serial batch proven from scratch, which is the cost the sweep exists to
# avoid. So the first K live lines IN QUEUE ORDER are dispatched whatever the chains want, and the
# chains are budgeted against that reservation rather than against the roots alone.
#
# THE FRONT IS STILL FIRST, AND FOR FREE: this reads the head of the list it is GIVEN, and the list
# the sweep gives it is already the front-ordered queue (lq_front_queue). A line the fleet owes an
# answer to IS the head of the live queue, so the two rules never contend.
lq_sweep_order() { # $1 = the live lines in QUEUE order, $2 = the same lines roots-first, $3 = K, $4 = slots
  local lines="$1" roots="$2" k="${3:-0}" slots="${4:-0}" l n=0 seen="$NL"
  case "$k" in ''|*[!0-9]*) k=0 ;; esac
  case "$slots" in ''|*[!0-9]*) slots=0 ;; esac
  [ "$slots" -gt 0 ] || return 0
  [ "$k" -le "$slots" ] || k="$slots"
  while IFS= read -r l || [ -n "$l" ]; do
    [ -n "$l" ] || continue
    [ "$n" -lt "$k" ] || break
    printf '%s\n' "$l"; seen="$seen$l$NL"; n=$((n + 1))
  done <<EOF
$lines
EOF
  while IFS= read -r l || [ -n "$l" ]; do
    [ -n "$l" ] || continue
    [ "$n" -lt "$slots" ] || break
    # THE RESERVED HEAD IS NOT HANDED A SECOND BOX. A head line that also roots a chain is at the
    # front of BOTH lists, and printing it twice would cost a box to prove the same line again.
    case "$seen" in *"$NL$l$NL"*) continue ;; esac
    printf '%s\n' "$l"; seen="$seen$l$NL"; n=$((n + 1))
  done <<EOF
$roots
EOF
}
# HOW MANY BOXES THE CHAINED HOLDS MAY ASK FOR. The roots want one each and the head wants K, and
# those two claims OVERLAP — a head line that roots a chain is one box, not two — so the reservation
# is the larger of them, never their sum. A budget smaller than the claim is no boxes, not a
# negative number that `lq_chain_candidates` would read as "unbounded".
lq_chain_budget() { # $1 = the sweep's whole budget, $2 = how many live lines root a chain, $3 = K
  local slots="${1:-0}" nroots="${2:-0}" k="${3:-0}" hold
  case "$slots" in ''|*[!0-9]*) slots=0 ;; esac
  case "$nroots" in ''|*[!0-9]*) nroots=0 ;; esac
  case "$k" in ''|*[!0-9]*) k=0 ;; esac
  hold="$nroots"; [ "$k" -le "$hold" ] || hold="$k"
  if [ "$hold" -ge "$slots" ]; then echo 0; else echo $((slots - hold)); fi
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# A CHAIN WHOSE ROOT IS RED HAS NO GREEN RUNG, AND THE FLEET IS TOLD SO
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# MEASURED 2026-09-10. Line 1 of the sweep was a chain's ROOT, proven ALONE, and it came back RED at
# 5481 s. Lines 4, 5 and 11 were DEEPER PREFIXES of that same chain — root+1, root+2, root+3 — and
# all three were still bisecting on three fleet boxes three hours later, when an operator killed
# them by hand. Every rung of a chain is the root's picks plus more picks; the root is red, so its
# picks are coming back off the tree, and there is no tree any of those rungs can be proven green
# on. Three boxes for three hours, to finish computing an answer that was already known and could
# not change.
#
# SO A ROOT RED STOPS THEM, AND `NONE:moot` IS WHAT THEY ARE SCORED. Not RED — nothing was learned
# about a rung's own picks, and a park would convict a line for its predecessor's fault, which is
# exactly what HELD exists to prevent. Not re-queued to the front either: a mooted rung is not a
# question the fleet still owes an answer to, because the HOLD it sits under is not being released
# at this tip whatever happens. It is simply as unproven as it was, and the next sweep — at a tip
# where the root has been repaired — may hand it a box again.
#
# WHAT COUNTS AS A ROOT RED, AND WHAT DOES NOT. A box that vanished, a harness that gave up and a
# red that is the BASE's are not verdicts on the root's picks (lq_preproof_verdict's whole rule), so
# they moot nothing: the rungs below keep their boxes and finish. Only a red the engine attributed
# to the root itself — a live single scored RED, or a chained slot whose PREFIX-1 row is RED —
# empties the chain.
lq_slot_root_red() { # $1 = sweep dir, $2 = slot number, $3 = the tip key; 0 when this slot proved its chain's ROOT red
  local dir="$1" j="$2" key="${3:-}" rc lg res rootl
  rootl="$(cat "$dir/line-$j.root" 2>/dev/null || true)"
  [ -n "$rootl" ] || return 1
  rc="$(cat "$dir/line-$j.rc" 2>/dev/null || true)"
  [ -n "$rc" ] || return 1
  lg="$dir/line-$j.log"; res="$dir/line-$j.batch.result"
  if [ -f "$dir/line-$j.chainkey" ]; then
    # THE ROOT'S OWN ROW OUT OF THE UNION'S OUTCOME FILE. land.sh's prefix bisect has already
    # attributed it: a RED there is "the root, alone on the tip, is the culprit".
    case "$(lq_outcome_row "$res" "$rootl")" in RED|RED-*) ;; *) return 1 ;; esac
    lq_box_gone "$rc" "$lg" && return 1
    lq_rc_is_harness "$rc" && return 1
    lq_harness_gave_up "$lg" && return 1
    lq_base_state_red "$lg" && return 1
    lq_line_red_is_base_oracle "$key" "$lg" && return 1
    return 0
  fi
  [ "$(lq_preproof_verdict "$rc" "$lg" "$res" "$key")" = RED ]
}
# WHICH SLOTS THAT RED EMPTIES. Every chained slot of the SAME chain that has not reported yet —
# and only those: a rung of another chain is another question, and a slot that already has its own
# rc has already answered. Marked as it goes, so the record loop below scores each one once.
lq_moot_deeper() { # $1 = sweep dir, $2 = slot count, $3 = the slot that judged, $4 = the root payload; prints the slots
  local dir="$1" n="${2:-0}" self="$3" rootl="$4" m=1
  [ -n "$rootl" ] || return 0
  case "$n" in ''|*[!0-9]*) return 0 ;; esac
  while [ "$m" -le "$n" ]; do
    if [ "$m" != "$self" ] && [ ! -f "$dir/line-$m.rc" ] && [ ! -f "$dir/line-$m.moot" ] \
       && [ -f "$dir/line-$m.chainkey" ] \
       && [ "$(cat "$dir/line-$m.root" 2>/dev/null || true)" = "$rootl" ]; then
      : >"$dir/line-$m.moot"
      printf '%s\n' "$m"
    fi
    m=$((m + 1))
  done
}
# THE REF THE TRANSPORT ISSUED, out of the transport's own first line ("host <h>   ref <r>   picks:").
# It is the name of the log, the rc and the pid file on the box, so it is the whole of what a cancel
# needs beyond the host.
lq_slot_ref() { # $1 = a slot's log; prints the ref land-remote issued for it, or nothing
  [ -n "${1:-}" ] && [ -f "$1" ] || return 0
  grep -oE 'ref[[:space:]]+land-[0-9]{8}-[0-9]{6}-[0-9]+' "$1" 2>/dev/null \
    | head -n1 | sed -E 's/^ref[[:space:]]+//'
}
# EVERY DESCENDANT, THEN THE PARENT. The slot's driver is a subshell whose child is land.sh, whose
# child is land-remote.sh polling the box; killing the subshell alone leaves the poller running and
# holding the fleet's cursor.
lq_kill_tree() { # $1 = pid
  local pid="${1:-}" listing p
  [ -n "$pid" ] || return 0
  listing="$(lq_ps)"
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    [ "$p" = "$pid" ] && continue
    lq_descends "$p" "$pid" "$listing" && kill -TERM "$p" 2>/dev/null
  done <<EOF
$(printf '%s\n' "$listing" | awk '{print $1}')
EOF
  kill -TERM "$pid" 2>/dev/null || true
  return 0
}
# THE BOX FIRST, THE DRIVER SECOND, AND THE BOX OVER land-remote's OWN CHANNEL. Killing the local
# driver first would leave the fleet box proving with nobody polling it — the same three hours of a
# box, now with no log coming back at all. `land-remote.sh --cancel <host> <ref>` signals the proof's
# process group through the same ssh the poll loop uses (see remote_cancel).
lq_cancel_slot() { # $1 = sweep dir, $2 = slot number, $3 = tree (default $W)
  local dir="$1" m="$2" tree="${3:-$W}" pid host ref
  host="$(cat "$dir/line-$m.host" 2>/dev/null || true)"
  ref="$(lq_slot_ref "$dir/line-$m.log")"
  if [ -n "$host" ] && [ -n "$ref" ] && [ -x "$tree/target/gate/land-remote.sh" ]; then
    bash "$tree/target/gate/land-remote.sh" --cancel "$host" "$ref" >>"$dir/line-$m.cancel.log" 2>&1 || true
  else
    lq_log "pre-prove: slot $m has no host/ref to cancel with (host='${host:-}' ref='${ref:-}'); only its driver is stopped"
  fi
  pid="$(cat "$dir/line-$m.driver" 2>/dev/null || true)"
  lq_kill_tree "$pid"
  return 0
}
# AND NO DEEPER RUNG IS HANDED A BOX WHILE THE ROOT IS RED. The ledger's RED row at this tip is one
# half; the other is this sweep's own list, because a root judged red at 20:10 must not be handed
# rungs by the sweep that starts at 20:12 — the ledger row is written only when the sweep ends.
lq_root_red_mark() { # $1 = sweep dir, $2 = the root payload
  [ -n "${2:-}" ] || return 0
  grep -qxF -- "$2" "$1/root-red.txt" 2>/dev/null || printf '%s\n' "$2" >>"$1/root-red.txt"
}
lq_chain_root_red() { # $1 = root payload, $2 = tip key, $3 = ledger (default $PP), $4 = this sweep's red-root list (optional)
  local rootl="${1:-}" key="${2:-}" led="${3:-$PP}" lst="${4:-}"
  [ -n "$rootl" ] || return 1
  [ -n "$lst" ] && [ -f "$lst" ] && grep -qxF -- "$rootl" "$lst" 2>/dev/null && return 0
  [ -n "$key" ] && [ -f "$led" ] || return 1
  LQ_AWK_R="$rootl" awk -F"$TAB" -v tip="$key" \
    '$1 == "RED" && $2 == tip && $4 == ENVIRON["LQ_AWK_R"] { found = 1 } END { exit(found ? 0 : 1) }' "$led"
}
# ── THE SWEEP'S SLOTS, WATCHED RATHER THAN MERELY WAITED FOR ──────────────────────────────────────
# A bare `wait` learns every verdict at once, at the end — which is exactly too late to act on the
# one verdict that makes three other proofs pointless. This polls the slots' rc files instead, and
# the moment a slot's verdict is in it asks whether that verdict emptied a chain. Everything else is
# unchanged: it ends when every slot has reported or been mooted, and `wait` still reaps the
# children so nothing is left running behind the sweep.
# A PREDICTION THE BATCH HAS ALREADY KILLED. The overlapped sweep is keyed at <tip + the in-flight
# batch's picks>; if that batch comes back with any row that is not GREEN, the tree the sweep is
# proving against will NEVER EXIST — the picks go back out, the tip does not move, and every row the
# sweep is about to write is a row about nothing. MEASURED 13:13 on 09-11: a batch read RED and ten
# pre-proofs kept running for the better part of an hour against the dead prediction, holding ten
# boxes the next sweep then could not have.
#
# The moot-cancel already exists for a chain whose ROOT was proven red (lq_moot_deeper); this is the
# same fact one level up, and it fires the same way — the proofs are cancelled ON THE FLEET, the
# slots are marked moot, and the next loop re-dispatches at the tip that really is.
lq_prediction_dead() { # $1 = the in-flight batch file; 0 when its result is in and is not wholly green
  local bf="${1:-}"
  [ -n "$bf" ] && [ -s "$bf.result" ] || return 1
  awk -F"$TAB" 'NF && $1 != "GREEN" { bad = 1 } END { exit !bad }' "$bf.result"
}
lq_sweep_watch() { # $1 = sweep dir, $2 = slot count, $3 = tip key, $4 = tree (default $W), $5 = the in-flight batch
  local dir="$1" n="${2:-0}" key="${3:-}" tree="${4:-$W}" inflight="${5:-}" j fin rootl mooted mm
  case "$n" in ''|*[!0-9]*) wait; return 0 ;; esac
  [ "$n" -gt 0 ] || { wait; return 0; }
  while :; do
    # THE PREDICTION THIS SWEEP IS KEYED AT, BEFORE ANYTHING ELSE IS ASKED (see lq_prediction_dead).
    if [ -n "$inflight" ] && lq_prediction_dead "$inflight"; then
      lq_log "pre-prove: the batch in flight came back NOT GREEN — the predicted tree $(printf '%.9s' "$key") will never exist; every line still on a box is proving nothing"
      j=1
      while [ "$j" -le "$n" ]; do
        if [ ! -f "$dir/line-$j.rc" ] && [ ! -f "$dir/line-$j.moot" ]; then
          : >"$dir/line-$j.moot"
          lq_log "pre-prove: slot $j cancelled on the fleet — its tree is the dead prediction; NONE:moot, re-dispatched at the real tip next loop"
          lq_cancel_slot "$dir" "$j" "$tree"
        fi
        j=$((j + 1))
      done
      break
    fi
    fin=0; j=1
    while [ "$j" -le "$n" ]; do
      if [ -f "$dir/line-$j.moot" ]; then fin=$((fin + 1)); j=$((j + 1)); continue; fi
      if [ -f "$dir/line-$j.rc" ]; then
        fin=$((fin + 1))
        if [ ! -f "$dir/line-$j.judged" ]; then
          : >"$dir/line-$j.judged"
          if lq_slot_root_red "$dir" "$j" "$key"; then
            rootl="$(cat "$dir/line-$j.root" 2>/dev/null || true)"
            lq_root_red_mark "$dir" "$rootl"
            mooted="$(lq_moot_deeper "$dir" "$n" "$j" "$rootl")"
            for mm in $mooted; do
              lq_log "pre-prove: slot $j proved the chain ROOT red alone; slot $mm is a DEEPER prefix of it — cancelled on the fleet, scored NONE:moot"
              lq_cancel_slot "$dir" "$mm" "$tree"
            done
          fi
        fi
      fi
      j=$((j + 1))
    done
    [ "$fin" -lt "$n" ] || break
    sleep "${LANDQ_SWEEP_POLL_SECS:-20}"
  done
  wait
}

# ── HOW MANY PROOF SLOTS THIS DISPATCH WANTS ─────────────────────────────────────────────────────
# ONE PER LINE, AND THE TWO PROOFS THAT ARE NOT LINES. A sweep is not the only thing on the fleet
# when it runs: the base-only replay is a proof of the tip itself on a box of its own, and the batch
# the runner is about to pop needs a box too. Counting only the lines is how a twelve-line sweep
# takes every box that is awake and the batch behind it finds none.
#
# THE BATCH IS COUNTED ONLY WHEN IT IS NOT ALREADY RUNNING. A batch in flight is already holding a
# box, and that box reports itself busy to the allocator — counting it again would start a box for a
# slot that is already spoken for, and "never more than it needs" is the whole rule.
lq_sweep_slot_demand() { # $1 = live lines, $2 = chained holds, $3 = base replay wanted (0|1), $4 = a batch is in flight (0|1)
  local nlive="${1:-0}" nch="${2:-0}" base="${3:-0}" inflight="${4:-0}" d
  case "$nlive" in ''|*[!0-9]*) nlive=0 ;; esac
  case "$nch"   in ''|*[!0-9]*) nch=0 ;; esac
  case "$base"  in ''|*[!0-9]*) base=0 ;; esac
  case "$inflight" in ''|*[!0-9]*) inflight=0 ;; esac
  d=$(( nlive + nch + base ))
  [ "$inflight" = 1 ] || d=$(( d + 1 ))
  echo "$d"
}

lq_preprove_sweep() { # $1 = tree to prove FROM (default $W), $2 = the sha rows are keyed by (default that tree's HEAD), $3 = the batch in flight (optional)
  local tree="${1:-$W}" inflight="${3:-}"
  local tip; tip="$(git -C "$tree" rev-parse HEAD)"
  local key="${2:-$tip}"
  local dir="$tree/target/gate/preprove-$key"
  mkdir -p "$dir"
  # WHERE THIS SWEEP IS, so the status file can say which line is on which box and for how long
  # without the reader having to guess a directory name out of a tip (see lq_status_json).
  printf '%s\n' "$dir" >"$SWEEPPTR"
  # THE LINES THE FLEET OWES AN ANSWER TO GO FIRST (see lq_front_add). The reordering is a copy of
  # the queue, never the queue itself: the queue file is the operator's, and the runner rewrites it
  # only when it pops or parks.
  local qf="$Q"
  if [ -s "$FRONT" ]; then
    lq_front_queue "$Q" >"$dir/queue-front.txt"
    qf="$dir/queue-front.txt"
    lq_log "pre-prove: $(grep -c . "$FRONT" || true) line(s) the fleet owes an answer to are offered a box first"
  fi
  local lines; lines="$(lq_disjoint_lines "$PREPROVE_LINES" "$qf" "$tree" "$key" "$inflight")"
  local nlive; nlive="$(printf '%s\n' "$lines" | grep -c . || true)"
  case "$nlive" in ''|*[!0-9]*) nlive=0 ;; esac
  # THE HELD LINES THAT CAN BE PROVEN TODAY (see the chained pre-proof note). They take the boxes the
  # live lines leave, and their claim is checked against everything already spoken for: the batch in
  # flight, the lines already green at this key, and the live lines this sweep is about to hand out.
  local chained="" claimf="$dir/claimed.txt"
  if [ "$LAND_CHAIN_DEPTH" -ge 2 ]; then
    { if [ -n "$inflight" ] && [ -f "$inflight" ]; then cat "$inflight"; fi
      if [ -f "$PP" ]; then awk -F"$TAB" -v tip="$key" '$1 == "GREEN" && $2 == tip {print $4}' "$PP" | sort -u; fi
      printf '%s\n' "$lines"; } >"$claimf"
    # THE PREFERENCE (see lq_chain_roots_first): the chained holds are budgeted against the live
    # lines that ROOT a chain, not against every live line, so a rootless single never takes the box
    # a chain was going to be filled with. The live list is then re-ordered roots first and trimmed
    # to whatever the chained holds left — which can only ever trim rootless singles.
    local roots nroots=0
    roots="$(lq_chain_roots_first "$lines" "$Q" "$tree")"
    nroots="$(printf '%s\n' "$roots" | while IFS= read -r l; do [ -n "$l" ] && lq_line_roots_a_hold "$l" "$Q" && echo x; done | grep -c . || true)"
    case "$nroots" in ''|*[!0-9]*) nroots=0 ;; esac
    # THE HEAD'S RESERVATION, CLAMPED TO WHAT THERE IS (see lq_sweep_order). K live lines cannot be
    # reserved out of fewer than K live lines, and never out of more than the sweep's whole budget.
    local kact="$PREPROVE_HEAD"
    case "$kact" in ''|*[!0-9]*) kact=0 ;; esac
    [ "$kact" -le "$nlive" ] || kact="$nlive"
    [ "$kact" -le "$PREPROVE_LINES" ] || kact="$PREPROVE_LINES"
    chained="$(lq_chain_candidates "$(lq_chain_budget "$PREPROVE_LINES" "$nroots" "$kact")" "$Q" "$tree" "$key" "$claimf" "$dir/root-red.txt")"
    local nch; nch="$(printf '%s\n' "$chained" | grep -c . || true)"
    case "$nch" in ''|*[!0-9]*) nch=0 ;; esac
    if [ "$nch" -gt 0 ] && [ $((nlive + nch)) -gt "$PREPROVE_LINES" ]; then
      lines="$(lq_sweep_order "$lines" "$roots" "$kact" $((PREPROVE_LINES - nch)))"
      nlive="$(printf '%s\n' "$lines" | grep -c . || true)"
      case "$nlive" in ''|*[!0-9]*) nlive=0 ;; esac
      lq_log "pre-prove: the head, then chains before singles — $kact head slot(s) reserved, $nch chained hold(s) and $nlive live line(s) of a budget of $PREPROVE_LINES ($nroots of the live lines root a chain)"
    else
      lines="$(lq_sweep_order "$lines" "$roots" "$kact" "$PREPROVE_LINES")"
    fi
  fi
  if [ -z "$lines" ] && [ -z "$chained" ]; then
    lq_log "pre-prove: no disjoint line and no chained hold to hand out at $(printf '%.9s' "$key")"; return 0
  fi
  # ONE BOX PER LINE, ALLOCATED BEFORE ANY OF THEM STARTS.
  #
  # `fleet_pick_host` is a read-modify-write of a cursor FILE shared by every agent on this host, so
  # six processes asking at once can be handed the same box — and six pre-proofs queued on one box
  # is the wall clock of six serial landings, which is the opposite of the point. The hosts are
  # therefore picked here, serially, before a single child is launched, and each is named to
  # `land.sh --remote <host>` explicitly rather than left to `auto`.
  lq_stage_engine "$tree"
  # shellcheck source=scripts/ci-remote-lib.sh
  . "$tree/target/gate/ci-remote-lib.sh" 2>/dev/null || {
    lq_log "pre-prove: no ci-remote-lib.sh; the sweep has no transport and is skipped"; return 0; }
  ( remote_wrapper ) || { lq_log "pre-prove: no ssh wrapper for the fleet; sweep skipped"; return 0; }
  # ONE PROBE ROUND FOR THE WHOLE SWEEP. Measured 2026-09-10: dispatching twelve pre-proofs took
  # from 18:41 to 19:1x, because every line walked the fleet box by box with a `timeout 15 ssh`
  # apiece — and asked again whenever it was handed a box this sweep already held. The table is
  # probed ONCE, every box at the same time and the round still bounded by that same 15 s, and each
  # line is then a read of it plus a take. A box that turns out to have vanished is dropped from the
  # table by the line that lost it, below, so the table is only ever more accurate than the round.
  # ── START WHAT THIS DISPATCH NEEDS, AND NOTHING ELSE, BEFORE THE ROUND ─────────────────────────
  # An idle box is STOPPED (scripts/ci-fleet-power.sh, on the reconcile's timer), which costs EBS and
  # nothing else and is 60-90 s from proving. So the sweep asks for the slots it is about to use
  # BEFORE it probes: --ensure-slots subtracts the free slots on the boxes already awake, starts
  # only the whole boxes the shortfall needs at BUSBAR_PROVE_PER_BOX slots each, and WAITS for the
  # same readiness probe the allocator asks — a box that is merely starting is not free, and a box
  # counted before it is ready is a line dispatched into a bootstrap. It never goes past
  # CI_RUNNER_RUNNING_MAX; if it cannot get there the sweep dispatches to what there is and says so,
  # exactly as it does today when the fleet is short.
  local nch_d=0
  [ -n "$chained" ] && nch_d="$(printf '%s\n' "$chained" | grep -c . || true)"
  local want; want="$(lq_sweep_slot_demand "$nlive" "$nch_d" "${LANDQ_BASE_REPLAY:-1}" \
    "$( [ -n "$inflight" ] && [ -f "$inflight" ] && echo 1 || echo 0 )")"
  if [ -x "$tree/target/gate/ci-fleet-power.sh" ]; then
    lq_log "pre-prove: this dispatch wants $want proof slot(s) — starting only what the awake fleet is short of"
    bash "$tree/target/gate/ci-fleet-power.sh" --ensure-slots "$want" >/dev/null 2>&1 \
      || lq_log "pre-prove: could not start a stopped box; dispatching to the boxes that are already awake"
  fi
  fleet_table_open "$dir/fleet-table" >/dev/null \
    || lq_log "pre-prove: the fleet probe round found nothing to cache; each line will ask the fleet itself"
  # THE BASE REPLAY TAKES ITS SLOT FIRST (see lq_base_replay_reserve). It is what makes every other
  # verdict in this sweep readable — an unmeasured tip turns the oracle's rows into a line's own red
  # with no evidence — so it is never what the sweep spends its leftovers on. The reserved box is in
  # `hosts` from the start, so no line can be handed it.
  local basehost; basehost="$(lq_base_replay_reserve "$key" "$lines
$chained" || true)"
  local i=0 line hosts="$basehost" cand
  [ -n "$basehost" ] && lq_log "base state: $basehost reserved for the base replay at $(printf '%.9s' "$key") BEFORE any line was dispatched"
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    # ONE ASK, NAMING THE BOXES THIS SWEEP ALREADY HOLDS: the allocator refuses them itself, so a
    # box is never handed out twice and no line has to re-probe the fleet to discover that.
    # shellcheck disable=SC2086
    if lq_preprove_needs_box "$tree"; then
      cand="$( fleet_pick_host $hosts )" || cand=""
      [ -n "$cand" ] || { lq_log "pre-prove: out of free boxes; the rest of the sweep waits for the next one"; break; }
      hosts="$hosts $cand"
    else
      cand=""
    fi
    i=$((i + 1))
    local bf="$dir/line-$i.batch"
    printf '%s\n' "$line" >"$bf"
    printf '%s\n' "${cand:-latchkey}" >"$dir/line-$i.host"
    date +%s >"$dir/line-$i.start"   # when this line went to that box, for the status file
    # THE CHAIN THIS SLOT IS THE ROOT OF, if it is one (see lq_slot_root_red). A live single's root
    # is itself: when it is proven red alone, the rungs held behind it are empty.
    printf '%s\n' "$(lq_line_payload "$line")" >"$dir/line-$i.root"
    (
      # `--preprove` AS AN ARGUMENT, not LAND_PREPROVE in the environment. land.sh converts one
      # into the other for a caller who typed the variable, but the argv is what reaches the box —
      # see land.sh's own note — and a sweep whose mode depended on that conversion would be one
      # refactor away from six real landings nobody asked for.
      # THE STAGED ENGINE, whose `here` is this tree (see lq_stage_engine), and WITHOUT the shard
      # fan-out: the sweep's parallelism is across lines, and a fan-out inside each of six pre-proofs
      # would ask the fleet for four boxes apiece.
      # </dev/null: this child is backgrounded while the loop is still READING the list of lines
      # from its heredoc, and a child that inherits that stdin eats the next line — measured: three
      # disjoint lines, two boxes chosen, no "out of free boxes", the third line simply never read.
      lq_dispatch_preprove "$tree" "$cand" "$bf" \
        >"$dir/line-$i.log" 2>&1 </dev/null
      echo $? >"$dir/line-$i.rc"
    ) &
    printf '%s\n' "$!" >"$dir/line-$i.driver"
  done <<EOF
$lines
EOF
  # ── THE CHAINED HELDS, on whatever boxes are left ────────────────────────────────────────────
  # THE BATCH FILE IS THE WHOLE CHAIN, root first: land.sh applies the picks of every line in file
  # order with `cherry-pick -x` and exports the BASE it started from to the gates (land_export_gate_base
  # $base0), so the tree proven is the tip + the predecessor's picks + this line's, with the gates'
  # merge-base at the tip — exactly the tree this line lands into, and exactly the rows the batch
  # will carry. The dependent's own verdict comes out of the box's per-line outcome file, which
  # land.sh's bisect has already attributed line by line.
  local ck ctext
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    # THE CHAIN BEFORE THE BOX. A candidate whose chain no longer resolves must not first be handed
    # a host it then never uses: `fleet_pick_host` is a read-modify-write of a shared cursor, and a
    # box taken and abandoned is a box the next line in this very loop is refused.
    local chain2; chain2="$(lq_chain_of "$line" "$Q" "$tree" "$LAND_CHAIN_DEPTH")" || continue
    [ -n "$chain2" ] || continue
    # shellcheck disable=SC2086
    if lq_preprove_needs_box "$tree"; then
      cand="$( fleet_pick_host $hosts )" || cand=""
      [ -n "$cand" ] || { lq_log "pre-prove: out of free boxes; the chained holds wait for the next sweep"; break; }
      hosts="$hosts $cand"
    else
      cand=""
    fi
    ctext="$(printf '%s' "$chain2" | tail -n1)"
    ck="$(printf '%s' "$chain2" | sed '$d' | lq_chain_key "$key")"
    i=$((i + 1))
    local bf2="$dir/line-$i.batch"
    # A CHAINED PRE-PROOF IS A BATCH OF EXACTLY ONE UNIT, and it is marked as one: a red chain
    # bisected by halves would ask a box to prove a dependent without its predecessor beneath it —
    # a conflict, and a verdict about nothing. Marked, it bisects by PREFIX, and the dependent's own
    # row comes back GREEN, RED (it is the culprit) or HELD (a line before it was), which is exactly
    # what lq_chain_preproof_verdict reads.
    : >"$bf2"
    printf '%s\n' "$chain2" | { u=0; while IFS= read -r cl || [ -n "$cl" ]; do
        [ -n "$cl" ] || continue
        u=$((u + 1)); [ "$u" = 1 ] || printf '#UNIT 1\n' >>"$bf2"
        printf '%s\n' "$cl" >>"$bf2"
      done; }
    printf '%s\n' "${cand:-latchkey}" >"$dir/line-$i.host"
    date +%s >"$dir/line-$i.start"   # when this line went to that box, for the status file
    printf '%s\n' "$ck" >"$dir/line-$i.chainkey"
    printf '%s\n' "$ctext" >"$dir/line-$i.chaintext"
    # THE ROOT OF THE CHAIN THIS RUNG STANDS ON — the first line of the unit, which is what the
    # union's prefix bisect judges first and what a live single of the same chain proves alone.
    printf '%s\n' "$(printf '%s\n' "$chain2" | head -n1)" >"$dir/line-$i.root"
    lq_log "pre-prove: chained $(printf '%.70s' "$ctext") on $(printf '%s' "$chain2" | grep -c .) line(s) at $(printf '%.9s' "$key")"
    (
      lq_dispatch_preprove "$tree" "$cand" "$bf2" \
        >"$dir/line-$i.log" 2>&1 </dev/null
      echo $? >"$dir/line-$i.rc"
    ) &
    printf '%s\n' "$!" >"$dir/line-$i.driver"
  done <<EOF
$chained
EOF
  # ── AND THE BASE ITSELF, IF NOTHING HAS MEASURED THIS TIP ────────────────────────────────────
  # Only when it is unknown, only on a box the lines above did not take, and never when the sweep
  # has no oracle family to ask about. An unmeasured tip is not an emergency — it only means an
  # oracle red is scored RED, which is what the engine did before this existed.
  if [ -n "$basehost" ]; then
    lq_base_red_replay "$tree" "$dir" "$key" "$lines
$chained" "$basehost" || true
  elif [ "${LANDQ_BASE_REPLAY:-1}" = 1 ] && ! lq_base_red_known "$key"; then
    lq_log "base state: no box could be RESERVED for the base replay at $(printf '%.9s' "$key") before the lines went out; the tip stays unmeasured this sweep and an oracle red is NONE:base-unmeasured"
  fi
  lq_log "pre-prove: $i line(s) out on the fleet against $(printf '%.9s' "$key")"
  lq_sweep_watch "$dir" "$i" "$key" "$tree" "$inflight"
  # THE BASE IS LEARNED BEFORE A SINGLE LINE IS SCORED: the per-line verdicts below ask which rows
  # were already red at this tip.
  if [ -f "$dir/base.log" ]; then
    if lq_base_red_learn "$key" "$dir/base.log"; then
      # THE REPLAY'S RESULT, in the same three columns the comparison uses — so "what the base's
      # red on that row was" is a file beside the replay's log, not a re-read of the log.
      lq_base_red_result "$key" "$dir/base.log" "$dir/base.detail" || true
    else
      lq_log "base state: the base replay did not reach the oracle leg; $(printf '%.9s' "$key") stays unmeasured (log: $dir/base.log)"
    fi
  fi

  # RECORD, one row per line, keyed by the tip. A sweep whose box never reported leaves NO row —
  # which reads as NONE, which is "not pre-proven", which is exactly true. A missing verdict is
  # never written down as either colour.
  local j=1
  while [ "$j" -le "$i" ]; do
    # A MOOTED RUNG (see lq_moot_deeper). Its chain's root was proven red while it was still
    # bisecting, so it was stopped on the fleet. NONE — it is exactly as unproven as it was — and
    # NOT lq_front_add'ed: it is not a question the fleet owes an answer to, because the hold it
    # sits under is not being released at this tip whatever any box says.
    if [ -f "$dir/line-$j.moot" ]; then
      lq_log "pre-prove: line $j cancelled — its chain's ROOT was proven red alone; NONE:moot, not re-queued (log: $dir/line-$j.log)"
      j=$((j + 1)); continue
    fi
    local rc; rc="$(cat "$dir/line-$j.rc" 2>/dev/null || true)"
    local text; text="$(head -n1 "$dir/line-$j.batch")"
    # A CHAINED SLOT IS KEYED BY (tip, the predecessor picks) AND SPEAKS FOR THE DEPENDENT ONLY.
    # `key` is the whole ledger key and `text` is the line the row is about — the same two columns
    # an unchained row carries, so every reader (lq_preproved_status, the popper, the prune) reads
    # both kinds with the code it already has.
    local rkey
    if [ -f "$dir/line-$j.chainkey" ]; then
      rkey="$(cat "$dir/line-$j.chainkey")"; text="$(cat "$dir/line-$j.chaintext")"
      case "$(lq_chain_preproof_verdict "$rc" "$dir/line-$j.log" "$dir/line-$j.batch.result" "$text" "$key")" in
        GREEN) printf 'GREEN%s%s%s%s%s%s\n' "$TAB" "$rkey" "$TAB" "$dir/line-$j.log" "$TAB" "$text" >>"$PP"
               lq_log "pre-prove: chained GREEN for $(printf '%.70s' "$text") at $rkey" ;;
        RED)   printf 'RED%s%s%s%s%s%s\n' "$TAB" "$rkey" "$TAB" "$dir/line-$j.log" "$TAB" "$text" >>"$PP" ;;
        NONE:*) lq_log "pre-prove: chained line $j not a verdict on the line; no record written (log: $dir/line-$j.log)" ;;
      esac
      j=$((j + 1)); continue
    fi
    case "$(lq_preproof_verdict "$rc" "$dir/line-$j.log" "$dir/line-$j.batch.result" "$key")" in
      GREEN) printf 'GREEN%s%s%s%s%s%s\n' "$TAB" "$key" "$TAB" "$dir/line-$j.log" "$TAB" "$text" >>"$PP"; lq_front_drop "$text" ;;
      RED)   printf 'RED%s%s%s%s%s%s\n' "$TAB" "$key" "$TAB" "$dir/line-$j.log" "$TAB" "$text" >>"$PP"; lq_front_drop "$text" ;;
      NONE:box)  lq_front_add "$text"
                 # THE BOX IS OUT OF THIS SWEEP'S TABLE. It was reachable when the round was made
                 # and it is not now, and the table is what every remaining allocation reads.
                 fleet_table_drop "$(cat "$dir/line-$j.host" 2>/dev/null || true)"
                 lq_log "pre-prove: line $j lost its BOX mid-proof (reclaimed, or it stopped answering); no verdict on the line — re-queued to the front (log: $dir/line-$j.log)" ;;
      NONE:harness)  lq_front_add "$text"
                 lq_log "pre-prove: line $j died of a HARNESS failure on its box (a give-up the recorder refused), not of anything its picks did; re-queued to the front (log: $dir/line-$j.log)" ;;
      NONE:never-reported) lq_log "pre-prove: line $j never reported; no record written (log: $dir/line-$j.log)" ;;
      NONE:base)  lq_log "pre-prove: line $j red against the BASE (a ceiling the head repairs); recorded NONE, not parked (log: $dir/line-$j.log)" ;;
      NONE:moved) lq_log "pre-prove: line $j refused by the tree-moved guard; re-queued, not parked (log: $dir/line-$j.log)" ;;
    esac
    j=$((j + 1))
  done
  fleet_table_close
  # NO LINE IS ON A BOX ANY MORE, and the status file must not keep saying one is.
  rm -f "$SWEEPPTR"
  lq_log "pre-prove: recorded in $PP"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# WHY A LINE WAS PARKED, AND WHAT THE QUEUE LOOKS LIKE, WITHOUT OPENING A LOG
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# A `#RED-preproof` park named the log and nothing else, so every tick that wanted to know what had
# happened opened a file on a fleet box's copy-back and read for the sentence. The sentence is in
# that log; it is put in the ledger BESIDE the park, so the log stays the evidence and the ledger
# stays readable. The first line that says why, in the order the engine says it: land.sh's own
# verdict, then a gate's FAIL row, then a compiler error.
lq_preproof_reason() { # $1 = log path; prints the one line that says why, or nothing
  local lg="$1" re out
  [ -n "$lg" ] && [ -f "$lg" ] || return 0
  for re in 'land\.sh: RED[^a-z]' '^FAIL ' '^[[:space:]]*error(\[|:)' '^[[:space:]]*(RED|FAILED)[: ]'; do
    out="$(grep -m1 -E "$re" "$lg" 2>/dev/null | tr -d '\r' | cut -c1-200)"
    [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
  done
  return 0
}

# THE STATE OF THE QUEUE IN ONE LINE, written at every loop top, so a tick reads `tail -n 1` of
# target/gate/landq4.status instead of reconstructing the queue from the log. Parked counts BOTH
# kinds of park — the pre-proof's and the landing's — because both are lines that need a human.
lq_status() { # $1 = queue (default $Q), $2 = done ledger (default $D), $3 = tree (default $W)
  local q="${1:-$Q}" d="${2:-$D}" tree="${3:-$W}" live held parked landed tip
  live="$(grep -cE '^--' "$q" 2>/dev/null || true)"
  held="$(grep -cE '^#HOLD' "$q" 2>/dev/null || true)"
  parked="$(grep -cE '^#(RED|PARK)' "$q" 2>/dev/null || true)"
  landed="$(grep -cE '^GREEN ' "$d" 2>/dev/null || true)"
  tip="$(git -C "$tree" rev-parse --short HEAD 2>/dev/null)"
  printf 'live %s held %s parked %s landed %s tip %s\n' \
    "${live:-0}" "${held:-0}" "${parked:-0}" "${landed:-0}" "${tip:-?}"
}


# THE STATUS FILE'S BODY, kept as one string so the function that writes it stays a function and the
# shell never has to carry a heredoc through a subshell. Every field is read from a file the runner
# already writes; nothing here asks the fleet or the network anything.
LQ_STATUS_PY='
import json, os, time, glob

E = os.environ
def rd(p):
    try:
        return open(p, encoding="utf-8", errors="replace").read()
    except Exception:
        return ""
def count(p, pred):
    return sum(1 for l in rd(p).splitlines() if pred(l))

q = E["LQJ_Q"]
d = {
    "written": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "written_epoch": int(time.time()),
    "pid": int(E.get("LQJ_PID") or 0),
    "loop": int(E.get("LQJ_LOOP") or 0),
    "tip": E.get("LQJ_TIP") or "?",
    "engine_sha": E.get("LQJ_ENGINE") or "?",
    "prove_per_box": E.get("LQJ_PPB") or "?",
    "preprove_lines": E.get("LQJ_PPL") or "?",
    "live": count(q, lambda l: l.startswith("--")),
    "held": count(q, lambda l: l.startswith("#HOLD")),
    "parked": count(q, lambda l: l.startswith("#RED") or l.startswith("#PARK")),
    "landed": count(E["LQJ_D"], lambda l: l.startswith("GREEN ")),
}

bf = E.get("LQJ_BATCH") or ""
batch = {"lines": [], "legs": [], "started_epoch": None}
if bf and os.path.exists(bf):
    batch["lines"] = [l for l in rd(bf).splitlines() if l.strip() and not l.lstrip().startswith("#")]
    try:
        batch["started_epoch"] = int(E.get("LQJ_BSTART") or 0) or int(os.path.getmtime(bf))
    except Exception:
        batch["started_epoch"] = None
    legs, seen = [], set()
    for l in rd(bf + ".log").splitlines():
        if l.startswith("land.sh: leg "):
            n = l.split("land.sh: leg ", 1)[1].split()[0]
            if n not in seen:
                seen.add(n); legs.append(n)
    batch["legs"] = legs
d["batch"] = batch

sweep = []
ptr = (rd(E.get("LQJ_SWEEPPTR") or "").strip() or "")
if ptr and os.path.isdir(ptr):
    for hf in sorted(glob.glob(os.path.join(ptr, "line-*.host"))):
        stem = hf[: -len(".host")]
        if os.path.exists(stem + ".rc") or os.path.exists(stem + ".moot"):
            continue
        line = (rd(stem + ".chaintext").strip() or rd(stem + ".batch").split("\n")[0].strip())
        try:
            st = int(rd(stem + ".start").strip() or 0) or int(os.path.getmtime(hf))
        except Exception:
            st = None
        sweep.append({"box": rd(hf).strip() or "?", "line": line, "started_epoch": st})
d["sweep"] = sweep

backoff = {}
for l in rd(E["LQJ_FAULTS"]).splitlines():
    f = l.split("\t")
    if len(f) >= 2 and f[0]:
        try:
            backoff[f[0]] = int(f[1])
        except ValueError:
            pass
d["backoff"] = backoff
faults = []
for l in rd(E["LQJ_RING"]).splitlines():
    f = l.split("\t")
    if len(f) >= 2:
        faults.append({"at": f[0], "class": f[1], "text": f[2] if len(f) > 2 else ""})
d["faults"] = faults[-5:]

pages, direct = [], None
for l in rd(E["LQJ_PAGE"]).splitlines():
    f = l.split("\t")
    if len(f) >= 2:
        pg = {"at": f[0], "kind": f[1], "text": f[2] if len(f) > 2 else ""}
        pages.append(pg)
        if pg["kind"] == "direct-edit":
            direct = "%s %s" % (pg["at"], pg["text"])
d["pages"] = pages[-5:]
d["direct_edit"] = direct

out = E["LQJ_OUT"]
tmp = out + ".tmp"
fh = open(tmp, "w", encoding="utf-8")
json.dump(d, fh, indent=1, sort_keys=True)
fh.write("\n")
fh.close()
os.replace(tmp, out)
'
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# ONE STATUS FILE, AND NOTHING TAILS A LOG (F7)
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# The hourly tick read five symlinked files with tail-headed pipelines and still could not say what
# the runner was doing; agents were parked on monitors; every "what is it up to" cost somebody a
# reconstruction from a 40 MB log. So the runner writes ONE file, every loop and at every state
# change, and `landq-ctl status` renders it in twenty-five lines: nobody needs the log again.
#
# WRITTEN TEMP+MV, always. A reader that catches the file half-written does not get a slow answer,
# it gets a CONFIDENT WRONG one — and a tick that says "live 0" because it read between two writes
# is how a queue gets declared empty while it is a hundred and twenty deep.
#
# WHAT IT CARRIES: the tip and the engine sha that is running; live/held/parked/landed; the batch in
# flight with its lines, its legs and when it started; every line on a box in the sweep with its box
# and when it went there; the backoff counter per fault class; the last five faults with their
# times; the fleet's per-box proof slot count AS READ (never a constant — the fleet is moving from
# c7a.8xlarge at one proof per box to c7a.16xlarge at two, and a status file that hard-coded either
# would be lying within the day); and the DIRECT-EDIT page flag.
STATUSJ="${LANDQ_STATUS_JSON:-$W/target/gate/landq.status.json}"
SWEEPPTR="${LANDQ_SWEEP_PTR:-$W/target/gate/landq4.sweep}"
LQ_LOOP=0
# THE ENGINE THAT IS RUNNING, not the tree it is landing into. The scripts may be a checkout or a
# staged copy under land-fanout-<sha>/scripts; both are asked, in that order, and neither is guessed.
lq_engine_sha() {
  local g b
  g="$(git -C "$SCRIPTS" rev-parse --short HEAD 2>/dev/null || true)"
  [ -n "$g" ] && { printf '%s\n' "$g"; return 0; }
  b="$(basename "$(dirname "$SCRIPTS")" 2>/dev/null || true)"
  case "$b" in land-fanout-*) printf '%s\n' "$(printf '%.9s' "${b#land-fanout-}")"; return 0 ;; esac
  printf '?\n'
}
# THE FLEET'S PER-BOX PROOF SLOT COUNT, AS READ. The environment wins (it is what the sweep and the
# power script actually use); failing that, the number the staged library defaults to is read out of
# the library itself. A constant here would be a measurement nobody took.
lq_prove_per_box() {
  local v="${BUSBAR_PROVE_PER_BOX:-}" f
  [ -n "$v" ] && { printf '%s\n' "$v"; return 0; }
  for f in "$W/target/gate/ci-remote-lib.sh" "$SCRIPTS/ci-remote-lib.sh"; do
    [ -f "$f" ] || continue
    v="$(sed -n 's/^PROVE_PER_BOX="\${BUSBAR_PROVE_PER_BOX:-\([0-9]*\)}"$/\1/p' "$f" | head -n1)"
    [ -n "$v" ] && { printf '%s\n' "$v"; return 0; }
  done
  printf '?\n'
}
lq_status_json() { # $1 = the batch file in flight (optional), $2 = when it started (epoch, optional)
  local bf="${1:-}" bstart="${2:-}" out="${STATUSJ}"
  mkdir -p "$(dirname "$out")" 2>/dev/null || true
  LQJ_OUT="$out" LQJ_Q="$Q" LQJ_D="$D" LQJ_FAULTS="$FAULTS" LQJ_RING="$FAULTRING" \
  LQJ_PAGE="$PAGE" LQJ_BATCH="$bf" LQJ_BSTART="$bstart" LQJ_SWEEPPTR="$SWEEPPTR" \
  LQJ_TIP="$(git -C "$W" rev-parse --short HEAD 2>/dev/null || true)" \
  LQJ_ENGINE="$(lq_engine_sha)" LQJ_PPB="$(lq_prove_per_box)" LQJ_PPL="$PREPROVE_LINES" \
  LQJ_LOOP="$LQ_LOOP" LQJ_PID="$$" \
  python3 -c "$LQ_STATUS_PY" || return 1
  return 0
}
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE POPPER
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# Pre-proven-green lines first, and ONLY those while any exist at this tip: they are the lines with
# evidence behind them, and running them together is what makes the larger batch worth taking. A
# line pre-proven RED at this tip is parked `#RED-preproof <log>` rather than popped. Everything
# else is popped exactly as it always was, in queue order.
lq_pop() { # $1 = tip, $2 = batch size, $3 = batch file out, $4 = keep file out; prints the count
  local tip="$1" b="$2" batch="$3" keep="$4" line st n=0 greens=0 claimed="" gates=0 alone=0 f moves="" m qarows=0 r bfix=0
  local cand chained csha chain cdep canc ckey cin ca parked="$TAB" ufiles uroot
  : >"$batch"; : >"$keep"; : >"$batch.chain"
  greens="$(awk -F"$TAB" -v tip="$tip" '$1 == "GREEN" && $2 == tip {print $4}' "$PP" 2>/dev/null | sort -u | grep -c . || true)"
  case "$greens" in ''|*[!0-9]*) greens=0 ;; esac
  local anychain=0
  awk -F"$TAB" -v tip="$tip" 'index($2, tip "@") == 1 { f = 1; exit } END { exit !f }' "$PP" 2>/dev/null && anychain=1
  while IFS= read -r line || [ -n "$line" ]; do
    cand=""; chained=0
    case "$line" in
      ''|'#'*)
        # ── A CHAINED HELD LINE MAY RIDE ITS PREDECESSOR'S BATCH ──────────────────────────────
        # Only beside the predecessor, only after it, and only on a chained green taken at THIS tip
        # over THESE predecessor picks. The tag is not struck and the queue is not rewritten: this
        # is a pop-time decision, and a dependent whose predecessor is not in this batch is written
        # back to the keep file byte for byte, tag and all.
        # THE CHEAP GATE FIRST. Resolving a chain costs a `git diff` per pick per member, and the
        # queue is 121 held lines deep: with no chained row at this tip in the ledger there is
        # nothing a chain could be admitted ON, and nothing parked could drop, so none is walked.
        csha=""; chain=""
        if [ "$anychain" = 1 ]; then
          case "$line" in '#HOLD-after-'*) csha="$(lq_hold_after_sha "$line")" ;; esac
        fi
        if [ -n "$csha" ]; then
          chain="$(lq_chain_of "$line" "$Q" "$W" "$LAND_CHAIN_DEPTH")" || chain=""
        fi
        if [ -z "$chain" ]; then printf '%s\n' "$line" >>"$keep"; continue; fi
        cdep="$(printf '%s' "$chain" | tail -n1)"
        canc="$(printf '%s' "$chain" | sed '$d')"
        ckey="$(printf '%s\n' "$canc" | lq_chain_key "$tip")"
        # EVERY ancestor already in this batch, in order — else there is no chain to ride.
        cin=1
        while IFS= read -r ca; do
          [ -n "$ca" ] || continue
          case "$parked" in *"$TAB$ca$TAB"*) cin=2; break ;; esac
          grep -qxF -- "$ca" "$batch" || { cin=0; break; }
        done <<EOF
$canc
EOF
        if [ "$cin" = 2 ]; then
          # ITS PREDECESSOR WAS PARKED THIS POP. The line goes back to held and its chained verdict
          # goes with it: a green over picks nobody is landing is evidence about nothing.
          LQ_AWK_T="$cdep" awk -F"$TAB" '!($4 == ENVIRON["LQ_AWK_T"] && index($2, "@") > 0)' "$PP" >"$PP.tmp" 2>/dev/null && mv "$PP.tmp" "$PP"
          lq_log "chained: $(printf '%.80s' "$cdep") stays held — its predecessor was parked; verdict dropped"
          printf '%s\n' "$line" >>"$keep"; continue
        fi
        if [ "$cin" != 1 ] || [ "$(lq_preproved_status "$ckey" "$cdep")" != GREEN ]; then
          printf '%s\n' "$line" >>"$keep"; continue
        fi
        cand="$cdep"; chained=1 ;;
      --*) cand="$line" ;;
      *) printf '#MALFORMED %s\n' "$line" >>"$keep"
         lq_log "queue lint: parked a malformed line: $(printf '%.80s' "$line")"; continue ;;
    esac
    if [ "$chained" = 1 ]; then
      # ONE UNIT (see "WHAT MAY SHARE A BATCH"). The candidate joins the unit its chain already
      # holds in this batch: the files of its ancestors are not a clash, the one-gate-line and
      # ceiling-move rules are the unit's and already taken, and everything the batch has claimed
      # OUTSIDE this unit refuses it exactly as before.
      ufiles="$(lq_unit_files "$canc" "$W")"
      uroot="$(lq_batch_index "$batch" "$(printf '%s\n' "$chain" | head -n1)")"
      case "$uroot" in ''|*[!0-9]*) uroot="" ;; esac
      if [ -n "$uroot" ] && [ "$n" -lt "$b" ] && lq_may_join "$cand" "$W" "$n" "$claimed" "$gates" "$alone" "$moves" "$qarows" "$bfix" "$ufiles"; then
        printf '#UNIT %s\n' "$uroot" >>"$batch"
        printf '%s\n' "$cand" >>"$batch"; n=$((n + 1))
        printf '%s%s%s%s%s\n' "$cand" "$TAB" "$line" "$TAB" "$(printf '%s' "$canc" | tail -n1)" >>"$batch.chain"
        lq_log "chained: $cand after $csha (unit $uroot, line $n of the batch)"
        r="$(lq_line_qa_rows "$cand" "$W")"; [ "$r" = 0 ] || qarows=1
        while IFS= read -r f; do [ -n "$f" ] && claimed="$claimed$f$TAB"; done <<EOF
$(lq_line_files "$cand" "$W")
EOF
        while IFS= read -r m; do [ -n "$m" ] && [ "$m" != "?" ] && moves="$moves$m$TAB"; done <<EOF
$(lq_line_ceiling_moves "$cand" "$W")
EOF
        lq_line_touches_gates "$cand" "$W" && gates=1
        lq_line_was_red "$cand" && alone=1
      else printf '%s\n' "$line" >>"$keep"; fi
      continue
    fi
    st="$(lq_preproved_status "$tip" "$line")"
    if [ "$st" = RED ]; then
      # PARKED WITH ITS LOG, so the marker names where the evidence is rather than only that there
      # was some. A `#RED-preproof` line is requeued the same way a `#RED` one is.
      local lg; lg="$(LQ_AWK_T="$line" awk -F"$TAB" -v tip="$tip" '$1 == "RED" && $2 == tip && $4 == ENVIRON["LQ_AWK_T"] {print $3}' "$PP" 2>/dev/null | tail -1)"
      # ...UNLESS THE RED IS THE BASE'S (rule 2c, made real). lq_preproof_verdict rules on this at
      # SWEEP time, but the popper parked every recorded RED regardless — so a row written by an
      # older engine, or by a sweep whose log grew its base sentence after the verdict was taken,
      # parked a line that nothing is wrong with. The log is read again HERE, against the tree, and
      # a base-state red is recorded NONE: the line stays live and unmarked. (Audit 14.)
      if lq_base_state_red "$lg" "$W"; then
        lq_log "pre-prove RED at $(printf '%.9s' "$tip") is the BASE's (a ceiling the head repairs); NONE, left live: $(printf '%.80s' "$line") (log: $lg)"
        st=NONE
      else
        printf '#RED-preproof %s %s\n' "${lg:-no-log}" "$line" >>"$keep"
        parked="$parked$line$TAB"   # every line chained behind it goes back to held (see above)
        local why; why="$(lq_preproof_reason "$lg")"
        lq_log "pre-prove RED at $(printf '%.9s' "$tip"): parked $(printf '%.80s' "$line") (log: ${lg:-none})"
        lq_log "pre-prove RED reason: ${why:-<no reason line in the log>}"
        continue
      fi
    fi
    if [ "$greens" -gt 0 ] && [ "$st" != GREEN ]; then
      printf '%s\n' "$line" >>"$keep"; continue
    fi
    if [ "$n" -lt "$b" ] && lq_may_join "$line" "$W" "$n" "$claimed" "$gates" "$alone" "$moves" "$qarows" "$bfix"; then
      printf '%s\n' "$line" >>"$batch"; n=$((n + 1))
      r="$(lq_line_qa_rows "$line" "$W")"; [ "$r" = 0 ] || qarows=1
      lq_line_is_base_fix "$line" "$W" && bfix=1
      while IFS= read -r f; do [ -n "$f" ] && claimed="$claimed$f$TAB"; done <<EOF
$(lq_line_files "$line" "$W")
EOF
      while IFS= read -r m; do [ -n "$m" ] && [ "$m" != "?" ] && moves="$moves$m$TAB"; done <<EOF
$(lq_line_ceiling_moves "$line" "$W")
EOF
      lq_line_touches_gates "$line" "$W" && gates=1
      lq_line_was_red "$line" && alone=1
    else printf '%s\n' "$line" >>"$keep"; fi
  done <"$Q"
  echo "$n"
}

# HOW A RED LINE GOES BACK, when the line rode a chain into the batch.
#
# A chained line was popped as a PAYLOAD — the `#HOLD-after-<sha>` tag is not in the batch file,
# because land.sh is being asked to land it — and `#RED <payload>` would put it back into the queue
# with its hold gone. If its PREDECESSOR went green the hold is moot (the sha is on the tree, and
# rule (c) would strike the tag on the next loop), so the ordinary `#RED` park is right. If the
# predecessor did NOT go green, the line is exactly as held as it was an hour ago and its own red is
# a red over a union that was never the union it will land in: it goes back HELD, tag and all, and
# its chained verdict is dropped. Never orphaned live, never orphaned un-held.
lq_park_line() { # $1 = the line text as the batch result names it, $2 = batch file, $3 = red file, $4 = its outcome (default RED)
  local text="$1" bf="$2" red="$3" st="${4:-RED}" held="" pred="" pst=""
  if [ -f "$bf.chain" ]; then
    held="$(LQ_AWK_T="$text" awk -F"$TAB" '$1 == ENVIRON["LQ_AWK_T"] { h = $2 } END { print h }' "$bf.chain")"
    pred="$(LQ_AWK_T="$text" awk -F"$TAB" '$1 == ENVIRON["LQ_AWK_T"] { p = $3 } END { print p }' "$bf.chain")"
  fi
  if [ -n "$held" ] && [ -n "$pred" ] && [ -f "$bf.result" ]; then
    pst="$(LQ_AWK_T="$pred" awk -F"$TAB" '$2 == ENVIRON["LQ_AWK_T"] { s = $1 } END { print s }' "$bf.result")"
  fi
  if [ -n "$held" ] && [ "$pst" != GREEN ]; then
    printf '%s\n' "$held" >>"$red"
    LQ_AWK_T="$text" awk -F"$TAB" '!($4 == ENVIRON["LQ_AWK_T"] && index($2, "@") > 0)' "$PP" >"$PP.tmp" 2>/dev/null && mv "$PP.tmp" "$PP"
    lq_log "chained: $(printf '%.80s' "$text") back to HELD — its predecessor was not green; verdict dropped"
    return 0
  fi
  # A HELD OUTCOME IS NEVER A RED PARK. land.sh says HELD for a line inside a unit that stands
  # after the culprit: nothing of it was proven and nothing of it was applied. With no chain map to
  # put it back under its hold (a batch file written by an older engine), it goes back exactly as
  # land.sh received it — live and unmarked — rather than being parked for a red that is not its.
  if [ "$st" = HELD ]; then
    printf '%s\n' "$text" >>"$red"
    lq_log "unit: $(printf '%.80s' "$text") was never proven (a line before it in its unit was the culprit); requeued unchanged"
    return 0
  fi
  printf '#RED %s\n' "$text" >>"$red"
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# CI-AWARE PUSH — unchanged in substance from the runner this replaces.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# A RUN THAT HAS SAT `queued` FOR AN HOUR IS NOT RUNNING. The tip's CI umbrella (label busbar-xl)
# sat queued from 22:39 because slot-branch proof runs held every busbar-xl runner, and a push
# deferred on "ci still running" would have kept every landing local for as long as that lasted.
# Queued past 60 minutes reads as `none`: there is no verdict to wait for. `in_progress` still waits.
# ...AND AN `in_progress` RUN ON THE PREVIOUS TIP IS NOT A REASON TO HOLD A PUSH THIS WORKFLOW IS
# ABOUT TO CANCEL. The queued rule above has an escape (60 minutes); `in_progress` had none, so a
# tip whose CI took two hours deferred every landing behind it for two hours — while .github/
# workflows/ci.yml carries
#
#     concurrency:
#       group: ci-${{ github.ref }}
#       cancel-in-progress: true
#
# which means the push the runner is deferring would have CANCELLED that run anyway. The wait buys a
# verdict that GitHub throws away the moment the wait ends. So the workflow is READ, on the tree, and
# `in_progress` reads as "no verdict to wait for" exactly when the workflow says so: the group must be
# keyed by the ref (a group that is not per-ref cancels somebody else's run, not this branch's) and
# `cancel-in-progress` must be true. Anything else still waits, as it always did.
LQ_CI_WORKFLOW="${LANDQ_CI_WORKFLOW:-.github/workflows/ci.yml}"
lq_ci_cancels_in_progress() { # $1 = tree (default $W); 0 when a push to this branch cancels the run in progress on it
  local tree="${1:-$W}" blk
  blk="$(grep -A2 '^concurrency:' "$tree/$LQ_CI_WORKFLOW" 2>/dev/null)"
  [ -n "$blk" ] || return 1
  printf '%s\n' "$blk" | grep -qE '^[[:space:]]*cancel-in-progress:[[:space:]]*true[[:space:]]*$' || return 1
  printf '%s\n' "$blk" | grep -qE '^[[:space:]]*group:.*(github\.ref|github\.head_ref)' || return 1
  return 0
}
lq_epoch() { # $1 = ISO-8601 UTC stamp (2026-09-10T22:39:00Z); prints epoch seconds, or nothing
  # GNU date takes -d <stamp>; BSD date's -d is something else entirely (it would print NOW).
  if date --version >/dev/null 2>&1; then date -u -d "$1" +%s 2>/dev/null || true
  else date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s 2>/dev/null || true; fi
}
lq_ci_verdict() { # $1 = "<status> <conclusion> <createdAt>" as gh printed it, $2 = now (epoch; default: now), $3 = 1 when CI cancels its own in-progress run on this ref
  local st con created now="${2:-$(date +%s)}" cancels="${3:-}" at age
  st="${1%% *}"; con="${1#* }"; con="${con%% *}"; created="${1##* }"
  [ "$created" = "$1" ] && created=""
  case "$st $con" in
    "completed success") echo success ;;
    "completed failure"|"completed timed_out") echo failure ;;
    "completed cancelled") echo cancelled ;;
    " "|"null null") echo none ;;
    "in_progress "*)
      # The push cancels it; there is nothing to wait for. Its own verdict, not `none`, so the
      # ledger says WHY this push went over a run that was still going.
      [ "$cancels" = 1 ] && { echo cancelled-in-progress; return 0; }
      echo running ;;
    "queued "*)
      at="$(lq_epoch "$created")"
      if [ -n "$at" ]; then age=$(( now - at )); [ "$age" -gt 3600 ] && { echo none; return 0; }; fi
      echo running ;;
    *) echo running ;;
  esac
}
ci_conclusion() { # $1 = sha ; prints: success|failure|cancelled|cancelled-in-progress|running|none
  local out cancels=""
  lq_ci_cancels_in_progress "$W" && cancels=1
  out="$(gh run list -R "$REPO" --workflow CI --commit "$1" --limit 1 \
        --json status,conclusion,createdAt --jq '.[0] | "\(.status) \(.conclusion) \(.createdAt)"' 2>/dev/null)"
  lq_ci_verdict "$out" "" "$cancels"
}

try_push() {
  local last head c
  last="$(git -C "$W" rev-parse "origin/$BR")"
  head="$(git -C "$W" rev-parse HEAD)"
  [ "$last" = "$head" ] && return 0
  c="$(ci_conclusion "$last")"
  case "$c" in
    cancelled-in-progress)
      lq_log "push over in_progress CI on $(printf '%.8s' "$last"): cancelled by CI's own concurrency"
      git -C "$W" push -q origin "HEAD:$BR" \
        && lq_log "pushed $(git -C "$W" rev-parse --short HEAD) (ci of $(printf '%.8s' "$last"): in_progress, cancelled by the push)" ;;
    success|none|cancelled)
      git -C "$W" push -q origin "HEAD:$BR" \
        && lq_log "pushed $(git -C "$W" rev-parse --short HEAD) (ci of $(printf '%.8s' "$last"): $c)" ;;
    running) lq_log "push deferred: ci still running on $(printf '%.8s' "$last")" ;;
    failure)
      if [ -f "$W/target/gate/PUSH-ANYWAY" ]; then
        git -C "$W" push -q origin "HEAD:$BR" \
          && lq_log "pushed $(git -C "$W" rev-parse --short HEAD) (ci RED on $(printf '%.8s' "$last"), PUSH-ANYWAY set)"
      else
        [ -f "$W/target/gate/CI-RED" ] || {
          lq_log "=== CI RED on $(printf '%.8s' "$last"); pushes held, landings continue locally (touch PUSH-ANYWAY to override)"
          echo "CI-RED $last" >>"$D"; }
        touch "$W/target/gate/CI-RED"
      fi ;;
  esac
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# --selftest: the decisions above, proven RED before anything is called green
# ──────────────────────────────────────────────────────────────────────────────────────────────────
lq_selftest() {
  local root; root="$(mktemp -d "$LAND_TMP/landq4-selftest.XXXXXX")"
  local repo="$root/repo" fails=0
  # THE ENGINE'S SOURCE WITHOUT ITS SELF-TEST. A `grep -c … "$0"` that asks whether the runner does
  # something counts the line that ASSERTS it as well as the line that does it; this file with the
  # self-test cut out of it is the implementation and nothing else.
  local LQ_SRC="$root/src-nosel.sh"
  sed '/^lq_selftest() {/,/^}$/d' "$0" >"$LQ_SRC"
  mkdir -p "$repo"
  _t() { # $1 = name, $2 = expected, $3 = got
    if [ "$2" = "$3" ]; then printf '  ok   %-52s\n' "$1"
    else printf '  FAIL %-52s (wanted [%s], got [%s])\n' "$1" "$2" "$3"; fails=$((fails + 1)); fi
  }
  git -C "$repo" init -q
  git -C "$repo" config user.email landq@selftest; git -C "$repo" config user.name landq
  git -C "$repo" config commit.gpgsign false
  mkdir -p "$root/nohooks"; git -C "$repo" config core.hooksPath "$root/nohooks"
  printf 'x\n' >"$repo/base.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm base
  printf 'a\n' >"$repo/a.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm a
  local ha; ha="$(git -C "$repo" rev-parse HEAD)"
  printf 'b\n' >"$repo/b.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm b
  local hb; hb="$(git -C "$repo" rev-parse HEAD)"
  printf 'a2\n' >>"$repo/a.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm a-again
  local ha2; ha2="$(git -C "$repo" rev-parse HEAD)"
  printf 'b2\n' >>"$repo/b.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm b-again
  local hb2; hb2="$(git -C "$repo" rev-parse HEAD)"
  printf 'c\n' >"$repo/c.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm c
  local hc; hc="$(git -C "$repo" rev-parse HEAD)"
  mkdir -p "$repo/xtask/src/gates"
  printf 'g1\n' >"$repo/xtask/src/gates/g1.rs"; git -C "$repo" add -A; git -C "$repo" commit -qm g1
  local hg1; hg1="$(git -C "$repo" rev-parse HEAD)"
  printf 'g2\n' >"$repo/xtask/src/gates/g2.rs"; git -C "$repo" add -A; git -C "$repo" commit -qm g2
  local hg2; hg2="$(git -C "$repo" rev-parse HEAD)"
  # The ceilings: a base with two files, then a line that DECLARES a raise of a kind-isolation figure
  # (the entry lives in construction.toml, as they all do), and a line that LOWERS that same figure.
  mkdir -p "$repo/qa"
  printf '[gate]\nx = 1\n\n[rules.legacy-reach]\nceiling = 92\n' >"$repo/qa/construction.toml"
  printf '[rules.x]\nfigure = "47"\n' >"$repo/qa/kind-isolation.toml"
  git -C "$repo" add -A; git -C "$repo" commit -qm ceilings-base
  local hcb; hcb="$(git -C "$repo" rev-parse HEAD)"
  printf '[gate]\nx = 1\n\n[gate.ceiling_raises."rules.x.figure"]\nfile = "qa/kind-isolation.toml"\nfrom = 47\nto = 60\nbecause = "first gating figure"\n\n[rules.legacy-reach]\nceiling = 92\n' >"$repo/qa/construction.toml"
  git -C "$repo" add -A; git -C "$repo" commit -qm declares-raise
  local hraise; hraise="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q "$hcb"
  printf '[rules.x]\nfigure = "40"\n' >"$repo/qa/kind-isolation.toml"
  git -C "$repo" add -A; git -C "$repo" commit -qm lowers-figure
  local hlower; hlower="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q "$hcb"
  printf '[gate]\nx = 1\n\n[rules.legacy-reach]\nceiling = 80\n' >"$repo/qa/construction.toml"
  git -C "$repo" add -A; git -C "$repo" commit -qm lowers-other
  local hother; hother="$(git -C "$repo" rev-parse HEAD)"
  # A FIGURE-ONLY re-pin of construction.toml (no row added or removed) — what K1 lands by measurement.
  git -C "$repo" checkout -q "$hcb"
  printf '[gate]\nx = 2\n\n[rules.legacy-reach]\nceiling = 92\n' >"$repo/qa/construction.toml"
  git -C "$repo" add -A; git -C "$repo" commit -qm repins-figure
  local hfig; hfig="$(git -C "$repo" rev-parse HEAD)"
  # A line that adds a `[[minted]]` row beside a figure: a row diff, never shared.
  git -C "$repo" checkout -q "$hcb"
  printf '[gate]\nx = 1\n\n[[minted]]\nkind = "k"\n\n[rules.legacy-reach]\nceiling = 92\n' >"$repo/qa/construction.toml"
  git -C "$repo" add -A; git -C "$repo" commit -qm mints-row
  local hmint; hmint="$(git -C "$repo" rev-parse HEAD)"
  # Two lines that re-pin a figure BESIDE code (what K1 lands): figure-only qa diffs, not base fixes.
  git -C "$repo" checkout -q "$hcb"
  printf '[gate]\nx = 2\n\n[rules.legacy-reach]\nceiling = 92\n' >"$repo/qa/construction.toml"; printf 'k1\n' >"$repo/k1.txt"
  git -C "$repo" add -A; git -C "$repo" commit -qm repins-with-code
  local hfig2; hfig2="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q "$hcb"
  printf '[gate]\nx = 1\n\n[rules.legacy-reach]\nceiling = 90\n' >"$repo/qa/construction.toml"; printf 'm\n' >"$repo/m.txt"
  git -C "$repo" add -A; git -C "$repo" commit -qm repins-other-with-code
  local hfigB; hfigB="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q -f master 2>/dev/null || git -C "$repo" checkout -q -f main 2>/dev/null || git -C "$repo" checkout -q -f "$hg2"

  echo "landq4 selftest: a line's file set"
  _t "the files of a one-pick line"  "a.txt"  "$(lq_line_files "--prove $ha" "$repo")"
  _t "an unresolvable pick is UNKNOWN, not empty" "?" "$(lq_line_files "--prove deadbee" "$repo")"
  _t "a line with no picks is UNKNOWN, not empty" "?" "$(lq_line_files "--tests busbar" "$repo")"

  echo "landq4 selftest: the disjoint pick (queue order kept, overlaps left where they are)"
  local qf="$root/queue.txt"
  printf -- '--prove %s\n--prove %s\n--prove %s\n--prove %s\n' "$ha" "$hb" "$ha2" "$hc" >"$qf"
  # a and b and c are disjoint; a2 touches a.txt again and must NOT join a's sweep.
  _t "three disjoint lines out of four" \
     "$(printf -- '--prove %s\n--prove %s\n--prove %s' "$ha" "$hb" "$hc")" \
     "$(lq_disjoint_lines 6 "$qf" "$repo")"
  _t "the cap is honoured" \
     "$(printf -- '--prove %s\n--prove %s' "$ha" "$hb")" \
     "$(lq_disjoint_lines 2 "$qf" "$repo")"
  # A COMMENT IS NOT A LINE. A parked #RED line must not be handed to a box.
  printf -- '#RED --prove %s\n--prove %s\n' "$ha" "$hb" >"$root/queue2.txt"
  _t "a parked line is not swept" "$(printf -- '--prove %s' "$hb")" \
     "$(lq_disjoint_lines 6 "$root/queue2.txt" "$repo")"

  echo "landq4 selftest: the pre-prove ledger (a record is about ONE tip and no other)"
  local pp="$root/preproved.txt"
  printf 'GREEN\ttip1\t/l/1\t--prove %s\nRED\ttip1\t/l/2\t--prove %s\n' "$ha" "$hb" >"$pp"
  _t "green at its own tip"        GREEN "$(lq_preproved_status tip1 "--prove $ha" "$pp")"
  _t "red at its own tip"          RED   "$(lq_preproved_status tip1 "--prove $hb" "$pp")"
  # THE CASE THE TIP COLUMN EXISTS FOR. The same line, the same verdict, a tip that has since moved:
  # the record says nothing about the tree the runner is on now, so it must read as NONE.
  _t "green at a DIFFERENT tip is NONE" NONE "$(lq_preproved_status tip2 "--prove $ha" "$pp")"
  _t "a line with no row at all is NONE" NONE "$(lq_preproved_status tip1 "--prove $hc" "$pp")"
  _t "no ledger at all is NONE"    NONE "$(lq_preproved_status tip1 "--prove $ha" "$root/absent.txt")"

  echo "landq4 selftest: the batch size (8 only when 8 lines are pre-proven at THIS tip)"
  _bs() { local n="$1"; shift; ( LAND_BATCH="$n"; lq_batch_size "$@" ); }
  _t "no ledger -> the ordinary batch" 4 "$(_bs "" tip1 "$root/absent.txt")"
  _t "two greens -> the ordinary batch" 4 "$(_bs "" tip1 "$pp")"
  local i=0; : >"$root/pp8.txt"
  while [ "$i" -lt 8 ]; do printf 'GREEN\ttip1\t/l/%s\t--prove line%s\n' "$i" "$i" >>"$root/pp8.txt"; i=$((i + 1)); done
  _t "eight greens at this tip -> 8"    8 "$(_bs "" tip1 "$root/pp8.txt")"
  _t "eight greens at ANOTHER tip -> the ordinary batch" 4 "$(_bs "" tip2 "$root/pp8.txt")"
  # THE DEFAULT MOVES; AN EXPLICIT NUMBER DOES NOT. An operator who wrote LAND_BATCH=6 gets 6,
  # eight pre-proven lines or none.
  _t "an explicit LAND_BATCH=6 with eight greens is 6"  6 "$(_bs 6 tip1 "$root/pp8.txt")"
  # LAND_BATCH IS A CEILING. Six with no ledger used to be six; the audit's rule is that a batch above
  # four is only taken when that many lines are green at this tip, whatever the environment says.
  _t "an explicit LAND_BATCH=6 with no ledger is 4"      4 "$(_bs 6 tip1 "$root/absent.txt")"
  _t "an explicit LAND_BATCH=8 with two greens is 4"     4 "$(_bs 8 tip1 "$pp")"
  _t "an explicit LAND_BATCH=8 with eight greens is 8"   8 "$(_bs 8 tip1 "$root/pp8.txt")"
  _t "an explicit LAND_BATCH=3 is 3 (smaller is always allowed)" 3 "$(_bs 3 tip1 "$root/absent.txt")"
  # Eight ROWS but only four distinct lines is not eight pre-proven lines. A sweep re-run against
  # the same tip appends, and counting rows would let one line stand in for the batch.
  : >"$root/pp8dup.txt"
  i=0; while [ "$i" -lt 8 ]; do printf 'GREEN\ttip1\t/l/%s\t--prove line%s\n' "$i" "$((i % 4))" >>"$root/pp8dup.txt"; i=$((i + 1)); done
  _t "eight rows over four lines -> the ordinary batch" 4 "$(_bs "" tip1 "$root/pp8dup.txt")"

  echo "landq4 selftest: the sweep does not re-prove a green line, and claims its files first"
  local savedPP0="$PP"; PP="$pp"   # GREEN tip1 for a; RED tip1 for b
  # a is green at tip1: not swept again; a2 touches a.txt, which a's green already claims; b (red at
  # tip1, but the ledger's colour is not the sweep's business) and c are what is left.
  _t "a green line is skipped and its files stay claimed" \
     "$(printf -- '--prove %s\n--prove %s' "$hb" "$hc")" \
     "$(lq_disjoint_lines 6 "$qf" "$repo" tip1)"
  _t "at another tip the ledger is not consulted" \
     "$(printf -- '--prove %s\n--prove %s\n--prove %s' "$ha" "$hb" "$hc")" \
     "$(lq_disjoint_lines 6 "$qf" "$repo" tip2)"
  PP="$savedPP0"

  echo "landq4 selftest: what may share a batch (one file, one judge, one red-once line)"
  local savedW="$W" savedD="$D"; W="$repo"; D="$root/done.txt"; : >"$D"
  local savedQ="$Q" savedPP="$PP" savedL="$L"
  Q="$root/popq.txt"; PP="$root/pp-none.txt"; : >"$PP"; L="$root/log.txt"; : >"$L"
  # ONE FILE. a and a2 both touch a.txt: a2 waits for a batch a is not in.
  printf -- '--prove %s\n--prove %s\n--prove %s\n' "$ha" "$ha2" "$hb" >"$Q"
  n="$(lq_pop tipX 4 "$root/b3.txt" "$root/k3.txt")"
  _t "two lines on one file: the second waits"  "$(printf -- '--prove %s\n--prove %s' "$ha" "$hb")" "$(cat "$root/b3.txt")"
  _t "  ...and is kept unmarked, in order"        "--prove $ha2" "$(cat "$root/k3.txt")"
  # ONE JUDGE. g1 and g2 both touch xtask/src/gates/: one per batch.
  printf -- '--prove %s\n--prove %s\n--prove %s\n' "$hg1" "$hg2" "$hc" >"$Q"
  n="$(lq_pop tipX 4 "$root/b4.txt" "$root/k4.txt")"
  _t "two gate edits: one per batch"   "$(printf -- '--prove %s\n--prove %s' "$hg1" "$hc")" "$(cat "$root/b4.txt")"
  _t "  ...the other waits"            "--prove $hg2" "$(cat "$root/k4.txt")"
  # ONE RED-ONCE LINE. b went red in an earlier batch (the done ledger says so): it lands alone.
  printf 'RED batch=1 log=/l/x --prove %s\nGREEN batch=1 log=/l/x --prove %s\n' "$hb" "$ha" >"$D"
  _t "the ledger remembers a red line"      0 "$(lq_line_was_red "--prove $hb"; echo $?)"
  _t "a green line is not a red one"        1 "$(lq_line_was_red "--prove $ha"; echo $?)"
  printf -- '--prove %s\n--prove %s\n--prove %s\n' "$ha" "$hb" "$hc" >"$Q"
  n="$(lq_pop tipX 4 "$root/b5.txt" "$root/k5.txt")"
  _t "a red-once line does not join a batch"  "$(printf -- '--prove %s\n--prove %s' "$ha" "$hc")" "$(cat "$root/b5.txt")"
  printf -- '--prove %s\n--prove %s\n' "$hb" "$hc" >"$Q"
  n="$(lq_pop tipX 4 "$root/b6.txt" "$root/k6.txt")"
  _t "a red-once line at the head lands ALONE" "--prove $hb" "$(cat "$root/b6.txt")"
  _t "  ...and nothing joins it"               "--prove $hc" "$(cat "$root/k6.txt")"
  : >"$D"
  # ONE CEILING, RAISED AND LOWERED. The declaration is in construction.toml, the figure it names is
  # in kind-isolation.toml — two files, so the one-file rule does not see it; this rule does.
  echo "landq4 selftest: a declared raise and a lowering of the same ceiling never share"
  _t "the raise line's move is named"      "raise qa/kind-isolation.toml:rules.x.figure" "$(lq_line_ceiling_moves "--prove $hraise" "$repo")"
  _t "the lowering line's move is named"   "lower qa/kind-isolation.toml:rules.x.figure" "$(lq_line_ceiling_moves "--prove $hlower" "$repo")"
  _t "a lowering of another ceiling is another key" "lower qa/construction.toml:rules.legacy-reach.ceiling" "$(lq_line_ceiling_moves "--prove $hother" "$repo")"
  printf -- '--prove %s\n--prove %s\n--prove %s\n' "$hraise" "$hlower" "$hother" >"$Q"
  n="$(lq_pop tipX 4 "$root/b8.txt" "$root/k8.txt")"
  _t "raise K and lower K do not share"   "--prove $hraise" "$(cat "$root/b8.txt")"
  _t "  ...the lowering waits"             "--prove $hlower" "$(head -n1 "$root/k8.txt")"
  printf -- '--prove %s\n--prove %s\n' "$hlower" "$hraise" >"$Q"
  n="$(lq_pop tipX 4 "$root/b9.txt" "$root/k9.txt")"
  _t "  ...in either order"                "--prove $hlower" "$(cat "$root/b9.txt")"
  # UNKNOWN SHARES WITH NOBODY. A line whose pick does not resolve is not "touches nothing".
  printf -- '--prove %s\n--prove deadbee\n--prove %s\n' "$ha" "$hc" >"$Q"
  n="$(lq_pop tipX 4 "$root/b7.txt" "$root/k7.txt")"
  _t "an unresolvable line does not join"      "$(printf -- '--prove %s\n--prove %s' "$ha" "$hc")" "$(cat "$root/b7.txt")"
  # qa/*.toml IS SHARED ONLY OVER FIGURE-ONLY DIFFS. hother lowers a figure, hfig re-pins one: they
  # share construction.toml. hmint adds a `[[minted]]` row and hraise a `[gate.ceiling_raises.]`
  # entry: rows, so neither shares with a figure-only line, in either order.
  echo "landq4 selftest: a ceiling file is shared over figure-only diffs, never over row diffs"
  _t "a figure re-pin has no row diff"          0 "$(lq_line_qa_rows "--prove $hfig" "$repo")"
  _t "a lowering has no row diff"               0 "$(lq_line_qa_rows "--prove $hother" "$repo")"
  _t "a minted row is a row diff"               1 "$(lq_line_qa_rows "--prove $hmint" "$repo")"
  _t "a declared raise is a row diff"           1 "$(lq_line_qa_rows "--prove $hraise" "$repo")"
  _t "an unresolvable line's rows are UNKNOWN"  "?" "$(lq_line_qa_rows "--prove deadbee" "$repo")"
  _t "a figure re-pin beside code has no row diff" 0 "$(lq_line_qa_rows "--prove $hfig2" "$repo")"
  printf -- '--prove %s\n--prove %s\n' "$hfig2" "$hfigB" >"$Q"
  n="$(lq_pop tipX 4 "$root/b10.txt" "$root/k10.txt")"
  _t "two figure-only lines share the ceiling file" "$(printf -- '--prove %s\n--prove %s' "$hfig2" "$hfigB")" "$(cat "$root/b10.txt")"
  printf -- '--prove %s\n--prove %s\n' "$hmint" "$hfig2" >"$Q"
  n="$(lq_pop tipX 4 "$root/b11.txt" "$root/k11.txt")"
  _t "a row diff at the head: the figure line waits" "--prove $hmint" "$(cat "$root/b11.txt")"
  printf -- '--prove %s\n--prove %s\n' "$hfig2" "$hmint" >"$Q"
  n="$(lq_pop tipX 4 "$root/b12.txt" "$root/k12.txt")"
  _t "  ...and behind a figure line, the row line waits" "--prove $hfig2" "$(cat "$root/b12.txt")"
  _t "  ...kept, unmarked"                        "--prove $hmint" "$(cat "$root/k12.txt")"
  # THE SWEEP SHARES THE SAME WAY (lq_disjoint_lines claims files first).
  local qf2="$root/queue2.txt"
  printf -- '--prove %s\n--prove %s\n--prove %s\n' "$hfig2" "$hfigB" "$hmint" >"$qf2"
  _t "the sweep hands out two figure-only lines together, and holds the row line" \
     "$(printf -- '--prove %s\n--prove %s' "$hfig2" "$hfigB")" "$(lq_disjoint_lines 6 "$qf2" "$repo")"
  printf -- '--prove %s\n--prove %s\n' "$hmint" "$hfig2" >"$qf2"
  _t "  ...and behind a row line, the figure line waits" "--prove $hmint" "$(lq_disjoint_lines 6 "$qf2" "$repo")"
  # A BASE FIX JOINS NOBODY, in either position; a multi-pick line's files are the UNION of its picks.
  echo "landq4 selftest: a base fix joins nobody; a line's files are the union of its picks"
  printf -- '--prove %s\n--prove %s\n' "$hother" "$ha" >"$Q"
  n="$(lq_pop tipX 4 "$root/b15.txt" "$root/k15.txt")"
  _t "a base fix at the head lands alone"      "--prove $hother" "$(cat "$root/b15.txt")"
  _t "  ...the crate line waits"               "--prove $ha" "$(cat "$root/k15.txt")"
  printf -- '--prove %s\n--prove %s\n--prove %s\n' "$ha" "$hother" "$hb" >"$Q"
  n="$(lq_pop tipX 4 "$root/b16.txt" "$root/k16.txt")"
  _t "a base fix behind a crate line does not join" "$(printf -- '--prove %s\n--prove %s' "$ha" "$hb")" "$(cat "$root/b16.txt")"
  _t "  ...and is kept, unmarked"               "--prove $hother" "$(cat "$root/k16.txt")"
  _t "three picks: the union of their files"    "$(printf 'a.txt\nb.txt\nc.txt')" "$(lq_line_files "--prove $ha $hb $hc" "$repo")"
  _t "a qa pick beside a crate pick is not a base fix" 1 "$(lq_line_is_base_fix "--prove $hother $ha" "$repo"; echo $?)"
  _t "two qa-only picks together are one"       0 "$(lq_line_is_base_fix "--prove $hother $hlower" "$repo"; echo $?)"
  W="$savedW"; D="$savedD"; Q="$savedQ"; PP="$savedPP"; L="$savedL"

  echo "landq4 selftest: one engine in the tree (the census)"
  local fake="/x/tree" list
  list="$(printf '100 1 bash /x/tree/scripts/land.sh --batch b\n200 %s bash /x/tree/target/gate/land.run.sh --batch c\n300 200 cargo xtask gate construction --selftest /x/tree\n400 1 tail -f /x/tree/target/gate/landq.out\n500 1 bash /elsewhere/scripts/land.sh --batch d\n' "$$")"
  LANDQ_CENSUS_DRY=1 lq_census $$ "$fake" "$list" >"$root/census.txt"
  _t "an engine under the tree that is not the runner's is a stranger" 1 "$(grep -c '^stranger pid 100 killed' "$root/census.txt" || true)"
  _t "the runner's own child is OWN, not a stranger" 1 "$(grep -c '^own pid 200 ' "$root/census.txt" || true)"
  _t "  ...as is its grandchild"               1 "$(grep -c '^own pid 300 ' "$root/census.txt" || true)"
  _t "a tail -f reader of the tree is listed, and is not killed" 1 "$(grep -c '^reader pid 400 ' "$root/census.txt" || true)"
  _t "  ...never as a stranger"                0 "$(grep -c 'stranger pid 400 ' "$root/census.txt" || true)"
  _t "an engine in ANOTHER tree is not ours to kill" 0 "$(grep -c 'pid 500 ' "$root/census.txt" || true)"
  _t "the log line has the ruled form"         1 "$(grep -c '^stranger pid 100 killed (' "$root/census.txt" || true)"
  _t "a census that found the chain is not broken" 0 "$(LANDQ_CENSUS_DRY=1 lq_census $$ "$fake" "$list" >/dev/null; echo $?)"
  _t "an EMPTY census is broken (rc 1)"        1 "$(LANDQ_CENSUS_DRY=1 lq_census $$ "$fake" "$(printf '600 1 vim /elsewhere\n700 1 sleep 9')" >/dev/null; echo $?)"
  _t "the census reads the command line, never cwd first" 0 "$(grep -c 'readlink "/proc/\$pid/cwd"' "$0" || true)"
  # A REAL STRANGER IS KILLED: a process whose argv names an engine under the tree and whose ancestry
  # does not reach the holder (pid 1 stands in for a holder it does not descend from).
  ( exec -a "bash $fake/scripts/land.sh --batch stray" sleep 300 ) &
  local straypid=$!; sleep 0.3
  lq_census 1 "$fake" >"$root/census2.txt"
  sleep 0.3
  _t "a live stranger is named"                1 "$(grep -c "^stranger pid $straypid killed" "$root/census2.txt" || true)"
  _t "  ...and is dead afterwards"             1 "$(kill -0 "$straypid" 2>/dev/null; echo $?)"
  kill "$straypid" 2>/dev/null; wait "$straypid" 2>/dev/null

  # ── THE 03:27 DEFECT: THE CENSUS KILLED ITS OWN LAUNCHER AND THE INTEGRATOR'S MONITOR ──────────
  # Rule 2a read the command STRING, and a string that names the tree was a mutator. Two shells
  # that mutate nothing were named by it: the zsh that launched the runner (the tree is in the
  # snapshot path it sources) and the zsh wrapping the monitor's `tail -f`. Both were killed; the
  # runner survived only because it was already orphaned.
  local anclist ppid_of_me; ppid_of_me="$(ps -o ppid= -p $$ 2>/dev/null | tr -d ' ')"
  anclist="$(printf '%s %s bash landq4.sh --loop\n%s 1 /bin/zsh -c source %s/.snapshot; exec bash landq4.sh\n800 1 bash -c cd %s && git reset --hard\n' \
             "$$" "$ppid_of_me" "$ppid_of_me" "$fake" "$fake")"
  LANDQ_CENSUS_DRY=1 lq_census $$ "$fake" "$anclist" >"$root/census3.txt"
  # RED BEFORE GREEN: under the descend-only rule the launcher was a stranger, because the walk only
  # ever went DOWN from the holder and a launcher is above it.
  _t "the launcher descends from the holder: no"  1 "$(lq_descends "$ppid_of_me" $$ "$anclist"; echo $?)"
  _t "  ...and the reader rule does not save it"  1 "$(lq_is_reader "/bin/zsh -c source $fake/.snapshot; exec bash landq4.sh"; echo $?)"
  _t "an ANCESTOR of the runner is never a stranger" 1 "$(grep -c "^ancestor pid $ppid_of_me (kept) " "$root/census3.txt" || true)"
  _t "  ...never killed"                        0 "$(grep -c "stranger pid $ppid_of_me " "$root/census3.txt" || true)"
  # AND THE EXEMPTION IS NARROW. `bash -c 'cd <W> && git reset --hard'` is the 22:50 mis-launch
  # shape: it hides behind a -c string exactly as well as a monitor does, and it is a stranger.
  _t "a mutator behind a -c string is still a stranger" 1 "$(grep -c '^stranger pid 800 killed' "$root/census3.txt" || true)"

  # A LIVE WRAPPED READER, kept by a census that is not in dry-run: the monitor's shape.
  local largs="/bin/zsh -c tail -f $fake/target/gate/landq.out"
  ( exec -a "$largs" sleep 300 ) &
  local monpid=$!; sleep 0.3
  lq_census 1 "$fake" >"$root/census4.txt"
  sleep 0.3
  # THE READING LIST, MEASURED. Audit 14's question was whether anything but `tail` survives; these
  # are the answers, one per command, and the refusals beside them.
  _t "grep of a log under the tree is a reader"  0 "$(lq_is_reader "grep -n RED $fake/target/gate/landq.out"; echo $?)"
  _t "  ...cat"                                  0 "$(lq_is_reader "cat $fake/target/gate/land-queue.txt"; echo $?)"
  _t "  ...ls"                                   0 "$(lq_is_reader "ls -la $fake/target/gate"; echo $?)"
  _t "  ...wc"                                   0 "$(lq_is_reader "wc -l $fake/target/gate/land-queue.txt"; echo $?)"
  _t "  ...head"                                 0 "$(lq_is_reader "head -n5 $fake/target/gate/landq.out"; echo $?)"
  _t "  ...awk"                                  0 "$(lq_is_reader "awk {print} $fake/target/gate/landq.out"; echo $?)"
  _t "  ...sed -n"                               0 "$(lq_is_reader "sed -n 1,5p $fake/target/gate/landq.out"; echo $?)"
  _t "  ...and a wrapped pipeline of them"       0 "$(lq_is_reader "/bin/zsh -c grep RED $fake/x | wc -l"; echo $?)"
  _t "sed WITHOUT -n can edit: not a reader"     1 "$(lq_is_reader "sed -i s/a/b/ $fake/target/gate/land-queue.txt"; echo $?)"
  _t "a redirection out of a reader: not a reader" 1 "$(lq_is_reader "cat $fake/x > $fake/y"; echo $?)"
  _t "tee is not on the list"                    1 "$(lq_is_reader "tail -f $fake/x | tee $fake/y"; echo $?)"
  _t "nor is anything the list does not name"    1 "$(lq_is_reader "/bin/zsh -c git -C $fake reset --hard"; echo $?)"
  # THE HARNESS'S OWN WRAPPER, VERBATIM. Every shell in this fleet is launched as
  # `/bin/zsh -c 'source …/shell-snapshots/snapshot-zsh-<n>.sh 2>/dev/null; <cmd>'`; the `;` and the
  # `>` in that prologue made every one of them a stranger, and this is the exact string the census
  # killed at 03:24. Judged on what comes AFTER the prologue, and on nothing else.
  local snap="/bin/zsh -c source /Users/x/.claude/shell-snapshots/snapshot-zsh-1757.sh 2>/dev/null;"
  _t "the harness's wrapper around a reader is a reader" 0 "$(lq_is_reader "$snap tail -f $fake/target/gate/landq.out"; echo $?)"
  _t "  ...around grep too"                      0 "$(lq_is_reader "$snap grep -c RED $fake/target/gate/landq.out"; echo $?)"
  _t "  ...but around a mutator it is a stranger" 1 "$(lq_is_reader "$snap git -C $fake reset --hard"; echo $?)"
  _t "  ...and a dot-file prologue is the same"  0 "$(lq_is_reader "/bin/sh -c . /tmp/snap.sh; cat $fake/x"; echo $?)"
  _t "a prologue that does something else is not stripped" 1 "$(lq_is_reader "/bin/zsh -c source /tmp/s.sh && rm -rf $fake; cat $fake/x"; echo $?)"
  _t "  ...nor is one that pipes"                1 "$(lq_is_reader "/bin/zsh -c source /tmp/s.sh | tee $fake/y; cat $fake/x"; echo $?)"
  _t "the pre-rule test (argv begins with tail) misses it" 0 "$(printf '%s' "$largs" | grep -cE '^tail( |$)' || true)"
  _t "a monitor wrapped in a shell is a reader, kept" 1 "$(grep -c "^reader pid $monpid (kept) " "$root/census4.txt" || true)"
  _t "  ...and is ALIVE afterwards"             0 "$(kill -0 "$monpid" 2>/dev/null; echo $?)"
  kill "$monpid" 2>/dev/null; wait "$monpid" 2>/dev/null

  # CWD IS A MUTATOR'S MARK. `sleep` names no engine and no tree; its cwd IS the tree, and that is
  # enough — this is the shape of every editor, shell and helper a slot leaves sitting in it.
  local cwdtree="$root/cwdtree"; mkdir -p "$cwdtree"
  ( cd "$cwdtree" && exec sleep 300 ) &
  local cwdpid=$!; sleep 0.3
  LANDQ_CENSUS_DRY=1 lq_census 1 "$cwdtree" >"$root/census5.txt" 2>/dev/null
  _t "a process whose CWD is the tree is a stranger" 1 "$(grep -c "^stranger pid $cwdpid killed" "$root/census5.txt" || true)"
  _t "  ...though its argv names neither tree nor engine" 0 "$(ps -o args= -p "$cwdpid" 2>/dev/null | grep -c "$cwdtree" || true)"
  kill "$cwdpid" 2>/dev/null; wait "$cwdpid" 2>/dev/null

  # ── THE SUPERVISED RUNNER NAMES NOTHING (F1d, measured 2026-09-11) ────────────────────────────
  # Under scripts/landq-supervisor.sh the chain is `bash landq-supervisor.sh` → `bash
  # <engine home>/scripts/landq4.sh` → `bash <engine home>/scripts/land.sh`, started from
  # ~/Developer/tmp: not one of those strings contains the tree. Judged by argv the census saw
  # NOTHING and refused every batch (`NONE:census-empty`) at every loop top. Judged by PID — the
  # lock holder and its descendants — it sees its own chain, and the queue moves.
  local suplist
  suplist="$(printf '900 1 bash /Users/x/.busbar-engine/current/scripts/landq-supervisor.sh\n%s 900 bash /Users/x/.busbar-engine/current/scripts/landq4.sh\n950 %s bash /Users/x/.busbar-engine/current/scripts/land.sh --batch b\n980 950 cargo xtask gate construction --selftest\n990 1 bash /x/tree/scripts/land.sh --batch stray\n' "$$" "$$")"
  # RED BEFORE GREEN: the text rules alone say the supervised runner is not in the tree at all.
  _t "the supervised runner's argv names the tree nowhere" 0 \
     "$(printf '%s' "$suplist" | grep -v 'batch stray' | grep -c "$fake" || true)"
  LANDQ_CENSUS_DRY=1 lq_census $$ "$fake" "$suplist" >"$root/census6.txt"
  _t "a supervised census is not broken"       0 "$(LANDQ_CENSUS_DRY=1 lq_census $$ "$fake" "$suplist" >/dev/null; echo $?)"
  _t "  ...the runner itself is own, by pid"   1 "$(grep -c "^own pid $$ " "$root/census6.txt" || true)"
  _t "  ...so is the land.sh it started"       1 "$(grep -c '^own pid 950 ' "$root/census6.txt" || true)"
  _t "  ...and the gate below that"            1 "$(grep -c '^own pid 980 ' "$root/census6.txt" || true)"
  _t "  ...none of them killed"                0 "$(grep -c "stranger pid \($$\|950\|980\) " "$root/census6.txt" || true)"
  # AND A STRANGER IS STILL JUDGED BY THE THREE TEXT FORMS: identity by pid exempts the chain, not
  # the host.
  _t "a stranger in the tree is still killed"  1 "$(grep -c '^stranger pid 990 killed' "$root/census6.txt" || true)"
  _t "  ...and the supervisor above is left alone" 0 "$(grep -c 'pid 900 ' "$root/census6.txt" || true)"
  _t "the chain is recognised by pid before any text rule" 1 \
     "$(grep -c 'if lq_descends "\$pid" "\$holder" "\$list"; then' "$LQ_SRC")"

  _t "the main flow takes the census before the sweep and the pop" 1 "$(grep -c '^  census="\$(lq_census \$\$ "\$W")"' "$0")"
  _t "  ...and refuses on an empty one"        1 "$(grep -c '^    fn="\$(lq_fault_record census-empty ' "$0")"

  echo "landq4 selftest: the tree must be settled (HEAD is the last landed tip, nothing modified)"
  local tipf="$root/tip.txt"
  _t "first run: the tip as found is the tip"  0 "$(lq_tree_settled "$repo" "$tipf"; echo $?)"
  _t "  ...and is written down"                "$(git -C "$repo" rev-parse HEAD)" "$(cat "$tipf")"
  printf 'dirty\n' >>"$repo/a.txt"
  _t "a modified tracked file refuses"         1 "$(lq_tree_settled "$repo" "$tipf"; echo $?)"
  git -C "$repo" checkout -q -- a.txt
  printf 'stray\n' >"$repo/untracked.txt"
  _t "an untracked file does not (target/ notes live there)" 0 "$(lq_tree_settled "$repo" "$tipf"; echo $?)"
  rm -f "$repo/untracked.txt"
  printf 'z\n' >"$repo/z.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm z
  _t "a HEAD that is not the last landed tip refuses" 1 "$(lq_tree_settled "$repo" "$tipf"; echo $?)"
  git -C "$repo" rev-parse HEAD >"$tipf"
  _t "  ...until the tip is recorded"          0 "$(lq_tree_settled "$repo" "$tipf"; echo $?)"
  _t "the main flow refuses an unsettled tree" 1 "$(grep -c 'if ! lq_tree_settled "\$W" "\$TIPF"; then' "$0")"

  echo "landq4 selftest: a base fix pops alone; a sweep of one line is skipped"
  _t "a qa-only line is a base fix"            0 "$(lq_line_is_base_fix "--prove $hother" "$repo"; echo $?)"
  _t "a two-file ceiling line is one too"      0 "$(lq_line_is_base_fix "--prove $hraise" "$repo"; echo $?)"
  _t "a crate line is not"                     1 "$(lq_line_is_base_fix "--prove $ha" "$repo"; echo $?)"
  _t "an unresolvable line is not"             1 "$(lq_line_is_base_fix "--prove deadbee" "$repo"; echo $?)"
  local savedQ3="$Q"; Q="$root/bfq.txt"
  printf -- '# note\n--prove %s\n--prove %s\n--prove %s\n' "$hother" "$ha" "$hb" >"$Q"
  _t "three live lines counted (comments are not)" 3 "$(lq_live_lines "$Q")"
  _t "the head live line is the base fix"     "--prove $hother" "$(lq_head_line "$Q")"
  n="$(lq_pop_head_alone "$root/b13.txt" "$root/k13.txt")"
  _t "the head pops alone"                     "--prove $hother" "$(cat "$root/b13.txt")"
  _t "  ...one line"                           1 "$n"
  _t "  ...everything else is kept, in order"  "$(printf -- '# note\n--prove %s\n--prove %s' "$ha" "$hb")" "$(cat "$root/k13.txt")"
  printf -- '# only notes\n' >"$Q"
  _t "no live line: nothing popped"            0 "$(lq_pop_head_alone "$root/b14.txt" "$root/k14.txt")"
  Q="$savedQ3"
  _t "the main flow skips the sweep for a base-fix head" 1 "$(grep -c 'lq_line_is_base_fix "\$headline" "\$W"; then' "$0")"
  _t "the main flow skips the sweep with no live line at all" 1 "$(grep -c '\[ "\$(lq_live_lines "\$Q")" -lt 1 \]' "$0")"
  _t "  ...and no longer at two: one live line roots every chain behind it" 0 \
     "$(grep -c '\[ "\$(lq_live_lines "\$Q")" -lt 2 \]' "$0")"

  echo "landq4 selftest: a pre-proof red against the base, or by the tree-moved guard, is NONE"
  printf 'ceiling-rose: rules.x.figure is 47 at the base and 60 here\n' >"$root/pl1.log"
  printf 'FAIL ceiling-rose: busbar-core x api ROSE since the base\n' >"$root/pl2.log"
  printf 'land-remote: ERROR: the landed tip abc is not a fast-forward of this tree — refusing\n' >"$root/pl3.log"
  printf 'land.sh: RED — tests failed in: busbar\n' >"$root/pl4.log"
  _t "rc 0 is GREEN"                           GREEN "$(lq_preproof_verdict 0 "$root/pl4.log")"
  _t "no rc is never-reported"                 "NONE:never-reported" "$(lq_preproof_verdict "" "$root/pl4.log")"
  _t "a red naming the base is NONE"           "NONE:base" "$(lq_preproof_verdict 1 "$root/pl1.log")"
  _t "  ...as is ROSE since the base"          "NONE:base" "$(lq_preproof_verdict 1 "$root/pl2.log")"
  _t "the tree-moved guard's red is NONE (re-queued)" "NONE:moved" "$(lq_preproof_verdict 2 "$root/pl3.log")"
  _t "an ordinary red is RED"                  RED "$(lq_preproof_verdict 1 "$root/pl4.log")"
  _t "the sweep records through the verdict"   1 "$(grep -c 'case "\$(lq_preproof_verdict "\$rc" "\$dir/line-\$j.log" "\$dir/line-\$j.batch.result" "\$key")" in' "$0")"

  # T0-D5, THE DEFECT ITSELF, in the shape it really arrived: the box's per-line outcome says GREEN,
  # the log's last two lines are the pruned landed-ref warning and the exit, no tree-moved guard is
  # named anywhere, and rc is 2. That is a GREEN line, and it was parked #RED-preproof for 2.2 h of
  # fleet time. The fixture is the tail of line-3.log of the sweep at 76f1887af, verbatim.
  printf 'land.sh: === GREEN lines 1 — proven by: cargo test (xtask ); kind-isolation green;\n' >"$root/pl5.log"
  printf 'land.sh: PRE-PROVE — published nothing; tree back at 76f1887af (proven against 76f1887af)\n' >>"$root/pl5.log"
  printf '[remote 14:33:41] WARNING: no landed tip came back from i-0b0e1585e8567d01a (refs/heads/land-20260910-122102-15256-landed)\n' >>"$root/pl5.log"
  printf '[remote 14:33:41] host i-0b0e1585e8567d01a   exit 2   wall 7950s\n' >>"$root/pl5.log"
  printf 'GREEN\t--prove --tests xtask 6d5bba552 4b6e3e40c 8d48b75ab\n' >"$root/pl5.batch.result"
  printf 'RED\t--prove --tests xtask 6d5bba552 4b6e3e40c 8d48b75ab\n' >"$root/pl6.batch.result"
  printf 'GREEN\t--prove one\nRED\t--prove two\n' >"$root/pl7.batch.result"
  : >"$root/pl8.batch.result"
  _t "rc 2, no guard named, outcome GREEN = GREEN" GREEN "$(lq_preproof_verdict 2 "$root/pl5.log" "$root/pl5.batch.result")"
  _t "  ...and without the outcome file it was RED" RED  "$(lq_preproof_verdict 2 "$root/pl5.log")"
  _t "a RED outcome cannot green a red rc"        RED   "$(lq_preproof_verdict 1 "$root/pl4.log" "$root/pl6.batch.result")"
  _t "a mixed outcome is not GREEN"               RED   "$(lq_preproof_verdict 1 "$root/pl4.log" "$root/pl7.batch.result")"
  _t "an empty outcome file rules nothing"        RED   "$(lq_preproof_verdict 1 "$root/pl4.log" "$root/pl8.batch.result")"
  _t "a missing outcome file rules nothing"       "NONE:base" "$(lq_preproof_verdict 1 "$root/pl1.log" "$root/nope.result")"
  _t "  ...and the tree-moved guard still wins over no outcome" "NONE:moved" "$(lq_preproof_verdict 2 "$root/pl3.log" "$root/nope.result")"

  # ── A BOX THAT VANISHED MID-PROOF IS NO VERDICT ON THE LINE ──────────────────────────────────
  # Measured 2026-09-10 (the sweep of twelve that started 14:12): lines 10 and 11 ended `exit 2`
  # "unreachable for 10 polls — no verdict" / "scp: Connection closed" after 1735 s and 10116 s
  # because AWS reclaimed the spot instances under them. The engine had no word for that, so both
  # were scored RED — a colour about a line whose proof never finished. It is NONE:box: nothing was
  # learned, so nothing is recorded, and the line goes back to the FRONT of the pre-proof list
  # (it has already waited two hours for an answer that never came).
  echo "landq4 selftest: a box reclaimed mid-proof is NONE:box, re-queued, never RED"
  printf 'land.sh: [lines 1] plan: plugins fmt gatefiles tests clippy kind-isolation gate\n' >"$root/plbox.log"
  printf '[remote 21:43:50] ERROR: i-07af07dd77dfea9d9 unreachable for 10 polls — no verdict\n' >>"$root/plbox.log"
  printf 'scp: Connection closed\n' >>"$root/plbox.log"
  printf '[remote 21:44:08] host i-07af07dd77dfea9d9   exit 2   wall 1735s\n' >>"$root/plbox.log"
  _t "the box vanished: NONE:box, not RED"     "NONE:box" "$(lq_preproof_verdict 2 "$root/plbox.log")"
  _t "  ...and the transport's own rc 75 says it alone" "NONE:box" "$(lq_preproof_verdict 75 "$root/pl4.log")"
  _t "a GREEN outcome still outranks it"       GREEN "$(lq_preproof_verdict 75 "$root/plbox.log" "$root/pl5.batch.result")"
  _t "an ordinary red is still RED"            RED   "$(lq_preproof_verdict 1 "$root/pl4.log")"
  _t "the sweep re-queues a NONE:box line to the front" 1 "$(grep -c 'NONE:box)  lq_front_add "\$text"' "$0")"
  # THE FRONT LIST: the lines that were denied an answer by the fleet, not by their own picks.
  local savedFRONT="$FRONT"; FRONT="$root/front.txt"; : >"$FRONT"
  local fq="$root/frontq.txt"
  printf -- '--prove aaa1111\n--prove bbb2222\n--prove ccc3333\n' >"$fq"
  lq_front_add "--prove ccc3333"
  _t "a re-queued line comes first"            "--prove ccc3333" "$(lq_front_queue "$fq" | head -1)"
  _t "  ...and every other line is still there, in order" "$(printf -- '--prove aaa1111\n--prove bbb2222')" "$(lq_front_queue "$fq" | tail -n +2)"
  _t "  ...and it is not there twice"          1 "$(lq_front_add "--prove ccc3333"; grep -c . "$FRONT")"
  _t "a line that left the queue leaves the front list" 3 "$(lq_front_queue "$fq" | grep -c .)"
  printf -- '--prove aaa1111\n--prove bbb2222\n' >"$fq"
  _t "  ...and is simply not offered"          2 "$(lq_front_queue "$fq" | grep -c .)"
  _t "an empty front list changes nothing"     "$(cat "$fq")" "$(: >"$FRONT"; lq_front_queue "$fq")"
  lq_front_add "--prove bbb2222"; lq_front_drop "--prove bbb2222"
  _t "a line that got a real verdict is dropped from the front" 0 "$(grep -c . "$FRONT")"
  FRONT="$savedFRONT"
  _t "the sweep asks the front-ordered queue for its lines" 1 "$(grep -c 'lq_disjoint_lines "\$PREPROVE_LINES" "\$qf"' "$0")"

  # ── A HARNESS THAT GAVE UP IS NOT A RED LINE ─────────────────────────────────────────────────
  # T0-D10's contract: a driver that cannot do its job marks `effects.harness_error`, prints
  # `harness give-up:` and exits 70; the recorder refuses the cell and the recording is RED. land.sh
  # reads that evidence OUT OF THE RECORDING and says so in one sentence; this engine reads the
  # sentence. Measured 2026-09-10: three pre-proofs were parked RED on `documented|changelog|
  # admin-restart` with `/put_settings_body … -> ""` — the driver's second boot did not come up
  # within ORACLE_BOOT_BOUND_SECS on a loaded box, and the give-up was recorded as the LINE's red.
  echo "landq4 selftest: a harness give-up is NONE:harness, re-queued, never RED"
  printf 'land.sh: RED — oracle: a HARNESS failure, not a divergence: harness give-up: port 46611 busy\n' >"$root/plharn.log"
  printf 'land.sh:       no verdict on the picks — the harness gave up on this box; re-run the line elsewhere\n' >>"$root/plharn.log"
  printf 'land.sh: RED — oracle families: ^(documented)[|]\n' >>"$root/plharn.log"
  _t "a harness give-up is NONE:harness"       "NONE:harness" "$(lq_preproof_verdict 1 "$root/plharn.log")"
  _t "  ...and the driver's exit 70 says it too" "NONE:harness" \
     "$(printf 'land.sh: RED — oracle: the driver exited 70 (harness_error)\n' >"$root/plharn2.log"; lq_preproof_verdict 1 "$root/plharn2.log")"
  # THE FALSE POSITIVE THE RULE MUST NOT HAVE. A landing that TOUCHES a driver runs that driver's
  # own --selftest on the box, and one of those selftests plants a busy port on purpose and prints
  # the give-up as a PASSING row. A line whose log merely contains those words is an ordinary red.
  printf 'documented-admin-restart selftest: a planted busy port is a harness failure\n' >"$root/plharn3.log"
  printf '  ok    the driver exited 70 (non-zero) on a harness failure\n' >>"$root/plharn3.log"
  printf '  ok    the capture carries effects.harness_error (port 64295 busy)\n' >>"$root/plharn3.log"
  printf 'harness give-up: port 64295 busy\n' >>"$root/plharn3.log"
  printf 'land.sh: RED — tests failed in: busbar-core\n' >>"$root/plharn3.log"
  _t "a driver SELFTEST that prints the words is still RED" RED "$(lq_preproof_verdict 1 "$root/plharn3.log")"
  _t "a GREEN outcome still outranks a give-up"  GREEN "$(lq_preproof_verdict 1 "$root/plharn.log" "$root/pl5.batch.result")"
  _t "a vanished box outranks it (nothing ran)"  "NONE:box" "$(lq_preproof_verdict 75 "$root/plharn.log")"
  _t "the sweep re-queues a NONE:harness line to the front" 1 "$(grep -c 'NONE:harness)  lq_front_add "\$text"' "$0")"
  # ── A RECORDING THAT IS ABSENT IS NOT A RECORDING THAT DIFFERS ────────────────────────────────
  # MEASURED 2026-09-10: a batch union went RED on `requested cell 'admin.ops|…' was recorded by no
  # shard` — an oracle SHARD THAT NEVER RAN — and this engine scored it as the LINE's red and
  # parked the line. Nothing was compared with the golden for that cell, so there was no difference
  # to have found: the proof did not fail, it did not finish. land.sh says so in the same sentence
  # it uses for a driver that gives up (its land_harness_red), and the verdict follows it.
  printf 'land.sh: RED — oracle: a HARNESS failure, not a divergence: requested cell %s was recorded by no shard\n' "'admin.ops|x'" >"$root/plshard.log"
  printf 'land.sh:       no verdict on the picks — the recording is ABSENT, not different; re-run the line elsewhere\n' >>"$root/plshard.log"
  printf "land.sh: RED — requested cell 'admin.ops|x' was recorded by no shard\n" >>"$root/plshard.log"
  _t "a cell recorded by no shard is NONE:harness" "NONE:harness" "$(lq_preproof_verdict 1 "$root/plshard.log")"
  _t "  ...so the line goes to the FRONT, not to a park" "NONE:harness" \
     "$(lq_preproof_verdict 1 "$root/plshard.log" "" tipS)"
  printf 'land.sh: RED — oracle: a HARNESS failure, not a divergence: oracle shard 1 produced no exit status: it never reported\n' >"$root/plshard2.log"
  printf 'land.sh:       no verdict on the picks — the recording is ABSENT, not different; re-run the line elsewhere\n' >>"$root/plshard2.log"
  _t "a shard that produced no report is NONE:harness too" "NONE:harness" "$(lq_preproof_verdict 1 "$root/plshard2.log")"
  # AND THE FALSE POSITIVE THE RULE MUST NOT HAVE: a cell that WAS recorded and DID differ.
  printf "land.sh: RED — oracle families: ^(admin[.]ops)[|] (see /t/out.report)\n" >"$root/plshard3.log"
  _t "an ordinary oracle divergence is still RED"  RED "$(lq_preproof_verdict 1 "$root/plshard3.log")"
  # …and a chained rung reads the same rule, through the same predicate.
  printf 'RED%sDEEP\n' "$TAB" >"$root/plshard.result"
  _t "a chained rung reads it too"             "NONE:harness" \
     "$(lq_chain_preproof_verdict 1 "$root/plshard.log" "$root/plshard.result" DEEP tipS)"

  # ── THE ORACLE ROWS THAT ARE RED AT THE TIP ITSELF ───────────────────────────────────────────
  # Measured 2026-09-10: line 12 (a base probe) and line 8 were parked RED on
  # `boot.refusal|BOOT-P29|validate`, `boot.refusal|BOOT-P30|validate` and
  # `neutrality|routes|admin-openapi-paths` — rows that are RED AT THE BASE, on the tip, with no
  # picks at all. The engine recorded RED rather than NONE:base because its base-state predicate
  # only knows the construction gate's CEILING words ("at the base", "ROSE since the base"); an
  # oracle row has no such sentence. A line's own red is a row that was PASS at the base.
  echo "landq4 selftest: an oracle row red at the tip is the BASE's red, not the line's"
  local savedBR="$BASERED" savedL9="$L"; BASERED="$root/basered.txt"; : >"$BASERED"; L="$root/basered-log.txt"; : >"$L"
  local tipA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa tipB=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  printf '  | boot.refusal|BOOT-P29|validate\tFAIL\teffects.stderr\tadditive: not a superset\n' >"$root/orc1.log"
  printf '  | boot.refusal|BOOT-P30|validate\tFAIL\teffects.stderr\tadditive: not a superset\n' >>"$root/orc1.log"
  printf '  | boot.warning|BOOT-W21|boot\tPASS\t\t\n' >>"$root/orc1.log"
  printf 'land.sh: RED — oracle families: ^(boot)[|] (see /home/ubuntu/x.report)\n' >>"$root/orc1.log"
  _t "the FAIL rows are read out of a log"     "$(printf 'boot.refusal|BOOT-P29|validate\nboot.refusal|BOOT-P30|validate')" "$(lq_oracle_fail_rows "$root/orc1.log")"
  _t "a PASS row is not one of them"           0 "$(lq_oracle_fail_rows "$root/orc1.log" | grep -c 'BOOT-W21')"
  _t "nothing is known about a tip yet"        1 "$(lq_base_red_known "$tipA"; echo $?)"
  lq_base_red_learn "$tipA" "$root/orc1.log"
  _t "  ...and known once a proof at that tip has been read" 0 "$(lq_base_red_known "$tipA"; echo $?)"
  _t "  ...with the rows it measured"          2 "$(lq_base_red_rows "$tipA" | grep -c .)"
  _t "  ...keyed by the tip, so another tip knows nothing" 1 "$(lq_base_red_known "$tipB"; echo $?)"
  _t "a proof that never reached the oracle leg teaches nothing" 1 \
     "$(printf 'land.sh: RED — tests failed in: busbar-core\n' >"$root/orc0.log"; lq_base_red_learn "$tipB" "$root/orc0.log"; lq_base_red_known "$tipB"; echo $?)"
  # A GREEN proof at a tip is a MEASUREMENT TOO: it says the base has no red oracle row at all.
  printf 'land.sh: oracle green on: ^(boot)[|] (240 owed, 3 merged shard(s))\n' >"$root/orcg.log"
  lq_base_red_learn "$tipB" "$root/orcg.log"
  _t "a green oracle leg measures the empty set" 0 "$(lq_base_red_known "$tipB"; echo $?)"
  _t "  ...which is empty"                       0 "$(lq_base_red_rows "$tipB" | grep -c .)"
  # THE RULE ITSELF.
  _t "a line whose only red rows are the base's is NONE:base" "NONE:base" "$(lq_preproof_verdict 1 "$root/orc1.log" "" "$tipA")"
  printf '  | boot.refusal|BOOT-P31|validate\tFAIL\teffects.stderr\tadditive: not a superset\n' >"$root/orc2.log"
  printf 'land.sh: RED — oracle families: ^(boot)[|]\n' >>"$root/orc2.log"
  _t "  ...and ONE row that was PASS at the base is the line's own RED" RED "$(lq_preproof_verdict 1 "$root/orc2.log" "" "$tipA")"
  cat "$root/orc1.log" >"$root/orc3.log"
  printf 'land.sh: RED — tests failed in: busbar-core\n' >>"$root/orc3.log"
  _t "a red that is not the oracle's is still RED"  RED "$(lq_preproof_verdict 1 "$root/orc3.log" "" "$tipA")"
  _t "an unmeasured tip cannot launder anything"    RED "$(lq_preproof_verdict 1 "$root/orc1.log" "" "$tipB")"
  _t "  ...and with no tip at all the rule does not run" RED "$(lq_preproof_verdict 1 "$root/orc1.log")"
  _t "a GREEN outcome still outranks it"            GREEN "$(lq_preproof_verdict 1 "$root/orc1.log" "$root/pl5.batch.result" "$tipA")"
  # The ledger is keyed by the tip and pruned with it, exactly like the pre-proof ledger.
  # ── THE SAME ROW, A DIFFERENT DIVERGENCE, IS THE LINE'S OWN RED (pass-22 RED-24) ─────────────
  # The predicate above matched a base red by ROW IDENTITY and nothing else, so a line that broke
  # an already-base-red row FURTHER — same cell, a different divergence — had its only red row in
  # the base-red set and was recorded NONE:base: no colour, no park, still live. The rows in that
  # set are exactly the rows the queue is there to REPAIR, so the second breakage stayed invisible
  # until the repairing line tried to make the row green and found a second fault it did not cause.
  # THE REPORT ALREADY CARRIES WHAT SETTLES IT. A FAIL row is
  # `<cell id>  FAIL  <class list>  <first divergence>` (xtask/src/ledger.rs's Row::tsv), so the
  # set records the DETAIL beside the row, and a red is the base's only when its detail matches.
  _t "the detail is read off the FAIL row, not just the id" \
     "$(printf 'boot.refusal|BOOT-P29|validate\teffects.stderr\tadditive: not a superset')" \
     "$(lq_oracle_fail_detail "$root/orc1.log" | head -1)"
  _t "  ...and the base remembers it"          "$(printf 'effects.stderr\tadditive: not a superset')" \
     "$(lq_base_red_detail "$tipA" 'boot.refusal|BOOT-P29|validate')"
  _t "  ...for every row it measured"          2 "$(lq_base_red_rows "$tipA" | while IFS= read -r r; do lq_base_red_detail "$tipA" "$r"; done | grep -c 'additive: not a superset')"
  # THE SAME ROW, THE SAME DIVERGENCE: still the base's.
  _t "the same rows for the same reason are still NONE:base" "NONE:base" "$(lq_preproof_verdict 1 "$root/orc1.log" "" "$tipA")"
  # THE SAME ROW, A DIFFERENT DIVERGENCE: the line's.
  printf '  | boot.refusal|BOOT-P29|validate\tFAIL\tbody,effects.stderr\tbody /refusal/code: 3 -> 7\n' >"$root/orc5.log"
  printf '  | boot.refusal|BOOT-P30|validate\tFAIL\teffects.stderr\tadditive: not a superset\n' >>"$root/orc5.log"
  printf 'land.sh: RED — oracle families: ^(boot)[|]\n' >>"$root/orc5.log"
  _t "a base-red row broken DIFFERENTLY is the line's own RED" RED "$(lq_preproof_verdict 1 "$root/orc5.log" "" "$tipA")"
  _t "  ...and the log carries the BASE's detail"  1 \
     "$(: >"$L"; lq_preproof_verdict 1 "$root/orc5.log" "" "$tipA" >/dev/null; grep -c 'base: effects.stderr additive: not a superset' "$L")"
  _t "  ...and the LINE's beside it"               1 \
     "$(grep -c 'line: body,effects.stderr body /refusal/code: 3 -> 7' "$L")"
  _t "  ...naming the row they disagree about"     1 \
     "$(grep -c 'boot.refusal|BOOT-P29|validate is red at the tip and red here, but NOT the same divergence' "$L")"
  # A ROW WHOSE CLASS LIST ALONE MOVED is a different divergence too: the classes are the report's
  # own account of WHAT diverged, and a row that grew a second one is not the row that was there.
  printf '  | boot.refusal|BOOT-P29|validate\tFAIL\teffects.stderr,effects.exit\tadditive: not a superset\n' >"$root/orc6.log"
  printf '  | boot.refusal|BOOT-P30|validate\tFAIL\teffects.stderr\tadditive: not a superset\n' >>"$root/orc6.log"
  printf 'land.sh: RED — oracle families: ^(boot)[|]\n' >>"$root/orc6.log"
  _t "a wider class list on a base-red row is the line's RED too" RED "$(lq_preproof_verdict 1 "$root/orc6.log" "" "$tipA")"
  # AND A SET LEARNED BEFORE THE DETAIL EXISTED LAUNDERS NOTHING. An old file's rows carry no
  # detail at all; that is not "the same detail", it is no measurement, and the safe direction is
  # the line's own RED until the tip is measured again (which the prune below forces anyway).
  printf '  | boot.refusal|BOOT-P29|validate\tFAIL\teffects.stderr\tadditive: not a superset\n' >"$root/orc7.log"
  printf 'land.sh: RED — oracle families: ^(boot)[|]\n' >>"$root/orc7.log"
  printf '%s%s#measured\n%s%sboot.refusal|BOOT-P29|validate\n' "$tipB" "$TAB" "$tipB" "$TAB" >>"$BASERED"
  _t "a detail-less row from an older set cannot launder" RED "$(lq_preproof_verdict 1 "$root/orc7.log" "" "$tipB")"
  awk -F"$TAB" -v tp="$tipB" '$1 != tp' "$BASERED" >"$BASERED.t" && mv -f "$BASERED.t" "$BASERED"
  _t "a tip move drops every other tip's rows"  1 "$(lq_base_red_prune "$tipA"; lq_base_red_known "$tipB"; echo $?)"
  _t "  ...and keeps the tip it was pruned to"   0 "$(lq_base_red_known "$tipA"; echo $?)"
  BASERED="$savedBR"; L="$savedL9"

  # ── THE BASE REPLAY: HOW A TIP GETS MEASURED WHEN NO PROOF HAS ──────────────────────────────
  # ── AND THE REPLAY'S RESULT SAYS WHAT IT MEASURED, IN THE SAME THREE COLUMNS ─────────────────
  # A tip is measured one of two ways — the last wholly-green landed batch, or a base-only replay
  # (a batch with NO hashes, the tip itself, proven on a box the lines did not take). The
  # comparison above is only as good as what those two write down, so BOTH write the same result
  # beside the log they read: the row, its class list and its first divergence. An operator asking
  # "what was the base's red on that row" reads a file rather than a 40 MB proof log, and the
  # engine's answer and the operator's are the same bytes.
  echo "landq4 selftest: the base-only replay's result carries the divergence, not just the row"
  local savedBR2="$BASERED" savedL2="$L"; BASERED="$root/basered2.txt"; : >"$BASERED"; L="$root/basered2-log.txt"; : >"$L"
  local tipC=cccccccccccccccccccccccccccccccccccccccc
  lq_base_red_learn "$tipC" "$root/orc1.log"
  lq_base_red_result "$tipC" "$root/orc1.log" "$root/base.detail"
  _t "the replay's result is the row AND its divergence" \
     "$(printf 'boot.refusal|BOOT-P29|validate\teffects.stderr\tadditive: not a superset')" "$(head -1 "$root/base.detail")"
  _t "  ...one row per red row at the tip"      2 "$(grep -c . "$root/base.detail")"
  _t "  ...and it is exactly what the comparison reads" \
     "$(lq_base_red_detail "$tipC" 'boot.refusal|BOOT-P29|validate')" \
     "$(awk -F"$TAB" '$1 == "boot.refusal|BOOT-P29|validate" { print $2 FS $3 }' "$root/base.detail")"
  _t "  ...and the queue log names each divergence" 1 \
     "$(grep -c 'boot.refusal|BOOT-P29|validate effects.stderr additive: not a superset' "$L")"
  # A GREEN replay measures the empty set, and says so rather than leaving a stale file behind.
  lq_base_red_result "$tipC" "$root/orcg.log" "$root/base.detail"
  _t "a green replay's result is empty, not stale" 0 "$(grep -c . "$root/base.detail")"
  _t "the sweep writes the replay's result down"   1 "$(grep -c 'lq_base_red_result "\$key" "\$dir/base.log"' "$0")"
  _t "  ...and the landed batch's, in the same shape" 1 "$(grep -c 'lq_base_red_result "\$newtip" "\$batch.log"' "$0")"
  BASERED="$savedBR2"; L="$savedL2"
  echo "landq4 selftest: the families a sweep must measure at the base"
  _t "a quoted families regex is read off a line" "^(llm|route\\.failover|hooks)[|]" "$(lq_line_families "--prove --tests busbar --families '^(llm|route\\.failover|hooks)[|]' abc1234")"
  _t "a bare one is read too"                     "^(boot)[|]" "$(lq_line_families "--prove --families ^(boot)[|] abc1234")"
  _t "a line with none says nothing"              "" "$(lq_line_families "--prove --tests xtask abc1234")"
  _t "the sweep's families are the union"         "^(boot)[|]|^(documented)[|]" \
     "$(printf -- '--prove --families ^(boot)[|] aaa1111\n--prove --tests xtask bbb2222\n--prove --families ^(documented)[|] ccc3333\n' | lq_families_union)"
  _t "  ...deduplicated"                          "^(boot)[|]" \
     "$(printf -- '--prove --families ^(boot)[|] aaa1111\n--prove --families ^(boot)[|] bbb2222\n' | lq_families_union)"
  _t "  ...and empty when no line names one"      "" "$(printf -- '--prove --tests xtask aaa1111\n' | lq_families_union)"
  _t "the sweep measures the base when nothing else has" 1 "$(grep -cF 'lq_base_red_replay "$tree" "$dir" "$key"' "$LQ_SRC")"
  _t "  ...on a box the lines did not take"       1 "$(grep -c '^lq_base_red_[r]eplay() {' "$0")"
  _t "  ...and the batch it sends has NO hashes"  1 "$(grep -c "printf -- '--prove --famil[i]es %s.n' " "$0")"
  _t "the landed batch teaches the new tip"       1 "$(grep -c 'lq_base_red_learn "\$newtip"' "$0")"

  # ── THE SWEEP PROBES THE FLEET ONCE, NOT ONCE PER LINE ───────────────────────────────────────
  # MEASURED 2026-09-10: the sweep of twelve pre-proofs took from 18:41 to 19:1x simply to
  # DISPATCH. Each line asked `fleet_pick_host` for a box, and each of those calls walked
  # twenty-three boxes ONE AT A TIME with a `timeout 15 ssh … test -d` apiece — and asked again,
  # up to four times, whenever the box it was handed was one this sweep already held. The fleet was
  # asked the same question hundreds of times, serially, before the first proof started.
  # The transport now makes ONE ROUND (ci-remote-lib.sh: fleet_table_open, every box at once inside
  # the same 15 s) and the sweep allocates from that table: one call per line, naming the boxes it
  # already holds so a repeat is never handed out and never has to be asked for twice.
  echo "landq4 selftest: the sweep probes the fleet once, allocates from the table, and drops a box it lost"
  _t "the sweep opens ONE table before it dispatches"      1 "$(grep -c 'fleet_table_open "\$dir/fleet-table"' "$0")"
  _t "  ...and closes it only once every line is scored"   1 "$(grep -c '^  fleet_table_close$' "$0")"
  _t "a line asks for a box ONCE, naming the ones it holds" 2 "$(grep -c 'fleet_pick_host \$hosts' "$LQ_SRC")"
  _t "  ...and the base replay's box is reserved BEFORE them" 1 \
     "$( [ "$(grep -nF 'basehost="$(lq_base_replay_reserve ' "$LQ_SRC" | head -n1 | cut -d: -f1)" \
          -lt "$(grep -nF 'cand="$( fleet_pick_host $hosts )"' "$LQ_SRC" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  _t "  ...so no line re-probes the fleet looking for one"  0 "$(grep -c 'try=\$((try + 1))' "$0")"
  # …OR THE WORD `latchkey` WHEN NO BOX WAS TAKEN. The status file's question is "where is this
  # line being proven", and on the latchkey backend the honest answer is not a box id; an empty
  # file would read as "nowhere", which is the one thing it was never.
  _t "the box each line went to is written down"            2 "$(grep -c 'printf .%s.n. "\${cand:-latchkey}" >"\$dir/line-\$i.host"' "$0")"
  _t "a line that LOST its box drops it from the table"     1 "$(grep -c 'fleet_table_drop "\$(cat "\$dir/line-\$j.host"' "$0")"
  # THE RECORDER'S BOUNDS ARE FORWARDED, NEVER INVENTED HERE. A bound this runner set would be a
  # laptop's guess about a box's speed; the box measures its own load (land.sh's land_oracle_bounds).
  # What the runner owes is the CHANNEL: an operator who exported one gets it on the box.
  _t "the runner forwards a bound the operator set" 2 "$(grep -c '^\[ -n "\${ORACLE_' "$0")"
  _t "  ...and invents neither of them"             0 "$(grep -c '^export ORACLE_\(BOOT\|EGRESS\)' "$0")"

  echo "landq4 selftest: a CI run queued for over an hour is no verdict to wait for"
  local now0; now0="$(lq_epoch 2026-09-11T00:00:00Z)"
  _t "the stamp parses on this host"           1 "$( [ -n "$now0" ] && echo 1 || echo 0)"
  _t "queued 81 minutes: none"                 none    "$(lq_ci_verdict "queued null 2026-09-10T22:39:00Z" "$now0")"
  _t "queued 10 minutes: running"              running "$(lq_ci_verdict "queued null 2026-09-10T23:50:00Z" "$now0")"
  _t "in_progress for two hours: still running" running "$(lq_ci_verdict "in_progress null 2026-09-10T22:00:00Z" "$now0")"
  _t "completed success"                       success "$(lq_ci_verdict "completed success 2026-09-10T22:00:00Z" "$now0")"
  _t "completed timed_out is failure"          failure "$(lq_ci_verdict "completed timed_out 2026-09-10T22:00:00Z" "$now0")"
  _t "completed cancelled"                     cancelled "$(lq_ci_verdict "completed cancelled 2026-09-10T22:00:00Z" "$now0")"
  _t "no run at all: none"                     none    "$(lq_ci_verdict "" "$now0")"
  _t "gh's null null: none"                    none    "$(lq_ci_verdict "null null null" "$now0")"
  _t "queued with an unreadable stamp: running (never guessed)" running "$(lq_ci_verdict "queued null whenever" "$now0")"
  _t "ci_conclusion asks gh for createdAt"     1 "$(grep -c '^        --json status,conclusion,createdAt' "$0")"

  echo "landq4 selftest: the staged engine (the sweep runs the copy whose root is THIS tree)"
  local savedW2="$W" savedS="$SCRIPTS"; W="$root/tree"; SCRIPTS="$root/scratch/scripts"
  mkdir -p "$SCRIPTS" "$W"
  printf '#!/usr/bin/env bash\nhere="$(cd "$(dirname "$0")/.." && pwd)"\necho "here=$here"\n' >"$SCRIPTS/land.sh"
  printf '#!/usr/bin/env bash\nREPO="$(cd "$(dirname "$0")/.." && pwd)"\necho "REPO=$REPO"\n' >"$SCRIPTS/land-remote.sh"
  printf 'rlog() { :; }\n' >"$SCRIPTS/ci-remote-lib.sh"
  lq_stage_engine
  _t "land.run.sh's root is the runner's tree, not the scratch" "here=$W" "$(bash "$W/target/gate/land.run.sh")"
  _t "land-remote.sh's REPO is the runner's tree"               "REPO=$W" "$(bash "$W/target/gate/land-remote.sh")"
  # THREE: the live lines, the chained holds, and the base replay that measures the tip itself —
  # and all three now go through ONE dispatcher (lq_dispatch_preprove), which is the point: a
  # backend cannot be half-adopted by a sweep that forgot one of its three loops. So the count that
  # used to be 3 launches is 3 DISPATCHES and exactly ONE fleet launch, inside the dispatcher.
  _t "the sweep dispatches live lines, chains and the base alike"  3 \
     "$(grep -c 'lq_dispatch_preprove "\$tree"' "$0")"
  _t "  ...and the fleet leg is launched from exactly one place"   1 \
     "$(grep -c 'bash "\$tree/target/gate/land.run.sh" --preprove' "$0")"
  _t "the sweep never launches \$SCRIPTS/land.sh"              0 "$(grep -c 'bash "\$SCRIPTS/land.sh" --preprove' "$0")"

  # ── BUSBAR_PROVE_BACKEND, DRIVEN OVER A STUBBED `latchkey` ────────────────────────────────────
  # The dispatcher is the one thing in this file that decides which MACHINE a proof runs on, so it
  # is driven here rather than described: two stub scripts stand in for prove-latchkey.sh and the
  # staged fleet engine, each of them recording that it ran and returning a code the dispatcher has
  # to act on. No runner is rented and no box is touched.
  echo "landq4 selftest: BUSBAR_PROVE_BACKEND routes the sweep's pre-proof, and the fleet is the fallback"
  local bt="$root/backend"; mkdir -p "$bt/scripts" "$bt/target/gate"
  # BOTH STUBS WHERE THE DISPATCHER REALLY LOOKS: the STAGED transport under target/gate (never
  # `$tree/scripts` — that is the live defect this file now refuses), and the staged fleet engine
  # beside it. A stub placed where the code does not look is a case that passes by not running.
  _lkstub() { printf '#!/usr/bin/env bash\necho latchkey "$@" >>"%s/calls"\nexit ${LK_STUB_RC:-0}\n' "$bt" >"$bt/target/gate/prove-latchkey.run.sh"; chmod +x "$bt/target/gate/prove-latchkey.run.sh"; }
  _flstub() { printf '#!/usr/bin/env bash\necho fleet "$@" >>"%s/calls"\nexit 0\n' "$bt" >"$bt/target/gate/land.run.sh"; chmod +x "$bt/target/gate/land.run.sh"; }
  _lkstub; _flstub
  printf -- '--prove --tests xtask\n' >"$bt/b.batch"
  _bk() { # $1 = backend, $2 = host, $3 = stub rc; prints "<rc> <who>"
    local rc who
    : >"$bt/calls"
    LANDQ_PROVE_BACKEND="$1" LK_STUB_RC="$3" lq_dispatch_preprove "$bt" "$2" "$bt/b.batch" >/dev/null 2>&1
    rc=$?
    who="$(awk '{print $1}' "$bt/calls" | tr '\n' ',' | sed 's/,$//')"
    printf '%s %s\n' "$rc" "${who:-nobody}"
  }
  # THE DEFAULT IS THE FLEET, and it is the default because an unset variable must mean "what this
  # engine did yesterday".
  _t "an unset BUSBAR_PROVE_BACKEND is the fleet"            fleet "$(BUSBAR_PROVE_BACKEND=""; LANDQ_PROVE_BACKEND="${BUSBAR_PROVE_BACKEND:-fleet}"; lq_preprove_backend)"
  _t "BUSBAR_PROVE_BACKEND=latchkey is a backend this engine has" latchkey "$(LANDQ_PROVE_BACKEND=latchkey; lq_preprove_backend)"
  # A BACKEND NOBODY IMPLEMENTED IS NOT A SILENT PASS-THROUGH. It falls back to the fleet AND says
  # so: a typo that quietly proved nothing on a machine nobody named is the shape this refuses.
  _t "a backend this engine does not have falls back to the fleet" fleet "$(LANDQ_PROVE_BACKEND=azure; lq_preprove_backend 2>/dev/null)"
  # THE REFUSAL IS SAID OUT LOUD, IN THE ENGINE'S OWN LOG — `lq_log` appends to $L, so the case
  # points $L at a scratch file and reads it back. Driving the real function, not describing it.
  _t "  ...and says so in the log"                           1 \
     "$( L="$bt/backend.log"; : >"$L"; LANDQ_PROVE_BACKEND=azure lq_preprove_backend >/dev/null; \
         grep -c 'is not a backend this engine has' "$bt/backend.log" )"
  _t "the fleet backend launches the staged engine"          "0 fleet"    "$(_bk fleet i-0stub 0)"
  _t "the latchkey backend launches prove-latchkey.sh"       "0 latchkey" "$(_bk latchkey i-0stub 0)"
  _t "  ...and its RED is the line's red, not a fallback"    "1 latchkey" "$(_bk latchkey i-0stub 1)"
  # 75 IS "NO JOB WAS CREATED", WHICH IS NOT A VERDICT. The workspace's 20-runner cap is shared with
  # CI and was measured full for seven consecutive submissions; a line that met a full account has
  # learned NOTHING about its tree, so it goes to a box rather than being scored.
  _t "a latchkey 75 overflows onto the box the sweep holds"  "0 latchkey,fleet" "$(_bk latchkey i-0stub 75)"
  _t "  ...and with NO box to fall back to it is an honest 75" "75 latchkey" "$(_bk latchkey '' 75)"
  # THE CAP. Twelve, not twenty, so the CI this is replacing still has runners.
  _t "the latchkey job cap defaults to twelve"               12 "$(LATCHKEY_MAX_JOBS="${LATCHKEY_MAX_JOBS:-12}"; echo "$LATCHKEY_MAX_JOBS")"
  _t "a full cap takes a box instead of a runner"            "0 fleet" "$(LATCHKEY_MAX_JOBS=0 _bk latchkey i-0stub 0)"
  # AND A FULL CAP ASKS THE ALLOCATOR FOR ONE, where a free slot does not.
  # THE TREE IS AN ARGUMENT, because the answer depends on whether THAT tree has a staged transport
  # — the second half of the live defect. $bt is the stub tree, and it has one.
  _t "a free latchkey slot needs no fleet box"               1 "$(LANDQ_PROVE_BACKEND=latchkey LATCHKEY_MAX_JOBS=12 lq_preprove_needs_box "$bt"; echo $?)"
  _t "  ...a full cap does"                                  0 "$(LANDQ_PROVE_BACKEND=latchkey LATCHKEY_MAX_JOBS=0 lq_preprove_needs_box "$bt"; echo $?)"
  _t "  ...and the fleet backend always does"                0 "$(LANDQ_PROVE_BACKEND=fleet lq_preprove_needs_box "$bt"; echo $?)"

  # ── THE TRANSPORT COMES FROM THE ENGINE HOME, NOT FROM THE TREE (live defect, 18:09) ──────────
  # The first live latchkey sweep ran `bash "$tree/scripts/prove-latchkey.sh"` and the runner tree
  # is the checkout at the LANDED tip, which does not carry an unlanded script. Every line came back
  # `No such file or directory`, exit 127. Driven here over a stubbed engine home whose scripts/ has
  # the transport and whose TREE deliberately does not — which is the live tree's exact shape.
  echo "landq4 selftest: the latchkey transport is staged from the engine home, and an absent one is not a red"
  local eh="$root/enginehome"; mkdir -p "$eh/scripts" "$bt/target/gate"
  printf '#!/usr/bin/env bash\nREPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"\necho staged "$REPO" "$@" >>"%s/calls"\nexit ${LK_STUB_RC:-0}\n' "$bt" >"$eh/scripts/prove-latchkey.sh"
  printf '#!/usr/bin/env bash\nhere="x"\n' >"$eh/scripts/land.sh"
  printf '#!/usr/bin/env bash\nREPO="x"\n' >"$eh/scripts/land-remote.sh"
  printf 'rlog() { :; }\n' >"$eh/scripts/ci-remote-lib.sh"
  [ -e "$bt/scripts/prove-latchkey.sh" ] && rm -f "$bt/scripts/prove-latchkey.sh"
  _t "the TREE does not carry the transport (the live shape)" 0 \
     "$( [ -f "$bt/scripts/prove-latchkey.sh" ] && echo 1 || echo 0)"
  ( SCRIPTS="$eh/scripts"; W="$bt"; lq_stage_engine "$bt" ) >/dev/null 2>&1
  _t "  ...so lq_stage_engine puts it under target/gate"     1 \
     "$( [ -f "$bt/target/gate/prove-latchkey.run.sh" ] && echo 1 || echo 0)"
  # AND ITS REPO IS THIS TREE, NOT THE SCRATCH IT WAS COPIED FROM — the bug this function's header
  # is about, one script further on: a transport rooted in the scratch packs the wrong tree.
  _t "  ...with REPO pinned to the tree, not the engine home" 1 \
     "$(grep -c "^REPO=\"$bt\"$" "$bt/target/gate/prove-latchkey.run.sh")"
  : >"$bt/calls"
  _t "  ...and the dispatcher runs THAT copy"                "0 staged" \
     "$(LANDQ_PROVE_BACKEND=latchkey lq_dispatch_preprove "$bt" i-0stub "$bt/b.batch" >/dev/null 2>&1; \
        printf '%s %s\n' "$?" "$(awk 'NR==1{print $1}' "$bt/calls")")"
  # AN ENGINE HOME ARCHIVED BEFORE THIS LANDED HAS NO TRANSPORT. It must take a box, not a 127.
  # (lq_stage_engine has just overwritten target/gate with the stub home's copies, so the fleet
  # stub goes back first — otherwise the fallback case would be measuring the stub home's land.sh.)
  _flstub
  rm -f "$bt/target/gate/prove-latchkey.run.sh"
  _t "a home with no transport asks the allocator for a box"  0 \
     "$(LANDQ_PROVE_BACKEND=latchkey LATCHKEY_MAX_JOBS=12 lq_preprove_needs_box "$bt"; echo $?)"
  _t "  ...and dispatches to the fleet rather than exit 127"  "0 fleet" "$(_bk latchkey i-0stub 0)"
  _t "  ...and with no box it is an honest 75, never a 127"   "75 nobody" "$(_bk latchkey '' 0)"
  # A HOME WITHOUT THE SOURCE LEAVES NO STALE COPY BEHIND. A transport from a previous home would
  # otherwise go on being dispatched after the home that owned it was replaced.
  : >"$bt/target/gate/prove-latchkey.run.sh"
  ( SCRIPTS="$root/no-such-home/scripts"; W="$bt"; lq_stage_engine "$bt" ) >/dev/null 2>&1
  _t "a home without the transport removes the stale staged copy" 0 \
     "$( [ -f "$bt/target/gate/prove-latchkey.run.sh" ] && echo 1 || echo 0)"

  # ── AN EXIT CODE THAT CANNOT BE A VERDICT IS NOT A RED (live defect, 18:09) ───────────────────
  # 127 was recorded `RED <tip>@…` in preproved.txt and the lines were parked `#RED-preproof`.
  # Nothing had been built, picked or judged.
  echo "landq4 selftest: 126/127/70 are the harness's codes, never a tree's verdict"
  local hl="$root/harness.log"; : >"$hl"
  _t "the shell's could-not-find (127) is NONE:harness"      "NONE:harness" "$(lq_preproof_verdict 127 "$hl")"
  _t "the shell's could-not-execute (126) is too"            "NONE:harness" "$(lq_preproof_verdict 126 "$hl")"
  _t "a driver's give-up (70) is too"                        "NONE:harness" "$(lq_preproof_verdict 70 "$hl")"
  # …AND A REAL VERDICT IS STILL A REAL VERDICT. A rule that swallowed rc 1 would park nothing ever
  # again, which is the opposite failure and the more expensive one.
  _t "a prover's own RED (1) is still RED"                   RED    "$(lq_preproof_verdict 1 "$hl")"
  _t "a prover's own refusal (2) is unchanged"               RED    "$(lq_preproof_verdict 2 "$hl")"
  _t "  ...and 0 is still GREEN"                             GREEN  "$(lq_preproof_verdict 0 "$hl")"
  # 75 IS LEFT EXACTLY WHERE IT WAS: already a NONE, already never a park. Relabelling it would
  # rewrite every reclaimed box in the ledger.
  _t "75 is still a NONE (and still the box's)"              "NONE:box" "$(lq_preproof_verdict 75 "$hl")"
  # THE CHAINED PATH TOO: a rung whose dispatcher died 127 was never judged either.
  printf 'RED\t--prove --tests xtask\n' >"$root/harness.result"
  _t "a chained rung is NONE:harness on 127, not RED"        "NONE:harness" \
     "$(lq_chain_preproof_verdict 127 "$hl" "$root/harness.result" '--prove --tests xtask')"
  _t "  ...and still RED when the prover really said so"     RED \
     "$(lq_chain_preproof_verdict 1 "$hl" "$root/harness.result" '--prove --tests xtask')"
  # AND A CHAIN ROOT IS NOT SCORED RED ON ONE EITHER — a red root empties every rung behind it.
  local sd="$root/sweepdir"; mkdir -p "$sd"
  printf -- '--prove --tests xtask\n' >"$sd/line-1.root"
  printf 'k\n' >"$sd/line-1.chainkey"; : >"$sd/line-1.log"
  cp "$root/harness.result" "$sd/line-1.batch.result"
  echo 127 >"$sd/line-1.rc"
  _t "a chain ROOT is not proven red by a 127"               1 "$(lq_slot_root_red "$sd" 1 ''; echo $?)"
  echo 1 >"$sd/line-1.rc"
  _t "  ...and IS when the prover proved it red"             0 "$(lq_slot_root_red "$sd" 1 ''; echo $?)"
  # THE SWEEP READS EVERY LINE IT WAS GIVEN, even though each child it starts is backgrounded while
  # the loop is still reading its list: a child that inherited that stdin ate the next line (three
  # disjoint lines, two boxes chosen, no "out of free boxes"). The stub engine swallows its stdin
  # on purpose; the stub library hands out a fresh box per ask.
  echo "landq4 selftest: the sweep hands out EVERY disjoint line (a child does not eat the next one)"
  printf '#!/usr/bin/env bash\ncat >/dev/null\nexit 0\n' >"$SCRIPTS/land.sh"
  # The stub allocator takes a second per ask, as the real one takes several: without that the
  # parent reads all three lines before any child has had the chance to eat one, and the case
  # cannot go red.
  printf 'rlog() { :; }\nremote_wrapper() { :; }\nfleet_pick_host() { sleep 1; echo "box-$RANDOM$RANDOM"; }\n' >"$SCRIPTS/ci-remote-lib.sh"
  local savedQ0="$Q" savedPP1="$PP" savedL1="$L" savedP="$PREPROVE_LINES"
  Q="$root/sweepq.txt"; PP="$root/sweep-pp.txt"; : >"$PP"; L="$root/sweep-log.txt"; : >"$L"; PREPROVE_LINES=6
  printf -- '--prove %s\n--prove %s\n--prove %s\n' "$ha" "$hb" "$hc" >"$Q"
  ( cd "$repo" && W="$repo" SCRIPTS="$SCRIPTS" lq_preprove_sweep ) >/dev/null 2>&1
  _t "three lines out, three recorded" 3 "$(grep -c . "$PP")"
  _t "the sweep says three went out"   1 "$(grep -c 'pre-prove: 3 line(s) out' "$L")"
  rm -rf "$repo/target/gate/preprove-"*
  Q="$savedQ0"; PP="$savedPP1"; L="$savedL1"; PREPROVE_LINES="$savedP"
  W="$savedW2"; SCRIPTS="$savedS"

  echo "landq4 selftest: the lock (one runner per host; a dead holder is stale)"
  local savedLock="$LOCK"; LOCK="$root/lock"
  _t "an absent lock is taken"              0 "$(lq_lock_acquire $$ >/dev/null; echo $?)"
  _t "  ...and names this pid"              "$$" "$(head -n1 "$LOCK")"
  _t "  ...and the runner pid is exported"  "$$" "$(lq_lock_acquire $$ >/dev/null; echo "$LANDQ_RUNNER_PID")"
  # The export must reach the CALLER, not just the subshell a `$(...)` would run the function in:
  # this case takes the lock in this shell and reads the variable here; the next one pins the main
  # flow to that form, because the substitution form passed the case above while the runner refused
  # its own batch with "landq4.sh (pid N) holds the landing lock".
  unset LANDQ_RUNNER_PID; lq_lock_acquire $$ >/dev/null
  _t "  ...in the calling shell, not a subshell" "$$" "${LANDQ_RUNNER_PID:-unset}"
  _t "the main flow takes the lock in its own shell" 0 "$(grep -c 'holder="\$(lq_lock_acquire' "$0")"
  _t "a live holder refuses a second runner" "$$" "$(lq_lock_acquire 1 2>/dev/null; true)"
  printf '999999999\n' >"$LOCK"
  _t "a dead holder is taken over"          0 "$(lq_lock_acquire $$ >/dev/null; echo $?)"
  lq_lock_release $$
  _t "release removes the lock"             1 "$( [ -f "$LOCK" ]; echo $?)"
  LOCK="$savedLock"

  echo "landq4 selftest: the popper"
  Q="$root/popq.txt"; PP="$pp"; L="$root/log.txt"; : >"$L"; W="$repo"
  printf -- '--prove %s\n--prove %s\n--prove %s\n' "$ha" "$hb" "$hc" >"$Q"
  local n; n="$(lq_pop tip1 4 "$root/b.txt" "$root/k.txt")"
  _t "one line popped (only the pre-proven green)" 1 "$n"
  _t "it is the green one" "--prove $ha" "$(cat "$root/b.txt")"
  _t "the red one is parked #RED-preproof" 1 "$(grep -c '^#RED-preproof /l/2 ' "$root/k.txt" || true)"
  _t "the unproven one is kept, unmarked"  1 "$(grep -cx -- "--prove $hc" "$root/k.txt" || true)"
  # WITH NOTHING PRE-PROVEN, THE QUEUE RUNS AS IT ALWAYS DID. The stage is an accelerator; a fleet
  # that is unreachable must not stop the queue.
  printf -- '--prove %s\n--prove %s\n--prove %s\n' "$ha" "$hb" "$hc" >"$Q"
  n="$(lq_pop tipX 4 "$root/b2.txt" "$root/k2.txt")"
  _t "no records at this tip -> the ordinary pop" 3 "$n"

  # ── RULE 2c MADE REAL AT THE POP: A BASE-STATE RED IS NONE, NOT A PARK ────────────────────────
  # lq_preproof_verdict rules on this at SWEEP time and always has. The POPPER did not: it parked
  # every recorded RED, so a row written by an older engine — or by a sweep whose log grew its base
  # sentence after the verdict was taken — parked a line that nothing is wrong with, and the
  # integrator had to un-park it by hand. Audit 14 measured it still doing so.
  echo "landq4 selftest: a base-state red is NONE at the pop too, and the line stays live"
  local bslog="$root/base-state.log" ordlog="$root/ordinary-red.log" gatelog="$root/gate-rows.log"
  printf 'FAIL ceiling-rose: busbar-core x api ROSE since the base\n' >"$bslog"
  printf 'land.sh: RED — tests failed in: busbar\n' >"$ordlog"
  printf 'land.sh: RED — construction gate rows red that the standing list does not name: x\n' >"$gatelog"
  mkdir -p "$repo/qa"; rm -f "$repo/qa/construction.toml"
  _t "an ordinary red is not a base-state red" 1 "$(lq_base_state_red "$ordlog" "$repo"; echo $?)"
  # THE RAISES PRECONDITION IS GONE (audit 17): it was false on the whole current tip, and it was
  # the ONLY difference between what the sweep decided and what the popper decided about one log.
  _t "the base phrase with NO raises on the tip is the base's" 0 "$(lq_base_state_red "$bslog" "$repo"; echo $?)"
  _t "  ...and the sweep says the same of the same log" "NONE:base" "$(lq_preproof_verdict 1 "$bslog")"
  _t "  ...as does the popper's reader"        0 "$(lq_base_state_red "$bslog" "$repo"; echo $?)"
  _t "an ordinary red agrees the other way too" RED "$(lq_preproof_verdict 1 "$ordlog")"
  _t "one predicate, no second regex reader"   0 "$(grep -c 'grep -qiE "\$LQ_BASE_STATE_RE" "\$2"' "$0")"
  printf '[gate.ceiling_raises.core-x-api]\nfigure = 60\n' >"$repo/qa/construction.toml"
  _t "the base phrase on a tip that carries raises is the base's" 0 "$(lq_base_state_red "$bslog" "$repo"; echo $?)"
  _t "  ...as are the construction gate's own words" 0 "$(lq_base_state_red "$gatelog" "$repo"; echo $?)"
  _t "a log that is not on disk is not a base-state red" 1 "$(lq_base_state_red "$root/nosuch.log" "$repo"; echo $?)"
  _t "  ...nor is an empty log path"           1 "$(lq_base_state_red "" "$repo"; echo $?)"
  # AT THE POP. One line, recorded RED at this tip, whose log is the base's: it must be popped, and
  # nothing may be written in front of it.
  local savedPP4="$PP"; PP="$root/pp-basestate.txt"
  printf 'RED%stip1%s%s%s--prove %s\n' "$TAB" "$TAB" "$bslog" "$TAB" "$hb" >"$PP"
  printf -- '--prove %s\n' "$hb" >"$Q"
  n="$(lq_pop tip1 4 "$root/b17.txt" "$root/k17.txt")"
  _t "a base-state red is not parked"          0 "$(grep -c '#RED-preproof' "$root/k17.txt" || true)"
  _t "  ...the line stays live and unmarked"   "--prove $hb" "$(cat "$root/b17.txt")"
  _t "  ...and the ledger says why"            1 "$(grep -c "is the BASE's (a ceiling the head repairs); NONE, left live" "$L" || true)"
  # AND AN ORDINARY RED IS STILL PARKED — the rule narrows nothing else.
  printf 'RED%stip1%s%s%s--prove %s\n' "$TAB" "$TAB" "$ordlog" "$TAB" "$hb" >"$PP"
  n="$(lq_pop tip1 4 "$root/b18.txt" "$root/k18.txt")"
  _t "an ordinary pre-proof red is still parked" 1 "$(grep -c "^#RED-preproof $ordlog " "$root/k18.txt" || true)"
  PP="$savedPP4"; rm -f "$repo/qa/construction.toml"
  Q="$savedQ"; PP="$savedPP"; L="$savedL"; W="$savedW"

  # ── A HOLD THAT NAMES A SHA RELEASES ITSELF (see lq_release_holds) ─────────────────────────────
  # The integrator cannot un-hold a line from inside the engine, and the engine used to be unable to
  # un-hold one at all: a `#HOLD-after-<sha>` line stayed a comment until somebody edited the file,
  # which meant a queue that had already earned its release sat still until the next human tick.
  echo "landq4 selftest: a #HOLD-after-<sha> releases itself when the sha has landed"
  savedQ="$Q"; savedW="$W"; W="$repo"
  local hland hside
  hland="$(git -C "$repo" rev-parse --short=9 HEAD)"
  git -C "$repo" checkout -q -b hold-side
  printf 'side\n' >"$repo/side.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm side
  hside="$(git -C "$repo" rev-parse --short=9 HEAD)"
  git -C "$repo" checkout -q -
  Q="$root/holdq.txt"
  printf '# a note about #HOLD-after-%s that is only a note\n#HOLD-after-%s --prove landed\n#HOLD-after-%s --prove unlanded\n#HOLD-after-strike --prove worded\n#HOLD-after-%s #K5-L3 --prove twotags\n#K5-L3 #HOLD-after-%s --prove tagsecond\n#HOLD-after-zzzzzzz --prove nothex\n--prove live\n' \
    "$hland" "$hland" "$hside" "$hland" "$hland" >"$Q"
  lq_release_holds "$repo" >"$root/rel.txt"
  _t "the landed hold is released"             1 "$(grep -cx -- "--prove landed" "$Q" || true)"
  # Three lines carry that sha, and each release is its own log line: the ledger reads how many
  # lines a landing freed, not merely that something was freed.
  _t "  ...and the release is logged, by tag"  3 "$(grep -cx "released #HOLD-after-$hland: landed" "$root/rel.txt" || true)"
  _t "a sha that has NOT landed still holds"   1 "$(grep -cx -- "#HOLD-after-$hside --prove unlanded" "$Q" || true)"
  _t "  ...and is not logged as released"      0 "$(grep -c "$hside" "$root/rel.txt" || true)"
  _t "a hold on a WORD is the integrator's"    1 "$(grep -cx -- '#HOLD-after-strike --prove worded' "$Q" || true)"
  _t "a tag that is not hex is a word"         1 "$(grep -cx -- '#HOLD-after-zzzzzzz --prove nothex' "$Q" || true)"
  _t "one tag of several is dropped, the rest hold" 1 "$(grep -cx -- '#K5-L3 --prove twotags' "$Q" || true)"
  _t "  ...wherever in the prefix it sits"     1 "$(grep -cx -- '#K5-L3 --prove tagsecond' "$Q" || true)"
  _t "a comment that merely mentions a tag is untouched" 1 "$(grep -c "^# a note about #HOLD-after-$hland " "$Q" || true)"
  _t "a live line is untouched"                1 "$(grep -cx -- '--prove live' "$Q" || true)"
  _t "the file keeps every line it had"        8 "$(grep -c . "$Q" || true)"
  # A QUEUE WITH NOTHING TO RELEASE IS NOT REWRITTEN — the file is left byte-identical, so a
  # release is always something that happened rather than a rewrite that might have.
  printf '#HOLD-after-%s --prove unlanded\n--prove live\n' "$hside" >"$Q"
  local before; before="$(cksum <"$Q")"
  lq_release_holds "$repo" >"$root/rel2.txt"
  _t "nothing to release: the queue is untouched" "$before" "$(cksum <"$Q")"
  _t "  ...and nothing is logged"              0 "$(grep -c . "$root/rel2.txt" || true)"
  # ── THE WAY THIS TREE ACTUALLY LANDS: `cherry-pick -x` ────────────────────────────────────────
  # `merge-base --is-ancestor` is the obvious question and it is the wrong one. land.sh lands with
  # `cherry-pick -x`, so the landed commit is a NEW sha and the sha the queue names is an ancestor
  # of nothing: audit 15 measured 30 of 30 commits on the tip carrying a cherry-pick trailer and 0
  # of the batch's picks being ancestors. The fixture lands the held commit the way the engine does.
  local hpick hpicked mainbr
  mainbr="$(git -C "$repo" rev-parse --abbrev-ref HEAD)"
  git -C "$repo" checkout -q -b hold-pick-src
  printf 'picked\n' >"$repo/picked.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm picked
  hpick="$(git -C "$repo" rev-parse --short=9 HEAD)"
  git -C "$repo" checkout -q "$mainbr"
  git -C "$repo" cherry-pick -x "$hpick" >"$root/pick.log" 2>&1 || _t "the fixture's cherry-pick took" 0 1
  hpicked="$(git -C "$repo" rev-parse --short=9 HEAD)"
  _t "the landing made a NEW sha"              1 "$( [ "$hpick" != "$hpicked" ] && echo 1 || echo 0)"
  _t "  ...and the picked sha is an ancestor of nothing" 1 "$(git -C "$repo" merge-base --is-ancestor "$hpick" HEAD 2>/dev/null; echo $?)"
  _t "  ...but the trailer names it"           1 "$(git -C "$repo" log --format=%b -1 | grep -c "cherry picked from commit " || true)"
  _t "a hold on a cherry-PICKED sha is landed" 0 "$(lq_landed_here "$repo" "$hpick"; echo $?)"
  _t "  ...and one on a sha nobody picked is not" 1 "$(lq_landed_here "$repo" "$hside"; echo $?)"
  printf '#HOLD-after-%s --prove picked\n#HOLD-after-%s --prove stillheld\n' "$hpick" "$hside" >"$Q"
  lq_release_holds "$repo" >"$root/rel3.txt"
  _t "the cherry-picked hold is released"      1 "$(grep -cx -- '--prove picked' "$Q" || true)"
  _t "  ...and logged"                         1 "$(grep -cx "released #HOLD-after-$hpick: landed" "$root/rel3.txt" || true)"
  _t "  ...while the unpicked one still holds" 1 "$(grep -cx -- "#HOLD-after-$hside --prove stillheld" "$Q" || true)"
  _t "the main flow releases holds before it reads the head" 1 "$(grep -c '^  lq_release_holds "\$W" | while' "$0")"

  # ── THE QUEUE IS REWRITTEN BY ITS READER, ONLY IF IT MOVED, AND ONLY IF NOBODY ELSE MOVED IT ───
  # The runner used to rewrite land-queue.txt in full from its own snapshot on EVERY loop, unlocked:
  # an integrator's edit inside the read→rewrite window was reverted with no error and no log line,
  # and the runner then idled on a queue that no longer said what its owner had just said. (Audit 14.)
  echo "landq4 selftest: the queue rewrite (only what changed, under a lock, and only if it did not move)"
  local savedQ5="$Q" savedQL="$QLOCK"
  Q="$root/lockq.txt"; QLOCK="$root/lockq.lock"; rm -rf "$QLOCK"
  printf -- '--prove one\n--prove two\n' >"$Q"
  # A STAMP THAT DOES NOT MATCH ITSELF REFUSES EVERY REWRITE. These two cases are the ones the
  # fleet box went red on: on Linux the first form of this asked GNU stat for FILESYSTEM status,
  # whose free-block counts move between two calls, and the runner then refused its own writes.
  _t "the stamp is stable while the file is"   1 "$(a="$(lq_qstamp)"; b="$(lq_qstamp)"; [ "$a" = "$b" ] && echo 1 || echo 0)"
  _t "  ...and is mtime:cksum, on one line"    1 "$(lq_qstamp | grep -cxE '[0-9]+:[0-9]+ [0-9]+' || true)"
  _t "the stamp moves when the file does"      1 "$(a="$(lq_qstamp)"; printf -- '--prove one\n' >>"$Q"; b="$(lq_qstamp)"; [ "$a" != "$b" ] && echo 1 || echo 0)"
  printf -- '--prove one\n--prove two\n' >"$Q"
  # A LOOP THAT CHANGED NOTHING WRITES NOTHING. This is the whole of the first rule: the file that
  # would be written back is compared with the one on disk, so "did this loop change the queue" is
  # measured rather than remembered.
  cp "$Q" "$root/keep-same.txt"
  _t "a loop that popped, parked and released nothing does not rewrite" 1 "$(lq_queue_rewrite "$root/keep-same.txt" "$(lq_qstamp)"; echo $?)"
  _t "  ...and its candidate is dropped"       1 "$( [ -f "$root/keep-same.txt" ]; echo $?)"
  local st1; st1="$(lq_qstamp)"
  printf -- '--prove two\n' >"$root/keep-popped.txt"
  _t "a loop that popped a line does rewrite"  0 "$(lq_queue_rewrite "$root/keep-popped.txt" "$st1"; echo $?)"
  _t "  ...and the queue is what it wrote"     "--prove two" "$(cat "$Q")"
  # THE CASE THIS EXISTS FOR: the runner reads, the integrator edits, the runner writes back.
  printf -- '--prove one\n--prove two\n' >"$Q"
  st1="$(lq_qstamp)"                                                    # the runner reads the queue
  printf -- '--prove two\n' >"$root/keep-race.txt"                       # ...and decides to pop line one
  printf -- '--prove one\n--prove two\n--prove THREE-by-hand\n' >"$Q"   # the integrator edits it meanwhile
  local qr; lq_queue_rewrite "$root/keep-race.txt" "$st1" >"$root/qrw.txt" 2>&1; qr=$?
  _t "an edit made between the read and the rewrite is REFUSED" 2 "$qr"
  _t "  ...and it SURVIVES"                    1 "$(grep -cx -- '--prove THREE-by-hand' "$Q" || true)"
  _t "  ...with every line it had"             3 "$(grep -c . "$Q" || true)"
  _t "  ...and the refusal is logged, in words" 1 "$(grep -c 'REFUSED to rewrite land-queue.txt' "$root/qrw.txt" || true)"

  # ── THE INBOX: WHERE AN INTEGRATOR APPENDS WITHOUT RACING THE RUNNER ──────────────────────────
  # MEASURED 2026-09-10 on T0-D12: lq_queue_rewrite REFUSED twice in one day, both times because
  # the integrator appended a hand-back line to land-queue.txt while the runner was inside its
  # read -> sweep -> pop -> rewrite window. A sweep is six to ten minutes, so that window is very
  # nearly the whole loop: the refusal is not a rare race, it is the normal outcome of typing. The
  # refusal itself is right — an edit must never be silently overwritten — and its cost is that the
  # loop's whole pop is thrown away and taken again, which is how a queue of 120 lines goes nowhere
  # for twenty minutes because two lines were handed back.
  #
  # So there is a file the integrator appends to INSTEAD: target/gate/land-queue.inbox.txt. Nothing
  # reads it but the runner, at the top of its loop, under the queue lock, before the stamp is
  # taken — every line moved to the TAIL of land-queue.txt in the order it was written, the inbox
  # truncated, and only THEN the stamp. An append made at any point after that lands in the inbox,
  # not in the file the stamp describes, so the rewrite at the end of the loop still matches and the
  # pop stands. The line is folded in at the next loop top, one minute later.
  echo "landq4 selftest: the inbox (an append that does not race the runner's rewrite)"
  local savedIB="${INBOX:-}"; INBOX="$root/inbox.txt"; : >"$INBOX"
  printf -- '--prove A\n--prove B\n' >"$Q"
  _t "an empty inbox folds nothing"            0 "$(lq_inbox_fold "$Q" "$INBOX")"
  local ist; ist="$(lq_qstamp)"                                   # the runner stamps AFTER the fold
  printf -- '--prove C-handed-back\n' >>"$INBOX"                  # the integrator, mid-sweep
  printf -- '--prove B\n' >"$root/inbox-keep.txt"                 # the loop pops A
  _t "an inbox append mid-loop does not refuse the rewrite" 0 "$(lq_queue_rewrite "$root/inbox-keep.txt" "$ist"; echo $?)"
  _t "  ...so the pop is taken THIS loop"      "--prove B" "$(cat "$Q")"
  _t "the next loop top folds it"              1 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...to the TAIL of the queue"           "--prove C-handed-back" "$(tail -n1 "$Q")"
  _t "  ...and the inbox is truncated"         0 "$(grep -c . "$INBOX" 2>/dev/null || true)"
  # COMMENTS AND HOLDS TOO, IN ORDER. A hand-back is usually a `#HOLD-after-<sha>` line with a
  # comment above it; an inbox that dropped either would be a queue the integrator has to repair.
  printf '# K5 hand-back\n#HOLD-after-abc1234 --prove held-one\n--prove live-one\n' >"$INBOX"
  _t "comments and holds fold too"             3 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...in the order they were written"     "# K5 hand-back|#HOLD-after-abc1234 --prove held-one|--prove live-one" \
     "$(tail -n3 "$Q" | tr '\n' '|' | sed 's/|$//')"
  # A QUEUE WITH NO FINAL NEWLINE. Appending to it blind would graft the first inbox line onto the
  # last queue line and produce one payload nobody wrote.
  printf -- '--prove A' >"$Q"; printf -- '--prove B\n' >"$INBOX"
  _t "a queue with no final newline gains one" 1 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...so the folded line is its own line" 2 "$(grep -c . "$Q" || true)"
  # AND THE REFUSAL STILL STANDS FOR A DIRECT EDIT. The inbox is an easier door, not an open one.
  printf -- '--prove A\n--prove B\n' >"$Q"; ist="$(lq_qstamp)"
  printf -- '--prove BY-HAND\n' >>"$Q"
  printf -- '--prove B\n' >"$root/inbox-direct.txt"
  _t "a DIRECT edit of land-queue.txt is still refused" 2 "$(lq_queue_rewrite "$root/inbox-direct.txt" "$ist" >/dev/null 2>&1; echo $?)"
  _t "  ...and that edit survives"             1 "$(grep -cx -- '--prove BY-HAND' "$Q" || true)"
  INBOX="$savedIB"
  _t "the runner folds the inbox at the loop top" 1 "$(grep -c '^  infold="$(lq_inbox_fold ' "$LQ_SRC")"
  _t "  ...under the queue lock"               1 \
     "$( [ "$(grep -n '^  if ! lq_qlock; then' "$LQ_SRC" | head -n1 | cut -d: -f1)" \
          -lt "$(grep -n '^  infold="$(lq_inbox_fold ' "$LQ_SRC" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  _t "  ...and the stamp is taken AFTER the fold" 1 \
     "$( [ "$(grep -n '^  infold="$(lq_inbox_fold ' "$LQ_SRC" | head -n1 | cut -d: -f1)" \
          -lt "$(grep -n '^  qstamp="\$(lq_qstamp)"' "$LQ_SRC" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  # ONE WRITER.
  rm -rf "$QLOCK"
  _t "the queue lock is taken"                 0 "$(lq_qlock 2; echo $?)"
  _t "  ...and a second writer does not get it" 1 "$(lq_qlock 1; echo $?)"
  printf '999999999\n' >"$QLOCK/pid"
  _t "a lock whose holder is dead is taken over" 0 "$(lq_qlock 3; echo $?)"
  lq_qunlock
  _t "unlocking releases it"                   1 "$( [ -d "$QLOCK" ]; echo $?)"
  _t "the main flow takes the lock before it pops" 1 "$(grep -c '^  if ! lq_qlock; then' "$0")"
  _t "  ...and a refused rewrite PAGES instead of dropping the pop" 1 \
     "$(grep -c '^    lq_page direct-edit ' "$LQ_SRC")"
  _t "  ...and never rewrites the queue unconditionally" 0 "$(grep -c '^  mv "\$keep" "\$Q"' "$0")"
  Q="$savedQ5"; QLOCK="$savedQL"
  Q="$savedQ"; W="$savedW"


  # ── THE OVERLAP: SWEEP THE NEXT LINES WHILE THIS BATCH PROVES ─────────────────────────────────
  # Every tip move drops the ledger, so the sweep for batch N+1 could not start until batch N had
  # landed — one serial sweep per batch, 38 batches, 54 minutes apiece (audit 16). The tree batch N
  # will make is known before it returns, because `cherry-pick -x` changes the commit and not the
  # tree; these cases prove exactly that, and prove that the prediction is believed only when the
  # LANDED TREE says it was right.
  echo "landq4 selftest: the predicted tip (pre-prove the next lines against the tree this batch will make)"
  local prepo="$root/prepo"; mkdir -p "$prepo"
  git -C "$prepo" init -q
  git -C "$prepo" config user.email landq@selftest; git -C "$prepo" config user.name landq
  git -C "$prepo" config commit.gpgsign false; git -C "$prepo" config core.hooksPath "$root/nohooks"
  printf 'x\n' >"$prepo/base.txt"; git -C "$prepo" add -A; git -C "$prepo" commit -qm base
  local ptip; ptip="$(git -C "$prepo" rev-parse HEAD)"
  local pmain; pmain="$(git -C "$prepo" rev-parse --abbrev-ref HEAD)"
  git -C "$prepo" checkout -q -b psrc
  printf 'p\n' >"$prepo/p.txt"; git -C "$prepo" add -A; git -C "$prepo" commit -qm p
  local hp; hp="$(git -C "$prepo" rev-parse HEAD)"
  printf 'q\n' >"$prepo/q.txt"; git -C "$prepo" add -A; git -C "$prepo" commit -qm q
  local hq; hq="$(git -C "$prepo" rev-parse HEAD)"
  git -C "$prepo" checkout -q -b pclash "$ptip"
  printf 'other\n' >"$prepo/base.txt"; git -C "$prepo" add -A; git -C "$prepo" commit -qm clash1
  printf 'other2\n' >"$prepo/base.txt"; git -C "$prepo" add -A; git -C "$prepo" commit -qm clash2
  local hclash; hclash="$(git -C "$prepo" rev-parse HEAD)"
  git -C "$prepo" checkout -q "$pmain"
  local pbatch="$root/pbatch.txt"
  printf -- '--prove %s\n--prove %s\n' "$hp" "$hq" >"$pbatch"
  local pred psha ptree
  pred="$(lq_predict_tip "$prepo" "$pbatch" "$root/predwt")"
  psha="${pred%% *}"; ptree="${pred##* }"
  _t "a prediction is made for a batch that applies" 1 "$( [ -n "$psha" ] && echo 1 || echo 0)"
  _t "  ...and the runner's OWN tree never moved"    "$ptip" "$(git -C "$prepo" rev-parse HEAD)"
  # NOW LAND IT THE WAY land.sh LANDS: cherry-pick -x, in the batch's order.
  # A REAL LANDING IS MINUTES LATER THAN THE PREDICTION, and a commit carries its committer date:
  # the landed sha differs from the predicted one for that reason alone, which is the whole point of
  # comparing TREES. (Without the date the fixture picks in the same second and the two shas collide,
  # and the case would prove nothing.)
  GIT_COMMITTER_DATE='2030-01-01T00:00:00Z' git -C "$prepo" cherry-pick -x "$hp" >/dev/null 2>&1
  GIT_COMMITTER_DATE='2030-01-01T00:00:01Z' git -C "$prepo" cherry-pick -x "$hq" >/dev/null 2>&1
  local landed; landed="$(git -C "$prepo" rev-parse HEAD)"
  _t "the landed sha is NOT the predicted sha"       1 "$( [ "$landed" != "$psha" ] && echo 1 || echo 0)"
  _t "  ...nor the sha the queue line named"         1 "$( [ "$landed" != "$hq" ] && echo 1 || echo 0)"
  _t "  ...because the trailer made a new commit"    2 "$(git -C "$prepo" log --format=%b "$ptip".. | grep -c 'cherry picked from commit ' || true)"
  _t "the landed TREE **is** the predicted tree"     "$ptree" "$(git -C "$prepo" rev-parse 'HEAD^{tree}')"
  # A PICK THAT DOES NOT APPLY HAS NO PREDICTION — nothing is guessed and nothing is swept.
  printf -- '--prove %s\n' "$hclash" >"$root/pbatch2.txt"
  _t "a conflicting pick yields no prediction"       "" "$(lq_predict_tip "$prepo" "$root/pbatch2.txt" "$root/predwt")"
  _t "  ...and reports rc 1"                         1 "$(lq_predict_tip "$prepo" "$root/pbatch2.txt" "$root/predwt" >/dev/null; echo $?)"
  _t "  ...leaving the scratch worktree unpicked"    "$(git -C "$prepo" rev-parse HEAD)" "$(git -C "$root/predwt" rev-parse HEAD)"
  _t "a batch file that is not there is no prediction" 1 "$(lq_predict_tip "$prepo" "$root/nosuch.txt" "$root/predwt" >/dev/null 2>&1; echo $?)"

  echo "landq4 selftest: the overlapped rows are believed only when the LANDED tree is the predicted one"
  local ppo="$root/pp-overlap.txt"
  printf 'GREEN%s%s%s/l/9%s--prove zz\nGREEN%stipOTHER%s/l/8%s--prove yy\n' \
    "$TAB" "$psha" "$TAB" "$TAB" "$TAB" "$TAB" "$TAB" >"$ppo"
  _t "predicted tree matches: the rows are VALID"    0 "$(lq_preproof_rekey "$psha" "$ptree" "$landed" "$prepo" "$ppo"; echo $?)"
  _t "  ...re-keyed to the tip that landed"          GREEN "$(lq_preproved_status "$landed" "--prove zz" "$ppo")"
  _t "  ...and nothing is left at the prediction"    NONE  "$(lq_preproved_status "$psha" "--prove zz" "$ppo")"
  _t "  ...while another tip's row is untouched"     GREEN "$(lq_preproved_status tipOTHER "--prove yy" "$ppo")"
  # A RED BATCH BISECTS, AND A BISECT LANDS A DIFFERENT TREE: the overlapped pre-proofs are discarded
  # exactly as every stale row has always been.
  printf 'GREEN%s%s%s/l/9%s--prove zz\nGREEN%stipOTHER%s/l/8%s--prove yy\n' \
    "$TAB" "$psha" "$TAB" "$TAB" "$TAB" "$TAB" "$TAB" >"$ppo"
  _t "a bisect landed another tree: NOT valid"       1 "$(lq_preproof_rekey "$psha" "$ptree" "$ptip" "$prepo" "$ppo"; echo $?)"
  _t "  ...and the overlapped rows are gone"         NONE "$(lq_preproved_status "$ptip" "--prove zz" "$ppo")"
  _t "  ...and gone from the prediction too"         NONE "$(lq_preproved_status "$psha" "--prove zz" "$ppo")"
  _t "  ...while another tip's row SURVIVES"         GREEN "$(lq_preproved_status tipOTHER "--prove yy" "$ppo")"
  _t "a landed sha that does not resolve is NOT valid" 1 "$(lq_preproof_rekey "$psha" "$ptree" deadbeef "$prepo" "$ppo"; echo $?)"
  # AND THE POP THEN TAKES THEM WITH NO SECOND SWEEP: a line re-keyed to the landed tip is a
  # pre-proven green at that tip, which is what the popper reads.
  local savedQ6="$Q" savedPP6="$PP" savedL6="$L" savedW6="$W"
  Q="$root/overq.txt"; PP="$ppo"; L="$root/overlog.txt"; : >"$L"; W="$repo"
  printf 'GREEN%s%s%s/l/9%s--prove %s\n' "$TAB" "$psha" "$TAB" "$TAB" "$ha" >"$ppo"
  lq_preproof_rekey "$psha" "$ptree" "$landed" "$prepo" "$ppo"
  printf -- '--prove %s\n--prove %s\n' "$ha" "$hb" >"$Q"
  _t "the next pop takes the overlapped line, and only it" 1 "$(lq_pop "$landed" 4 "$root/ob.txt" "$root/ok.txt")"
  _t "  ...and it is the pre-proven one"             "--prove $ha" "$(cat "$root/ob.txt")"
  Q="$savedQ6"; PP="$savedPP6"; L="$savedL6"; W="$savedW6"

  # A LINE WHOSE FILES MEET THE BATCH'S IS NEVER SWEPT AGAINST THE PREDICTION. The prediction says
  # what the TREE will be; it says nothing about a pick that touches what the batch just changed.
  echo "landq4 selftest: the overlapped sweep claims the in-flight batch's files first"
  local inb="$root/inflight.txt"; printf -- '--prove %s\n' "$ha" >"$inb"
  printf -- '--prove %s\n--prove %s\n' "$ha2" "$hb" >"$root/overq2.txt"
  _t "the overlapping line is held, the disjoint one goes out" \
     "$(printf -- '--prove %s' "$hb")" \
     "$(lq_disjoint_lines 6 "$root/overq2.txt" "$repo" "" "$inb")"
  _t "with no batch in flight both go out" \
     "$(printf -- '--prove %s\n--prove %s' "$ha2" "$hb")" \
     "$(lq_disjoint_lines 6 "$root/overq2.txt" "$repo")"
  _t "a batch file that is not there claims nothing" \
     "$(printf -- '--prove %s\n--prove %s' "$ha2" "$hb")" \
     "$(lq_disjoint_lines 6 "$root/overq2.txt" "$repo" "" "$root/nosuch.txt")"

  echo "landq4 selftest: the main flow overlaps the sweep with the proof"
  _t "the batch is launched in the background"       1 "$(grep -c '^  bash "\$W/target/gate/land.run.sh" --batch "\$batch" >>"\$L" 2>&1 &$' "$0")"
  _t "  ...and waited for, so rc is still the batch's" 1 "$(grep -c '^  wait "\$bpid"$' "$0")"
  _t "the prediction is taken BEFORE the batch is launched" 1 \
     "$( [ "$(grep -n 'read -r predicted predtree' "$0" | head -n1 | cut -d: -f1)" -lt "$(grep -n '^  bash "\$W/target/gate/land.run.sh" --batch' "$0" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  _t "the overlapped sweep proves from the prediction" 1 "$(grep -c 'lq_preprove_sweep "\$LQ_PREDICT" "\$predicted" "\$batch"' "$0")"
  # THE OVERLAPPED SWEEP MUST NOT REAP THE BATCH. lq_preprove_sweep ends with a bare `wait`; run in
  # the runner's own shell it would wait for the backgrounded batch as well, and `wait "$bpid"` on an
  # already-reaped job is rc 127 — the batch's verdict, thrown away, every batch read as red.
  _t "a bare wait in a subshell leaves the batch to its own wait" 0 \
     "$(bash -c 'sleep 1 & bp=$!; ( sleep 0.2 & wait ); wait $bp; echo $?' 2>/dev/null)"
  _t "  ...and in the same shell the verdict is LOST"           127 \
     "$(bash -c 'sleep 1 & bp=$!; sleep 0.2 & wait; wait $bp; echo $?' 2>/dev/null)"
  _t "the main flow runs the overlapped sweep in a subshell"      1 \
     "$(grep -c '^    ( lq_preprove_sweep "\$LQ_PREDICT" "\$predicted" "\$batch" )$' "$0")"
  _t "  ...and is skipped when there is no prediction" 1 "$(grep -c '^    lq_log "overlap: no prediction' "$0")"
  _t "the landed tree is checked against the predicted one" 1 "$(grep -c 'if lq_preproof_rekey "\$predicted" "\$predtree" "\$newtip" "\$W"; then' "$0")"


  # ── AN `in_progress` RUN THE PUSH ITSELF CANCELS IS NOT A RUN TO WAIT FOR ─────────────────────
  echo "landq4 selftest: in_progress on the previous tip, under a workflow that cancels it"
  local wfroot="$root/wf"; mkdir -p "$wfroot/.github/workflows"
  printf 'on: push\nconcurrency:\n  group: ci-${{ github.ref }}\n  cancel-in-progress: true\n\njobs: {}\n' >"$wfroot/.github/workflows/ci.yml"
  _t "a per-ref group that cancels in progress"  0 "$(lq_ci_cancels_in_progress "$wfroot"; echo $?)"
  printf 'on: push\nconcurrency:\n  group: ci-${{ github.ref }}\n  cancel-in-progress: false\n' >"$wfroot/.github/workflows/ci.yml"
  _t "cancel-in-progress false still waits"      1 "$(lq_ci_cancels_in_progress "$wfroot"; echo $?)"
  # A GROUP THAT IS NOT PER-REF cancels somebody else's run, not this branch's.
  printf 'on: push\nconcurrency:\n  group: ci-global\n  cancel-in-progress: true\n' >"$wfroot/.github/workflows/ci.yml"
  _t "a group that is not keyed by the ref waits" 1 "$(lq_ci_cancels_in_progress "$wfroot"; echo $?)"
  # A JOB-LEVEL block is not the workflow's: `^concurrency:` is anchored on purpose.
  printf 'on: push\njobs:\n  a:\n    concurrency:\n      group: ci-${{ github.ref }}\n      cancel-in-progress: true\n' >"$wfroot/.github/workflows/ci.yml"
  _t "a job's own concurrency is not the workflow's" 1 "$(lq_ci_cancels_in_progress "$wfroot"; echo $?)"
  printf 'on: push\njobs: {}\n' >"$wfroot/.github/workflows/ci.yml"
  _t "no concurrency block at all waits"         1 "$(lq_ci_cancels_in_progress "$wfroot"; echo $?)"
  _t "no workflow file at all waits"             1 "$(lq_ci_cancels_in_progress "$root/nosuchtree"; echo $?)"
  # THIS TREE'S OWN CI, read as it stands: the measurement the rule rests on. THE TREE IS THE ONE
  # THE QUEUE LANDS INTO, not the one beside this file: the engine is STAGED — copied to
  # /tmp/land-fanout-<tip>/scripts and run from there — and `dirname $0/..` is then a scratch
  # directory with no .github at all, which made this case red in the very place the integrator
  # runs `bash <script> --selftest` before a restart. LANDQ_ROOT is where the landings happen.
  local ownrepo; ownrepo="$(cd "$(dirname "$0")/.." && pwd)"
  [ -d "$ownrepo/.github/workflows" ] || ownrepo="${LANDQ_ROOT:-$ownrepo}"
  _t "this repository's CI does cancel in progress" 0 "$(lq_ci_cancels_in_progress "$ownrepo"; echo $?)"
  _t "  ...and the staged engine reads the landing tree, not its scratch dir" 1 "$(grep -c 'ownrepo="\${LANDQ_ROOT:-\$ownrepo}"' "$0")"
  # THE VERDICT.
  _t "in_progress under a cancelling workflow is no wait" cancelled-in-progress \
     "$(lq_ci_verdict "in_progress null 2026-09-10T22:00:00Z" "$now0" 1)"
  _t "  ...and without one it still waits"       running "$(lq_ci_verdict "in_progress null 2026-09-10T22:00:00Z" "$now0")"
  _t "  ...and an empty flag is not one"         running "$(lq_ci_verdict "in_progress null 2026-09-10T22:00:00Z" "$now0" "")"
  # THE RULE IS ABOUT `in_progress` AND NOTHING ELSE. Every other status reads as it always did.
  _t "queued under a cancelling workflow: unchanged" running "$(lq_ci_verdict "queued null 2026-09-10T23:50:00Z" "$now0" 1)"
  _t "  ...and the 60-minute escape is unchanged"    none "$(lq_ci_verdict "queued null 2026-09-10T22:39:00Z" "$now0" 1)"
  _t "completed success is unchanged"                success "$(lq_ci_verdict "completed success 2026-09-10T22:00:00Z" "$now0" 1)"
  _t "completed failure is unchanged"                failure "$(lq_ci_verdict "completed failure 2026-09-10T22:00:00Z" "$now0" 1)"
  _t "no run at all is unchanged"                    none "$(lq_ci_verdict "" "$now0" 1)"
  # THE PUSH, AND ITS WORDS.
  _t "ci_conclusion reads the workflow on the tree" 1 "$(grep -c '^  lq_ci_cancels_in_progress "\$W" && cancels=1$' "$0")"
  _t "  ...and hands the flag to the verdict"       1 "$(grep -c '^  lq_ci_verdict "\$out" "" "\$cancels"$' "$0")"
  _t "try_push pushes over it"                      1 "$(grep -c '^    cancelled-in-progress)$' "$0")"
  _t "  ...and says why, in the log"                1 "$(grep -c '^      lq_log "push over in_progress CI on ' "$0")"

  # ── A LANDED TIP REACHES ORIGIN BEFORE THE NEXT SWEEP, NOT AFTER IT ──────────────────────────
  echo "landq4 selftest: a landed-but-unpushed tip is pushed at the loop top, before the sweep"
  local savedW9="$W" savedL9="$L" savedBR9="$BR"
  local orig="$root/origin.git" work="$root/pushwork"
  git init -q --bare "$orig"
  git clone -q "$repo" "$work" >/dev/null 2>&1
  git -C "$work" config user.email landq@selftest; git -C "$work" config user.name landq
  git -C "$work" config commit.gpgsign false; git -C "$work" config core.hooksPath "$root/nohooks"
  git -C "$work" remote remove origin; git -C "$work" remote add origin "$orig"
  BR=simbr; W="$work"; L="$root/pushlog.txt"; : >"$L"
  git -C "$work" push -q origin "HEAD:$BR"
  git -C "$work" fetch -q origin
  # CI IS NOT ASKED OVER THE NETWORK HERE: the conclusion is stubbed, because what is under test is
  # WHEN the push runs, not what GitHub says about the tip before it.
  ci_conclusion() { echo none; }
  _t "an already-pushed tip is a no-op"        0 "$(try_push; echo $?)"
  _t "  ...and says nothing"                   0 "$(grep -c . "$L" || true)"
  printf 'landed\n' >"$work/landed.txt"; git -C "$work" add -A; git -C "$work" commit -qm landed
  try_push >/dev/null 2>&1
  _t "a landed tip is pushed"                  "$(git -C "$work" rev-parse HEAD)" "$(git -C "$work" rev-parse "origin/$BR")"
  _t "  ...and the log names it"               1 "$(grep -c "^pushed $(git -C "$work" rev-parse --short HEAD) " "$L" || true)"
  unset -f ci_conclusion
  W="$savedW9"; L="$savedL9"; BR="$savedBR9"
  # THE ORDER IN THE LOOP: the push is above the census, the sweep and the pop, not below them.
  _t "the loop pushes at its top, and still after the batch" 2 "$(grep -c '^  try_push$' "$0")"
  _t "  ...before it reads the tip"            1 \
     "$( [ "$(grep -n '^  try_push$' "$0" | head -n1 | cut -d: -f1)" -lt "$(grep -n '^  tip="\$(git -C "\$W" rev-parse HEAD)"$' "$0" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  _t "  ...and before the sweep is handed out"  1 \
     "$( [ "$(grep -n '^  try_push$' "$0" | head -n1 | cut -d: -f1)" -lt "$(grep -n 'lq_preprove_sweep; fi$' "$0" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"


  # ── A PARK SAYS WHY, AND THE QUEUE SAYS WHERE IT STANDS, WITHOUT OPENING A LOG ────────────────
  echo "landq4 selftest: a #RED-preproof park carries its reason line"
  local savedQ7="$Q" savedPP7="$PP" savedL7="$L" savedW7="$W" savedD7="$D"
  local rl="$root/reason-land.log" rf="$root/reason-fail.log" re2="$root/reason-err.log" rn="$root/reason-none.log"
  printf 'building\nland.sh: RED — tests failed in: busbar-core\nmore noise\n' >"$rl"
  printf 'FAIL construction: legacy-reach 94 > 92\nland.sh: RED — gate rows red\n' >"$rf"
  printf 'error[E0433]: failed to resolve: use of undeclared crate\n' >"$re2"
  printf 'all quiet\n' >"$rn"
  _t "land.sh's own verdict is the reason"  "land.sh: RED — tests failed in: busbar-core" "$(lq_preproof_reason "$rl")"
  # THE ENGINE'S OWN VERDICT OUTRANKS A ROW IT PRINTED ON THE WAY: "gate rows red" names the gate,
  # a single FAIL row names one figure of it.
  _t "land.sh's verdict outranks a gate row"  "land.sh: RED — gate rows red" "$(lq_preproof_reason "$rf")"
  printf 'FAIL construction: legacy-reach 94 > 92\nnoise\n' >"$rf"
  _t "a gate's FAIL row when that is all there is" "FAIL construction: legacy-reach 94 > 92" "$(lq_preproof_reason "$rf")"
  _t "a compiler error is a reason"         "error[E0433]: failed to resolve: use of undeclared crate" "$(lq_preproof_reason "$re2")"
  _t "a log with nothing to say says nothing" "" "$(lq_preproof_reason "$rn")"
  _t "a log that is not there says nothing"   "" "$(lq_preproof_reason "$root/nosuch.log")"
  _t "no log at all says nothing"             "" "$(lq_preproof_reason "")"
  # AT THE POP: the park is unchanged, and the ledger now carries the sentence beside it.
  Q="$root/reasonq.txt"; PP="$root/reason-pp.txt"; L="$root/reason-log.txt"; : >"$L"; W="$repo"
  printf 'RED%stip1%s%s%s--prove %s\n' "$TAB" "$TAB" "$rl" "$TAB" "$hb" >"$PP"
  printf -- '--prove %s\n' "$hb" >"$Q"
  local rn2; rn2="$(lq_pop tip1 4 "$root/rb.txt" "$root/rk.txt")"
  _t "the line is still parked with its log"   1 "$(grep -c "^#RED-preproof $rl " "$root/rk.txt" || true)"
  _t "  ...and the ledger carries the reason"  1 "$(grep -cx "pre-prove RED reason: land.sh: RED — tests failed in: busbar-core" "$L" || true)"
  printf 'RED%stip1%s%s%s--prove %s\n' "$TAB" "$TAB" "$rn" "$TAB" "$hb" >"$PP"
  printf -- '--prove %s\n' "$hb" >"$Q"; : >"$L"
  rn2="$(lq_pop tip1 4 "$root/rb2.txt" "$root/rk2.txt")"
  _t "a log with no sentence says so, in words" 1 "$(grep -cx 'pre-prove RED reason: <no reason line in the log>' "$L" || true)"

  # ── CHAINED PRE-PROOFS: a held line proven on the tree its predecessor will make ───────────────
  echo "landq4 selftest: chained pre-proofs (a #HOLD-after-<sha> line rides its predecessor)"
  local savedQ8="$Q" savedPP8="$PP" savedL8="$L" savedW8="$W" savedD8="$D" savedCD8="$LAND_CHAIN_DEPTH"
  Q="$root/chq.txt"; PP="$root/chpp.txt"; L="$root/chlog.txt"; D="$root/chdone.txt"; W="$repo"
  : >"$D"
  local cb="$root/chbatch.txt" ckp="$root/chkeep.txt" cn
  # THE TAG IS READ, AND ONLY IN ITS SHA FORM (rule (6)).
  _t "a #HOLD-after-<sha> tag names its predecessor" "$ha" "$(lq_hold_after_sha "#HOLD-after-$ha --prove $hb")"
  _t "a short sha is a sha"                    "$(printf '%.9s' "$ha")" \
     "$(lq_hold_after_sha "#HOLD-after-$(printf '%.9s' "$ha") --prove $hb")"
  _t "a WORD-form hold is never chained"       "" "$(lq_hold_after_sha "#HOLD-dialect-kind-mint --prove $hb")"
  _t "two HOLD tags name no single predecessor" "" "$(lq_hold_after_sha "#HOLD-after-$ha #HOLD-arena --prove $hb")"
  # A LABEL BESIDE THE HOLD IS NOT A SECOND DEPENDENCY — 36 of the queue's held lines are this shape.
  _t "a slot label beside the hold is not one"  "$ha" "$(lq_hold_after_sha "#HOLD-after-$ha #T0-B2-seam --prove $hb")"
  _t "  ...in either order"                     "$ha" "$(lq_hold_after_sha "#T0-B2-seam #HOLD-after-$ha --prove $hb")"
  _t "  ...and the payload is still the line"   "--prove $hb" "$(lq_line_payload "#HOLD-after-$ha #T0-B2-seam --prove $hb")"
  _t "a word-form hold beside a label is still refused" "" \
     "$(lq_hold_after_sha "#HOLD-dialect-kind-mint #T0-B2-seam --prove $hb")"
  _t "a label alone is no hold at all"          "" "$(lq_hold_after_sha "#T0-B2-seam --prove $hb")"
  _t "a #RED park is not a hold"               "" "$(lq_hold_after_sha "#RED-preproof /l/1 --prove $hb")"
  _t "a live line is not a hold"               "" "$(lq_hold_after_sha "--prove $hb")"
  _t "the payload is the line behind the tags" "--prove $hb" "$(lq_line_payload "#HOLD-after-$ha --prove $hb")"
  _t "  ...and a live line is its own payload" "--prove $hb" "$(lq_line_payload "--prove $hb")"
  # THE CHAIN ITSELF, root first.
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n#HOLD-after-%s --prove %s\n' "$ha" "$ha" "$hb" "$hb" "$hc" >"$Q"
  _t "a two-line chain is root-then-self"  "--prove $ha
--prove $hb" "$(lq_chain_of "#HOLD-after-$ha --prove $hb" "$Q" "$repo" 4)"
  _t "a three-line chain walks transitively" "--prove $ha
--prove $hb
--prove $hc" "$(lq_chain_of "#HOLD-after-$hb --prove $hc" "$Q" "$repo" 4)"
  _t "  ...and the depth is a wall"        "" "$(lq_chain_of "#HOLD-after-$hb --prove $hc" "$Q" "$repo" 2)"
  _t "  ...refused, not truncated"         1 "$(lq_chain_of "#HOLD-after-$hb --prove $hc" "$Q" "$repo" 2 >/dev/null; echo $?)"
  _t "a hold naming nothing in the queue is no chain" 1 \
     "$(lq_chain_of "#HOLD-after-deadbeef1 --prove $hb" "$Q" "$repo" 4 >/dev/null; echo $?)"
  _t "the ledger key is tip@picks"         "tip1@$ha" "$(printf -- '--prove %s\n' "$ha" | lq_chain_key tip1)"
  _t "  ...in chain order, for two picks"  "tip1@$ha+$hb" "$(printf -- '--prove %s\n--prove %s\n' "$ha" "$hb" | lq_chain_key tip1)"

  # (1) A TWO-LINE CHAIN LANDS IN ONE BATCH — and the log says so, in the shape a tick greps for.
  : >"$L"
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n' "$ha" "$ha" "$hb" >"$Q"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$ha" "$TAB" "$ha" "$TAB" "$TAB" "$hb" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "a two-line chain lands in ONE batch"      2 "$cn"
  _t "  ...the predecessor first"               "--prove $ha" "$(lq_batch_lines "$cb" | sed -n 1p)"
  _t "  ...the dependent after it"              "--prove $hb" "$(lq_batch_lines "$cb" | sed -n 2p)"
  # ...AND THE UNIT BOUNDARY TRAVELS WITH IT, in band, naming the ROOT's landing-line number.
  _t "  ...under a #UNIT marker naming the root" "#UNIT 1" "$(sed -n 2p "$cb")"
  _t "  ...and the root itself carries none"    "--prove $ha" "$(sed -n 1p "$cb")"
  _t "  ...so the batch is 2 landing lines of 3" "2 3" \
     "$(printf '%s %s' "$(lq_batch_lines "$cb" | grep -c .)" "$(grep -c . "$cb")")"
  _t "  ...nothing left live"                   0 "$(grep -c '^--' "$ckp" || true)"
  _t "  ...the log line shape"                  1 "$(grep -cxF "chained: --prove $hb after $ha (unit 1, line 2 of the batch)" "$L" || true)"
  _t "  ...and the batch remembers where it came from" 1 \
     "$(grep -cF -- "--prove $hb$TAB#HOLD-after-$ha --prove $hb$TAB--prove $ha" "$cb.chain" || true)"
  # THE VERDICT IS KEYED BY THE PREDECESSOR'S PICKS: a green over other picks is not this line's.
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$ha" "$TAB" "$hc" "$TAB" "$TAB" "$hb" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "a green over OTHER picks does not admit it" 1 "$cn"
  _t "  ...and the line is still held, tag intact" 1 "$(grep -cx -- "#HOLD-after-$ha --prove $hb" "$ckp" || true)"
  # (6) A TIP MOVE DROPS IT.
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$ha" "$TAB" "$ha" "$TAB" "$TAB" "$hb" >"$PP"
  _t "a chained green is found at its own tip"  GREEN "$(lq_preproved_status "tip1@$ha" "--prove $hb")"
  _t "  ...and at no other tip"                 NONE  "$(lq_preproved_status "tip2@$ha" "--prove $hb")"
  _t "the prune keeps the new tip's chained rows" 1 \
     "$(awk -F"$TAB" -v tip="tip1" '$2 == tip || index($2, tip "@") == 1' "$PP" | grep -c "tip1@$ha" || true)"
  _t "  ...and drops the old tip's, chained and bare" 0 \
     "$(awk -F"$TAB" -v tip="tip2" '$2 == tip || index($2, tip "@") == 1' "$PP" | grep -c . || true)"
  _t "the runner's own prune is that expression" 1 \
     "$(grep -cF "awk -F\"\$TAB\" -v tip=\"\$newtip\" '\$2 == tip || index(\$2, tip \"@\") == 1'" "$0")"
  _t "  ...and the batch ceiling counts chained greens" 1 \
     "$(grep -cF "'\$1 == \"GREEN\" && (\$2 == tip || index(\$2, tip \"@\") == 1) {print \$4}'" "$0")"
  LAND_BATCH=8 _t "eight chained greens are eight" 8 "$( { printf 'GREEN%stip1@%s%s/l%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hb"
      printf 'GREEN%stip1@%s%s/l%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hc"
      printf 'GREEN%stip1@%s%s/l%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hg1"
      printf 'GREEN%stip1@%s%s/l%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hg2"
      printf 'GREEN%stip1@%s%s/l%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hcb"
      printf 'GREEN%stip1@%s%s/l%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hfig"
      printf 'GREEN%stip1@%s%s/l%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hmint"
      printf 'GREEN%stip1%s/l%s--prove %s\n' "$TAB" "$TAB" "$TAB" "$ha"; } >"$root/ch8.txt"; LAND_BATCH=8 lq_batch_size tip1 "$root/ch8.txt")"

  # (2) A THREE-LINE CHAIN WITH DEPTH 2 LANDS THE FIRST TWO.
  LAND_CHAIN_DEPTH=2
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n#HOLD-after-%s --prove %s\n' "$ha" "$ha" "$hb" "$hb" "$hc" >"$Q"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\nGREEN%stip1@%s+%s%s/l/c%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$ha" "$TAB" "$ha" "$TAB" "$TAB" "$hb" "$TAB" "$ha" "$hb" "$TAB" "$TAB" "$hc" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "depth 2: the first two of a three-line chain" 2 "$cn"
  _t "  ...and the third is still held"          1 "$(grep -cx -- "#HOLD-after-$hb --prove $hc" "$ckp" || true)"
  LAND_CHAIN_DEPTH=4
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "depth 4: all three ride one batch"         3 "$cn"
  _t "  ...in chain order"                       "--prove $hc" "$(lq_batch_lines "$cb" | sed -n 3p)"
  _t "  ...all three in ONE unit, rooted at line 1" 2 "$(grep -cx '#UNIT 1' "$cb" || true)"

  # (3) A RED PREDECESSOR RETURNS THE DEPENDENT TO HELD, WITH NO VERDICT LEFT.
  : >"$L"
  local credlog="$root/ch-red.log"; printf 'FAIL construction: legacy-reach 94 > 92\n' >"$credlog"
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n' "$ha" "$ha" "$hb" >"$Q"
  printf 'RED%stip1%s%s%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\n' \
     "$TAB" "$TAB" "$credlog" "$TAB" "$ha" "$TAB" "$ha" "$TAB" "$TAB" "$hb" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "a parked predecessor pops nothing"        0 "$cn"
  _t "  ...the predecessor is parked"           1 "$(grep -c "^#RED-preproof $credlog " "$ckp" || true)"
  _t "  ...the dependent is back to held, tag intact" 1 "$(grep -cx -- "#HOLD-after-$ha --prove $hb" "$ckp" || true)"
  _t "  ...and its chained verdict is dropped"  0 "$(grep -c "tip1@$ha" "$PP" || true)"
  _t "  ...the bare-tip rows are untouched"     1 "$(grep -c "^RED${TAB}tip1${TAB}" "$PP" || true)"
  _t "  ...and the log says why"                1 "$(grep -c 'stays held — its predecessor was parked; verdict dropped' "$L" || true)"

  # (3, at the landing) A CHAINED LINE WHOSE PREDECESSOR CAME BACK RED GOES BACK HELD, NOT #RED.
  : >"$L"
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n' "$ha" "$ha" "$hb" >"$Q"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$ha" "$TAB" "$ha" "$TAB" "$TAB" "$hb" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  printf 'RED%s--prove %s\nRED%s--prove %s\n' "$TAB" "$ha" "$TAB" "$hb" >"$cb.result"
  local cred="$root/ch-red.txt"; : >"$cred"
  lq_park_line "--prove $ha" "$cb" "$cred"; lq_park_line "--prove $hb" "$cb" "$cred"
  _t "the predecessor parks as #RED"            1 "$(grep -cx -- "#RED --prove $ha" "$cred" || true)"
  _t "the dependent goes back HELD, not #RED"   1 "$(grep -cx -- "#HOLD-after-$ha --prove $hb" "$cred" || true)"
  _t "  ...and never as a bare payload"         0 "$(grep -cx -- "#RED --prove $hb" "$cred" || true)"
  _t "  ...its chained verdict dropped with it" 0 "$(grep -c "tip1@$ha" "$PP" || true)"
  # ...AND WHEN THE PREDECESSOR WENT GREEN, THE HOLD IS MOOT AND THE ORDINARY PARK IS RIGHT.
  printf 'GREEN%stip1@%s%s/l/b%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hb" >"$PP"
  printf 'GREEN%s--prove %s\nRED%s--prove %s\n' "$TAB" "$ha" "$TAB" "$hb" >"$cb.result"
  : >"$cred"; lq_park_line "--prove $hb" "$cb" "$cred"
  _t "a green predecessor makes the hold moot"  1 "$(grep -cx -- "#RED --prove $hb" "$cred" || true)"
  _t "  ...and an unchained line parks as it always did" 1 \
     "$(: >"$cred"; lq_park_line "--prove $hc" "$cb" "$cred"; grep -cx -- "#RED --prove $hc" "$cred" || true)"
  _t "the HALT requeue maps a payload back to its held line" 1 \
     "$(grep -c 'print (($0 in m) ? m\[$0\] : $0)' "$0")"

  # (4) THE RULES ARE BETWEEN UNITS — and this is the measurement T0-D6 handed back (51 -> 50).
  #
  # A GATES LINE AFTER A GATES LINE IN ONE CHAIN IS ONE UNIT: one judge, evolved by two picks, and
  # the prefix ladder attributes a red to the pick that caused it. Two gate lines that are NOT one
  # chain are still two batches — the rule did not go away, it moved up a grain.
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n' "$hg1" "$hg1" "$hg2" >"$Q"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$hg1" "$TAB" "$hg1" "$TAB" "$TAB" "$hg2" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "a gates line CHAINED to a gates line is one unit" 2 "$cn"
  _t "  ...and the unit is marked as one"        1 "$(grep -cx '#UNIT 1' "$cb" || true)"
  # THE COUNTER-CASE: the same two lines, unchained, still refuse each other.
  printf -- '--prove %s\n--prove %s\n' "$hg1" "$hg2" >"$Q"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1%s/l/b%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$hg1" "$TAB" "$TAB" "$TAB" "$hg2" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "  ...but two UNITS still edit one judge apart" 1 "$cn"
  # ── THE ONE-FILE RULE, AT THE UNIT GRAIN ──────────────────────────────────────────────────────
  # THE MEASUREMENT THIS CHANGE EXISTS FOR. A dependent that touches its predecessor's file is the
  # ordinary shape of a held line — that overlap is WHY it is held — and it is what kept the live
  # queue at 50 batches with chaining already in.
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n' "$ha" "$ha" "$ha2" >"$Q"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$ha" "$TAB" "$ha" "$TAB" "$TAB" "$ha2" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "two lines on one file INSIDE a chain are one batch" 2 "$cn"
  _t "  ...the dependent is the second landing line" "--prove $ha2" "$(lq_batch_lines "$cb" | sed -n 2p)"
  _t "  ...and it rides under the root's unit marker" 1 "$(grep -cx '#UNIT 1' "$cb" || true)"
  # THE COUNTER-CASE, and it is the rule that has not moved: the same overlap BETWEEN units refuses.
  printf -- '--prove %s\n--prove %s\n' "$ha" "$ha2" >"$Q"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1%s/l/b%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$ha" "$TAB" "$TAB" "$TAB" "$ha2" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "two lines on one file in two units are two batches" 1 "$cn"
  _t "  ...the second waits for a batch without the first" 1 "$(grep -cx -- "--prove $ha2" "$ckp" || true)"
  # A THIRD UNIT MEETING THE CHAIN'S FILES IS REFUSED TOO: a unit's file set is the UNION of its
  # lines', so the DEPENDENT's files are claimed against the rest of the batch just as the root's are.
  _t "a unit's file set is the union of its lines" "a.txt${TAB}" "$(lq_unit_files "--prove $ha
--prove $ha2" "$repo")"
  _t "  ...over two files, in order, without repeats" "a.txt${TAB}b.txt${TAB}" \
     "$(lq_unit_files "--prove $ha
--prove $hb
--prove $ha2" "$repo")"
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n--prove %s\n' "$ha" "$ha" "$hb" "$hb2" >"$Q"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\nGREEN%stip1%s/l/c%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$ha" "$TAB" "$ha" "$TAB" "$TAB" "$hb" "$TAB" "$TAB" "$TAB" "$hb2" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "a line meeting the DEPENDENT's file is refused" 2 "$cn"
  _t "  ...and waits, live, for the next batch"  1 "$(grep -cx -- "--prove $hb2" "$ckp" || true)"

  # (5) A BASE FIX IS NEVER IN A CHAIN, at either end.
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n' "$hfig" "$hfig" "$hb" >"$Q"
  _t "a base-fix predecessor is not chainable"  1 \
     "$(lq_chain_of "#HOLD-after-$hfig --prove $hb" "$Q" "$repo" 4 >/dev/null; echo $?)"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$hfig" "$TAB" "$hfig" "$TAB" "$TAB" "$hb" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "  ...so the base fix pops alone"          1 "$cn"
  _t "  ...and the dependent stays held"        1 "$(grep -cx -- "#HOLD-after-$hfig --prove $hb" "$ckp" || true)"
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n' "$ha" "$ha" "$hfig" >"$Q"
  _t "a base-fix DEPENDENT is not chainable"    1 \
     "$(lq_chain_of "#HOLD-after-$ha --prove $hfig" "$Q" "$repo" 4 >/dev/null; echo $?)"
  # ...AND THE JOIN ITSELF REFUSES IT, tag or no tag: a unit forgives a file overlap, never a line
  # that re-pins what every line in the batch is judged against.
  _t "a base fix is refused a unit to join"     1 \
     "$(lq_may_join "--prove $hfig" "$repo" 0 "a.txt$TAB" 0 0 "" 0 0 "a.txt$TAB"; echo $?)"
  _t "  ...and is still allowed to open one"    0 \
     "$(lq_may_join "--prove $hfig" "$repo" 0 "" 0 0 "" 0 0 ""; echo $?)"
  _t "  ...while an ordinary line joins on the unit's own file" 0 \
     "$(lq_may_join "--prove $ha2" "$repo" 1 "a.txt$TAB" 0 0 "" 0 0 "a.txt$TAB"; echo $?)"
  _t "  ...and is refused when that file is ANOTHER unit's" 1 \
     "$(lq_may_join "--prove $ha2" "$repo" 1 "a.txt$TAB" 0 0 "" 0 0 ""; echo $?)"

  # ── THE CEILING COUNTS LINES, NOT UNITS ───────────────────────────────────────────────────────
  # LAND_BATCH bounds what is proven in one union; a unit of three is three lines of proving. A unit
  # that does not fit whole is admitted as far as it fits — the admitted prefix is itself a chain —
  # and the tail keeps its hold for the next batch.
  LAND_CHAIN_DEPTH=4
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n#HOLD-after-%s --prove %s\n' "$ha" "$ha" "$hb" "$hb" "$hc" >"$Q"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\nGREEN%stip1@%s+%s%s/l/c%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$ha" "$TAB" "$ha" "$TAB" "$TAB" "$hb" "$TAB" "$ha" "$hb" "$TAB" "$TAB" "$hc" >"$PP"
  cn="$(lq_pop tip1 2 "$cb" "$ckp")"
  _t "a ceiling of 2 takes 2 LINES of a 3-line unit" 2 "$cn"
  _t "  ...and the third keeps its hold"        1 "$(grep -cx -- "#HOLD-after-$hb --prove $hc" "$ckp" || true)"
  cn="$(lq_pop tip1 3 "$cb" "$ckp")"
  _t "  ...a ceiling of 3 takes the whole unit" 3 "$cn"
  _t "  ...which is ONE unit of three lines, not three batches" 2 "$(grep -cx '#UNIT 1' "$cb" || true)"

  # ── AND THE CEILING REACHES EIGHT: A CHAINED UNIT OF EIGHT, POPPED WHOLE ───────────────────────
  # LANDQ_PREPROVE_LINES is 12 on the live queue now, so eight distinct greens at one tip is a shape
  # that HAPPENS rather than a shape that is argued about — lq_batch_size returns 8 for it (the
  # "eight chained greens are eight" case above). What that ceiling is worth depends on the POPPER
  # honouring it, and on LAND_CHAIN_DEPTH, which is a SECOND ceiling and is 4: a chain of eight at
  # depth 4 is four lines, whatever LAND_BATCH says. Both are asked here, because an operator who
  # raises LAND_BATCH to 8 and gets 4 has no way to tell which ceiling took it.
  local h8 i prev key
  h8=""
  for i in 1 2 3 4 5 6 7 8; do
    printf 'e%s\n' "$i" >"$repo/e$i.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm "e$i"
    h8="$h8 $(git -C "$repo" rev-parse HEAD)"
  done
  h8="${h8# }"
  # The queue: a live root and seven holds, each naming the one before it.
  : >"$Q"; prev=""
  for i in $h8; do
    if [ -z "$prev" ]; then printf -- '--prove %s\n' "$i" >>"$Q"
    else printf -- '#HOLD-after-%s --prove %s\n' "$prev" "$i" >>"$Q"; fi
    prev="$i"
  done
  # …and a chained green for every one of them, keyed exactly as lq_chain_key writes it.
  : >"$PP"; key=""
  for i in $h8; do
    if [ -z "$key" ]; then printf 'GREEN%stip1%s/l/e%s--prove %s\n' "$TAB" "$TAB" "$TAB" "$i" >>"$PP"
    else printf 'GREEN%stip1@%s%s/l/e%s--prove %s\n' "$TAB" "$key" "$TAB" "$TAB" "$i" >>"$PP"; fi
    if [ -z "$key" ]; then key="$i"; else key="$key+$i"; fi
  done
  _t "eight chained greens at this tip make the ceiling 8" 8 "$(LAND_BATCH=8 lq_batch_size tip1 "$PP")"
  # THE DEPTH IS THE OTHER CEILING, and at its default it is the binding one.
  LAND_CHAIN_DEPTH=4
  cn="$(lq_pop tip1 8 "$cb" "$ckp")"
  _t "depth 4 caps an eight-line chain at four"  4 "$cn"
  _t "  ...and the other four keep their holds"  4      "$(grep -c '^#HOLD-after-' "$ckp" || true)"
  # RAISE THE DEPTH AND THE WHOLE UNIT RIDES ONE BATCH — eight lines, one union, one bisect ladder.
  LAND_CHAIN_DEPTH=8
  cn="$(lq_pop tip1 8 "$cb" "$ckp")"
  _t "depth 8 and LAND_BATCH 8 pop all eight"    8 "$cn"
  _t "  ...as ONE unit, not eight batches"       7 "$(grep -cx '#UNIT 1' "$cb" || true)"
  _t "  ...in chain order, root first"           "--prove $(printf '%s' "$h8" | cut -d' ' -f1)" "$(lq_batch_lines "$cb" | sed -n 1p)"
  _t "  ...and last is last"                     "--prove $(printf '%s' "$h8" | cut -d' ' -f8)" "$(lq_batch_lines "$cb" | sed -n 8p)"
  _t "  ...and nothing is left holding"          0 "$(grep -c '^#HOLD-after-' "$ckp" || true)"
  # AND THE LINE CEILING STILL BINDS ABOVE THE DEPTH: LAND_BATCH is what is PROVEN in one union.
  cn="$(lq_pop tip1 6 "$cb" "$ckp")"
  _t "a ceiling of 6 takes six of the eight"     6 "$cn"
  _t "  ...and the last two keep their holds"    2 "$(grep -c '^#HOLD-after-' "$ckp" || true)"
  LAND_CHAIN_DEPTH=4

  # ── THE SWEEP PREFERS CHAINS OVER SINGLES ─────────────────────────────────────────────────────
  # A box on a single buys one line in the next batch; a box on a chain root makes its whole chain
  # provable, and those land together as one unit. So the roots take their boxes first.
  printf -- '--prove %s\n--prove %s\n#HOLD-after-%s --prove %s\n' "$hc" "$ha" "$ha" "$hb" >"$Q"
  _t "a live line with a hold behind it roots a chain" 0 \
     "$(lq_line_roots_a_hold "--prove $ha" "$Q"; echo $?)"
  _t "  ...and one with nothing behind it does not"    1 \
     "$(lq_line_roots_a_hold "--prove $hc" "$Q"; echo $?)"
  _t "  ...a word-form hold roots nothing"             1 \
     "$(printf -- '--prove %s\n#HOLD-dialect-kind-mint --prove %s\n' "$ha" "$hb" >"$root/wq.txt"; \
        lq_line_roots_a_hold "--prove $ha" "$root/wq.txt"; echo $?)"
  printf -- '--prove %s\n--prove %s\n#HOLD-after-%s --prove %s\n' "$hc" "$ha" "$ha" "$hb" >"$Q"
  _t "the root goes before the single, order otherwise kept" "--prove $ha
--prove $hc" "$(lq_chain_roots_first "--prove $hc
--prove $ha" "$Q" "$repo")"
  _t "  ...and nothing is dropped or invented"  2 "$(lq_chain_roots_first "--prove $hc
--prove $ha" "$Q" "$repo" | grep -c . || true)"
  # …the roots' claim now goes through lq_chain_budget, which weighs it against the head's (below).
  _t "the sweep budgets the chained holds against the ROOTS" 1 \
     "$(grep -c 'chained="$(lq_chain_candidates "$(lq_chain_budget "$PREPROVE_LINES" "$nroots"' "$LQ_SRC")"
  _t "  ...and trims the live list, roots first, to what is left" 1 \
     "$(grep -c 'lq_sweep_order "$lines" "$roots" "$kact" $((PREPROVE_LINES - nch))' "$LQ_SRC")"

  # ── HELD: WHAT COMES BACK FROM A UNIT THAT WAS BISECTED BY PREFIX ──────────────────────────────
  # land.sh says HELD for a line standing after the culprit in its unit: never proven, never
  # applied. It goes back under its hold and its chained verdict goes with it — never parked #RED.
  : >"$L"
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n#HOLD-after-%s --prove %s\n' "$ha" "$ha" "$hb" "$hb" "$hc" >"$Q"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s--prove %s\nGREEN%stip1@%s+%s%s/l/c%s--prove %s\n' \
     "$TAB" "$TAB" "$TAB" "$ha" "$TAB" "$ha" "$TAB" "$TAB" "$hb" "$TAB" "$ha" "$hb" "$TAB" "$TAB" "$hc" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "the three-line unit pops whole"           3 "$cn"
  # The culprit is line 2 of 3: line 1 green with its own proof, line 3 HELD (land.sh case M1).
  printf 'GREEN%s--prove %s\nRED%s--prove %s\nHELD%s--prove %s\n' "$TAB" "$ha" "$TAB" "$hb" "$TAB" "$hc" >"$cb.result"
  : >"$cred"
  lq_park_line "--prove $hb" "$cb" "$cred" RED
  lq_park_line "--prove $hc" "$cb" "$cred" HELD
  # Its predecessor DID go green, so this line's hold is moot (rule (c) strikes the tag on the next
  # loop) and the ordinary #RED park is the right one — exactly as it was before units existed.
  _t "the culprit parks #RED, its hold moot"    1 "$(grep -cx -- "#RED --prove $hb" "$cred" || true)"
  _t "the line after it goes back HELD"          1 "$(grep -cx -- "#HOLD-after-$hb --prove $hc" "$cred" || true)"
  _t "  ...and never as a #RED park"             0 "$(grep -c -- "^#RED --prove $hc\$" "$cred" || true)"
  _t "  ...nor as a bare live line"              0 "$(grep -cx -- "--prove $hc" "$cred" || true)"
  _t "  ...its chained verdict dropped with it"  0 "$(grep -c "tip1@$ha+$hb" "$PP" || true)"
  _t "the runner counts a HELD line apart from a red" 1 "$(grep -c 'HELD) nheld=$((nheld + 1))' "$LQ_SRC")"
  _t "a HELD pre-proof row is no verdict at all" "NONE:held" \
     "$(printf 'HELD%s--prove %s\n' "$TAB" "$hb" >"$root/held-outcome.txt"; \
        lq_chain_preproof_verdict 1 "$rn" "$root/held-outcome.txt" "--prove $hb")"
  _t "  ...so nothing is recorded for it"        1 "$(grep -c 'NONE:\*) lq_log "pre-prove: chained line' "$LQ_SRC")"
  # A HELD line with no chain map is requeued as it stands — live, unmarked, unproven.
  : >"$cred"; lq_park_line "--prove $hc" "$root/nosuchbatch" "$cred" HELD
  _t "an unmapped HELD line is requeued unchanged" 1 "$(grep -cx -- "--prove $hc" "$cred" || true)"

  # ── THE MARKERS ARE NOT LANDING LINES ─────────────────────────────────────────────────────────
  # The runner compares the outcome file against the LANDING lines; counting the file's lines would
  # HALT a perfectly good batch for "2 of 3 outcomes" the moment a unit marker was in it.
  printf -- '--prove %s\n#UNIT 1\n--prove %s\n# a note\n' "$ha" "$hb" >"$root/mk.txt"
  _t "a batch file's landing lines skip its markers" 2 "$(lq_batch_lines "$root/mk.txt" | grep -c .)"
  _t "  ...and the file itself is longer"        4 "$(grep -c . "$root/mk.txt")"
  _t "  ...the root is landing line 1"           1 "$(lq_batch_index "$root/mk.txt" "--prove $ha")"
  _t "  ...the dependent is landing line 2"      2 "$(lq_batch_index "$root/mk.txt" "--prove $hb")"
  _t "  ...and a line not in it has no index"    "" "$(lq_batch_index "$root/mk.txt" "--prove $hc")"
  _t "the runner counts landing lines, not file lines" 1 \
     "$(grep -c 'want="$(lq_batch_lines "$batch" | grep -c . || true)"' "$LQ_SRC")"
  _t "  ...and the HALT requeue never puts a marker in the queue" 1 \
     "$(grep -A1 -F '/^[[:space:]]*(#|$)/ { next }' "$LQ_SRC" | grep -c 'print (($0 in m)')"
  _t "a chained pre-proof is handed to the box as ONE unit" 1 \
     "$(grep -c "printf '#UNIT 1" "$LQ_SRC")"

  # THE SWEEP'S SIDE: which held lines are worth a box, and what a chained box's verdict is.
  printf -- '--prove %s\n#HOLD-after-%s --prove %s\n#HOLD-dialect-kind-mint --prove %s\n' "$ha" "$ha" "$hb" "$hc" >"$Q"
  : >"$PP"; printf -- '--prove %s\n' "$ha" >"$root/chclaim.txt"
  _t "the sweep offers the chained hold a box"  "#HOLD-after-$ha --prove $hb" \
     "$(lq_chain_candidates 4 "$Q" "$repo" tip1 "$root/chclaim.txt")"
  _t "  ...and never a word-form hold"          0 \
     "$(lq_chain_candidates 4 "$Q" "$repo" tip1 "$root/chclaim.txt" | grep -c 'dialect-kind-mint' || true)"
  _t "  ...nor one already green at that key"   "" \
     "$(printf 'GREEN%stip1@%s%s/l%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hb" >"$PP"; \
        lq_chain_candidates 4 "$Q" "$repo" tip1 "$root/chclaim.txt")"
  _t "  ...nor one whose OWN files are spoken for" "" \
     "$(: >"$PP"; printf -- '--prove %s\n--prove %s\n' "$ha" "$hb" >"$root/chclaim.txt"; \
        lq_chain_candidates 4 "$Q" "$repo" tip1 "$root/chclaim.txt")"
  _t "  ...and no boxes means no candidates"    "" \
     "$(printf -- '--prove %s\n' "$ha" >"$root/chclaim.txt"; lq_chain_candidates 0 "$Q" "$repo" tip1 "$root/chclaim.txt")"
  # THE DEPENDENT'S OWN ROW OUT OF THE UNION'S OUTCOME FILE.
  local cres="$root/ch-outcome.txt"
  printf 'GREEN%s--prove %s\nRED%s--prove %s\n' "$TAB" "$ha" "$TAB" "$hb" >"$cres"
  _t "the dependent's own row is read"          RED   "$(lq_outcome_row "$cres" "--prove $hb")"
  _t "  ...and the predecessor's is its own"    GREEN "$(lq_outcome_row "$cres" "--prove $ha")"
  _t "  ...a line not in the file has no row"   ""    "$(lq_outcome_row "$cres" "--prove $hc")"
  _t "a chained RED is the dependent's"         RED   "$(lq_chain_preproof_verdict 1 "$rn" "$cres" "--prove $hb")"
  _t "a chained GREEN under a red union is still green" GREEN \
     "$(printf 'RED%s--prove %s\nGREEN%s--prove %s\n' "$TAB" "$ha" "$TAB" "$hb" >"$cres"; \
        lq_chain_preproof_verdict 1 "$rn" "$cres" "--prove $hb")"
  _t "a base-state red is the BASE's, chained too" "NONE:base" \
     "$(printf 'RED%s--prove %s\n' "$TAB" "$hb" >"$cres"; \
        printf 'ceiling-rose: the figure ROSE since the base\n' >"$root/ch-base.log"; \
        lq_chain_preproof_verdict 1 "$root/ch-base.log" "$cres" "--prove $hb")"
  _t "a chained RED whose box vanished is NONE:box" "NONE:box" \
     "$(lq_chain_preproof_verdict 75 "$rn" "$cres" "--prove $hb")"
  _t "  ...and one whose harness gave up is NONE:harness" "NONE:harness" \
     "$(printf 'land.sh: RED — oracle: a HARNESS failure, not a divergence: harness give-up: port busy\n' >"$root/ch-harn.log"
        lq_chain_preproof_verdict 1 "$root/ch-harn.log" "$cres" "--prove $hb")"
  _t "no outcome at all falls back to the rc rules" "NONE:never-reported" \
     "$(lq_chain_preproof_verdict "" "$rn" "$root/nosuch" "--prove $hb")"
  _t "  ...and a clean rc is green"             GREEN "$(lq_chain_preproof_verdict 0 "$rn" "$root/nosuch" "--prove $hb")"
  # ── A QUEUE LINE IS BYTES, AND `awk -v` IS NOT ────────────────────────────────────────────────
  # 44 of the queue's lines are the `--tests`/`--families` form and carry a regex with a backslash
  # (`^(llm|route\.failover|hooks)[|]`). `awk -v x=…` runs its value through awk's own escape
  # processing, so that line arrives inside awk as `route.failover` and equals NOTHING in the
  # ledger: the pre-proof RED log could not be found (parked `#RED-preproof no-log`), and a chained
  # verdict could neither be read back nor dropped. Every line-valued comparison goes through
  # ENVIRON, which is bytes.
  local bsl="--prove --tests busbar --families '^(llm|route\\.failover|hooks)[|]' $hb"
  printf 'GREEN%s--prove %s\nRED%s%s\n' "$TAB" "$ha" "$TAB" "$bsl" >"$cres"
  _t "a line with a backslash finds its own row" RED "$(lq_outcome_row "$cres" "$bsl")"
  _t "  ...and awk -v would not have"            1 \
     "$( [ "$(awk -F"$TAB" -v w="$bsl" '$2 == w { print $1 }' "$cres")" = "" ] && echo 1 || echo 0)"
  # …and so does every other reader that matches a queue line inside awk: the popper's RED log,
  # and the pre-proof index the union inherits from. Both, by count, so a third cannot use -v.
  _t "  ...the popper and the union index read by ENVIRON too" 2 \
     "$(grep -c 'LQ_AWK_T="\$line" awk -F"\$TAB" -v tip="\$tip"' "$0")"
  _t "  ...and no line is compared by awk -v anywhere" 0 \
     "$(grep -c 'awk -F"\$TAB" -v t="\$' "$0")"
  # THE PARK, over a line of that shape, end to end.
  : >"$L"
  printf -- '--prove %s\n#HOLD-after-%s %s\n' "$ha" "$ha" "$bsl" >"$Q"
  printf 'GREEN%stip1%s/l/a%s--prove %s\nGREEN%stip1@%s%s/l/b%s%s\n' \
     "$TAB" "$TAB" "$TAB" "$ha" "$TAB" "$ha" "$TAB" "$TAB" "$bsl" >"$PP"
  cn="$(lq_pop tip1 4 "$cb" "$ckp")"
  _t "a backslash line rides the chain"         2 "$cn"
  printf 'RED%s--prove %s\nRED%s%s\n' "$TAB" "$ha" "$TAB" "$bsl" >"$cb.result"
  : >"$cred"; lq_park_line "$bsl" "$cb" "$cred"
  _t "  ...and goes back HELD by its own bytes" 1 "$(grep -cFx -- "#HOLD-after-$ha $bsl" "$cred" || true)"
  _t "  ...its chained verdict dropped"         0 "$(grep -c "tip1@$ha" "$PP" || true)"

  # A CHAINED GREEN BECOMES AN ORDINARY GREEN WHEN ITS CHAIN LANDS — the whole point of the change.
  : >"$L"
  local crb="$root/ch-rekey.batch" crr="$root/ch-rekey.batch.result"
  printf -- '--prove %s\n' "$ha" >"$crb"
  printf 'GREEN%s--prove %s\n' "$TAB" "$ha" >"$crr"
  printf 'GREEN%stip1@%s%s/l/b%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hb" >"$PP"
  _t "the row over exactly these picks moves"   1 "$(lq_chain_rekey tip1 tip2 "$crb" "$crr")"
  _t "  ...and is now a plain green at the new tip" GREEN "$(lq_preproved_status tip2 "--prove $hb")"
  _t "  ...so the tip-move prune keeps it"      1 \
     "$(awk -F"$TAB" -v tip="tip2" '$2 == tip || index($2, tip "@") == 1' "$PP" | grep -c . || true)"
  # A PREFIX IS NOT THE TREE: the batch landed more than the row's chain.
  printf -- '--prove %s\n--prove %s\n' "$ha" "$hc" >"$crb"
  printf 'GREEN%s--prove %s\nGREEN%s--prove %s\n' "$TAB" "$ha" "$TAB" "$hc" >"$crr"
  printf 'GREEN%stip1@%s%s/l/b%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hb" >"$PP"
  _t "a row over a PREFIX of the picks does not" 0 "$(lq_chain_rekey tip1 tip2 "$crb" "$crr")"
  # ...AND A BATCH THAT WAS NOT WHOLLY GREEN LEFT A TREE THAT IS NOT THE SUM OF ITS PICKS.
  printf -- '--prove %s\n' "$ha" >"$crb"
  printf 'RED%s--prove %s\n' "$TAB" "$ha" >"$crr"
  printf 'GREEN%stip1@%s%s/l/b%s--prove %s\n' "$TAB" "$ha" "$TAB" "$TAB" "$hb" >"$PP"
  _t "a red batch re-keys nothing"              0 "$(lq_chain_rekey tip1 tip2 "$crb" "$crr")"
  _t "  ...nor does a missing result file"      0 "$(lq_chain_rekey tip1 tip2 "$crb" "$root/nosuch")"
  _t "the runner re-keys before it prunes"      1 \
     "$( [ "$(grep -n '^  chrk="\$(lq_chain_rekey ' "$0" | head -n1 | cut -d: -f1)" -lt "$(grep -n '^  \[ "\$newtip" = "\$tip" \] ||' "$0" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"

  _t "one live line is now worth a sweep"       1 \
     "$(grep -c 'if \[ "$(lq_live_lines "\$Q")" -lt 1 \]' "$0")"
  Q="$savedQ8"; PP="$savedPP8"; L="$savedL8"; W="$savedW8"; D="$savedD8"; LAND_CHAIN_DEPTH="$savedCD8"

  echo "landq4 selftest: the status line (a tick reads tail -n 1, not the log)"
  D="$root/status-done.txt"
  printf -- '--prove %s\n--prove %s\n#HOLD-after-abc123456 --prove held\n#RED --prove parked\n#RED-preproof /l/1 --prove parked2\n# a comment\n\n' "$ha" "$hb" >"$Q"
  printf 'GREEN batch=1 log=/l/a one\nRED batch=1 log=/l/b two\nGREEN batch=2 log=/l/c three\nCI-RED deadbeef\n' >"$D"
  _t "live, held, parked and landed are counted" \
     "live 2 held 1 parked 2 landed 2 tip $(git -C "$repo" rev-parse --short HEAD)" \
     "$(lq_status "$Q" "$D" "$repo")"
  _t "  ...and it is ONE line"                 1 "$(lq_status "$Q" "$D" "$repo" | grep -c . )"
  _t "  ...so tail -n 1 is the whole state"    "$(lq_status "$Q" "$D" "$repo")" "$(lq_status "$Q" "$D" "$repo" | tail -n 1)"
  : >"$Q"; : >"$D"
  _t "an empty queue counts zeroes, not blanks" \
     "live 0 held 0 parked 0 landed 0 tip $(git -C "$repo" rev-parse --short HEAD)" \
     "$(lq_status "$Q" "$D" "$repo")"
  _t "a tree that is not one is tip ?"         "live 0 held 0 parked 0 landed 0 tip ?" "$(lq_status "$Q" "$D" "$root/nosuchtree")"
  _t "the runner writes it at every loop top"  1 "$(grep -c '^  lq_status >"\$W/target/gate/landq4.status"$' "$0")"
  _t "  ...before it reads the tip"            1 \
     "$( [ "$(grep -n '^  lq_status >"\$W/target/gate/landq4.status"$' "$0" | head -n1 | cut -d: -f1)" -lt "$(grep -n '^  tip="\$(git -C "\$W" rev-parse HEAD)"$' "$0" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  _t "  ...and puts it in the log too"         1 "$(grep -c '^  lq_log "status: ' "$0")"



  # ── WHAT THE UNION MAY INHERIT FROM ITS MEMBERS (see lq_preproof_index) ───────────────────────
  echo "landq4 selftest: the union is told which members were pre-proven green at this tip"
  local savedQi="$Q" savedPPi="$PP" savedWi="$W"
  W="$repo"; PP="$root/inh-pp.txt"
  local ibatch="$root/inh.batch"
  printf -- '--prove %s\n--prove %s\n' "$ha" "$hb" >"$ibatch"
  printf 'GREEN%stipI%s/l/a.log%s--prove %s\n' "$TAB" "$TAB" "$TAB" "$ha" >"$PP"
  printf 'RED%stipI%s/l/b.log%s--prove %s\n' "$TAB" "$TAB" "$TAB" "$hb" >>"$PP"
  _t "only the GREEN member is offered"        1 "$(lq_preproof_index "$ibatch" tipI "$repo" "$PP")"
  _t "  ...naming its log and the files it touches" "/l/a.log${TAB}a.txt" "$(cat "$ibatch.preproofs")"
  _t "a row at ANOTHER tip is not offered"     0 "$(lq_preproof_index "$ibatch" tipJ "$repo" "$PP")"
  printf 'GREEN%stipI%s/l/b.log%s--prove %s\n' "$TAB" "$TAB" "$TAB" "$hb" >>"$PP"
  _t "two green members are two rows"          2 "$(lq_preproof_index "$ibatch" tipI "$repo" "$PP")"
  _t "  ...and the RED row for the same line does not add a third" 2 "$(grep -c . "$ibatch.preproofs")"
  _t "an empty ledger offers nothing"          0 "$(lq_preproof_index "$ibatch" tipI "$repo" "$root/nosuch-pp.txt")"
  _t "  ...and writes an EMPTY index, not a stale one" 0 "$(grep -c . "$ibatch.preproofs" 2>/dev/null || true)"
  Q="$savedQi"; PP="$savedPPi"; W="$savedWi"
  _t "the runner writes the index before it launches" 1 \
     "$( [ "$(grep -n '^  ninh="\$(lq_preproof_index ' "$LQ_SRC" | head -n1 | cut -d: -f1)" \
          -lt "$(grep -n '^  bash "\$W/target/gate/land.run.sh" --batch' "$LQ_SRC" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  _t "  ...and names it to land.sh in the environment" 1 \
     "$(grep -c '^  export LAND_PREPROOF_INDEX="\$batch.preproofs"$' "$LQ_SRC")"
  _t "  ...and logs which legs were inherited, and from where" 1 \
     "$(grep -c 'inherited from the pre-proof log' "$LQ_SRC")"
  _t "  ...saying so explicitly when none was"  1 \
     "$(grep -c 'no leg inherited; the union paid for everything' "$LQ_SRC")"

  # ── A ROOT PROVEN RED MOOTS EVERY DEEPER RUNG OF ITS CHAIN ────────────────────────────────────
  # MEASURED 2026-09-10: line 1 of a sweep — a chain's ROOT, proven ALONE — came back RED at
  # 5481 s. Lines 4, 5 and 11 were deeper PREFIXES of that same chain, and all three were still
  # bisecting on three fleet boxes three hours later, when an operator killed them by hand. Every
  # rung of a chain stands on the root's picks. The root is red; the root's picks are coming back
  # off the tree; there is no tree any of those rungs can be green on. Three boxes and three hours
  # for an answer that was already known and could not change.
  echo "landq4 selftest: a red chain ROOT cancels the deeper rungs still on the fleet"
  local mroot="$root/moot"; mkdir -p "$mroot"
  printf 'ROOT-LINE\n' >"$mroot/line-1.root"; printf 'ROOT-LINE\n' >"$mroot/line-1.batch"
  printf 'RED%sROOT-LINE\n' "$TAB" >"$mroot/line-1.batch.result"; echo 1 >"$mroot/line-1.rc"
  : >"$mroot/line-1.log"
  local m
  for m in 2 3; do printf 'ROOT-LINE\n' >"$mroot/line-$m.root"; : >"$mroot/line-$m.chainkey"; done
  printf 'OTHER-ROOT\n' >"$mroot/line-4.root"; : >"$mroot/line-4.chainkey"
  printf 'ROOT-LINE\n' >"$mroot/line-5.root"; : >"$mroot/line-5.chainkey"; echo 0 >"$mroot/line-5.rc"
  _t "a live single proven RED is its chain's root red" 0 \
     "$(lq_slot_root_red "$mroot" 1 tipX >/dev/null 2>&1; echo $?)"
  _t "the deeper rungs of that chain are mooted"  "2 3" \
     "$(lq_moot_deeper "$mroot" 5 1 ROOT-LINE | tr '\n' ' ' | sed 's/ $//')"
  _t "  ...and each is marked, so it is scored once" 2 \
     "$(ls "$mroot" | grep -c '\.moot$' || true)"
  _t "  ...a rung of ANOTHER chain is left alone"  0 "$( [ -f "$mroot/line-4.moot" ] && echo 1 || echo 0)"
  _t "  ...and a rung that already reported is not killed" 0 "$( [ -f "$mroot/line-5.moot" ] && echo 1 || echo 0)"
  # A GREEN root, a box that vanished and a harness give-up are NOT a root red: nothing was learned
  # about the root's picks, so the rungs beneath it are exactly as unproven as they were.
  printf 'GREEN%sROOT-LINE\n' "$TAB" >"$mroot/line-1.batch.result"
  _t "a GREEN root moots nothing"                 1 "$(lq_slot_root_red "$mroot" 1 tipX >/dev/null 2>&1; echo $?)"
  printf 'RED%sROOT-LINE\n' "$TAB" >"$mroot/line-1.batch.result"
  printf 'land.sh: RED — oracle: a HARNESS failure, not a divergence: harness give-up: port busy\n' >"$mroot/line-1.log"
  _t "a harness give-up is not a root red either" 1 "$(lq_slot_root_red "$mroot" 1 tipX >/dev/null 2>&1; echo $?)"
  : >"$mroot/line-1.log"
  # THE CHAINED SLOT'S OWN PREFIX-1 ROW says the same thing: the root is red inside the union.
  printf 'ROOT-LINE\n' >"$mroot/line-6.root"; : >"$mroot/line-6.chainkey"; echo 1 >"$mroot/line-6.rc"
  : >"$mroot/line-6.log"; printf 'RED%sROOT-LINE\nHELD%sDEEP-LINE\n' "$TAB" "$TAB" >"$mroot/line-6.batch.result"
  _t "a chained slot whose PREFIX-1 row is RED is a root red" 0 \
     "$(lq_slot_root_red "$mroot" 6 tipX >/dev/null 2>&1; echo $?)"
  # THE CANCEL IS land-remote's, over land-remote's channel, and the local driver goes with it.
  local cdir="$root/cancel"; mkdir -p "$cdir/target/gate"
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >>"%s/asked.txt"\n' "$cdir" >"$cdir/target/gate/land-remote.sh"
  chmod +x "$cdir/target/gate/land-remote.sh"
  printf '[remote 22:15:00] host i-0abc   ref land-20260910-221500-4242   picks: 1234567\n' >"$mroot/line-2.log"
  printf 'i-0abc\n' >"$mroot/line-2.host"
  _t "the ref is read out of the transport's own log" "land-20260910-221500-4242" "$(lq_slot_ref "$mroot/line-2.log")"
  lq_cancel_slot "$mroot" 2 "$cdir" >/dev/null 2>&1
  _t "the box's proof is stopped over land-remote's channel" "--cancel i-0abc land-20260910-221500-4242" \
     "$(cat "$cdir/asked.txt" 2>/dev/null || true)"
  # NOT RE-QUEUED. A mooted rung is not an unanswered question the fleet owes: its root is red, so
  # the HOLD it is parked under is not going to be released this tip either way.
  _t "a mooted slot is scored NONE:moot"        1 "$(grep -c 'NONE:moot, not re-queued (log:' "$LQ_SRC")"
  _t "  ...and is NOT put on the owed-answer front" 0 \
     "$(grep -c 'moot.*lq_front_add\|lq_front_add.*moot' "$LQ_SRC")"
  # NO DEEPER RUNG IS DISPATCHED WHILE THE ROOT IS RED.
  local savedPPm="$PP"; PP="$root/moot-pp.txt"
  printf 'RED%stipX%s/l/1%sROOT-LINE\n' "$TAB" "$TAB" "$TAB" >"$PP"
  _t "a chain whose root is RED at this tip is not a candidate" 0 "$(lq_chain_root_red ROOT-LINE tipX "$PP"; echo $?)"
  _t "  ...a GREEN root is"                     1 "$(lq_chain_root_red OTHER-ROOT tipX "$PP"; echo $?)"
  printf 'ROOT-2\n' >"$root/rootred.txt"
  _t "  ...and this sweep's own red roots count too" 0 "$(lq_chain_root_red ROOT-2 tipX "$PP" "$root/rootred.txt"; echo $?)"
  PP="$savedPPm"
  _t "lq_chain_candidates refuses a red root"   1 \
     "$(sed -n '/^lq_chain_candidates() {/,/^}$/p' "$LQ_SRC" | grep -c '^    lq_chain_root_red "')"
  _t "the sweep watches its slots instead of a bare wait" 1 "$(grep -c '^  lq_sweep_watch "\$dir"' "$LQ_SRC")"

  # ── THE SWEEP STARTS THE BOXES IT NEEDS, AND COUNTS THE TWO PROOFS THAT ARE NOT LINES ─────────
  # An idle box is STOPPED now (scripts/ci-fleet-power.sh), so "how many boxes are awake" is a
  # decision this sweep makes rather than a fact it inherits. The arithmetic is the whole of it:
  # one slot per live line, one per chained hold, one for the base-only replay, and one for the
  # batch the runner is about to pop — but NOT for a batch already in flight, which is holding a
  # box that already reports itself busy. Counting that twice would start a box for a slot that is
  # already spoken for, and "never more than it needs" is the rule the bill is made of.
  echo "landq4 selftest: the sweep asks for the slots it is about to use, and no more"
  _t "six lines, no chains, a replay and a batch to come" 8 "$(lq_sweep_slot_demand 6 0 1 0)"
  _t "  ...with the batch already in flight, one fewer"   7 "$(lq_sweep_slot_demand 6 0 1 1)"
  _t "  ...with the replay turned off, one fewer again"   6 "$(lq_sweep_slot_demand 6 0 0 1)"
  _t "chained holds are slots too"                        9 "$(lq_sweep_slot_demand 6 2 1 1)"
  _t "an empty sweep still leaves the batch a box"        1 "$(lq_sweep_slot_demand 0 0 0 0)"
  _t "a junk count is zero, never a fleet"                1 "$(lq_sweep_slot_demand x y z 0)"
  _t "the sweep asks the power switch BEFORE it probes" 1 \
     "$([ "$(grep -n 'ci-fleet-power.sh" --ensure-slots' "$LQ_SRC" | head -n1 | cut -d: -f1)" \
        -lt "$(grep -n 'fleet_table_open "\$dir/fleet-table"' "$LQ_SRC" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  _t "  ...and a fleet it cannot grow is not fatal"     1 \
     "$(grep -c 'dispatching to the boxes that are already awake' "$LQ_SRC")"
  _t "the power switch is staged with the engine"       1 \
     "$(grep -c 'cp "\$SCRIPTS/ci-fleet-power.sh" "\$t/target/gate/ci-fleet-power.sh"' "$LQ_SRC")"
  _t "  ...and records each slot's root and driver" 2 \
     "$(grep -c 'line-\$i\.root"$\|line-\$i\.driver"$' "$LQ_SRC")"

  # ── THE HEAD OF THE LIVE QUEUE KEEPS ITS SLOTS ────────────────────────────────────────────────
  # MEASURED 2026-09-10: a sweep of twelve spent its WHOLE budget on chained holds — "9 chained
  # holds + 3 live lines, 3 of the live lines root a chain" — and the two lines at the HEAD of the
  # queue got no pre-proof at all; the integrator put them in preprove-front.txt by hand. The chain
  # preference is right (a chain is worth its depth, a single is worth one) and it is not right
  # ENOUGH to take every box: the head of the queue is what the runner is about to POP, and a pop
  # of a line nobody pre-proved is the serial batch the sweep exists to avoid.
  echo "landq4 selftest: the sweep reserves slots for the head of the live queue"
  local hl hr
  hl="$(printf 'L1\nL2\nL3\nL4\n')"
  hr="$(printf 'L3\nL4\nL1\nL2\n')"
  _t "the first K live lines take their slots" "L1 L2 L3" \
     "$(lq_sweep_order "$hl" "$hr" 2 3 | tr '\n' ' ' | sed 's/ $//')"
  _t "  ...and the rest are still roots first" "L1 L2 L3 L4" \
     "$(lq_sweep_order "$hl" "$hr" 2 4 | tr '\n' ' ' | sed 's/ $//')"
  _t "K=0 is exactly the old chains-before-singles" "L3 L4 L1" \
     "$(lq_sweep_order "$hl" "$hr" 0 3 | tr '\n' ' ' | sed 's/ $//')"
  _t "a head line that ROOTS a chain is not listed twice" "L3 L1" \
     "$(lq_sweep_order "$(printf 'L3\nL1\n')" "$(printf 'L3\nL1\n')" 1 2 | tr '\n' ' ' | sed 's/ $//')"
  _t "K larger than the live list is the live list" "L1 L2" \
     "$(lq_sweep_order "$(printf 'L1\nL2\n')" "$(printf 'L2\nL1\n')" 9 9 | tr '\n' ' ' | sed 's/ $//')"
  _t "no slots is no lines"                    "" "$(lq_sweep_order "$hl" "$hr" 2 0)"
  # THE CHAINED HOLDS ARE BUDGETED AGAINST THE RESERVATION TOO. Without this the chains are handed
  # `budget - nroots` boxes, take them, and the trim below has nothing left to give the head.
  _t "the chain budget never eats the reserved head" 4 "$(lq_chain_budget 6 0 2)"
  _t "  ...and the roots' own claim still counts" 3 "$(lq_chain_budget 6 3 2)"
  _t "  ...the two claims are not added twice"  3 "$(lq_chain_budget 6 2 3)"
  _t "  ...and it never goes negative"          0 "$(lq_chain_budget 2 9 2)"
  # …and the blunt `head -n` that dropped them is GONE, not merely bypassed.
  _t "the sweep orders with it, not with head -n" 0 \
     "$(grep -c 'head -n \$((PREPROVE_LINES' "$LQ_SRC")"
  _t "  ...on BOTH arms of the trim"            2 "$(grep -c 'lq_sweep_order "\$lines" "\$roots"' "$LQ_SRC")"
  _t "  ...and the chain budget is asked for"   1 "$(grep -c 'lq_chain_candidates "\$(lq_chain_budget ' "$LQ_SRC")"
  # THE FRONT IS STILL FIRST. lq_sweep_order's head is the head of the list it is GIVEN, and the
  # list the sweep gives it is the front-ordered queue — so an owed line is still offered a box
  # before anything else, and the reservation is over what is left.
  _t "the front reordering happens before the reservation" 1 \
     "$( [ "$(grep -n 'lq_front_queue "\$Q" >"\$dir/queue-front.txt"' "$LQ_SRC" | head -n1 | cut -d: -f1)" \
          -lt "$(grep -n 'lines="\$(lq_sweep_order ' "$LQ_SRC" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  Q="$savedQ7"; PP="$savedPP7"; L="$savedL7"; W="$savedW7"; D="$savedD7"

  # ── TWO FAULTS MEASURED ON THE LIVE RUNNER, 09-11 (F2, second round) ──────────────────────────
  echo "landq4 selftest: a dead prediction cancels its sweep, and the base replay is reserved first"
  local droot="$root/dead"; mkdir -p "$droot"
  # (1) THE DEAD PREDICTION. The overlapped sweep is keyed at <tip + the in-flight batch's picks>;
  # a batch that comes back with ANY row that is not GREEN kills that tree for good.
  printf 'GREEN%s--prove A\nGREEN%s--prove B\n' "$TAB" "$TAB" >"$droot/b1.result"
  printf 'GREEN%s--prove A\nRED%s--prove B\n' "$TAB" "$TAB" >"$droot/b2.result"
  printf 'GREEN%s--prove A\nHELD%s--prove B\n' "$TAB" "$TAB" >"$droot/b3.result"
  printf 'RED-CONFLICT%s--prove A\n' "$TAB" >"$droot/b4.result"
  _t "a wholly green batch keeps its prediction alive" 1 "$(lq_prediction_dead "$droot/b1"; echo $?)"
  _t "  ...one RED row kills it"               0 "$(lq_prediction_dead "$droot/b2"; echo $?)"
  _t "  ...a HELD row kills it too"            0 "$(lq_prediction_dead "$droot/b3"; echo $?)"
  _t "  ...and so does a conflict"             0 "$(lq_prediction_dead "$droot/b4"; echo $?)"
  _t "a batch with no result yet has not killed it" 1 "$(lq_prediction_dead "$droot/nothing"; echo $?)"
  _t "  ...and neither has no batch at all"    1 "$(lq_prediction_dead ""; echo $?)"
  # THE WATCH CANCELS ON THE FLEET. Three slots, one already reported; the other two are cancelled
  # and marked moot rather than left proving a tree that will never exist.
  local sw="$droot/sweep"; mkdir -p "$sw"
  printf '0\n' >"$sw/line-1.rc"; printf 'i-a\n' >"$sw/line-1.host"; : >"$sw/line-1.batch"
  printf 'i-b\n' >"$sw/line-2.host"; : >"$sw/line-2.batch"
  printf 'i-c\n' >"$sw/line-3.host"; : >"$sw/line-3.batch"
  local savedLd="$L"; L="$droot/watch.log"; : >"$L"
  lq_sweep_watch "$sw" 3 deadkey "$repo" "$droot/b2" >/dev/null 2>&1
  _t "the watch returns at once on a dead prediction" 1 \
     "$(grep -c 'the predicted tree .* will never exist' "$L")"
  _t "  ...the unfinished slots are mooted"    2 "$(ls "$sw"/line-*.moot 2>/dev/null | grep -c . || true)"
  _t "  ...slot 2 among them"                  1 "$([ -f "$sw/line-2.moot" ] && echo 1 || echo 0)"
  _t "  ...and slot 3"                         1 "$([ -f "$sw/line-3.moot" ] && echo 1 || echo 0)"
  _t "  ...the slot that already reported is left alone" 0 "$([ -f "$sw/line-1.moot" ] && echo 1 || echo 0)"
  _t "  ...each cancellation says why"         2 "$(grep -c 'its tree is the dead prediction' "$L")"
  # AND A SWEEP WITH NO BATCH IN FLIGHT IS NEVER CANCELLED BY THIS. An ordinary loop-top sweep has
  # no prediction to be wrong about, and a rule that fired there would cancel the whole queue.
  local sw2="$droot/sweep2"; mkdir -p "$sw2"
  printf '0\n' >"$sw2/line-1.rc"; printf 'i-a\n' >"$sw2/line-1.host"; : >"$sw2/line-1.batch"
  : >"$L"
  lq_sweep_watch "$sw2" 1 realkey "$repo" "" >/dev/null 2>&1
  _t "an unoverlapped sweep is never cancelled for a prediction" 0 \
     "$(grep -c 'will never exist' "$L")"
  L="$savedLd"
  _t "the watch is given the batch in flight"  1 "$(grep -cF 'lq_sweep_watch "$dir" "$i" "$key" "$tree" "$inflight"' "$LQ_SRC")"
  # (2) THE BASE REPLAY'S BOX IS RESERVED BEFORE THE LINES GO OUT, and when there is none the
  # batch's oracle red is NONE:base-unmeasured rather than a park with no evidence behind it.
  local savedBR="$BASERED"; BASERED="$droot/basered.txt"; : >"$BASERED"
  printf 'land.sh: RED — oracle families: route\n' >"$droot/orc.log"
  printf 'cell.178.count%sFAIL%skind-isolation | the row diverged\n' "$TAB" "$TAB" >>"$droot/orc.log"
  printf 'land.sh: oracle green on: route\n' >"$droot/green.log"
  _t "an oracle red at an UNMEASURED tip is not the line's" 0 \
     "$(lq_red_is_unmeasured_oracle tipX "$droot/orc.log"; echo $?)"
  printf 'tipX\t#measured\n' >"$BASERED"
  _t "  ...and at a MEASURED tip it is judged normally" 1 \
     "$(lq_red_is_unmeasured_oracle tipX "$droot/orc.log"; echo $?)"
  : >"$BASERED"
  _t "  ...a red with no oracle leg at all is not this" 1 \
     "$(printf 'land.sh: RED — clippy\n' >"$droot/cl.log"; lq_red_is_unmeasured_oracle tipX "$droot/cl.log"; echo $?)"
  _t "  ...and a green oracle leg is not a red"  1 \
     "$(lq_red_is_unmeasured_oracle tipX "$droot/green.log"; echo $?)"
  BASERED="$savedBR"
  _t "the landing path asks it before it parks" 1 \
     "$(grep -cF 'if lq_red_is_unmeasured_oracle "$tip" "$batch.log"; then' "$LQ_SRC")"
  _t "  ...and requeues the line LIVE and unchanged" 1 \
     "$(grep -cF 'lq_log "=== $(lq_fault_verdict base-unmeasured):' "$LQ_SRC")"
  _t "  ...counted as neither green nor red"   1 "$(grep -c 'nnone=\$((nnone + 1))' "$LQ_SRC")"
  _t "  ...and such a batch never teaches the base" 1 \
     "$(grep -cF '[ "${nnone:-0}" = 0 ] && [ -s "$batch.log" ]' "$LQ_SRC")"
  _t "the reservation happens, and names the tip" 1 \
     "$(grep -c 'BEFORE any line was dispatched' "$LQ_SRC")"
  _t "  ...and the reserved box is in hosts from the start" 1 \
     "$(grep -cF 'local i=0 line hosts="$basehost" cand' "$LQ_SRC")"
  _t "  ...the old after-the-lines pick is GONE" 0 "$(grep -c 'fleet_pick_host \$taken' "$LQ_SRC")"
  _t "  ...and the old sentence with it"       0 \
     "$(grep -v '^#' "$LQ_SRC" | grep -c 'no free box for the base replay' || true)"

  # ── ONE STATUS FILE (F7) ──────────────────────────────────────────────────────────────────────
  # The file is JSON or it is nothing: a tick that has to parse prose is a tick that is confidently
  # wrong twice a day. Every key the tick, the integrator and landq-ctl need is asserted present
  # after ONE loop's worth of writing, and the whole of it is validated by python3's own parser.
  echo "landq4 selftest: one status file, written temp+mv, valid JSON, every key"
  local savedSJ="${STATUSJ:-}" savedSP="${SWEEPPTR:-}" savedQ8="$Q" savedD8="$D"
  local savedF8="${FAULTS:-}" savedR8="${FAULTRING:-}" savedPG8="${PAGE:-}" savedW8="$W"
  local sroot="$root/statusdir"; mkdir -p "$sroot"
  STATUSJ="$sroot/landq.status.json"; SWEEPPTR="$sroot/sweep.ptr"
  Q="$sroot/queue.txt"; D="$sroot/done.txt"
  FAULTS="$sroot/faults.txt"; FAULTRING="$sroot/ring.txt"; PAGE="$sroot/page.txt"
  W="$repo"
  printf -- '--prove A\n--prove B\n#HOLD-after-abc1234 --prove C\n#RED --prove D\n#PARK-owner --prove E\n' >"$Q"
  printf 'GREEN batch=1 log=x\nGREEN batch=2 log=y\nNONE:box no-result 2026-09-11T20:00:00\n' >"$D"
  printf 'box-unreachable\t3\t1789155000\tscp: Connection closed\n' >"$FAULTS"
  printf '2026-09-11T20:00:00Z\tbox-unreachable\tscp: Connection closed\n' >"$FAULTRING"
  printf '2026-09-11T20:01:00Z\tdirect-edit\tland-queue.txt was written by somebody else\n' >"$PAGE"
  # A batch in flight, and a sweep with one line on a box and one already judged.
  local sb="$sroot/batch.txt"; printf -- '--prove A\n#UNIT 1\n' >"$sb"
  printf 'land.sh: leg gates (4 file(s))\nland.sh: leg oracle\nland.sh: leg gates (again)\n' >"$sb.log"
  local sd="$sroot/preprove-tip"; mkdir -p "$sd"; printf '%s\n' "$sd" >"$SWEEPPTR"
  printf 'i-071084387d22ed544\n' >"$sd/line-1.host"; printf -- '--prove C\n' >"$sd/line-1.batch"
  printf '1789154000\n' >"$sd/line-1.start"
  printf 'i-0b0e1585e8567d01a\n' >"$sd/line-2.host"; printf -- '--prove D\n' >"$sd/line-2.batch"
  printf '0\n' >"$sd/line-2.rc"                       # this one has a verdict; it is off its box
  LQ_LOOP=41
  _t "the status file is written"              0 "$(lq_status_json "$sb" 1789155000; echo $?)"
  _t "  ...and it is valid JSON"               0 "$(python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$STATUSJ" >/dev/null 2>&1; echo $?)"
  _t "  ...written temp+mv, with no temp left" 0 "$([ -f "$STATUSJ.tmp" ] && echo 1 || echo 0)"
  _t "  ...and the writer is a temp+mv, by construction" 1 "$(grep -c 'os.replace(tmp, out)' "$LQ_SRC")"
  local jq_; jq_() { python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    d = d[int(k)] if isinstance(d, list) else d[k]
print("" if d is None else d)' "$STATUSJ" "$1"; }
  _t "it carries the tip"                      "$(git -C "$repo" rev-parse --short HEAD)" "$(jq_ tip)"
  _t "  ...the engine sha it is running"       1 "$( [ -n "$(jq_ engine_sha)" ] && echo 1 || echo 0)"
  _t "  ...the loop number"                    41 "$(jq_ loop)"
  _t "  ...the live count"                     2  "$(jq_ live)"
  _t "  ...the held count"                     1  "$(jq_ held)"
  _t "  ...the parked count, both marks"       2  "$(jq_ parked)"
  _t "  ...the landed count"                   2  "$(jq_ landed)"
  _t "  ...the per-box proof slot count it READ" 1 "$( [ -n "$(jq_ prove_per_box)" ] && echo 1 || echo 0)"
  _t "  ...which is the environment's when it is set" 4 \
     "$(BUSBAR_PROVE_PER_BOX=4 lq_status_json "$sb" 1789155000; jq_ prove_per_box)"
  _t "  ...and never a constant in this file"  0 "$(grep -c 'prove_per_box.*: *[0-9]' "$LQ_SRC")"
  _t "  ...how many lines a sweep wants"       "$PREPROVE_LINES" "$(jq_ preprove_lines)"
  _t "the batch in flight is named"            "--prove A" "$(jq_ batch.lines.0)"
  _t "  ...its markers are not lines"          1 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["batch"]["lines"]))' "$STATUSJ")"
  _t "  ...when it started"                    1789155000 "$(jq_ batch.started_epoch)"
  _t "  ...and the legs its log announced, deduped" "gates" "$(jq_ batch.legs.0)"
  _t "  ...in order"                           "oracle" "$(jq_ batch.legs.1)"
  _t "the sweep names the box a line is on"    "i-071084387d22ed544" "$(jq_ sweep.0.box)"
  _t "  ...the line it is proving"             "--prove C" "$(jq_ sweep.0.line)"
  _t "  ...and when it went there"             1789154000 "$(jq_ sweep.0.started_epoch)"
  _t "  ...a line that already has a verdict is OFF its box" 1 \
     "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["sweep"]))' "$STATUSJ")"
  _t "the backoff counter is per class"        3 "$(jq_ backoff.box-unreachable)"
  _t "the last faults carry their class"       "box-unreachable" "$(jq_ faults.0.class)"
  _t "  ...their time"                         "2026-09-11T20:00:00Z" "$(jq_ faults.0.at)"
  _t "  ...and their text"                     "scp: Connection closed" "$(jq_ faults.0.text)"
  _t "the DIRECT-EDIT flag is raised"          1 "$( [ -n "$(jq_ direct_edit)" ] && echo 1 || echo 0)"
  _t "  ...and it says when"                   1 "$(jq_ direct_edit | grep -c '2026-09-11T20:01:00Z')"
  # …and with nothing happening at all the file is still valid JSON with every key in it.
  rm -f "$SWEEPPTR" "$PAGE" "$FAULTS" "$FAULTRING"
  _t "an idle loop writes it too"              0 "$(lq_status_json; echo $?)"
  _t "  ...still valid JSON"                   0 "$(python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$STATUSJ" >/dev/null 2>&1; echo $?)"
  _t "  ...with every key present"             0 "$(python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
want=["written","written_epoch","pid","loop","tip","engine_sha","prove_per_box","preprove_lines",
      "live","held","parked","landed","batch","sweep","backoff","faults","pages","direct_edit"]
missing=[k for k in want if k not in d]
sys.exit(1 if missing else 0)' "$STATUSJ"; echo $?)"
  _t "  ...no batch, and it says so"           "" "$(jq_ batch.started_epoch)"
  _t "  ...no line on a box"                   0 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["sweep"]))' "$STATUSJ")"
  _t "  ...and no page"                        "" "$(jq_ direct_edit)"
  # THE SITES: every loop, and at every state change.
  _t "the runner writes it at the loop top, after the fold, and when the batch comes back" 3 \
     "$(grep -c '^  lq_status_json$' "$LQ_SRC")"
  _t "  ...and the one after the fold comes before the dispatch" 1 \
     "$( [ "$(grep -n '^  lq_status_json$' "$LQ_SRC" | sed -n 2p | cut -d: -f1)" \
          -lt "$(grep -n '^  lq_status_json "\$batch" "\$bstart"$' "$LQ_SRC" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  _t "  ...the loop-top one FIRST"             1 \
     "$( [ "$(grep -n '^  lq_status_json$' "$LQ_SRC" | head -n1 | cut -d: -f1)" \
          -lt "$(grep -n '^  lq_status_json "\$batch" "\$bstart"$' "$LQ_SRC" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  _t "  ...counting the loop as it goes"       1 "$(grep -c '^  LQ_LOOP=\$((LQ_LOOP + 1))$' "$LQ_SRC")"
  _t "  ...when the batch goes to a box"       1 "$(grep -c '^  lq_status_json "\$batch" "\$bstart"$' "$LQ_SRC")"
  _t "  ...and on every fault"                 3 "$(grep -c 'lq_status_json; sleep\|^    lq_status_json$' "$LQ_SRC")"
  _t "the sweep says where it is"              1 "$(grep -cF '>"$SWEEPPTR"' "$LQ_SRC")"
  _t "  ...and takes it back when it is over"  1 "$(grep -c '^  rm -f "\$SWEEPPTR"$' "$LQ_SRC")"
  _t "  ...each slot's start is written down"  2 "$(grep -cF 'date +%s >"$dir/line-$i.start"' "$LQ_SRC")"
  STATUSJ="$savedSJ"; SWEEPPTR="$savedSP"; Q="$savedQ8"; D="$savedD8"
  FAULTS="$savedF8"; FAULTRING="$savedR8"; PAGE="$savedPG8"; W="$savedW8"; LQ_LOOP=0

  # ── THE COMMAND GRAMMAR (F3): THE RUNNER IS THE ONLY WRITER OF land-queue.txt ─────────────────
  # Every verb, applied to a real queue through the real fold, and each was RED before the grammar
  # existed — lq_inbox_fold appended every inbox line verbatim, so `PARK <sha> …` went into the
  # queue AS A LINE and a park still needed a direct edit.
  echo "landq4 selftest: the inbox is a COMMAND file, and the runner is the only writer"
  local savedIB6="${INBOX:-}" savedQ6b="$Q" savedL6="$L"
  INBOX="$root/cmd-inbox.txt"; Q="$root/cmd-queue.txt"; L="$root/cmd.log"; : >"$L"
  local c1 c2 c3
  c1="$(git -C "$repo" rev-parse --short "$ha")"; c2="$(git -C "$repo" rev-parse --short "$hb")"
  c3="$(git -C "$repo" rev-parse --short "$hc")"
  printf -- '--prove --tests xtask %s\n--prove --tests xtask %s\n--prove --tests xtask %s\n' "$c1" "$c2" "$c3" >"$Q"
  # ADD, bare and explicit.
  printf 'ADD --prove --tests xtask deadbee\n' >"$INBOX"
  _t "ADD appends to the tail"                 1 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...as a line, without its verb"        "--prove --tests xtask deadbee" "$(tail -n1 "$Q")"
  printf -- '#HOLD-after-%s --prove --tests xtask beadfee\n' "$c1" >"$INBOX"
  _t "a BARE line is still an ADD (T0-D13's form)" 1 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...tags and all"                       1 "$(grep -c -- "^#HOLD-after-$c1 --prove --tests xtask beadfee$" "$Q")"
  # PARK / UNPARK.
  printf 'PARK %s the owner has not ruled on it\n' "$c2" >"$INBOX"
  _t "PARK tags the line that names the sha"   1 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...with its reason as one token"       1 "$(grep -c -- "^#PARK-the-owner-has-not-ruled-on-it --prove --tests xtask $c2$" "$Q")"
  _t "  ...and it is no longer live"           0 "$(grep -c -- "^--prove --tests xtask $c2$" "$Q")"
  printf 'UNPARK %s\n' "$c2" >"$INBOX"
  _t "UNPARK takes the tag off"                1 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...and the line is live again"         1 "$(grep -c -- "^--prove --tests xtask $c2$" "$Q")"
  # A PRE-PROOF PARK carries a log path that is not a tag; un-parking must take that with it.
  _t "un-parking a #RED-preproof drops its log too" "--prove --tests xtask $c2" \
     "$(lq_line_unpark "#RED-preproof /var/log/line-3.log --prove --tests xtask $c2")"
  _t "  ...and a plain #RED park too"          "--prove --tests xtask $c2" \
     "$(lq_line_unpark "#RED --prove --tests xtask $c2")"
  _t "  ...while a HOLD is not a park and stays" "#HOLD-after-abc1234 --prove x" \
     "$(lq_line_unpark "#HOLD-after-abc1234 --prove x")"
  # SUPERSEDE.
  printf 'SUPERSEDE %s --prove --tests xtask %s recut1\n' "$c3" "$c3" >"$INBOX"
  _t "SUPERSEDE replaces the line"             1 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...with the new one, in place"         1 "$(grep -c -- "^--prove --tests xtask $c3 recut1$" "$Q")"
  _t "  ...and the old one is gone"            0 "$(grep -c -- "^--prove --tests xtask $c3$" "$Q")"
  # RETAG.
  printf 'RETAG %s #HOLD-after-%s #T0-B2-seam\n' "$c1" "$c2" >"$INBOX"
  _t "RETAG replaces the leading tags"         1 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...with exactly the ones given"        1 "$(grep -c -- "^#HOLD-after-$c2 #T0-B2-seam --prove --tests xtask $c1$" "$Q")"
  printf 'RETAG %s\n' "$c1" >"$INBOX"
  _t "  ...and RETAG with no tag at all goes LIVE" 1 "$(lq_inbox_fold "$Q" "$INBOX" >/dev/null; grep -c -- "^--prove --tests xtask $c1$" "$Q")"
  # FRONT.
  printf 'FRONT %s\n' "$c3" >"$INBOX"
  _t "FRONT moves the line to the head"        1 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...and it is the first line of the file" "--prove --tests xtask $c3 recut1" "$(head -n1 "$Q")"
  _t "  ...named once and once only"           1 "$(grep -c -- "^--prove --tests xtask $c3 recut1$" "$Q")"
  # MALFORMED IS LOGGED WITH ITS TEXT AND SKIPPED — never fatal, and never a line in the queue.
  local qbefore; qbefore="$(cksum <"$Q")"
  printf 'PARK\nUNPARK 0000000\nSUPERSEDE %s\nRETAG %s notatag\nFRONT zzzz\n' "$c1" "$c1" >"$INBOX"
  _t "five malformed commands apply none of them" 0 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...and change the queue not at all"    "$qbefore" "$(cksum <"$Q")"
  _t "  ...the fold still returns 0, never fatal" 0 "$(printf 'FRONT\n' >"$INBOX"; lq_inbox_fold "$Q" "$INBOX" >/dev/null; echo $?)"
  _t "  ...each is logged with its own text"   1 "$(grep -c 'inbox: MALFORMED, skipped: \[RETAG .* notatag\]' "$L")"
  _t "  ...a verb with no sha says so"         1 "$(grep -c 'inbox: MALFORMED, skipped: \[PARK\] — PARK with no sha' "$L")"
  _t "  ...a sha nobody names says so"         1 "$(grep -c 'no queue line names 0000000' "$L")"
  _t "  ...and the inbox is emptied either way" 0 "$(grep -c . "$INBOX" 2>/dev/null; true)"
  # A COMMAND APPENDED DURING A SWEEP IS FOLDED NEXT LOOP, AND THE POP THAT LOOP IS TAKEN. This is
  # the whole reason the grammar exists: the same command written INTO land-queue.txt would have
  # moved the file under the stamp and cost this loop's pop.
  printf -- '--prove --tests xtask %s\n--prove --tests xtask %s\n' "$c1" "$c2" >"$Q"
  local cst; cst="$(lq_qstamp)"                                    # the runner stamps, then sweeps
  printf 'PARK %s mid-sweep\n' "$c2" >>"$INBOX"                    # the integrator, mid-sweep
  printf -- '--prove --tests xtask %s\n' "$c2" >"$root/cmd-keep.txt"   # the loop popped c1
  _t "a command written mid-sweep does not refuse the rewrite" 0 \
     "$(lq_queue_rewrite "$root/cmd-keep.txt" "$cst"; echo $?)"
  _t "  ...so the pop STANDS this loop"        1 "$(grep -c -- "^--prove --tests xtask $c2$" "$Q")"
  _t "  ...and the popped line is gone"        0 "$(grep -c -- "^--prove --tests xtask $c1$" "$Q")"
  _t "  ...the command is folded at the NEXT loop top" 1 "$(lq_inbox_fold "$Q" "$INBOX")"
  _t "  ...and it took effect"                 1 "$(grep -c -- "^#PARK-mid-sweep --prove --tests xtask $c2$" "$Q")"
  # THE TRIPWIRE. A direct edit is refused as it always was — and now the popped lines are taken out
  # of the queue AS IT NOW READS, so the edit stands AND the pop stands.
  printf -- '--prove --tests xtask %s\n--prove --tests xtask %s\n' "$c1" "$c2" >"$Q"
  local dst; dst="$(lq_qstamp)"
  printf -- '--prove --tests xtask BY-HAND\n' >>"$Q"               # somebody edits the file itself
  printf -- '--prove --tests xtask %s\n' "$c2" >"$root/cmd-keep2.txt"
  _t "a DIRECT edit is still refused"          2 "$(lq_queue_rewrite "$root/cmd-keep2.txt" "$dst" >/dev/null 2>&1; echo $?)"
  printf -- '--prove --tests xtask %s\n' "$c1" >"$root/cmd-batch.txt"; : >"$root/cmd-batch.txt.chain"
  _t "  ...and the reconcile drops the popped line only" 1 "$(lq_queue_reconcile "$root/cmd-batch.txt" "$Q")"
  _t "  ...the popped line is gone"            0 "$(grep -c -- "^--prove --tests xtask $c1$" "$Q")"
  _t "  ...the hand edit SURVIVES"             1 "$(grep -cx -- '--prove --tests xtask BY-HAND' "$Q")"
  _t "  ...and so does everything else"        1 "$(grep -c -- "^--prove --tests xtask $c2$" "$Q")"
  # THE PAGE. A direct edit is an error, not a routine, and it is visible without reading a log.
  local savedPG="${PAGE:-}"; PAGE="$root/page.txt"; rm -f "$PAGE"
  lq_page direct-edit "land-queue.txt was written by somebody other than the runner"
  _t "the page is recorded"                    1 "$(grep -c 'direct-edit' "$PAGE")"
  _t "  ...with a UTC stamp"                   1 "$(grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]+Z' "$PAGE")"
  _t "  ...and it is in the log too"           1 "$(grep -c 'PAGE \[direct-edit\]' "$L")"
  _t "  ...and it clears"                      1 "$(lq_page_clear; [ -f "$PAGE" ] && echo 0 || echo 1)"
  PAGE="$savedPG"
  # THE SITE: the runner pages and re-reads; it no longer throws the pop away.
  _t "the refused rewrite pages"               1 "$(grep -c '^    lq_page direct-edit ' "$LQ_SRC")"
  _t "  ...re-reads and reconciles"            1 "$(grep -c 'lq_queue_reconcile "\$batch" "\$Q"' "$LQ_SRC")"
  _t "  ...and only drops the batch when the lock will not come" 1 \
     "$(grep -c 'and the lock did not come free' "$LQ_SRC")"
  _t "landq-ctl is the tool, and it is in the tree" 1 \
     "$([ -f "$(dirname "$0")/landq-ctl.sh" ] && echo 1 || echo 0)"
  INBOX="$savedIB6"; Q="$savedQ6b"; L="$savedL6"

  # ── THE FAULT TAXONOMY (F2) ───────────────────────────────────────────────────────────────────
  # Every class is driven from the SENTENCE the transport really wrote, taken from the running
  # engine's log, and each case was RED before the taxonomy existed: the engine had no class at all
  # and the batch site exited 1.
  echo "landq4 selftest: an infrastructure fault is a class, a backoff and a NONE — never a HALT"
  local savedF="${FAULTS:-}" savedR="${FAULTRING:-}"
  FAULTS="$root/faults.txt"; FAULTRING="$root/faultring.txt"; : >"$FAULTS"; : >"$FAULTRING"
  local fdir="$root/faultlogs"; mkdir -p "$fdir"
  printf 'land-remote: no prepared, reachable on-demand box among the 0 in %s/.busbar-fleet\n' "$HOME" >"$fdir/probe.log"
  printf 'land-remote: could not push the integration base 4197eb098 to i-071084387d22ed544\n' >"$fdir/basepush.log"
  printf '[remote 21:44:08] the instance was stopped: Service initiated\n' >"$fdir/spot.log"
  printf 'land.sh: RED — oracle: a HARNESS failure, not a divergence (documented)\n' >"$fdir/harn.log"
  printf 'scp: Connection closed\n' >"$fdir/scp.log"
  printf 'ssh: connect to host i-0b0e1585e8567d01a port 22: Connection timed out\n' >"$fdir/ssh.log"
  printf 'land-remote: i-07af07dd77dfea9d9 unreachable for 10 polls — no verdict\n' >"$fdir/poll.log"
  printf 'rsync: connection unexpectedly closed\n' >"$fdir/rsync.log"
  printf 'gate kind-isolation: FAIL cell.178.count 19 -> 27\n' >"$fdir/realred.log"
  _t "probe-empty is its own class"            "probe-empty"      "$(lq_fault_class 2 "$fdir/probe.log")"
  # A STOPPED BOX IS NOT AN UNREACHABLE ONE (FLEET-2's cost posture): it is started and retried.
  printf 'An error occurred (TargetNotConnected) when calling the StartSession operation
' >"$fdir/stopped.log"
  printf 'ci-fleet-power: 0 running box(es) are stopped; the sweep must start what it needs
' >"$fdir/asleep.log"
  _t "a stopped box is its own class"          "box-stopped"      "$(lq_fault_class 2 "$fdir/stopped.log")"
  _t "  ...and so is a fleet that is all asleep" "box-stopped"    "$(lq_fault_class 2 "$fdir/asleep.log")"
  _t "  ...it outranks box-unreachable"        "box-stopped"      "$(printf 'ssh: connect to host i-a port 22: Connection refused\nAn error occurred (TargetNotConnected)\n' >"$fdir/both.log"; lq_fault_class 2 "$fdir/both.log")"
  _t "  ...and the engine starts a box for it" 1 "$(grep -c 'box-stopped|probe-empty) lq_fault_wake 1' "$LQ_SRC")"
  _t "  ...with no staged power script it still retries" 1 \
     "$(LANDQ_LOG="$root/wake.log" L="$root/wake.log" lq_fault_wake 1 "$root/nosuchtree" >/dev/null 2>&1; echo $?)"
  _t "the base push failing is its own class"  "base-push-failed" "$(lq_fault_class 2 "$fdir/basepush.log")"
  _t "a reclaimed spot instance is its own class" "spot-reclaimed" "$(lq_fault_class 2 "$fdir/spot.log")"
  _t "the harness give-up keeps its class"     "harness"          "$(lq_fault_class 1 "$fdir/harn.log")"
  _t "an scp that closed is box-unreachable"   "box-unreachable"  "$(lq_fault_class 2 "$fdir/scp.log")"
  _t "  ...as is an ssh that never connected"  "box-unreachable"  "$(lq_fault_class 2 "$fdir/ssh.log")"
  _t "  ...and a poller that gave up"          "box-unreachable"  "$(lq_fault_class 2 "$fdir/poll.log")"
  _t "  ...and an rsync that closed"           "box-unreachable"  "$(lq_fault_class 2 "$fdir/rsync.log")"
  _t "  ...and rc 75 with no log at all"       "box-unreachable"  "$(lq_fault_class 75 "")"
  # A REAL RED IS NOT A FAULT, and this is the case the whole taxonomy has to get right: a line that
  # was judged and went red must still go red, or the engine has stopped judging.
  _t "a gate that really failed is NO class"   ""                 "$(lq_fault_class 1 "$fdir/realred.log")"
  _t "  ...and rc 1 with no log is no class either" ""            "$(lq_fault_class 1 "")"
  # …but a BATCH with no outcomes always has one: nothing was learned, whatever the log says.
  _t "a batch with no outcomes is a fault even so" "box-unreachable" "$(lq_batch_fault_class 1 "$fdir/realred.log")"
  _t "  ...and keeps the more precise class when there is one" "probe-empty" \
     "$(lq_batch_fault_class 2 "$fdir/probe.log")"
  # THE BACKOFF: 1, 2, 4, 8, 15 and 15 from then on.
  _t "the first fault waits a minute"          60   "$(lq_backoff_secs 1)"
  _t "  ...the second two"                     120  "$(lq_backoff_secs 2)"
  _t "  ...the third four"                     240  "$(lq_backoff_secs 3)"
  _t "  ...the fourth eight"                   480  "$(lq_backoff_secs 4)"
  _t "  ...and it caps at fifteen"             900  "$(lq_backoff_secs 5)"
  _t "  ...and stays there"                    900  "$(lq_backoff_secs 40)"
  _t "  ...a count of nothing is the first"    60   "$(lq_backoff_secs "")"
  # THE COUNTER IS PER CLASS, and one class firing does not back another one off.
  _t "an unseen class has not fired"           0 "$(lq_fault_count box-unreachable)"
  _t "the first record counts one"             1 "$(lq_fault_record box-unreachable "scp: Connection closed")"
  _t "  ...the second two"                     2 "$(lq_fault_record box-unreachable "scp: Connection closed")"
  _t "  ...and another class is still at one"  1 "$(lq_fault_record probe-empty "no prepared, reachable on-demand box among the 0")"
  _t "  ...the ledger has one row per class"   2 "$(grep -c . "$FAULTS")"
  _t "  ...and the count is readable"          2 "$(lq_fault_count box-unreachable)"
  _t "clearing one class leaves the other"     0 "$(lq_fault_clear box-unreachable; lq_fault_count box-unreachable)"
  _t "  ...which is untouched"                 1 "$(lq_fault_count probe-empty)"
  _t "a batch that came back clears them all"  0 "$(lq_fault_clear; grep -c . "$FAULTS" 2>/dev/null; true)"
  # THE RING keeps the last few faults with their text, for the status file to render.
  _t "the ring keeps the last five"            5 "$(for i in 1 2 3 4 5 6 7; do lq_fault_record box-unreachable "fault $i" >/dev/null; done; grep -c . "$FAULTRING")"
  _t "  ...and the newest is last"             1 "$(tail -n1 "$FAULTRING" | grep -c 'fault 7')"
  _t "  ...with its class beside it"           1 "$(tail -n1 "$FAULTRING" | grep -c 'box-unreachable')"
  # THE VERDICT IS THE ENGINE'S EXISTING WORD FOR "NOTHING WAS LEARNED".
  _t "a class becomes a NONE verdict"          "NONE:probe-empty" "$(lq_fault_verdict probe-empty)"
  # A STALE LOCK. A dead pid, and — the one that cost a night — a LIVE pid that is somebody else.
  _t "a dead pid's lock is stale"              0 "$(lq_lock_stale 999999 "Thu Sep 11 00:00:00 2026"; echo $?)"
  _t "this shell's own lock is NOT stale"      1 "$(lq_lock_stale $$ "$(lq_pid_start $$)"; echo $?)"
  _t "  ...but the same pid with another start time IS" 0 \
     "$(lq_lock_stale $$ "Thu Jan  1 00:00:00 1970"; echo $?)"
  _t "  ...and an old lock with no start time is respected" 1 "$(lq_lock_stale $$ ""; echo $?)"
  _t "a pid that is not a number is stale"     0 "$(lq_lock_stale "" ""; echo $?)"
  # THE SITE ITSELF: the batch-outcome mismatch no longer exits, and HALT is left to the ONE tree
  # fact. Counted on the implementation with the selftest cut out of it.
  _t "no-result no longer HALTs"               0 "$(grep -c 'HALT: land.sh --batch left' "$LQ_SRC")"
  _t "  ...it requeues, backs off and continues" 1 \
     "$(grep -c 'sleep "\$fwait"; continue' "$LQ_SRC")"
  _t "  ...naming the class in the ledger"     1 "$(grep -c 'lq_fault_verdict "\$fcls") no-result' "$LQ_SRC")"
  _t "  ...and the requeue still happens first" 1 \
     "$( [ "$(grep -n 'cat "\$batch.requeue" "\$Q"' "$LQ_SRC" | head -n1 | cut -d: -f1)" \
          -lt "$(grep -n 'fn="\$(lq_fault_record "\$fcls"' "$LQ_SRC" | head -n1 | cut -d: -f1)" ] && echo 1 || echo 0)"
  # TWO HALTS ARE LEFT, AND BOTH ARE FACTS ABOUT THE TREE (see THE EXIT-CODE CONTRACT): a head
  # line that will not apply twice, and a tree that stays moved. Nothing else leaves the loop.
  _t "exactly TWO HALTs are left in the engine" 2 "$(grep -c '=== HALT:' "$LQ_SRC")"
  _t "  ...one is head-conflict-twice"         1 "$(grep -c 'echo "HALT head-conflict-twice' "$LQ_SRC")"
  _t "  ...and it is the only exit 1 there is" 1 "$(grep -c '^      exit 1$' "$LQ_SRC")"
  _t "  ...the other is a tree that stays moved" 1 "$(grep -c 'echo "HALT tree-moved' "$LQ_SRC")"
  _t "  ...and it is the only exit 3 there is" 1 "$(grep -c '^      exit 3$' "$LQ_SRC")"
  _t "  ...and it waits for a run of refusals, not one" 1 \
     "$(grep -c 'fn:-0}" -ge "\$LQ_TREE_MOVED_HALT_AFTER"' "$LQ_SRC")"
  _t "both HALTs raise a page"                 2 "$(grep -c 'lq_page halt-' "$LQ_SRC")"
  _t "the lock held by a live runner is exit 2, not a HALT" 1 \
     "$(grep -c 'only one runner lands on this host" >&2; exit 2' "$LQ_SRC")"
  _t "a batch with outcomes clears the counters" 1 "$(grep -c '^  lq_fault_clear$' "$LQ_SRC")"
  _t "the census's empty answer is a counted class" 1 "$(grep -c 'lq_fault_record census-empty' "$LQ_SRC")"
  _t "  ...and so is a tree that moved"        1 "$(grep -c 'lq_fault_record tree-moved' "$LQ_SRC")"
  _t "the host lock records the holder's start time" 1 \
     "$(grep -cF 'lq_pid_start "$me")" >"$LOCK"' "$LQ_SRC")"
  _t "  ...and the queue lock does too"        1 "$(grep -c 'lq_pid_start "\$\$" >"\$QLOCK/start"' "$LQ_SRC")"
  FAULTS="$savedF"; FAULTRING="$savedR"

  # ── THE EXIT-CODE CONTRACT AND THE BOUNDARY SIGNAL (F1) ───────────────────────────────────────
  echo "landq4 selftest: the exit-code contract and the boundary the supervisor reads"
  _t "the contract names four codes, once"     1 "$(grep -c '^LQ_EXIT_STOP=0; LQ_EXIT_HALT_HEAD=1; LQ_EXIT_LOCKED=2; LQ_EXIT_HALT_TREE_MOVED=3$' "$LQ_SRC")"
  _t "the STOP marker exits 0"                 1 "$(grep -c '^    exit 0; }$' "$LQ_SRC")"
  _t "  ...and signals the boundary on the way out" 1 \
     "$(grep -c 'lq_log "STOP marker seen"; lq_boundary' "$LQ_SRC")"
  local savedB="${BOUNDARY:-}"; BOUNDARY="$root/boundary.txt"
  lq_boundary deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
  _t "a boundary is ONE line"                  1 "$(grep -c . "$BOUNDARY")"
  _t "  ...carrying the tip it landed at"      1 "$(grep -c 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' "$BOUNDARY")"
  _t "  ...behind an epoch, so a reader can age it" 1 \
     "$(awk '{print ($1 ~ /^[0-9]{10}$/) ? 1 : 0}' "$BOUNDARY")"
  lq_boundary cafe123cafe123cafe123cafe123cafe123cafe1
  _t "the signal is rewritten, never appended" 1 "$(grep -c . "$BOUNDARY")"
  _t "  ...and it is the newest boundary"      1 "$(grep -c 'cafe123' "$BOUNDARY")"
  _t "  ...written temp+mv, so no reader sees half of it" 1 \
     "$(grep -c 'mv "\$BOUNDARY.tmp" "\$BOUNDARY"' "$LQ_SRC")"
  _t "  ...and nothing is left behind"         0 "$([ -e "$BOUNDARY.tmp" ] && echo 1 || echo 0)"
  _t "a batch signals its boundary at the tip it landed" 1 \
     "$(grep -c '^  lq_boundary "\$newtip"' "$LQ_SRC")"
  BOUNDARY="$savedB"

  # ── NO SCRATCH UNDER /tmp (owner rule, 2026-09-11) ────────────────────────────────────────────
  # The pattern is built from a variable so that this assertion is not itself the thing it counts.
  echo "landq4 selftest: no scratch under the wiped directories"
  local _sl="/" _pat
  _pat="(^|[^[:alnum:]_.-])${_sl}tmp(${_sl}|[^[:alnum:]]|\$)"
  _t "the engine names no absolute /tmp path" 0 \
     "$(grep -vE '^[[:space:]]*#' "$LQ_SRC" | grep -cE "$_pat" || true)"
  _t "  ...and it takes no TMPDIR fallback either" 0 \
     "$(grep -vE '^[[:space:]]*#' "$LQ_SRC" | grep -c 'TMPDIR' || true)"
  _t "  ...the scratch root is LAND_TMP, declared once" 1 \
     "$(grep -c '^LAND_TMP=' "$LQ_SRC")"
  _t "  ...and this very selftest ran under it" 1 \
     "$(case "$root" in "$LAND_TMP"/*) echo 1 ;; *) echo 0 ;; esac)"

  rm -rf "$root"
  if [ "$fails" -eq 0 ]; then
    echo "landq4 selftest: GREEN (file sets, disjoint sweep, tip-keyed ledger, batch ceiling, one-file/one-judge/red-alone,"
    echo "                        popper, chains admitted as ONE UNIT, unit markers, HELD lines, head before chains before singles)"
    return 0
  fi
  echo "landq4 selftest: RED ($fails failure(s))" >&2
  return 1
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --selftest) lq_selftest; exit $? ;;
esac

mkdir -p "$W/target/gate"
touch "$Q" "$D" "$PP"
# The lock is taken IN THIS SHELL, never inside a command substitution: `$(lq_lock_acquire ...)` runs
# the function in a subshell, so the `export LANDQ_RUNNER_PID` it performs dies with that subshell
# and the batch this runner then launches is refused by its own lock as an outsider.
if ! lq_lock_acquire $$ >"$W/target/gate/landq4.holder"; then
  echo "landq4.sh: another runner (pid $(cat "$W/target/gate/landq4.holder")) holds $LOCK — only one runner lands on this host" >&2; exit 2
fi
rm -f "$W/target/gate/landq4.holder"
trap 'lq_lock_release $$' EXIT

if [ "${1:-}" = "--preprove-once" ]; then
  lq_preprove_sweep
  exit $?
fi

consec_head_conflict=0
while true; do
  # A STOP IS A BOUNDARY (see lq_boundary): the supervisor's adoption check reads this signal, and
  # an engine adopted by an integrator's own STOP must not look like a runner that vanished.
  [ -f "$W/target/gate/STOP" ] && {
    lq_log "STOP marker seen"; lq_boundary "$(git -C "$W" rev-parse HEAD 2>/dev/null || true)"
    exit 0; }

  # THE STATE OF THE QUEUE IN ONE LINE (see lq_status), first thing, every loop: a tick reads
  # `tail -n 1 target/gate/landq4.status` rather than the log.
  lq_status >"$W/target/gate/landq4.status"
  lq_log "status: $(cat "$W/target/gate/landq4.status")"
  # ...AND THE WHOLE OF IT AS JSON (see lq_status_json), every loop and at every state change below.
  # `landq-ctl status` renders this file; the tick reads nothing else, and no agent tails the log.
  LQ_LOOP=$((LQ_LOOP + 1))
  lq_status_json

  # A LANDED TIP REACHES ORIGIN WITHIN THE MINUTE, and the sweep is not what it waits for.
  # MEASURED 07:20 on 09-10: K1 landed, the loop went straight into a sweep, and `origin` sat at
  # 76f1887af for over twenty minutes while eight boxes proved the next lines — until the
  # integrator pushed by hand. The push at the BOTTOM of the loop only runs when the batch is
  # over; a sweep is the better part of an hour, and every slot cutting a line in that window cut
  # it on a tip that was already stale. `try_push` is a no-op when HEAD is origin's, so running it
  # first costs one `rev-parse` on the ordinary loop and closes the window on every other one.
  try_push

  tip="$(git -C "$W" rev-parse HEAD)"
  # ONE ENGINE IN THE TREE (see lq_census): strangers are killed and logged, and a tree that is not
  # settled — HEAD is not the last landed tip, or something tracked is modified — refuses the batch.
  TIPF="$W/target/gate/landq4.tip"
  census="$(lq_census $$ "$W")"; census_rc=$?
  printf '%s\n' "$census" | while IFS= read -r s; do [ -n "$s" ] && lq_log "census: $s"; done
  # A REFUSED BATCH IS A FAULT WITH A NAME (see THE FAULT TAXONOMY), not a silent minute. Neither
  # of these exits — a runner that gives up on a broken census or a moved tree loses more than it
  # protects, and the census is usually about to kill the stray that moved the tree — but both are
  # now COUNTED, backed off and carried in the status file, so a tree that stays moved pages rather
  # than idling forever with a line in a log nobody is tailing.
  if [ "$census_rc" != 0 ]; then
    lq_log "=== $(lq_fault_verdict census-empty): the census saw nothing at all, not even this runner's own chain; batch REFUSED, nothing popped"
    fn="$(lq_fault_record census-empty "the census returned no process at all")"
    lq_status_json; sleep "$(lq_backoff_secs "$fn")"; continue
  fi
  if ! lq_tree_settled "$W" "$TIPF"; then
    lq_log "=== $(lq_fault_verdict tree-moved): HEAD $(git -C "$W" rev-parse --short HEAD) is not the last landed tip $(cut -c1-9 "$TIPF") or the tree is modified; batch REFUSED, nothing popped"
    fn="$(lq_fault_record tree-moved "HEAD $(git -C "$W" rev-parse --short HEAD) is not the last landed tip, or the tree is modified")"
    # ...AND A TREE THAT STAYS MOVED IS THE SECOND TREE FACT (see THE EXIT-CODE CONTRACT). The
    # first four refusals are a stray process the census kills; the fifth is somebody's checkout.
    if [ "${fn:-0}" -ge "$LQ_TREE_MOVED_HALT_AFTER" ]; then
      lq_log "=== HALT: the tree has been moved under the runner $fn loops in a row; it needs an integrator"
      lq_page halt-tree-moved "HEAD $(git -C "$W" rev-parse --short HEAD) is not the last landed tip $(cut -c1-9 "$TIPF" 2>/dev/null || true), $fn loops in a row"
      echo "HALT tree-moved $(date +%FT%T)" >>"$D"
      lq_status_json
      exit 3
    fi
    lq_status_json; sleep "$(lq_backoff_secs "$fn")"; continue
  fi
  lq_fault_clear census-empty; lq_fault_clear tree-moved
  batch="$W/target/gate/landq4-batch.$$.txt"; keep="$W/target/gate/landq4-keep.$$.txt"
  # ONE WRITER OF THE QUEUE (see lq_qlock). Taken here and dropped the moment the rewrite is taken
  # or refused; the pre-prove sweep below runs INSIDE it only because the pop that follows must read
  # the file the sweep judged. A lock this runner cannot get is not an error: somebody else is
  # editing, and the loop is simply taken again.
  if ! lq_qlock; then
    lq_log "queue: the queue lock is held by pid $(cat "$QLOCK/pid" 2>/dev/null || echo '?'); nothing popped this loop"
    sleep 60; continue
  fi
  # A HOLD THAT NAMES A SHA RELEASES ITSELF (see lq_release_holds) — before the head is read, so a
  # line freed by the last batch can be this batch's head, base fix and all.
  lq_release_holds "$W" | while IFS= read -r s; do [ -n "$s" ] && lq_log "queue: $s"; done
  # THE INBOX, FOLDED TO THE TAIL BEFORE THE STAMP IS TAKEN (see lq_inbox_fold). This is the only
  # reader of it, and the stamp below is what makes the fold worth anything: an append made from
  # here on goes to the inbox, not to the file this stamp describes, so the rewrite at the end of
  # this loop cannot be refused for it.
  infold="$(lq_inbox_fold "$Q" "$INBOX")"
  [ "${infold:-0}" = 0 ] || lq_log "queue: $infold line(s) folded in from the inbox to the tail of land-queue.txt"
  qstamp="$(lq_qstamp)"
  headline="$(lq_head_line "$Q")"
  if [ -n "$headline" ] && lq_line_is_base_fix "$headline" "$W"; then
    # A BASE FIX POPS ALONE (see lq_line_is_base_fix): no sweep, the head by itself, nothing behind it.
    lq_log "base fix at the head ($(printf '%.60s' "$headline")): sweep skipped, popped alone"
    B=1; n="$(lq_pop_head_alone "$batch" "$keep")"
  else
    # THE SWEEP RUNS FIRST, and its cost is somebody else's cores. It is best-effort by construction:
    # a sweep that reaches no box writes no rows, and the pop below then behaves exactly as the
    # unaccelerated runner does. Fewer than two live lines: nothing to run in parallel, no sweep.
    # ONE LIVE LINE IS NOW WORTH A SWEEP. It was not, when only live lines were swept: one line and
    # one box is the serial runner with extra steps. With chained pre-proofs a single live line is the
    # ROOT of every chain behind it, and the sweep has as many boxes' worth of work as the queue is deep.
    if [ "$(lq_live_lines "$Q")" -lt 1 ]; then lq_log "pre-prove: no live line to sweep or chain from; sweep skipped"
    else [ "${LANDQ_NO_PREPROVE:-}" = 1 ] || lq_preprove_sweep; fi
    B="$(lq_batch_size "$tip")"
    n="$(lq_pop "$tip" "$B" "$batch" "$keep")"
  fi
  # THE REWRITE, ONCE, GUARDED (see lq_queue_rewrite): only when this loop actually changed the
  # queue, and only if the file is still the one that was read. A refusal drops THIS RUNNER'S loop,
  # never the edit — the batch is thrown away unlanded and the pop is taken again next loop.
  lq_queue_rewrite "$keep" "$qstamp" >"$W/target/gate/landq4-qrw.$$.txt" 2>&1; qrc=$?
  lq_qunlock
  while IFS= read -r s; do [ -n "$s" ] && lq_log "$s"; done <"$W/target/gate/landq4-qrw.$$.txt"
  rm -f "$W/target/gate/landq4-qrw.$$.txt"
  if [ "$qrc" = 2 ]; then
    # DIRECT EDIT (see lq_page and lq_queue_reconcile). The edit stands, and so does the pop: the
    # popped lines are taken out of the queue AS IT NOW READS rather than the whole loop being
    # thrown away. landq-ctl is the only tool that should be writing this file, so this is an error
    # worth paging about — and it is never a reason to drop a pop.
    lq_page direct-edit "land-queue.txt was written by somebody other than the runner; landq-ctl is the only tool that should write it"
    if lq_qlock 60; then
      lq_log "queue: DIRECT EDIT — re-read; $(lq_queue_reconcile "$batch" "$Q") popped line(s) removed from the queue as it now stands; the edit stands and the pop stands"
      lq_qunlock
    else
      lq_log "queue: DIRECT EDIT — and the lock did not come free, so this loop's batch is dropped and re-popped next loop; nothing is lost"
      rm -f "$batch" "$batch.chain"; sleep 60; continue
    fi
  fi
  # THE QUEUE JUST CHANGED — the inbox was folded, holds were released, lines were popped or parked
  # — and a status file still showing the counts from before the fold is a status file that is wrong
  # for the whole minute an integrator is most likely to be reading it (they have just typed a
  # command). Written here, under nobody's lock, before the batch or the idle sleep.
  lq_status_json
  if [ "${n:-0}" -eq 0 ]; then
    rm -f "$batch" "$batch.chain"; try_push; sleep 60; continue
  fi

  lq_log "=== $(date +%H:%M:%S) batch of $n line(s) (size $B), head: $(lq_batch_lines "$batch" | head -n1 | cut -c1-100)"
  rm -f "$batch.result"
  # The staged engine (see lq_stage_engine): a landing can change land.sh without changing the copy
  # that is landing it.
  lq_stage_engine
  # WHAT THIS UNION MAY INHERIT FROM ITS MEMBERS' PRE-PROOFS (see lq_preproof_index and land.sh's
  # land_preproof_inherits). Written BEFORE the batch is launched, because land.sh reads it as it
  # plans; a batch with no green member at this tip gets an empty index and the full proof.
  ninh="$(lq_preproof_index "$batch" "$tip" "$W")"
  export LAND_PREPROOF_INDEX="$batch.preproofs"
  lq_log "union: ${ninh:-0} member(s) of this batch were pre-proven GREEN at $(printf '%.9s' "$tip"); their logs are offered to the union proof"
  # THE OVERLAP (see lq_predict_tip): the tree this batch will make is built HERE, before the batch
  # is launched — the batch is about to move HEAD, and the prediction is of THIS tip plus these picks.
  predicted=""; predtree=""
  if [ "${LANDQ_NO_OVERLAP:-}" != 1 ]; then
    read -r predicted predtree <<<"$(lq_predict_tip "$W" "$batch")"
  fi
  # THE FULL PROOF, OVER THE UNION, ALWAYS. A pre-proof chose which lines are here; it is not any
  # part of the verdict on them.
  #
  # BACKGROUNDED, so the next sweep runs while the box proves. It is the same foreground wait either
  # way — `wait` is what `rc` is read from — but between the launch and the wait the runner has the
  # idle boxes and a tip to spend them on.
  # THE BATCH'S OWN SEGMENT OF THE LOG. The landing streams into $L as it always has (an operator
  # tails it); the byte offset is remembered here so the segment this batch wrote can be cut out
  # afterwards and read as the measurement of the tip it produced. No redirection changes: a pipe
  # into `tee` would make `wait` read TEE's exit status and every batch would be green.
  lq_l0="$(wc -c <"$L" 2>/dev/null || echo 0)"; case "$lq_l0" in ''|*[!0-9]*) lq_l0=0 ;; esac
  bstart="$(date +%s)"
  bash "$W/target/gate/land.run.sh" --batch "$batch" >>"$L" 2>&1 &
  bpid=$!
  # THE STATE CHANGED: a batch is on a box now, and the status file says which lines and since when.
  lq_status_json "$batch" "$bstart"
  if [ -n "$predicted" ]; then
    lq_log "overlap: pre-proving the next disjoint lines against the PREDICTED tip $(printf '%.9s' "$predicted") (tree $(printf '%.9s' "$predtree")) while the batch proves"
    # IN A SUBSHELL, AND THAT IS THE WHOLE OF WHY. lq_preprove_sweep ends with a bare `wait`, which
    # in THIS shell would also reap the backgrounded batch — and `wait "$bpid"` on an already-reaped
    # job is "pid N is not a child of this shell", rc 127. The batch's own verdict would have been
    # thrown away and every batch read as red. A subshell's bare `wait` waits for its own children
    # only; everything the sweep produces is files, so it loses nothing by running in one.
    ( lq_preprove_sweep "$LQ_PREDICT" "$predicted" "$batch" )
  else
    lq_log "overlap: no prediction for this batch (a pick does not apply cleanly onto this tip); no overlapped sweep"
  fi
  wait "$bpid"
  rc=$?

  # THE LANDING LINES, NOT THE FILE'S LINES: a batch file carries `#UNIT <k>` markers now, and
  # land.sh writes one outcome per LANDING line (see lq_batch_lines).
  tail -c +"$((lq_l0 + 1))" "$L" >"$batch.log" 2>/dev/null || : >"$batch.log"
  # WHICH LEGS THE UNION DID NOT PAY FOR, AND WHOSE PRE-PROOF PAID INSTEAD. In the ledger, beside
  # the batch, so a green union with a shorter plan than the last one says why without anybody
  # opening a 40 MB log on a fleet box's copy-back.
  if [ -s "$batch.inherited" ]; then
    while IFS="$TAB" read -r ileg ilog; do
      [ -n "$ileg" ] || continue
      lq_log "union: $ileg was NOT re-run — inherited from the pre-proof log $ilog (green there on the same owing file set, at this tip)"
    done <"$batch.inherited"
  else
    lq_log "union: no leg inherited; the union paid for everything its file set owes"
  fi
  want="$(lq_batch_lines "$batch" | grep -c . || true)"
  got="$(grep -c . "$batch.result" 2>/dev/null || true)"
  if [ "${got:-0}" != "${want:-0}" ]; then
    lq_qlock 60 || lq_log "queue: requeueing without the lock (it did not come free); the queue may have been edited"
    # LINES REQUEUED UNCHANGED — and for a chained line "unchanged" is the HELD line it was
    # popped from, not the payload the batch file carried. A payload put back bare is a line that
    # was never un-held going live with its predecessor still unlanded.
    awk -F"$TAB" -v cf="$batch.chain" \
      'BEGIN { while ((getline l < cf) > 0) { n = split(l, a, "\t"); if (n >= 2) m[a[1]] = a[2] } }
       /^[[:space:]]*(#|$)/ { next }
       { print (($0 in m) ? m[$0] : $0) }' "$batch" >"$batch.requeue"
    cat "$batch.requeue" "$Q" >"$Q.tmp" && mv "$Q.tmp" "$Q"; rm -f "$batch.requeue"; lq_qunlock
    # NOT A HALT (see THE FAULT TAXONOMY). A batch that came back with no per-line outcomes learned
    # NOTHING about its lines: land.sh writes one outcome row per landing line before it writes
    # anything else, so an empty result file is a statement about the transport and never about the
    # picks. The lines are back on the queue unchanged and LIVE, the class is read out of the
    # batch's own log, and the loop is taken again after the class's backoff — 1, 2, 4, 8, 15
    # minutes — with the counter in the status file. Five of the fifteen HALTs measured 09-09..09-11
    # were exactly this, each costing every minute until a human restarted the runner by hand.
    fcls="$(lq_batch_fault_class "$rc" "$batch.log")"
    fmsg="land.sh --batch left ${got:-0} of ${want:-0} per-line outcomes (rc $rc)"
    fn="$(lq_fault_record "$fcls" "$fmsg")"
    fwait="$(lq_backoff_secs "$fn")"
    # A FLEET THAT IS ASLEEP IS FIXED, NOT WAITED FOR (see lq_fault_wake).
    case "$fcls" in box-stopped|probe-empty) lq_fault_wake 1 "$W" ;; esac
    lq_log "=== $(lq_fault_verdict "$fcls"): $fmsg; ${want:-0} line(s) requeued unchanged and still LIVE — nothing parked, nothing red"
    lq_log "=== backoff: this is fault $fn of class $fcls in a row; the batch is re-taken in $((fwait / 60)) min"
    echo "$(lq_fault_verdict "$fcls") no-result $(date +%FT%T)" >>"$D"
    git -C "$W" cherry-pick --abort 2>/dev/null
    rm -f "$batch" "$batch.chain"
    lq_status_json
    sleep "$fwait"; continue
  fi
  # THE BATCH CAME BACK WITH OUTCOMES IN IT, so the transport works and every class's run of faults
  # is over: the next one starts at a minute again.
  lq_fault_clear

  red="$W/target/gate/landq4-red.$$.txt"; : >"$red"
  head_conflict=0; first=1; ngreen=0; nred=0; nheld=0; nnone=0
  while IFS="$TAB" read -r st text; do
    [ -n "$st" ] || continue
    case "$st" in
      GREEN) ngreen=$((ngreen + 1)) ;;
      # HELD — a line INSIDE A UNIT that stands after the culprit its prefix bisect found. Its
      # predecessor did not land, so its picks were never proven and never applied: it is not a red,
      # it is the held line it was an hour ago. lq_park_line writes back the `#HOLD-after-<sha>` line
      # it was popped from (its predecessor is not GREEN in this result, by construction) and drops
      # its chained verdict. Never parked as red, never orphaned live.
      HELD) nheld=$((nheld + 1)); lq_park_line "$text" "$batch" "$red" HELD ;;
      RED-CONFLICT) nred=$((nred + 1)); lq_park_line "$text" "$batch" "$red"
                    [ "$first" = 1 ] && head_conflict=1 ;;
      # AN ORACLE RED AT A TIP NOBODY MEASURED IS NOT THE LINE'S (see lq_red_is_unmeasured_oracle):
      # it goes back LIVE and to the front of the next sweep, which now reserves the base replay's
      # box before it dispatches anything — so the next judgement has the evidence this one lacked.
      *) if lq_red_is_unmeasured_oracle "$tip" "$batch.log"; then
           nnone=$((nnone + 1))
           lq_fault_record base-unmeasured "an oracle red at $(printf '%.9s' "$tip"), a tip no base replay has measured" >/dev/null
           lq_front_add "$text"
           printf '%s\n' "$text" >>"$red"
           lq_log "=== $(lq_fault_verdict base-unmeasured): $(printf '%.80s' "$text") went red on ORACLE rows at a tip nobody has measured; requeued LIVE and unchanged, to the front of the next sweep — never parked"
         else
           nred=$((nred + 1)); lq_park_line "$text" "$batch" "$red"
         fi ;;
    esac
    first=0
  done <"$batch.result"
  # Read UNDER the lock and written back at once: there is no read→rewrite window to lose an edit
  # in, and a red line is never dropped for want of a lock.
  [ -s "$red" ] && {
    lq_qlock 60 || lq_log "queue: parking reds without the lock (it did not come free)"
    cat "$red" "$Q" >"$Q.tmp" && mv "$Q.tmp" "$Q"; lq_qunlock; }
  # THE PRE-PROVE LEDGER IS DROPPED WHEN THE TIP MOVES. Every row is keyed by the tip it was taken
  # on and would be ignored anyway; deleting them keeps the file from becoming a history nobody
  # reads and keeps `lq_batch_size` honest about what is CURRENT.
  newtip="$(git -C "$W" rev-parse HEAD)"
  # THE CHAINED ROWS TAKEN OVER EXACTLY THESE PICKS ARE ROWS ABOUT THE TREE THAT JUST LANDED
  # (see lq_chain_rekey). They become ordinary greens at the new tip, and the lines they speak for
  # pop in the very next batch with no sweep at all — which is the arithmetic this change is for.
  chrk="$(lq_chain_rekey "$tip" "$newtip" "$batch" "$batch.result")"
  [ "${chrk:-0}" = 0 ] || lq_log "chained: $chrk pre-proof(s) were taken over exactly these picks; re-keyed to $(git -C "$W" rev-parse --short HEAD) — those lines need no sweep"
  # ...EXCEPT THE ROWS TAKEN AGAINST THE PREDICTION OF THIS VERY MOVE (see lq_preproof_rekey). The
  # landed TREE is compared with the predicted tree — `cherry-pick -x` changes the commit and not the
  # tree — and equal means those rows are rows about the tree that is now HEAD.
  if [ -n "$predicted" ]; then
    if lq_preproof_rekey "$predicted" "$predtree" "$newtip" "$W"; then
      lq_log "overlap: the landed tree IS the predicted tree; the overlapped pre-proofs stand at $(git -C "$W" rev-parse --short HEAD) — no second sweep"
    else
      lq_log "overlap: the landed tree is NOT the predicted tree (a bisect, or something else landed); the overlapped pre-proofs are dropped"
    fi
  fi
  # A CHAINED ROW KEYS BY `<tip>@<predecessor picks>`, so the prune matches that prefix too — and
  # a row taken at the OLD tip goes whichever shape it has: a chained green is evidence about the
  # tree it was taken on, and the tip moving is exactly what makes it not evidence any more.
  [ "$newtip" = "$tip" ] || { awk -F"$TAB" -v tip="$newtip" '$2 == tip || index($2, tip "@") == 1' "$PP" >"$PP.tmp" 2>/dev/null; mv "$PP.tmp" "$PP"; }
  # THE LANDED PROOF IS THE NEXT SWEEP'S MEASUREMENT OF THE BASE (see lq_base_red_learn). Only a
  # batch that was WHOLLY green counts: a batch with a red line in it recorded the oracle over a
  # tree carrying that line's picks, and the rows it failed on may be the picks'. The tip moved, so
  # every other tip's rows go with the pre-proof ledger's.
  [ "$newtip" = "$tip" ] || lq_base_red_prune "$newtip"
  if [ "$newtip" != "$tip" ] && [ "${nred:-0}" = 0 ] && [ "${nheld:-0}" = 0 ] && [ "${nnone:-0}" = 0 ] && [ -s "$batch.log" ]; then
    lq_base_red_learn "$newtip" "$batch.log" \
      && lq_base_red_result "$newtip" "$batch.log" "$batch.base-detail" || true
  fi
  printf '%s\n' "$newtip" >"$TIPF"   # the last landed tip, which the next census checks HEAD against
  lq_boundary "$newtip"              # A BATCH ENDED HERE (see lq_boundary): the supervisor may adopt
  lq_log "=== $(date +%H:%M:%S) batch done: $ngreen green, $nred parked as #RED, $nheld back to HELD, $nnone requeued live as NONE; tip $(git -C "$W" rev-parse --short HEAD)"
  rm -f "$batch" "$batch.chain" "$red"
  lq_status_json

  if [ "$head_conflict" = 1 ]; then
    consec_head_conflict=$((consec_head_conflict + 1))
    if [ "$consec_head_conflict" -ge 2 ]; then
      lq_log "=== HALT: the first queue line conflicted twice in a row; it needs re-picking by hand"
      lq_page halt-head-conflict-twice "the first queue line conflicted twice in a row; it needs re-picking by hand"
      echo "HALT head-conflict-twice $(date +%FT%T)" >>"$D"
      lq_status_json
      exit 1
    fi
  else
    consec_head_conflict=0
  fi

  try_push
done
