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
REPO="${LANDQ_GH_REPO:-GetBusbar/busbar}"
BR="${LANDQ_BRANCH:-integration/oracle-phase0}"
SCRIPTS="${LAND_SH_SRC:-$W/scripts}"

# HOW MANY BOXES THE PRE-PROVE STAGE MAY HOLD AT ONCE. Six leaves the fleet room for the serial
# runner's own box and for whatever an operator is doing by hand.
PREPROVE_LINES="${LANDQ_PREPROVE_LINES:-6}"

export LAND_ORACLE_SHARDS="${LAND_ORACLE_SHARDS:-3}"
export LAND_ORACLE_PORT_BASE="${LAND_ORACLE_PORT_BASE:-50100}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
export XTASK_GATE_CEILING_SECS="${XTASK_GATE_CEILING_SECS:-900}"

TAB="$(printf '\t')"

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
lq_disjoint_lines() { # $1 = max, $2 = queue file, $3 = repo (default $W), $4 = tip (optional)
  local max="$1" qf="$2" repo="${3:-$W}" tip="${4:-}" line files claimed="" n=0 clash f
  if [ -n "$tip" ] && [ -f "$PP" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      files="$(lq_line_files "$line" "$repo")"
      case "$files" in '?'|'') continue ;; esac
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
    clash=0
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      case "$TAB$claimed" in *"$TAB$f$TAB"*) clash=1; break ;; esac
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
    n="$(awk -F"$TAB" -v tip="$tip" '$1 == "GREEN" && $2 == tip {print $4}' "$pp" | sort -u | grep -c . || true)"
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
# THE JOIN DECISION for one candidate against the batch so far. Prints nothing; the exit status is the
# answer, and the caller extends the claimed set only on a yes.
#   $1 = line  $2 = repo  $3 = lines in batch so far  $4 = claimed files (TAB-joined)  $5 = gates already taken (0|1)
#   $6 = batch holds a was-red line (0|1)  $7 = ceiling moves claimed so far ("raise K" / "lower K", TAB-joined)
lq_may_join() {
  local line="$1" repo="$2" nb="$3" claimed="$4" gates="$5" alone="$6" moves="${7:-}" files f m kind key
  [ "$alone" = 0 ] || return 1                         # a red-once line took the whole batch
  if lq_line_was_red "$line"; then [ "$nb" = 0 ] || return 1; fi
  files="$(lq_line_files "$line" "$repo")"
  case "$files" in '?'|'') [ "$nb" = 0 ] || return 1 ;; esac   # unknown shares with nobody
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$TAB$claimed" in *"$TAB$f$TAB"*) return 1 ;; esac
  done <<EOF
$files
EOF
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
lq_stage_engine() {
  mkdir -p "$W/target/gate"
  sed "s|^here=.*|here=\"$W\"|" "$SCRIPTS/land.sh" >"$W/target/gate/land.run.sh"
  sed "s|^REPO=.*|REPO=\"$W\"|" "$SCRIPTS/land-remote.sh" >"$W/target/gate/land-remote.sh"
  cp "$SCRIPTS/ci-remote-lib.sh" "$W/target/gate/ci-remote-lib.sh"
  chmod +x "$W/target/gate/land.run.sh" "$W/target/gate/land-remote.sh"
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE PRE-PROVE SWEEP
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# One box per line, in parallel, each against the CURRENT tip and each publishing nothing. The
# runner's own tree is never touched: `--preprove` makes land.sh reset the box's tree to the base
# it started from, so the tip land-remote.sh brings back is the tip it sent and the fast-forward is
# a no-op. That is the whole safety argument, and it is proven by land.sh's own self-test
# ("pre: the tree did NOT move").
lq_preprove_sweep() {
  local tip; tip="$(git -C "$W" rev-parse HEAD)"
  local lines; lines="$(lq_disjoint_lines "$PREPROVE_LINES" "$Q" "$W" "$tip")"
  [ -n "$lines" ] || { lq_log "pre-prove: no disjoint line to hand out at $(printf '%.9s' "$tip")"; return 0; }
  local dir="$W/target/gate/preprove-$tip"
  mkdir -p "$dir"
  # ONE BOX PER LINE, ALLOCATED BEFORE ANY OF THEM STARTS.
  #
  # `fleet_pick_host` is a read-modify-write of a cursor FILE shared by every agent on this host, so
  # six processes asking at once can be handed the same box — and six pre-proofs queued on one box
  # is the wall clock of six serial landings, which is the opposite of the point. The hosts are
  # therefore picked here, serially, before a single child is launched, and each is named to
  # `land.sh --remote <host>` explicitly rather than left to `auto`.
  lq_stage_engine
  # shellcheck source=scripts/ci-remote-lib.sh
  . "$W/target/gate/ci-remote-lib.sh" 2>/dev/null || {
    lq_log "pre-prove: no ci-remote-lib.sh; the sweep has no transport and is skipped"; return 0; }
  ( remote_wrapper ) || { lq_log "pre-prove: no ssh wrapper for the fleet; sweep skipped"; return 0; }
  local i=0 line hosts="" cand try
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    cand=""; try=0
    while [ "$try" -lt $(( PREPROVE_LINES * 4 )) ]; do
      try=$((try + 1))
      local h; h="$( fleet_pick_host )" || h=""
      [ -n "$h" ] || break
      case " $hosts " in *" $h "*) continue ;; esac
      cand="$h"; hosts="$hosts $h"; break
    done
    [ -n "$cand" ] || { lq_log "pre-prove: out of free boxes; the rest of the sweep waits for the next one"; break; }
    i=$((i + 1))
    local bf="$dir/line-$i.batch"
    printf '%s\n' "$line" >"$bf"
    (
      # `--preprove` AS AN ARGUMENT, not LAND_PREPROVE in the environment. land.sh converts one
      # into the other for a caller who typed the variable, but the argv is what reaches the box —
      # see land.sh's own note — and a sweep whose mode depended on that conversion would be one
      # refactor away from six real landings nobody asked for.
      # THE STAGED ENGINE, whose `here` is this tree (see lq_stage_engine), and WITHOUT the shard
      # fan-out: the sweep's parallelism is across lines, and a fan-out inside each of six pre-proofs
      # would ask the fleet for four boxes apiece.
      env -u LAND_SELFTEST_SHARDS bash "$W/target/gate/land.run.sh" --preprove --remote "$cand" --batch "$bf" \
        >"$dir/line-$i.log" 2>&1
      echo $? >"$dir/line-$i.rc"
    ) &
  done <<EOF
$lines
EOF
  lq_log "pre-prove: $i line(s) out on the fleet against $(printf '%.9s' "$tip")"
  wait

  # RECORD, one row per line, keyed by the tip. A sweep whose box never reported leaves NO row —
  # which reads as NONE, which is "not pre-proven", which is exactly true. A missing verdict is
  # never written down as either colour.
  local j=1
  while [ "$j" -le "$i" ]; do
    local rc; rc="$(cat "$dir/line-$j.rc" 2>/dev/null || true)"
    local text; text="$(head -n1 "$dir/line-$j.batch")"
    if [ -z "$rc" ]; then
      lq_log "pre-prove: line $j never reported; no record written (log: $dir/line-$j.log)"
    elif [ "$rc" = 0 ]; then
      printf 'GREEN%s%s%s%s%s%s\n' "$TAB" "$tip" "$TAB" "$dir/line-$j.log" "$TAB" "$text" >>"$PP"
    else
      printf 'RED%s%s%s%s%s%s\n' "$TAB" "$tip" "$TAB" "$dir/line-$j.log" "$TAB" "$text" >>"$PP"
    fi
    j=$((j + 1))
  done
  lq_log "pre-prove: recorded in $PP"
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
  local tip="$1" b="$2" batch="$3" keep="$4" line st n=0 greens=0 claimed="" gates=0 alone=0 f moves="" m
  : >"$batch"; : >"$keep"
  greens="$(awk -F"$TAB" -v tip="$tip" '$1 == "GREEN" && $2 == tip {print $4}' "$PP" 2>/dev/null | sort -u | grep -c . || true)"
  case "$greens" in ''|*[!0-9]*) greens=0 ;; esac
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*) printf '%s\n' "$line" >>"$keep"; continue ;;
      --*) ;;
      *) printf '#MALFORMED %s\n' "$line" >>"$keep"
         lq_log "queue lint: parked a malformed line: $(printf '%.80s' "$line")"; continue ;;
    esac
    st="$(lq_preproved_status "$tip" "$line")"
    if [ "$st" = RED ]; then
      # PARKED WITH ITS LOG, so the marker names where the evidence is rather than only that there
      # was some. A `#RED-preproof` line is requeued the same way a `#RED` one is.
      local lg; lg="$(awk -F"$TAB" -v tip="$tip" -v t="$line" '$1 == "RED" && $2 == tip && $4 == t {print $3}' "$PP" 2>/dev/null | tail -1)"
      printf '#RED-preproof %s %s\n' "${lg:-no-log}" "$line" >>"$keep"
      lq_log "pre-prove RED at $(printf '%.9s' "$tip"): parked $(printf '%.80s' "$line") (log: ${lg:-none})"
      continue
    fi
    if [ "$greens" -gt 0 ] && [ "$st" != GREEN ]; then
      printf '%s\n' "$line" >>"$keep"; continue
    fi
    if [ "$n" -lt "$b" ] && lq_may_join "$line" "$W" "$n" "$claimed" "$gates" "$alone" "$moves"; then
      printf '%s\n' "$line" >>"$batch"; n=$((n + 1))
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

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# CI-AWARE PUSH — unchanged in substance from the runner this replaces.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
ci_conclusion() { # $1 = sha ; prints: success|failure|cancelled|running|none
  local out
  out="$(gh run list -R "$REPO" --workflow CI --commit "$1" --limit 1 \
        --json status,conclusion --jq '.[0] | "\(.status) \(.conclusion)"' 2>/dev/null)"
  case "$out" in
    "completed success") echo success ;;
    "completed failure"|"completed timed_out") echo failure ;;
    "completed cancelled") echo cancelled ;;
    ""|"null null") echo none ;;
    *) echo running ;;
  esac
}

try_push() {
  local last head c
  last="$(git -C "$W" rev-parse "origin/$BR")"
  head="$(git -C "$W" rev-parse HEAD)"
  [ "$last" = "$head" ] && return 0
  c="$(ci_conclusion "$last")"
  case "$c" in
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
  local root; root="$(mktemp -d "${TMPDIR:-/tmp}/landq4-selftest.XXXXXX")"
  local repo="$root/repo" fails=0
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
  W="$savedW"; D="$savedD"; Q="$savedQ"; PP="$savedPP"; L="$savedL"

  echo "landq4 selftest: the staged engine (the sweep runs the copy whose root is THIS tree)"
  local savedW2="$W" savedS="$SCRIPTS"; W="$root/tree"; SCRIPTS="$root/scratch/scripts"
  mkdir -p "$SCRIPTS" "$W"
  printf '#!/usr/bin/env bash\nhere="$(cd "$(dirname "$0")/.." && pwd)"\necho "here=$here"\n' >"$SCRIPTS/land.sh"
  printf '#!/usr/bin/env bash\nREPO="$(cd "$(dirname "$0")/.." && pwd)"\necho "REPO=$REPO"\n' >"$SCRIPTS/land-remote.sh"
  printf 'rlog() { :; }\n' >"$SCRIPTS/ci-remote-lib.sh"
  lq_stage_engine
  _t "land.run.sh's root is the runner's tree, not the scratch" "here=$W" "$(bash "$W/target/gate/land.run.sh")"
  _t "land-remote.sh's REPO is the runner's tree"               "REPO=$W" "$(bash "$W/target/gate/land-remote.sh")"
  _t "the sweep launches the staged engine"                     1 "$(grep -c 'bash "\$W/target/gate/land.run.sh" --preprove' "$0")"
  _t "the sweep never launches \$SCRIPTS/land.sh"              0 "$(grep -c 'bash "\$SCRIPTS/land.sh" --preprove' "$0")"
  W="$savedW2"; SCRIPTS="$savedS"

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
  Q="$savedQ"; PP="$savedPP"; L="$savedL"; W="$savedW"

  rm -rf "$root"
  if [ "$fails" -eq 0 ]; then
    echo "landq4 selftest: GREEN (file sets, disjoint sweep, tip-keyed ledger, batch ceiling, one-file/one-judge/red-alone, popper)"
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

if [ "${1:-}" = "--preprove-once" ]; then
  lq_preprove_sweep
  exit $?
fi

consec_head_conflict=0
while true; do
  [ -f "$W/target/gate/STOP" ] && { lq_log "STOP marker seen"; exit 0; }

  tip="$(git -C "$W" rev-parse HEAD)"
  # THE SWEEP RUNS FIRST, and its cost is somebody else's cores. It is best-effort by construction:
  # a sweep that reaches no box writes no rows, and the pop below then behaves exactly as the
  # unaccelerated runner does.
  [ "${LANDQ_NO_PREPROVE:-}" = 1 ] || lq_preprove_sweep

  B="$(lq_batch_size "$tip")"
  batch="$W/target/gate/landq4-batch.$$.txt"; keep="$W/target/gate/landq4-keep.$$.txt"
  n="$(lq_pop "$tip" "$B" "$batch" "$keep")"
  if [ "${n:-0}" -eq 0 ]; then
    mv "$keep" "$Q"; rm -f "$batch"; try_push; sleep 60; continue
  fi
  mv "$keep" "$Q"

  lq_log "=== $(date +%H:%M:%S) batch of $n line(s) (size $B), head: $(head -n1 "$batch" | cut -c1-100)"
  rm -f "$batch.result"
  # The staged engine (see lq_stage_engine): a landing can change land.sh without changing the copy
  # that is landing it.
  lq_stage_engine
  # THE FULL PROOF, OVER THE UNION, ALWAYS. A pre-proof chose which lines are here; it is not any
  # part of the verdict on them.
  bash "$W/target/gate/land.run.sh" --batch "$batch" >>"$L" 2>&1
  rc=$?

  want="$(grep -c . "$batch" || true)"
  got="$(grep -c . "$batch.result" 2>/dev/null || true)"
  if [ "${got:-0}" != "${want:-0}" ]; then
    cat "$batch" "$Q" >"$Q.tmp" && mv "$Q.tmp" "$Q"
    lq_log "=== HALT: land.sh --batch left ${got:-0} of ${want:-0} per-line outcomes (rc $rc); lines requeued unchanged"
    echo "HALT no-result $(date +%FT%T)" >>"$D"
    git -C "$W" cherry-pick --abort 2>/dev/null
    rm -f "$batch"; exit 1
  fi

  red="$W/target/gate/landq4-red.$$.txt"; : >"$red"
  head_conflict=0; first=1; ngreen=0; nred=0
  while IFS="$TAB" read -r st text; do
    [ -n "$st" ] || continue
    case "$st" in
      GREEN) ngreen=$((ngreen + 1)) ;;
      RED-CONFLICT) nred=$((nred + 1)); printf '#RED %s\n' "$text" >>"$red"
                    [ "$first" = 1 ] && head_conflict=1 ;;
      *) nred=$((nred + 1)); printf '#RED %s\n' "$text" >>"$red" ;;
    esac
    first=0
  done <"$batch.result"
  [ -s "$red" ] && { cat "$red" "$Q" >"$Q.tmp" && mv "$Q.tmp" "$Q"; }
  # THE PRE-PROVE LEDGER IS DROPPED WHEN THE TIP MOVES. Every row is keyed by the tip it was taken
  # on and would be ignored anyway; deleting them keeps the file from becoming a history nobody
  # reads and keeps `lq_batch_size` honest about what is CURRENT.
  newtip="$(git -C "$W" rev-parse HEAD)"
  [ "$newtip" = "$tip" ] || { awk -F"$TAB" -v tip="$newtip" '$2 == tip' "$PP" >"$PP.tmp" 2>/dev/null; mv "$PP.tmp" "$PP"; }
  lq_log "=== $(date +%H:%M:%S) batch done: $ngreen green, $nred parked as #RED; tip $(git -C "$W" rev-parse --short HEAD)"
  rm -f "$batch" "$red"

  if [ "$head_conflict" = 1 ]; then
    consec_head_conflict=$((consec_head_conflict + 1))
    if [ "$consec_head_conflict" -ge 2 ]; then
      lq_log "=== HALT: the first queue line conflicted twice in a row; it needs re-picking by hand"
      echo "HALT head-conflict-twice $(date +%FT%T)" >>"$D"
      exit 1
    fi
  else
    consec_head_conflict=0
  fi

  try_push
done
