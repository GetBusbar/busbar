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
  # qa/*.toml IS SHARED OVER FIGURE-ONLY DIFFS here too (see lq_line_qa_rows): a sweep that never
  # let two figure-only lines share a box never reached the eight greens the larger batch waits for.
  local max="$1" qf="$2" repo="${3:-$W}" tip="${4:-}" line files claimed="" n=0 clash f crows=0 myrows
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
# THE JOIN DECISION for one candidate against the batch so far. Prints nothing; the exit status is the
# answer, and the caller extends the claimed set only on a yes.
#   $1 = line  $2 = repo  $3 = lines in batch so far  $4 = claimed files (TAB-joined)  $5 = gates already taken (0|1)
#   $6 = batch holds a was-red line (0|1)  $7 = ceiling moves claimed so far ("raise K" / "lower K", TAB-joined)
#   $8 = batch holds a line with qa row diffs (0|1)  $9 = batch holds a base fix (0|1)
lq_may_join() {
  local line="$1" repo="$2" nb="$3" claimed="$4" gates="$5" alone="$6" moves="${7:-}" brows="${8:-0}" bfix="${9:-0}" files f m kind key myrows
  [ "$alone" = 0 ] || return 1                         # a red-once line took the whole batch
  [ "$bfix" = 0 ] || return 1                          # a base fix took the whole batch
  if lq_line_was_red "$line"; then [ "$nb" = 0 ] || return 1; fi
  # A BASE FIX JOINS NOBODY (see lq_line_is_base_fix): a line that touches only qa/*.toml re-pins
  # what every other line in the batch would be judged against, and lands alone.
  if lq_line_is_base_fix "$line" "$repo"; then [ "$nb" = 0 ] || return 1; fi
  files="$(lq_line_files "$line" "$repo")"
  case "$files" in '?'|'') [ "$nb" = 0 ] || return 1 ;; esac   # unknown shares with nobody
  myrows="$(lq_line_qa_rows "$line" "$repo")"; case "$myrows" in ''|'?') myrows=1 ;; esac
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$TAB$claimed" in *"$TAB$f$TAB"*)
      # qa/*.toml IS SHARED when the diffs on both sides are figure-only (see lq_line_qa_rows).
      case "$f" in qa/*.toml) [ "$myrows" = 0 ] && [ "$brows" = 0 ] && continue ;; esac
      return 1 ;;
    esac
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
  local a="$1" s
  case "$a" in
    *" -lc "*) s="${a#*" -lc "}" ;;
    *" -c "*)  s="${a#*" -c "}" ;;
    *) s="$a" ;;
  esac
  s="${s#\'}"; s="${s#\"}"
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
    if lq_descends "$pid" "$holder" "$list"; then
      printf 'own pid %s (%s)\n' "$pid" "$(printf '%.100s' "$args")"; continue
    fi
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
  local m
  m="$(stat -f %m "$Q" 2>/dev/null || stat -c %Y "$Q" 2>/dev/null || echo 0)"
  printf '%s:%s\n' "$m" "$(cksum <"$Q" 2>/dev/null || echo 0)"
}
lq_qlock() { # $1 = seconds to wait (default 30); 0 when this shell holds the queue lock
  local wait="${1:-30}" i=0 owner
  while ! mkdir "$QLOCK" 2>/dev/null; do
    owner="$(cat "$QLOCK/pid" 2>/dev/null || true)"
    if [ -n "$owner" ] && [ "$owner" != "$$" ] && ! kill -0 "$owner" 2>/dev/null; then
      rm -rf "$QLOCK"           # the holder is dead; a corpse does not hold a queue
    fi
    i=$((i + 1)); [ "$i" -lt "$wait" ] || return 1
    sleep 1
  done
  printf '%s\n' "$$" >"$QLOCK/pid"
  return 0
}
lq_qunlock() { rm -rf "$QLOCK"; }
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
         && git -C "$1" merge-base --is-ancestor "$sha" HEAD 2>/dev/null; then
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
lq_pop_head_alone() { # $1 = batch file out, $2 = keep file out; the head live line alone, all else kept in order; prints the count
  local line first=1
  : >"$1"; : >"$2"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in --*) if [ "$first" = 1 ]; then printf '%s\n' "$line" >>"$1"; first=0; continue; fi ;; esac
    printf '%s\n' "$line" >>"$2"
  done <"$Q"
  echo $((1 - first))
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# WHAT A PRE-PROOF'S EXIT MEANS. GREEN and RED are the colours the ledger records. Two reds are NOT
# a verdict on the line and are recorded as nothing (NONE — "not pre-proven"), so the popper neither
# parks nor prefers them: a red whose log names the BASE ("at the base", "ROSE since the base") is
# `ceiling-rose` judging against a base the head line is about to repair; a red the tree-moved
# guard raised is a race with the tip, and the line is simply queued again.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# BASE-STATE: A RED THAT IS THE BASE'S, NOT THE LINE'S (rule 2c). Two things must both be true, and
# the second is what keeps this from becoming a way to launder any red at all: the log must SAY the
# figures it refused are the base's — "at the base", "ROSE since the base", or the construction
# gate's own words for rows that are red without being on the standing list — AND the tip must
# actually carry raise headers (`[gate.ceiling_raises.…]` in qa/), which is the state the phrase
# describes. On a tip with no raises pending, a red naming the base is just a red.
LQ_BASE_STATE_RE='at the base|ROSE since the base|construction gate rows red that the standing list does not name'
lq_tip_has_raises() { # $1 = tree; 0 when the tip carries ceiling-raise headers
  grep -rqE '^\[gate\.ceiling_raises\.' "$1"/qa 2>/dev/null
}
lq_base_state_red() { # $1 = log path, $2 = tree; 0 when this RED is the base's
  [ -n "${1:-}" ] && [ -f "$1" ] || return 1
  grep -qiE "$LQ_BASE_STATE_RE" "$1" 2>/dev/null || return 1
  lq_tip_has_raises "$2"
}
lq_preproof_verdict() { # $1 = rc ('' = never reported), $2 = log; prints GREEN, RED, or NONE:<why>
  [ -n "$1" ] || { echo "NONE:never-reported"; return 0; }
  [ "$1" = 0 ] && { echo GREEN; return 0; }
  if grep -qiE "$LQ_BASE_STATE_RE" "$2" 2>/dev/null; then echo "NONE:base"; return 0; fi
  if grep -qE 'not a fast-forward of this tree|this tree is NOT moved|tip (has )?moved' "$2" 2>/dev/null; then echo "NONE:moved"; return 0; fi
  echo RED
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
# THE LOCK: ONLY THE RUNNER LANDS. A host-wide file naming this process; land.sh refuses a
# `--remote` landing that is not a pre-proof while a live pid is in it (a slot proves its own branch
# with --preprove). A second runner refuses to start over a live holder; a dead pid is stale and is
# taken over. Everything this runner launches inherits LANDQ_RUNNER_PID and is exempt.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
LOCK="${LANDQ_LOCK:-$HOME/.busbar-landq4.lock}"
lq_lock_acquire() { # $1 = my pid; 0 = held by me now, 1 = a live runner holds it (its pid on stdout)
  local me="$1" pid
  if [ -f "$LOCK" ]; then
    pid="$(head -n1 "$LOCK" 2>/dev/null | tr -d '[:space:]')"
    case "$pid" in ''|*[!0-9]*) pid="" ;; esac
    if [ -n "$pid" ] && [ "$pid" != "$me" ] && kill -0 "$pid" 2>/dev/null; then printf '%s\n' "$pid"; return 1; fi
  fi
  printf '%s\n%s\n' "$me" "$W" >"$LOCK"
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
      # </dev/null: this child is backgrounded while the loop is still READING the list of lines
      # from its heredoc, and a child that inherits that stdin eats the next line — measured: three
      # disjoint lines, two boxes chosen, no "out of free boxes", the third line simply never read.
      env -u LAND_SELFTEST_SHARDS bash "$W/target/gate/land.run.sh" --preprove --remote "$cand" --batch "$bf" \
        >"$dir/line-$i.log" 2>&1 </dev/null
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
    case "$(lq_preproof_verdict "$rc" "$dir/line-$j.log")" in
      GREEN) printf 'GREEN%s%s%s%s%s%s\n' "$TAB" "$tip" "$TAB" "$dir/line-$j.log" "$TAB" "$text" >>"$PP" ;;
      RED)   printf 'RED%s%s%s%s%s%s\n' "$TAB" "$tip" "$TAB" "$dir/line-$j.log" "$TAB" "$text" >>"$PP" ;;
      NONE:never-reported) lq_log "pre-prove: line $j never reported; no record written (log: $dir/line-$j.log)" ;;
      NONE:base)  lq_log "pre-prove: line $j red against the BASE (a ceiling the head repairs); recorded NONE, not parked (log: $dir/line-$j.log)" ;;
      NONE:moved) lq_log "pre-prove: line $j refused by the tree-moved guard; re-queued, not parked (log: $dir/line-$j.log)" ;;
    esac
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
  local tip="$1" b="$2" batch="$3" keep="$4" line st n=0 greens=0 claimed="" gates=0 alone=0 f moves="" m qarows=0 r bfix=0
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
        lq_log "pre-prove RED at $(printf '%.9s' "$tip"): parked $(printf '%.80s' "$line") (log: ${lg:-none})"
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

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# CI-AWARE PUSH — unchanged in substance from the runner this replaces.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# A RUN THAT HAS SAT `queued` FOR AN HOUR IS NOT RUNNING. The tip's CI umbrella (label busbar-xl)
# sat queued from 22:39 because slot-branch proof runs held every busbar-xl runner, and a push
# deferred on "ci still running" would have kept every landing local for as long as that lasted.
# Queued past 60 minutes reads as `none`: there is no verdict to wait for. `in_progress` still waits.
lq_epoch() { # $1 = ISO-8601 UTC stamp (2026-09-10T22:39:00Z); prints epoch seconds, or nothing
  # GNU date takes -d <stamp>; BSD date's -d is something else entirely (it would print NOW).
  if date --version >/dev/null 2>&1; then date -u -d "$1" +%s 2>/dev/null || true
  else date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s 2>/dev/null || true; fi
}
lq_ci_verdict() { # $1 = "<status> <conclusion> <createdAt>" as gh printed it, $2 = now (epoch; default: now)
  local st con created now="${2:-$(date +%s)}" at age
  st="${1%% *}"; con="${1#* }"; con="${con%% *}"; created="${1##* }"
  [ "$created" = "$1" ] && created=""
  case "$st $con" in
    "completed success") echo success ;;
    "completed failure"|"completed timed_out") echo failure ;;
    "completed cancelled") echo cancelled ;;
    " "|"null null") echo none ;;
    "queued "*)
      at="$(lq_epoch "$created")"
      if [ -n "$at" ]; then age=$(( now - at )); [ "$age" -gt 3600 ] && { echo none; return 0; }; fi
      echo running ;;
    *) echo running ;;
  esac
}
ci_conclusion() { # $1 = sha ; prints: success|failure|cancelled|running|none
  local out
  out="$(gh run list -R "$REPO" --workflow CI --commit "$1" --limit 1 \
        --json status,conclusion,createdAt --jq '.[0] | "\(.status) \(.conclusion) \(.createdAt)"' 2>/dev/null)"
  lq_ci_verdict "$out"
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

  _t "the main flow takes the census before the sweep and the pop" 1 "$(grep -c '^  census="\$(lq_census \$\$ "\$W")"' "$0")"
  _t "  ...and refuses on an empty one"        1 "$(grep -c '^    lq_log "=== census: EMPTY' "$0")"

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
  _t "the main flow skips the sweep below two live lines" 1 "$(grep -c '\[ "\$(lq_live_lines "\$Q")" -lt 2 \]' "$0")"

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
  _t "the sweep records through the verdict"   1 "$(grep -c 'case "\$(lq_preproof_verdict "\$rc" "\$dir/line-\$j.log")" in' "$0")"

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
  _t "the sweep launches the staged engine"                     1 "$(grep -c 'bash "\$W/target/gate/land.run.sh" --preprove' "$0")"
  _t "the sweep never launches \$SCRIPTS/land.sh"              0 "$(grep -c 'bash "\$SCRIPTS/land.sh" --preprove' "$0")"
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
  # BOTH HALVES ARE REQUIRED. Without this one the phrase alone would launder any red at all.
  _t "the base phrase alone, with no raises on the tip, is still a red" 1 "$(lq_base_state_red "$bslog" "$repo"; echo $?)"
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
  _t "the main flow releases holds before it reads the head" 1 "$(grep -c '^  lq_release_holds "\$W" | while' "$0")"

  # ── THE QUEUE IS REWRITTEN BY ITS READER, ONLY IF IT MOVED, AND ONLY IF NOBODY ELSE MOVED IT ───
  # The runner used to rewrite land-queue.txt in full from its own snapshot on EVERY loop, unlocked:
  # an integrator's edit inside the read→rewrite window was reverted with no error and no log line,
  # and the runner then idled on a queue that no longer said what its owner had just said. (Audit 14.)
  echo "landq4 selftest: the queue rewrite (only what changed, under a lock, and only if it did not move)"
  local savedQ5="$Q" savedQL="$QLOCK"
  Q="$root/lockq.txt"; QLOCK="$root/lockq.lock"; rm -rf "$QLOCK"
  printf -- '--prove one\n--prove two\n' >"$Q"
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
  # ONE WRITER.
  rm -rf "$QLOCK"
  _t "the queue lock is taken"                 0 "$(lq_qlock 2; echo $?)"
  _t "  ...and a second writer does not get it" 1 "$(lq_qlock 1; echo $?)"
  printf '999999999\n' >"$QLOCK/pid"
  _t "a lock whose holder is dead is taken over" 0 "$(lq_qlock 3; echo $?)"
  lq_qunlock
  _t "unlocking releases it"                   1 "$( [ -d "$QLOCK" ]; echo $?)"
  _t "the main flow takes the lock before it pops" 1 "$(grep -c '^  if ! lq_qlock; then' "$0")"
  _t "  ...drops its OWN loop when the rewrite is refused" 1 "$(grep -c '^  if \[ "\$qrc" = 2 \]; then rm -f "\$batch"; sleep 60; continue; fi' "$0")"
  _t "  ...and never rewrites the queue unconditionally" 0 "$(grep -c '^  mv "\$keep" "\$Q"' "$0")"
  Q="$savedQ5"; QLOCK="$savedQL"
  Q="$savedQ"; W="$savedW"

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
  [ -f "$W/target/gate/STOP" ] && { lq_log "STOP marker seen"; exit 0; }

  tip="$(git -C "$W" rev-parse HEAD)"
  # ONE ENGINE IN THE TREE (see lq_census): strangers are killed and logged, and a tree that is not
  # settled — HEAD is not the last landed tip, or something tracked is modified — refuses the batch.
  TIPF="$W/target/gate/landq4.tip"
  census="$(lq_census $$ "$W")"; census_rc=$?
  printf '%s\n' "$census" | while IFS= read -r s; do [ -n "$s" ] && lq_log "census: $s"; done
  if [ "$census_rc" != 0 ]; then
    lq_log "=== census: EMPTY — not even this runner's own chain is visible; the census is broken, batch REFUSED"
    sleep 60; continue
  fi
  if ! lq_tree_settled "$W" "$TIPF"; then
    lq_log "=== census: batch REFUSED — HEAD $(git -C "$W" rev-parse --short HEAD) is not the last landed tip $(cut -c1-9 "$TIPF") or the tree is modified; nothing popped"
    sleep 60; continue
  fi
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
    if [ "$(lq_live_lines "$Q")" -lt 2 ]; then lq_log "pre-prove: fewer than two live lines; sweep skipped"
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
  if [ "$qrc" = 2 ]; then rm -f "$batch"; sleep 60; continue; fi
  if [ "${n:-0}" -eq 0 ]; then
    rm -f "$batch"; try_push; sleep 60; continue
  fi

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
    lq_qlock 60 || lq_log "queue: requeueing without the lock (it did not come free); the queue may have been edited"
    cat "$batch" "$Q" >"$Q.tmp" && mv "$Q.tmp" "$Q"; lq_qunlock
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
  # Read UNDER the lock and written back at once: there is no read→rewrite window to lose an edit
  # in, and a red line is never dropped for want of a lock.
  [ -s "$red" ] && {
    lq_qlock 60 || lq_log "queue: parking reds without the lock (it did not come free)"
    cat "$red" "$Q" >"$Q.tmp" && mv "$Q.tmp" "$Q"; lq_qunlock; }
  # THE PRE-PROVE LEDGER IS DROPPED WHEN THE TIP MOVES. Every row is keyed by the tip it was taken
  # on and would be ignored anyway; deleting them keeps the file from becoming a history nobody
  # reads and keeps `lq_batch_size` honest about what is CURRENT.
  newtip="$(git -C "$W" rev-parse HEAD)"
  [ "$newtip" = "$tip" ] || { awk -F"$TAB" -v tip="$newtip" '$2 == tip' "$PP" >"$PP.tmp" 2>/dev/null; mv "$PP.tmp" "$PP"; }
  printf '%s\n' "$newtip" >"$TIPF"   # the last landed tip, which the next census checks HEAD against
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
