#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE LANDING QUEUE, CONSUMED THROUGH PULL REQUESTS.
#
# The queue file does not change. It is still one landing per line, in the grammar land.sh taught
# the agents to write, so a queue drafted for the old consumer is consumable by this one without a
# rewrite. What changes is who renders the verdict: land.sh ran a hand-picked subset of the gate on
# the integrator's laptop and printed GREEN; this runs `scripts/pr-land.sh` per line and reads
# GitHub's required contexts. The local proof flags on each line are therefore ACCEPTED AND
# IGNORED, with a note printed per line saying so — silently dropping them would let an operator go
# on believing `--families` was recorded, which is worse than the old behaviour, not better.
#
#   scripts/pr-queue.sh [--queue F] [--base dev] [--parallel N] [--dry-run]
#
# --queue F     the queue file (default: land-queue.txt at the repository root).
# --base B      the branch every PR targets (default: dev).
# --parallel N  open up to N PRs at once, but ONLY over lines whose pick sets touch DISJOINT files.
#               Default is 1: one PR at a time, waited on to green.
# --dry-run     print what would happen; open nothing.
#
# LINE GRAMMAR (unchanged):
#   [--tests "pkg pkg"] [--families 'regex'] [--gate 'rule|rule'] <hash>...
#   # …            a comment
#   STOP           consumption halts HERE. Everything below is left for the next run.
#   (blank)        ignored
#
# WHY DISJOINT FILES IS THE PARALLELISM RULE. Two PRs open at once against the same base are two
# branches cut from the same tip; GitHub's merge queue serialises the merges and re-tests each on
# the updated base, so correctness never depends on this rule. What the rule buys is that the
# SECOND PR does not predictably conflict on rebase after the first merges — the one failure that
# turns a parallel batch into more human work than a serial one. Overlap on even one path and the
# lines go in separate batches.
set -uo pipefail
sdir="$(cd "$(dirname "$0")" && pwd)"
here="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "pr-queue.sh: not inside a git work tree" >&2; exit 2; }
# The lander is a variable so the self-test can put a recording shim in its place; every real run
# uses the one that sits beside this file.
PR_LAND="${PR_LAND:-$sdir/pr-land.sh}"

queue="$here/land-queue.txt"; base="dev"; parallel=1; dry=0
while [ $# -gt 0 ]; do
  case "$1" in
    --queue) queue="$2"; shift 2 ;;
    --base) base="$2"; shift 2 ;;
    --parallel) parallel="$2"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    --selftest) exec bash "$sdir/pr-queue-selftest.sh" ;;
    --help|-h) sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "pr-queue.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -f "$queue" ] || { echo "pr-queue.sh: no queue file at $queue" >&2; exit 2; }
case "$parallel" in ''|*[!0-9]*) echo "pr-queue.sh: --parallel wants a number" >&2; exit 2 ;; esac
[ "$parallel" -ge 1 ] || { echo "pr-queue.sh: --parallel must be >= 1" >&2; exit 2; }

ledger="${queue%.txt}.done"
G="git -C $here"

# ── READ THE QUEUE ────────────────────────────────────────────────────────────────────────────────
# Each surviving line becomes one record: "hashes<TAB>ignored-flags". The flags are kept, not
# discarded, so the note below can name them and the ledger can record that they were ignored.
mkdir -p "$here/.fix"
plan="$here/.fix/pr-queue-plan.$$"
batchf="$here/.fix/pr-queue-batch.$$"
trap 'rm -f "$plan" "$batchf"' EXIT
: >"$plan"; : >"$batchf"

# THE SPLIT IS shlex's, NOT THE SHELL'S. `set -- $line` looked right and was wrong: the documented
# grammar is `--tests "pkg pkg"`, and word-splitting a read line turns that into the three tokens
# `--tests`, `"pkg`, `pkg"` — so `pkg"` fell through to the hash branch and the queue would have
# tried to cherry-pick a package name. A queue line is a quoted argv; it has to be parsed as one.
tokq="$(python3 - "$queue" "$plan" <<'PY'
import shlex, sys
queue, plan = sys.argv[1], sys.argv[2]
IGNORED_WITH_VALUE = {"--tests", "--families", "--gate"}
IGNORED_BARE = {"--prove"}
rows, stopped = [], 0
for lineno, raw in enumerate(open(queue), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if line == "STOP" or line.startswith("STOP "):
        stopped = 1
        break
    toks = shlex.split(line)
    hashes, ignored = [], []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in IGNORED_WITH_VALUE:
            ignored.append("%s %s" % (t, shlex.quote(toks[i + 1]) if i + 1 < len(toks) else ""))
            i += 2
        elif t in IGNORED_BARE:
            ignored.append(t); i += 1
        elif t.startswith("-"):
            sys.exit("pr-queue.sh: line %d: unknown flag %s — refusing to guess" % (lineno, t))
        else:
            hashes.append(t); i += 1
    if not hashes:
        sys.exit("pr-queue.sh: line %d names no hashes: %s" % (lineno, line))
    rows.append("%s\t%s" % (" ".join(hashes), " ".join(ignored)))
open(plan, "w").write("".join(r + "\n" for r in rows))
print("%d %d" % (len(rows), stopped))
PY
)" || exit 2
lines="${tokq%% *}"; stopped="${tokq##* }"
[ "$stopped" = "1" ] || stopped=""

[ "${lines:-0}" -gt 0 ] || { echo "pr-queue.sh: nothing to land (queue empty${stopped:+ above STOP})"; exit 0; }
echo "pr-queue.sh: $lines landing(s) to open onto $base${stopped:+ (STOP marker honoured; the rest is left queued)}"

# ── THE FILE SETS, FOR THE DISJOINTNESS RULE ──────────────────────────────────────────────────────
# `git diff-tree --no-commit-id --name-only -r <hash>` is the paths ONE commit touched. A line's set
# is the union over its hashes. A merge commit in a queue would print nothing under -r without
# -m, so it is refused rather than treated as touching no file — "touches nothing" is exactly the
# answer that would make it disjoint from everything and batch it with anything.
files_of() {
  for h in $1; do
    if [ "$($G rev-list --no-walk --count --merges "$h" 2>/dev/null || echo 0)" != "0" ]; then
      echo "pr-queue.sh: $h is a merge commit; the queue takes non-merge commits only" >&2
      return 1
    fi
    $G diff-tree --no-commit-id --name-only -r "$h" || return 1
  done
}

disjoint() { # $1,$2 newline-separated path sets
  [ -z "$(printf '%s\n' "$1" | sort -u | comm -12 - <(printf '%s\n' "$2" | sort -u))" ]
}

# ── CONSUME ───────────────────────────────────────────────────────────────────────────────────────
# Batches are built greedily in queue order: a line joins the open batch only if its paths are
# disjoint from every line already in it and the batch is under --parallel. Queue ORDER is
# preserved — a line never overtakes the line above it — because the queue's order is the
# integrator's stated intent and a scheduler that reorders it is making a decision nobody wrote.
opened=0; failed=0
batch_files=""; batch_n=0

flush_batch() {
  [ "$batch_n" -gt 0 ] || return 0
  # One PR per line in the batch. With a batch of one the PR is waited on to green; with more, the
  # PRs are opened and GitHub's merge queue orders them, because waiting serially on N PRs is
  # exactly the serialisation --parallel was asked to avoid.
  waitflag="--wait"
  [ "$batch_n" -gt 1 ] && waitflag=""
  rc=0
  while IFS= read -r rec; do
    hashes="${rec%%	*}"; ignored="${rec#*	}"
    [ "$ignored" = "$rec" ] && ignored=""
    [ -z "$ignored" ] || echo "pr-queue.sh: NOTE — ignoring the local proof flags on this line ($ignored). CI judges this landing, not this laptop."
    # shellcheck disable=SC2086  # $hashes and $waitflag are argv fragments by design
    if [ "$dry" = 1 ]; then
      echo "+ $PR_LAND $hashes --base $base $waitflag --dry-run"
      bash "$PR_LAND" $hashes --base "$base" $waitflag --dry-run || true
      opened=$((opened + 1))
    # shellcheck disable=SC2086
    elif bash "$PR_LAND" $hashes --base "$base" $waitflag; then
      opened=$((opened + 1))
      printf '%s\t%s\tOPENED\tbase=%s\tignored=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$hashes" "$base" "${ignored:-none}" >>"$ledger"
    else
      failed=$((failed + 1)); rc=1
      printf '%s\t%s\tRED\tbase=%s\tignored=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$hashes" "$base" "${ignored:-none}" >>"$ledger"
      echo "pr-queue.sh: STOPPING — $hashes did not go green; its PR is left open. The rest stays queued." >&2
      break
    fi
  done <"$batchf"
  : >"$batchf"; batch_files=""; batch_n=0
  return "$rc"
}

while IFS= read -r rec; do
  hashes="${rec%%	*}"
  fset="$(files_of "$hashes")" || { failed=$((failed + 1)); break; }
  if [ "$batch_n" -ge "$parallel" ] || { [ -n "$batch_files" ] && ! disjoint "$fset" "$batch_files"; }; then
    flush_batch || break
  fi
  printf '%s\n' "$rec" >>"$batchf"
  batch_files="${batch_files:+$batch_files
}$fset"
  batch_n=$((batch_n + 1))
done <"$plan"
[ "$failed" -eq 0 ] && { flush_batch || true; }

echo "pr-queue.sh: $opened PR(s) opened, $failed red; ledger: $ledger"
[ "$failed" -eq 0 ] || exit 1
