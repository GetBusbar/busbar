#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE SELF-TEST FOR scripts/pr-queue.sh.
#
# The queue consumer's whole job is deciding WHICH lines become PRs, in WHAT order, and in what
# batches — so the lander itself is replaced by a shim that records its argv and returns whatever
# the case asks for. What is under test is the scheduling and the bookkeeping, never GitHub.
#
# Cases:
#   A  the land.sh flags (--tests/--families/--gate) are accepted, IGNORED, and the ignoring is SAID.
#   B  STOP halts consumption; lines below it are never opened.
#   C  the default is one PR at a time, and that PR is waited on (--wait is passed).
#   D  --parallel 2 batches two DISJOINT lines together (no --wait, the merge queue orders them)
#      and splits two OVERLAPPING lines into separate batches.
#   E  a red landing stops the queue, leaves the rest queued, and writes a RED ledger row.
#   F  the ledger records one row per landing, with the ignored flags named.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
root="$here/.fix/pr-queue-selftest.$$"
trap 'rm -rf "$root"' EXIT
rm -rf "$root"; mkdir -p "$root"

fails=0
ok()  { echo "  ok   — $*"; }
bad() { echo "  BAD  — $*" >&2; fails=$((fails + 1)); }

# ── THE LANDER SHIM ───────────────────────────────────────────────────────────────────────────────
# Records its argv one line per call, and fails for any hash listed in $SHIM_RED.
mkdir -p "$root/bin"
cat >"$root/bin/land-shim.sh" <<'SHIM'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SHIM_LOG"
for h in $*; do
  case " ${SHIM_RED:-} " in *" $h "*) echo "shim: RED on $h" >&2; exit 1 ;; esac
done
exit 0
SHIM
chmod +x "$root/bin/land-shim.sh"
export PR_LAND="$root/bin/land-shim.sh"

# ── THE THROWAWAY REPOSITORY ──────────────────────────────────────────────────────────────────────
# Four commits: two touching `a`, two touching `b` and `c`. That is enough to distinguish "disjoint"
# from "overlapping" without any of it being a judgement call.
wt="$root/wt"
mkdir -p "$root/nohooks"
git init -q -b dev "$wt"
git -C "$wt" config user.email t@example.invalid
git -C "$wt" config user.name  Selftest
git -C "$wt" config core.hooksPath "$root/nohooks"
seed() { printf '%s\n' "$2" >"$wt/$1"; git -C "$wt" add "$1"; git -C "$wt" commit -qm "$3"; git -C "$wt" rev-parse HEAD; }
: >"$wt/.keep"; git -C "$wt" add .keep; git -C "$wt" commit -qm base
A1="$(seed a 1 'touch a')"
B1="$(seed b 1 'touch b')"
C1="$(seed c 1 'touch c')"
A2="$(seed a 2 'touch a again')"

run_queue() { # $1 = queue body, rest = flags
  local body="$1"; shift
  printf '%s\n' "$body" >"$wt/land-queue.txt"
  rm -f "$wt/land-queue.done"
  : >"$SHIM_LOG"
  (cd "$wt" && bash "$here/scripts/pr-queue.sh" "$@") 2>&1
}
export SHIM_LOG="$root/shim.log"; : >"$SHIM_LOG"

# ── CASE A: THE LOCAL PROOF FLAGS ARE ACCEPTED, IGNORED, AND SAID TO BE IGNORED ───────────────────
echo "case A — --tests/--families/--gate are accepted and ignored, out loud"
out="$(run_queue "--tests \"busbar core\" --families 'llm.*' --gate 'rowA|rowB' $A1" --base dev)"; rc=$?
[ "$rc" -eq 0 ] && ok "exit 0" || bad "exited $rc: $out"
case "$out" in *"ignoring the local proof flags"*) ok "says it is ignoring them" ;; *) bad "silently dropped the flags: $out" ;; esac
case "$out" in *"--families"*) ok "names the flags it ignored" ;; *) bad "did not name the ignored flags" ;; esac
grep -q -- '--tests' "$SHIM_LOG" && bad "passed --tests through to the lander" || ok "the lander never sees them"
grep -q "$A1" "$SHIM_LOG" && ok "the hash did reach the lander" || bad "the hash never reached the lander"
# The grammar is a QUOTED argv. Word-splitting `--tests "pkg pkg"` yields the token `pkg"`, which
# the hash branch would happily hand to cherry-pick; only one hash may ever reach the lander here.
[ "$(tr ' ' '\n' <"$SHIM_LOG" | grep -c '^[0-9a-f]\{40\}$')" = "1" ] \
  && ok "a quoted multi-word flag value is not mistaken for a hash" \
  || bad "the quoted --tests value leaked into the hash list"

# ── CASE B: STOP HALTS CONSUMPTION ────────────────────────────────────────────────────────────────
echo "case B — STOP halts consumption"
out="$(run_queue "$A1
STOP
$B1" --base dev)"
grep -q "$A1" "$SHIM_LOG" && ok "the line above STOP landed" || bad "the line above STOP did not land"
grep -q "$B1" "$SHIM_LOG" && bad "a line below STOP landed anyway" || ok "the line below STOP stayed queued"
case "$out" in *"STOP marker honoured"*) ok "says STOP was honoured" ;; *) bad "never mentions STOP" ;; esac

# ── CASE C: ONE AT A TIME, WAITED ON ──────────────────────────────────────────────────────────────
echo "case C — the default is one PR at a time, waited on"
out="$(run_queue "$A1
$B1" --base dev)"
[ "$(grep -c . "$SHIM_LOG")" = "2" ] && ok "two landings, two lander calls" || bad "expected 2 lander calls, got $(grep -c . "$SHIM_LOG")"
[ "$(grep -c -- '--wait' "$SHIM_LOG")" = "2" ] && ok "each solo PR is waited on" || bad "a solo PR was not waited on"

# ── CASE D: --parallel 2 BATCHES DISJOINT LINES AND SPLITS OVERLAPPING ONES ───────────────────────
echo "case D — --parallel 2 batches disjoint lines and splits overlapping ones"
out="$(run_queue "$B1
$C1" --base dev --parallel 2)"
[ "$(grep -c -- '--wait' "$SHIM_LOG")" = "0" ] \
  && ok "a batch of two is not waited on serially (the merge queue orders them)" \
  || bad "a parallel batch was still waited on serially"
[ "$(grep -c . "$SHIM_LOG")" = "2" ] && ok "both disjoint lines were opened" || bad "expected 2 opens"
# b and a-again overlap nothing; a and a-again DO overlap, so they must not share a batch.
out="$(run_queue "$A1
$A2" --base dev --parallel 2)"
[ "$(grep -c -- '--wait' "$SHIM_LOG")" = "2" ] \
  && ok "two lines touching the same file are two batches of one" \
  || bad "overlapping lines were batched together"

# ── CASE E: A RED LANDING STOPS THE QUEUE ─────────────────────────────────────────────────────────
echo "case E — a red landing stops the queue and leaves the rest queued"
SHIM_RED="$A1" out="$(SHIM_RED="$A1" run_queue "$A1
$B1" --base dev)"; rc=$?
[ "$rc" -ne 0 ] && ok "exit non-zero ($rc)" || bad "a red landing reported success"
grep -q "$B1" "$SHIM_LOG" && bad "kept going past the red" || ok "the line after the red stayed queued"
case "$out" in *"STOPPING"*) ok "says it stopped" ;; *) bad "never says it stopped" ;; esac
grep -q "RED" "$wt/land-queue.done" && ok "ledger carries a RED row" || bad "no RED row in the ledger"

# ── CASE F: THE LEDGER ────────────────────────────────────────────────────────────────────────────
echo "case F — the ledger records every landing and what it ignored"
out="$(run_queue "--gate 'rowA' $B1
$C1" --base dev)"
[ "$(grep -c . "$wt/land-queue.done")" = "2" ] && ok "one ledger row per landing" || bad "ledger rows: $(grep -c . "$wt/land-queue.done")"
grep -q "ignored=--gate rowA" "$wt/land-queue.done" && ok "the ledger names the ignored flags" || bad "the ledger does not name the ignored flags"
grep -q "ignored=none" "$wt/land-queue.done" && ok "a line with no flags says none" || bad "no 'ignored=none' row"
grep -q "OPENED" "$wt/land-queue.done" && ok "ledger carries an OPENED row" || bad "no OPENED row"

if [ "$fails" -eq 0 ]; then
  echo "pr-queue-selftest: GREEN — 6 cases; flags ignored aloud, STOP honoured, batching by disjoint files, ledger written"
  exit 0
fi
echo "pr-queue-selftest: RED — $fails assertion(s) failed" >&2
exit 1
