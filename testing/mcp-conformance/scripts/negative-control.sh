#!/usr/bin/env bash
# NEGATIVE CONTROL: prove the battery actually catches defects.
#
# A battery that only ever runs against a good implementation tells you nothing
# about its own sensitivity. This runs it against deliberately broken fake
# servers and shows which test catches which defect. If a row here goes green,
# the corresponding test has stopped working.
#
# THE MODE LIST IS NOT WRITTEN HERE, AND THAT IS THE POINT.
#
# It used to be: seven mode names, typed into the `for` loop below, out of the twenty-four the fake
# server implements. Seventeen named attacks — `stall`, `wrong-id`, `dup-response`, `half-answer`,
# `truncate`, every MRTR mode — had NO negative control at all, so nothing anywhere proved the
# battery still caught them, and a mode added to the peer joined that silent majority by default.
# A hand-written second list of anything drifts from the first the day somebody adds to the first.
#
# So the list is read FROM THE PEER (`fake-server.mjs --list-modes`, which prints the keys of the
# MODE_METHODS table it dispatches on). Adding a mode to the peer adds it here on the same commit.
# `honest` is run like the rest: it is the row that must stay clean, and a red there means the
# harness is failing an honest peer.
set -uo pipefail
cd "$(dirname "$0")/.."
NODE="$(command -v node)"
FAKE="$(pwd)/fakepeer/fake-server.mjs"

# THE DRIFT GUARD. If the peer ever stops answering `--list-modes` — renamed, moved, or the table
# deleted — this script would otherwise iterate an empty list and print a clean, empty table that
# reads exactly like a pass. A negative control that exercises nothing is the defect this whole
# battery exists to catch, one level up.
MODES="$($NODE "$FAKE" --list-modes 2>/dev/null)"
MODE_COUNT="$(printf '%s\n' "$MODES" | grep -c . || true)"
if [ "${MODE_COUNT:-0}" -lt 20 ]; then
  echo "FAIL: the fake peer reported only ${MODE_COUNT:-0} mode(s) via --list-modes." >&2
  echo "      The negative control derives its rows from that table, so it would have exercised" >&2
  echo "      ${MODE_COUNT:-0} attack(s) and printed a table that reads like a pass. Fix the peer's" >&2
  echo "      MODE_METHODS table or its --list-modes handling before believing any row below." >&2
  exit 1
fi

# A per-mode ceiling. `stall` answers nothing and `giant` writes twelve megabytes, so a mode that
# wedges must cost this script one timeout rather than the whole run: a negative control nobody can
# wait out is a negative control nobody runs.
PER_MODE_TIMEOUT="${MCP_NEGCTL_TIMEOUT:-120}"
timeout_cmd=""
command -v timeout >/dev/null 2>&1 && timeout_cmd="timeout $PER_MODE_TIMEOUT"
command -v gtimeout >/dev/null 2>&1 && timeout_cmd="gtimeout $PER_MODE_TIMEOUT"

# MODES A SERVER-ROLE RUN CANNOT CATCH, DECLARED, WITH THE REASON.
#
# Not every attack is visible from every direction. `injection` puts prompt-injection text in a tool
# DESCRIPTION: the bytes are legal MCP and the harm lands on whatever reads the description, so a
# server-role run of the battery has nothing to fail. Recording that here, by name, is the honest
# form: it keeps the row in the table (the mode still runs, and its output is still printed), while
# saying out loud which direction would be needed to catch it.
#
# The list is checked in BOTH directions below. A mode that stops being catchable joins it in a
# commit that says why; a mode listed here that starts being caught fails this script, so the
# allowance cannot outlive the gap it excuses.
UNCATCHABLE_FROM_SERVER_ROLE="injection"

printf "%-18s %-36s %s\n" "MODE" "VERDICT" "TESTS THAT FAILED"
caught=0
wedged=""
blessed=""
stale=""
for mode in $MODES; do
  # shellcheck disable=SC2086
  OUT=$(MCP_FAKE_MODE="$mode" $timeout_cmd "$NODE" bin/mcp-battery.mjs run --name "fake-$mode" \
    --server-cmd "$NODE $FAKE" --tier push,pr --role server 2>&1)
  R=$(echo "$OUT" | grep "^results" | sed 's/results *: //')
  F=$(echo "$OUT" | grep -E "^  (FAIL|ERR )" | sed -E 's/^  (FAIL|ERR ) *\[[^]]*\] *//' | tr '\n' ' ')
  allowed=0
  case " $UNCATCHABLE_FROM_SERVER_ROLE " in *" $mode "*) allowed=1 ;; esac
  if [ -n "$F" ]; then
    caught=$((caught+1))
    [ "$allowed" = 1 ] && stale="$stale $mode"
    [ "$mode" = "honest" ] && blessed="$blessed honest-was-rejected"
  elif [ -z "$R" ]; then
    # No results line at all: the peer wedged the run (it answers nothing, by design, and every
    # scenario waited out its failsafe until the per-mode ceiling fired). That is not a peer being
    # BLESSED -- nothing about it was reported as fine -- but it is also not a caught defect, so it
    # is counted and printed on its own.
    wedged="$wedged $mode"
  elif [ "$mode" != "honest" ] && [ "$allowed" = 0 ]; then
    blessed="$blessed $mode"
  fi
  printf "%-18s %-36s %s\n" "$mode" "${R:-<no verdict: the peer never answered; the run was stopped at ${PER_MODE_TIMEOUT}s>}" "$F"
done

# THE SENSITIVITY FLOOR. Every row above being clean means the battery caught NOTHING while being
# fed two dozen deliberately broken peers, which is the one outcome this script must never report
# as success. It is a floor and not a per-mode expectation on purpose: some modes are aimed at the
# CLIENT direction and are legitimately invisible to a server-role run, and pinning each mode to a
# named test here would be a second list to drift.
echo
echo "modes exercised: $MODE_COUNT   caught: $caught  wedged:${wedged:- none}"
rc=0
if [ -n "$blessed" ]; then
  echo "FAIL: a deliberately BROKEN peer was blessed —$blessed" >&2
  echo "      Every mode is a named attack. A mode that produces no failure and is not declared in" >&2
  echo "      UNCATCHABLE_FROM_SERVER_ROLE means the test that used to catch it has stopped working." >&2
  rc=1
fi
if [ -n "$stale" ]; then
  echo "FAIL: a mode declared uncatchable from the server role WAS caught —$stale" >&2
  echo "      The allowance is now a lie. Delete it: an excuse must not outlive the gap it excuses." >&2
  rc=1
fi
if [ "$caught" -lt 5 ]; then
  echo "FAIL: the battery caught $caught of $MODE_COUNT deliberately broken peers. It is not" >&2
  echo "      sensitive enough to be believed about a subject." >&2
  rc=1
fi
[ "$rc" -eq 0 ] && echo "negative control behaved: $caught of $MODE_COUNT modes caught, honest clean."
exit "$rc"
