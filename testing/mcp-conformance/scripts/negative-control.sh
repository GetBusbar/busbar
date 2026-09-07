#!/usr/bin/env bash
# NEGATIVE CONTROL: prove the battery actually catches defects.
#
# A battery that only ever runs against a good implementation tells you nothing
# about its own sensitivity. This runs it against deliberately broken fake
# servers and shows which test catches which defect.
#
# IT NOW ASSERTS, AND THAT IS THE POINT OF THIS FILE.
#
# The header used to say "if a row here goes green, the corresponding test has
# stopped working" -- and then printed a table and exited 0 whatever the table
# said. `set -uo pipefail` with no `-e`, the battery's exit code captured into
# `$(...)` and discarded, and `printf` as the last command: this script could
# not fail. Its own claim to be a sensitivity proof was a claim a human had to
# verify by reading, every time, and the only machine that ever read it was one
# step in `.github/workflows/mcp-conformance.yml`. So the documented local
# invocation in README.md, and any second caller, inherited a permanently green
# sensitivity proof -- an instrument that reports PASS over a battery that has
# stopped being able to fail.
#
# THE CLAIM IS MADE PER MODE, BY NAME, IN BOTH DIRECTIONS. For each deliberately
# broken peer there is a NAMED test that must FAIL against it; and the HONEST
# peer must produce no failure at all. A battery that always passes and a
# battery that always fails are equally useless, and only the pair can tell them
# apart. This is the same shape the sibling A2A workflow's `PAIRS` map already
# imposes on its own negative control.
set -uo pipefail
cd "$(dirname "$0")/.."
NODE="$(command -v node)"

# mode -> the test that exists to catch the defect that mode injects.
# `honest` is the positive control and names no catcher: nothing may fail.
MODES=(
  "honest:"
  "no-resulttype:SRV.TOOLS.LIST-SHAPE"
  "noise-on-stdout:SRV.STDIO.STDOUT-IS-CLEAN"
  "retired-code:SRV.ERR.NO-RETIRED-CODES"
  "bad-icon:HOSTILE.ICON-SCHEME-SAFETY"
  "no-cache-hints:SRV.CACHE.HINTS-ON-CACHEABLE-RESULTS"
  "sub-no-ack:CONC.SUBSCRIPTION-ACK-FIRST"
)

# A run that executed almost nothing would satisfy "the honest peer had no
# failures" vacuously, which is the false green one level up from the one this
# script exists to refuse. The fake server answers the whole server tier, so
# anything near this floor means the run did not happen.
MIN_EXECUTED=30

bad=0
printf "%-18s %-36s %s\n" "MODE" "VERDICT" "TESTS THAT FAILED"
for entry in "${MODES[@]}"; do
  mode="${entry%%:*}"; want="${entry#*:}"
  OUT=$(MCP_FAKE_MODE="$mode" "$NODE" bin/mcp-battery.mjs run --name "fake-$mode" \
    --server-cmd "$NODE $(pwd)/fakepeer/fake-server.mjs" --tier push,pr --role server 2>&1)
  R=$(echo "$OUT" | grep "^results" | sed 's/results *: //')
  F=$(echo "$OUT" | grep -E "^  (FAIL|ERR )" | sed -E 's/^  (FAIL|ERR ) *\[[^]]*\] *//' | tr '\n' ' ')
  printf "%-18s %-36s %s\n" "$mode" "$R" "$F"

  # The row must have been PRODUCED. A mode whose run printed no `results` line
  # crashed, and a crash that leaves the table blank must not read as "no
  # failures were reported".
  if [ -z "$R" ]; then
    printf '  BAD: %s produced no results line at all. The battery did not run; nothing here is a proof.\n' "$mode" >&2
    printf '%s\n' "$OUT" | tail -20 >&2
    bad=$((bad + 1))
    continue
  fi
  ran=$(printf '%s' "$R" | sed -n 's/^\([0-9][0-9]*\) pass.*/\1/p')
  fails=$(printf '%s' "$R" | sed -n 's/.*, \([0-9][0-9]*\) fail.*/\1/p')
  case "${ran:-x}${fails:-x}" in
    *x*) printf '  BAD: %s: could not read a pass/fail count out of "%s".\n' "$mode" "$R" >&2
         bad=$((bad + 1)); continue ;;
  esac
  if [ "$((ran + fails))" -lt "$MIN_EXECUTED" ]; then
    printf '  BAD: %s decided only %s scenarios, below the floor of %s. A run this small proves nothing about sensitivity.\n' \
      "$mode" "$((ran + fails))" "$MIN_EXECUTED" >&2
    bad=$((bad + 1))
    continue
  fi

  if [ -z "$want" ]; then
    # THE POSITIVE CONTROL. Without it, every RED below is equally consistent
    # with a battery that fails against everything, which detects nothing.
    if [ "$fails" -eq 0 ]; then
      printf '  ok:  honest peer, %s scenarios, no failures\n' "$ran"
    else
      printf '  BAD: the HONEST peer failed %s scenario(s): %s\n' "$fails" "$F" >&2
      printf '       A battery that is red against a correct peer cannot tell a defect from a peer.\n' >&2
      bad=$((bad + 1))
    fi
    continue
  fi

  case " $F " in
    *" $want "*)
      printf '  ok:  %s caught by %s\n' "$mode" "$want" ;;
    *)
      printf '  BAD: %s was NOT caught by %s. That test has stopped working, or the mode has stopped\n' "$mode" "$want" >&2
      printf '       injecting its defect. Either way the battery is now blind to it, and every green\n' >&2
      printf '       it reports over this surface is a green nobody has watched go red.\n' >&2
      bad=$((bad + 1)) ;;
  esac
done

echo
if [ "$bad" -ne 0 ]; then
  printf 'NEGATIVE CONTROL FAILED: %d of %d modes did not behave as declared.\n' "$bad" "${#MODES[@]}" >&2
  exit 1
fi
printf 'negative control: %d modes, each injected defect caught by the test named for it,\n' "$((${#MODES[@]} - 1))"
printf 'and none of them reported against the honest peer.\n'
