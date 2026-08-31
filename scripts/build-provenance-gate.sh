#!/usr/bin/env bash
# build-provenance-gate — assert a built busbar binary self-reports the EXPECTED optimization posture.
#
# WHY. The ~20% "regression" incident was a build-config mismatch that no test could see because no
# binary said out loud how it was built. crates/busbar/build.rs now bakes the posture into the binary
# and `busbar --build-info` prints it as one stable line:
#   profile=release opt-level=3 lto=... debug-assertions=false pgo=false target=... target-cpu=...
# This gate parses that line and asserts the fields that a shipped/optimized binary MUST have, so a
# release build that is secretly debug/non-PGO fails CI instead of shipping and being misdiagnosed.
#
# USAGE:
#   build-provenance-gate.sh <binary> <expect-profile> <expect-pgo>   # run the binary, assert
#   build-provenance-gate.sh --line "<stamp line>" <expect-profile> <expect-pgo>   # assert a literal
#   build-provenance-gate.sh --selftest
# <expect-profile> is release|debug; <expect-pgo> is true|false. For a release build the gate also
# pins opt-level=3 and debug-assertions=false (the optimized invariants); a debug build only pins the
# profile/pgo it was told to expect.
#
# `--selftest` proves the assertions go RED on a mis-built stamp before their GREEN is trusted.
set -euo pipefail

field() { printf '%s\n' "$1" | tr ' ' '\n' | awk -F= -v k="$2" '$1==k{print $2; exit}'; }

# Assert one stamp LINE against (expect_profile, expect_pgo). Prints findings; returns 0/1.
assert_line() {
  local line="$1" expect_profile="$2" expect_pgo="$3" fail=0
  local profile opt da pgo
  profile="$(field "$line" profile)"
  opt="$(field "$line" opt-level)"
  da="$(field "$line" debug-assertions)"
  pgo="$(field "$line" pgo)"

  echo "  stamp: $line"

  if [ "$profile" != "$expect_profile" ]; then
    echo "  FAIL: profile = '${profile:-<absent>}' (expect $expect_profile)"; fail=1
  else echo "  ok: profile = $profile"; fi

  if [ "$pgo" != "$expect_pgo" ]; then
    echo "  FAIL: pgo = '${pgo:-<absent>}' (expect $expect_pgo)"; fail=1
  else echo "  ok: pgo = $pgo"; fi

  # Optimized invariants apply only to a release build.
  if [ "$expect_profile" = "release" ]; then
    if [ "$opt" != "3" ]; then
      echo "  FAIL: opt-level = '${opt:-<absent>}' (release must be 3)"; fail=1
    else echo "  ok: opt-level = $opt"; fi
    if [ "$da" != "false" ]; then
      echo "  FAIL: debug-assertions = '${da:-<absent>}' (release must be false)"; fail=1
    else echo "  ok: debug-assertions = $da"; fi
  fi

  return $fail
}

selftest() {
  echo "[selftest] a debug stamp claiming to be a release build must be REJECTED:"
  if assert_line "profile=debug opt-level=0 lto=(profile-table) debug-assertions=true pgo=false target=x target-cpu=default" release false >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted a debug stamp as release"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] a release stamp with debug-assertions=true must be REJECTED:"
  if assert_line "profile=release opt-level=3 lto=fat debug-assertions=true pgo=false target=x target-cpu=default" release false >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted debug-assertions=true in a release build"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] a release stamp with pgo=false must be REJECTED when pgo=true is required:"
  if assert_line "profile=release opt-level=3 lto=fat debug-assertions=false pgo=false target=x target-cpu=default" release true >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted pgo=false when pgo=true required"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] a correct optimized release stamp (pgo=false, dev CI) must be ACCEPTED:"
  if ! assert_line "profile=release opt-level=3 lto=(profile-table) debug-assertions=false pgo=false target=x target-cpu=default" release false >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: rejected a correct release stamp"; return 1
  fi
  echo "  ok: accepted"

  echo "[selftest] a correct PGO release stamp (pgo=true, release job) must be ACCEPTED:"
  if ! assert_line "profile=release opt-level=3 lto=fat debug-assertions=false pgo=true target=x target-cpu=default" release true >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: rejected a correct PGO release stamp"; return 1
  fi
  echo "  ok: accepted"

  echo "[selftest] PASS"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest; exit $?
fi

if [ "${1:-}" = "--line" ]; then
  LINE="$2"; EXPECT_PROFILE="$3"; EXPECT_PGO="$4"
else
  BIN="$1"; EXPECT_PROFILE="$2"; EXPECT_PGO="$3"
  [ -x "$BIN" ] || { echo "build-provenance-gate: '$BIN' is not an executable" >&2; exit 2; }
  LINE="$("$BIN" --build-info)"
fi

echo "== build-provenance-gate: expect profile=$EXPECT_PROFILE pgo=$EXPECT_PGO =="
if assert_line "$LINE" "$EXPECT_PROFILE" "$EXPECT_PGO"; then
  echo "build-provenance-gate: PASS"
else
  echo "build-provenance-gate: FAIL — the binary was NOT built with the expected optimized posture." >&2
  echo "A mis-built binary is exactly the ~20% 'regression' this stamp exists to prevent shipping." >&2
  exit 1
fi
