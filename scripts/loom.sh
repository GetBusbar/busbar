#!/usr/bin/env bash
# The targeted loom model of the config-mutation swap invariant
# (crates/busbar-core/src/admin/v1/json/tests/txn_loom.rs). Loom explores thread interleavings
# exhaustively, so it is SLOW and deliberately NOT part of `cargo test --workspace`: the module sits
# behind the optional `loom-model` feature and only this script turns it on.
set -euo pipefail
cd "$(dirname "$0")/.."
# --release: the exhaustive interleaving search runs much faster optimized. It was ALSO believed to
# be load-bearing for stack depth -- that claim is now disproven and the comment corrected rather
# than left standing: this model's two bodies, lifted verbatim into a standalone crate, run clean in
# DEBUG at the bare 32 KiB default coroutine stack, on both macOS/arm64 and Linux/arm64, and at
# every size in between up to 512 MiB on Linux. Whatever the old
# note's "instant overflow on the Linux runner" was, it was not this model outgrowing a coroutine
# stack, and it was not something --release fixed; see the LOOM_STACK_WORDS doc comment in
# txn_loom.rs for what the stack_size knob can and cannot reach. Coroutine stack size is set there, in
# 8-byte WORDS -- loom's generator-backed coroutines never read RUST_MIN_STACK at all, so an env
# var here cannot reach the mechanism.
# NO PREEMPTION BOUND BY DEFAULT. This used to pin LOOM_MAX_PREEMPTIONS=3, which is loom's own
# "the search is too big" escape hatch: it stops exploring after N preemptions, so executions past
# that depth are simply never run and a bug living in one of them reads as green. This model does
# not need it. It has two threads of four operations each; the FULL, unbounded search -- every
# interleaving, no depth cut -- completes in well under a second, so the bound bought nothing and
# gave up the tail of the state space. Unset means unbounded (loom's `preemption_bound: None`).
# An explicit LOOM_MAX_PREEMPTIONS in the environment is still honoured, for bisecting a failure
# down to its shallowest interleaving; it is a debugging aid, not the gate's setting.
# BOTH packages, unit targets of each (`--bins --lib`): the txn_loom module lives in
# `admin/v1/json/tests/`, which the core split (step 3.7) moves into `busbar-core`'s lib. A
# selector naming only the bin target would come back GREEN AND EMPTY on the far side of that
# move — the classic vacuous gate — so the selector names both sides of the seam and the count
# floor below refuses a run that executed zero models.
# ── THE COUNT FLOOR ── a filter that matches nothing still exits 0. The loom gate is only a gate
# if at least one model actually ran; sum every harness's "N passed" and refuse zero.
#
# One function, so `--selftest` drives the REAL reader rather than a copy of it. The count is
# scraped out of a test harness's output, which is the fragile half: the day libtest reworks that
# line, or the selector stops matching, this reads 0 — and 0 used to be reachable only through a
# real cargo run, which is why nothing had ever watched it happen.
loom_ran_count() {   # $1 = the captured cargo output
  printf '%s\n' "$1" | sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' | awk '{s+=$1} END {print s+0}'
}

if [ "${1:-}" = "--selftest" ]; then
  fails=0; cases=0
  say() { printf '%s  %s\n' "$1" "$2"; cases=$((cases + 1)); [ "$1" = PASS ] || fails=$((fails + 1)); }
  echo "== loom gate SELF-TEST (the count floor, without paying for an exhaustive search) =="

  # THE VACUOUS RUN. `cargo test <filter>` over a filter that selects nothing exits 0 and prints
  # `test result: ok. 0 passed`. That is the shape this floor exists to refuse, and it is exactly
  # what a renamed module or a moved test target produces.
  vacuous=$'\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 412 filtered out\n'
  [ "$(loom_ran_count "$vacuous")" -eq 0 ] \
    && say PASS "a run that selected no test counts 0 models" \
    || say FAIL "a zero-test run counted $(loom_ran_count "$vacuous")"

  # BOTH HARNESSES. The models live behind a crate split, so the selector names busbar AND
  # busbar-core and the count is the SUM — a floor read off one harness would be met by the side
  # that still carries them while the other silently emptied.
  two=$'test result: ok. 1 passed; 0 failed; 0 ignored\ntest result: ok. 2 passed; 0 failed; 0 ignored\n'
  [ "$(loom_ran_count "$two")" -eq 3 ] \
    && say PASS "the count sums every harness, not just the first" \
    || say FAIL "two harnesses summed to $(loom_ran_count "$two")"

  # A FAILED run must not be read for its count at all; its own status is what stops the gate.
  failed=$'test result: FAILED. 0 passed; 1 failed; 0 ignored\n'
  [ "$(loom_ran_count "$failed")" -eq 0 ] \
    && say PASS "a FAILED harness line is not counted as a model that ran" \
    || say FAIL "a failed run counted $(loom_ran_count "$failed")"

  # And the floor itself: 0 refused, 1 accepted. Without this the two cases above only prove a
  # sed pipeline, not that the gate does anything with what it read.
  [ "$(loom_ran_count "$vacuous")" -lt 1 ] && [ "$(loom_ran_count "$two")" -ge 1 ] \
    && say PASS "the floor refuses 0 and accepts 1 or more" \
    || say FAIL "the floor does not discriminate 0 from 3"

  echo
  [ "$fails" -eq 0 ] && { echo "loom gate selftest: GREEN (${cases} cases)"; exit 0; }
  echo "loom gate selftest: RED (${fails}/${cases} cases failed)"; exit 1
fi

out=$(cargo test --release -p busbar -p busbar-core --bins --lib --features loom-model txn_loom -- --nocapture "$@" 2>&1) && status=0 || status=$?
printf '%s\n' "$out"
[ "$status" -eq 0 ] || exit "$status"

ran=$(loom_ran_count "$out")
if [ "${ran:-0}" -lt 1 ]; then
  echo "loom gate VACUOUS: the txn_loom filter matched ${ran:-0} test(s) across busbar + busbar-core." >&2
  echo "The models moved or were renamed; point this script at their new home. A green run that" >&2
  echo "executed nothing is not a pass." >&2
  exit 1
fi
echo "loom gate: ${ran} interleaving model(s) ran to completion"
