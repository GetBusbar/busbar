#!/usr/bin/env bash
# The targeted loom model of the config-mutation swap invariant
# (crates/busbar/src/admin/v1/json/tests/txn_loom.rs). Loom explores thread interleavings
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
out=$(cargo test --release -p busbar -p busbar-core --bins --lib --features loom-model txn_loom -- --nocapture "$@" 2>&1) && status=0 || status=$?
printf '%s\n' "$out"
[ "$status" -eq 0 ] || exit "$status"

# ── THE COUNT FLOOR ── a filter that matches nothing still exits 0. The loom gate is only a gate
# if at least one model actually ran; sum every harness's "N passed" and refuse zero.
ran=$(printf '%s\n' "$out" | sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' | awk '{s+=$1} END {print s+0}')
if [ "${ran:-0}" -lt 1 ]; then
  echo "loom gate VACUOUS: the txn_loom filter matched ${ran:-0} test(s) across busbar + busbar-core." >&2
  echo "The models moved or were renamed; point this script at their new home. A green run that" >&2
  echo "executed nothing is not a pass." >&2
  exit 1
fi
echo "loom gate: ${ran} interleaving model(s) ran to completion"
