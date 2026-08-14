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
cargo test --release -p busbar --bin busbar --features loom-model txn_loom -- --nocapture "$@"
