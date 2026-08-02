#!/usr/bin/env bash
# The targeted loom model of the config-mutation swap invariant
# (crates/busbar/src/admin/v1/json/tests/txn_loom.rs). Loom explores thread interleavings
# exhaustively, so it is SLOW and deliberately NOT part of `cargo test --workspace`: the module sits
# behind the optional `loom-model` feature and only this script turns it on.
set -euo pipefail
cd "$(dirname "$0")/.."
# --release: debug-build frames under loom's instrumentation overflowed the coroutine stack on the
# Linux CI runner even at 512 MiB (instant overflow, not search exhaustion) -- release-mode frame
# sizes are the lever that actually changes the depth profile, and the exhaustive interleaving
# search runs much faster optimized anyway. Coroutine stack size itself is set in txn_loom.rs
# (loom::thread::Builder::stack_size, in 8-byte WORDS) -- loom's generator-backed coroutines never
# read RUST_MIN_STACK at all, so an env var here can't reach the actual mechanism.
LOOM_MAX_PREEMPTIONS="${LOOM_MAX_PREEMPTIONS:-3}" \
  cargo test --release -p busbar --bin busbar --features loom-model txn_loom -- --nocapture "$@"
