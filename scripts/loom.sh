#!/usr/bin/env bash
# The targeted loom model of the config-mutation swap invariant
# (crates/busbar/src/admin/v1/json/tests/txn_loom.rs). Loom explores thread interleavings
# exhaustively, so it is SLOW and deliberately NOT part of `cargo test --workspace`: the module sits
# behind the optional `loom-model` feature and only this script turns it on.
set -euo pipefail
cd "$(dirname "$0")/.."
# Loom's exhaustive interleaving exploration builds deep synthetic call stacks; the default thread
# stack (test harness threads, not just main) can overflow on CI runners even when the SAME model
# passes instantly locally (confirmed: this model runs clean in ~0.01s on a dev machine at the
# default size) -- this is loom's own documented failure mode, not a signal about the model itself.
# 64 MiB (loom's own README-recommended floor) was NOT enough on this repo's actual GitHub Actions
# runner (confirmed: still overflowed at 64 MiB in a real CI run) -- CI runners can need
# substantially more headroom than a dev machine for this class of issue. 512 MiB costs nothing
# (it's a virtual reservation, not committed memory) and gives real margin.
RUST_MIN_STACK="${RUST_MIN_STACK:-536870912}" \
LOOM_MAX_PREEMPTIONS="${LOOM_MAX_PREEMPTIONS:-3}" \
  cargo test -p busbar --bin busbar --features loom-model txn_loom -- --nocapture "$@"
