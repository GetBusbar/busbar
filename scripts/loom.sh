#!/usr/bin/env bash
# The targeted loom model of the config-mutation swap invariant
# (crates/busbar/src/admin/v1/json/tests/txn_loom.rs). Loom explores thread interleavings
# exhaustively, so it is SLOW and deliberately NOT part of `cargo test --workspace`: the module sits
# behind the optional `loom-model` feature and only this script turns it on.
set -euo pipefail
cd "$(dirname "$0")/.."
LOOM_MAX_PREEMPTIONS="${LOOM_MAX_PREEMPTIONS:-3}" \
  cargo test -p busbar --bin busbar --features loom-model txn_loom -- --nocapture "$@"
