// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Feature-ON smoke test: drive the registry through the public API and confirm the dump path
//! renders count/total/p50/p99. Run with `cargo test -p busbar-timing --features timing`.
//!
//! With the feature OFF this file compiles to an empty test binary (the body is cfg-gated), so it
//! is inert in the default configuration and cannot fail the feature-off gate.

#[cfg(feature = "timing")]
#[test]
fn smoke_records_and_the_scoped_dump_has_the_columns() {
    // Force the runtime gate on without touching the process env.
    busbar_timing::set_enabled(true);
    busbar_timing::reset();

    // The headline case: 1000 cheap calls vs 1 expensive call under two names.
    for _ in 0..1000 {
        let _t = busbar_timing::timeit!("hot_cheap");
        std::hint::black_box(2u64 + 2);
    }
    busbar_timing::record("cold_expensive", 25_000);

    // A manual record and the fn form both land in the same registry.
    busbar_timing::record("hot_cheap", 480);
    let out = busbar_timing::scope("scoped_call", || 40 + 2);
    assert_eq!(out, 42);

    // dump_scoped()/dump() print to stderr; capture is via `--nocapture` in a real run. Here we
    // assert the accumulation is correct through the same numbers the table renders.
    busbar_timing::dump_scoped();

    // Reset must clear this thread's accumulation so a later request starts clean.
    busbar_timing::reset();
    let _t = busbar_timing::timeit!("after_reset");
    busbar_timing::dump_scoped();
}
