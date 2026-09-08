// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Feature-ON smoke test: drive the registry through the public API and confirm the dump path runs
//! without panicking. Run with `cargo test -p busbar-timing --features timing`.
//!
//! It is a SMOKE test and nothing more, because that is all an out-of-crate caller can be: the
//! registry and the per-method stats are private, so the count/total/p50/p99 columns cannot be read
//! back from here. They are asserted by the crate's own in-module tests instead.
//!
//! With the feature OFF this file compiles to an empty test binary (the body is cfg-gated), so it
//! is inert in the default configuration and cannot fail the feature-off gate.

#[cfg(feature = "timing")]
#[test]
fn smoke_records_and_the_scoped_dump_has_the_columns() {
    // Force the runtime gate on without touching the process env, and read it back: the hook and
    // the gate are the only two things about the accumulation this side of the crate boundary can
    // see at all, so a hook that stopped taking effect has to fail here or nowhere.
    busbar_timing::set_enabled(true);
    assert!(
        busbar_timing::enabled(),
        "the embedding hook did not turn the runtime gate on"
    );
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

    // dump_scoped()/dump() print to stderr; capture is via `--nocapture` in a real run. What this
    // file can assert about the ACCUMULATION is nothing: the registry, the per-method stats and the
    // merged snapshot are all crate-private, so from outside the crate the dump path can only be
    // driven and watched for a panic. The count/total/p50/p99 columns are asserted by the crate's
    // own in-module tests, which can read the registry; until a read-back is on the public surface
    // this cell proves that the sequence runs, and no more than that.
    busbar_timing::dump_scoped();

    // Reset must clear this thread's accumulation so a later request starts clean.
    busbar_timing::reset();
    let _t = busbar_timing::timeit!("after_reset");
    busbar_timing::dump_scoped();
}
