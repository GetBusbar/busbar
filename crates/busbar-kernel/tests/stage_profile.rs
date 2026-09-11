// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STAGE REPORT PROMISES NO ATTRIBUTION THE LOOP DOES NOT MAKE.
//!
//! The profiler's table is the loop's own steps plus the wait inside Route, and an operator reading
//! `BUSBAR_PROFILE` is entitled to read it as "this is where the request's time went". That claim
//! is only true if every row the report ENUMERATES is a row something actually TIMED — the defect
//! this cell exists against is a table with rows nothing fires, which is an operator surface that
//! lies about where the time went by omitting whole steps from the accounting.
//!
//! So: one request through the real loop, with the profiler on, and every declared stage recorded
//! EXACTLY ONCE. Once, not "at least once": a stage timed twice per request is an attribution that
//! double-counts, and a loop that called a step twice would be a defect of its own.
//!
//! It is its own test binary because the profiler is process-global and these assertions are about
//! counts. A cell sharing a binary with the rest of the battery would be counting the battery's
//! requests as well as its own.

mod common;

use busbar_kernel::profile::{self, Stage};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{run_unit, AccrualMeter, Ended, Kernel, Run};

use common::{cell, ctx, Canary, TestUnits};

#[test]
fn every_declared_stage_fires_exactly_once_per_request() {
    profile::set_enabled(true);
    profile::reset();

    let kernel = Kernel::new();
    let units = TestUnits::passing();
    let cell = cell(&kernel);
    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let ended = run_unit(
        &kernel,
        &units,
        &ctx(1),
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    );
    assert!(
        matches!(ended, Ended::Settled { .. }),
        "the request has to reach its end, or the stages it did not reach are unmeasured rather \
         than missing"
    );

    let missing: Vec<&'static str> = Stage::ALL
        .iter()
        .filter(|s| profile::seen(**s) != 1)
        .map(|s| s.name())
        .collect();
    assert!(
        missing.is_empty(),
        "every stage the report enumerates is timed once by the loop; these were not: {missing:?} \
         (counts: {:?})",
        Stage::ALL
            .iter()
            .map(|s| (s.name(), profile::seen(*s)))
            .collect::<Vec<_>>()
    );
}
