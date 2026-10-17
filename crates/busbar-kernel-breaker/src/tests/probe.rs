// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A HEALTH PROBE'S ANSWER reaches every cell of its destination, as 1.5.5's `health.rs`
//! `probe_lane` folded it: a success recovers a tripped destination in the default cell and every
//! pool's; a client fault records nothing; a transient failure is recorded under each pool's own
//! configuration; the prober's trigger reads every cell and creates none.
//!
//! The test here take no token: the prober's trigger reads the cell census, which is the crate's
//! own. The tests that record a probe's answer through the `Pass<Route>`-taking seam run in
//! busbar-kernel (`src/tests/members/breaker/probe_tests.rs`), where minting is the kernel's.

use super::NOW;
use crate::cfg::BreakerCfg;
use crate::{BreakerUnit, DestinationId};

const POOL: &str = "p";

#[test]
fn the_probers_trigger_reads_every_cell_and_creates_none() {
    let unit = BreakerUnit::new();
    let d = DestinationId::new(1);
    assert!(!unit.suppressing(d, NOW));
    assert!(!unit.has_cell("", d));
    // A pool cell alone suppressing is enough.
    unit.cell(POOL, d)
        .open(NOW, &BreakerCfg::default(), None, 0);
    assert!(unit.suppressing(d, NOW));
    assert!(!unit.has_cell("", d));
}
