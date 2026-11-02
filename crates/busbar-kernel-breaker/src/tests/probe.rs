// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A HEALTH PROBE'S ANSWER reaches every cell of its destination, as 1.5.5's `health.rs`

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

    unit.cell(POOL, d)
        .open(NOW, &BreakerCfg::default(), None, 0);
    assert!(unit.suppressing(d, NOW));
    assert!(!unit.has_cell("", d));
}
