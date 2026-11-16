// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The slot cell behind `Instance::{is_live, quarantine, ceilings_us}` (IF §10.4, §11.2 round 14): one state word
//! `(epoch << 32) | st`, quarantine a CAS from `(epoch, LIVE)`, `is_live` one Acquire load, and the ceiling row
//! the watchdog reads.

use std::sync::atomic::Ordering;

use busbar_plugin_abi::host_side::driver::SlotCell;

#[test]
fn a_new_cell_is_live_in_its_epoch_and_no_other() {
    let cell = SlotCell::new(7, &[0; 64]);
    assert!(cell.is_live(7));
    assert!(!cell.is_live(6));
    assert!(!cell.is_live(8));
    assert_eq!(cell.epoch(), 7);
}

#[test]
fn quarantine_takes_effect_once_and_only_in_the_owners_epoch() {
    let cell = SlotCell::new(3, &[0; 64]);
    assert!(!cell.quarantine(2), "a stale epoch changes nothing");
    assert!(cell.is_live(3));
    assert!(cell.quarantine(3), "the owner's epoch quarantines");
    assert!(!cell.is_live(3));
    assert!(!cell.quarantine(3), "already quarantined: nothing to do");
    assert_eq!(cell.epoch(), 3);
}

#[test]
fn the_ceiling_row_is_the_one_alloc_wrote() {
    let mut row = [0u32; 64];
    row[0] = 5_000_000;
    row[61] = 3_600_000_000;
    row[63] = 9;
    let cell = SlotCell::new(1, &row);
    for (i, want) in row.iter().enumerate() {
        assert_eq!(cell.ceilings_us()[i].load(Ordering::Relaxed), *want, "{i}");
    }
}
