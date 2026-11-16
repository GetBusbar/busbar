// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SECRET-FOREIGN (ABI-MIN3-INTERFACE §14): Handles 0, len+1, 65,535 and another instance's: DENIED, audited
//! `secret_handle_foreign`.
//!
//! W1-L4 (custody, merged): the arm drives the kernel's real `Custody` (the fixture is C-SECRET-CYCLE's). Instance
//! 1 is bound handles 1..=3 and instance 2 handle 7. Custody refuses `ForeignHandle` for 0, len+1 (4), 65,535 and
//! instance 2's handle 7, writes one `HandleForeign` audit row for each, and calls no secret instance. The
//! DENIED a plugin sees is the Need layer's mapping of this one variant (no text, no source name).

use busbar_kernel::custody::{CustodyDenied, SecretCustody};

use crate::c_secret_cycle::{caller, fixture, foreign_rows, ready};

#[test]
fn foreign_and_out_of_range_handles_are_denied_and_audited() {
    let (custody, world) = fixture(&[(1, 1), (1, 2), (1, 3), (2, 7)]);
    let who = caller(1);
    let mut rows = 0;
    for handle in [0u32, 4, 65_535, 7] {
        assert_eq!(
            ready(custody.resolve(&who, handle)).err(),
            Some(CustodyDenied::ForeignHandle),
            "handle {handle}"
        );
        rows += 1;
        assert_eq!(
            foreign_rows(&world),
            rows,
            "one audit row per refusal, handle {handle}"
        );
    }
    // A bound handle still resolves: the refusals poisoned nothing.
    ready(custody.resolve(&who, 1)).expect("a bound handle resolves");
    assert_eq!(foreign_rows(&world), rows);
}
