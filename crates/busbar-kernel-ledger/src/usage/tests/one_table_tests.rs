// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settlement table is ONE function, and it is not in this crate.
//!
//! The live table is `busbar_kernel::teller::settle_amount`, reached from the teller's one exit
//! path. This unit used to ship a second table — `settle` over an end kind, with its own flag
//! vocabulary and its own request-slot rule — that nothing in production called. The two disagreed:
//! a completed unit whose settle record was lost and whose destination reported nothing billed the
//! kernel's floor under the dead table and nothing under the live one (item 436). A table nobody
//! calls is a claim about billing that nothing enforces, so the cell below keeps it gone.

/// The usage unit declares and re-exports no settlement table: no end kind, no settle flags, no
/// flag bridge and no request-slot rule of its own.
#[test]
fn the_usage_unit_ships_no_second_settlement_table() {
    let unit = include_str!("../mod.rs");
    for needle in [
        "mod settlement",
        "pub use settlement",
        "UnitEndKind",
        "SettleFlag",
        "posting_flags",
        "requests_settled",
    ] {
        assert!(
            !unit.contains(needle),
            "usage/mod.rs carries `{needle}`: the settlement table is the teller's settle_amount, \
             and a second one here is a billing rule nothing in production runs"
        );
    }
}
