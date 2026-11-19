// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money join of a native entry's retirement. An admitted entry leaves the Node book only
//! when its checkpoint removal is acknowledged and its whole fee target set has its receipt; and
//! once both hold it DOES leave. Before FEE-DEBT r1 produced the fee receipt the join was held
//! shut by a constant, so every admitted native unit stayed installed for the life of the process
//! and the shutdown drain reported it unresolved at its cut.

use super::MoneyJoin;

/// The defect: an admitted entry holding both receipts must retire.
#[test]
fn an_admitted_entry_with_its_checkpoint_and_fee_receipts_retires() {
    assert!(
        MoneyJoin {
            admitted: true,
            checkpoint_confirmed: true,
            fee_join_complete: true,
        }
        .complete(),
        "an admitted native entry whose checkpoint is confirmed and whose fee receipt is complete \
         was kept installed"
    );
}

/// Neither receipt stands in for the other, and nothing stands in for either.
#[test]
fn an_admitted_entry_missing_either_receipt_stays_installed() {
    for (checkpoint_confirmed, fee_join_complete) in [(false, false), (true, false), (false, true)]
    {
        assert!(
            !MoneyJoin {
                admitted: true,
                checkpoint_confirmed,
                fee_join_complete,
            }
            .complete(),
            "retired with checkpoint_confirmed={checkpoint_confirmed} \
             fee_join_complete={fee_join_complete}"
        );
    }
}

/// An entry refused before admission opened no money: it has no money join to wait for.
#[test]
fn an_entry_that_was_never_admitted_has_no_money_join() {
    assert!(MoneyJoin {
        admitted: false,
        checkpoint_confirmed: false,
        fee_join_complete: false,
    }
    .complete());
}
