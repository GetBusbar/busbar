// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CANCEL-BILL (ABI-MIN3-INTERFACE §14): Cumulative USAGE and the §12.4 cancel table.
//!
//! W1-K8A: the arm runs on the kernel's own decider (`plane_driver::usage`, IF §12.4) with the facts the
//! driver keeps (`far_end_answered`, `streamed`). Rule 4 (the budget hold released once on its own path)
//! is the driver's release path and is not decided here.

use busbar_contract::caps::ReasonCode;
use busbar_kernel::plane_driver::usage::{bill, Bill, Ending, SessionUsage, CANCEL_RULES};
use busbar_plugin_abi::plane::{UsageRec, SRC_ESTIMATED, SRC_REPORTED};

fn reported(amount: u64) -> UsageRec {
    UsageRec {
        amount,
        scale: 0,
        source: SRC_REPORTED,
    }
}

fn posted(bill: &Bill<'_>) -> Option<Vec<u64>> {
    match bill {
        Bill::Usage(kept) => Some(kept.iter().map(|r| r.amount).collect()),
        Bill::Estimate | Bill::Nothing => None,
    }
}

fn cancel(far_end_answered: bool, streamed: bool) -> Ending {
    Ending::Cancel {
        cause: ReasonCode::ClientGone,
        far_end_answered,
        streamed,
    }
}

#[test]
fn cumulative_usage_and_the_cancel_table() {
    // USAGE answered on three pieces as 10, 25, 40.
    let mut session = SessionUsage::new();
    for amount in [10, 25, 40] {
        session.answer("tokens", reported(amount)).unwrap();
    }
    assert_eq!(
        posted(&bill(Ending::End, &session)),
        Some(vec![40]),
        "end posts 40, not 75"
    );
    assert_eq!(
        posted(&bill(cancel(true, true), &session)),
        Some(vec![40]),
        "client gone after streaming posts 40"
    );
    assert_eq!(
        bill(cancel(false, false), &session),
        Bill::Nothing,
        "cancelled before any upstream head: nothing, and no estimate"
    );
    assert_eq!(
        bill(cancel(true, false), &session),
        Bill::Nothing,
        "cancelled after the head, before a byte reached the client: 0"
    );
    assert_eq!(
        posted(&bill(Ending::Failed, &session)),
        Some(vec![40]),
        "a plane FAULT bills exactly the usage the session accepted (40), once, never an estimate"
    );
    // A report the session refuses is never kept, so it is never billed: the failed session still bills 40.
    assert!(
        session.answer("BAD CLASS", reported(999)).is_err(),
        "a report with an invalid class is refused"
    );
    assert_eq!(
        posted(&bill(Ending::Failed, &session)),
        Some(vec![40]),
        "the refused report adds nothing to what a failed session bills"
    );

    let mut estimated = SessionUsage::new();
    estimated
        .answer(
            "tokens",
            UsageRec {
                amount: 40,
                scale: 0,
                source: SRC_ESTIMATED,
            },
        )
        .unwrap();
    assert_eq!(
        bill(cancel(true, true), &estimated),
        Bill::Nothing,
        "an SRC_ESTIMATED last value on cancel posts nothing"
    );

    // The four rule texts, byte-equal to the 1.5.5 contract module's numbered headings (its plane
    // module's cancel table, `//! N. RULE:`), pinned here so the check outlives that module.
    const PINNED_1_5_5: [&str; 4] = [
        "1. A TRANSLATE-ABORT IS NEVER BILLED:",
        "2. ONLY FAR-END-REPORTED USAGE IS BILLED:",
        "3. A NON-STREAMED PARTIAL BILLS ZERO:",
        "4. THE BUDGET REFUND IS A SEPARATE ACT:",
    ];
    for (n, rule) in CANCEL_RULES.iter().enumerate() {
        assert_eq!(
            format!("{}. {rule}:", n + 1),
            PINNED_1_5_5[n],
            "rule {} differs from the 1.5.5 text",
            n + 1
        );
    }
}
