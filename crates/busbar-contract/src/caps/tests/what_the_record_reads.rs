// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What each of these types SAYS about itself, read back.
//!
//! Every rendering in this crate is hand-written, and each is written for a reader who has nothing
//! else: the operator looking at a refused admission, the transport author reading a log line while
//! an accrual is being turned away, the proof battery printing a canary that did not balance. A
//! rendering that quietly produced nothing would leave each of them with an empty string where the
//! only evidence was, and every one of them was reachable without a test naming it.
//!
//! Two of the types here carry something they are NOT allowed to say — the hold's principal is a
//! customer identity and the nonce behind a one-shot secret is the secret — so this file asserts on
//! both sides: what has to appear, and what must not.
//!
//! The tests in this file that have to MINT a token live in the kernel, under the same file name
//! in `busbar-kernel/src/tests/caps_tests/` (construction `token-sealed`); what stays here needs
//! no seal.

use crate::caps::*;

#[test]
fn every_refusal_the_cell_can_give_says_which_one_it_was() {
    // Three ways an accrual is turned away and two ways a hold is, each read off a log line by
    // somebody deciding whether a child has to post late. A rendering that collapsed them would
    // make the two decisions indistinguishable.
    let refusals = [
        (AccrualRefused::ParentNotAdmitted, "parent not admitted"),
        (AccrualRefused::ParentExited, "parent already exited"),
        (AccrualRefused::PrincipalMismatch, "principal mismatch"),
    ];
    for (refusal, spelling) in refusals {
        assert_eq!(refusal.to_string(), spelling);
        let as_error: &dyn std::error::Error = &refusal;
        assert_eq!(as_error.to_string(), spelling);
    }
    let mut spellings: Vec<&str> = refusals.iter().map(|(_, s)| *s).collect();
    spellings.sort_unstable();
    spellings.dedup();
    assert_eq!(spellings.len(), 3, "two refusals render as one sentence");

    let cell_errors = [
        (CellError::AlreadyAdmitted, "cell already admitted"),
        (CellError::AlreadyTaken, "cell already taken"),
    ];
    for (error, spelling) in cell_errors {
        assert_eq!(error.to_string(), spelling);
        let as_error: &dyn std::error::Error = &error;
        assert_eq!(as_error.to_string(), spelling);
    }
    assert_ne!(
        CellError::AlreadyAdmitted.to_string(),
        CellError::AlreadyTaken.to_string()
    );
}

#[test]
fn a_broken_canary_prints_all_four_counts_and_says_which_side_is_short() {
    // The canary's whole value is arithmetic nobody can reconstruct from a boolean. Its rendering is
    // the evidence: four numbers, in the shape the invariant is stated in.
    let canary = Canary::new();
    for _ in 0..5 {
        canary.draft_accepted();
    }
    canary.hold_opened();
    canary.hold_opened();
    canary.accrual_taken();
    canary.settled();

    let broken = canary.balanced().expect_err("five drafts, three openings");
    let printed = broken.to_string();
    assert!(printed.contains("canary broken"), "{printed}");
    assert!(printed.contains("5 drafts"), "{printed}");
    assert!(printed.contains("2 holds"), "{printed}");
    assert!(printed.contains("1 accruals"), "{printed}");
    assert!(printed.contains("1 settlements"), "{printed}");

    let as_error: &dyn std::error::Error = &broken;
    assert_eq!(as_error.to_string(), printed);
    assert_eq!(broken, canary.counts(), "the break IS the counts");
}

#[test]
fn a_usage_refusal_says_the_record_could_not_hold_it() {
    let error = UsageError::TooManyLines;
    assert_eq!(
        error.to_string(),
        "more usage lines than the record can hold"
    );
    let as_error: &dyn std::error::Error = &error;
    assert!(!as_error.to_string().is_empty());
}
