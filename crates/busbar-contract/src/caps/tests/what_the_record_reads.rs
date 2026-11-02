// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What each of these types SAYS about itself, read back.

use crate::caps::*;

/// Every way an accrual is turned away, with its rendering. Hand-kept, so the cell below holds it to

const REFUSALS: &[(AccrualRefused, &str)] = &[
    (AccrualRefused::ParentNotAdmitted, "parent not admitted"),
    (AccrualRefused::ParentExited, "parent already exited"),
    (AccrualRefused::PrincipalMismatch, "principal mismatch"),
];

/// Every way the cell refuses a transition, with its rendering. Hand-kept, as above.
const CELL_ERRORS: &[(CellError, &str)] = &[
    (CellError::AlreadyAdmitted, "cell already admitted"),
    (CellError::AlreadyTaken, "cell already taken"),
    (CellError::CallMismatch, "admittance grant of another call"),
];

#[test]
fn every_refusal_the_cell_can_give_says_which_one_it_was() {
    let refusals = REFUSALS;
    for (refusal, spelling) in refusals {
        assert_eq!(refusal.to_string(), *spelling);
        let as_error: &dyn std::error::Error = refusal;
        assert_eq!(as_error.to_string(), *spelling);
    }
    let mut spellings: Vec<&str> = refusals.iter().map(|(_, s)| *s).collect();
    spellings.sort_unstable();
    spellings.dedup();
    assert_eq!(
        spellings.len(),
        REFUSALS.len(),
        "two refusals render as one sentence"
    );

    for (error, spelling) in CELL_ERRORS {
        assert_eq!(error.to_string(), *spelling);
        let as_error: &dyn std::error::Error = error;
        assert_eq!(as_error.to_string(), *spelling);
    }
    let mut cell_spellings: Vec<&str> = CELL_ERRORS.iter().map(|(_, s)| *s).collect();
    cell_spellings.sort_unstable();
    cell_spellings.dedup();
    assert_eq!(
        cell_spellings.len(),
        CELL_ERRORS.len(),
        "two cell errors render as one sentence"
    );
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
