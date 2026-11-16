// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::count::CountError;
use busbar_kernel_ledger::cost::{plane_fee_lane, PER_REQUEST, PER_SESSION};

#[test]
fn ledger_request_fees_include_only_legacy_and_named_request_fee_rows() {
    let mut cell = BudgetCell::fresh(0);
    cell.billable_requests = 2;
    cell.accrue(
        &plane_fee_lane("decisions"),
        1,
        &BTreeMap::from([(PER_REQUEST.into(), 3)]),
    );
    cell.accrue(
        &plane_fee_lane("decisions"),
        2,
        &BTreeMap::from([(PER_REQUEST.into(), 4)]),
    );
    cell.accrue(
        &plane_fee_lane("voice"),
        2,
        &BTreeMap::from([(PER_SESSION.into(), 9)]),
    );
    cell.accrue(
        "decisions\u{1f}model",
        2,
        &BTreeMap::from([(PER_REQUEST.into(), 100)]),
    );
    cell.accrue(
        "legacy-model",
        2,
        &BTreeMap::from([(PER_REQUEST.into(), 100)]),
    );
    assert_eq!(billable_request_count(&cell), Ok(9));
}

#[test]
fn ledger_request_fees_refuse_fraction_negative_and_overflow_without_rounding() {
    for (count, error) in [
        (Count::parse("0.5").unwrap(), CountError::NotWhole),
        (Count::from_micros(-1_000_000), CountError::Negative),
        (
            Count::from_integer(i128::from(u64::MAX) + 1).unwrap(),
            CountError::OutOfRange,
        ),
    ] {
        let mut cell = BudgetCell::fresh(0);
        cell.accrue(
            &plane_fee_lane("decisions"),
            0,
            &BTreeMap::from([(PER_REQUEST.into(), 1)]),
        );
        cell.models[0].cur.insert(PER_REQUEST.into(), count);
        assert_eq!(billable_request_count(&cell), Err(error));
    }
    let mut cell = BudgetCell::fresh(0);
    cell.billable_requests = u64::MAX;
    cell.accrue(
        &plane_fee_lane("decisions"),
        0,
        &BTreeMap::from([(PER_REQUEST.into(), 1)]),
    );
    assert_eq!(billable_request_count(&cell), Err(CountError::OutOfRange));
}
