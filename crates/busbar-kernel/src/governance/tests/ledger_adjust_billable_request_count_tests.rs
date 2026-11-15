// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::count::CountError;
use busbar_kernel_ledger::cost::{plane_fee_lane, PER_REQUEST, PER_SESSION};

fn units(class: &str, count: u64) -> BTreeMap<String, u64> {
    let mut units = BTreeMap::new();
    units.insert(class.to_owned(), count);
    units
}

#[test]
fn ledger_request_fees_include_only_legacy_and_named_request_fee_rows() {
    let mut cell = BudgetCell::fresh(0);
    cell.billable_requests = 2;
    cell.accrue(&plane_fee_lane("decisions"), 1, &units(PER_REQUEST, 3));
    cell.accrue(&plane_fee_lane("decisions"), 2, &units(PER_REQUEST, 4));
    cell.accrue(&plane_fee_lane("voice"), 2, &units(PER_SESSION, 9));
    cell.accrue("decisions\u{1f}model", 2, &units(PER_REQUEST, 100));
    cell.accrue("legacy-model", 2, &units(PER_REQUEST, 100));
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
        cell.accrue(&plane_fee_lane("decisions"), 0, &units(PER_REQUEST, 1));
        cell.models[0].cur.insert(PER_REQUEST.into(), count);
        assert_eq!(billable_request_count(&cell), Err(error));
    }
    let mut cell = BudgetCell::fresh(0);
    cell.billable_requests = u64::MAX;
    cell.accrue(&plane_fee_lane("decisions"), 0, &units(PER_REQUEST, 1));
    assert_eq!(billable_request_count(&cell), Err(CountError::OutOfRange));
}
