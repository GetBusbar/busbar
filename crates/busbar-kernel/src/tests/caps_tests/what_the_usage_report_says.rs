// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The provenance of a number, and the three questions asked about it.
//!
//! A usage line is a quantity plus where it came from, and the crate answers three questions about
//! the source: did the kernel derive it, did somebody else report it, and is it a floor rather than
//! a count. Those three decide whether a figure wants a companion to be checked against, whether the
//! variance rule has anything to compare, and whether the posting carries the estimate mark onto the
//! disputes report — and each of them was a function nothing called with both answers in mind. A
//! predicate that says yes to everything and one that says no to everything are the same defect from
//! two directions, and neither of them changed a single existing test.
//!
//! The report's own bound is here for the same reason: `MAX_USAGE_LINES` is the size of a fixed
//! record, so the last report that FITS has to be accepted. A ceiling that refused it would drop the
//! final line of the largest unit the node runs, and the only place that shows is a bill.
//!
//! Moved here from `busbar-contract/src/caps/tests/what_the_usage_report_says.rs`: every test in
//! this file mints a token, and a token constructor is spelled only inside the kernel (construction
//! `token-sealed`). The tests in that file that need no token stayed with the contract.

use busbar_contract::caps::*;

fn seal() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

fn line(source: QuantitySource) -> UsageLine {
    UsageLine {
        class: MeterClassId::new("class"),
        quantity: 1,
        source,
        estimated: false,
    }
}
#[test]
fn a_report_hands_back_the_lines_it_was_given() {
    // The lines are what the posting is evidence FOR. A report that handed back an empty slice would
    // settle an amount with nothing on the record saying what it was for, and the settlement itself
    // would look untouched.
    let k = seal();
    let lines = vec![
        UsageLine {
            class: MeterClassId::new("tokens"),
            quantity: 900,
            source: QuantitySource::Locator {
                direction: busbar_contract::ClassDirection::Response,
                ptr: LocatorPtr::new("/usage/total_tokens"),
            },
            estimated: false,
        },
        UsageLine {
            class: MeterClassId::new("seconds"),
            quantity: 12,
            source: QuantitySource::KernelElapsedMono,
            estimated: false,
        },
    ];
    let usage =
        Usage::report(&Grant::<Consumption>::mint(&k), lines.clone()).expect("two lines fit");
    assert_eq!(usage.lines(), &lines[..]);
    assert_eq!(usage.lines().len(), 2);
    assert_eq!(usage.lines()[0].quantity, 900);
    assert_eq!(usage.lines()[1].class, MeterClassId::new("seconds"));
    assert_eq!(usage.total(), 912);
    assert!(!usage.is_estimated());
}

#[test]
fn the_largest_report_the_record_can_hold_is_accepted() {
    // The boundary the bound is written at. `MAX_USAGE_LINES` is the size of the fixed record, so a
    // report of exactly that many lines is the last one that FITS — refusing it would drop the final
    // line of the biggest unit the node runs, and the place that shows is a bill.
    let k = seal();
    let full: Vec<UsageLine> = (0..MAX_USAGE_LINES)
        .map(|_| line(QuantitySource::Count))
        .collect();
    let usage =
        Usage::report(&Grant::<Consumption>::mint(&k), full).expect("exactly the bound fits");
    assert_eq!(usage.lines().len(), MAX_USAGE_LINES);
    assert_eq!(usage.total(), MAX_USAGE_LINES as u64);

    // And one past it does not, in either constructor.
    let over: Vec<UsageLine> = (0..MAX_USAGE_LINES + 1)
        .map(|_| line(QuantitySource::Count))
        .collect();
    assert_eq!(
        Usage::report(&Grant::<Consumption>::mint(&k), over.clone()),
        Err(UsageError::TooManyLines)
    );
    assert_eq!(
        Usage::estimate(&Grant::<Consumption>::mint(&k), over),
        Err(UsageError::TooManyLines),
        "the estimate goes through the same bound rather than around it"
    );
}

#[test]
fn a_cell_counts_the_accruals_it_took_and_starts_at_none() {
    // One of the four numbers the canary balances. A count that started at one would have the
    // canary reporting a settlement missing on every clean run; one that never moved would let a
    // child's spend disappear without the arithmetic noticing.
    let k = seal();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&k);
    let cell = HoldCell::new(Hold::open(&admit, PrincipalId::new("acct-1"), 0));
    assert_eq!(cell.accruals(), 0, "a fresh cell has taken nothing");

    let arrival = cell
        .admit(
            Hold::open(&admit, PrincipalId::new("acct-1"), 1_000),
            &admit,
        )
        .expect("admitted");
    assert_eq!(cell.accruals(), 0, "passing the door is not an accrual");

    let mut children = Vec::new();
    for expected in 1..=3 {
        children.push(
            cell.accrue_child(&PrincipalId::new("acct-1"), 10, &admit)
                .expect("an admitted parent takes a child's spend"),
        );
        assert_eq!(cell.accruals(), expected);
    }

    // A refused accrual is not one the cell took.
    cell.accrue_child(&PrincipalId::new("acct-2"), 10, &admit)
        .expect_err("another principal's child is refused");
    assert_eq!(cell.accruals(), 3);

    let ledger = Grant::<WriteMoney>::mint(&k);
    for child in children {
        let _ = Posted::into_parent(child, &cell, &ledger).expect("the parent is still open");
    }
    let taken = cell
        .take(&Grant::<Exit>::mint(&k))
        .expect("the exit takes it");
    let _ = Posted::settle(
        arrival,
        0,
        &Usage::report(&Grant::<Consumption>::mint(&k), Vec::new()).unwrap(),
        &ledger,
    );
    let _ = Posted::settle(
        taken,
        30,
        &Usage::report(&Grant::<Consumption>::mint(&k), Vec::new()).unwrap(),
        &ledger,
    );
}
