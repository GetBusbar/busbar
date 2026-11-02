// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    let k = seal();
    let full: Vec<UsageLine> = (0..MAX_USAGE_LINES)
        .map(|_| line(QuantitySource::Count))
        .collect();
    let usage =
        Usage::report(&Grant::<Consumption>::mint(&k), full).expect("exactly the bound fits");
    assert_eq!(usage.lines().len(), MAX_USAGE_LINES);
    assert_eq!(usage.total(), MAX_USAGE_LINES as u64);

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
    let k = seal();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&k);
    let cell = HoldCell::new(Hold::open(&admit, PrincipalId::new("acct-1")));
    assert_eq!(cell.accruals(), 0, "a fresh cell has taken nothing");

    let arrival = cell
        .admit(Hold::open(&admit, PrincipalId::new("acct-1")), &admit)
        .expect("admitted");
    assert_eq!(cell.accruals(), 0, "passing the door is not an accrual");

    let mut children = Vec::new();
    for expected in 1..=3 {
        children.push(
            cell.accrue_child(&PrincipalId::new("acct-1"), &admit)
                .expect("an admitted parent takes a child"),
        );
        assert_eq!(cell.accruals(), expected);
    }

    cell.accrue_child(&PrincipalId::new("acct-2"), &admit)
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
