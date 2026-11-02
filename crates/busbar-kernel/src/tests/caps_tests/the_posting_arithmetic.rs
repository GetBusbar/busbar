// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::step::MeterClassId;
use busbar_contract::caps::usage::{QuantitySource, UsageLine};
use busbar_contract::caps::*;

fn seal() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

fn nothing_used(k: &KernelSeal) -> Usage {
    Usage::report(&Grant::<Consumption>::mint(k), Vec::new())
        .expect("an empty report is within the bound")
}

fn opened(k: &KernelSeal, who: &str) -> Hold {
    Hold::open(&Grant::<Admittance>::mint(k), PrincipalId::new(who))
}

fn one_line(quantity: u64) -> Vec<UsageLine> {
    vec![UsageLine {
        class: MeterClassId::new("tokens"),
        quantity,
        source: QuantitySource::Count,
        estimated: false,
    }]
}

#[test]
fn a_posting_carries_the_count_its_unit_reported_and_whose_it_is() {
    let k = seal();
    let usage = Usage::report(&Grant::<Consumption>::mint(&k), one_line(1_000))
        .expect("one line is within the bound");
    let posted = Posted::settle(
        opened(&k, "acct-1"),
        1_000,
        &usage,
        &Grant::<WriteMoney>::mint(&k),
    );
    assert_eq!(posted.quantity(), 1_000);
    assert_eq!(posted.principal().as_str(), "acct-1");
    assert!(
        posted.flags().is_clean(),
        "a reported count is believed as reported: {:?}",
        posted.flags()
    );
}

#[test]
fn a_count_the_node_estimated_is_flagged_estimated() {
    let k = seal();
    let usage = Usage::estimate(&Grant::<Consumption>::mint(&k), one_line(40))
        .expect("one line is within the bound");
    let posted = Posted::settle(
        opened(&k, "acct-1"),
        40,
        &usage,
        &Grant::<WriteMoney>::mint(&k),
    );
    assert!(posted.flags().contains(PostingFlags::ESTIMATED));
}

#[test]
fn a_flag_the_ledger_decides_on_is_added_without_clearing_what_the_report_decided() {
    let k = seal();
    let usage = Usage::estimate(&Grant::<Consumption>::mint(&k), one_line(50))
        .expect("one line is within the bound");
    let posted = Posted::settle(
        opened(&k, "acct-1"),
        50,
        &usage,
        &Grant::<WriteMoney>::mint(&k),
    )
    .flagged(PostingFlags::METER_DISPUTED)
    .flagged(PostingFlags::DOWNGRADED);
    assert!(posted.flags().contains(PostingFlags::ESTIMATED));
    assert!(posted.flags().contains(PostingFlags::METER_DISPUTED));
    assert!(posted.flags().contains(PostingFlags::DOWNGRADED));
    assert!(!posted.flags().contains(PostingFlags::LATE_ACCRUAL));
}

#[test]
fn the_live_slot_is_not_displaced_by_a_second_admission() {
    let k = seal();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&k);
    let cell = HoldCell::new(opened(&k, "acct-0"));
    let arrival = cell
        .admit(opened(&k, "acct-1"), &admit)
        .expect("the first admission wins");
    assert_eq!(arrival.principal().as_str(), "acct-0");

    let rejected = cell
        .admit(opened(&k, "acct-2"), &admit)
        .expect_err("a cell takes one admission");
    assert_eq!(rejected.error, CellError::AlreadyAdmitted);
    assert_eq!(rejected.hold.principal().as_str(), "acct-2");

    let live = cell
        .take(&Grant::<Exit>::mint(&k))
        .expect("the cell still holds the admitted hold");
    assert_eq!(
        live.principal().as_str(),
        "acct-1",
        "the live slot was not displaced"
    );

    let ledger = Grant::<WriteMoney>::mint(&k);
    let _ = Posted::settle(arrival, 0, &nothing_used(&k), &ledger);
    let _ = Posted::settle(rejected.hold, 0, &nothing_used(&k), &ledger);
    let _ = Posted::settle(live, 0, &nothing_used(&k), &ledger);
}

#[test]
fn a_child_that_missed_its_parent_is_handed_back_rather_than_posted_against_an_empty_slot() {
    let k = seal();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&k);
    let ledger = Grant::<WriteMoney>::mint(&k);
    let cell = HoldCell::new(opened(&k, "acct-1"));
    let arrival = cell.admit(opened(&k, "acct-1"), &admit).expect("admitted");

    let accrual = cell
        .accrue_child(&PrincipalId::new("acct-1"), &admit)
        .expect("an admitted parent takes a child");
    assert_eq!(cell.accruals(), 1);

    let taken = cell
        .take(&Grant::<Exit>::mint(&k))
        .expect("the parent exits");
    let handed_back = Posted::into_parent(accrual, &cell, &ledger)
        .expect_err("the parent is gone; the child posts late");
    assert_eq!(handed_back.principal().as_str(), "acct-1");

    let late = Posted::settle_late(handed_back, &ledger);
    assert!(late.flags().contains(PostingFlags::LATE_ACCRUAL));
    assert_eq!(late.principal().as_str(), "acct-1");
    let _ = Posted::settle(arrival, 0, &nothing_used(&k), &ledger);
    let _ = Posted::settle(taken, 0, &nothing_used(&k), &ledger);
}

#[test]
fn a_child_of_another_principal_is_refused_and_one_before_admission_too() {
    let k = seal();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&k);
    let cell = HoldCell::new(opened(&k, "acct-1"));
    assert_eq!(
        cell.accrue_child(&PrincipalId::new("acct-1"), &admit)
            .expect_err("the parent has not passed the door"),
        AccrualRefused::ParentNotAdmitted
    );
    let arrival = cell.admit(opened(&k, "acct-1"), &admit).expect("admitted");
    assert_eq!(
        cell.accrue_child(&PrincipalId::new("acct-2"), &admit)
            .expect_err("another principal never runs under this admission"),
        AccrualRefused::PrincipalMismatch
    );
    assert_eq!(cell.accruals(), 0, "a refused accrual is not counted");
    let ledger = Grant::<WriteMoney>::mint(&k);
    let _ = Posted::settle(arrival, 0, &nothing_used(&k), &ledger);
    let taken = cell.take(&Grant::<Exit>::mint(&k)).expect("taken");
    let _ = Posted::settle(taken, 0, &nothing_used(&k), &ledger);
}
