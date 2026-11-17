// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::limits::process_admission::ProcessAdmission;

fn budget(entries: u32, operator: u32) -> std::sync::Arc<ProcessAdmission> {
    let bytes = u32::try_from(Layout::new::<Entry>().size()).unwrap();
    ProcessAdmission::with_limits(
        0,
        bytes.checked_mul(entries).unwrap(),
        bytes.checked_mul(operator).unwrap(),
    )
}

fn book(budget: &std::sync::Arc<ProcessAdmission>) -> TerminalBook {
    TerminalBook::new(
        budget.connection_storage(AdmissionClass::Data),
        budget.connection_storage(AdmissionClass::Operator),
    )
}

fn unit(node: &super::super::Node) -> RetainedUnit {
    RetainedUnit::reserved(node.kernel.next_call())
}

#[test]
fn denial_before_first_backing_preserves_the_original_unit() {
    let node = super::super::Node::new();
    let budget = budget(2, 1);
    let data = budget.connection_storage(AdmissionClass::Data);
    let held = data.try_reserve(Layout::new::<Entry>().size()).unwrap();
    let mut book = book(&budget);
    let original = unit(&node);
    let call = original.call;
    let returned = book
        .insert(AdmissionClass::Data, UnitKey::new(1), original)
        .err()
        .unwrap();
    assert_eq!(returned.call, call);
    assert_eq!(book.len(), 0);
    assert_eq!(book.data.entries.capacity(), 0);
    assert!(book.data.credit.is_none());
    drop(held);
    assert!(book
        .insert(AdmissionClass::Data, UnitKey::new(1), returned)
        .is_ok());
}

#[test]
fn replacement_needs_full_overlap_and_does_not_borrow_operator_reserve() {
    let node = super::super::Node::new();
    let budget = budget(4, 2);
    let mut book = book(&budget);
    let first = unit(&node);
    let call = first.call;
    assert!(book
        .insert(AdmissionClass::Data, UnitKey::new(1), first)
        .is_ok());
    // Two-entry replacement plus the original one-entry allocation exceeds Data's two.
    assert!(book
        .insert(AdmissionClass::Data, UnitKey::new(2), unit(&node))
        .is_err());
    assert_eq!(
        book.get(AdmissionClass::Data, UnitKey::new(1))
            .unwrap()
            .call,
        call
    );
    assert_eq!(book.data.entries.capacity(), 1);
    assert_eq!(
        book.data.credit.as_ref().unwrap().len(),
        Layout::new::<Entry>().size()
    );
    assert!(book
        .insert(AdmissionClass::Operator, UnitKey::new(3), unit(&node))
        .is_ok());
    assert_eq!(book.len(), 2);
    assert!(book
        .get(AdmissionClass::Operator, UnitKey::new(1))
        .is_none());
}

#[test]
fn growth_retains_spare_charge_until_backing_is_destroyed() {
    let node = super::super::Node::new();
    let budget = budget(12, 2);
    let data = budget.connection_storage(AdmissionClass::Data);
    let mut book = book(&budget);
    for key in [3, 1, 2] {
        assert!(book
            .insert(AdmissionClass::Data, UnitKey::new(key), unit(&node))
            .is_ok());
    }
    let entry_bytes = Layout::new::<Entry>().size();
    assert_eq!(book.data.entries.capacity(), 4);
    assert_eq!(book.data.credit.as_ref().unwrap().len(), 4 * entry_bytes);
    assert!(book.remove(AdmissionClass::Data, UnitKey::new(2)).is_some());
    assert_eq!(book.data.credit.as_ref().unwrap().len(), 4 * entry_bytes);
    let remainder = data.try_reserve(6 * entry_bytes).unwrap();
    assert!(data.try_reserve(1).is_err());
    drop(remainder);
    assert!(book.remove(AdmissionClass::Data, UnitKey::new(1)).is_some());
    assert!(book.remove(AdmissionClass::Data, UnitKey::new(3)).is_some());
    assert_eq!(book.data.entries.capacity(), 0);
    assert!(book.data.credit.is_none());
    assert!(data.try_reserve(10 * entry_bytes).is_ok());
}

#[test]
fn duplicate_key_cannot_create_a_second_owner_in_another_class() {
    let node = super::super::Node::new();
    let budget = budget(8, 4);
    let mut book = book(&budget);
    assert!(book
        .insert(AdmissionClass::Data, UnitKey::new(7), unit(&node))
        .is_ok());
    let duplicate = unit(&node);
    let call = duplicate.call;
    let returned = book
        .insert(AdmissionClass::Operator, UnitKey::new(7), duplicate)
        .err()
        .unwrap();
    assert_eq!(returned.call, call);
    assert_eq!(book.operator.entries.capacity(), 0);
    assert_eq!(book.len(), 1);
}

#[test]
fn finite_horizon_finishes_despite_arrivals_and_removed_endpoint() {
    let node = super::super::Node::new();
    let budget = budget(64, 32);
    let mut book = book(&budget);
    for (class, key) in [
        (AdmissionClass::Data, 2),
        (AdmissionClass::Operator, 3),
        (AdmissionClass::Data, 5),
    ] {
        assert!(book.insert(class, UnitKey::new(key), unit(&node)).is_ok());
    }
    let upper = book.max_key();
    assert_eq!(upper, 5);
    assert_eq!(
        book.next(None, upper),
        Some((AdmissionClass::Data, UnitKey::new(2)))
    );
    assert!(book.remove(AdmissionClass::Data, UnitKey::new(5)).is_some());
    for key in 6..16 {
        assert!(book
            .insert(AdmissionClass::Data, UnitKey::new(key), unit(&node))
            .is_ok());
    }
    assert_eq!(
        book.next(Some(2), upper),
        Some((AdmissionClass::Operator, UnitKey::new(3)))
    );
    assert!(book.next(Some(3), upper).is_none());
    assert!(book.next(Some(u64::MAX), u64::MAX).is_none());
    assert!(book.next(None, 0).is_none());
    assert_eq!(book.values().count(), book.len());
}

#[test]
fn destruction_returns_both_original_backing_credits() {
    let node = super::super::Node::new();
    let budget = budget(8, 4);
    let data = budget.connection_storage(AdmissionClass::Data);
    let operator = budget.connection_storage(AdmissionClass::Operator);
    let mut book = book(&budget);
    assert!(book
        .insert(AdmissionClass::Data, UnitKey::new(1), unit(&node))
        .is_ok());
    assert!(book
        .insert(AdmissionClass::Operator, UnitKey::new(2), unit(&node))
        .is_ok());
    drop(book);
    let bytes = Layout::new::<Entry>().size();
    let data_all = data.try_reserve(4 * bytes).unwrap();
    let operator_all = operator.try_reserve(4 * bytes).unwrap();
    assert!(operator.try_reserve(1).is_err());
    drop((data_all, operator_all));
}

/// Explicit remote qualification, not a correctness timing assertion. Uses the
/// actual final RetainedUnit layout and production process byte limits.
#[test]
#[ignore = "run explicitly on the pinned CI runner for terminal book cost qualification"]
fn terminal_book_saturated_cost() {
    use std::time::Instant;

    let node = super::super::Node::new();
    let budget = ProcessAdmission::new(0);
    let mut book = book(&budget);
    let started = Instant::now();
    let mut key = 2u64;
    while book
        .insert(AdmissionClass::Data, UnitKey::new(key), unit(&node))
        .is_ok()
    {
        key = key.checked_add(2).unwrap();
    }
    let fill = started.elapsed();
    let population = book.len();
    assert!(population >= 64);
    let backing = book.data.credit.as_ref().unwrap().len();
    let upper = book.max_key();
    let started = Instant::now();
    let mut last = None;
    for _ in 0..64 {
        let (_, next) = book.next(last, upper).unwrap();
        last = Some(std::hint::black_box(next.get()));
    }
    let scan = started.elapsed();
    let started = Instant::now();
    for removed in (2..=128).step_by(2) {
        assert!(book
            .remove(AdmissionClass::Data, UnitKey::new(removed))
            .is_some());
    }
    let remove = started.elapsed();
    let started = Instant::now();
    for inserted in (1..128).step_by(2) {
        assert!(book
            .insert(AdmissionClass::Data, UnitKey::new(inserted), unit(&node))
            .is_ok());
    }
    let insert = started.elapsed();
    let data_limit = usize::try_from(
        busbar_kernel::limits::process_admission::BODY_BYTES
            - busbar_kernel::limits::process_admission::OPERATOR_BODY_BYTES,
    )
    .unwrap();
    let _saturated_data = budget
        .connection_storage(AdmissionClass::Data)
        .try_reserve(data_limit - backing)
        .unwrap();
    let started = Instant::now();
    assert!(book
        .insert(AdmissionClass::Operator, UnitKey::new(key), unit(&node))
        .is_ok());
    let operator = started.elapsed();
    eprintln!(
        "terminal_book entry_bytes={} population={population} backing_bytes={backing} fill={fill:?} scan64={scan:?} remove_front64={remove:?} insert_front64={insert:?} operator_insert={operator:?}",
        Layout::new::<Entry>().size(),
    );
}

fn install_reserved(
    node: &super::super::Node,
    class: AdmissionClass,
    keys: std::ops::RangeInclusive<u64>,
) {
    let mut book = node
        .lost
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let book = book.as_mut().expect("fixture Node binds its terminal book");
    for key in keys {
        assert!(book.insert(class, UnitKey::new(key), unit(node)).is_ok());
    }
}

/// The adopted bound: one native pulse examines at most 64 candidates, irrelevant legacy
/// entries included, and resumes from its cursor instead of rescanning the book.
#[tokio::test]
async fn native_pulse_examines_at_most_64_candidates() {
    let node = super::super::Node::new();
    install_reserved(&node, AdmissionClass::Data, 1..=100);
    let mut cursor = None;
    assert_eq!(node.drive_native(&mut cursor).await, 0);
    assert_eq!(
        cursor,
        Some(64),
        "the pulse stopped after 64 examined entries"
    );
    assert_eq!(node.drive_native(&mut cursor).await, 0);
    assert_eq!(
        cursor, None,
        "the remaining 36 completed the finite horizon"
    );
    assert_eq!(
        node.terminal_pending(),
        100,
        "a pulse never removes legacy custody"
    );
}

/// The original request lease class selects the partition; the RAII reservation unwinds
/// before effects and leaves no record behind.
#[test]
fn reservation_uses_the_request_class_and_unwinds_before_effects() {
    let node = super::super::Node::new();
    let call = node.kernel.next_call();
    let key = UnitKey::new(7);
    let reservation = node
        .reserve_terminal(AdmissionClass::Operator, key, call)
        .expect("funded reservation");
    {
        let book = node
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let book = book.as_ref().unwrap();
        assert!(book.get(AdmissionClass::Operator, key).is_some());
        assert!(book.get(AdmissionClass::Data, key).is_none());
    }
    drop(reservation);
    assert_eq!(node.terminal_pending(), 0);
}

/// Absent process storage binding refuses a new unit before any effect; no default account.
#[test]
fn unbound_terminal_storage_refuses_before_effects() {
    let node = super::super::Node::new();
    *node
        .lost
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    let call = node.kernel.next_call();
    assert!(node
        .reserve_terminal(AdmissionClass::Data, UnitKey::new(1), call)
        .is_none());
    assert_eq!(node.terminal_pending(), 0);
}

/// Data saturation cannot consume the protected Operator reserve through the Node.
#[test]
fn saturated_data_terminal_storage_keeps_operator_reservations() {
    let node = super::super::Node::new();
    let process = budget(4, 2);
    node.rebind_terminal_storage(&process);
    let data = process.connection_storage(AdmissionClass::Data);
    let _held = data.try_reserve(2 * Layout::new::<Entry>().size()).unwrap();
    assert!(node
        .reserve_terminal(
            AdmissionClass::Data,
            UnitKey::new(1),
            node.kernel.next_call()
        )
        .is_none());
    let operator = node
        .reserve_terminal(
            AdmissionClass::Operator,
            UnitKey::new(2),
            node.kernel.next_call(),
        )
        .expect("the Operator reserve remains available");
    drop(operator);
}
