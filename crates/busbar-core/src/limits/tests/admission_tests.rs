// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/limits/admission.rs`.

use super::*;

#[test]
fn exhausting_permits_returns_none() {
    let gate = AdmissionGate::new(1, "test-exhaust");
    let _held = gate.try_enter().expect("first entry admits");
    assert!(
        gate.try_enter().is_none(),
        "a saturated gate must deny further entries"
    );
}

#[test]
fn dropping_a_permit_frees_a_slot() {
    let gate = AdmissionGate::new(1, "test-release");
    let held = gate.try_enter().expect("first entry admits");
    assert!(
        gate.try_enter().is_none(),
        "saturated while the only permit is held"
    );
    drop(held);
    assert!(
        gate.try_enter().is_some(),
        "dropping the held permit must free the slot"
    );
}

#[test]
fn denied_entry_increments_the_gate_counter() {
    crate::metrics::init();
    let gate = AdmissionGate::new(1, "test-denied-counter");
    let _held = gate.try_enter().expect("first entry admits");
    assert!(gate.try_enter().is_none(), "second entry must be denied");

    let out = crate::metrics::render();
    assert!(
        out.contains("busbar_admission_denied_total{gate=\"test-denied-counter\"} 1"),
        "a denied try_enter must increment the per-gate denied counter; got:\n{out}"
    );
}

/// THE QUEUEING CONTRACT (replaces the instant-503 shed, whose fail/retry storm collapsed the
/// gateway under a 12k-client herd on the rig): an over-cap arrival WAITS FIFO and is admitted
/// the moment a slot frees; a waiter whose caller gives up leaves the queue with no residue; and
/// the memory bound holds throughout — never more than N permits exist.
#[tokio::test]
async fn a_saturated_gate_queues_fifo_and_cancelled_waiters_leave_cleanly() {
    let gate = std::sync::Arc::new(AdmissionGate::new(1, "test-queue"));
    let held = gate.enter_queued().await;

    // Two queued waiters, in order.
    let g1 = gate.clone();
    let first = tokio::spawn(async move { g1.enter_queued().await });
    tokio::task::yield_now().await;
    let g2 = gate.clone();
    let second = tokio::spawn(async move { g2.enter_queued().await });
    tokio::task::yield_now().await;
    assert!(!first.is_finished() && !second.is_finished(), "both parked");

    // The FIRST waiter (FIFO) is admitted when the slot frees; the second still waits.
    drop(held);
    let first_permit = first.await.expect("first waiter admitted");
    tokio::task::yield_now().await;
    assert!(
        !second.is_finished(),
        "FIFO: the second waiter keeps waiting"
    );

    // A cancelled waiter leaves no residue: abort the second, free the slot, and a FRESH
    // arrival gets it immediately (a leaked queue position would starve it).
    second.abort();
    drop(first_permit);
    let fresh = tokio::time::timeout(std::time::Duration::from_secs(5), gate.enter_queued())
        .await
        .expect("a cancelled waiter must not hold the freed slot");
    drop(fresh);
}

/// CONCURRENT-CAP BOUNDARY at N > 1: a gate of N permits admits EXACTLY N in-flight holders and
/// denies the (N+1)th — the instantaneous cap is N, not N-1 (off-by-one over-throttle) nor N+1
/// (over-admit past the cap). Freeing exactly one held permit re-opens exactly one slot: the next
/// `try_enter` admits, and the one after that is denied again. This is the shape of the group
/// `{ concurrent: N }` gauge — an operator's in-flight cap must admit the full N they configured.
#[test]
fn concurrent_cap_admits_exactly_n_and_frees_one_at_a_time() {
    let gate = AdmissionGate::new(3, "test-concurrent-boundary");
    assert_eq!(gate.available_permits(), 3);
    let a = gate.try_enter().expect("1st of 3 admits");
    let b = gate.try_enter().expect("2nd of 3 admits");
    let c = gate.try_enter().expect("3rd of 3 admits");
    assert_eq!(gate.available_permits(), 0, "all 3 slots held");
    assert!(
        gate.try_enter().is_none(),
        "the 4th must be denied — the cap is exactly 3, never 4"
    );
    drop(b);
    assert_eq!(
        gate.available_permits(),
        1,
        "freeing one reopens exactly one slot"
    );
    let d = gate
        .try_enter()
        .expect("one freed slot admits exactly one more");
    assert!(
        gate.try_enter().is_none(),
        "and only one — the cap re-saturates at 3"
    );
    drop((a, c, d));
    assert_eq!(
        gate.available_permits(),
        3,
        "all holders gone, cap fully restored"
    );
}

#[test]
fn unbounded_sentinel_never_denies() {
    let gate = AdmissionGate::new(Semaphore::MAX_PERMITS, "test-unbounded");
    // Hold a generous handful of permits; an unbounded gate must keep admitting.
    let held: Vec<_> = (0..1000).map(|_| gate.try_enter().unwrap()).collect();
    assert!(gate.try_enter().is_some());
    drop(held);
}
