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

/// The inbound-shed 503's `Retry-After` is DERIVED from `store::SHED_RETRY_FLOOR_MS`, not a bare
/// hardcoded `"1"` that drifts silently the day the floor changes. The header must equal the floor
/// rounded UP to whole seconds — the same value the shedding taxonomy advertises for this condition.
#[test]
fn inbound_shed_retry_after_is_derived_from_the_shed_floor() {
    let resp = inbound_overloaded_response();
    let hv = resp
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .expect("a shed 503 carries a Retry-After");
    let expected = crate::store::SHED_RETRY_FLOOR_MS.div_ceil(1000);
    assert_eq!(
        hv.to_str().unwrap(),
        expected.to_string(),
        "Retry-After must track SHED_RETRY_FLOOR_MS (whole seconds, rounded up), not a hardcoded constant"
    );
    assert!(
        expected >= 1,
        "a sub-second floor still rounds up to at least one whole second"
    );
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
