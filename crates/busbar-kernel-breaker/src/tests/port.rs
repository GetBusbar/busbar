//! Tests for `port.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use crate::classify::WireFault;
use crate::Outcome;

// ── outcome_and_label: the four-way fold, ported from `classify_error`'s match arms ─────────

#[test]
fn client_fault_records_nothing() {
    let (outcome, label) = outcome_and_label(Disposition::ClientFault, Some(30));
    assert_eq!(outcome, Outcome::RecordNothing);
    assert_eq!(label, label::CLIENT_FAULT);
}

#[test]
fn context_length_records_nothing() {
    let (outcome, label) = outcome_and_label(Disposition::ContextLength, None);
    assert_eq!(outcome, Outcome::RecordNothing);
    assert_eq!(label, label::CONTEXT_LENGTH);
}

#[test]
fn transient_upstream_threads_retry_after_through() {
    let (outcome, label) = outcome_and_label(Disposition::TransientUpstream, Some(42));
    assert_eq!(
        outcome,
        Outcome::Transient {
            retry_after: Some(42)
        }
    );
    assert_eq!(label, label::TRANSIENT_UPSTREAM);
}

#[test]
fn transient_upstream_with_no_retry_after() {
    let (outcome, _) = outcome_and_label(Disposition::TransientUpstream, None);
    assert_eq!(outcome, Outcome::Transient { retry_after: None });
}

#[test]
fn hard_down_is_hard_down() {
    let (outcome, label) = outcome_and_label(Disposition::HardDown, None);
    assert_eq!(outcome, Outcome::HardDown);
    assert_eq!(label, label::HARD_DOWN);
}

// ── classify_upstream: the reading, and nothing else ──────────────────────────────────────────

fn answered(fault: Option<WireFault>, retry_after: Option<u64>) -> Classified {
    classify_upstream(UpstreamStatus {
        reading: Reading::Answered(fault),
        retry_after,
    })
}

/// Each fault reading lands on 1.5.5's disposition for the answers its framer reads that way: a
/// refused credential takes the destination down everywhere, a transient fault counts toward a
/// trip with the stated wait as its floor, and the caller's own fault records nothing.
#[test]
fn every_fault_reading_carries_its_disposition() {
    let hard = answered(Some(WireFault::Hard), Some(9));
    assert_eq!(
        (hard.disposition, hard.outcome, hard.label),
        (Disposition::HardDown, Outcome::HardDown, label::HARD_DOWN)
    );
    let transient = answered(Some(WireFault::Transient), Some(9));
    assert_eq!(
        (transient.disposition, transient.outcome, transient.label),
        (
            Disposition::TransientUpstream,
            Outcome::Transient {
                retry_after: Some(9)
            },
            label::TRANSIENT_UPSTREAM
        )
    );
    let caller = answered(Some(WireFault::Caller), Some(9));
    assert_eq!(
        (caller.disposition, caller.outcome, caller.label),
        (
            Disposition::ClientFault,
            Outcome::RecordNothing,
            label::CLIENT_FAULT
        )
    );
}

/// THE RED ARM'S RUNTIME HALF: an answer whose framer stated no fault reading (a framer with no
/// fault table) is the caller's, never an outage. Reading an unread answer as a failure of the
/// destination would trip a live member on every error it relayed.
#[test]
fn an_answer_with_no_fault_reading_is_the_callers() {
    let got = answered(None, Some(30));
    assert_eq!(got.disposition, Disposition::ClientFault);
    assert_eq!(got.outcome, Outcome::RecordNothing);
}

/// No answer at all is the kernel's own fact, and a failure OF the destination: transient, so it
/// trips the cell (1.5.5's relay hop classifier read its transport-failure arm as a network
/// failure). Treating it as the caller's let a destination failing this way keep taking traffic.
#[test]
fn no_answer_is_a_transient_failure_that_trips() {
    let got = classify_upstream(UpstreamStatus {
        reading: Reading::NoAnswer,
        retry_after: None,
    });
    assert_eq!(got.disposition, Disposition::TransientUpstream);
    assert_eq!(got.outcome, Outcome::Transient { retry_after: None });
}

/// The stated wait rides through only where the disposition reads it: a hard-down's cooldown is
/// the configured one, and a caller's fault records nothing to floor.
#[test]
fn the_stated_wait_floors_only_a_transient_fault() {
    assert_eq!(
        answered(Some(WireFault::Hard), Some(7)).outcome,
        Outcome::HardDown
    );
    assert_eq!(
        answered(Some(WireFault::Caller), Some(7)).outcome,
        Outcome::RecordNothing
    );
    assert_eq!(
        answered(Some(WireFault::Transient), None).outcome,
        Outcome::Transient { retry_after: None }
    );
}
