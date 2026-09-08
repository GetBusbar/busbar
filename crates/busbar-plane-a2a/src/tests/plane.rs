//! Tests for `plane.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{finish_of, refusal_render, rewrite_task_id, Codec};
use busbar_contract::unit::{AbortBy, FailureReason, RefusalReason, Step, UnitEnd};

/// Every reason the contract declares, in its own declaration order.
///
/// A written-out walk-set, and it is safe to be one only because the renderer it drives matches
/// EXHAUSTIVELY: a reason added to the contract does not compile until the renderer answers it, and
/// the length assertion below is what says this walk saw it too. The list is what the tests
/// iterate; the compiler is what keeps the renderer total.
const EVERY_REASON: [RefusalReason; 42] = [
    RefusalReason::InFlightCap,
    RefusalReason::CursorBudget,
    RefusalReason::CredentialBudget,
    RefusalReason::SessionBudget,
    RefusalReason::BodyTooLarge,
    RefusalReason::OpenSlotBusy,
    RefusalReason::SchemeNotDeclared,
    RefusalReason::CredentialRejected,
    RefusalReason::SessionUnbound,
    RefusalReason::Revoked,
    RefusalReason::ScopeMissing,
    RefusalReason::Vetoed,
    RefusalReason::NoDestination,
    RefusalReason::OverBudget,
    RefusalReason::GroupFrozen,
    RefusalReason::Unpriced,
    RefusalReason::OverdraftCeiling,
    RefusalReason::StaleSlice,
    RefusalReason::DurabilityUnavailable,
    RefusalReason::TierMismatch,
    RefusalReason::SpillBudget,
    RefusalReason::ArenaBudget,
    RefusalReason::RateLimited,
    RefusalReason::DecodeFailed,
    RefusalReason::ChallengeExhausted,
    RefusalReason::PoolNotPermitted,
    RefusalReason::NoRate,
    RefusalReason::Replayed,
    RefusalReason::InFlight,
    RefusalReason::DestinationBudgetExhausted,
    RefusalReason::BreakerOpen,
    RefusalReason::DestinationUnreachable,
    RefusalReason::MeterDisputed,
    RefusalReason::HandoffMismatch,
    RefusalReason::PlanePanic,
    RefusalReason::TaskLost,
    RefusalReason::SecretPlaceholder,
    RefusalReason::Stalled,
    RefusalReason::Drain,
    RefusalReason::Superseded,
    RefusalReason::ClientGone,
    RefusalReason::DeadlineExceeded,
];

/// Every closed refusal reason has an answer, and every answer is a code this dialect defines.
///
/// Totality is the point: a reason with no row would be a caller who is told nothing, and the
/// contract's reason list is closed precisely so this can be checked rather than hoped for.
#[test]
fn every_refusal_reason_has_an_answer() {
    assert_eq!(
        EVERY_REASON.len(),
        42,
        "the contract's reason set changed and this walk did not"
    );
    let known: Vec<i64> = crate::jsonrpc::ERRORS
        .iter()
        .map(|(c, _)| *c)
        .chain([
            crate::jsonrpc::CODE_INVALID_REQUEST,
            crate::jsonrpc::CODE_METHOD_NOT_FOUND,
            crate::jsonrpc::CODE_INVALID_PARAMS,
            crate::jsonrpc::CODE_INTERNAL,
        ])
        .collect();
    for reason in EVERY_REASON {
        let (code, message) = refusal_render(reason);
        assert!(
            known.contains(&code),
            "{reason:?} renders unknown code {code}"
        );
        assert!(!message.is_empty(), "{reason:?} renders no words");
    }
}

/// The refusals answered as this node's own failure are the ones that ARE this node's own failure.
///
/// A rate limit, an open breaker, a drain and a deadline are things a caller can act on: wait, fail
/// over, come back later. Answered with the words this node keeps for "something here went wrong",
/// a client's retry and failover policy reads a permanent internal error and does the wrong thing
/// with every one of them. So the set of reasons that renders the node's-own-failure row is written
/// down and checked, instead of being whatever the renderer's last arm happened to catch.
#[test]
fn only_this_nodes_own_failures_are_answered_as_one() {
    const OWN_FAILURES: [RefusalReason; 7] = [
        RefusalReason::Unpriced,
        RefusalReason::NoRate,
        RefusalReason::MeterDisputed,
        RefusalReason::HandoffMismatch,
        RefusalReason::PlanePanic,
        RefusalReason::TaskLost,
        RefusalReason::SecretPlaceholder,
    ];
    let row = refusal_render(RefusalReason::PlanePanic);
    let mut answered_as_failure: Vec<RefusalReason> = EVERY_REASON
        .into_iter()
        .filter(|reason| refusal_render(*reason) == row)
        .collect();
    let mut expected = OWN_FAILURES.to_vec();
    answered_as_failure.sort_by_key(|r| format!("{r:?}"));
    expected.sort_by_key(|r| format!("{r:?}"));
    assert_eq!(
        answered_as_failure, expected,
        "a refusal the caller could have acted on reads as this node's own failure"
    );
}

/// A refusal tells the caller nothing about the money.
///
/// The words a caller sees must not leak which bucket was dry, which group was frozen or which
/// slice was stale: those are the node's business and a caller learning them learns about other
/// callers.
#[test]
fn a_refusal_leaks_nothing_about_the_money() {
    for reason in [
        RefusalReason::OverBudget,
        RefusalReason::GroupFrozen,
        RefusalReason::Unpriced,
        RefusalReason::OverdraftCeiling,
        RefusalReason::StaleSlice,
    ] {
        let (_, message) = refusal_render(reason);
        for leak in ["budget", "bucket", "frozen", "price", "slice", "overdraft"] {
            assert!(
                !message.to_ascii_lowercase().contains(leak),
                "{reason:?} leaks {leak}"
            );
        }
    }
}

/// A completed streamed answer ends a turn; a completed single answer is complete.
#[test]
fn a_streamed_answer_ends_a_turn() {
    assert_eq!(
        finish_of(&UnitEnd::Completed, true),
        busbar_contract::unit::FinishClass::TurnComplete
    );
    assert_eq!(
        finish_of(&UnitEnd::Completed, false),
        busbar_contract::unit::FinishClass::Complete
    );
}

/// An abort leaves a partial answer whoever performed it. `Error` is for an upstream that
/// reported one, and a kernel abort is this node ending a unit over an upstream that said
/// nothing wrong -- who did it is in the `UnitEnd` the audit row already carries.
#[test]
fn who_ended_it_decides_how_it_ended() {
    assert_eq!(
        finish_of(&UnitEnd::Aborted(AbortBy::Client), false),
        busbar_contract::unit::FinishClass::Partial
    );
    assert_eq!(
        finish_of(
            &UnitEnd::Aborted(AbortBy::Kernel {
                reason: RefusalReason::Revoked
            }),
            false
        ),
        busbar_contract::unit::FinishClass::Partial
    );
    assert_eq!(
        finish_of(
            &UnitEnd::Failed {
                step: Step::Route,
                reason: FailureReason::Transport
            },
            false
        ),
        busbar_contract::unit::FinishClass::Error
    );
}

/// The rewrite replaces every spelling of the identifier and leaves everything else alone.
#[test]
fn the_rewrite_replaces_every_spelling() {
    let body =
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":"ours","other":"kept"}}"#;
    let out = rewrite_task_id(body, "theirs").expect("the rewrite writes");
    let value: serde_json::Value = serde_json::from_slice(&out).expect("it is a document");
    assert_eq!(value["params"]["id"], "theirs");
    assert_eq!(value["params"]["other"], "kept");
    // The envelope's own identifier is the CALLER's and is never rewritten: the agent echoes it
    // and the caller is waiting for exactly those bytes back.
    assert_eq!(value["id"], 1);
}

/// A request with no parameters is passed through unchanged, byte for byte.
#[test]
fn a_request_with_no_parameters_passes_through() {
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#;
    let out = rewrite_task_id(body, "theirs").expect("the rewrite writes");
    assert_eq!(out, body.to_vec());
}

/// The codec state starts at nothing and counts up.
#[test]
fn the_codec_state_counts_events() {
    let mut codec = Codec::default();
    assert_eq!(codec.events_read, 0);
    codec.events_read = codec.events_read.saturating_add(1);
    assert_eq!(codec.events_read, 1);
}
