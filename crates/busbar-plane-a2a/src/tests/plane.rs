//! Tests for `plane.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{finish_of, refusal_render, rewrite_task_id, Codec};
use busbar_contract::unit::{AbortBy, FailureReason, RefusalReason, Step, UnitEnd};

/// Every closed refusal reason has an answer, and every answer is a code this dialect defines.
///
/// Totality is the point: a reason with no row would be a caller who is told nothing, and the
/// contract's reason list is closed precisely so this can be checked rather than hoped for.
/// EVERY reason the kernel closes a unit for, so a new variant cannot be added without deciding what
/// this dialect answers it with. The list is exhaustive against `busbar_contract::unit::RefusalReason`
/// (42 variants); `refusal_render`'s own match is `_`-free, so a reason absent here is one this test
/// would silently skip — the two lists are kept in step on purpose.
const ALL_REFUSAL_REASONS: [RefusalReason; 42] = [
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
    RefusalReason::Stalled,
    RefusalReason::SecretPlaceholder,
    RefusalReason::Drain,
    RefusalReason::Superseded,
    RefusalReason::ClientGone,
    RefusalReason::DeadlineExceeded,
];

#[test]
fn every_refusal_reason_has_an_answer() {
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
    for reason in ALL_REFUSAL_REASONS {
        let (code, message) = refusal_render(reason);
        assert!(
            known.contains(&code),
            "{reason:?} renders unknown code {code}"
        );
        assert!(!message.is_empty(), "{reason:?} renders no words");
    }
}

/// An operational refusal — a rate limit, an open breaker, a drain, a spent budget — is NOT a node
/// fault, and a caller must not be told it is one. Before the exhaustive mapping every reason but a
/// hand-picked nine fell through a `_` arm to `CODE_INTERNAL`, so a client throttled by this node was
/// told the node had broken and retried the wrong thing. These reasons must reach the caller as a
/// real refusal (`UnsupportedOperation`, this binding's nearest defined code), never as internal.
#[test]
fn no_operational_refusal_is_answered_as_an_internal_fault() {
    for reason in [
        RefusalReason::RateLimited,
        RefusalReason::BreakerOpen,
        RefusalReason::Drain,
        RefusalReason::OverBudget,
        RefusalReason::GroupFrozen,
        RefusalReason::PoolNotPermitted,
        RefusalReason::Replayed,
        RefusalReason::DestinationBudgetExhausted,
        RefusalReason::DestinationUnreachable,
        RefusalReason::OverdraftCeiling,
        RefusalReason::Superseded,
        RefusalReason::DeadlineExceeded,
    ] {
        let (code, _) = refusal_render(reason);
        assert_ne!(
            code,
            crate::jsonrpc::CODE_INTERNAL,
            "{reason:?} reaches the caller as an internal fault"
        );
    }
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
