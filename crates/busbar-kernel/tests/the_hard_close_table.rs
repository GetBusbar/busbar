// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which endings close the session they happened on, one row per arm.
//!
//! Hard-closing a session is the most expensive answer the kernel has: every unit still on it goes,
//! and a caller mid-conversation is cut off. So the rule is a table, and a table is only proven by
//! reading every row of it AND by reading the rows either side of each condition — an arm nothing
//! distinguishes from its neighbour is an arm that can be deleted with every cell still green, and
//! that arm is either a session that never closes when it must or one that closes when it must not.

use busbar_caps::{OriginKind, ReasonCode, StepName};
use busbar_contract::Framing;
use busbar_kernel::inflight::{hard_closes, Binding, HardClose};

/// The money reasons the door refuses a provider push for, as the design names them.
const MONEY_REASONS: [ReasonCode; 6] = [
    ReasonCode::OverBudget,
    ReasonCode::GroupFrozen,
    ReasonCode::Unpriced,
    ReasonCode::OverdraftCeiling,
    ReasonCode::StaleSlice,
    ReasonCode::DurabilityUnavailable,
];

/// A provider push refused at the door FOR MONEY closes the session; refused for anything else, it
/// does not.
///
/// This is what bounds the exposure of a dry bucket to one push: the floor line posts and the
/// session goes. The guard is the whole of it — with every reason treated as a money reason a
/// session dies on a decode slip, and with none of them it survives a bucket it can never pay from
/// and pushes again.
#[test]
fn a_provider_push_refused_at_the_door_closes_the_session_only_for_a_money_reason() {
    for reason in MONEY_REASONS {
        assert_eq!(
            hard_closes(
                OriginKind::Provider,
                StepName::Admit,
                reason,
                Framing::Stream,
                Binding::Bound,
            ),
            Some(HardClose::ProviderRefusedForMoney),
            "{reason:?} is a money reason"
        );
    }
    for reason in [
        ReasonCode::ArenaBudget,
        ReasonCode::CursorBudget,
        ReasonCode::OpenSlotBusy,
    ] {
        assert_eq!(
            hard_closes(
                OriginKind::Provider,
                StepName::Admit,
                reason,
                Framing::Stream,
                Binding::Bound,
            ),
            None,
            "{reason:?} is not a money reason and the session stands"
        );
    }
    // And the cap is its own arm, at any step: the push never reached the door at all.
    assert_eq!(
        hard_closes(
            OriginKind::Provider,
            StepName::Arrival,
            ReasonCode::InFlightCap,
            Framing::Stream,
            Binding::Bound,
        ),
        Some(HardClose::ProviderRefusedForMoney)
    );
}

/// The endings that close a session whatever it arrived on, and what each is named.
///
/// Each of these is a session that has nothing left to be: its plane state is poisoned, its
/// credential was taken from a session that never had one, its principal was revoked, or the
/// connection under it is not the one the handoff named. The NAME matters as much as the closing —
/// it is what the exceptions report says happened — so each row asserts its own.
#[test]
fn the_endings_that_close_a_session_whatever_it_arrived_on() {
    for (reason, expected) in [
        (ReasonCode::PlanePanic, HardClose::PlanePanic),
        (ReasonCode::SessionUnbound, HardClose::SessionUnbound),
        (ReasonCode::Revoked, HardClose::Revoked),
        (ReasonCode::HandoffMismatch, HardClose::HandoffMismatch),
    ] {
        for origin in [OriginKind::Client, OriginKind::Provider] {
            for framing in [Framing::Stream, Framing::Datagram] {
                for binding in [Binding::Bound, Binding::Unbound] {
                    assert_eq!(
                        hard_closes(origin, StepName::Route, reason, framing, binding),
                        Some(expected),
                        "{reason:?} on {origin:?}/{framing:?}/{binding:?}"
                    );
                }
            }
        }
    }
}

/// A decode failure closes a stream and spares a datagram, and a failed re-check closes a bound
/// session and spares an unbound one.
///
/// Two arms, each load-bearing on exactly one fact, and each proven by the row either side of it.
#[test]
fn the_two_arms_that_turn_on_the_transport_and_the_binding() {
    assert_eq!(
        hard_closes(
            OriginKind::Client,
            StepName::Decode,
            ReasonCode::DecodeFailed,
            Framing::Stream,
            Binding::Bound,
        ),
        Some(HardClose::DecodeFailedOnStream),
        "a stream that lost sync is suspect for every later byte"
    );
    assert_eq!(
        hard_closes(
            OriginKind::Client,
            StepName::Decode,
            ReasonCode::DecodeFailed,
            Framing::Datagram,
            Binding::Bound,
        ),
        None,
        "one bad datagram is one bad datagram"
    );

    assert_eq!(
        hard_closes(
            OriginKind::Client,
            StepName::Authenticate,
            ReasonCode::Unauthenticated,
            Framing::Stream,
            Binding::Bound,
        ),
        Some(HardClose::BoundPrincipalFailed),
        "a bound session running as somebody it cannot prove it is has nothing left to be"
    );
    assert_eq!(
        hard_closes(
            OriginKind::Client,
            StepName::Authenticate,
            ReasonCode::Unauthenticated,
            Framing::Stream,
            Binding::Unbound,
        ),
        None,
        "on an unbound session a bad credential is one bad unit"
    );
}

/// An ordinary refusal closes nothing.
#[test]
fn an_ordinary_refusal_leaves_the_session_up() {
    assert_eq!(
        hard_closes(
            OriginKind::Client,
            StepName::Admit,
            ReasonCode::OverBudget,
            Framing::Stream,
            Binding::Bound,
        ),
        None,
        "a client unit refused for money is one refused unit"
    );
    assert_eq!(
        hard_closes(
            OriginKind::Client,
            StepName::Decode,
            ReasonCode::OpenSlotBusy,
            Framing::Stream,
            Binding::Bound,
        ),
        None
    );
}
