// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ARITY POSTURE at the pick face — whether an unavailable primary reroutes, or refuses.
//!
//! The [`select`](crate::select) walk always picks ONE member, but what a failed pick MEANS depends
//! on why the pool was assembled. A fresh submission to a pool of interchangeable members
//! ([`Arity::ChooseOne`]) may fail over: a tripped primary reroutes to a verified twin before
//! anything reaches a socket and the caller never learns. An addressed or resumed request
//! ([`Arity::ExactlyOne`]) is PINNED to the one member that holds its state — the id names work that
//! exists at exactly one backend — so failover would be a migration, not a retry, and a tripped
//! pinned member REFUSES the verb rather than dispatching to a twin that does not have the state.
//!
//! This is the egress-face reading of the same [`ExactlyOne`](Arity::ExactlyOne)/
//! [`ChooseOne`](Arity::ChooseOne) posture the verify step selects candidates under: there it decides
//! how many destinations a request may resolve to; here it decides whether an unavailable resolved
//! one may be swapped. Stating it as data means the failover loop asks one question —
//! [`Arity::may_failover`] — instead of scattering "was this pinned" through the walk.

use crate::ports::Unavailable;

/// HOW the pool a pick walks was assembled, which decides whether a failed primary reroutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arity {
    /// Pinned to one backend — an addressed or resumed request whose state exists at exactly one
    /// member. An unavailable member [`refuses`](Reroute::Refuse) rather than rerouting.
    ExactlyOne,
    /// A pool of interchangeable members — a fresh submission. An unavailable member
    /// [`fails over`](Reroute::Failover) to a verified twin.
    ChooseOne,
}

impl Arity {
    /// Whether a pick under this posture may fail over to another member. Only [`Arity::ChooseOne`]
    /// may; [`Arity::ExactlyOne`] is pinned and refuses instead.
    #[must_use]
    pub fn may_failover(self) -> bool {
        matches!(self, Arity::ChooseOne)
    }
}

/// The refusal a PINNED member raises when it cannot serve — the verb is refused, not rerouted.
///
/// Carries the pinned member so the refusal names WHICH backend held the state, and the
/// [`Unavailable`] that closed it so the caller renders the right status and, for a breaker cooldown,
/// an exact `Retry-After` from the cell's own deadline. The state stays readable from busbar's own
/// store; what is refused is a fresh dispatch to a backend that cannot take it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedRefusal<T> {
    /// The pinned member the request is bound to — the one backend that holds its state.
    pub pinned: T,
    /// Why that member cannot serve right now, carried verbatim so nothing about the availability
    /// answer is re-decided here.
    pub cause: Unavailable,
}

impl<T> PinnedRefusal<T> {
    /// The exact retry hint, in whole seconds since the epoch, when the cause is a breaker cooldown
    /// with a known deadline. `None` for causes that carry no deadline, so the caller can tell an
    /// "come back at this second" refusal from one with no useful hint.
    #[must_use]
    pub fn retry_at(&self) -> Option<u64> {
        match self.cause {
            Unavailable::BreakerOpen { until } => Some(until),
            _ => None,
        }
    }
}

/// WHAT a failed primary pick does under a posture — reroute, or refuse carrying the pinned member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reroute<T> {
    /// The walk may try another member — the [`Arity::ChooseOne`] pool path.
    Failover,
    /// Pinned: refuse the verb rather than rerouting, carrying the pinned member and its cause.
    Refuse(PinnedRefusal<T>),
}

/// DECIDE what an unavailable primary does under `posture`.
///
/// [`Arity::ChooseOne`] yields [`Reroute::Failover`] and the walk continues; [`Arity::ExactlyOne`]
/// yields [`Reroute::Refuse`] carrying `pinned` and `cause`, so the caller refuses the verb with the
/// pinned member named and the cooldown, if any, in hand. The `pinned` value is consumed into the
/// refusal on the pinned path only — a failover has no member to carry, so it drops it.
pub fn on_primary_unavailable<T>(posture: Arity, pinned: T, cause: Unavailable) -> Reroute<T> {
    if posture.may_failover() {
        Reroute::Failover
    } else {
        Reroute::Refuse(PinnedRefusal { pinned, cause })
    }
}

#[cfg(test)]
#[path = "tests/arity_tests.rs"]
mod arity_tests;
