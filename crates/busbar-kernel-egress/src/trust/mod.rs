// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-unit-trust — the verify step, as a unit
//!
//! One question, asked once per unit and before anything is charged: **where may this go?** The
//! answer is a set of sealed destinations, and sealing is the whole point — the egress unit will
//! dial what a sealed destination says and nothing else, and the lane is re-checked against it after
//! the outbound request is decorated, so nothing downstream can quietly move the unit to a cheaper
//! or a different lane.
//!
//! ## The three guards, in this order
//!
//! The order is not stylistic. Every check that can refuse runs BEFORE the door charges, because
//! nothing may reject a request that has already been charged:
//!
//! 1. The requested pool's allow-list.
//! 2. Every fallback pool reachable from it, walked with the same visited-set guard the dispatch
//!    itself uses, so a chain that cycles terminates. A key restricted to one pool can never be
//!    served by a fallback pool it may not use, because the dispatch that far down cannot re-check
//!    the key — this boundary is the only place that check exists.
//! 3. The unpriced-destination gate, which refuses with the invalid-request shape rather than a
//!    quota shape, because an unpriced arbitrary name is a bad request and not an exhausted budget.
//!
//! ## The network guard, and what it covers today
//!
//! Where a unit may go is this unit's question, and the address a destination resolves to is part
//! of it. [`net::check_destination`] states the whole discipline once: the metadata denylist over
//! the configured base AND over the paths joined to it, then exactly one resolution, then a
//! judgement of every answered address, then a pin.
//!
//! It is NOT one guard pinned for every carrier. No production path calls
//! [`net::check_destination`], and no production [`KindFacts`] answers
//! [`KindFacts::net_guard_passes`]. The provider dial (`attempt.rs`) hands its destination straight
//! to the carrier, whose client re-parses the authority and resolves the name itself, with no pin;
//! what guards a provider URL is the configuration-time check ([`net::ssrf_blocked_host`], the
//! 1.5.5 validators), exactly as 1.5.5 guarded it. The fetches that DO resolve-then-pin — the ones
//! the host makes on an operator's or a caller's behalf — call [`net::resolve_and_pin`] or
//! [`net::pin_answer`] directly, and the `dest.judge` host service asks [`net::check_structure`].
//! A provider dial is not resolved-then-pinned before it connects, because that would refuse a
//! name resolving to a private address where 1.5.5 accepted it.
//!
//! ## The exclusion rule
//!
//! A tripped, budget-exhausted or at-capacity lane is EXCLUDED from the walk, never "ordered last
//! and attempted". Where each exclusion happens is itself the behaviour:
//!
//! - Weight-zero (an operator draining a member), not-admissible (dead or over its lifetime request
//!   budget) and breaker-open lanes are filtered BEFORE the weighted credit walk, so they never
//!   consume a turn. The verify step excludes an open lane too, and it asks the SAME question
//!   through [`BreakerQuery::admits_lane`] rather than forming its own opinion — one exclusion,
//!   spelled once, so the pick order the walk produces is the pick order the seal agrees with.
//! - Only an at-capacity lane reaches the admission after selection, and so does consume one.
//!
//! A pool with every lane excluded still proceeds through the door — the slot is drawn and retained
//! — and ends at the pool's exhaustion terminal.
//!
//! ## The ordering natives are hooks
//!
//! Session affinity, the ranked walk and the weighted floor every deployment gets when it names no
//! strategy are all destination-changing hooks, declared as such
//! ([`order::OrderingHook::may_change_destination`]) rather than privileged. That is what keeps the
//! pick order a stated policy with an audit trail instead of an unstated property of a loop.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod arity;
pub mod counterparty;
pub mod destination;
pub mod guard;
pub mod lane;
pub mod net;
pub mod order;
pub mod swrr;
pub mod unit;

pub use arity::{select, Arity, ArityRefusal, Selection};
pub use counterparty::{admit as counterparty_admit, CounterpartyFacts, CounterpartyRefusal};
pub use destination::{
    kind_permitted, kind_rule_passes, Candidate, DestinationFacts, KindFacts, OriginKind,
};
pub use guard::{
    destination_guard, fallback_pools_authorized, pool_authorized, priced, GuardRefusal, PoolView,
    RefusalKind,
};
pub use lane::{
    survives_prewalk_filter, BreakerQuery, BreakerView, LaneCandidate, LaneTable, Unavailable,
};
pub use net::{
    check_destination, check_destination_facts, AddressRefusal, Denylist, GuardPolicy,
    NetworkRefusal, PinnedTarget, Resolver,
};
pub use order::{
    pick, reconcile_order, sticky_position, OrderVerdict, OrderingHook, Pick, PickOutcome,
};
pub use swrr::{select_weighted, SwrrState};
pub use unit::{Trust, VerifyRequest};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
