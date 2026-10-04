// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # busbar-unit-egress — the egress unit
//!
//! The design gives this unit the fifth step of the loop and one sentence's worth of job: take the
//! plane's route plan, walk the verified set the trust unit sealed, and send. Everything under
//! that sentence is here and nothing else is.
//!
//! ## The four parts
//!
//! **The pool.** This unit owns the pool per transport and destination: the membership, each
//! member's weight and overrides, the walk's deadline and hop count, the per-pool blocklist, and
//! what to do when there is nowhere to send. A member's lifetime request budget is the breaker
//! unit's counter, but it is this unit that spends it — after the upstream's success, never at
//! selection — and this unit that gives it back when the answer does not arrive whole.
//!
//! **The walk.** One stepper, in [`walk`]: the deadline before every step including one that
//! starts a streamed answer, the one pick, what a refusal for size means for the next hop, and the
//! pool's terminal when its members are spent. It takes the pool's hop cap plus one members, and
//! its caller fails over only before the first byte reaches the client.
//!
//! **The attempt's bound.** In [`attempt`]: the cap on time to the first answer, never beyond what
//! the walk has left. The attempt itself — the durable record, the dial, the read — is the walk's
//! caller's, one per member the walk takes.
//!
//! **The terminals.** In [`exhaustion`]: the shed with its honest wait, the spill into another
//! pool, the bounded wait for a slot, and the one documented breaker bypass.
//!
//! ## What is deliberately not here
//!
//! The dialect codecs are not here. This unit reads no body: it never parses an answer, never
//! knows what a protocol is, and holds no literal from one.
//!
//! The breaker's state machine is the breaker unit's. This unit consults it before an attempt and
//! records against it after, through the one trait in [`ports`]. The table that says what a given
//! upstream status means to a given destination is data that trait consumes, not a match arm here
//! — which is why the same walk serves a destination whose operator remapped every code.
//!
//! The money is the admission and ledger units'. This unit answers which member is attempted and
//! what the shed says, and settles nothing.
//!
//! ## What is bound by the integrator
//!
//! Everything in [`ports`] marked `// contract:`: the breaker, the journal, the pool's permit
//! store, the clock and the counters. Each is a small trait with a settled shape; none of them is a
//! decision this unit is still waiting to make.
//!
//! ## A note on the words
//!
//! The refusals this unit produces carry the literal words of the previous release, gathered in
//! [`wire`] so they cannot drift. What goes on the wire is the plane's rendering of them; what is
//! fixed here is the status, the kind, the words and the wait.

pub mod arity;
pub mod attempt;
// Folded from the former `busbar-unit-trust` crate (#36: trust folds into egress).
pub mod exhaustion;
pub mod pool;
pub mod ports;
// The query-parameter auth fields (the auth ABI's FIELD_QUERY) on the request target.
pub mod query_auth;
pub mod race;
pub mod select;
pub mod trust;
pub mod upstream;
pub mod walk;
pub mod wire;

pub use arity::{on_primary_unavailable, Arity, PinnedRefusal, Reroute};
pub use pool::{
    Failover, Member, OnExhausted, Pool, DEFAULT_FAILOVER_CAP, DEFAULT_FAILOVER_DEADLINE_SECS,
};
pub use select::{RequestCtx, WeightedFloor};
pub use walk::{Step, Taken, Walk, WalkPorts};
pub use wire::Shed;

#[cfg(test)]
mod tests;
