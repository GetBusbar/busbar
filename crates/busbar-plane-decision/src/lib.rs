//! The decision plane: what bytes mean, for the `jev` dialect.
//!
//! ## What this crate is
//!
//! An ADAPTER, over a protocol this crate speaks for itself rather than borrowing from a codec
//! crate one hop away: jev is two small HTTP+JSON operations (`POST /v1/systemone`,
//! `GET /v1/models`), byte-identity passthrough to `api.typesafe.ai`, and there is no separate
//! wire vocabulary crate to adapt over the way `busbar-llm-codec` still exists for
//! their planes. The signed design (DECISION #39, jev v5 sign-off) rules this deliberately: ONE
//! crate, not a pure-plane-plus-impure-host split. See `Cargo.toml`'s header for why that also
//! means this crate names `busbar-substrate` — a widening its pure siblings do not carry.
//!
//! ## What this crate is not
//!
//! It holds no governance, no breaker, no hook seat, no signing key and no arithmetic over a
//! metered quantity. Those are units, and a unit is on the far side of the kernel from a plane. The
//! metering method here returns LOCATORS — the class, and the quantity this codec already read off
//! a SUCCESS response — and never a price, never a hold and never a decision. The routing method
//! returns a plan and never a connection. Nothing in this crate opens a socket, reads a file or
//! reads a clock other than the one the context hands it.
//!
//! ## What it holds across calls
//!
//! Nothing. The plane is a value with no interior mutability, asserted by a test rather than by a
//! comment. jev's two operations are each complete in one request/response pair — there is no
//! streamed answer and no task-like durable state — so this plane keeps no per-connection codec
//! state beyond what every plane's session machinery already provides.
//!
//! ## The PII witness, stated once
//!
//! A `systemone` exchange carries a caller-supplied `state` and the provider's `answers` — the
//! decision content itself. This plane never reads either: every pointer it resolves is declared in
//! `codec.rs`, and neither `state` nor `answers` is on that list. The body is still forwarded
//! byte-identically (the point of a passthrough dialect), but nothing this plane READS — no fact,
//! no record leg, no content fact — can ever carry those bytes, because it never looked at them.
//! `tests/jev.rs::pii_witness_never_surfaces_state_or_answers_in_any_fact` drives a fixture whose
//! body echoes both and asserts no fact this plane emits contains either value.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
pub mod codec;
pub mod config;
pub mod facts;
pub mod meta;
pub mod ops;
pub mod plane;
pub mod records;

use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

/// One configured decision provider this plane may name.
///
/// Every string is borrowed for the life of the program, because a plane's declarations are read at
/// registration and sealed. The seam a configured name must reach here through is
/// [`busbar_contract::ids::Registration`]: whoever builds this plane from a `decisions:` block
/// interns every config-derived key through it exactly once and hands over names that outlive it.
///
/// Nothing does that yet. The composition root (`busbar/src/root/plane_decision.rs`) installs this
/// plane's identity and config seam and builds no `DecisionPlane` today — its `build` is `None` —
/// so outside this crate's own tests no `DecisionProvider` is constructed and no request reaches
/// the plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionProvider {
    /// The name the operator gave this provider, and the resource the scope unit judges.
    pub id: &'static str,
    /// The priced lane this provider is reached on.
    pub lane: busbar_contract::ids::LaneId,
    /// The host to dial.
    pub host: &'static str,
    /// The transport the hop is made over. jev rides plain HTTP.
    pub transport: &'static str,
}

/// The decision plane.
///
/// The one field is a borrowed, immutable list. There is no cell here, no lock and no atomic: the
/// purity test asserts that by walking the type, not by trusting this sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionPlane {
    providers: &'static [DecisionProvider],
}

impl DecisionPlane {
    /// A plane with a configured provider set.
    #[must_use]
    pub const fn new(providers: &'static [DecisionProvider]) -> Self {
        Self { providers }
    }

    /// A plane with nothing configured.
    ///
    /// It answers every question the loop asks, and its answer to "where does this go" is a
    /// destination the trust unit refuses. That is the honest answer for a plane with no provider —
    /// not a panic, and not a fabricated host.
    pub const EMPTY: Self = Self::new(&[]);

    /// The configured providers, in declaration order.
    #[must_use]
    pub const fn providers(&self) -> &'static [DecisionProvider] {
        self.providers
    }
}

impl Default for DecisionPlane {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Plugin for DecisionPlane {
    fn key(&self) -> &'static str {
        <Self as busbar_contract::plane::PlaneMeta>::KEY
    }

    fn kind(&self) -> Kind {
        Kind::Plane
    }

    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
