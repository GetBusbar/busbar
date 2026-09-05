//! The A2A plane: what bytes mean, for one protocol spelled two ways.
//!
//! ## What this crate is
//!
//! An ADAPTER. Every method of the plane kind here is a few lines over a codec that already exists:
//! the envelope shape, the method vocabulary, the error code table and the record kinds. No wire
//! format is written twice, because a wire format written twice is two wire formats that will
//! disagree, and the one that disagrees quietly is the one that reaches a customer.
//!
//! ## What this crate is not
//!
//! It holds no governance, no breaker, no hook seat, no signing key and no arithmetic over a metered
//! quantity. Those are units, and a unit is on the far side of the kernel from a plane. The metering
//! method here returns LOCATORS — the class, where the number is, and the number the codec already
//! read — and never a price, never a hold and never a decision. The routing method returns a plan
//! and never a connection. Nothing in this crate opens a socket, reads a file or reads a clock other
//! than the one the context hands it.
//!
//! ## What it holds across calls
//!
//! Nothing. The plane is a value with no interior mutability, asserted by a test rather than by a
//! comment. What state a streamed answer needs lives in the kernel-held per-connection codec state,
//! which the kernel hands in and takes back.
//!
//! ## Where this adapter had to write something down twice, and why
//!
//! The codec crate holds the envelope reader, the error table and the method vocabulary, and it
//! holds all three where only its own crate can see them. This crate may not widen that visibility.
//! So three things are written once more here — the method table, the error code table, and the
//! envelope's member shape — and each of them is PINNED by a test that reads the codec's own source
//! or the conformance rig's own tables. A copy that is checked is not a second opinion. A copy that
//! is not checked is, and there are none of those here.
//!
//! The full list of places the contract did not fit this protocol is in the notes each module
//! carries: the correlation type that cannot hold a named identifier, the arena that cannot hold a
//! span table, the introspection verb that takes no argument, and the single byte class that cannot
//! separate what was sent from what came back.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
pub mod facts;
pub mod jsonrpc;
pub mod meta;
pub mod ops;
pub mod plane;
pub mod records;
pub mod spans;

use busbar_contract::ids::LaneId;
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

/// One configured agent this plane may name.
///
/// Every string is borrowed for the life of the program, because a plane's declarations are read at
/// registration and sealed. Configured names reach here through the seam that says so:
/// [`busbar_contract::ids::Registration`]. The composition root builds one at boot, interns every
/// config-derived key through it exactly once, and hands over names that outlive it — so nothing
/// after registration can vary them, and the memory the names occupy is a fixed term rather than
/// one that grows with traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Agent {
    /// The name the operator gave this agent, and the resource the scope unit judges.
    pub id: &'static str,
    /// The priced lane this agent is reached on.
    pub lane: LaneId,
    /// The host to dial.
    pub host: &'static str,
    /// Which of the two transports the hop is made over.
    pub transport: &'static str,
}

/// The A2A plane.
///
/// The one field is a borrowed, immutable list. There is no cell here, no lock and no atomic: the
/// purity test asserts that by walking the type, not by trusting this sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A2aPlane {
    agents: &'static [Agent],
}

impl A2aPlane {
    /// A plane with a configured agent set.
    #[must_use]
    pub const fn new(agents: &'static [Agent]) -> Self {
        Self { agents }
    }

    /// A plane with nothing configured.
    ///
    /// It answers every question the loop asks, and its answer to "where does this go" is a
    /// destination the trust unit refuses. That is the honest answer for a plane with no agent — not
    /// a panic, and not a fabricated host.
    pub const EMPTY: Self = Self::new(&[]);

    /// The configured agents, in declaration order.
    #[must_use]
    pub const fn agents(&self) -> &'static [Agent] {
        self.agents
    }
}

impl Default for A2aPlane {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Plugin for A2aPlane {
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
