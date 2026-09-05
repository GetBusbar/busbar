//! The LLM plane: what bytes mean, for six dialects of one protocol.
//!
//! ## What this crate is
//!
//! An ADAPTER. Every method of the plane kind here is a few lines over a codec that already exists:
//! the dialect readers and writers, the intermediate representation they meet in, and the
//! dialect-shaped error envelopes. No wire format is written twice, because a wire format written
//! twice is two wire formats that will disagree, and the one that disagrees quietly is the one that
//! reaches a customer.
//!
//! ## What this crate is not
//!
//! It holds no governance, no breaker, no hook seat and no arithmetic over a metered quantity.
//! Those are units, and a unit is on the far side of the kernel from a plane. The metering method
//! here returns LOCATORS — the class, where the number is, and the number the codec already read —
//! and never a price, never a hold and never a decision. The routing method returns a plan and
//! never a connection. Nothing in this crate opens a socket, reads a file or reads a clock other
//! than the one the context hands it.
//!
//! ## What it holds across calls
//!
//! Nothing. The plane is a value with no interior mutability, asserted by a test rather than by a
//! comment. What state a streamed answer needs lives in the kernel-held per-connection codec state,
//! which the kernel hands in and takes back.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
pub mod codec;
pub mod dialect;
pub mod meta;

use busbar_contract::ids::LaneId;
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

/// One configured upstream this plane may name.
///
/// Every string is borrowed for the life of the program, because a plane's declarations are read at
/// registration and sealed. Configured names reach here through the seam that says so:
/// [`busbar_contract::ids::Registration`]. The composition root builds one at boot, interns every
/// config-derived key through it exactly once, and hands over names that outlive it — so nothing
/// after registration can vary them, and the memory the names occupy is a fixed term rather than
/// one that grows with traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Upstream {
    /// The priced lane this upstream is reached on.
    pub lane: LaneId,
    /// The host to dial.
    pub host: &'static str,
    /// Which of the six dialects the upstream speaks.
    pub dialect: &'static str,
    /// The model name the request is rewritten to carry.
    pub model: &'static str,
}

/// The LLM plane.
///
/// The one field is a borrowed, immutable list. There is no cell here, no lock and no atomic: the
/// purity test asserts that by walking the type, not by trusting this sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LlmPlane {
    upstreams: &'static [Upstream],
}

impl LlmPlane {
    /// A plane with a configured upstream set.
    #[must_use]
    pub const fn new(upstreams: &'static [Upstream]) -> Self {
        Self { upstreams }
    }

    /// A plane with nothing configured.
    ///
    /// It answers every question the loop asks, and its answer to "where does this go" is a
    /// destination the trust unit refuses. That is the honest answer for a plane with no upstream —
    /// not a panic, and not a fabricated host.
    pub const EMPTY: Self = Self::new(&[]);

    /// The configured upstreams, in declaration order.
    #[must_use]
    pub const fn upstreams(&self) -> &'static [Upstream] {
        self.upstreams
    }

    /// The upstream a unit of this operation class should be offered, if any is configured.
    ///
    /// First match wins, which is the declaration order the operator wrote. Choosing among several
    /// is the trust unit's and the ranking hooks' business, not this plane's: a plane that picked a
    /// winner would be making a decision, and a plane makes none.
    #[must_use]
    pub fn first_upstream(&self) -> Option<&'static Upstream> {
        self.upstreams.first()
    }
}

impl Default for LlmPlane {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Plugin for LlmPlane {
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
