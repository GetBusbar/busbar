//! The MCP plane: what bytes mean, for a protocol that names its operation in the body.
//!
//! ## What this crate is
//!
//! An ADAPTER. Every method of the plane kind here is a few lines over a codec that already exists:
//! the envelope shape, the method vocabulary, the error code table, the result discriminators and
//! the record kinds. No wire format is written twice, because a wire format written twice is two
//! wire formats that will disagree, and the one that disagrees quietly is the one that reaches a
//! customer.
//!
//! ## What this crate is not
//!
//! It holds no governance, no breaker, no hook seat, no approval decision and no arithmetic over a
//! metered quantity. Those are units, and a unit is on the far side of the kernel from a plane. The
//! metering method here returns LOCATORS — the class, where the number is, and the number the codec
//! already read — and never a price, never a hold and never a decision. The routing method returns a
//! plan and never a connection. Nothing in this crate opens a socket, reads a file or reads a clock
//! other than the one the context hands it.
//!
//! ## What it holds across calls
//!
//! Nothing. The plane is a value with no interior mutability, asserted by a test rather than by a
//! comment. What state a held stream needs lives in the kernel-held per-connection codec state,
//! which the kernel hands in and takes back.
//!
//! ## Where this adapter had to write something down twice, and why
//!
//! The codec crate holds the method table, the error codes and the result discriminators, and it
//! holds all of them where only its own crate can see them; the envelope reader and writer live one
//! crate further away still, on the kernel side, where a plane may not name them at all. This crate
//! may not widen any of that. So those things are written once more here — and each of them is
//! PINNED by a test that reads the codec's own source or the conformance battery's own tables. A
//! copy that is checked is not a second opinion. A copy that is not checked is, and there are none
//! of those here.
//!
//! The full list of places the contract did not fit this protocol is in the notes each module
//! carries: the mount path that is configured where a claim must be a constant, the correlation type
//! that cannot hold a named identifier, the arena that cannot hold a span table, and the
//! introspection verb that takes no argument.

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

/// One registered server this plane may name.
///
/// Every string is borrowed for the life of the program, because a plane's declarations are read at
/// registration and sealed. Configured names reach here the way the design says a dynamically
/// declared key reaches a registry: the composition root reads the configuration once, hands over
/// names that outlive it, and nothing after that can vary them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Server {
    /// The name the operator gave this server, and the resource the scope unit judges.
    pub id: &'static str,
    /// The priced lane this server is reached on.
    pub lane: LaneId,
    /// The host to dial, or the empty string for a server this node launches itself.
    pub host: &'static str,
    /// Which of the three transports the hop is made over.
    pub transport: &'static str,
}

/// The MCP plane.
///
/// The one field is a borrowed, immutable list. There is no cell here, no lock and no atomic: the
/// purity test asserts that by walking the type, not by trusting this sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McpPlane {
    servers: &'static [Server],
}

impl McpPlane {
    /// A plane with a registered server set.
    #[must_use]
    pub const fn new(servers: &'static [Server]) -> Self {
        Self { servers }
    }

    /// A plane with nothing registered.
    ///
    /// It answers every question the loop asks, and its answer to "where does this go" is a
    /// destination the trust unit refuses. That is the honest answer for a plane with no server —
    /// not a panic, and not a fabricated host.
    pub const EMPTY: Self = Self::new(&[]);

    /// The registered servers, in declaration order.
    #[must_use]
    pub const fn servers(&self) -> &'static [Server] {
        self.servers
    }
}

impl Default for McpPlane {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Plugin for McpPlane {
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
