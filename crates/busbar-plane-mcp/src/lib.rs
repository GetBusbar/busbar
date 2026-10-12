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

/// The session revisions raised into, and lowered out of, the one dispatch.
pub mod adapt;
pub mod answer;
/// The argument half of the dispatch SSRF guard: a schema-aware walk judging every URL and host a
/// call's arguments carry.
pub mod argguard;
pub mod ask;
pub mod call;
pub mod catalogue;
pub mod checks;
pub mod client;
pub mod codec;
pub mod diagnostics;
pub mod door;
pub mod endpoint;
pub mod framing;
pub mod identity;
pub mod jsonrpc;
/// The line carrier's meanings: one JSON-RPC message per line, each its own unit.
pub mod line;
pub mod tool_arrival;
pub mod tool_claims;
pub mod tool_door;
pub mod tool_facts;
pub mod tool_meta;
pub mod tool_ops;
/// The `transport: stdio` servers: one long-lived child per server, its messages correlated by id.
pub mod tool_program;
pub mod tool_scope;
/// SEP-2663, the tasks extension: a task's state, shapes, sweep and durable rows.
pub mod tool_tasks;
pub mod tools_config;

/// THE PLANE'S DECLARED METADATA (`declares.json`): its manifest `declares` section, the static
/// statement the root reads for this linked plugin as it reads every default-linked plugin's (the
/// codes its catalog holds, [`diagnostics::DIAGNOSTICS`]; a test holds the two equal) and its
/// breaker fact (ARCHITECT Q4): one transient failure below the trip threshold never benches a
/// member, the 1.5.5 MCP client leg's posture.
pub const DECLARES: &str = include_str!("declares.json");
/// THE DOOR CRATE'S CONVENTIONAL PATH, `<crate>::plane_door::door`: what a test-linked `door:` row's
/// generated table names (the build scripts of the crates that test-link this door). The door
/// itself is [`tool_door::door`].
pub mod plane_door {
    pub use crate::tool_door::door;
}
pub mod reads;
pub mod record;
/// The dated revisions of the one MCP dialect, and their negotiation.
pub mod revision;
pub mod sanitize;
/// The sealed `requestState`: busbar's own ask state, signed by the host.
pub mod seal;
/// `subscriptions/listen`, as a state machine any carrier drives.
pub mod subscribe;
pub mod tool_records;
/// Bounded, owner-bound session state for the session revisions.
pub mod tool_sessions;
/// The trust surface: approvals, sightings, the derived state and the admin views.
pub mod trust;

/// THE REGISTRY KEY MCP IS KNOWN BY, in the protocol registry and in the plane registry alike.
///
/// Named ONCE, here, because three declarations read it and all three must agree: this crate's
/// [`plane`] kind `KEY`, the engine's `PLANE_DECLARATION.key`, and the engine's `ProtocolDecl.name`. It
/// lives on the PLANE side because a plane is the thing being named — a key spelled engine-side
/// would be a key the plane could only copy, which is how two answers to "what is this plane
/// called" start to differ.
pub const PLANE_KEY: &str = "mcp";

use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

/// The MCP plane.
///
/// It carries no field: it is the type the plane's declarations (`PlaneMeta`) and its identity
/// (`Plugin`) hang on, and the served door reads those. There is no cell here, no lock and no
/// atomic: the purity test asserts that by walking the source, not by trusting this sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McpPlane;

impl McpPlane {
    /// The plane. Nothing varies per instance, so there is one value of it.
    pub const EMPTY: Self = Self;
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
