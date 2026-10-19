//! The LLM plane: what bytes mean, for six dialects of one protocol.
//!
//! ## What this crate is
//!
//! An ADAPTER, served through ONE door: its memory-ABI door ([`plane_door`]), which drives the sans-I/O
//! exchange steps in [`exchange`] (arrive, attempt, reply, refuse) over a codec that already exists:
//! the dialect readers and writers, the intermediate representation they meet in, and the
//! dialect-shaped error envelopes. No wire format is written twice, because a wire format written
//! twice is two wire formats that will disagree, and the one that disagrees quietly is the one that
//! reaches a customer.
//!
//! ## What this crate is not
//!
//! It holds no governance, no breaker, no hook seat and no arithmetic over a metered quantity.
//! Those are units, and a unit is on the far side of the kernel from a plane. What it reports of a
//! metered quantity is the far end's own counts, by class ([`plane_door::counts`]) — never a price,
//! never a hold and never a decision. Nothing in this crate opens a socket, reads a file or reads a
//! clock other than the one its host hands it.
//!
//! ## What it holds across calls
//!
//! Only the door's ABI-mandated state: the shaping of its current refresh generation and the units
//! in flight across their calls, named exactly by the purity test. The declaration type
//! ([`LlmPlane`]) holds nothing at all.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
// `#![deny(missing_docs)]` above is a rule this crate holds itself to; the `codec` module was not
// written under it and is exempt, scoped to exactly this module.
#[allow(missing_docs)]
pub mod codec;
pub mod dialect;
pub mod exchange;
pub mod meta;
pub mod plane_door;
pub mod refusal;

/// THE PLANE'S DECLARED METADATA (`declares.json`): the `declares` section its signed tarball carries
/// and the one the composition root reads for its linked door (`linked-declares`), one file for both
/// — the transport scheme it needs and every code its catalog holds
/// ([`codec::diagnostics::DIAGNOSTICS`]; a test holds the two equal), so the host's catalogue learns
/// this plane's codes from its door's declaration whichever way the plane came in.
pub const DECLARES: &str = include_str!("../declares.json");

use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

/// The LLM plane's DECLARATION: the type its compile-time words ([`busbar_contract::plane::PlaneMeta`],
/// in [`meta`]) are spoken through, and the registry identity ([`Plugin`]) they name.
///
/// It holds nothing. The plane is served through its memory-ABI door ([`plane_door`]) alone; the
/// trait-object surface this type once also implemented was never dispatched and is deleted
/// ("A capability that is never constructed does not ship"), so what remains here is the one set of
/// declarations the door reads (its key, its operation classes and its meter classes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LlmPlane;

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
