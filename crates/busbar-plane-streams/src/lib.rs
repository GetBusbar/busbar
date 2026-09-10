//! The voice plane: what bytes mean, for duplex/live-voice sessions.
//!
//! ## What this crate is
//!
//! An ADAPTER, in the same sense `busbar-plane-llm` is one: every method of the plane kind here is a
//! thin wrapper over a codec that already exists in `busbar-voice` — the OpenAI Realtime and Gemini
//! Live dialect readers/writers and the four-layer duplex/session IR they meet in
//! (`docs/design/plane4-duplex-session.md`, the four-layer IR section). No wire format for those two dialects is written
//! twice.
//!
//! It writes NO wire shape of its own any more. The Twilio Media Streams envelope and the G.711
//! µ-law transform used to live here, as `twilio.rs` and `ulaw.rs` plus their cells; they are one
//! carrier's vocabulary and one carrier's sample format, which is the DIALECT kind, and they left
//! for `busbar-plane-streams-twilio` on the commit that minted it. What stays is the
//! FACE they implement ([`dialect`]) and the registry the composition root fills.
//!
//! ## What this crate is not
//!
//! It holds no governance, no breaker, no hook seat and no arithmetic over a metered quantity. Those
//! are units, on the far side of the kernel from a plane. The metering method here returns
//! LOCATORS — the class and the quantity the codec (or this crate's own bookkeeping) already
//! computed — never a price. The routing method returns a plan, never a connection. Nothing here
//! opens a socket, reads a file, or reads a clock other than the one the context hands it.
//!
//! ## The dependency seam, stated honestly
//!
//! `busbar-voice`'s own plane machinery (`PLANE_DECL`, `mount`, `runtime`, `topology`) is built
//! against a different, older plane architecture (`busbar_substrate::plane::registry::PlaneDecl`,
//! the same shape `busbar-mcp`/`busbar-a2a` use) and is gated behind busbar-voice's `runtime` cargo
//! feature. This crate depends on `busbar-voice` with `default-features = false` and never turns
//! `runtime` on, so none of that machinery, and none of the async runtime it would pull in
//! (`tokio`, `async-trait`, `futures`), is ever part of this crate's build. What this crate DOES use
//! is `busbar_voice_codec::ir` — the plane-4 duplex/session intermediate representation and both dialect
//! codecs — which is unconditional in `busbar-voice`'s own manifest (no feature gate at all) and is
//! pure, sync, and free of any async surface. `cargo tree -p busbar-plane-streams` is the proof.
//!
//! ## What it holds across calls
//!
//! Nothing of its own. The plane value itself ([`VoicePlane`]) is immutable and carries only its
//! configured upstream list. What a session needs across frames — the codec's per-connection state,
//! the negotiated dialect, the counters this crate derives itself (`audio_seconds_in`, `tool_calls`),
//! and the one pending IR event a two-step ingress/egress or decode/encode pair needs to hand across
//! — lives in the kernel-held [`busbar_contract::plane::PlaneSessionState`], via
//! [`session::VoiceSessionState`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
pub mod dialect;
pub mod governed;
pub mod meta;
pub mod plane;
pub mod session;
pub mod surface;
pub mod tools;

#[cfg(test)]
mod tests;

use busbar_contract::ids::LaneId;
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};
use dialect::Dialect;

/// One configured upstream this plane may dial or pair a claim against.
///
/// Borrowed for the life of the program, the same way `busbar-plane-llm::Upstream` is: the
/// composition root interns every config-derived key once through
/// [`busbar_contract::ids::Registration`] and hands over names that outlive it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Upstream {
    /// The priced lane this upstream is reached on.
    pub lane: LaneId,
    /// The host to dial.
    pub host: &'static str,
    /// Which dialect the upstream speaks — a row of [`dialect`]'s table, never a variant. Always
    /// one whose [`Dialect::duplex_upstream`] is true: the carrier is ingress only, and a session
    /// that arrives on it is routed to one of these upstreams, never dialed as one.
    pub dialect: &'static Dialect,
}

/// The voice plane.
///
/// The one field is a borrowed, immutable list: no cell, no lock, no atomic. The purity test in
/// `tests::purity` asserts that by walking the type rather than by trusting this sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoicePlane {
    upstreams: &'static [Upstream],
}

impl VoicePlane {
    /// A plane with a configured upstream set.
    #[must_use]
    pub const fn new(upstreams: &'static [Upstream]) -> Self {
        Self { upstreams }
    }

    /// A plane with nothing configured.
    ///
    /// It answers every question the loop asks; its answer to "where does this go" is a destination
    /// the trust unit refuses. That is the honest answer for a plane with no upstream configured —
    /// not a panic, and not a fabricated host.
    pub const EMPTY: Self = Self::new(&[]);

    /// The configured upstreams, in declaration order.
    #[must_use]
    pub const fn upstreams(&self) -> &'static [Upstream] {
        self.upstreams
    }

    /// The first configured upstream that speaks a given dialect.
    ///
    /// First match wins, the declaration order the operator wrote. Choosing among several when more
    /// than one qualifies is the trust unit's and the ranking hooks' business, not this plane's.
    #[must_use]
    pub fn upstream_for_dialect(&self, dialect: &Dialect) -> Option<&'static Upstream> {
        self.upstreams.iter().find(|u| u.dialect == dialect)
    }
}

impl Default for VoicePlane {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Plugin for VoicePlane {
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
