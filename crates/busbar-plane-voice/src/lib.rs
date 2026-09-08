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
//! Two things this crate DOES write itself, because nothing upstream provides them and the task this
//! crate exists for names them explicitly:
//!
//! * A minimal Twilio Media Streams JSON reader/writer ([`twilio`]) — `busbar-voice` has no dialect
//!   codec for Twilio's own wire, and the one Twilio-shaped module in that crate
//!   (`busbar_voice_codec::topology::twilio`) is gated behind its `runtime` cargo feature, which this crate
//!   never turns on (see the crate-root dependency note below). So this crate's Twilio reader/writer
//!   is written from the wire shape alone, independently, and is NOT a copy of that module.
//! * A standard G.711 µ-law ↔ PCM16 transform ([`ulaw`]) — `busbar-voice` only carries the byte-rate
//!   bookkeeping for the format (`busbar_voice_codec::ir::media::AudoFormat`), not an actual sample
//!   transcoder; its own doc comments call the transcode an unimplemented "seam...armed only when a
//!   lane declares it." This crate is the lane that declares it.
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
//! This crate names FIVE direct dependencies and no others: `busbar-contract`, `busbar-voice-codec`,
//! `serde_json`, `bytes` and `async-trait`. `tests/dependency_seam.rs` is the top level of
//! `cargo tree -p busbar-plane-voice`, pinned as a set — this paragraph stops being true the moment
//! that test stops passing, which is the arrangement the paragraph is worth having under.
//!
//! Three things that arrangement corrects, because this header stated all three the other way round
//! and none of them was checked:
//!
//! * **There is no `busbar-voice` edge.** `busbar-voice`'s own plane machinery (`PLANE_DECL`,
//!   `mount`, `runtime`, `topology`) is built against a different, older plane architecture
//!   (`busbar_substrate::plane::registry::PlaneDecl`) and would drag an async runtime behind it. This
//!   crate does not depend on it at all, with or without features: what it names is
//!   `busbar-voice-codec` — the plane-4 duplex/session IR and both dialect codecs, split out of the
//!   plugin precisely so a PURE kind could name them, and pure, sync and free of any async surface.
//!   No dependency line here carries a `default-features` flag, because none needs one.
//! * **The edge runs the OTHER WAY.** `crates/busbar-voice/src/runtime/session.rs` reads
//!   `use busbar_plane_voice::governed::GovernedSession;` — the retiring crate depends on this
//!   plane. That inversion is what lets the plane stay pure while the legacy runtime consumes its
//!   ports ([`governed`], [`tools`]); a plane crate that named its own composition root would be the
//!   actual violation.
//! * **`async-trait` IS part of this crate's build.** It is a direct, non-dev dependency, for
//!   [`tools`]'s `ToolExecutor` port. It is a proc macro that expands to boxed futures and pulls no
//!   I/O into the closure, and it sits on the reviewed allow-list a pure kind may name — which is
//!   the honest defence of it, rather than a claim that it is not here.
//!
//! ## What it holds across calls
//!
//! Nothing of its own. The plane value itself ([`VoicePlane`]) is immutable and carries only its
//! configured upstream list. What a session needs across frames — the codec's per-connection state,
//! the negotiated dialect, the counters this crate derives itself (`audio_seconds_in`, `tool_calls`)
//! and which turn they belong to — lives in the kernel-held
//! [`busbar_contract::plane::PlaneSessionState`], via [`session::VoiceSessionState`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
pub mod governed;
pub mod meta;
pub mod oneshot;
pub mod plane;
pub mod session;
pub mod tools;
pub mod twilio;
pub mod ulaw;

#[cfg(test)]
mod tests;

use busbar_contract::ids::LaneId;
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};
use claims::Dialect;

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
    /// Which dialect the upstream speaks. Always one of the two duplex dialects this plane can
    /// DIAL — `openai-realtime` or `gemini-live`. Twilio and the one-shot dialects are ingress-only
    /// claims; a unit that arrives on them is routed to one of these two upstreams, never dialed as
    /// one itself.
    pub dialect: Dialect,
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
    pub fn upstream_for_dialect(&self, dialect: Dialect) -> Option<&'static Upstream> {
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
