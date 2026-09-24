//! The STREAMING plane: what bytes mean, for duplex/live sessions. Voice is ONE dialect inside this
//! plane (DECISIONS #18) — never the plane's name.
//!
//! ## What this crate is
//!
//! An ADAPTER, in the same sense `busbar-plane-llm` is one: every method of the plane kind here is a
//! thin wrapper over a codec that already exists in `busbar-voice-codec` — the OpenAI Realtime and
//! Gemini Live dialect readers/writers and the four-layer duplex/session IR they meet in
//! (`docs/design/plane4-duplex-session.md`, the four-layer IR section). No wire format for those two dialects is written
//! twice.
//!
//! Two things this crate DOES write itself, because nothing upstream provides them and the task this
//! crate exists for names them explicitly:
//!
//! * A minimal Twilio Media Streams JSON reader/writer ([`twilio`]) — `busbar-voice-codec` has no
//!   dialect codec for Twilio's own wire, and the one Twilio-shaped module in that crate
//!   (`busbar_voice_codec::topology::twilio`) is gated behind its `runtime` cargo feature, which this crate
//!   never turns on (see the crate-root dependency note below). So this crate's Twilio reader/writer
//!   is written from the wire shape alone, independently, and is NOT a copy of that module.
//! * A standard G.711 µ-law ↔ PCM16 transform ([`ulaw`]) — `busbar-voice-codec` only carries the byte-rate
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
//! THIS CRATE DOES NOT DEPEND ON `busbar-voice`, AND THE EDGE RUNS THE OTHER WAY. Measured with
//! `cargo tree -p busbar-plane-streaming --edges normal --depth 1`, this crate's whole direct
//! closure is `busbar-contract` + `busbar-voice-codec` + `serde_json` + `bytes` + `async-trait`
//! (a proc-macro). It is `busbar-voice` that names THIS crate (`crates/busbar-voice/Cargo.toml`),
//! not the reverse — so there is no `default-features = false` on a `busbar-voice` line here,
//! because there is no such line at all.
//!
//! `busbar-voice`'s own plane machinery (`PLANE_DECL`, `mount`, `runtime`, `topology`) is built
//! against a different, older plane architecture (`busbar_kernel::plane::registry::PlaneDecl`,
//! the same shape `busbar-mcp`/`busbar-a2a` use) and is gated behind busbar-voice's `runtime` cargo
//! feature. None of that machinery, and none of the async runtime it would pull in (`tokio`,
//! `futures`, `hyper`), is reachable from here — the closure above measures zero of them.
//!
//! What this crate DOES use is `busbar_voice_codec::ir` — the plane-4 duplex/session intermediate
//! representation and both dialect codecs — which is unconditional in `busbar-voice-codec`'s own
//! manifest (that crate's one feature, `runtime`, is not in `default` and this crate never turns it
//! on) and is pure, sync, and free of any async surface.
//!
//! ## What it holds across calls
//!
//! Nothing of its own. The plane value itself ([`StreamingPlane`]) is immutable and carries only its
//! configured upstream list. What a session needs across frames — the codec's per-connection state,
//! the negotiated dialect, the counters this crate derives itself (`audio_seconds_in`, `tool_calls`),
//! and the one pending IR event a two-step ingress/egress or decode/encode pair needs to hand across
//! — lives in the kernel-held [`busbar_contract::plane::PlaneSessionState`], via
//! [`session::VoiceSessionState`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
pub mod governed;
pub mod meta;
pub mod oneshot;
pub mod plane;
pub mod register;
pub mod session;
pub mod tools;
pub mod twilio;
pub mod ulaw;

#[cfg(test)]
mod tests;

use busbar_contract::ids::LaneId;
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

/// The dialect roster this plane speaks, re-exported so a caller names it through the STREAMING plane it
/// registered. The live realtime voice dialect appears here as [`Dialect::OpenaiRealtime`] /
/// [`Dialect::GeminiLive`] — one dialect among the five, never the plane's name.
pub use claims::Dialect;

/// The composition-root wiring shape and the plane value it registers (the plane side of S1/S4).
pub use register::{plane_for_root, CAP_KEY};

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

/// The streaming plane. Voice is one dialect inside it (DECISIONS #18), not its name.
///
/// The one field is a borrowed, immutable list: no cell, no lock, no atomic. The purity test in
/// `tests::purity` asserts that by walking the type rather than by trusting this sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamingPlane {
    upstreams: &'static [Upstream],
}

impl StreamingPlane {
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

impl Default for StreamingPlane {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Plugin for StreamingPlane {
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
