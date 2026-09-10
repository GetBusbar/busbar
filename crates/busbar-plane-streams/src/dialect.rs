// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIALECT FACE OF THIS PLANE, AND THE REGISTRY IT IS LOOKED UP IN.
//!
//! ## Why this module exists
//!
//! A dialect is a PLUGIN KIND. `docs/design/ARCHITECTURE.md`'s plugin-kind section names it, and
//! the kind rule the owner stated on 2026-09-10 is the whole reason this module replaces what was
//! here before: **a kind-neutral crate knows KINDS and FACES, never INSTANCES.** Relative to the
//! dialect kind this crate is the neutral party, and until this commit it was `if x == this vendor
//! else if x == that one` at its own altitude — seven `match` arms on a closed `Dialect` enum in
//! [`crate::plane`], three more in [`crate::claims`], and one in the composition root's own tests.
//! An enum variant per vendor is instance dispatch with a type system in front of it.
//!
//! The replacement is the shape the sibling plane one crate over already uses: a TABLE OF DATA ROWS
//! KEYED BY `&'static str`, with [`dialect`] as the only way in. There is no enum and there is no
//! `match` on a dialect anywhere in this crate any more. What the seven arms actually differed on
//! is four fields — whether the dialect brings its own [`Envelope`], whether it meters its own
//! uplink, what session configuration it locks, and whether it can be dialed as an upstream — so
//! those four are what a row carries.
//!
//! ## The direction rule, and why the registry is not a dependency
//!
//! `xtask/src/gates/kind_isolation.rs` fixes the direction: *"the dialect names its plane; the
//! plane never names a dialect… the plane-to-dialect edge never can be."* So [`register`] is a
//! runtime seam, not a Cargo edge: the COMPOSITION ROOT links both crates and hands this crate the
//! rows. That is the same seam the plane/transport registry is one level up, and it is what lets
//! `scripts/plane-delete-test.sh` physically remove a dialect crate and get an honest "absent"
//! instead of a link error.
//!
//! ## What is in the table today, and what is deliberately not
//!
//! The three duplex dialects of this plane are rows here. Two of them are still declared BY this
//! crate because no crate of their own exists yet; that is a stated remainder, not a design — each
//! becomes its own dialect crate and its row leaves this file the way the carrier's does, by
//! [`register`].
//!
// The two one-shot operations are NOT rows here and are not dialects of this plane's duplex
// sessions: they are single request/response operations that leave this crate in a later pass.
// They stay where they are, named as strings by `crate::claims` alone, until that pass.
//!
//! Nothing in this module parses, writes, allocates or reads a clock. A row is data and three
//! function pointers, and the functions belong to whoever declared the row.

use std::sync::RwLock;

use busbar_contract::plane::Ingress;
use busbar_contract::unit::Ctx;
use busbar_contract::wire::{Decode, Encode, FrameCursor};
use busbar_voice_codec::ir::{config::SessionConfig, event::IrClientEvent};

use crate::session::VoiceSessionState;

/// A dialect that carries its OWN frame envelope, rather than riding the shared duplex IR codec.
///
/// Three functions, and they are exactly the three places a carrier's own JSON envelope and its own
/// sample format are the difference: reading an arriving frame, relaying one onward, and rendering
/// one downlink audio frame back in the client's shape. A dialect whose frames the shared codec
/// already reads declares no envelope at all ([`Dialect::envelope`] is `None`) and none of these is
/// ever reached for it.
pub struct Envelope {
    /// Read one arriving frame of this dialect's wire into an [`Ingress`] answer.
    ///
    /// The session state is this dialect's own to advance — the identity its envelope binds at
    /// start ([`VoiceSessionState::envelope_id`]), the turn it opens or relays onto.
    pub decode_ingress: for<'u> fn(
        &mut FrameCursor<'u>,
        &mut VoiceSessionState,
        &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode>,
    /// Turn one arriving frame into the client event to relay upstream, or `None` for a frame that
    /// carries nothing to relay (a lifecycle event, or one this reader does not model).
    ///
    /// A dialect that declares [`Dialect::meters_own_uplink`] takes its uplink meter HERE, from the
    /// raw carrier payload before any transform widens it.
    pub relay_ingress: fn(&[u8], &mut VoiceSessionState) -> Result<Option<IrClientEvent>, Encode>,
    /// Render one downlink audio frame into the buffer the session holds
    /// ([`VoiceSessionState::render_buf`]), in this dialect's own envelope and sample format.
    ///
    /// It fills a buffer rather than returning one because a call sends fifty downlink frames a
    /// second and the buffer is held across them: a returned `Vec` would be fifty allocations a
    /// second the held buffer exists to remove.
    pub render_downlink_audio: fn(&mut VoiceSessionState, &[u8]),
}

/// ONE DIALECT OF THIS PLANE, as data.
///
/// Every field is a fact the loop asks about, and none of them is a vendor's name in this plane's
/// code: the name is a `&'static str` the row's OWNER wrote, and this crate only ever compares it.
pub struct Dialect {
    /// The dialect's registry name — the string on the [`crate::meta::FACT_DIALECT`] session fact,
    /// the string the `dialects` verb answers, and the string a dialect crate is named for.
    pub name: &'static str,
    /// Whether this plane can DIAL an upstream speaking this dialect, as opposed to only serving
    /// clients that arrive on it.
    pub duplex_upstream: bool,
    /// Whether a unit on this dialect authenticates once at session open and rides the session,
    /// rather than presenting a credential on every unit.
    pub authenticates_from_session: bool,
    /// THE UPLINK-METERING RULE: whether this dialect counts its own admitted audio.
    ///
    /// A dialect with its own envelope prices the CARRIER's payload, before any transform — what
    /// the caller spoke is that dialect's own format on its own wire. Every other dialect is
    /// metered by the plane, off the shared IR, at the relay seam.
    pub meters_own_uplink: bool,
    /// This dialect's own frame envelope, when it has one.
    pub envelope: Option<&'static Envelope>,
    /// The session configuration this dialect LOCKS, when it locks one.
    ///
    /// `None` means the dialect opens on the deployment's own declared defaults. A carrier leg that
    /// is µ-law end to end locks its posture here and nothing may resample it.
    pub locked_session_config: Option<fn() -> SessionConfig>,
}

impl PartialEq for Dialect {
    /// Two rows are the same dialect when they answer to the same name. The registry admits one row
    /// per name, so name equality IS row identity.
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Dialect {}

impl core::fmt::Debug for Dialect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Dialect").field(&self.name).finish()
    }
}

/// The OpenAI Realtime dialect's name.
pub const NAME_OPENAI_REALTIME: &str = "openai-realtime";

/// The Gemini Live dialect's name.
pub const NAME_GEMINI_LIVE: &str = "gemini-live";

/// The OpenAI Realtime (GA) dialect — PCM16 frames, tool calls, full duplex.
///
/// Declared by this crate because no dialect crate of its own exists yet. See the module header.
pub static OPENAI_REALTIME: Dialect = Dialect {
    name: NAME_OPENAI_REALTIME,
    duplex_upstream: true,
    authenticates_from_session: true,
    meters_own_uplink: false,
    envelope: None,
    locked_session_config: None,
};

/// The Google Gemini Live (`BidiGenerateContent`) dialect — JSON frames, tool calls.
///
/// Declared by this crate because no dialect crate of its own exists yet. See the module header.
pub static GEMINI_LIVE: Dialect = Dialect {
    name: NAME_GEMINI_LIVE,
    duplex_upstream: true,
    authenticates_from_session: true,
    meters_own_uplink: false,
    envelope: None,
    locked_session_config: None,
};

/// The rows this crate declares itself, in claim-declaration order.
static DECLARED: &[&Dialect] = &[
    &OPENAI_REALTIME,
    &GEMINI_LIVE,
    &crate::twilio::TWILIO_MEDIA_STREAMS,
];

/// The rows a composition root registered at boot, in registration order.
///
/// A lock and not a `OnceLock<Vec<_>>` because registration is one call per dialect and the root
/// makes them one at a time; reads are lock-free-ish and never allocate.
static REGISTERED: RwLock<Vec<&'static Dialect>> = RwLock::new(Vec::new());

/// REGISTER ONE DIALECT. The composition root's call, and the only way a row this crate did not
/// write itself reaches the table.
///
/// Idempotent by name: registering the same name twice keeps the first row, so a root that wires a
/// dialect twice gets one table entry rather than a shadowed second opinion about a wire.
pub fn register(d: &'static Dialect) {
    let Ok(mut rows) = REGISTERED.write() else {
        return;
    };
    if DECLARED.iter().any(|r| r.name == d.name) || rows.iter().any(|r| r.name == d.name) {
        return;
    }
    rows.push(d);
}

/// THE ROW FOR ONE DIALECT, BY NAME — the only way into the table.
///
/// The declared rows first, then the registered ones, which is the order they were minted in.
#[must_use]
pub fn dialect(name: &str) -> Option<&'static Dialect> {
    if let Some(d) = DECLARED.iter().find(|d| d.name == name) {
        return Some(d);
    }
    let rows = REGISTERED.read().ok()?;
    rows.iter().find(|d| d.name == name).copied()
}

/// How many dialects the table answers for, declared and registered together.
///
/// The `dialects` verb's own figure: what this node can actually serve, not what a constant says
/// it could.
#[must_use]
pub fn count() -> usize {
    DECLARED.len() + REGISTERED.read().map(|r| r.len()).unwrap_or(0)
}
