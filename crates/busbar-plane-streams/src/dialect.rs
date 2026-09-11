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
//! NOTHING. No row is declared by this crate any more, and that is the end state the two previous
//! cuts were walking toward rather than a gap in this one. All three of this plane's dialects live
//! in crates of their own and reach this table through [`register`], which is what the direction
//! rule requires and what lets `scripts/plane-delete-test.sh` remove any one of them and get an
//! honest absence instead of a link error. [`DECLARED`] is an empty slice and is kept, rather than
//! deleted, because the next dialect to be written in-tree before it earns a crate has a place to
//! sit and a reader who can see it is meant to be temporary.
//!
//! AND THE ROW NOW CARRIES ITS OWN READER. Until the Gemini dialect was cut, this crate held two
//! functions whose whole body was `if dialect.name == <that vendor> { one codec } else { the
//! other }` — instance dispatch with a string comparison in front of it, in the crate the direction
//! rule makes the neutral party, which is the same shape the deleted `Dialect` enum was. The reader
//! and the writer are FIELDS of the row now ([`Dialect::reader`], [`Dialect::writer`]), filled by
//! whoever declared the row. `None` on either means "the SHARED IR reads this dialect's frames" —
//! a declared answer, not a missing one — and it is what every dialect whose frames ARE that IR
//! says.
//!
// The two one-shot operations are NOT rows here and are not dialects of this plane's duplex
// sessions: they are single request/response operations that leave this crate in a later pass.
// They stay where they are, named as strings by `crate::claims` alone, until that pass.
//!
//! ## And the plane no longer has a DEFAULT dialect either
//!
//! [`first`] is this crate's answer to "no dialect was negotiated". It used to be one vendor's row,
//! by name, at five call sites in [`crate::plane`] — a neutral crate whose fallback is an instance,
//! which is the same fusion an `if name ==` is and is only quieter because the vendor it named
//! happened to be written first. A POSITION is not an instance: the first row is the declaration
//! order the composition root registered in, which is the order the operator wrote, and it stays
//! correct on a node that registers a different set.
//!
//! Nothing in this module parses, writes, allocates or reads a clock. A row is data and three
//! function pointers, and the functions belong to whoever declared the row.

use std::sync::RwLock;

use busbar_contract::plane::Ingress;
use busbar_contract::unit::Ctx;
use busbar_contract::wire::{Decode, Encode, FrameCursor};
/// THE VOCABULARY THIS FACE IS WRITTEN IN, RE-EXPORTED RATHER THAN RE-REACHED.
///
/// A dialect crate implements the face in this module, so it needs the face's own types — and the
/// place to get them is the face, not the crate the face happens to borrow them from. Re-exporting
/// here is what lets a dialect crate name its PLANE for the types its plane's face is written in,
/// which is the direction rule's own shape; without it every dialect would reach past its plane into
/// the pre-split codec half for a trait its plane already knows, and the codec half would end up in
/// each dialect's dependency line for a reason that has nothing to do with reading a wire.
pub use busbar_voice_codec::ir::{
    config::SessionConfig,
    event::{IrClientEvent, IrServerEvent},
    DecodeState, DuplexReader, DuplexWriter, WireEvent, WireRef,
};

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
    /// THE READER FOR THIS DIALECT'S FRAMES, when it brings one of its own.
    ///
    /// `None` means the SHARED duplex IR reads them — which is a DECLARED answer and not a missing
    /// one: a dialect whose frames ARE that IR has no second reader to name, and saying so is how
    /// this crate knows it may use its own without asking a vendor. The field exists because the
    /// alternative, measured, was `if dialect.name == <one vendor>` in [`crate::plane`]'s own body.
    pub reader: Option<fn() -> Box<dyn DuplexReader>>,
    /// THE WRITER FOR THIS DIALECT'S FRAMES. See [`Dialect::reader`]; the same rule, the other
    /// direction.
    pub writer: Option<fn() -> Box<dyn DuplexWriter>>,
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

/// The rows this crate declares itself, in claim-declaration order.
///
/// EMPTY, and that is the shape this file was walking toward: every dialect of this plane is a
/// crate, and a neutral crate holds no instance. It is kept rather than deleted so that a dialect
/// written in-tree before it earns a crate has a place to sit where a reader can see it is meant to
/// be temporary — the two rows that sat here both left, on the two commits that cut their crates.
static DECLARED: &[&Dialect] = &[];

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

/// THE FIRST ROW THE TABLE ANSWERS FOR, or `None` on a node with no dialect registered at all.
///
/// The plane's own "no dialect was negotiated" answer, and it is a POSITION rather than a vendor.
/// Five call sites in [`crate::plane`] used to spell that answer as one particular row, by name — a
/// neutral crate defaulting to an instance, which is the same fusion an `if name ==` is and only
/// quieter because that vendor was written first. The position is the declaration order the
/// composition root registered in, which is the order the operator wrote; choosing among several
/// when more than one qualifies is not this table's job, and neither is inventing a name when none
/// was negotiated.
#[must_use]
pub fn first() -> Option<&'static Dialect> {
    if let Some(d) = DECLARED.first() {
        return Some(d);
    }
    let rows = REGISTERED.read().ok()?;
    rows.first().copied()
}

/// HOW MANY ROWS THIS CRATE DECLARES ITSELF. Zero, and it is a function rather than a comment so a
/// cell can assert it: a neutral crate that starts declaring instances again would be caught by the
/// arithmetic and not by a reviewer noticing a `static`.
#[must_use]
pub fn declared_count() -> usize {
    DECLARED.len()
}

/// How many dialects the table answers for, declared and registered together.
///
/// The `dialects` verb's own figure: what this node can actually serve, not what a constant says
/// it could.
#[must_use]
pub fn count() -> usize {
    DECLARED.len() + REGISTERED.read().map(|r| r.len()).unwrap_or(0)
}
