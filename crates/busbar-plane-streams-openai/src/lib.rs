// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPENAI REALTIME (GA) DIALECT of the streams plane — a wire's VOCABULARY, as a crate.
//!
//! ## What this crate is
//!
//! It is a DIALECT: one vendor's duplex event vocabulary, the `type`-tagged JSON roster a GA
//! Realtime socket carries in both directions. It is NOT a WIRE: every byte of framing this leg has
//! is carried by a transport crate the tree already has, and this crate names none of them — a
//! dialect that named a wire would be the plane-transport fusion one level down.
//!
//! ## Why the row is here and the reader is not
//!
//! The plane's PRE-SPLIT codec half is simultaneously THIS dialect's reader/writer and the SHARED
//! duplex IR every dialect that declares no reader of its own rides: the other duplex dialect's
//! reader maps INTO it and the carrier's µ-law transform targets it. Moving it into this crate would
//! gut the IR two sibling dialects depend on and would put this crate in their dependency path — the
//! plane fusion one level down, which the kind rules refuse. So what left the neutral plane on the
//! commit that minted this crate is exactly what made that plane an INSTANCE-NAMER: this dialect's
//! NAME and its ROW. The shared IR stays where it is, named by the plane as the IR it is, not as a
//! vendor.
//!
//! That is not a deferral dressed up. It is the measured shape of a pre-split codec half, stated in
//! `ARCHITECTURE.md` §1.1's own words ("until the pre-split `*-codec` halves are split"), and this
//! crate carries no reader precisely so that the absence is visible rather than papered over with a
//! copy.
//!
//! ## The direction, and how the plane ever sees this
//!
//! The dialect names its plane; the plane never names a dialect. This crate depends on
//! `busbar-plane-streams` and on nothing else in the workspace; nothing depends on this crate
//! except the COMPOSITION ROOT, which calls
//! `busbar_plane_streams::dialect::register(&OPENAI_REALTIME)` at boot. That is why
//! `scripts/plane-delete-test.sh` can remove this directory and get an honest "the dialect is
//! absent" from a node that still boots and still serves the other dialects, rather than a link
//! error.
//!
//! ## What the row declares, and why each field is a fact and not a branch
//!
//! Every one of the row's facts used to be a `match` arm or an `if name ==` test at the plane's own
//! altitude. They are data here: this dialect can be DIALED as an upstream, it authenticates once
//! at session open and rides the session, it does NOT meter its own uplink (the plane meters it off
//! the shared IR at the relay seam, because this dialect's frames ARE that IR), it brings no
//! envelope of its own, it locks no session configuration, and it names no reader of its own for
//! the reason the section above states.
//!
//! ## And the plane no longer defaults to this dialect either
//!
//! Five call sites in the neutral plane answered "I could not tell which dialect this is" with
//! THIS ROW, by name. A neutral crate whose fallback is one vendor is the same fusion an `if name
//! ==` is, just quieter — it is only invisible because this vendor happened to be written first.
//! They answer with `dialect::first()` now: a POSITION in the table, which is the declaration order
//! the composition root registered in, which is the order the operator wrote. The root registers
//! this dialect first, so the answer is byte-identical and the reason for it is no longer a name.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use busbar_plane_streams::dialect::Dialect;

/// This dialect's WIRE NAME — the string on the session's dialect fact, the string the `dialects`
/// verb answers, and the string the plane's claim table names this dialect by.
///
/// Declared once, here, on the row that carries it. The crate is named `…-streams-openai` because
/// the gate caps a crate name at four segments and `…-streams-openai-realtime` is five; the wire
/// name is not shortened with it.
pub const NAME: &str = "openai-realtime";

/// THE OPENAI REALTIME (GA) DIALECT ROW — PCM16 frames, tool calls, full duplex.
///
/// The row the plane's table answers `NAME` with once the composition root has registered it. It
/// was a `&'static` the NEUTRAL plane wrote until the commit that minted this crate.
pub static OPENAI_REALTIME: Dialect = Dialect {
    name: NAME,
    // This plane can DIAL an upstream speaking this dialect, not only serve clients arriving on it.
    duplex_upstream: true,
    // One credential presented at the upgrade, then frames until close.
    authenticates_from_session: true,
    // The plane meters this dialect off the shared IR at the relay seam. A dialect meters its OWN
    // uplink only when it carries an envelope whose payload is priced before a transform widens it;
    // this dialect's frames are the IR, so there is no "before".
    meters_own_uplink: false,
    // No envelope of its own: this dialect's frames are the shared duplex IR's own wire.
    envelope: None,
    // Opens on the deployment's own declared session defaults; locks nothing.
    locked_session_config: None,
    // DECLARED `None`, not left blank: this dialect's frames ARE the shared duplex IR, so the IR's
    // own reader is the reader and there is no second one to name. It is the only row of the three
    // for which `None` is a statement about the dialect rather than about a transform — the
    // carrier's frames are widened into the IR and the other duplex dialect's are mapped into it,
    // where these ARE it.
    reader: None,
    writer: None,
};
