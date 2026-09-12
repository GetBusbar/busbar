// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GEMINI LIVE DIALECT of the streams plane — a wire's VOCABULARY, as a crate.
//!
//! ## What this crate is
//!
//! It is a DIALECT: one vendor's duplex event vocabulary (`BidiGenerateContent`), its JSON frame
//! shapes, and the reader/writer that maps them into this plane's shared duplex IR. It is NOT a
//! WIRE: every byte of framing this leg has is carried by a transport crate the tree already has,
//! and this crate names none of them — a dialect that named a wire would be the plane-transport
//! fusion one level down.
//!
//! ## What it took OUT of the neutral plane, which is the point of the cut
//!
//! `busbar-plane-streams` carried two functions — `reader_for` and `writer_for` — whose whole body
//! was `if dialect.name == NAME_GEMINI_LIVE { GeminiLiveCodec } else { OpenAiRealtimeCodec }`. That
//! is instance dispatch with a string comparison in front of it, at the altitude of the one crate
//! the dialect kind's direction rule makes the NEUTRAL party, and it is the same shape VT-2 deleted
//! from that crate when the `Dialect` enum and its seven `match` arms went. The replacement is the
//! shape the rest of the row already is: the reader and the writer are FIELDS
//! ([`busbar_plane_streams::dialect::Dialect::reader`],
//! [`busbar_plane_streams::dialect::Dialect::writer`]), this crate fills them with its own codec,
//! and the neutral plane names `GeminiLiveCodec` nowhere at all.
//!
//! A dialect whose frames the SHARED IR already reads leaves both fields `None` — that is what
//! `None` means here, and it is why `None` is not a missing reader but a declared one. The shared
//! IR is `busbar_voice_codec::ir::codec`, which is simultaneously the GA realtime dialect's own
//! reader and the IR every other dialect of this plane maps into; this dialect maps into it rather
//! than restating it, which is exactly the `dialect -> codec` edge `ARCHITECTURE.md` §6 grants
//! until the pre-split codec halves are split.
//!
//! ## The direction, and how the plane ever sees this
//!
//! The dialect names its plane; the plane never names a dialect. This crate depends on
//! `busbar-plane-streams` and on the shared IR, and on nothing else in the workspace; nothing
//! depends on this crate except the COMPOSITION ROOT, which calls
//! `busbar_plane_streams::dialect::register(&GEMINI_LIVE)` at boot. That is why
//! `scripts/plane-delete-test.sh` can remove this directory and get an honest "the dialect is
//! absent" from a node that still boots and still serves the other dialects, rather than a link
//! error.
//!
//! ## What the row declares, and why each field is a fact and not a branch
//!
//! This dialect can be DIALED as an upstream, it authenticates once at session open and rides the
//! session, it does NOT meter its own uplink (the plane meters it off the shared IR at the relay
//! seam, because this dialect's frames become that IR before any quantity is taken), it brings no
//! frame ENVELOPE of its own (an envelope is the carrier-shaped face — a dialect whose payload must
//! be priced before a transform widens it — and this dialect has no such transform), and it locks
//! no session configuration. Its reader and writer it declares itself.
//!
//! ## What is NOT here, and the line that brings it
//!
//! The reader/writer SOURCE (`busbar_voice_codec::ir::codec::gemini`, ~800 lines plus ~1,270 of
//! cells) has not moved into this directory. It is reached here as a type, from the pre-split codec
//! half, the same way the carrier's crate reaches the IR it targets. Moving it is the codec SPLIT's
//! line (`ARCHITECTURE.md` §1.1, "D36 becomes the SPLIT of each codec into dialect crates"), and it
//! requires five reader helpers that are private to `ir::codec` today (`parse`, `wire_of`,
//! `str_at`, `decode_audio`, `encode_audio`) to become part of that crate's public surface — a
//! surface raise on a frozen-adjacent crate, which is a measurement of its own and not a line to
//! smuggle into a mint.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// THE FACE'S OWN VOCABULARY, TAKEN OFF THE FACE. `DuplexReader`/`DuplexWriter` are re-exported by
// the plane's dialect module precisely so a dialect names its PLANE for the types its plane's face
// is written in. Only the CODEC — this dialect's own reader/writer, which is what the pre-split half
// still holds — is reached past it.
use busbar_plane_streams::dialect::{CredentialAt, Dialect, DuplexReader, DuplexWriter};
use busbar_voice_codec::ir::GeminiLiveCodec;

/// This dialect's WIRE NAME — the string on the session's dialect fact, the string the `dialects`
/// verb answers, and the string the plane's claim table names this dialect by.
///
/// Declared once, here, on the row that carries it. The crate is named `…-streams-gemini` because
/// the gate caps a crate name at four segments and `…-streams-gemini-live` is five; the wire name
/// is not shortened with it.
pub const NAME: &str = "gemini-live";

/// This dialect's reader — the shape an arriving frame of this vendor's wire is read in.
fn reader() -> Box<dyn DuplexReader> {
    Box::new(GeminiLiveCodec)
}

/// This dialect's writer — the shape a departing IR event is rendered in.
fn writer() -> Box<dyn DuplexWriter> {
    Box::new(GeminiLiveCodec)
}

/// THE GOOGLE GEMINI LIVE (`BidiGenerateContent`) DIALECT ROW — JSON frames, tool calls.
///
/// The row the plane's table answers `NAME` with once the composition root has registered it. It
/// was a `&'static` the NEUTRAL plane wrote, and its reader was an `if` in that plane's own body,
/// until the commit that minted this crate.
pub static GEMINI_LIVE: Dialect = Dialect {
    name: NAME,
    // This plane can DIAL an upstream speaking this dialect, not only serve clients arriving on it.
    duplex_upstream: true,
    // One credential presented at the upgrade, then frames until close.
    authenticates_from_session: true,
    // The plane meters this dialect off the shared IR at the relay seam. A dialect meters its OWN
    // uplink only when it carries an envelope whose payload is priced before a transform widens it.
    meters_own_uplink: false,
    // No frame envelope of its own: this dialect's frames map into the shared duplex IR, they do
    // not wrap it.
    envelope: None,
    // Opens on the deployment's own declared session defaults; locks nothing.
    locked_session_config: None,
    // THE TWO FIELDS THIS CRATE EXISTS FOR. They were an `if name ==` in the neutral plane.
    reader: Some(reader),
    writer: Some(writer),
    // THIS VENDOR PUTS THE KEY IN THE QUERY STRING. It is its published scheme for this protocol
    // and not a choice anything in this tree makes; declaring it here is what lets the wire present
    // it without the neutral plane, the composition root or the transport naming this vendor. It is
    // also the whole reason the contract owns a URL redactor: a secret in a query string is a secret
    // in every URL-shaped error message and audit record unless something takes it back out.
    credential_at: Some(CredentialAt::Query("key")),
    // DECLARED `None`: a leg on this dialect is DIALLED, and it gets its opening event the way every
    // dialled leg does — by relaying the one its upstream sent. A node that announced its own on top
    // of the upstream's would put two openings on one session.
    opening_event: None,
    // DECLARED `None`: a leg on this dialect is DIALLED, so a request always has an upstream to be
    // answered by, and a node that answered one itself would be answering for a provider.
    request_terminal: None,
};
