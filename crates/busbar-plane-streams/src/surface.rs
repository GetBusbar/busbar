// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SERVED SURFACE OF THIS PLANE'S DUPLEX SESSIONS, as data.
//!
//! ## Why a declaration and not a server
//!
//! [`crate::claims`] already says which arriving bytes are this plane's. That is enough to ROUTE a
//! session and nowhere near enough to SERVE one. A mount that has to open a duplex session needs the
//! facts a claim deliberately leaves out: which mount points a session may be opened at, whether the
//! upgrade has to carry a credential, and what media type the frames it will write back are in.
//!
//! Until this module those three lived inside a protocol's own server, which is what made a wire
//! protocol a crate. They are declared here in the plane-agnostic vocabulary
//! [`busbar_contract::transport::surface`] defines, and a session mount reads them without knowing
//! which plane or which dialect they belong to. Nothing here opens anything, holds anything or reads
//! anything: it is a `const`.
//!
//! ## No transport is named here, and that is a rule
//!
//! [`BindingDecl::transport`] is a REGISTRY KEY, and the one written below is
//! [`crate::claims::WS_TRANSPORT`] — the same `&'static str` this plane's own claims are already
//! declared against, borrowed rather than re-spelled. A second copy of that word would be a second
//! opinion about which registry entry carries these bindings, and the one that disagreed would be
//! the one that answered nothing. This crate names no transport CRATE and reaches no transport code;
//! the word is data on both sides of the seam.
//!
//! ## Two bindings, one per duplex dialect
//!
//! * **[`BINDING_OPENAI_REALTIME`]** — the OpenAI Realtime shape. Its mount is `/v1/realtime`.
//! * **[`BINDING_GEMINI_LIVE`]** — the Gemini Live (`BidiGenerateContent`) shape. Its mount is the
//!   service path a Gemini-shaped client resolves against a base URL.
//!
//! How an event INSIDE either session names itself is not declared here and is not declarable here.
//! A frame of an open session is not addressed: which operation it is, is what this plane's own
//! reader makes of it, from the frames before it. The duplex kind carries the three facts a mount
//! has before the upgrade — the binding, the method, the bar — and stops there, which is the whole
//! of what a wire is entitled to know.
//!
//! ## Every mount is its own claim's, and nobody else's
//!
//! The mounts below are not a second, independently-written route table: each one is a path the
//! declaring dialect's claim selector in [`crate::claims::DIALECT_CLAIMS`] already matches, and no
//! other dialect's. `tests/surface.rs` asserts exactly that, in both directions, so a mount added
//! here that the claim would not admit is RED rather than a route that answers for a session the
//! kernel routed to a different dialect.
//!
//! ## What is deliberately NOT declared
//!
//! * **The two one-shot HTTP operations.** `transcribe` and `tts` are claimed
//!   ([`crate::claims::DIALECT_CLAIMS`]) and are not rows here. A [`Dispatch::Target`] row carries a
//!   request and a response media type, and this plane has no one-shot wire shape written down to
//!   take either from — `claims.rs`'s own header says the real one-shot wire is scheduled with the
//!   `webrtc` leg. Two media types invented here would be two media types a conformant client is
//!   answered with and nobody chose. The absence is declared, not forgotten.
//! * **`duplex_turn`, `tool_call` and the telephony dialect.** The first two are the operation
//!   classes the frames INSIDE an open session carry, and a frame is not addressed: which operation
//!   it is, is what the plane reads out of it. A row for either would be a dispatch nothing could
//!   ever match. The third has no claim and no transport crate, for the reasons `claims.rs` states.

use busbar_contract::transport::surface::{
    Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};

use crate::claims::Dialect;

/// The OpenAI Realtime binding's name — the dialect's own word for itself.
pub const BINDING_OPENAI_REALTIME: &str = Dialect::OpenaiRealtime.name();

/// The Gemini Live binding's name — the dialect's own word for itself.
pub const BINDING_GEMINI_LIVE: &str = Dialect::GeminiLive.name();

/// The media type every frame of both duplex dialects is in, in both directions.
///
/// One constant and not two, because it is genuinely one answer: both wires are JSON text frames,
/// and the audio they carry rides base64 INSIDE a frame rather than as a frame of its own. A
/// deployment that later served a binary audio sub-protocol would be declaring a third binding with
/// its own media type, not changing this one.
pub const MEDIA_JSON: &str = "application/json";

/// The request method an upgrade arrives with.
///
/// The upgrade's own, fixed by the wire that carries it: after it there is no method at all, which
/// is the whole reason a session is addressed by its binding rather than by an operation in a
/// target.
const UPGRADE: &str = "GET";

/// Where an OpenAI Realtime session is opened.
///
/// The base every route of that dialect sits under, and the exact string
/// [`crate::claims::DIALECT_CLAIMS`]'s `PathSuffix` selector for this dialect matches.
const MOUNT_OPENAI_REALTIME: &str = "/v1/realtime";

/// Where a Gemini Live session is opened.
///
/// The service path the generative-language wire spells `BidiGenerateContent` on, which is what a
/// Gemini-shaped client resolves when it is handed this node as its base: the client derives its
/// target from the service descriptor rather than choosing one, so a mount declared any other way
/// would leave the only spelling that dialect's clients send answering nothing. It is the string
/// this plane's `PathContains` selector for the dialect is written to admit.
const MOUNT_GEMINI_LIVE: &str =
    "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent";

/// Opening a duplex session: the one addressable operation of this surface.
///
/// Two rows, one per dialect, and both in the DUPLEX kind. A session is addressed by its binding —
/// the binding's own mounts are where — because after the upgrade this wire has no target, no method
/// and no document, and what the frames that follow mean is this plane's to decide from the session's
/// own state rather than something any dispatch row could match.
///
/// Until the contract carried a duplex kind these were document rows, and each had to carry a
/// `member` and a `name` that nothing resolved and nothing could resolve: the events they named are
/// frames INSIDE an open session, and a frame is not addressed. They said, in the only vocabulary
/// available, that a mount could read an operation's name out of an arriving document here — which
/// left a mount unable to tell this from an ordinary posted-envelope endpoint on the same wire.
///
/// Both behind a credential. A session presents one ONCE, on the upgrade, and never again —
/// [`Dialect::authenticates_from_session`] is the same fact stated on the plane's side — so a bar
/// declared open here would be a session that could never be resolved to a principal at any later
/// frame either.
const D_SESSION_OPEN: &[Dispatch] = &[
    Dispatch::Duplex {
        binding: BINDING_OPENAI_REALTIME,
        method: UPGRADE,
        bar: Bar::Credential,
    },
    Dispatch::Duplex {
        binding: BINDING_GEMINI_LIVE,
        method: UPGRADE,
        bar: Bar::Credential,
    },
];

/// THE SURFACE.
///
/// [`Answering::Stream`], because that is what a session is: one open, a run of answers, and the
/// last of them ends it. A row that said [`Answering::Unary`] would tell a mount to close the
/// direction after the first frame it wrote, which is a session cut at its first answer.
pub const SURFACE: WireSurface = WireSurface {
    bindings: &[
        BindingDecl {
            name: BINDING_OPENAI_REALTIME,
            transport: crate::claims::WS_TRANSPORT,
            mounts: &[MOUNT_OPENAI_REALTIME],
        },
        BindingDecl {
            name: BINDING_GEMINI_LIVE,
            transport: crate::claims::WS_TRANSPORT,
            mounts: &[MOUNT_GEMINI_LIVE],
        },
    ],
    operations: &[Operation {
        op: crate::meta::OP_SESSION_OPEN.as_str(),
        dispatch: D_SESSION_OPEN,
        answering: Answering::Stream,
        request_media: MEDIA_JSON,
        response_media: MEDIA_JSON,
    }],
};

#[cfg(test)]
#[path = "tests/surface.rs"]
mod tests;
