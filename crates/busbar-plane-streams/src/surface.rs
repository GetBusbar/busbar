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
//! ## Three bindings, one per duplex dialect, at the URLs this node has always served
//!
//! * **[`BINDING_OPENAI_REALTIME`]** — the OpenAI Realtime shape, on the browser sideband socket:
//!   `/v1/realtime/sideband/{call_id}`.
//! * **[`BINDING_CARRIER`]** — the carrier media leg: `/v1/realtime/telephony/{call_id}`.
//! * **[`BINDING_GEMINI_LIVE`]** — the Gemini Live thin duplex: `/v1/realtime/gemini/{call_id}`.
//!
//! THOSE THREE STRINGS ARE THE PUBLISHED SURFACE and are not this module's to choose. They are what
//! `docs/voice.md` documents, what a deployment's carrier is configured to dial, and what every
//! conformant client of this node already sends; a declaration that spelled them any other way
//! would be a served URL changed by a refactor, which is the one thing a re-declaration of an
//! existing surface may not do. Each carries the `{call_id}` its published form has always carried
//! — the mount is a PATTERN ([`busbar_contract::transport::surface::BindingDecl::mounts`]), which
//! is the vocabulary that makes that expressible at all.
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
//! * **`duplex_turn` and `tool_call`.** These are the operation classes the frames INSIDE an open
//!   session carry, and a frame is not addressed: which operation it is, is what the plane reads
//!   out of it. A row for either would be a dispatch nothing could ever match.
//!
//! The carrier used to be listed here too, as a dialect with no claim and no wire crate. It has a
//! claim now and a binding below: the wire it was waiting for was already registered.

use busbar_contract::transport::surface::{
    Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};

/// The OpenAI Realtime binding's name — the dialect's own word for itself.
pub const BINDING_OPENAI_REALTIME: &str = crate::dialect::NAME_OPENAI_REALTIME;

/// The Gemini Live binding's name — the dialect's own word for itself.
pub const BINDING_GEMINI_LIVE: &str = crate::dialect::NAME_GEMINI_LIVE;

/// The carrier binding's name — the dialect's own word for itself, borrowed from the claim table
/// rather than re-spelled here.
pub const BINDING_CARRIER: &str = crate::claims::CARRIER;

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

/// The segment every one of the three duplex mounts captures: the call this session is about.
///
/// One name, because it is the name the fact is published under on all three bindings and a second
/// spelling would be a second fact. The word is the one the served URLs have always carried —
/// `docs/voice.md` writes `{call_id}` in each of its three upgrade rows — and `tests/surface.rs`
/// holds every declared mount to ending in exactly this capture rather than trusting three
/// hand-written copies of it.
pub(crate) const CAPTURE_CALL_ID: &str = "call_id";

/// Whether a mount pattern ends in the one declared capture, answerable at compile time.
///
/// A const rather than a test, because it is the only thing holding three hand-written strings to
/// one name, and a name that drifted would publish a fact under a spelling the composition above
/// does not read — which is not a failure any wire could report.
const fn ends_in_the_capture(mount: &str) -> bool {
    let (m, want) = (mount.as_bytes(), CAPTURE_CALL_ID.as_bytes());
    // `/{name}`: the separator, the brace, the name, the closing brace.
    if m.len() < want.len() + 3 {
        return false;
    }
    let start = m.len() - want.len() - 3;
    if m[start] != b'/' || m[start + 1] != b'{' || m[m.len() - 1] != b'}' {
        return false;
    }
    let mut i = 0;
    while i < want.len() {
        if m[start + 2 + i] != want[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Where an OpenAI Realtime session is opened: the browser's persistent sideband control socket.
///
/// The published URL, byte for byte. Not the plane's audience base `/v1/realtime` — that base is
/// where the one-shot mint and SDP-broker passes live and is not a place a session is opened at all,
/// and a binding declared there would advertise a session mount at a target no client upgrades on.
const MOUNT_OPENAI_REALTIME: &str = "/v1/realtime/sideband/{call_id}";

/// Where a carrier session is opened: the carrier media leg, `g711_ulaw` end to end.
///
/// The published URL, byte for byte, and it replaces the `/twilio/stream` this file invented one
/// commit ago. That invention was the mistake this commit undoes: a mount is not a place a
/// declaration is free to pick, it is where a deployment's carrier is already configured to dial,
/// and moving it would have taken every live carrier configuration down while every test in the
/// tree stayed green.
const MOUNT_CARRIER: &str = "/v1/realtime/telephony/{call_id}";

/// Where a Gemini Live session is opened: the thin duplex proxy, the same shape as the carrier leg.
///
/// The published URL, byte for byte, and it replaces the generative-language SERVICE path this file
/// carried. A Gemini-shaped client pointed at a provider derives that service path from the
/// descriptor — but this node is not the provider, it is the proxy in front of one, and what it
/// serves is its own URL keyed by the call, exactly as the carrier leg is. The service path is what
/// this plane DIALS upstream, which is the far side of the leg and no part of what it mounts.
const MOUNT_GEMINI_LIVE: &str = "/v1/realtime/gemini/{call_id}";

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
/// [`crate::dialect::Dialect::authenticates_from_session`] is the same fact, as data — so a bar
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
    // The carrier, behind a credential like the other two: its clients present a signature over the
    // upgrade, once, and never again. A bar declared open here would be a session that could never
    // be resolved to a principal at any later frame either.
    Dispatch::Duplex {
        binding: BINDING_CARRIER,
        method: UPGRADE,
        bar: Bar::Credential,
    },
];

/// Every declared mount captures the call, under the one name, and it is checked here rather than
/// left to three copies of a word agreeing by inspection.
const _: () = assert!(ends_in_the_capture(MOUNT_OPENAI_REALTIME));
const _: () = assert!(ends_in_the_capture(MOUNT_CARRIER));
const _: () = assert!(ends_in_the_capture(MOUNT_GEMINI_LIVE));

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
        BindingDecl {
            name: BINDING_CARRIER,
            transport: crate::claims::WS_TRANSPORT,
            mounts: &[MOUNT_CARRIER],
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
