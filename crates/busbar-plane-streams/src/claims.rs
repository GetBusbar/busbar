//! The claims this plane makes over arriving bytes, and the four dialects they name.
//!
//! `docs/design/ARCHITECTURE.md`'s protocol-inventory table (the row keyed `voice`) names the
//! dialect roster this plane speaks and the transports it claims them on:
//!
//! `openai-realtime, gemini-live, twilio-media-streams, one-shot transcribe/tts` over
//! `ws, webrtc, twilio-media, http`.
//!
//! This module claims TWO transports today: `ws` (both duplex JSON dialects and the carrier) and
//! `http` (the two one-shot operations). One is deliberately unclaimed:
//!
//! * **`webrtc`** — and it is unclaimed because there is nothing to claim, not because a reader is
//!   owed. The browser topology's MEDIA never touches this node: the browser establishes it
//!   directly with the provider off the ephemeral secret this plane mints, peer to peer. What this
//!   node carries for that call is the SIDEBAND control socket, which is a WebSocket carrying the
//!   OpenAI Realtime event vocabulary and is claimed above as that dialect. There is no RTP and no
//!   ICE anywhere in this workspace, and a plane may not claim a transport it cannot read frames
//!   from.
//!
//! **THE CARRIER CLAIM IS BACK, ON [`WS_TRANSPORT`].** It was dropped because it named a wire with
//! no crate, and a claim nothing registers is a boot refusal that stops the whole node rather than
//! one plane. What was missing was never a wire: the carrier arrives as an upgrade and duplex
//! message frames, and the wire named below carries every byte of that. The missing thing was a
//! home for the VOCABULARY, and that home is a dialect crate. So the claim comes back on the wire
//! that was always underneath it, and the invented row it used to name is deleted from the
//! architecture's own table rather than filled in.
//!
//! Leaving either unclaimed is an honest, documented gap, not a silent one: a future pass that gives
//! this crate an RTP data-channel reader, or the tree a telephony transport, can add the claim
//! without touching any other one, because claims are declared independently and the boot's own
//! overlap check is what proves they stay disjoint.
//!
//! ## THE CLAIMED PATHS ARE THE SERVED PATHS, and the served paths are 1.5.x's
//!
//! The three duplex legs are claimed at `/v1/realtime/sideband/{call_id}`,
//! `/v1/realtime/telephony/{call_id}` and `/v1/realtime/gemini/{call_id}` — the URLs
//! `docs/voice.md` documents, the URLs a deployment's carrier is configured to dial, and the URLs
//! every conformant client of this node already sends. They are not this module's to choose. A
//! previous pass on this line declared `/v1/realtime`, `/twilio/stream` and a generative-language
//! service path instead, which were all three defensible readings of what the dialects are and all
//! three a served surface changed by a refactor: every test in the tree would have stayed green
//! while every live carrier configuration answered 404.
//!
//! Each is spelled as ONE LEVEL UNDER its own base, which is exactly the shape of the URL, because
//! the one level is the call. A closed form rather than a suffix or a substring, and the difference
//! is what the boot's overlap check can prove about it: two one-level prefixes overlap only when
//! they are the same string.
//!
//! `/v1/realtime` itself is NOT claimed. It is the RFC 8707 audience base every one of these legs
//! presents a token for and the mount the one-shot mint and SDP-broker passes live under, and it is
//! not a place a session is opened; the audience and the session mount are two different facts and
//! the old `PathSuffix("/v1/realtime")` claim was the first standing in for the second. It matched
//! none of the three URLs this plane serves.
//!
//! ## A DIALECT IS A NAME HERE, NEVER A VARIANT
//!
//! There used to be a `Dialect` enum in this file, with one variant per vendor and three `match`
//! arms over it. That is instance dispatch in the crate the dialect kind's direction rule makes
//! the NEUTRAL party, and it is deleted. A claim carries the dialect's NAME — the same
//! `&'static str` the session fact carries and the same one a dialect crate is named for — and
//! [`crate::dialect`] is the table it resolves in.
//!
//! The two one-shot names below are STRINGS AND NOTHING ELSE, and deliberately have no row in that
//! table: `transcribe` and `tts` are HTTP operations, not streaming dialects, and they leave this
//! plane in a later pass.

use busbar_contract::grammar::{one_level_under, Claim, Selector};

/// The transport both JSON duplex dialects (`openai-realtime`, `gemini-live`) are claimed against.
pub const WS_TRANSPORT: &str = "ws";

/// The transport the two one-shot operations (`transcribe`, `tts`) are claimed against.
pub const HTTP_TRANSPORT: &str = "http";

/// The credential scheme every one of this plane's claims authenticates under.
///
/// One scheme with alternatives, not several schemes, the same discipline `busbar-plane-llm` uses:
/// which alternative a unit narrows to is the authenticate step's answer.
pub(crate) const SCHEME: &str = "voice-key";

/// The alternatives a duplex-session unit (`ws`) may narrow to: a bearer token or a vendor API-key
/// header, presented once at session open and cached for the life of the session.
const WS_SCHEME_ALTS: &[&str] = &["bearer", "api-key"];

/// The alternative the carrier's own clients present: a signature over the request, computed by the
/// carrier with the account's own secret. One alternative and not two — a carrier leg never carries
/// a bearer token or a vendor API key, and offering either would be this plane admitting a
/// credential shape no client of that dialect ever sends.
const CARRIER_SCHEME_ALTS: &[&str] = &["twilio-signature"];

/// The alternatives a one-shot HTTP unit may narrow to — the same two an ordinary API caller uses.
const HTTP_SCHEME_ALTS: &[&str] = &["bearer", "api-key"];

/// The names this plane's declared claims carry, in declaration order.
///
/// The three STREAMING dialects have rows in [`crate::dialect`]; the two one-shot operations do
/// not, for the reason this module's header states.
pub const TRANSCRIBE: &str = "transcribe";

/// See [`TRANSCRIBE`].
pub const TTS: &str = "tts";

/// The carrier dialect's name — the same `&'static str` its own crate declares as `NAME`, and the
/// same one the session fact carries.
///
/// A NAME AND NOTHING ELSE. Naming a dialect is not depending on one: no crate is reached, no code
/// is linked, and `scripts/plane-delete-test.sh` still removes the dialect crate and gets an honest
/// absence. What a claim table says is which arriving bytes are this plane's and under what name it
/// will look the reader up; the reader itself arrives through `crate::dialect::register`.
///
/// STATED, NOT SMUGGLED: `ARCHITECTURE.md` 1.1 says a plane's `CLAIMS` is "the union of its own and
/// its registered dialects'", which would put this row on the dialect's side and union it at
/// registration. `PlaneMeta::CLAIMS` is an associated CONSTANT, so a union computed at boot cannot
/// reach it, and the kernel reads the constant. Moving the claim to the dialect is the next finding
/// on this line and needs the constant to become a declaration the root can fill.
pub const CARRIER: &str = "twilio-media-streams";

/// The Gemini Live dialect's name — the same `&'static str` its own crate declares as `NAME`, and
/// the same one the session fact carries.
///
/// A NAME AND NOTHING ELSE, for the reason [`CARRIER`] states above it: naming a dialect is not
/// depending on one. It was `crate::dialect::NAME_GEMINI_LIVE` until that dialect got a crate, and
/// a claim table that kept reaching into the dialect TABLE for a name would have made the table the
/// place a claim's spelling lived — which is the plane holding an instance's word again, one
/// indirection further out.
pub const GEMINI_LIVE: &str = "gemini-live";

/// The browser sideband socket: one level under `/v1/realtime/sideband`, which is the call.
const SIDEBAND: Selector = Selector::PrefixOneLevel("/v1/realtime/sideband");

/// The carrier media leg: one level under `/v1/realtime/telephony`, which is the call.
const TELEPHONY: Selector = Selector::PrefixOneLevel("/v1/realtime/telephony");

/// The Gemini Live thin duplex: one level under `/v1/realtime/gemini`, which is the call.
const GEMINI: Selector = Selector::PrefixOneLevel("/v1/realtime/gemini");

/// One claim with the dialect it names recorded beside it, the same pairing
/// `busbar_plane_llm::claims::LadderClaim` uses for its ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialectClaim {
    /// Which dialect this claim names, by name — never by variant.
    pub dialect: &'static str,
    /// The claim itself.
    pub claim: Claim,
}

/// Build one claim over a selector, on a transport, under an alternative set.
const fn claim(
    transport: &'static str,
    selector: Selector,
    alts: &'static [&'static str],
) -> Claim {
    Claim {
        transport,
        selector,
        scheme: Some(SCHEME),
        scheme_alternatives: alts,
        // None of the four dialects' claims declares an idempotency location: a duplex session has
        // no single request body to key a replay on, and the two one-shot operations are read
        // straight through rather than replay-cached, matching the previous release's behaviour.
        idempotency: None,
    }
}

/// The declared claims, dialect-tagged, in the order the boot's overlap check sees them.
pub const DIALECT_CLAIMS: &[DialectClaim] = &[
    // THE THREE DUPLEX LEGS, EACH AT THE URL IT HAS ALWAYS BEEN SERVED AT, and each spelled as ONE
    // LEVEL UNDER its own base — which is exactly the shape of the served URL, because the one level
    // is the call. A closed form rather than a suffix or a substring, and the difference is what the
    // boot's overlap check can prove: two one-level prefixes overlap only when they are the same
    // string, where two substrings are compared by giving up and calling them overlapping.
    //
    // `/v1/realtime` itself is deliberately NOT claimed here. It is the audience base the one-shot
    // mint and SDP-broker passes live under, not a place a session is opened, and a claim on the
    // base would admit all three legs under whichever dialect happened to name it — a session read
    // by the wrong dialect's reader, which fails some frames into an open call rather than at the
    // door, because all three speak JSON over the same wire.
    //
    // THE SIDEBAND LEG IS THIS DIALECT'S, and its claim used to name the base and therefore matched
    // nothing it served. The socket carries the OpenAI Realtime GA event vocabulary — the same
    // events the direct realtime socket carries — and it is the CONTROL channel of a browser call
    // whose media never touches this node at all: the browser establishes its media path directly
    // with the provider off the ephemeral secret this plane mints. There is no second dialect to
    // claim it under and no `webrtc` claim to make: this node carries no RTP and no ICE, and a plane
    // may not claim a transport it cannot read frames from.
    DialectClaim {
        dialect: crate::dialect::NAME_OPENAI_REALTIME,
        claim: claim(WS_TRANSPORT, SIDEBAND, WS_SCHEME_ALTS),
    },
    DialectClaim {
        dialect: GEMINI_LIVE,
        claim: claim(WS_TRANSPORT, GEMINI, WS_SCHEME_ALTS),
    },
    // THE CARRIER, on `ws` — the transport that was always underneath it — and at the TELEPHONY URL
    // rather than the `/twilio/stream` the previous commit invented. A mount is not a string a
    // declaration may pick: it is where a deployment's carrier is already configured to dial. And
    // the vendor's name leaves the path with it, which is the second thing that was wrong with
    // `/twilio`: a claim selector is read by the front door, and the front door's routing table is
    // the one place an instance name is never allowed to be.
    DialectClaim {
        dialect: CARRIER,
        claim: claim(WS_TRANSPORT, TELEPHONY, CARRIER_SCHEME_ALTS),
    },
    DialectClaim {
        dialect: TRANSCRIBE,
        claim: claim(
            HTTP_TRANSPORT,
            Selector::PathSuffix("/v1/audio/transcriptions"),
            HTTP_SCHEME_ALTS,
        ),
    },
    DialectClaim {
        dialect: TTS,
        claim: claim(
            HTTP_TRANSPORT,
            Selector::PathSuffix("/v1/audio/speech"),
            HTTP_SCHEME_ALTS,
        ),
    },
];

/// The claims, one field narrower, as [`busbar_contract::plane::PlaneMeta::CLAIMS`] wants them.
///
/// Written out rather than derived because a declaration is an associated constant, and a constant
/// cannot run a loop over another constant.
pub const CLAIMS: &[Claim] = &[
    DIALECT_CLAIMS[0].claim,
    DIALECT_CLAIMS[1].claim,
    DIALECT_CLAIMS[2].claim,
    DIALECT_CLAIMS[3].claim,
    DIALECT_CLAIMS[4].claim,
];

/// The two lists cannot drift: one is the other with a field dropped, and a constant cannot loop
/// over a constant, so the equality is asserted at compile time instead of trusted.
const _: () = assert!(CLAIMS.len() == DIALECT_CLAIMS.len());

/// Which dialect a request's target names, by walking the claims in declaration order.
///
/// The same walk the kernel runs itself from the declared claims, exposed here so the decode step
/// can name the dialect it is about to read without a second, differently-ordered answer existing
/// anywhere.
#[must_use]
pub fn dialect_for(path: &str) -> Option<&'static str> {
    DIALECT_CLAIMS
        .iter()
        .find(|c| matches_selector(&c.claim.selector, path))
        .map(|c| c.dialect)
}

/// Whether one selector matches a request path.
///
/// Only the forms this plane's claims actually use are answered.
pub(crate) fn matches_selector(s: &Selector, path: &str) -> bool {
    match s {
        // The contract's own rule, READ rather than restated. A plane that reimplemented the form
        // would be a second opinion about which claim a request matches, and the one request the two
        // disagree on is exactly the one the boot's overlap check proved could not exist.
        Selector::PrefixOneLevel(prefix) => one_level_under(prefix, path),
        Selector::PathSuffix(suffix) => path.ends_with(suffix),
        _ => false,
    }
}
