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
//! * **`webrtc`** — no codec surface for the RTP media plane exists anywhere in this crate's closure
//!   (the legacy WebRTC topology is `runtime`-gated and, per its own module documentation, is a
//!   browser-sideband ferry over the same JSON event vocabulary rather than a distinct wire format —
//!   but a plane cannot claim a transport it cannot decode frames from without lying about what it
//!   reads).
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
    DialectClaim {
        dialect: crate::dialect::NAME_OPENAI_REALTIME,
        claim: claim(
            WS_TRANSPORT,
            Selector::PathSuffix("/v1/realtime"),
            WS_SCHEME_ALTS,
        ),
    },
    DialectClaim {
        dialect: crate::dialect::NAME_GEMINI_LIVE,
        claim: claim(
            WS_TRANSPORT,
            Selector::PathContains("BidiGenerateContent"),
            WS_SCHEME_ALTS,
        ),
    },
    // THE CARRIER, on `ws` — the transport that was always underneath it. One level under
    // `/twilio` and no deeper: the carrier posts its stream to a single mount, and a claim that
    // admitted arbitrary depth would be this plane claiming a subtree it does not serve.
    DialectClaim {
        dialect: CARRIER,
        claim: claim(
            WS_TRANSPORT,
            Selector::PrefixOneLevel("/twilio"),
            CARRIER_SCHEME_ALTS,
        ),
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
        Selector::PathSuffix(suffix) => path.ends_with(suffix),
        Selector::PathContains(needle) => path.contains(needle),
        // The contract's rule, read rather than restated: a second spelling here could hand a
        // request to a dialect the boot's overlap check never saw this plane claim.
        Selector::PrefixOneLevel(prefix) => one_level_under(prefix, path),
        _ => false,
    }
}
