//! The claims this plane makes over arriving bytes, and the four dialects they name.
//!
//! `docs/design/ARCHITECTURE.md`'s protocol-inventory table (the row keyed `voice`) names the
//! dialect roster this plane speaks and the transports it claims them on:
//!
//! `openai-realtime, gemini-live, twilio-media-streams, one-shot transcribe/tts` over
//! `ws, webrtc, twilio-media, http`.
//!
//! This module claims two of those four transports today: `ws` (both duplex JSON dialects) and
//! `http` (the two one-shot operations). Two are deliberately unclaimed, for the same reason stated
//! twice:
//!
//! * **`webrtc`** — no codec surface for the RTP media plane exists anywhere in this crate's closure
//!   (busbar-voice's WebRTC topology is `runtime`-gated and, per its own module documentation, is a
//!   browser-sideband ferry over the same JSON event vocabulary rather than a distinct wire format —
//!   but a plane cannot claim a transport it cannot decode frames from without lying about what it
//!   reads).
//! * **`twilio-media`** — the telephony transport has **no crate in the tree**. The architecture's
//!   transport table lists thirteen and seven exist; `twilio-media` is one of the six that do not,
//!   and a claim on a transport nothing registers is a boot refusal, not a silent 404. Until that
//!   transport crate lands (the same phase the `webrtc` leg and the real one-shot wire shape are
//!   scheduled for) the claim is dropped rather than declared and refused: a node whose composition
//!   root cannot seal is a node that does not boot, and the carrier's own codec below
//!   ([`crate::twilio`], [`crate::ulaw`]) is complete and untouched — it is the arrival path, not
//!   the reader, that is missing. Restoring the claim is one entry in [`DIALECT_CLAIMS`].
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

/// The transport the telephony dialect (`twilio-media-streams`) *would* be claimed against, kept as
/// the name the restored claim will use rather than as a live one.
///
/// No claim in [`DIALECT_CLAIMS`] names it: see this module's own header for why, and for what has
/// to exist before one does. It is a `&'static str` and nothing else — naming a transport is not
/// claiming it.
pub const TWILIO_TRANSPORT: &str = "twilio-media";

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

/// The alternatives a one-shot HTTP unit may narrow to — the same two an ordinary API caller uses.
const HTTP_SCHEME_ALTS: &[&str] = &["bearer", "api-key"];

/// The names this plane's declared claims carry, in declaration order.
///
/// The three STREAMING dialects have rows in [`crate::dialect`]; the two one-shot operations do
/// not, for the reason this module's header states.
pub const TRANSCRIBE: &str = "transcribe";

/// See [`TRANSCRIBE`].
pub const TTS: &str = "tts";

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
    // The telephony claim used to sit here, on `twilio-media` over `PrefixOneLevel("/twilio")`,
    // under a `twilio-signature` alternative. It is dropped, not commented out for later: the
    // transport it named has no crate, and a claim whose transport nothing registers is a boot
    // refusal that stops the whole node rather than one plane. The header says what has to exist
    // before it comes back, and the carrier's own codec is untouched so the reader that reads the
    // wire is still here when it does.
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
