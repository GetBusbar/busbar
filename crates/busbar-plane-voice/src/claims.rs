//! The claims this plane makes over arriving bytes, and the four dialects they name.
//!
//! `docs/design/ARCHITECTURE.md`'s protocol-inventory table (the row keyed `voice`) names the
//! dialect roster this plane speaks and the transports it claims them on:
//!
//! `openai-realtime, gemini-live, twilio-media-streams, one-shot transcribe/tts` over
//! `ws, webrtc, twilio-media, http`.
//!
//! This module claims three of those four transports today: `ws` (both duplex JSON dialects),
//! `twilio-media` (the telephony dialect) and `http` (the two one-shot operations). It does not
//! claim `webrtc`: no codec surface for the RTP media plane exists anywhere in this crate's closure
//! (busbar-voice's WebRTC topology is `runtime`-gated and, per its own module documentation, is a
//! browser-sideband ferry over the same JSON event vocabulary rather than a distinct wire format —
//! but a plane cannot claim a transport it cannot decode frames from without lying about what it
//! reads). Leaving `webrtc` unclaimed is an honest, documented gap, not a silent one: a future pass
//! that gives this crate an RTP data-channel reader can add the claim without touching any other
//! one, because claims are declared independently and the boot's own overlap check is what proves
//! they stay disjoint.

use busbar_contract::grammar::{Claim, Selector};

/// The transport both JSON duplex dialects (`openai-realtime`, `gemini-live`) are claimed against.
pub const WS_TRANSPORT: &str = "ws";

/// The transport the telephony dialect (`twilio-media-streams`) is claimed against.
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

/// The alternatives a Twilio Media Streams unit may narrow to: Twilio's own request-signature
/// scheme, checked at the inbound webhook and re-bound to the WS connection by the admission guard.
const TWILIO_SCHEME_ALTS: &[&str] = &["twilio-signature"];

/// The alternatives a one-shot HTTP unit may narrow to — the same two an ordinary API caller uses.
const HTTP_SCHEME_ALTS: &[&str] = &["bearer", "api-key"];

/// The four dialects this plane's declared claims name.
///
/// This is the open-vocabulary dialect name, kept as a closed Rust enum inside this crate only
/// because every method that switches on it is exhaustive and a fifth dialect is a code change
/// here regardless; nothing about [`busbar_contract::grammar::Claim`] requires a closed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dialect {
    /// OpenAI Realtime (GA) — WebSocket, PCM16, tool calls, full duplex.
    OpenaiRealtime,
    /// Google Gemini Live (`BidiGenerateContent`) — WebSocket, tool calls.
    GeminiLive,
    /// Twilio Media Streams — WebSocket, G.711 µ-law telephony audio.
    TwilioMediaStreams,
    /// A one-shot speech-to-text request.
    OneShotTranscribe,
    /// A one-shot text-to-speech request.
    OneShotTts,
}

impl Dialect {
    /// The dialect's own name, as recorded in facts and answered by the `dialects` admin verb.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Dialect::OpenaiRealtime => "openai-realtime",
            Dialect::GeminiLive => "gemini-live",
            Dialect::TwilioMediaStreams => "twilio-media-streams",
            Dialect::OneShotTranscribe => "transcribe",
            Dialect::OneShotTts => "tts",
        }
    }

    /// Whether this dialect is one of the two JSON duplex wires this plane can also DIAL an
    /// upstream as (the codec-backed dialects, as opposed to the ingress-only Twilio and one-shot
    /// claims).
    #[must_use]
    pub const fn is_duplex_upstream(self) -> bool {
        matches!(self, Dialect::OpenaiRealtime | Dialect::GeminiLive)
    }

    /// Whether a unit on this dialect authenticates once at session open and rides the session
    /// (`CredentialLocator::from_session`), rather than presenting a credential on every unit.
    ///
    /// True for the three session-bound dialects; false for the two one-shot HTTP operations, which
    /// present a credential on the one request they are.
    #[must_use]
    pub const fn authenticates_from_session(self) -> bool {
        matches!(
            self,
            Dialect::OpenaiRealtime | Dialect::GeminiLive | Dialect::TwilioMediaStreams
        )
    }
}

/// One claim with the dialect it names recorded beside it, the same pairing
/// `busbar_plane_llm::claims::LadderClaim` uses for its ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialectClaim {
    /// Which dialect this claim names.
    pub dialect: Dialect,
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
        scheme: SCHEME,
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
        dialect: Dialect::OpenaiRealtime,
        claim: claim(
            WS_TRANSPORT,
            Selector::PathSuffix("/v1/realtime"),
            WS_SCHEME_ALTS,
        ),
    },
    DialectClaim {
        dialect: Dialect::GeminiLive,
        claim: claim(
            WS_TRANSPORT,
            Selector::PathContains("BidiGenerateContent"),
            WS_SCHEME_ALTS,
        ),
    },
    DialectClaim {
        dialect: Dialect::TwilioMediaStreams,
        claim: claim(
            TWILIO_TRANSPORT,
            Selector::PrefixOneLevel("/twilio"),
            TWILIO_SCHEME_ALTS,
        ),
    },
    DialectClaim {
        dialect: Dialect::OneShotTranscribe,
        claim: claim(
            HTTP_TRANSPORT,
            Selector::PathSuffix("/v1/audio/transcriptions"),
            HTTP_SCHEME_ALTS,
        ),
    },
    DialectClaim {
        dialect: Dialect::OneShotTts,
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

/// Which dialect a request's target names, by walking the claims in declaration order.
///
/// The same walk the kernel runs itself from the declared claims, exposed here so the decode step
/// can name the dialect it is about to read without a second, differently-ordered answer existing
/// anywhere.
#[must_use]
pub fn dialect_for(path: &str) -> Option<Dialect> {
    DIALECT_CLAIMS
        .iter()
        .find(|c| matches_selector(&c.claim.selector, path))
        .map(|c| c.dialect)
}

/// Whether one selector matches a request path.
///
/// Only the forms this plane's claims actually use are answered.
fn matches_selector(s: &Selector, path: &str) -> bool {
    match s {
        Selector::PathSuffix(suffix) => path.ends_with(suffix),
        Selector::PathContains(needle) => path.contains(needle),
        Selector::PrefixOneLevel(prefix) => {
            let Some(rest) = path.strip_prefix(prefix) else {
                return false;
            };
            let rest = rest.strip_prefix('/').unwrap_or(rest);
            !rest.is_empty()
        }
        _ => false,
    }
}
