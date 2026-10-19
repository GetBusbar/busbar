//! The claims this plane makes over arriving bytes.
//!
//! The design pins the protocol-detection ladder rung by rung, and the rungs are already written
//! down: each dialect module of the codec crate carries a predicate that answers "do I claim these
//! bytes, and how tightly", and the tightness number IS the rung. This module says the same thing in
//! the contract's own vocabulary — one claim per selector, in rung order — so the kernel can decide
//! the routing question at boot instead of running a hand-ordered chain of ifs per request.
//!
//! Two notes on the translation, because neither is free:
//!
//! A rung that tests two headers, or four paths, is several claims here. The contract's claim
//! carries exactly one selector, and that is the right shape: a boot that has to decide whether two
//! claims could match the same bytes cannot do it through an unexplained disjunction. The rung
//! numbering below records which claims came from one rung, so the order is still checkable against
//! the ladder.
//!
//! Within one plane the claims are an ordered set with most-specific-wins precedence, so the fact
//! that a header-present claim conservatively overlaps another claim on the same header is expected
//! and is not a boot refusal. The overlap rule is what stops two DIFFERENT planes claiming one
//! request; ordering is what settles a contest inside this one.
//!
//! ## One ladder, 1.5.5's
//!
//! The ladder the served door walks is each dialect's own claim predicate, folded tightest-first
//! ([`crate::exchange::arrive::detect`]); this table states the same ladder as declared claims. The
//! two are held to ONE answer, and that answer is 1.5.5's router (`proto/detect.rs`
//! `protocol_id`), by a test that walks both over 1.5.5's whole resolver table and the shapes the
//! two once disagreed on (`tests/claims_ladder.rs`). Every rung below reproduces a 1.5.5 rung:
//! rung 6 is 1.5.5's `/v1{,beta}/models/` PREFIX, so a bare `/v1/models` (the listing) names no
//! dialect; rung 13 is 1.5.5's `/model/` ... `/invoke`, whatever lies between; and rung 14 holds
//! 1.5.5's whole `/v1/audio/` surface.
//!
//! The selector grammar reads a path as its non-empty segments, where 1.5.5 compared raw strings,
//! so the two pattern rungs (6 and 13) can read a path carrying an empty segment (`//`) differently
//! from 1.5.5. No other shape differs.

use busbar_contract::grammar::{Claim, PathSeg, Selector};

/// The transport every one of this plane's claims is made against.
///
/// The plane names a transport only as a claim. It never holds a connection, and the streaming
/// shape is the same transport's own event framing rather than a second claim here.
pub const TRANSPORT: &str = "http";

/// The streaming transport this plane also claims.
///
/// A streamed answer arrives on the event-stream framing of the same request, so the claims below
/// are made against the request transport and this key names the framing the response uses.
pub const STREAM_TRANSPORT: &str = "sse";

/// The credential scheme this plane's claims authenticate under.
///
/// One scheme with alternatives, not several schemes: which alternative a unit uses is the
/// authenticate step's answer, and a plane may only narrow within the set declared here.
const SCHEME: &str = "llm-key";

/// The alternatives a unit may be narrowed to.
///
/// The bearer form covers every dialect whose clients present a token in a header. The signed form
/// is the one dialect whose clients present a request signature instead, and the signing scheme is
/// the auth kind's business, never this plane's.
const SCHEME_ALTS: &[&str] = &["bearer", "api-key", "request-signature"];

/// One claim, with the ladder rung it came from recorded beside it.
///
/// The rung is carried so the ladder test can assert the order without re-deriving it from the
/// selector shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LadderClaim {
    /// Which rung of the detection ladder this claim is.
    pub rung: u16,
    /// Which dialect the rung names.
    pub dialect: &'static str,
    /// The claim itself.
    pub claim: Claim,
}

/// Build one claim over a selector.
const fn claim(selector: Selector) -> Claim {
    Claim {
        transport: TRANSPORT,
        selector,
        scheme: Some(SCHEME),
        scheme_alternatives: SCHEME_ALTS,
        // The design says an idempotency location is claim CONFIG for this plane, and that a
        // migrated configuration carries none. Declaring one here would change the shape of every
        // request that reaches the upstream, so none is declared.
        idempotency: None,
    }
}

/// A path pattern that matches a model-scoped invoke path: `/model/`, one or more segments (a model
/// id an unencoded client sends with its own `/` spans several), then `invoke` — 1.5.5's
/// `starts_with("/model/") && ends_with("/invoke")`.
const MODEL_INVOKE: &[PathSeg] = &[PathSeg::Lit("model"), PathSeg::Plus, PathSeg::Lit("invoke")];

/// A path pattern that matches the model-scoped surface of one API version: `/v1/models/` and at
/// least one segment after it — 1.5.5's `/v1/models/` prefix, which the bare listing path
/// `/v1/models` does not carry.
const V1_MODELS: &[PathSeg] = &[
    PathSeg::Lit("v1"),
    PathSeg::Lit("models"),
    PathSeg::Var,
    PathSeg::Tail,
];

/// The same surface of the preview API version (1.5.5's `/v1beta/models/` prefix).
const V1BETA_MODELS: &[PathSeg] = &[
    PathSeg::Lit("v1beta"),
    PathSeg::Lit("models"),
    PathSeg::Var,
    PathSeg::Tail,
];

busbar_contract::claims_from_ladder! {
    /// The ladder, in rung order, tightest first.
    ///
    /// Every rung of the codec crate's detection predicates appears here exactly once, and the
    /// rungs appear in ascending order. The ladder test asserts both.
    LADDER,
    /// The claims, in ladder order, as the declaration constant wants them.
    ///
    /// The same list one field narrower. It used to be twenty-five lines transcribed by index
    /// beside the ladder itself, because a constant cannot loop over a constant; the macro writes
    /// both from the one table below, so a rung added in one and forgotten in the other is not a
    /// shape this file can take.
    CLAIMS,
    LadderClaim,
    claim,

    // Rung 1: a request signature in the authorization header is the tightest evidence there is —
    // no other dialect's clients ever send one.
    1 => "bedrock", Selector::HeaderPrefix("authorization", "AWS4-HMAC-SHA256"),

    // Rung 2: two vendor-specific version headers, either of which names the dialect on its own.
    2 => "anthropic", Selector::HeaderPresent("anthropic-version"),
    2 => "anthropic", Selector::HeaderPresent("anthropic-beta"),

    // Rung 3: a vendor-specific key header.
    3 => "gemini", Selector::HeaderPresent("x-goog-api-key"),

    // Rung 4: a key header two vendors could in principle send, which is why it sits below rung 2.
    4 => "anthropic", Selector::HeaderPresent("x-api-key"),

    // Rung 5: the action suffixes of one vendor's model-scoped surface.
    5 => "gemini", Selector::PathContains(":generateContent"),
    5 => "gemini", Selector::PathContains(":streamGenerateContent"),
    5 => "gemini", Selector::PathContains(":embedContent"),
    5 => "gemini", Selector::PathContains(":batchEmbedContents"),
    5 => "gemini", Selector::PathContains(":predict"),

    // Rung 6: the same vendor's model-scoped surface without an action suffix, on either version:
    // 1.5.5's `/v1{,beta}/models/` prefix. A pattern needs a segment after `models`, so the prefix
    // with nothing after it is its own exact path.
    6 => "gemini", Selector::PathPattern(V1_MODELS),
    6 => "gemini", Selector::PathPattern(V1BETA_MODELS),
    6 => "gemini", Selector::ExactPath("/v1/models/"),
    6 => "gemini", Selector::ExactPath("/v1beta/models/"),

    // Rung 7: the widely-copied chat surface.
    7 => "openai", Selector::PathSuffix("/v1/chat/completions"),

    // Rung 8: another vendor's chat surface, on either of its two versions.
    8 => "cohere", Selector::PathSuffix("/v2/chat"),
    8 => "cohere", Selector::PathSuffix("/v1/chat"),

    // Rung 9: that vendor's two non-chat surfaces.
    9 => "cohere", Selector::PathSuffix("/v2/embed"),
    9 => "cohere", Selector::PathSuffix("/v2/rerank"),

    // Rung 10: one vendor's second, newer request surface.
    10 => "responses", Selector::PathSuffix("/v1/responses"),

    // Rung 11: a path that names a dialect only because nothing tighter claimed it.
    11 => "anthropic", Selector::PathContains("/v1/messages"),

    // Rung 12: one vendor's turn-shaped surface.
    12 => "bedrock", Selector::PathContains("/converse"),

    // Rung 13: the same vendor's model-scoped invoke path. `/model/invoke` is 1.5.5's too (it
    // starts with `/model/` and ends with `/invoke`); the pattern needs a segment between, so it
    // is stated as its own exact path.
    13 => "bedrock", Selector::PathPattern(MODEL_INVOKE),
    13 => "bedrock", Selector::ExactPath("/model/invoke"),

    // Rung 14: the loosest rung — the non-chat surfaces of the widely-copied dialect, 1.5.5's set
    // exactly: the whole `/v1/audio/` surface (transcriptions, translations and speech) with them.
    14 => "openai", Selector::PathSuffix("/v1/embeddings"),
    14 => "openai", Selector::PathSuffix("/v1/moderations"),
    14 => "openai", Selector::PathContains("/v1/images/"),
    14 => "openai", Selector::PathContains("/v1/audio/"),
}

/// Which dialect a request's path and headers name, by walking the DECLARED ladder in order.
///
/// The served door does not call this: it names an arrival's dialect by folding each dialect's
/// own claim predicate ([`crate::exchange::arrive::detect`]). This walk answers what the
/// declaration says, and the ladder test holds the two to one answer, 1.5.5's, over its whole
/// resolver table.
#[must_use]
pub fn dialect_for<'h>(
    path: &str,
    header: &dyn Fn(&str) -> Option<&'h str>,
) -> Option<&'static str> {
    LADDER
        .iter()
        .find(|c| matches_selector(&c.claim.selector, path, header))
        .map(|c| c.dialect)
}

/// Whether one selector matches a request's path and headers.
///
/// PUBLIC so the crate's own conformance tests can walk every form; this crate compiles no
/// conditionally-compiled item, so a test of a private helper has nowhere to live.
///
/// EVERY form is answered explicitly. A wildcard arm here would silently answer "no match" for a
/// form added to the vocabulary later, which is the one way a claim this plane declares could stop
/// being evaluated without anything failing to compile.
///
/// The forms this plane cannot answer are the ones about the CONNECTION rather than the request --
/// the handshake name, the client certificate, the stream, the protocol, the local port. Nothing
/// here is given any of them, so `false` is the honest answer and not a default: a plane that
/// guessed at a fact it was never handed would be routing on something it made up.
#[must_use]
pub fn matches_selector<'h>(
    s: &Selector,
    path: &str,
    header: &dyn Fn(&str) -> Option<&'h str>,
) -> bool {
    match s {
        Selector::ExactPath(p) => path == *p,
        Selector::PrefixOneLevel(prefix) => busbar_contract::grammar::one_level_under(prefix, path),
        Selector::PathPattern(pattern) => busbar_contract::grammar::pattern_matches(pattern, path),
        Selector::PathSuffix(suffix) => path.ends_with(suffix),
        Selector::PathContains(needle) => path.contains(needle),
        Selector::HeaderExact(name, value) => header(name) == Some(*value),
        Selector::HeaderPresent(name) => header(name).is_some(),
        Selector::HeaderPrefix(name, prefix) => header(name).is_some_and(|v| v.starts_with(prefix)),
        Selector::Sni(_)
        | Selector::ClientCertSubject(_)
        | Selector::StreamName(_)
        | Selector::Alpn(_)
        | Selector::Port(_) => false,
    }
}
