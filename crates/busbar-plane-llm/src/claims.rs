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

/// A path pattern that matches a model-scoped invoke path.
const MODEL_INVOKE: &[PathSeg] = &[PathSeg::Lit("model"), PathSeg::Var, PathSeg::Lit("invoke")];

/// A path pattern that matches the model-scoped surface of one API version.
///
/// The variable segment before the tail is what makes this ONE model rather than the collection.
/// A tail swallows whatever remains including NOTHING, so a pattern that ended at the collection
/// name claimed the bare listing target too — a route with no model in it, no operation class here
/// for it, and no request document for this plane to read.
const V1_MODELS: &[PathSeg] = &[
    PathSeg::Lit("v1"),
    PathSeg::Lit("models"),
    PathSeg::Var,
    PathSeg::Tail,
];

/// A path pattern that matches the model-scoped surface of the preview API version.
///
/// Named one model at a time for the same reason as the stable version above.
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

    // Rung 6: the same vendor's model-scoped surface without an action suffix, on either version.
    6 => "gemini", Selector::PathPattern(V1_MODELS),
    6 => "gemini", Selector::PathPattern(V1BETA_MODELS),

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

    // Rung 13: the same vendor's model-scoped invoke path.
    13 => "bedrock", Selector::PathPattern(MODEL_INVOKE),

    // Rung 14: the loosest rung — the non-chat surfaces of the widely-copied dialect.
    //
    // The audio surface is named one path at a time rather than as the whole `/v1/audio/` prefix.
    // Two of that prefix's three paths — `transcriptions` and `speech` — are the one-shot operations
    // the architecture's plane inventory gives to the voice plane, and the voice plane claims them
    // by name. A prefix claim here claimed them too, so the two planes' claims overlapped on the
    // request rather than dividing it, and which one answered rested on the boot ordering agreeing
    // with the inventory rather than on either plane saying what it owns. What is left is the path
    // no other plane claims.
    14 => "openai", Selector::PathSuffix("/v1/embeddings"),
    14 => "openai", Selector::PathSuffix("/v1/moderations"),
    14 => "openai", Selector::PathContains("/v1/images/"),
    14 => "openai", Selector::PathSuffix("/v1/audio/translations"),
}

/// Which dialect a request's path and headers name, by walking the ladder in order.
///
/// The kernel does this walk itself from the declared claims; the same walk is exposed here so the
/// decode step can name the dialect it is about to read without a second, differently-ordered
/// answer existing anywhere.
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
