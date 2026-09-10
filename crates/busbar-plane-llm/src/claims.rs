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
///
/// PUBLIC because a dialect crate builds its OWN rungs with it. Every claim of this plane — the
/// plane's own and every dialect's — is built here, so the transport, the scheme and the
/// alternative set a claim carries are stated once and cannot be restated differently by a crate
/// that registers into this plane later.
#[must_use]
pub const fn claim(selector: Selector) -> Claim {
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

    // RUNGS 2 AND 4 ARE NOT HERE. They are the first HEADER rungs to leave this table — two version
    // headers at two and a key header at four — and they belong to the dialect crate that claims
    // them, `busbar-plane-llm-anthropic`. The registry's merged walk interleaves a registered
    // header rung at its number exactly as it does a path rung, so a request carrying one of those
    // headers is still answered at two or four, above every path rung, as it always was.

    // RUNGS 3, 5 AND 6 ARE NOT HERE. They belong to `busbar-plane-llm-gemini`: a key header at
    // three, five action suffixes at five and the model-scoped surface as two path PATTERNS at six
    // — the first pattern rungs to leave this table, and the loosest path family of the six. The
    // merged walk interleaves them at their numbers, so a bare `/v1beta/models/...` request is
    // still answered at six, above the chat suffixes another vendor could share.

    // RUNG 7 IS NOT HERE. It is the widely-copied chat surface, and it belongs to the dialect crate
    // that claims it — `busbar-plane-llm-openai` declares it and the registry's merged walk
    // interleaves it back at seven, so a request that reached rung 7 before reaches it still. A gap
    // in this table is what a carved-out dialect looks like from the plane's side.

    // Rung 8: another vendor's chat surface, on either of its two versions.
    8 => "cohere", Selector::PathSuffix("/v2/chat"),
    8 => "cohere", Selector::PathSuffix("/v1/chat"),

    // Rung 9: that vendor's two non-chat surfaces.
    9 => "cohere", Selector::PathSuffix("/v2/embed"),
    9 => "cohere", Selector::PathSuffix("/v2/rerank"),

    // RUNG 10 IS NOT HERE. It was one vendor's second, newer request surface, and it belongs to the
    // dialect crate that claims it — `busbar-plane-llm-responses` declares it and the registry's
    // merged walk interleaves it back at ten, so a request that reached rung 10 before reaches it
    // still. It is the second gap in this table, and a second gap is what says the split is a
    // pattern rather than one carve-out.

    // RUNG 11 IS NOT HERE EITHER; it left with rungs 2 and 4, because all three are the same
    // dialect's. It was the path a request reached only when no vendor header claimed it first.

    // Rung 12: one vendor's turn-shaped surface.
    12 => "bedrock", Selector::PathContains("/converse"),

    // Rung 13: the same vendor's model-scoped invoke path.
    13 => "bedrock", Selector::PathPattern(MODEL_INVOKE),

    // RUNG 14 IS NOT HERE EITHER, and it left with rung 7 because both are the same dialect's. It
    // was the loosest rung this table had — the non-chat surfaces of the widely-copied vocabulary —
    // and the reasoning that shaped it went with it to the crate that owns it: the audio surface is
    // named one path at a time rather than as a `/v1/audio/` prefix, because two of that prefix's
    // three paths are the voice plane's by the architecture's own plane inventory.
    //
    // Rung 13 is therefore the last rung this crate declares. That is not a ceiling: the merged
    // walk is over every source, so a registered dialect's rung fifteen would be walked after this
    // one without a line changing here.
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
