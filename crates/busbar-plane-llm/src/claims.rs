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

/// A path pattern that matches the whole model-scoped surface of one API version.
const V1_MODELS: &[PathSeg] = &[PathSeg::Lit("v1"), PathSeg::Lit("models"), PathSeg::Tail];

/// A path pattern that matches the whole model-scoped surface of the preview API version.
const V1BETA_MODELS: &[PathSeg] = &[
    PathSeg::Lit("v1beta"),
    PathSeg::Lit("models"),
    PathSeg::Tail,
];

/// The ladder, in rung order, tightest first.
///
/// Every rung of the codec crate's detection predicates appears here exactly once, and the rungs
/// appear in ascending order. The ladder test asserts both.
pub const LADDER: &[LadderClaim] = &[
    // Rung 1: a request signature in the authorization header is the tightest evidence there is —
    // no other dialect's clients ever send one.
    LadderClaim {
        rung: 1,
        dialect: "bedrock",
        claim: claim(Selector::HeaderPrefix("authorization", "AWS4-HMAC-SHA256")),
    },
    // Rung 2: two vendor-specific version headers, either of which names the dialect on its own.
    LadderClaim {
        rung: 2,
        dialect: "anthropic",
        claim: claim(Selector::HeaderPresent("anthropic-version")),
    },
    LadderClaim {
        rung: 2,
        dialect: "anthropic",
        claim: claim(Selector::HeaderPresent("anthropic-beta")),
    },
    // Rung 3: a vendor-specific key header.
    LadderClaim {
        rung: 3,
        dialect: "gemini",
        claim: claim(Selector::HeaderPresent("x-goog-api-key")),
    },
    // Rung 4: a key header two vendors could in principle send, which is why it sits below rung 2.
    LadderClaim {
        rung: 4,
        dialect: "anthropic",
        claim: claim(Selector::HeaderPresent("x-api-key")),
    },
    // Rung 5: the action suffixes of one vendor's model-scoped surface.
    LadderClaim {
        rung: 5,
        dialect: "gemini",
        claim: claim(Selector::PathContains(":generateContent")),
    },
    LadderClaim {
        rung: 5,
        dialect: "gemini",
        claim: claim(Selector::PathContains(":streamGenerateContent")),
    },
    LadderClaim {
        rung: 5,
        dialect: "gemini",
        claim: claim(Selector::PathContains(":embedContent")),
    },
    LadderClaim {
        rung: 5,
        dialect: "gemini",
        claim: claim(Selector::PathContains(":batchEmbedContents")),
    },
    LadderClaim {
        rung: 5,
        dialect: "gemini",
        claim: claim(Selector::PathContains(":predict")),
    },
    // Rung 6: the same vendor's model-scoped surface without an action suffix, on either version.
    LadderClaim {
        rung: 6,
        dialect: "gemini",
        claim: claim(Selector::PathPattern(V1_MODELS)),
    },
    LadderClaim {
        rung: 6,
        dialect: "gemini",
        claim: claim(Selector::PathPattern(V1BETA_MODELS)),
    },
    // Rung 7: the widely-copied chat surface.
    LadderClaim {
        rung: 7,
        dialect: "openai",
        claim: claim(Selector::PathSuffix("/v1/chat/completions")),
    },
    // Rung 8: another vendor's chat surface, on either of its two versions.
    LadderClaim {
        rung: 8,
        dialect: "cohere",
        claim: claim(Selector::PathSuffix("/v2/chat")),
    },
    LadderClaim {
        rung: 8,
        dialect: "cohere",
        claim: claim(Selector::PathSuffix("/v1/chat")),
    },
    // Rung 9: that vendor's two non-chat surfaces.
    LadderClaim {
        rung: 9,
        dialect: "cohere",
        claim: claim(Selector::PathSuffix("/v2/embed")),
    },
    LadderClaim {
        rung: 9,
        dialect: "cohere",
        claim: claim(Selector::PathSuffix("/v2/rerank")),
    },
    // Rung 10: one vendor's second, newer request surface.
    LadderClaim {
        rung: 10,
        dialect: "responses",
        claim: claim(Selector::PathSuffix("/v1/responses")),
    },
    // Rung 11: a path that names a dialect only because nothing tighter claimed it.
    LadderClaim {
        rung: 11,
        dialect: "anthropic",
        claim: claim(Selector::PathContains("/v1/messages")),
    },
    // Rung 12: one vendor's turn-shaped surface.
    LadderClaim {
        rung: 12,
        dialect: "bedrock",
        claim: claim(Selector::PathContains("/converse")),
    },
    // Rung 13: the same vendor's model-scoped invoke path.
    LadderClaim {
        rung: 13,
        dialect: "bedrock",
        claim: claim(Selector::PathPattern(MODEL_INVOKE)),
    },
    // Rung 14: the loosest rung — the non-chat surfaces of the widely-copied dialect.
    LadderClaim {
        rung: 14,
        dialect: "openai",
        claim: claim(Selector::PathSuffix("/v1/embeddings")),
    },
    LadderClaim {
        rung: 14,
        dialect: "openai",
        claim: claim(Selector::PathSuffix("/v1/moderations")),
    },
    LadderClaim {
        rung: 14,
        dialect: "openai",
        claim: claim(Selector::PathContains("/v1/images/")),
    },
    LadderClaim {
        rung: 14,
        dialect: "openai",
        claim: claim(Selector::PathContains("/v1/audio/")),
    },
];

/// The claims, in ladder order, as the declaration constant wants them.
///
/// This is the same list one field narrower. It is written out rather than derived because a
/// declaration is an associated constant, and a constant cannot run a loop over another constant.
pub const CLAIMS: &[Claim] = &[
    LADDER[0].claim,
    LADDER[1].claim,
    LADDER[2].claim,
    LADDER[3].claim,
    LADDER[4].claim,
    LADDER[5].claim,
    LADDER[6].claim,
    LADDER[7].claim,
    LADDER[8].claim,
    LADDER[9].claim,
    LADDER[10].claim,
    LADDER[11].claim,
    LADDER[12].claim,
    LADDER[13].claim,
    LADDER[14].claim,
    LADDER[15].claim,
    LADDER[16].claim,
    LADDER[17].claim,
    LADDER[18].claim,
    LADDER[19].claim,
    LADDER[20].claim,
    LADDER[21].claim,
    LADDER[22].claim,
    LADDER[23].claim,
    LADDER[24].claim,
];

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
/// Only the forms this plane's claims actually use are answered; any other form is not a match,
/// because a plane that guessed at a form it never declared would be answering a question it was
/// never asked.
fn matches_selector<'h>(
    s: &Selector,
    path: &str,
    header: &dyn Fn(&str) -> Option<&'h str>,
) -> bool {
    match s {
        Selector::HeaderPresent(name) => header(name).is_some(),
        Selector::HeaderPrefix(name, prefix) => header(name).is_some_and(|v| v.starts_with(prefix)),
        Selector::PathContains(needle) => path.contains(needle),
        Selector::PathSuffix(suffix) => path.ends_with(suffix),
        Selector::PathPattern(pattern) => pattern_matches(pattern, path),
        _ => false,
    }
}

/// Whether a segment pattern matches a concrete path.
///
/// The same rule the contract's own overlap check uses, one direction only: a variable takes one
/// segment and a tail takes whatever remains, including nothing.
fn pattern_matches(pattern: &[PathSeg], path: &str) -> bool {
    let mut segments = path.split('/').filter(|s| !s.is_empty());
    for seg in pattern {
        match seg {
            PathSeg::Tail => return true,
            PathSeg::Lit(lit) => match segments.next() {
                Some(s) if s == *lit => {}
                _ => return false,
            },
            PathSeg::Var => {
                if segments.next().is_none() {
                    return false;
                }
            }
        }
    }
    segments.next().is_none()
}
