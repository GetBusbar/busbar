//! The claims are the detection ladder, in the ladder's own order.
//!
//! The ladder is the thing that decides which dialect a request is, and getting its ORDER wrong is
//! not a compile error and not a crash — it is a request quietly read as the wrong dialect. So the
//! order is asserted, rung by rung, and every rung is asserted to route what it claims to route.

use busbar_contract::grammar::Selector;
use busbar_contract::plane::PlaneMeta;
use busbar_plane_llm::claims::{dialect_for, CLAIMS, LADDER};
use busbar_plane_llm::LlmPlane;

/// The ladder has fourteen rungs, numbered without a gap.
#[test]
fn the_ladder_has_fourteen_rungs_in_ascending_order() {
    let mut seen: Vec<u16> = LADDER.iter().map(|c| c.rung).collect();
    assert!(
        seen.windows(2).all(|w| w[0] <= w[1]),
        "the claims are not in rung order: {seen:?}"
    );
    seen.dedup();
    assert_eq!(
        seen,
        (1..=14).collect::<Vec<u16>>(),
        "the rungs are not one through fourteen without a gap"
    );
}

/// What the plane declares is the ladder, one claim per entry, in the same order.
#[test]
fn the_declared_claims_are_the_ladder() {
    assert_eq!(<LlmPlane as PlaneMeta>::CLAIMS.len(), LADDER.len());
    for (declared, entry) in <LlmPlane as PlaneMeta>::CLAIMS.iter().zip(LADDER) {
        assert_eq!(*declared, entry.claim);
    }
    assert_eq!(CLAIMS.len(), LADDER.len());
}

/// Every claim is made against the one transport this plane claims, under one scheme.
#[test]
fn every_claim_names_one_transport_and_one_scheme() {
    let first = LADDER[0].claim;
    for entry in LADDER {
        assert_eq!(entry.claim.transport, first.transport);
        assert_eq!(entry.claim.scheme, first.scheme);
        assert_eq!(
            entry.claim.scheme_alternatives, first.scheme_alternatives,
            "a claim narrows to a different alternative set than its siblings"
        );
        assert!(
            entry.claim.idempotency.is_none(),
            "an idempotency rule is claim configuration, not a plane declaration"
        );
    }
}

/// One request built to exercise one rung: a request target, the headers it carries, and the
/// dialect the rung it exercises names.
type LadderCase = (
    &'static str,
    &'static [(&'static str, &'static str)],
    &'static str,
);

/// A request that matches only one rung is routed to that rung's dialect.
///
/// The cases are the rungs themselves: one request per rung, built to satisfy that rung and nothing
/// tighter, with the dialect the rung names as the expected answer.
#[test]
fn each_rung_routes_its_own_dialect() {
    let cases: &[LadderCase] = &[
        (
            "/anything",
            &[("authorization", "AWS4-HMAC-SHA256 Credential=x")],
            "bedrock",
        ),
        (
            "/anything",
            &[("anthropic-version", "2023-06-01")],
            "anthropic",
        ),
        (
            "/anything",
            &[("anthropic-beta", "tools-2024")],
            "anthropic",
        ),
        ("/anything", &[("x-goog-api-key", "k")], "gemini"),
        ("/anything", &[("x-api-key", "k")], "anthropic"),
        ("/v1beta/models/x:generateContent", &[], "gemini"),
        ("/v1beta/models/x:streamGenerateContent", &[], "gemini"),
        ("/v1beta/models/x:embedContent", &[], "gemini"),
        ("/v1beta/models/x:batchEmbedContents", &[], "gemini"),
        ("/v1beta/models/x:predict", &[], "gemini"),
        ("/v1/models/gpt-4o", &[], "gemini"),
        ("/v1beta/models/gemini", &[], "gemini"),
        ("/v1/chat/completions", &[], "openai"),
        ("/v2/chat", &[], "cohere"),
        ("/v1/chat", &[], "cohere"),
        ("/v2/embed", &[], "cohere"),
        ("/v2/rerank", &[], "cohere"),
        ("/v1/responses", &[], "responses"),
        ("/v1/messages", &[], "anthropic"),
        ("/model/claude/converse", &[], "bedrock"),
        ("/model/claude/invoke", &[], "bedrock"),
        ("/v1/embeddings", &[], "openai"),
        ("/v1/moderations", &[], "openai"),
        ("/v1/images/generations", &[], "openai"),
        ("/v1/audio/speech", &[], "openai"),
    ];
    assert_eq!(
        cases.len(),
        LADDER.len(),
        "every claim needs a request that exercises it"
    );
    for (path, headers, expected) in cases {
        let header = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| *v)
        };
        assert_eq!(
            dialect_for(path, &header),
            Some(*expected),
            "the request target {path} with headers {headers:?} routed to the wrong dialect"
        );
    }
}

/// A request that matches no rung names no dialect.
#[test]
fn an_unclaimed_request_names_no_dialect() {
    let none = |_: &str| None;
    assert_eq!(dialect_for("/healthz", &none), None);
    assert_eq!(dialect_for("/", &none), None);
    assert_eq!(dialect_for("/api/status", &none), None);
}

/// A header rung beats a path rung, whichever way the request is built.
///
/// This is the whole point of the ordering: a request whose target says one dialect and whose
/// headers say another is the header's, because a header a client sent deliberately is stronger
/// evidence than a path shape several dialects share.
#[test]
fn a_header_rung_wins_over_a_path_rung() {
    let goog = |name: &str| (name == "x-goog-api-key").then_some("k");
    assert_eq!(
        dialect_for("/v1/chat/completions", &goog),
        Some("gemini"),
        "a vendor key header must outrank a shared path shape"
    );
}

/// The selector forms this plane uses are the five the ladder needs and no others.
///
/// A form the transport cannot evaluate is refused at boot, so the set is worth pinning: a sixth
/// form appearing here is a claim that may not be evaluable where it is claimed.
#[test]
fn the_ladder_uses_only_the_forms_it_needs() {
    for entry in LADDER {
        assert!(
            matches!(
                entry.claim.selector,
                Selector::HeaderPresent(_)
                    | Selector::HeaderPrefix(_, _)
                    | Selector::PathContains(_)
                    | Selector::PathSuffix(_)
                    | Selector::PathPattern(_)
            ),
            "rung {} uses a selector form the ladder does not need: {:?}",
            entry.rung,
            entry.claim.selector
        );
    }
}
