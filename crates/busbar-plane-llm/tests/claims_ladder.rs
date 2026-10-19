//! The claims are the detection ladder, in the ladder's own order.
//!
//! The ladder is the thing that decides which dialect a request is, and getting its ORDER wrong is
//! not a compile error and not a crash — it is a request quietly read as the wrong dialect. So the
//! order is asserted, rung by rung, and every rung is asserted to route what it claims to route.

use busbar_contract::grammar::Selector;
use busbar_contract::plane::PlaneMeta;
use busbar_plane_llm::claims::{dialect_for, CLAIMS, LADDER};
use busbar_plane_llm::exchange::arrive::detect;
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
        ("/v1/models/", &[], "gemini"),
        ("/v1beta/models/", &[], "gemini"),
        ("/v1/chat/completions", &[], "openai"),
        ("/v2/chat", &[], "cohere"),
        ("/v1/chat", &[], "cohere"),
        ("/v2/embed", &[], "cohere"),
        ("/v2/rerank", &[], "cohere"),
        ("/v1/responses", &[], "responses"),
        ("/v1/messages", &[], "anthropic"),
        ("/model/claude/converse", &[], "bedrock"),
        ("/model/claude/invoke", &[], "bedrock"),
        ("/model/invoke", &[], "bedrock"),
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

/// The selector forms this plane uses are the six the ladder needs and no others.
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
                    | Selector::ExactPath(_)
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

/// The two dialects that carry the model in the request target say so, and the four that carry it
/// in the body say that.
///
/// The location is the value's ACTUAL place. It used to be a body pointer for all six, which was
/// only true because the arrival path had copied a target-carried model into the body first; a
/// location that describes where something was put rather than where it is is a location that goes
/// wrong the moment the putting stops.
#[test]
fn the_two_target_carried_dialects_name_a_path_segment() {
    use busbar_contract::grammar::{ArrivalLocation, Location};
    use busbar_plane_llm::dialect::{dialect, DIALECTS};

    for name in ["gemini", "bedrock"] {
        let d = dialect(name).expect("the dialect is in the table");
        assert_eq!(
            d.model_location,
            Location::Arrival(ArrivalLocation::PathSegment(0)),
            "{name} does not name the path segment its model is in"
        );
    }
    for name in ["anthropic", "openai", "responses", "cohere"] {
        let d = dialect(name).expect("the dialect is in the table");
        assert_eq!(
            d.model_location,
            Location::Arrival(ArrivalLocation::FirstFrameJsonPointer("/model")),
            "{name} does not name the body member its model is in"
        );
    }

    // Exactly two of the six, so a seventh dialect added on either side is a visible change here.
    let carried = DIALECTS
        .iter()
        .filter(|d| {
            matches!(
                d.model_location,
                Location::Arrival(ArrivalLocation::PathSegment(_))
            )
        })
        .count();
    assert_eq!(carried, 2);
}

/// ONE LADDER, 1.5.5'S. The declared ladder ([`dialect_for`] over [`LADDER`]) and the ladder the
/// served door walks ([`detect`], each dialect's own claim predicate) give ONE answer, and it is the
/// answer 1.5.5's router gave (v1.5.5 `crates/busbar/src/proto/detect.rs` `protocol_id`): every
/// path of 1.5.5's `resolver_table` (its body-disambiguated paths among them), and the shapes the
/// declared ladder once answered otherwise.
///
/// RED before the declared ladder was put back to 1.5.5's rungs: `/v1/models` (the listing) named
/// gemini because rung 6 was a pattern whose tail matched nothing; `/v1/audio/transcriptions` and
/// `/v1/audio/speech` named no dialect because rung 14 had dropped them; `/model/a/b/invoke` and
/// `/model/invoke` named none because rung 13 took exactly one segment between.
#[test]
fn the_declared_ladder_and_the_served_walk_are_one_ladder_1_5_5s() {
    type Case = (
        &'static str,
        &'static [(&'static str, &'static str)],
        Option<&'static str>,
    );
    let cases: &[Case] = &[
        // 1.5.5's resolver_table, the protocol column.
        ("/v1/chat/completions", &[], Some("openai")),
        ("/v1/embeddings", &[], Some("openai")),
        ("/v1/moderations", &[], Some("openai")),
        ("/v1/images/generations", &[], Some("openai")),
        ("/v1/audio/transcriptions", &[], Some("openai")),
        ("/v1/audio/translations", &[], Some("openai")),
        ("/v1/audio/speech", &[], Some("openai")),
        ("/v2/chat", &[], Some("cohere")),
        ("/v2/embed", &[], Some("cohere")),
        ("/v2/rerank", &[], Some("cohere")),
        ("/v1/responses", &[], Some("responses")),
        (
            "/claude-3/v1/messages",
            &[("anthropic-version", "2023-06-01")],
            Some("anthropic"),
        ),
        (
            "/v1/messages",
            &[("x-api-key", "sk-ant-xxx")],
            Some("anthropic"),
        ),
        (
            "/v1/messages",
            &[("anthropic-beta", "prompt-caching-2024-07-31")],
            Some("anthropic"),
        ),
        (
            "/v1beta/models/x:generateContent",
            &[("x-goog-api-key", "k")],
            Some("gemini"),
        ),
        ("/v1beta/models/x:embedContent", &[], Some("gemini")),
        ("/v1beta/models/x:predict", &[], Some("gemini")),
        (
            "/model/m/converse",
            &[("authorization", "AWS4-HMAC-SHA256 Credential=x")],
            Some("bedrock"),
        ),
        ("/v1/models", &[], None),
        ("/healthz", &[], None),
        // 1.5.5's body-disambiguated paths: the router named the dialect from the path alone.
        ("/model/m/invoke", &[], Some("bedrock")),
        ("/v1beta/models/x:generateContent", &[], Some("gemini")),
        // The shapes the declared ladder once answered otherwise.
        ("/v1/models/x", &[], Some("gemini")),
        ("/v1/models/", &[], Some("gemini")),
        ("/v1beta/models", &[], None),
        ("/v1beta/models/x", &[], Some("gemini")),
        ("/model/a/b/invoke", &[], Some("bedrock")),
        ("/model/invoke", &[], Some("bedrock")),
        ("/model/a", &[], None),
        ("/v1/audio/anything-else", &[], Some("openai")),
        // 1.5.5's header order: a header rung wins over every path rung.
        (
            "/v1/chat/completions",
            &[("x-goog-api-key", "k")],
            Some("gemini"),
        ),
        ("/v1/audio/speech", &[("x-api-key", "k")], Some("anthropic")),
    ];
    let mut differing = Vec::new();
    for (path, headers, want) in cases {
        let header = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| *v)
        };
        let fields: Vec<(&[u8], &[u8])> = headers
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect();
        let declared = dialect_for(path, &header);
        let served = detect(path, &fields);
        if declared != *want || served != *want {
            differing.push(format!(
                "{path} {headers:?}: 1.5.5 {want:?}, declared {declared:?}, served {served:?}"
            ));
        }
    }
    assert!(
        differing.is_empty(),
        "the declared ladder, the served walk and 1.5.5 are not one ladder:\n{}",
        differing.join("\n")
    );
}
