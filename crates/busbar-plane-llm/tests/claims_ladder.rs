//! The claims are the detection ladder, in the ladder's own order.
//!
//! The ladder is the thing that decides which dialect a request is, and getting its ORDER wrong is
//! not a compile error and not a crash — it is a request quietly read as the wrong dialect. So the
//! order is asserted, rung by rung, and every rung is asserted to route what it claims to route.

mod harness;

use busbar_contract::grammar::Selector;
use busbar_contract::plane::PlaneMeta;
use busbar_plane_llm::claims::{CLAIMS, LADDER};
use busbar_plane_llm::LlmPlane;

/// THE LADDER THE PLANE WALKS IS EVERY SOURCE'S, AND IT IS STILL ONE THROUGH FOURTEEN.
///
/// This case used to read `LADDER` — the constant in this crate — because every rung was in it.
/// Rungs 7 and 14 are a carved-out dialect's now, declared in `busbar-plane-llm-openai` and merged
/// back in at registration, so reading the constant would assert about HALF the ladder and call the
/// gaps it found correct.
///
/// So the subject is the WALK, which is the thing that actually decides a request. It is asserted
/// to be exactly what it was before the split: ascending, and one through fourteen without a gap.
/// A carved-out rung that came back at the wrong number, or did not come back at all, fails here.
#[test]
fn the_walked_ladder_is_fourteen_rungs_in_ascending_order() {
    let plane = harness::plane(&[]);
    let mut seen: Vec<u16> = Vec::new();
    plane.walk_ladder(|c| seen.push(c.rung));
    assert!(
        seen.windows(2).all(|w| w[0] <= w[1]),
        "the merged ladder is not in rung order: {seen:?}"
    );
    seen.dedup();
    assert_eq!(
        seen,
        (1..=14).collect::<Vec<u16>>(),
        "the walked rungs are not one through fourteen without a gap"
    );
}

/// THE RUNGS THIS CRATE STILL DECLARES ASCEND, AND THE GAPS ARE THE CARVED-OUT DIALECTS'.
///
/// The plane's own constant is no longer contiguous, and that is the split rather than a defect —
/// but "no longer contiguous" is not a licence for any shape at all. Ascending is still required,
/// because the merge only walks an ordered source correctly, and a gap is only allowed where a
/// dialect crate took the rung.
#[test]
fn the_planes_own_rungs_ascend_and_gap_only_where_a_dialect_left() {
    let mut seen: Vec<u16> = LADDER.iter().map(|c| c.rung).collect();
    assert!(
        seen.windows(2).all(|w| w[0] <= w[1]),
        "the claims are not in rung order: {seen:?}"
    );
    seen.dedup();
    let missing: Vec<u16> = (1..=14).filter(|r| !seen.contains(r)).collect();
    assert_eq!(
        missing,
        vec![7, 14],
        "the rungs this crate no longer declares are not the ones a dialect crate took"
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
///
/// ASKED OF THE PLANE, not of this crate's own constant: two of the rungs below are a registered
/// dialect's, and the answer a request gets is the merged walk's answer. That the answers are
/// UNCHANGED — every one of the twenty-six requests routes where it routed before the split — is
/// the case that says the carve-out moved a declaration and not a behaviour.
#[test]
fn each_rung_routes_its_own_dialect() {
    let plane = harness::plane(&[]);
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
        // Not `/v1/audio/speech` and not `/v1/audio/transcriptions`: those two are the voice
        // plane's one-shot operations, and this plane's audio claim is the path it leaves behind.
        ("/v1/audio/translations", &[], "openai"),
    ];
    let mut walked = 0usize;
    plane.walk_ladder(|_| walked += 1);
    assert_eq!(
        cases.len(),
        walked,
        "every claim the plane walks needs a request that exercises it"
    );
    for (path, headers, expected) in cases {
        let header = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| *v)
        };
        assert_eq!(
            plane.dialect_for(path, &header),
            Some(*expected),
            "the request target {path} with headers {headers:?} routed to the wrong dialect"
        );
    }
}

/// A request that matches no rung names no dialect.
#[test]
fn an_unclaimed_request_names_no_dialect() {
    let plane = harness::plane(&[]);
    let none = |_: &str| None;
    assert_eq!(plane.dialect_for("/healthz", &none), None);
    assert_eq!(plane.dialect_for("/", &none), None);
    assert_eq!(plane.dialect_for("/api/status", &none), None);
}

/// A header rung beats a path rung, whichever way the request is built.
///
/// This is the whole point of the ordering: a request whose target says one dialect and whose
/// headers say another is the header's, because a header a client sent deliberately is stronger
/// evidence than a path shape several dialects share.
#[test]
fn a_header_rung_wins_over_a_path_rung() {
    let plane = harness::plane(&[]);
    let goog = |name: &str| (name == "x-goog-api-key").then_some("k");
    assert_eq!(
        plane.dialect_for("/v1/chat/completions", &goog),
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

    // ASKED OF THE PLANE, so a carved-out dialect is asked through its registration and the six are
    // still six. Reading `DIALECTS` here would have counted the five that remain and called the
    // total correct.
    let plane = harness::plane(&[]);
    let row = |name: &str| {
        plane
            .locations(name)
            .expect("the dialect is one this plane speaks")
    };

    for name in ["gemini", "bedrock"] {
        assert_eq!(
            row(name).model_location,
            Location::Arrival(ArrivalLocation::PathSegment(0)),
            "{name} does not name the path segment its model is in"
        );
    }
    for name in ["anthropic", "openai", "responses", "cohere"] {
        assert_eq!(
            row(name).model_location,
            Location::Arrival(ArrivalLocation::FirstFrameJsonPointer("/model")),
            "{name} does not name the body member its model is in"
        );
    }

    // Exactly two of the six, so a seventh dialect added on either side is a visible change here.
    let mut carried = 0usize;
    let mut total = 0usize;
    plane.walk_dialects(|d| {
        total += 1;
        if matches!(
            d.model_location,
            Location::Arrival(ArrivalLocation::PathSegment(_))
        ) {
            carried += 1;
        }
    });
    assert_eq!(total, 6, "the plane no longer speaks all six dialects");
    assert_eq!(carried, 2);
}
