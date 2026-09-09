//! What the admission step is told about a request, checked against a real request of each dialect.
//!
//! Two facts leave this plane at admission and both are money: WHERE the client's own response
//! ceiling is, which is what the hold is sized off, and WHICH BYTES are the priced input, which is
//! what the input side of the bill is measured over. Neither is a value this plane computes — both
//! are LOCATIONS it declares — so neither can be checked by reading the number that comes out. What
//! can be checked is that the location the plane declares is the location the client actually used,
//! and that is what the tests below do: build a real request of each dialect, run the real decode,
//! and ask the admission facts to resolve themselves against the body that arrived.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::plane::{Ingress, Plane};
use busbar_contract::unit::AdmitFacts;
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::dialect::{self, Dialect};

/// The ceiling every fixture below asks for, so one expected value serves every row.
const CEILING: &[u8] = b"64";

/// One request of one dialect, carrying its response ceiling under ONE named spelling.
///
/// The spelling is a field rather than a comment because the table is checked against the dialect
/// table: a dialect that grows a spelling and does not grow a row here fails the coverage check
/// below, so no spelling can be added and left unproven.
struct Request {
    /// The dialect whose door this request arrives at.
    dialect: &'static str,
    /// The one response-ceiling pointer this body carries the ceiling under.
    spelling: &'static str,
    /// The body, exactly as a client of that dialect sends it.
    body: &'static str,
}

/// One request per dialect per accepted ceiling spelling.
///
/// Every body carries the SAME ceiling — the value is never the point — and every body carries it
/// under exactly one of its dialect's accepted spellings, because a body carrying both would pass
/// whichever spelling the plane declared and prove nothing about the other.
const REQUESTS: &[Request] = &[
    Request {
        dialect: "anthropic",
        spelling: "/max_tokens",
        body: r#"{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello there"}],"max_tokens":64}"#,
    },
    Request {
        dialect: "openai",
        spelling: "/max_tokens",
        body: r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello there"}],"max_tokens":64}"#,
    },
    // The newer spelling, sent alone, exactly as a client of this vendor's reasoning models sends
    // it: those models refuse the older key outright, so such a client has no second spelling to
    // fall back on and a plane that names only the older one reads no ceiling at all.
    Request {
        dialect: "openai",
        spelling: "/max_completion_tokens",
        body: r#"{"model":"o3","messages":[{"role":"user","content":"hello there"}],"max_completion_tokens":64}"#,
    },
    Request {
        dialect: "gemini",
        spelling: "/generationConfig/maxOutputTokens",
        body: r#"{"contents":[{"role":"user","parts":[{"text":"hello there"}]}],"generationConfig":{"maxOutputTokens":64}}"#,
    },
    Request {
        dialect: "bedrock",
        spelling: "/inferenceConfig/maxTokens",
        body: r#"{"messages":[{"role":"user","content":[{"text":"hello there"}]}],"inferenceConfig":{"maxTokens":64}}"#,
    },
    Request {
        dialect: "responses",
        spelling: "/max_output_tokens",
        body: r#"{"model":"gpt-4o","input":[{"role":"user","content":"hello there"}],"max_output_tokens":64}"#,
    },
    Request {
        dialect: "cohere",
        spelling: "/max_tokens",
        body: r#"{"model":"command-r-plus","messages":[{"role":"user","content":"hello there"}],"max_tokens":64}"#,
    },
];

/// Run one fixture through the real decode and the real admission step, and hand what came out to
/// `check` alongside the unit it was derived from.
///
/// The unit is built the way the kernel builds one, over the draft the plane's own decode step
/// produced, so the span table the admission facts resolve against is the table the shipped path
/// resolves against — not one the test filled in.
fn admitting(
    request: &Request,
    check: impl FnOnce(&Dialect, &busbar_contract::unit::Unit<'_>, &AdmitFacts),
) {
    let plane = harness::plane(&[]);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for(request.dialect), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);

    let frames = vec![harness::frame(request.body.as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let draft = match plane.decode_ingress(&mut cursor, None, &ctx) {
        Ok(Ingress::OneShot(draft)) => draft,
        other => panic!(
            "the {} fixture must decode as one complete unit, got {other:?}",
            request.dialect
        ),
    };
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);
    // ASKED OF THE PLANE, not of the plane's own table. A dialect this crate carved out answers
    // through the registry and not through `dialect::DIALECTS`, and a case that consulted only the
    // closed table would be green for the five that have not moved and red for every one that has.
    let d = plane
        .locations(request.dialect)
        .expect("the fixture names a dialect this plane speaks");
    let facts = plane.admit(&unit, &ctx);
    check(d, &unit, &facts);
}

/// Every spelling of the response ceiling a dialect accepts is a spelling the admission facts read.
///
/// The ceiling sizes the HOLD — the money set aside before the upstream is called — and the plane
/// states it as a list of places rather than a value, so the kernel resolves the first place that
/// hits. A spelling declared in the dialect table and dropped on the way to the admission facts is
/// therefore invisible at the door it matters at: the request carries a ceiling, the plane finds
/// none, and the hold is sized off a key the client never sent. That is not a parse error and no
/// round-trip test sees it, because the bytes on the wire are unaffected.
///
/// Each fixture carries its ceiling under ONE spelling, and the assertion is the one the kernel
/// makes: resolve the declared places against the body that arrived, and read the ceiling out.
#[test]
fn every_accepted_ceiling_spelling_reaches_the_admission_facts() {
    for request in REQUESTS {
        admitting(request, |d, unit, facts| {
            let found = facts.max_response_bytes(&unit.body());
            assert_eq!(
                found,
                Some(CEILING),
                "the {} request carries its response ceiling under {} and the admission facts read \
                 {found:?} rather than the ceiling the client sent: the hold would be sized off a \
                 key that never arrived",
                d.name,
                request.spelling
            );
        });
    }
}

/// The priced input is the CONVERSATION the client sent, never the whole document around it.
///
/// The input side of the bill is measured over the span the admission step names, and a span that
/// widens to the whole body prices the controls: the model name, the sampling knobs, the tool
/// declarations, the response ceiling itself. Every one of those is a byte the client sent, so the
/// number that comes out is plausible, larger than it should be, and wrong in the customer's
/// disfavour on every single request — the failure mode a plane cannot be allowed to have.
///
/// Checked three ways, because a span can be wrong without being obviously wrong. It must be the
/// span the dialect's own conversation pointer resolves to. It must not be the whole body. And it
/// must not contain the ceiling member the fixture carries — the nearest control to the
/// conversation, and the one a span that reached one member too far would swallow first.
#[test]
fn the_priced_input_is_the_conversation_and_not_the_whole_body() {
    for request in REQUESTS {
        admitting(request, |d, unit, facts| {
            let body = unit.body().body();
            let span = facts.input_span.unwrap_or_else(|| {
                panic!(
                    "the {} request names no priced input at all, so the bill has no input side",
                    d.name
                )
            });
            let priced = body
                .get(span.start..span.end)
                .expect("the priced span lies inside the body it was resolved in");
            let conversation = unit.body().pointer(d.input_pointer).unwrap_or_else(|| {
                panic!(
                    "the {} fixture must carry its conversation under {}",
                    d.name, d.input_pointer
                )
            });

            assert_eq!(
                priced, conversation,
                "the {} request prices a span that is not what {} resolves to",
                d.name, d.input_pointer
            );
            assert_ne!(
                priced, body,
                "the {} request prices its WHOLE body as input, so every control the client sent \
                 is billed as conversation",
                d.name
            );
            let control = request
                .spelling
                .rsplit('/')
                .next()
                .expect("a pointer names at least one member");
            assert!(
                !windows_contain(priced, control.as_bytes()),
                "the {} request prices the {control} control as input: the span has reached past \
                 the conversation into the controls around it",
                d.name
            );
            assert!(
                windows_contain(priced, b"hello there"),
                "the {} request prices a span that does not contain the conversation the client \
                 sent, so the input side of the bill is measured over the wrong bytes",
                d.name
            );
        });
    }
}

/// Whether one byte string occurs in another.
fn windows_contain(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The fixtures above cover every spelling the dialect table declares, and only declared ones.
///
/// Without this the coverage test is only as good as the day it was written: a dialect that grows a
/// third accepted spelling would sail past a fixture set that names two. Checked in both
/// directions, so a fixture naming a spelling the table has since dropped is a failure too.
#[test]
fn the_fixtures_name_every_declared_ceiling_spelling() {
    for d in dialect::DIALECTS {
        let covered: Vec<&str> = REQUESTS
            .iter()
            .filter(|r| r.dialect == d.name)
            .map(|r| r.spelling)
            .collect();
        assert_eq!(
            covered,
            d.max_response_pointers.to_vec(),
            "the {} fixtures cover {covered:?}, and the dialect table declares {:?}: a spelling \
             with no fixture is a spelling nothing proves reaches the admission facts",
            d.name,
            d.max_response_pointers
        );
    }
}
