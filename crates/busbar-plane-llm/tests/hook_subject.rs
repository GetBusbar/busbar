//! What a HOOK is told this plane's unit is about, checked against a real request of each dialect.
//!
//! The subject a policy hook decides about here is the MODEL the caller asked for and the document
//! that asks for it. Neither is a value this plane computes — both are LOCATIONS it declares, on the
//! same terms as every other step — so what can be checked is that the places it declares are the
//! places the client actually used, and that they are the SAME places the admission step already
//! names. The second half is the one that matters: two answers about where the model is would be two
//! opinions, and a hook screening one while the door prices the other is the defect this face exists
//! to make impossible.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::plane::{Ingress, Plane};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::LlmPlane;

/// One real request of one dialect, of the shape a client of that dialect sends.
///
/// Four dialects rather than one, and four different places for the model: two carry it in the body
/// under different member names, one carries it in the request target, and one does not carry it at
/// all. A face that answered with a constant would pass on the first and fail on the rest.
const BODIES: &[(&str, &str)] = &[
    (
        "anthropic",
        r#"{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello there"}],"max_tokens":64}"#,
    ),
    (
        "openai",
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello there"}],"max_tokens":64}"#,
    ),
    (
        "gemini",
        r#"{"contents":[{"role":"user","parts":[{"text":"hello there"}]}],"generationConfig":{"maxOutputTokens":64}}"#,
    ),
    (
        "bedrock",
        r#"{"messages":[{"role":"user","content":[{"text":"hello there"}]}],"inferenceConfig":{"maxTokens":64}}"#,
    ),
];

/// Build the node the plane runs in, ONCE, and hand it to `f`.
///
/// One construction site for the arriving stack in this whole file, deliberately: this plane is
/// blind to the transport axis and a test file that names a wire in every function is a test file
/// that has taken an opinion about which wire the plane serves. Everything below reaches the stack
/// through here.
fn with_ctx(dialect: &str, f: impl FnOnce(&LlmPlane, &busbar_contract::unit::Ctx<'_>)) {
    let plane = LlmPlane::new(&[]);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for(dialect), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    f(&plane, &ctx);
}

/// Run one fixture through the real decode, then hand the unit to `check` — the same shape
/// `admit_facts.rs` uses, so both steps are asked about the same unit the shipped path builds.
fn on_unit(
    dialect: &str,
    body: &str,
    check: impl FnOnce(&LlmPlane, &busbar_contract::unit::Unit<'_>, &busbar_contract::unit::Ctx<'_>),
) {
    with_ctx(dialect, |plane, ctx| {
        let frames = vec![harness::frame(body.as_bytes())];
        let mut cursor = FrameCursor::new(&frames);
        let draft = match plane.decode_ingress(&mut cursor, None, ctx) {
            Ok(Ingress::OneShot(draft)) => draft,
            other => {
                panic!("the {dialect} fixture must decode as one complete unit, got {other:?}")
            }
        };
        let unit = harness::unit(draft.op, draft.body_ir, draft.facts);
        check(plane, &unit, ctx);
    });
}

/// The hook's subject locator IS the admission step's lane locator — one answer, not two agreeing
/// ones.
///
/// This is the identity the face is worth having. A hook is asked to decide about the model, and the
/// door is asked to price the lane; if those two resolved different places, an operator could write
/// a gate that screens one model while the request is admitted, held and billed against another, and
/// nothing on the wire would show it. Asserting equality of the LOCATORS rather than of two resolved
/// strings is deliberate: it fails on the commit that introduces a second opinion, not on the
/// request that happens to expose it.
#[test]
fn the_hook_subject_is_the_lane_the_door_prices() {
    for (dialect, body) in BODIES {
        on_unit(dialect, body, |plane, unit, ctx| {
            let subject = plane
                .hook_subject(unit, ctx)
                .expect("a decoded request of a declared dialect has a subject");
            let admit = plane.admit(unit, ctx);
            assert_eq!(
                subject.subject_locator, admit.lane_locator,
                "{dialect}: the place a hook screens the model must be the place the door prices it"
            );
        });
    }
}

/// The argument payload a content-granted hook is shown is the WHOLE request document.
///
/// Narrower would be wrong on this plane and the narrowing is tempting, because the admission step
/// already computes a smaller span — the priced input. But the priced input is the conversation, and
/// a guardrail's job includes the controls around it: the tool definitions it may invoke, the
/// response format it may be coerced into. A hook shown only what is billed would be blind to the
/// half of the request an injection attack is carried in.
#[test]
fn a_granted_hook_is_shown_the_whole_document() {
    for (dialect, body) in BODIES {
        on_unit(dialect, body, |plane, unit, ctx| {
            let subject = plane
                .hook_subject(unit, ctx)
                .expect("a decoded request of a declared dialect has a subject");
            let span = subject
                .argument_span
                .unwrap_or_else(|| panic!("{dialect}: a request with a body has an argument span"));
            let bytes = unit.body().body();
            assert_eq!(
                (span.start, span.end),
                (0, bytes.len()),
                "{dialect}: the argument payload is the request document, entire"
            );
            assert_eq!(
                &bytes[span.start..span.end],
                body.as_bytes(),
                "{dialect}: the span must resolve to the bytes the client actually sent"
            );
        });
    }
}

/// A body of a dialect this plane does not serve names no subject — it does not name an empty one.
///
/// `None` and `Some(everything absent)` are different answers and the difference is load-bearing: a
/// gate attached to something that answers `None` is an operator error the composition can report,
/// while a gate handed an empty payload would read it as content screened clean. Fail-closed means
/// the absence has to be visible.
#[test]
fn an_unresolvable_dialect_names_no_subject_rather_than_an_empty_one() {
    with_ctx("anthropic", |plane, ctx| {
        // A unit with no dialect fact at all: the shape the plane sees when the decode step never
        // resolved one, which is exactly when it has nothing to say about a subject.
        let unit = harness::unit(
            busbar_contract::ids::OpClassId::new("chat"),
            busbar_contract::bounded::Ir::empty(),
            busbar_contract::bounded::Facts::new(),
        );
        assert!(
            plane.hook_subject(&unit, ctx).is_none(),
            "a unit whose dialect was never resolved has no subject to name"
        );
    });
}
