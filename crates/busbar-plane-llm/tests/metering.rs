//! The metering step returns locators, and the quantities in them are already normalized.
//!
//! Two things are asserted here and they are the two that decide a bill.
//!
//! The plane returns no total, no price and no decision — only which class, where the number is,
//! and the number the codec already read. That is the whole of what a plane is allowed to say about
//! money.
//!
//! And the four classes partition the input once. Some dialects report a cached count INSIDE their
//! input total and some report it beside; a plane that added the two families together for the
//! first kind would bill the cached prefix twice. The codec's reader is where that is settled, and
//! the case below is the one where getting it wrong is worth eighty tokens a request.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Plane, Progress};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::{LlmPlane, Upstream};

/// One configured upstream, speaking the dialect the answers below are written in.
const UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-openai"),
    host: "openai.invalid",
    dialect: "openai",
    model: "gpt-4o-mini",
}];

/// The request that opens the unit.
const REQUEST: &str =
    r#"{"model":"gpt-4o-mini","max_tokens":32,"messages":[{"role":"user","content":"Hello"}]}"#;

/// Meter one answer and return the lines as (class, quantity) pairs.
fn meter(answer: &str) -> Vec<(String, Option<u64>)> {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("openai"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("openai.invalid", LaneId::new("lane-openai"));

    let request = vec![harness::frame(REQUEST.as_bytes())];
    let mut cursor = FrameCursor::new(&request);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("decodes")
    {
        busbar_contract::plane::Ingress::OneShot(draft) => draft,
        other => panic!("expected one complete unit, got {other:?}"),
    };
    let unit = harness::unit(draft.op, draft.body_ir);

    let frames = vec![harness::frame(answer.as_bytes())];
    let mut answers = FrameCursor::new(&frames);
    let response = match plane
        .decode_response(&mut answers, &dest, None, &ctx)
        .expect("reads the answer")
    {
        Progress::Terminal { r, .. } => r,
        other => panic!("a whole answer must be terminal, got {other:?}"),
    };
    plane
        .meter(&unit, &response, &ctx)
        .lines
        .as_slice()
        .iter()
        .map(|l| (l.class.as_str().to_string(), l.quantity))
        .collect()
}

/// A cached prefix is counted once, not twice.
///
/// This dialect's wire total INCLUDES the cached count: a hundred prompt tokens of which eighty
/// were served from a cache. The two lines must read twenty and eighty, not a hundred and eighty.
#[test]
fn a_cached_prefix_is_counted_once() {
    let answer = r#"{"id":"chatcmpl-1","object":"chat.completion","created":1752000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110,"prompt_tokens_details":{"cached_tokens":80}}}"#;
    let lines = meter(answer);
    assert_eq!(
        lines,
        vec![
            ("tokens_in".to_string(), Some(20)),
            ("tokens_out".to_string(), Some(10)),
            ("cache_read".to_string(), Some(80)),
        ],
        "the cached prefix was not subtracted from the wire input total"
    );
}

/// An answer with no cache accounting reports two lines, not four zeros.
///
/// A class the upstream said nothing about is absent, because "not reported" and "reported as zero"
/// are different facts and the settlement treats them differently.
#[test]
fn an_unreported_class_is_absent_rather_than_zero() {
    let answer = r#"{"id":"chatcmpl-2","object":"chat.completion","created":1752000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16}}"#;
    let lines = meter(answer);
    assert_eq!(
        lines,
        vec![
            ("tokens_in".to_string(), Some(12)),
            ("tokens_out".to_string(), Some(4)),
        ]
    );
}

/// Every line names where its number was found, and every class is one the plane declared.
#[test]
fn every_line_is_a_locator_for_a_declared_class() {
    use busbar_contract::plane::PlaneMeta;
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("openai"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("openai.invalid", LaneId::new("lane-openai"));

    let request = vec![harness::frame(REQUEST.as_bytes())];
    let mut cursor = FrameCursor::new(&request);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("decodes")
    {
        busbar_contract::plane::Ingress::OneShot(draft) => draft,
        other => panic!("expected one complete unit, got {other:?}"),
    };
    let unit = harness::unit(draft.op, draft.body_ir);

    let answer = r#"{"id":"chatcmpl-3","object":"chat.completion","created":1752000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110,"prompt_tokens_details":{"cached_tokens":80}}}"#;
    let frames = vec![harness::frame(answer.as_bytes())];
    let mut answers = FrameCursor::new(&frames);
    let response = match plane
        .decode_response(&mut answers, &dest, None, &ctx)
        .expect("reads the answer")
    {
        Progress::Terminal { r, .. } => r,
        other => panic!("a whole answer must be terminal, got {other:?}"),
    };

    let declared: Vec<&str> = <LlmPlane as PlaneMeta>::METER_CLASSES
        .iter()
        .map(|c| c.key.as_str())
        .collect();
    for line in plane.meter(&unit, &response, &ctx).lines.as_slice() {
        assert!(
            declared.contains(&line.class.as_str()),
            "the metering step named the undeclared class {}",
            line.class
        );
        assert!(
            line.location.is_some(),
            "the {} line says no place its number came from",
            line.class
        );
        assert!(
            line.lane.is_none(),
            "the answer named no lane, so no line may claim one"
        );
    }
}
