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
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);

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

/// Meter one STREAMED answer frame and return the lines as (class, quantity) pairs.
///
/// The same walk as [`meter`], except the answer arrives as a server-sent event rather than as a
/// whole document. Nothing else about the unit changes: same request, same upstream, same dialect.
fn meter_event(event: &str) -> Vec<(String, Option<u64>)> {
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
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);

    let frames = vec![harness::frame(event.as_bytes())];
    let mut answers = FrameCursor::new(&frames);
    let response = match plane
        .decode_response(&mut answers, &dest, None, &ctx)
        .expect("reads the answer")
    {
        Progress::Terminal { r, .. } | Progress::Frame { r, .. } => r,
        other => panic!("an answer frame must carry a response, got {other:?}"),
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
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);

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

/// A streamed answer bills the tokens it reported.
///
/// The usage figures of a streamed answer ride in the final event's data payload, not in a bare
/// document. The metering step used to hand the whole event frame -- `data:` line and all -- to a
/// JSON parser, which failed, and a failed parse returned no lines at all: every streamed request
/// metered zero and settled free.
#[test]
fn a_streamed_usage_frame_meters_the_tokens_it_reports() {
    let event = "data: {\"id\":\"chatcmpl-4\",\"object\":\"chat.completion.chunk\",\"created\":1752000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":10,\"total_tokens\":110,\"prompt_tokens_details\":{\"cached_tokens\":80}}}\n\n";
    let lines = meter_event(event);
    assert_eq!(
        lines,
        vec![
            ("tokens_in".to_string(), Some(20)),
            ("tokens_out".to_string(), Some(10)),
            ("cache_read".to_string(), Some(80)),
        ],
        "a streamed answer metered nothing"
    );
}

/// The end-of-stream marker is not a document, and it meters nothing rather than failing.
#[test]
fn the_end_of_stream_marker_meters_nothing() {
    assert!(meter_event("data: [DONE]\n\n").is_empty());
}

/// One configured upstream speaking the dialect that reports all four classes at once.
///
/// This dialect states its two cache counts BESIDE its input total rather than inside it, so a
/// single answer of its shape exercises every class the plane can name. The other dialects report a
/// subset of the same four; none of them reports a fifth.
const ADDITIVE_UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-anthropic"),
    host: "anthropic.invalid",
    dialect: "anthropic",
    model: "claude",
}];

/// Every class the plane DECLARES is a class the metering step emits.
///
/// The companion of [`every_line_is_a_locator_for_a_declared_class`], and the direction that costs
/// money. A declared class is what an operator prices in the rate card; a class the plane never
/// reports posts NO line — not a zero line, no line — so the class prices at nothing, the invoice is
/// short by whatever it was worth, and nothing anywhere reports a discrepancy. Four classes were
/// declared for the non-chat operations and not one of them was ever emitted by any decode path.
///
/// So the two sets are asserted EQUAL. A class added to the declaration without a decode path that
/// reads it fails here, which is the moment to notice rather than the invoice.
#[test]
fn every_declared_class_is_a_class_the_metering_step_emits() {
    use busbar_contract::plane::PlaneMeta;
    let plane = LlmPlane::new(ADDITIVE_UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("anthropic"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("anthropic.invalid", LaneId::new("lane-anthropic"));

    let request =
        br#"{"model":"claude","max_tokens":32,"messages":[{"role":"user","content":"Hello"}]}"#;
    let request = vec![harness::frame(request)];
    let mut cursor = FrameCursor::new(&request);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("decodes")
    {
        busbar_contract::plane::Ingress::OneShot(draft) => draft,
        other => panic!("expected one complete unit, got {other:?}"),
    };
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);

    let answer = br#"{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":20,"output_tokens":10,"cache_read_input_tokens":80,"cache_creation_input_tokens":40}}"#;
    let frames = vec![harness::frame(answer)];
    let mut answers = FrameCursor::new(&frames);
    let response = match plane
        .decode_response(&mut answers, &dest, None, &ctx)
        .expect("reads the answer")
    {
        Progress::Terminal { r, .. } => r,
        other => panic!("a whole answer must be terminal, got {other:?}"),
    };

    let mut emitted: Vec<&str> = plane
        .meter(&unit, &response, &ctx)
        .lines
        .as_slice()
        .iter()
        .map(|line| line.class.as_str())
        .collect();
    emitted.sort_unstable();
    let mut declared: Vec<&str> = <LlmPlane as PlaneMeta>::METER_CLASSES
        .iter()
        .map(|class| class.key.as_str())
        .collect();
    declared.sort_unstable();
    assert_eq!(
        declared, emitted,
        "a class is declared that no answer can make the plane report, or reported that none declares"
    );
}
