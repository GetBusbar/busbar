//! What `content_facts` reads off a finished or a streaming answer, checked value by value.
//!
//! `content_facts` has a purity twin in `purity.rs` (called twice, same answer both times) and a
//! parity twin in `golden_parity.rs` (the plane agrees with the codec it delegates to), but neither
//! checks that the FACTS THEMSELVES are the ones the answer actually carries — a purity test passes
//! on two wrong answers as readily as on two right ones. This file drives a real answer of each
//! shape (whole and streamed) through the real dialect readers and asserts on the model, the
//! identity, the finish reason and the tool-call count `content_facts` hands the export/audit path.
//!
//! The finish-reason table is the other half: `stop_name` is this plane's own closed vocabulary,
//! never the upstream's token, and every one of its nine names is exercised here against a real
//! upstream `finish_reason`/`stop_reason` that reads to it — six from Anthropic's own vocabulary,
//! and the three Anthropic cannot name (`safety`, `error`, an unmodeled token) from Cohere's, whose
//! reader is the one member of the dialect table that reaches all nine `IrStopReason` variants.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Ingress, Plane, Progress};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::meta;
use busbar_plane_llm::Upstream;

const ANTHROPIC_UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-anthropic"),
    host: "anthropic.invalid",
    dialect: "anthropic",
    model: "claude",
}];

const COHERE_UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-cohere"),
    host: "cohere.invalid",
    dialect: "cohere",
    model: "command-r",
}];

/// Decode one whole (non-streamed) answer and return the `content_facts` the plane reads off it.
fn whole_answer_facts(
    dialect: &str,
    upstreams: &'static [Upstream],
    request: &[u8],
    answer: &[u8],
) -> Vec<(String, String)> {
    let plane = harness::plane(upstreams);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for(dialect), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination(upstreams[0].host, upstreams[0].lane);

    let frames = vec![harness::frame(request)];
    let mut cursor = FrameCursor::new(&frames);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("the request decodes")
    {
        Ingress::OneShot(draft) => draft,
        other => panic!("expected one complete unit, got {other:?}"),
    };
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);

    let frames = vec![harness::frame(answer)];
    let mut answers = FrameCursor::new(&frames);
    let response = match plane
        .decode_response(&mut answers, &dest, None, &ctx)
        .expect("the answer decodes")
    {
        Progress::Terminal { r, .. } => r,
        other => panic!("a whole answer must be terminal, got {other:?}"),
    };

    pairs(&plane.content_facts(&unit, &response, &ctx).facts)
}

fn pairs(facts: &busbar_contract::bounded::Facts<'_>) -> Vec<(String, String)> {
    facts
        .iter()
        .map(|(k, v)| (k.to_string(), format!("{v:?}")))
        .collect()
}

fn get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

const ANTHROPIC_REQUEST: &[u8] =
    br#"{"model":"claude","max_tokens":32,"messages":[{"role":"user","content":"Hello"}]}"#;

/// A whole answer names its model, its identity, how it stopped, and how many tools it asked for.
///
/// Two tool-use blocks beside one text block, so the count is provably COUNTING the blocks rather
/// than reporting a fixed 0 or 1: a wrong implementation that always emitted `1` (the "there was
/// content" reading) or `0` (the "count is a v2 field, not read yet" reading) both fail this.
#[test]
fn a_whole_answer_names_its_model_identity_finish_and_tool_calls() {
    let answer = br#"{"id":"msg_42","type":"message","role":"assistant","model":"claude-3-5-sonnet","content":[{"type":"text","text":"Checking."},{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{"city":"Paris"}},{"type":"tool_use","id":"toolu_2","name":"get_time","input":{"city":"Paris"}}],"stop_reason":"tool_use","usage":{"input_tokens":50,"output_tokens":20}}"#;
    let facts = whole_answer_facts("anthropic", ANTHROPIC_UPSTREAMS, ANTHROPIC_REQUEST, answer);

    assert_eq!(
        get(&facts, meta::FACT_RESPONSE_MODEL),
        Some(r#"Str("claude-3-5-sonnet")"#),
        "the model the upstream reported: {facts:?}"
    );
    assert_eq!(
        get(&facts, meta::FACT_RESPONSE_ID),
        Some(r#"Str("msg_42")"#),
        "the upstream's own identifier for the answer: {facts:?}"
    );
    assert_eq!(
        get(&facts, meta::FACT_FINISH_REASON),
        Some(r#"Str("tool_use")"#),
        "the plane's own closed name for the stop reason: {facts:?}"
    );
    assert_eq!(
        get(&facts, meta::FACT_TOOL_CALLS),
        Some("Int(2)"),
        "two tool_use blocks, not the fixed 0 or 1 a wrong count would report: {facts:?}"
    );
}

/// An answer that names no tool use still reports the count: zero, not an absent fact.
#[test]
fn an_answer_with_no_tool_use_reports_zero_tool_calls() {
    let answer = br#"{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"Hi"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":2}}"#;
    let facts = whole_answer_facts("anthropic", ANTHROPIC_UPSTREAMS, ANTHROPIC_REQUEST, answer);
    assert_eq!(
        get(&facts, meta::FACT_TOOL_CALLS),
        Some("Int(0)"),
        "no tool_use block, so the count is zero rather than missing: {facts:?}"
    );
}

/// One finish-reason case: an upstream token that reads to a named [`busbar_llm_codec::ir::IrStopReason`]
/// renders under `stop_name`'s own closed word for it, never the upstream's own spelling.
struct FinishCase {
    /// The dialect whose vocabulary supplies the token.
    dialect: &'static str,
    upstreams: &'static [Upstream],
    request: &'static [u8],
    /// The answer, carrying the upstream's own token in its own field name.
    answer: &'static str,
    /// The plane's own closed name `stop_name` must render.
    want: &'static str,
}

const COHERE_REQUEST: &[u8] =
    br#"{"model":"command-r","messages":[{"role":"user","content":"Hello"}]}"#;

/// Every one of the nine `IrStopReason` variants, reached through a real upstream token.
///
/// Anthropic's own vocabulary reaches six (`end_turn`, `max_tokens`, `stop_sequence`, `tool_use`,
/// `pause_turn`, `refusal`); Cohere's reaches the other three this plane can still receive from an
/// upstream: `ERROR_TOXIC` (content-moderation stop, distinct from a generic error) and `ERROR`
/// (infrastructure failure) name `Safety` and `Error`, and an unmodeled token names the catch-all
/// `Other`. A finish reason silently mapped to the wrong word, or a variant `stop_name` forgot to
/// name at all, both fail one row here.
const FINISH_CASES: &[FinishCase] = &[
    FinishCase {
        dialect: "anthropic",
        upstreams: ANTHROPIC_UPSTREAMS,
        request: ANTHROPIC_REQUEST,
        answer: r#"{"id":"m1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#,
        want: "end_turn",
    },
    FinishCase {
        dialect: "anthropic",
        upstreams: ANTHROPIC_UPSTREAMS,
        request: ANTHROPIC_REQUEST,
        answer: r#"{"id":"m2","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hi"}],"stop_reason":"max_tokens","usage":{"input_tokens":1,"output_tokens":1}}"#,
        want: "max_tokens",
    },
    FinishCase {
        dialect: "anthropic",
        upstreams: ANTHROPIC_UPSTREAMS,
        request: ANTHROPIC_REQUEST,
        answer: r#"{"id":"m3","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hi"}],"stop_reason":"stop_sequence","usage":{"input_tokens":1,"output_tokens":1}}"#,
        want: "stop_sequence",
    },
    FinishCase {
        dialect: "anthropic",
        upstreams: ANTHROPIC_UPSTREAMS,
        request: ANTHROPIC_REQUEST,
        answer: r#"{"id":"m4","type":"message","role":"assistant","model":"claude","content":[{"type":"tool_use","id":"t1","name":"f","input":{}}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}"#,
        want: "tool_use",
    },
    FinishCase {
        dialect: "anthropic",
        upstreams: ANTHROPIC_UPSTREAMS,
        request: ANTHROPIC_REQUEST,
        answer: r#"{"id":"m5","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hi"}],"stop_reason":"pause_turn","usage":{"input_tokens":1,"output_tokens":1}}"#,
        want: "pause_turn",
    },
    FinishCase {
        dialect: "anthropic",
        upstreams: ANTHROPIC_UPSTREAMS,
        request: ANTHROPIC_REQUEST,
        answer: r#"{"id":"m6","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hi"}],"stop_reason":"refusal","usage":{"input_tokens":1,"output_tokens":1}}"#,
        want: "refusal",
    },
    FinishCase {
        dialect: "cohere",
        upstreams: COHERE_UPSTREAMS,
        request: COHERE_REQUEST,
        answer: r#"{"id":"c1","finish_reason":"ERROR_TOXIC","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]},"usage":{"tokens":{"input_tokens":1,"output_tokens":1}}}"#,
        want: "safety",
    },
    FinishCase {
        dialect: "cohere",
        upstreams: COHERE_UPSTREAMS,
        request: COHERE_REQUEST,
        answer: r#"{"id":"c2","finish_reason":"ERROR","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]},"usage":{"tokens":{"input_tokens":1,"output_tokens":1}}}"#,
        want: "error",
    },
    FinishCase {
        dialect: "cohere",
        upstreams: COHERE_UPSTREAMS,
        request: COHERE_REQUEST,
        // A token Cohere does not document and this reader does not model, so it must fall to the
        // catch-all rather than to any of the eight named variants.
        answer: r#"{"id":"c3","finish_reason":"USER_CANCEL","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]},"usage":{"tokens":{"input_tokens":1,"output_tokens":1}}}"#,
        want: "other",
    },
];

#[test]
fn every_stop_reason_variant_renders_its_own_closed_name() {
    // Every `stop_name` arm is named by some row above; a variant added to the enum without a row
    // here would still make this constant assertion pass, so the arm count is pinned directly.
    const IR_STOP_REASON_VARIANT_COUNT: usize = 9;
    let named: std::collections::HashSet<&str> = FINISH_CASES.iter().map(|c| c.want).collect();
    assert_eq!(
        named.len(),
        IR_STOP_REASON_VARIANT_COUNT,
        "the case table does not name exactly the nine IrStopReason variants: {named:?}"
    );

    for case in FINISH_CASES {
        let facts = whole_answer_facts(
            case.dialect,
            case.upstreams,
            case.request,
            case.answer.as_bytes(),
        );
        let want = format!(r#"Str("{}")"#, case.want);
        assert_eq!(
            get(&facts, meta::FACT_FINISH_REASON),
            Some(want.as_str()),
            "dialect {} answer {:?} did not render {}: {facts:?}",
            case.dialect,
            case.answer,
            case.want
        );
    }
}

/// One streamed SSE frame, in the transport's own event framing.
fn event(name: &str, data: &str) -> Vec<u8> {
    format!("event: {name}\ndata: {data}\n\n").into_bytes()
}

/// `content_facts` on a streaming answer's OPENING frame names the model and the identity — the
/// two things a single frame is entitled to claim about the whole answer it opens.
#[test]
fn a_stream_opening_frame_names_model_and_identity() {
    let plane = harness::plane(ANTHROPIC_UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("anthropic"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("anthropic.invalid", LaneId::new("lane-anthropic"));

    let request = vec![harness::frame(ANTHROPIC_REQUEST)];
    let mut cursor = FrameCursor::new(&request);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("the request decodes")
    {
        Ingress::OneShot(draft) => draft,
        other => panic!("expected one complete unit, got {other:?}"),
    };
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);

    let start = event(
        "message_start",
        r#"{"type":"message_start","message":{"id":"msg_stream_1","role":"assistant","model":"claude-3-5-haiku"}}"#,
    );
    let frames = vec![harness::frame(&start)];
    let mut answers = FrameCursor::new(&frames);
    let (Progress::Frame { r, .. } | Progress::Terminal { r, .. }) = plane
        .decode_response(&mut answers, &dest, None, &ctx)
        .expect("the opening frame decodes")
    else {
        unreachable!()
    };

    let facts = pairs(&plane.content_facts(&unit, &r, &ctx).facts);
    assert_eq!(
        get(&facts, meta::FACT_RESPONSE_MODEL),
        Some(r#"Str("claude-3-5-haiku")"#),
        "the opening event's own model: {facts:?}"
    );
    assert_eq!(
        get(&facts, meta::FACT_RESPONSE_ID),
        Some(r#"Str("msg_stream_1")"#),
        "the opening event's own identity: {facts:?}"
    );
    assert!(
        get(&facts, meta::FACT_FINISH_REASON).is_none(),
        "the opening event states nothing about how the answer ends: {facts:?}"
    );
}

/// `content_facts` on the frame carrying the stop reason names it, and names nothing about model or
/// identity — the closing event's own twin of the opening-frame test above.
#[test]
fn a_stream_closing_frame_names_the_finish_reason_only() {
    let plane = harness::plane(ANTHROPIC_UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("anthropic"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("anthropic.invalid", LaneId::new("lane-anthropic"));

    let request = vec![harness::frame(ANTHROPIC_REQUEST)];
    let mut cursor = FrameCursor::new(&request);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("the request decodes")
    {
        Ingress::OneShot(draft) => draft,
        other => panic!("expected one complete unit, got {other:?}"),
    };
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);

    let delta = event(
        "message_delta",
        r#"{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":7}}"#,
    );
    let frames = vec![harness::frame(&delta)];
    let mut answers = FrameCursor::new(&frames);
    let (Progress::Frame { r, .. } | Progress::Terminal { r, .. }) = plane
        .decode_response(&mut answers, &dest, None, &ctx)
        .expect("the closing frame decodes")
    else {
        unreachable!()
    };

    let facts = pairs(&plane.content_facts(&unit, &r, &ctx).facts);
    assert_eq!(
        get(&facts, meta::FACT_FINISH_REASON),
        Some(r#"Str("tool_use")"#),
        "the closing event's own stop reason: {facts:?}"
    );
    assert!(
        get(&facts, meta::FACT_RESPONSE_MODEL).is_none(),
        "the closing event states nothing about the model: {facts:?}"
    );
}
