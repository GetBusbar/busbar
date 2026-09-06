//! A client that asked to be streamed to is dialled the upstream's streaming action.
//!
//! Four of the six dialects say "stream me" with a body member, and the codec's own reader reads
//! it. The other two say it in the request TARGET, as a distinct action on the same model surface —
//! their two bodies are byte-identical, so nothing in the body can tell them apart. The plane picks
//! the upstream action off the fact the decode step wrote, so a fact read only from the body
//! silently downgraded every streamed request of those two dialects to one whole answer.

mod harness;

use busbar_contract::bounded::{FactValue, Labels};
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Ingress, Plane};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::{meta, LlmPlane, Upstream};

/// One upstream per target-carried dialect, each on its own lane.
const UPSTREAMS: &[Upstream] = &[
    Upstream {
        lane: LaneId::new("lane-gemini"),
        host: "gemini.invalid",
        dialect: "gemini",
        model: "gemini-2.0-flash",
    },
    Upstream {
        lane: LaneId::new("lane-bedrock"),
        host: "bedrock.invalid",
        dialect: "bedrock",
        model: "claude-sonnet-4",
    },
    Upstream {
        lane: LaneId::new("lane-openai"),
        host: "openai.invalid",
        dialect: "openai",
        model: "gpt-4o-mini",
    },
];

/// Decode one request at one target and report the streaming fact and the hop's request target.
fn decode_and_dial(path: &'static str, body: &str, lane: &'static str) -> (bool, String) {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(path, &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);

    let frames = vec![harness::frame(body.as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("the body is this dialect's shape")
    {
        Ingress::OneShot(draft) => draft,
        other => panic!("a whole request body decodes as one complete unit, got {other:?}"),
    };
    let streamed = matches!(
        draft.facts.get(meta::FACT_STREAM),
        Some(FactValue::Bool(true))
    );

    let host = UPSTREAMS
        .iter()
        .find(|u| u.lane == LaneId::new(lane))
        .expect("the lane is configured")
        .host;
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);
    let dest = harness::destination(host, LaneId::new(lane));
    let egress = plane
        .encode_egress(&unit, &dest, None, &ctx)
        .expect("the unit is expressible for this destination");
    let target = egress
        .envelope
        .fields
        .as_slice()
        .iter()
        .find(|f| f.name == "path")
        .map(|f| String::from_utf8_lossy(f.value.as_slice()).into_owned())
        .expect("the hop names a request target");
    (streamed, target)
}

/// The dialect whose streaming action is a suffix on the model surface.
#[test]
fn a_target_carried_streaming_ask_reaches_the_streaming_action() {
    let body = r#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#;

    let (streamed, target) = decode_and_dial(
        "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        body,
        "lane-gemini",
    );
    assert!(
        streamed,
        "the client asked for a stream in the request target and the decode step did not hear it"
    );
    assert!(
        target.contains(":streamGenerateContent"),
        "a streamed ask was dialled at the whole-answer action: {target}"
    );

    // The same body at the whole-answer target is still a whole answer: the marker is evidence,
    // not a default.
    let (streamed, target) = decode_and_dial(
        "/v1beta/models/gemini-2.0-flash:generateContent",
        body,
        "lane-gemini",
    );
    assert!(!streamed, "a whole-answer ask was read as a streamed one");
    assert!(
        !target.contains(":streamGenerateContent"),
        "a whole-answer ask was dialled at the streaming action: {target}"
    );
}

/// The dialect whose streaming action is a separate turn verb.
#[test]
fn the_turn_dialects_streaming_verb_reaches_the_streaming_action() {
    let body = r#"{"messages":[{"role":"user","content":[{"text":"hi"}]}]}"#;

    let (streamed, target) = decode_and_dial(
        "/model/claude-sonnet-4/converse-stream",
        body,
        "lane-bedrock",
    );
    assert!(
        streamed,
        "the client asked for a stream in the request target and the decode step did not hear it"
    );
    assert!(
        target.ends_with("/converse-stream"),
        "a streamed ask was dialled at the whole-answer verb: {target}"
    );

    let (streamed, target) =
        decode_and_dial("/model/claude-sonnet-4/converse", body, "lane-bedrock");
    assert!(!streamed, "a whole-answer ask was read as a streamed one");
    assert!(
        target.ends_with("/converse"),
        "a whole-answer ask was dialled at the streaming verb: {target}"
    );
}

/// A dialect that says it in the body is still read from the body, by its own reader.
#[test]
fn a_body_carried_streaming_ask_is_still_the_bodys_own_answer() {
    let streamed_body =
        r#"{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    let (streamed, _) = decode_and_dial("/v1/chat/completions", streamed_body, "lane-openai");
    assert!(streamed, "a body-carried streaming ask was not read");

    let whole_body = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;
    let (streamed, _) = decode_and_dial("/v1/chat/completions", whole_body, "lane-openai");
    assert!(
        !streamed,
        "a request that asked for no stream was read as one"
    );
}
