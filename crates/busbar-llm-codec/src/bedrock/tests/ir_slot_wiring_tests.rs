// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR MAPPING: the Bedrock reader FILLS and the Bedrock writer EMITS
//! the typed IR slots the Converse wire has a member for (`ir-slots-landed.md`), and the writer
//! reads the lane capabilities (`LaneCaps`) the way the Anthropic writer does. One test per
//! defect / slot id; each drives the real reader → seam → writer path on a real body.

use super::*;
use serde_json::{json, Value};

/// The production REQUEST translate steps (reader → egress seam → lane write).
fn xreq_lane(ingress: &'static str, body: &Value, model: &str, caps: LaneCaps) -> Value {
    let ingress_p = crate::proto_codec::protocol_for(ingress).expect("ingress");
    let mut req = ingress_p.reader().read_request(body).expect("read_request");
    crate::chat_handle::chat_prepare_for_egress(
        &mut req,
        &busbar_substrate_values::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: ingress,
            egress_requires_max_tokens: false,
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
            lane_caps: caps,
        },
    );
    writer().write_request_for_lane(&req, model, &caps)
}

/// A bare user turn.
fn user_turn(text: &str) -> crate::ir::IrMessage {
    crate::ir::IrMessage {
        role: crate::ir::IrRole::User,
        content: vec![crate::ir::IrBlock::Text {
            text: text.into(),
            cache_control: None,
            citations: Vec::new(),
            refusal: false,
        }],
    }
}

const CLAUDE_NEWEST: &str = "us.anthropic.claude-opus-4-7-v1:0";

fn adaptive() -> LaneCaps {
    LaneCaps {
        anthropic_adaptive_thinking: true,
        ..Default::default()
    }
}

/// BED-10 / IR-16 (buffered): `model_context_window_exceeded` reads as `MaxTokens` PLUS the
/// `ContextWindowExceeded` detail, and the Bedrock writer writes the detail back as Converse's own
/// spelling instead of degrading it to `max_tokens`.
#[test]
fn bed10_context_window_detail_is_read_and_written_buffered() {
    let body = json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "partial"}]}},
        "stopReason": "model_context_window_exceeded",
        "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}
    });
    let resp = BedrockReader.read_response(&body).expect("read");
    assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::MaxTokens));
    assert_eq!(
        resp.stop_detail,
        Some(crate::ir::IrStopDetail::ContextWindowExceeded)
    );
    let back = writer().write_response(&resp);
    assert_eq!(
        back["stopReason"], "model_context_window_exceeded",
        "{back}"
    );
    // The coarse reason alone still writes the coarse value.
    let mut coarse = resp.clone();
    coarse.stop_detail = None;
    assert_eq!(writer().write_response(&coarse)["stopReason"], "max_tokens");
}

/// BED-10 / IR-16 (stream writer + buffered→stream synthesis): the stop-bearing delta carries the
/// detail, and both the live `messageStop` frame and the frames synthesized for a buffered upstream
/// spell it `model_context_window_exceeded` (buffered == stream).
#[test]
fn bed10_context_window_detail_rides_the_message_stop_frame() {
    let ev = crate::ir::IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
        stop_sequence: None,
        usage: crate::ir::IrUsage::default(),
        stop_detail: Some(crate::ir::IrStopDetail::ContextWindowExceeded),
    };
    let (et, payload) = writer().write_response_event(&ev).expect("frame");
    assert_eq!(et, "messageStop");
    assert_eq!(payload["stopReason"], "model_context_window_exceeded");

    let ir = crate::ir::IrResponse {
        content: vec![crate::ir::IrBlock::Text {
            text: "partial".into(),
            cache_control: None,
            citations: Vec::new(),
            refusal: false,
        }],
        stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
        stop_detail: Some(crate::ir::IrStopDetail::ContextWindowExceeded),
        ..Default::default()
    };
    let mut bytes = bedrock_response_to_eventstream(&ir, Some(1));
    let frames = busbar_substrate_values::eventstream::drain_frames(&mut bytes);
    let stop = frames
        .iter()
        .find(|(t, _)| t == "messageStop")
        .expect("messageStop");
    let payload: Value = serde_json::from_slice(&stop.1).expect("json");
    assert_eq!(payload["stopReason"], "model_context_window_exceeded");
}

/// BED-10 / IR-16 and BED-11 (stream reader): the `messageStop` frame's context-window stop and
/// matched stop string are buffered with the stop reason and carried on the ONE combined
/// `MessageDelta` the `metadata` frame completes (buffered == stream).
#[test]
fn bed10_bed11_stream_stop_detail_and_stop_sequence_are_carried() {
    let mut state = crate::ir::StreamDecodeState::default();
    let reader = BedrockReader;
    for frame in [
        json!({"type": "messageStart", "role": "assistant"}),
        json!({"type": "messageStop", "stopReason": "model_context_window_exceeded",
            "additionalModelResponseFields": {"stop_sequence": "END"}}),
    ] {
        reader.read_response_events("", &frame, &mut state);
    }
    let evs = reader.read_response_events(
        "",
        &json!({"type": "metadata", "usage": {"inputTokens": 3, "outputTokens": 2}}),
        &mut state,
    );
    match &evs[0] {
        crate::ir::IrStreamEvent::MessageDelta {
            stop_reason,
            stop_sequence,
            stop_detail,
            ..
        } => {
            assert_eq!(*stop_reason, Some(crate::ir::IrStopReason::MaxTokens));
            assert_eq!(stop_sequence.as_deref(), Some("END"));
            assert_eq!(
                *stop_detail,
                Some(crate::ir::IrStopDetail::ContextWindowExceeded)
            );
        }
        other => panic!("expected the combined MessageDelta, got {other:?}"),
    }
}

/// IR-12: a Converse document's `citations.enabled` and `context` are read into the Media slot and
/// written back on a cross-protocol write (the verbatim stash is gone there), so the switch and the
/// context are not lost when the IR — not the raw block — is the carrier.
#[test]
fn ir12_document_citations_and_context_cross() {
    let body = json!({
        "messages": [{"role": "user", "content": [
            {"document": {"format": "txt", "name": "memo", "source": {"text": "hello"},
                "context": "a memo", "citations": {"enabled": true}}},
            {"text": "summarize"}
        ]}]
    });
    let mut ir = BedrockReader.read_request(&body).expect("read");
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::Media {
            citations, context, ..
        } => {
            assert_eq!(*citations, Some(true));
            assert_eq!(context.as_deref(), Some("a memo"));
        }
        other => panic!("expected Media, got {other:?}"),
    }
    ir.extra.clear();
    let out = writer().write_request(&ir);
    let doc = &out["messages"][0]["content"][0]["document"];
    assert_eq!(doc["citations"], json!({"enabled": true}), "{out}");
    assert_eq!(doc["context"], "a memo", "{out}");
}

/// IR-03: Converse `requestMetadata` reads into the typed metadata, and a foreign caller's metadata
/// is written as `requestMetadata` — with an entry Converse would reject dropped, not the request.
#[test]
fn ir03_request_metadata_maps_both_ways() {
    let body = json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "requestMetadata": {"team": "search", "run": "42"}
    });
    let ir = BedrockReader.read_request(&body).expect("read");
    assert_eq!(
        ir.metadata,
        Some(vec![
            ("run".to_string(), "42".to_string()),
            ("team".to_string(), "search".to_string()),
        ])
    );
    // Same-protocol: the raw object is re-emitted verbatim (once).
    assert_eq!(
        writer().write_request(&ir)["requestMetadata"],
        body["requestMetadata"]
    );

    // Cross-protocol (no raw object): the typed metadata is written, minus an entry Converse's
    // pattern rejects.
    let foreign = crate::ir::IrRequest {
        messages: vec![user_turn("hi")],
        metadata: Some(vec![
            ("team".to_string(), "search".to_string()),
            ("note".to_string(), "has a ! bang".to_string()),
        ]),
        ..Default::default()
    };
    let out = writer().write_request(&foreign);
    assert_eq!(out["requestMetadata"], json!({"team": "search"}), "{out}");
    assert!(writer().dropped_egress_controls(&foreign).is_empty());
}

/// IR-10: an allowed-tools subset reaches Converse as the listed tools only (the constraint by
/// omission), with the mode on `toolChoice`.
#[test]
fn ir10_allowed_tools_send_only_the_listed_tools() {
    let mut ir = crate::ir::IrRequest {
        messages: vec![user_turn("hi")],
        tools: ["a", "b", "c"]
            .iter()
            .map(|n| crate::ir::IrTool {
                name: (*n).to_string(),
                input_schema: json!({"type": "object"}),
                ..Default::default()
            })
            .collect(),
        tool_choice: Some(crate::ir::IrToolChoice::Required),
        allowed_tools: Some(vec!["c".to_string(), "a".to_string()]),
        ..Default::default()
    };
    let out = writer().write_request(&ir);
    let names: Vec<&str> = out["toolConfig"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|t| t["toolSpec"]["name"].as_str())
        .collect();
    assert_eq!(names, vec!["a", "c"], "{out}");
    assert_eq!(out["toolConfig"]["toolChoice"], json!({"any": {}}), "{out}");
    // No restriction: every tool.
    ir.allowed_tools = None;
    let out = writer().write_request(&ir);
    assert_eq!(out["toolConfig"]["tools"].as_array().map(Vec::len), Some(3));
}

/// IR-11 and the request slots with no Converse member: dropped from the wire and REPORTED, so the
/// seam audits each one instead of the control vanishing silently.
#[test]
fn ir_slots_without_a_converse_member_are_reported_dropped() {
    let ir = crate::ir::IrRequest {
        messages: vec![user_turn("hi")],
        store: Some(true),
        safety_identifier: Some("u-1".into()),
        prompt_cache_key: Some("k".into()),
        verbosity: Some(crate::ir::IrVerbosity::Low),
        output_modalities: Some(vec![
            crate::ir::IrModality::Text,
            crate::ir::IrModality::Audio,
        ]),
        hosted_tools: vec![crate::ir::IrHostedTool::CodeExecution],
        ..Default::default()
    };
    assert_eq!(
        writer().dropped_egress_controls(&ir),
        vec![
            "store",
            "safety_identifier",
            "prompt_cache_key",
            "verbosity",
            "output_modalities",
            "code_execution"
        ]
    );
    let wire = writer().write_request(&ir).to_string();
    for k in [
        "store",
        "safety_identifier",
        "prompt_cache_key",
        "verbosity",
        "code_execution",
    ] {
        assert!(
            !wire.contains(k),
            "{k} leaked onto the Converse wire: {wire}"
        );
    }
    // Text-only output is Converse's own behaviour — nothing is dropped for it.
    let text_only = crate::ir::IrRequest {
        messages: vec![user_turn("hi")],
        output_modalities: Some(vec![crate::ir::IrModality::Text]),
        ..Default::default()
    };
    assert!(writer().dropped_egress_controls(&text_only).is_empty());
}

/// IR-18: a history reasoning block's signature is attributed from the conversation's model id
/// (Claude → Anthropic; another visible provider → BedrockOther; an id that reveals nothing →
/// unknown), and the writer never sends a signature another family minted.
#[test]
fn ir18_signature_origin_is_read_and_a_foreign_signature_is_not_sent() {
    let body = |model: &str| {
        json!({
            "model": model,
            "messages": [
                {"role": "user", "content": [{"text": "q"}]},
                {"role": "assistant", "content": [
                    {"reasoningContent": {"reasoningText": {"text": "think", "signature": "sig"}}},
                    {"text": "a"}
                ]},
                {"role": "user", "content": [{"text": "q2"}]}
            ]
        })
    };
    let origin = |model: &str| match &BedrockReader
        .read_request(&body(model))
        .expect("read")
        .messages[1]
        .content[0]
    {
        crate::ir::IrBlock::Thinking {
            signature_origin, ..
        } => *signature_origin,
        other => panic!("expected Thinking, got {other:?}"),
    };
    use crate::ir::IrSignatureOrigin as O;
    assert_eq!(
        origin("us.anthropic.claude-sonnet-4-5-v1:0"),
        Some(O::Anthropic)
    );
    assert_eq!(origin("amazon.nova-pro-v1:0"), Some(O::BedrockOther));
    assert_eq!(origin("global.deepseek.r1-v1:0"), Some(O::BedrockOther));
    assert_eq!(origin("my-alias"), None);
    assert_eq!(
        origin("arn:aws:bedrock:us-east-1:1:application-inference-profile/abc123"),
        None
    );

    let thinking = |origin: Option<O>| crate::ir::IrRequest {
        messages: vec![
            user_turn("q"),
            crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::Thinking {
                    text: "think".into(),
                    signature: Some("sig".into()),
                    redacted: false,
                    cache_control: None,
                    kind: None,
                    signature_origin: origin,
                }],
            },
            user_turn("q2"),
        ],
        ..Default::default()
    };
    let sig = |origin: Option<O>| {
        writer().write_request(&thinking(origin))["messages"][1]["content"][0]["reasoningContent"]
            ["reasoningText"]
            .get("signature")
            .cloned()
    };
    assert_eq!(sig(Some(O::Anthropic)), Some(json!("sig")));
    assert_eq!(sig(Some(O::BedrockOther)), Some(json!("sig")));
    assert_eq!(sig(None), Some(json!("sig")));
    assert_eq!(sig(Some(O::Gemini)), None);
    assert_eq!(sig(Some(O::OpenAi)), None);
}

/// LANE CAPS: a Bedrock Claude lane declaring adaptive thinking gets `thinking:{type:"adaptive"}`
/// plus `output_config.effort` for a WORD ask (the newest Claude models 400 on `budget_tokens`);
/// "model decides" is adaptive with no invented word; a numeric ask keeps its budget; and a lane
/// without the capability keeps the budget form.
#[test]
fn lane_caps_adaptive_thinking_on_a_bedrock_claude_lane() {
    let chat = json!({
        "model": "gpt-5",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 8192,
        "temperature": 0.5,
        "reasoning_effort": "high"
    });
    let out = xreq_lane("openai", &chat, CLAUDE_NEWEST, adaptive());
    assert_eq!(
        out["additionalModelRequestFields"],
        json!({"thinking": {"type": "adaptive"}, "output_config": {"effort": "high"}}),
        "{out}"
    );
    assert!(out["inferenceConfig"].get("temperature").is_none(), "{out}");
    // Without the capability: the budget form, exactly as before.
    let out = xreq_lane("openai", &chat, CLAUDE_NEWEST, LaneCaps::default());
    assert_eq!(
        out["additionalModelRequestFields"]["thinking"]["type"], "enabled",
        "{out}"
    );
    assert!(out
        .pointer("/additionalModelRequestFields/output_config")
        .is_none());

    let req = |ask| crate::ir::IrRequest {
        messages: vec![user_turn("hi")],
        max_tokens: Some(8192),
        reasoning: Some(ask),
        ..Default::default()
    };
    use crate::ir::{IrReasoningAsk as A, IrReasoningEffort as E};
    let amrf = |ask| {
        writer().write_request_for_lane(&req(ask), CLAUDE_NEWEST, &adaptive())
            ["additionalModelRequestFields"]
            .clone()
    };
    assert_eq!(amrf(A::Dynamic), json!({"thinking": {"type": "adaptive"}}));
    assert_eq!(
        amrf(A::Effort(E::Max)),
        json!({"thinking": {"type": "adaptive"}, "output_config": {"effort": "max"}})
    );
    assert_eq!(
        amrf(A::Effort(E::Minimal)),
        json!({"thinking": {"type": "adaptive"}, "output_config": {"effort": "low"}})
    );
    assert_eq!(
        amrf(A::Budget(2048)),
        json!({"thinking": {"type": "enabled", "budget_tokens": 2048}})
    );
    // A non-Claude model never gets Claude's spelling, capability or not.
    let nova = writer().write_request_for_lane(
        &req(A::Effort(E::High)),
        "amazon.nova-pro-v1:0",
        &adaptive(),
    );
    assert!(nova.get("additionalModelRequestFields").is_none(), "{nova}");
}

/// IR-09 `Off`: Claude's `thinking:{type:"disabled"}` and Nova's `reasoningConfig:{type:"disabled"}`
/// read as the explicit OFF ask, and OFF is written as `disabled` — never projected through the
/// budget table, where it would read as the smallest ENABLE ask — with sampling knobs kept.
#[test]
fn ir09_reasoning_off_reads_and_writes_disabled() {
    for amrf in [
        json!({"thinking": {"type": "disabled"}}),
        json!({"reasoningConfig": {"type": "disabled"}}),
    ] {
        let body = json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "additionalModelRequestFields": amrf
        });
        let ir = BedrockReader.read_request(&body).expect("read");
        assert_eq!(ir.reasoning, Some(crate::ir::IrReasoningAsk::Off), "{body}");
    }
    let req = crate::ir::IrRequest {
        messages: vec![user_turn("hi")],
        max_tokens: Some(8192),
        temperature: Some(0.5),
        reasoning: Some(crate::ir::IrReasoningAsk::Off),
        ..Default::default()
    };
    for caps in [LaneCaps::default(), adaptive()] {
        let out = writer().write_request_for_lane(&req, CLAUDE_NEWEST, &caps);
        assert_eq!(
            out["additionalModelRequestFields"],
            json!({"thinking": {"type": "disabled"}}),
            "{out}"
        );
        assert_eq!(out["inferenceConfig"]["temperature"], 0.5, "{out}");
    }
}

/// The adaptive reader half: Anthropic-on-Bedrock `thinking:{type:"adaptive"}` with an
/// `output_config.effort` word reads as that effort (`xhigh`/`max` included), without one as
/// "model decides"; and the same-protocol body is re-emitted verbatim, not re-synthesized.
#[test]
fn adaptive_thinking_ask_is_read_from_additional_model_request_fields() {
    use crate::ir::{IrReasoningAsk as A, IrReasoningEffort as E};
    let read = |amrf: Value| {
        let body = json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "additionalModelRequestFields": amrf
        });
        let ir = BedrockReader.read_request(&body).expect("read");
        let back = writer().write_request(&ir);
        assert_eq!(
            back["additionalModelRequestFields"], body["additionalModelRequestFields"],
            "{back}"
        );
        ir.reasoning
    };
    assert_eq!(
        read(json!({"thinking": {"type": "adaptive"}, "output_config": {"effort": "xhigh"}})),
        Some(A::Effort(E::XHigh))
    );
    assert_eq!(
        read(json!({"thinking": {"type": "adaptive"}})),
        Some(A::Dynamic)
    );
    assert_eq!(
        read(json!({"output_config": {"effort": "medium"}})),
        Some(A::Effort(E::Medium))
    );
}

/// A fresh writer per use (the const constructor carries per-stream state).
fn writer() -> BedrockWriter {
    BedrockWriter
}
