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
    let ingress_p = crate::codec::proto_codec::protocol_for(ingress).expect("ingress");
    let mut req = ingress_p.reader().read_request(body).expect("read_request");
    crate::codec::chat_handle::chat_prepare_for_egress(
        &mut req,
        &busbar_contract::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: ingress,
            egress_requires_max_tokens: false,
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::codec::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
            lane_caps: caps,
        },
    );
    writer().write_request_for_lane(crate::codec::test_host::HOST, &req, model, &caps)
}

/// A bare user turn.
fn user_turn(text: &str) -> crate::codec::ir::IrMessage {
    crate::codec::ir::IrMessage {
        role: crate::codec::ir::IrRole::User,
        content: vec![crate::codec::ir::IrBlock::Text {
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
    let resp = BedrockReader
        .read_response(crate::codec::test_host::HOST, &body)
        .expect("read");
    assert_eq!(
        resp.stop_reason,
        Some(crate::codec::ir::IrStopReason::MaxTokens)
    );
    assert_eq!(
        resp.stop_detail,
        Some(crate::codec::ir::IrStopDetail::ContextWindowExceeded)
    );
    let back = writer().write_response(crate::codec::test_host::HOST, &resp);
    assert_eq!(
        back["stopReason"], "model_context_window_exceeded",
        "{back}"
    );
    // The coarse reason alone still writes the coarse value.
    let mut coarse = resp.clone();
    coarse.stop_detail = None;
    assert_eq!(
        writer().write_response(crate::codec::test_host::HOST, &coarse)["stopReason"],
        "max_tokens"
    );
}

/// BED-10 / IR-16 (stream writer + buffered→stream synthesis): the stop-bearing delta carries the
/// detail, and both the live `messageStop` frame and the frames synthesized for a buffered upstream
/// spell it `model_context_window_exceeded` (buffered == stream).
#[test]
fn bed10_context_window_detail_rides_the_message_stop_frame() {
    let ev = crate::codec::ir::IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::codec::ir::IrStopReason::MaxTokens),
        stop_sequence: None,
        usage: crate::codec::ir::IrUsage::default(),
        stop_detail: Some(crate::codec::ir::IrStopDetail::ContextWindowExceeded),
    };
    let (et, payload) = writer()
        .write_response_event(crate::codec::test_host::HOST, &ev)
        .expect("frame");
    assert_eq!(et, "messageStop");
    assert_eq!(payload["stopReason"], "model_context_window_exceeded");

    let ir = crate::codec::ir::IrResponse {
        content: vec![crate::codec::ir::IrBlock::Text {
            text: "partial".into(),
            cache_control: None,
            citations: Vec::new(),
            refusal: false,
        }],
        stop_reason: Some(crate::codec::ir::IrStopReason::MaxTokens),
        stop_detail: Some(crate::codec::ir::IrStopDetail::ContextWindowExceeded),
        ..Default::default()
    };
    let mut bytes = bedrock_response_to_eventstream(crate::codec::test_host::HOST, &ir, Some(1));
    let frames = crate::codec::eventstream::drain_frames(&mut bytes);
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
    let mut state = crate::codec::ir::StreamDecodeState::default();
    let reader = BedrockReader;
    for frame in [
        json!({"type": "messageStart", "role": "assistant"}),
        json!({"type": "messageStop", "stopReason": "model_context_window_exceeded",
            "additionalModelResponseFields": {"stop_sequence": "END"}}),
    ] {
        reader.read_response_events(crate::codec::test_host::HOST, "", &frame, &mut state);
    }
    let evs = reader.read_response_events(
        crate::codec::test_host::HOST,
        "",
        &json!({"type": "metadata", "usage": {"inputTokens": 3, "outputTokens": 2}}),
        &mut state,
    );
    match &evs[0] {
        crate::codec::ir::IrStreamEvent::MessageDelta {
            stop_reason,
            stop_sequence,
            stop_detail,
            ..
        } => {
            assert_eq!(
                *stop_reason,
                Some(crate::codec::ir::IrStopReason::MaxTokens)
            );
            assert_eq!(stop_sequence.as_deref(), Some("END"));
            assert_eq!(
                *stop_detail,
                Some(crate::codec::ir::IrStopDetail::ContextWindowExceeded)
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
        crate::codec::ir::IrBlock::Media {
            citations, context, ..
        } => {
            assert_eq!(*citations, Some(true));
            assert_eq!(context.as_deref(), Some("a memo"));
        }
        other => panic!("expected Media, got {other:?}"),
    }
    ir.extra.clear();
    let out = writer().write_request(crate::codec::test_host::HOST, &ir);
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
        writer().write_request(crate::codec::test_host::HOST, &ir)["requestMetadata"],
        body["requestMetadata"]
    );

    // Cross-protocol (no raw object): the typed metadata is written, minus an entry Converse's
    // pattern rejects.
    let foreign = crate::codec::ir::IrRequest {
        messages: vec![user_turn("hi")],
        metadata: Some(vec![
            ("team".to_string(), "search".to_string()),
            ("note".to_string(), "has a ! bang".to_string()),
        ]),
        ..Default::default()
    };
    let out = writer().write_request(crate::codec::test_host::HOST, &foreign);
    assert_eq!(out["requestMetadata"], json!({"team": "search"}), "{out}");
    assert!(writer().dropped_egress_controls(&foreign).is_empty());
}

/// IR-10: an allowed-tools subset reaches Converse as the listed tools only (the constraint by
/// omission), with the mode on `toolChoice`.
#[test]
fn ir10_allowed_tools_send_only_the_listed_tools() {
    let mut ir = crate::codec::ir::IrRequest {
        messages: vec![user_turn("hi")],
        tools: ["a", "b", "c"]
            .iter()
            .map(|n| crate::codec::ir::IrTool {
                name: (*n).to_string(),
                input_schema: json!({"type": "object"}),
                ..Default::default()
            })
            .collect(),
        tool_choice: Some(crate::codec::ir::IrToolChoice::Required),
        allowed_tools: Some(vec!["c".to_string(), "a".to_string()]),
        ..Default::default()
    };
    let out = writer().write_request(crate::codec::test_host::HOST, &ir);
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
    let out = writer().write_request(crate::codec::test_host::HOST, &ir);
    assert_eq!(out["toolConfig"]["tools"].as_array().map(Vec::len), Some(3));
}

/// IR-11 and the request slots with no Converse member: dropped from the wire and REPORTED, so the
/// seam audits each one instead of the control vanishing silently.
#[test]
fn ir_slots_without_a_converse_member_are_reported_dropped() {
    let ir = crate::codec::ir::IrRequest {
        messages: vec![user_turn("hi")],
        store: Some(true),
        safety_identifier: Some("u-1".into()),
        prompt_cache_key: Some("k".into()),
        verbosity: Some(crate::codec::ir::IrVerbosity::Low),
        output_modalities: Some(vec![
            crate::codec::ir::IrModality::Text,
            crate::codec::ir::IrModality::Audio,
        ]),
        hosted_tools: vec![crate::codec::ir::IrHostedTool::CodeExecution],
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
    let wire = writer()
        .write_request(crate::codec::test_host::HOST, &ir)
        .to_string();
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
    let text_only = crate::codec::ir::IrRequest {
        messages: vec![user_turn("hi")],
        output_modalities: Some(vec![crate::codec::ir::IrModality::Text]),
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
        crate::codec::ir::IrBlock::Thinking {
            signature_origin, ..
        } => *signature_origin,
        other => panic!("expected Thinking, got {other:?}"),
    };
    use crate::codec::ir::IrSignatureOrigin as O;
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

    let thinking = |origin: Option<O>| crate::codec::ir::IrRequest {
        messages: vec![
            user_turn("q"),
            crate::codec::ir::IrMessage {
                role: crate::codec::ir::IrRole::Assistant,
                content: vec![crate::codec::ir::IrBlock::Thinking {
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
        writer().write_request(crate::codec::test_host::HOST, &thinking(origin))["messages"][1]
            ["content"][0]["reasoningContent"]["reasoningText"]
            .get("signature")
            .cloned()
    };
    assert_eq!(sig(Some(O::Anthropic)), Some(json!("sig")));
    assert_eq!(sig(Some(O::BedrockOther)), Some(json!("sig")));
    assert_eq!(sig(None), Some(json!("sig")));
    assert_eq!(sig(Some(O::Gemini)), None);
    assert_eq!(sig(Some(O::OpenAi)), None);
}

/// A REASONING ASK DOES NOT CROSS INTO OR OUT OF BEDROCK, as in 1.5.5. The writer dropped every
/// cross-protocol ask ("no Bedrock Converse mapping in this release", v1.5.5
/// `crates/busbar/src/proto/bedrock/writer.rs:139-146`) and the reader promoted none (v1.5.5
/// `crates/busbar/src/proto/bedrock/reader.rs:678`, `reasoning: None`), so no request bills
/// thinking tokens 1.5.5 did not bill. Whatever the ask, the lane capabilities or the model family,
/// the egress body carries no `thinking`/`output_config`, keeps its sampling knobs, and the drop
/// is reported; a Bedrock caller's native ask stays a same-protocol member, re-emitted verbatim.
/// RED while a foreign ask wrote Claude `thinking` (and stripped `temperature`) on a Claude lane, or
/// the reader promoted `thinking`/`reasoningConfig`/`output_config.effort` into the IR.
#[test]
fn a_reasoning_ask_neither_reaches_nor_leaves_bedrock_as_in_1_5_5() {
    let chat = json!({
        "model": "gpt-5",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 8192,
        "temperature": 0.5,
        "reasoning_effort": "high"
    });
    for caps in [LaneCaps::default(), adaptive()] {
        for model in [CLAUDE_NEWEST, "amazon.nova-pro-v1:0"] {
            let out = xreq_lane("openai", &chat, model, caps);
            assert!(
                out.get("additionalModelRequestFields").is_none(),
                "{model}: {out}"
            );
            assert_eq!(out["inferenceConfig"]["temperature"], 0.5, "{model}: {out}");
        }
    }
    use crate::codec::ir::{IrReasoningAsk as A, IrReasoningEffort as E};
    for ask in [
        A::Off,
        A::Dynamic,
        A::Budget(2048),
        A::Effort(E::High),
        A::Effort(E::Max),
    ] {
        let req = crate::codec::ir::IrRequest {
            messages: vec![user_turn("hi")],
            max_tokens: Some(8192),
            temperature: Some(0.5),
            top_k: Some(40),
            reasoning: Some(ask),
            ..Default::default()
        };
        for caps in [LaneCaps::default(), adaptive()] {
            let out = writer().write_request_for_lane(
                crate::codec::test_host::HOST,
                &req,
                CLAUDE_NEWEST,
                &caps,
            );
            assert_eq!(
                out["additionalModelRequestFields"],
                json!({"top_k": 40}),
                "{ask:?}: {out}"
            );
            assert_eq!(out["inferenceConfig"]["temperature"], 0.5, "{ask:?}: {out}");
        }
        assert!(writer()
            .dropped_egress_controls(&req)
            .contains(&crate::codec::drops::name::REASONING));
    }
    for amrf in [
        json!({"thinking": {"type": "enabled", "budget_tokens": 4096}}),
        json!({"thinking": {"type": "disabled"}}),
        json!({"thinking": {"type": "adaptive"}, "output_config": {"effort": "xhigh"}}),
        json!({"thinking": {"type": "adaptive"}}),
        json!({"output_config": {"effort": "medium"}}),
        json!({"reasoningConfig": {"type": "enabled", "maxReasoningEffort": "high"}}),
        json!({"reasoningConfig": {"type": "disabled"}}),
    ] {
        let body = json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "additionalModelRequestFields": amrf
        });
        let ir = BedrockReader.read_request(&body).expect("read");
        assert_eq!(ir.reasoning, None, "{body}");
        let back = writer().write_request(crate::codec::test_host::HOST, &ir);
        assert_eq!(
            back["additionalModelRequestFields"], body["additionalModelRequestFields"],
            "the same-protocol native ask is re-emitted verbatim: {back}"
        );
    }
}

/// A fresh writer per use (the const constructor carries per-stream state).
fn writer() -> BedrockWriter {
    BedrockWriter
}
