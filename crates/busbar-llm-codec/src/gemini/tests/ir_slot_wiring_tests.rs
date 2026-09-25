// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR-slot wiring: the Gemini reader FILLS and the Gemini writer
//! EMITS the typed slots its defects need. One test per defect / slot id; each drives the production
//! reader and writer (and the cross-protocol seam, `chat_prepare_for_egress`, where the seam matters).

use super::*;
use crate::ir::{
    IrBlock, IrDelta, IrHostedTool, IrMessage, IrModality, IrReasoningAsk, IrRequest, IrRole,
    IrServiceTier, IrSignatureOrigin, IrStreamEvent, IrThinkingKind, IrTool, IrToolChoice,
    IrWebFetch, IrWebSearch, StreamDecodeState,
};
use serde_json::{json, Value};

/// A Gemini request read, then put through the cross-protocol seam as a foreign (`anthropic`)
/// ingress would be — so `extra` is cleared and only TYPED slots reach the writer.
fn read_then_seam(body: &Value) -> IrRequest {
    read_then_seam_from("gemini", body)
}

/// A request in the `ingress` dialect read, then put through the cross-protocol seam toward Gemini.
fn read_then_seam_from(ingress: &str, body: &Value) -> IrRequest {
    let mut ir = crate::proto_codec::protocol_for(ingress)
        .expect("ingress")
        .reader()
        .read_request(body)
        .expect("read_request");
    crate::chat_handle::chat_prepare_for_egress(
        &mut ir,
        &busbar_substrate_values::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: "anthropic",
            egress_requires_max_tokens: false,
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
            lane_caps: Default::default(),
        },
    );
    ir
}

/// A minimal IR request (one user turn), for writer-side tests.
fn bare_ir() -> IrRequest {
    let mut ir = GeminiReader
        .read_request(&json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}))
        .expect("read_request");
    ir.extra.clear();
    ir
}

/// A fresh writer (the `GeminiWriter` const carries per-stream state, so it is not borrowed).
fn gw() -> GeminiWriter {
    GeminiWriter
}

fn function_tool(name: &str) -> IrTool {
    IrTool {
        name: name.to_string(),
        input_schema: json!({"type": "object"}),
        ..Default::default()
    }
}

/// GEM-10 / IR-11 (reader): `googleSearch` / `codeExecution` / `urlContext` are read into the typed
/// hosted-tool slot — which crosses the seam — instead of a raw hosted tool the seam drops. A kind
/// with no neutral form (`fileSearch`) stays raw.
#[test]
fn gem10_gemini_hosted_tools_read_into_the_typed_slot() {
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
    "tools": [
        {"functionDeclarations": [{"name": "g", "parameters": {"type": "object"}}]},
        {"googleSearch": {}}, {"codeExecution": {}}, {"urlContext": {}},
        {"fileSearch": {"fileSearchStoreNames": ["s"]}}
    ]});
    let ir = GeminiReader.read_request(&body).expect("read");
    assert_eq!(
        ir.hosted_tools,
        vec![
            IrHostedTool::WebSearch(IrWebSearch::default()),
            IrHostedTool::CodeExecution,
            IrHostedTool::WebFetch(IrWebFetch::default()),
        ]
    );
    let raw: Vec<_> = ir.tools.iter().filter_map(|t| t.hosted.clone()).collect();
    assert_eq!(
        raw,
        vec![json!({"fileSearch": {"fileSearchStoreNames": ["s"]}})]
    );

    // Through the seam the three typed tools survive (the raw one is dropped) and a Gemini backend
    // gets them back in its own spelling beside the function.
    let out = gw().write_request(&read_then_seam(&body));
    assert_eq!(
        out["tools"],
        json!([
            {"functionDeclarations": [{"name": "g", "parameters": {"type": "object"}}]},
            {"googleSearch": {}}, {"codeExecution": {}}, {"urlContext": {}}
        ]),
        "{out}"
    );
}

/// GEM-10 / IR-11 (writer): a foreign hosted tool reaches a Gemini backend as its Gemini kind, with
/// the parameters Gemini lacks dropped and the tool kept — including when it is the only tool.
#[test]
fn ir11_foreign_hosted_tools_write_as_gemini_tools() {
    let mut ir = bare_ir();
    ir.hosted_tools = vec![
        IrHostedTool::WebSearch(IrWebSearch {
            max_uses: Some(3),
            allowed_domains: vec!["example.com".to_string()],
            ..Default::default()
        }),
        IrHostedTool::WebFetch(IrWebFetch {
            max_uses: Some(1),
            ..Default::default()
        }),
        IrHostedTool::CodeExecution,
    ];
    let out = gw().write_request(&ir);
    assert_eq!(
        out["tools"],
        json!([{"googleSearch": {}}, {"urlContext": {}}, {"codeExecution": {}}]),
        "{out}"
    );
}

/// GEM-19 / IR-18 (writer): a reasoning signature minted by another family is NOT sent to Gemini as
/// `thoughtSignature`; a Gemini-minted one, and one of unknown origin, still are.
#[test]
fn gem19_foreign_signature_is_not_sent_as_thought_signature() {
    let thinking = |sig: &str, origin: Option<IrSignatureOrigin>| IrBlock::Thinking {
        text: "reasoning".to_string(),
        signature: Some(sig.to_string()),
        redacted: false,
        cache_control: None,
        kind: None,
        signature_origin: origin,
    };
    let mut ir = bare_ir();
    ir.messages.push(IrMessage {
        role: IrRole::Assistant,
        content: vec![
            thinking("anthropic-sig", Some(IrSignatureOrigin::Anthropic)),
            thinking("openai-blob", Some(IrSignatureOrigin::OpenAi)),
            thinking("gemini-sig", Some(IrSignatureOrigin::Gemini)),
            thinking("unknown-sig", None),
        ],
    });
    let out = gw().write_request(&ir);
    let parts = &out["contents"][1]["parts"];
    assert_eq!(parts[0].get("thoughtSignature"), None, "{out}");
    assert_eq!(parts[1].get("thoughtSignature"), None, "{out}");
    assert_eq!(parts[2]["thoughtSignature"], "gemini-sig", "{out}");
    assert_eq!(parts[3]["thoughtSignature"], "unknown-sig", "{out}");
    // The reasoning text itself is still carried.
    assert_eq!(parts[0]["text"], "reasoning");
    assert_eq!(parts[0]["thought"], true);
}

/// IR-17 / IR-18 (reader): a Gemini thought part is a reasoning SUMMARY. A Gemini BACKEND's
/// signature is Gemini-minted; a request history turn's signature is whatever the client echoes (a
/// Gemini client of a foreign backend echoes that backend's blob), so its origin stays unknown.
#[test]
fn ir17_ir18_gemini_thought_parts_are_summary_with_gemini_origin() {
    let thinking = |block: &IrBlock| match block {
        IrBlock::Thinking {
            kind,
            signature_origin,
            ..
        } => (*kind, *signature_origin),
        other => panic!("not thinking: {other:?}"),
    };
    let resp = GeminiReader
        .read_response(
            &json!({"candidates": [{"content": {"role": "model", "parts": [
            {"text": "t", "thought": true, "thoughtSignature": "s"}, {"text": "a"}]},
            "finishReason": "STOP"}]}),
        )
        .expect("read");
    assert_eq!(
        thinking(&resp.content[0]),
        (
            Some(IrThinkingKind::Summary),
            Some(IrSignatureOrigin::Gemini)
        )
    );
    let req = GeminiReader
        .read_request(&json!({"contents": [
            {"role": "user", "parts": [{"text": "q"}]},
            {"role": "model", "parts": [{"text": "t", "thought": true, "thoughtSignature": "s"}]}
        ]}))
        .expect("read");
    assert_eq!(
        thinking(&req.messages[1].content[0]),
        (Some(IrThinkingKind::Summary), None)
    );
}

/// GEM-16 (reader half): a streamed citation's UTF-8 BYTE offsets become the IR's CHARACTER offsets,
/// converted against the answer text streamed so far.
#[test]
fn gem16_stream_citation_byte_offsets_read_as_characters() {
    let mut state = StreamDecodeState::default();
    // "héllo wörld": `é` and `ö` are two bytes each. "wörld" is chars 6..11, bytes 7..13.
    let chunks = [
        json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "héllo "}]}}]}),
        json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "wörld"}]},
            "citationMetadata": {"citationSources": [
                {"startIndex": 7, "endIndex": 13, "uri": "https://example.com"}]},
            "finishReason": "STOP"}]}),
    ];
    let events: Vec<IrStreamEvent> = chunks
        .iter()
        .flat_map(|c| GeminiReader.read_response_events("", c, &mut state))
        .collect();
    let cites: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockDelta {
                delta: IrDelta::CitationsDelta(c),
                ..
            } => Some(c.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(cites.len(), 1, "{events:?}");
    assert_eq!(
        (cites[0].start_index, cites[0].end_index),
        (Some(6), Some(11))
    );
    assert_eq!(state.streamed_text, "héllo wörld");
}

/// IR-03: Gemini `labels` read into the caller-metadata map; the map written back as `labels`, with
/// only the entries that break Gemini's label syntax dropped.
#[test]
fn ir03_labels_carry_as_metadata() {
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "labels": {"team": "search", "env": "prod"}});
    let ir = read_then_seam(&body);
    let mut metadata = ir.metadata.clone().expect("labels read as metadata");
    metadata.sort();
    assert_eq!(
        metadata,
        vec![
            ("env".to_string(), "prod".to_string()),
            ("team".to_string(), "search".to_string()),
        ]
    );
    assert_eq!(
        gw().write_request(&ir)["labels"],
        json!({"team": "search", "env": "prod"})
    );

    let mut ir = bare_ir();
    ir.metadata = Some(vec![
        ("user_id".to_string(), "u-42".to_string()),
        ("Session".to_string(), "x".to_string()),
        ("note".to_string(), "has space".to_string()),
    ]);
    assert_eq!(
        gw().write_request(&ir)["labels"],
        json!({"user_id": "u-42"})
    );
}

/// IR-10: `allowedFunctionNames` with more than one name is carried as the IR tool subset (not
/// relaxed to "any tool"); a "must call" subset is written back natively, a "may call" subset by
/// declaring only the listed functions.
#[test]
fn ir10_allowed_function_names_carry_as_the_tool_subset() {
    let tools = json!([{"functionDeclarations": [
        {"name": "a", "parameters": {"type": "object"}},
        {"name": "b", "parameters": {"type": "object"}},
        {"name": "c", "parameters": {"type": "object"}}]}]);
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "tools": tools,
        "toolConfig": {"functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": ["a", "b"]}}});
    let ir = read_then_seam(&body);
    assert_eq!(ir.tool_choice, Some(IrToolChoice::Required));
    assert_eq!(
        ir.allowed_tools,
        Some(vec!["a".to_string(), "b".to_string()])
    );
    let out = gw().write_request(&ir);
    assert_eq!(
        out["toolConfig"]["functionCallingConfig"],
        json!({"mode": "ANY", "allowedFunctionNames": ["a", "b"]}),
        "{out}"
    );
    assert_eq!(
        out["tools"][0]["functionDeclarations"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );

    // "May call one of these": only the listed functions are declared.
    let mut ir = bare_ir();
    ir.tools = vec![function_tool("a"), function_tool("b"), function_tool("c")];
    ir.tool_choice = Some(IrToolChoice::Auto);
    ir.allowed_tools = Some(vec!["b".to_string()]);
    let out = gw().write_request(&ir);
    let names: Vec<&str> = out["tools"][0]["functionDeclarations"]
        .as_array()
        .expect("decls")
        .iter()
        .filter_map(|d| d["name"].as_str())
        .collect();
    assert_eq!(names, vec!["b"], "{out}");
    assert_eq!(
        out["toolConfig"]["functionCallingConfig"],
        json!({"mode": "AUTO"})
    );
}

/// IR-19: `generationConfig.responseModalities` carries as the IR output modalities.
#[test]
fn ir19_response_modalities_carry() {
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {"responseModalities": ["TEXT", "IMAGE"]}});
    let ir = read_then_seam(&body);
    assert_eq!(
        ir.output_modalities,
        Some(vec![IrModality::Text, IrModality::Image])
    );
    let mut ir = bare_ir();
    ir.output_modalities = Some(vec![IrModality::Text, IrModality::Audio]);
    assert_eq!(
        gw().write_request(&ir)["generationConfig"]["responseModalities"],
        json!(["TEXT", "AUDIO"])
    );
}

/// IR-09: `thinkingBudget: 0` is reasoning switched OFF (not "never said"). Off is written back as
/// budget 0 only for a model that accepts it (the gemini-2.5-flash family); for any other model, or
/// with no model known, it is omitted so the request never 400s.
#[test]
fn ir09_thinking_budget_zero_is_off() {
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {"thinkingConfig": {"thinkingBudget": 0}}});
    let ir = read_then_seam(&body);
    assert_eq!(ir.reasoning, Some(IrReasoningAsk::Off));
    for model in [
        "gemini-2.5-flash",
        "models/gemini-2.5-flash-lite-preview-06-17",
    ] {
        assert_eq!(
            gw().write_request_for_model(&ir, model)["generationConfig"]["thinkingConfig"],
            json!({"thinkingBudget": 0}),
            "{model}"
        );
    }
    for model in ["gemini-2.5-pro", "gemini-3-pro-preview", "gemini-2.0-flash"] {
        let out = gw().write_request_for_model(&ir, model);
        assert!(out.get("generationConfig").is_none(), "{model}: {out}");
    }
    assert!(gw().write_request(&ir).get("generationConfig").is_none());
}

/// IR-09 across the seam: an Anthropic `thinking:{type:"disabled"}` (read as Off) reaches a Gemini
/// flash backend as budget 0 — never as the smallest ENABLE budget — and a Gemini pro backend
/// with no thinkingConfig at all.
#[test]
fn ir09_anthropic_thinking_disabled_reaches_gemini_as_off() {
    let body = json!({"model": "claude", "max_tokens": 64, "thinking": {"type": "disabled"},
        "messages": [{"role": "user", "content": "hi"}]});
    let ir = read_then_seam_from("anthropic", &body);
    assert_eq!(ir.reasoning, Some(IrReasoningAsk::Off));
    let flash = gw().write_request_for_model(&ir, "gemini-2.5-flash");
    assert_eq!(
        flash["generationConfig"]["thinkingConfig"],
        json!({"thinkingBudget": 0}),
        "{flash}"
    );
    let pro = gw().write_request_for_model(&ir, "gemini-2.5-pro");
    assert!(
        pro["generationConfig"].get("thinkingConfig").is_none(),
        "{pro}"
    );
}

/// GEM-10 / IR-11 across the seam: an Anthropic hosted web search / code execution reaches a
/// Gemini backend as `googleSearch` / `codeExecution`.
#[test]
fn ir11_anthropic_hosted_tools_reach_gemini() {
    let body = json!({"model": "claude", "max_tokens": 64,
    "messages": [{"role": "user", "content": "hi"}],
    "tools": [
        {"type": "web_search_20250305", "name": "web_search", "max_uses": 2},
        {"type": "code_execution_20250825", "name": "code_execution"}
    ]});
    let ir = read_then_seam_from("anthropic", &body);
    let out = gw().write_request_for_model(&ir, "gemini-2.5-flash");
    assert_eq!(
        out["tools"],
        json!([{"googleSearch": {}}, {"codeExecution": {}}]),
        "{out}"
    );
}

/// IR-04..07: the slots Gemini has no form for are not written and are reported to the seam.
#[test]
fn ir04_to_07_unsupported_slots_are_dropped_and_reported() {
    let mut ir = bare_ir();
    ir.service_tier = Some(IrServiceTier::Priority);
    ir.store = Some(true);
    ir.safety_identifier = Some("s".to_string());
    ir.prompt_cache_key = Some("k".to_string());
    ir.verbosity = Some(crate::ir::IrVerbosity::Low);
    assert_eq!(
        gw().dropped_egress_controls(&ir),
        vec![
            "service_tier",
            "store",
            "safety_identifier",
            "prompt_cache_key",
            "verbosity"
        ]
    );
    let out = gw().write_request(&ir);
    for k in [
        "service_tier",
        "store",
        "safety_identifier",
        "prompt_cache_key",
        "verbosity",
    ] {
        assert!(out.get(k).is_none(), "{k}: {out}");
    }
}
