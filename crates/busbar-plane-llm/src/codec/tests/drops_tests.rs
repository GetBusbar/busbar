// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE DROP PATH (design F3 "Drops"; spec Part 2 #76). For every dialect, in both directions, a
//! translate attempt that cannot carry a member WARNS naming its wire path and hands the path to
//! the seam's audit; nothing is put in a dropped block's place. Each dialect test carries a RED
//! arm: the same request or answer with only what the dialect maps drops nothing, so a walker that
//! names too much (or a reader that substitutes) fails here.

use super::*;
use crate::codec::proto_codec::protocol_for;
use crate::codec::translate::{TranslateCodec as _, TranslateReqInput};
use busbar_contract::codec::EgressWire;
use busbar_contract::ir::egress_prep::EgressPrep;
use busbar_contract::operation::OpVerb;
use busbar_contract::testkit::WarnCapture;
use serde_json::{json, Value};

const SEAM: Seam<'static> = Seam {
    direction: Direction::Request,
    ingress: "openai",
    egress: "anthropic",
};

fn prep(ingress: &str) -> EgressPrep<'_> {
    EgressPrep {
        ingress_protocol: ingress,
        egress_requires_max_tokens: true,
        lane_default_max_tokens: None,
        global_default_max_tokens: 4096,
        reasoning_allowed: true,
        reasoning_budgets: crate::codec::ir::REASONING_BUDGET_DEFAULTS,
        prompt_caching_allowed: true,
        cache_control_cap: None,
        lane_caps: Default::default(),
        thought_signature_fill: false,
    }
}

// ───────────────────────────── the primitive ─────────────────────────────

#[test]
fn a_drop_outside_a_translate_attempt_says_nothing() {
    let cap = WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        note(Dropped::new(
            "logit_bias",
            &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
            "dropped",
        ))
    });
    assert!(
        cap.messages().is_empty(),
        "a relay drops nothing: {:?}",
        cap.messages()
    );
}

#[test]
fn a_drop_warns_once_per_path_and_comes_back_for_the_audit() {
    let cap = WarnCapture::default();
    let ((), paths) = tracing::subscriber::with_default(cap.clone(), || {
        scope(SEAM, || {
            for path in ["logit_bias", "store", "logit_bias"] {
                note(Dropped::new(
                    path,
                    &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                    "dropped",
                ));
            }
        })
    });
    assert_eq!(paths, ["logit_bias", "store"]);
    assert_eq!(cap.count("path=logit_bias"), 1, "{:?}", cap.messages());
    assert!(
        cap.contains("diag=BUSBAR-7085")
            && cap.contains("direction=request")
            && cap.contains("ingress=openai")
            && cap.contains("egress=anthropic"),
        "the warn names the code, the direction and both dialects: {:?}",
        cap.messages()
    );
}

#[test]
fn a_scope_ends_with_its_attempt_even_on_unwind() {
    let unwound = std::panic::catch_unwind(|| {
        scope(SEAM, || panic!("the attempt fails"));
    });
    assert!(unwound.is_err());
    let cap = WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        note(Dropped::new(
            "store",
            &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
            "dropped",
        ))
    });
    assert!(cap.messages().is_empty(), "no attempt is left open");
}

#[test]
fn the_block_walker_names_what_the_grammar_does_not_model() {
    const TAGGED: Blocks = Blocks {
        at: &["messages[]", "content[]"],
        tag: Some("type"),
        modelled: &["text"],
        companions: &[],
    };
    let body = json!({"messages": [
        {"content": [{"type": "text"}, {"type": "document"}, {"no": "type"}, "a string"]},
        {"content": "plain"},
        {"content": [{"type": "document"}]}
    ]});
    assert_eq!(
        TAGGED.unmodelled(&body),
        ["messages[].content[].type=document", "messages[].content[]"],
        "each kind once; a non-object block is the reader's to refuse, never a drop"
    );
    const KEYED: Blocks = Blocks {
        at: &["candidates[]", "content", "parts[]"],
        tag: None,
        modelled: &["text"],
        companions: &["thought"],
    };
    let body = json!({"candidates": [{"content": {"parts": [
        {"text": "a", "thought": true}, {"thought": true, "executableCode": {}}
    ]}}]});
    assert_eq!(
        KEYED.unmodelled(&body),
        ["candidates[].content.parts[].executableCode"]
    );
}

#[test]
fn parked_members_are_named_as_the_reader_declares_them() {
    const PARKED: &[Parked] = &[
        Parked {
            key: "__hint",
            holds: Holds::Nothing,
        },
        Parked {
            key: "__names",
            holds: Holds::Path("messages[].name"),
        },
        Parked {
            key: "config",
            holds: Holds::Members(&["carried"]),
        },
        Parked {
            key: "__extras",
            holds: Holds::Items("messages[]", &["__marker"]),
        },
    ];
    let extra = json!({
        "__hint": true,
        "__names": {"0": "alice"},
        "config": {"carried": 1, "mapped": 2, "lost": 3},
        "__extras": {"0": {"audio": {}, "__marker": "f"}},
        "logit_bias": {}
    });
    let paths = extra_paths(extra.as_object().unwrap(), PARKED, |p| {
        p == ["config", "mapped"]
    });
    // `extra` is a sorted map: the paths come in its key order.
    assert_eq!(
        paths,
        [
            "messages[].audio",
            "messages[].name",
            "config.lost",
            "logit_bias"
        ]
    );
}

// ───────────────────────────── request direction, per dialect ─────────────────────────────

/// Translate `body` from `ingress` onto `egress`: the far end's body, what the seam audits, and the
/// warns.
fn translate(ingress: &str, egress: &str, body: &Value) -> (Value, Vec<String>, WarnCapture) {
    let _ = protocol_for(ingress);
    let handler = crate::codec::decl_of(ingress)
        .and_then(|d| d.handler)
        .and_then(|h| h.operation_handler(OpVerb::CHAT))
        .expect("a chat handler");
    let cap = WarnCapture::default();
    let p = prep(ingress);
    let out = tracing::subscriber::with_default(cap.clone(), || {
        handler.translate_request(TranslateReqInput::Json(body), Some(egress), &p, "m")
    });
    let Ok(out) = out else {
        panic!("{ingress} -> {egress}: the request must translate");
    };
    let EgressWire::Json(wire) = out.wire else {
        panic!("{ingress} -> {egress}: a chat request writes JSON");
    };
    (wire, out.dropped_controls, cap)
}

/// The drop is warned and audited under `paths`; the RED arm — the request without the unmapped
/// members — drops nothing; and no empty text block stands in for a dropped one.
fn request_drops(
    ingress: &str,
    egress: &str,
    with: Value,
    without: Value,
    paths: &[&str],
    not: &[&str],
) {
    let (wire, audited, cap) = translate(ingress, egress, &with);
    for path in paths {
        assert!(
            audited.iter().any(|a| a == path),
            "{ingress} -> {egress}: `{path}` must reach the audit: {audited:?}"
        );
        assert_eq!(
            cap.count(&format!("path={path}")),
            1,
            "{ingress} -> {egress}: one warn names `{path}`: {:?}",
            cap.messages()
        );
    }
    for path in not {
        assert!(
            !audited.iter().any(|a| a.starts_with(path)),
            "{ingress} -> {egress}: `{path}` crosses and must not be named: {audited:?}"
        );
    }
    let written = wire.to_string();
    assert!(
        !written.contains(r#""text":"""#),
        "{ingress} -> {egress}: nothing is substituted for a dropped block: {written}"
    );
    let (_, audited, cap) = translate(ingress, egress, &without);
    assert!(
        audited.is_empty() && !cap.contains("path="),
        "{ingress} -> {egress}: RED arm — a request of mapped members drops nothing: {audited:?} \
         {:?}",
        cap.messages()
    );
}

#[test]
fn openai_chat_request_drops_name_the_wire_path() {
    request_drops(
        "openai",
        "anthropic",
        json!({"model": "m", "logit_bias": {"1": 2}, "messages": [{"role": "user", "content": [
            {"type": "text", "text": "hi"}, {"type": "x_future", "x": 1}
        ]}]}),
        json!({"model": "m", "messages": [{"role": "user", "content": [
            {"type": "text", "text": "hi"}
        ]}]}),
        &["logit_bias", "messages[].content[].type=x_future"],
        &["model", "messages[].content[].type=text"],
    );
}

#[test]
fn anthropic_request_drops_name_the_wire_path() {
    request_drops(
        "anthropic",
        "openai",
        json!({"model": "m", "max_tokens": 10, "container": "c",
        "metadata": {"user_id": "u", "x": "y"},
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "hi"}, {"type": "container_upload", "file_id": "f"}
        ]}]}),
        json!({"model": "m", "max_tokens": 10, "metadata": {"user_id": "u"},
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]}),
        &[
            "container",
            "metadata.x",
            "messages[].content[].type=container_upload",
        ],
        &["metadata.user_id", "max_tokens"],
    );
}

#[test]
fn gemini_request_drops_name_the_wire_path() {
    request_drops(
        "gemini",
        "openai",
        json!({"contents": [{"role": "user", "parts": [
                {"text": "hi"}, {"executableCode": {"language": "PYTHON", "code": "1"}}
            ]}],
            "safetySettings": [{"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"}],
            "generationConfig": {"temperature": 0.5, "maxOutputTokens": 5,
                "mediaResolution": "MEDIA_RESOLUTION_LOW"}}),
        json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {"temperature": 0.5, "maxOutputTokens": 5}}),
        &[
            "safetySettings",
            "generationConfig.mediaResolution",
            "contents[].parts[].executableCode",
        ],
        &[
            "generationConfig.temperature",
            "generationConfig.maxOutputTokens",
        ],
    );
}

#[test]
fn bedrock_request_drops_name_the_wire_path() {
    request_drops(
        "bedrock",
        "openai",
        json!({"messages": [{"role": "user", "content": [
                {"text": "hi"}, {"guardContent": {"text": {"text": "g"}}}
            ]}],
            "guardrailConfig": {"guardrailIdentifier": "g", "guardrailVersion": "1"},
            "inferenceConfig": {"maxTokens": 5, "temperature": 0.2}}),
        json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {"maxTokens": 5, "temperature": 0.2}}),
        &["guardrailConfig", "messages[].content[].guardContent"],
        &["inferenceConfig"],
    );
}

#[test]
fn cohere_request_drops_name_the_wire_path() {
    request_drops(
        "cohere",
        "openai",
        json!({"model": "m", "safety_mode": "STRICT", "messages": [{"role": "user", "content": [
            {"type": "text", "text": "hi"}, {"type": "x_future"}
        ]}]}),
        json!({"model": "m", "messages": [{"role": "user", "content": [
            {"type": "text", "text": "hi"}
        ]}]}),
        &["safety_mode", "messages[].content[].type=x_future"],
        &["model"],
    );
}

#[test]
fn responses_request_drops_name_the_wire_path() {
    request_drops(
        "responses",
        "openai",
        json!({"model": "m", "previous_response_id": "r", "text": {"verbosity": "low", "x": 1},
        "input": [{"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": "hi"}, {"type": "x_future"}
        ]}]}),
        json!({"model": "m", "text": {"verbosity": "low"},
        "input": [{"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": "hi"}
        ]}]}),
        &[
            "previous_response_id",
            "text.x",
            "input[].content[].type=x_future",
        ],
        &["model", "text.verbosity"],
    );
}

// ───────────────────────────── response direction, per dialect ─────────────────────────────

/// Translate the far end's `body` (`egress`) for a caller of `ingress`: the caller's body and the
/// warns.
fn answer(egress: &str, ingress: &str, body: &Value) -> (String, Vec<String>, WarnCapture) {
    let _ = protocol_for(egress);
    let ctx = crate::exchange::reply::whole::WholeCtx {
        ingress,
        egress,
        operation: OpVerb::CHAT,
        model: "m",
        wants_stream: false,
        json_array: false,
        request: None,
        now_s: 1,
        elapsed_ms: None,
    };
    let bytes = serde_json::to_vec(body).unwrap();
    let cap = WarnCapture::default();
    let whole = tracing::subscriber::with_default(cap.clone(), || {
        crate::exchange::reply::whole::translate(&ctx, 200, &bytes)
    });
    assert_eq!(
        whole.end,
        crate::exchange::reply::whole::WholeEnd::Delivered,
        "{egress} -> {ingress}: the answer must translate"
    );
    (
        String::from_utf8(whole.answer.body).unwrap(),
        whole.dropped,
        cap,
    )
}

/// The answer's drop is warned under `paths`; the RED arm — the answer with only what maps —
/// drops nothing; no empty text block stands in for a dropped one.
fn response_drops(egress: &str, ingress: &str, with: Value, without: Value, paths: &[&str]) {
    let (body, audited, cap) = answer(egress, ingress, &with);
    for path in paths {
        assert_eq!(
            audited.iter().filter(|a| a == path).count(),
            1,
            "{egress} -> {ingress}: one audit row names `{path}`: {audited:?}"
        );
        assert_eq!(
            cap.count(&format!("path={path}")),
            1,
            "{egress} -> {ingress}: one warn names `{path}`: {:?}",
            cap.messages()
        );
    }
    assert!(cap.contains("direction=response"), "{:?}", cap.messages());
    assert!(
        !body.contains(r#""text":"""#),
        "{egress} -> {ingress}: nothing is substituted for a dropped block: {body}"
    );
    let (_, audited, cap) = answer(egress, ingress, &without);
    assert!(
        audited.is_empty(),
        "{egress} -> {ingress}: RED arm: {audited:?}"
    );
    assert!(
        !cap.contains("path="),
        "{egress} -> {ingress}: RED arm — an answer of mapped members drops nothing: {:?}",
        cap.messages()
    );
}

#[test]
fn anthropic_answer_drops_name_the_wire_path() {
    let answer = |content: Value| {
        json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
            "content": content, "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}})
    };
    response_drops(
        "anthropic",
        "openai",
        answer(json!([{"type": "text", "text": "hi"}, {"type": "x_future"}])),
        answer(json!([{"type": "text", "text": "hi"}])),
        &["content[].type=x_future"],
    );
}

#[test]
fn openai_chat_answer_drops_name_the_wire_path() {
    let answer = |content: Value| {
        json!({"id": "c", "object": "chat.completion", "created": 1, "model": "m",
            "choices": [{"index": 0, "finish_reason": "stop",
                "message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
    };
    response_drops(
        "openai",
        "anthropic",
        answer(json!([{"type": "text", "text": "hi"}, {"type": "x_future"}])),
        answer(json!([{"type": "text", "text": "hi"}])),
        &["choices[].message.content[].type=x_future"],
    );
}

#[test]
fn responses_answer_drops_name_the_wire_path() {
    let answer = |content: Value| {
        json!({"id": "resp_1", "object": "response", "created_at": 1, "model": "m",
            "status": "completed",
            "output": [{"type": "message", "id": "m1", "role": "assistant", "content": content}],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}})
    };
    response_drops(
        "responses",
        "openai",
        answer(json!([
            {"type": "output_text", "text": "hi", "annotations": []}, {"type": "x_future"}
        ])),
        answer(json!([{"type": "output_text", "text": "hi", "annotations": []}])),
        &["output[].content[].type=x_future"],
    );
}

/// DF-MAP-IR-GAPS section E: a Responses answer carrying a hosted-tool item (`web_search_call`)
/// translated to another dialect gives one drop WARN and one audit row naming the wire path. RED
/// before: the reader warned outside the drop path (no path, no audit row).
#[test]
fn responses_hosted_tool_item_is_dropped_on_the_drop_path() {
    let answer = |hosted: bool| {
        let mut output = vec![json!({"type": "message", "id": "m1", "role": "assistant",
            "content": [{"type": "output_text", "text": "hi", "annotations": []}]})];
        if hosted {
            output.insert(
                0,
                json!({"type": "web_search_call", "id": "ws_1", "status": "completed"}),
            );
        }
        json!({"id": "resp_1", "object": "response", "created_at": 1, "model": "m",
            "status": "completed", "output": output,
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}})
    };
    response_drops(
        "responses",
        "openai",
        answer(true),
        answer(false),
        &["output[].type=web_search_call"],
    );
}

#[test]
fn gemini_answer_drops_name_the_wire_path() {
    let answer = |parts: Value, rated: bool| {
        let mut candidate = json!({"content": {"role": "model", "parts": parts},
            "finishReason": "STOP"});
        if rated {
            candidate["safetyRatings"] =
                json!([{"category": "HARM_CATEGORY_HATE_SPEECH", "probability": "NEGLIGIBLE"}]);
        }
        json!({"candidates": [candidate],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1,
                "totalTokenCount": 2}})
    };
    response_drops(
        "gemini",
        "openai",
        answer(
            json!([{"text": "hi"}, {"executableCode": {"language": "PYTHON", "code": "1"}}]),
            true,
        ),
        answer(json!([{"text": "hi"}]), false),
        &[
            "candidates[].content.parts[].executableCode",
            "candidates[].safetyRatings",
        ],
    );
}

#[test]
fn bedrock_answer_drops_name_the_wire_path() {
    let answer = |content: Value, trace: bool| {
        let mut body = json!({"output": {"message": {"role": "assistant", "content": content}},
            "stopReason": "end_turn",
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}});
        if trace {
            body["trace"] = json!({"guardrail": {}});
        }
        body
    };
    response_drops(
        "bedrock",
        "openai",
        answer(json!([{"text": "hi"}, {"x_future": {}}]), true),
        answer(json!([{"text": "hi"}]), false),
        &["output.message.content[].x_future", "trace"],
    );
}

#[test]
fn cohere_answer_drops_name_the_wire_path() {
    let answer = |content: Value| {
        json!({"id": "c", "finish_reason": "COMPLETE",
            "message": {"role": "assistant", "content": content},
            "usage": {"tokens": {"input_tokens": 1, "output_tokens": 1}}})
    };
    response_drops(
        "cohere",
        "openai",
        answer(json!([{"type": "text", "text": "hi"}, {"type": "x_future"}])),
        answer(json!([{"type": "text", "text": "hi"}])),
        &["message.content[].type=x_future"],
    );
}
