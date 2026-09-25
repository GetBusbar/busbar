//! IR MAPPING (owner directive Q57): every field the Anthropic dialect carries that the IR and the
//! other dialect can also carry must map. One probe per audit defect (ANT-01..ANT-18,
//! `ir-mapping-audit.md` §4.1), driven through the production step list — reader →
//! `chat_prepare_for_egress` / `chat_prepare_for_ingress` → writer, and `StreamTranslate` for a
//! stream — on a real wire body, so each test fails if the defect it names comes back.
use super::super::proto_codec::protocol_for;
use serde_json::{json, Value};

/// Cross-protocol REQUEST: `ingress` reader → the egress seam → `egress` writer.
fn xreq(ingress: &'static str, egress: &str, body: &Value) -> Value {
    let ingress_p = protocol_for(ingress).expect("ingress protocol");
    let egress_p = protocol_for(egress).expect("egress protocol");
    let mut req = ingress_p
        .reader()
        .read_request(body)
        .expect("request reads");
    super::super::chat_handle::chat_prepare_for_egress(
        &mut req,
        &busbar_substrate_values::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: ingress,
            egress_requires_max_tokens: true,
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
            lane_caps: Default::default(),
        },
    );
    egress_p.writer().write_request(&req)
}

/// [`xreq`] onto a lane with the declared capabilities, through the production lane write.
fn xreq_lane(
    ingress: &'static str,
    egress: &str,
    body: &Value,
    caps: &super::super::proto_codec::LaneCaps,
) -> Value {
    let egress_p = protocol_for(egress).expect("egress protocol");
    let mut req = protocol_for(ingress)
        .expect("ingress protocol")
        .reader()
        .read_request(body)
        .expect("request reads");
    super::super::chat_handle::chat_prepare_for_egress(
        &mut req,
        &busbar_substrate_values::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: ingress,
            egress_requires_max_tokens: true,
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
            lane_caps: Default::default(),
        },
    );
    egress_p
        .writer()
        .write_request_for_lane(&req, "claude-x", caps)
}

/// A lane of the newest Claude generation: declares adaptive thinking AND native structured
/// outputs (the shipped catalog's model patterns turn both on for Opus 4.7+/5.x, Sonnet 5, Fable).
fn newest_lane() -> super::super::proto_codec::LaneCaps {
    super::super::proto_codec::LaneCaps {
        anthropic_adaptive_thinking: true,
        native_structured_output: true,
        ..Default::default()
    }
}

/// Cross-protocol buffered RESPONSE: `egress` (backend) reader → ingress seam → `ingress` writer.
fn xresp(egress: &str, ingress: &'static str, body: &Value) -> Value {
    let egress_p = protocol_for(egress).expect("egress protocol");
    let ingress_p = protocol_for(ingress).expect("ingress protocol");
    let mut resp = egress_p
        .reader()
        .read_response(body)
        .expect("response reads");
    super::super::chat_handle::chat_prepare_for_ingress(&mut resp, ingress, 1_752_000_000);
    ingress_p.writer().write_response(&resp)
}

/// Cross-protocol STREAM: backend `egress` SSE bytes → the `ingress` client's bytes.
fn xstream(egress: &str, ingress: &str, raw: &str) -> String {
    let mut st =
        super::super::proto_stream::StreamTranslate::new(ingress, egress).expect("translator");
    let mut out = st.feed(raw.as_bytes());
    out.extend(st.finish());
    String::from_utf8_lossy(&out).into_owned()
}

fn user_text(text: &str) -> Value {
    json!({"role": "user", "content": [{"type": "text", "text": text}]})
}

/// ANT-01: an Anthropic `document` with a `text` source is carried BASE64 on the IR, so a foreign
/// writer's base64 slot holds the real encoding of the text, not the raw text posing as base64.
#[test]
fn ant01_text_document_reaches_foreign_writers_as_real_base64() {
    let body = json!({
        "model": "m", "max_tokens": 100,
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "read"},
            {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "plain doc"}}
        ]}]
    });
    // base64("plain doc") == "cGxhaW4gZG9j"
    let openai = serde_json::to_string(&xreq("anthropic", "openai", &body)).unwrap();
    assert!(
        openai.contains("data:text/plain;base64,cGxhaW4gZG9j"),
        "openai file_data must be the base64 of the text; got {openai}"
    );
    assert!(!openai.contains("base64,plain doc"), "{openai}");
    let bedrock = xreq("anthropic", "bedrock", &body);
    let bedrock_s = serde_json::to_string(&bedrock).unwrap();
    assert!(
        bedrock_s.contains("\"bytes\":\"cGxhaW4gZG9j\""),
        "bedrock document bytes must be base64; got {bedrock_s}"
    );
}

/// ANT-02: a foreign text/plain document (base64 on the IR) reaches Anthropic as a `text` source
/// holding the DECODED text; a mime Anthropic has no inline document source for is dropped, never
/// sent as a corrupt `text` source.
#[test]
fn ant02_foreign_text_document_is_decoded_into_the_text_source() {
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "read"},
            {"type": "file", "file": {"filename": "a.txt", "file_data": "data:text/plain;base64,cGxhaW4gZG9j"}},
            {"type": "file", "file": {"filename": "a.zip", "file_data": "data:application/zip;base64,UEsDBA=="}}
        ]}]
    });
    let out = xreq("openai", "anthropic", &body);
    let content = out
        .pointer("/messages/0/content")
        .unwrap()
        .as_array()
        .unwrap();
    let docs: Vec<&Value> = content.iter().filter(|b| b["type"] == "document").collect();
    assert_eq!(
        docs.len(),
        1,
        "only the text document has an Anthropic source; got {out}"
    );
    assert_eq!(
        docs[0]["source"],
        json!({"type": "text", "media_type": "text/plain", "data": "plain doc"}),
        "{out}"
    );
    assert!(
        content
            .iter()
            .all(|b| b["type"] != "text" || b["text"] != ""),
        "no empty-text placeholder may be sent; got {out}"
    );
}

/// ANT-03: a Files-API image (`source.type:"file"`) is an Anthropic-only handle: a foreign writer
/// must not receive an empty base64 image, and the Anthropic writer re-emits it verbatim.
#[test]
fn ant03_file_image_source_is_a_vendor_handle_not_empty_base64() {
    let body = json!({
        "model": "m", "max_tokens": 100,
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "hi"},
            {"type": "image", "source": {"type": "file", "file_id": "file_abc"}}
        ]}]
    });
    for egress in ["openai", "responses", "gemini", "bedrock", "cohere"] {
        let s = serde_json::to_string(&xreq("anthropic", egress, &body)).unwrap();
        assert!(!s.contains("data:;base64,"), "{egress}: {s}");
        assert!(
            !s.contains("\"data\":\"\""),
            "{egress}: empty inline bytes: {s}"
        );
    }
    let ir = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_request(&body)
        .unwrap();
    let back = protocol_for("anthropic")
        .unwrap()
        .writer()
        .write_request(&ir);
    assert_eq!(
        back.pointer("/messages/0/content/1"),
        Some(&json!({"type": "image", "source": {"type": "file", "file_id": "file_abc"}})),
        "{back}"
    );
}

/// ANT-04: Anthropic `tools[].strict` is read and reaches OpenAI's `function.strict`.
#[test]
fn ant04_tool_strict_is_read() {
    let body = json!({
        "model": "m", "max_tokens": 100,
        "messages": [user_text("hi")],
        "tools": [{"name": "f", "description": "d", "strict": true,
                   "input_schema": {"type": "object", "properties": {}, "additionalProperties": false}}]
    });
    let out = xreq("anthropic", "openai", &body);
    assert_eq!(
        out.pointer("/tools/0/function/strict"),
        Some(&json!(true)),
        "{out}"
    );
}

/// ANT-05: an OpenAI strict function tool keeps `strict: true` on the Anthropic tool.
#[test]
fn ant05_tool_strict_is_written() {
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"type": "function", "function": {"name": "f", "strict": true,
            "parameters": {"type": "object", "properties": {}, "additionalProperties": false}}}]
    });
    let out = xreq("openai", "anthropic", &body);
    assert_eq!(out.pointer("/tools/0/strict"), Some(&json!(true)), "{out}");
}

/// ANT-06: Anthropic `output_config.format` (and the deprecated `output_format`) reach a foreign
/// backend as its structured-output directive.
#[test]
fn ant06_output_config_format_is_read() {
    let schema = json!({"type": "object", "properties": {"a": {"type": "string"}},
                        "required": ["a"], "additionalProperties": false});
    for body in [
        json!({"model": "m", "max_tokens": 100, "messages": [user_text("hi")],
               "output_config": {"format": {"type": "json_schema", "schema": schema}}}),
        json!({"model": "m", "max_tokens": 100, "messages": [user_text("hi")],
               "output_format": {"type": "json_schema", "schema": schema}}),
    ] {
        let out = xreq("anthropic", "openai", &body);
        assert_eq!(
            out.pointer("/response_format/type"),
            Some(&json!("json_schema")),
            "{out}"
        );
        assert_eq!(
            out.pointer("/response_format/json_schema/schema"),
            Some(&schema),
            "{out}"
        );
    }
}

/// ANT-07 (with ANT-08): on a lane that declares native structured outputs, a foreign
/// `response_format` rides Anthropic's native `output_config.format`. The caller's own `tool_choice` and parallelism survive untouched, no
/// synthetic tool is invented, and the combination still carries under thinking.
#[test]
fn ant07_response_format_is_native_and_leaves_tool_choice_alone() {
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"type": "function", "function": {"name": "lookup",
            "parameters": {"type": "object", "properties": {"q": {"type": "string"}}}}}],
        "tool_choice": {"type": "function", "function": {"name": "lookup"}},
        "parallel_tool_calls": false,
        "response_format": {"type": "json_schema", "json_schema": {"name": "out",
            "schema": {"type": "object", "properties": {"n": {"type": "object", "properties": {}}}}}}
    });
    let out = xreq_lane("openai", "anthropic", &body, &newest_lane());
    assert_eq!(
        out["tool_choice"],
        json!({"type": "tool", "name": "lookup", "disable_parallel_tool_use": true}),
        "the caller's tool_choice and parallelism must survive; got {out}"
    );
    let tools = out["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1, "no synthetic tool may be added; got {out}");
    assert_eq!(
        out.pointer("/output_config/format/type"),
        Some(&json!("json_schema"))
    );
    assert_eq!(
        out.pointer("/output_config/format/schema/additionalProperties"),
        Some(&json!(false)),
        "{out}"
    );
    assert_eq!(
        out.pointer("/output_config/format/schema/properties/n/additionalProperties"),
        Some(&json!(false)),
        "nested objects must be closed too; got {out}"
    );

    // Under thinking the schema is NOT lost (the forced tool used to be downgraded to auto).
    let mut thinking = body.clone();
    thinking.as_object_mut().unwrap().remove("tool_choice");
    thinking["reasoning_effort"] = json!("low");
    let out2 = xreq_lane("openai", "anthropic", &thinking, &newest_lane());
    assert_eq!(out2["thinking"]["type"], "adaptive", "{out2}");
    assert_eq!(
        out2.pointer("/output_config/format/type"),
        Some(&json!("json_schema")),
        "{out2}"
    );
    assert_eq!(
        out2.pointer("/output_config/effort"),
        Some(&json!("low")),
        "{out2}"
    );

    // A schema-less JSON mode has no Anthropic form: nothing is invented, and the drop is reported.
    let mut object_mode = body.clone();
    object_mode["response_format"] = json!({"type": "json_object"});
    let ir = protocol_for("openai")
        .unwrap()
        .reader()
        .read_request(&object_mode)
        .unwrap();
    let anthropic = protocol_for("anthropic").unwrap();
    let w = anthropic.writer();
    let out3 = w.write_request_for_lane(&ir, "claude-x", &newest_lane());
    assert!(out3.get("output_config").is_none(), "{out3}");
    assert_eq!(out3["tools"].as_array().unwrap().len(), 1, "{out3}");
    assert!(w
        .dropped_egress_controls_for_lane(&ir, &newest_lane())
        .contains(&"response_format"));
}

/// ANT-07, the lane that does NOT declare native structured outputs (the default — Claude 3.x,
/// Sonnet 4 / Opus 4.0 400 on `output_config.format`): the directive takes the pre-capability
/// forced-tool form, byte for byte what this writer sent before the capability existed, and the
/// forced answer is mapped back to text on the buffered path.
#[test]
fn ant07_default_lane_keeps_the_forced_tool() {
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "response_format": {"type": "json_schema", "json_schema": {"name": "out",
            "schema": {"type": "object", "properties": {"n": {"type": "integer"}}}}}
    });
    let out = xreq_lane("openai", "anthropic", &body, &Default::default());
    assert!(out.get("output_config").is_none(), "{out}");
    assert_eq!(
        out["tool_choice"],
        json!({"type": "tool", "name": "busbar_response_format"}),
        "{out}"
    );
    assert_eq!(
        out["tools"][0]["input_schema"],
        json!({"type": "object", "properties": {"n": {"type": "integer"}}}),
        "{out}"
    );
    // The model-blind write is the default-lane write.
    assert_eq!(xreq("openai", "anthropic", &body), out);
    // A schema-less JSON mode is carried (permissive object schema), so nothing is reported dropped.
    let ir = protocol_for("openai")
        .unwrap()
        .reader()
        .read_request(
            &json!({"model": "m", "messages": [{"role": "user", "content": "hi"}],
            "response_format": {"type": "json_object"}}),
        )
        .unwrap();
    let anthropic = protocol_for("anthropic").unwrap();
    let w = anthropic.writer();
    assert!(!w
        .dropped_egress_controls_for_lane(&ir, &Default::default())
        .contains(&"response_format"));

    // The forced tool_use answer comes back to a foreign client as text.
    let resp = json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-x",
        "content": [{"type": "tool_use", "id": "toolu_1", "name": "busbar_response_format",
                     "input": {"n": 3}}],
        "stop_reason": "tool_use", "stop_sequence": null,
        "usage": {"input_tokens": 3, "output_tokens": 4}});
    let o = xresp("anthropic", "openai", &resp);
    assert_eq!(
        o["choices"][0]["message"]["content"],
        json!("{\"n\":3}"),
        "{o}"
    );
    assert_eq!(o["choices"][0]["finish_reason"], json!("stop"), "{o}");
}

/// ANT-09: Anthropic adaptive thinking and `output_config.effort` reach foreign backends.
#[test]
fn ant09_adaptive_thinking_and_effort_are_read() {
    let with_effort = json!({"model": "m", "max_tokens": 100, "messages": [user_text("hi")],
        "thinking": {"type": "adaptive"}, "output_config": {"effort": "xhigh"}});
    let out = xreq("anthropic", "openai", &with_effort);
    assert_eq!(
        out["reasoning_effort"], "high",
        "xhigh reads as the IR's top level; got {out}"
    );
    let adaptive = json!({"model": "m", "max_tokens": 100, "messages": [user_text("hi")],
        "thinking": {"type": "adaptive"}});
    let g = xreq("anthropic", "gemini", &adaptive);
    assert_eq!(
        g.pointer("/generationConfig/thinkingConfig/thinkingBudget"),
        Some(&json!(-1)),
        "adaptive is 'the model decides' = Gemini dynamic; got {g}"
    );
}

/// ANT-10: a word-form reasoning ask reaches an adaptive-thinking lane (Opus 4.7+/5.x, Sonnet 5,
/// Fable — where `budget_tokens` is a 400) as adaptive thinking + effort, and every other lane as
/// `budget_tokens` (architect lane-capability ruling).
#[test]
fn ant10_effort_ask_is_written_as_adaptive() {
    let body = json!({"model": "gpt-5", "messages": [{"role": "user", "content": "hi"}],
                      "max_completion_tokens": 8000, "reasoning_effort": "medium"});
    let out = xreq_lane("openai", "anthropic", &body, &newest_lane());
    assert_eq!(out["thinking"], json!({"type": "adaptive"}), "{out}");
    assert_eq!(
        out.pointer("/output_config/effort"),
        Some(&json!("medium")),
        "{out}"
    );
    // A lane that does not declare adaptive thinking (the default) gets `budget_tokens`, the only
    // on-mode Haiku 4.5 / Sonnet 4.5 / Opus 4.5 and older accept.
    let old = xreq_lane("openai", "anthropic", &body, &Default::default());
    assert_eq!(old["thinking"]["type"], json!("enabled"), "{old}");
    assert_eq!(
        old["thinking"]["budget_tokens"],
        json!(crate::ir::REASONING_BUDGET_DEFAULTS[2].min(8000 - 1024)),
        "{old}"
    );
    assert!(old.get("output_config").is_none(), "{old}");
}

/// ANT-11: `model_context_window_exceeded` is a length cut-off on every foreign client, buffered and
/// streamed — never a natural stop.
#[test]
fn ant11_context_window_stop_is_a_length_stop() {
    let body = json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "claude",
        "content": [{"type": "text", "text": "partial"}],
        "stop_reason": "model_context_window_exceeded", "stop_sequence": null,
        "usage": {"input_tokens": 10, "output_tokens": 5}});
    let out = xresp("anthropic", "openai", &body);
    assert_eq!(
        out.pointer("/choices/0/finish_reason"),
        Some(&json!("length")),
        "{out}"
    );
    let g = xresp("anthropic", "gemini", &body);
    assert_eq!(
        g.pointer("/candidates/0/finishReason"),
        Some(&json!("MAX_TOKENS")),
        "{g}"
    );

    let raw = concat!(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude\",\"content\":[],\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"model_context_window_exceeded\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":5}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    );
    let s = xstream("anthropic", "openai", raw);
    assert!(s.contains("\"finish_reason\":\"length\""), "{s}");
}

/// ANT-12: a foreign content-filter stop reaches an Anthropic client as `refusal`, buffered and
/// streamed — never as a completed `end_turn`.
#[test]
fn ant12_content_filter_stop_is_a_refusal() {
    let body = json!({"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "partial"},
                     "finish_reason": "content_filter"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}});
    let out = xresp("openai", "anthropic", &body);
    assert_eq!(out["stop_reason"], "refusal", "{out}");

    let raw = concat!(
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"partial\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"content_filter\"}]}\n\n",
        "data: [DONE]\n\n",
    );
    let s = xstream("openai", "anthropic", raw);
    assert!(s.contains("\"stop_reason\":\"refusal\""), "{s}");
}

/// ANT-13: an Anthropic server tool is hosted, not a function: it never reaches a foreign backend as
/// a function tool with a null schema, and the Anthropic writer re-emits its raw definition.
#[test]
fn ant13_server_tools_are_hosted_not_functions() {
    let body = json!({"model": "m", "max_tokens": 100, "messages": [user_text("hi")],
    "tools": [
        {"name": "f", "input_schema": {"type": "object"}},
        {"type": "web_search_20250305", "name": "web_search", "max_uses": 3},
        {"type": "bash_20250124", "name": "bash"}
    ]});
    for egress in ["openai", "responses", "gemini", "bedrock", "cohere"] {
        let s = serde_json::to_string(&xreq("anthropic", egress, &body)).unwrap();
        assert!(
            !s.contains("web_search"),
            "{egress}: server tool leaked as a function: {s}"
        );
        assert!(
            !s.contains("\"bash\""),
            "{egress}: server tool leaked as a function: {s}"
        );
    }
    let ir = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_request(&body)
        .unwrap();
    let back = protocol_for("anthropic")
        .unwrap()
        .writer()
        .write_request(&ir);
    assert_eq!(
        back.pointer("/tools/1"),
        Some(&json!({"type": "web_search_20250305", "name": "web_search", "max_uses": 3})),
        "{back}"
    );
}

/// ANT-14: a streamed server-tool block (`server_tool_use` + its `input_json_delta`s + stop, then a
/// `web_search_tool_result`) is suppressed WHOLE: a foreign client sees no orphan tool-argument
/// deltas for a block that never opened, and the answer text still arrives.
#[test]
fn ant14_suppressed_stream_block_drops_its_deltas_and_stop() {
    let raw = concat!(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude\",\"content\":[],\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"server_tool_use\",\"id\":\"srvtoolu_1\",\"name\":\"web_search\",\"input\":{}}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"query\\\":\\\"x\\\"}\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"web_search_tool_result\",\"tool_use_id\":\"srvtoolu_1\",\"content\":[]}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"text_delta\",\"text\":\"answer\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":2}\n\n",
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":5}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    );
    let decoder = protocol_for("anthropic").unwrap();
    let mut state = crate::ir::StreamDecodeState::default();
    let mut events = Vec::new();
    for frame in raw.split("\n\n").filter(|f| !f.is_empty()) {
        let mut lines = frame.lines();
        let ev = lines.next().unwrap().trim_start_matches("event: ");
        let data: Value =
            serde_json::from_str(lines.next().unwrap().trim_start_matches("data: ")).unwrap();
        events.extend(decoder.reader().read_response_events(ev, &data, &mut state));
    }
    for ev in &events {
        match ev {
            crate::ir::IrStreamEvent::BlockDelta { index, .. }
            | crate::ir::IrStreamEvent::BlockStop { index } => {
                assert_eq!(*index, 2, "only the text block may surface; got {events:?}")
            }
            _ => {}
        }
    }
    let s = xstream("anthropic", "openai", raw);
    assert!(
        !s.contains("tool_calls"),
        "no orphan tool deltas may reach the client: {s}"
    );
    assert!(s.contains("answer"), "{s}");
}

/// ANT-15: a foreign backend's image/attachment output is omitted from an Anthropic response (an
/// assistant message has no image/document response block); its JSON output rides as text.
#[test]
fn ant15_response_image_and_json_blocks_are_not_invalid_blocks() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![
            crate::ir::IrBlock::Text {
                text: "here".to_string(),
                cache_control: None,
                citations: Vec::new(),
                refusal: false,
            },
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Base64 {
                    media_type: "image/png".to_string(),
                    data: "iVBO".to_string(),
                },
                cache_control: None,
                detail: None,
            },
            crate::ir::IrBlock::Json(json!({"k": 1})),
        ],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
            detail: crate::ir::IrUsageDetail::default(),
        },
        model: Some("m".to_string()),
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
        request_echo: None,
        stop_detail: None,
    };
    let out = protocol_for("anthropic")
        .unwrap()
        .writer()
        .write_response(&resp);
    let content = out["content"].as_array().unwrap();
    assert!(
        content.iter().all(|b| b["type"] == "text"),
        "only text response blocks; got {out}"
    );
    assert_eq!(content.len(), 2, "{out}");
    assert_eq!(content[1]["text"], "{\"k\":1}", "{out}");
}

/// ANT-16: a Bedrock JSON tool result reaches Anthropic as a text block of its JSON, not `[]`.
#[test]
fn ant16_json_tool_result_is_carried_as_text() {
    let body = json!({"messages": [
        {"role": "user", "content": [{"text": "q"}]},
        {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t1", "name": "f", "input": {}}}]},
        {"role": "user", "content": [{"toolResult": {"toolUseId": "t1", "content": [{"json": {"x": 1}}]}}]}
    ]});
    let out = xreq("bedrock", "anthropic", &body);
    assert_eq!(
        out.pointer("/messages/2/content/0/content"),
        Some(&json!([{"type": "text", "text": "{\"x\":1}"}])),
        "{out}"
    );
}

/// ANT-17: inside a `tool_result`, an attachment with no Anthropic projection (audio, a foreign
/// vendor handle) and an empty text are omitted — never the empty-text placeholder Anthropic
/// rejects.
#[test]
fn ant17_tool_result_content_is_filtered_like_message_content() {
    let req = crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "t1".to_string(),
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "ok".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                        refusal: false,
                    },
                    crate::ir::IrBlock::Media {
                        kind: crate::ir::IrMediaKind::Audio,
                        source: crate::ir::IrImageSource::Base64 {
                            media_type: "audio/wav".to_string(),
                            data: "UklG".to_string(),
                        },
                        name: None,
                        cache_control: None,
                        citations: None,
                        context: None,
                    },
                    crate::ir::IrBlock::Image {
                        source: crate::ir::IrImageSource::Vendor {
                            vendor: "responses",
                            value: json!({"file_id": "file_1"}),
                        },
                        cache_control: None,
                        detail: None,
                    },
                    crate::ir::IrBlock::Text {
                        text: String::new(),
                        cache_control: None,
                        citations: Vec::new(),
                        refusal: false,
                    },
                ],
                is_error: false,
                cache_control: None,
            }],
        }],
        max_tokens: Some(16),
        ..Default::default()
    };
    let out = protocol_for("anthropic")
        .unwrap()
        .writer()
        .write_request(&req);
    assert_eq!(
        out.pointer("/messages/0/content/0/content"),
        Some(&json!([{"type": "text", "text": "ok"}])),
        "{out}"
    );
}

/// ANT-18: a `search_result_location` citation keeps its `source` (as the neutral url) on read, and
/// a neutral search-result citation is written back with the search-result field names.
#[test]
fn ant18_search_result_citation_source_maps_both_ways() {
    let body = json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "claude",
        "content": [{"type": "text", "text": "cited", "citations": [{
            "type": "search_result_location", "source": "https://kb/1", "title": "KB",
            "cited_text": "c", "search_result_index": 0, "start_block_index": 0, "end_block_index": 1
        }]}],
        "stop_reason": "end_turn", "stop_sequence": null,
        "usage": {"input_tokens": 1, "output_tokens": 1}});
    let resp = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_response(&body)
        .unwrap();
    let crate::ir::IrBlock::Text { citations, .. } = &resp.content[0] else {
        panic!("text block expected");
    };
    assert_eq!(citations[0].url.as_deref(), Some("https://kb/1"));
    assert_eq!(citations[0].document_index, Some(0));

    let mut neutral = citations[0].clone();
    neutral.raw = None;
    let written = super::write_citation(&neutral);
    assert_eq!(
        written,
        json!({"type": "search_result_location", "cited_text": "c", "source": "https://kb/1",
               "title": "KB", "search_result_index": 0, "start_block_index": 0, "end_block_index": 1}),
    );
}
