//! IR SLOT WIRING: the Anthropic reader FILLS and the Anthropic writer EMITS every
//! typed IR slot `ir-slots-landed.md` lists Anthropic under — IR-09 (ANT-09), IR-16 (ANT-11), IR-11
//! (ANT-13), IR-02 refusal category, IR-04, IR-10, IR-12, IR-18 and the "N" slots. Each probe runs
//! the production step list (reader → `chat_prepare_for_egress` / `chat_prepare_for_ingress` →
//! writer), so the Anthropic egress sees exactly what a foreign ingress's IR would hand it.
use super::super::proto_codec::protocol_for;
use serde_json::{json, Value};

fn read(body: &Value) -> crate::ir::IrRequest {
    protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_request(body)
        .expect("request reads")
}

/// The egress seam, then the Anthropic writer on a lane with `caps`. `extra` is cleared by the
/// seam, so only the TYPED slots reach the writer — the path a foreign ingress takes.
fn egress(mut req: crate::ir::IrRequest, caps: &super::super::proto_codec::LaneCaps) -> Value {
    super::super::chat_handle::chat_prepare_for_egress(
        &mut req,
        &busbar_contract::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: "openai",
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
    protocol_for("anthropic")
        .unwrap()
        .writer()
        .write_request_for_lane(&req, "claude-x", caps)
}

fn newest_lane() -> super::super::proto_codec::LaneCaps {
    super::super::proto_codec::LaneCaps {
        anthropic_adaptive_thinking: true,
        native_structured_output: true,
        ..Default::default()
    }
}

fn base() -> Value {
    json!({"model": "m", "max_tokens": 4000,
           "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]})
}

fn with(mut body: Value, key: &str, v: Value) -> Value {
    body[key] = v;
    body
}

/// Buffered backend response → ingress seam → Anthropic client writer.
fn resp_to_anthropic(resp: &mut crate::ir::IrResponse) -> Value {
    super::super::chat_handle::chat_prepare_for_ingress(resp, "anthropic", 1_752_000_000);
    protocol_for("anthropic")
        .unwrap()
        .writer()
        .write_response(resp)
}

fn anthropic_response(stop_reason: &str, stop_details: Value) -> Value {
    json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "claude",
           "content": [{"type": "text", "text": "partial"}],
           "stop_reason": stop_reason, "stop_details": stop_details, "stop_sequence": null,
           "usage": {"input_tokens": 10, "output_tokens": 5}})
}

// ── IR-09 / ANT-09 ────────────────────────────────────────────────────────────────────────────────

/// ANT-09: `thinking:{type:"disabled"}` is the explicit OFF ask, and the Anthropic writer emits it
/// back as `disabled` (never a zero budget that drops the ask, never an enable ask).
#[test]
fn ant09_thinking_disabled_reads_as_off_and_writes_disabled() {
    let body = with(base(), "thinking", json!({"type": "disabled"}));
    let ir = read(&body);
    assert_eq!(ir.reasoning, Some(crate::ir::IrReasoningAsk::Off));
    for caps in [Default::default(), newest_lane()] {
        let out = egress(ir.clone(), &caps);
        assert_eq!(out["thinking"], json!({"type": "disabled"}), "{out}");
        assert!(out.get("output_config").is_none(), "{out}");
    }
}

/// ANT-09: `output_config.effort` `xhigh` / `max` read as the IR-09 words above High and are written
/// back verbatim on an adaptive lane; a budget lane takes the table's top entry.
#[test]
fn ant09_effort_xhigh_and_max_are_carried() {
    use crate::ir::{IrReasoningAsk::Effort, IrReasoningEffort as E};
    for (word, want) in [("xhigh", E::XHigh), ("max", E::Max)] {
        let body = with(
            with(base(), "thinking", json!({"type": "adaptive"})),
            "output_config",
            json!({"effort": word}),
        );
        let ir = read(&body);
        assert_eq!(ir.reasoning, Some(Effort(want)), "{word}");
        let out = egress(ir.clone(), &newest_lane());
        assert_eq!(out["thinking"], json!({"type": "adaptive"}), "{out}");
        assert_eq!(
            out.pointer("/output_config/effort"),
            Some(&json!(word)),
            "{out}"
        );
        let old = egress(ir, &Default::default());
        assert_eq!(
            old["thinking"],
            json!({"type": "enabled", "budget_tokens":
                crate::ir::REASONING_BUDGET_DEFAULTS[3].min(4000 - 1024)}),
            "{old}"
        );
    }
}

// ── IR-16 / ANT-11 and IR-02 ──────────────────────────────────────────────────────────────────────

/// ANT-11: `model_context_window_exceeded` reads as MaxTokens + ContextWindowExceeded, and an
/// Anthropic client gets the exact token back (buffered), not the coarser `max_tokens`.
#[test]
fn ant11_context_window_stop_round_trips_buffered() {
    let body = anthropic_response("model_context_window_exceeded", Value::Null);
    let mut ir = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_response(&body)
        .unwrap();
    assert_eq!(ir.stop_reason, Some(crate::ir::IrStopReason::MaxTokens));
    assert_eq!(
        ir.stop_detail,
        Some(crate::ir::IrStopDetail::ContextWindowExceeded)
    );
    let out = resp_to_anthropic(&mut ir);
    assert_eq!(out["stop_reason"], "model_context_window_exceeded", "{out}");
    assert_eq!(out["stop_details"], Value::Null, "{out}");
}

/// ANT-11, stream: the `message_delta` carries the refinement and writes the exact token back.
#[test]
fn ant11_context_window_stop_round_trips_stream() {
    let data = json!({"type": "message_delta",
        "delta": {"stop_reason": "model_context_window_exceeded", "stop_sequence": null},
        "usage": {"output_tokens": 5}});
    let ev = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_response_event("message_delta", &data)
        .expect("event");
    match &ev {
        crate::ir::IrStreamEvent::MessageDelta {
            stop_reason,
            stop_detail,
            ..
        } => {
            assert_eq!(*stop_reason, Some(crate::ir::IrStopReason::MaxTokens));
            assert_eq!(
                *stop_detail,
                Some(crate::ir::IrStopDetail::ContextWindowExceeded)
            );
        }
        other => panic!("not a message_delta: {other:?}"),
    }
    let (_, out) = protocol_for("anthropic")
        .unwrap()
        .writer()
        .write_response_event(&ev)
        .expect("written");
    assert_eq!(
        out.pointer("/delta/stop_reason"),
        Some(&json!("model_context_window_exceeded")),
        "{out}"
    );
}

/// IR-02: a refusal's `stop_details` (category, explanation) is read and written back, buffered
/// and stream; any other stop keeps `stop_details: null`.
#[test]
fn ir02_refusal_stop_details_are_carried() {
    let details = json!({"type": "refusal", "category": "cyber", "explanation": "declined"});
    let mut ir = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_response(&anthropic_response("refusal", details.clone()))
        .unwrap();
    assert_eq!(ir.stop_reason, Some(crate::ir::IrStopReason::Refusal));
    assert_eq!(
        ir.stop_detail,
        Some(crate::ir::IrStopDetail::Refusal {
            category: Some("cyber".into()),
            explanation: Some("declined".into()),
        })
    );
    let out = resp_to_anthropic(&mut ir);
    assert_eq!(out["stop_details"], details, "{out}");

    let data = json!({"type": "message_delta",
        "delta": {"stop_reason": "refusal", "stop_sequence": null, "stop_details": details},
        "usage": {"output_tokens": 1}});
    let ev = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_response_event("message_delta", &data)
        .unwrap();
    let (_, out) = protocol_for("anthropic")
        .unwrap()
        .writer()
        .write_response_event(&ev)
        .unwrap();
    assert_eq!(out.pointer("/delta/stop_details"), Some(&details), "{out}");

    let mut plain = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_response(&anthropic_response("end_turn", Value::Null))
        .unwrap();
    assert_eq!(plain.stop_detail, None);
    assert_eq!(resp_to_anthropic(&mut plain)["stop_details"], Value::Null);
}

// ── IR-11 / ANT-13 ────────────────────────────────────────────────────────────────────────────────

/// ANT-13: web search / web fetch / code execution read into the typed hosted-tool slot (with
/// their parameters), never as a function tool; other server tools stay raw and same-protocol-only.
#[test]
fn ant13_server_tools_read_into_hosted_slot() {
    use crate::ir::IrHostedTool as H;
    let body = with(
        base(),
        "tools",
        json!([
            {"name": "f", "input_schema": {"type": "object"}},
            {"type": "web_search_20260209", "name": "web_search", "max_uses": 3,
             "allowed_domains": ["a.com"],
             "user_location": {"type": "approximate", "city": "Paris", "country": "FR"}},
            {"type": "web_fetch_20250910", "name": "web_fetch", "blocked_domains": ["b.com"]},
            {"type": "code_execution_20250825", "name": "code_execution"},
            {"type": "bash_20250124", "name": "bash"}
        ]),
    );
    let ir = read(&body);
    assert_eq!(
        ir.hosted_tools,
        vec![
            H::WebSearch(crate::ir::IrWebSearch {
                max_uses: Some(3),
                allowed_domains: vec!["a.com".into()],
                blocked_domains: vec![],
                user_location: Some(crate::ir::IrUserLocation {
                    city: Some("Paris".into()),
                    country: Some("FR".into()),
                    ..Default::default()
                }),
                search_context_size: None,
            }),
            H::WebFetch(crate::ir::IrWebFetch {
                max_uses: None,
                allowed_domains: vec![],
                blocked_domains: vec!["b.com".into()],
            }),
            H::CodeExecution,
        ]
    );
    let names: Vec<&str> = ir.tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        ["f", "bash"],
        "only the function + unmodeled server tool stay raw"
    );
    assert!(ir.tools[1].hosted.is_some());
}

/// ANT-13 / IR-11 write side: a hosted tool that crossed the seam (e.g. from Responses or Gemini)
/// reaches Anthropic as its server tool, with its parameters; a field Anthropic lacks is dropped and
/// the tool kept.
#[test]
fn ir11_hosted_tools_are_written_as_anthropic_server_tools() {
    let mut ir = read(&base());
    ir.hosted_tools = vec![
        crate::ir::IrHostedTool::WebSearch(crate::ir::IrWebSearch {
            max_uses: Some(2),
            allowed_domains: vec!["a.com".into()],
            blocked_domains: vec!["b.com".into()],
            user_location: Some(crate::ir::IrUserLocation {
                timezone: Some("Europe/Paris".into()),
                ..Default::default()
            }),
            search_context_size: Some(crate::ir::IrVerbosity::High),
        }),
        crate::ir::IrHostedTool::WebFetch(Default::default()),
        crate::ir::IrHostedTool::CodeExecution,
    ];
    ir.tool_choice = Some(crate::ir::IrToolChoice::Auto);
    let out = egress(ir, &Default::default());
    assert_eq!(
        out["tools"],
        json!([
            {"type": "web_search_20250305", "name": "web_search", "max_uses": 2,
             "allowed_domains": ["a.com"],
             "user_location": {"type": "approximate", "timezone": "Europe/Paris"}},
            {"type": "web_fetch_20250910", "name": "web_fetch"},
            {"type": "code_execution_20250825", "name": "code_execution"}
        ]),
        "{out}"
    );
    // A tool_choice survives: the hosted tools are a real tools array.
    assert_eq!(out["tool_choice"], json!({"type": "auto"}), "{out}");
}

// ── IR-04 / IR-10 / IR-12 / IR-18 / N slots ───────────────────────────────────────────────────────

/// IR-04: `auto` / `standard_only` read and write; a foreign Flex tier has no Anthropic form.
#[test]
fn ir04_service_tier_is_carried() {
    use crate::ir::IrServiceTier as T;
    assert_eq!(
        read(&with(base(), "service_tier", json!("standard_only"))).service_tier,
        Some(T::Default)
    );
    for (tier, want) in [
        (T::Auto, Some("auto")),
        (T::Priority, Some("auto")),
        (T::Default, Some("standard_only")),
        (T::Flex, None),
    ] {
        let mut ir = read(&base());
        ir.service_tier = Some(tier);
        let dropped = protocol_for("anthropic")
            .unwrap()
            .writer()
            .dropped_egress_controls(&ir);
        let out = egress(ir, &Default::default());
        assert_eq!(
            out.get("service_tier").and_then(|v| v.as_str()),
            want,
            "{tier:?}"
        );
        assert_eq!(
            dropped.contains(&"service_tier"),
            want.is_none(),
            "{tier:?}"
        );
    }
}

/// IR-10: a tool subset is expressed by omission — only the listed function tools are sent.
#[test]
fn ir10_allowed_tools_send_only_the_listed_tools() {
    let body = with(
        base(),
        "tools",
        json!([
            {"name": "a", "input_schema": {"type": "object"}},
            {"name": "b", "input_schema": {"type": "object"}}
        ]),
    );
    let mut ir = read(&body);
    ir.allowed_tools = Some(vec!["b".into()]);
    ir.tool_choice = Some(crate::ir::IrToolChoice::Required);
    let out = egress(ir, &Default::default());
    let names: Vec<&str> = out["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["b"], "{out}");
    assert_eq!(out["tool_choice"]["type"], "any", "{out}");
}

/// IR-12: a document's `citations.enabled` and `context` ride the Media slot and are written back.
#[test]
fn ir12_document_citations_and_context_are_carried() {
    let body = with(
        base(),
        "messages",
        json!([{"role": "user", "content": [
            {"type": "text", "text": "read"},
            {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "doc"},
             "context": "a memo", "citations": {"enabled": true}}
        ]}]),
    );
    let ir = read(&body);
    match &ir.messages[0].content[1] {
        crate::ir::IrBlock::Media {
            citations, context, ..
        } => {
            assert_eq!(*citations, Some(true));
            assert_eq!(context.as_deref(), Some("a memo"));
        }
        other => panic!("not a Media block: {other:?}"),
    }
    let out = egress(ir, &Default::default());
    let doc = out.pointer("/messages/0/content/1").unwrap();
    assert_eq!(doc["context"], "a memo", "{out}");
    assert_eq!(doc["citations"], json!({"enabled": true}), "{out}");
}

/// IR-18: an Anthropic-read signature is marked Anthropic; on Anthropic egress a thinking block
/// signed by another vendor is dropped like an unsigned one (Anthropic 400s on it), while an
/// Anthropic-origin one is sent.
#[test]
fn ir18_only_anthropic_signatures_are_sent() {
    let body = with(
        base(),
        "messages",
        json!([
            {"role": "user", "content": [{"type": "text", "text": "q"}]},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "t", "signature": "sig-a"},
                {"type": "text", "text": "a"}
            ]},
            {"role": "user", "content": [{"type": "text", "text": "q2"}]}
        ]),
    );
    let ir = read(&body);
    match &ir.messages[1].content[0] {
        crate::ir::IrBlock::Thinking {
            signature_origin, ..
        } => assert_eq!(
            *signature_origin,
            Some(crate::ir::IrSignatureOrigin::Anthropic)
        ),
        other => panic!("not thinking: {other:?}"),
    }
    let out = egress(ir.clone(), &Default::default());
    assert_eq!(
        out.pointer("/messages/1/content/0/signature"),
        Some(&json!("sig-a")),
        "{out}"
    );
    let mut foreign = ir;
    if let crate::ir::IrBlock::Thinking {
        signature_origin, ..
    } = &mut foreign.messages[1].content[0]
    {
        *signature_origin = Some(crate::ir::IrSignatureOrigin::Gemini);
    }
    let out = egress(foreign, &Default::default());
    assert_eq!(
        out.pointer("/messages/1/content"),
        Some(&json!([{"type": "text", "text": "a"}])),
        "{out}"
    );
}

/// The "N" slots: Anthropic has no member for them, so they are reported as dropped and nothing is
/// written for them.
#[test]
fn n_slots_are_reported_dropped_and_not_written() {
    let mut ir = read(&base());
    ir.metadata = Some(vec![("k".into(), "v".into())]);
    ir.store = Some(true);
    ir.safety_identifier = Some("s".into());
    ir.prompt_cache_key = Some("p".into());
    ir.verbosity = Some(crate::ir::IrVerbosity::Low);
    ir.output_modalities = Some(vec![
        crate::ir::IrModality::Text,
        crate::ir::IrModality::Audio,
    ]);
    let dropped = protocol_for("anthropic")
        .unwrap()
        .writer()
        .dropped_egress_controls(&ir);
    for slot in [
        "metadata",
        "store",
        "safety_identifier",
        "prompt_cache_key",
        "verbosity",
        "output_modalities",
    ] {
        assert!(dropped.contains(&slot), "{slot} not reported: {dropped:?}");
    }
    let out = egress(ir, &Default::default());
    for key in [
        "metadata",
        "store",
        "safety_identifier",
        "prompt_cache_key",
        "verbosity",
        "modalities",
    ] {
        assert!(out.get(key).is_none(), "{key} written: {out}");
    }
}
