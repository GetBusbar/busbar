// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AUDIT-AND-ALLOW for the two cross-dialect egress controls the target dialect cannot natively
//! represent: `response_format` (dropped on Anthropic AND Bedrock egress) and `tool_choice:none`
//! (`IrToolChoice::None`, "do NOT call a tool" — dropped on Bedrock egress). Forwarding behaviour is
//! UNCHANGED (the request still translates and forwards a 200); the fix is that each drop now emits a
//! FIRST-CLASS, hash-chained audit event (`egress.control_unrepresentable`, outcome `degraded`)
//! rather than only a `tracing::warn!` invisible to the audit trail.

use super::translate_request_cross_protocol;
use crate::test_support::{LaneSpec, TestApp};
use busbar_kernel::test_support::engine_kit::EngineTestKit as _;
use serde_json::json;

fn http() -> busbar_substrate_values::transport::Transport {
    busbar_substrate_values::transport::Transport::Http
}

/// Cross-protocol OpenAI → Anthropic request carrying `response_format` to a lane that declares NO
/// native structured outputs (the default — `LaneCaps::native_structured_output` false) forwards
/// (Ok, body rebuilt) TRANSLATED to Anthropic tool-forcing rather than dropped, so NO
/// `response_format on anthropic` degraded audit event is recorded. The lane that DOES declare the
/// capability is `native_structured_output_lane_drops_schema_less_json_with_audit` below.
#[test]
fn openai_to_anthropic_response_format_forwards_and_translates_not_dropped() {
    crate::testkit::install_test_seams();
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "claude-3-5-sonnet",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "response_format": {"type": "json_object"}
    });
    let hop_bytes = bytes::Bytes::from(busbar_substrate_values::json::to_vec(&body).unwrap());
    // Unique principal so the assertion below reads THIS test's event out of the shared audit ring
    // without racing other tests that append to the same global log.
    let caller = "test-key-anthropic-respfmt";
    let (host, rt) = crate::engine::test_host_rt(&app);
    let out = translate_request_cross_protocol(
        &host,
        &rt,
        0,
        "openai",
        busbar_substrate_values::handlers::chat("openai", http()),
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        caller,
    );
    let bytes = out.expect("translate-and-allow: a translated response_format must forward");
    assert!(
        !bytes.is_empty(),
        "the request body must still be rebuilt and forwarded"
    );
    // The rebuilt Anthropic body must carry the tool-forcing translation, not a bare response_format.
    let rebuilt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        rebuilt.get("response_format").is_none(),
        "Anthropic egress must not carry a bare response_format; got {rebuilt}"
    );
    assert_eq!(
        rebuilt.pointer("/tool_choice/name"),
        Some(&json!("busbar_response_format")),
        "response_format must be translated to forced tool-use; got {rebuilt}"
    );
    // And NO `response_format on anthropic` degraded event may be recorded — it is honored, not dropped.
    let entries = crate::test_support::engine_kit::CORE_ENGINE_KIT.audit_entries();
    let dropped = entries.iter().any(|e| {
        e.principal == caller
            && e.action == "egress.control_unrepresentable"
            && e.resource == "response_format on anthropic"
    });
    assert!(
        !dropped,
        "response_format is now translated on Anthropic; no `degraded` drop event must be recorded"
    );
}

/// Cross-protocol OpenAI → Bedrock request carrying `tool_choice:"none"` STILL forwards (the backend
/// may still call a tool — behaviour unchanged), and a `degraded` audit event is recorded.
#[test]
fn openai_to_bedrock_tool_choice_none_forwards_and_audits_degraded() {
    crate::testkit::install_test_seams();
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "anthropic.claude-3-5-sonnet",
            crate::proto_codec::PROTO_BEDROCK,
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{
            "type": "function",
            "function": {"name": "get_weather", "parameters": {"type": "object"}}
        }],
        "tool_choice": "none"
    });
    let hop_bytes = bytes::Bytes::from(busbar_substrate_values::json::to_vec(&body).unwrap());
    let caller = "test-key-bedrock-toolnone";
    let (host, rt) = crate::engine::test_host_rt(&app);
    let out = translate_request_cross_protocol(
        &host,
        &rt,
        0,
        "openai",
        busbar_substrate_values::handlers::chat("openai", http()),
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        caller,
    );
    let bytes =
        out.expect("audit-and-allow: a dropped tool_choice=none must still forward, not reject");
    assert!(
        !bytes.is_empty(),
        "the request body must still be forwarded"
    );
    let entries = crate::test_support::engine_kit::CORE_ENGINE_KIT.audit_entries();
    let hit = entries
        .iter()
        .find(|e| {
            e.principal == caller
                && e.action == "egress.control_unrepresentable"
                && e.outcome == "degraded"
        })
        .expect("a first-class `degraded` audit event must be recorded for the drop");
    assert_eq!(hit.resource, "tool_choice=none on bedrock");
}

/// Direct unit test of the handler/Op seam (`OpDispatch::egress_dropped_controls`, forwarding the
/// writer vtable's `dropped_egress_controls_for_lane`): an Anthropic lane with the default
/// capabilities TRANSLATES `response_format` (tool-forcing), so it drops nothing here, while a lane
/// declaring native structured outputs drops the schema-less `json_object`; the Bedrock egress still
/// drops BOTH `response_format` and `tool_choice=none`.
#[test]
fn egress_dropped_controls_reports_the_right_controls_per_dialect() {
    crate::testkit::install_test_seams();
    let ingress = busbar_substrate_values::handlers::chat("openai", http());
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{
            "type": "function",
            "function": {"name": "get_weather", "parameters": {"type": "object"}}
        }],
        "response_format": {"type": "json_object"},
        "tool_choice": "none"
    });
    let ir = ingress
        .op_handler
        .read_request_value(&body)
        .expect("openai body must parse to IR");

    // The dropped-controls audit inverted onto the handle at the G6 A4b dissolve: `ir` is the chat
    // `Box<dyn IrHandle>` and answers per egress protocol string.
    // Anthropic: response_format is TRANSLATED to tool-forcing (owner-reported bug fix), not
    // dropped — and Anthropic natively models every other control here, so it drops nothing.
    assert!(ir.egress_dropped_controls("anthropic").is_empty());
    // Bedrock: neither response_format nor tool_choice=none has a native representation.
    assert_eq!(
        ir.egress_dropped_controls("bedrock"),
        vec!["response_format", "tool_choice=none"],
    );
    // OpenAI egress (same-dialect writer) drops neither — the default empty vec.
    assert!(ir.egress_dropped_controls("openai").is_empty());

    // The same request prepared for a lane that declares native structured outputs: a schema-less
    // JSON mode has no native form there, so Anthropic reports it dropped.
    let mut native = ingress
        .op_handler
        .read_request_value(&body)
        .expect("openai body must parse to IR");
    native.prepare_for_egress(&prep_for(
        busbar_substrate_values::ir::egress_prep::LaneCaps {
            native_structured_output: true,
            ..Default::default()
        },
    ));
    assert_eq!(
        native.egress_dropped_controls("anthropic"),
        vec!["response_format"]
    );
}

fn prep_for(
    lane_caps: busbar_substrate_values::ir::egress_prep::LaneCaps,
) -> busbar_substrate_values::ir::egress_prep::EgressPrep<'static> {
    busbar_substrate_values::ir::egress_prep::EgressPrep {
        ingress_protocol: "openai",
        egress_requires_max_tokens: true,
        lane_default_max_tokens: None,
        global_default_max_tokens: 4096,
        reasoning_allowed: true,
        reasoning_budgets: [1024, 4096, 8192, 16384],
        prompt_caching_allowed: true,
        cache_control_cap: None,
        thought_signature_fill: false,
        lane_caps,
    }
}

/// Run one cross-protocol OpenAI → `protocol` request through the ENGINE seam onto a lane declaring
/// `caps`; the rebuilt upstream body, and the caller id the audit ring is keyed by.
fn translate_onto(
    caller: &str,
    model: &str,
    protocol: &'static str,
    caps: busbar_substrate_values::ir::egress_prep::LaneCaps,
    body: serde_json::Value,
) -> serde_json::Value {
    crate::testkit::install_test_seams();
    let app = TestApp::new()
        .lane(LaneSpec::new(model, protocol, "http://unused.local").lane_caps(caps))
        .build();
    let hop_bytes = bytes::Bytes::from(busbar_substrate_values::json::to_vec(&body).unwrap());
    let (host, rt) = crate::engine::test_host_rt(&app);
    let out = translate_request_cross_protocol(
        &host,
        &rt,
        0,
        "openai",
        busbar_substrate_values::handlers::chat("openai", http()),
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        caller,
    )
    .expect("the request forwards");
    serde_json::from_slice(&out).unwrap()
}

/// ANT-07 on a lane that DECLARES native structured outputs: a schema-carrying directive rides
/// `output_config.format` (no forced tool), and a schema-less `json_object` — which has no native
/// form — is dropped AND audited as `response_format on anthropic`.
#[test]
fn native_structured_output_lane_drops_schema_less_json_with_audit() {
    let native = busbar_substrate_values::ir::egress_prep::LaneCaps {
        native_structured_output: true,
        ..Default::default()
    };
    let schema = json!({"type": "object", "properties": {"a": {"type": "string"}}});
    let with_schema = translate_onto(
        "test-key-anthropic-native-schema",
        "claude-opus-5",
        crate::proto_codec::PROTO_ANTHROPIC,
        native,
        json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}],
               "response_format": {"type": "json_schema", "json_schema": {"name": "o", "schema": schema}}}),
    );
    assert_eq!(
        with_schema.pointer("/output_config/format/type"),
        Some(&json!("json_schema")),
        "{with_schema}"
    );
    assert!(with_schema.get("tool_choice").is_none(), "{with_schema}");

    let caller = "test-key-anthropic-native-object";
    let object_mode = translate_onto(
        caller,
        "claude-opus-5",
        crate::proto_codec::PROTO_ANTHROPIC,
        native,
        json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}],
               "response_format": {"type": "json_object"}}),
    );
    assert!(object_mode.get("output_config").is_none(), "{object_mode}");
    assert!(object_mode.get("tools").is_none(), "{object_mode}");
    let entries = crate::test_support::engine_kit::CORE_ENGINE_KIT.audit_entries();
    assert!(
        entries.iter().any(|e| e.principal == caller
            && e.action == "egress.control_unrepresentable"
            && e.resource == "response_format on anthropic"),
        "the schema-less drop must be audited on a native lane"
    );
}

/// ANT-10 through the engine seam: a word-form reasoning ask reaches an adaptive-thinking lane as
/// `thinking:{type:"adaptive"}` + `output_config.effort`, and a default lane as `budget_tokens`.
#[test]
fn adaptive_thinking_is_a_lane_capability() {
    let body = json!({"model": "gpt-5", "messages": [{"role": "user", "content": "hi"}],
                      "max_tokens": 32000, "reasoning_effort": "high"});
    let adaptive = translate_onto(
        "test-key-anthropic-adaptive-on",
        "claude-opus-5",
        crate::proto_codec::PROTO_ANTHROPIC,
        busbar_substrate_values::ir::egress_prep::LaneCaps {
            anthropic_adaptive_thinking: true,
            ..Default::default()
        },
        body.clone(),
    );
    assert_eq!(
        adaptive["thinking"],
        json!({"type": "adaptive"}),
        "{adaptive}"
    );
    assert_eq!(
        adaptive.pointer("/output_config/effort"),
        Some(&json!("high"))
    );
    let budget = translate_onto(
        "test-key-anthropic-adaptive-off",
        "claude-sonnet-4-5",
        crate::proto_codec::PROTO_ANTHROPIC,
        Default::default(),
        body,
    );
    assert_eq!(budget["thinking"]["type"], json!("enabled"), "{budget}");
    assert!(budget["thinking"]["budget_tokens"].is_u64(), "{budget}");
    assert!(budget.get("output_config").is_none(), "{budget}");
}

/// OAI-01 through the engine seam: a cross-protocol cap reaches a lane declaring
/// `max_output_key: max_completion_tokens` (the catalog's `openai` entry) under that key, and any
/// other OpenAI-protocol lane (an OpenAI-compatible host) under `max_tokens`.
#[test]
fn max_output_key_is_a_lane_capability() {
    use busbar_substrate_values::ir::egress_prep::{LaneCaps, MaxOutputKey};
    let completion = LaneCaps {
        max_output_key: MaxOutputKey::MaxCompletionTokens,
        ..Default::default()
    };
    let anthropic_body = |max: u32| {
        json!({"model": "claude-x", "max_tokens": max,
               "messages": [{"role": "user", "content": "hi"}]})
    };
    for (caller, caps, key, other) in [
        (
            "test-key-oai-mct-on",
            completion,
            "max_completion_tokens",
            "max_tokens",
        ),
        (
            "test-key-oai-mct-off",
            LaneCaps::default(),
            "max_tokens",
            "max_completion_tokens",
        ),
    ] {
        let out = translate_anthropic_onto_openai(caller, caps, anthropic_body(77));
        assert_eq!(out[key], json!(77), "{out}");
        assert!(out.get(other).is_none(), "{out}");
    }
}

fn translate_anthropic_onto_openai(
    caller: &str,
    caps: busbar_substrate_values::ir::egress_prep::LaneCaps,
    body: serde_json::Value,
) -> serde_json::Value {
    crate::testkit::install_test_seams();
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gpt-5",
                crate::proto_codec::PROTO_OPENAI,
                "http://unused.local",
            )
            .lane_caps(caps),
        )
        .build();
    let hop_bytes = bytes::Bytes::from(busbar_substrate_values::json::to_vec(&body).unwrap());
    let (host, rt) = crate::engine::test_host_rt(&app);
    let out = translate_request_cross_protocol(
        &host,
        &rt,
        0,
        "anthropic",
        busbar_substrate_values::handlers::chat("anthropic", http()),
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        caller,
    )
    .expect("the request forwards");
    serde_json::from_slice(&out).unwrap()
}
