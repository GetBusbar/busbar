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
use busbar_kernel::testkit::engine_kit::EngineTestKit as _;
use serde_json::json;

fn http() -> busbar_substrate_values::transport::Transport {
    busbar_substrate_values::transport::Transport::Http
}

/// Cross-protocol OpenAI → Anthropic request carrying `response_format` forwards (Ok, body rebuilt)
/// and — since the owner-reported bug fix — is TRANSLATED to Anthropic tool-forcing rather than
/// dropped, so NO `response_format on anthropic` degraded audit event is recorded (the structured-
/// output directive is honored, not degraded). Contrast the Bedrock path below, which still drops.
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
/// writer vtable's `dropped_egress_controls`): the Anthropic egress now TRANSLATES `response_format`
/// (tool-forcing), so it drops nothing here; the Bedrock egress still drops BOTH `response_format`
/// and `tool_choice=none`.
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
}
