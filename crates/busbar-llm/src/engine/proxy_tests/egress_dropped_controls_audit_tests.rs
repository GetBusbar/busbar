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
use serde_json::json;

fn http() -> crate::transport::Transport {
    crate::transport::Transport::Http
}

/// Cross-protocol OpenAI → Anthropic request carrying `response_format` STILL forwards (Ok, body
/// rebuilt), and a `degraded` audit event naming the dropped control on the egress dialect is
/// recorded under the caller's key id.
#[test]
fn openai_to_anthropic_response_format_forwards_and_audits_degraded() {
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "claude-3-5-sonnet",
            crate::proto::PROTO_ANTHROPIC,
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "response_format": {"type": "json_object"}
    });
    let hop_bytes = bytes::Bytes::from(crate::json::to_vec(&body).unwrap());
    // Unique principal so the assertion below reads THIS test's event out of the shared audit ring
    // without racing other tests that append to the same global log.
    let caller = "test-key-anthropic-respfmt";
    let out = translate_request_cross_protocol(
        &app,
        0,
        "openai",
        crate::handlers::chat("openai", http()),
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
        caller,
    );
    let bytes =
        out.expect("audit-and-allow: a dropped response_format must still forward, not reject");
    assert!(
        !bytes.is_empty(),
        "the request body must still be rebuilt and forwarded"
    );
    let entries = crate::admin::audit::AUDIT.export();
    let hit = entries.iter().find(|e| {
        e.principal == caller
            && e.action == "egress.control_unrepresentable"
            && e.outcome == "degraded"
    });
    let hit = hit.expect("a first-class `degraded` audit event must be recorded for the drop");
    assert_eq!(
        hit.resource, "response_format on anthropic",
        "the audit resource must name the dropped control and the egress dialect"
    );
}

/// Cross-protocol OpenAI → Bedrock request carrying `tool_choice:"none"` STILL forwards (the backend
/// may still call a tool — behaviour unchanged), and a `degraded` audit event is recorded.
#[test]
fn openai_to_bedrock_tool_choice_none_forwards_and_audits_degraded() {
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "anthropic.claude-3-5-sonnet",
            crate::proto::PROTO_BEDROCK,
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
    let hop_bytes = bytes::Bytes::from(crate::json::to_vec(&body).unwrap());
    let caller = "test-key-bedrock-toolnone";
    let out = translate_request_cross_protocol(
        &app,
        0,
        "openai",
        crate::handlers::chat("openai", http()),
        Some(body),
        crate::proxy::APPLICATION_JSON,
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
    let entries = crate::admin::audit::AUDIT.export();
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
/// writer vtable's `dropped_egress_controls`): the Anthropic egress drops `response_format`, and the
/// Bedrock egress drops BOTH `response_format` and `tool_choice=none`.
#[test]
fn egress_dropped_controls_reports_the_right_controls_per_dialect() {
    let ingress = crate::handlers::chat("openai", http());
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
    // Anthropic: only response_format has no native representation.
    assert_eq!(
        ir.egress_dropped_controls("anthropic"),
        vec!["response_format"],
    );
    // Bedrock: neither response_format nor tool_choice=none has a native representation.
    assert_eq!(
        ir.egress_dropped_controls("bedrock"),
        vec!["response_format", "tool_choice=none"],
    );
    // OpenAI egress (same-dialect writer) drops neither — the default empty vec.
    assert!(ir.egress_dropped_controls("openai").is_empty());
}
