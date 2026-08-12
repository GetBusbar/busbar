// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `(mcp, ToolCall)` cell's tests. The contract a codec cell is held to is the one its own
//! trait doc states — "feed it wire, assert the IR; feed it IR, assert the wire" — so these are
//! round-trip and refusal tests, and nothing else.

use super::*;

fn call_wire(params: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params
    }))
    .expect("fixture")
}

#[test]
fn a_tools_call_reads_into_the_tool_call_ir() {
    let wire = call_wire(serde_json::json!({
        "name": "fs_read", "arguments": { "path": "/etc/hosts" }
    }));
    let ir = ToolCallOperation
        .read_request(&wire, crate::proxy::APPLICATION_JSON)
        .expect("a well-formed tools/call reads");
    let IrReq::ToolCall(r) = ir else {
        panic!("a tools/call is a ToolCall")
    };
    assert_eq!(r.tool, "fs_read");
    assert_eq!(r.arguments["path"], "/etc/hosts");
}

/// A TOOL THAT TAKES NO ARGUMENTS IS STILL CALLABLE. Absent `arguments` is an empty object, not a
/// refusal — rejecting it would refuse a legal call.
#[test]
fn absent_arguments_are_an_empty_object_not_a_refusal() {
    let wire = call_wire(serde_json::json!({ "name": "ping" }));
    let ir = ToolCallOperation
        .read_request(&wire, crate::proxy::APPLICATION_JSON)
        .expect("a tool with no arguments is a legal call");
    let IrReq::ToolCall(r) = ir else {
        panic!("a tools/call is a ToolCall")
    };
    assert_eq!(r.arguments, serde_json::json!({}));
}

#[test]
fn a_call_that_names_no_tool_is_refused() {
    let wire = call_wire(serde_json::json!({ "arguments": {} }));
    assert!(
        ToolCallOperation
            .read_request(&wire, crate::proxy::APPLICATION_JSON)
            .is_err(),
        "a tools/call with no `params.name` names no tool, so there is nothing to dispatch"
    );
}

/// THE TWO ERROR CHANNELS STAY SEPARATE, and this is the assertion that pins it.
///
/// A tool that RAN and FAILED is a successful exchange carrying `isError: true`. It must survive
/// the codec as a RESULT, because rendering it as a protocol error would tell the caller their
/// request was malformed when their tool merely returned an error — and would make an upstream
/// failure indistinguishable from a policy refusal to anything reading dispositions.
#[test]
fn a_failed_tool_is_a_result_not_a_protocol_error() {
    let wire = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "result": { "content": [{ "type": "text", "text": "no such file" }], "isError": true }
    }))
    .expect("fixture");
    let ir = ToolCallOperation
        .read_response(&wire)
        .expect("a tool error is a well-formed response");
    let IrResp::ToolCall(r) = ir else {
        panic!("a tools/call answer is a ToolCall")
    };
    assert!(r.is_error, "the tool's own verdict survives");
    assert_eq!(r.content[0]["text"], "no such file");
}

#[test]
fn the_request_round_trips_through_the_codec() {
    let wire = call_wire(serde_json::json!({
        "name": "search", "arguments": { "q": "busbar" }
    }));
    let ir = ToolCallOperation
        .read_request(&wire, crate::proxy::APPLICATION_JSON)
        .expect("reads");
    let out: serde_json::Value =
        serde_json::from_slice(&ToolCallOperation.write_request(&ir)).expect("writes JSON");
    assert_eq!(out["jsonrpc"], "2.0");
    assert_eq!(out["method"], "tools/call");
    assert_eq!(out["params"]["name"], "search");
    assert_eq!(out["params"]["arguments"]["q"], "busbar");
    assert!(
        out.get("id").is_none(),
        "THE CALLER'S ID DOES NOT TRAVEL. Correlation is decided on the way out and read back by \
         `ingress::jsonrpc::read_response`; echoing the caller's id would let a backend's reply to \
         one conversation be served as another's."
    );
}

#[test]
fn the_response_round_trips_through_the_codec() {
    let ir = IrResp::ToolCall(ToolCallResp {
        content: serde_json::json!([{ "type": "text", "text": "ok" }]),
        is_error: false,
        structured: Some(serde_json::json!({ "rows": 2 })),
        extra: Default::default(),
    });
    let out: serde_json::Value =
        serde_json::from_slice(&ToolCallOperation.write_response(&ir).bytes).expect("writes JSON");
    assert_eq!(out["result"]["content"][0]["text"], "ok");
    assert_eq!(out["result"]["isError"], false);
    assert_eq!(out["result"]["structuredContent"]["rows"], 2);
}

/// Structured content is CARRIED, never synthesised: busbar models no output schema, so a tool that
/// returned none must not be given one.
#[test]
fn structured_content_is_omitted_when_the_tool_produced_none() {
    let ir = IrResp::ToolCall(ToolCallResp {
        content: serde_json::json!([]),
        is_error: false,
        structured: None,
        extra: Default::default(),
    });
    let out: serde_json::Value =
        serde_json::from_slice(&ToolCallOperation.write_response(&ir).bytes).expect("writes JSON");
    assert!(out["result"].get("structuredContent").is_none());
}

// ── THE MATRIX DECLARATIONS ──────────────────────────────────────────────────────────────────────

/// MCP SERVES `ToolCall` AND NOTHING ELSE — which is the "no MCP to Chat" rule, enforced by the
/// absence of a cell rather than by a runtime check. There is no handler to translate a tool call
/// into a chat completion through, so the pair is unrepresentable.
#[test]
fn mcp_serves_tool_call_and_refuses_every_other_operation() {
    let h = McpRequestHandler;
    assert!(h.operation_handler(Operation::ToolCall).is_some());
    for op in [
        Operation::Chat,
        Operation::Embeddings,
        Operation::Moderation,
        Operation::Image,
        Operation::Transcription,
        Operation::Speech,
        Operation::Rerank,
    ] {
        assert!(
            h.operation_handler(op).is_none(),
            "MCP must serve no operation but ToolCall; {} has no cell and must not acquire one by \
             accident",
            op.name()
        );
    }
}

/// THE OPERATION IS IN THE BODY, not the path — the opposite of OpenAI, and the reason this
/// handler is one of the few that reads the body to resolve.
#[test]
fn the_operation_is_resolved_from_the_body_method() {
    let h = McpRequestHandler;
    let body = call_wire(serde_json::json!({ "name": "t" }));
    assert_eq!(
        h.resolve_operation("/mcp", &body),
        Some(Operation::ToolCall)
    );
    assert_eq!(
        h.resolve_operation("/v1/chat/completions", &body),
        None,
        "the path still has to be this protocol's mount"
    );
    let other = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list"
    }))
    .expect("fixture");
    assert_eq!(
        h.resolve_operation("/mcp", &other),
        None,
        "a method busbar serves no operation for is a no-handler 404, not a guess"
    );
    assert_eq!(
        h.resolve_operation("/mcp", b"not json"),
        None,
        "an unparseable body names no operation"
    );
}
