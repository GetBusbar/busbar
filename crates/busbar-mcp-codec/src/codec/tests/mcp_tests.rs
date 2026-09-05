// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MCP cells' tests. The contract a codec cell is held to is the one its own trait doc states —
//! "feed it wire, assert the IR; feed it IR, assert the wire" — so these are round-trip and refusal
//! tests, and nothing else. The notification tests are the same contract for a message that has no
//! answer: write it, read it back, and assert it is what it was.

use super::handler::McpRequestHandler;
use super::invoke::InvokeOperation;
use super::*;
use busbar_api::operation::Operation;
use busbar_substrate_values::handlers::{OperationHandler, RequestHandler};
use busbar_substrate_values::ir::invoke::InvokeResp;
use busbar_substrate_values::ir::subscribe::SubscribeIntent;

fn call_wire(params: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params
    }))
    .expect("fixture")
}

#[test]
fn a_tools_call_reads_into_the_invoke_ir() {
    let wire = call_wire(serde_json::json!({
        "name": "fs_read", "arguments": { "path": "/etc/hosts" }
    }));
    let ir = super::invoke::read_invoke_request(&wire).expect("a well-formed tools/call reads");
    let r = ir;
    assert_eq!(r.tool, "fs_read");
    assert_eq!(r.arguments["path"], "/etc/hosts");
}

/// A TOOL THAT TAKES NO ARGUMENTS IS STILL CALLABLE. Absent `arguments` is an empty object, not a
/// refusal — rejecting it would refuse a legal call.
#[test]
fn absent_arguments_are_an_empty_object_not_a_refusal() {
    let wire = call_wire(serde_json::json!({ "name": "ping" }));
    let ir = super::invoke::read_invoke_request(&wire)
        .expect("a tool with no arguments is a legal call");
    let r = ir;
    assert_eq!(r.arguments, serde_json::json!({}));
}

#[test]
fn a_call_that_names_no_tool_is_refused() {
    let wire = call_wire(serde_json::json!({ "arguments": {} }));
    assert!(
        super::invoke::read_invoke_request(&wire).is_err(),
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
    let ir =
        super::invoke::read_invoke_response(&wire).expect("a tool error is a well-formed response");
    let r = ir;
    assert!(r.is_error, "the tool's own verdict survives");
    assert_eq!(r.content[0]["text"], "no such file");
}

#[test]
fn the_request_round_trips_through_the_codec() {
    let wire = call_wire(serde_json::json!({
        "name": "search", "arguments": { "q": "busbar" }
    }));
    let ir = super::invoke::read_invoke_request(&wire).expect("reads");
    let out: serde_json::Value =
        serde_json::from_slice(&super::invoke::invoke_write_request(&ir)).expect("writes JSON");
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
    let ir = InvokeResp {
        content: serde_json::json!([{ "type": "text", "text": "ok" }]),
        is_error: false,
        structured: Some(serde_json::json!({ "rows": 2 })),
        extra: Default::default(),
    };
    let out: serde_json::Value =
        serde_json::from_slice(&super::invoke::invoke_write_response(&ir).bytes)
            .expect("writes JSON");
    assert_eq!(out["result"]["content"][0]["text"], "ok");
    assert_eq!(out["result"]["isError"], false);
    assert_eq!(out["result"]["structuredContent"]["rows"], 2);
}

/// Structured content is CARRIED, never synthesised: busbar models no output schema, so a tool that
/// returned none must not be given one.
#[test]
fn structured_content_is_omitted_when_the_tool_produced_none() {
    let ir = InvokeResp {
        content: serde_json::json!([]),
        is_error: false,
        structured: None,
        extra: Default::default(),
    };
    let out: serde_json::Value =
        serde_json::from_slice(&super::invoke::invoke_write_response(&ir).bytes)
            .expect("writes JSON");
    assert!(out["result"].get("structuredContent").is_none());
}

// ── THE MATRIX DECLARATIONS ──────────────────────────────────────────────────────────────────────

/// MCP SERVES `Invoke` AND `Subscribe` TODAY — and the "no MCP to Chat" rule is enforced by the
/// absence of a cell rather than by a runtime check. There is no handler to translate an invocation
/// into a chat completion through, so the pair is unrepresentable.
///
/// The seven LLM operations are a permanent NO. `Catalogue`/`Fetch`/`Task`/`Control` are a NOT-YET —
/// MCP does speak all four — and they are asserted here for the same reason: until the cell exists,
/// the handler must not report one, and this test is what would catch a cell appearing without its
/// own conformance evidence.
#[test]
fn mcp_serves_invoke_and_subscribe_and_refuses_every_other_operation() {
    let h = McpRequestHandler;
    assert!(h.operation_handler(Operation::INVOKE).is_some());
    assert!(h.operation_handler(Operation::SUBSCRIBE).is_some());
    for op in [
        Operation::CHAT,
        Operation::EMBEDDINGS,
        Operation::MODERATION,
        Operation::IMAGE,
        Operation::TRANSCRIPTION,
        Operation::SPEECH,
        Operation::RERANK,
        Operation::CATALOGUE,
        Operation::FETCH,
        Operation::TASK,
        Operation::CONTROL,
    ] {
        assert!(
            h.operation_handler(op).is_none(),
            "MCP must serve no operation but Invoke and Subscribe; {} has no cell and must not \
             acquire one by accident",
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
    assert_eq!(h.resolve_operation("/mcp", &body), Some(Operation::INVOKE));
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

// ── THE ATTRIBUTED OUTCOME NOW SPANS OPERATIONS ──────────────────────────────────────────────────

/// A NON-CHAT OPERATION GETS AN ATTRIBUTED FAILURE, which was structurally impossible before.
///
/// `extract_error` used to live only on `proto::ProtocolReader` — a trait whose `read_request`
/// returns `IrRequest` and whose `read_response` returns `IrResponse`, i.e. the CHAT subclass
/// types. It is the chat codec, so anything hung off it was available to chat protocols alone.
/// That, and not an oversight, is why the breaker never spanned the tool and agent paths: a
/// non-chat protocol could not implement the trait that carried the capability.
///
/// Now it is on the operation codec, so a failing tool server produces something the breaker can
/// classify instead of the silence that made a non-2xx invisible on a plane built outside the
/// matrix.
#[test]
fn a_failing_tool_server_produces_a_classifiable_outcome() {
    let raw = InvokeOperation.extract_error(503, br#"{"error":"upstream is down"}"#);
    assert_eq!(
        raw.http_status, 503,
        "the status is what the breaker classifies, and it must survive"
    );
    assert!(
        raw.provider_code.is_none() && raw.structured_type.is_none(),
        "and a cell that cannot read its upstream's error vocabulary must claim none, rather than \
         invent one it could not have parsed"
    );
    assert!(
        raw.retry_after_secs.is_none(),
        "this sees only the body; the forwarding layer holds the headers and fills this in after"
    );
}

// ── THE SUBSCRIPTION CELL ────────────────────────────────────────────────────────────────────────

fn subscription_wire(method: &str, params: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 7, "method": method, "params": params
    }))
    .expect("fixture")
}

/// A CALLER CAN ASK TO BE TOLD WHEN A NAMED THING CHANGES, and can ask to stop. Both are the same
/// operation, and the direction the registration moves survives the codec.
#[test]
fn both_subscription_verbs_read_into_one_operation_with_their_intent_intact() {
    for (method, want) in [
        ("resources/subscribe", SubscribeIntent::Register),
        ("resources/unsubscribe", SubscribeIntent::Deregister),
    ] {
        let wire = subscription_wire(method, serde_json::json!({ "uri": "file:///log.txt" }));
        let ir = super::subscribe::read_subscribe_request(&wire)
            .expect("a well-formed subscription request reads");
        let r = ir;
        assert_eq!(r.intent, want);
        assert_eq!(r.target, "file:///log.txt");
    }
}

/// THE TWO VERBS ARE ONE OPERATION AS FAR AS ROUTING IS CONCERNED. The engine must never learn that
/// there were two method names; the intent is the codec's business.
#[test]
fn the_subscription_verbs_resolve_to_the_subscription_operation() {
    let h = McpRequestHandler;
    for method in ["resources/subscribe", "resources/unsubscribe"] {
        let body = subscription_wire(method, serde_json::json!({ "uri": "u" }));
        assert_eq!(
            h.resolve_operation("/mcp", &body),
            Some(Operation::SUBSCRIBE),
            "{method} names the subscription operation"
        );
    }
}

/// A REQUEST THAT NAMES NOTHING IS REFUSED. A subscription to the empty string is not a narrower
/// subscription; it is one nothing downstream could judge or deliver.
#[test]
fn a_subscription_that_names_no_target_is_refused() {
    for params in [
        serde_json::json!({}),
        serde_json::json!({ "uri": "" }),
        serde_json::json!({ "uri": 3 }),
    ] {
        assert!(
            super::subscribe::read_subscribe_request(&subscription_wire(
                "resources/subscribe",
                params.clone()
            ))
            .is_err(),
            "a subscription request whose params are {params} names no target"
        );
    }
}

#[test]
fn the_subscription_request_round_trips_through_the_codec() {
    let wire = subscription_wire(
        "resources/unsubscribe",
        serde_json::json!({ "uri": "file:///a" }),
    );
    let ir = super::subscribe::read_subscribe_request(&wire).expect("reads");
    let out: serde_json::Value =
        serde_json::from_slice(&super::subscribe::subscribe_write_request(&ir))
            .expect("writes JSON");
    assert_eq!(out["jsonrpc"], "2.0");
    assert_eq!(
        out["method"], "resources/unsubscribe",
        "the direction the registration moves is carried by the method name, so it must survive"
    );
    assert_eq!(out["params"]["uri"], "file:///a");
    assert!(
        out.get("id").is_none(),
        "THE CALLER'S ID DOES NOT TRAVEL, for the same reason it does not on an invocation: \
         correlation is decided on the way out and read back when the answer arrives."
    );
}

/// THE ACKNOWLEDGEMENT IS THE CONTENT. An empty result is a successful registration, not a missing
/// one, and it must not be mistaken for a peer that returned a record.
#[test]
fn an_empty_result_is_an_acknowledgement_and_not_a_registration_record() {
    let wire = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 7, "result": {}
    }))
    .expect("fixture");
    let ir = super::subscribe::read_subscribe_response(&wire).expect("reads");
    let r = ir;
    assert_eq!(r.registration, None);
    let out: serde_json::Value =
        serde_json::from_slice(&super::subscribe::subscribe_write_response(&r).bytes)
            .expect("writes JSON");
    assert_eq!(
        out["result"],
        serde_json::json!({}),
        "and it is written back as the empty result the protocol asks for, never as null"
    );
}

/// A PEER THAT DOES RETURN A REGISTRATION RECORD HAS IT CARRIED, NOT DISCARDED. The record is the
/// peer's; busbar neither invents one nor drops one.
#[test]
fn a_registration_record_is_carried_through_untouched() {
    let wire = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 7, "result": { "id": "sub-1", "uri": "file:///a" }
    }))
    .expect("fixture");
    let ir = super::subscribe::read_subscribe_response(&wire).expect("reads");
    let r = ir;
    assert_eq!(r.registration.as_ref().expect("carried")["id"], "sub-1");
    let out: serde_json::Value =
        serde_json::from_slice(&super::subscribe::subscribe_write_response(&r).bytes)
            .expect("writes JSON");
    assert_eq!(out["result"]["uri"], "file:///a");
}

/// A REGISTRATION IS METERED. Not because a model ran — none did — but because a call nothing charges
/// for is a call a caller can make without limit, and the budget tree is the only thing that would
/// otherwise see it.
#[test]
fn a_subscription_is_flat_metered_rather_than_free() {
    let ir = busbar_substrate_values::ir::subscribe::SubscribeResp {
        registration: None,
        extra: Default::default(),
    };
    assert!(
        matches!(
            busbar_substrate_values::ir::handle::IrHandle::billing(
                &busbar_substrate_values::ir::neutral_handles::SubscribeRespHandle(ir)
            ),
            Some(busbar_substrate_values::billing::Billing::Flat)
        ),
        "a registration bills one unit, so it lands on the same budget tree as every other call"
    );
}

// ── THE NOTIFICATION VOCABULARY ──────────────────────────────────────────────────────────────────

/// THE MESSAGE THAT MAKES A SUBSCRIPTION WORTH HAVING, and its sibling that says a tool list moved.
/// One reader and one writer for both directions of travel: busbar emits these when it is the server
/// and receives them when it is the client, and a second implementation per direction is how two
/// readings of one message come to disagree.
#[test]
fn the_notifications_round_trip_and_carry_no_id() {
    for n in [
        McpNotification::ToolsListChanged,
        McpNotification::ResourceUpdated {
            uri: "file:///log.txt".to_string(),
        },
    ] {
        let out: serde_json::Value = serde_json::from_slice(&n.write()).expect("writes JSON");
        assert_eq!(out["jsonrpc"], "2.0");
        assert_eq!(out["method"], n.method());
        assert!(
            out.get("id").is_none(),
            "a notification has no id: an id would make it a request, and a request obliges an \
             answer nobody is waiting for"
        );
        let back = McpNotification::read(
            out["method"].as_str().expect("a method name"),
            out.get("params"),
        );
        assert_eq!(back.as_ref(), Some(&n), "and it reads back as what it was");
    }
}

#[test]
fn the_tools_list_changed_notification_carries_no_params_at_all() {
    let out: serde_json::Value =
        serde_json::from_slice(&McpNotification::ToolsListChanged.write()).expect("writes JSON");
    assert_eq!(out["method"], "notifications/tools/list_changed");
    assert!(
        out.get("params").is_none(),
        "this message has no parameters, so emitting an empty object would be inventing a member"
    );
}

/// AN UPDATE THAT NAMES NO RESOURCE IS NOT AN UPDATE. Acting on it would mean guessing which of a
/// caller's subscriptions it was about.
#[test]
fn a_resource_update_that_names_no_resource_is_not_read() {
    assert_eq!(
        McpNotification::read("notifications/resources/updated", None),
        None
    );
    assert_eq!(
        McpNotification::read(
            "notifications/resources/updated",
            Some(&serde_json::json!({ "uri": "" }))
        ),
        None
    );
}

/// A NOTIFICATION THIS PROTOCOL DOES NOT CARRY IS DROPPED, NOT REFUSED. JSON-RPC 2.0 forbids
/// replying to a notification, so there is nothing to send back and inventing an error envelope
/// would break that rule to report a message that harmed nothing.
#[test]
fn an_unknown_notification_is_simply_not_one_of_these() {
    assert_eq!(McpNotification::read("notifications/nope", None), None);
}

// THE SDK-IDENTITY PIN MOVED TO `busbar-mcp` — the crate that still names `rmcp` (the SDK
// hard-depends on `tokio`, which may not enter a pure kind's closure, so this crate spells the five
// method names as literals). It is `src/tests/sdk_vocabulary_tests.rs` there, under the same test
// name, and it now pins all five against the SDK rather than one — see that file.
