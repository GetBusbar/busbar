// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The relayed call, pure: admission in the engine's order and words, the request the client
//! dialect builds, and the far end's answer settled.

use serde_json::{json, Value};

use super::*;
use crate::catalogue::{Catalogue, ToolEntry};

/// One server: an approved tool whose `path` argument is mirrored in `Mcp-Param-Path`, a tool
/// awaiting approval, a tool that must be answered as a task, and a tool that asks its caller.
const SECTION: &str = r#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"},
  "grants": {"roots": true}, "roots": [{"uri": "file:///work", "name": "work"}],
  "tools_allow": {
    "read_file": {"schema_hash": "sha256:aa", "input_schema": {"type": "object", "properties": {"path": {"type": "string", "x-mcp-header": "Path"}}}, "output_schema": {"type": "object", "required": ["n"]}},
    "draft": {},
    "batch": {"schema_hash": "sha256:bb", "task_support": "required"},
    "confirm": {"schema_hash": "sha256:cc", "ask_caller": [{"ok": {"method": "elicitation/create", "params": {"message": "sure?"}}}]}
  }}}"#;

fn section() -> crate::tools_config::ToolsCfg {
    crate::door::read_tools_section(SECTION.as_bytes()).expect("the section reads")
}

fn catalogue() -> Catalogue {
    Catalogue::build(1, &section())
}

fn everyone(_: &str, _: &str) -> bool {
    true
}

fn params(name: &str, arguments: Value) -> Value {
    json!({ "name": name, "arguments": arguments, "_meta": {} })
}

fn proceed(_: &ToolEntry, _: &Value) -> crate::ask::AskDecision {
    crate::ask::AskDecision::Proceed
}

fn no_header(_: &str) -> Option<String> {
    None
}

fn refused(a: Admission) -> (Refusal, Option<CallLine>) {
    match a {
        Admission::Refused(r, line) => (r, line),
        other => panic!("not refused: {other:?}"),
    }
}

fn go(a: Admission) -> AdmittedCall {
    match a {
        Admission::Go(a) => a,
        other => panic!("not admitted: {other:?}"),
    }
}

#[test]
fn a_call_with_no_name_is_malformed_and_logged_with_no_tool() {
    let (r, line) = refused(admit_call(
        &catalogue(),
        &json!(1),
        Some(&json!({})),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!((r.status, r.code), (400, crate::codec::CODE_INVALID_PARAMS));
    assert_eq!(r.message, "`params.name` is required and must be a string.");
    let line = line.expect("logged");
    assert_eq!(
        (line.tool.as_str(), line.reason.as_str()),
        ("", "malformed_params")
    );
}

#[test]
fn a_name_past_the_ceiling_is_refused_before_the_log_opens() {
    let long = "x".repeat(MAX_TOOL_NAME_BYTES + 1);
    let (r, line) = refused(admit_call(
        &catalogue(),
        &json!(1),
        Some(&params(&long, json!({}))),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(r.status, 400);
    assert!(r.message.starts_with("`params.name` is 257 bytes"));
    assert_eq!(line, None, "no log line holds the oversized name");
}

#[test]
fn an_unknown_and_an_ungranted_tool_read_the_same_and_log_apart() {
    let (unknown, line) = refused(admit_call(
        &catalogue(),
        &json!(1),
        Some(&params("fs_nope", json!({}))),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(unknown.status, 404);
    assert_eq!(line.expect("logged").reason, "unknown_tool");
    let (hidden, line) = refused(admit_call(
        &catalogue(),
        &json!(1),
        Some(&params("fs_read_file", json!({}))),
        &no_header,
        &|kind: &str, _: &str| kind != crate::door::SCOPE_TOOL,
        &mut proceed,
    ));
    assert_eq!(hidden.status, 404);
    assert_eq!(
        hidden.message,
        unknown.message.replace("fs_nope", "fs_read_file")
    );
    assert_eq!(line.expect("logged").reason, "not_granted");
}

#[test]
fn a_tool_with_no_approved_hash_does_not_serve() {
    let (r, line) = refused(admit_call(
        &catalogue(),
        &json!(1),
        Some(&params("fs_draft", json!({}))),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(r.status, 403);
    assert_eq!(r.data, Some(json!({ "reason": "not_approved" })));
    assert_eq!(line.expect("logged").reason, "not_approved");
}

#[test]
fn a_mirrored_parameter_must_agree_with_the_body() {
    let cat = catalogue();
    let p = params("fs_read_file", json!({ "path": "/a" }));
    let (r, line) = refused(admit_call(
        &cat,
        &json!(1),
        Some(&p),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(
        (r.status, r.code),
        (400, crate::codec::CODE_HEADER_MISMATCH)
    );
    assert!(r.message.contains("`Mcp-Param-Path`"));
    let line = line.expect("logged");
    assert_eq!(
        (
            line.server.as_str(),
            line.tool.as_str(),
            line.tool_digest.as_str()
        ),
        ("fs", "fs_read_file", "sha256:aa")
    );
    let wrong = |name: &str| (name == "mcp-param-path").then(|| "/b".to_string());
    let (r, _) = refused(admit_call(
        &cat,
        &json!(1),
        Some(&p),
        &wrong,
        &everyone,
        &mut proceed,
    ));
    assert!(r
        .message
        .ends_with("does not match the body's `arguments.path`."));
    let right = |name: &str| (name == "mcp-param-path").then(|| "/a".to_string());
    let a = go(admit_call(
        &cat,
        &json!(1),
        Some(&p),
        &right,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(a.arguments, json!({ "path": "/a" }));
    assert_eq!(a.progress_token, None);
}

#[test]
fn a_required_task_needs_the_extension() {
    let (r, line) = refused(admit_call(
        &catalogue(),
        &json!(1),
        Some(&params("fs_batch", json!({}))),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(
        (r.status, r.code),
        (400, crate::codec::CODE_MISSING_CLIENT_CAPABILITY)
    );
    assert_eq!(line.expect("logged").reason, REASON_TASKS_UNDECLARED);
    let declared = json!({ "name": "fs_batch", "arguments": {},
        "_meta": { crate::codec::META_CLIENT_CAPABILITIES: { "extensions": { TASKS_EXTENSION_ID: {} } } } });
    go(admit_call(
        &catalogue(),
        &json!(1),
        Some(&declared),
        &no_header,
        &everyone,
        &mut proceed,
    ));
}

#[test]
fn an_answer_binds_only_what_was_asked_and_never_a_sent_argument() {
    let cat = catalogue();
    let answered = json!({ "name": "fs_confirm", "arguments": {}, "inputResponses": { "ok": true }, "_meta": {} });
    let a = go(admit_call(
        &cat,
        &json!(1),
        Some(&answered),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(a.arguments, json!({ "ok": true }));
    let smuggled = json!({ "name": "fs_confirm", "arguments": {}, "inputResponses": { "amount": 1 }, "_meta": {} });
    let (r, line) = refused(admit_call(
        &cat,
        &json!(1),
        Some(&smuggled),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(r.status, 404);
    assert!(r.message.starts_with("the answer named `amount`"));
    assert_eq!(line.expect("logged").reason, REASON_ANSWER_UNDECLARED);
    let rewritten = json!({ "name": "fs_confirm", "arguments": { "ok": false }, "inputResponses": { "ok": true }, "_meta": {} });
    refused(admit_call(
        &cat,
        &json!(1),
        Some(&rewritten),
        &no_header,
        &everyone,
        &mut proceed,
    ));
}

fn admitted() -> AdmittedCall {
    let right = |name: &str| (name == "mcp-param-path").then(|| "/a".to_string());
    go(admit_call(
        &catalogue(),
        &json!(7),
        Some(&params("fs_read_file", json!({ "path": "/a" }))),
        &right,
        &everyone,
        &mut proceed,
    ))
}

#[test]
fn the_request_is_the_dialect_builders_at_the_members_path() {
    let section = section();
    let def = section.servers.get("fs").expect("registered");
    let o = outbound(&admitted(), "fs", def, 0, None).expect("reachable");
    assert_eq!((o.verb, o.target.as_str()), ("POST", "/fs"));
    let body: Value = serde_json::from_slice(&o.body).expect("json");
    assert_eq!(
        body["params"]["name"],
        json!("read_file"),
        "the upstream's own name"
    );
    assert_eq!(body["id"], json!(0));
    assert_eq!(
        body["params"]["_meta"][crate::codec::META_CLIENT_CAPABILITIES],
        json!({ "roots": {} }),
        "the roots grant with roots declared is advertised"
    );
    assert!(
        o.fields.iter().all(|(n, _)| n != "authorization"),
        "no credential here"
    );
    assert!(o
        .fields
        .contains(&("mcp-name".to_string(), "read_file".to_string())));
}

#[test]
fn the_target_is_the_urls_path_and_query() {
    assert_eq!(path_of("https://h.example"), "/");
    assert_eq!(path_of("https://h.example/a/b"), "/a/b");
    assert_eq!(path_of("https://h.example/a?x=1"), "/a?x=1");
    assert_eq!(path_of("https://h.example?x=1"), "/?x=1");
}

#[test]
fn the_last_event_is_the_answer() {
    let raw = b"event: message\ndata: {\"a\":1}\n\ndata: {\"b\":\ndata: 2}\n\n";
    assert_eq!(last_sse_data(raw), b"{\"b\":\n2}".to_vec());
    assert_eq!(last_sse_data(b"nothing"), Vec::<u8>::new());
}

fn answer_of(s: Settled) -> (u32, Value, CallLine) {
    match s {
        Settled::Answer { status, body, line } => {
            (status, serde_json::from_slice(&body).expect("json"), line)
        }
        other => panic!("an answer: {other:?}"),
    }
}

fn settle_far(far: &str) -> Settled {
    let section = section();
    settle_call(
        &admitted(),
        section.servers.get("fs"),
        200,
        far.as_bytes(),
        false,
        0,
    )
}

#[test]
fn a_result_is_normalised_stamped_and_dispatched() {
    let (status, body, line) = answer_of(settle_far(
        r#"{"jsonrpc":"2.0","id":0,"result":{"content":[],"structuredContent":{"n":1}}}"#,
    ));
    assert_eq!(status, 200);
    assert_eq!(body["id"], json!(7));
    assert_eq!(body["result"]["resultType"], json!("complete"));
    assert_eq!((line.outcome, line.reason.as_str()), ("dispatched", ""));
}

#[test]
fn structured_output_breaking_the_published_schema_is_a_tool_failure() {
    let (status, body, line) = answer_of(settle_far(
        r#"{"jsonrpc":"2.0","id":0,"result":{"content":[],"structuredContent":{}}}"#,
    ));
    assert_eq!(status, 200);
    assert_eq!(body["result"]["isError"], json!(true));
    assert_eq!(line.reason, "upstream_failed");
}

#[test]
fn an_upstream_error_is_a_tool_failure_naming_the_server() {
    let (status, body, line) = answer_of(settle_far(
        r#"{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"nope"}}"#,
    ));
    assert_eq!(status, 200);
    let text = body["result"]["content"][0]["text"].as_str().expect("text");
    assert_eq!(
        text,
        "The MCP server `fs` did not complete this tool call: MCP upstream answered JSON-RPC error -32601: nope"
    );
    assert_eq!(
        (line.outcome, line.reason.as_str()),
        ("dispatched", "upstream_failed")
    );
}

#[test]
fn an_answer_to_something_else_is_never_served() {
    let (_, body, _) = answer_of(settle_far(r#"{"jsonrpc":"2.0","id":5,"result":{}}"#));
    assert!(body["result"]["content"][0]["text"]
        .as_str()
        .is_some_and(|t| t.contains("cannot correlate")));
}

#[test]
fn an_ungranted_ask_is_refused_and_never_forwarded() {
    let (status, body, line) = answer_of(settle_far(
        r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"e":{"method":"elicitation/create"}}}}"#,
    ));
    assert_eq!(status, 403);
    assert_eq!(body["error"]["data"]["reason"], json!("ask_ungranted"));
    assert!(body.get("result").is_none());
    assert_eq!(line.outcome, "refused");
}

#[test]
fn a_granted_roots_ask_is_satisfied_from_the_declared_roots() {
    let s = settle_far(
        r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}},"requestState":"s"}}"#,
    );
    match s {
        Settled::Next { continuation, kind } => {
            assert_eq!(kind, "roots");
            assert_eq!(
                continuation,
                json!({ "inputResponses": { "r": { "roots": [{ "uri": "file:///work", "name": "work" }] } }, "requestState": "s" })
            );
        }
        other => panic!("the next round: {other:?}"),
    }
}

#[test]
fn the_round_cap_bites_before_the_grant_is_read() {
    let section = section();
    let far = br#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}}}}"#;
    let (status, body, _) = answer_of(settle_call(
        &admitted(),
        section.servers.get("fs"),
        200,
        far,
        false,
        3,
    ));
    assert_eq!(status, 403);
    assert_eq!(body["error"]["data"]["reason"], json!("ask_round_cap"));
}

#[test]
fn a_result_still_carrying_an_ask_is_refused_at_the_terminal_check() {
    assert_eq!(
        upstream_ask_field(&json!({ "requestState": "x" })),
        Some("requestState")
    );
    assert_eq!(upstream_ask_field(&json!({ "content": [] })), None);
}

#[test]
fn a_tasks_verb_is_gated_then_names_no_task_of_this_callers() {
    let undeclared = task_verb(&json!(1), Some(&json!({ "taskId": "t", "_meta": {} })));
    assert_eq!(
        undeclared.code,
        crate::codec::CODE_MISSING_CLIENT_CAPABILITY
    );
    let meta = json!({ crate::codec::META_CLIENT_CAPABILITIES: { "extensions": { TASKS_EXTENSION_ID: {} } } });
    let no_id = task_verb(&json!(1), Some(&json!({ "_meta": meta })));
    assert_eq!(
        (no_id.status, no_id.code),
        (400, crate::codec::CODE_INVALID_PARAMS)
    );
    assert_eq!(
        no_id.message,
        "`params.taskId` is required and must be a string."
    );
    let unknown = task_verb(&json!(1), Some(&json!({ "taskId": "t", "_meta": meta })));
    assert_eq!(
        unknown.message,
        "No task with that `taskId` exists for this caller."
    );
}
