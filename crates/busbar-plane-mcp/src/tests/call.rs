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
  "grants": {"roots": true},
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
    assert_eq!(
        line.audit, None,
        "the served engine audited no malformed call"
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
    let line = line.expect("logged");
    assert_eq!(line.reason, "unknown_tool");
    assert_eq!(line.audit, Some(AuditRow::tool("fs_nope", false)));
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

/// THE KERNEL'S VERDICT, RENDERED (ARCHITECT Q3): the door judges no trust; it renders what the
/// kernel's Approve (`trust.serves`) answered for the called tool. An item never sighted is not
/// found, as an unknown name is; a known one the operator has not approved is refused; every other
/// distrust is refused under its own reason; a server the re-fetch could not reach fails the call
/// as an upstream failure (a tool error), never sent.
#[test]
fn the_kernels_trust_verdict_is_rendered_and_never_judged_here() {
    use busbar_contract::abi::host::service as svc;
    let cases: [(Trust, Option<(u32, &str)>); 8] = [
        (Trust::Verdict(svc::DISTRUST_NONE), None),
        (
            Trust::Verdict(svc::DISTRUST_UNKNOWN_ITEM),
            Some((404, "unknown_tool")),
        ),
        (
            Trust::Verdict(svc::DISTRUST_NOT_APPROVED),
            Some((403, "not_approved")),
        ),
        (
            Trust::Verdict(svc::DISTRUST_CHANGED),
            Some((403, "quarantined")),
        ),
        (
            Trust::Verdict(svc::DISTRUST_QUARANTINED),
            Some((403, "quarantined")),
        ),
        (
            Trust::Verdict(svc::DISTRUST_UNSIGHTED),
            Some((403, "pending")),
        ),
        (
            Trust::Verdict(svc::DISTRUST_UNKNOWN),
            Some((403, "not_serving")),
        ),
        (
            Trust::Unreached("down".to_string()),
            Some((200, "upstream_failed")),
        ),
    ];
    for (trust, want) in cases {
        let mut asked = Vec::new();
        let admission = admit_trusted(
            &catalogue(),
            &json!(1),
            Some(&params("fs_draft", json!({}))),
            &no_header,
            &everyone,
            &mut |entry: &ToolEntry| {
                asked.push((entry.server.clone(), entry.tool.clone()));
                trust.clone()
            },
            &|_| false,
            &mut proceed,
        );
        assert_eq!(
            asked,
            [("fs".to_string(), "draft".to_string())],
            "the verdict is asked once, of the called tool's registration and trust key"
        );
        match want {
            None => {
                go(admission);
            }
            Some((200, reason)) => match admission {
                Admission::Unreached(body, line) => {
                    let body: Value = serde_json::from_slice(&body).expect("json");
                    assert_eq!(body["result"]["isError"], json!(true), "a tool error");
                    assert_eq!(line.reason, reason);
                    assert_eq!(line.outcome, "refused", "never sent");
                }
                other => panic!("the unreached call is a tool error: {other:?}"),
            },
            Some((status, reason)) => {
                let (r, line) = refused(admission);
                assert_eq!(r.status, status, "{trust:?}");
                assert_eq!(r.data, Some(json!({ "reason": reason })), "{trust:?}");
                assert_eq!(line.expect("logged").reason, reason, "{trust:?}");
            }
        }
    }
}

/// The verdict is asked only of a tool the caller is granted: an ungranted call is not found before
/// the kernel is asked anything.
#[test]
fn the_verdict_is_asked_only_after_the_grants() {
    let (r, _) = refused(admit_trusted(
        &catalogue(),
        &json!(1),
        Some(&params("fs_draft", json!({}))),
        &no_header,
        &|_, _| false,
        &mut |_| panic!("the kernel is asked about an ungranted call"),
        &|_| false,
        &mut proceed,
    ));
    assert_eq!(r.status, 404);
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
        line.audit, None,
        "a header mismatch is malformed, never audited"
    );
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
    let line = line.expect("logged");
    assert_eq!(line.reason, REASON_TASKS_UNDECLARED);
    assert_eq!(line.audit, Some(AuditRow::tool("fs_batch", false)));
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
    // A RELAYED ASK NEEDS A CALLER WHO CAN ANSWER IT (Law 11): the roots grant alone advertises
    // nothing to a caller that declared no roots; with the caller's roots declared it is.
    assert_eq!(
        body["params"]["_meta"][crate::codec::META_CLIENT_CAPABILITIES],
        json!({}),
        "nothing is advertised the caller could not answer"
    );
    let mut declaring = admitted();
    declaring.capabilities = json!({ "roots": {}, "sampling": {} });
    let o = outbound(&declaring, "fs", def, 0, None).expect("reachable");
    let body: Value = serde_json::from_slice(&o.body).expect("json");
    assert_eq!(
        body["params"]["_meta"][crate::codec::META_CLIENT_CAPABILITIES],
        json!({ "roots": {} }),
        "the roots grant and the caller's roots advertise roots; an ungranted kind is not"
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

/// A result with no `resultType` gets the dialect's `complete` ahead of the upstream's own members,
/// which follow as they came; an empty result is the stamp alone.
#[test]
fn a_result_is_stamped_and_dispatched() {
    let settled = settle_far(
        r#"{"jsonrpc":"2.0","id":0,"result":{"content":[],"structuredContent":{"n":1}}}"#,
    );
    let Settled::Answer { body: bytes, .. } = &settled else {
        panic!("an answer: {settled:?}")
    };
    assert_eq!(
        String::from_utf8_lossy(bytes),
        r#"{"id":7,"jsonrpc":"2.0","result":{"resultType":"complete","content":[],"structuredContent":{"n":1}}}"#
    );
    let (status, body, line) = answer_of(settled);
    assert_eq!(status, 200);
    assert_eq!(body["id"], json!(7));
    assert_eq!(body["result"]["resultType"], json!("complete"));
    assert_eq!((line.outcome, line.reason.as_str()), ("dispatched", ""));
    assert_eq!(line.audit, Some(AuditRow::tool("fs_read_file", true)));
    let (_, empty, _) = answer_of(settle_far(r#"{"jsonrpc":"2.0","id":0,"result":{ }}"#));
    assert_eq!(empty["result"], json!({ "resultType": "complete" }));
}

/// The far end's answer carrying `result` as the upstream wrote it.
fn far_result(result: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":0,"result":{result}}}"#)
}

/// LAW 11 (THE DESIGN 2126, 2131-2132; product hard rule 3369-3373): a tool's result is the
/// upstream's data and reaches the caller as the upstream sent it. `Vec<String>` and `<b>x</b>` in
/// the content text, in `structuredContent` and in `_meta` are the tool's answer, not markup busbar
/// may strip, and the result's bytes are the upstream's own, member order included.
/// RED arm: a built-in strip served `Vec` for `Vec<String>` and `x` for `<b>x</b>`.
#[test]
fn a_result_reaches_its_caller_as_the_upstream_sent_it() {
    let sent = r#"{"resultType":"complete","structuredContent":{"t":"Vec<String>","n":1,"h":"<b>x</b>"},"content":[{"type":"text","text":"fn f() -> Vec<String> { <b>x</b> }"}],"_meta":{"m":"<i>y</i>"}}"#;
    let settled = settle_far(&far_result(sent));
    let Settled::Answer { body: bytes, .. } = &settled else {
        panic!("an answer: {settled:?}")
    };
    assert!(
        bytes.windows(sent.len()).any(|w| w == sent.as_bytes()),
        "the upstream's result bytes, verbatim: {}",
        String::from_utf8_lossy(bytes)
    );
    let (status, body, line) = answer_of(settled);
    assert_eq!(status, 200);
    assert_eq!(body["id"], json!(7));
    assert_eq!(
        body["result"],
        serde_json::from_str::<Value>(sent).expect("json"),
        "the upstream's result, unchanged"
    );
    assert_eq!((line.outcome, line.reason.as_str()), ("dispatched", ""));
}

/// LAW 11 (THE DESIGN 2131-2132): a `structuredContent` that does not match the tool's published
/// `outputSchema` is still the upstream's answer. It is relayed unchanged; busbar never answers in
/// the upstream's place.
/// RED arm: busbar replaced it with its own `isError` result, "The structured result was NOT
/// served".
#[test]
fn structured_output_breaking_the_published_schema_is_relayed_unchanged() {
    let sent = r#"{"resultType":"complete","content":[],"structuredContent":{}}"#;
    let (status, body, line) = answer_of(settle_far(&far_result(sent)));
    assert_eq!(status, 200);
    assert_eq!(
        body["result"],
        serde_json::from_str::<Value>(sent).expect("json"),
        "the upstream's result, as it came"
    );
    assert_eq!((line.outcome, line.reason.as_str()), ("dispatched", ""));
    assert_eq!(line.audit, Some(AuditRow::tool("fs_read_file", true)));
}

/// THE TASK PATH SETTLES THE SAME RESULT (Law 11): a task's completed result is the upstream's,
/// stored and served as it came. A source plant, because the task's continuation is reached only
/// through a live door: no rewrite of the result is named on that path.
/// RED arm: `door_tasks.rs` ran the markup strip over every completed task result.
#[test]
fn the_task_path_names_no_rewrite_of_the_result() {
    let source = include_str!("../door_tasks.rs");
    assert!(
        !source.contains("sanitize::"),
        "a task's completed result passes through no markup strip"
    );
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
    assert_eq!(
        line.audit,
        Some(AuditRow::tool("fs_read_file", false)),
        "the call went out and did not succeed: rejected"
    );
}

/// LAW 11 (THE DESIGN 2126, 2131-2132; product hard rule 3369-3373): the upstream's JSON-RPC
/// error message is the upstream's data and reaches the caller unchanged inside busbar's failure
/// words; `Vec<String>` and `<b>x</b>` are not markup busbar may strip.
/// RED arm: the failure text ran through the markup strip, serving `Vec` and `x`.
#[test]
fn an_upstream_error_message_reaches_its_caller_unchanged() {
    let (_, body, _) = answer_of(settle_far(
        r#"{"jsonrpc":"2.0","id":0,"error":{"code":-32602,"message":"want Vec<String>, got <b>x</b>"}}"#,
    ));
    let text = body["result"]["content"][0]["text"].as_str().expect("text");
    assert_eq!(
        text,
        "The MCP server `fs` did not complete this tool call: MCP upstream answered JSON-RPC error -32602: want Vec<String>, got <b>x</b>"
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

/// LAW 11 (U16): a granted roots ask is RELAYED to the caller, its result as it came; busbar
/// answers none of it. RED arm: a satisfier answering from the operator's roots would settle a
/// next round (an answer busbar wrote) instead of handing the upstream's result back.
#[test]
fn a_granted_roots_ask_is_relayed_to_the_caller_as_it_came() {
    let far = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}},"requestState":"s"}}"#;
    match settle_far(far) {
        Settled::Relay {
            result,
            round,
            child,
        } => {
            assert_eq!(round, 0);
            assert_eq!(
                child, None,
                "an `input_required` result is not a child's request"
            );
            let sent: Value = serde_json::from_str(far).expect("json");
            assert_eq!(
                result, sent["result"],
                "the upstream's result, byte for byte"
            );
        }
        other => panic!("relayed: {other:?}"),
    }
}

/// LAW 11 (BUSBAR-1.6.0 lines 2127-2132, the relay-only ruling at 418-422): a granted SAMPLING ask
/// is relayed to the caller exactly as the upstream sent it. busbar runs no completion for it on any
/// plane; the caller answers it. A pin: predev already relays on this path, and this holds it there.
#[test]
fn a_granted_sampling_ask_is_relayed_to_the_caller_unchanged() {
    let section = section();
    let mut def = section.servers.get("fs").expect("fs").clone();
    def.grants.sampling = true;
    let far = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"s":{"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":5}}},"requestState":"opaque"}}"#;
    match settle_call(&admitted(), Some(&def), 200, far.as_bytes(), false, 0) {
        Settled::Relay {
            result,
            round,
            child,
        } => {
            assert_eq!(round, 0);
            assert_eq!(child, None);
            let sent: Value = serde_json::from_str(far).expect("json");
            assert_eq!(
                result, sent["result"],
                "the upstream's sampling ask, byte for byte"
            );
        }
        other => panic!("relayed: {other:?}"),
    }
}

/// LAW 11 (finding 20): what the caller reads about an upstream's ask says what the code does — the
/// ask is RELAYED to the caller, or not relayed under the operator's policy. It never says busbar
/// satisfies an ask, or that an ask terminates at busbar.
#[test]
fn an_ask_refusal_tells_the_caller_the_ask_is_relayed_never_satisfied() {
    let ungranted = settle_far(
        r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"s":{"method":"sampling/createMessage"}}}}"#,
    );
    let mixed =
        settle_far(r#"{"jsonrpc":"2.0","id":0,"result":{"content":[],"requestState":"x"}}"#);
    for settled in [ungranted, mixed] {
        let (status, body, _) = answer_of(settled);
        assert_eq!(status, 403);
        let message = body["error"]["message"].as_str().expect("message");
        for stale in ["satisf", "terminates at busbar", "never forwarded"] {
            assert!(
                !message.contains(stale),
                "the caller-visible text says `{stale}`: {message}"
            );
        }
        assert!(
            message.contains("relayed"),
            "the caller-visible text names the relay: {message}"
        );
    }
}

/// An ask mixing a granted kind with an ungranted one is refused naming the ungranted one: the
/// most privileged kind alone does not decide a map whose lesser entries are ungranted.
#[test]
fn an_ask_mixing_an_ungranted_kind_is_refused() {
    let (status, body, _) = answer_of(settle_far(
        r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"},"e":{"method":"elicitation/create"}}}}"#,
    ));
    assert_eq!(status, 403);
    assert_eq!(body["error"]["data"]["reason"], json!("ask_ungranted"));
    assert!(body["error"]["message"]
        .as_str()
        .is_some_and(|m| m.contains("elicitation")));
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

/// THE INVOKE REWRITE CONTRACT, as the served engine applied a `prompt: rw` hook's reply to a
/// call's arguments: an object `content`, a JSON-string `content` that parses to an object, or a
/// role-less entry itself; the last usable entry wins; nothing usable is not applied.
#[test]
fn a_rewrite_replaces_the_arguments_by_the_invoke_contract() {
    let body = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fs_read","arguments":{"path":"/secret"},"_meta":{"k":"v"}}}"#;
    let args = |rewrite: serde_json::Value| {
        rewritten(body, &serde_json::to_vec(&rewrite).unwrap()).map(|b| {
            let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
            assert_eq!(v["params"]["_meta"], serde_json::json!({ "k": "v" }));
            assert_eq!(v["id"], 7);
            v["params"]["arguments"].clone()
        })
    };
    let object = serde_json::json!({ "path": "/x" });
    assert_eq!(
        args(serde_json::json!({ "messages": [{ "role": "user", "content": object }] })),
        Some(object.clone())
    );
    assert_eq!(
        args(
            serde_json::json!({ "messages": [{ "role": "user", "content": "{\"path\":\"/x\"}" }] })
        ),
        Some(object.clone())
    );
    assert_eq!(
        args(serde_json::json!({ "messages": [{ "path": "/x" }] })),
        Some(object.clone())
    );
    assert_eq!(
        args(serde_json::json!({ "messages": [
            { "role": "user", "content": { "path": "/first" } },
            { "role": "user", "content": "plain words" },
            { "role": "user", "content": { "path": "/x" } },
        ] })),
        Some(object)
    );
    // Nothing usable: a role with no content, plain text, a scalar, no messages at all.
    assert_eq!(
        args(serde_json::json!({ "messages": [{ "role": "user" }] })),
        None
    );
    assert_eq!(
        args(serde_json::json!({ "messages": [{ "role": "user", "content": "7" }] })),
        None
    );
    assert_eq!(args(serde_json::json!({ "tools": [] })), None);
    assert_eq!(rewritten(body, b"not json"), None);
    // A request that is not a call is never rewritten.
    let list = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    assert_eq!(
        rewritten(
            list,
            br#"{"messages":[{"role":"user","content":{"path":"/x"}}]}"#
        ),
        None
    );
}

/// THE AUDIT ROW OF BUSBAR'S OWN ASK (SEAM-L(k)): an ask of the caller is `mcp.caller_ask` applied on
/// the tool; a task created is the call applied; a task that could not start is rejected.
#[test]
fn an_ask_of_the_caller_and_a_task_are_audited_in_the_engines_words() {
    let mut ask = |_: &ToolEntry, _: &Value| crate::ask::AskDecision::Ask {
        asks: Vec::new(),
        request_state: "s".to_string(),
        round: 1,
    };
    let line = match admit_call(
        &catalogue(),
        &json!(1),
        Some(&params("fs_confirm", json!({}))),
        &no_header,
        &everyone,
        &mut ask,
    ) {
        Admission::Asked(_, line) => line,
        other => panic!("asked: {other:?}"),
    };
    assert_eq!(
        line.audit,
        Some(AuditRow {
            action: ACTION_CALLER_ASK,
            resource: "mcp_tool:fs_confirm".to_string(),
            applied: true,
        })
    );
    let entry = catalogue().tool("fs_batch").expect("registered").clone();
    assert_eq!(
        task_line(&entry, busbar_contract::vocab::REASON_TASK_CREATED).audit,
        Some(AuditRow::tool("fs_batch", true))
    );
    assert_eq!(
        task_line(&entry, "task_unavailable").audit,
        Some(AuditRow::tool("fs_batch", false))
    );
}
