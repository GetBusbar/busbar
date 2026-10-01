// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP+JSON line's arrival: the envelope each route composes (member for member the engine's
//! `rest.rs`), the verb a `POST /tasks/{id}` names, the captures and the query as the router and
//! `Query` decoded them, and the answer re-framed by what it is.

use super::*;
use crate::door::ROUTES;
use serde_json::json;

/// The route `verb target` of the door's routes.
fn route(verb: &str, target: &str) -> &'static Route {
    ROUTES
        .iter()
        .find(|r| r.verb == verb && r.target == target)
        .expect("a door route")
}

/// The envelope `verb target` composes over `body`, read back as JSON.
fn composed(verb: &str, path: &str, target: &str, body: &[u8]) -> Value {
    let bytes = compose(route(verb, path), target, body)
        .expect("composes")
        .expect("a line route");
    serde_json::from_slice(&bytes).expect("JSON")
}

/// The envelope `{"jsonrpc","id","method","params"}` with the fixed id.
fn envelope(name: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": REST_RPC_ID, "method": name, "params": params})
}

/// QUERY STRINGS ARE TYPED ON THE WAY INTO THE ENVELOPE. `historyLength=5` means the NUMBER five to
/// every reader of the composed envelope; left as a string, a filter is silently not applied, which
/// is the failure mode that errors nowhere.
#[test]
fn query_values_are_typed_the_way_the_envelope_wants_them() {
    assert_eq!(json_scalar("5"), json!(5));
    assert_eq!(json_scalar("-3"), json!(-3));
    assert_eq!(json_scalar("true"), json!(true));
    assert_eq!(json_scalar("false"), json!(false));
    assert_eq!(json_scalar("ctx-1"), json!("ctx-1"));
    assert_eq!(json_scalar(""), json!(""));
}

/// ABSENT IS NOT EMPTY. A query parameter the caller omitted must not appear in the composed params
/// at all: `historyLength` absent means "no opinion" and is a different request from
/// `historyLength: null`.
#[test]
fn an_omitted_query_parameter_is_absent_from_the_params() {
    let params = Params::new()
        .set("id", "t-1")
        .maybe("historyLength", None)
        .into_value();
    assert_eq!(params, json!({"id": "t-1"}));

    let asked = "7".to_string();
    let params = Params::new()
        .set("id", "t-1")
        .maybe("historyLength", Some(&asked))
        .into_value();
    assert_eq!(params, json!({"id": "t-1", "historyLength": 7}));
}

/// THE PATH WINS OVER THE BODY. A `taskId` member in a posted push-notification config must not
/// re-point the request at a task the caller did not address.
#[test]
fn a_body_member_cannot_re_point_the_addressed_task() {
    let params = Params::new()
        .merge(&json!({"taskId": "somebody-elses", "url": "https://receiver.example/hook"}))
        .set("taskId", "the-one-addressed")
        .into_value();
    assert_eq!(params["taskId"], "the-one-addressed");
    assert_eq!(params["url"], "https://receiver.example/hook");
}

/// AN EMPTY BODY IS NOT A PARSE FAILURE. `POST /tasks/{id}:cancel` carries none, and neither does a
/// `DELETE`; refusing them for a body they are not supposed to have would refuse the specification's
/// own request shape.
#[test]
fn an_absent_body_composes_empty_params() {
    assert_eq!(json_body(b""), json!({}));
    assert_eq!(json_body(b"nope"), json!({}));
    assert_eq!(json_body(b"{\"message\":1}"), json!({"message": 1}));
}

/// EVERY ROUTE OF THE LINE composes the engine's envelope: the method its request line names, the
/// path captures, the typed query members it reads (and no other), the body verbatim.
#[test]
fn each_route_composes_the_engines_envelope() {
    let body = br#"{"message":{"role":"ROLE_USER","parts":[]}}"#;
    assert_eq!(
        composed("POST", "/a2a/message:send", "/a2a/message:send", body),
        envelope(
            method::SEND_MESSAGE,
            json!({"message": {"role": "ROLE_USER", "parts": []}})
        )
    );
    assert_eq!(
        composed("POST", "/a2a/message:stream", "/a2a/message:stream", body)["method"],
        method::SEND_STREAM_MESSAGE
    );
    assert_eq!(
        composed(
            "GET",
            "/a2a/tasks",
            "/a2a/tasks?pageSize=5&status=working&unknown=x&includeArtifacts=true",
            b""
        ),
        envelope(
            method::LIST_TASKS,
            json!({"pageSize": 5, "status": "working", "includeArtifacts": true})
        )
    );
    assert_eq!(
        composed(
            "GET",
            "/a2a/tasks/{id}",
            "/a2a/tasks/t%2D1?historyLength=2",
            b""
        ),
        envelope(method::GET_TASK, json!({"id": "t-1", "historyLength": 2}))
    );
    assert_eq!(
        composed("POST", "/a2a/tasks/{id}", "/a2a/tasks/t-1:cancel", b""),
        envelope(method::CANCEL_TASK, json!({"id": "t-1"}))
    );
    assert_eq!(
        composed("POST", "/a2a/tasks/{id}", "/a2a/tasks/a:b:subscribe", b""),
        envelope(method::SUBSCRIBE_TO_TASK, json!({"id": "a:b"}))
    );
    let configs = "/a2a/tasks/{id}/pushNotificationConfigs";
    assert_eq!(
        composed(
            "POST",
            configs,
            "/a2a/tasks/t-1/pushNotificationConfigs",
            br#"{"taskId":"other","url":"https://r.example/h"}"#
        ),
        envelope(
            method::CREATE_PUSH_CONFIG,
            json!({"taskId": "t-1", "url": "https://r.example/h"})
        )
    );
    assert_eq!(
        composed(
            "GET",
            configs,
            "/a2a/tasks/t-1/pushNotificationConfigs?pageToken=p+2",
            b""
        ),
        envelope(
            method::LIST_PUSH_CONFIGS,
            json!({"taskId": "t-1", "pageToken": "p 2"})
        )
    );
    let config = "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}";
    let one = "/a2a/tasks/t-1/pushNotificationConfigs/c-9";
    assert_eq!(
        composed("GET", config, one, b""),
        envelope(
            method::GET_PUSH_CONFIG,
            json!({"taskId": "t-1", "id": "c-9"})
        )
    );
    assert_eq!(
        composed("DELETE", config, one, b""),
        envelope(
            method::DELETE_PUSH_CONFIG,
            json!({"taskId": "t-1", "id": "c-9"})
        )
    );
    assert_eq!(
        composed(
            "GET",
            "/a2a/extendedAgentCard",
            "/a2a/extendedAgentCard",
            b""
        ),
        envelope(method::GET_EXTENDED_AGENT_CARD, json!({}))
    );
}

/// A `POST /tasks/{id}` NAMING NO VERB is the engine's `404` + `MethodNotFound`, in its words, before
/// anything else is judged; a route that is not the line's, or a path that does not fit, composes
/// nothing.
#[test]
fn a_task_post_naming_no_verb_is_the_engines_404() {
    let task = route("POST", "/a2a/tasks/{id}");
    for target in ["/a2a/tasks/t-1", "/a2a/tasks/t-1:archive"] {
        let refusal = compose(task, target, b"").expect_err("refused");
        assert_eq!(
            (refusal.status, refusal.code, refusal.id.clone()),
            (404, -32601, None)
        );
        let addressed = target.trim_start_matches("/a2a/tasks/");
        assert_eq!(
            refusal.message,
            format!(
                "`{addressed}` names no operation on this binding; the task operations are \
                 `{{id}}:cancel` and `{{id}}:subscribe`"
            )
        );
        assert_eq!(refusal.aip193()["error"]["status"], "UNIMPLEMENTED");
    }
    assert_eq!(compose(task, "/a2a/tasks", b""), Ok(None));
    assert_eq!(compose(route("POST", "/a2a"), "/a2a", b"{}"), Ok(None));
}

/// A PATH CAPTURE IS DECODED AS THE ROUTER DECODED IT: `%XX` is the byte and `+` stays a `+`; a
/// capture whose bytes are not UTF-8 composes nothing.
#[test]
fn path_captures_decode_as_the_router_did() {
    assert_eq!(path_decode("a%3Ab+c").as_deref(), Some("a:b+c"));
    assert_eq!(path_decode("%zz%4").as_deref(), Some("%zz%4"));
    assert_eq!(path_decode("%FF"), None);
    let task = route("GET", "/a2a/tasks/{id}");
    assert_eq!(compose(task, "/a2a/tasks/%FF", b""), Ok(None));
}

/// A QUERY COMPONENT IS DECODED AS `Query` DECODED IT: `+` is a space, `%XX` the byte, a repeated
/// key keeps the last value.
#[test]
fn query_components_decode_as_the_extractor_did() {
    let q = query_map(Some("a=1+2&b=%41&a=3&&c"));
    assert_eq!(q.get("a").map(String::as_str), Some("3"));
    assert_eq!(q.get("b").map(String::as_str), Some("A"));
    assert_eq!(q.get("c").map(String::as_str), Some(""));
    assert!(query_map(None).is_empty());
}

/// RE-FRAMED BY WHAT IT IS: a result is the body verbatim, an error the AIP-193 document at the
/// answer's status, anything else untouched.
#[test]
fn an_answer_is_reframed_by_what_it_is() {
    let result = br#"{"jsonrpc":"2.0","id":"a2a-http-json","result":{"tasks":[]}}"#;
    assert_eq!(reframe(200, result), br#"{"tasks":[]}"#.to_vec());
    let error = br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"no such task","data":[{"reason":"TASK_NOT_FOUND"}]}}"#;
    let doc: Value = serde_json::from_slice(&reframe(404, error)).expect("JSON");
    assert_eq!(
        doc,
        json!({"error": {"code": 404, "status": "NOT_FOUND", "message": "no such task",
            "details": [{"reason": "TASK_NOT_FOUND"}]}})
    );
    let other = br#"{"status":"unavailable"}"#;
    assert_eq!(reframe(503, other), other.to_vec());
    assert_eq!(reframe(502, b"not json"), b"not json".to_vec());
}
