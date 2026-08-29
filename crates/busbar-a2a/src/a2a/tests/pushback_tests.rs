// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CALLBACK SUBSTITUTION: busbar as the CLIENT of A2A's four push-notification config verbs,
//! over all three bindings, plus the endpoint the substitution points a backend at.
//!
//! ## What these tests are evidence for
//!
//! Twelve cells of `qa/method-inventory.json` — `a2a|<binding>|client|client|<verb>` for
//! `CreateTaskPushNotificationConfig`, `GetTaskPushNotificationConfig`,
//! `ListTaskPushNotificationConfigs` and `DeleteTaskPushNotificationConfig` on each of `jsonrpc`,
//! `http+json` and `grpc`.
//!
//! A cell here is a claim that BUSBAR ISSUES the operation, so the only thing that can prove one is
//! the request on the wire. Every test below reads it off the recording seam and [`issued_last`]
//! PANICS when there was none — which is not a formality on this plane: all four verbs are also
//! answered LOCALLY, so every one of them returns `200` while making no hop at all. "It returned
//! 200" is exactly the false green this file exists to make impossible.
//!
//! ## And what the substitution is FOR, which is the part that is not about coverage
//!
//! `crate::a2a::pushback` carries the argument. In one line: before it, a backend was never told
//! anything, so a task interrupted and completed out of band delivered NOTHING to a caller that had
//! registered a callback precisely so it would not have to poll.
//!
//! ## THE PROPERTY THAT MATTERS MORE THAN THE CELLS
//!
//! [`the_substituted_registration_carries_neither_the_callers_url_nor_its_secret`] is the reason
//! this is a substitution and not a relay. It scans every byte of every request in the five
//! encodings `relay_harness::encodings` defines, for the caller's webhook URL and the caller's
//! webhook credential, on all three bindings.

use super::relay_harness::*;
use crate::a2a::pushback;
use crate::a2a::relay::{BINDING_GRPC, BINDING_HTTP_JSON, BINDING_JSONRPC};

/// THE CALLER'S OWN WEBHOOK, and its own secret. Distinctive, because both are needles in the scan.
const CALLER_HOOK: &str = "https://receiver.caller.test/notify";
const CALLER_SECRET: &str = "caller-webhook-secret-NEVER-ON-A-HOP-4c1f";

/// The config id the CALLER uses. Also a needle: busbar addresses the backend by an id of its own,
/// and the caller's handle is a fact about busbar's record that a backend has no business holding.
const CALLER_CONFIG_ID: &str = "caller-cfg-9a2b";

/// The backend's own name for the task every fixture here opens, and the id busbar's substituted
/// registration is therefore addressed by.
const BACKEND_TASK: &str = "BACKEND-OWN-TASK-ID";

/// busbar's own config id at the backend, spelled by the production function so a test cannot agree
/// with a stale copy of it.
fn our_config_id() -> String {
    pushback::config_id(BACKEND_TASK)
}

// ══ DRIVING ONE OPERATION, AND READING WHAT WENT OUT ═════════════════════════════════════════════

/// Call `planner` with `envelope` and hand back the LAST request busbar asked to have sent.
///
/// PANICS when the request under test produced no new hop. The submission that opens the task made
/// one, so a bare "the log is not empty" would pass for every verb here whether or not the verb
/// itself ever reached the wire — the count is taken before and after, and it must have moved.
async fn issued_last(h: &Harness, before: usize, envelope: &serde_json::Value) -> Recorded {
    let (status, body) = call_agent(h, "planner", envelope).await;
    let sent = h.sent();
    assert!(
        sent.len() > before,
        "busbar made NO NEW outbound hop for {:?}. It answered {status} with {body}. This verb is \
         also answered locally, so a `200` proves nothing — a client-leg cell is a claim about a \
         request on the wire, and there was none.",
        envelope.get("method")
    );
    sent.into_iter().next_back().expect("just checked")
}

/// The path (and query) of a recorded request's URL, with the origin removed.
fn path_of(r: &Recorded) -> String {
    let url = url::Url::parse(&r.url).expect("the recorded URL parses");
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    }
}

fn body_json(r: &Recorded) -> serde_json::Value {
    serde_json::from_slice(&r.body).unwrap_or_else(|e| {
        panic!(
            "the outbound body is not JSON ({e}): {:?}",
            String::from_utf8_lossy(&r.body)
        )
    })
}

fn envelope_for(method: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params })
}

/// The v0.3 submission, answered by a backend that is still WORKING.
///
/// WORKING and not completed, and that is load-bearing rather than incidental: busbar does not arm
/// a backend for a task it already holds as terminal (`pushback::worth_registering`), because that
/// would be registering a webhook for an event that cannot happen. A fixture whose task completed
/// would make every test in this file assert nothing.
fn submission() -> serde_json::Value {
    envelope()
}

fn v10_submission() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 7, "method": "SendMessage",
        "params": { "message": { "messageId": "m-1", "role": "ROLE_USER",
                                 "parts": [{ "text": "PLAN THE MIGRATION" }] } }
    })
}

/// The caller's `CreateTaskPushNotificationConfig`, naming ITS url, ITS credential and ITS id.
fn create_call(task: &str) -> serde_json::Value {
    envelope_for(
        "CreateTaskPushNotificationConfig",
        serde_json::json!({
            "taskId": task,
            "id": CALLER_CONFIG_ID,
            "url": CALLER_HOOK,
            "authentication": { "scheme": "Bearer", "credentials": CALLER_SECRET },
        }),
    )
}

/// A `message/send` that opens ONE live task, and the busbar task id it was answered with.
async fn open_a_task(h: &Harness, submission: &serde_json::Value) -> String {
    let (status, answer) = call_agent(h, "planner", submission).await;
    assert_eq!(status, 200, "the submission must succeed: {answer}");
    let id = answer
        .pointer("/result/id")
        .or_else(|| answer.pointer("/result/task/id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the submission answered no task id: {answer}"));
    assert!(!id.is_empty(), "the submission answered an empty task id");
    id.to_string()
}

/// Open a task and register the caller's config on it, leaving the substituted registration in
/// place. Hands back the busbar task id — the setup every read and the delete share.
async fn open_and_register(h: &Harness, submission: &serde_json::Value) -> String {
    let task = open_a_task(h, submission).await;
    let (status, body) = call_agent(h, "planner", &create_call(&task)).await;
    assert_eq!(
        status, 200,
        "the caller's registration must succeed: {body}"
    );
    task
}

// ══ THE JSON-RPC BINDING ═════════════════════════════════════════════════════════════════════════

/// A backend that is still WORKING, in the JSON-RPC dialect.
fn jsonrpc_working() -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 7,
        "result": { "id": BACKEND_TASK, "contextId": "BACKEND-OWN-CONTEXT", "kind": "task",
                    "status": { "state": "working" } }
    })
    .to_string()
}

/// The backend's answer to a push-config verb, carrying BUSBAR'S OWN config id — so the
/// reconciliation in `receive::mirror_push_config` finds its registration and does not re-arm.
/// [`a_read_that_does_not_find_busbars_registration_re_arms_it`] drives the other side of that.
fn jsonrpc_config() -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 0,
        "result": { "taskId": BACKEND_TASK, "id": pushback::config_id(BACKEND_TASK),
                    "url": "https://busbar.example/a2a/push" }
    })
    .to_string()
}

fn jsonrpc_config_list() -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 0,
        "result": { "configs": [{ "taskId": BACKEND_TASK, "id": pushback::config_id(BACKEND_TASK),
                                  "url": "https://busbar.example/a2a/push" }],
                    "nextPageToken": "" }
    })
    .to_string()
}

fn jsonrpc_null() -> String {
    serde_json::json!({ "jsonrpc": "2.0", "id": 0, "result": null }).to_string()
}

/// One JSON-RPC hop, asserted whole: the verb, the endpoint, and the method the envelope names.
fn assert_jsonrpc(r: &Recorded, method: &str) {
    assert_eq!(r.http_method, "POST", "JSON-RPC is a POST to one endpoint");
    assert_eq!(r.url, BACKEND, "the operator's endpoint, verbatim");
    let body = body_json(r);
    assert_eq!(
        body.get("method").and_then(serde_json::Value::as_str),
        Some(method),
        "the envelope on the wire must name `{method}`: {body}"
    );
}

#[tokio::test]
async fn jsonrpc_client_issues_create_task_push_notification_config() {
    let h = harness_on(
        in_turn(200, vec![jsonrpc_working(), jsonrpc_config()]),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_a_task(&h, &submission()).await;
    let before = h.sent().len();
    let sent = issued_last(&h, before, &create_call(&task)).await;
    assert_jsonrpc(&sent, "CreateTaskPushNotificationConfig");

    // THE SUBSTITUTION ITSELF, member by member.
    let params = body_json(&sent)["params"].clone();
    assert_eq!(
        params["taskId"], BACKEND_TASK,
        "the registration addresses the BACKEND's own task id, not busbar's: {params}"
    );
    assert_eq!(
        params["id"],
        our_config_id(),
        "the registration is busbar's own, under busbar's own id: {params}"
    );
    assert_eq!(
        params["url"], "https://busbar.example/a2a/push",
        "the backend is given BUSBAR's address and not the caller's: {params}"
    );
    let token = params["authentication"]["credentials"]
        .as_str()
        .unwrap_or_default();
    assert!(
        token.starts_with(&format!("{task}.")),
        "the credential must be the capability busbar minted for THIS task: {params}"
    );
}

#[tokio::test]
async fn jsonrpc_client_issues_get_task_push_notification_config() {
    let h = harness_on(
        in_turn(
            200,
            vec![jsonrpc_working(), jsonrpc_config(), jsonrpc_config()],
        ),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_and_register(&h, &submission()).await;
    let before = h.sent().len();
    let sent = issued_last(
        &h,
        before,
        &envelope_for(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "taskId": task, "id": CALLER_CONFIG_ID }),
        ),
    )
    .await;
    assert_jsonrpc(&sent, "GetTaskPushNotificationConfig");
    assert_eq!(body_json(&sent)["params"]["id"], our_config_id());
}

#[tokio::test]
async fn jsonrpc_client_issues_list_task_push_notification_configs() {
    let h = harness_on(
        in_turn(
            200,
            vec![jsonrpc_working(), jsonrpc_config(), jsonrpc_config_list()],
        ),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_and_register(&h, &submission()).await;
    let before = h.sent().len();
    let sent = issued_last(
        &h,
        before,
        &envelope_for(
            "ListTaskPushNotificationConfigs",
            serde_json::json!({ "taskId": task }),
        ),
    )
    .await;
    assert_jsonrpc(&sent, "ListTaskPushNotificationConfigs");
    assert_eq!(body_json(&sent)["params"]["taskId"], BACKEND_TASK);
}

#[tokio::test]
async fn jsonrpc_client_issues_delete_task_push_notification_config() {
    let h = harness_on(
        in_turn(
            200,
            vec![jsonrpc_working(), jsonrpc_config(), jsonrpc_null()],
        ),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_and_register(&h, &submission()).await;
    let before = h.sent().len();
    let sent = issued_last(
        &h,
        before,
        &envelope_for(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "taskId": task, "id": CALLER_CONFIG_ID }),
        ),
    )
    .await;
    assert_jsonrpc(&sent, "DeleteTaskPushNotificationConfig");
    assert_eq!(body_json(&sent)["params"]["id"], our_config_id());
}

// ══ THE HTTP+JSON BINDING ════════════════════════════════════════════════════════════════════════
//
// A2A section 11.3: the request line IS the operation, so what is asserted per verb is the verb and
// the path — a `POST` to a collection, a `GET` of one member, a `GET` of the collection, a `DELETE`
// of one member — and, where there is a body, that it is the params and nothing else.

fn rest_working() -> String {
    serde_json::json!({ "id": BACKEND_TASK, "contextId": "BACKEND-OWN-CONTEXT", "kind": "task",
                        "status": { "state": "working" } })
    .to_string()
}

fn rest_config() -> String {
    serde_json::json!({ "taskId": BACKEND_TASK, "id": pushback::config_id(BACKEND_TASK),
                        "url": "https://busbar.example/a2a/push" })
    .to_string()
}

fn rest_config_list() -> String {
    serde_json::json!({
        "configs": [{ "taskId": BACKEND_TASK, "id": pushback::config_id(BACKEND_TASK),
                      "url": "https://busbar.example/a2a/push" }],
        "nextPageToken": ""
    })
    .to_string()
}

#[tokio::test]
async fn http_json_client_issues_create_task_push_notification_config() {
    let h = harness_on(
        in_turn(200, vec![rest_working(), rest_config()]),
        BINDING_HTTP_JSON,
    )
    .await;
    let task = open_a_task(&h, &submission()).await;
    let before = h.sent().len();
    let sent = issued_last(&h, before, &create_call(&task)).await;
    assert_eq!(sent.http_method, "POST");
    assert_eq!(
        path_of(&sent),
        format!("/a2a/tasks/{BACKEND_TASK}/pushNotificationConfigs")
    );
    let body = body_json(&sent);
    assert_eq!(body["url"], "https://busbar.example/a2a/push");
    assert_eq!(body["id"], our_config_id());
    assert!(
        body.get("method").is_none() && body.get("jsonrpc").is_none(),
        "the REST body must carry no JSON-RPC envelope members: {body}"
    );
}

#[tokio::test]
async fn http_json_client_issues_get_task_push_notification_config() {
    let h = harness_on(
        in_turn(200, vec![rest_working(), rest_config(), rest_config()]),
        BINDING_HTTP_JSON,
    )
    .await;
    let task = open_and_register(&h, &submission()).await;
    let before = h.sent().len();
    let sent = issued_last(
        &h,
        before,
        &envelope_for(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "taskId": task, "id": CALLER_CONFIG_ID }),
        ),
    )
    .await;
    assert_eq!(
        sent.http_method, "GET",
        "A2A binds this read to a GET; a POST here is a different request"
    );
    assert_eq!(
        path_of(&sent),
        format!(
            "/a2a/tasks/{BACKEND_TASK}/pushNotificationConfigs/{}",
            our_config_id()
        )
    );
    assert!(
        sent.body.is_empty(),
        "a GET carries no body: {:?}",
        String::from_utf8_lossy(&sent.body)
    );
}

#[tokio::test]
async fn http_json_client_issues_list_task_push_notification_configs() {
    let h = harness_on(
        in_turn(200, vec![rest_working(), rest_config(), rest_config_list()]),
        BINDING_HTTP_JSON,
    )
    .await;
    let task = open_and_register(&h, &submission()).await;
    let before = h.sent().len();
    let sent = issued_last(
        &h,
        before,
        &envelope_for(
            "ListTaskPushNotificationConfigs",
            serde_json::json!({ "taskId": task }),
        ),
    )
    .await;
    assert_eq!(sent.http_method, "GET");
    assert_eq!(
        path_of(&sent),
        format!("/a2a/tasks/{BACKEND_TASK}/pushNotificationConfigs"),
        "a list addresses the COLLECTION; a member path here would be a different operation"
    );
}

#[tokio::test]
async fn http_json_client_issues_delete_task_push_notification_config() {
    let h = harness_on(
        in_turn(200, vec![rest_working(), rest_config(), String::new()]),
        BINDING_HTTP_JSON,
    )
    .await;
    let task = open_and_register(&h, &submission()).await;
    let before = h.sent().len();
    let sent = issued_last(
        &h,
        before,
        &envelope_for(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "taskId": task, "id": CALLER_CONFIG_ID }),
        ),
    )
    .await;
    assert_eq!(
        sent.http_method, "DELETE",
        "A2A binds the withdrawal to a DELETE. A client that spelled every operation as a POST \
         would look correct in a log that only kept the URL."
    );
    assert_eq!(
        path_of(&sent),
        format!(
            "/a2a/tasks/{BACKEND_TASK}/pushNotificationConfigs/{}",
            our_config_id()
        )
    );
}

// ══ THE gRPC BINDING ═════════════════════════════════════════════════════════════════════════════
//
// The one binding that cannot be a courier. The frames busbar composed are decoded back with the
// SDK — `a2a_pb` — rather than with busbar's own reader, so the oracle is the SDK and not the code
// under test.

/// One gRPC frame, as a backend answers it.
fn grpc_frame<M: prost::Message>(message: &M) -> Vec<u8> {
    let len = prost::Message::encoded_len(message);
    let mut out = vec![0u8];
    out.extend_from_slice(&(u32::try_from(len).expect("a fixture fits in a frame")).to_be_bytes());
    prost::Message::encode(message, &mut out).expect("the message encodes");
    out
}

/// A protobuf frame is not UTF-8, and the recording transport hands fixtures back as `String`, so it
/// travels as latin-1 — byte for byte, and turned back into bytes on the way out.
fn as_fixture(bytes: &[u8]) -> String {
    bytes.iter().map(|b| *b as char).collect()
}

/// The rpc path a recorded request addresses, and the message it carries, decoded with the SDK.
fn grpc_message<T>(r: &Recorded) -> T
where
    T: prost::Message + Default,
{
    assert_eq!(r.http_method, "POST", "a gRPC call is always a POST");
    assert!(
        r.body.len() >= 5,
        "a gRPC frame is five bytes and a message"
    );
    assert_eq!(
        r.body[0], 0,
        "busbar offers no compression, so the flag is 0"
    );
    let len = u32::from_be_bytes([r.body[1], r.body[2], r.body[3], r.body[4]]) as usize;
    assert_eq!(r.body.len(), 5 + len, "the prefix must describe the frame");
    <T as prost::Message>::decode(&r.body[5..]).expect("the frame decodes as the rpc's request")
}

fn grpc_working() -> String {
    as_fixture(&grpc_frame(&a2a_pb::proto::SendMessageResponse {
        payload: Some(a2a_pb::proto::send_message_response::Payload::Task(
            a2a_pb::proto::Task {
                id: BACKEND_TASK.to_string(),
                context_id: "BACKEND-OWN-CONTEXT".to_string(),
                status: Some(a2a_pb::proto::TaskStatus {
                    state: a2a_pb::proto::TaskState::Working as i32,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )),
    }))
}

fn grpc_config_message() -> a2a_pb::proto::TaskPushNotificationConfig {
    a2a_pb::proto::TaskPushNotificationConfig {
        id: pushback::config_id(BACKEND_TASK),
        task_id: BACKEND_TASK.to_string(),
        url: "https://busbar.example/a2a/push".to_string(),
        ..Default::default()
    }
}

fn grpc_config() -> String {
    as_fixture(&grpc_frame(&grpc_config_message()))
}

fn grpc_config_list() -> String {
    as_fixture(&grpc_frame(
        &a2a_pb::proto::ListTaskPushNotificationConfigsResponse {
            configs: vec![grpc_config_message()],
            next_page_token: String::new(),
        },
    ))
}

/// `google.protobuf.Empty` — a complete frame carrying a zero-length message, which is what the
/// withdrawal answers with. An EMPTY BODY would not be a frame at all and the reader would
/// correctly refuse it.
fn grpc_empty() -> String {
    as_fixture(&[0, 0, 0, 0, 0])
}

#[tokio::test]
async fn grpc_client_issues_create_task_push_notification_config() {
    let h = harness_on(
        in_turn(200, vec![grpc_working(), grpc_config()]),
        BINDING_GRPC,
    )
    .await;
    let task = open_a_task(&h, &v10_submission()).await;
    let before = h.sent().len();
    let sent = issued_last(&h, before, &create_call(&task)).await;
    assert_eq!(
        path_of(&sent),
        "/lf.a2a.v1.A2AService/CreateTaskPushNotificationConfig"
    );
    let req: a2a_pb::proto::TaskPushNotificationConfig = grpc_message(&sent);
    assert_eq!(req.task_id, BACKEND_TASK);
    assert_eq!(req.id, our_config_id());
    assert_eq!(req.url, "https://busbar.example/a2a/push");
    let token = req
        .authentication
        .as_ref()
        .map(|a| a.credentials.clone())
        .unwrap_or_default();
    assert!(
        token.starts_with(&format!("{task}.")),
        "the rpc must carry the capability busbar minted for THIS task"
    );
}

#[tokio::test]
async fn grpc_client_issues_get_task_push_notification_config() {
    let h = harness_on(
        in_turn(200, vec![grpc_working(), grpc_config(), grpc_config()]),
        BINDING_GRPC,
    )
    .await;
    let task = open_and_register(&h, &v10_submission()).await;
    let before = h.sent().len();
    let sent = issued_last(
        &h,
        before,
        &envelope_for(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "taskId": task, "id": CALLER_CONFIG_ID }),
        ),
    )
    .await;
    assert_eq!(
        path_of(&sent),
        "/lf.a2a.v1.A2AService/GetTaskPushNotificationConfig"
    );
    let req: a2a_pb::proto::GetTaskPushNotificationConfigRequest = grpc_message(&sent);
    assert_eq!(req.task_id, BACKEND_TASK);
    assert_eq!(req.id, our_config_id());
}

#[tokio::test]
async fn grpc_client_issues_list_task_push_notification_configs() {
    let h = harness_on(
        in_turn(200, vec![grpc_working(), grpc_config(), grpc_config_list()]),
        BINDING_GRPC,
    )
    .await;
    let task = open_and_register(&h, &v10_submission()).await;
    let before = h.sent().len();
    let sent = issued_last(
        &h,
        before,
        &envelope_for(
            "ListTaskPushNotificationConfigs",
            serde_json::json!({ "taskId": task }),
        ),
    )
    .await;
    assert_eq!(
        path_of(&sent),
        "/lf.a2a.v1.A2AService/ListTaskPushNotificationConfigs"
    );
    let req: a2a_pb::proto::ListTaskPushNotificationConfigsRequest = grpc_message(&sent);
    assert_eq!(req.task_id, BACKEND_TASK);
}

#[tokio::test]
async fn grpc_client_issues_delete_task_push_notification_config() {
    let h = harness_on(
        in_turn(200, vec![grpc_working(), grpc_config(), grpc_empty()]),
        BINDING_GRPC,
    )
    .await;
    let task = open_and_register(&h, &v10_submission()).await;
    let before = h.sent().len();
    let sent = issued_last(
        &h,
        before,
        &envelope_for(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "taskId": task, "id": CALLER_CONFIG_ID }),
        ),
    )
    .await;
    assert_eq!(
        path_of(&sent),
        "/lf.a2a.v1.A2AService/DeleteTaskPushNotificationConfig"
    );
    let req: a2a_pb::proto::DeleteTaskPushNotificationConfigRequest = grpc_message(&sent);
    assert_eq!(req.task_id, BACKEND_TASK);
    assert_eq!(req.id, our_config_id());
}

// ══ THE PROPERTIES THAT HOLD ACROSS ALL THREE LEGS ═══════════════════════════════════════════════

/// **THE WHOLE POINT OF SUBSTITUTING RATHER THAN RELAYING.**
///
/// The caller's webhook URL, the caller's webhook credential and the caller's own config id are
/// scanned for on EVERY byte of EVERY request busbar made, in the five encodings
/// `relay_harness::encodings` defines, on all three bindings. Relaying the caller's config — the
/// obvious implementation, and the one this is not — would put all three on the wire, and then the
/// backend would call the caller's receiver directly: around busbar's SSRF guard, outside busbar's
/// provenance, holding a secret the caller gave BUSBAR to present.
#[tokio::test]
async fn the_substituted_registration_carries_neither_the_callers_url_nor_its_secret() {
    for (binding, outcome, submission) in [
        (
            BINDING_JSONRPC,
            in_turn(200, vec![jsonrpc_working(), jsonrpc_config()]),
            submission(),
        ),
        (
            BINDING_HTTP_JSON,
            in_turn(200, vec![rest_working(), rest_config()]),
            submission(),
        ),
        (
            BINDING_GRPC,
            in_turn(200, vec![grpc_working(), grpc_config()]),
            v10_submission(),
        ),
    ] {
        let h = harness_on(outcome, binding).await;
        let task = open_a_task(&h, &submission).await;
        let before = h.sent().len();
        // The registration must have REACHED the wire, or the scan below is scanning nothing.
        let _ = issued_last(&h, before, &create_call(&task)).await;
        let wire = h.all_wire();
        for secret in [CALLER_HOOK, CALLER_SECRET, CALLER_CONFIG_ID] {
            for (encoding, needle) in encodings(secret) {
                assert!(
                    !contains(&wire, &needle),
                    "{binding}: the caller's own `{secret}` reached the backend hop, \
                     {encoding}-encoded. busbar SUBSTITUTES its callback; it does not relay the \
                     caller's."
                );
            }
        }
        // AND THE CALLER'S BUSBAR KEY, which never travels on any hop on this plane.
        for (encoding, needle) in encodings(&h.bearer) {
            assert!(
                !contains(&wire, &needle),
                "{binding}: the caller's busbar key reached the backend hop, {encoding}-encoded"
            );
        }
    }
}

/// A READ THAT DOES NOT FIND BUSBAR'S OWN REGISTRATION RE-ARMS IT.
///
/// This is the only reason issuing the read is worth a hop. busbar's answer to a caller's `get`
/// asserts that this callback will fire, and that assertion is true only while busbar's own
/// registration is still live at the agent — so a read that comes back without it has discovered a
/// callback armed at busbar and dead at the backend, and the create that follows is the repair.
#[tokio::test]
async fn a_read_that_does_not_find_busbars_registration_re_arms_it() {
    // The third answer is a config belonging to SOMEBODY ELSE: a well-formed answer that does not
    // name busbar's own id, which is exactly what a backend that dropped the registration returns.
    let stranger = serde_json::json!({
        "jsonrpc": "2.0", "id": 0,
        "result": { "taskId": BACKEND_TASK, "id": "somebody-elses-config",
                    "url": "https://elsewhere.test/hook" }
    })
    .to_string();
    let h = harness_on(
        in_turn(
            200,
            vec![
                jsonrpc_working(),
                jsonrpc_config(),
                stranger,
                jsonrpc_config(),
            ],
        ),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_and_register(&h, &submission()).await;
    let before = h.sent().len();
    let (status, body) = call_agent(
        &h,
        "planner",
        &envelope_for(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "taskId": task, "id": CALLER_CONFIG_ID }),
        ),
    )
    .await;
    assert_eq!(status, 200, "the caller's own read still succeeds: {body}");
    let after: Vec<Recorded> = h.sent().split_off(before);
    let methods: Vec<String> = after
        .iter()
        .map(|r| {
            body_json(r)
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert_eq!(
        methods,
        vec![
            "GetTaskPushNotificationConfig".to_string(),
            "CreateTaskPushNotificationConfig".to_string()
        ],
        "a read that did not find busbar's registration must re-make it"
    );
}

/// A TASK BUSBAR ALREADY HOLDS AS TERMINAL IS NOT ARMED.
///
/// Registering a callback for work that is over would be arming a webhook for an event that cannot
/// happen, and it would hand a backend a live capability for a task with nothing left to report.
/// This asserts the ABSENCE of a hop, which is the only thing that can tell "did not register" from
/// "registered and the fixture happened to answer".
#[tokio::test]
async fn a_terminal_task_is_not_armed_at_the_backend() {
    let h = harness_on(
        in_turn(200, vec![backend_ok(), jsonrpc_config()]),
        BINDING_JSONRPC,
    )
    .await;
    // `backend_ok` answers COMPLETED, so busbar records the task as terminal.
    let task = open_a_task(&h, &submission()).await;
    let before = h.sent().len();
    let (status, body) = call_agent(&h, "planner", &create_call(&task)).await;
    assert_eq!(
        status, 200,
        "the caller's own registration is still busbar's to accept: {body}"
    );
    assert_eq!(
        h.sent().len(),
        before,
        "busbar must make NO hop for a task it holds as terminal: {:?}",
        h.sent().split_off(before)
    );
}

// ══ THE ENDPOINT THE SUBSTITUTION POINTS A BACKEND AT ════════════════════════════════════════════

/// POST one push notification to busbar's own callback, with `token` as the bearer.
async fn push_to_busbar(h: &Harness, token: &str, document: &serde_json::Value) -> u16 {
    let mut req = reqwest::Client::new()
        .post(format!("http://{}/a2a/push", h.addr))
        .header("content-type", "application/json")
        .json(document);
    if !token.is_empty() {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    req.send()
        .await
        .expect("the push completes")
        .status()
        .as_u16()
}

/// The token busbar registered for `task`, read off the request it actually sent — never re-minted
/// by the test. A test that minted its own would be proving that two copies of one formula agree.
fn token_on_the_wire(sent: &Recorded) -> String {
    body_json(sent)["params"]["authentication"]["credentials"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// THE ROUND TRIP: a backend reports a task busbar was not holding open, busbar records it, and the
/// CALLER'S OWN WEBHOOK is delivered — by busbar, at the address busbar guarded, with the credential
/// the caller gave busbar to present.
///
/// This is the capability the whole substitution exists for. Before it, this delivery did not
/// happen at all: busbar delivered only on transitions it observed while holding a relayed request
/// open, so a task finished out of band notified nobody.
#[tokio::test]
async fn a_pushed_state_reaches_the_callers_own_webhook_through_busbar() {
    let h = harness_on(
        in_turn(200, vec![jsonrpc_working(), jsonrpc_config()]),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_a_task(&h, &submission()).await;
    let before = h.sent().len();
    let registration = issued_last(&h, before, &create_call(&task)).await;
    let token = token_on_the_wire(&registration);
    let after_registration = h.sent().len();

    let status = push_to_busbar(
        &h,
        &token,
        &serde_json::json!({ "id": BACKEND_TASK, "kind": "task",
                             "status": { "state": "completed" } }),
    )
    .await;
    assert_eq!(status, 202, "a well-formed push is taken");

    // THE DELIVERY IS DETACHED, so it is waited for rather than assumed — and the wait ENDS IN A
    // PANIC rather than in a skip.
    let delivered = wait_for_hop(&h, after_registration).await;
    assert_eq!(
        delivered.url, CALLER_HOOK,
        "the delivery must go to the CALLER's own webhook"
    );
    let presented = delivered
        .headers
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    assert_eq!(
        presented,
        format!("Bearer {CALLER_SECRET}"),
        "the caller's own webhook credential is presented at the caller's own webhook"
    );
}

/// Wait for one more request to reach the seam, and PANIC if none does.
///
/// A bounded poll rather than a sleep, and a panic rather than a skip: a test that quietly passed
/// when the delivery never happened would be certifying the exact silence this feature removes.
async fn wait_for_hop(h: &Harness, before: usize) -> Recorded {
    for _ in 0..200 {
        let sent = h.sent();
        if sent.len() > before {
            return sent.into_iter().next_back().expect("just checked");
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("busbar made no delivery for a pushed state within five seconds");
}

/// EVERY WAY OF NOT HOLDING A TOKEN IS ONE `401`.
///
/// No token, a token that is not one, a token whose MAC does not verify, and a token for a task
/// this presenter was never given — one answer for all of them, because telling them apart is how a
/// task id is confirmed by probing.
#[tokio::test]
async fn the_callback_endpoint_refuses_everything_but_the_token_busbar_minted() {
    let h = harness_on(
        in_turn(200, vec![jsonrpc_working(), jsonrpc_config()]),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_a_task(&h, &submission()).await;
    let before = h.sent().len();
    let registration = issued_last(&h, before, &create_call(&task)).await;
    let good = token_on_the_wire(&registration);
    assert!(!good.is_empty(), "the registration carried no token");

    // The MAC, flipped in its last character. Same shape, same task, wrong signature.
    let mut tampered = good.clone();
    let last = tampered.pop().unwrap_or('0');
    tampered.push(if last == '0' { '1' } else { '0' });

    let document = serde_json::json!({ "id": BACKEND_TASK, "kind": "task",
                                       "status": { "state": "completed" } });
    for (what, presented) in [
        ("no token at all", String::new()),
        ("a value that is not a token", "not-a-token".to_string()),
        ("a tampered MAC", tampered),
        (
            "a token for another task",
            format!("some-other-task.{}", good.rsplit('.').next().unwrap_or("")),
        ),
    ] {
        assert_eq!(
            push_to_busbar(&h, &presented, &document).await,
            401,
            "the callback endpoint admitted {what}"
        );
    }
}

// ══ THE TOKEN AND THE ADDRESS, AS VALUES ═════════════════════════════════════════════════════════

/// A MINTED TOKEN VERIFIES FOR ITS OWN TASK AND FOR NO OTHER.
#[test]
fn a_token_names_exactly_one_task() {
    let a = pushback::mint("task-a").expect("a process with a CSPRNG mints");
    let b = pushback::mint("task-b").expect("a process with a CSPRNG mints");
    assert_ne!(a, b, "two tasks must not share a capability");
    assert!(
        a.as_str().starts_with("task-a."),
        "the token names its task: {}",
        a.as_str()
    );
}

/// **BUSBAR NEVER OFFERS A BACKEND A PLAINTEXT ADDRESS FOR ITSELF.**
///
/// busbar refuses plaintext callbacks from its own callers, and handing a backend a plaintext
/// address for busbar would be busbar doing on a caller's behalf the thing it refuses — with the
/// task capability in cleartext on the wire. There is no knob and there is not going to be one:
/// `PUSH-DELIVER-001/002/003` are waived permanently for the same rule
/// (`testing/a2a-tck/WAIVERS.md`), and this is that rule stated in the other direction.
#[test]
fn no_plaintext_address_is_ever_offered_to_a_backend() {
    assert_eq!(
        pushback::callback_url("https://busbar.example"),
        Some("https://busbar.example/a2a/push".to_string())
    );
    assert_eq!(
        pushback::callback_url("https://busbar.example/"),
        Some("https://busbar.example/a2a/push".to_string()),
        "a trailing slash on the operator's public url is not a second address"
    );
    for plaintext in [
        "http://busbar.example",
        "http://127.0.0.1:8080",
        "not a url at all",
    ] {
        assert_eq!(
            pushback::callback_url(plaintext),
            None,
            "busbar offered a backend `{plaintext}` as its own callback"
        );
    }
}

/// THE MIRRORING RULE, AS A TABLE. A fifth push verb is a deliberate line in `mirrored_verb` rather
/// than a branch somebody forgets in one arm — and the two local verbs that name no registration at
/// a backend mirror onto nothing, which is a statement rather than an omission.
#[test]
fn every_push_config_verb_mirrors_and_nothing_else_does() {
    use crate::a2a::local::{Dialect, LocalVerb};
    assert_eq!(
        pushback::mirrored_verb(LocalVerb::CreatePushConfig(Dialect::V03)),
        Some("CreateTaskPushNotificationConfig"),
        "a v0.3 caller's spelling must mirror onto the v1.0 verb, because the two non-JSON-RPC \
         bindings have no v0.3 form at all"
    );
    assert_eq!(
        pushback::mirrored_verb(LocalVerb::GetPushConfig(Dialect::V10)),
        Some("GetTaskPushNotificationConfig")
    );
    assert_eq!(
        pushback::mirrored_verb(LocalVerb::ListPushConfigs(Dialect::V10)),
        Some("ListTaskPushNotificationConfigs")
    );
    assert_eq!(
        pushback::mirrored_verb(LocalVerb::DeletePushConfig(Dialect::V10)),
        Some("DeleteTaskPushNotificationConfig")
    );
    assert_eq!(pushback::mirrored_verb(LocalVerb::ListTasks), None);
    assert_eq!(pushback::mirrored_verb(LocalVerb::Subscribe), None);
}
