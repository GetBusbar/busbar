// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REQUESTS BUSBAR ORIGINATES, ON EACH BINDING (the engine's `pushback_tests.rs`
//! `*_client_issues_*_task_push_notification_config(s)` and `client_leg_tests.rs`
//! `*_client_issues_list_tasks`, ported): busbar's own registration mirrored onto the agent, and
//! the `ListTasks` that refreshes busbar's rows, as each binding puts them on the wire, and the
//! agent's answer read back. The gRPC oracle is the generated `pb` messages, decoded and encoded
//! with `prost` directly.

use super::*;
use crate::proto::pb;
use prost::Message as _;
use serde_json::json;

/// The agent's own id for the task.
const BACKEND_TASK: &str = "BACKEND-OWN-TASK-ID";

/// busbar's own callback.
const OURS: &str = "https://busbar.example/a2a/push";

/// The operator's `url:` for the agent.
const URL: &str = "https://backend.agent.test/a2a";

fn create() -> Value {
    create_params(BACKEND_TASK, OURS, "busbar-t.sig")
}

/// The request busbar originates for `method` on `binding`.
fn issued(binding: Binding, method: &str) -> busbar_contract::abi::sdk::exchange::Request {
    let params = params_for(method, BACKEND_TASK, &create());
    request(binding, URL, "1.0", method, &params).expect("the request is framed")
}

fn target(r: &busbar_contract::abi::sdk::exchange::Request) -> String {
    String::from_utf8_lossy(&r.target).into_owned()
}

/// One message in its length-prefixed form, as the grpc transport hands an answer back.
fn framed<M: prost::Message>(message: &M) -> Vec<u8> {
    let body = message.encode_to_vec();
    let mut out = vec![0u8];
    out.extend_from_slice(&u32::try_from(body.len()).expect("small").to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn config() -> pb::TaskPushNotificationConfig {
    pb::TaskPushNotificationConfig {
        id: config_id(BACKEND_TASK),
        task_id: BACKEND_TASK.into(),
        url: OURS.into(),
        ..Default::default()
    }
}

// ── gRPC ────────────────────────────────────────────────────────────────────────────────────────

/// `grpc_client_issues_create_task_push_notification_config`: busbar's own registration, as the
/// rpc's message: the agent's task, busbar's config id, busbar's callback and the capability busbar
/// minted for that task.
#[test]
fn grpc_client_issues_create_task_push_notification_config() {
    let r = issued(Binding::Grpc, method::CREATE_PUSH_CONFIG);
    assert_eq!(r.method, b"POST");
    assert_eq!(
        target(&r),
        "/lf.a2a.v1.A2AService/CreateTaskPushNotificationConfig"
    );
    let req = pb::TaskPushNotificationConfig::decode(r.body.as_slice()).expect("the rpc's request");
    assert_eq!(req.task_id, BACKEND_TASK);
    assert_eq!(req.id, config_id(BACKEND_TASK));
    assert_eq!(req.url, OURS);
    assert_eq!(
        req.authentication.map(|a| a.credentials).as_deref(),
        Some("busbar-t.sig"),
        "the rpc must carry the capability busbar minted for THIS task"
    );
}

/// `grpc_client_issues_get_task_push_notification_config`, and its answer read back: the
/// registration found is no drift.
#[test]
fn grpc_client_issues_get_task_push_notification_config() {
    let r = issued(Binding::Grpc, method::GET_PUSH_CONFIG);
    assert_eq!(
        target(&r),
        "/lf.a2a.v1.A2AService/GetTaskPushNotificationConfig"
    );
    let req = pb::GetTaskPushNotificationConfigRequest::decode(r.body.as_slice()).expect("request");
    assert_eq!(req.task_id, BACKEND_TASK);
    assert_eq!(req.id, config_id(BACKEND_TASK));
    let answer = answered(Binding::Grpc, method::GET_PUSH_CONFIG, 0, framed(&config()));
    let (status, body) = answer.as_ref().expect("an answer to read");
    assert_eq!(*status, 200);
    assert!(!drifted(
        Binding::Grpc,
        answer.as_ref().map(|(s, b)| (*s, b.as_slice())),
        &config_id(BACKEND_TASK)
    ));
    let doc: Value = serde_json::from_slice(body).expect("the envelope");
    assert_eq!(doc["id"], ORIGINATED_RPC_ID);
    assert_eq!(doc["result"]["taskId"], BACKEND_TASK);
}

/// `grpc_client_issues_list_task_push_notification_configs`, and a listing that does not hold
/// busbar's registration drifted.
#[test]
fn grpc_client_issues_list_task_push_notification_configs() {
    let r = issued(Binding::Grpc, method::LIST_PUSH_CONFIGS);
    assert_eq!(
        target(&r),
        "/lf.a2a.v1.A2AService/ListTaskPushNotificationConfigs"
    );
    let req =
        pb::ListTaskPushNotificationConfigsRequest::decode(r.body.as_slice()).expect("request");
    assert_eq!(req.task_id, BACKEND_TASK);
    let held = framed(&pb::ListTaskPushNotificationConfigsResponse {
        configs: vec![config()],
        next_page_token: String::new(),
    });
    let gone = framed(&pb::ListTaskPushNotificationConfigsResponse::default());
    let read = |bytes: Vec<u8>| answered(Binding::Grpc, method::LIST_PUSH_CONFIGS, 0, bytes);
    let id = config_id(BACKEND_TASK);
    assert!(!drifted(
        Binding::Grpc,
        read(held).as_ref().map(|(s, b)| (*s, b.as_slice())),
        &id
    ));
    assert!(drifted(
        Binding::Grpc,
        read(gone).as_ref().map(|(s, b)| (*s, b.as_slice())),
        &id
    ));
    // An answer with no message to read is no answer: drifted.
    assert_eq!(read(Vec::new()), None);
}

/// `grpc_client_issues_delete_task_push_notification_config`: the withdrawal's `Empty` answer (a
/// complete, zero-length message) reads as `null`.
#[test]
fn grpc_client_issues_delete_task_push_notification_config() {
    let r = issued(Binding::Grpc, method::DELETE_PUSH_CONFIG);
    assert_eq!(
        target(&r),
        "/lf.a2a.v1.A2AService/DeleteTaskPushNotificationConfig"
    );
    let req =
        pb::DeleteTaskPushNotificationConfigRequest::decode(r.body.as_slice()).expect("request");
    assert_eq!(req.task_id, BACKEND_TASK);
    assert_eq!(req.id, config_id(BACKEND_TASK));
    let (status, body) = answered(
        Binding::Grpc,
        method::DELETE_PUSH_CONFIG,
        0,
        vec![0, 0, 0, 0, 0],
    )
    .expect("the empty message is read");
    assert_eq!(status, 200);
    let doc: Value = serde_json::from_slice(&body).expect("the envelope");
    assert_eq!(doc["result"], Value::Null);
}

/// `grpc_client_issues_list_tasks`: the refresh's `ListTasks` as the rpc, and the agent's listing
/// moving only the rows busbar can match.
#[test]
fn grpc_client_issues_list_tasks() {
    let r = request(Binding::Grpc, URL, "1.0", LIST_TASKS, &json!({})).expect("framed");
    assert_eq!(target(&r), "/lf.a2a.v1.A2AService/ListTasks");
    let _ = pb::ListTasksRequest::decode(r.body.as_slice()).expect("a ListTasksRequest");
    let listing = framed(&pb::ListTasksResponse {
        tasks: vec![pb::Task {
            id: BACKEND_TASK.into(),
            status: Some(pb::TaskStatus {
                state: pb::TaskState::Completed as i32,
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    });
    let answer = answered(Binding::Grpc, LIST_TASKS, 0, listing);
    let ours =
        std::collections::BTreeMap::from([(BACKEND_TASK.to_string(), "busbar-t".to_string())]);
    assert_eq!(
        listed_states(
            Binding::Grpc,
            answer.as_ref().map(|(s, b)| (*s, b.as_slice())),
            &ours
        ),
        vec![(
            "busbar-t".to_string(),
            crate::a2a::task::TaskState::Completed
        )]
    );
}

/// Every other binding's answer is read as it came.
#[test]
fn an_answer_on_another_binding_is_read_as_it_came() {
    for binding in [Binding::JsonRpc, Binding::HttpJson] {
        assert_eq!(
            answered(binding, LIST_TASKS, 502, b"x".to_vec()),
            Some((502, b"x".to_vec()))
        );
    }
}

// ── JSON-RPC and HTTP+JSON ──────────────────────────────────────────────────────────────────────

/// `jsonrpc_client_issues_list_tasks`: the refresh is a POST of the JSON-RPC envelope naming
/// `ListTasks` at the operator's own path.
#[test]
fn jsonrpc_client_issues_list_tasks() {
    let r = request(Binding::JsonRpc, URL, "1.0", LIST_TASKS, &json!({})).expect("framed");
    assert_eq!(r.method, b"POST");
    assert_eq!(target(&r), "/a2a");
    let doc: Value = serde_json::from_slice(&r.body).expect("JSON");
    assert_eq!(doc["jsonrpc"], "2.0");
    assert_eq!(doc["method"], "ListTasks");
}

/// `http_json_client_issues_list_tasks`: a GET of the collection, no body.
#[test]
fn http_json_client_issues_list_tasks() {
    let r = request(Binding::HttpJson, URL, "1.0", LIST_TASKS, &json!({})).expect("framed");
    assert_eq!(
        r.method, b"GET",
        "A2A binds `ListTasks` to a GET of the collection"
    );
    assert_eq!(target(&r), "/a2a/tasks");
    assert!(r.body.is_empty(), "a GET carries no body");
}

/// `http_json_client_issues_create_task_push_notification_config`: a POST to the task's config
/// collection, its body busbar's own url and config id, and no JSON-RPC envelope member.
#[test]
fn http_json_client_issues_create_task_push_notification_config() {
    let r = issued(Binding::HttpJson, method::CREATE_PUSH_CONFIG);
    assert_eq!(r.method, b"POST");
    assert_eq!(
        target(&r),
        format!("/a2a/tasks/{BACKEND_TASK}/pushNotificationConfigs")
    );
    let body: Value = serde_json::from_slice(&r.body).expect("JSON");
    assert_eq!(body["url"], OURS);
    assert_eq!(body["id"], config_id(BACKEND_TASK));
    assert!(
        body.get("jsonrpc").is_none() && body.get("method").is_none(),
        "the REST body carries no JSON-RPC envelope member: {body}"
    );
}

/// `http_json_client_issues_get_task_push_notification_config`: a GET of busbar's own config on
/// the task, no body.
#[test]
fn http_json_client_issues_get_task_push_notification_config() {
    let r = issued(Binding::HttpJson, method::GET_PUSH_CONFIG);
    assert_eq!(r.method, b"GET");
    assert_eq!(
        target(&r),
        format!(
            "/a2a/tasks/{BACKEND_TASK}/pushNotificationConfigs/{}",
            config_id(BACKEND_TASK)
        )
    );
    assert!(r.body.is_empty());
}

/// `http_json_client_issues_list_task_push_notification_configs`: a GET of the collection, not of
/// a member.
#[test]
fn http_json_client_issues_list_task_push_notification_configs() {
    let r = issued(Binding::HttpJson, method::LIST_PUSH_CONFIGS);
    assert_eq!(r.method, b"GET");
    assert_eq!(
        target(&r),
        format!("/a2a/tasks/{BACKEND_TASK}/pushNotificationConfigs")
    );
    assert!(r.body.is_empty());
}
