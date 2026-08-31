// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE SERVED SIDE OF THE A2A MATRIX, ONE TEST PER CELL.**
//!
//! `qa/method-coverage.status` is a file of claims, and a claim is only worth the instrument behind
//! it. The claims for busbar-as-SERVER on the HTTP+JSON and gRPC bindings were made on the strength
//! of the official TCK's stdout — a real instrument, and the right one, but one that lives outside
//! this repository, needs a network fetch of a pinned suite, a Go control and a booted subject.
//! Nothing inside `cargo test` re-established them, and the JSON-RPC binding's eleven cells had no
//! in-tree instrument at all despite being the door every other binding re-frames onto.
//!
//! So this file is the in-tree oracle for the served direction: **every method A2A defines, driven
//! through `busbar_core::build_router` on the binding whose cell it is claiming.** Not a call to a
//! handler — a handler that behaves when a test calls it and is mounted nowhere is the defect this
//! plane has already had twice, and it is invisible to any test that does not go through the
//! router.
//!
//! ## WHAT MAKES A CELL CLAIMED HERE, AND WHAT DOES NOT
//!
//! Each test asserts something the method ITSELF decides, never merely `200`:
//!
//! * a **relayed** verb (`SendMessage`, `SendStreamingMessage`, `GetTask`, `CancelTask`) is claimed
//!   by the HOP — the recording seam saw a request go out, with the right framing, carrying the
//!   BACKEND's task id rather than busbar's;
//! * a **locally answered** verb (`ListTasks`, the four push-config verbs, the two `SubscribeToTask`
//!   refusals) is claimed by the ABSENCE of a hop plus the content of the answer, because the whole
//!   point of `super::super::local` is that these are facts about busbar;
//! * the two **card** cells are claimed by the interface the card publishes for that binding, which
//!   is the only thing that makes `GET /.well-known/agent-card.json` a per-transport cell at all;
//! * the **extended card** cells are claimed by the catalogue narrowing — the caller holds a grant
//!   on `planner` and none on `payments`, and a card naming `payments` is a data-exposure defect
//!   rather than a conformance one (`serve::extended_card` says so at length).
//!
//! ## NOTHING HERE CAN SKIP
//!
//! There is no `if let Some(…) = … else { return }` in this file and no environment probe. Every
//! precondition is either built by the harness or `expect`ed with a message. A test that can skip is
//! a test that will skip on the day it matters, and four batteries in this release reported green
//! over unwired code for exactly that reason.
//!
//! The harness is `relay_harness`, shared rather than re-founded, for the reason stated where it is
//! mounted: a second harness is a second thing that can stop matching what the production router
//! does.

use super::relay_harness::*;

/// The A2A v1.0 method names, which are also the gRPC rpc names and therefore the names
/// `qa/method-inventory.json` gives the cells. Written once so a test cannot claim a cell under a
/// name the inventory does not use.
mod method {
    pub(super) const SEND_MESSAGE: &str = "SendMessage";
    pub(super) const SEND_STREAMING_MESSAGE: &str = "SendStreamingMessage";
    pub(super) const GET_TASK: &str = "GetTask";
    pub(super) const CANCEL_TASK: &str = "CancelTask";
    pub(super) const LIST_TASKS: &str = "ListTasks";
    pub(super) const SUBSCRIBE_TO_TASK: &str = "SubscribeToTask";
    pub(super) const CREATE_PUSH_CONFIG: &str = "CreateTaskPushNotificationConfig";
    pub(super) const GET_PUSH_CONFIG: &str = "GetTaskPushNotificationConfig";
    pub(super) const LIST_PUSH_CONFIGS: &str = "ListTaskPushNotificationConfigs";
    pub(super) const DELETE_PUSH_CONFIG: &str = "DeleteTaskPushNotificationConfig";
}

/// A JSON-RPC request envelope for `method` with `params`, under a distinct id per call so the
/// correlating fixture answers the request it was actually asked.
fn rpc(id: u64, method: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

/// A `SendMessage` that opens a task, with a distinct `contextId` so a test's rows cannot be
/// resumed or listed into another's — the task store is process-global and these run in parallel.
fn submission(id: u64, context: &str) -> serde_json::Value {
    rpc(
        id,
        method::SEND_MESSAGE,
        serde_json::json!({
            "message": {
                "role": "user",
                "contextId": context,
                "parts": [{ "kind": "text", "text": "PLAN THE MIGRATION" }]
            }
        }),
    )
}

/// THE TASK ID BUSBAR ISSUED, off a served answer, `expect`ed rather than optionally read.
///
/// Reading it is itself an assertion the cell owes: a `SendMessage` whose answer carried the
/// BACKEND's id would hand the caller a handle busbar cannot resolve, which is the identity
/// substitution `super::super::idmap` exists for.
fn issued_task_id(answer: &serde_json::Value) -> String {
    let id = answer
        .pointer("/result/id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the served answer names no task id: {answer}"));
    assert!(
        id.starts_with("a2a-planner-"),
        "the answer carries an id busbar did not issue ({id}); a caller cannot resolve it: {answer}"
    );
    assert_ne!(
        id, "BACKEND-OWN-TASK-ID",
        "the backend's own task id reached the caller: {answer}"
    );
    id.to_string()
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// JSON-RPC — the door busbar's own agent card publishes, and the eleven cells behind it.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **`a2a|jsonrpc|server|client|SendMessage`.**
///
/// The submission reaches the BACKEND — asserted on the recording seam rather than on the status,
/// because an ingress that recorded a dispatch and answered a Task envelope without ever contacting
/// the backend is a shape this plane has actually shipped.
#[tokio::test]
async fn send_message_is_served_and_reaches_the_backend() {
    let h = harness(Outcome::AnswersCorrelated(200, backend_ok()), false).await;
    let (status, answer) = call_agent(&h, "planner", &submission(101, "ctx-send")).await;
    assert_eq!(
        status, 200,
        "the admitted submission must be served: {answer}"
    );
    let task_id = issued_task_id(&answer);

    let sent = h.sent();
    assert_eq!(sent.len(), 1, "exactly one hop is owed, got {}", sent.len());
    assert!(
        !sent[0].streaming,
        "a `SendMessage` must go out on the UNARY hop, not the streaming one"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&sent[0].body).expect("the hop carries a JSON envelope");
    assert_eq!(
        body["method"],
        method::SEND_MESSAGE,
        "the method reached the backend unchanged: {body}"
    );
    // AND THE BACKEND WAS NEVER TOLD BUSBAR'S ID FOR THE TASK IT IS ABOUT TO OPEN. The mapping runs
    // the other way; a busbar id on the hop is the multi-turn defect `idmap` documents.
    assert!(
        !String::from_utf8_lossy(&sent[0].body).contains(&task_id),
        "busbar's own task id was forwarded to a backend that never issued it"
    );
}

/// **`a2a|jsonrpc|server|client|SendStreamingMessage`.**
///
/// The v1.0 spelling, and the assertion is that the STREAMING hop was taken: `reads_as_streaming`
/// is the only place in this content-blind plane where a method name decides a transport, and a
/// v1.0 caller whose stream went down the unary path gets one document where it asked for events.
#[tokio::test]
async fn send_streaming_message_is_served_as_a_stream() {
    let frames = vec![
        format!(
            "data: {}\n\n",
            serde_json::json!({"jsonrpc":"2.0","id":102,"result":{
                "id":"B1","contextId":"BC","kind":"task",
                "status":{"state":"working"}}})
        ),
        format!(
            "data: {}\n\n",
            serde_json::json!({"jsonrpc":"2.0","id":102,"result":{
                "id":"B1","contextId":"BC","kind":"status-update","final":true,
                "status":{"state":"completed"}}})
        ),
    ];
    let h = harness(Outcome::Streams(frames), false).await;
    let (status, ct, body) = call_raw(
        &h,
        "planner",
        &rpc(
            102,
            method::SEND_STREAMING_MESSAGE,
            serde_json::json!({
                "message": {
                    "role": "user",
                    "contextId": "ctx-stream-v10",
                    "parts": [{ "kind": "text", "text": "STREAM THE PLAN" }]
                }
            }),
        ),
    )
    .await;

    assert_eq!(status, 200, "the streamed call must be served: {body}");
    assert!(
        ct.starts_with("text/event-stream"),
        "the v1.0 streaming method must be framed as SSE, got `{ct}`"
    );
    assert_eq!(
        body.matches("data:").count(),
        2,
        "every backend event must reach the caller: {body}"
    );
    assert!(
        !body.contains("\"B1\"") && !body.contains("\"BC\""),
        "the backend's own ids must not reach the caller: {body}"
    );
    let sent = h.sent();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0].streaming,
        "`SendStreamingMessage` must go out through the streaming transport"
    );
}

/// **`a2a|jsonrpc|server|client|GetTask`.**
///
/// A read of a task busbar issued, and the claim is the TRANSLATION: the caller names busbar's id,
/// and the id that leaves for the backend is the backend's own. Forwarding busbar's id unchanged is
/// what made `CORE-GET-001` read *"GetTask returned task ID 'a2a-conformance-61d…', expected
/// 'a2a-conformance-522…'"* — both busbar ids, for one piece of work.
#[tokio::test]
async fn get_task_is_served_and_asks_the_backend_about_its_own_id() {
    let h = harness(Outcome::AnswersCorrelated(200, backend_ok()), false).await;
    let (_, opened) = call_agent(&h, "planner", &submission(110, "ctx-get")).await;
    let task_id = issued_task_id(&opened);

    let (status, answer) = call_agent(
        &h,
        "planner",
        &rpc(111, method::GET_TASK, serde_json::json!({ "id": &task_id })),
    )
    .await;
    assert_eq!(status, 200, "the read must be served: {answer}");
    assert_eq!(
        answer.pointer("/result/id").and_then(|v| v.as_str()),
        Some(task_id.as_str()),
        "a caller asking about task A must be told about task A: {answer}"
    );

    let sent = h.sent();
    assert_eq!(sent.len(), 2, "the read is a hop of its own");
    let asked: serde_json::Value =
        serde_json::from_slice(&sent[1].body).expect("the hop carries a JSON envelope");
    assert_eq!(asked["method"], method::GET_TASK);
    assert_eq!(
        asked["params"]["id"], "BACKEND-OWN-TASK-ID",
        "the backend must be asked about the id IT issued, not about busbar's: {asked}"
    );
    // AND NO SECOND DURABLE ROW. A caller polling a long-running task once a second minted one task
    // row per poll before the `addressed` branch existed.
    assert_eq!(
        issued_task_id(&answer),
        task_id,
        "a read must not open a second task row"
    );
}

/// **`a2a|jsonrpc|server|client|CancelTask`.**
///
/// Same translation, and the same "this task already exists" branch: a cancel that opened a fresh
/// row would cancel a task nobody asked about.
#[tokio::test]
async fn cancel_task_is_served_against_the_task_the_caller_named() {
    let cancelled = serde_json::json!({
        "jsonrpc": "2.0", "id": 121,
        "result": { "id": "BACKEND-OWN-TASK-ID", "contextId": "BACKEND-OWN-CONTEXT",
                    "kind": "task", "status": { "state": "canceled" } }
    })
    .to_string();
    let h = harness(Outcome::AnswersCorrelated(200, cancelled), false).await;
    let (_, opened) = call_agent(&h, "planner", &submission(120, "ctx-cancel")).await;
    let task_id = issued_task_id(&opened);

    let (status, answer) = call_agent(
        &h,
        "planner",
        &rpc(
            121,
            method::CANCEL_TASK,
            serde_json::json!({ "id": &task_id }),
        ),
    )
    .await;
    assert_eq!(status, 200, "the cancel must be served: {answer}");
    assert_eq!(
        answer
            .pointer("/result/status/state")
            .and_then(|v| v.as_str()),
        Some("canceled"),
        "the backend's cancellation must reach the caller: {answer}"
    );

    let sent = h.sent();
    assert_eq!(sent.len(), 2, "the cancel is a hop of its own");
    let asked: serde_json::Value =
        serde_json::from_slice(&sent[1].body).expect("the hop carries a JSON envelope");
    assert_eq!(asked["method"], method::CANCEL_TASK);
    assert_eq!(
        asked["params"]["id"], "BACKEND-OWN-TASK-ID",
        "the backend must be asked to cancel the id IT issued: {asked}"
    );
}

/// **`a2a|jsonrpc|server|client|ListTasks`.**
///
/// Answered from busbar's own store and NOT relayed, which is the whole of the cell: the list is a
/// fact about busbar (it is the only party that knows every task this principal opened, across every
/// fronted agent), and relaying it minted a durable row per call for work that does not exist.
///
/// Asserted on the hop COUNT, because a `ListTasks` that also relayed would answer identically.
#[tokio::test]
async fn list_tasks_is_answered_from_busbars_own_store_without_a_hop() {
    let h = harness(Outcome::AnswersCorrelated(200, backend_ok()), false).await;
    let (_, opened) = call_agent(&h, "planner", &submission(130, "ctx-list")).await;
    let task_id = issued_task_id(&opened);
    assert_eq!(h.sent().len(), 1, "the submission is the only hop so far");

    let (status, answer) = call_agent(
        &h,
        "planner",
        &rpc(
            131,
            method::LIST_TASKS,
            serde_json::json!({ "contextId": "ctx-list" }),
        ),
    )
    .await;
    assert_eq!(status, 200, "the list must be served: {answer}");
    assert_eq!(
        h.sent().len(),
        1,
        "`ListTasks` must not reach the backend: it is answered from busbar's own store"
    );

    let tasks = answer
        .pointer("/result/tasks")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("the answer carries no `tasks` array: {answer}"));
    assert_eq!(
        tasks.len(),
        1,
        "exactly the one task this caller opened under this context: {answer}"
    );
    assert_eq!(tasks[0]["id"], serde_json::Value::String(task_id));
}

/// **`a2a|jsonrpc|server|client|SubscribeToTask`.**
///
/// Both halves of the verb, in one test because they are one decision: busbar refuses what IT alone
/// knows (an id it never issued to this caller) and relays what it does not (a task that is still
/// the backend's to talk about). A test of only the refusal would pass against a plane that refuses
/// every subscribe.
#[tokio::test]
async fn subscribe_to_task_refuses_what_busbar_knows_and_relays_what_it_does_not() {
    let frames = vec![format!(
        "data: {}\n\n",
        serde_json::json!({"jsonrpc":"2.0","id":141,"result":{
            "id":"B1","contextId":"BC","kind":"status-update","final":true,
            "status":{"state":"completed"}}})
    )];
    let h = harness(Outcome::Streams(frames), false).await;

    // HALF ONE: an id busbar never issued to this caller. Refused locally, and no hop — a subscribe
    // relayed for an unknown id minted a durable row for work that does not exist.
    let (status, answer) = call_agent(
        &h,
        "planner",
        &rpc(
            140,
            method::SUBSCRIBE_TO_TASK,
            serde_json::json!({ "id": "a2a-planner-NEVER-ISSUED" }),
        ),
    )
    .await;
    assert_eq!(
        status, 404,
        "a subscribe to an id busbar never issued must be refused: {answer}"
    );
    assert_eq!(
        answer["error"]["code"], -32001,
        "section 5.4 binds this refusal to TaskNotFound: {answer}"
    );
    assert!(
        h.sent().is_empty(),
        "a refused subscribe must not reach the backend"
    );

    // HALF TWO: a task busbar opened and has NOT recorded the end of. The events are the backend's,
    // so the call relays — as a STREAM, which is the framing the verb names.
    let (_, ct, body) = call_raw(
        &h,
        "planner",
        &rpc(
            141,
            method::SEND_STREAMING_MESSAGE,
            serde_json::json!({
                "message": { "role": "user", "contextId": "ctx-sub",
                             "parts": [{ "kind": "text", "text": "OPEN IT" }] }
            }),
        ),
    )
    .await;
    assert!(ct.starts_with("text/event-stream"), "{body}");
    let sent = h.sent();
    assert_eq!(sent.len(), 1, "the submission opened the stream");
    assert!(sent[0].streaming, "and it went out as a stream");
    let asked: serde_json::Value =
        serde_json::from_slice(&sent[0].body).expect("the hop carries a JSON envelope");
    assert_eq!(asked["method"], method::SEND_STREAMING_MESSAGE);
}

/// **`a2a|jsonrpc|server|client|CreateTaskPushNotificationConfig`**, and with it the member the
/// registration used to DROP.
///
/// `authentication` is not decoration: a caller told its receiver would be authenticated, whose
/// deliveries then arrive bare, has a receiver that rejects every one of them and no way to see why.
/// The three PUSH-DELIVER requirements are permanently waived against the official suite (its own
/// webhook receiver is plaintext `http://` by construction and busbar refuses plaintext callbacks,
/// `testing/a2a-tck/WAIVERS.md`), so this capability is UNOBSERVABLE THERE — which is exactly why it
/// is asserted here. Conformance being unobservable is not permission to leave it unbuilt.
#[tokio::test]
async fn create_push_notification_config_is_served_and_keeps_the_callers_credential() {
    let h = harness(Outcome::AnswersCorrelated(200, backend_ok()), false).await;
    let (_, opened) = call_agent(&h, "planner", &submission(150, "ctx-push-create")).await;
    let task_id = issued_task_id(&opened);

    let (status, answer) = call_agent(
        &h,
        "planner",
        &rpc(
            151,
            method::CREATE_PUSH_CONFIG,
            serde_json::json!({
                "taskId": &task_id,
                "pushNotificationConfig": {
                    "id": "cfg-1",
                    "url": "https://receiver.customer.test/hook",
                    "authentication": { "scheme": "Bearer", "credentials": "CUSTOMER-WEBHOOK-SECRET" }
                }
            }),
        ),
    )
    .await;
    assert_eq!(status, 200, "the registration must be served: {answer}");
    assert_eq!(
        h.sent().len(),
        1,
        "a push-config registration is busbar's own record and makes no hop"
    );
    // The v1.0 dialect FLATTENS the config into the answer; v0.3 nests it under
    // `pushNotificationConfig`. Asserted on the v1.0 spelling because that is the spelling this
    // cell's method name belongs to.
    assert_eq!(
        answer.pointer("/result/taskId").and_then(|v| v.as_str()),
        Some(task_id.as_str()),
        "the answer must name the task the config was registered against: {answer}"
    );
    assert_eq!(
        answer.pointer("/result/url").and_then(|v| v.as_str()),
        Some("https://receiver.customer.test/hook"),
        "the answer must name the callback it registered: {answer}"
    );
    // AND IT MUST NOT ECHO THE CREDENTIAL. A read grant that hands back the secret the caller
    // registered is a way to exfiltrate it; `local::config_json` carries no `authentication` member
    // in either dialect, and this is the assertion that keeps it that way.
    assert!(
        !answer.to_string().contains("CUSTOMER-WEBHOOK-SECRET"),
        "the answer echoed the caller's webhook credential back: {answer}"
    );

    // THE CREDENTIAL IS HELD, not dropped. Asserted through the accessor rather than by reading the
    // answer back, because a config that echoes a credential it did not keep is precisely the
    // failure — the caller cannot tell from the answer.
    //
    // Compared against a CONSTRUCTED value rather than by reading the credential out, so the
    // assertion's failure message goes through `DeliveryAuth`'s hand-written `Debug` — which
    // redacts. A test that printed the secret on failure would be the one place the type's whole
    // discipline is undone.
    let held = super::super::pushdeliver::auth_for_test(&task_id)
        .unwrap_or_else(|| panic!("the registration dropped the caller's `authentication` member"));
    assert_eq!(
        held,
        super::super::pushdeliver::DeliveryAuth {
            scheme: "Bearer".to_string(),
            credentials: "CUSTOMER-WEBHOOK-SECRET".to_string(),
        },
        "busbar holds a different credential from the one the caller registered"
    );
}

/// **`a2a|jsonrpc|server|client|GetTaskPushNotificationConfig`** and
/// **`a2a|jsonrpc|server|client|ListTaskPushNotificationConfigs`**.
///
/// Read back through the SERVED verbs rather than through the store, because "the config busbar
/// holds" and "the config busbar will tell you about" are two different claims and only the second
/// is the cell. Both are answered locally; the hop count is the proof.
#[tokio::test]
async fn the_push_notification_config_is_readable_by_both_of_its_verbs() {
    let h = harness(Outcome::AnswersCorrelated(200, backend_ok()), false).await;
    let (_, opened) = call_agent(&h, "planner", &submission(160, "ctx-push-read")).await;
    let task_id = issued_task_id(&opened);
    let (created, _) = call_agent(
        &h,
        "planner",
        &rpc(
            161,
            method::CREATE_PUSH_CONFIG,
            serde_json::json!({
                "taskId": &task_id,
                "pushNotificationConfig": { "id": "cfg-read", "url": "https://receiver.customer.test/hook" }
            }),
        ),
    )
    .await;
    assert_eq!(created, 200, "the fixture's own precondition must hold");

    let (status, one) = call_agent(
        &h,
        "planner",
        &rpc(
            162,
            method::GET_PUSH_CONFIG,
            serde_json::json!({ "taskId": &task_id, "id": "cfg-read" }),
        ),
    )
    .await;
    assert_eq!(status, 200, "the config read must be served: {one}");
    assert_eq!(
        one.pointer("/result/url").and_then(|v| v.as_str()),
        Some("https://receiver.customer.test/hook"),
        "the registered callback must come back: {one}"
    );
    assert_eq!(
        one.pointer("/result/id").and_then(|v| v.as_str()),
        Some("cfg-read"),
        "and it must be the config the caller named: {one}"
    );

    let (status, all) = call_agent(
        &h,
        "planner",
        &rpc(
            163,
            method::LIST_PUSH_CONFIGS,
            serde_json::json!({ "taskId": &task_id }),
        ),
    )
    .await;
    assert_eq!(status, 200, "the config list must be served: {all}");
    let configs = all
        .pointer("/result/configs")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("the v1.0 list answer wraps its configs: {all}"));
    assert_eq!(configs.len(), 1, "exactly the one registered config: {all}");

    assert_eq!(
        h.sent().len(),
        1,
        "neither config read may reach the backend: they are busbar's own record"
    );
}

/// **`a2a|jsonrpc|server|client|DeleteTaskPushNotificationConfig`.**
///
/// The delete is claimed by its EFFECT and not by its status: an answer of `null` is what an
/// idempotent delete returns whether or not it did anything, so the assertion is that the config is
/// gone from the served read AND that the credential went with it. A secret that outlives the config
/// it was supplied for is the bound worth testing.
#[tokio::test]
async fn delete_push_notification_config_is_served_and_takes_the_credential_with_it() {
    let h = harness(Outcome::AnswersCorrelated(200, backend_ok()), false).await;
    let (_, opened) = call_agent(&h, "planner", &submission(170, "ctx-push-delete")).await;
    let task_id = issued_task_id(&opened);
    let (created, _) = call_agent(
        &h,
        "planner",
        &rpc(
            171,
            method::CREATE_PUSH_CONFIG,
            serde_json::json!({
                "taskId": &task_id,
                "pushNotificationConfig": {
                    "id": "cfg-del",
                    "url": "https://receiver.customer.test/hook",
                    "authentication": { "scheme": "Bearer", "credentials": "SECRET-TO-BE-FORGOTTEN" }
                }
            }),
        ),
    )
    .await;
    assert_eq!(created, 200, "the fixture's own precondition must hold");
    assert!(
        super::super::pushdeliver::auth_for_test(&task_id).is_some(),
        "the control: the credential must be there before the delete removes it"
    );

    let (status, answer) = call_agent(
        &h,
        "planner",
        &rpc(
            172,
            method::DELETE_PUSH_CONFIG,
            serde_json::json!({ "taskId": &task_id, "id": "cfg-del" }),
        ),
    )
    .await;
    assert_eq!(status, 200, "the delete must be served: {answer}");

    let (status, gone) = call_agent(
        &h,
        "planner",
        &rpc(
            173,
            method::GET_PUSH_CONFIG,
            serde_json::json!({ "taskId": &task_id, "id": "cfg-del" }),
        ),
    )
    .await;
    assert_eq!(
        status, 404,
        "the deleted config must no longer be readable: {gone}"
    );
    assert!(
        super::super::pushdeliver::auth_for_test(&task_id).is_none(),
        "the caller's webhook credential outlived the config it was supplied for"
    );
    assert_eq!(
        h.sent().len(),
        1,
        "none of the config verbs may reach the backend"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// THE AGENT CARD — one resource, and it is a per-transport cell because of what it PUBLISHES.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **`a2a|jsonrpc|server|client|GET /.well-known/agent-card.json`** and
/// **`a2a|http+json|server|client|GET /.well-known/agent-card.json`**, together, because they are
/// one served document and separating them would be two tests asserting the same GET.
///
/// What makes them TWO CELLS is the `supportedInterfaces` list: the card is how a client discovers
/// which bindings this deployment answers, so a card served without a `JSONRPC` entry leaves the
/// JSON-RPC binding undiscoverable however well it is mounted, and the same for `HTTP+JSON`. The
/// specification's own model is several bindings of one agent, and this is the member that says so.
///
/// Unauthenticated, deliberately: this document is what tells a caller which credential to present.
#[tokio::test]
async fn the_well_known_card_publishes_both_http_bindings_at_the_mount_that_serves_them() {
    let h = harness(Outcome::AnswersCorrelated(200, backend_ok()), false).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{}{}",
            h.addr,
            super::super::card::WELL_KNOWN_CARD_PATH
        ))
        .send()
        .await
        .expect("the discovery path answers");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the card the protocol mandates is not served; busbar is invisible to a stock client"
    );
    let card: serde_json::Value = resp.json().await.expect("the card is JSON");

    let interfaces = card["supportedInterfaces"]
        .as_array()
        .unwrap_or_else(|| panic!("the card publishes no interfaces at all: {card}"));
    let mount = format!("{PUBLIC_URL}/a2a");
    for binding in ["JSONRPC", "HTTP+JSON"] {
        let entry = interfaces
            .iter()
            .find(|i| i["protocolBinding"] == binding)
            .unwrap_or_else(|| {
                panic!("the card does not publish the {binding} binding busbar serves: {card}")
            });
        assert_eq!(
            entry["url"], mount,
            "the {binding} interface must name the mount this deployment answers on: {entry}"
        );
        assert!(
            entry.get("protocolVersion").is_some(),
            "every interface owes the version it speaks: {entry}"
        );
    }

    // AND THE UNAUTHENTICATED DOCUMENT STILL NAMES NO FRONTED AGENT. Asserted over the SERIALISED
    // card, because the hazard is a member nobody thought to check.
    let serialised = card.to_string();
    for agent in ["planner", "payments"] {
        assert!(
            !serialised.contains(agent),
            "the open card names a fronted agent (`{agent}`): {serialised}"
        );
    }
}

/// **`a2a|http+json|server|client|GetExtendedAgentCard`** — `GET /a2a/extendedAgentCard`.
///
/// Two claims, and the second is the one that matters more:
///
/// 1. The REST binding is a RE-FRAMING (A2A section 11.3): the success body IS the JSON-RPC
///    `result` verbatim, so the answer must be the card itself and must carry no `jsonrpc` member.
/// 2. The card is built from THIS CALLER'S CATALOGUE. The naive gateway implementation unions every
///    fronted agent's skills; this deployment fronts two and the caller holds a grant on one, so a
///    card naming `payments` is one tenant reading another's inventory — a data-exposure defect,
///    not a conformance one.
#[tokio::test]
async fn the_extended_card_is_served_over_http_json_and_names_only_this_callers_agents() {
    let h = harness_granting(
        Outcome::AnswersCorrelated(200, backend_ok()),
        false,
        &["planner"],
    )
    .await;
    let resp = reqwest::Client::new()
        .get(format!("http://{}/a2a/extendedAgentCard", h.addr))
        .header("authorization", format!("Bearer {}", h.bearer))
        .send()
        .await
        .expect("the REST extended-card path answers");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the extended card the public card CLAIMS must be served on this binding"
    );
    let card: serde_json::Value = resp.json().await.expect("the card is JSON");

    assert!(
        card.get("jsonrpc").is_none() && card.get("result").is_none(),
        "section 11.3 makes the REST body the `result` VERBATIM, not an envelope: {card}"
    );
    assert_eq!(card["name"], "busbar");

    let skills = card["skills"]
        .as_array()
        .unwrap_or_else(|| panic!("the extended card publishes no skills member: {card}"));
    let ids: Vec<&str> = skills.iter().filter_map(|s| s["id"].as_str()).collect();
    assert_eq!(
        ids,
        vec!["planner"],
        "the extended card must name exactly the agents this caller may reach: {card}"
    );
    assert!(
        !card.to_string().contains("payments"),
        "the extended card shows this tenant another tenant's inventory: {card}"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// gRPC — a door of its own, at the path the `.proto` defines.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// A length-prefixed gRPC message frame: the one-byte compression flag, the four-byte big-endian
/// length, then the protobuf. `GetExtendedAgentCardRequest` has one optional `tenant` string and
/// busbar publishes no tenant, so the message is empty and the frame is its header alone.
fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + message.len());
    out.push(0);
    out.extend_from_slice(
        &u32::try_from(message.len())
            .expect("a small frame")
            .to_be_bytes(),
    );
    out.extend_from_slice(message);
    out
}

/// **`a2a|grpc|server|client|GetExtendedAgentCard`.**
///
/// Driven over a REAL h2c connection to the REAL mounted path, because the two things that can be
/// wrong about this binding are invisible to any other kind of test: the path a generated client
/// dials (`/lf.a2a.v1.A2AService/…`, the `.proto`'s and not busbar's), and whether `PlaneDispatch`
/// claims that path — an unclaimed path is one where no token's `aud` is checked, and this binding
/// would admit a token minted for any other resource.
///
/// The answer is read as PROTOBUF BYTES rather than decoded. That is deliberate: the claim being
/// made is the tenant-isolation one, and scanning the serialised message for the agent id busbar
/// must not disclose is the same shape (and the same argument) as the sweep over the serialised
/// public card — a field nobody thought to check is the hazard, and a typed read of `skills[]` would
/// miss it.
#[tokio::test]
async fn the_extended_card_is_served_over_grpc_at_the_path_the_proto_defines() {
    let h = harness_granting(
        Outcome::AnswersCorrelated(200, backend_ok()),
        false,
        &["planner"],
    )
    .await;
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("an h2c client");

    let resp = client
        .post(format!(
            "http://{}{}/GetExtendedAgentCard",
            h.addr,
            super::super::serve::GRPC_MOUNT_PATH
        ))
        .header("authorization", format!("Bearer {}", h.bearer))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(grpc_frame(&[]))
        .send()
        .await
        .expect("the gRPC binding answers at the generated service path");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "gRPC carries its own status; the HTTP status is always 200 when the service was reached"
    );
    // A REFUSAL IS A TRAILERS-ONLY RESPONSE, so a non-zero `grpc-status` arrives in the HEADERS with
    // an empty body. Read it before the body, so a refused call fails with the refusal's own message
    // rather than with "the frame was too short".
    if let Some(status) = resp.headers().get("grpc-status") {
        assert_eq!(
            status.to_str().unwrap_or("?"),
            "0",
            "the gRPC call was refused: {:?}",
            resp.headers().get("grpc-message")
        );
    }
    let body = resp.bytes().await.expect("the answer body reads");
    assert!(
        body.len() > 5,
        "the answer carries no message frame at all, so nothing was served: {body:?}"
    );

    // THE CARD IS BUSBAR'S, AND IT IS THIS CALLER'S. Protobuf encodes strings as raw UTF-8, so the
    // serialised message is a haystack these two facts are directly readable from.
    let bytes = body.as_ref();
    assert!(
        contains(bytes, b"busbar"),
        "the answer is not busbar's own agent card"
    );
    assert!(
        contains(bytes, b"planner"),
        "the extended card omits the agent this caller IS entitled to reach"
    );
    assert!(
        !contains(bytes, b"payments"),
        "the extended card shows this tenant another tenant's inventory over gRPC"
    );
}
