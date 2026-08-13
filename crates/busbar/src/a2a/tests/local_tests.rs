// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/a2a/local.rs` — the verbs busbar answers itself.
//!
//! ## Why every test names its own principal
//!
//! `super::super::taskstore::TASKS` is a process-global and these tests run in parallel with every
//! other test in the crate. The tenancy boundary is the principal, so a test that invents its own
//! principal is isolated by exactly the mechanism under test rather than by a lock somebody has to
//! remember to take. Two of these tests then use that same mechanism as the ASSERTION — a second
//! principal's rows must be invisible — which would be impossible against a store a test had to
//! clear first.
//!
//! ## What is asserted, and what is deliberately not
//!
//! These are decision tests. The dispatch that reaches them lives in `super::super::receive` and is
//! exercised end to end by the conformance rig; what is pinned here is the part that can be wrong
//! silently: WHICH verbs are local, what each one answers, and — most of all — the three refusals
//! that only busbar can make. A subscribe to a live task is asserted to be relayed, because a local
//! answer there would be busbar inventing the backend's events.

use super::super::local::{self, Dialect, LocalVerb};
use super::super::task::{Direction, Task, TaskState};
use super::super::taskstore::TASKS;

// ══ HELPERS ══════════════════════════════════════════════════════════════════════════════════════

/// Open a real task row for `principal` and move it to `state`.
fn open(principal: &str, task_id: &str, context_id: &str, state: TaskState, now: u64) {
    let task = Task::submitted(task_id, context_id, principal, Direction::Inbound, now)
        .expect("a task with these fields is constructible");
    TASKS.submit(&task, task_id).expect("the row records");
    if state != TaskState::Submitted {
        TASKS
            .transition(task_id, state, now, task_id)
            .expect("the transition is legal");
    }
}

fn envelope(method: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

fn rpc_id() -> serde_json::Value {
    serde_json::json!(1)
}

/// The JSON body of a response, read back off the wire the way a caller reads it.
async fn body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("the body reads");
    serde_json::from_slice(&bytes).expect("the body is JSON")
}

async fn result(response: axum::response::Response) -> serde_json::Value {
    let doc = body(response).await;
    assert!(
        doc.get("error").is_none(),
        "expected a result, got an error: {doc}"
    );
    doc.get("result").cloned().expect("a result member")
}

async fn error_code(response: axum::response::Response) -> i64 {
    let doc = body(response).await;
    doc.pointer("/error/code")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_else(|| panic!("expected an error code, got {doc}"))
}

// ══ WHICH VERBS ARE LOCAL ════════════════════════════════════════════════════════════════════════

/// The list is EXACT. A method that is not here relays unread, which is this plane's default and the
/// property content-blind dispatch is about — so an accidental addition is a silent change to
/// content-blindness, and an accidental removal is a verb going back to a backend that cannot
/// answer it.
#[test]
fn exactly_these_methods_are_answered_locally() {
    for m in [
        "ListTasks",
        "tasks/list",
        "CreateTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/set",
        "GetTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/get",
        "ListTaskPushNotificationConfigs",
        "tasks/pushNotificationConfig/list",
        "DeleteTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/delete",
        "SubscribeToTask",
        "tasks/resubscribe",
    ] {
        assert!(
            local::verb_of(m).is_some(),
            "`{m}` must be answered locally"
        );
    }
    // The submission and read verbs are the backend's work and must never appear above.
    for m in [
        "SendMessage",
        "message/send",
        "SendStreamingMessage",
        "message/stream",
        "GetTask",
        "tasks/get",
        "CancelTask",
        "tasks/cancel",
        "GetExtendedAgentCard",
    ] {
        assert!(local::verb_of(m).is_none(), "`{m}` must be relayed");
    }
}

/// The two dialects are told apart, because they disagree about the SHAPE of a config and not only
/// about the method name.
#[test]
fn the_push_verbs_carry_the_dialect_that_named_them() {
    assert_eq!(
        local::verb_of("CreateTaskPushNotificationConfig"),
        Some(LocalVerb::CreatePushConfig(Dialect::V10))
    );
    assert_eq!(
        local::verb_of("tasks/pushNotificationConfig/set"),
        Some(LocalVerb::CreatePushConfig(Dialect::V03))
    );
}

// ══ ListTasks ════════════════════════════════════════════════════════════════════════════════════

/// THE TENANCY BOUNDARY, which is the MUST this verb is graded on: a caller sees its own rows and
/// nobody else's, and the two principals' rows share a `contextId` here precisely so that the filter
/// cannot be what is doing the work.
#[tokio::test]
async fn list_tasks_returns_only_this_callers_rows() {
    let mine = "key-list-mine";
    let theirs = "key-list-theirs";
    open(mine, "lt-mine-1", "ctx-shared", TaskState::Working, 1_000);
    open(
        theirs,
        "lt-theirs-1",
        "ctx-shared",
        TaskState::Working,
        1_000,
    );

    let env = envelope(
        "ListTasks",
        serde_json::json!({ "context_id": "ctx-shared" }),
    );
    let listed = result(local::list_tasks(&env, &rpc_id(), mine)).await;
    let ids: Vec<&str> = listed["tasks"]
        .as_array()
        .expect("tasks is an array")
        .iter()
        .filter_map(|t| t["id"].as_str())
        .collect();
    assert_eq!(
        ids,
        vec!["lt-mine-1"],
        "another key's task must be invisible"
    );
}

/// Most recently updated first, and the state is the PROTOCOL's spelling rather than the store's.
#[tokio::test]
async fn list_tasks_is_newest_first_and_speaks_the_wire_state() {
    let me = "key-list-order";
    open(me, "lt-old", "ctx-order", TaskState::Working, 1_000);
    open(me, "lt-new", "ctx-order", TaskState::Completed, 2_000);

    let env = envelope(
        "ListTasks",
        serde_json::json!({ "context_id": "ctx-order" }),
    );
    let listed = result(local::list_tasks(&env, &rpc_id(), me)).await;
    let tasks = listed["tasks"].as_array().expect("tasks is an array");
    assert_eq!(tasks[0]["id"], "lt-new");
    assert_eq!(tasks[1]["id"], "lt-old");
    assert_eq!(tasks[0]["status"]["state"], "TASK_STATE_COMPLETED");
}

/// `nextPageToken` is PRESENT ON EVERY PAGE and EMPTY on the last one. A client's paging loop
/// terminates on this member, so omitting it on the final page is how the loop becomes infinite.
#[tokio::test]
async fn list_tasks_pages_by_cursor_and_ends_with_an_empty_token() {
    let me = "key-list-page";
    for (i, id) in ["lt-p1", "lt-p2", "lt-p3"].iter().enumerate() {
        open(
            me,
            id,
            "ctx-page",
            TaskState::Working,
            1_000 + i as u64 * 10,
        );
    }

    let first = result(local::list_tasks(
        &envelope(
            "ListTasks",
            serde_json::json!({ "context_id": "ctx-page", "page_size": 2 }),
        ),
        &rpc_id(),
        me,
    ))
    .await;
    assert_eq!(first["tasks"].as_array().expect("array").len(), 2);
    let token = first["nextPageToken"].as_str().expect("a token member");
    assert!(
        !token.is_empty(),
        "a page with more behind it carries a cursor"
    );

    let second = result(local::list_tasks(
        &envelope(
            "ListTasks",
            serde_json::json!({ "context_id": "ctx-page", "page_size": 2, "page_token": token }),
        ),
        &rpc_id(),
        me,
    ))
    .await;
    let rest = second["tasks"].as_array().expect("array");
    assert_eq!(rest.len(), 1, "the cursor resumes after the first page");
    assert_eq!(
        rest[0]["id"], "lt-p1",
        "and the order is unchanged across it"
    );
    assert_eq!(
        second["nextPageToken"], "",
        "the final page's token must be present and empty"
    );
}

/// NO `artifacts`, NO `history` AND NO `status.timestamp`. busbar retains none of the first two and
/// holds an observation time rather than the agent's status time for the third, so publishing any of
/// them would be busbar filling a slot with something it does not have.
#[tokio::test]
async fn list_tasks_publishes_only_what_busbar_holds() {
    let me = "key-list-shape";
    open(me, "lt-shape", "ctx-shape", TaskState::Completed, 1_000);
    let listed = result(local::list_tasks(
        &envelope(
            "ListTasks",
            serde_json::json!({ "context_id": "ctx-shape", "include_artifacts": true }),
        ),
        &rpc_id(),
        me,
    ))
    .await;
    let task = &listed["tasks"][0];
    assert!(
        task.get("artifacts").is_none(),
        "busbar retains no artifacts"
    );
    assert!(task.get("history").is_none(), "busbar retains no history");
    assert!(
        task["status"].get("timestamp").is_none(),
        "busbar holds its own observation time, not the agent's status time"
    );
}

// ══ SubscribeToTask ══════════════════════════════════════════════════════════════════════════════

/// THE DEFAULT IS STILL RELAY. A live task this caller owns produces NO local answer, because its
/// events are the backend's and inventing them is the failure this whole module is bounded to avoid.
#[test]
fn subscribing_to_a_live_task_is_relayed() {
    let me = "key-sub-live";
    open(me, "sub-live", "ctx-sub", TaskState::Working, 1_000);
    let env = envelope("SubscribeToTask", serde_json::json!({ "id": "sub-live" }));
    assert!(
        local::subscribe_refusal(&env, &rpc_id(), me).is_none(),
        "a live task's events are the backend's"
    );
}

/// A terminal task earns `UnsupportedOperation` (-32004): busbar recorded the ending itself, so
/// there is nothing further to subscribe to.
#[tokio::test]
async fn subscribing_to_a_terminal_task_is_refused() {
    let me = "key-sub-done";
    open(me, "sub-done", "ctx-sub", TaskState::Completed, 1_000);
    let env = envelope("SubscribeToTask", serde_json::json!({ "id": "sub-done" }));
    let refusal =
        local::subscribe_refusal(&env, &rpc_id(), me).expect("a terminal task is refused");
    assert_eq!(error_code(refusal).await, -32004);
}

/// An id busbar never issued, and ANOTHER PRINCIPAL'S id, earn the SAME `TaskNotFound` (-32001).
/// Relayed, both of these reached a backend that had never heard of the id and an accommodating one
/// opened a stream — a caller handed a live subscription to work that does not exist.
#[tokio::test]
async fn subscribing_to_an_unknown_or_foreign_task_is_task_not_found() {
    let me = "key-sub-unknown";
    let other = "key-sub-owner";
    open(other, "sub-foreign", "ctx-sub", TaskState::Working, 1_000);

    let unknown = envelope(
        "SubscribeToTask",
        serde_json::json!({ "id": "no-such-task-at-all" }),
    );
    let refusal = local::subscribe_refusal(&unknown, &rpc_id(), me).expect("refused");
    assert_eq!(error_code(refusal).await, -32001);

    let foreign = envelope(
        "SubscribeToTask",
        serde_json::json!({ "id": "sub-foreign" }),
    );
    let refusal = local::subscribe_refusal(&foreign, &rpc_id(), me).expect("refused");
    assert_eq!(
        error_code(refusal).await,
        -32001,
        "another tenant's id must be indistinguishable from a nonexistent one"
    );
}

// ══ PUSH-CONFIG CRUD ═════════════════════════════════════════════════════════════════════════════

/// The seam a create needs, answering one public address so the SSRF guard has something to pass.
fn seam() -> std::sync::Arc<dyn super::super::relay::RelaySeam> {
    use super::super::fetch::{FetchPolicy, HttpResponse, Resolver};
    use super::super::relay::{ChunkFlow, RelaySeam, RelayTransport, StreamHead};
    use std::net::{IpAddr, Ipv4Addr};

    struct PublicResolver;
    impl Resolver for PublicResolver {
        fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
        }
    }
    struct NoTransport;
    impl RelayTransport for NoTransport {
        fn send(
            &self,
            _http_method: &str,
            _url: &reqwest::Url,
            _addr: IpAddr,
            _headers: &[(String, String)],
            _body: &[u8],
        ) -> Result<HttpResponse, String> {
            Err("this test opens no socket".to_string())
        }
        fn post_stream(
            &self,
            _url: &reqwest::Url,
            _addr: IpAddr,
            _headers: &[(String, String)],
            _body: &[u8],
            _on_chunk: &mut (dyn FnMut(&[u8]) -> ChunkFlow + Send),
        ) -> Result<StreamHead, String> {
            Err("this test opens no socket".to_string())
        }
    }
    struct Seam(FetchPolicy);
    impl RelaySeam for Seam {
        fn resolver(&self) -> &dyn Resolver {
            &PublicResolver
        }
        fn transport(&self) -> &dyn RelayTransport {
            &NoTransport
        }
        fn policy(&self) -> &FetchPolicy {
            &self.0
        }
    }
    std::sync::Arc::new(Seam(FetchPolicy::default()))
}

const HOOK: &str = "https://hook.caller.test/notify";

/// The whole CRUD round trip, terminated at busbar: create, read back, list, delete, and the read
/// after the delete. The backend agent is never asked, and there is no backend in this test to ask.
#[tokio::test]
async fn a_push_config_is_created_read_listed_and_deleted_at_busbar() {
    let me = "key-push-crud";
    open(me, "push-crud", "ctx-push", TaskState::Completed, 1_000);

    let created = result(
        local::create_push_config(
            Dialect::V10,
            &envelope(
                "CreateTaskPushNotificationConfig",
                serde_json::json!({ "task_id": "push-crud", "id": "cfg-1", "url": HOOK }),
            ),
            &rpc_id(),
            me,
            seam(),
            1_000,
        )
        .await,
    )
    .await;
    assert_eq!(created["id"], "cfg-1");
    assert_eq!(created["url"], HOOK);
    assert_eq!(created["taskId"], "push-crud");

    // THE DURABLE ROW CARRIES THE CALLBACK, which is what makes the delivery path — unchanged by
    // this module — able to find it.
    assert_eq!(
        TASKS
            .get_scoped(me, "push-crud")
            .expect("the row is this caller's")
            .push_callback
            .as_deref(),
        Some(HOOK)
    );

    let read = result(local::get_push_config(
        Dialect::V10,
        &envelope(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-crud", "id": "cfg-1" }),
        ),
        &rpc_id(),
        me,
    ))
    .await;
    assert_eq!(read["url"], HOOK);

    let listed = result(local::list_push_configs(
        Dialect::V10,
        &envelope(
            "ListTaskPushNotificationConfigs",
            serde_json::json!({ "task_id": "push-crud" }),
        ),
        &rpc_id(),
        me,
    ))
    .await;
    assert_eq!(listed["configs"].as_array().expect("array").len(), 1);

    let deleted = local::delete_push_config(
        &envelope(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-crud", "id": "cfg-1" }),
        ),
        &rpc_id(),
        me,
        1_001,
    );
    assert!(
        body(deleted).await.get("error").is_none(),
        "a delete succeeds"
    );

    // AND THE CALLBACK IS OFF THE ROW. A deleted config that still receives the completion is the
    // one outcome a delete exists to prevent.
    assert_eq!(
        TASKS
            .get_scoped(me, "push-crud")
            .expect("row")
            .push_callback,
        None
    );

    let gone = local::get_push_config(
        Dialect::V10,
        &envelope(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-crud", "id": "cfg-1" }),
        ),
        &rpc_id(),
        me,
    );
    assert_eq!(error_code(gone).await, -32001);
}

/// A second delete is not an error. A client retrying a delete after a timeout must not be told its
/// retry failed for doing exactly what the first attempt already achieved.
#[tokio::test]
async fn deleting_an_absent_config_is_idempotent() {
    let me = "key-push-idem";
    open(me, "push-idem", "ctx-push", TaskState::Completed, 1_000);
    let response = local::delete_push_config(
        &envelope(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-idem", "id": "never-registered" }),
        ),
        &rpc_id(),
        me,
        1_000,
    );
    assert!(body(response).await.get("error").is_none());
}

/// THE SSRF GUARD RUNS ON THIS PATH TOO, and it is the CALLER's fault. A callback registered by the
/// CRUD verb and a callback registered inline on a submission must be judged by one rule; two rules
/// is how one of them becomes the way around the other.
#[tokio::test]
async fn a_private_callback_is_refused_by_the_same_guard_as_the_inline_path() {
    let me = "key-push-ssrf";
    open(me, "push-ssrf", "ctx-push", TaskState::Completed, 1_000);
    let refused = local::create_push_config(
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({
                "task_id": "push-ssrf",
                "id": "cfg-ssrf",
                "url": "https://169.254.169.254/latest/meta-data",
            }),
        ),
        &rpc_id(),
        me,
        seam(),
        1_000,
    )
    .await;
    assert_eq!(error_code(refused).await, -32602);
    assert_eq!(
        TASKS
            .get_scoped(me, "push-ssrf")
            .expect("row")
            .push_callback,
        None,
        "a refused callback must not reach the durable row"
    );
}

/// A CONFIG NAMING A CREDENTIAL IS ACCEPTED, STORED, AND PRESENTED ON DELIVERY.
///
/// It used to be REFUSED, on the argument that the delivery sent no credential — which was a true
/// statement about the delivery and an unbuildable position for a customer, because a receiver that
/// cannot authenticate its caller has to treat the webhook URL itself as the secret. So this asserts
/// the three things that make the capability real: the verb succeeds, the credential reaches the
/// delivery path, and the read verb does NOT hand it back.
#[tokio::test]
async fn a_config_naming_credentials_is_stored_and_presented_but_never_echoed_back() {
    let me = "key-push-auth";
    open(me, "push-auth", "ctx-push", TaskState::Completed, 1_000);
    let created = local::create_push_config(
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({
                "task_id": "push-auth",
                "id": "cfg-auth",
                "url": HOOK,
                "authentication": { "scheme": "Bearer", "credentials": "s3cret" },
            }),
        ),
        &rpc_id(),
        me,
        seam(),
        1_000,
    )
    .await;
    let doc = result(created).await;
    assert_eq!(doc["url"], HOOK, "{doc}");

    // THE CREDENTIAL REACHED THE PATH THAT SENDS IT.
    let held = super::super::pushdeliver::auth_for_test("push-auth").expect("a stored credential");
    assert_eq!(held.scheme, "Bearer");

    // AND THE READ VERB DOES NOT RETURN IT. A `get` needs only a task id and a config id, so a
    // response carrying the secret would turn every read grant into a way to exfiltrate it.
    let read = local::get_push_config(
        Dialect::V10,
        &envelope(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-auth", "id": "cfg-auth" }),
        ),
        &rpc_id(),
        me,
    );
    let echoed = result(read).await;
    assert!(
        !echoed.to_string().contains("s3cret"),
        "a read verb echoed the caller's webhook credential: {echoed}"
    );
}

/// AN `authentication` BUSBAR CANNOT PUT ON A HEADER IS REFUSED AS THE CALLER'S FAULT, rather than
/// accepted and silently not sent — which is the exact failure the whole member is replacing. And
/// the refusal does not quote the credential back, because a message that does puts the secret in
/// the caller's logs, the proxy's logs and busbar's own error path.
#[tokio::test]
async fn an_authentication_block_with_no_scheme_is_refused_without_echoing_the_secret() {
    let me = "key-push-noscheme";
    open(me, "push-noscheme", "ctx-push", TaskState::Completed, 1_000);
    let refused = local::create_push_config(
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({
                "task_id": "push-noscheme",
                "id": "cfg-noscheme",
                "url": HOOK,
                "authentication": { "credentials": "s3cret" },
            }),
        ),
        &rpc_id(),
        me,
        seam(),
        1_000,
    )
    .await;
    let doc = body(refused).await;
    assert_eq!(
        doc.pointer("/error/code").and_then(|v| v.as_i64()),
        Some(-32602),
        "{doc}"
    );
    assert!(
        !doc.to_string().contains("s3cret"),
        "the refusal quoted the caller's credential back: {doc}"
    );
}

/// `token` STAYS REFUSED, and the distinction from `authentication` is the point. There is no
/// header or body member the delivery puts a v0.3 `token` in, so storing it would promise the
/// receiver a value it never sees — which is precisely the argument that was wrongly applied to
/// `authentication`.
#[tokio::test]
async fn a_config_naming_a_v03_token_is_still_refused_because_nothing_carries_it() {
    let me = "key-push-token";
    open(me, "push-token", "ctx-push", TaskState::Completed, 1_000);
    let refused = local::create_push_config(
        Dialect::V03,
        &envelope(
            "tasks/pushNotificationConfig/set",
            serde_json::json!({
                "task_id": "push-token",
                "pushNotificationConfig": { "id": "cfg-token", "url": HOOK, "token": "opaque" },
            }),
        ),
        &rpc_id(),
        me,
        seam(),
        1_000,
    )
    .await;
    assert_eq!(error_code(refused).await, -32004);
}

/// ONE CONFIG PER TASK, REFUSED OUT LOUD. busbar's durable row holds one callback and its delivery
/// is one request, so answering `OK` to a second config would be promising a delivery busbar does
/// not make.
#[tokio::test]
async fn a_second_config_on_one_task_is_refused_rather_than_silently_dropped() {
    let me = "key-push-second";
    open(me, "push-second", "ctx-push", TaskState::Completed, 1_000);
    let first = local::create_push_config(
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-second", "id": "cfg-a", "url": HOOK }),
        ),
        &rpc_id(),
        me,
        seam(),
        1_000,
    )
    .await;
    assert!(body(first).await.get("error").is_none());

    let second = local::create_push_config(
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-second", "id": "cfg-b", "url": HOOK }),
        ),
        &rpc_id(),
        me,
        seam(),
        1_000,
    )
    .await;
    assert_eq!(error_code(second).await, -32004);
}

/// ANOTHER TENANT'S TASK IS NOT A TASK. Every push verb resolves its task through the same scoped
/// lookup, so a caller cannot attach a callback of its own to somebody else's work — which would be
/// a caller reading another tenant's task outcomes at a URL it chose.
#[tokio::test]
async fn a_push_config_cannot_be_attached_to_another_tenants_task() {
    let owner = "key-push-owner";
    let intruder = "key-push-intruder";
    open(owner, "push-owned", "ctx-push", TaskState::Completed, 1_000);
    let refused = local::create_push_config(
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-owned", "id": "cfg-x", "url": HOOK }),
        ),
        &rpc_id(),
        intruder,
        seam(),
        1_000,
    )
    .await;
    assert_eq!(error_code(refused).await, -32001);
    assert_eq!(
        TASKS
            .get_scoped(owner, "push-owned")
            .expect("row")
            .push_callback,
        None
    );
}

/// The v0.3 spelling answers in the v0.3 SHAPE. A well-formed document in the other dialect is a
/// document that version's client cannot read.
#[tokio::test]
async fn the_v0_3_spelling_is_answered_in_the_v0_3_shape() {
    let me = "key-push-v03";
    open(me, "push-v03", "ctx-push", TaskState::Completed, 1_000);
    let created = result(
        local::create_push_config(
            Dialect::V03,
            &envelope(
                "tasks/pushNotificationConfig/set",
                serde_json::json!({
                    "taskId": "push-v03",
                    "pushNotificationConfig": { "id": "cfg-v03", "url": HOOK },
                }),
            ),
            &rpc_id(),
            me,
            seam(),
            1_000,
        )
        .await,
    )
    .await;
    assert_eq!(created["pushNotificationConfig"]["id"], "cfg-v03");
    assert_eq!(created["pushNotificationConfig"]["url"], HOOK);
    assert!(
        created.get("url").is_none(),
        "the v1.0 flattening must not leak into a v0.3 answer"
    );
}

// ══ THE TWO ERAS OF THE JSON-RPC METHOD NAME ═════════════════════════════════════════════════════

/// **BOTH SPELLINGS OF EVERY METHOD ARE READ THE SAME WAY, AND THE LIST IS NOT HAND-WRITTEN.**
///
/// A2A's JSON-RPC method names have two eras and both are live:
///
///   * SPEC 9.1 "Method Naming" makes the JSON-RPC name the PascalCase rpc name — `SendMessage`,
///     `GetTask`, `GetExtendedAgentCard`. This is what the official suite's own JSON-RPC client
///     sends, on every call.
///   * SPEC 3.6.2 requires an agent to read a missing `A2A-Version` header AS 0.3 — so the 0.3-era
///     `category/action` names are not history, they are the DEFAULT for every version-less client,
///     and a version-less client is one an agent must keep working for.
///
/// So neither era may be preferred, and the failure this locks out is the asymmetric one: a method
/// read under one spelling and not the other, which is a verb that works or does not work depending
/// on which decade the caller's SDK was written in. It is not hypothetical — busbar's own dispatch
/// grew each of these pairs one spelling at a time.
///
/// THE PAIRS COME FROM `qa/method-inventory.json`, which is GENERATED from the proto. A table typed
/// out here would be a list of the methods whoever wrote it was thinking about, which is exactly how
/// coverage ends at J with nobody noticing.
#[test]
fn every_a2a_method_is_read_identically_under_both_of_its_live_json_rpc_names() {
    const INVENTORY: &str = include_str!("../../../../../qa/method-inventory.json");
    let doc: serde_json::Value = serde_json::from_str(INVENTORY).expect("the inventory parses");
    let methods = doc["methods"].as_array().expect("a methods array");

    /// Every way this plane can recognise a method name, as one comparable verdict. A method that
    /// is RELAYED is recognised by none of them, and that is a legitimate answer — busbar is
    /// content-blind by default. What may never differ is the answer for the two spellings of ONE
    /// method.
    fn how_busbar_reads(method: &str) -> (Option<&'static str>, bool, bool) {
        let verb = local::verb_of(method).map(|v| match v {
            local::LocalVerb::ListTasks => "ListTasks",
            local::LocalVerb::CreatePushConfig(_) => "CreatePushConfig",
            local::LocalVerb::GetPushConfig(_) => "GetPushConfig",
            local::LocalVerb::ListPushConfigs(_) => "ListPushConfigs",
            local::LocalVerb::DeletePushConfig(_) => "DeletePushConfig",
            local::LocalVerb::Subscribe => "Subscribe",
        });
        // The two readers that are not `verb_of`: the streaming classifier the catalogue filters
        // on, and the extended-card verb the ingress answers before it selects an agent.
        let streams = crate::a2a::receive::reads_as_streaming_for_test(method);
        let extended = matches!(
            method,
            "GetExtendedAgentCard" | "agent/getAuthenticatedExtendedCard"
        );
        (verb, streams, extended)
    }

    let mut checked = 0;
    for m in methods {
        if m["protocol"] != "a2a" {
            continue;
        }
        let (Some(pascal), Some(slash)) = (
            m["wire_names"]["jsonrpc_1_0"].as_str(),
            m["wire_names"]["jsonrpc_0_3"].as_str(),
        ) else {
            // The two non-method surfaces (the well-known card, the push delivery) have no
            // JSON-RPC name in either era. Nothing to compare.
            continue;
        };
        checked += 1;
        assert_eq!(
            how_busbar_reads(pascal),
            how_busbar_reads(slash),
            "`{pascal}` (SPEC 9.1) and `{slash}` (the 0.3 name SPEC 3.6.2 keeps live) are read \
             differently by this plane, so this method works for one era's clients and not the \
             other's"
        );
    }
    // THE FLOOR. A loop that matched nothing would pass this test while asserting nothing at all.
    assert!(
        checked >= 11,
        "only {checked} A2A methods carried both wire names; the inventory is not being read"
    );
}
