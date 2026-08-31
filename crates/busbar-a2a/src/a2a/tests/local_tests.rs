// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-a2a/src/a2a/local.rs` — the verbs busbar answers itself.
//!
//! ## Why every test names its own principal
//!
//! `busbar_core::plane::taskstore::TASKS` is a process-global and these tests run in parallel with every
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
use crate::taskstore::TASKS;

// ══ HELPERS ══════════════════════════════════════════════════════════════════════════════════════

/// The battery's clock BASE: real wall time, captured once per process. The registry under test is
/// the process-global `TASKS`, which runs the production retention sweep on every submit — and the
/// OTHER batteries sharing it (the front door, the relay, push delivery) drive the ingress with the
/// REAL host clock. A fixed synthetic epoch here would sit hundreds of millions of seconds in the
/// sweep's past, so a completed task opened by one of these tests would be collected as an expired
/// terminal row the moment any concurrent test submitted. Offsets off this base stay far inside the
/// terminal-task TTL, so relative order is preserved and nothing ages out mid-test.
fn epoch() -> u64 {
    static BASE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BASE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock after 1970")
            .as_secs()
    })
}

/// Open a real task row for `principal` and move it to `state`.
fn open(principal: &str, task_id: &str, context_id: &str, state: TaskState, now: u64) {
    let task = Task::submitted(task_id, context_id, principal, Direction::Inbound, now)
        .expect("a task with these fields is constructible");
    TASKS
        .submit(&task.to_row(), task_id)
        .expect("the row records");
    if state != TaskState::Submitted {
        TASKS
            .transition(
                task_id,
                task_id,
                crate::a2a::task::plan_transition(state, now),
            )
            .expect("the transition is legal");
    }
}

/// A neutral `EngineHost` over a bare app. The three task-store reads/writes these verbs go through
/// (`task_get_scoped` / `task_set_push_callback`) are pure `TASKS.*` calls that ignore the app, so
/// any host serves — the tenancy the tests assert is the process-global store's, keyed by principal.
fn host() -> std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost> {
    busbar_core::plane_host::engine_host(&busbar_core::test_support::TestApp::new().build())
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
    crate::testkit::install_test_seams();
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
    crate::testkit::install_test_seams();
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
    crate::testkit::install_test_seams();
    let mine = "key-list-mine";
    let theirs = "key-list-theirs";
    open(mine, "lt-mine-1", "ctx-shared", TaskState::Working, epoch());
    open(
        theirs,
        "lt-theirs-1",
        "ctx-shared",
        TaskState::Working,
        epoch(),
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
    crate::testkit::install_test_seams();
    let me = "key-list-order";
    open(me, "lt-old", "ctx-order", TaskState::Working, epoch());
    open(
        me,
        "lt-new",
        "ctx-order",
        TaskState::Completed,
        epoch() + 100,
    );

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

/// `pageSize` and `totalSize` are REQUIRED members of the response and were BOTH omitted.
///
/// `a2a::ListTasksResponse` types them `page_size: i32` and `total_size: i32`, neither
/// `#[serde(default)]` — so a body without them cannot deserialise into the very struct busbar's own
/// gRPC ListTasks leg builds from this JSON. `totalSize` is the count matching the filter BEFORE
/// pagination; `pageSize` is the effective (clamped) page this response was cut to.
#[tokio::test]
async fn list_tasks_carries_the_required_page_size_and_total_size() {
    crate::testkit::install_test_seams();
    let me = "key-list-sizes";
    for (i, id) in ["ls-1", "ls-2", "ls-3"].iter().enumerate() {
        open(
            me,
            id,
            "ctx-sizes",
            TaskState::Working,
            epoch() + i as u64 * 10,
        );
    }

    let listed = result(local::list_tasks(
        &envelope(
            "ListTasks",
            serde_json::json!({ "context_id": "ctx-sizes", "page_size": 2 }),
        ),
        &rpc_id(),
        me,
    ))
    .await;

    assert_eq!(
        listed.get("totalSize"),
        Some(&serde_json::json!(3)),
        "total_size counts the whole filtered set before pagination: {listed}"
    );
    assert_eq!(
        listed.get("pageSize"),
        Some(&serde_json::json!(2)),
        "page_size is the effective page the response was cut to: {listed}"
    );
}

/// `nextPageToken` is PRESENT ON EVERY PAGE and EMPTY on the last one. A client's paging loop
/// terminates on this member, so omitting it on the final page is how the loop becomes infinite.
#[tokio::test]
async fn list_tasks_pages_by_cursor_and_ends_with_an_empty_token() {
    crate::testkit::install_test_seams();
    let me = "key-list-page";
    for (i, id) in ["lt-p1", "lt-p2", "lt-p3"].iter().enumerate() {
        open(
            me,
            id,
            "ctx-page",
            TaskState::Working,
            epoch() + i as u64 * 10,
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
    crate::testkit::install_test_seams();
    let me = "key-list-shape";
    open(me, "lt-shape", "ctx-shape", TaskState::Completed, epoch());
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
    crate::testkit::install_test_seams();
    let me = "key-sub-live";
    open(me, "sub-live", "ctx-sub", TaskState::Working, epoch());
    let env = envelope("SubscribeToTask", serde_json::json!({ "id": "sub-live" }));
    assert!(
        local::subscribe_refusal(host().as_ref(), &env, &rpc_id(), me).is_none(),
        "a live task's events are the backend's"
    );
}

/// A terminal task earns `UnsupportedOperation` (-32004): busbar recorded the ending itself, so
/// there is nothing further to subscribe to.
#[tokio::test]
async fn subscribing_to_a_terminal_task_is_refused() {
    crate::testkit::install_test_seams();
    let me = "key-sub-done";
    open(me, "sub-done", "ctx-sub", TaskState::Completed, epoch());
    let env = envelope("SubscribeToTask", serde_json::json!({ "id": "sub-done" }));
    let refusal = local::subscribe_refusal(host().as_ref(), &env, &rpc_id(), me)
        .expect("a terminal task is refused");
    assert_eq!(error_code(refusal).await, -32004);
}

/// An id busbar never issued, and ANOTHER PRINCIPAL'S id, earn the SAME `TaskNotFound` (-32001).
/// Relayed, both of these reached a backend that had never heard of the id and an accommodating one
/// opened a stream — a caller handed a live subscription to work that does not exist.
#[tokio::test]
async fn subscribing_to_an_unknown_or_foreign_task_is_task_not_found() {
    crate::testkit::install_test_seams();
    let me = "key-sub-unknown";
    let other = "key-sub-owner";
    open(other, "sub-foreign", "ctx-sub", TaskState::Working, epoch());

    let unknown = envelope(
        "SubscribeToTask",
        serde_json::json!({ "id": "no-such-task-at-all" }),
    );
    let refusal =
        local::subscribe_refusal(host().as_ref(), &unknown, &rpc_id(), me).expect("refused");
    assert_eq!(error_code(refusal).await, -32001);

    let foreign = envelope(
        "SubscribeToTask",
        serde_json::json!({ "id": "sub-foreign" }),
    );
    let refusal =
        local::subscribe_refusal(host().as_ref(), &foreign, &rpc_id(), me).expect("refused");
    assert_eq!(
        error_code(refusal).await,
        -32001,
        "another tenant's id must be indistinguishable from a nonexistent one"
    );
}

// ══ PUSH-CONFIG CRUD ═════════════════════════════════════════════════════════════════════════════

/// The seam a create needs, answering one public address so the SSRF guard has something to pass.
fn seam() -> std::sync::Arc<dyn super::super::relay::RelaySeam> {
    use super::super::fetch::{HttpResponse, Resolver};
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
            _url: &url::Url,
            _addr: IpAddr,
            _headers: &[(String, String)],
            _body: &[u8],
        ) -> Result<HttpResponse, String> {
            Err("this test opens no socket".to_string())
        }
        fn post_stream(
            &self,
            _url: &url::Url,
            _addr: IpAddr,
            _headers: &[(String, String)],
            _body: &[u8],
            _on_chunk: &mut (dyn FnMut(&[u8]) -> ChunkFlow + Send),
        ) -> Result<StreamHead, String> {
            Err("this test opens no socket".to_string())
        }
    }
    struct Seam;
    impl RelaySeam for Seam {
        fn resolver(&self) -> &dyn Resolver {
            &PublicResolver
        }
        fn transport(&self) -> &dyn RelayTransport {
            &NoTransport
        }
    }
    std::sync::Arc::new(Seam)
}

const HOOK: &str = "https://hook.caller.test/notify";

/// The whole CRUD round trip, terminated at busbar: create, read back, list, delete, and the read
/// after the delete. The backend agent is never asked, and there is no backend in this test to ask.
#[tokio::test]
async fn a_push_config_is_created_read_listed_and_deleted_at_busbar() {
    crate::testkit::install_test_seams();
    let me = "key-push-crud";
    open(me, "push-crud", "ctx-push", TaskState::Completed, epoch());

    let created = result(
        local::create_push_config(
            host().as_ref(),
            Dialect::V10,
            &envelope(
                "CreateTaskPushNotificationConfig",
                serde_json::json!({ "task_id": "push-crud", "id": "cfg-1", "url": HOOK }),
            ),
            &rpc_id(),
            me,
            seam(),
            epoch(),
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
            .push_callback,
        HOOK
    );

    let read = result(local::get_push_config(
        host().as_ref(),
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
        host().as_ref(),
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
        host().as_ref(),
        local::Dialect::V10,
        &envelope(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-crud", "id": "cfg-1" }),
        ),
        &rpc_id(),
        me,
        epoch() + 1,
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
        ""
    );

    let gone = local::get_push_config(
        host().as_ref(),
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
    crate::testkit::install_test_seams();
    let me = "key-push-idem";
    open(me, "push-idem", "ctx-push", TaskState::Completed, epoch());
    let response = local::delete_push_config(
        host().as_ref(),
        local::Dialect::V10,
        &envelope(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-idem", "id": "never-registered" }),
        ),
        &rpc_id(),
        me,
        epoch(),
    );
    assert!(body(response).await.get("error").is_none());
}

/// THE SSRF GUARD RUNS ON THIS PATH TOO, and it is the CALLER's fault. A callback registered by the
/// CRUD verb and a callback registered inline on a submission must be judged by one rule; two rules
/// is how one of them becomes the way around the other.
#[tokio::test]
async fn a_private_callback_is_refused_by_the_same_guard_as_the_inline_path() {
    crate::testkit::install_test_seams();
    let me = "key-push-ssrf";
    open(me, "push-ssrf", "ctx-push", TaskState::Completed, epoch());
    let refused = local::create_push_config(
        host().as_ref(),
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
        epoch(),
    )
    .await;
    assert_eq!(error_code(refused).await, -32602);
    assert_eq!(
        TASKS
            .get_scoped(me, "push-ssrf")
            .expect("row")
            .push_callback,
        "",
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
    crate::testkit::install_test_seams();
    let me = "key-push-auth";
    open(me, "push-auth", "ctx-push", TaskState::Completed, epoch());
    let created = local::create_push_config(
        host().as_ref(),
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
        epoch(),
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
        host().as_ref(),
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
    crate::testkit::install_test_seams();
    let me = "key-push-noscheme";
    open(
        me,
        "push-noscheme",
        "ctx-push",
        TaskState::Completed,
        epoch(),
    );
    let refused = local::create_push_config(
        host().as_ref(),
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
        epoch(),
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
    crate::testkit::install_test_seams();
    let me = "key-push-token";
    open(me, "push-token", "ctx-push", TaskState::Completed, epoch());
    let refused = local::create_push_config(
        host().as_ref(),
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
        epoch(),
    )
    .await;
    assert_eq!(error_code(refused).await, -32004);
}

/// ONE CONFIG PER TASK, REFUSED OUT LOUD. busbar's durable row holds one callback and its delivery
/// is one request, so answering `OK` to a second config would be promising a delivery busbar does
/// not make.
#[tokio::test]
async fn a_second_config_on_one_task_is_refused_rather_than_silently_dropped() {
    crate::testkit::install_test_seams();
    let me = "key-push-second";
    open(me, "push-second", "ctx-push", TaskState::Completed, epoch());
    let first = local::create_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-second", "id": "cfg-a", "url": HOOK }),
        ),
        &rpc_id(),
        me,
        seam(),
        epoch(),
    )
    .await;
    assert!(body(first).await.get("error").is_none());

    let second = local::create_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-second", "id": "cfg-b", "url": HOOK }),
        ),
        &rpc_id(),
        me,
        seam(),
        epoch(),
    )
    .await;
    assert_eq!(error_code(second).await, -32004);
}

/// ANOTHER TENANT'S TASK IS NOT A TASK. Every push verb resolves its task through the same scoped
/// lookup, so a caller cannot attach a callback of its own to somebody else's work — which would be
/// a caller reading another tenant's task outcomes at a URL it chose.
#[tokio::test]
async fn a_push_config_cannot_be_attached_to_another_tenants_task() {
    crate::testkit::install_test_seams();
    let owner = "key-push-owner";
    let intruder = "key-push-intruder";
    open(
        owner,
        "push-owned",
        "ctx-push",
        TaskState::Completed,
        epoch(),
    );
    let refused = local::create_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-owned", "id": "cfg-x", "url": HOOK }),
        ),
        &rpc_id(),
        intruder,
        seam(),
        epoch(),
    )
    .await;
    assert_eq!(error_code(refused).await, -32001);
    assert_eq!(
        TASKS
            .get_scoped(owner, "push-owned")
            .expect("row")
            .push_callback,
        ""
    );
}

// ══ THE TENANCY BOUNDARY ON EVERY TASK-ADDRESSING VERB ═══════════════════════════════════════════
//
// A2A section 3.3.2: a server "MUST NOT reveal the existence of resources the client is not
// authorized to access". Section 13.1 requires the check on EVERY Protocol Operations request,
// scoped to the caller's authorized access boundaries.
//
// The defect these lock out was found on `GetTask` — one operation, tested by one person. The
// failure mode this section exists to prevent is fixing that one and leaving the siblings, so each
// verb below is probed with TWO principals and asserts BOTH halves. A single-principal test cannot
// tell perfect scoping from none: it sees an answer and cannot say whose task it was about.
//
// The non-owner half is asserted by COMPARISON against the absent-id answer, not by asserting "an
// error". Status, error code and body shape must all match, because any one of them differing is
// the existence oracle 3.3.2 forbids.

/// The full answer a caller sees — status, and the JSON body it carries — so the two halves of an
/// indistinguishability claim are compared on everything observable rather than on a code.
async fn observable(response: axum::response::Response) -> (u16, serde_json::Value) {
    let status = response.status().as_u16();
    (status, body(response).await)
}

/// `GetTaskPushNotificationConfig`: the owner reads its own config; nobody else can tell that there
/// is a task to have one.
#[tokio::test]
async fn get_push_config_is_answered_for_the_owner_and_is_an_absent_task_for_everybody_else() {
    crate::testkit::install_test_seams();
    let owner = "key-cfgget-owner";
    let intruder = "key-cfgget-intruder";
    open(
        owner,
        "cfgget-owned",
        "ctx-cfgget",
        TaskState::Working,
        epoch(),
    );
    local::create_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({ "taskId": "cfgget-owned", "id": "cfg-1", "url": HOOK }),
        ),
        &rpc_id(),
        owner,
        seam(),
        epoch(),
    )
    .await;

    // THE OWNER CAN.
    let mine = result(local::get_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "taskId": "cfgget-owned", "id": "cfg-1" }),
        ),
        &rpc_id(),
        owner,
    ))
    .await;
    assert_eq!(mine["url"], HOOK);

    // THE NON-OWNER CANNOT, and gets the answer an id that never existed gets.
    let foreign = observable(local::get_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "taskId": "cfgget-owned", "id": "cfg-1" }),
        ),
        &rpc_id(),
        intruder,
    ))
    .await;
    let absent = observable(local::get_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "taskId": "cfgget-never-existed", "id": "cfg-1" }),
        ),
        &rpc_id(),
        intruder,
    ))
    .await;
    assert_eq!(
        foreign, absent,
        "status, error code and body must be identical for another principal's task and for a task \
         that does not exist"
    );
    assert_eq!(
        foreign.1.pointer("/error/code"),
        Some(&serde_json::json!(-32001))
    );
}

/// `ListTaskPushNotificationConfigs`: the same two-principal probe on the enumeration-by-task verb.
/// It is the one whose answer is a LIST, so a non-owner must not be given an empty list either —
/// an empty list for a task that exists and a refusal for a task that does not are distinguishable.
#[tokio::test]
async fn list_push_configs_is_answered_for_the_owner_and_is_an_absent_task_for_everybody_else() {
    crate::testkit::install_test_seams();
    let owner = "key-cfglist-owner";
    let intruder = "key-cfglist-intruder";
    open(
        owner,
        "cfglist-owned",
        "ctx-cfglist",
        TaskState::Working,
        epoch(),
    );
    local::create_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({ "taskId": "cfglist-owned", "id": "cfg-l", "url": HOOK }),
        ),
        &rpc_id(),
        owner,
        seam(),
        epoch(),
    )
    .await;

    let mine = result(local::list_push_configs(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "ListTaskPushNotificationConfigs",
            serde_json::json!({ "taskId": "cfglist-owned" }),
        ),
        &rpc_id(),
        owner,
    ))
    .await;
    assert_eq!(mine["configs"].as_array().map(Vec::len), Some(1));

    let foreign = observable(local::list_push_configs(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "ListTaskPushNotificationConfigs",
            serde_json::json!({ "taskId": "cfglist-owned" }),
        ),
        &rpc_id(),
        intruder,
    ))
    .await;
    let absent = observable(local::list_push_configs(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "ListTaskPushNotificationConfigs",
            serde_json::json!({ "taskId": "cfglist-never-existed" }),
        ),
        &rpc_id(),
        intruder,
    ))
    .await;
    assert_eq!(foreign, absent);
    assert_eq!(
        foreign.1.pointer("/error/code"),
        Some(&serde_json::json!(-32001))
    );
}

/// `DeleteTaskPushNotificationConfig`: the WRITE half. A delete that crossed the boundary would not
/// leak a fact, it would DISARM another principal's callback — so the assertion is on the owner's
/// row as well as on the answer.
#[tokio::test]
async fn delete_push_config_cannot_disarm_another_principals_callback() {
    crate::testkit::install_test_seams();
    let owner = "key-cfgdel-owner";
    let intruder = "key-cfgdel-intruder";
    open(
        owner,
        "cfgdel-owned",
        "ctx-cfgdel",
        TaskState::Working,
        epoch(),
    );
    local::create_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "CreateTaskPushNotificationConfig",
            serde_json::json!({ "taskId": "cfgdel-owned", "id": "cfg-d", "url": HOOK }),
        ),
        &rpc_id(),
        owner,
        seam(),
        epoch(),
    )
    .await;

    let foreign = observable(local::delete_push_config(
        host().as_ref(),
        local::Dialect::V10,
        &envelope(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "taskId": "cfgdel-owned", "id": "cfg-d" }),
        ),
        &rpc_id(),
        intruder,
        epoch() + 1,
    ))
    .await;
    let absent = observable(local::delete_push_config(
        host().as_ref(),
        local::Dialect::V10,
        &envelope(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "taskId": "cfgdel-never-existed", "id": "cfg-d" }),
        ),
        &rpc_id(),
        intruder,
        epoch() + 1,
    ))
    .await;
    assert_eq!(foreign, absent);

    // THE CALLBACK IS STILL ARMED, which is the half an answer-only assertion cannot see.
    assert_eq!(
        TASKS
            .get_scoped(owner, "cfgdel-owned")
            .expect("the owner's row")
            .push_callback,
        HOOK
    );

    // AND THE OWNER CAN STILL DELETE IT — a boundary that also refused the owner would pass the
    // test above while breaking the verb.
    let mine = local::delete_push_config(
        host().as_ref(),
        local::Dialect::V10,
        &envelope(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "taskId": "cfgdel-owned", "id": "cfg-d" }),
        ),
        &rpc_id(),
        owner,
        epoch() + 2,
    );
    // v1.0 delete answers ProtoJSON Empty (`{}`), not null (see `delete_push_config`).
    assert_eq!(result(mine).await, serde_json::json!({}));
    assert_eq!(
        TASKS
            .get_scoped(owner, "cfgdel-owned")
            .expect("the owner's row")
            .push_callback,
        ""
    );
}

/// `SubscribeToTask`, BOTH halves in one place. The refusal half already had a test; what was
/// missing beside it was the owner's, and a scoping test without it cannot distinguish a correct
/// boundary from a verb that refuses everybody.
#[tokio::test]
async fn subscribe_is_relayed_for_the_owner_and_is_an_absent_task_for_everybody_else() {
    crate::testkit::install_test_seams();
    let owner = "key-sub-both-owner";
    let intruder = "key-sub-both-intruder";
    open(
        owner,
        "sub-both",
        "ctx-sub-both",
        TaskState::Working,
        epoch(),
    );

    // THE OWNER CAN: no local refusal at all, so the subscribe relays and the backend's events are
    // the answer.
    assert!(local::subscribe_refusal(
        host().as_ref(),
        &envelope("SubscribeToTask", serde_json::json!({ "id": "sub-both" })),
        &rpc_id(),
        owner
    )
    .is_none());

    let foreign = observable(
        local::subscribe_refusal(
            host().as_ref(),
            &envelope("SubscribeToTask", serde_json::json!({ "id": "sub-both" })),
            &rpc_id(),
            intruder,
        )
        .expect("a foreign id must be refused"),
    )
    .await;
    let absent = observable(
        local::subscribe_refusal(
            host().as_ref(),
            &envelope(
                "SubscribeToTask",
                serde_json::json!({ "id": "sub-never-existed" }),
            ),
            &rpc_id(),
            intruder,
        )
        .expect("an absent id must be refused"),
    )
    .await;
    assert_eq!(foreign, absent);
}

/// The v0.3 spelling answers in the v0.3 SHAPE. A well-formed document in the other dialect is a
/// document that version's client cannot read.
#[tokio::test]
async fn the_v0_3_spelling_is_answered_in_the_v0_3_shape() {
    crate::testkit::install_test_seams();
    let me = "key-push-v03";
    open(me, "push-v03", "ctx-push", TaskState::Completed, epoch());
    let created = result(
        local::create_push_config(
            host().as_ref(),
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
            epoch(),
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
    crate::testkit::install_test_seams();
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

/// THE DELETE IS HONEST: when the DURABLE clear fails, the verb must not proceed as if deleted —
/// the config stays registered everywhere (local map, delivery pins, durable row) and the caller
/// gets the internal error so its retry means something. Once the store accepts the clear, the
/// retry removes it everywhere. The old shape removed the local entry FIRST and swallowed the
/// durable failure, which acknowledged a delete while the durable callback survived — after a
/// restart the "deleted" config would still receive the task's completion, the one outcome a
/// delete exists to prevent.
#[tokio::test]
async fn a_delete_whose_durable_clear_fails_keeps_the_config_and_returns_the_error() {
    crate::testkit::install_test_seams();
    // A sink is attached to the process-wide TASKS below, so the one lock every sink-attaching
    // test takes is held for the duration (see `taskstore::TASKS_SINK_LOCK`).
    let _guard = crate::taskstore::TASKS_SINK_LOCK.lock().await;
    let me = "key-push-delfail";
    open(
        me,
        "push-delfail",
        "ctx-push",
        TaskState::Completed,
        epoch(),
    );

    let created = result(
        local::create_push_config(
            host().as_ref(),
            Dialect::V10,
            &envelope(
                "CreateTaskPushNotificationConfig",
                serde_json::json!({ "task_id": "push-delfail", "id": "cfg-df", "url": HOOK }),
            ),
            &rpc_id(),
            me,
            seam(),
            epoch(),
        )
        .await,
    )
    .await;
    assert_eq!(created["id"], "cfg-df");

    /// A store whose task-row upserts fail for EXACTLY ONE task id (this test's) and delegate for
    /// every other, so the failure is deterministic without disturbing any concurrent test that
    /// writes through the same process-global registry while the sink is attached.
    struct RefuseOneTaskRow(busbar_store_memory::MemoryStore);
    impl busbar_api::Store for RefuseOneTaskRow {
        fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
            self.0.put_key(key)
        }
        fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
            self.0.get_key(id)
        }
        fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
            self.0.list_keys()
        }
        fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
            self.0.delete_key(id)
        }
        fn get_usage(&self, b: &str, w: u64) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
            self.0.get_usage(b, w)
        }
        fn put_usage(
            &self,
            b: &str,
            w: u64,
            l: &busbar_api::UsageLedger,
        ) -> busbar_api::StoreResult<()> {
            self.0.put_usage(b, w, l)
        }
        fn add_metering(&self, d: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
            self.0.add_metering(d)
        }
        fn list_metering(&self, b: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
            self.0.list_metering(b)
        }
        fn upsert_plane_record(
            &self,
            record: &busbar_api::PlaneRecord,
        ) -> busbar_api::StoreResult<()> {
            if record.id == "push-delfail" {
                return Err(busbar_api::StoreError("disk is full".to_string()));
            }
            self.0.upsert_plane_record(record)
        }
    }
    let refusing: std::sync::Arc<dyn busbar_api::Store> =
        std::sync::Arc::new(RefuseOneTaskRow(busbar_store_memory::MemoryStore::new()));
    TASKS.set_sink(busbar_core::plane::store::PlaneStoreView::narrow(refusing));

    let refused = local::delete_push_config(
        host().as_ref(),
        local::Dialect::V10,
        &envelope(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-delfail", "id": "cfg-df" }),
        ),
        &rpc_id(),
        me,
        epoch() + 1,
    );
    assert_eq!(
        error_code(refused).await,
        -32603,
        "a delete whose durable clear failed answers the internal error, never OK"
    );
    assert_eq!(
        TASKS
            .get_scoped(me, "push-delfail")
            .expect("row")
            .push_callback,
        HOOK,
        "the durable row still carries the callback — nothing pretended it was cleared"
    );
    let still_there = result(local::get_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-delfail", "id": "cfg-df" }),
        ),
        &rpc_id(),
        me,
    ))
    .await;
    assert_eq!(
        still_there["url"], HOOK,
        "the local config entry was kept too: the registry never claims less than the row holds"
    );

    // The store recovers (sink detached = the documented store:memory posture, whose clear
    // succeeds) — the caller's RETRY now removes the config everywhere.
    TASKS.clear_sink_for_test();
    let retried = local::delete_push_config(
        host().as_ref(),
        local::Dialect::V10,
        &envelope(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-delfail", "id": "cfg-df" }),
        ),
        &rpc_id(),
        me,
        epoch() + 2,
    );
    assert!(
        body(retried).await.get("error").is_none(),
        "once the durable clear succeeds the delete is acknowledged"
    );
    assert_eq!(
        TASKS
            .get_scoped(me, "push-delfail")
            .expect("row")
            .push_callback,
        "",
        "and the callback is off the row"
    );
    let gone = local::get_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "GetTaskPushNotificationConfig",
            serde_json::json!({ "task_id": "push-delfail", "id": "cfg-df" }),
        ),
        &rpc_id(),
        me,
    );
    assert_eq!(error_code(gone).await, -32001, "removed everywhere");
}

/// The catalogue filter's "this task registers a callback" read covers EVERY spelling the callback
/// guard covers — the same three-pointer list, because a filter reading only v0.3's
/// `pushNotificationConfig` silently stopped constraining v1.0 callers (the exact one-spelling
/// lesson the guard's own doc comment records from the SSRF fix).
#[test]
fn shape_of_reads_push_config_under_all_three_spellings() {
    let shape = |cfg: serde_json::Value| {
        crate::a2a::receive::shape_of_for_test(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "SendMessage",
            "params": { "configuration": cfg }
        }))
        .requires_push_notifications
    };
    assert!(
        shape(serde_json::json!({ "pushNotificationConfig": { "url": HOOK } })),
        "v0.3 spelling"
    );
    assert!(
        shape(serde_json::json!({ "taskPushNotificationConfig": { "url": HOOK } })),
        "v1.0 flat spelling declares push work too"
    );
    assert!(
        shape(serde_json::json!({
            "taskPushNotificationConfig": { "pushNotificationConfig": { "url": HOOK } }
        })),
        "v1.0 nested spelling declares push work too"
    );
    assert!(
        !shape(serde_json::json!({ "acceptedOutputModes": ["text"] })),
        "a configuration naming no callback constrains nothing"
    );
}

/// v0.3 push-config delete reads the config id from `pushNotificationConfigId` (its own spelling),
/// not from `id` (which on v0.3 is the TASK). The old code read `id` unconditionally, so a v0.3
/// delete matched no stored config, cleared NOTHING, and answered success — a revocation that
/// revoked nothing, leaving the callback and credential live on the durable row. This drives the
/// v0.3 spellings end to end and asserts the durable callback is actually gone.
#[tokio::test]
async fn v03_delete_reads_pushnotificationconfigid_and_actually_clears() {
    crate::testkit::install_test_seams();
    let me = "key-v03-del";
    open(me, "v03-del", "ctx-push", TaskState::Completed, epoch());

    // v0.3 set: the task is `id`, the config is nested under `pushNotificationConfig` with its own id.
    let created = result(
        local::create_push_config(
            host().as_ref(),
            Dialect::V03,
            &envelope(
                "tasks/pushNotificationConfig/set",
                serde_json::json!({
                    "id": "v03-del",
                    "pushNotificationConfig": { "id": "cfg-v03", "url": HOOK }
                }),
            ),
            &rpc_id(),
            me,
            seam(),
            epoch(),
        )
        .await,
    )
    .await;
    assert_eq!(
        created["pushNotificationConfig"]["id"], "cfg-v03",
        "{created}"
    );
    assert_eq!(
        TASKS.get_scoped(me, "v03-del").expect("row").push_callback,
        HOOK,
        "the durable row carries the callback after the v0.3 set"
    );

    // v0.3 delete: task named by `id`, config named by `pushNotificationConfigId`.
    let deleted = local::delete_push_config(
        host().as_ref(),
        Dialect::V03,
        &envelope(
            "tasks/pushNotificationConfig/delete",
            serde_json::json!({ "id": "v03-del", "pushNotificationConfigId": "cfg-v03" }),
        ),
        &rpc_id(),
        me,
        epoch() + 1,
    );
    assert!(
        body(deleted).await.get("error").is_none(),
        "the v0.3 delete succeeds"
    );
    assert_eq!(
        TASKS.get_scoped(me, "v03-del").expect("row").push_callback,
        "",
        "the durable callback is ACTUALLY cleared — the whole point the v0.3 config-id spelling fix \
         closes: the old code matched the task id, cleared nothing, and still answered success"
    );
}

/// The v1.0 REST/gRPC delete answers `google.protobuf.Empty` — ProtoJSON `{}` — not a literal
/// `null` (which a strict Empty decoder rejects as not-an-object). v0.3's JSON-RPC method keeps
/// `result: null`.
#[tokio::test]
async fn delete_empty_answer_shape_matches_the_dialect() {
    crate::testkit::install_test_seams();
    let me = "key-del-shape";
    open(me, "del-shape", "ctx-push", TaskState::Completed, epoch());

    let v10 = result(local::delete_push_config(
        host().as_ref(),
        Dialect::V10,
        &envelope(
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({ "taskId": "del-shape", "id": "nope" }),
        ),
        &rpc_id(),
        me,
        epoch(),
    ))
    .await;
    assert_eq!(
        v10,
        serde_json::json!({}),
        "v1.0 delete answers ProtoJSON Empty ({{}}), never null"
    );

    let v03 = result(local::delete_push_config(
        host().as_ref(),
        Dialect::V03,
        &envelope(
            "tasks/pushNotificationConfig/delete",
            serde_json::json!({ "id": "del-shape", "pushNotificationConfigId": "nope" }),
        ),
        &rpc_id(),
        me,
        epoch(),
    ))
    .await;
    assert_eq!(
        v03,
        serde_json::Value::Null,
        "v0.3 delete keeps result: null"
    );
}
