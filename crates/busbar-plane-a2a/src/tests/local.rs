// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verbs the plane answers itself, over the test's host records: the engine's bytes, and a
//! config that is a record.

use busbar_contract::abi::host::service::{DEST_ALLOWED, DEST_INTERNAL, DEST_UNRESOLVABLE};

use super::*;
use crate::tasks::tests::{step, submitted, Book, ALICE, BOB};

/// The host records, and the destination judge's one verdict.
struct Desk {
    book: Book,
    verdict: u64,
}

impl Records for Desk {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.book.get(kind, key)
    }
    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        self.book.list(kind, prefix)
    }
    fn claim(&mut self, kind: &str, key: &str, ttl_ms: u64) -> Result<bool, Halt> {
        self.book.claim(kind, key, ttl_ms)
    }
}

impl Reach for Desk {
    fn judge(&mut self, _dest: &str) -> Result<u64, Halt> {
        Ok(self.verdict)
    }
}

/// Alice holds `t1` and `t2`, Bob `t3`.
fn desk() -> Desk {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    submitted(&mut book, ALICE, "t2", 200);
    submitted(&mut book, BOB, "t3", 100);
    Desk {
        book,
        verdict: DEST_ALLOWED,
    }
}

/// Call `method` with `params` as `caller` and apply its writes: the status and the parsed body.
fn call(desk: &mut Desk, method: &str, params: Value, caller: &str) -> (u32, Value) {
    let verb = verb_of(method).expect("a local verb");
    let envelope = json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params });
    let mut out = Vec::new();
    let answer = answer(desk, verb, &envelope, caller, 300, &mut out)
        .unwrap()
        .expect("answered here");
    desk.book.apply(&out);
    (answer.status, serde_json::from_slice(&answer.body).unwrap())
}

/// The error a body carries: its code and its message.
fn error_of(body: &Value) -> (i64, String) {
    (
        body["error"]["code"].as_i64().unwrap(),
        body["error"]["message"].as_str().unwrap().to_string(),
    )
}

#[test]
fn every_listed_method_is_a_local_verb() {
    for method in crate::LOCAL_VERB_METHODS {
        assert!(verb_of(method).is_some(), "{method}");
    }
    assert_eq!(verb_of("SendMessage"), None);
}

/// `ListTasks` answers the caller's own rows, newest first, one page at a time, with the engine's
/// members.
#[test]
fn list_tasks_answers_the_callers_own_rows_a_page_at_a_time() {
    let mut desk = desk();
    let (status, body) = call(&mut desk, "ListTasks", json!({ "pageSize": 1 }), ALICE);
    assert_eq!(status, 200);
    assert_eq!(body["id"], 7);
    let result = &body["result"];
    assert_eq!(
        result["tasks"],
        json!([{ "id": "t2", "contextId": "ctx-1", "status": { "state": "TASK_STATE_SUBMITTED" } }])
    );
    assert_eq!(
        (result["pageSize"].clone(), result["totalSize"].clone()),
        (json!(1), json!(2))
    );
    assert_eq!(result["nextPageToken"], "200:t2");
    let (_, body) = call(
        &mut desk,
        "tasks/list",
        json!({ "page_token": "200:t2" }),
        ALICE,
    );
    assert_eq!(body["result"]["tasks"][0]["id"], "t1");
    assert_eq!(
        body["result"]["nextPageToken"], "",
        "present, and empty on the last page"
    );
    let (_, body) = call(
        &mut desk,
        "ListTasks",
        json!({ "status": "completed" }),
        ALICE,
    );
    assert_eq!(body["result"]["totalSize"], 0);
}

/// A config is created, read, listed and deleted as a record of its task, in each dialect's shape,
/// and its credential is never echoed.
#[test]
fn a_push_config_lives_as_a_record_of_its_task() {
    let mut desk = desk();
    let cfg = json!({ "taskId": "t1", "id": "c1", "url": "https://hooks.example/cb",
                      "authentication": { "scheme": "Bearer", "credentials": "s3cret" } });
    let (status, body) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
    assert_eq!(status, 200);
    assert_eq!(
        body["result"],
        json!({ "taskId": "t1", "id": "c1", "url": "https://hooks.example/cb" })
    );
    assert!(!body.to_string().contains("s3cret"));
    assert!(desk
        .book
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
        .is_some());

    let (_, body) = call(
        &mut desk,
        "tasks/pushNotificationConfig/get",
        json!({ "id": "t1", "pushNotificationConfigId": "c1" }),
        ALICE,
    );
    assert_eq!(
        body["result"],
        json!({ "taskId": "t1", "pushNotificationConfig": { "id": "c1", "url": "https://hooks.example/cb" } })
    );
    let (_, body) = call(
        &mut desk,
        "tasks/pushNotificationConfig/list",
        json!({ "id": "t1" }),
        ALICE,
    );
    assert!(body["result"].is_array());
    let (_, body) = call(
        &mut desk,
        "ListTaskPushNotificationConfigs",
        json!({ "taskId": "t1" }),
        ALICE,
    );
    assert_eq!(body["result"]["nextPageToken"], "");
    assert_eq!(body["result"]["configs"].as_array().map(Vec::len), Some(1));

    let second = json!({ "taskId": "t1", "id": "c2", "url": "https://hooks.example/cb" });
    let (status, body) = call(&mut desk, "CreateTaskPushNotificationConfig", second, ALICE);
    assert_eq!(
        (status, error_of(&body).0),
        (400, -32004),
        "one config per task"
    );

    let (_, body) = call(
        &mut desk,
        "DeleteTaskPushNotificationConfig",
        json!({ "taskId": "t1", "id": "c1" }),
        ALICE,
    );
    assert_eq!(body["result"], json!({}));
    assert!(
        desk.book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_none(),
        "a tombstone"
    );
    let (status, body) = call(
        &mut desk,
        "GetTaskPushNotificationConfig",
        json!({ "taskId": "t1", "id": "c1" }),
        ALICE,
    );
    assert_eq!(status, 404);
    assert_eq!(
        error_of(&body).1,
        "no push notification config with that id is registered for this task"
    );
    let (_, body) = call(
        &mut desk,
        "tasks/pushNotificationConfig/delete",
        json!({ "id": "t1", "pushNotificationConfigId": "c1" }),
        ALICE,
    );
    assert_eq!(body["result"], Value::Null, "idempotent, v0.3's null");
}

/// The credential is a sealed field of the stored record and appears in no answer.
#[test]
fn the_stored_credential_rides_the_record_and_never_an_answer() {
    let mut desk = desk();
    let cfg = json!({ "taskId": "t1", "id": "c1", "url": "https://hooks.example/cb",
                      "authentication": { "scheme": "Bearer", "credentials": "s3cret" } });
    let (_, created) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
    let bytes = desk
        .book
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
        .expect("the record");
    let held: PushConfig = serde_json::from_slice(bytes).unwrap();
    assert_eq!(
        held.authentication,
        Some(DeliveryAuth {
            scheme: "Bearer".into(),
            credentials: "s3cret".into(),
        })
    );
    assert!(!format!("{held:?}").contains("s3cret"));
    let (_, got) = call(
        &mut desk,
        "GetTaskPushNotificationConfig",
        json!({ "taskId": "t1", "id": "c1" }),
        ALICE,
    );
    let (_, listed) = call(
        &mut desk,
        "ListTaskPushNotificationConfigs",
        json!({ "taskId": "t1" }),
        ALICE,
    );
    for body in [created, got, listed] {
        assert!(!body.to_string().contains("s3cret"));
    }
}

/// A record written before the field existed still reads, and a config without a credential
/// writes none.
#[test]
fn a_record_without_the_credential_field_reads_as_none() {
    let old: PushConfig =
        serde_json::from_str(r#"{"id":"c1","url":"https://hooks.example/cb"}"#).unwrap();
    assert_eq!(old.authentication, None);
    assert!(!serde_json::to_string(&old)
        .unwrap()
        .contains("authentication"));
    let kept = PushConfig {
        authentication: Some(DeliveryAuth {
            scheme: "Basic".into(),
            credentials: "abc".into(),
        }),
        ..old
    };
    let again: PushConfig = serde_json::from_slice(&serde_json::to_vec(&kept).unwrap()).unwrap();
    assert_eq!(again, kept);
}

/// Another caller's task is not found, with the engine's ErrorInfo, at 404.
#[test]
fn another_callers_task_is_not_found() {
    let mut desk = desk();
    let (status, body) = call(
        &mut desk,
        "GetTaskPushNotificationConfig",
        json!({ "taskId": "t3", "id": "" }),
        ALICE,
    );
    assert_eq!(status, 404);
    assert_eq!(
        body,
        json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": -32001, "message": NO_SUCH_TASK,
            "data": [{ "@type": crate::ERROR_INFO_TYPE, "domain": crate::ERROR_INFO_DOMAIN, "reason": "TASK_NOT_FOUND" }] } })
    );
}

/// The callback floor refuses in the engine's words: a scheme, an internal literal, a name that
/// resolves to nothing, a name the judge finds internal, a `token`, a bad credential, no `url`.
#[test]
fn a_callback_is_refused_in_the_engines_words() {
    let cases: [(Value, u64, i64, &str); 7] = [
        (json!({ "url": "http://hooks.example/" }), DEST_ALLOWED, -32602, "push callback scheme `http` is refused; a callback carries task metadata off-box and must be https"),
        (json!({ "url": "https://10.0.0.1/" }), DEST_ALLOWED, -32602, "push callback resolves to the INTERNAL address 10.0.0.1; delivering there would lend busbar's network position to the caller"),
        (json!({ "url": "https://gone.example/" }), DEST_UNRESOLVABLE, -32602, "push callback host `gone.example` resolved to no addresses; nothing was checked, so nothing is allowed"),
        (json!({ "url": "https://inside.example/" }), DEST_INTERNAL, -32602, "push callback resolves to the INTERNAL address inside.example; delivering there would lend busbar's network position to the caller"),
        (json!({ "url": "https://hooks.example/", "token": "t" }), DEST_ALLOWED, -32004, "busbar does not carry a push notification config `token`"),
        (json!({ "url": "https://hooks.example/", "authentication": { "credentials": "x" } }), DEST_ALLOWED, -32602, "a push notification config's `authentication` must name a `scheme`"),
        (json!({ "id": "c" }), DEST_ALLOWED, -32602, "a push notification config must name the `url` busbar is to call"),
    ];
    for (cfg, verdict, code, words) in cases {
        let mut desk = desk();
        desk.verdict = verdict;
        let params = json!({ "id": "t1", "pushNotificationConfig": cfg });
        let (status, body) = call(&mut desk, "tasks/pushNotificationConfig/set", params, ALICE);
        let (got, message) = error_of(&body);
        assert_eq!((status, got), (400, code), "{message}");
        assert!(message.starts_with(words), "{message}");
        assert!(desk
            .book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_none());
    }
}

/// A subscribe to a task busbar did not issue to this caller is not found, to one it holds as
/// terminal is unsupported, and to a live one is the backend's to answer.
#[test]
fn a_subscribe_is_refused_only_where_busbar_knows_better() {
    let mut desk = desk();
    let mut out = Vec::new();
    crate::tasks::transition(
        &mut desk.book,
        &step(ALICE, 250),
        "t2",
        TaskState::Completed,
        &mut out,
    )
    .unwrap();
    desk.book.apply(&out);
    let envelope = |id: &str| json!({ "jsonrpc": "2.0", "id": 1, "method": "SubscribeToTask", "params": { "id": id } });
    let refused = |desk: &mut Desk, id: &str| {
        answer(
            desk,
            LocalVerb::Subscribe,
            &envelope(id),
            ALICE,
            300,
            &mut Vec::new(),
        )
        .unwrap()
    };
    assert_eq!(refused(&mut desk, "t3").map(|a| a.status), Some(404));
    assert_eq!(refused(&mut desk, "t2").map(|a| a.status), Some(400));
    assert_eq!(refused(&mut desk, "t1"), None);
}
