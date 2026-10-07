// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verbs the plane answers itself, over the test's host records: the engine's bytes, and a
//! config that is a record.

use busbar_contract::abi::host::service::{
    DEST_ALLOWED, DEST_INTERNAL, DEST_NO_HOST, DEST_OBFUSCATED, DEST_PLAINTEXT, DEST_SCHEME,
    DEST_UNRESOLVABLE,
};

use super::*;
use crate::tasks::tests::{step, submitted, Book, ALICE, BOB};

/// The host records, the destination judge's one verdict, and every destination it was asked.
struct Desk {
    book: Book,
    verdict: u64,
    judged: Vec<String>,
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
    fn judge(&mut self, dest: &str) -> Result<u64, Halt> {
        self.judged.push(dest.to_string());
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
        judged: Vec::new(),
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
        (json!({ "url": "http://hooks.example/" }), DEST_PLAINTEXT, -32602, "push callback scheme `http` is refused; a callback carries task metadata off-box and must be https"),
        (json!({ "url": "https://10.0.0.1/" }), DEST_INTERNAL, -32602, "push callback resolves to the INTERNAL address 10.0.0.1; delivering there would lend busbar's network position to the caller"),
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

// ── the engine's local-verb cells (`busbar-a2a` `local_tests.rs`), on the door ──────────────────

/// Exactly the task-store verbs are answered here; the submission and read verbs are the
/// backend's work and are relayed.
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
        assert!(verb_of(m).is_some(), "`{m}` must be answered locally");
    }
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
        assert!(verb_of(m).is_none(), "`{m}` must be relayed");
    }
}

/// Each push verb carries the dialect its spelling names, so its answer takes that dialect's shape.
#[test]
fn the_push_verbs_carry_the_dialect_that_named_them() {
    let pairs: [(&str, &str, fn(Dialect) -> LocalVerb); 4] = [
        (
            "CreateTaskPushNotificationConfig",
            "tasks/pushNotificationConfig/set",
            LocalVerb::CreatePushConfig,
        ),
        (
            "GetTaskPushNotificationConfig",
            "tasks/pushNotificationConfig/get",
            LocalVerb::GetPushConfig,
        ),
        (
            "ListTaskPushNotificationConfigs",
            "tasks/pushNotificationConfig/list",
            LocalVerb::ListPushConfigs,
        ),
        (
            "DeleteTaskPushNotificationConfig",
            "tasks/pushNotificationConfig/delete",
            LocalVerb::DeletePushConfig,
        ),
    ];
    for (v10, v03, verb) in pairs {
        assert_eq!(verb_of(v10), Some(verb(Dialect::V10)), "{v10}");
        assert_eq!(verb_of(v03), Some(verb(Dialect::V03)), "{v03}");
    }
}

/// A config cannot be attached to another caller's task: the create is the absent-task refusal,
/// and no record is written under either caller.
#[test]
fn a_push_config_cannot_be_attached_to_another_tenants_task() {
    let mut desk = desk();
    let cfg = json!({ "task_id": "t1", "id": "cfg-x", "url": "https://hooks.example/cb" });
    let (_, body) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, BOB);
    assert_eq!(error_of(&body), (-32001, NO_SUCH_TASK.to_string()));
    for caller in [ALICE, BOB] {
        assert!(desk
            .book
            .value(KIND_PUSH_CONFIG, &task_key(caller, "t1"))
            .is_none());
    }
    assert!(
        desk.judged.is_empty(),
        "nothing was judged for a foreign task"
    );
}

/// The list is answered for the owner; for anybody else it is the absent-task refusal, byte for
/// byte the one an id that never existed gets, and never an empty list.
#[test]
fn list_push_configs_is_answered_for_the_owner_and_is_an_absent_task_for_everybody_else() {
    let mut desk = desk();
    let cfg = json!({ "taskId": "t1", "id": "cfg-l", "url": "https://hooks.example/cb" });
    call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
    let list = |desk: &mut Desk, task: &str, caller: &str| {
        call(
            desk,
            "ListTaskPushNotificationConfigs",
            json!({ "taskId": task }),
            caller,
        )
    };
    let (_, mine) = list(&mut desk, "t1", ALICE);
    assert_eq!(mine["result"]["configs"].as_array().map(Vec::len), Some(1));
    let foreign = list(&mut desk, "t1", BOB);
    let absent = list(&mut desk, "never-existed", BOB);
    assert_eq!(foreign, absent);
    assert_eq!(error_of(&foreign.1).0, -32001);
}

/// Another caller's delete cannot disarm the owner's callback: it answers as for an absent task and
/// the owner's record stays, and the owner can still delete it.
#[test]
fn delete_push_config_cannot_disarm_another_principals_callback() {
    let mut desk = desk();
    let cfg = json!({ "taskId": "t1", "id": "cfg-d", "url": "https://hooks.example/cb" });
    call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
    let delete = |desk: &mut Desk, task: &str, caller: &str| {
        call(
            desk,
            "DeleteTaskPushNotificationConfig",
            json!({ "taskId": task, "id": "cfg-d" }),
            caller,
        )
    };
    let foreign = delete(&mut desk, "t1", BOB);
    let absent = delete(&mut desk, "never-existed", BOB);
    assert_eq!(foreign, absent);
    assert!(
        desk.book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_some(),
        "the owner's callback is still armed"
    );
    let (status, mine) = delete(&mut desk, "t1", ALICE);
    assert_eq!((status, mine["result"].clone()), (200, json!({})));
    assert!(desk
        .book
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
        .is_none());
}

/// A subscribe is relayed for the owner of a live task (no local refusal); for anybody else it is
/// refused exactly as an id that never existed is.
#[test]
fn subscribe_is_relayed_for_the_owner_and_is_an_absent_task_for_everybody_else() {
    let mut desk = desk();
    let envelope = |id: &str| json!({ "jsonrpc": "2.0", "id": 1, "method": "SubscribeToTask", "params": { "id": id } });
    let mut refusal = |id: &str, caller: &str| {
        answer(
            &mut desk,
            LocalVerb::Subscribe,
            &envelope(id),
            caller,
            300,
            &mut Vec::new(),
        )
        .unwrap()
    };
    assert_eq!(refusal("t1", ALICE), None, "the owner's subscribe relays");
    let foreign = refusal("t1", BOB).expect("a foreign id is refused");
    let absent = refusal("never-existed", BOB).expect("an absent id is refused");
    assert_eq!(foreign, absent);
}

/// The v0.3 spelling is answered in the v0.3 shape: the config nested under
/// `pushNotificationConfig`, and no flattened `url`.
#[test]
fn the_v0_3_spelling_is_answered_in_the_v0_3_shape() {
    let mut desk = desk();
    let params = json!({ "taskId": "t1",
                         "pushNotificationConfig": { "id": "cfg-v03", "url": "https://hooks.example/cb" } });
    let (status, body) = call(&mut desk, "tasks/pushNotificationConfig/set", params, ALICE);
    assert_eq!(status, 200, "{body}");
    let created = &body["result"];
    assert_eq!(created["pushNotificationConfig"]["id"], "cfg-v03");
    assert_eq!(
        created["pushNotificationConfig"]["url"],
        "https://hooks.example/cb"
    );
    assert!(
        created.get("url").is_none(),
        "the v1.0 flattening must not leak into a v0.3 answer"
    );
}

/// Every A2A method of the inventory is read the same way under its v1.0 and its v0.3 JSON-RPC
/// name: the local verb it is, the class it is relayed as, and whether its answer is events.
#[test]
fn every_a2a_method_is_read_identically_under_both_of_its_live_json_rpc_names() {
    const INVENTORY: &str = include_str!("../../../../qa/method-inventory.json");
    let doc: Value = serde_json::from_str(INVENTORY).expect("the inventory parses");
    let methods = doc["methods"].as_array().expect("a methods array");
    fn how_busbar_reads(method: &str) -> (Option<&'static str>, String, Option<bool>) {
        let verb = verb_of(method).map(|v| match v {
            LocalVerb::ListTasks => "ListTasks",
            LocalVerb::CreatePushConfig(_) => "CreatePushConfig",
            LocalVerb::GetPushConfig(_) => "GetPushConfig",
            LocalVerb::ListPushConfigs(_) => "ListPushConfigs",
            LocalVerb::DeletePushConfig(_) => "DeletePushConfig",
            LocalVerb::Subscribe => "Subscribe",
        });
        let class = crate::ops::relay_class(method).as_str().to_string();
        let streams = crate::ops::row_for(method).map(|r| r.multi_frame);
        (verb, class, streams)
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
            continue;
        };
        checked += 1;
        assert_eq!(
            how_busbar_reads(pascal),
            how_busbar_reads(slash),
            "`{pascal}` and `{slash}` are read differently by this plane"
        );
    }
    assert!(
        checked >= 11,
        "only {checked} A2A methods carried both wire names; the inventory is not being read"
    );
}

/// A v0.3 set then a v0.3 delete naming the config by `pushNotificationConfigId` (the task by `id`)
/// actually clears the record, not only answers success.
#[test]
fn v03_delete_reads_pushnotificationconfigid_and_actually_clears() {
    let mut desk = desk();
    let set = json!({ "id": "t1",
                      "pushNotificationConfig": { "id": "cfg-v03", "url": "https://hooks.example/cb" } });
    let (_, created) = call(&mut desk, "tasks/pushNotificationConfig/set", set, ALICE);
    assert_eq!(
        created["result"]["pushNotificationConfig"]["id"], "cfg-v03",
        "{created}"
    );
    assert!(desk
        .book
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
        .is_some());
    let (status, deleted) = call(
        &mut desk,
        "tasks/pushNotificationConfig/delete",
        json!({ "id": "t1", "pushNotificationConfigId": "cfg-v03" }),
        ALICE,
    );
    assert_eq!(status, 200);
    assert!(deleted.get("error").is_none(), "{deleted}");
    assert!(
        desk.book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_none(),
        "the record is ACTUALLY cleared"
    );
}

// ── the callback floor: the host's verdict, the engine's words (`pushnotify_tests.rs`) ──────────

/// THE DESTINATION IS THE HOST'S TO JUDGE (`BUSBAR-1.6.0.md` §5, the ONE destination guard): an
/// internal literal is refused because the host's judge refused it, and the judge was asked for it;
/// a judge that admits it (an operator's allow-list) is not second-guessed by a check of the
/// plane's own. RED before the guard moved: the plane refused the literal itself and never asked.
#[test]
fn an_internal_callback_is_refused_on_the_hosts_verdict_and_the_host_is_asked() {
    let url = "https://10.0.0.1/cb";
    let mut desk = desk();
    desk.verdict = DEST_INTERNAL;
    let cfg = json!({ "taskId": "t1", "id": "c1", "url": url });
    let (status, body) = call(
        &mut desk,
        "CreateTaskPushNotificationConfig",
        cfg.clone(),
        ALICE,
    );
    assert_eq!(status, 400);
    assert_eq!(
        error_of(&body),
        (
            -32602,
            "push callback resolves to the INTERNAL address 10.0.0.1; delivering there would lend \
             busbar's network position to the caller"
                .to_string()
        )
    );
    assert_eq!(desk.judged, vec![url.to_string()], "the host decided it");

    let mut admitted = self::desk();
    let (status, body) = call(
        &mut admitted,
        "CreateTaskPushNotificationConfig",
        cfg,
        ALICE,
    );
    assert_eq!(
        status, 200,
        "no check of the plane's own refuses it: {body}"
    );
    assert_eq!(admitted.judged, vec![url.to_string()]);
}

/// An alternate IPv4 spelling is refused in the engine's words, on the host's verdict.
#[test]
fn obfuscated_ipv4_hosts_are_refused_before_anything_is_resolved() {
    for host in [
        "2130706433",
        "0x7f000001",
        "017700000001",
        "127.1",
        "0xa9.0xfe.0xa9.0xfe",
    ] {
        let url = format!("https://{host}/cb");
        let mut desk = desk();
        desk.verdict = DEST_OBFUSCATED;
        let cfg = json!({ "taskId": "t1", "id": "c1", "url": url });
        let (_, body) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
        assert_eq!(
            error_of(&body),
            (
                -32602,
                format!(
                    "push callback host `{host}` is an alternate IPv4 encoding, which resolves to \
                     an address a canonical literal check would not see"
                )
            ),
            "`{host}`"
        );
        assert_eq!(desk.judged, vec![url.clone()]);
    }
}

/// A URL whose authority names a user is malformed, refused rather than normalised, before the
/// host is asked anything.
#[test]
fn a_url_with_userinfo_is_refused_rather_than_normalised() {
    let url = "https://169.254.169.254@caller.example/cb";
    let mut desk = desk();
    let cfg = json!({ "taskId": "t1", "id": "c1", "url": url });
    let (_, body) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
    assert_eq!(
        error_of(&body),
        (-32602, format!("push callback URL is malformed: `{url}`"))
    );
    assert!(desk.judged.is_empty());
}

/// A string that is not a URL is refused, and a scheme the host does not admit is refused in the
/// engine's scheme words.
#[test]
fn malformed_urls_are_refused() {
    let words = |url: &str| format!("push callback URL is malformed: `{url}`");
    for (url, verdict, said) in [
        ("not-a-url", DEST_ALLOWED, words("not-a-url")),
        (
            "https:/caller.example",
            DEST_ALLOWED,
            words("https:/caller.example"),
        ),
        (
            "https://",
            DEST_ALLOWED,
            "push callback URL has no host".to_string(),
        ),
        ("://x", DEST_ALLOWED, words("://x")),
        (
            "https://caller.example:99999/",
            DEST_NO_HOST,
            words("https://caller.example:99999/"),
        ),
        (
            "ftp://caller.example/",
            DEST_SCHEME,
            "push callback scheme `ftp` is refused; a callback carries task metadata off-box and \
             must be https"
                .to_string(),
        ),
    ] {
        let mut desk = desk();
        desk.verdict = verdict;
        let cfg = json!({ "taskId": "t1", "id": "c1", "url": url });
        let (status, body) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
        assert_eq!((status, error_of(&body)), (400, (-32602, said)), "`{url}`");
        assert!(desk
            .book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_none());
    }
}
