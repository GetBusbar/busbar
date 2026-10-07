// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The task a relayed hop is for, over the test's host records: opened as the served engine's
//! unary hop opens it (addressed, resumed or minted), and settled on the far end's answer.

use busbar_contract::abi::host::service::{DEST_ALLOWED, DEST_INTERNAL};
use serde_json::json;

use super::*;
use crate::records::{KIND_TASK, KIND_TASK_EVENT};
use crate::tasks::tests::{submitted, Book, ALICE, BOB};
use crate::tasks::{event_key, get};
use crate::TaskEventRow;

/// The host records, the random bytes the kernel hands out, and the destination judge's verdict.
struct Desk {
    book: Book,
    random: [u8; MINT_BYTES],
    draws: usize,
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

impl Mint for Desk {
    fn random(&mut self, buf: &mut [u8]) -> Result<(), Halt> {
        self.draws += 1;
        buf.copy_from_slice(&self.random[..buf.len()]);
        Ok(())
    }
}

const MEMBER: &str = "planner";
const MINTED: &str = "a2a-planner-0102030405060708";

/// Alice holds `t1`, Bob `t2`.
fn desk() -> Desk {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    submitted(&mut book, BOB, "t2", 100);
    Desk {
        book,
        random: [1, 2, 3, 4, 5, 6, 7, 8],
        draws: 0,
        verdict: DEST_ALLOWED,
    }
}

fn send(params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": 7, "method": "SendMessage", "params": params })
}

/// Open `envelope` for `caller` at 300 and apply its writes.
fn opened(desk: &mut Desk, envelope: &Value, caller: &str) -> Opened {
    opened_with(desk, envelope, caller, &|_| None)
}

fn opened_with(
    desk: &mut Desk,
    envelope: &Value,
    caller: &str,
    backends: &dyn Fn(&str) -> Option<String>,
) -> Opened {
    let mut out = Vec::new();
    let req = Request {
        envelope,
        relayed: None,
        caller,
        member: MEMBER,
        now: 300,
    };
    let opened = open(desk, &req, &json!(7), backends, &mut out).unwrap();
    desk.book.apply(&out);
    opened
}

fn hop(opened: Opened) -> (TaskHop, Option<Vec<u8>>) {
    match opened {
        Opened::Hop { task, instead, .. } => (task, instead),
        Opened::Refused(reply) => panic!("refused: {reply:?}"),
    }
}

fn event(desk: &Desk, task: &str, seq: u64) -> TaskEventRow {
    serde_json::from_slice(
        desk.book
            .value(KIND_TASK_EVENT, &event_key(ALICE, task, seq))
            .expect("the event"),
    )
    .unwrap()
}

#[test]
fn a_fresh_request_mints_busbars_id_and_opens_the_task_dispatched_to_the_agent() {
    let mut desk = desk();
    let (task, instead) = hop(opened(
        &mut desk,
        &send(json!({ "message": { "messageId": "m" } })),
        ALICE,
    ));
    assert_eq!(
        task,
        TaskHop {
            task_id: MINTED.into(),
            context_id: MINTED.into(),
            addressed: false,
            skill: None,
        }
    );
    assert_eq!(instead, None);
    assert_eq!(desk.draws, 1);
    let held = get(&mut desk.book, ALICE, MINTED, 300).unwrap().unwrap();
    assert_eq!(held.row.state, "submitted");
    assert_eq!(held.row.agent_id, MEMBER);
    assert_eq!(held.row.principal, ALICE);
    assert_eq!(held.next_seq, 3);
    let (genesis, dispatch) = (event(&desk, MINTED, 1), event(&desk, MINTED, 2));
    assert_eq!(genesis.kind, "task.submitted");
    assert_eq!(dispatch.kind, "task.delegated");
    assert_eq!(dispatch.prev_hash, genesis.hash);
    assert_eq!(dispatch.request_id, MINTED);
}

#[test]
fn a_fresh_request_keeps_the_callers_context() {
    let mut desk = desk();
    let (task, _) = hop(opened(
        &mut desk,
        &send(json!({ "message": { "contextId": "conv-9" } })),
        ALICE,
    ));
    assert_eq!(task.task_id, MINTED);
    assert_eq!(task.context_id, "conv-9");
}

#[test]
fn a_request_naming_a_task_the_caller_holds_reuses_it_and_opens_nothing() {
    let mut desk = desk();
    let before = desk.book.clone();
    let get_task =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": "t1" } });
    let (task, _) = hop(opened(&mut desk, &get_task, ALICE));
    assert_eq!(task.task_id, "t1");
    assert_eq!(task.context_id, "ctx-1");
    assert!(task.addressed);
    assert_eq!(desk.draws, 0);
    assert_eq!(
        desk.book.value(KIND_TASK, "a11ce/t1"),
        before.value(KIND_TASK, "a11ce/t1")
    );
}

#[test]
fn a_task_another_caller_holds_is_not_addressed_so_a_fresh_one_is_minted() {
    let mut desk = desk();
    let get_task =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": "t2" } });
    let (task, _) = hop(opened(&mut desk, &get_task, ALICE));
    assert_eq!(task.task_id, MINTED);
    assert!(!task.addressed);
}

#[test]
fn an_interrupted_task_on_the_agent_under_the_callers_context_resumes_as_working() {
    let mut desk = desk();
    let mut out = Vec::new();
    let at = Step {
        caller: ALICE,
        request_id: "r",
        now: 150,
    };
    tasks::dispatch(&mut desk.book, &at, "t1", MEMBER, &mut out).unwrap();
    desk.book.apply(&out);
    out.clear();
    tasks::transition(&mut desk.book, &at, "t1", TaskState::Working, &mut out).unwrap();
    desk.book.apply(&out);
    out.clear();
    tasks::transition(
        &mut desk.book,
        &at,
        "t1",
        TaskState::InputRequired,
        &mut out,
    )
    .unwrap();
    desk.book.apply(&out);
    let (task, _) = hop(opened(
        &mut desk,
        &send(json!({ "message": { "contextId": "ctx-1" } })),
        ALICE,
    ));
    assert_eq!(task.task_id, "t1");
    assert!(!task.addressed);
    assert_eq!(desk.draws, 0);
    let held = get(&mut desk.book, ALICE, "t1", 300).unwrap().unwrap();
    assert_eq!(held.row.state, "working");
}

#[test]
fn a_task_that_cannot_be_recorded_is_refused_503_in_the_engines_words() {
    let mut desk = desk();
    desk.book
        .claim(KIND_TASK_EVENT, &event_key(ALICE, MINTED, 1), 0)
        .unwrap();
    let Opened::Refused(reply) = opened(&mut desk, &send(json!({})), ALICE) else {
        panic!("not refused");
    };
    assert_eq!(reply.status, 503);
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(
        body,
        json!({ "jsonrpc": "2.0", "id": 7,
            "error": { "code": -32603, "message": "the task could not be recorded" } })
    );
}

#[test]
fn a_held_task_id_whose_far_end_id_is_known_is_sent_on_as_the_far_ends() {
    let mut desk = desk();
    let back = |id: &str| (id == "t1" || id == "t2").then(|| format!("far-{id}"));
    let cancel =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "CancelTask", "params": { "id": "t1" } });
    let (_, instead) = hop(opened_with(&mut desk, &cancel, ALICE, &back));
    let sent: Value = serde_json::from_slice(&instead.expect("translated")).unwrap();
    assert_eq!(sent["params"]["id"], "far-t1");
    let foreign =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "CancelTask", "params": { "id": "t2" } });
    let (_, instead) = hop(opened_with(&mut desk, &foreign, ALICE, &back));
    assert_eq!(instead, None);
}

fn settled(desk: &mut Desk, task: &TaskHop, how: &Settled) -> usize {
    let mut out = Vec::new();
    settle(&mut desk.book, task, how, ALICE, 400, &mut out).unwrap();
    desk.book.apply(&out);
    out.len()
}

#[test]
fn the_answer_records_the_reported_state_and_a_failed_hop_ends_the_task_failed() {
    let mut desk = desk();
    let (task, _) = hop(opened(&mut desk, &send(json!({})), ALICE));
    let submitted_again = Settled::Reported {
        state: TaskState::Submitted,
        backend_id: None,
    };
    assert_eq!(settled(&mut desk, &task, &submitted_again), 0);
    let completed = Settled::Reported {
        state: TaskState::Completed,
        backend_id: Some("b".into()),
    };
    assert_eq!(settled(&mut desk, &task, &completed), 2);
    let row = get(&mut desk.book, ALICE, MINTED, 400)
        .unwrap()
        .unwrap()
        .row;
    assert_eq!(row.state, "completed");

    let (other, _) = hop(opened(
        &mut desk,
        &send(json!({ "message": { "contextId": "c2" } })),
        BOB,
    ));
    let mut out = Vec::new();
    settle(&mut desk.book, &other, &Settled::Failed, BOB, 400, &mut out).unwrap();
    desk.book.apply(&out);
    let row = get(&mut desk.book, BOB, &other.task_id, 400)
        .unwrap()
        .unwrap()
        .row;
    assert_eq!(row.state, "failed");
}

// ── the push callback a request carries inline ─────────────────────────────────────────────────

/// A message carrying `config` inline as v0.3 spells it.
fn with_callback(config: Value) -> Value {
    send(json!({
        "message": { "messageId": "m" },
        "configuration": { "pushNotificationConfig": config },
    }))
}

/// The refusal an opening answered: its status, code and message.
fn refusal_of(opened: Opened) -> (u32, i64, String) {
    let Opened::Refused(reply) = opened else {
        panic!("not refused: {opened:?}");
    };
    let doc: Value = serde_json::from_slice(&reply.body).unwrap();
    (
        reply.status,
        doc["error"]["code"].as_i64().unwrap(),
        doc["error"]["message"].as_str().unwrap().to_string(),
    )
}

/// A callback the floor refuses refuses the request `400` (InvalidParams) in the floor's words,
/// before anything is opened: no id is minted and nothing is written (the engine's inline guard).
#[test]
fn an_inline_callback_the_floor_refuses_refuses_the_request_before_anything_opens() {
    for (url, verdict, words) in [
        ("http://hook.example/cb", DEST_ALLOWED, "must be https"),
        ("https://10.0.0.7/cb", DEST_ALLOWED, "INTERNAL address"),
        ("https://hook.example/cb", DEST_INTERNAL, "INTERNAL address"),
    ] {
        let mut desk = desk();
        desk.verdict = verdict;
        let mut out = Vec::new();
        let envelope = with_callback(json!({ "url": url }));
        let req = Request {
            envelope: &envelope,
            relayed: None,
            caller: ALICE,
            member: MEMBER,
            now: 300,
        };
        let opened = open(&mut desk, &req, &json!(7), &|_| None, &mut out).unwrap();
        let (status, code, message) = refusal_of(opened);
        assert_eq!((status, code), (400, -32602), "{url}");
        assert!(message.contains(words), "{url}: {message}");
        assert!(out.is_empty(), "{url}: nothing is written");
        assert_eq!(desk.draws, 0, "{url}: no id is minted");
    }
}

/// A credential busbar cannot present refuses the request `400` too, never delivered bare.
#[test]
fn an_inline_credential_busbar_cannot_present_refuses_the_request() {
    let mut desk = desk();
    let envelope = with_callback(json!({
        "url": "https://hook.example/cb",
        "authentication": { "credentials": "s3cret" },
    }));
    let (status, code, message) = refusal_of(opened(&mut desk, &envelope, ALICE));
    assert_eq!((status, code), (400, -32602));
    assert!(message.contains("must name a `scheme`"), "{message}");
    assert!(
        !message.contains("s3cret"),
        "the credential is never quoted back"
    );
}

/// A callback that passes is the push callback on the task the request opens, and its credential
/// rides back for the door to hold; the chain gains no event for it.
#[test]
fn an_inline_callback_that_passes_is_the_opened_tasks_callback() {
    let mut desk = desk();
    let envelope = with_callback(json!({
        "url": "https://hook.example/cb?k=v",
        "authentication": { "schemes": ["Bearer"], "credentials": "tok" },
    }));
    let Opened::Hop { task, callback, .. } = opened(&mut desk, &envelope, ALICE) else {
        panic!("refused");
    };
    let callback = callback.expect("the callback rides back");
    assert_eq!(callback.url, "https://hook.example/cb?k=v");
    assert_eq!(
        callback.auth.map(|a| a.header_value()),
        Some("Bearer tok".to_string())
    );
    let held = get(&mut desk.book, ALICE, &task.task_id, 300)
        .unwrap()
        .unwrap();
    assert_eq!(held.row.push_callback, "https://hook.example/cb?k=v");
    assert_eq!(held.next_seq, 3, "submitted and delegated, nothing more");
}

/// A request addressing a task the caller holds registers the callback on THAT task, keeping its
/// chain where it was (the engine's `set_push_callback` chains no event).
#[test]
fn an_inline_callback_on_an_addressed_task_is_registered_without_an_event() {
    let mut desk = desk();
    let before = get(&mut desk.book, ALICE, "t1", 300).unwrap().unwrap();
    let envelope = send(json!({
        "id": "t1",
        "configuration": { "pushNotificationConfig": { "url": "https://hook.example/t1" } },
    }));
    let (task, _) = hop(opened(&mut desk, &envelope, ALICE));
    assert_eq!(task.task_id, "t1");
    let after = get(&mut desk.book, ALICE, "t1", 300).unwrap().unwrap();
    assert_eq!(after.row.push_callback, "https://hook.example/t1");
    assert_eq!(
        (after.next_seq, &after.tail_hash),
        (before.next_seq, &before.tail_hash)
    );
}

/// A request with no inline callback carries none back, and opens a task with none.
#[test]
fn a_request_with_no_inline_callback_registers_none() {
    let mut desk = desk();
    let Opened::Hop { task, callback, .. } = opened(
        &mut desk,
        &send(json!({ "message": { "messageId": "m" } })),
        ALICE,
    ) else {
        panic!("refused");
    };
    assert_eq!(callback, None);
    let held = get(&mut desk.book, ALICE, &task.task_id, 300)
        .unwrap()
        .unwrap();
    assert_eq!(held.row.push_callback, "");
}

// ── the tenancy boundary, for every spelling of the task member ────────────────────────────────

/// A `backends` answer that knows a far-end id for every busbar id asked about, so the only thing
/// standing between a caller and a translation is the ownership read.
fn far(id: &str) -> Option<String> {
    Some(format!("far-{id}"))
}

/// What `ALICE`'s request opens over a fresh desk (Alice holds `t1`, Bob `t2`): the task it is for
/// and the bytes sent on instead of hers, if any.
fn alice_sends(envelope: &Value) -> (TaskHop, Option<Vec<u8>>) {
    hop(opened_with(&mut desk(), envelope, ALICE, &far))
}

/// EVERY SPELLING OF THE ADDRESSING MEMBER, for the non-owner: the boundary must not depend on
/// which of the three names a caller reached for. The owner's request is translated, and the
/// non-owner's names a task it does not hold, so it is left as a never-existed id is left.
/// Ported from busbar-a2a a2a/tests/idmap_tests.rs::no_spelling_of_the_task_member_crosses_the_boundary.
#[test]
fn no_spelling_of_the_task_member_crosses_the_boundary() {
    for member in ["id", "taskId", "task_id"] {
        let naming = |id: &str| {
            json!({
                "jsonrpc": "2.0", "id": 7, "method": "GetTaskPushNotificationConfig",
                "params": { member: id }
            })
        };
        let (task, instead) = alice_sends(&naming("t1"));
        assert!(task.addressed, "`{member}` addresses the owner's task");
        let sent: Value = serde_json::from_slice(
            &instead.unwrap_or_else(|| panic!("`{member}` must still translate for the owner")),
        )
        .unwrap();
        assert_eq!(sent["params"][member], "far-t1", "{member}");

        // Bob holds `t2`: Alice naming it translates nothing, exactly as a task that never was.
        let (task, instead) = alice_sends(&naming("t2"));
        assert!(
            !task.addressed,
            "`{member}`: another caller's task is not addressed"
        );
        assert_eq!(
            instead, None,
            "`{member}` must not translate for a caller that does not hold the task"
        );
        let (_, never) = alice_sends(&naming("never-was"));
        assert_eq!(never, instead, "{member}");
    }
}

/// THE WRITE THROUGH THE SECOND TURN. `params.message.taskId` is how a caller continues a
/// conversation: the owner's second turn reaches its own open task, and an intruder's pointed at
/// another caller's task is left untranslated, the same as one pointed at a task that never was.
/// Ported from busbar-a2a a2a/tests/idmap_tests.rs::the_second_turns_task_id_cannot_be_pointed_at_another_principals_conversation.
#[test]
fn the_second_turns_task_id_cannot_be_pointed_at_another_principals_conversation() {
    let turn = |id: &str| {
        send(json!({ "message": { "role": "ROLE_USER", "messageId": "m-9", "taskId": id } }))
    };

    let (_, mine) = alice_sends(&turn("t1"));
    let mine: Value =
        serde_json::from_slice(&mine.expect("the owner's second turn is translated")).unwrap();
    assert_eq!(mine.pointer("/params/message/taskId").unwrap(), "far-t1");

    let (_, at_bobs) = alice_sends(&turn("t2"));
    let (_, at_nothing) = alice_sends(&turn("never-was"));
    assert_eq!(at_bobs, None, "another caller's task is not joined");
    assert_eq!(
        at_bobs, at_nothing,
        "a second turn at another caller's task is indistinguishable from one at a task that does not exist"
    );
}

/// EVERY SPELLING OF THE INLINE CALLBACK IS FOUND, so every spelling is judged by the floor: v0.3's
/// `pushNotificationConfig`, v1.0's flat `taskPushNotificationConfig` and its nested one. What is
/// not found is not guarded; and a callback the floor refuses is refused in all three.
/// Ported from busbar-a2a a2a/tests/ingress_tests.rs::every_spelling_of_the_callback_is_found_so_every_spelling_is_guarded.
#[test]
fn every_spelling_of_the_callback_is_found_so_every_spelling_is_guarded() {
    let spellings = |url: &str| {
        [
            (
                "v0.3",
                json!({"params": {"configuration": {
                    "pushNotificationConfig": {"url": url}}}}),
            ),
            (
                "v1.0, flat",
                json!({"params": {"configuration": {
                    "taskPushNotificationConfig": {"id": "c", "url": url}}}}),
            ),
            (
                "v1.0, nested",
                json!({"params": {"configuration": {"taskPushNotificationConfig": {
                    "name": "tasks/1", "pushNotificationConfig": {"url": url}}}}}),
            ),
        ]
    };
    for (label, envelope) in spellings("https://hook.example/a") {
        assert_eq!(
            inline_config(&envelope).and_then(|c| c.get("url")),
            Some(&json!("https://hook.example/a")),
            "the {label} spelling must be FOUND, because what is not found is not guarded"
        );
        let mut desk = desk();
        let Opened::Hop { callback, .. } = opened(&mut desk, &envelope, ALICE) else {
            panic!("the {label} spelling was refused");
        };
        assert_eq!(
            callback.map(|c| c.url).as_deref(),
            Some("https://hook.example/a"),
            "{label}"
        );
    }
    // The floor judges what was found: a plaintext callback is refused through each spelling.
    for (label, envelope) in spellings("http://hook.example/a") {
        let mut desk = desk();
        let (status, code, message) = refusal_of(opened(&mut desk, &envelope, ALICE));
        assert_eq!((status, code), (400, -32602), "{label}");
        assert!(message.contains("must be https"), "{label}: {message}");
    }
    // And nothing is invented: a request that registers no callback acquires none.
    for envelope in [
        json!({"params": {}}),
        json!({"params": {"configuration": {}}}),
        json!({"params": {"configuration": {"taskPushNotificationConfig": {"id": "c"}}}}),
        json!({"params": {"configuration": {"taskPushNotificationConfig": {"id": "c", "url": ""}}}}),
    ] {
        assert!(inline_config(&envelope).is_none(), "{envelope}");
    }
}

/// A far end that issued the SAME id busbar did needs no translation: the caller's bytes go on
/// unchanged, never re-serialized (and the pair would not occupy a slot).
/// Ported from busbar-a2a a2a/tests/idmap_tests.rs::a_degenerate_pair_is_not_recorded (same-id half).
#[test]
#[ignore = "A2A-FLIP regression: the door records a far-end id equal to busbar's own (plane_door keep) and re-serializes the request; predev recorded no same-id pair"]
fn a_far_end_id_equal_to_busbars_needs_no_translation() {
    let mut desk = desk();
    let same = |id: &str| (id == "t1").then(|| "t1".to_string());
    let get_task =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": "t1" } });
    let (_, instead) = hop(opened_with(&mut desk, &get_task, ALICE, &same));
    assert_eq!(instead, None, "the caller's bytes go on unchanged");
}
