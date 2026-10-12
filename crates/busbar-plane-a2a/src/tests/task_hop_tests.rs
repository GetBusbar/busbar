// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The task a relayed hop is for, over the test's host records: opened as the served engine's
//! unary hop opens it (addressed, resumed or minted), and settled on the far end's answer.

use busbar_contract::abi::host::service::{DEST_ALLOWED, DEST_INTERNAL, DEST_PLAINTEXT};
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
        addressed: None,
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
    // The event's `request_id` join key is not on the chain: the host keeps a chained record's own
    // bytes, every one of them digested, and the join key stays out of the digest (ARCHITECT
    // ruling B1).
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
    settle(
        &mut desk.book,
        task,
        how,
        ALICE,
        400,
        &mut out,
        &Latches::new(),
    )
    .unwrap();
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
    settle(
        &mut desk.book,
        &other,
        &Settled::Failed,
        BOB,
        400,
        &mut out,
        &Latches::new(),
    )
    .unwrap();
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
/// The refusal is the host destination judge's verdict (plaintext, an internal literal or name),
/// worded by the plane.
#[test]
fn an_inline_callback_the_floor_refuses_refuses_the_request_before_anything_opens() {
    for (url, verdict, words) in [
        ("http://hook.example/cb", DEST_PLAINTEXT, "must be https"),
        (
            "https://10.0.0.7/cb",
            DEST_INTERNAL,
            "INTERNAL address 10.0.0.7",
        ),
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
            addressed: None,
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
        after.next_seq, before.next_seq,
        "no event was chained: the chain's position is kept"
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
        // The host's judge answers a plaintext destination under the open-web class this need
        // declares `DEST_PLAINTEXT` (busbar-core-connector process.rs, `GuardJudge::named`); the
        // plane asks it rather than reading the scheme itself, so the double answers as it does.
        desk.verdict = DEST_PLAINTEXT;
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
fn a_far_end_id_equal_to_busbars_needs_no_translation() {
    let mut desk = desk();
    let same = |id: &str| (id == "t1").then(|| "t1".to_string());
    let get_task =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": "t1" } });
    let (_, instead) = hop(opened_with(&mut desk, &get_task, ALICE, &same));
    assert_eq!(instead, None, "the caller's bytes go on unchanged");
}
// ── a hop the kernel refused before it dialled ─────────────────────────────────────────────────

/// Open `envelope` for Alice at 300: what opened, and the record writes the opening made (applied).
fn opened_writing(desk: &mut Desk, envelope: &Value) -> (Opened, Vec<Write>) {
    let mut out = Vec::new();
    let req = Request {
        envelope,
        relayed: None,
        caller: ALICE,
        member: MEMBER,
        addressed: None,
        now: 300,
    };
    let opened = open(desk, &req, &json!(7), &|_| None, &mut out).unwrap();
    desk.book.apply(&out);
    (opened, out)
}

// ── a refused hop's task end, racing another writer of the task ───────────────────────────────

/// End the refused hop's `task` failed, as the door ends it on the refused piece, on the unit's
/// own ticket: [`settle`] on `Settled::Failed` over the host's records (`plane_door::settle_task`).
fn ended_on_refusal(d: &mut Desk, task: &TaskHop) -> Vec<Write> {
    let mut out = Vec::new();
    settle(
        &mut d.book,
        task,
        &Settled::Failed,
        ALICE,
        300,
        &mut out,
        &Latches::new(),
    )
    .unwrap();
    out
}

/// A HOP REFUSED FOR AN UNAVAILABLE CREDENTIAL ENDS ITS TASK WITHOUT LOSING ANOTHER WRITER'S
/// CHANGE (the engine's `end_task`, origin/predev `crates/busbar-a2a/src/a2a/receive.rs:3485-3500`:
/// `TASKS.transition` under the task's own lock, `crates/busbar-kernel/src/plane/handle_engine.rs:
/// 711-736`). Another unit moves the addressed task between the hop's opening and its refusal; the
/// end is chained after that move: the other writer's event stands, the failure is the next one,
/// and the task as held is failed with the chain's tail on the failure.
#[test]
fn a_refused_hops_task_end_keeps_a_concurrent_writers_change() {
    let mut d = desk();
    let get_task =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": "t1" } });
    let (addressed, _) = opened_writing(&mut d, &get_task);
    let Opened::Hop { task, .. } = addressed else {
        panic!("refused");
    };
    let next = get(&mut d.book, ALICE, "t1", 300)
        .unwrap()
        .unwrap()
        .next_seq;

    // ANOTHER UNIT moves the task while the refused hop is handled: it wins the next sequence.
    let mut theirs = Vec::new();
    let other = Step {
        caller: ALICE,
        request_id: "another-unit",
        now: 300,
    };
    crate::tasks::transition(&mut d.book, &other, "t1", TaskState::Working, &mut theirs)
        .unwrap()
        .expect("it moved");
    d.book.apply(&theirs);
    let their_event = d
        .book
        .value(KIND_TASK_EVENT, &event_key(ALICE, "t1", next))
        .cloned()
        .expect("their event");

    let ours = ended_on_refusal(&mut d, &task);
    d.book.apply(&ours);

    assert_eq!(
        d.book
            .value(KIND_TASK_EVENT, &event_key(ALICE, "t1", next))
            .cloned(),
        Some(their_event),
        "the other writer's event stands"
    );
    let failed = event(&d, "t1", next + 1);
    assert_eq!(failed.state, "failed", "the failure is the next event");
    let held = get(&mut d.book, ALICE, "t1", 300).unwrap().unwrap();
    assert_eq!(held.row.state, "failed");
    // The failure is the chain's tail: the door holds no tail hash of its own, since the host seals
    // the chain on the record path (B1 ruling 1, coordinator 2026-10-07).
    assert_eq!(held.next_seq, next + 2);
}

// ── ported from the engine's `relay_stream_tests` ──────────────────────────────────────────────

/// Put `caller`'s `task` on [`MEMBER`] and walk it through `states` at 150.
fn walk(desk: &mut Desk, caller: &str, task: &str, states: &[TaskState]) {
    let at = Step {
        caller,
        request_id: "r",
        now: 150,
    };
    let mut out = Vec::new();
    tasks::dispatch(&mut desk.book, &at, task, MEMBER, &mut out).unwrap();
    desk.book.apply(&out);
    for state in states {
        let mut out = Vec::new();
        tasks::transition(&mut desk.book, &at, task, *state, &mut out).unwrap();
        desk.book.apply(&out);
    }
}

/// Ported from busbar-a2a a2a/tests/relay_stream_tests.rs::an_interrupt_from_the_backend_is_relayed_transparently_and_pauses_the_task.
/// A far end's `input-required` answer is relayed as 200 with its question, under busbar's ids,
/// and the task it settles is PAUSED: live, never terminal.
#[test]
fn an_interrupt_from_the_backend_is_relayed_transparently_and_pauses_the_task() {
    use crate::relay::{Answer, From as Side, Piece, Relay};
    let mut desk = desk();
    let (task, _) = hop(opened(
        &mut desk,
        &send(json!({ "message": { "contextId": "ctx-abc" } })),
        ALICE,
    ));
    let mut r = Relay::new(json!(7), "1.0");
    r.for_task(task.clone());
    let piece = |from, bytes, status, last| Piece {
        from,
        bytes,
        status,
        last,
    };
    let url = "https://vendor.example/a2a";
    assert!(matches!(
        r.on_piece(piece(Side::Kernel(Some(url)), &[], None, false)),
        Answer::Attempt(_)
    ));
    let ask = br#"{"jsonrpc":"2.0","id":7,"method":"SendMessage","params":{}}"#;
    assert!(matches!(
        r.on_piece(piece(Side::Caller, ask, None, true)),
        Answer::ToFarEnd(_) | Answer::ToFarEndLent
    ));
    let far = json!({
        "jsonrpc": "2.0", "id": 7,
        "result": {
            "id": "B1", "contextId": "BC", "kind": "task",
            "status": {
                "state": "input-required",
                "message": { "role": "agent", "parts": [{ "kind": "text", "text": "WHICH REGION?" }] }
            }
        }
    })
    .to_string();
    let Answer::ToCaller(reply) = r.on_piece(piece(Side::FarEnd, far.as_bytes(), Some(200), true))
    else {
        panic!("no answer");
    };
    assert_eq!(reply.status, 200, "an interrupt is not a failure");
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["result"]["status"]["state"], "input-required");
    assert_eq!(
        body["result"]["status"]["message"]["parts"][0]["text"], "WHICH REGION?",
        "the backend's question must reach the caller"
    );
    assert_eq!(
        body["result"]["id"], MINTED,
        "busbar's id, not the backend's"
    );
    assert_eq!(
        body["result"]["contextId"], "ctx-abc",
        "the caller's context, unchanged"
    );

    for how in r.take_settled() {
        settled(&mut desk, &task, &how);
    }
    let row = get(&mut desk.book, ALICE, MINTED, 400)
        .unwrap()
        .unwrap()
        .row;
    let state = TaskState::parse(&row.state).unwrap();
    assert_eq!(state, TaskState::InputRequired);
    assert!(
        !state.is_terminal() && state.is_interrupted(),
        "a paused task is live: the retention sweep must never treat it as collectable"
    );
}

/// Ported from busbar-a2a a2a/tests/relay_stream_tests.rs::a_context_id_belonging_to_another_principal_does_not_resume_that_task.
#[test]
fn a_context_id_belonging_to_another_principal_does_not_resume_that_task() {
    let mut desk = desk();
    // Bob's task on the agent is interrupted under context `ctx-1`.
    walk(
        &mut desk,
        BOB,
        "t2",
        &[TaskState::Working, TaskState::InputRequired],
    );
    let (task, _) = hop(opened(
        &mut desk,
        &send(json!({ "message": { "contextId": "ctx-1" } })),
        ALICE,
    ));
    assert_eq!(
        task.task_id, MINTED,
        "Alice must NOT resume Bob's paused task by naming its contextId: a fresh one is minted"
    );
    assert_eq!(desk.draws, 1);
    let bobs = get(&mut desk.book, BOB, "t2", 300).unwrap().unwrap().row;
    assert_eq!(bobs.state, "input-required", "Bob's task was not touched");
}

/// Ported from busbar-a2a a2a/tests/relay_stream_tests.rs::a_completed_task_is_not_resumed_by_reusing_its_context_id.
#[test]
fn a_completed_task_is_not_resumed_by_reusing_its_context_id() {
    let mut desk = desk();
    walk(
        &mut desk,
        ALICE,
        "t1",
        &[TaskState::Working, TaskState::Completed],
    );
    let (task, _) = hop(opened(
        &mut desk,
        &send(json!({ "message": { "contextId": "ctx-1" } })),
        ALICE,
    ));
    assert_ne!(
        task.task_id, "t1",
        "completed work must not be resurrected by re-using its contextId"
    );
    assert_eq!(task.task_id, MINTED);
    let done = get(&mut desk.book, ALICE, "t1", 300).unwrap().unwrap().row;
    assert_eq!(done.state, "completed");
}

/// Ported from busbar-a2a a2a/tests/relay_stream_tests.rs::a_streamed_artifact_advances_the_durable_resume_cursor.
#[test]
fn a_streamed_artifact_advances_the_durable_resume_cursor() {
    let mut desk = desk();
    let (task, _) = hop(opened(&mut desk, &send(json!({})), ALICE));
    let artifact = Settled::Event {
        state: None,
        artifact: true,
        backend_id: Some("B1".into()),
    };
    settled(&mut desk, &task, &artifact);
    settled(&mut desk, &task, &artifact);
    let mid = get(&mut desk.book, ALICE, MINTED, 400)
        .unwrap()
        .unwrap()
        .row;
    assert_eq!(
        mid.artifact_cursor, 2,
        "each artifact chunk advances the durable cursor"
    );
    let terminal = Settled::Event {
        state: Some(TaskState::Completed),
        artifact: false,
        backend_id: Some("B1".into()),
    };
    settled(&mut desk, &task, &terminal);
    let row = get(&mut desk.book, ALICE, MINTED, 400)
        .unwrap()
        .unwrap()
        .row;
    assert_eq!(row.artifact_cursor, 2);
    assert_eq!(
        row.state, "completed",
        "the terminal event lands on the task"
    );
}

// ── a hop that left and heard nothing back: its task end, racing another writer of the task ───

/// End `task`, whose hop left and heard nothing back, failed, as the door ends it on the refused
/// piece, on the unit's own ticket: [`settle`] on `Settled::Failed` over the host's records
/// (`plane_door::settle_task`).
fn ended_after_no_answer(d: &mut Desk, task: &TaskHop) -> Vec<Write> {
    ended_on_refusal(d, task)
}

/// A HOP THAT LEFT AND HEARD NOTHING BACK ENDS THE TASK IT OPENED WITHOUT LOSING ANOTHER WRITER'S
/// CHANGE (the engine's `refuse_hop` on `RelayRefusal::Transport`, origin/predev
/// `crates/busbar-a2a/src/a2a/receive.rs:3325` and its `fail_task` arm `:3463-3471`, then
/// `end_task` `:3485-3500`: `TASKS.transition` under the task's own lock,
/// `crates/busbar-kernel/src/plane/handle_engine.rs:711-736`). Another unit moves the task the hop
/// minted between its opening and the end; the end is chained after that move: the other writer's
/// event stands, the failure is the next one, and the task as held is failed with the chain's tail
/// on the failure.
#[test]
fn a_hop_that_heard_nothing_back_ends_its_task_keeping_a_concurrent_writers_change() {
    let mut d = desk();
    let (fresh, _) = opened_writing(&mut d, &send(json!({})));
    let Opened::Hop { task, .. } = fresh else {
        panic!("refused");
    };
    let id = task.task_id.clone();
    let next = get(&mut d.book, ALICE, &id, 300).unwrap().unwrap().next_seq;

    // ANOTHER UNIT moves the task while the hop's end is made: it wins the next sequence.
    let mut theirs = Vec::new();
    let other = Step {
        caller: ALICE,
        request_id: "another-unit",
        now: 300,
    };
    crate::tasks::transition(&mut d.book, &other, &id, TaskState::Working, &mut theirs)
        .unwrap()
        .expect("it moved");
    d.book.apply(&theirs);
    let their_event = d
        .book
        .value(KIND_TASK_EVENT, &event_key(ALICE, &id, next))
        .cloned()
        .expect("their event");

    let ours = ended_after_no_answer(&mut d, &task);
    d.book.apply(&ours);

    assert_eq!(
        d.book
            .value(KIND_TASK_EVENT, &event_key(ALICE, &id, next))
            .cloned(),
        Some(their_event),
        "the other writer's event stands"
    );
    let failed = event(&d, &id, next + 1);
    assert_eq!(failed.state, "failed", "the failure is the next event");
    let held = get(&mut d.book, ALICE, &id, 300).unwrap().unwrap();
    assert_eq!(held.row.state, "failed");
    // The failure is the chain's tail: the door holds no tail hash of its own, since the host seals
    // the chain on the record path (B1 ruling 1, coordinator 2026-10-07).
    assert_eq!(held.next_seq, next + 2);
}

// ── a record write the store refuses is reported, and the answer stands ────────────────────────

/// Every event's level and rendered fields, sent down a channel (the plane holds no subscriber
/// dependency, so the `tracing` trait is implemented by hand). Admits every level, so the
/// assertion holds whichever side of the error-once latch this process is on.
struct Capture(std::sync::mpsc::Sender<(tracing::Level, String)>);

struct Render<'a>(&'a mut String);

impl tracing::field::Visit for Render<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = String::new();
        event.record(&mut Render(&mut line));
        let _ = self.0.send((*event.metadata().level(), line));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Settle `how` on Alice's task as BOB, who holds no such task: the store refuses the write.
/// Answers what the call answered, the writes it staged, and the lines it logged.
fn refused_settle(how: &Settled) -> (Result<Option<TaskRow>, Halt>, usize, Vec<String>) {
    let mut desk = desk();
    let (task, _) = hop(opened(&mut desk, &send(json!({})), ALICE));
    let (sent, heard) = std::sync::mpsc::channel();
    let mut out = Vec::new();
    let answer = tracing::subscriber::with_default(Capture(sent), || {
        settle(
            &mut desk.book,
            &task,
            how,
            BOB,
            400,
            &mut out,
            &Latches::new(),
        )
    });
    let lines = heard.try_iter().map(|(_, line)| line).collect();
    (answer, out.len(), lines)
}

/// **A REFUSED CURSOR WRITE IS SURFACED, AND THE ANSWER STANDS.** Ported from origin/predev
/// `crates/busbar-a2a/src/a2a/tests/relay_stream_tests.rs:824`
/// `a_resume_cursor_the_store_refuses_is_surfaced` (`receive.rs:3180-3204`
/// `advance_resume_cursor`): the diagnostic, naming the task, in predev's words. RED arm: the
/// refusal was swallowed, so nothing was logged.
#[test]
fn a_resume_cursor_the_store_refuses_is_surfaced_and_the_answer_stands() {
    let artifact = Settled::Event {
        state: None,
        artifact: true,
        backend_id: None,
    };
    let (answer, staged, lines) = refused_settle(&artifact);
    assert!(matches!(answer, Ok(None)), "the answer stands");
    assert_eq!(staged, 0, "a refused write stages nothing");
    let banner = crate::diagnostics::A2A_RELAYED_OUTCOME_UNRECORDED
        .banner()
        .to_string();
    assert!(
        lines.iter().any(|l| l.contains(&banner)
            && l.contains(MINTED)
            && l.contains("resume cursor could not be recorded")),
        "the refused cursor write is logged under {banner}, naming the task: {lines:?}"
    );
}

/// **A REFUSED STATE TRANSITION IS SURFACED, AND THE ANSWER STANDS**, each arm under predev's
/// code and words: the unary hop's reported state (`receive.rs:3239`), a streamed event's state
/// with the state named (`:2965`), and a task that could not be ended `failed` (`:3508`).
#[test]
fn a_transition_the_store_refuses_is_surfaced_and_the_answer_stands() {
    let reported = Settled::Reported {
        state: TaskState::Completed,
        backend_id: None,
    };
    let streamed = Settled::Event {
        state: Some(TaskState::Working),
        artifact: false,
        backend_id: None,
    };
    let arms: [(&Settled, &busbar_contract::diagnostic::Diagnostic, &[&str]); 3] = [
        (
            &reported,
            &crate::diagnostics::A2A_RELAYED_OUTCOME_UNRECORDED,
            &["the relayed task's outcome could not be recorded"],
        ),
        (
            &streamed,
            &crate::diagnostics::A2A_RELAYED_OUTCOME_UNRECORDED,
            &[
                "a streamed task transition could not be recorded",
                "state=working",
            ],
        ),
        (
            &Settled::Failed,
            &crate::diagnostics::A2A_FAILURE_UNRECORDED,
            &["a failed task could not be recorded as failed"],
        ),
    ];
    for (how, diag, words) in arms {
        let (answer, staged, lines) = refused_settle(how);
        assert!(matches!(answer, Ok(None)), "the answer stands: {how:?}");
        assert_eq!(staged, 0, "a refused write stages nothing: {how:?}");
        let banner = diag.banner().to_string();
        assert!(
            lines.iter().any(|l| l.contains(&banner)
                && l.contains(MINTED)
                && words.iter().all(|w| l.contains(w))),
            "{how:?} is logged under {banner} naming the task and {words:?}: {lines:?}"
        );
    }
}

/// **ERROR ONCE, THEN DEBUG**, per condition, as predev latched it (`receive.rs:3195-3201`): the
/// first refusal of a kind is logged at ERROR and every one after it at DEBUG; a different kind has
/// its own latch. The latches here are the test's own, so the order is not the process's.
#[test]
fn a_refused_write_is_an_error_the_first_time_and_debug_after() {
    use tracing::Level;
    let latches = Latches::new();
    let (sent, heard) = std::sync::mpsc::channel();
    tracing::subscriber::with_default(Capture(sent), || {
        Refused::Cursor.report(&latches, "t1", "no such task");
        Refused::Cursor.report(&latches, "t1", "no such task");
        Refused::Cursor.report(&latches, "t2", "no such task");
        Refused::Relayed.report(&latches, "t1", "no such task");
    });
    let levels: Vec<Level> = heard.try_iter().map(|(level, _)| level).collect();
    assert_eq!(
        levels,
        [Level::ERROR, Level::DEBUG, Level::DEBUG, Level::ERROR],
        "error on the first refusal of a kind, debug on the rest"
    );
}

/// THE ENGINE'S ANSWER SHOULD THE STORE REFUSE THE OPENING'S WRITES (the kernel then ends the unit
/// `durability_unavailable`, and the door's `refusal` renders this in place of the kernel's words),
/// stated by the opening that staged them, echoing the request id: a fresh task's is predev's `503`
/// `-32603` "the task could not be recorded" (`busbar-a2a` `receive.rs:2032-2049`); a resumed
/// task's its `409` `-32002` "this task cannot be resumed", with the `TASK_NOT_CANCELABLE`
/// `ErrorInfo` every A2A-defined code carries (`receive.rs:1985-2001`, `rpcerror.rs:305-318`); an
/// addressed task's is none, because predev sent the hop whether or not the callback it carried was
/// recorded (`receive.rs:2080-2096`).
#[test]
fn an_opening_states_the_engines_answer_should_the_store_refuse_its_writes() {
    let unrecorded = |opened: Opened| match opened {
        Opened::Hop { unrecorded, .. } => unrecorded,
        Opened::Refused(reply) => panic!("refused: {reply:?}"),
    };
    // Each stage opens on a fresh desk: the constructor is kept under its own name, since the
    // desks below shadow `desk`.
    let mut desk = desk();
    let fresh = unrecorded(opened(
        &mut desk,
        &send(json!({ "message": { "messageId": "m" } })),
        ALICE,
    ))
    .expect("a fresh task's opening states its answer");
    assert_eq!(fresh.status, 503);
    assert_eq!(
        fresh.envelope(),
        json!({ "jsonrpc": "2.0", "id": 7,
            "error": { "code": -32603, "message": "the task could not be recorded" } })
    );

    let mut desk = self::desk();
    let mut out = Vec::new();
    let at = Step {
        caller: ALICE,
        request_id: "r",
        now: 150,
    };
    tasks::dispatch(&mut desk.book, &at, "t1", MEMBER, &mut out).unwrap();
    for state in [TaskState::Working, TaskState::InputRequired] {
        desk.book.apply(&out);
        out.clear();
        tasks::transition(&mut desk.book, &at, "t1", state, &mut out).unwrap();
    }
    desk.book.apply(&out);
    let resumed = unrecorded(opened(
        &mut desk,
        &send(json!({ "message": { "contextId": "ctx-1" } })),
        ALICE,
    ))
    .expect("a resumed task's opening states its answer");
    assert_eq!(resumed.status, 409);
    assert_eq!(
        resumed.envelope(),
        json!({ "jsonrpc": "2.0", "id": 7, "error": {
            "code": -32002,
            "message": "this task cannot be resumed",
            "data": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": "a2a-protocol.org",
                "reason": "TASK_NOT_CANCELABLE",
            }],
        } })
    );

    let mut desk = self::desk();
    let addressed = unrecorded(opened(
        &mut desk,
        &send(json!({
            "id": "t1",
            "configuration": { "pushNotificationConfig": { "url": "https://hook.example/t1" } },
        })),
        ALICE,
    ));
    assert_eq!(
        addressed, None,
        "the engine sent an addressed task's hop whether or not its callback was recorded"
    );
}
