// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEP-2663 task substrate — the properties the wire depends on, tested where they are decided. The
//! served engine's `tasks_tests.rs`, ported onto the door's task (`Task` held by the instance, its
//! handle the kernel's work handle), with the cases the durable rows add.

use std::collections::BTreeMap;

use serde_json::json;

use super::*;
use crate::tools_config::{AskEntryCfg, TaskSupport};

const T0: u64 = 1_700_000_000_000;

fn task(principal: &str) -> Task {
    Task::new("0123456789abcdef0123456789abcdef", principal, 7, "d1", T0)
}

/// Two callers, two tasks, and neither can address the other's. The refusal is INDISTINGUISHABLE
/// from an unknown id on purpose (the verbs answer `-32602 unknown taskId` for both).
#[test]
fn a_task_is_addressable_only_by_the_principal_it_was_created_for() {
    let mine = task("key-a");
    assert!(mine.owned_by("key-a"));
    assert!(
        !mine.owned_by("key-b"),
        "a task filed under one principal must not resolve for another"
    );
}

/// A TOOL that ran and reported an error is `completed` with `result.isError`, NOT `failed`.
#[test]
fn a_tool_error_settles_as_completed_and_a_protocol_error_settles_as_failed() {
    let mut ran = task("key-status");
    assert!(ran.complete(
        json!({ "isError": true, "content": [{ "type": "text", "text": "the file was not found" }] }),
        T0,
    ));
    let detailed = ran.detailed();
    assert_eq!(detailed["status"], "completed");
    assert_eq!(detailed["result"]["isError"], true);
    assert!(
        detailed.get("error").is_none(),
        "a tool that RAN carries no protocol `error`"
    );

    let mut broke = task("key-status");
    assert!(broke.fail(
        -32603,
        "the upstream answered JSON-RPC error -32000".into(),
        T0
    ));
    let detailed = broke.detailed();
    assert_eq!(detailed["status"], "failed");
    assert_eq!(detailed["error"]["code"], -32603);
    assert!(
        detailed.get("result").is_none(),
        "`failed` is a PROTOCOL error and must carry no `result` beside its `error`"
    );
}

/// `tasks/cancel` on a settled task changes nothing and is not an error.
#[test]
fn cancelling_a_terminal_task_leaves_its_settled_status_alone() {
    let mut t = task("key-cancel");
    t.complete(json!({ "content": [] }), T0);
    assert!(!t.cancel(T0 + 1));
    assert_eq!(
        t.detailed()["status"],
        "completed",
        "a cancel arriving after completion must not rewrite the settled status"
    );
}

/// An ask, built the ONE way a `CallerAsk` can be built: from an operator-written config entry.
fn elicitation(key: &str) -> CallerAsk {
    CallerAsk::from_config(
        key,
        &AskEntryCfg {
            method: "elicitation/create".into(),
            params: Some(json!({})),
        },
    )
}

/// PARTIAL FULFILMENT: answering one key of a two-key round removes that key and leaves the task
/// parked on the other.
#[test]
fn answering_one_of_two_asks_leaves_the_task_parked_on_the_other() {
    let mut t = task("key-partial");
    t.park(vec![elicitation("first"), elicitation("second")], T0);
    assert_eq!(t.detailed()["status"], "input_required");
    assert!(!t.answered());

    let mut answered = Map::new();
    answered.insert("first".into(), json!({ "action": "accept" }));
    assert!(t.deliver(&answered, T0));
    let detailed = t.detailed();
    assert_eq!(detailed["status"], "input_required");
    let pending = detailed["inputRequests"].as_object().expect("a map");
    assert!(
        !pending.contains_key("first"),
        "an answered key MUST be removed from `inputRequests`"
    );
    assert!(
        pending.contains_key("second"),
        "an unanswered key MUST remain"
    );

    let mut rest = Map::new();
    rest.insert("second".into(), json!({ "action": "accept" }));
    t.deliver(&rest, T0);
    assert!(t.answered());
    assert_eq!(
        t.detailed()["status"],
        "working",
        "with every ask answered the task leaves `input_required` and resumes"
    );
    // A round re-parked after its keys were answered asks nothing again.
    t.park(vec![elicitation("first")], T0);
    assert!(t.answered());
    assert_eq!(t.detailed()["status"], "working");
}

/// The CreateTaskResult is FLAT and carries none of the DetailedTask-only members.
#[test]
fn the_creation_result_is_flat_and_carries_no_detailed_task_members() {
    let created = task("key-shape").created();
    let obj = created.as_object().expect("an object");
    for member in [
        "taskId",
        "status",
        "createdAt",
        "lastUpdatedAt",
        "ttlMs",
        "pollIntervalMs",
        "content",
    ] {
        assert!(
            obj.contains_key(member),
            "`{member}` is on the creation result"
        );
    }
    assert_eq!(obj["ttlMs"], TASK_TTL_MS);
    assert_eq!(obj["pollIntervalMs"], TASK_POLL_INTERVAL_MS);
    assert_eq!(obj["content"], json!([]));
    for forbidden in ["task", "result", "error", "inputRequests", "requestState"] {
        assert!(
            !obj.contains_key(forbidden),
            "`CreateTaskResult` must not carry `{forbidden}`"
        );
    }
    for legacy in ["ttl", "pollInterval"] {
        assert!(!obj.contains_key(legacy), "the v1 `{legacy}` key is gone");
    }
    // The envelope stamps the discriminator on the flat shape.
    let envelope: Value = serde_json::from_slice(&task_result(&json!(4), created)).expect("JSON");
    assert_eq!(envelope["id"], 4);
    assert_eq!(envelope["result"]["resultType"], "task");
    assert_eq!(envelope["result"]["status"], "working");
}

/// `requestState` never appears on the tasks wire, at any status.
#[test]
fn no_task_shape_ever_carries_request_state() {
    let mut t = task("key-no-state");
    assert!(t.created().get("requestState").is_none());
    assert!(t.detailed().get("requestState").is_none());
    t.park(vec![elicitation("confirm")], T0);
    assert!(t.detailed().get("requestState").is_none());
}

/// The extension is declared by PRESENCE under `extensions`, and `null` is not a declaration.
#[test]
fn the_extension_is_declared_by_presence_and_null_is_not_a_declaration() {
    use crate::call::{client_declares_tasks, TASKS_EXTENSION_ID};
    assert!(client_declares_tasks(
        &json!({ "extensions": { TASKS_EXTENSION_ID: {} } })
    ));
    assert!(!client_declares_tasks(&json!({})));
    assert!(!client_declares_tasks(&json!({ "extensions": {} })));
    assert!(!client_declares_tasks(
        &json!({ "extensions": { TASKS_EXTENSION_ID: Value::Null } })
    ));
    assert!(
        !client_declares_tasks(&json!({ "tasks": {} })),
        "the v1-style slot is not the extension declaration"
    );
}

/// `task_support` crossed with the caller's declaration.
#[test]
fn task_support_crossed_with_the_callers_declaration() {
    assert!(!TaskSupport::None.creates_task(true));
    assert!(!TaskSupport::None.creates_task(false));
    assert!(TaskSupport::Optional.creates_task(true));
    assert!(
        !TaskSupport::Optional.creates_task(false),
        "`optional` falls through to a synchronous result rather than locking the caller out"
    );
    assert!(TaskSupport::Required.creates_task(true));
    assert!(
        !TaskSupport::Required.creates_task(false),
        "`required` never creates a task for a caller that cannot receive one"
    );
}

/// The timestamp format the wire fixes, across a leap day and a non-leap century.
#[test]
fn timestamps_render_as_iso_8601_utc() {
    assert_eq!(iso8601_ms(0), "1970-01-01T00:00:00.000Z");
    assert_eq!(iso8601_ms(1_709_209_496_789), "2024-02-29T12:24:56.789Z");
    assert_eq!(iso8601_ms(4_107_542_400_000), "2100-03-01T00:00:00.000Z");
}

/// `cancel` reports whether THIS call made the transition — the guard a single cancel record rests
/// on when a caller's cancel and the kernel's race.
#[test]
fn cancel_reports_the_transition_it_made_and_only_that_one() {
    let mut t = task("key-cancel-cas");
    assert!(
        t.cancel(T0),
        "the first cancel of a working task performs it"
    );
    assert!(
        !t.cancel(T0),
        "a second cancel finds the task terminal and reports no transition"
    );
    assert!(
        !t.complete(json!({}), T0),
        "a cancelled task never completes"
    );
    assert!(!t.fail(-1, String::new(), T0), "nor fails");
}

/// THE ABANDONMENT CEILING: an active task whose last update is older than
/// `ACTIVE_TASK_ABANDON_MS` is CANCELLED by the create-time sweep — a transition, never a drop, its
/// continuation woken to see it and its handle listed to settle — and then rides the ordinary
/// retention out; a younger active task is untouched.
#[test]
fn an_abandoned_active_task_is_cancelled_by_the_sweep_and_then_ages_out() {
    let mut tasks: BTreeMap<String, Task> = BTreeMap::new();
    let ticket = Ticket {
        slot: 3,
        generation: 1,
    };
    let mut old = Task::new("old", "key-abandon", 1, "d", T0);
    old.runner = Some((9, ticket));
    tasks.insert("old".into(), old);
    // Exactly AT the ceiling is not abandoned (the bound is strict, matching `is_expired`).
    tasks.insert(
        "young".into(),
        Task::new("young", "key-abandon", 2, "d", T0 + ACTIVE_TASK_ABANDON_MS),
    );
    let sweep_now = T0 + ACTIVE_TASK_ABANDON_MS + 1;
    let swept = sweep(&mut tasks, sweep_now);
    assert_eq!(
        tasks["old"].status(),
        Status::Cancelled,
        "cancelled, not dropped"
    );
    assert_eq!(
        swept.wake,
        vec![ticket],
        "its continuation is woken to see it"
    );
    assert_eq!(swept.settle.len(), 1, "its handle is settled with it");
    assert_eq!(swept.settle[0].0, 1);
    assert_eq!(tasks["young"].status(), Status::Working);
    // A second sweep does not list the settle again.
    assert!(sweep(&mut tasks, sweep_now).settle.is_empty());
    // The cancel stamped `updated_ms = sweep_now`, so the ordinary retention now applies.
    let swept = sweep(&mut tasks, sweep_now + TASK_TTL_MS + 1);
    assert!(
        !tasks.contains_key("old"),
        "after the retention the cancelled task is dropped like any other terminal task"
    );
    assert!(swept.strike.is_empty(), "it wrote no result to strike");
    assert!(
        tasks.contains_key("young"),
        "the active task survives every sweep"
    );
}

/// THE CAP drops the oldest TERMINAL tasks first, never a working one, and lists every dropped
/// task's result chunks to strike.
#[test]
fn the_cap_drops_the_oldest_terminal_tasks_and_never_a_working_one() {
    let mut tasks: BTreeMap<String, Task> = BTreeMap::new();
    for n in 0..MAX_RETAINED_TASKS {
        let id = format!("w{n:05}");
        tasks.insert(id.clone(), Task::new(&id, "k", n as u64 + 10, "d", T0));
    }
    let mut done = Task::new("done", "k", 1, "d", T0);
    done.complete(json!({ "content": [] }), T0);
    done.chunks = 2;
    tasks.insert("done".into(), done);
    let swept = sweep(&mut tasks, T0 + 1);
    assert!(!tasks.contains_key("done"), "the terminal task made room");
    assert_eq!(tasks.len(), MAX_RETAINED_TASKS, "every working task kept");
    assert_eq!(swept.strike, vec![("done".to_string(), 2)]);
}

/// THE 257th distinct key is refused; 256 are accepted; a REPEAT of an already-held key still
/// updates in place instead of being counted as new.
#[test]
fn a_tasks_answer_map_is_capped_at_max_task_answers_distinct_keys() {
    let mut t = task("key-answers-cap");
    for i in 0..MAX_TASK_ANSWERS {
        let mut batch = Map::new();
        batch.insert(format!("k{i}"), json!(i));
        assert!(t.deliver(&batch, T0), "key {i} must be accepted");
    }
    assert_eq!(t.answers().len(), MAX_TASK_ANSWERS);
    let mut repeat = Map::new();
    repeat.insert("k0".to_string(), json!("updated"));
    assert!(t.deliver(&repeat, T0), "a repeat is not a new key");
    assert_eq!(t.answers().get("k0"), Some(&json!("updated")));
    assert_eq!(t.answers().len(), MAX_TASK_ANSWERS);
    let mut overflow = Map::new();
    overflow.insert("overflow".to_string(), json!("no"));
    assert!(
        !t.deliver(&overflow, T0),
        "the 257th distinct key is refused"
    );
    assert!(t.answers().get("overflow").is_none());
    assert_eq!(t.answers().len(), MAX_TASK_ANSWERS);
}

/// A batch that would cross the ceiling is refused WHOLE, not truncated.
#[test]
fn a_batch_that_would_cross_the_ceiling_is_refused_whole_not_truncated() {
    let mut t = task("key-answers-batch");
    let mut batch = Map::new();
    for i in 0..(MAX_TASK_ANSWERS - 1) {
        batch.insert(format!("k{i}"), json!(i));
    }
    assert!(t.deliver(&batch, T0));
    let mut over = Map::new();
    over.insert("k0".to_string(), json!("repeat, not new"));
    over.insert("new-a".to_string(), json!("new"));
    over.insert("new-b".to_string(), json!("new"));
    assert!(!t.deliver(&over, T0));
    assert_eq!(t.answers().len(), MAX_TASK_ANSWERS - 1);
    assert!(t.answers().get("new-a").is_none());
    assert!(t.answers().get("new-b").is_none());
}

/// THE DURABLE ROW round-trips, fits the work record, and anything else reads as no row.
#[test]
fn the_durable_row_round_trips_and_fits_the_work_record() {
    let mut t = Task::new("r", "k", 1, &run_digest(&json!({ "name": "fs_read" })), T0);
    t.complete(json!({ "content": [] }), T0 + 5);
    let bytes = t.row();
    assert!(bytes.len() <= busbar_contract::abi::host::service::MAX_WORK_RECORD);
    let row = WorkRow::read(&bytes).expect("a row");
    assert_eq!(row.status, Status::Completed);
    assert_eq!((row.created_ms, row.updated_ms), (T0, T0 + 5));
    let back = Task::from_row("r", "k", 1, &row, t.terminal().as_ref());
    assert_eq!(
        back.detailed(),
        t.detailed(),
        "a task read back answers as it did"
    );
    assert!(WorkRow::read(b"t1|working|1|2").is_none());
    assert!(WorkRow::read(b"t2|working|1|2|d").is_none());
    assert!(WorkRow::read(b"t1|done|1|2|d").is_none());
}

/// THE RESULT IN CHUNKS: each a plane record, read back in key order whole; a result too long to
/// write is not written.
#[test]
fn a_result_is_written_in_ordered_chunks_and_read_back_whole() {
    let text = "x".repeat(RESULT_CHUNK_BYTES * 3);
    let terminal = json!({ "result": { "content": [{ "type": "text", "text": text }] } });
    let chunks = result_chunks("abc", &terminal);
    assert!(chunks.len() >= 3);
    assert!(chunks
        .iter()
        .all(|(k, v)| k.starts_with(&chunk_prefix("abc"))
            && v.len() <= busbar_contract::bounded::MAX_RECORD_BYTES));
    let mut keys: Vec<&Vec<u8>> = chunks.iter().map(|(k, _)| k).collect();
    keys.sort();
    assert_eq!(keys, chunks.iter().map(|(k, _)| k).collect::<Vec<_>>());
    assert_eq!(
        read_chunks(chunks.iter().map(|(_, v)| v.as_slice())),
        Some(terminal)
    );
    let huge = json!({ "result": "y".repeat(RESULT_CHUNK_BYTES * (MAX_RESULT_CHUNKS + 1)) });
    assert!(result_chunks("abc", &huge).is_empty());
    assert_eq!(read_chunks(std::iter::empty()), None);
}

/// The answers become arguments under the operator's keys, a clone; and the task's own rounds are
/// filtered to what the caller declared, an emptied round dropped.
#[test]
fn answers_merge_into_the_arguments_and_rounds_filter_by_the_callers_declaration() {
    let mut answers = Map::new();
    answers.insert("user_name".into(), json!("ada"));
    assert_eq!(
        merge_answers(&json!({ "path": "/a" }), &answers),
        json!({ "path": "/a", "user_name": "ada" })
    );
    assert_eq!(
        merge_answers(&json!({ "path": "/a" }), &Map::new()),
        json!({ "path": "/a" })
    );
    let mut round: crate::tools_config::AskRoundCfg = indexmap::IndexMap::new();
    round.insert(
        "confirm".into(),
        AskEntryCfg {
            method: "elicitation/create".into(),
            params: None,
        },
    );
    let rounds = vec![round];
    assert!(task_ask_rounds(&rounds, &json!({})).is_empty());
    let declared = task_ask_rounds(&rounds, &json!({ "elicitation": {} }));
    assert_eq!(declared.len(), 1);
    assert_eq!(declared[0][0].key(), "confirm");
}

/// The digest names the call: another argument is another digest.
#[test]
fn the_run_digest_names_the_call() {
    let a = run_digest(&json!({ "name": "fs_read", "arguments": { "path": "/a" } }));
    let b = run_digest(&json!({ "name": "fs_read", "arguments": { "path": "/b" } }));
    assert_ne!(a, b);
    assert_eq!(
        a,
        run_digest(&json!({ "name": "fs_read", "arguments": { "path": "/a" } }))
    );
}

/// LAW 11 ON THE TASK PATH (ARCHITECT Q6): a task parked on its upstream's ask is `input_required`
/// with the upstream's `inputRequests` verbatim; the caller's answers are kept for the retry and
/// never merged into the tool's arguments; the park is taken once, when every key is answered.
#[test]
fn a_task_parked_on_its_upstreams_ask_hands_the_answers_back_once() {
    let mut t = task("k");
    let requests: Map<String, Value> = serde_json::from_value(json!({
        "draft": {"method": "sampling/createMessage", "params": {"maxTokens": 9}},
        "ok": {"method": "elicitation/create", "params": {"message": "sure?"}},
    }))
    .unwrap();
    t.park_relay(&requests, "sealed".into(), json!({"name": "fs_x"}), 5);
    assert_eq!(t.status(), Status::InputRequired);
    assert_eq!(
        t.detailed()["inputRequests"],
        Value::Object(requests.clone()),
        "the upstream's requests, verbatim"
    );
    assert!(t.deliver(
        &serde_json::from_value(json!({"draft": {"x": 1}})).unwrap(),
        6
    ));
    assert_eq!(t.take_relay(), None, "one key is still unanswered");
    assert_eq!(t.status(), Status::InputRequired);
    assert!(t.deliver(
        &serde_json::from_value(json!({"ok": {"action": "accept"}})).unwrap(),
        7
    ));
    assert_eq!(t.status(), Status::Working);
    assert!(
        t.answers().is_empty(),
        "an upstream's answers are never arguments"
    );
    let park = t.take_relay().expect("the park, answered");
    assert_eq!(park.state, "sealed");
    assert_eq!(park.params, json!({"name": "fs_x"}));
    assert_eq!(park.responses["draft"], json!({"x": 1}));
    assert_eq!(park.responses["ok"], json!({"action": "accept"}));
    assert_eq!(t.take_relay(), None, "taken once");
    // A cancelled task parks nothing.
    let mut gone = task("k");
    assert!(gone.cancel(8));
    gone.park_relay(&requests, "sealed".into(), json!({}), 9);
    assert_eq!(gone.status(), Status::Cancelled);
    assert_eq!(gone.take_relay(), None);
}

/// THE TASK STORE IS HOST RECORDS (BUSBAR-1.6.0.md, the mcp bullet): a live task's state — its
/// status, its `inputRequests` in order, its answers, the round of its own asks and the upstream
/// ask it is parked on — reads back from its records into the task its row makes, and answers the
/// same `tasks/get`.
#[test]
fn a_live_tasks_state_reads_back_from_its_records() {
    let row = WorkRow {
        status: Status::Working,
        created_ms: T0,
        updated_ms: T0,
        digest: "d1".into(),
    };
    let mut own = task("k");
    own.park(vec![elicitation("b"), elicitation("a")], T0 + 1);
    assert!(own.deliver(&serde_json::from_value(json!({"z": 1})).unwrap(), T0 + 2));
    own.asked = Some((1, json!({"name": "fs_x"})));
    let mut relayed = task("k");
    let requests: Map<String, Value> =
        serde_json::from_value(json!({"r": {"method": "roots/list"}})).unwrap();
    relayed.park_relay(&requests, "sealed".into(), json!({"name": "fs_x"}), T0 + 3);
    for held in [own, relayed] {
        let parts = live_parts(&held.id, &held.live());
        assert!(parts
            .iter()
            .all(|(k, _)| k.starts_with(&live_prefix(&held.id))));
        let bytes: Vec<u8> = parts.iter().flat_map(|(_, v)| v.clone()).collect();
        let mut read = Task::from_row(&held.id, "k", 7, &row, None);
        read.take_live(&read_live(&bytes).expect("a live document"));
        assert_eq!(read.detailed(), held.detailed());
        assert_eq!(read.answers(), held.answers());
        assert_eq!(read.asked, held.asked);
        assert_eq!(read.relayed(), held.relayed());
        assert_eq!(read.take_relay(), held.clone().take_relay());
    }
}

/// A SHORTER STATE WRITTEN OVER A LONGER ONE reads back as itself: the longer one's chunks past it
/// are not read.
#[test]
fn a_live_state_reads_back_whole_over_an_earlier_longer_one() {
    let short = json!({"status": "working", "updated": 1});
    let long = json!({"status": "input_required", "updated": 0, "pad": "x".repeat(2000)});
    let mut stored: BTreeMap<Vec<u8>, Vec<u8>> = live_parts("t", &long).into_iter().collect();
    stored.extend(live_parts("t", &short));
    let bytes: Vec<u8> = stored.values().flatten().copied().collect();
    assert_eq!(read_live(&bytes), Some(short));
}

/// THE INDEX ROW of a live task: a run's lease that lapsed, or nothing moving it past the
/// abandonment ceiling, leaves it behind; a task parked on its caller is not left behind by time
/// short of that ceiling.
#[test]
fn a_task_is_left_behind_once_its_runs_lease_lapses_or_it_is_abandoned() {
    let run = Lease {
        until_ms: T0 + 10,
        updated_ms: T0,
    };
    assert_eq!(Lease::read(&run.bytes()), Some(run));
    assert!(!run.left_behind(T0 + 10));
    assert!(run.left_behind(T0 + 11));
    let parked = Lease {
        until_ms: 0,
        updated_ms: T0,
    };
    assert!(!parked.left_behind(T0 + ACTIVE_TASK_ABANDON_MS));
    assert!(parked.left_behind(T0 + ACTIVE_TASK_ABANDON_MS + 1));
    assert_eq!(Lease::read(b"l1|1"), None);
    assert!(index_key("k", "t").starts_with(&index_prefix("k")));
    assert_ne!(index_prefix("k"), index_prefix("j"));
}

/// Finding 24 [LOW]: `tasks/update` on a terminal task changes nothing — no answer is kept and its
/// last update stands.
#[test]
fn an_update_to_a_terminal_task_changes_nothing() {
    let mut t = task("k");
    assert!(t.complete(json!({"content": []}), T0 + 1));
    let before = t.clone();
    assert!(t.deliver(&serde_json::from_value(json!({"a": 1})).unwrap(), T0 + 9));
    assert_eq!(t, before);
}
