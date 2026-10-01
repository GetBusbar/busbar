// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The task store over host records, against [`Book`]: a map that answers `records.get/list/claim`
//! as the kernel does (a tombstone reads as absent) and applies an answer's writes.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// THE HOST RECORDS, as a test holds them.
#[derive(Debug, Default, Clone)]
pub(crate) struct Book {
    rows: BTreeMap<(String, String), Vec<u8>>,
    claims: BTreeSet<(String, String)>,
    /// Another writer's change, applied the moment this one next claims, so this one loses.
    race: Option<Vec<Write>>,
}

impl Book {
    /// Apply an answer's writes: a put, or an empty value's tombstone.
    pub(crate) fn apply(&mut self, writes: &[Write]) {
        for w in writes {
            let at = (w.kind.to_string(), w.key.clone());
            if w.value.is_empty() {
                self.rows.remove(&at);
            } else {
                self.rows.insert(at, w.value.clone());
            }
        }
    }

    /// The live value of `kind` under `key`.
    pub(crate) fn value(&self, kind: &str, key: &str) -> Option<&Vec<u8>> {
        self.rows.get(&(kind.to_string(), key.to_string()))
    }

    /// Put `held` as `caller`'s task, as a write would.
    pub(crate) fn hold(&mut self, caller: &str, held: &Held) {
        self.apply(&[Write {
            kind: KIND_TASK,
            key: task_key(caller, &held.row.task_id),
            value: serde_json::to_vec(held).unwrap(),
        }]);
    }
}

impl Records for Book {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        Ok(self.value(kind, key).cloned())
    }

    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        Ok(self
            .rows
            .iter()
            .filter(|((k, key), _)| k == kind && key.starts_with(prefix))
            .map(|((_, key), v)| (key.clone(), v.clone()))
            .collect())
    }

    fn claim(&mut self, kind: &str, key: &str, _ttl_ms: u64) -> Result<bool, Halt> {
        if let Some(theirs) = self.race.take() {
            self.apply(&theirs);
            self.claims.insert((kind.to_string(), key.to_string()));
        }
        Ok(self.claims.insert((kind.to_string(), key.to_string())))
    }
}

/// Two callers' references.
pub(crate) const ALICE: &str = "a11ce";
pub(crate) const BOB: &str = "b0b";

/// A row for `task`, submitted at `now`.
pub(crate) fn row(task: &str, now: u64) -> TaskRow {
    crate::a2a::task::Task::submitted(
        task,
        "ctx-1",
        "someone",
        crate::a2a::task::Direction::Inbound,
        now,
    )
    .unwrap()
    .to_row()
}

/// `caller`'s step at `now`.
pub(crate) fn step(caller: &str, now: u64) -> Step<'_> {
    Step {
        caller,
        request_id: "req-1",
        now,
    }
}

/// Submit `task` for `caller` at `now` and apply it.
pub(crate) fn submitted(book: &mut Book, caller: &str, task: &str, now: u64) {
    let mut out = Vec::new();
    submit(book, &step(caller, now), row(task, now), &mut out).unwrap();
    book.apply(&out);
}

fn event(book: &Book, caller: &str, task: &str, seq: u64) -> TaskEventRow {
    serde_json::from_slice(
        book.value(KIND_TASK_EVENT, &event_key(caller, task, seq))
            .unwrap(),
    )
    .unwrap()
}

/// The engine's frozen v2 chain (`busbar-a2a` `chain_golden.rs`): the plane seals new events under
/// the same digest, byte for byte.
#[test]
fn the_digest_is_the_engines_frozen_v2_digest() {
    const V2_1: &[u8] = br#"{"task_id":"task-1","seq":1,"ts":1700000000,"kind":"task.submitted","context_id":"ctx-1","principal":"vk_alice","agent_id":"planner","state":"submitted","request_id":"req-1","prev_hash":"","hash":"07d3b2028b0729c42fdaae5f4d59c3a98749aa88db89caabcacb5ebe3981ec28","digest_version":2}"#;
    const V2_2: &[u8] = br#"{"task_id":"task-1","seq":2,"ts":1700000060,"kind":"task.working","context_id":"ctx-1","principal":"vk_alice","agent_id":"planner","state":"working","request_id":"req-2","prev_hash":"07d3b2028b0729c42fdaae5f4d59c3a98749aa88db89caabcacb5ebe3981ec28","hash":"c77eb9be8b1da1f46888ba29c137914b17c91ec0303c61bdb99870bc5d1c9f2d","digest_version":2}"#;
    for bytes in [V2_1, V2_2] {
        let ev: TaskEventRow = serde_json::from_slice(bytes).unwrap();
        assert_eq!(digest(&ev), ev.hash);
    }
}

/// A task is held under its caller's prefix: its caller reads it back, another caller reads the same
/// nothing a missing id reads, and a list is the caller's own.
#[test]
fn a_task_is_read_back_by_its_caller_only() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    submitted(&mut book, BOB, "t2", 100);
    let held = get(&mut book, ALICE, "t1", 100).unwrap().unwrap();
    assert_eq!(held.row.principal, ALICE, "the row is the caller's");
    assert_eq!((held.next_seq, held.row.state.as_str()), (2, "submitted"));
    assert_eq!(get(&mut book, BOB, "t1", 100).unwrap(), None);
    assert_eq!(get(&mut book, ALICE, "nope", 100).unwrap(), None);
    let ids: Vec<String> = list(&mut book, ALICE, 100)
        .unwrap()
        .into_iter()
        .map(|r| r.task_id)
        .collect();
    assert_eq!(ids, vec!["t1".to_string()]);
    for nobody in ["", "A11CE", "a/b"] {
        assert_eq!(
            get(&mut book, nobody, "t1", 100).unwrap(),
            None,
            "{nobody:?} holds nothing"
        );
        assert!(submit(&mut book, &step(nobody, 1), row("t9", 1), &mut Vec::new()).is_err());
    }
}

/// A change chains its event onto the tail the task record carries, under the digest, and a second
/// submit of the same id is refused.
#[test]
fn a_change_chains_its_event_onto_the_tail() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    let mut out = Vec::new();
    let moved = transition(
        &mut book,
        &step(ALICE, 160),
        "t1",
        TaskState::Working,
        &mut out,
    )
    .unwrap();
    book.apply(&out);
    assert_eq!(moved.map(|r| r.state), Some("working".to_string()));
    let (e1, e2) = (event(&book, ALICE, "t1", 1), event(&book, ALICE, "t1", 2));
    assert_eq!(
        (e1.kind.as_str(), e1.prev_hash.as_str(), e1.ts),
        (EV_SUBMITTED, "", 100)
    );
    assert_eq!((e2.kind.as_str(), e2.ts), ("task.working", 160));
    assert_eq!(e2.prev_hash, e1.hash);
    for e in [&e1, &e2] {
        assert_eq!(digest(e), e.hash);
        assert_eq!(e.digest_version, DIGEST_VERSION_LEN_PREFIXED);
    }
    let held = get(&mut book, ALICE, "t1", 160).unwrap().unwrap();
    assert_eq!((held.next_seq, held.tail_hash), (3, e2.hash));
    let again = submit(
        &mut book,
        &step(ALICE, 200),
        row("t1", 200),
        &mut Vec::new(),
    );
    assert!(
        matches!(again, Err(Halt::Failed(_))),
        "the genesis sequence is taken"
    );
    let illegal = transition(
        &mut book,
        &step(ALICE, 170),
        "t1",
        TaskState::Submitted,
        &mut Vec::new(),
    );
    assert!(matches!(illegal, Err(Halt::Failed(_))));
}

/// RACE-SAFE: a writer that loses its sequence to another writer re-reads and takes the next one,
/// on top of the other's change rather than over it.
#[test]
fn a_change_that_loses_its_sequence_takes_the_next() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    let mut theirs = Vec::new();
    dispatch(
        &mut book.clone(),
        &step(ALICE, 110),
        "t1",
        "planner",
        &mut theirs,
    )
    .unwrap();
    book.race = Some(theirs);
    let mut out = Vec::new();
    transition(
        &mut book,
        &step(ALICE, 120),
        "t1",
        TaskState::Working,
        &mut out,
    )
    .unwrap();
    book.apply(&out);
    let held = get(&mut book, ALICE, "t1", 120).unwrap().unwrap();
    assert_eq!(
        held.row.agent_id, "planner",
        "the other writer's change stands"
    );
    assert_eq!(held.row.state, "working");
    assert_eq!(held.next_seq, 4);
    let (e2, e3) = (event(&book, ALICE, "t1", 2), event(&book, ALICE, "t1", 3));
    assert_eq!(
        (e2.kind.as_str(), e3.kind.as_str()),
        ("task.delegated", "task.working")
    );
    assert_eq!(e3.prev_hash, e2.hash);
}

/// The cursor only moves forward; a push delivery chains an event and leaves the row alone.
#[test]
fn the_cursor_moves_forward_and_a_delivery_only_chains() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    let mut out = Vec::new();
    assert!(
        advance_cursor(&mut book, &step(ALICE, 110), "t1", 3, &mut out)
            .unwrap()
            .is_some()
    );
    book.apply(&out);
    assert_eq!(
        advance_cursor(&mut book, &step(ALICE, 120), "t1", 2, &mut Vec::new()).unwrap(),
        None
    );
    let mut out = Vec::new();
    record_push_delivery(
        &mut book,
        &step(ALICE, 130),
        "t1",
        "task.push_delivered",
        &mut out,
    )
    .unwrap();
    book.apply(&out);
    let held = get(&mut book, ALICE, "t1", 130).unwrap().unwrap();
    assert_eq!((held.row.artifact_cursor, held.row.updated_at), (3, 110));
    assert_eq!(event(&book, ALICE, "t1", 3).ts, 130);
}

/// A terminal task past its window reads as absent: the engine's `evict_terminal` window.
#[test]
fn a_terminal_task_past_its_window_reads_as_absent() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    let mut out = Vec::new();
    transition(
        &mut book,
        &step(ALICE, 200),
        "t1",
        TaskState::Completed,
        &mut out,
    )
    .unwrap();
    book.apply(&out);
    assert!(get(&mut book, ALICE, "t1", 200 + TERMINAL_TTL_SECS)
        .unwrap()
        .is_some());
    assert!(get(&mut book, ALICE, "t1", 201 + TERMINAL_TTL_SECS)
        .unwrap()
        .is_none());
    assert!(list(&mut book, ALICE, 201 + TERMINAL_TTL_SECS)
        .unwrap()
        .is_empty());
}

/// THE SWEEP: an abandoned active task is canceled through its chain; an expired terminal task goes
/// as tombstones (its row, its events, its push config), and a task whose id it prefixes stays.
#[test]
fn the_sweep_cancels_the_abandoned_and_tombstones_the_expired() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    submitted(&mut book, ALICE, "t10", 100);
    submitted(&mut book, BOB, "idle", 100);
    let mut out = Vec::new();
    transition(
        &mut book,
        &step(ALICE, 100),
        "t1",
        TaskState::Completed,
        &mut out,
    )
    .unwrap();
    book.apply(&out);
    book.apply(&[Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(ALICE, "t1"),
        value: b"{}".to_vec(),
    }]);
    let now = 101 + ABANDON_SECS;
    let mut out = Vec::new();
    sweep(&mut book, now, 64, &mut out).unwrap();
    book.apply(&out);
    assert!(book.value(KIND_TASK, &task_key(ALICE, "t1")).is_none());
    assert!(book
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
        .is_none());
    assert!(book
        .value(KIND_TASK_EVENT, &event_key(ALICE, "t1", 1))
        .is_none());
    assert!(
        book.value(KIND_TASK_EVENT, &event_key(ALICE, "t10", 1))
            .is_some(),
        "not its events"
    );
    for (caller, task) in [(ALICE, "t10"), (BOB, "idle")] {
        let held = get(&mut book, caller, task, now).unwrap().unwrap();
        assert_eq!(held.row.state, "canceled", "{task} was abandoned");
        assert_eq!(event(&book, caller, task, 2).kind, "task.terminal");
    }
}

/// THE CAP: while the store holds MAX_RETAINED or more, the oldest terminal tasks go, and an active
/// one never does; the sweep touches no more than its budget.
#[test]
fn the_sweep_holds_the_cap_with_terminal_tasks_only() {
    let mut book = Book::default();
    let held = |task: String, state: &str, at: u64| {
        let mut row = row(&task, at);
        row.state = state.to_string();
        Held {
            row,
            next_seq: 2,
            tail_hash: String::new(),
        }
    };
    for i in 0..MAX_RETAINED - 1 {
        book.hold(ALICE, &held(format!("a{i:05}"), "working", 50));
    }
    book.hold(ALICE, &held("old".into(), "completed", 10));
    book.hold(ALICE, &held("new".into(), "completed", 20));
    let mut out = Vec::new();
    sweep(&mut book, 30, 1, &mut out).unwrap();
    book.apply(&out);
    assert!(
        book.value(KIND_TASK, &task_key(ALICE, "old")).is_none(),
        "the oldest terminal first"
    );
    assert!(
        book.value(KIND_TASK, &task_key(ALICE, "new")).is_some(),
        "the budget was one"
    );
    let mut out = Vec::new();
    sweep(&mut book, 30, 64, &mut out).unwrap();
    book.apply(&out);
    assert!(book.value(KIND_TASK, &task_key(ALICE, "new")).is_none());
    assert_eq!(
        list(&mut book, ALICE, 30).unwrap().len(),
        MAX_RETAINED - 1,
        "no active task goes"
    );
}
