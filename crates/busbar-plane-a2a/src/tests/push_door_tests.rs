// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's half of push delivery, over the test's host records: what a moved task queues, and
//! the chain records an attempt owes.

use busbar_contract::vocab::{EV_PUSH_DELIVERED, EV_PUSH_FAILED};

use super::*;
use crate::a2a::task::TaskState;
use crate::push::DeliveryAuth;
use crate::records::{KIND_PUSH_CONFIG, KIND_TASK_EVENT};
use crate::tasks::tests::{submitted, Book, ALICE, BOB};
use crate::tasks::{event_key, get, task_key};
use crate::TaskEventRow;

/// Alice's task `t1`, moved to `working`, with `callback` on its row.
fn moved(book: &mut Book, callback: &str) -> TaskRow {
    submitted(book, ALICE, "t1", 100);
    let mut held = get(book, ALICE, "t1", 100).unwrap().unwrap();
    held.row.push_callback = callback.to_string();
    book.hold(ALICE, &held);
    let mut out = Vec::new();
    let at = Step {
        caller: ALICE,
        request_id: "r",
        now: 200,
    };
    let row = tasks::transition(book, &at, "t1", TaskState::Working, &mut out)
        .unwrap()
        .expect("moved");
    book.apply(&out);
    row
}

fn config(url: &str, auth: Option<DeliveryAuth>) -> PushConfig {
    PushConfig {
        id: "cfg".into(),
        url: url.into(),
        authentication: auth,
    }
}

/// A moved task whose caller registered a push config queues ONE notification, due at once, to
/// the config's URL, presenting the config's credential, and keyed to the caller.
#[test]
fn a_moved_task_with_a_registered_config_queues_its_notification_to_that_config() {
    let mut book = Book::default();
    let row = moved(&mut book, "");
    let auth = DeliveryAuth {
        scheme: "Bearer".into(),
        credentials: "tok".into(),
    };
    let d = Deliveries::new();
    assert!(queue(
        &d,
        &row,
        Some(&config("https://hook.example/cb", Some(auth)))
    ));
    let due = d.next_due(0).expect("due at once");
    assert_eq!(due.url, "https://hook.example/cb");
    assert_eq!(due.caller, ALICE);
    assert_eq!(due.task_id, "t1");
    let body: serde_json::Value = serde_json::from_slice(&due.body).unwrap();
    assert_eq!(body["task"]["status"]["state"], "working");
    let request = d.request(&due);
    assert!(request
        .fields
        .iter()
        .any(|(n, v)| n == b"authorization" && v == b"Bearer tok"));
}

/// With no config held, the callback on the row (an inline config's) is the destination; with
/// neither, nothing is queued.
#[test]
fn the_rows_own_callback_is_the_destination_and_no_callback_queues_nothing() {
    let mut book = Book::default();
    let row = moved(&mut book, "https://inline.example/cb");
    let d = Deliveries::new();
    assert!(queue(&d, &row, None));
    assert_eq!(d.next_due(0).expect("due").url, "https://inline.example/cb");

    let mut silent_book = Book::default();
    let silent = moved(&mut silent_book, "");
    let quiet = Deliveries::new();
    assert!(!queue(&quiet, &silent, None));
    assert_eq!(quiet.next_tick_ns(), 0, "no tick is wanted");
}

/// The config a moved task's notification goes to is read through the piece's records, under the
/// caller's own key: another caller's config for a task of the same id is never it.
#[test]
fn the_config_is_read_under_the_callers_own_key() {
    let mut book = Book::default();
    let row = moved(&mut book, "");
    let theirs = serde_json::to_vec(&config("https://bob.example/cb", None)).unwrap();
    book.apply(&[Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(BOB, "t1"),
        value: theirs,
    }]);
    let d = Deliveries::new();
    assert!(!queue_moved(&d, &mut book, ALICE, &row).unwrap());
    let mine = serde_json::to_vec(&config("https://alice.example/cb", None)).unwrap();
    book.apply(&[Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(ALICE, "t1"),
        value: mine,
    }]);
    assert!(queue_moved(&d, &mut book, ALICE, &row).unwrap());
    assert_eq!(d.next_due(0).expect("due").url, "https://alice.example/cb");
}

/// What an attempt owes is filed on its task's chain as the attempt's record kind, with no request
/// id (no inbound request originates a delivery); another caller's owed outcome is not filed.
#[test]
fn an_owed_outcome_is_filed_on_its_tasks_chain() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    submitted(&mut book, ALICE, "t2", 100);
    let owed = vec![
        Owed {
            caller: ALICE.into(),
            task_id: "t1".into(),
            kind: EV_PUSH_DELIVERED,
        },
        Owed {
            caller: ALICE.into(),
            task_id: "t2".into(),
            kind: EV_PUSH_FAILED,
        },
        Owed {
            caller: BOB.into(),
            task_id: "t1".into(),
            kind: EV_PUSH_DELIVERED,
        },
    ];
    let mut out = Vec::new();
    file_owed(&mut book, ALICE, &owed, 300, &mut out).unwrap();
    book.apply(&out);
    let ev = |task: &str| -> TaskEventRow {
        serde_json::from_slice(
            book.value(KIND_TASK_EVENT, &event_key(ALICE, task, 2))
                .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(ev("t1").kind, EV_PUSH_DELIVERED);
    assert_eq!(ev("t1").request_id, "");
    assert_eq!(ev("t1").ts, 300);
    assert_eq!(ev("t2").kind, EV_PUSH_FAILED);
    assert_eq!(out.len(), 4, "two chain changes: a row and an event each");
}
