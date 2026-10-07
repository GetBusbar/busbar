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

// ── one attempt, over a test's host (the engine's `pushdeliver_tests.rs`) ──────────────────────

use std::cell::RefCell;

use busbar_contract::abi::host::service::{DEST_INTERNAL, DEST_PLAINTEXT};
use busbar_contract::vocab::EV_PUSH_REFUSED;

use crate::push::Settled;

/// A public address a callback resolves to at registration.
const AT_REGISTRATION: &str = "203.0.113.7";

/// A host whose judge answers each attempt from a script (the last answer repeats), and whose
/// receiver answers `status`; every judged URL and every send is logged.
struct TestHost {
    verdicts: RefCell<Vec<Option<(u64, Vec<String>)>>>,
    status: u16,
    judged: RefCell<Vec<String>>,
    sent: RefCell<Vec<String>>,
}

impl TestHost {
    fn answering(verdicts: Vec<Option<(u64, &[&str])>>, status: u16) -> Self {
        TestHost {
            verdicts: RefCell::new(
                verdicts
                    .into_iter()
                    .map(|v| {
                        v.map(|(verdict, a)| {
                            (verdict, a.iter().copied().map(String::from).collect())
                        })
                    })
                    .collect(),
            ),
            status,
            judged: RefCell::default(),
            sent: RefCell::default(),
        }
    }
}

impl Line for TestHost {
    fn judge(&self, url: &str) -> Poll<Option<(u64, Vec<String>, String)>> {
        self.judged.borrow_mut().push(url.to_string());
        let mut script = self.verdicts.borrow_mut();
        let next = if script.len() > 1 {
            script.remove(0)
        } else {
            script[0].clone()
        };
        Poll::Ready(next.map(|(verdict, addrs)| {
            let within = addrs.join(",");
            (verdict, addrs, within)
        }))
    }

    fn send(&self, _ex: &mut Exchange, url: &str) -> Poll<Option<u16>> {
        self.sent.borrow_mut().push(url.to_string());
        Poll::Ready(Some(self.status))
    }
}

/// A `completed` task of Alice's with `callback`, its notification queued with a credential.
fn queued(callback: &str) -> Deliveries {
    let mut book = Book::default();
    let mut row = moved(&mut book, callback);
    row.state = "completed".into();
    let d = Deliveries::new();
    let auth = DeliveryAuth {
        scheme: "Bearer".into(),
        credentials: "tok".into(),
    };
    assert!(queue(&d, &row, Some(&config(callback, Some(auth)))));
    d
}

/// One `tick`'s attempt at `now_ns`, settled as the tick settles it.
fn tick_once(d: &Deliveries, host: &TestHost, now_ns: u64) -> (Attempted, Settled) {
    let delivery = d.next_due(now_ns).expect("a delivery is due");
    let mut flight = Flight {
        delivery,
        exchange: None,
    };
    let Poll::Ready((end, reached)) = attempt(host, d, &mut flight) else {
        panic!("the test's host never pends");
    };
    d.reached(&flight.delivery.url, &reached);
    d.owe(&flight.delivery, end);
    (end, d.settle(&flight.delivery.task_id, end, now_ns, 128))
}

/// The base case: a completed task with a callback is POSTed to it once, on the addresses the judge
/// just judged, and its delivered record is owed; its last delivery drops the credential.
#[test]
fn a_completed_task_with_a_callback_is_delivered() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    let (end, settled) = tick_once(&d, &host, 0);
    assert_eq!(end, Attempted::Delivered);
    assert_eq!(settled, Settled::Done(EV_PUSH_DELIVERED));
    assert_eq!(*host.sent.borrow(), vec![callback.to_string()]);
    assert_eq!(
        d.rebound(callback, &["198.51.100.9".to_string()]),
        Some(Attempted::Moved),
        "the addresses the delivery reached are the ones the judge judged"
    );
    assert_eq!(d.take_owed(ALICE, None)[0].kind, EV_PUSH_DELIVERED);
}

/// A callback that resolves to an internal address at DELIVERY (it passed at registration) is
/// refused by the judge on this attempt, and nothing is sent.
#[test]
fn a_callback_that_became_internal_after_registration_is_refused_at_delivery() {
    let d = queued("https://hook.caller.test/notify");
    let host = TestHost::answering(vec![Some((DEST_INTERNAL, &[][..]))], 200);
    let (end, settled) = tick_once(&d, &host, 0);
    assert_eq!(end, Attempted::Judged(DEST_INTERNAL));
    assert_eq!(settled, Settled::Done(EV_PUSH_REFUSED), "never retried");
    assert!(host.sent.borrow().is_empty(), "refused before the socket");
}

/// Across a restart no reached address survives, so the anti-rebinding rule has nothing to compare
/// with: the judge alone still refuses the internal answer.
#[test]
fn the_rebind_is_still_refused_when_no_pin_survives_the_restart() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    assert_eq!(d.rebound(callback, &[]), None, "nothing reached: a restart");
    let host = TestHost::answering(vec![Some((DEST_INTERNAL, &[][..]))], 200);
    let (end, _) = tick_once(&d, &host, 0);
    assert_eq!(end, Attempted::Judged(DEST_INTERNAL));
    assert!(host.sent.borrow().is_empty());
}

/// A name that resolves to nothing at delivery, or a judgement that could not be made, is refused:
/// nothing was checked, so nothing is allowed.
#[test]
fn a_name_that_resolves_to_nothing_at_delivery_time_is_refused() {
    for script in [Some((DEST_UNRESOLVABLE, &[][..])), None] {
        let d = queued("https://hook.caller.test/notify");
        let host = TestHost::answering(vec![script], 200);
        let (end, _) = tick_once(&d, &host, 0);
        assert_eq!(end, Attempted::Judged(DEST_UNRESOLVABLE));
        assert!(host.sent.borrow().is_empty());
    }
}

/// A private address is refused with no socket: no exchange is framed and nothing is sent, so the
/// caller's credential reaches no refused destination.
#[test]
fn a_private_address_is_refused_with_no_socket() {
    let d = queued("https://hook.caller.test/notify");
    let host = TestHost::answering(vec![Some((DEST_INTERNAL, &[][..]))], 200);
    let delivery = d.next_due(0).expect("due");
    let mut flight = Flight {
        delivery,
        exchange: None,
    };
    let _ = attempt(&host, &d, &mut flight);
    assert!(flight.exchange.is_none(), "no request was framed");
    assert!(host.sent.borrow().is_empty(), "no socket");
}

/// A plaintext callback that reached a row is refused at DELIVERY on the host's verdict (the
/// open-web class admits a secure connection only), and nothing is sent.
#[test]
fn a_plaintext_callback_is_refused_at_delivery() {
    let callback = "http://hook.caller.test/notify";
    let d = queued(callback);
    let host = TestHost::answering(vec![Some((DEST_PLAINTEXT, &[][..]))], 200);
    let (end, settled) = tick_once(&d, &host, 0);
    assert_eq!(end, Attempted::Judged(DEST_PLAINTEXT));
    assert_eq!(settled, Settled::Done(EV_PUSH_REFUSED));
    assert_eq!(*host.judged.borrow(), vec![callback.to_string()]);
    assert!(host.sent.borrow().is_empty());
}

/// The judge is asked again on the retry: a receiver that failed with a `503` is retried, and the
/// retry's fresh verdict (now internal) refuses it before anything is sent a second time.
#[test]
fn the_guard_is_re_run_on_the_retry() {
    let d = queued("https://hook.caller.test/notify");
    let host = TestHost::answering(
        vec![
            Some((DEST_ALLOWED, &[AT_REGISTRATION][..])),
            Some((DEST_INTERNAL, &[][..])),
        ],
        503,
    );
    let (first, settled) = tick_once(&d, &host, 0);
    assert_eq!(first, Attempted::Status(503));
    let Settled::Retry(at) = settled else {
        panic!("a 503 is retried: {settled:?}");
    };
    let (second, settled) = tick_once(&d, &host, at);
    assert_eq!(second, Attempted::Judged(DEST_INTERNAL));
    assert_eq!(settled, Settled::Done(EV_PUSH_REFUSED));
    assert_eq!(host.judged.borrow().len(), 2, "judged on every attempt");
    assert_eq!(host.sent.borrow().len(), 1, "the retry sent nothing");
}

/// A DELETED CONFIG TAKES ITS WEBHOOK CREDENTIAL OUT OF PLANE MEMORY (the engine's delete called
/// `pushdeliver::forget`): the tombstone a delete writes for the caller's task drops the credential
/// the delivery would present; another caller's tombstone, or a config written, drops nothing.
#[test]
fn a_deleted_config_takes_its_credential_out_of_memory() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let due = d.next_due(0).expect("due");
    let presented = |d: &Deliveries| {
        d.request(&due)
            .fields
            .iter()
            .any(|(n, _)| n == b"authorization")
    };
    let tombstone = |caller: &str| Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(caller, "t1"),
        value: Vec::new(),
    };
    let written = Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(ALICE, "t1"),
        value: b"{}".to_vec(),
    };
    forget_deleted(&d, ALICE, &[tombstone(BOB), written]);
    assert!(presented(&d), "nothing of Alice's was deleted");
    forget_deleted(&d, ALICE, &[tombstone(ALICE)]);
    assert!(!presented(&d), "the deleted config's credential is gone");
}
