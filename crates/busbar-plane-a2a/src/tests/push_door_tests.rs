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
    let at = Stamp {
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
        credentials: busbar_contract::Redacted::new("tok".into()),
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

use busbar_contract::abi::host::service::{DEST_INTERNAL, DEST_PLAINTEXT};
use busbar_contract::vocab::EV_PUSH_REFUSED;

use crate::push::DeliverySettled;

/// A public address a callback resolves to at registration.
const AT_REGISTRATION: &str = "203.0.113.7";

/// One scripted judgement: a verdict and the addresses it judged; `None` = nothing was checked.
type Scripted = Option<(u64, Vec<String>)>;

/// A host whose judge answers each attempt from a script (the last answer repeats), and whose
/// receiver answers `status`; every judged URL and every send is logged, and every send's framed
/// exchange is read back: the fields the far end is handed, keyed to the URL they went to.
struct TestHost {
    verdicts: Vec<Scripted>,
    status: u16,
    judged: Vec<String>,
    sent: Vec<String>,
    /// Each send's URL and the fields its exchange framed, in send order.
    framed: Vec<(String, Vec<(Vec<u8>, Vec<u8>)>)>,
    /// How many sends answer PENDING before one reaches the receiver.
    pends: u32,
    /// How many attempts were abandoned (their connection closed).
    abandoned: u32,
}

impl TestHost {
    fn answering(verdicts: Vec<Option<(u64, &[&str])>>, status: u16) -> Self {
        TestHost {
            verdicts: verdicts
                .into_iter()
                .map(|v| {
                    v.map(|(verdict, a)| (verdict, a.iter().copied().map(String::from).collect()))
                })
                .collect(),
            status,
            judged: Vec::new(),
            sent: Vec::new(),
            framed: Vec::new(),
            pends: 0,
            abandoned: 0,
        }
    }
}

impl Line for TestHost {
    fn judge(&mut self, url: &str) -> Poll<Option<Judgement>> {
        self.judged.push(url.to_string());
        let next = if self.verdicts.len() > 1 {
            self.verdicts.remove(0)
        } else {
            self.verdicts[0].clone()
        };
        Poll::Ready(next.map(|(verdict, addrs)| {
            let within = addrs.join(",");
            (verdict, addrs, within)
        }))
    }

    fn send(&mut self, ex: &mut Exchange, url: &str) -> Poll<Option<u16>> {
        if self.pends > 0 {
            self.pends -= 1;
            return Poll::Pending;
        }
        self.sent.push(url.to_string());
        let fields = ex
            .framed_fields()
            .into_iter()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect();
        self.framed.push((url.to_string(), fields));
        Poll::Ready(Some(self.status))
    }

    fn jitter(&mut self) -> u8 {
        128
    }

    fn abandon(&mut self, _stream: Option<u64>) {
        self.abandoned += 1;
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
        credentials: busbar_contract::Redacted::new("tok".into()),
    };
    assert!(queue(&d, &row, Some(&config(callback, Some(auth)))));
    d
}

/// One `tick`'s attempt at `now_ns`, settled as the tick settles it.
fn tick_once(d: &Deliveries, host: &mut TestHost, now_ns: u64) -> (Attempted, DeliverySettled) {
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
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    let (end, settled) = tick_once(&d, &mut host, 0);
    assert_eq!(end, Attempted::Delivered);
    assert_eq!(settled, DeliverySettled::Done(EV_PUSH_DELIVERED));
    assert_eq!(host.sent, vec![callback.to_string()]);
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
    let mut host = TestHost::answering(vec![Some((DEST_INTERNAL, &[][..]))], 200);
    let (end, settled) = tick_once(&d, &mut host, 0);
    assert_eq!(end, Attempted::Judged(DEST_INTERNAL));
    assert_eq!(
        settled,
        DeliverySettled::Done(EV_PUSH_REFUSED),
        "never retried"
    );
    assert!(host.sent.is_empty(), "refused before the socket");
}

/// THE CALLER'S OWN CREDENTIAL IS PRESENTED, and it is the caller's — not busbar's (ported from the
/// engine's `pushdeliver_tests.rs::the_callers_own_webhook_credential_is_presented_on_the_delivery`,
/// the `egress-auth × a2a-server` cell). A caller whose webhook authenticates registers its
/// `authentication` with the push config; the exchange the attempt actually frames and sends, once
/// the judge admits the callback, carries exactly one `authorization` field, `<scheme>
/// <credentials>` as RFC 9110 spells it and as the caller wrote it. Read off the SENT exchange, as
/// predev read its sent log: framing the attempt without the held credential, or an exchange that
/// drops the field, reds here. The credential is never printed: a failure names the field, not its
/// value.
#[test]
fn the_callers_own_webhook_credential_is_presented_on_the_delivery() {
    let callback = "https://hook.caller.test/notify";
    let mut book = Book::default();
    let row = moved(&mut book, callback);
    let d = Deliveries::new();
    let auth = DeliveryAuth {
        scheme: "Bearer".into(),
        credentials: busbar_contract::Redacted::new("receiver-issued-token".into()),
    };
    assert!(queue(&d, &row, Some(&config(callback, Some(auth)))));
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    let (end, _) = tick_once(&d, &mut host, 0);
    assert_eq!(end, Attempted::Delivered);
    assert_eq!(
        host.sent,
        vec![callback.to_string()],
        "the delivery is sent once, to the caller's callback"
    );
    assert_eq!(host.framed.len(), 1, "one exchange was framed and sent");
    let (url, fields) = &host.framed[0];
    assert_eq!(
        url, callback,
        "the framed exchange is the one sent to the callback"
    );
    let presented: Vec<&[u8]> = fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(b"authorization"))
        .map(|(_, value)| value.as_slice())
        .collect();
    assert_eq!(
        presented.len(),
        1,
        "the sent exchange carries {} authorization field(s), not exactly one",
        presented.len()
    );
    assert!(
        presented[0] == b"Bearer receiver-issued-token".as_slice(),
        "the sent exchange's authorization field is not the credential the caller registered"
    );
}

/// Across a restart no reached address survives, so the anti-rebinding rule has nothing to compare
/// with: the judge alone still refuses the internal answer.
#[test]
fn the_rebind_is_still_refused_when_no_pin_survives_the_restart() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    assert_eq!(d.rebound(callback, &[]), None, "nothing reached: a restart");
    let mut host = TestHost::answering(vec![Some((DEST_INTERNAL, &[][..]))], 200);
    let (end, _) = tick_once(&d, &mut host, 0);
    assert_eq!(end, Attempted::Judged(DEST_INTERNAL));
    assert!(host.sent.is_empty());
}

/// A name that resolves to nothing at delivery, or a judgement that could not be made, is refused:
/// nothing was checked, so nothing is allowed.
#[test]
fn a_name_that_resolves_to_nothing_at_delivery_time_is_refused() {
    for script in [Some((DEST_UNRESOLVABLE, &[][..])), None] {
        let d = queued("https://hook.caller.test/notify");
        let mut host = TestHost::answering(vec![script], 200);
        let (end, _) = tick_once(&d, &mut host, 0);
        assert_eq!(end, Attempted::Judged(DEST_UNRESOLVABLE));
        assert!(host.sent.is_empty());
    }
}

/// A private address is refused with no socket: no exchange is framed and nothing is sent, so the
/// caller's credential reaches no refused destination.
#[test]
fn a_private_address_is_refused_with_no_socket() {
    let d = queued("https://hook.caller.test/notify");
    let mut host = TestHost::answering(vec![Some((DEST_INTERNAL, &[][..]))], 200);
    let delivery = d.next_due(0).expect("due");
    let mut flight = Flight {
        delivery,
        exchange: None,
    };
    let _ = attempt(&mut host, &d, &mut flight);
    assert!(flight.exchange.is_none(), "no request was framed");
    assert!(host.sent.is_empty(), "no socket");
}

/// A plaintext callback that reached a row is refused at DELIVERY on the host's verdict (the
/// open-web class admits a secure connection only), and nothing is sent.
#[test]
fn a_plaintext_callback_is_refused_at_delivery() {
    let callback = "http://hook.caller.test/notify";
    let d = queued(callback);
    let mut host = TestHost::answering(vec![Some((DEST_PLAINTEXT, &[][..]))], 200);
    let (end, settled) = tick_once(&d, &mut host, 0);
    assert_eq!(end, Attempted::Judged(DEST_PLAINTEXT));
    assert_eq!(settled, DeliverySettled::Done(EV_PUSH_REFUSED));
    assert_eq!(host.judged, vec![callback.to_string()]);
    assert!(host.sent.is_empty());
}

/// The judge is asked again on the retry: a receiver that failed with a `503` is retried, and the
/// retry's fresh verdict (now internal) refuses it before anything is sent a second time.
#[test]
fn the_guard_is_re_run_on_the_retry() {
    let d = queued("https://hook.caller.test/notify");
    let mut host = TestHost::answering(
        vec![
            Some((DEST_ALLOWED, &[AT_REGISTRATION][..])),
            Some((DEST_INTERNAL, &[][..])),
        ],
        503,
    );
    let (first, settled) = tick_once(&d, &mut host, 0);
    assert_eq!(first, Attempted::Status(503));
    let DeliverySettled::Retry(at) = settled else {
        panic!("a 503 is retried: {settled:?}");
    };
    let (second, settled) = tick_once(&d, &mut host, at);
    assert_eq!(second, Attempted::Judged(DEST_INTERNAL));
    assert_eq!(settled, DeliverySettled::Done(EV_PUSH_REFUSED));
    assert_eq!(host.judged.len(), 2, "judged on every attempt");
    assert_eq!(host.sent.len(), 1, "the retry sent nothing");
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

/// A queued notification wakes the instance's driver ticket (R-PUSH), so the kernel ticks and
/// attempts it at once; a task that queues nothing wakes nothing; an unarmed wake is a no-op.
#[test]
fn a_queued_notification_wakes_the_driver_ticket() {
    let mut book = Book::default();
    let row = moved(&mut book, "https://inline.example/cb");
    let (told, woken) = std::sync::mpsc::channel::<()>();
    let d = Deliveries::new();
    assert!(queue(&d, &row, None), "unarmed: queued, no wake to make");
    d.arm(|| {
        Box::new(move || {
            let _ = told.send(());
        })
    });
    d.arm(|| panic!("armed once"));
    assert_eq!(woken.try_iter().count(), 0, "arming wakes nothing");
    assert!(queue(&d, &row, None));
    assert_eq!(woken.try_iter().count(), 1, "queue wakes the ticket");
    let silent = moved(&mut Book::default(), "");
    assert!(!queue(&d, &silent, None));
    assert_eq!(woken.try_iter().count(), 0, "nothing queued, nothing woken");
}

/// The pushback path (`queue_moved`, the agent's own report of a task's move) wakes the driver
/// ticket after queueing the caller's delivery.
#[test]
fn queue_moved_wakes_the_driver_ticket() {
    let mut book = Book::default();
    let row = moved(&mut book, "https://inline.example/cb");
    let (told, woken) = std::sync::mpsc::channel::<()>();
    let d = Deliveries::new();
    d.arm(|| {
        Box::new(move || {
            let _ = told.send(());
        })
    });
    assert!(queue_moved(&d, &mut book, ALICE, &row).unwrap());
    assert_eq!(woken.try_iter().count(), 1);
}

/// A delivery is never sent twice (R-PUSH): a `tick` whose exchange pends holds the attempt, and a
/// second `tick` while it is held starts nothing and calls nothing; `drive` alone carries it on, and
/// the receiver is reached EXACTLY once. RED against a variant where the tick and drive both
/// deliver (two receiver hits).
#[test]
fn a_pending_attempt_is_delivered_once_whether_tick_or_drive_runs_first() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let attempting = Attempting::default();
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    host.pends = 1;
    assert_eq!(tick_over(&mut host, &d, &attempting, 0), Outcome::Pending);
    assert!(host.sent.is_empty(), "the exchange is still in flight");
    let judged = host.judged.len();
    // The kernel's next tick (a timer, or another queued item's wake) while the attempt is held.
    assert_eq!(tick_over(&mut host, &d, &attempting, 1), Outcome::Ready);
    assert_eq!(
        host.judged.len(),
        judged,
        "a held attempt makes no host call"
    );
    assert!(host.sent.is_empty(), "the tick did not deliver");
    // The wake the pending service raised: `drive` finishes the one request.
    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    assert_eq!(host.sent, vec![callback.to_string()], "exactly one request");
    // Neither path delivers it again.
    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    assert_eq!(tick_over(&mut host, &d, &attempting, 2), Outcome::Ready);
    assert_eq!(host.sent.len(), 1, "never sent twice");
    assert_eq!(d.take_owed(ALICE, None).len(), 1, "one outcome owed");
}

/// A lost wake still ends in exactly one delivery (R-PUSH, coordinator option (b)): an attempt left
/// held with no `drive` is abandoned by the first tick past predev's delivery timeout (60 s,
/// `transport.rs:92`), which is asked for at that moment, and its delivery is requeued under the
/// retry rules and then sent once. RED against round 2's behaviour (a held attempt is never given
/// up): nothing is ever sent.
#[test]
fn a_dropped_wake_ends_in_exactly_one_delivery_after_the_timeout() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let attempting = Attempting::default();
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    host.pends = 1;
    let start = 1_000;
    assert_eq!(
        tick_over(&mut host, &d, &attempting, start),
        Outcome::Pending
    );
    assert_eq!(
        next_tick_ns(&d, &attempting),
        start + DELIVERY_TIMEOUT_NS,
        "the tick is asked for at the abandonment"
    );
    // Before the timeout the attempt is the drive's, and no wake comes.
    assert_eq!(
        tick_over(&mut host, &d, &attempting, start + 1),
        Outcome::Ready
    );
    assert_eq!(host.abandoned, 0);
    // At the timeout: cancelled first, then requeued; nothing else is in flight.
    let at = start + DELIVERY_TIMEOUT_NS;
    assert_eq!(tick_over(&mut host, &d, &attempting, at), Outcome::Ready);
    assert_eq!(host.abandoned, 1, "the attempt's connection was closed");
    assert!(
        host.sent.is_empty(),
        "the requeue waits out its retry delay"
    );
    assert_eq!(attempting.deadline_ns(), 0, "nothing is held");
    let again = next_tick_ns(&d, &attempting);
    assert!(again > at, "the retry is asked for: {again}");
    assert_eq!(tick_over(&mut host, &d, &attempting, again), Outcome::Ready);
    assert_eq!(
        host.sent,
        vec![callback.to_string()],
        "exactly one delivery"
    );
    assert_eq!(
        next_tick_ns(&d, &attempting),
        0,
        "nothing is left to tick for"
    );
}

/// An attempt cancelled by abandonment never also completes: the connection it held is closed, and
/// a late `drive` (the old connection's answer arriving) finds nothing to carry on, so the
/// receiver is reached once, by the requeued attempt. RED against a variant that abandons without
/// dropping the attempt (the late drive sends it a second time).
#[test]
fn an_abandoned_attempt_never_also_completes() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let attempting = Attempting::default();
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    host.pends = 1;
    assert_eq!(tick_over(&mut host, &d, &attempting, 0), Outcome::Pending);
    let at = DELIVERY_TIMEOUT_NS;
    assert_eq!(tick_over(&mut host, &d, &attempting, at), Outcome::Ready);
    assert_eq!(host.abandoned, 1);
    // The old connection's answer arrives late, waking the driver ticket.
    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    assert!(
        host.sent.is_empty(),
        "the abandoned attempt did not complete"
    );
    let again = next_tick_ns(&d, &attempting);
    assert_eq!(tick_over(&mut host, &d, &attempting, again), Outcome::Ready);
    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    assert_eq!(
        host.sent,
        vec![callback.to_string()],
        "reached exactly once"
    );
    assert_eq!(host.abandoned, 1);
}
