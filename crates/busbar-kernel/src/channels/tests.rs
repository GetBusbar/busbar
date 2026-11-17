// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §12.19: respawn and trip, the ask line, the signal registry.

use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::ask_line::{AskLine, Write};
use super::respawn::{delay, Respawn, Spawn, TRIP_AT, WINDOW};
use super::signals::{SignalRegistry, Signalled};
use super::SessionSignals;

const MS: Duration = Duration::from_millis(1);

#[test]
fn the_schedule_is_100_ms_doubling_then_the_trip() {
    assert_eq!(delay(1), Some(100 * MS));
    assert_eq!(delay(2), Some(200 * MS));
    assert_eq!(delay(3), Some(400 * MS));
    assert_eq!(delay(4), Some(800 * MS));
    assert_eq!(delay(TRIP_AT), None);
    assert_eq!(delay(0), Some(Duration::ZERO));
}

#[test]
fn a_child_that_exits_at_once_backs_off_then_trips_on_the_fifth_end() {
    let t0 = Instant::now();
    let mut r = Respawn::new();
    assert_eq!(r.next(t0), Spawn::Now, "the first attach spawns at once");
    let mut at = t0;
    for (n, wait) in [100u32, 200, 400, 800].into_iter().enumerate() {
        assert!(!r.ended(at), "end {} does not trip", n + 1);
        assert_eq!(r.next(at), Spawn::After(wait * MS));
        assert_eq!(r.next(at + (wait / 2) * MS), Spawn::After((wait / 2) * MS));
        at += wait * MS;
        assert_eq!(r.next(at), Spawn::Now, "respawned after {wait} ms");
    }
    assert!(r.ended(at), "the 5th end inside 60 s trips");
    assert!(r.is_tripped());
    assert_eq!(r.next(at), Spawn::Tripped);
    assert_eq!(
        r.next(at + 2 * WINDOW),
        Spawn::Tripped,
        "a trip holds until the upstream is declared anew"
    );
    assert!(!r.ended(at + MS), "a tripped channel trips once");
    r.redeclared();
    assert!(!r.is_tripped());
    assert_eq!(r.next(at + MS), Spawn::Now);
}

#[test]
fn ends_older_than_the_window_are_not_counted() {
    let t0 = Instant::now();
    let mut r = Respawn::new();
    for n in 0..4 {
        assert!(!r.ended(t0 + n * MS));
    }
    let later = t0 + WINDOW + 10 * MS;
    assert_eq!(
        r.next(later),
        Spawn::Now,
        "every counted end left the window"
    );
    assert!(!r.ended(later), "the 5th end, but only the 1st inside 60 s");
    assert_eq!(r.next(later), Spawn::After(100 * MS));
}

#[test]
fn a_serial_line_writes_one_ask_at_a_time_and_answers_never_queue() {
    let mut line = AskLine::new(true);
    assert_eq!(line.send(1, b"a1", true), Write::Now(b"a1".to_vec().into()));
    assert_eq!(line.send(2, b"b1", true), Write::Queued);
    assert_eq!(line.send(3, b"c1", true), Write::Queued);
    // A reply to the member's own request (no MSG_ASK) is written at once, even under CH_SERIAL.
    assert_eq!(
        line.send(2, b"reply", false),
        Write::Now(b"reply".to_vec().into())
    );
    assert_eq!(line.head(), Some(1), "DX_OUTSTANDING goes to the head");
    assert_eq!(line.finished(1), vec![Box::<[u8]>::from(&b"b1"[..])]);
    assert_eq!(line.head(), Some(2));
    // The head detaching hands the line on.
    assert_eq!(line.detached(2), vec![Box::<[u8]>::from(&b"c1"[..])]);
    assert_eq!(line.head(), Some(3));
    assert_eq!(line.finished(3), Vec::<Box<[u8]>>::new());
    assert!(line.is_empty());
    assert_eq!(line.head(), None);
}

#[test]
fn an_open_line_writes_every_ask_at_once() {
    let mut line = AskLine::new(false);
    assert_eq!(line.send(1, b"a", true), Write::Now(b"a".to_vec().into()));
    assert_eq!(line.send(2, b"b", true), Write::Now(b"b".to_vec().into()));
    assert_eq!(line.len(), 2);
    assert_eq!(line.finished(2), Vec::<Box<[u8]>>::new());
    assert_eq!(line.head(), Some(1));
}

#[test]
fn a_generation_end_fails_each_open_slot_once() {
    let mut line = AskLine::new(true);
    let _ = line.send(1, b"a", true);
    let _ = line.send(2, b"b", true);
    let _ = line.send(1, b"c", true);
    assert_eq!(line.ended(), vec![1, 2]);
    assert!(line.is_empty());
}

#[test]
fn a_waiting_ask_of_a_detached_slot_is_never_written() {
    let mut line = AskLine::new(true);
    let _ = line.send(1, b"a", true);
    let _ = line.send(2, b"b", true);
    let _ = line.send(3, b"c", true);
    assert!(line.detached(2).is_empty(), "the head is still 1");
    assert_eq!(line.finished(1), vec![Box::<[u8]>::from(&b"c"[..])]);
}

#[test]
fn signal_reaches_the_sessions_of_the_key_and_subject_only() {
    let reg = SignalRegistry::new();
    let (tx_a, mut rx_a) = mpsc::channel(4);
    let (tx_b, mut rx_b) = mpsc::channel(4);
    let (tx_c, mut rx_c) = mpsc::channel(4);
    let (tx_d, mut rx_d) = mpsc::channel(4);
    let alice = Some([1u8; 32]);
    let bob = Some([2u8; 32]);
    let _a = reg.register(7, b"task-1", alice, tx_a);
    let _b = reg.register(7, b"task-1", bob, tx_b);
    let _c = reg.register(7, b"task-2", alice, tx_c);
    let _d = reg.register(8, b"task-1", alice, tx_d);

    assert_eq!(reg.signal(7, b"task-1", None, 9, b"hi"), 2);
    let want = Signalled {
        flags: 9,
        bytes: b"hi".to_vec().into(),
    };
    assert_eq!(rx_a.try_recv().unwrap(), want);
    assert_eq!(rx_b.try_recv().unwrap(), want);
    assert!(rx_c.try_recv().is_err(), "another key");
    assert!(rx_d.try_recv().is_err(), "another instance");

    assert_eq!(reg.signal(7, b"task-1", alice, 9, b"you"), 1);
    assert!(rx_a.try_recv().is_ok());
    assert!(rx_b.try_recv().is_err(), "another subject");
    assert_eq!(reg.signal(7, b"none", None, 9, b"x"), 0);
}

#[test]
fn a_full_session_is_skipped_and_counted_and_a_dropped_guard_unregisters() {
    let reg = SignalRegistry::new();
    let (tx_a, _rx_a) = mpsc::channel(1);
    let (tx_b, mut rx_b) = mpsc::channel(4);
    let a = reg.register(1, b"k", None, tx_a);
    let b = reg.register(1, b"k", None, tx_b);
    assert_eq!(reg.signal(1, b"k", None, 0, b"1"), 2);
    assert_eq!(reg.signal(1, b"k", None, 0, b"2"), 1, "a is full");
    assert_eq!(reg.dropped(), 1);
    assert_eq!(reg.live(1, b"k"), 2);
    drop(a);
    assert_eq!(reg.live(1, b"k"), 1);
    drop(b);
    assert_eq!(reg.live(1, b"k"), 0);
    assert_eq!(reg.signal(1, b"k", None, 0, b"3"), 0);
    assert_eq!(rx_b.try_recv().unwrap().bytes.as_ref(), b"1");
}

#[test]
fn a_signal_fans_out_to_at_most_max_fanout_sessions() {
    let reg = SignalRegistry::new();
    let n = busbar_plugin_abi::plane::MAX_FANOUT as usize + 3;
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        let (tx, rx) = mpsc::channel(1);
        held.push((reg.register(2, b"k", None, tx), rx));
    }
    assert_eq!(
        reg.signal(2, b"k", None, 0, b"x"),
        busbar_plugin_abi::plane::MAX_FANOUT
    );
}

mod attachments {
    use super::super::link::Link;
    use super::super::{Attachment, ChannelMsg};
    use crate::plugin_records::RecordsDenied;
    use tokio::sync::mpsc;

    fn link(
        serial: bool,
    ) -> (
        super::super::budget::UnitBudget,
        std::sync::Arc<Link>,
        mpsc::Receiver<super::super::protected::GuardedWrite>,
    ) {
        let instance = super::super::budget::ChannelBudget::new().instance();
        let unit = instance.unit();
        let (link, queue) = Link::new(
            serial,
            super::super::frame::Framing::Ndjson,
            instance.link(),
        );
        (unit, link, queue)
    }

    fn attach(
        budget: &super::super::budget::UnitBudget,
        link: &std::sync::Arc<Link>,
        slot: u64,
        greet: bool,
    ) -> (Attachment, mpsc::Sender<ChannelMsg>) {
        let (tx, rx) = mpsc::channel(4);
        (
            Attachment::linked(
                link.clone(),
                budget.clone(),
                1,
                slot,
                greet,
                bytes::Bytes::new(),
                rx,
            )
            .unwrap(),
            tx,
        )
    }

    #[tokio::test]
    async fn send_writes_in_arrival_order_and_recv_yields_then_ends() {
        let (unit, link, mut queue) = link(false);
        let (mut a, tx) = attach(&unit, &link, 1, true);
        a.send(b"one", false).await.unwrap();
        a.send(b"two", true).await.unwrap();
        assert_eq!(queue.recv().await.unwrap().as_bytes(), b"one");
        assert_eq!(queue.recv().await.unwrap().as_bytes(), b"two");
        tx.send(ChannelMsg::Message(b"in".as_slice().into()))
            .await
            .unwrap();
        assert!(matches!(a.recv().await, Some(ChannelMsg::Message(m)) if &*m == b"in"));
        drop(tx);
        assert!(matches!(a.recv().await, Some(ChannelMsg::Ended)));
    }

    #[tokio::test]
    async fn serial_asks_wait_their_turn_and_detach_hands_on() {
        let (unit, link, mut queue) = link(true);
        let (mut a, _ta) = attach(&unit, &link, 1, true);
        let (mut b, _tb) = attach(&unit, &link, 2, false);
        a.send(b"a", true).await.unwrap();
        b.send(b"b", true).await.unwrap();
        b.send(b"reply", false).await.unwrap();
        assert_eq!(queue.recv().await.unwrap().as_bytes(), b"a");
        assert_eq!(queue.recv().await.unwrap().as_bytes(), b"reply");
        assert!(queue.try_recv().is_err(), "b's ask waits behind a's");
        drop(a);
        assert_eq!(queue.recv().await.unwrap().as_bytes(), b"b");
    }

    #[tokio::test]
    async fn only_the_greeting_session_readies_and_a_dead_writer_is_unavailable() {
        let (unit, link, queue) = link(false);
        let (mut g, _tg) = attach(&unit, &link, 1, true);
        let (mut n, _tn) = attach(&unit, &link, 2, false);
        n.ready(b"no").unwrap();
        assert!(link.ready_tail().is_none());
        g.ready(b"yes").unwrap();
        assert_eq!(link.ready_tail().as_deref(), Some(b"yes".as_slice()));
        drop(queue);
        assert_eq!(g.send(b"x", false).await, Err(RecordsDenied::Unavailable));
    }

    #[tokio::test]
    async fn a_detaching_greeter_hands_the_greet_on() {
        let (unit, link, _queue) = link(false);
        let (g, _tg) = attach(&unit, &link, 1, true);
        drop(g);
        link.greet_released().await;
    }

    #[test]
    fn ready_aliases_retain_one_backing_and_retired_publication_releases_its_credit() {
        let (unit, link, queue) = link(false);
        let (mut g, tx) = attach(&unit, &link, 1, true);
        let before = unit.used().bytes;
        g.ready(b"ready").unwrap();
        assert_eq!(unit.used().bytes, before + 5);
        let first = link.ready_tail().unwrap();
        let second = link.ready_tail().unwrap();
        assert_eq!(first.as_ptr(), second.as_ptr());
        g.ready(b"ignored").unwrap();
        assert_eq!(unit.used().bytes, before + 5);
        drop((g, tx, queue, link, first));
        assert_eq!(unit.used().bytes, 5);
        drop(second);
        assert_eq!(unit.used().bytes, 0);

        let (unit, link, _queue) = self::link(false);
        let (mut g, _tx) = attach(&unit, &link, 1, true);
        let before = unit.used().bytes;
        link.ended();
        assert_eq!(g.ready(b"late"), Err(RecordsDenied::Unavailable));
        assert!(link.ready_tail().is_none());
        assert_eq!(unit.used().bytes, before);
    }
}

// IF §12.23, C-LINE-CARRIER: the carrier table behind `PlaneOut::Emit`.
mod line_carriers {
    use std::sync::{Arc, Mutex};

    use busbar_contract::abi::mechanism::KindCode;
    use busbar_contract::services::{Caller, Incarnation};

    use crate::channels::line_carriers::{CarrierSink, LineCarriers};

    fn owner(name: &str) -> Incarnation {
        Caller::for_test(Arc::from(name), KindCode::Plane)
            .incarnation()
            .clone()
    }

    fn recording() -> (CarrierSink, Arc<Mutex<Vec<Vec<u8>>>>) {
        let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let into = Arc::clone(&seen);
        let sink: CarrierSink = Arc::new(move |b: &[u8]| {
            into.lock().unwrap().push(b.to_vec());
            true
        });
        (sink, seen)
    }

    #[test]
    fn ids_are_non_zero_and_never_repeat() {
        let carriers = LineCarriers::new();
        let me = owner("mcp");
        let (sink, _) = recording();
        let a = carriers.open(&me, Arc::from("anon"), Arc::clone(&sink));
        let b = carriers.open(&me, Arc::from("anon"), sink);
        assert_ne!(a, b);
        assert!(a.get() > 0 && b.get() > 0);
    }

    #[test]
    fn an_emit_reaches_the_carrier_its_owner_holds() {
        let carriers = LineCarriers::new();
        let me = owner("mcp");
        let (sink, seen) = recording();
        let id = carriers.open(&me, Arc::from("key-1"), sink).get();
        assert!(carriers.emit_from_plane(&me, id, b"{\"ping\":1}"));
        assert_eq!(*seen.lock().unwrap(), vec![b"{\"ping\":1}".to_vec()]);
        assert_eq!(carriers.dropped(), 0);
        assert_eq!(carriers.emit(&me, id, b"x").as_deref(), Some("key-1"));
    }

    #[test]
    fn another_instances_carrier_drops_the_emit_and_counts_it() {
        let carriers = LineCarriers::new();
        let (sink, seen) = recording();
        let id = carriers.open(&owner("mcp"), Arc::from("anon"), sink).get();
        assert!(!carriers.emit_from_plane(&owner("other"), id, b"x"));
        assert!(
            !carriers.emit_from_plane(&owner("mcp"), id, b"x"),
            "a replacement with an equal name is another incarnation"
        );
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(carriers.dropped(), 2);
    }

    #[test]
    fn an_ended_or_unknown_carrier_drops_the_emit_and_counts_it() {
        let carriers = LineCarriers::new();
        let me = owner("mcp");
        let (sink, seen) = recording();
        let id = carriers.open(&me, Arc::from("anon"), sink).get();
        assert!(carriers.is_open(&me, id));
        assert!(carriers.end(id));
        assert!(!carriers.end(id), "a carrier ends once");
        assert!(!carriers.is_open(&me, id));
        assert!(!carriers.emit_from_plane(&me, id, b"x"));
        assert!(!carriers.emit_from_plane(&me, id + 1_000_000, b"x"));
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(carriers.dropped(), 2);
    }

    #[test]
    fn a_writer_that_is_gone_ends_the_carrier() {
        let carriers = LineCarriers::new();
        let me = owner("mcp");
        let id = carriers
            .open(&me, Arc::from("anon"), Arc::new(|_: &[u8]| false))
            .get();
        assert!(!carriers.emit_from_plane(&me, id, b"x"));
        assert!(!carriers.is_open(&me, id));
        assert_eq!(carriers.dropped(), 1);
    }
}
