// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::host::conn::connector::StreamIn;
use std::time::{Duration, Instant};

fn needs(timeout_ms: u64) -> &'static [Need] {
    let mut needs = NAMED;
    needs[0].timeout_ms = timeout_ms;
    Box::leak(Box::new(needs))
}

fn timed(table: &Arc<Scripted>, timeout_ms: u64) -> Plugin<TestKind> {
    bound_over_needs(table.clone(), Adopter::unwatched(), needs(timeout_ms))
}

fn establish(p: &Plugin<TestKind>, seq: u32, timeout_ms: u32) -> ServiceOut {
    call(
        p,
        CONN_SLOTS.establish,
        &EstablishIn {
            head: head_of::<EstablishIn>(service::ESTABLISH, seq),
            need: 0,
            timeout_ms,
            target: abi_str("127.0.0.1:9"),
            within: abi_str(""),
            member: abi_str(""),
        },
    )
}

fn state(p: &Plugin<TestKind>) -> &'static super::super::ConnState {
    &crate::dispatch::handle::resolve(p.inner.ctx())
        .unwrap()
        .conn_state
}

fn expire(p: &Plugin<TestKind>, service: u32, seq: u32) {
    let handle = head_of::<IoIn>(service, seq).handle;
    state(p).waits.lock().unwrap().get_mut(&handle).unwrap().at = Instant::now();
}

#[test]
fn raw_establish_uses_the_declared_need_unless_the_caller_overrides_it() {
    for (need, caller, effective) in [
        (700, 0, 700),
        (700, 123, 123),
        (0, 0, 0),
        (u64::MAX, 0, u64::MAX),
    ] {
        let table = Arc::new(Scripted::default());
        let p = timed(&table, need);
        let out = establish(&p, 0, caller);
        assert!(ready(&out), "{}", error_text(&out));
        assert_eq!(*table.declared_timeouts.lock().unwrap(), vec![need]);
        assert_eq!(
            *table.timeouts.lock().unwrap(),
            vec![(effective, 0)],
            "dial inheritance must leave the request bound zero"
        );
        assert_eq!(
            state(&p)
                .streams()
                .get(&out.value)
                .unwrap()
                .reply_timeout_ms,
            need
        );
    }
}

#[test]
fn a_table_without_independent_bounds_refuses_an_unsupported_distinct_dial_bound() {
    let table = Arc::new(Recording::default());
    let p = bound_over_needs(table.clone(), Adopter::unwatched(), needs(700));
    let out = establish(&p, 0, 0);
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Refused));
    assert!(table.opened.lock().unwrap().is_empty());
    let desc = OpenDesc {
        target: "127.0.0.1:9",
        timeout_ms: 123,
        ..Default::default()
    };
    assert!(
        table
            .open_request(p.inner.instance, NeedId(0), &desc, false, 123)
            .is_ok(),
        "equal existing bounds retain the legacy path"
    );
}

#[test]
fn pending_establish_keeps_one_open_and_its_original_bound_across_recall() {
    let table = Arc::new(Scripted {
        landing: true,
        ..Default::default()
    });
    let p = timed(&table, 700);
    assert_eq!(
        establish(&p, 0, 0).outcome,
        RawOutcome::of(Outcome::Pending)
    );
    assert_eq!(
        establish(&p, 1, 0).outcome,
        RawOutcome::of(Outcome::Pending)
    );
    assert_eq!(*table.timeouts.lock().unwrap(), vec![(700, 0)]);
    assert_eq!(table.opened.lock().unwrap().len(), 1);
    let stored = state(&p).dialling.lock().unwrap().get(&T).unwrap().1;
    assert_eq!(
        establish(&p, 2, 123).outcome,
        RawOutcome::of(Outcome::Pending)
    );
    assert!(
        table.slab.get(p.inner.instance, stored).is_err(),
        "a changed establish replaces and closes the earlier dial"
    );
    assert_eq!(*table.timeouts.lock().unwrap(), vec![(700, 0), (123, 0)]);
    drop(super::super::forget(p.inner.instance, T));
    assert!(state(&p).dialling.lock().unwrap().is_empty());
}

#[test]
fn framed_end_preserves_independent_dial_request_and_reply_bounds() {
    for (caller, request_timeout) in [(0, 0), (123, 0), (123, 250), (0, u64::MAX)] {
        let table = Arc::new(Scripted {
            framed: true,
            ..Default::default()
        });
        let p = timed(&table, 700);
        let stream = establish(&p, 0, caller).value;
        let mut head = head_piece();
        head.timeout_ms = request_timeout;
        assert!(ready(&request(&p, 1, stream, &head, HEAD_BYTES)));
        assert!(ready(&request(
            &p,
            2,
            stream,
            &kind_piece(REQUEST_BODY),
            b"first"
        )));
        assert!(ready(&request(
            &p,
            3,
            stream,
            &kind_piece(REQUEST_BODY),
            b"last"
        )));
        assert!(table.opened.lock().unwrap().is_empty());
        assert!(ready(&request(
            &p,
            4,
            stream,
            &kind_piece(REQUEST_END),
            b""
        )));
        let effective = if caller == 0 { 700 } else { u64::from(caller) };
        assert_eq!(
            *table.timeouts.lock().unwrap(),
            vec![(effective, request_timeout)]
        );
        assert_eq!(
            *table.opened.lock().unwrap(),
            vec![(
                NeedId(0),
                "127.0.0.1:9".to_owned(),
                b"PATCH".to_vec(),
                b"/v1/x".to_vec(),
                vec![("a".to_owned(), b"1".to_vec())],
                b"firstlast".to_vec(),
            )]
        );
        assert_eq!(
            state(&p).streams().get(&stream).unwrap().reply_timeout_ms,
            700
        );

        assert!(ready(&request(
            &p,
            4,
            stream,
            &kind_piece(REQUEST_END),
            b""
        )));
        assert_eq!(table.timeouts.lock().unwrap().len(), 1);
    }
}

#[test]
fn a_pending_raw_read_keeps_its_clock_and_replays_the_original_timeout() {
    let table = Arc::new(Scripted::default());
    let p = timed(&table, 700);
    let stream = establish(&p, 0, 0).value;
    let mut buf = [0; 8];
    assert_eq!(
        raw_read(&p, 1, stream, &mut buf).outcome,
        RawOutcome::of(Outcome::Pending)
    );
    let handle = head_of::<IoIn>(service::READ, 1).handle;
    let original = state(&p).waits.lock().unwrap().get(&handle).unwrap().at;
    assert_eq!(
        raw_read(&p, 1, stream, &mut buf).outcome,
        RawOutcome::of(Outcome::Pending)
    );
    assert_eq!(
        state(&p).waits.lock().unwrap().get(&handle).unwrap().at,
        original
    );
    expire(&p, service::READ, 1);
    let timeout = raw_read(&p, 1, stream, &mut buf);
    assert_eq!(timeout.outcome, RawOutcome::of(Outcome::Failed));
    assert_eq!(error_text(&timeout), ConnError::Timeout.text());
    assert!(state(&p).waits.lock().unwrap().is_empty());
    let parked = table.parked.lock().unwrap().len();
    assert_eq!(raw_read(&p, 1, stream, &mut buf).outcome, timeout.outcome);
    assert_eq!(
        table.parked.lock().unwrap().len(),
        parked,
        "replay never reaches the backend again"
    );
    table
        .script
        .lock()
        .unwrap()
        .push_back((piece(PieceKind::Body, None, None, 2), b"ok".to_vec()));
    assert!(ready(&raw_read(&p, 2, stream, &mut buf)));
    assert_eq!(&buf[..2], b"ok");
}

#[test]
fn each_framed_reply_wait_has_its_own_bound_and_completed_replay_spends_none() {
    let table = Arc::new(Scripted {
        framed: true,
        ..Default::default()
    });
    let p = timed(&table, 700);
    let stream = establish(&p, 0, 0).value;
    let mut head = head_piece();
    head.timeout_ms = 0;
    assert!(ready(&request(&p, 1, stream, &head, HEAD_BYTES)));
    assert!(ready(&request(
        &p,
        2,
        stream,
        &kind_piece(REQUEST_END),
        b""
    )));
    let mut buf = [0; 8];
    assert_eq!(
        read_reply(&p, 3, stream, &mut buf).0.outcome,
        RawOutcome::of(Outcome::Pending)
    );
    let key = head_of::<ReplyIn>(service::READ_REPLY, 3).handle;
    let original = state(&p).waits.lock().unwrap().get(&key).unwrap().at;
    assert_eq!(
        read_reply(&p, 3, stream, &mut buf).0.outcome,
        RawOutcome::of(Outcome::Pending)
    );
    assert_eq!(
        state(&p).waits.lock().unwrap().get(&key).unwrap().at,
        original
    );
    table
        .script
        .lock()
        .unwrap()
        .push_back((piece(PieceKind::Fields, Some(200), None, 0), Vec::new()));
    let (out, reply) = read_reply(&p, 3, stream, &mut buf);
    assert!(ready(&out));
    assert_eq!(reply.kind, REPLY_HEAD);
    assert!(state(&p).waits.lock().unwrap().is_empty());
    assert_eq!(read_reply(&p, 3, stream, &mut buf).1.kind, REPLY_HEAD);
    assert!(state(&p).waits.lock().unwrap().is_empty());
    assert_eq!(
        read_reply(&p, 4, stream, &mut buf).0.outcome,
        RawOutcome::of(Outcome::Pending)
    );
    expire(&p, service::READ_REPLY, 4);
    let (out, _) = read_reply(&p, 4, stream, &mut buf);
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Failed));
    assert_eq!(error_text(&out), ConnError::Timeout.text());
    assert!(state(&p).streams().get(&stream).unwrap().ended);
}

#[test]
fn forgetting_a_ticket_or_closing_a_stream_retires_pending_wait_clocks() {
    let table = Arc::new(Scripted::default());
    let p = timed(&table, 700);
    let stream = establish(&p, 0, 0).value;
    let mut buf = [0; 8];
    assert_eq!(
        raw_read(&p, 1, stream, &mut buf).outcome,
        RawOutcome::of(Outcome::Pending)
    );
    expire(&p, service::READ, 1);
    drop(super::super::forget(p.inner.instance, T));
    assert!(state(&p).waits.lock().unwrap().is_empty());
    assert_eq!(
        raw_read(&p, 1, stream, &mut buf).outcome,
        RawOutcome::of(Outcome::Pending),
        "a reused completion identity starts its new wait after retirement"
    );
    super::super::forget_worker(
        &[p.inner.instance],
        crate::dispatch::ticket::decode(T.slot).0,
    );
    assert!(state(&p).waits.lock().unwrap().is_empty());
    assert_eq!(
        raw_read(&p, 2, stream, &mut buf).outcome,
        RawOutcome::of(Outcome::Pending)
    );
    let closed = call(
        &p,
        CONN_SLOTS.close,
        &StreamIn {
            head: head_of::<StreamIn>(service::CLOSE, 3),
            stream,
        },
    );
    assert!(ready(&closed));
    assert!(state(&p).waits.lock().unwrap().is_empty());
}

#[derive(Default)]
struct Wakes {
    notified: tokio::sync::Notify,
    count: std::sync::atomic::AtomicUsize,
}

impl crate::dispatch::ticket::WakeRoute for Wakes {
    fn wake(
        &self,
        ticket: Ticket,
        supplier: Option<&'static crate::dispatch::ticket::InstanceWake>,
    ) {
        assert_eq!(ticket, T);
        let supplier = supplier.unwrap();
        assert!(supplier.conn_state.streams.try_lock().is_ok());
        assert!(supplier.conn_state.waits.try_lock().is_ok());
        self.count.fetch_add(1, AtomicOrdering::SeqCst);
        self.notified.notify_one();
    }
}

#[test]
fn a_pending_reply_timer_retains_its_wake_and_close_cancels_the_next_one() {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let table = Arc::new(Scripted::default());
            let p = timed(&table, 30);
            let wakes = Arc::new(Wakes::default());
            let route: Arc<dyn crate::dispatch::ticket::WakeRoute> = wakes.clone();
            let wake = crate::dispatch::handle::resolve(p.inner.ctx()).unwrap();
            assert!(wake.route.set(Arc::downgrade(&route)).is_ok());
            let stream = establish(&p, 0, 0).value;
            let mut buf = [0; 8];
            assert_eq!(
                raw_read(&p, 1, stream, &mut buf).outcome,
                RawOutcome::of(Outcome::Pending)
            );
            tokio::time::timeout(Duration::from_secs(2), wakes.notified.notified())
                .await
                .unwrap();
            assert_eq!(
                error_text(&raw_read(&p, 1, stream, &mut buf)),
                ConnError::Timeout.text()
            );
            assert_eq!(
                raw_read(&p, 2, stream, &mut buf).outcome,
                RawOutcome::of(Outcome::Pending)
            );
            let closed = call(
                &p,
                CONN_SLOTS.close,
                &StreamIn {
                    head: head_of::<StreamIn>(service::CLOSE, 3),
                    stream,
                },
            );
            assert!(ready(&closed));
            let count = wakes.count.load(AtomicOrdering::SeqCst);
            tokio::time::sleep(Duration::from_millis(60)).await;
            assert_eq!(
                wakes.count.load(AtomicOrdering::SeqCst),
                count,
                "a retired wait must leave no timer wake"
            );
        });
}
