// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::host::conn::connector::{FactsIn, StreamFacts, StreamIn};

fn secured() -> Arc<Scripted> {
    Arc::new(Scripted {
        framed: true,
        facts: Mutex::new(Some(ConnFacts {
            peer_cert: Some(busbar_contract::transport::wire::CertFacts {
                subject: String::new(),
                issuer: String::new(),
                fingerprint: "cd".repeat(32),
            }),
            ..ConnFacts::default()
        })),
        ..Scripted::default()
    })
}

fn facts(p: &Plugin<TestKind>, seq: u32, stream: u64) -> (ServiceOut, u32) {
    // SAFETY: the facts service receives a writable, zero-initialized plain ABI record.
    let mut observed: StreamFacts = unsafe { std::mem::zeroed() };
    let input = FactsIn {
        head: head_of::<FactsIn>(service::FACTS, seq),
        stream,
        facts: &mut observed,
    };
    (call(p, CONN_SLOTS.facts, &input), observed.secure)
}

fn close(p: &Plugin<TestKind>, stream: u64) -> ServiceOut {
    let mut head = head_of::<StreamIn>(service::CLOSE, 0);
    head.handle.ticket = Ticket::NONE;
    call(p, CONN_SLOTS.close, &StreamIn { head, stream })
}

#[test]
fn prepared_request_facts_before_and_after_head_preserve_buffered_request_and_connection() {
    for after_head in [false, true] {
        let table = secured();
        *table.facts_pends.lock().unwrap() = 2;
        let p = bound_over(&table);
        let stream = opened_stream(&p, 0).value;
        if after_head {
            assert!(ready(&request(&p, 1, stream, &head_piece(), HEAD_BYTES)));
            assert!(ready(&request(
                &p,
                2,
                stream,
                &kind_piece(REQUEST_BODY),
                b"credential-CANARY"
            )));
        }
        for _ in 0..2 {
            assert_eq!(
                facts(&p, 3, stream).0.outcome,
                RawOutcome::of(Outcome::Pending)
            );
            assert_eq!(table.prepared.lock().unwrap().len(), 1);
            assert!(
                table.opened.lock().unwrap().is_empty(),
                "neither an empty request nor credentials may be sent while facts pend"
            );
            assert!(table.writes.lock().unwrap().is_empty());
        }
        let (answer, secure) = facts(&p, 3, stream);
        assert!(ready(&answer));
        assert_eq!(secure, 1);
        assert_eq!(
            facts(&p, 3, stream).1,
            1,
            "facts replay retains the actual answer"
        );
        if !after_head {
            assert!(ready(&request(&p, 4, stream, &head_piece(), HEAD_BYTES)));
            assert!(ready(&request(
                &p,
                5,
                stream,
                &kind_piece(REQUEST_BODY),
                b"credential-CANARY"
            )));
        }
        assert!(
            ready(&facts(&p, 6, stream).0),
            "facts remain callable with a buffered head and body"
        );
        assert!(table.opened.lock().unwrap().is_empty());
        assert!(ready(&request(
            &p,
            7,
            stream,
            &kind_piece(REQUEST_END),
            &[]
        )));
        assert!(
            ready(&request(&p, 7, stream, &kind_piece(REQUEST_END), &[])),
            "END replay commits once"
        );
        let prepared = table.prepared.lock().unwrap()[0].0;
        assert_eq!(*table.committed.lock().unwrap(), vec![prepared]);
        let opened = table.opened.lock().unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].2, b"PATCH");
        assert_eq!(opened[0].3, b"/v1/x");
        assert_eq!(opened[0].4, vec![("a".into(), b"1".to_vec())]);
        assert_eq!(opened[0].5, b"credential-CANARY");
        drop(opened);
        assert!(ready(&close(&p, stream)));
        assert_eq!(table.closed.lock().unwrap().len(), 1);
        assert_eq!(table.closed.lock().unwrap()[0].1, prepared);
    }
}

#[test]
fn prepared_request_missing_facts_and_cancellation_close_without_application_bytes() {
    for unavailable in [false, true] {
        let table = secured();
        if unavailable {
            *table.facts.lock().unwrap() = None;
        } else {
            *table.facts_pends.lock().unwrap() = 5;
        }
        let p = bound_over(&table);
        let stream = opened_stream(&p, 0).value;
        assert!(ready(&request(&p, 1, stream, &head_piece(), HEAD_BYTES)));
        assert!(ready(&request(
            &p,
            2,
            stream,
            &kind_piece(REQUEST_BODY),
            b"retained-CANARY"
        )));
        assert!(!ready(&facts(&p, 3, stream).0));
        if unavailable {
            assert_eq!(table.closed.lock().unwrap().len(), 1);
        }
        assert!(ready(&close(&p, stream)));
        assert_eq!(table.closed.lock().unwrap().len(), 1);
        assert!(table.opened.lock().unwrap().is_empty());
        assert!(table.writes.lock().unwrap().is_empty());
        assert!(!ready(&facts(&p, 4, stream).0));
        assert_eq!(
            table.prepared.lock().unwrap().len(),
            1,
            "a cancelled facts poll cannot redial"
        );
    }
}

#[test]
fn prepared_request_pending_commit_keeps_the_same_connection_and_sends_once() {
    let table = secured();
    *table.commit_pends.lock().unwrap() = 2;
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    assert!(ready(&facts(&p, 1, stream).0));
    assert!(ready(&request(&p, 2, stream, &head_piece(), HEAD_BYTES)));
    assert!(ready(&request(
        &p,
        3,
        stream,
        &kind_piece(REQUEST_BODY),
        b"CANARY"
    )));
    assert!(ready(&request(
        &p,
        4,
        stream,
        &kind_piece(REQUEST_END),
        &[]
    )));
    assert!(table.opened.lock().unwrap().is_empty());
    let mut bytes = [0; 64];
    assert_eq!(
        read_reply(&p, 5, stream, &mut bytes).0.outcome,
        RawOutcome::of(Outcome::Pending)
    );
    assert!(table.opened.lock().unwrap().is_empty());
    let _ = read_reply(&p, 5, stream, &mut bytes);
    assert_eq!(table.opened.lock().unwrap().len(), 1);
    assert_eq!(
        table.committed.lock().unwrap()[0],
        table.prepared.lock().unwrap()[0].0
    );
    assert!(ready(&close(&p, stream)));
    assert_eq!(table.closed.lock().unwrap().len(), 1);
}

#[test]
fn prepared_request_facts_deadline_is_not_restarted_by_pending_poll() {
    let table = secured();
    *table.facts_pends.lock().unwrap() = 5;
    let mut need = NAMED;
    need[0].timeout_ms = 1000;
    let p = bound_over_needs(
        table.clone(),
        Adopter::unwatched(),
        Box::leak(Box::new(need)),
    );
    let stream = opened_stream(&p, 0).value;
    assert_eq!(
        facts(&p, 1, stream).0.outcome,
        RawOutcome::of(Outcome::Pending)
    );
    let state = &crate::dispatch::handle::resolve(p.inner.ctx())
        .unwrap()
        .conn_state;
    let handle = head_of::<FactsIn>(service::FACTS, 1).handle;
    state.waits.lock().unwrap().get_mut(&handle).unwrap().at = std::time::Instant::now();
    let result = facts(&p, 1, stream).0;
    assert_eq!(result.outcome, RawOutcome::of(Outcome::Failed));
    assert!(error_text(&result).contains("deadline"));
    assert_eq!(table.prepared.lock().unwrap().len(), 1);
    assert_eq!(table.closed.lock().unwrap().len(), 1);
    assert!(table.opened.lock().unwrap().is_empty());
    assert!(ready(&close(&p, stream)));
    assert_eq!(table.closed.lock().unwrap().len(), 1);
}

#[test]
fn prepared_request_pending_member_auth_commits_on_the_prepared_connection() {
    let probe = Arc::new(LockProbe::default());
    let observed = secured().facts.lock().unwrap().clone();
    let table = Arc::new(Scripted {
        framed: true,
        auth: Some(probe.clone()),
        facts: Mutex::new(observed),
        ..Scripted::default()
    });
    table
        .script
        .lock()
        .unwrap()
        .push_back((piece(PieceKind::Fields, Some(200), None, 0), Vec::new()));
    let dispatcher = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let p = bound_over_by(&table, dispatcher.adopter());
    let stream = opened_stream(&p, 0).value;
    assert!(ready(&facts(&p, 1, stream).0));
    whole_request_on(&p, 2, stream);
    assert!(table.opened.lock().unwrap().is_empty());
    let mut bytes = [0; 64];
    let (result, got) = read_reply(&p, 4, stream, &mut bytes);
    assert!(ready(&result), "{}", error_text(&result));
    assert_eq!(got.kind, REPLY_HEAD);
    assert_eq!(
        table.committed.lock().unwrap()[0],
        table.prepared.lock().unwrap()[0].0
    );
    assert_eq!(table.opened.lock().unwrap().len(), 1);
    assert_eq!(probe.seen.calls.load(AtomicOrdering::SeqCst), 2);
    assert!(!probe.seen.under_lock.load(AtomicOrdering::SeqCst));
    assert!(ready(&close(&p, stream)));
    assert_eq!(table.closed.lock().unwrap().len(), 1);
}

#[test]
fn prepared_request_commit_cannot_relax_previously_confirmed_security() {
    let table = secured();
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    assert_eq!(facts(&p, 1, stream).1, 1);
    assert!(ready(&request(&p, 2, stream, &head_piece(), HEAD_BYTES)));
    assert!(ready(&request(
        &p,
        3,
        stream,
        &kind_piece(REQUEST_BODY),
        b"CANARY"
    )));
    *table.facts.lock().unwrap() = Some(ConnFacts::default());
    assert!(ready(&request(
        &p,
        4,
        stream,
        &kind_piece(REQUEST_END),
        &[]
    )));
    let mut bytes = [0; 16];
    let result = read_reply(&p, 5, stream, &mut bytes).0;
    assert_eq!(result.outcome, RawOutcome::of(Outcome::Refused));
    assert!(table.opened.lock().unwrap().is_empty());
    assert_eq!(table.closed.lock().unwrap().len(), 1);
    assert!(ready(&close(&p, stream)));
    assert_eq!(table.closed.lock().unwrap().len(), 1);
}
