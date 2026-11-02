// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::plane_driver::{CallerEnd, SessionCaller, SessionInput};

struct Owner {
    id: u32,
    dropped: Arc<Mutex<Vec<u32>>>,
    released: Option<Arc<tokio::sync::Notify>>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.dropped.lock().unwrap().push(self.id);
        if let Some(released) = &self.released {
            released.notify_one();
        }
    }
}

fn input(id: u32, dropped: &Arc<Mutex<Vec<u32>>>) -> SessionInput {
    SessionInput {
        bytes: format!("piece:{id}").into_bytes(),
        custody: Some(Arc::new(Owner {
            id,
            dropped: dropped.clone(),
            released: None,
        })),
    }
}

struct OwnedCaller(tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<SessionInput>>);

impl CallerEnd for OwnedCaller {
    fn head(&self, _: u32, _: Vec<(Vec<u8>, Vec<u8>)>) {}

    async fn write(&self, _: &[u8]) -> bool {
        true
    }
}

impl SessionCaller for OwnedCaller {
    async fn read(&self) -> Option<Vec<u8>> {
        panic!("the session must use the owned read seam")
    }

    async fn read_owned(&self) -> Option<SessionInput> {
        self.0.lock().await.recv().await
    }
}

struct CreditCaller {
    inner: OwnedCaller,
    released: Arc<tokio::sync::Notify>,
    wrote: AtomicBool,
}

impl CallerEnd for CreditCaller {
    fn head(&self, _: u32, _: Vec<(Vec<u8>, Vec<u8>)>) {}

    async fn write(&self, _: &[u8]) -> bool {
        self.released.notified().await;
        self.wrote.store(true, Ordering::SeqCst);
        true
    }
}

impl SessionCaller for CreditCaller {
    async fn read(&self) -> Option<Vec<u8>> {
        self.inner.read().await
    }

    async fn read_owned(&self) -> Option<SessionInput> {
        self.inner.read_owned().await
    }
}

async fn drive<C: SessionCaller>(
    units: &busbar_kernel::plane_driver::PlaneUnits<'_, common::TestUnits, cases::Far, C>,
) -> busbar_contract::caps::Outcome {
    use busbar_kernel::teller::{run_unit_async, AccrualMeter, Ended, Kernel, Run};
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        busbar_kernel::slice::ConcurrencyGauge::new(),
        busbar_kernel::canary::Canary::new(),
        busbar_kernel::slice::LeaseCell::new(),
        AccrualMeter::new(),
    );
    let cell = common::cell(&kernel);
    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
        taps: None,
    };
    match run_unit_async(&kernel, units, &common::ctx(7), run, units).await {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    }
}

async fn poll_pending(future: &mut Pin<Box<impl Future>>) {
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

fn borrowed(plane: &Double) -> (usize, Vec<u8>) {
    let held = plane.sessions.borrowed.lock().unwrap();
    let (input, _lent) = held
        .as_ref()
        .expect("the crossing retained its host buffers");
    // SAFETY: the real pump lent this allocation to the retained crossing above.
    (
        input.0.bytes.ptr as usize,
        unsafe { bytes(input.0.bytes) }.to_vec(),
    )
}

fn release_borrowed(plane: &Double) {
    let held = plane.sessions.borrowed.lock().unwrap().take();

    drop(held);
}

#[tokio::test]
async fn the_owned_read_default_preserves_existing_callers() {
    let caller = OnceCaller::new(b"old caller");
    let piece = caller
        .read_owned()
        .await
        .expect("the existing read's piece");
    assert_eq!(piece.bytes, b"old caller");
    assert!(piece.custody.is_none());
}

#[tokio::test]
async fn cancelling_an_unresolved_owned_read_loses_no_piece() {
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let dropped = Arc::new(Mutex::new(Vec::new()));
    let mut reading = Box::pin(caller.read_owned());
    poll_pending(&mut reading).await;
    drop(reading);
    assert!(send.send(input(1, &dropped)).is_ok());
    let piece = caller
        .read_owned()
        .await
        .expect("the next reader owns the piece");
    assert_eq!(piece.bytes, b"piece:1");
    assert!(dropped.lock().unwrap().is_empty());
    drop(piece);
    assert_eq!(*dropped.lock().unwrap(), vec![1]);
}

#[tokio::test]
async fn a_session_retires_consumed_input_before_waiting_for_another_piece() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let dropped = Arc::new(Mutex::new(Vec::new()));
    let (steps, far) = (common::TestUnits::passing(), cases::Far::new(&[], &[]));
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let mut running = Box::pin(drive(&units));

    poll_pending(&mut running).await;
    let first = input(1, &dropped);
    let first_at = first.bytes.as_ptr() as usize;
    assert!(send.send(first).is_ok());
    poll_pending(&mut running).await;
    assert_eq!(
        *dropped.lock().unwrap(),
        vec![1],
        "the consumed allocation retires while the next caller read is pending"
    );
    assert_eq!(*r.plane.sessions.read_at.lock().unwrap(), vec![first_at]);

    let second = input(2, &dropped);
    let second_at = second.bytes.as_ptr() as usize;
    assert!(send.send(second).is_ok());
    poll_pending(&mut running).await;
    assert_eq!(
        *dropped.lock().unwrap(),
        vec![1, 2],
        "each consumed allocation retires exactly once, without another input or EOF"
    );
    assert_eq!(
        *r.plane.sessions.read_at.lock().unwrap(),
        vec![first_at, second_at]
    );
    assert_eq!(
        *r.plane.sessions.read.lock().unwrap(),
        vec![(7, b"piece:1".to_vec()), (7, b"piece:2".to_vec())],
    );

    drop(send);
    assert_eq!(running.await, busbar_contract::caps::Outcome::Completed);
    assert_eq!(*dropped.lock().unwrap(), vec![1, 2]);
}

#[tokio::test]
async fn an_admitted_session_opens_once_before_its_first_caller_piece() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let (steps, far) = (common::TestUnits::passing(), cases::Far::new(&[], &[]));
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let mut running = Box::pin(drive(&units));
    poll_pending(&mut running).await;
    assert_eq!(r.plane.sessions.initials.load(Ordering::SeqCst), 1);
    assert!(r.plane.sessions.read.lock().unwrap().is_empty());
    assert_eq!(*r.plane.sessions.open.lock().unwrap(), vec![7]);

    let dropped = Arc::new(Mutex::new(Vec::new()));
    assert!(send.send(input(1, &dropped)).is_ok());
    poll_pending(&mut running).await;
    assert_eq!(r.plane.sessions.initials.load(Ordering::SeqCst), 1);
    assert_eq!(
        *r.plane.sessions.read.lock().unwrap(),
        vec![(7, b"piece:1".to_vec())]
    );
    drop(send);
    assert_eq!(running.await, busbar_contract::caps::Outcome::Completed);
    assert!(r.plane.sessions.open.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_session_dials_an_empty_open_and_relays_server_output_before_caller_input() {
    struct Caller {
        inner: OwnedCaller,
        heard: Mutex<Vec<u8>>,
    }
    impl CallerEnd for Caller {
        fn head(&self, _: u32, _: Vec<(Vec<u8>, Vec<u8>)>) {}
        async fn write(&self, bytes: &[u8]) -> bool {
            self.heard.lock().unwrap().extend_from_slice(bytes);
            true
        }
    }
    impl SessionCaller for Caller {
        async fn read(&self) -> Option<Vec<u8>> {
            self.inner.read().await
        }
        async fn read_owned(&self) -> Option<SessionInput> {
            self.inner.read_owned().await
        }
    }
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    r.plane.sessions.server_first.store(true, Ordering::SeqCst);
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = Caller {
        inner: OwnedCaller(tokio::sync::Mutex::new(receive)),
        heard: Mutex::new(Vec::new()),
    };
    let (steps, far) = (
        common::TestUnits::passing(),
        cases::Far::held(&["fixture-lane"]),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let mut running = Box::pin(drive(&units));
    for _ in 0..16 {
        poll_pending(&mut running).await;
        if caller.heard.lock().unwrap().starts_with(cases::GREETING) {
            break;
        }
    }
    let sent = far.sent();
    assert_eq!(sent.len(), 1, "one dial before any caller piece");
    assert_eq!(sent[0].verb, b"GET");
    assert_eq!(sent[0].target, b"/open");
    assert!(sent[0].body.is_empty());
    assert!(caller.heard.lock().unwrap().starts_with(cases::GREETING));
    assert!(r.plane.sessions.read.lock().unwrap().is_empty());

    let dropped = Arc::new(Mutex::new(Vec::new()));
    assert!(send.send(input(1, &dropped)).is_ok());
    for _ in 0..16 {
        poll_pending(&mut running).await;
        if !far.written().is_empty() {
            break;
        }
    }
    assert_eq!(far.sent().len(), 1, "later input uses the held connection");
    assert_eq!(far.written(), vec![(b"piece:1".to_vec(), true)]);
    assert_eq!(r.plane.sessions.initials.load(Ordering::SeqCst), 1);
    drop(send);
    assert_eq!(running.await, busbar_contract::caps::Outcome::Completed);
}

#[tokio::test]
async fn a_session_retires_consumed_input_before_waiting_for_output_credit() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let released = Arc::new(tokio::sync::Notify::new());
    let caller = CreditCaller {
        inner: OwnedCaller(tokio::sync::Mutex::new(receive)),
        released: released.clone(),
        wrote: AtomicBool::new(false),
    };
    let dropped = Arc::new(Mutex::new(Vec::new()));
    let piece = SessionInput {
        bytes: b"credit".to_vec(),
        custody: Some(Arc::new(Owner {
            id: 1,
            dropped: dropped.clone(),
            released: Some(released),
        })),
    };
    let at = piece.bytes.as_ptr() as usize;
    assert!(send.send(piece).is_ok());
    let (steps, far) = (common::TestUnits::passing(), cases::Far::new(&[], &[]));
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let mut running = Box::pin(drive(&units));
    poll_pending(&mut running).await;
    assert_eq!(*dropped.lock().unwrap(), vec![1]);
    assert!(
        caller.wrote.load(Ordering::SeqCst),
        "input retirement must return the credit needed to complete this output"
    );
    assert_eq!(*r.plane.sessions.read_at.lock().unwrap(), vec![at]);
    assert_eq!(
        *r.plane.sessions.read.lock().unwrap(),
        vec![(7, b"credit".to_vec())]
    );
    drop(send);
    assert_eq!(running.await, busbar_contract::caps::Outcome::Completed);
    assert_eq!(*dropped.lock().unwrap(), vec![1]);
}

#[tokio::test]
async fn a_resumed_session_retires_input_after_its_ready_crossing() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    *r.plane.sessions.input_mode.lock().unwrap() = SessionInputMode::Pending;
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let dropped = Arc::new(Mutex::new(Vec::new()));
    let piece = input(1, &dropped);
    let at = piece.bytes.as_ptr() as usize;
    assert!(send.send(piece).is_ok());
    let (steps, far) = (common::TestUnits::passing(), cases::Far::new(&[], &[]));
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let mut running = Box::pin(drive(&units));
    poll_pending(&mut running).await;
    assert!(dropped.lock().unwrap().is_empty());
    assert_eq!(borrowed(&r.plane), (at, b"piece:1".to_vec()));

    release_borrowed(&r.plane);
    assert!(r.plane.release_controlled(true));
    poll_pending(&mut running).await;
    assert_eq!(*dropped.lock().unwrap(), vec![1]);
    drop(send);
    assert_eq!(running.await, busbar_contract::caps::Outcome::Completed);
    assert_eq!(*dropped.lock().unwrap(), vec![1]);
}

#[tokio::test]
async fn cancelling_a_pending_session_keeps_input_custody_for_its_crossing() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    *r.plane.sessions.input_mode.lock().unwrap() = SessionInputMode::Pending;
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let dropped = Arc::new(Mutex::new(Vec::new()));
    let piece = input(1, &dropped);
    let at = piece.bytes.as_ptr() as usize;
    assert!(send.send(piece).is_ok());
    let (steps, far) = (common::TestUnits::passing(), cases::Far::new(&[], &[]));
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let mut running = Box::pin(drive(&units));
    poll_pending(&mut running).await;
    assert!(
        r.plane
            .controlled
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .0
             .0
            .lock()
            .unwrap()
            .polled_pending
    );
    assert!(dropped.lock().unwrap().is_empty());
    assert_eq!(borrowed(&r.plane), (at, b"piece:1".to_vec()));

    drop(running);
    assert!(
        dropped.lock().unwrap().is_empty(),
        "the abandoned crossing still borrows input"
    );
    assert_eq!(borrowed(&r.plane), (at, b"piece:1".to_vec()));
    assert!(r.plane.release_controlled(true));
    r.driver.sweep();
    assert!(
        dropped.lock().unwrap().is_empty(),
        "the crossing has not returned its buffers"
    );
    release_borrowed(&r.plane);
    assert_eq!(*dropped.lock().unwrap(), vec![1]);
}

#[tokio::test]
async fn a_faulted_session_keeps_input_custody_after_the_near_side_returns() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    *r.plane.sessions.input_mode.lock().unwrap() = SessionInputMode::Fault;
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let dropped = Arc::new(Mutex::new(Vec::new()));
    let piece = input(1, &dropped);
    let at = piece.bytes.as_ptr() as usize;
    assert!(send.send(piece).is_ok());
    let (steps, far) = (common::TestUnits::passing(), cases::Far::new(&[], &[]));
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let outcome = drive(&units).await;
    assert!(matches!(
        outcome,
        busbar_contract::caps::Outcome::Failed(_, busbar_contract::caps::ReasonCode::PlanePanic)
    ));
    assert!(
        dropped.lock().unwrap().is_empty(),
        "the finished pump's buffers remain lent"
    );
    assert_eq!(borrowed(&r.plane), (at, b"piece:1".to_vec()));
    release_borrowed(&r.plane);
    assert_eq!(*dropped.lock().unwrap(), vec![1]);
}

#[tokio::test]
async fn a_session_cancels_its_idle_near_far_and_two_pending_legs_once() {
    for (near_pending, far_pending, caller_drop) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, false),
        (true, true, true),
    ] {
        let mut r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
        let rows = Arc::new(AuditRows::default());
        r.driver = r.driver.with_audit(rows.clone());
        r.plane.sessions.cancel_row.store(true, Ordering::SeqCst);
        r.plane
            .sessions
            .far_pending
            .store(far_pending, Ordering::SeqCst);
        r.plane
            .sessions
            .server_first
            .store(far_pending, Ordering::SeqCst);
        if near_pending {
            *r.plane.sessions.input_mode.lock().unwrap() = SessionInputMode::Cancellable;
        }
        let (send, receive) = tokio::sync::mpsc::unbounded_channel();
        let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
        let dropped = Arc::new(Mutex::new(Vec::new()));
        let (steps, far) = (
            common::TestUnits::passing(),
            cases::Far::held(&["fixture-lane"]),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
        let mut running = Box::pin(drive(&units));
        poll_pending(&mut running).await;
        if near_pending {
            assert!(send.send(input(1, &dropped)).is_ok());
        }
        let expected = usize::from(near_pending) + usize::from(far_pending);
        for _ in 0..32 {
            poll_pending(&mut running).await;
            if r.plane.held.lock().unwrap().len() == expected {
                break;
            }
        }
        assert_eq!(r.plane.held.lock().unwrap().len(), expected);
        assert!(dropped.lock().unwrap().is_empty());
        if caller_drop {
            drop(running);
            drop(units);
            for _ in 0..4 {
                r.driver.sweep();
            }
        } else {
            r.driver.reload();
            assert!(matches!(
                running.await,
                busbar_contract::caps::Outcome::Failed(_, busbar_contract::caps::ReasonCode::Drain)
            ));
        }
        assert_eq!(
            r.stats()[stat::CANCELS],
            1,
            "near={near_pending}, far={far_pending}, drop={caller_drop}"
        );
        assert_eq!(r.plane.closes.lock().unwrap().get(&7), Some(&1));
        assert!(r.plane.held.lock().unwrap().is_empty());
        assert!(r.plane.held_lent.lock().unwrap().is_empty());
        assert_eq!(r.book.bills().len(), 1);
        assert_eq!(rows.0.lock().unwrap().len(), 1);
        assert_eq!(rows.0.lock().unwrap()[0].0, "session.cancel");
        assert_eq!(
            *dropped.lock().unwrap(),
            if near_pending { vec![1] } else { vec![] }
        );
        r.driver.sweep();
        assert_eq!(r.stats()[stat::CANCELS], 1);
        assert_eq!(rows.0.lock().unwrap().len(), 1);
        assert_eq!(r.book.bills().len(), 1);
    }
}

#[tokio::test]
async fn a_dropped_session_retains_the_queued_cancel_reply_until_sweep() {
    let mut r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let rows = Arc::new(AuditRows::default());
    r.driver = r.driver.with_audit(rows.clone());
    r.plane.sessions.cancel_row.store(true, Ordering::SeqCst);
    r.plane
        .sessions
        .delay_cancel_reply
        .store(true, Ordering::SeqCst);
    let (_send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let (steps, far) = (common::TestUnits::passing(), cases::Far::new(&[], &[]));
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let mut running = Box::pin(drive(&units));
    poll_pending(&mut running).await;
    r.driver.reload();
    poll_pending(&mut running).await;
    assert_eq!(r.stats()[stat::CANCELS], 1, "control submission is eager");
    assert!(r.book.bills().is_empty());
    drop(running);
    drop(units);
    r.driver.sweep();
    assert!(
        r.book.bills().is_empty(),
        "an idle sibling cannot bill before the result owner"
    );
    assert!(rows.0.lock().unwrap().is_empty());
    r.plane.sessions.cancel_reply.notify_one();
    for _ in 0..4 {
        r.driver.sweep();
    }
    assert_eq!(r.driver.buried(), 0);
    assert_eq!(r.book.bills().len(), 1);
    assert_eq!(rows.0.lock().unwrap().len(), 1);
    assert_eq!(r.stats()[stat::CANCELS], 1);
}

#[tokio::test(start_paused = true)]
async fn an_idle_session_deadline_cancels_the_logical_unit_once() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let (_send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let (steps, far) = (common::TestUnits::passing(), cases::Far::new(&[], &[]));
    let deadline = now_ns().saturating_add(60_000_000_000);
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/session", b""),
        deadline,
    );
    let mut running = Box::pin(drive(&units));
    poll_pending(&mut running).await;
    tokio::time::advance(Duration::from_secs(61)).await;
    assert!(matches!(
        running.await,
        busbar_contract::caps::Outcome::Failed(
            _,
            busbar_contract::caps::ReasonCode::DeadlineExceeded
        )
    ));
    assert_eq!(r.stats()[stat::CANCELS], 1);
    assert_eq!(r.plane.closes.lock().unwrap().get(&7), Some(&1));
    assert_eq!(r.book.bills().len(), 1);
}

#[tokio::test]
async fn normal_session_completion_wins_over_its_pending_siblings_retirement() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    r.plane.sessions.server_first.store(true, Ordering::SeqCst);
    r.plane.sessions.far_pending.store(true, Ordering::SeqCst);
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let (steps, far) = (
        common::TestUnits::passing(),
        cases::Far::held(&["fixture-lane"]),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let mut running = Box::pin(drive(&units));
    for _ in 0..32 {
        poll_pending(&mut running).await;
        if !r.plane.held.lock().unwrap().is_empty() {
            break;
        }
    }
    assert_eq!(r.plane.held.lock().unwrap().len(), 1);
    drop(send);
    poll_pending(&mut running).await;
    assert!(
        r.plane.sessions.open.lock().unwrap().is_empty(),
        "caller EOF completed the logical unit"
    );

    let (ticket, (slot, out)) = {
        let mut held = r.plane.held.lock().unwrap();
        let ticket = *held.keys().next().unwrap();
        (ticket, held.remove(&ticket).unwrap())
    };
    slot.put(ready(Outcome::Failed), out);
    let lent = r.plane.held_lent.lock().unwrap().remove(&ticket);
    drop(lent);
    assert_eq!(running.await, busbar_contract::caps::Outcome::Completed);
    assert_eq!(r.stats()[stat::CANCELS], 0);
    assert!(r.book.bills().is_empty());
}
