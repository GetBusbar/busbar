// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Caller allocation custody through the real session pump and its contract-level crossings.

use super::*;
use busbar_kernel::plane_driver::{CallerEnd, SessionCaller, SessionInput};

struct Owner {
    id: u32,
    dropped: Arc<Mutex<Vec<u32>>>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.dropped.lock().unwrap().push(self.id);
    }
}

fn input(id: u32, dropped: &Arc<Mutex<Vec<u32>>>) -> SessionInput {
    SessionInput {
        bytes: format!("piece:{id}").into_bytes(),
        custody: Some(Arc::new(Owner {
            id,
            dropped: dropped.clone(),
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

/// The retained crossing's `Lent` keeps the allocation alive while these initialized bytes are
/// read. Nothing is read after releasing that ownership, and no spare or freed bytes are read.
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
    // Drop the crossing's ownership outside the fixture lock.
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
async fn a_session_keeps_consumed_input_custody_until_replacement_or_completion() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let dropped = Arc::new(Mutex::new(Vec::new()));
    let (steps, far) = (common::TestUnits::passing(), cases::Far::new(&[], &[]));
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let mut running = Box::pin(drive(&units));

    // The pending caller read resolves to the first piece when it is delivered.
    poll_pending(&mut running).await;
    let first = input(1, &dropped);
    let first_at = first.bytes.as_ptr() as usize;
    assert!(send.send(first).is_ok());
    poll_pending(&mut running).await;
    assert!(
        dropped.lock().unwrap().is_empty(),
        "consumption kept the allocation"
    );
    assert_eq!(*r.plane.sessions.read_at.lock().unwrap(), vec![first_at]);

    let second = input(2, &dropped);
    let second_at = second.bytes.as_ptr() as usize;
    assert!(send.send(second).is_ok());
    poll_pending(&mut running).await;
    assert_eq!(
        *dropped.lock().unwrap(),
        vec![1],
        "replacement retires only the old owner"
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
