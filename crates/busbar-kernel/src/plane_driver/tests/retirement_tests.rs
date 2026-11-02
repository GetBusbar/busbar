// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Callbacks observe the real far-end mutex while its pinned owner is still live.

use super::*;
use std::sync::atomic::AtomicPtr;

#[derive(Default)]
struct Probe {
    state: AtomicPtr<Mutex<State>>,
    seen: Mutex<Vec<(&'static str, bool)>>,
}

impl Probe {
    fn check(&self, effect: &'static str) {
        let state = self.state.load(Ordering::Acquire);
        assert!(
            !state.is_null(),
            "the pinned far end owns the checked mutex"
        );
        // SAFETY: each test installs this pointer only after pinning its owned EgressFarEnd,
        // invokes effects only through shared borrows while that owner is live, and clears
        // it immediately after the owner drops. No released or spare allocation is read.
        let available = unsafe { &*state }.try_lock().is_ok();
        self.seen.lock().unwrap().push((effect, available));
    }

    fn callback(self: &Arc<Self>, effect: &'static str) -> Arc<dyn Fn() + Send + Sync> {
        let probe = self.clone();
        Arc::new(move || probe.check(effect))
    }

    fn assert_effects(&self, expected: &[&'static str]) {
        let seen = self.seen.lock().unwrap();
        assert!(seen.iter().all(|(_, available)| *available), "{seen:?}");
        for expected in expected {
            assert_eq!(
                seen.iter().filter(|(effect, _)| effect == expected).count(),
                1,
                "{seen:?}"
            );
        }
    }
}

struct WatchingJournal(Arc<Probe>);

impl Journal for WatchingJournal {
    fn dispatched(&self, _: &Dispatched) -> Result<(), DurabilityUnavailable> {
        Ok(())
    }

    fn abandoned(&self, _: &Dispatched) {
        self.0.check("journal");
    }
}

struct WatchingCapacity(Arc<Probe>);

struct WatchingPermit {
    destination: DestinationId,
    callback: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for WatchingPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchingPermit")
            .field("destination", &self.destination)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for WatchingCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WatchingCapacity")
    }
}

impl PermitHandle for WatchingPermit {
    fn destination(&self) -> DestinationId {
        self.destination
    }
}

impl Drop for WatchingPermit {
    fn drop(&mut self) {
        (self.callback)();
    }
}

impl Capacity for WatchingCapacity {
    fn try_acquire(&self, destination: DestinationId) -> Option<Permit> {
        Some(Permit::new(Box::new(WatchingPermit {
            destination,
            callback: self.0.callback("permit"),
        })))
    }

    fn acquire_any<'a>(
        &'a self,
        _: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>> {
        Box::pin(std::future::ready(None))
    }
}

fn watching(script: Script) -> (Rig, Arc<Probe>) {
    let mut r = rig(&[("a.test", script)], OnExhausted::Status503, None);
    let probe = Arc::new(Probe::default());
    r.egress.capacity = Arc::new(WatchingCapacity(probe.clone()));
    r.egress.journal = Arc::new(WatchingJournal(probe.clone()));
    *r.table.on_close.lock().unwrap() = Some(probe.callback("close"));
    *r.book.on_refund.lock().unwrap() = Some(probe.callback("refund"));
    (r, probe)
}

#[tokio::test]
async fn settling_an_unanswered_attempt_retires_outside_the_state_mutex() {
    let (r, probe) = watching(Script::Silent);
    let far = Box::pin(r.egress.unit(route()));
    probe.state.store(
        (&far.state as *const Mutex<State>).cast_mut(),
        Ordering::Release,
    );
    let t = token();
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    far.settle();
    probe.assert_effects(&["close", "journal", "permit"]);
    probe.state.store(std::ptr::null_mut(), Ordering::Release);
    drop(far);
}

#[tokio::test]
async fn settling_a_buffered_success_refunds_outside_the_state_mutex() {
    let (r, probe) = watching(Script::Answer(200, None, vec![b"body"]));
    let far = Box::pin(r.egress.unit(route()));
    probe.state.store(
        (&far.state as *const Mutex<State>).cast_mut(),
        Ordering::Release,
    );
    let t = token();
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let head = far.next(&t).await.expect("the success head");
    assert!(!head.last);
    far.settle();
    probe.assert_effects(&["close", "refund", "permit"]);
    assert_eq!(r.book.refunded.load(Ordering::SeqCst), 1);
    probe.state.store(std::ptr::null_mut(), Ordering::Release);
    drop(far);
}

#[tokio::test]
async fn a_complete_attempt_retires_outside_the_state_mutex() {
    let (r, probe) = watching(Script::Answer(200, None, vec![b"body"]));
    let far = Box::pin(r.egress.unit(route()));
    probe.state.store(
        (&far.state as *const Mutex<State>).cast_mut(),
        Ordering::Release,
    );
    let t = token();
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    assert!(pieces.last().is_some_and(|piece| piece.last));
    probe.assert_effects(&["close", "permit"]);
    assert_eq!(r.book.refunded.load(Ordering::SeqCst), 0);
    probe.state.store(std::ptr::null_mut(), Ordering::Release);
    drop(far);
    probe.assert_effects(&["close", "permit"]);
}

#[tokio::test]
async fn a_cut_buffered_answer_refunds_and_closes_outside_the_state_mutex() {
    let (r, probe) = watching(Script::Broken(200, vec![b"body"]));
    let far = Box::pin(r.egress.unit(route()));
    probe.state.store(
        (&far.state as *const Mutex<State>).cast_mut(),
        Ordering::Release,
    );
    let t = token();
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    assert!(pieces.last().is_some_and(|piece| piece.last && piece.cut));
    probe.assert_effects(&["close", "refund", "permit"]);
    probe.state.store(std::ptr::null_mut(), Ordering::Release);
    drop(far);
}

#[tokio::test]
async fn an_open_error_abandons_its_dispatch_outside_the_state_mutex() {
    let (r, probe) = watching(Script::Refused);
    let far = Box::pin(r.egress.unit(route()));
    probe.state.store(
        (&far.state as *const Mutex<State>).cast_mut(),
        Ordering::Release,
    );
    let t = token();
    let _ = far.member(&t, 1).await;
    assert!(!far.send(&t, request()).await);
    probe.assert_effects(&["journal", "permit"]);
    assert_eq!(r.table.closed.load(Ordering::SeqCst), 0);
    probe.state.store(std::ptr::null_mut(), Ordering::Release);
    drop(far);
}

#[tokio::test]
async fn an_unwinding_close_still_drops_the_detached_permit_outside_the_mutex() {
    let (r, probe) = watching(Script::Silent);
    let far = Box::pin(r.egress.unit(route()));
    probe.state.store(
        (&far.state as *const Mutex<State>).cast_mut(),
        Ordering::Release,
    );
    let t = token();
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let on_close = probe.clone();
    *r.table.on_close.lock().unwrap() = Some(Arc::new(move || {
        on_close.check("close");
        panic!("the scripted connector close unwound");
    }));
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| far.settle()));
    assert!(unwound.is_err());
    probe.assert_effects(&["close", "permit"]);
    assert!(
        far.state.try_lock().is_ok(),
        "the state mutex is not poisoned"
    );
    probe.state.store(std::ptr::null_mut(), Ordering::Release);
    drop(far);
}
