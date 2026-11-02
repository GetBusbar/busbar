// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
        self.0.check("capacity");
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
async fn an_unwinding_close_still_retires_the_detached_resources_outside_the_mutex() {
    let (r, probe) = all_watching(Script::Silent);
    let far = Box::pin(r.egress.unit(route()));
    probe.state.store(
        (&far.state as *const Mutex<State>).cast_mut(),
        Ordering::Release,
    );
    let t = token();
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);

    {
        let mut state = far.lock();
        let live = state.live.as_mut().unwrap();
        live.probe = Some(7);
        live.spent = true;
    }
    let on_close = probe.clone();
    *r.table.on_close.lock().unwrap() = Some(Arc::new(move || {
        on_close.check("close");
        panic!("the scripted connector close unwound");
    }));
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| far.settle()));
    assert!(unwound.is_err());
    probe.assert_effects(&[
        "close",
        "release_probe",
        "refund_budget",
        "journal",
        "permit",
    ]);
    assert_eq!(r.book.refunded.load(Ordering::SeqCst), 1);
    assert!(
        far.state.try_lock().is_ok(),
        "the state mutex is not poisoned"
    );
    assert_eq!(far.lock().retiring, 0, "unwinding restores selection");
    probe.state.store(std::ptr::null_mut(), Ordering::Release);
    drop(far);
}

#[tokio::test]
async fn dropping_an_unanswered_far_end_retires_its_live_attempt_once() {
    let (r, probe) = watching(Script::Silent);
    let far = Box::pin(r.egress.unit(route()));
    probe.state.store(
        (&far.state as *const Mutex<State>).cast_mut(),
        Ordering::Release,
    );
    let t = token();
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);

    drop(far);
    probe.state.store(std::ptr::null_mut(), Ordering::Release);
    probe.assert_effects(&["close", "journal", "permit"]);
}

struct WatchingBreaker {
    inner: Arc<Book>,
    probe: Arc<Probe>,
}

impl Breaker for WatchingBreaker {
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable> {
        self.probe.check("admit");
        self.inner.try_admit(pool, destination, now)
    }
    fn unavailable(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> Option<Unavailable> {
        self.probe.check("unavailable");
        self.inner.unavailable(pool, destination, now, token)
    }

    fn ready(&self, pool: &str, destination: DestinationId, now: u64, token: &Pass<Route>) -> bool {
        self.probe.check("ready");
        self.inner.ready(pool, destination, now, token)
    }
    fn admissible(&self, destination: DestinationId) -> bool {
        self.probe.check("admissible");
        self.inner.admissible(destination)
    }
    fn cooldown_remaining(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> u64 {
        self.probe.check("cooldown");
        self.inner.cooldown_remaining(pool, destination, now, token)
    }
    fn classify(&self, destination: DestinationId, status: UpstreamStatus) -> Classified {
        self.probe.check("classify");
        self.inner.classify(destination, status)
    }
    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        now: u64,
        token: &Pass<Route>,
    ) -> bool {
        self.probe.check("observe");
        self.inner.observe(pool, destination, outcome, now, token)
    }
    fn suppressing(&self, destination: DestinationId, now: u64) -> bool {
        self.probe.check("suppressing");
        self.inner.suppressing(destination, now)
    }
    fn probed(&self, destination: DestinationId, outcome: Outcome, now: u64, token: &Pass<Route>) {
        self.probe.check("probed");
        self.inner.probed(destination, outcome, now, token);
    }
    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, now: u64) {
        self.probe.check("release_probe");
        self.inner.release_probe(pool, destination, epoch, now);
    }
    fn spend_budget(&self, destination: DestinationId) -> bool {
        self.probe.check("spend");
        self.inner.spend_budget(destination)
    }
    fn refund_budget(&self, destination: DestinationId) {
        self.probe.check("refund_budget");
        self.inner.refund_budget(destination);
    }
}

struct WatchingClock(Arc<Probe>);
impl WatchingClock {
    fn check(&self, effect: &'static str) {
        if !self.0.state.load(Ordering::Acquire).is_null() {
            self.0.check(effect);
        }
    }
}
impl Clock for WatchingClock {
    fn now_secs(&self) -> u64 {
        self.check("seconds");
        Wall.now_secs()
    }
    fn now_millis(&self) -> u128 {
        self.check("millis");
        Wall.now_millis()
    }
    fn now_micros(&self) -> u128 {
        self.check("micros");
        Wall.now_micros()
    }
    fn sleep(&self, millis: u64) -> BoxFut<'_, ()> {
        self.check("sleep");
        Wall.sleep(millis)
    }
}

struct WatchingTelemetry(Arc<Probe>);
impl Telemetry for WatchingTelemetry {
    fn upstream_attempt(&self, _: &str, _: DestinationId) {
        self.0.check("attempt");
    }
    fn upstream_latency(&self, _: DestinationId, _: f64) {
        self.0.check("latency");
    }
    fn upstream_failure(&self, _: &str, _: DestinationId, _: &'static str) {
        self.0.check("failure");
    }
    fn failover(&self, _: &str, _: &'static str) {
        self.0.check("failover");
    }
    fn breaker_trip(&self, _: &str, _: DestinationId) {
        self.0.check("trip");
    }
    fn queued(&self, _: &str, _: i64) {
        self.0.check("queued");
    }
}

fn all_watching(script: Script) -> (Rig, Arc<Probe>) {
    let (mut rig, probe) = watching(script);
    rig.egress.breaker = fixed_breaker(Arc::new(WatchingBreaker {
        inner: rig.book.clone(),
        probe: probe.clone(),
    }));
    rig.egress.clock = Arc::new(WatchingClock(probe.clone()));
    rig.egress.telemetry = Arc::new(WatchingTelemetry(probe.clone()));
    (rig, probe)
}

#[tokio::test]
async fn selection_classification_clock_and_telemetry_callbacks_leave_state_unlocked() {
    let scripts = [
        Script::Answer(200, None, vec![b"body"]),
        Script::Answer(401, None, vec![b"denied"]),
        Script::Answer(529, Some(2), vec![b"retry"]),
        Script::Broken(200, vec![b"body"]),
        Script::Ended(
            401,
            WireStatusClass::CallerFault,
            Some(WireFault::Hard),
            vec![b"body"],
        ),
        Script::Refused,
    ];
    for script in scripts {
        let (rig, probe) = all_watching(script);
        let far = Box::pin(rig.egress.unit(route()));
        probe.state.store(
            (&far.state as *const Mutex<State>).cast_mut(),
            Ordering::Release,
        );
        let token = token();
        assert!(matches!(far.member(&token, 1).await, Pick::Member { .. }));
        if far.send(&token, request()).await {
            let _ = drain(&far, &token).await;
        }
        let _ = far.member_wait(&token, "m0");
        let _ = far.remaining(&token);
        far.settle();
        let seen = probe.seen.lock().unwrap();
        assert!(seen.iter().all(|(_, available)| *available), "{seen:?}");
        assert!(
            seen.iter().any(|(effect, _)| *effect == "admit"),
            "{seen:?}"
        );
        assert!(
            seen.iter().any(|(effect, _)| *effect == "millis"),
            "{seen:?}"
        );
        drop(seen);
        probe.state.store(std::ptr::null_mut(), Ordering::Release);
        drop(far);
    }
}

struct QueueCapacity(Arc<Probe>);
impl Capacity for QueueCapacity {
    fn try_acquire(&self, _: DestinationId) -> Option<Permit> {
        self.0.check("capacity_full");
        None
    }
    fn acquire_any<'a>(
        &'a self,
        waiting: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>> {
        self.0.check("capacity_queue");
        let destination = waiting.first().copied();
        Box::pin(async move {
            destination.map(|destination| {
                (
                    destination,
                    Permit::new(Box::new(WatchingPermit {
                        destination,
                        callback: self.0.callback("permit"),
                    })),
                )
            })
        })
    }
}

#[tokio::test]
async fn queued_selection_parking_waiting_and_recheck_leave_state_unlocked() {
    let (mut rig, probe) = all_watching(Script::Answer(200, None, vec![b"body"]));
    rig.egress.pools.get_mut(POOL).unwrap().on_exhausted = OnExhausted::Queue { max_ms: 100 };
    rig.egress.capacity = Arc::new(QueueCapacity(probe.clone()));
    let far = Box::pin(rig.egress.unit(route()));
    probe.state.store(
        (&far.state as *const Mutex<State>).cast_mut(),
        Ordering::Release,
    );
    let token = token();
    assert!(matches!(far.member(&token, 1).await, Pick::Member { .. }));
    far.settle();
    let seen = probe.seen.lock().unwrap();
    assert!(seen.iter().all(|(_, available)| *available), "{seen:?}");
    assert!(
        seen.iter().any(|(effect, _)| *effect == "capacity_queue"),
        "{seen:?}"
    );
    assert_eq!(
        seen.iter()
            .filter(|(effect, _)| *effect == "queued")
            .count(),
        2,
        "{seen:?}"
    );
    drop(seen);
    probe.state.store(std::ptr::null_mut(), Ordering::Release);
    drop(far);
}

#[derive(Debug)]
struct SemaphoreCapacity(Arc<tokio::sync::Semaphore>);

#[derive(Debug)]
struct SemaphorePermit {
    destination: DestinationId,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl PermitHandle for SemaphorePermit {
    fn destination(&self) -> DestinationId {
        self.destination
    }
}

impl Capacity for SemaphoreCapacity {
    fn try_acquire(&self, destination: DestinationId) -> Option<Permit> {
        self.0.clone().try_acquire_owned().ok().map(|permit| {
            Permit::new(Box::new(SemaphorePermit {
                destination,
                _permit: permit,
            }))
        })
    }

    fn acquire_any<'a>(
        &'a self,
        _: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>> {
        Box::pin(std::future::ready(None))
    }
}

#[tokio::test]
async fn returning_a_semaphore_permit_wakes_a_waiter_outside_the_state_mutex() {
    struct Reenter(Arc<Probe>);
    impl std::task::Wake for Reenter {
        fn wake(self: Arc<Self>) {
            self.0.check("permit_wake");
        }
    }

    let (mut r, probe) = watching(Script::Silent);

    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    r.egress.capacity = Arc::new(SemaphoreCapacity(slots.clone()));
    let far = Box::pin(r.egress.unit(route()));
    probe.state.store(
        (&far.state as *const Mutex<State>).cast_mut(),
        Ordering::Release,
    );
    let t = token();
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let mut waiting = Box::pin(slots.acquire_owned());
    let waker = std::task::Waker::from(Arc::new(Reenter(probe.clone())));
    let mut cx = Context::from_waker(&waker);
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    far.settle();
    probe.assert_effects(&["close", "journal", "permit_wake"]);
    assert!(waiting.as_mut().poll(&mut cx).is_ready());
    probe.state.store(std::ptr::null_mut(), Ordering::Release);
    drop(far);
}
