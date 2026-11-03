// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::{load_linked, Bind, ConnTable, Kind, LinkedRow, NoSink, NO_BLOB};
use busbar_contract::abi::mechanism::{
    call::{RawOutcome, FLAG_RESUME},
    door::{Door, DoorParts},
    lifecycle::{OpenIn, OpenOut, OpsHead, ReleaseIn},
    KindCode,
};
use std::collections::HashSet;
use std::sync::OnceLock;

const WAIT: Duration = Duration::from_secs(10);
type Probe = Arc<dyn Fn() + Send + Sync>;
type CloseProbe = Arc<dyn Fn(Ticket) + Send + Sync>;
type Identity = (u64, u64, u64, u64);
#[derive(Default)]
struct State {
    next: AtomicU64,
    leases: Mutex<HashSet<u64>>,
    released: AtomicU64,
    calls: AtomicU64,
    commits: AtomicU64,
    cancels: AtomicU64,
    release_scopes: Mutex<Vec<Option<Identity>>>,
    probe: Mutex<Option<Probe>>,
    close_probe: Mutex<Option<CloseProbe>>,
    services: Option<busbar_contract::abi::sdk::services::Services>,
    extensions: Mutex<std::collections::HashMap<u64, Box<[u8]>>>,
    entered: AtomicBool,
    unblock: AtomicBool,
}
struct LeaseKind;
impl Kind for LeaseKind {
    const CODE: KindCode = KindCode::Export;
    type Ops = OpsHead;
    const TIMEOUT: Outcome = Outcome::Failed;
    fn short(a: &super::super::Answer) -> bool {
        a.slot == slot::TICK && a.out::<TickOut>().is_ok_and(|o| o.next_tick_ns == 99)
    }
}
fn issued(state: &State, head: &mut OutHead) {
    let lease = state.next.fetch_add(1, Ordering::SeqCst) + 1;
    assert!(state.leases.lock().unwrap().insert(lease));
    head.lease = lease;
}
crate::dispatch_tests::c_abi! {
    fn open(_: *mut std::ffi::c_void, input: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        let (input, out) = unsafe { (&*input.cast::<OpenIn>(), &mut *out.cast::<OpenOut>()) };
        // SAFETY: the loader lends its complete host tables for OPEN; the copied service
        // callbacks validate their context and remain callable until this instance closes.
        let services = unsafe { input.host.as_ref().and_then(|host| busbar_contract::abi::sdk::services::Services::from_raw(host)) };
        out.instance = Box::into_raw(Box::new(State { services, ..State::default() })).cast();
        out.head.outcome = RawOutcome::of(Outcome::Ready);
        RawOutcome::of(Outcome::Ready)
    }
    fn close(instance: *mut std::ffi::c_void, input: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        let state = unsafe { Box::from_raw(instance.cast::<State>()) };
        let probe = state.close_probe.lock().unwrap().take();
        if let Some(probe) = probe {
            // SAFETY: CLOSE's actual initialized input starts with InHead and stays live
            // through this synchronous callback; no service output escapes the crossing.
            probe(unsafe { (*input.cast::<InHead>()).ticket });
        }
        drop(state);
        unsafe { (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Ready); }
        RawOutcome::of(Outcome::Ready)
    }
    fn release(instance: *mut std::ffi::c_void, input: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        let (state, input, out) = unsafe { (&*instance.cast::<State>(), &*input.cast::<ReleaseIn>(), &mut *out.cast::<OutHead>()) };
        let present = state.leases.lock().unwrap().remove(&input.lease);
        let outcome = if present { Outcome::Ready } else { Outcome::Refused };
        if present {
            state.extensions.lock().unwrap().remove(&input.lease);
            state.release_scopes.lock().unwrap().push(super::super::framing_context::current().map(|s| (s.owner(), s.leg(), s.listener(), s.connection())));
            let probe = state.probe.lock().unwrap().clone();
            if let Some(probe) = probe { probe(); }
            state.released.fetch_add(1, Ordering::SeqCst);
        }
        out.outcome = RawOutcome::of(outcome);
        RawOutcome::of(outcome)
    }
    fn tick(instance: *mut std::ffi::c_void, input: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        let (state, input, out) = unsafe { (&*instance.cast::<State>(), &*input.cast::<TickIn>(), &mut *out.cast::<TickOut>()) };
        state.calls.fetch_add(1, Ordering::SeqCst);
        let resumed = input.head.flags & FLAG_RESUME != 0;
        let outcome = match input.now_ns {
            1 if !resumed => { issued(state, &mut out.head); Outcome::Pending }
            2 if !resumed => Outcome::Pending,
            3 => { issued(state, &mut out.head); out.next_tick_ns = 99; Outcome::Failed }
            4 | 6 => {
                if input.now_ns == 6 {
                    state.entered.store(true, Ordering::Release);
                    while !state.unblock.load(Ordering::Acquire) { std::thread::yield_now(); }
                }
                let prior = unsafe { super::super::plugin::blob_bytes(input.head.extensions) };
                match busbar_contract::abi::sdk::auth_door::short_reply::decode(prior).unwrap() {
                    Some(lease) => {
                        assert!(state.leases.lock().unwrap().contains(&lease));
                        state.commits.fetch_add(1, Ordering::SeqCst);
                        Outcome::Ready
                    }
                    None => {
                        issued(state, &mut out.head);
                        let bytes = busbar_contract::abi::sdk::auth_door::short_reply::encode(out.head.lease).into_boxed_slice();
                        out.head.extensions = busbar_contract::abi::mechanism::call::Blob { ptr: bytes.as_ptr(), len: bytes.len(), fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS, flags: 0 };
                        state.extensions.lock().unwrap().insert(out.head.lease, bytes);
                        out.next_tick_ns = 99;
                        Outcome::Failed
                    }
                }
            }
            _ => { issued(state, &mut out.head); state.commits.fetch_add(1, Ordering::SeqCst); Outcome::Ready }
        };
        out.head.outcome = RawOutcome::of(outcome);
        RawOutcome::of(outcome)
    }
    fn cancel(instance: *mut std::ffi::c_void, _: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        let (state, out) = unsafe { (&*instance.cast::<State>(), &mut *out.cast::<OutHead>()) };
        state.cancels.fetch_add(1, Ordering::SeqCst);
        issued(state, out);
        out.outcome = RawOutcome::of(Outcome::Ready);
        RawOutcome::of(Outcome::Ready)
    }
    fn door() -> &'static Door {
        static ADDRESS: OnceLock<usize> = OnceLock::new();
        let address = *ADDRESS.get_or_init(|| {
            let real = crate::dispatch_test_plugin::door().parts();
            let mut ops = unsafe { *real.ops };
            ops.open = Some(open); ops.close = Some(close); ops.tick = Some(tick);
            ops.release = Some(release); ops.cancel = Some(cancel);
            let ops = Box::leak(Box::new(ops));
            let door = unsafe { Door::__from_parts(DoorParts { ops, ..real }) };
            Box::into_raw(Box::new(door)) as usize
        });
        unsafe { &*(address as *const Door) }
    }
}

fn rig() -> (Dispatcher, Plugin<LeaseKind>, *const State) {
    let d = Dispatcher::new(DispatchConfig::default());
    let p = load_linked::<LeaseKind>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: Arc::from("worker-lease"),
            max_inflight_cap: 2,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .unwrap();
    let mut frame = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: NO_BLOB,
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    assert_eq!(p.call(slot::OPEN, &mut frame).outcome, Outcome::Ready);
    (d, p, frame.out.instance.cast())
}
fn frame(mode: u64) -> Frame<TickIn, TickOut> {
    Frame::new(
        TickIn {
            head: in_head(),
            now_ns: mode,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    )
}
fn until(mut yes: impl FnMut() -> bool) {
    let start = Instant::now();
    while !yes() {
        assert!(start.elapsed() < WAIT, "fixture did not progress");
        std::thread::yield_now();
    }
}
fn wake(p: &Plugin<LeaseKind>, ticket: Ticket) {
    super::super::ticket::Waking::of(p.inner.wake)
        .unwrap()
        .wake(ticket);
}
fn release_done(p: &Plugin<LeaseKind>, done: &Done<TickIn, TickOut>) {
    assert_ne!(done.lease, 0);
    let mut frame = Frame::new(
        ReleaseIn {
            head: in_head(),
            lease: done.lease,
        },
        out_head(),
    );
    assert_eq!(p.call(slot::RELEASE, &mut frame).outcome, Outcome::Ready);
}

#[test]
fn settled_unpolled_reply_releases_under_its_captured_scope_outside_both_locks() {
    let (d, p, ptr) = rig();
    let state = unsafe { &*ptr };
    let ticket = d.mint(0).unwrap();
    let scope = d.framing_context(p.instance().0, 73, 0).unwrap();
    let expected = (p.instance().0, scope.leg(), 73, scope.connection());
    let reply = super::super::framing_context::with_context(Some(scope), || {
        d.submit(&p, ticket, slot::TICK, frame(0), DeadlineClass::Call, 0)
    });
    until(|| reply.slot.lock().settled);
    let slot = Arc::clone(&reply.slot);
    let worker = d.worker(0).unwrap();
    let unlocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let saw = unlocked.clone();
    *state.probe.lock().unwrap() = Some(Arc::new(move || {
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(200) {
            if let (Ok(a), Ok(b)) = (slot.v.try_lock(), worker.state.try_lock()) {
                drop((a, b));
                saw.store(true, Ordering::SeqCst);
                break;
            }
            std::thread::yield_now();
        }
    }));
    let unrelated = d.framing_context(p.instance().0, 99, 0).unwrap();
    super::super::framing_context::with_context(Some(unrelated), || drop(reply));
    until(|| state.released.load(Ordering::SeqCst) == 1);
    assert!(unlocked.load(Ordering::SeqCst));
    assert_eq!(*state.release_scopes.lock().unwrap(), vec![Some(expected)]);
    assert!(state.leases.lock().unwrap().is_empty());
    *state.probe.lock().unwrap() = None;
    d.recycle(ticket);
}

/// CLOSE crosses to a permanent FFI worker before its synchronous host callback. This raw
/// lifecycle input pins the scope at that callback; a product need not naturally call a service
/// while closing, and RELEASE custody alone does not exercise the CLOSE path.
#[test]
fn close_host_callback_keeps_the_submitted_framing_scope_outside_both_locks() {
    use crate::dispatch::auth_handle::{
        AuthCallAsk, AuthDone, AuthHandleHost, AuthRan, HandInAsk, RefusalBytes, RefuseAsk,
        UnitSecret,
    };
    use busbar_contract::abi::host::service::{UnitRef, LINE_NONE, REFUSE_NO_ROUTE, SCHEME_PLAIN};
    use busbar_contract::abi::mechanism::ticket::CompletionHandle;
    use busbar_contract::abi::sdk::services::HeadViewArgs;

    #[derive(Debug, PartialEq, Eq)]
    struct Seen {
        scope: Option<Identity>,
        framing: Option<u64>,
        owner: u64,
        conn: u64,
        worker: Option<(usize, u32)>,
        permanent: bool,
        thread: std::thread::ThreadId,
    }
    #[derive(Default)]
    struct Host {
        seen: Mutex<Vec<Seen>>,
        probe: Mutex<Option<Probe>>,
    }
    impl AuthHandleHost for Host {
        fn unit_secret(&self, _: u64, _: u64) -> Option<UnitSecret> {
            None
        }
        fn auth_call(&self, _: AuthCallAsk, _: AuthDone) -> AuthRan {
            AuthRan::Now(Err("no auth call in this lifecycle input"))
        }
        fn hand_in(&self, _: HandInAsk) -> Result<(u32, UnitRef), &'static str> {
            Err("no hand-in in this lifecycle input")
        }
        fn refuse(&self, ask: RefuseAsk) -> Result<RefusalBytes, &'static str> {
            self.seen.lock().unwrap().push(Seen {
                scope: super::super::framing_context::current()
                    .map(|s| (s.owner(), s.leg(), s.listener(), s.connection())),
                framing: ask.framing,
                owner: ask.owner,
                conn: ask.conn,
                worker: worker_mark(),
                permanent: crate::ffi_thread::on_permanent_worker(),
                thread: std::thread::current().id(),
            });
            let probe = self.probe.lock().unwrap().clone();
            if let Some(probe) = probe {
                probe();
            }
            Ok(RefusalBytes {
                status: 404,
                fields: Vec::new(),
                body: Vec::new(),
            })
        }
        fn framing_ended(&self, _: u64) {}
    }

    let (d, p, ptr) = rig();
    let host = Arc::new(Host::default());
    assert!(d.install_auth_handle(host.clone()));
    let scope = d.framing_context(p.instance().0, 73, 0).unwrap();
    scope.confirm(21).unwrap();
    let expected = (p.instance().0, scope.leg(), 73, scope.connection());
    let expected_worker = (Arc::as_ptr(&d.pool.env) as usize, 0);
    let caller = std::thread::current().id();
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (release, held) = std::sync::mpsc::channel();
    let held = Mutex::new(held);
    let service_ready = Arc::new(AtomicBool::new(false));
    let service_called = service_ready.clone();
    // SAFETY: rig's OPEN owns this State, and CLOSE has not been submitted yet. Only the
    // copied service snapshot and the callback escape this borrow; State is never read later.
    let state = unsafe { &*ptr };
    let services = state
        .services
        .expect("OPEN lent the actual host service table");
    *state.close_probe.lock().unwrap() = Some(Arc::new(move |ticket| {
        if entered_tx.send(()).is_err() || held.lock().unwrap().recv_timeout(WAIT).is_err() {
            return;
        }
        let refusal = services.unit_refuse(
            CompletionHandle {
                ticket,
                seq: 1,
                _reserved: 0,
            },
            UnitRef::NONE,
            REFUSE_NO_ROUTE,
            LINE_NONE,
            21,
            1,
            &HeadViewArgs {
                method: "GET",
                target: "/",
                scheme: SCHEME_PLAIN,
                ..HeadViewArgs::default()
            },
        );
        service_called.store(refusal.is_ok_and(|r| r.status == 404), Ordering::SeqCst);
    }));
    let ticket = d.mint(0).unwrap();
    let reply = super::super::framing_context::with_context(Some(scope.clone()), || {
        d.submit(
            &p,
            ticket,
            slot::CLOSE,
            Frame::new(in_head(), out_head()),
            DeadlineClass::Call,
            0,
        )
    });
    let caller_scope_restored = super::super::framing_context::current().is_none();
    entered
        .recv_timeout(WAIT)
        .expect("the actual CLOSE entered its FFI callback");
    let slot = Arc::clone(&reply.slot);
    let worker = d.worker(0).unwrap();
    let locks_available = Arc::new(AtomicBool::new(false));
    let unlocked = locks_available.clone();
    *host.probe.lock().unwrap() = Some(Arc::new(move || {
        if let (Ok(reply), Ok(worker)) = (slot.v.try_lock(), worker.state.try_lock()) {
            drop((reply, worker));
            unlocked.store(true, Ordering::SeqCst);
        }
    }));
    release.send(()).unwrap();
    let done = reply.wait(WAIT).expect("the lifecycle CLOSE finishes");
    *host.probe.lock().unwrap() = None;
    drop(reply);
    d.recycle(ticket);
    scope.end();

    assert!(caller_scope_restored);
    assert_eq!(done.outcome, Outcome::Ready);
    assert!(
        service_ready.load(Ordering::SeqCst),
        "unit_refuse answered inside CLOSE"
    );
    assert!(
        locks_available.load(Ordering::SeqCst),
        "the host callback held neither reply nor worker lock"
    );
    let seen = host.seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        1,
        "exactly one service callback ran inside CLOSE"
    );
    assert_eq!(
        seen.iter()
            .map(|s| (s.scope.map(|s| s.1), s.framing))
            .collect::<Vec<_>>(),
        vec![(Some(scope.leg()), Some(scope.leg()))]
    );
    assert_eq!(seen[0].scope, Some(expected));
    assert_eq!((seen[0].owner, seen[0].conn), (expected.0, 21));
    assert_eq!(seen[0].worker, Some(expected_worker));
    assert!(seen[0].permanent);
    assert_ne!(seen[0].thread, caller);
    assert!(!p.is_open());
}

#[test]
fn taking_a_raw_done_transfers_its_lease_without_host_double_release() {
    for asynchronous in [false, true] {
        let (d, p, ptr) = rig();
        let state = unsafe { &*ptr };
        let ticket = d.mint(0).unwrap();
        let reply = d.submit(&p, ticket, slot::TICK, frame(0), DeadlineClass::Call, 0);
        let done = if asynchronous {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap()
                .block_on(reply)
        } else {
            let done = reply.wait(WAIT).unwrap();
            drop(reply);
            done
        };
        assert_eq!(done.outcome, Outcome::Ready);
        assert_eq!(state.released.load(Ordering::SeqCst), 0);
        release_done(&p, &done);
        drop(done);
        assert_eq!(state.released.load(Ordering::SeqCst), 1);
        assert!(state.leases.lock().unwrap().is_empty());
        d.recycle(ticket);
    }
}

#[test]
fn ordinary_pending_releases_each_intermediate_lease_before_resume() {
    let (d, p, ptr) = rig();
    let state = unsafe { &*ptr };
    let ticket = d.mint(0).unwrap();
    let reply = d.submit(&p, ticket, slot::TICK, frame(1), DeadlineClass::Call, 0);
    until(|| d.is_pending(ticket));
    assert_eq!(state.released.load(Ordering::SeqCst), 1);
    assert!(state.leases.lock().unwrap().is_empty());
    wake(&p, ticket);
    let done = reply.wait(WAIT).unwrap();
    assert_eq!(done.outcome, Outcome::Ready);
    release_done(&p, &done);
    assert_eq!(state.released.load(Ordering::SeqCst), 2);
    d.recycle(ticket);
}

#[test]
fn abandoned_writebehind_commits_and_releases_its_late_answer() {
    for detach in [false, true] {
        let (d, p, ptr) = rig();
        let state = unsafe { &*ptr };
        let ticket = d.mint(0).unwrap();
        let reply = d.submit(
            &p,
            ticket,
            slot::TICK,
            frame(2),
            DeadlineClass::WriteBehind,
            0,
        );
        until(|| d.is_pending(ticket));
        if detach {
            reply.detach();
        } else {
            drop(reply);
        }
        wake(&p, ticket);
        until(|| state.released.load(Ordering::SeqCst) == 1);
        assert_eq!(state.commits.load(Ordering::SeqCst), 1);
        assert_eq!(state.cancels.load(Ordering::SeqCst), 0);
        assert!(state.leases.lock().unwrap().is_empty());
        d.recycle(ticket);
    }
}

#[test]
fn cancelled_call_releases_cancel_answer_once_and_late_wake_cannot_commit() {
    let (d, p, ptr) = rig();
    let state = unsafe { &*ptr };
    let ticket = d.mint(0).unwrap();
    let reply = d.submit(&p, ticket, slot::TICK, frame(2), DeadlineClass::Call, 0);
    until(|| d.is_pending(ticket));
    drop(reply);
    until(|| state.released.load(Ordering::SeqCst) == 1);
    assert_eq!(state.cancels.load(Ordering::SeqCst), 1);
    wake(&p, ticket);

    let barrier = d.mint(0).unwrap();
    let done = d
        .submit(&p, barrier, slot::TICK, frame(0), DeadlineClass::Call, 0)
        .wait(WAIT)
        .unwrap();
    assert_eq!(done.outcome, Outcome::Ready);
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
    release_done(&p, &done);
    assert_eq!(state.released.load(Ordering::SeqCst), 2);
    assert!(state.leases.lock().unwrap().is_empty());
    d.recycle(barrier);
    d.recycle(ticket);
}

#[test]
fn short_recall_and_second_short_release_exactly_once_each() {
    let (d, p, ptr) = rig();
    let state = unsafe { &*ptr };
    let ticket = d.mint(0).unwrap();
    let first = d
        .submit(&p, ticket, slot::TICK, frame(3), DeadlineClass::Call, 0)
        .wait(WAIT)
        .unwrap();
    assert!(first.short);
    assert_eq!(first.lease, 0);
    assert_eq!(state.released.load(Ordering::SeqCst), 1);
    let second = d
        .submit(&p, ticket, slot::TICK, frame(3), DeadlineClass::Call, 0)
        .wait(WAIT)
        .unwrap();
    assert_eq!(second.outcome, Outcome::Fault);
    assert_eq!(second.lease, 0);
    assert_eq!(state.released.load(Ordering::SeqCst), 2);
    assert!(state.leases.lock().unwrap().is_empty());
    d.recycle(ticket);
}

#[test]
fn negotiated_short_is_private_and_other_tickets_do_not_consume_it() {
    let (d, p, ptr) = rig();
    let state = unsafe { &*ptr };
    let first = d.mint(0).unwrap();
    let other = d.mint(0).unwrap();
    for ticket in [first, other] {
        let done = d
            .submit(&p, ticket, slot::TICK, frame(4), DeadlineClass::Call, 0)
            .wait(WAIT)
            .unwrap();
        assert!(done.short);
        assert_eq!(done.lease, 0);
    }
    assert_eq!(state.leases.lock().unwrap().len(), 2);
    assert_eq!(state.released.load(Ordering::SeqCst), 0);
    for (count, ticket) in [other, first].into_iter().enumerate() {
        let done = d
            .submit(&p, ticket, slot::TICK, frame(4), DeadlineClass::Call, 0)
            .wait(WAIT)
            .unwrap();
        assert_eq!(done.outcome, Outcome::Ready);
        assert_eq!(done.lease, 0);
        until(|| state.released.load(Ordering::SeqCst) == count as u64 + 1);
        d.recycle(ticket);
    }
    assert_eq!(state.commits.load(Ordering::SeqCst), 2);
    assert!(state.leases.lock().unwrap().is_empty());
}

#[test]
fn an_old_unread_short_cannot_retire_a_new_answer_on_the_same_ticket() {
    let (d, p, ptr) = rig();
    let state = unsafe { &*ptr };
    let ticket = d.mint(0).unwrap();
    let old = d.submit(&p, ticket, slot::TICK, frame(4), DeadlineClass::Call, 0);
    until(|| old.slot.lock().settled);
    assert_eq!(
        d.submit(&p, ticket, slot::TICK, frame(4), DeadlineClass::Call, 0)
            .wait(WAIT)
            .unwrap()
            .outcome,
        Outcome::Ready
    );
    until(|| state.released.load(Ordering::SeqCst) == 1);
    assert!(
        d.submit(&p, ticket, slot::TICK, frame(4), DeadlineClass::Call, 0)
            .wait(WAIT)
            .unwrap()
            .short
    );
    drop(old);
    assert_eq!(state.released.load(Ordering::SeqCst), 1);
    assert_eq!(state.leases.lock().unwrap().len(), 1);
    assert_eq!(
        d.submit(&p, ticket, slot::TICK, frame(4), DeadlineClass::Call, 0)
            .wait(WAIT)
            .unwrap()
            .outcome,
        Outcome::Ready
    );
    until(|| state.released.load(Ordering::SeqCst) == 2);
    assert!(state.leases.lock().unwrap().is_empty());
    d.recycle(ticket);
}

#[test]
fn a_second_short_retires_the_saved_answer_and_the_new_failed_lease() {
    let (d, p, ptr) = rig();
    let state = unsafe { &*ptr };
    let ticket = d.mint(0).unwrap();
    assert!(
        d.submit(&p, ticket, slot::TICK, frame(4), DeadlineClass::Call, 0)
            .wait(WAIT)
            .unwrap()
            .short
    );
    let done = d
        .submit(&p, ticket, slot::TICK, frame(3), DeadlineClass::Call, 0)
        .wait(WAIT)
        .unwrap();
    assert_eq!(done.outcome, Outcome::Fault);
    assert_eq!(done.lease, 0);
    until(|| state.released.load(Ordering::SeqCst) == 2);
    assert!(state.leases.lock().unwrap().is_empty());
    d.recycle(ticket);
}

#[test]
fn unread_short_or_ticket_abandon_returns_once_outside_locks() {
    for end in ["unread", "drop-client", "recycle"] {
        let (d, p, ptr) = rig();
        let state = unsafe { &*ptr };
        let ticket = d.mint(0).unwrap();
        let scope = d.framing_context(p.instance().0, 73, 0).unwrap();
        let expected = (p.instance().0, scope.leg(), 73, scope.connection());
        let reply = super::super::framing_context::with_context(Some(scope), || {
            d.submit(&p, ticket, slot::TICK, frame(4), DeadlineClass::Call, 0)
        });
        until(|| reply.slot.lock().settled);
        assert_eq!(state.released.load(Ordering::SeqCst), 0);
        let slot = reply.slot.clone();
        let worker = d.worker(0).unwrap();
        let unlocked = Arc::new(AtomicBool::new(false));
        let saw = unlocked.clone();
        *state.probe.lock().unwrap() = Some(Arc::new(move || {
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(200) {
                if let (Ok(a), Ok(b)) = (slot.v.try_lock(), worker.state.try_lock()) {
                    drop((a, b));
                    saw.store(true, Ordering::Release);
                    break;
                }
                std::thread::yield_now();
            }
        }));
        match end {
            "drop-client" => d.drop_client(ticket),
            "recycle" => d.recycle(ticket),
            _ => {}
        }
        if end == "unread" {
            drop(reply);
        } else {
            until(|| state.released.load(Ordering::SeqCst) == 1);
            drop(reply);
        }
        until(|| state.released.load(Ordering::SeqCst) == 1);
        assert!(unlocked.load(Ordering::Acquire), "{end}");
        assert_eq!(*state.release_scopes.lock().unwrap(), vec![Some(expected)]);
        assert!(state.leases.lock().unwrap().is_empty());
        *state.probe.lock().unwrap() = None;
        if end != "recycle" {
            d.recycle(ticket);
        }
    }
}

#[test]
fn replacing_a_worker_retires_completed_and_late_short_storage() {
    for late in [false, true] {
        let (d, p, ptr) = rig();
        let state = unsafe { &*ptr };

        struct Unblock<'a>(&'a AtomicBool);
        impl Drop for Unblock<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let unblock = Unblock(&state.unblock);
        let ticket = d.mint(0).unwrap();
        let reply = d.submit(
            &p,
            ticket,
            slot::TICK,
            frame(if late { 6 } else { 4 }),
            DeadlineClass::Call,
            0,
        );
        if late {
            until(|| state.entered.load(Ordering::Acquire));
        } else {
            assert!(reply.wait(WAIT).unwrap().short);
        }
        let worker = d.worker(0).unwrap();

        let gone = {
            let mut st = worker.lock();
            st.dead = true;
            Worker::fault_all(&mut st)
        };
        drop(gone);
        drop(unblock);
        until(|| state.released.load(Ordering::SeqCst) == 1);
        assert!(state.leases.lock().unwrap().is_empty());
        drop(reply);
        assert_eq!(state.released.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn writebehind_deadline_detaches_but_late_commit_and_lease_cleanup_still_finish() {
    let (d, p, ptr) = rig();
    let state = unsafe { &*ptr };
    let ticket = d.mint(0).unwrap();
    let reply = d.submit(
        &p,
        ticket,
        slot::TICK,
        frame(2),
        DeadlineClass::WriteBehind,
        now_ns() + 20_000_000,
    );
    let detached = reply.wait(WAIT).unwrap();
    assert!(detached.detached);
    assert_eq!(detached.lease, 0);
    wake(&p, ticket);
    until(|| state.released.load(Ordering::SeqCst) == 1);
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
    assert_eq!(state.cancels.load(Ordering::SeqCst), 0);
    assert!(state.leases.lock().unwrap().is_empty());
    d.recycle(ticket);
}

struct LentProbe(Probe);
impl Drop for LentProbe {
    fn drop(&mut self) {
        (self.0)();
    }
}
struct WakeProbe {
    probe: Probe,
    called: AtomicU64,
}
impl std::task::Wake for WakeProbe {
    fn wake(self: Arc<Self>) {
        (self.probe)();
        self.called.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn completion_waker_and_lent_destructor_can_reenter_after_worker_unlocks() {
    let (d, p, ptr) = rig();
    let state = unsafe { &*ptr };
    let ticket = d.mint(0).unwrap();
    let worker = d.worker(0).unwrap();
    let lent_unlocked = Arc::new(AtomicBool::new(false));
    let saw = lent_unlocked.clone();
    let held_worker = worker.clone();
    let lent = Arc::new(LentProbe(Arc::new(move || {
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(200) {
            if let Ok(g) = held_worker.state.try_lock() {
                drop(g);
                saw.store(true, Ordering::SeqCst);
                break;
            }
            std::thread::yield_now();
        }
    })));
    let mut reply = d.submit_lent(
        &p,
        ticket,
        slot::TICK,
        frame(2),
        DeadlineClass::Call,
        0,
        lent.clone(),
    );
    drop(lent);
    until(|| d.is_pending(ticket));
    assert!(!lent_unlocked.load(Ordering::SeqCst));
    let slot = reply.slot.clone();
    let wake_unlocked = Arc::new(AtomicBool::new(false));
    let saw = wake_unlocked.clone();
    let probe = Arc::new(WakeProbe {
        called: AtomicU64::new(0),
        probe: Arc::new(move || {
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(200) {
                if let (Ok(a), Ok(b)) = (slot.v.try_lock(), worker.state.try_lock()) {
                    drop((a, b));
                    saw.store(true, Ordering::SeqCst);
                    break;
                }
                std::thread::yield_now();
            }
        }),
    });
    let waker = Waker::from(probe.clone());
    assert!(Pin::new(&mut reply)
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    wake(&p, ticket);
    until(|| probe.called.load(Ordering::SeqCst) == 1);
    let done = reply.wait(WAIT).unwrap();
    until(|| lent_unlocked.load(Ordering::SeqCst));
    assert!(wake_unlocked.load(Ordering::SeqCst));
    release_done(&p, &done);
    assert_eq!(state.released.load(Ordering::SeqCst), 1);
    d.recycle(ticket);
}
