// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One op on a kept session: the body runs on the session it opened, which is handed back when
//! the body has answered; a session that does not open answers its failure and runs nothing.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use super::{on_kept, Kept, Pool, Wire};
use crate::abi::sdk::store::{Op, Step};

/// A session that opens unless told not to, and counts its hand-backs.
struct Session {
    done: Arc<AtomicU32>,
    ran: u32,
}

impl Kept for Session {
    type Shared = (Arc<AtomicU32>, bool);
    type Error = String;

    async fn open(_wire: Wire, (done, opens): Self::Shared) -> Result<Self, String> {
        if opens {
            Ok(Self { done, ran: 0 })
        } else {
            Err("the server refused the session".to_owned())
        }
    }

    async fn done(self) {
        self.done.fetch_add(1, Ordering::Relaxed);
    }
}

fn run(opens: bool, done: &Arc<AtomicU32>, body_ran: &Arc<AtomicU32>) -> Step<Result<u32, String>> {
    let body_ran = Arc::clone(body_ran);
    on_kept::<Session, _>(
        &mut Op::detached(),
        &Pool::new(1),
        (Arc::clone(done), opens),
        Err,
        move |s| {
            Box::pin(async move {
                body_ran.fetch_add(1, Ordering::Relaxed);
                s.ran += 1;
                Ok(s.ran)
            })
        },
    )
}

#[test]
fn an_op_runs_its_body_on_its_session_and_hands_the_session_back() {
    let (done, body_ran) = (Arc::default(), Arc::default());
    assert_eq!(run(true, &done, &body_ran), Step::Ready(Ok(1)));
    assert_eq!(body_ran.load(Ordering::Relaxed), 1);
    assert_eq!(done.load(Ordering::Relaxed), 1);
}

#[test]
fn a_session_that_does_not_open_answers_its_failure_and_runs_nothing() {
    let (done, body_ran) = (Arc::default(), Arc::default());
    assert_eq!(
        run(false, &done, &body_ran),
        Step::Ready(Err("the server refused the session".to_owned()))
    );
    assert_eq!(body_ran.load(Ordering::Relaxed), 0);
    assert_eq!(done.load(Ordering::Relaxed), 0);
}

mod replay_handles {
    use super::*;
    use crate::abi::host::conn::connector::{
        EstablishIn, IdentityIn, IoIn, ProcessIdentity, StreamIn,
    };
    use crate::abi::host::service::{ClockNowIn, ClockReading};
    use crate::abi::mechanism::call::Outcome;
    use crate::abi::mechanism::ticket::{CompletionHandle, Ticket};
    use crate::abi::sdk::conn::{ConnFailure, Host};
    use crate::abi::sdk::door::abi_str;
    use crate::abi::sdk::store::op::Parked;
    use crate::abi::sdk::store::wire::{drive_kept, Body};
    use crate::abi::sdk::test_support::fake::{self, FakeHost, FakeService, ServiceCall};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::mem::size_of;

    const TICKET: Ticket = Ticket {
        slot: 31,
        generation: 1,
    };
    const HOLDER: Ticket = Ticket {
        slot: 32,
        generation: 1,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Kind {
        Establish,
        Identity,
        Write,
        Read,
        Close,
    }

    #[derive(Clone, Copy, Default)]
    enum Mode {
        #[default]
        RepeatedPending,
        CancelRead,
        ZeroWrite,
        PoolWait,
    }

    struct Held {
        kind: Kind,
        bytes: Vec<u8>,
        attempts: usize,
        pending: usize,
        value: usize,
        completed: bool,
    }

    #[derive(Clone, Debug)]
    struct Call {
        kind: Kind,
        handle: CompletionHandle,
        bytes: Vec<u8>,
        ready: bool,
        value: usize,
    }

    #[derive(Default)]
    struct Script {
        mode: Mode,
        held: HashMap<CompletionHandle, Held>,
        calls: Vec<Call>,
        accepted: Vec<u8>,
        clocks: Vec<CompletionHandle>,
        bodies: usize,
        streams: usize,
        zero_used: bool,
        now: u64,
    }

    thread_local! { static SCRIPT: RefCell<Script> = RefCell::new(Script::default()); }

    fn script<R>(f: impl FnOnce(&mut Script) -> R) -> R {
        SCRIPT.with(|state| f(&mut state.borrow_mut()))
    }

    // Model the real host's handle binding and stored result: a completed request on the same
    // handle returns its original answer, including a successful zero-byte write.
    fn cross(kind: Kind, handle: CompletionHandle, bytes: &[u8]) -> (Outcome, usize) {
        script(|s| {
            if !s.held.contains_key(&handle) {
                let pending = match (s.mode, kind) {
                    (Mode::RepeatedPending, Kind::Establish | Kind::Read) => 2,
                    (Mode::RepeatedPending, Kind::Write) if bytes == b"A" => 2,
                    (Mode::CancelRead, Kind::Read) => usize::MAX,
                    (Mode::PoolWait, Kind::Read) if handle.ticket == HOLDER => usize::MAX,
                    _ => 0,
                };
                let value = match kind {
                    Kind::Establish => {
                        s.streams += 1;
                        s.streams
                    }
                    Kind::Write if matches!(s.mode, Mode::ZeroWrite) && !s.zero_used => {
                        s.zero_used = true;
                        0
                    }
                    Kind::Write => bytes.len(),
                    Kind::Read => b"reply".len(),
                    _ => 0,
                };
                s.held.insert(
                    handle,
                    Held {
                        kind,
                        bytes: bytes.to_vec(),
                        attempts: 0,
                        pending,
                        value,
                        completed: false,
                    },
                );
            }
            let held = s.held.get_mut(&handle).unwrap();
            assert_eq!(
                held.kind, kind,
                "a completion handle was rebound to another operation"
            );
            assert_eq!(
                held.bytes, bytes,
                "a completion handle was rebound to another request"
            );
            held.attempts += 1;
            let ready = held.attempts > held.pending;
            if ready && !held.completed {
                held.completed = true;
                if kind == Kind::Write {
                    s.accepted.extend_from_slice(&bytes[..held.value]);
                }
            }
            let value = held.value;
            s.calls.push(Call {
                kind,
                handle,
                bytes: bytes.to_vec(),
                ready,
                value,
            });
            (
                if ready {
                    Outcome::Ready
                } else {
                    Outcome::Pending
                },
                value,
            )
        })
    }

    struct Establish;
    impl FakeService for Establish {
        type In = EstablishIn;
        fn serve(call: &mut ServiceCall<EstablishIn>) -> Outcome {
            let (outcome, stream) = cross(Kind::Establish, call.input().head.handle, &[]);
            if outcome == Outcome::Ready {
                call.set_value(stream as u64);
            }
            outcome
        }
    }

    struct Write;
    impl FakeService for Write {
        type In = IoIn;
        fn serve(call: &mut ServiceCall<IoIn>) -> Outcome {
            let bytes = call.lent(|i| &i.buf).to_vec();
            let (outcome, written) = cross(Kind::Write, call.input().head.handle, &bytes);
            if outcome == Outcome::Ready {
                call.set_len(written as u64);
            }
            outcome
        }
    }

    struct Read;
    impl FakeService for Read {
        type In = IoIn;
        fn serve(call: &mut ServiceCall<IoIn>) -> Outcome {
            let (outcome, _) = cross(Kind::Read, call.input().head.handle, &[]);
            if outcome == Outcome::Ready {
                assert!(call.fill_lent(|i| &i.buf, b"reply"));
            }
            outcome
        }
    }

    struct Close;
    impl FakeService for Close {
        type In = StreamIn;
        fn serve(call: &mut ServiceCall<StreamIn>) -> Outcome {
            cross(Kind::Close, call.input().head.handle, &[]).0
        }
    }

    struct Identity;
    impl FakeService for Identity {
        type In = IdentityIn;
        fn serve(call: &mut ServiceCall<IdentityIn>) -> Outcome {
            let outcome = cross(Kind::Identity, call.input().head.handle, &[]).0;
            call.put(
                |i| &i.identity,
                ProcessIdentity {
                    size: size_of::<ProcessIdentity>() as u32,
                    _reserved: 0,
                    pid: 7,
                    os_user: abi_str("tester"),
                    program: abi_str("fixture"),
                },
            );
            outcome
        }
    }

    struct Clock;
    impl FakeService for Clock {
        type In = ClockNowIn;
        fn serve(call: &mut ServiceCall<ClockNowIn>) -> Outcome {
            let now = script(|s| {
                s.clocks.push(call.input().head.handle);
                s.now
            });
            call.put(
                |i| &i.reading,
                ClockReading {
                    size: size_of::<ClockReading>() as u32,
                    _reserved: 0,
                    mono_ns: now,
                    wall_ns: 0,
                },
            );
            Outcome::Ready
        }
    }

    fn host(mode: Mode) -> (FakeHost, Host) {
        script(|s| {
            *s = Script {
                mode,
                ..Script::default()
            }
        });
        let fake = FakeHost::new()
            .serve(fake::conn::ESTABLISH, Establish)
            .serve(fake::conn::WRITE, Write)
            .serve(fake::conn::READ, Read)
            .serve(fake::conn::CLOSE, Close)
            .serve(fake::conn::IDENTITY, Identity)
            .serve(fake::host::CLOCK_NOW, Clock);
        let host = Host::of(fake.lent());
        (fake, host)
    }

    type Start = fn(Wire) -> Body<Result<(), ConnFailure>>;

    fn enter(
        host: &Host,
        pool: &Arc<Pool>,
        ticket: Ticket,
        parked: Option<Parked>,
        start: Start,
    ) -> (Step<Result<(), ConnFailure>>, Parked, bool) {
        let mut op = Op::enter(ticket, Some(host), parked, None);
        let answer = drive_kept(&mut op, pool, move |wire| {
            script(|s| s.bodies += 1);
            start(wire)
        });
        let attempted = op.made_a_service();
        (answer, op.into_parked(), attempted)
    }

    fn finish(
        host: &Host,
        pool: &Arc<Pool>,
        ticket: Ticket,
        mut parked: Option<Parked>,
        start: Start,
    ) {
        for _ in 0..16 {
            let (answer, held, attempted) = enter(host, pool, ticket, parked, start);
            match answer {
                Step::Ready(result) => {
                    result.unwrap();
                    drop(held);
                    return;
                }
                Step::Pending { wake_at_ns } => {
                    if wake_at_ns == 0 {
                        assert!(
                            attempted,
                            "replayed Pending is still a real service attempt"
                        );
                    }
                    script(|s| s.now = s.now.max(wake_at_ns));
                    parked = Some(held);
                }
            }
        }
        panic!("the actual wire op did not finish after its scripted completions");
    }

    fn exchange(wire: Wire) -> Body<Result<(), ConnFailure>> {
        Box::pin(async move {
            wire.connect(0, None).await?;
            wire.write_all(b"A").await?;
            wire.write_all(b"B").await?;
            assert_eq!(wire.fill().await?, b"reply".len());
            wire.input(|bytes| assert_eq!(bytes, b"reply"));
            wire.close().await;
            Ok(())
        })
    }

    fn calls(kind: Kind) -> Vec<Call> {
        script(|s| s.calls.iter().filter(|c| c.kind == kind).cloned().collect())
    }

    #[test]
    fn repeated_pending_replays_one_handle_and_never_restarts_completed_wire_requests() {
        let (_fake, host) = host(Mode::RepeatedPending);
        let pool = Pool::new(1);
        finish(&host, &pool, TICKET, None, exchange);
        let establish = calls(Kind::Establish);
        assert_eq!(establish.len(), 3);
        assert!(establish
            .iter()
            .all(|call| call.handle == establish[0].handle));
        let writes = calls(Kind::Write);
        assert_eq!(
            writes.len(),
            4,
            "A pends twice; the distinct B request runs once"
        );
        assert!(writes[..3]
            .iter()
            .all(|call| call.handle == writes[0].handle && call.bytes == b"A"));
        assert!(!writes[0].ready && !writes[1].ready && writes[2].ready);
        assert_eq!(writes[3].bytes, b"B");
        assert!(writes[3].handle.seq > writes[2].handle.seq);
        let reads = calls(Kind::Read);
        assert_eq!(reads.len(), 3);
        assert!(reads.iter().all(|call| call.handle == reads[0].handle));
        assert!(reads[0].handle.seq > writes[3].handle.seq);
        assert_eq!(script(|s| s.accepted.clone()), b"AB");
        assert_eq!(
            script(|s| s.bodies),
            1,
            "the async body is never rebuilt on resume"
        );
    }

    fn hold_read(wire: Wire) -> Body<Result<(), ConnFailure>> {
        Box::pin(async move {
            wire.connect(0, Some("holder")).await?;
            wire.fill().await?;
            Ok(())
        })
    }

    #[test]
    fn cancelling_a_replayed_read_closes_with_a_fresh_handle_above_every_attempt() {
        let (_fake, host) = host(Mode::CancelRead);
        let pool = Pool::new(1);
        let (answer, held, attempted) = enter(&host, &pool, TICKET, None, hold_read);
        assert!(matches!(answer, Step::Pending { wake_at_ns: 0 }) && attempted);
        let (answer, held, attempted) = enter(&host, &pool, TICKET, Some(held), hold_read);
        assert!(matches!(answer, Step::Pending { wake_at_ns: 0 }) && attempted);
        let reads = calls(Kind::Read);
        assert_eq!(reads.len(), 2);
        assert_eq!(reads[0].handle, reads[1].handle);
        drop(held);
        let closed = calls(Kind::Close);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].handle.ticket, TICKET);
        assert!(
            closed[0].handle.seq > reads[0].handle.seq,
            "cleanup cannot reuse the pending read's handle"
        );
    }

    fn write_once(wire: Wire) -> Body<Result<(), ConnFailure>> {
        Box::pin(async move {
            wire.connect(0, None).await?;
            wire.write_all(b"A").await?;
            wire.close().await;
            Ok(())
        })
    }

    #[test]
    fn a_successful_zero_byte_write_retries_on_a_new_handle_after_its_timer_wait() {
        let (_fake, host) = host(Mode::ZeroWrite);
        let pool = Pool::new(1);
        finish(&host, &pool, TICKET, None, write_once);
        let writes = calls(Kind::Write);
        assert_eq!(writes.len(), 2);
        assert!(writes.iter().all(|call| call.ready && call.bytes == b"A"));
        assert_eq!((writes[0].value, writes[1].value), (0, 1));
        assert!(writes[1].handle.seq > writes[0].handle.seq);
        assert_eq!(script(|s| s.accepted.clone()), b"A");
        assert!(!script(|s| s.clocks.is_empty()));
        assert!(script(|s| s
            .clocks
            .iter()
            .all(|handle| handle.ticket.is_none())));
    }

    fn wait_then_connect(wire: Wire) -> Body<Result<(), ConnFailure>> {
        Box::pin(async move {
            assert_eq!(wire.os_user().await?, "tester");
            wire.connect(0, Some("waiter")).await?;
            wire.close().await;
            Ok(())
        })
    }

    #[test]
    fn a_pool_wait_does_not_replay_the_completed_request_that_preceded_it() {
        let (_fake, host) = host(Mode::PoolWait);
        let pool = Pool::new(1);
        let (answer, holder, _) = enter(&host, &pool, HOLDER, None, hold_read);
        assert!(matches!(answer, Step::Pending { wake_at_ns: 0 }));
        let (answer, waiting, _) = enter(&host, &pool, TICKET, None, wait_then_connect);
        assert!(matches!(answer, Step::Pending { wake_at_ns } if wake_at_ns != 0));
        let (answer, waiting, _) = enter(&host, &pool, TICKET, Some(waiting), wait_then_connect);
        assert!(matches!(answer, Step::Pending { wake_at_ns } if wake_at_ns != 0));
        assert_eq!(
            calls(Kind::Identity).len(),
            1,
            "pool retries do not rerun the prior completed Ask"
        );
        drop(holder);
        finish(&host, &pool, TICKET, Some(waiting), wait_then_connect);
        let identity = calls(Kind::Identity);
        let establish: Vec<_> = calls(Kind::Establish)
            .into_iter()
            .filter(|c| c.handle.ticket == TICKET)
            .collect();
        assert_eq!(establish.len(), 1);
        assert!(establish[0].handle.seq > identity[0].handle.seq);
        assert_eq!(script(|s| s.bodies), 2, "one body per original ticket");
    }
}

mod waiting {
    use std::ffi::c_void;
    use std::sync::{Mutex, MutexGuard, PoisonError, Weak};

    use super::*;
    use crate::abi::host::conn::connector::{ConnectorSlots, IoIn};
    use crate::abi::host::service::{ClockNowIn, HostSlots, ServiceOut};
    use crate::abi::mechanism::call::{Outcome, RawOutcome};
    use crate::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
    use crate::abi::sdk::conn::{ConnFailure, Host};
    use crate::abi::sdk::store::op::Parked;
    use crate::abi::sdk::store::wire::drive_kept;

    #[derive(Default)]
    struct Script {
        pool: Weak<Pool>,
        wakes: Vec<Ticket>,
        wake_locked: bool,
        read_ready: bool,
        now: u64,
        established: u64,
        cancel_on_wake: Option<Parked>,
    }

    static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
    }

    extern "C" fn wake(_: HostCtx, ticket: Ticket) {
        let canceled = {
            let mut script = SCRIPT.lock().unwrap();
            let script = script.as_mut().unwrap();
            script.wakes.push(ticket);
            if let Some(pool) = script.pool.upgrade() {
                script.wake_locked |= pool.st.try_lock().is_err();
            }
            script.cancel_on_wake.take()
        };
        drop(canceled);
    }

    extern "C" fn establish(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        let mut script = SCRIPT.lock().unwrap();
        let script = script.as_mut().unwrap();
        script.established += 1;
        // SAFETY: the SDK lends a writable ServiceOut for this call.
        unsafe { (*out).value = script.established };
        RawOutcome::of(Outcome::Ready)
    }

    extern "C" fn read(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        if !SCRIPT.lock().unwrap().as_ref().unwrap().read_ready {
            return RawOutcome::of(Outcome::Pending);
        }
        // SAFETY: the SDK lends an IoIn with a nonempty writable read buffer and output.
        unsafe {
            let input = &*input.cast::<IoIn>();
            *input.buf = b'x';
            (*out).len = 1;
        }
        RawOutcome::of(Outcome::Ready)
    }

    extern "C" fn close(_: HostCtx, _: *const c_void, _: *mut ServiceOut) -> RawOutcome {
        RawOutcome::of(Outcome::Ready)
    }

    extern "C" fn clock(_: HostCtx, input: *const c_void, _: *mut ServiceOut) -> RawOutcome {
        let now = SCRIPT.lock().unwrap().as_ref().unwrap().now;
        // SAFETY: the SDK lends a ClockNowIn and writable reading for this call.
        unsafe { (*(*input.cast::<ClockNowIn>()).reading).mono_ns = now };
        RawOutcome::of(Outcome::Ready)
    }

    fn host(pool: &Arc<Pool>) -> Host {
        use std::sync::OnceLock;
        static CONNS: OnceLock<ConnectorSlots> = OnceLock::new();
        static SERVICES: OnceLock<HostSlots> = OnceLock::new();
        let conns = CONNS.get_or_init(|| {
            // SAFETY: the table contains integers and optional function pointers only.
            let mut slots: ConnectorSlots = unsafe { std::mem::zeroed() };
            slots.size = std::mem::size_of::<ConnectorSlots>() as u32;
            slots.slots = crate::abi::host::conn::connector::SERVICES;
            slots.establish = Some(establish);
            slots.read = Some(read);
            slots.close = Some(close);
            slots
        });
        let services = SERVICES.get_or_init(|| {
            // SAFETY: the table contains integers and optional function pointers only.
            let mut slots: HostSlots = unsafe { std::mem::zeroed() };
            slots.size = std::mem::size_of::<HostSlots>() as u32;
            slots.slots = crate::abi::host::service::SERVICES;
            slots.clock_now = Some(clock);
            slots
        });
        *SCRIPT.lock().unwrap() = Some(Script {
            pool: Arc::downgrade(pool),
            ..Script::default()
        });
        /* SAFETY: these harness tables and callbacks are live for the snapshot. */
        unsafe {
            Host::from_raw(&HostTables {
                size: std::mem::size_of::<HostTables>() as u32,
                _reserved: 0,
                ctx: HostCtx::NONE,
                wake: Some(wake),
                conns,
                services,
                io: std::ptr::null(),
            })
        }
    }

    const HOLDER: Ticket = Ticket {
        slot: 1,
        generation: 1,
    };
    const FIRST: Ticket = Ticket {
        slot: 2,
        generation: 1,
    };
    const SECOND: Ticket = Ticket {
        slot: 3,
        generation: 1,
    };

    fn enter(
        pool: &Arc<Pool>,
        host: &Host,
        ticket: Ticket,
        parked: Option<Parked>,
        hold: bool,
        bound: u32,
    ) -> (Step<Result<(), ConnFailure>>, Parked) {
        let mut op = Op::enter(ticket, Some(host), parked, None);
        let step = drive_kept(&mut op, pool, move |wire| {
            Box::pin(async move {
                wire.bound(bound);
                wire.connect(0, None).await?;
                if hold {
                    wire.fill().await?;
                }
                Ok(())
            })
        });
        (step, op.into_parked())
    }

    fn pending(
        pool: &Arc<Pool>,
        host: &Host,
        ticket: Ticket,
        parked: Option<Parked>,
        hold: bool,
    ) -> Parked {
        let (step, parked) = enter(pool, host, ticket, parked, hold, 0);
        assert!(matches!(step, Step::Pending { .. }));
        parked
    }

    fn wakes() -> Vec<Ticket> {
        let (locked, wakes) = {
            let script = SCRIPT.lock().unwrap();
            let script = script.as_ref().unwrap();
            (script.wake_locked, script.wakes.clone())
        };
        assert!(!locked, "wake must run outside the pool lock");
        wakes
    }

    #[test]
    fn retrying_one_waiting_op_wakes_it_once_and_it_can_connect() {
        let _serial = serial();
        let pool = Pool::new(1);
        let host = host(&pool);
        let holder = pending(&pool, &host, HOLDER, None, true);
        let first = pending(&pool, &host, FIRST, None, false);
        let first = pending(&pool, &host, FIRST, Some(first), false);
        let first = pending(&pool, &host, FIRST, Some(first), false);
        drop(holder);
        assert_eq!(wakes(), vec![FIRST]);
        let (step, done) = enter(&pool, &host, FIRST, Some(first), false, 0);
        assert_eq!(step, Step::Ready(Ok(())));
        drop(done);
        assert_eq!(wakes(), vec![FIRST]);
        assert_eq!(pool.idle(), 1);
    }

    #[test]
    fn cancellation_retires_the_old_generation_before_the_slot_is_reused() {
        let _serial = serial();
        let pool = Pool::new(1);
        let host = host(&pool);
        let holder = pending(&pool, &host, HOLDER, None, true);
        drop(pending(&pool, &host, FIRST, None, false));
        let next = Ticket {
            generation: 2,
            ..FIRST
        };
        let waiting = pending(&pool, &host, next, None, false);
        drop(holder);
        assert_eq!(wakes(), vec![next]);
        drop(waiting);
    }

    #[test]
    fn cancellation_also_retires_a_waiter_already_selected_for_waking() {
        let _serial = serial();
        let pool = Pool::new(1);
        let host = host(&pool);
        let holder = pending(&pool, &host, HOLDER, None, true);
        let first = pending(&pool, &host, FIRST, None, false);
        let second = pending(&pool, &host, SECOND, None, false);
        SCRIPT.lock().unwrap().as_mut().unwrap().cancel_on_wake = Some(second);
        drop(holder);
        assert_eq!(wakes(), vec![FIRST]);
        drop(first);
    }

    #[test]
    fn a_woken_op_that_loses_the_connection_registers_again() {
        let _serial = serial();
        let pool = Pool::new(1);
        let host = host(&pool);
        let holder = pending(&pool, &host, HOLDER, None, true);
        let first = pending(&pool, &host, FIRST, None, true);
        let second = pending(&pool, &host, SECOND, None, false);
        drop(holder);
        assert_eq!(wakes(), vec![FIRST, SECOND]);
        let first = pending(&pool, &host, FIRST, Some(first), true);
        let second = pending(&pool, &host, SECOND, Some(second), false);
        let second = pending(&pool, &host, SECOND, Some(second), false);
        SCRIPT.lock().unwrap().as_mut().unwrap().read_ready = true;
        let (step, done) = enter(&pool, &host, FIRST, Some(first), true, 0);
        assert_eq!(step, Step::Ready(Ok(())));
        drop(done);
        assert_eq!(wakes(), vec![FIRST, SECOND, SECOND]);
        let (step, done) = enter(&pool, &host, SECOND, Some(second), false, 0);
        assert_eq!(step, Step::Ready(Ok(())));
        drop(done);
        let established = SCRIPT.lock().unwrap().as_ref().unwrap().established;
        assert_eq!(established, 2);
    }

    #[test]
    fn a_waiter_that_times_out_is_not_woken_when_a_connection_returns() {
        let _serial = serial();
        let pool = Pool::new(1);
        let host = host(&pool);
        let holder = pending(&pool, &host, HOLDER, None, true);
        let (step, waiting) = enter(&pool, &host, FIRST, None, false, 1);
        assert!(matches!(step, Step::Pending { .. }));
        SCRIPT.lock().unwrap().as_mut().unwrap().now = 1_000_000;
        let (step, done) = enter(&pool, &host, FIRST, Some(waiting), false, 1);
        assert!(matches!(step, Step::Ready(Err(ConnFailure::Failed(_)))));
        drop(done);
        drop(holder);
        assert!(wakes().is_empty());
    }
}
