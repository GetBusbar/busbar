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
