// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Credential writes through the real Wire/drive/host seam, including parked cancellation.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::task::{Context, Poll};

use super::{drive_kept, Body, Pool, Wire};
use crate::abi::host::conn::connector::{ConnectorSlots, FactsIn, IoIn, StreamFacts};
use crate::abi::host::service::ServiceOut;
use crate::abi::mechanism::call::{Outcome, RawOutcome};
use crate::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use crate::abi::sdk::conn::{ConnFailure, Host};
use crate::abi::sdk::cred::{Cred, Seal, NOT_SECURE};
use crate::abi::sdk::store::op::Parked;
use crate::abi::sdk::store::{Op, Step};
use crate::alloc_counter::InitializedPayloadProbe;

pub(super) fn watch(bytes: &[u8]) {
    // SAFETY: Output passes its owned allocation's initialized base prefix. Probe scopes below
    // keep every observed owner on this thread through deallocation, without retyping its bytes.
    unsafe { crate::alloc_counter::watch_initialized_payload(bytes) }
}

#[derive(Clone, Copy, Default)]
enum Security {
    #[default]
    Clear,
    Secure,
    Pending,
    Replay,
    Failed,
}

enum Write {
    Take(usize),
    Pending,
    Fail,
}

#[derive(Default)]
struct Script {
    security: Security,
    facts: usize,
    writes: VecDeque<Write>,
    offered: Vec<Vec<u8>>,
    accepted: Vec<u8>,
    established: u64,
    closed: usize,
}

static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn script<R>(f: impl FnOnce(&mut Script) -> R) -> R {
    f(SCRIPT.lock().unwrap().as_mut().unwrap())
}

extern "C" fn establish(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let stream = script(|s| {
        s.established += 1;
        s.established
    });
    // SAFETY: the connector lends its writable result for this call.
    unsafe { (*out).value = stream };
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn facts(_: HostCtx, input: *const c_void, _: *mut ServiceOut) -> RawOutcome {
    let security = script(|s| {
        s.facts += 1;
        s.security
    });
    match security {
        Security::Pending => return RawOutcome::of(Outcome::Pending),
        Security::Failed => return RawOutcome::of(Outcome::Failed),
        Security::Replay => return RawOutcome::of(Outcome::Ready),
        Security::Clear | Security::Secure => {}
    }
    // SAFETY: the connector lends FactsIn and its writable facts slot for this call.
    unsafe {
        let slot = &mut *(*input.cast::<FactsIn>()).facts;
        slot.size = std::mem::size_of::<StreamFacts>() as u32;
        slot.secure = u32::from(matches!(security, Security::Secure));
    }
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn upgrade(_: HostCtx, _: *const c_void, _: *mut ServiceOut) -> RawOutcome {
    script(|s| s.security = Security::Secure);
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn write(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the connector lends IoIn's initialized bytes and writable result for this call only.
    let bytes = unsafe {
        let input = &*input.cast::<IoIn>();
        std::slice::from_raw_parts(input.buf, input.len)
    };
    script(|s| {
        s.offered.push(bytes.to_vec());
        match s.writes.pop_front().unwrap_or(Write::Take(usize::MAX)) {
            Write::Pending => RawOutcome::of(Outcome::Pending),
            Write::Fail => RawOutcome::of(Outcome::Failed),
            Write::Take(n) => {
                let n = n.min(bytes.len());
                s.accepted.extend_from_slice(&bytes[..n]);
                // SAFETY: the SDK lends a writable ServiceOut for this call.
                unsafe { (*out).len = n as u64 };
                RawOutcome::of(Outcome::Ready)
            }
        }
    })
}

extern "C" fn close(_: HostCtx, _: *const c_void, _: *mut ServiceOut) -> RawOutcome {
    script(|s| s.closed += 1);
    RawOutcome::of(Outcome::Ready)
}

fn make_host(security: Security, has_facts: bool, writes: impl IntoIterator<Item = Write>) -> Host {
    static CONNS: OnceLock<ConnectorSlots> = OnceLock::new();
    static NO_FACTS: OnceLock<ConnectorSlots> = OnceLock::new();
    let slots = || {
        // SAFETY: ConnectorSlots contains only integers and optional function pointers.
        let mut slots: ConnectorSlots = unsafe { std::mem::zeroed() };
        slots.size = std::mem::size_of::<ConnectorSlots>() as u32;
        slots.slots = crate::abi::host::conn::connector::SERVICES;
        slots.establish = Some(establish);
        slots.facts = Some(facts);
        slots.upgrade_secure = Some(upgrade);
        slots.write = Some(write);
        slots.close = Some(close);
        slots
    };
    let conns = if has_facts {
        CONNS.get_or_init(slots)
    } else {
        NO_FACTS.get_or_init(|| ConnectorSlots {
            facts: None,
            ..slots()
        })
    };
    *SCRIPT.lock().unwrap() = Some(Script {
        security,
        writes: writes.into_iter().collect(),
        ..Script::default()
    });
    /* SAFETY: these harness tables and callbacks are live for the snapshot. */
    unsafe {
        Host::from_raw(&HostTables {
            size: std::mem::size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx::NONE,
            wake: None,
            conns,
            services: std::ptr::null(),
            io: std::ptr::null(),
        })
    }
}

const TICKET: Ticket = Ticket {
    slot: 7,
    generation: 3,
};
const CANARY: &[u8] = b"store-CANARY-credential";
type Answer = Result<(), ConnFailure>;
type Retained = Arc<Mutex<Option<Wire>>>;

fn seal(required: bool) -> Seal {
    let cred = Cred::captured(zeroize::Zeroizing::new(CANARY.to_vec()));
    if required {
        cred.secure_for("https://store.example").field()
    } else {
        cred.field()
    }
}

fn enter(
    pool: &Arc<Pool>,
    host: &Host,
    parked: Option<Parked>,
    body: impl FnOnce(Wire) -> Body<Answer>,
) -> (Step<Answer>, Parked) {
    let mut op = Op::enter(TICKET, Some(host), parked, None);
    let answer = drive_kept(&mut op, pool, body);
    (answer, op.into_parked())
}

fn start(required: bool, retained: Retained) -> impl FnOnce(Wire) -> Body<Answer> {
    move |wire| {
        Box::pin(async move {
            *retained.lock().unwrap() = Some(wire.clone());
            wire.connect(0, None).await?;
            wire.write_sealed(seal(required)).await
        })
    }
}

fn finish_probe(probe: InitializedPayloadProbe, minimum: usize) {
    let observed = probe.finish();
    assert!(!observed.reentered, "observer reentered the allocator");
    assert!(observed.payloads.len() >= minimum, "output was observed");
    for payload in observed.payloads {
        assert!(payload.freed, "output allocation survived: {payload:?}");
        assert!(!payload.reallocated, "output used unwiped Vec growth");
        #[cfg(target_os = "linux")]
        {
            assert_eq!(payload.read_error, None);
            assert!(payload.complete_read, "incomplete observation: {payload:?}");
            assert_eq!(payload.bytes_read, payload.len);
            assert!(payload.wiped, "output reached free unwiped: {payload:?}");
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(payload.read_error, Some(std::io::ErrorKind::Unsupported));
            assert!(!payload.complete_read);
        }
    }
}

#[test]
fn required_seals_refuse_clear_missing_failed_and_replayed_facts_and_are_not_kept() {
    let _serial = serial();
    for (security, has_facts) in [
        (Security::Clear, true),
        (Security::Clear, false),
        (Security::Failed, true),
        (Security::Replay, true),
    ] {
        let pool = Pool::new(1);
        let host = make_host(security, has_facts, []);
        let retained = Retained::default();
        let (step, parked) = enter(&pool, &host, None, start(true, retained.clone()));
        assert_eq!(
            step,
            Step::Ready(Err(ConnFailure::Refused(NOT_SECURE.into())))
        );
        assert!(script(|s| s.offered.is_empty()));
        assert!(retained
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .state()
            .out
            .remaining()
            .is_empty());
        drop(parked);
        assert_eq!(pool.live(), 0);
        assert_eq!(pool.idle(), 0);
        assert_eq!(script(|s| s.closed), 1);
    }
}

#[test]
fn pending_facts_write_nothing_then_secure_facts_and_partial_resume_send_exactly_once() {
    let _serial = serial();
    let pool = Pool::new(1);
    let host = make_host(Security::Pending, true, [Write::Take(3), Write::Pending]);
    let retained = Retained::default();
    let (step, parked) = enter(&pool, &host, None, start(true, retained.clone()));
    assert!(matches!(step, Step::Pending { wake_at_ns: 0 }));
    assert!(script(|s| s.offered.is_empty()));
    script(|s| s.security = Security::Secure);
    let (step, parked) = enter(&pool, &host, Some(parked), |_| panic!("restarted body"));
    assert!(matches!(step, Step::Pending { .. }));
    assert_eq!(script(|s| s.accepted.clone()), &CANARY[..3]);
    {
        let wire = retained.lock().unwrap();
        let st = wire.as_ref().unwrap().state();
        assert_eq!(
            &st.out.bytes[..3],
            &[0; 3],
            "consumed bytes wiped while parked"
        );
        assert_eq!(st.out.remaining(), &CANARY[3..]);
    }
    script(|s| s.writes.extend([Write::Take(2), Write::Take(usize::MAX)]));
    let (step, parked) = enter(&pool, &host, Some(parked), |_| panic!("restarted body"));
    assert_eq!(step, Step::Ready(Ok(())));
    assert_eq!(script(|s| s.accepted.clone()), CANARY);
    assert_eq!(
        script(|s| s.facts),
        2,
        "completed facts are retained across writes"
    );
    assert_eq!(pool.idle(), 1);
    drop(parked);
    drop(pool);
    assert_eq!(script(|s| s.closed), 1);
}

#[test]
fn security_refusal_is_latched_even_if_the_host_later_reports_secure() {
    let _serial = serial();
    let pool = Pool::new(1);
    let host = make_host(Security::Clear, true, []);
    let (step, parked) = enter(&pool, &host, None, |wire| {
        Box::pin(async move {
            wire.connect(0, None).await?;
            assert!(wire.write_sealed(seal(true)).await.is_err());
            wire.upgrade_secure(None).await?;
            wire.write_sealed(seal(true)).await
        })
    });
    assert_eq!(
        step,
        Step::Ready(Err(ConnFailure::Refused(NOT_SECURE.into())))
    );
    assert_eq!(script(|s| s.facts), 1);
    assert!(script(|s| s.offered.is_empty()));
    assert_eq!(pool.idle(), 0);
    drop(parked);
}

#[test]
fn replacing_a_refused_connection_checks_fresh_upgrade_facts_and_can_be_kept() {
    let _serial = serial();
    let pool = Pool::new(1);
    let host = make_host(Security::Clear, true, []);
    let (step, parked) = enter(&pool, &host, None, |wire| {
        Box::pin(async move {
            wire.connect(0, None).await?;
            assert!(wire.write_sealed(seal(true)).await.is_err());
            wire.reconnect().await?;
            wire.upgrade_secure(None).await?;
            wire.write_sealed(seal(true)).await
        })
    });
    assert_eq!(step, Step::Ready(Ok(())));
    assert_eq!(script(|s| s.accepted.clone()), CANARY);
    assert_eq!(script(|s| s.established), 2);
    assert_eq!(script(|s| s.facts), 2);
    assert_eq!(pool.idle(), 1);
    drop(parked);
    drop(pool);
    assert_eq!(script(|s| s.closed), 2);
}

#[test]
fn ordinary_writes_and_clear_permitted_seals_still_work_without_facts() {
    let _serial = serial();
    let pool = Pool::new(1);
    let host = make_host(Security::Clear, false, [Write::Take(2), Write::Take(0)]);
    let (step, parked) = enter(&pool, &host, None, |wire| {
        Box::pin(async move {
            wire.connect(0, None).await?;
            wire.write_all(b"public").await?;
            wire.write_sealed(seal(false)).await
        })
    });
    assert!(matches!(step, Step::Pending { .. }));
    let (step, parked) = enter(&pool, &host, Some(parked), |_| panic!("restarted body"));
    assert_eq!(step, Step::Ready(Ok(())));
    assert_eq!(
        script(|s| s.accepted.clone()),
        [b"public".as_slice(), CANARY].concat()
    );
    assert_eq!(script(|s| s.facts), 0);
    drop(parked);
    drop(pool);
}

#[test]
fn partial_write_cancellation_wipes_output_even_when_a_wire_clone_survives() {
    let _serial = serial();
    let pool = Pool::new(1);
    let host = make_host(Security::Secure, true, [Write::Take(4), Write::Pending]);
    let retained = Retained::default();
    // SAFETY: every instrumented output stays exclusively owned on this thread through drop.
    let probe = unsafe { InitializedPayloadProbe::start().expect("open memory observer") };
    let (step, parked) = enter(&pool, &host, None, start(true, retained.clone()));
    assert!(matches!(step, Step::Pending { .. }));
    drop(parked);
    assert_eq!(pool.live(), 0);
    assert_eq!(pool.idle(), 0);
    assert_eq!(script(|s| s.closed), 1);
    assert_eq!(script(|s| s.accepted.clone()), &CANARY[..4]);
    let wire = retained.lock().unwrap().take().unwrap();
    assert!(
        wire.state().out.remaining().is_empty(),
        "retained clone lost unsent output"
    );
    drop(wire);
    finish_probe(probe, 1);
}

#[test]
fn write_error_wipes_all_output_and_disqualifies_the_partial_connection() {
    let _serial = serial();
    let pool = Pool::new(1);
    let host = make_host(Security::Secure, true, [Write::Take(4), Write::Fail]);
    let retained = Retained::default();
    // SAFETY: observed initialized output is freed here on this thread.
    let probe = unsafe { InitializedPayloadProbe::start().expect("open memory observer") };
    let (step, parked) = enter(&pool, &host, None, start(true, retained.clone()));
    assert!(matches!(step, Step::Ready(Err(ConnFailure::Failed(_)))));
    drop(parked);
    assert_eq!(pool.live(), 0);
    assert_eq!(script(|s| s.accepted.clone()), &CANARY[..4]);
    drop(retained.lock().unwrap().take());
    finish_probe(probe, 1);
}

#[test]
fn successful_output_growth_and_body_unwind_wipe_every_owned_allocation() {
    let _serial = serial();
    let pool = Pool::new(1);
    let host = make_host(Security::Clear, false, []);
    // SAFETY: all output owners, including the body unwound below, stay on this thread.
    let probe = unsafe { InitializedPayloadProbe::start().expect("open memory observer") };
    let (step, parked) = enter(&pool, &host, None, |wire| {
        Box::pin(async move {
            wire.connect(0, None).await?;
            wire.write_all(b"short").await?;
            wire.write_all(&[b'x'; 2048]).await
        })
    });
    assert_eq!(step, Step::Ready(Ok(())));
    drop(parked);
    finish_probe(probe, 2);
    drop(pool);

    let pool = Pool::new(1);
    let host = make_host(Security::Secure, true, [Write::Pending]);
    let retained = Retained::default();
    // SAFETY: cancelled output is kept on this thread, then freed before observation ends.
    let probe = unsafe { InitializedPayloadProbe::start().expect("open memory observer") };
    let (step, parked) = enter(&pool, &host, None, start(true, retained.clone()));
    assert!(matches!(step, Step::Pending { .. }));
    drop(parked);
    drop(retained.lock().unwrap().take());
    finish_probe(probe, 1);

    struct Fault {
        body: Body<Answer>,
        fault: Arc<AtomicBool>,
    }
    impl Future for Fault {
        type Output = Answer;
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Answer> {
            assert!(!self.fault.load(Ordering::Relaxed), "body fault");
            self.body.as_mut().poll(cx)
        }
    }
    let fault = Arc::new(AtomicBool::new(false));
    script(|s| s.writes.push_back(Write::Pending));
    // SAFETY: output remains on this thread through the panic and destruction below.
    let probe = unsafe { InitializedPayloadProbe::start().expect("open memory observer") };
    let (step, parked) = enter(&pool, &host, None, {
        let fault = fault.clone();
        let retained = retained.clone();
        move |wire| {
            Box::pin(Fault {
                body: start(true, retained)(wire),
                fault,
            })
        }
    });
    assert!(matches!(step, Step::Pending { .. }));
    fault.store(true, Ordering::Relaxed);
    let mut op = Op::enter(TICKET, Some(&host), Some(parked), None);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drive_kept(&mut op, &pool, |_| -> Body<Answer> {
            panic!("restarted body")
        })
    }));

    drop(op.into_parked());
    assert!(result.is_err());
    assert!(retained
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .state()
        .out
        .remaining()
        .is_empty());
    drop(retained.lock().unwrap().take());
    finish_probe(probe, 1);
    assert_eq!(pool.live(), 0);
}

#[test]
fn dropping_an_in_body_write_future_wipes_it_and_prevents_pool_reuse() {
    let _serial = serial();
    let pool = Pool::new(1);
    let host = make_host(Security::Secure, true, [Write::Pending]);
    let (step, parked) = enter(&pool, &host, None, |wire| {
        Box::pin(async move {
            wire.connect(0, None).await?;
            let mut write = Box::pin(wire.write_sealed(seal(true)));
            std::future::poll_fn(|cx| {
                assert!(write.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(write);
            Ok(())
        })
    });
    assert_eq!(step, Step::Ready(Ok(())));
    assert!(script(|s| s.offered.is_empty()));
    assert_eq!(pool.idle(), 0);
    drop(parked);
}

#[test]
fn growing_live_output_wipes_the_previous_credential_allocation() {
    let _serial = serial();
    let pool = Pool::new(1);
    let host = make_host(Security::Secure, true, []);
    // SAFETY: both output allocations remain owned and are destroyed on this thread below.
    let probe = unsafe { InitializedPayloadProbe::start().expect("open memory observer") };
    let (step, parked) = enter(&pool, &host, None, |wire| {
        Box::pin(async move {
            wire.connect(0, None).await?;
            let mut first = Box::pin(wire.write_sealed(seal(true)));
            std::future::poll_fn(|cx| {
                assert!(first.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;

            let public = [b'x'; 2048];
            let mut second = Box::pin(wire.write_all(&public));
            std::future::poll_fn(|cx| {
                assert!(second.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(second);
            drop(first);
            Ok(())
        })
    });
    assert_eq!(step, Step::Ready(Ok(())));
    assert_eq!(pool.idle(), 0);
    assert!(script(|s| s.offered.is_empty()));
    drop(parked);
    finish_probe(probe, 2);
}

#[test]
fn a_kept_connection_requires_fresh_secure_facts_for_the_next_credential() {
    let _serial = serial();
    let pool = Pool::new(1);
    let host = make_host(Security::Secure, true, []);
    let (step, parked) = enter(&pool, &host, None, start(true, Retained::default()));
    assert_eq!(step, Step::Ready(Ok(())));
    drop(parked);
    assert_eq!(pool.idle(), 1);
    script(|s| s.security = Security::Clear);
    let (step, parked) = enter(&pool, &host, None, |wire| {
        Box::pin(async move {
            wire.connect(0, None).await?;
            assert!(wire.reused());
            wire.write_sealed(seal(true)).await
        })
    });
    assert_eq!(
        step,
        Step::Ready(Err(ConnFailure::Refused(NOT_SECURE.into())))
    );
    assert_eq!(script(|s| s.accepted.clone()), CANARY);
    assert_eq!(script(|s| s.established), 1);
    assert_eq!(script(|s| s.facts), 2);
    assert_eq!(pool.idle(), 0);
    drop(parked);
    assert_eq!(script(|s| s.closed), 1);
}
