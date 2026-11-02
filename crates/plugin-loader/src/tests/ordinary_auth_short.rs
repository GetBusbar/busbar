// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::auth_axis::AuthRows;
use crate::dispatch::{DispatchConfig, Dispatcher};
use crate::{LinkedPlugin, PluginRegistry};
use busbar_contract::abi::auth::{AuthPoints, Ops, DECISION_CONTINUE};
use busbar_contract::abi::auth::{IdentifyOut, VerifyIn, VERDICT_IDENTITY};
use busbar_contract::abi::mechanism::call::RawOutcome;
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_contract::abi::sdk::auth_door::{
    short_reply, verify_tail, with_tail, Answer, Verdict, VerifiedIdentity, VerifyPlugin,
    VerifyView,
};
use busbar_contract::abi::sdk::door::blank_out;
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::auth_calls::{Verified, VerifyRequest};
use std::ffi::c_void;
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;
use std::sync::{mpsc, Condvar, Mutex, OnceLock, PoisonError};
use std::time::Duration;

static SUBJECT: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| "s".repeat(busbar_contract::abi::auth::IDENTITY_BUF_BYTES + 1));

static SERIAL: Mutex<()> = Mutex::new(());
static VERIFIES: AtomicUsize = AtomicUsize::new(0);
static RELEASES: AtomicUsize = AtomicUsize::new(0);
static JUDGMENTS: AtomicUsize = AtomicUsize::new(0);
static RELEASE_GATE: Mutex<Option<Arc<ReleaseGate>>> = Mutex::new(None);
static BARRIER_FROM_WORKER: Mutex<Option<Arc<Dispatcher>>> = Mutex::new(None);
static SAME_WORKER_SEEN: AtomicBool = AtomicBool::new(false);
static SAME_WORKER_REJECTED: AtomicBool = AtomicBool::new(false);

#[derive(Default)]
struct ReleaseGate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

pub struct Probe;
impl VerifyPlugin for Probe {
    fn open(_: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
        Ok(Self)
    }

    fn verify(&self, _: &VerifyView<'_>) -> Answer {
        JUDGMENTS.fetch_add(1, Ordering::SeqCst);
        Verdict::Identity(VerifiedIdentity {
            subject: SUBJECT.to_string(),
            ..Default::default()
        })
        .into()
    }
}

mod real {
    use super::*;
    busbar_contract::auth_verify_door!(
        Probe,
        with_tail(
            statement("short-pin", "1.0.0", 8),
            &verify_tail(0, AuthPoints::HEAD)
        )
    );
}

fn real_ops() -> &'static Ops {
    // SAFETY: this exact descriptor is emitted by the real auth SDK macro above; its complete
    // immutable table and all nested backing remain static for the process.
    unsafe { &*real::door().ops().cast::<Ops>() }
}

extern "C" fn retained_verify(
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    VERIFIES.fetch_add(1, Ordering::SeqCst);
    let same_worker = BARRIER_FROM_WORKER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(dispatcher) = same_worker {
        // SAFETY: this selected VERIFY's complete input remains borrowed for this wrapper.
        let ticket = unsafe { (&*input.cast::<VerifyIn>()).head.ticket };
        SAME_WORKER_SEEN.store(dispatcher.current_worker().is_some(), Ordering::SeqCst);

        SAME_WORKER_REJECTED.store(
            !dispatcher.retirement_barrier(ticket, Duration::from_secs(60)),
            Ordering::SeqCst,
        );
    }
    // SAFETY: this wrapper occupies VERIFY and forwards the original live SDK instance,
    // exclusive complete host frames and nested loans unchanged through its original slot.
    unsafe { real_ops().verify.unwrap()(instance, input, out) }
}

extern "C" fn release(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    let gate = RELEASE_GATE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if let Some(gate) = gate {
        let mut state = gate.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.0 = true;
        gate.changed.notify_all();

        drop(
            gate.changed
                .wait_timeout_while(state, Duration::from_secs(30), |state| !state.1)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }
    RELEASES.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the loader returns this real SDK lease to the same still-live instance, using
    // its exact initialized ReleaseIn/OutHead frames before they leave the crossing.
    unsafe { real_ops().head.release.unwrap()(instance, input, out) }
}

extern "C" fn static_verify(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    VERIFIES.fetch_add(1, Ordering::SeqCst);
    // SAFETY: this fixture is installed only in VERIFY over the loader's complete frames.
    let input = unsafe { &*input.cast::<VerifyIn>() };
    let mut answer: IdentifyOut = blank_out();
    answer.head.size = std::mem::size_of::<IdentifyOut>() as u32;
    let outcome = if input.out_buf.buf_cap < SUBJECT.len() {
        answer.needed_bytes = SUBJECT.len() as u64;
        Outcome::Failed
    } else {
        // SAFETY: the initialized exclusive host identity buffer covers SUBJECT's bytes;
        // immutable static source bytes do not overlap it and no allocation is retained.
        unsafe {
            std::ptr::copy_nonoverlapping(SUBJECT.as_ptr(), input.out_buf.buf, SUBJECT.len());
        }
        answer.verdict = VERDICT_IDENTITY;
        answer.decision = DECISION_CONTINUE;
        answer.identity.subject = Span {
            offset: 0,
            len: SUBJECT.len() as u32,
        };
        Outcome::Ready
    };
    answer.head.outcome = RawOutcome::of(outcome);
    // SAFETY: the original host output remains exclusive and covers this complete IdentifyOut.
    unsafe { out.cast::<IdentifyOut>().write(answer) };
    RawOutcome::of(outcome)
}

fn wrapped(static_reply: bool) -> Door {
    let real = real::door();
    let mut ops = *real_ops();
    ops.verify = Some(if static_reply {
        static_verify
    } else {
        retained_verify
    });
    ops.head.release = Some(release);
    let ops = Box::leak(Box::new(ops));
    // SAFETY: the genuine SDK descriptor supplies immutable static Statement/tail data. The
    // leaked full table preserves every other slot; replacements keep their original ABI.
    unsafe {
        Door::__from_parts(DoorParts {
            ops: std::ptr::from_ref(ops).cast(),
            ..real.parts()
        })
        .__with_migrate(real.migrate())
    }
}

extern "C" fn retained_door() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let address = *DOOR.get_or_init(|| Box::into_raw(Box::new(wrapped(false))) as usize);
    // SAFETY: this immutable SDK descriptor and its table are leaked for the process lifetime.
    unsafe { &*(address as *const Door) }
}

extern "C" fn static_door() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let address = *DOOR.get_or_init(|| Box::into_raw(Box::new(wrapped(true))) as usize);
    // SAFETY: this immutable SDK descriptor and its table are leaked for the process lifetime.
    unsafe { &*(address as *const Door) }
}

fn opened(
    static_reply: bool,
) -> (
    Arc<Dispatcher>,
    Arc<dyn busbar_contract::auth_calls::AuthCalls>,
) {
    VERIFIES.store(0, Ordering::SeqCst);
    RELEASES.store(0, Ordering::SeqCst);
    JUDGMENTS.store(0, Ordering::SeqCst);
    SAME_WORKER_SEEN.store(false, Ordering::SeqCst);
    SAME_WORKER_REJECTED.store(false, Ordering::SeqCst);
    let door: DoorFn = if static_reply {
        static_door
    } else {
        retained_door
    };
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::auth_door_named(
            "short-pin",
            "short-pin",
            door,
        )])
        .unwrap();
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let rows = AuthRows::new(Arc::new(registry), dispatcher.clone());
    let auth = rows
        .open("short-pin", "short-pin", &serde_json::json!({}))
        .unwrap();
    (dispatcher, auth)
}
fn request() -> VerifyRequest {
    VerifyRequest {
        point: busbar_contract::abi::auth::AuthPoint::Head,
        ..Default::default()
    }
}
fn verify(auth: &dyn busbar_contract::auth_calls::AuthCalls) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let answer = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(10),
            Box::into_pin(auth.verify(request())),
        )
        .await
        .expect("the verify settles")
    });
    let Verified::Identity(identity) = answer.verified else {
        panic!("identity refused");
    };
    assert_eq!(identity.subject, SUBJECT.as_str());
}
#[test]
fn actual_retained_short_decision_is_judged_once_and_its_lease_released_once() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_, auth) = opened(false);
    verify(&*auth);
    assert_eq!(
        (
            VERIFIES.load(Ordering::SeqCst),
            RELEASES.load(Ordering::SeqCst),
            JUDGMENTS.load(Ordering::SeqCst)
        ),
        (2, 1, 1)
    );
}
#[test]
fn actual_static_short_decision_copies_without_a_reply_lease() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_, auth) = opened(true);
    verify(&*auth);
    assert_eq!(
        (
            VERIFIES.load(Ordering::SeqCst),
            RELEASES.load(Ordering::SeqCst),
            JUDGMENTS.load(Ordering::SeqCst)
        ),
        (2, 0, 0)
    );
}

#[test]
fn actual_submitted_short_fences_release_and_rejects_same_worker_wait() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (dispatcher, auth) = opened(false);
    let gate = Arc::new(ReleaseGate::default());
    *RELEASE_GATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(gate.clone());
    *BARRIER_FROM_WORKER
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(dispatcher);
    let (finished, received) = mpsc::channel();
    let client = std::thread::spawn(move || {
        verify(&*auth);
        finished.send(()).unwrap();
    });
    let state = gate.state.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut state, _) = gate
        .changed
        .wait_timeout_while(state, Duration::from_secs(10), |state| !state.0)
        .unwrap_or_else(PoisonError::into_inner);
    let entered = state.0;
    let returned_before_cleanup = received.recv_timeout(Duration::from_millis(100)).is_ok();
    let during = (
        VERIFIES.load(Ordering::SeqCst),
        RELEASES.load(Ordering::SeqCst),
        JUDGMENTS.load(Ordering::SeqCst),
    );
    state.1 = true;
    drop(state);
    gate.changed.notify_all();
    RELEASE_GATE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    BARRIER_FROM_WORKER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    client.join().expect("the actual verify caller completes");
    assert!(entered, "the actual SDK reply lease reached RELEASE");
    assert!(
        !returned_before_cleanup,
        "answer publication is not lease retirement"
    );
    assert_eq!(during, (2, 0, 1));
    assert!(SAME_WORKER_SEEN.load(Ordering::SeqCst));
    assert!(SAME_WORKER_REJECTED.load(Ordering::SeqCst));
    assert_eq!(
        (
            VERIFIES.load(Ordering::SeqCst),
            RELEASES.load(Ordering::SeqCst),
            JUDGMENTS.load(Ordering::SeqCst)
        ),
        (2, 1, 1)
    );
}
