// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::conformance::{dispatcher, exact, StaticDoor};
use busbar_contract::abi::auth::{AuthPoints, Ops, DECISION_CONTINUE};
use busbar_contract::abi::mechanism::call::RawOutcome;
use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_contract::abi::sdk::auth_door::{
    short_reply, verify_tail, with_tail, Answer, Verdict, VerifiedIdentity, VerifyPlugin,
    VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{mpsc, Condvar, Mutex, OnceLock, PoisonError};

const SUBJECT: &str = "short-pin-subject";
const LABEL: &str = "verify short, re-called";
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
            subject: SUBJECT.into(),
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
    let mut answer: IdentifyOut = output();
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

fn wrapped(static_reply: bool) -> StaticDoor {
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
        StaticDoor::new(
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
            .__with_migrate(real.migrate()),
        )
    }
}

extern "C" fn retained_door() -> &'static Door {
    static DOOR: OnceLock<StaticDoor> = OnceLock::new();
    DOOR.get_or_init(|| wrapped(false)).get()
}

extern "C" fn static_door() -> &'static Door {
    static DOOR: OnceLock<StaticDoor> = OnceLock::new();
    DOOR.get_or_init(|| wrapped(true)).get()
}

fn opened(static_reply: bool) -> (Arc<Dispatcher>, Plugin<Auth>, Presented) {
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
    let s = Subject::new(door, "unused", "{}");
    let d = dispatcher();
    let p = load::<Auth>(&s, Leg::Linked, s.bind(&d, "short-pin")).unwrap();
    assert_eq!(open(&p, b"{}").outcome, Outcome::Ready);
    let case = Presented::new(
        &serde_json::json!({
            "credential": null, "lines": {}, "verdict": format!("identity:{SUBJECT}")
        }),
        false,
    );
    (d, p, case)
}

fn counts() -> (usize, usize, usize) {
    (
        VERIFIES.load(Ordering::SeqCst),
        RELEASES.load(Ordering::SeqCst),
        JUDGMENTS.load(Ordering::SeqCst),
    )
}

#[test]
fn retained_short_pin_counts_cleanup_and_rejects_an_extra_verify_or_missing_release() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let storage = ShortReply::of(&serde_json::json!({}));
    assert_eq!(storage, ShortReply::Retained);

    {
        let (_d, p, mut case) = opened(false);
        let mut rec = Recorder::new(crossings(&p));
        rec.line(LABEL, storage.crossings(), || {
            verify_short(&p, &mut case, storage)
        });
        let fold = rec.fold();
        exact(&fold).unwrap();
        assert_eq!(fold[0].crossed, 3);
        assert!(fold[0]
            .answer
            .ends_with(&format!("verdict=Identity({SUBJECT})")));
        assert_eq!(counts(), (2, 1, 1), "VERIFY, RELEASE, actual judgments");
        assert_eq!(close(&p).outcome, Outcome::Ready);
    }

    {
        let (_d, p, mut case) = opened(false);
        let mut rec = Recorder::new(crossings(&p));
        rec.line(LABEL, storage.crossings(), || {
            let answer = verify_short(&p, &mut case, storage);
            assert!(verify_now(&p, &mut case).ends_with(&format!("verdict=Identity({SUBJECT})")));
            answer
        });
        let fold = rec.fold();
        let error = exact(&fold).expect_err("an extra VERIFY must be refused");
        assert!(error.contains("4 crossing(s), pinned 3"), "{error}");
        assert_eq!(counts(), (3, 1, 2));
        assert_eq!(close(&p).outcome, Outcome::Ready);
    }

    {
        let (_d, p, mut case) = opened(false);
        let mut rec = Recorder::new(crossings(&p));
        let held = rec.step(LABEL, storage.crossings(), || {
            let mut frame = case.frame(false);
            let mut first = p.call(slot::VERIFY, &mut frame);
            let token = first.recall.take().expect("the real short recall token");
            storage.check_lease(true, frame.out.head.lease);
            let reference = short_reply::encode(frame.out.head.lease);
            frame.input.head.extensions = Blob {
                ptr: reference.as_ptr(),
                len: reference.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            };
            frame.input.out_buf = case.buf(true);
            let copied = p.call(slot::VERIFY, &mut frame);
            assert_eq!(copied.outcome, Outcome::Ready);
            assert!(case
                .verdict(copied.outcome, &frame.out)
                .ends_with(&format!("verdict=Identity({SUBJECT})")));
            (
                "same retained decision copied; cleanup still held".into(),
                token,
            )
        });
        let fold = rec.fold();
        let error = exact(&fold).expect_err("missing RELEASE must be refused");
        assert!(error.contains("2 crossing(s), pinned 3"), "{error}");
        assert_eq!(counts(), (2, 0, 1));
        drop(held);
        assert_eq!(
            counts(),
            (2, 1, 1),
            "the actual held lease releases exactly once"
        );
        assert_eq!(close(&p).outcome, Outcome::Ready);
    }
}

#[test]
fn an_unleased_static_short_reply_requires_its_explicit_storage_declaration() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let storage = ShortReply::of(&serde_json::json!({"short_reply": "static"}));
    {
        let (_d, p, mut case) = opened(true);
        let mut rec = Recorder::new(crossings(&p));
        rec.line(LABEL, storage.crossings(), || {
            verify_short(&p, &mut case, storage)
        });
        let fold = rec.fold();
        exact(&fold).unwrap();
        assert_eq!(fold[0].crossed, 2);
        assert!(fold[0]
            .answer
            .ends_with(&format!("verdict=Identity({SUBJECT})")));
        assert_eq!(counts(), (2, 0, 0));
        assert_eq!(close(&p).outcome, Outcome::Ready);
    }
    for (static_reply, declared) in [(true, ShortReply::Retained), (false, ShortReply::Static)] {
        let (_d, p, mut case) = opened(static_reply);
        let mismatch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_short(&p, &mut case, declared)
        }));
        assert!(
            mismatch.is_err(),
            "the declared SHORT storage must match its real lease"
        );
        if !static_reply {
            assert_eq!(
                counts(),
                (1, 1, 1),
                "mismatched declaration still returns the SDK lease"
            );
        }
        assert_eq!(close(&p).outcome, Outcome::Ready);
    }
}

#[test]
fn submitted_short_fences_actual_release_and_rejects_same_worker_wait() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (d, p, case) = opened(false);
    let gate = Arc::new(ReleaseGate::default());
    *RELEASE_GATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&gate));
    *BARRIER_FROM_WORKER
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&d));
    let (finished, received) = mpsc::channel();
    let client = std::thread::spawn(move || {
        let storage = ShortReply::of(&serde_json::json!({}));
        let mut rec = Recorder::new(crossings(&p));
        rec.line(LABEL, storage.crossings(), || {
            verify_short_submitted(&p, &d, &case, storage)
        });
        let fold = rec.fold();
        let _ = finished.send(());
        (fold, p, d)
    });
    let state = gate.state.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut state, _) = gate
        .changed
        .wait_timeout_while(state, SUBMIT_WAIT, |state| !state.0)
        .unwrap_or_else(PoisonError::into_inner);
    let entered = state.0;
    let returned_before_cleanup = received.recv_timeout(Duration::from_millis(100)).is_ok();
    let during = counts();

    state.1 = true;
    drop(state);
    gate.changed.notify_all();
    let retired = RELEASE_GATE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    drop(retired);
    let retired = BARRIER_FROM_WORKER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    drop(retired);
    let (fold, p, _d) = client.join().expect("the submitted SHORT caller completes");
    assert!(entered, "the real deferred RELEASE reached its gate");
    assert!(
        !returned_before_cleanup,
        "Done publication is not completed lease retirement"
    );
    assert_eq!(
        during,
        (2, 0, 1),
        "no original RELEASE forwarded while gated"
    );
    assert!(SAME_WORKER_SEEN.load(Ordering::SeqCst));
    assert!(SAME_WORKER_REJECTED.load(Ordering::SeqCst));
    exact(&fold).unwrap();
    assert_eq!(
        fold[0].crossed, 3,
        "the retirement barrier adds no plugin crossing"
    );
    assert_eq!(counts(), (2, 1, 1));
    assert_eq!(close(&p).outcome, Outcome::Ready);
}
