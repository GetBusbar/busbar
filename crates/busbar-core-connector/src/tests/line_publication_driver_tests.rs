// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The publication actor's recall and held-source paths, driven through a real [`Pairing`] and

use super::*;
use crate::datagram::{Across, Leg, LegSink, LineStep, Pairing, Yielded};
use crate::framer::{Got, Refused};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

type Step = Box<dyn FnOnce(Option<&Across>) -> LineStep + Send>;

/// A leg whose crossings are scripted: each `poll_line` records its input and runs the next
/// scripted step (with no sink lock held, so a step may re-enter the pairing); an exhausted script
/// answers `Complete`.
#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<Step>>,
    inputs: Mutex<Vec<Option<Across>>>,
    on_channels: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    task: Mutex<Option<PublicationTask>>,
    closed: AtomicUsize,
}

impl Script {
    fn then(&self, step: impl FnOnce(Option<&Across>) -> LineStep + Send + 'static) {
        self.steps.lock().unwrap().push_back(Box::new(step));
    }

    fn crossed(&self) -> Vec<Option<Across>> {
        self.inputs.lock().unwrap().clone()
    }
}

impl LegSink for Script {
    fn line(&self, _: Across, _: Instant) {
        panic!("these tests cross LINE frames only through poll_line");
    }

    fn poll_line(
        &self,
        _cx: &mut Context<'_>,
        input: Option<&Across>,
        _text: bool,
        _now: Instant,
    ) -> Poll<Result<LineStep, Refused>> {
        self.inputs.lock().unwrap().push(input.cloned());
        let step = self.steps.lock().unwrap().pop_front();
        Poll::Ready(Ok(step.map_or(LineStep::Complete, |step| step(input))))
    }

    fn channels(&self, _: SessionBatch, _: Instant) -> Result<(), String> {
        let hook = self.on_channels.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        Ok(())
    }

    fn schedule(&self, task: PublicationTask) -> bool {
        *self.task.lock().unwrap() = Some(task);
        true
    }

    fn close(&self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

fn got(stream: u64, bytes: &[u8], fields: bool) -> Got {
    Got {
        stream,
        bytes: bytes.to_vec(),
        end_of_frame: true,
        status_code: None,
        handoff: false,
        status_class: 0,
        fault: 0,
        retry_after_secs: None,
        declared_len: None,
        fields,
        text: false,
        reason: None,
        failed: false,
        end: false,
    }
}

fn pairing_over(caller: &Arc<Script>, limit: Option<usize>) -> Arc<Pairing> {
    Pairing::with_memory_limit(
        Arc::clone(caller) as Arc<dyn LegSink>,
        "127.0.0.1:1".parse().unwrap(),
        limit,
    )
}

/// A pairing whose caller LINE `10` mirrors the upstream's LINE `20`, both legs attached.
fn bridged(caller: &Arc<Script>, upstream: &Arc<Script>) -> Arc<Pairing> {
    let pairing = pairing_over(caller, None);
    let now = Instant::now();
    pairing.sort(Leg::Caller, vec![got(10, b"kind: opaque\r\n", true)], now);
    pairing.sort(Leg::Upstream, vec![got(20, b"kind: opaque\r\n", true)], now);
    pairing
        .attach(Arc::clone(upstream) as Arc<dyn LegSink>)
        .unwrap();
    pairing
}

/// Publish a producer that still owes a same-op recall on `leg`, as a raw producer does.
fn owe_recall(pairing: &Arc<Pairing>, leg: Leg) {
    let _ = pairing.publish(
        leg,
        {
            let mut yielded = Yielded::default();
            yielded.continuing = true;
            yielded
        },
        Instant::now(),
    );
}

/// Run the scheduled actor to completion, then return the pairing's quiescent outcome.
fn drive(pairing: &Arc<Pairing>, scheduled_on: &Script) -> PublicationOutcome {
    let task = scheduled_on
        .task
        .lock()
        .unwrap()
        .take()
        .expect("the publication actor was scheduled");
    let runtime = crate::support::worker();
    runtime.block_on(task);
    runtime.block_on(pairing.published())
}

/// A recall that a crossing's own `Complete` races with: before the crossing returns, another
#[test]
fn a_recall_published_while_a_crossing_completes_is_drained_by_the_same_actor() {
    let caller = Arc::new(Script::default());
    let upstream = Arc::new(Script::default());
    let pairing = bridged(&caller, &upstream);

    let weak = Arc::downgrade(&pairing);
    caller.then(move |input| {
        assert!(input.is_none(), "a recall crossing carries no fresh input");
        owe_recall(&weak.upgrade().unwrap(), Leg::Caller);
        LineStep::Complete
    });

    caller.then(|input| {
        assert!(input.is_none());
        LineStep::Batch {
            yielded: {
                let mut yielded = Yielded::default();
                yielded.pieces = vec![got(10, b"tail", false)];
                yielded
            },
            accepted: false,
        }
    });
    upstream.then(|input| {
        assert_eq!(input.map(|a| a.bytes.as_slice()), Some(&b"tail"[..]));
        LineStep::Batch {
            yielded: Yielded::default(),
            accepted: true,
        }
    });

    owe_recall(&pairing, Leg::Caller);
    let outcome = drive(&pairing, &caller);

    assert!(outcome.failure.is_none(), "{outcome:?}");
    assert_eq!(
        upstream.crossed(),
        vec![
            Some(Across {
                stream: 20,
                bytes: b"tail".to_vec(),
                end_of_frame: true,
            }),
            None,
        ],
        "the healthy other leg received the drained continuation's frame, then its own recall"
    );
    assert_eq!(
        caller.crossed(),
        vec![None, None, None],
        "the completed crossing, the newly published recall, then its own follow-up recall"
    );
    assert_eq!(
        (
            outcome.accepted_frames,
            outcome.handed_frames,
            outcome.accepted_bytes,
            outcome.handed_bytes,
            outcome.cancelled_frames,
            outcome.cancelled_bytes,
        ),
        (1, 1, 4, 4, 0, 0)
    );
}

/// The converse: a recall that completes with nothing new published is not invented again.
#[test]
fn a_recall_that_completes_without_new_output_crosses_exactly_once() {
    let caller = Arc::new(Script::default());
    let upstream = Arc::new(Script::default());
    let pairing = bridged(&caller, &upstream);

    owe_recall(&pairing, Leg::Caller);
    let outcome = drive(&pairing, &caller);

    assert!(outcome.failure.is_none(), "{outcome:?}");
    assert_eq!(caller.crossed(), vec![None]);
    assert!(upstream.crossed().is_empty());
}

/// A crossing that needs storage credit has not finished the recall it was given: the recall is
#[test]
fn a_credit_crossing_keeps_the_recall_it_did_not_finish() {
    let caller = Arc::new(Script::default());
    let upstream = Arc::new(Script::default());
    let pairing = bridged(&caller, &upstream);

    let memory = pairing.memory_account();

    caller.then(move |_| {
        memory.progress_changed();
        LineStep::Credit
    });

    owe_recall(&pairing, Leg::Caller);
    let outcome = drive(&pairing, &caller);

    assert!(outcome.failure.is_none(), "{outcome:?}");
    assert_eq!(
        caller.crossed(),
        vec![None, None],
        "the recall refused for credit is crossed again, exactly once more"
    );
}

/// Observes the retirement of a held source's admission guard.
struct Retired {
    dropped: Arc<AtomicUsize>,
    lock_free: Arc<AtomicBool>,
    pairing: std::sync::Weak<Pairing>,
}

impl Drop for Retired {
    fn drop(&mut self) {
        if let Some(pairing) = self.pairing.upgrade() {
            self.lock_free
                .store(pairing.state.try_lock().is_ok(), Ordering::SeqCst);
        }
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// A source job whose crossing does not take its input is held by the actor. If the pairing
#[test]
fn a_close_during_a_non_accepting_batch_retires_the_held_source_immediately() {
    const SOURCE: &[u8] = b"original";
    let caller = Arc::new(Script::default());
    let pairing = pairing_over(&caller, Some(1 << 20));

    let custody = pairing
        .reserve_input_for(Leg::Caller, SOURCE.len())
        .unwrap();
    assert!(pairing.memory_account().used() > 0);
    let dropped = Arc::new(AtomicUsize::new(0));
    let lock_free = Arc::new(AtomicBool::new(false));
    let admission = Retired {
        dropped: Arc::clone(&dropped),
        lock_free: Arc::clone(&lock_free),
        pairing: Arc::downgrade(&pairing),
    };

    caller.then(|input| {
        assert_eq!(input.map(|a| a.bytes.as_slice()), Some(SOURCE));
        LineStep::Batch {
            yielded: Yielded::default(),
            accepted: false,
        }
    });

    let weak = Arc::downgrade(&pairing);
    *caller.on_channels.lock().unwrap() = Some(Box::new(move || weak.upgrade().unwrap().close()));

    pairing
        .submit_owned_guarded(
            Leg::Caller,
            Across {
                stream: 1,
                bytes: SOURCE.to_vec(),
                end_of_frame: true,
            },
            false,
            custody,
            Some(Box::new(admission)),
        )
        .unwrap();
    let outcome = drive(&pairing, &caller);

    assert_eq!(dropped.load(Ordering::SeqCst), 1, "admission retired once");
    assert!(
        lock_free.load(Ordering::SeqCst),
        "the admission guard was destroyed with the pairing lock released"
    );
    assert_eq!(
        pairing.memory_account().used(),
        0,
        "the held source's custody was released"
    );
    assert_eq!(
        caller.crossed().len(),
        1,
        "the unaccepted bytes were never crossed again"
    );
    assert_eq!(caller.closed.load(Ordering::SeqCst), 1);
    assert!(outcome.failure.is_some());
    assert_eq!(
        (
            outcome.original_bytes,
            outcome.original_handed_bytes,
            outcome.original_cancelled_bytes,
            outcome.original_uncertain_bytes,
        ),
        (SOURCE.len() as u64, 0, SOURCE.len() as u64, 0)
    );
    assert_eq!((outcome.accepted_frames, outcome.handed_frames), (0, 0));
}
