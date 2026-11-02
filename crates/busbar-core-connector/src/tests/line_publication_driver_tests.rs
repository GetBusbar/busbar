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

type Step = Box<dyn FnOnce(Option<&Across>) -> Result<LineStep, Refused> + Send>;

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
    messages: Mutex<Vec<Vec<u8>>>,
}

impl Script {
    fn then(&self, step: impl FnOnce(Option<&Across>) -> LineStep + Send + 'static) {
        self.steps
            .lock()
            .unwrap()
            .push_back(Box::new(move |input| Ok(step(input))));
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
        Poll::Ready(step.map_or(Ok(LineStep::Complete), |step| step(input)))
    }

    fn channels(&self, mut batch: SessionBatch, _: Instant) -> Result<(), String> {
        self.messages
            .lock()
            .unwrap()
            .extend(batch.pieces.drain(..).map(|piece| piece.bytes));
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
    runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the finite ordinary publication actor reaches quiescence");
        tokio::time::timeout(std::time::Duration::from_secs(5), pairing.published())
            .await
            .expect("the finite publication outcome is observable")
    })
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

// Fixed opaque samples exercise the publication actor, not a transport or an
// invented graph protocol. Each continuation accepts one independently specified
// input and yields only its precomputed values; no input byte selects behavior.
#[test]
fn fixed_finite_publication_frontiers_preserve_exact_paths_counts_and_quiescent_recalls() {
    const EDGES4: &[(u8, u8, u8)] = &[
        (1, 2, 3),
        (2, 4, 5),
        (3, 6, 7),
        (4, 8, 9),
        (5, 10, 11),
        (6, 12, 13),
        (7, 14, 15),
        (8, 16, 17),
        (9, 18, 19),
        (10, 20, 21),
        (11, 22, 23),
        (12, 24, 25),
        (13, 26, 27),
        (14, 28, 29),
        (15, 30, 31),
    ];
    const EDGES5: &[(u8, u8, u8)] = &[
        (1, 2, 3),
        (2, 4, 5),
        (3, 6, 7),
        (4, 8, 9),
        (5, 10, 11),
        (6, 12, 13),
        (7, 14, 15),
        (8, 16, 17),
        (9, 18, 19),
        (10, 20, 21),
        (11, 22, 23),
        (12, 24, 25),
        (13, 26, 27),
        (14, 28, 29),
        (15, 30, 31),
        (16, 32, 33),
        (17, 34, 35),
        (18, 36, 37),
        (19, 38, 39),
        (20, 40, 41),
        (21, 42, 43),
        (22, 44, 45),
        (23, 46, 47),
        (24, 48, 49),
        (25, 50, 51),
        (26, 52, 53),
        (27, 54, 55),
        (28, 56, 57),
        (29, 58, 59),
        (30, 60, 61),
        (31, 62, 63),
    ];
    const LEAVES4: &[&[u8]] = &[
        b"0000", b"0001", b"0010", b"0011", b"0100", b"0101", b"0110", b"0111", b"1000", b"1001",
        b"1010", b"1011", b"1100", b"1101", b"1110", b"1111",
    ];
    const LEAVES5: &[&[u8]] = &[
        b"00000", b"00001", b"00010", b"00011", b"00100", b"00101", b"00110", b"00111", b"01000",
        b"01001", b"01010", b"01011", b"01100", b"01101", b"01110", b"01111", b"10000", b"10001",
        b"10010", b"10011", b"10100", b"10101", b"10110", b"10111", b"11000", b"11001", b"11010",
        b"11011", b"11100", b"11101", b"11110", b"11111",
    ];
    for (edges, leaves, depth) in [(EDGES4, LEAVES4, 4_u32), (EDGES5, LEAVES5, 5)] {
        for large_inputs in [false, true] {
            let caller = Arc::new(Script::default());
            let upstream = Arc::new(Script::default());
            let limit = large_inputs.then_some(128 * crate::framer::FRAME_CAP);
            let pairing = pairing_over(&caller, limit);
            let now = Instant::now();
            pairing.sort(Leg::Caller, vec![got(10, b"kind: opaque\r\n", true)], now);
            pairing.sort(Leg::Upstream, vec![got(20, b"kind: opaque\r\n", true)], now);
            pairing
                .attach(upstream.clone() as Arc<dyn LegSink>)
                .unwrap();
            let prefix = if large_inputs {
                vec![b'r'; crate::framer::FRAME_CAP / 2]
            } else {
                b"root".to_vec()
            };
            for node in 1..=(2 * leaves.len() - 1) as u8 {
                let level = u8::BITS - 1 - node.leading_zeros();
                let (sink, line) = if level % 2 == 0 {
                    (&caller, 10)
                } else {
                    (&upstream, 20)
                };
                let mut expected = prefix.clone();
                expected.push(node);
                let samples = if let Some((_, left, right)) =
                    edges.iter().find(|(parent, _, _)| *parent == node)
                {
                    [*left, *right]
                        .into_iter()
                        .map(|child| {
                            let mut sample = prefix.clone();
                            sample.push(child);
                            got(line, &sample, false)
                        })
                        .collect::<Vec<_>>()
                } else {
                    let mut sample = prefix.clone();
                    sample.extend(
                        leaves[node as usize - leaves.len()]
                            .iter()
                            .map(|bit| bit - b'0'),
                    );
                    vec![got(99, &sample, false)]
                };
                sink.then(move |input| {
                    let input = input.expect("this concrete publication takes fresh input once");
                    assert_eq!(input.stream, line);
                    assert_eq!(input.bytes, expected);
                    LineStep::Batch {
                        yielded: {
                            let mut y = Yielded::default();
                            y.pieces = samples;
                            y
                        },
                        accepted: true,
                    }
                });
            }
            let mut source = prefix.clone();
            source.push(1);
            let custody = pairing
                .reserve_input_for(Leg::Caller, source.capacity())
                .unwrap();
            pairing
                .submit_owned(
                    Leg::Caller,
                    Across {
                        stream: 10,
                        bytes: source.clone(),
                        end_of_frame: true,
                    },
                    false,
                    custody,
                )
                .unwrap();
            let outcome = drive(&pairing, &caller);
            assert!(outcome.failure.is_none(), "{outcome:?}");
            assert_eq!(
                (
                    outcome.original_bytes,
                    outcome.original_handed_bytes,
                    outcome.original_cancelled_bytes,
                    outcome.original_uncertain_bytes
                ),
                (source.len() as u64, source.len() as u64, 0, 0)
            );
            let frames = (1_u64 << (depth + 1)) - 2;
            assert_eq!(
                (
                    outcome.accepted_frames,
                    outcome.handed_frames,
                    outcome.cancelled_frames,
                    outcome.uncertain_frames
                ),
                (frames, frames, 0, 0)
            );
            assert_eq!(outcome.accepted_bytes, frames * source.len() as u64);
            assert_eq!(outcome.handed_bytes, outcome.accepted_bytes);
            let expected = (0..1_usize << depth)
                .map(|path| {
                    let mut value = prefix.clone();
                    value.extend((0..depth).rev().map(|bit| ((path >> bit) & 1) as u8));
                    value
                })
                .collect::<Vec<_>>();
            let (messages, other) = if depth % 2 == 0 {
                (&caller.messages, &upstream.messages)
            } else {
                (&upstream.messages, &caller.messages)
            };
            assert_eq!(
                *messages.lock().unwrap(),
                expected,
                "fixed opaque continuations preserve independent leaf values and FIFO order"
            );
            assert!(other.lock().unwrap().is_empty());
            let calls = caller
                .crossed()
                .into_iter()
                .chain(upstream.crossed())
                .collect::<Vec<_>>();
            assert_eq!(calls.iter().flatten().count(), (1_usize << (depth + 1)) - 1);
            assert!(
                calls.iter().any(Option::is_none),
                "same-operation recalls are exercised"
            );
            assert!(
                caller.steps.lock().unwrap().is_empty()
                    && upstream.steps.lock().unwrap().is_empty()
            );
            assert!(!pairing.closed());
            pairing.close();
            assert_eq!(
                (
                    caller.closed.load(Ordering::SeqCst),
                    upstream.closed.load(Ordering::SeqCst)
                ),
                (1, 1)
            );
            assert_eq!(pairing.memory_account().used(), 0);
        }
    }
}

#[test]
fn a_fixed_partial_frontier_exhausts_without_replay_and_preserves_earlier_reader_custody() {
    const LIMIT: usize = 512 * 1024;
    const SOURCE: &[u8] = b"one accepted source";
    let caller = Arc::new(Script::default());
    let upstream = Arc::new(Script::default());
    let pairing = pairing_over(&caller, Some(LIMIT));
    let now = Instant::now();
    pairing.sort(Leg::Caller, vec![got(10, b"kind: opaque\r\n", true)], now);
    pairing.sort(Leg::Upstream, vec![got(20, b"kind: opaque\r\n", true)], now);
    pairing
        .attach(upstream.clone() as Arc<dyn LegSink>)
        .unwrap();
    let memory = pairing.memory_account();
    let retained = pairing.publish(
        Leg::Caller,
        {
            let mut y = Yielded::default();
            y.pieces = vec![
                got(99, &vec![b'x'; crate::framer::FRAME_CAP], false),
                got(99, &vec![b'y'; crate::framer::FRAME_CAP], false),
            ];
            y
        },
        now,
    );
    let readers = retained
        .owners
        .iter()
        .map(|owner| owner.reader_on(Leg::Caller))
        .collect::<Vec<_>>();
    assert_eq!(retained.pieces.len(), 2);
    assert!(memory.used() >= 2 * crate::framer::FRAME_CAP);
    let first = vec![b'a'; 4096];
    let second = vec![b'b'; 4097];
    let expected_first = first.clone();
    caller.then(move |input| {
        assert_eq!(input.unwrap().bytes, SOURCE);
        LineStep::Batch {
            yielded: {
                let mut y = Yielded::default();
                y.pieces = vec![got(10, &first, false), got(10, &second, false)];
                y
            },
            accepted: true,
        }
    });
    upstream.then(move |input| {
        assert_eq!(input.unwrap().bytes, expected_first);
        // This concrete next owned batch exceeds the remaining configured
        // custody. No invented transport generates or parses a feedback protocol.
        LineStep::Batch {
            yielded: {
                let mut y = Yielded::default();
                y.pieces = vec![got(20, &vec![b'z'; 2 * LIMIT], false)];
                y
            },
            accepted: true,
        }
    });
    let custody = pairing
        .reserve_input_for(Leg::Caller, SOURCE.len())
        .unwrap();
    pairing
        .submit_owned(
            Leg::Caller,
            Across {
                stream: 10,
                bytes: SOURCE.to_vec(),
                end_of_frame: true,
            },
            false,
            custody,
        )
        .unwrap();
    let outcome = drive(&pairing, &caller);
    assert_eq!(
        outcome.failure.as_deref(),
        Some(crate::datagram::LINE_MEMORY_EXHAUSTED)
    );
    assert_eq!(
        (
            outcome.original_bytes,
            outcome.original_handed_bytes,
            outcome.original_cancelled_bytes,
            outcome.original_uncertain_bytes
        ),
        (SOURCE.len() as u64, SOURCE.len() as u64, 0, 0)
    );
    assert_eq!(
        (
            outcome.accepted_frames,
            outcome.handed_frames,
            outcome.cancelled_frames,
            outcome.uncertain_frames
        ),
        (2, 1, 1, 0)
    );
    assert_eq!(
        (
            outcome.accepted_bytes,
            outcome.handed_bytes,
            outcome.cancelled_bytes,
            outcome.uncertain_bytes
        ),
        (8193, 4096, 4097, 0)
    );
    assert_eq!(
        outcome.accepted_frames,
        outcome.handed_frames + outcome.cancelled_frames
    );
    assert_eq!(
        outcome.accepted_bytes,
        outcome.handed_bytes + outcome.cancelled_bytes
    );
    assert_eq!(
        caller.crossed().iter().flatten().count(),
        1,
        "accepted source is never replayed"
    );
    assert_eq!(
        upstream.crossed().iter().flatten().count(),
        1,
        "the unresolved sibling never crosses"
    );
    assert!(pairing.closed());
    assert!(memory.used() <= LIMIT);
    assert_eq!(
        retained.pieces[0].bytes,
        vec![b'x'; crate::framer::FRAME_CAP]
    );
    assert_eq!(
        retained.pieces[1].bytes,
        vec![b'y'; crate::framer::FRAME_CAP]
    );
    assert_eq!(
        (
            caller.closed.load(Ordering::SeqCst),
            upstream.closed.load(Ordering::SeqCst)
        ),
        (1, 1)
    );
    let runtime = crate::support::worker();
    assert!(!runtime.block_on(pairing.send(
        Leg::Caller,
        10,
        b"never replay accepted bytes",
        false
    )));
    assert_eq!(pairing.publication_outcome(), outcome);
    drop(readers);
    drop(retained);
    assert_eq!(
        memory.used(),
        0,
        "earlier accepted readers keep custody through failure and release it exactly once"
    );

    let healthy_caller = Arc::new(Script::default());
    let healthy = pairing_over(&healthy_caller, Some(LIMIT));
    healthy_caller.then(|input| {
        assert_eq!(input.unwrap().bytes, b"healthy");
        LineStep::Batch {
            yielded: {
                let mut y = Yielded::default();
                y.pieces = vec![got(99, b"terminal", false)];
                y
            },
            accepted: true,
        }
    });
    let custody = healthy.reserve_input_for(Leg::Caller, 7).unwrap();
    healthy
        .submit_owned(
            Leg::Caller,
            Across {
                stream: 1,
                bytes: b"healthy".to_vec(),
                end_of_frame: true,
            },
            false,
            custody,
        )
        .unwrap();
    let outcome = drive(&healthy, &healthy_caller);
    assert!(outcome.failure.is_none());
    assert_eq!(
        *healthy_caller.messages.lock().unwrap(),
        vec![b"terminal".to_vec()]
    );
    assert!(
        !healthy.closed(),
        "another pairing under the same limit remains independent"
    );
    healthy.close();
}

#[test]
fn a_ready_batch_after_reentrant_close_counts_taken_source_and_cancels_its_line_output() {
    const SOURCE: &[u8] = b"taken once";
    let caller = Arc::new(Script::default());
    let upstream = Arc::new(Script::default());
    let pairing = bridged(&caller, &upstream);
    let weak = Arc::downgrade(&pairing);
    caller.then(move |input| {
        assert_eq!(input.unwrap().bytes, SOURCE);
        let pairing = weak.upgrade().unwrap();
        // Actual DatagramTurn::cross holds a producer while the framer is
        // crossing. Keep that same concrete owner across the reentrant close
        // so the returned LINE is classified before bridge metadata retires.
        let producer = pairing.memory.producer().unwrap();
        pairing.close();
        LineStep::Batch {
            yielded: {
                let mut y = Yielded::default();
                y.producer = producer;
                y.pieces = vec![got(10, SOURCE, false)];
                y
            },
            accepted: true,
        }
    });
    let custody = pairing
        .reserve_input_for(Leg::Caller, SOURCE.len())
        .unwrap();
    pairing
        .submit_owned(
            Leg::Caller,
            Across {
                stream: 1,
                bytes: SOURCE.to_vec(),
                end_of_frame: true,
            },
            false,
            custody,
        )
        .unwrap();
    let outcome = drive(&pairing, &caller);
    assert!(outcome.failure.is_some());
    assert_eq!(
        (
            outcome.original_bytes,
            outcome.original_handed_bytes,
            outcome.original_cancelled_bytes,
            outcome.original_uncertain_bytes
        ),
        (SOURCE.len() as u64, SOURCE.len() as u64, 0, 0)
    );
    assert_eq!(
        (
            outcome.accepted_frames,
            outcome.handed_frames,
            outcome.cancelled_frames,
            outcome.uncertain_frames
        ),
        (1, 0, 1, 0)
    );
    assert_eq!(outcome.cancelled_bytes, SOURCE.len() as u64);
    assert_eq!(caller.crossed().iter().flatten().count(), 1);
    assert!(
        upstream.crossed().is_empty(),
        "no destination crosses output after reentrant close"
    );
    assert_eq!(pairing.memory_account().used(), 0);
}

#[test]
fn fixed_channel_outputs_from_application_and_bridged_line_inputs_publish_once_in_order() {
    let caller = Arc::new(Script::default());
    let upstream = Arc::new(Script::default());
    let pairing = bridged(&caller, &upstream);
    let weak = Arc::downgrade(&pairing);
    caller.then(move |input| {
        assert_eq!(input.unwrap().bytes, b"application");
        // A concrete other-leg publication arrives while this source crossing
        // owns the actor. It must follow the current source's channel output.
        let session = weak.upgrade().unwrap().publish(
            Leg::Upstream,
            {
                let mut y = Yielded::default();
                y.pieces = vec![got(20, b"line frame", false)];
                y
            },
            Instant::now(),
        );
        assert!(
            session.pieces.is_empty(),
            "the LINE stays out of the upstream session"
        );
        LineStep::Batch {
            yielded: {
                let mut y = Yielded::default();
                y.pieces = vec![got(99, b"application output", false)];
                y
            },
            accepted: true,
        }
    });
    caller.then(|input| {
        let input = input.expect("the queued LINE crosses after the application input");
        assert_eq!(
            (input.stream, input.bytes.as_slice()),
            (10, b"line frame".as_slice())
        );
        LineStep::Batch {
            yielded: {
                let mut y = Yielded::default();
                y.pieces = vec![got(99, b"line output", false)];
                y
            },
            accepted: true,
        }
    });
    let custody = pairing.reserve_input_for(Leg::Caller, 11).unwrap();
    pairing
        .submit_owned(
            Leg::Caller,
            Across {
                stream: 1,
                bytes: b"application".to_vec(),
                end_of_frame: true,
            },
            false,
            custody,
        )
        .unwrap();
    let outcome = drive(&pairing, &caller);
    assert!(outcome.failure.is_none());
    assert_eq!(
        *caller.messages.lock().unwrap(),
        vec![b"application output".to_vec(), b"line output".to_vec()]
    );
    assert!(upstream.messages.lock().unwrap().is_empty());
    assert_eq!(
        caller
            .crossed()
            .into_iter()
            .flatten()
            .map(|across| across.bytes)
            .collect::<Vec<_>>(),
        vec![b"application".to_vec(), b"line frame".to_vec()]
    );
    assert_eq!(
        (
            outcome.original_bytes,
            outcome.original_handed_bytes,
            outcome.accepted_frames,
            outcome.handed_frames,
            outcome.cancelled_frames
        ),
        (11, 11, 1, 1, 0)
    );
    pairing.close();
}

#[test]
fn refusal_of_the_first_preaccepted_source_cancels_later_sources_without_crossing_them() {
    let caller = Arc::new(Script::default());
    let pairing = pairing_over(&caller, Some(1 << 20));
    caller.steps.lock().unwrap().push_back(Box::new(|input| {
        assert_eq!(input.unwrap().bytes, b"first accepted");
        Err(Refused {
            outcome: Outcome::Refused,
            error: "bounded producer refusal".into(),
        })
    }));
    for bytes in [b"first accepted".as_slice(), b"later accepted"] {
        let custody = pairing.reserve_input_for(Leg::Caller, bytes.len()).unwrap();
        assert!(pairing.retain_input(bytes.len()));
        pairing
            .submit_preaccepted_owned(
                Leg::Caller,
                Across {
                    stream: 1,
                    bytes: bytes.to_vec(),
                    end_of_frame: true,
                },
                false,
                custody,
                bytes.len(),
                None,
            )
            .unwrap();
    }
    let outcome = drive(&pairing, &caller);
    assert!(pairing.closed());
    assert_eq!(outcome.failure.as_deref(), Some("bounded producer refusal"));
    assert_eq!(
        (
            outcome.original_bytes,
            outcome.original_handed_bytes,
            outcome.original_cancelled_bytes,
            outcome.original_uncertain_bytes
        ),
        (28, 0, 28, 0)
    );
    assert_eq!(
        caller
            .crossed()
            .into_iter()
            .flatten()
            .map(|across| across.bytes)
            .collect::<Vec<_>>(),
        vec![b"first accepted".to_vec()]
    );
    assert!(!crate::support::worker().block_on(pairing.send(
        Leg::Caller,
        1,
        b"after refusal",
        false
    )));
    assert_eq!(pairing.publication_outcome(), outcome);
    assert_eq!(pairing.memory_account().used(), 0);
}

#[test]
fn a_real_credit_refusal_cancels_a_partial_frontier_instead_of_waiting_on_queued_readers() {
    const LIMIT: usize = 512 * 1024;
    let caller = Arc::new(Script::default());
    let upstream = Arc::new(Script::default());
    let pairing = pairing_over(&caller, Some(LIMIT));
    let now = Instant::now();
    pairing.sort(Leg::Caller, vec![got(10, b"kind: opaque\r\n", true)], now);
    pairing.sort(Leg::Upstream, vec![got(20, b"kind: opaque\r\n", true)], now);
    pairing
        .attach(upstream.clone() as Arc<dyn LegSink>)
        .unwrap();
    let memory = pairing.memory_account();
    let mut retained = pairing.publish(
        Leg::Caller,
        {
            let mut y = Yielded::default();
            y.pieces = vec![got(99, &vec![b'x'; 4096], false), got(99, b"", false)];
            y
        },
        now,
    );
    let readers = retained
        .owners
        .iter()
        .map(|owner| owner.reader_on(Leg::Caller))
        .collect::<Vec<_>>();
    // This batch has completed its handoff: its queued readers own storage, but
    // no active producer or consumption transfer can make independent progress.
    retained.producer = crate::publication::ProducerCustody::default();
    caller.then(|input| {
        assert_eq!(input.unwrap().bytes, b"seed");
        LineStep::Batch {
            yielded: {
                let mut y = Yielded::default();
                y.pieces = vec![got(10, b"first", false), got(10, b"second", false)];
                y
            },
            accepted: true,
        }
    });
    upstream.then(|input| {
        assert_eq!(input.unwrap().bytes, b"first");
        LineStep::Batch {
            yielded: {
                let mut y = Yielded::default();
                y.pieces = vec![got(20, b"feedback", false)];
                y
            },
            accepted: true,
        }
    });
    let pressure = Arc::new(Mutex::new(None));
    let held = pressure.clone();
    let credit = memory.clone();
    upstream.then(move |input| {
        assert_eq!(input.unwrap().bytes, b"second");
        let overhead = crate::publication::Memory::reservation_size(0).unwrap();
        let remaining = LIMIT - credit.used() - overhead;
        *held.lock().unwrap() = Some(credit.reserve(remaining).unwrap());
        assert!(
            credit.reserve(1).is_none(),
            "the next crossing genuinely has no storage credit"
        );
        LineStep::Credit
    });
    let custody = pairing.reserve_input_for(Leg::Caller, 4).unwrap();
    pairing
        .submit_owned(
            Leg::Caller,
            Across {
                stream: 1,
                bytes: b"seed".to_vec(),
                end_of_frame: true,
            },
            false,
            custody,
        )
        .unwrap();
    let outcome = drive(&pairing, &caller);
    assert_eq!(
        outcome.failure.as_deref(),
        Some(crate::datagram::LINE_MEMORY_EXHAUSTED)
    );
    assert_eq!(
        (
            outcome.original_bytes,
            outcome.original_handed_bytes,
            outcome.original_cancelled_bytes,
            outcome.original_uncertain_bytes
        ),
        (4, 4, 0, 0)
    );
    assert_eq!(
        (
            outcome.accepted_frames,
            outcome.handed_frames,
            outcome.cancelled_frames,
            outcome.uncertain_frames
        ),
        (3, 1, 2, 0)
    );
    assert_eq!(
        (
            outcome.accepted_bytes,
            outcome.handed_bytes,
            outcome.cancelled_bytes,
            outcome.uncertain_bytes
        ),
        (19, 5, 14, 0)
    );
    assert_eq!(
        outcome.accepted_frames,
        outcome.handed_frames + outcome.cancelled_frames
    );
    assert_eq!(
        outcome.accepted_bytes,
        outcome.handed_bytes + outcome.cancelled_bytes
    );
    assert_eq!(
        caller
            .crossed()
            .into_iter()
            .flatten()
            .map(|input| input.bytes)
            .collect::<Vec<_>>(),
        vec![b"seed".to_vec()],
        "accepted source and cancelled feedback are never replayed"
    );
    assert_eq!(
        upstream
            .crossed()
            .into_iter()
            .flatten()
            .map(|input| input.bytes)
            .collect::<Vec<_>>(),
        vec![b"first".to_vec(), b"second".to_vec()]
    );
    assert_eq!(retained.pieces[0].bytes, vec![b'x'; 4096]);
    assert!(retained.pieces[1].bytes.is_empty());
    assert!(memory.used() <= LIMIT);
    assert!(pairing.closed());
    assert_eq!(
        (
            caller.closed.load(Ordering::SeqCst),
            upstream.closed.load(Ordering::SeqCst)
        ),
        (1, 1)
    );
    drop(pressure.lock().unwrap().take());
    drop(readers);
    drop(retained);
    assert_eq!(memory.used(), 0);
}
