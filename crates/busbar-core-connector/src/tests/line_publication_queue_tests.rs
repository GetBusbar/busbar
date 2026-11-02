// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FIFO order and storage retirement, without timing or performance measurements.

use super::*;
use crate::framer::{Got, Refused};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

fn job(id: u8) -> Job {
    Job {
        to: Leg::Caller,
        across: Across {
            stream: u64::from(id),
            bytes: vec![id],
            end_of_frame: true,
        },
        now: Instant::now(),
        text: false,
        original: true,
        unpaired: None,
        _custody: Custody::default(),
        _admission: None,
    }
}

fn take(queue: &mut Queue, expected: u8) {
    let job = queue.pop().expect("the independently expected FIFO item");
    assert_eq!(job.across.stream, u64::from(expected));
    assert_eq!(job.across.bytes, [expected]);
}

#[test]
fn fifo_interleaves_new_tails_deferred_fronts_and_empty_refills() {
    let mut queue = Queue::default();
    assert!(queue.is_empty());
    assert!(queue.pop().is_none());
    for id in [1, 2, 3] {
        queue.push(job(id));
    }
    assert!(!queue.is_empty(), "a back-only queue is nonempty");
    take(&mut queue, 1);
    queue.push(job(4));
    queue.push(job(5));
    queue.push_front(job(0));
    take(&mut queue, 0);
    take(&mut queue, 2);
    queue.push_front(job(6));
    take(&mut queue, 6);
    take(&mut queue, 3);
    queue.push(job(7));
    take(&mut queue, 4);
    queue.push_front(job(8));
    for id in [8, 5, 7] {
        take(&mut queue, id);
    }
    assert!(queue.is_empty());
    assert!(queue.pop().is_none());
    queue.push(job(9));
    queue.push_front(job(10));
    queue.push(job(11));
    for id in [10, 9, 11] {
        take(&mut queue, id);
    }
    assert!(queue.is_empty());
}

type Hook = Box<dyn FnOnce() + Send>;

struct Sink {
    first_source: AtomicBool,
    paused: AtomicBool,
    accepted: Mutex<Vec<(u64, Vec<u8>)>>,
    channels: Mutex<Option<Hook>>,
    task: Mutex<Option<PublicationTask>>,
}

impl Sink {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            first_source: AtomicBool::new(true),
            paused: AtomicBool::new(true),
            accepted: Mutex::default(),
            channels: Mutex::default(),
            task: Mutex::default(),
        })
    }
}

impl LegSink for Sink {
    fn line(&self, _: Across, _: Instant) {
        panic!("the real publication actor uses poll_line");
    }

    fn poll_line(
        &self,
        _: &mut Context<'_>,
        input: Option<&Across>,
        _: bool,
        _: Instant,
    ) -> Poll<Result<LineStep, Refused>> {
        let Some(input) = input else {
            return Poll::Ready(Ok(LineStep::Complete));
        };
        if input.stream == 1 && input.bytes == b"a" {
            if self.first_source.swap(false, Ordering::SeqCst) {
                return Poll::Ready(Ok(LineStep::Batch {
                    yielded: Yielded::default(),
                    accepted: false,
                }));
            }
            if self.paused.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        self.accepted
            .lock()
            .unwrap()
            .push((input.stream, input.bytes.clone()));
        Poll::Ready(Ok(LineStep::Batch {
            yielded: Yielded::default(),
            accepted: true,
        }))
    }

    fn channels(&self, _: SessionBatch, _: Instant) -> Result<(), String> {
        let hook = self.channels.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        Ok(())
    }

    fn schedule(&self, task: PublicationTask) -> bool {
        let previous = self.task.lock().unwrap().replace(task);
        assert!(previous.is_none(), "one actor owns the queued episode");
        true
    }

    fn close(&self) {}
}

#[derive(Debug, PartialEq, Eq)]
struct Retirement {
    id: usize,
    used: usize,
    lock_free: bool,
}

struct Admission {
    id: usize,
    pairing: Weak<Pairing>,
    retired: Arc<Mutex<Vec<Retirement>>>,
}

impl Drop for Admission {
    fn drop(&mut self) {
        let pairing = self.pairing.upgrade().unwrap();
        let lock_free = pairing.state.try_lock().is_ok();
        let used = pairing.memory_account().used();
        self.retired.lock().unwrap().push(Retirement {
            id: self.id,
            used,
            lock_free,
        });
    }
}

fn enqueue(
    pairing: &Arc<Pairing>,
    id: usize,
    bytes: &[u8],
    retired: &Arc<Mutex<Vec<Retirement>>>,
    charges: &Arc<Mutex<Vec<(usize, usize)>>>,
) {
    let memory = pairing.memory_account();
    let before = memory.used();
    let custody = pairing
        .reserve_input_for(Leg::Caller, bytes.len() + std::mem::size_of::<Admission>())
        .unwrap();
    let charged = memory.used() - before;
    assert!(
        charged > bytes.len(),
        "each live node pays positive owner metadata"
    );
    charges.lock().unwrap().push((id, charged));
    pairing
        .submit_owned_guarded(
            Leg::Caller,
            Across {
                stream: 1,
                bytes: bytes.to_vec(),
                end_of_frame: true,
            },
            false,
            custody,
            Some(Box::new(Admission {
                id,
                pairing: Arc::downgrade(pairing),
                retired: Arc::clone(retired),
            })),
        )
        .unwrap();
}

fn piece(stream: u64, bytes: &[u8], fields: bool) -> Got {
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

#[test]
fn a_back_only_line_batch_starts_publication_and_preserves_its_empty_frame() {
    let sink = Sink::new();
    let pairing = Pairing::with_memory_limit(
        Arc::clone(&sink) as Arc<dyn LegSink>,
        "127.0.0.1:1".parse().unwrap(),
        Some(1 << 20),
    );
    let now = Instant::now();
    pairing.sort(Leg::Caller, vec![piece(10, b"kind: opaque\r\n", true)], now);
    pairing.sort(
        Leg::Upstream,
        vec![piece(20, b"kind: opaque\r\n", true)],
        now,
    );
    pairing
        .attach(Arc::clone(&sink) as Arc<dyn LegSink>)
        .unwrap();
    drop(pairing.publish(
        Leg::Upstream,
        {
            let mut yielded = Yielded::default();
            yielded.pieces = vec![piece(20, b"", false), piece(20, b"line", false)];
            yielded
        },
        now,
    ));
    assert!(
        pairing.memory_account().used() > 4,
        "empty output pays owner metadata too"
    );
    let mut task = sink
        .task
        .lock()
        .unwrap()
        .take()
        .expect("queued LINE output schedules its actor");
    let mut context = Context::from_waker(Waker::noop());
    assert!(task.as_mut().poll(&mut context).is_ready());
    drop(task);
    assert_eq!(
        *sink.accepted.lock().unwrap(),
        vec![(10, Vec::new()), (10, b"line".to_vec())]
    );
    let outcome = pairing.publication_outcome();
    assert_eq!(
        (
            outcome.accepted_frames,
            outcome.handed_frames,
            outcome.cancelled_frames
        ),
        (2, 2, 0)
    );
    assert_eq!((outcome.accepted_bytes, outcome.handed_bytes), (4, 4));
    assert!(outcome.failure.is_none());
    assert_eq!(pairing.memory_account().used(), 0);
    pairing.close();
}

#[test]
fn real_pairing_requeues_source_before_new_inputs_and_retires_both_queue_lists_once() {
    for cancel in [false, true] {
        let sink = Sink::new();
        let pairing = Pairing::with_memory_limit(
            Arc::clone(&sink) as Arc<dyn LegSink>,
            "127.0.0.1:1".parse().unwrap(),
            Some(1 << 20),
        );
        let now = Instant::now();
        pairing.sort(Leg::Caller, vec![piece(10, b"kind: opaque\r\n", true)], now);
        pairing.sort(
            Leg::Upstream,
            vec![piece(20, b"kind: opaque\r\n", true)],
            now,
        );
        pairing
            .attach(Arc::clone(&sink) as Arc<dyn LegSink>)
            .unwrap();
        let retired = Arc::new(Mutex::new(Vec::new()));
        let charges = Arc::new(Mutex::new(Vec::new()));
        enqueue(&pairing, 1, b"a", &retired, &charges);
        enqueue(&pairing, 2, b"bb", &retired, &charges);
        let weak = Arc::downgrade(&pairing);
        let on_retired = Arc::clone(&retired);
        let on_charges = Arc::clone(&charges);
        *sink.channels.lock().unwrap() = Some(Box::new(move || {
            let pairing = weak.upgrade().unwrap();
            enqueue(&pairing, 3, b"ccc", &on_retired, &on_charges);
            enqueue(&pairing, 4, b"dddd", &on_retired, &on_charges);
            drop(pairing.publish(
                Leg::Upstream,
                {
                    let mut yielded = Yielded::default();
                    yielded.pieces = vec![piece(20, b"", false), piece(20, b"line", false)];
                    yielded
                },
                Instant::now(),
            ));
        }));
        let mut task = sink.task.lock().unwrap().take().unwrap();
        let mut context = Context::from_waker(Waker::noop());
        assert!(task.as_mut().poll(&mut context).is_pending());
        // Actual output precedes the deferred source and newer accepted application jobs.
        assert_eq!(
            *sink.accepted.lock().unwrap(),
            vec![(10, Vec::new()), (10, b"line".to_vec())]
        );
        let charges = charges.lock().unwrap().clone();
        let total: usize = charges.iter().map(|(_, bytes)| bytes).sum();
        assert_eq!(pairing.memory_account().used(), total);
        assert!(retired.lock().unwrap().is_empty());
        {
            let state = pairing.lock();
            assert!(state.publications.inputs.front.is_some());
            assert!(state.publications.inputs.back.is_some());
        }
        let order = if cancel {
            pairing.close();
            let current = charges.iter().find(|(id, _)| *id == 1).unwrap().1;
            assert_eq!(pairing.memory_account().used(), current);
            assert_eq!(retired.lock().unwrap().len(), 3);
            drop(task);
            vec![2, 3, 4, 1]
        } else {
            sink.paused.store(false, Ordering::SeqCst);
            assert!(task.as_mut().poll(&mut context).is_ready());
            drop(task);
            assert_eq!(
                *sink.accepted.lock().unwrap(),
                vec![
                    (10, Vec::new()),
                    (10, b"line".to_vec()),
                    (1, b"a".to_vec()),
                    (1, b"bb".to_vec()),
                    (1, b"ccc".to_vec()),
                    (1, b"dddd".to_vec())
                ]
            );
            vec![1, 2, 3, 4]
        };
        let mut remaining = total;
        let expected: Vec<_> = order
            .into_iter()
            .map(|id| {
                remaining -= charges.iter().find(|(owner, _)| *owner == id).unwrap().1;
                Retirement {
                    id,
                    used: remaining,
                    lock_free: true,
                }
            })
            .collect();
        assert_eq!(*retired.lock().unwrap(), expected);
        assert_eq!(pairing.memory_account().used(), 0);
        let outcome = pairing.publication_outcome();
        assert_eq!(
            (
                outcome.original_bytes,
                outcome.original_handed_bytes,
                outcome.original_cancelled_bytes,
                outcome.original_uncertain_bytes
            ),
            if cancel {
                (10, 0, 10, 1)
            } else {
                (10, 10, 0, 0)
            }
        );
        assert_eq!(
            (
                outcome.accepted_frames,
                outcome.handed_frames,
                outcome.cancelled_frames,
                outcome.uncertain_frames
            ),
            (2, 2, 0, 0)
        );
        assert_eq!(
            (
                outcome.accepted_bytes,
                outcome.handed_bytes,
                outcome.cancelled_bytes,
                outcome.uncertain_bytes
            ),
            (4, 4, 0, 0)
        );
        assert_eq!(outcome.failure.is_some(), cancel);
        if !cancel {
            assert!(!pairing.closed());
            pairing.close();
        }
        assert_eq!(retired.lock().unwrap().len(), 4);
    }
}
