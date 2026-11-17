// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §12.9: the durable push queue, on core's in-tree store.

use std::cell::Cell;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::types::KindCode;

use super::{Dropped, PushQueue, PushSink, Round, StorePushQueue, MAX_PUSH};
use crate::plugin_records::RecordsDenied;
use crate::retry::{PortError, Retry, RetryPolicy, RetrySite};

const START: u64 = 1_800_000_000;

thread_local! {
    static NOW: Cell<u64> = const { Cell::new(START) };
}

fn clock() -> u64 {
    NOW.with(Cell::get)
}

fn advance(s: u64) {
    NOW.with(|cell| cell.set(cell.get() + s));
}

pub(super) fn caller<'a>(plugin: &'a str, name: &'a str, instance: u64) -> Caller<'a> {
    Caller {
        plugin,
        kind: KindCode::Plane,
        name,
        instance,
        slot: 0,
        chain: 1,
        deadline: std::time::Instant::now(),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

/// Retries every 10 s up to `stop_at` attempts; asserts it is asked for the push site only.
struct Every10s {
    stop_at: u32,
}

impl RetryPolicy for Every10s {
    fn next(&self, site: RetrySite, attempt: u32, _err: &PortError) -> Retry {
        assert_eq!(site, RetrySite::PlanePush);
        if attempt >= self.stop_at {
            Retry::Stop
        } else {
            Retry::After(Duration::from_secs(10))
        }
    }
}

/// Answers each delivery from a script (true = delivered); records what it saw.
#[derive(Default)]
struct Script {
    answers: Mutex<Vec<bool>>,
    seen: Mutex<Vec<(String, u64, Vec<u8>)>>,
    calls: AtomicU32,
}

impl Script {
    fn answering(answers: &[bool]) -> Self {
        let mut answers = answers.to_vec();
        answers.reverse();
        Self {
            answers: Mutex::new(answers),
            ..Self::default()
        }
    }
}

impl PushSink for Script {
    fn deliver<'a>(
        &'a self,
        who: &'a Caller<'_>,
        recs: &'a [u8],
    ) -> BoxFut<'a, Result<(), PortError>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.seen
            .lock()
            .unwrap()
            .push((who.name.to_string(), who.instance, recs.to_vec()));
        let ok = self.answers.lock().unwrap().pop().unwrap_or(true);
        Box::pin(async move {
            if ok {
                Ok(())
            } else {
                Err(PortError::Call(CallError::Deadline))
            }
        })
    }
}

async fn queue(stop_at: u32) -> StorePushQueue {
    StorePushQueue::with_clock(
        crate::real_store::core().await,
        Arc::new(Every10s { stop_at }),
        clock,
    )
}

#[tokio::test]
async fn a_push_is_delivered_once_under_the_live_instance_and_leaves_the_queue() {
    let q = queue(8).await;
    let old = caller("busbar-plane-a2a", "agents", 3);
    q.enqueue(&old, 60, b"recs").await.unwrap();
    // A restart: another runtime id, the same configured name, the same queue.
    let live = caller("busbar-plane-a2a", "agents", 9);
    assert_eq!(q.queued(&live).await.unwrap(), 1);
    let sink = Script::default();
    let round = q.deliver_due(&live, &sink).await.unwrap();
    assert_eq!(
        round,
        Round {
            delivered: 1,
            retried: 0,
            dropped: vec![]
        }
    );
    assert_eq!(
        *sink.seen.lock().unwrap(),
        vec![("agents".to_string(), 9, b"recs".to_vec())]
    );
    assert_eq!(q.queued(&live).await.unwrap(), 0);
    assert_eq!(q.deliver_due(&live, &sink).await.unwrap(), Round::default());
}

#[tokio::test]
async fn a_failed_attempt_waits_its_backoff_then_is_retried() {
    let q = queue(8).await;
    let who = caller("p", "a", 1);
    q.enqueue(&who, 600, b"x").await.unwrap();
    let sink = Script::answering(&[false, true]);
    let round = q.deliver_due(&who, &sink).await.unwrap();
    assert_eq!((round.delivered, round.retried), (0, 1));
    // Not due yet: nothing is attempted.
    advance(5);
    assert_eq!(q.deliver_due(&who, &sink).await.unwrap(), Round::default());
    assert_eq!(sink.calls.load(Ordering::Relaxed), 1);
    advance(5);
    let round = q.deliver_due(&who, &sink).await.unwrap();
    assert_eq!(round.delivered, 1);
    assert_eq!(q.queued(&who).await.unwrap(), 0);
}

#[tokio::test]
async fn the_policy_giving_up_drops_the_row() {
    let q = queue(2).await;
    let who = caller("p", "b", 1);
    q.enqueue(&who, 600, b"x").await.unwrap();
    let sink = Script::answering(&[false, false]);
    assert_eq!(q.deliver_due(&who, &sink).await.unwrap().retried, 1);
    advance(10);
    let round = q.deliver_due(&who, &sink).await.unwrap();
    assert_eq!(round.dropped, vec![Dropped::GaveUp]);
    assert_eq!(q.queued(&who).await.unwrap(), 0);
}

#[tokio::test]
async fn a_push_past_its_ttl_is_dropped_undelivered() {
    let q = queue(8).await;
    let who = caller("p", "c", 1);
    q.enqueue(&who, 30, b"x").await.unwrap();
    advance(31);
    let sink = Script::default();
    let round = q.deliver_due(&who, &sink).await.unwrap();
    assert_eq!(round.dropped, vec![Dropped::Expired]);
    assert_eq!(sink.calls.load(Ordering::Relaxed), 0);
    assert_eq!(q.queued(&who).await.unwrap(), 0);
}

#[tokio::test]
async fn rows_are_kept_per_configured_name_and_forgotten_with_it() {
    let q = queue(8).await;
    let a = caller("p", "one", 1);
    let b = caller("p", "two", 1);
    let other_plugin = caller("q", "one", 1);
    q.enqueue(&a, 60, b"1").await.unwrap();
    q.enqueue(&a, 60, b"2").await.unwrap();
    q.enqueue(&b, 60, b"3").await.unwrap();
    assert_eq!(q.queued(&a).await.unwrap(), 2);
    assert_eq!(q.queued(&other_plugin).await.unwrap(), 0);
    assert_eq!(q.forget(&a).await.unwrap(), 2);
    assert_eq!(q.queued(&a).await.unwrap(), 0);
    assert_eq!(q.queued(&b).await.unwrap(), 1);
}

#[tokio::test]
async fn an_oversized_or_empty_push_is_refused() {
    let q = queue(8).await;
    let who = caller("p", "d", 1);
    assert_eq!(
        q.enqueue(&who, 60, &vec![0; MAX_PUSH + 1]).await,
        Err(RecordsDenied::TooLarge)
    );
    assert_eq!(q.enqueue(&who, 60, b"").await, Err(RecordsDenied::Invalid));
    assert_eq!(q.queued(&who).await.unwrap(), 0);
}

/// Removal can race an already-started connector attempt. Its failure must not recreate the row.
struct ForgetDuringDelivery<'q>(&'q StorePushQueue);

impl PushSink for ForgetDuringDelivery<'_> {
    fn deliver<'a>(
        &'a self,
        who: &'a Caller<'_>,
        _recs: &'a [u8],
    ) -> BoxFut<'a, Result<(), PortError>> {
        Box::pin(async move {
            assert_eq!(self.0.forget(who).await.unwrap(), 1);
            Err(PortError::Call(CallError::Deadline))
        })
    }
}

#[tokio::test]
async fn failed_delivery_does_not_resurrect_a_forgotten_push() {
    let q = queue(8).await;
    let who = caller("p", "removed-during-delivery", 1);
    q.enqueue(&who, 600, b"callback").await.unwrap();
    let round = q
        .deliver_due(&who, &ForgetDuringDelivery(&q))
        .await
        .unwrap();
    assert_eq!(round.retried, 0, "the removed row was not rescheduled");
    assert_eq!(q.queued(&who).await.unwrap(), 0);
    advance(10);
    let sink = Script::default();
    assert_eq!(q.deliver_due(&who, &sink).await.unwrap(), Round::default());
    assert_eq!(sink.calls.load(Ordering::Relaxed), 0);
}
