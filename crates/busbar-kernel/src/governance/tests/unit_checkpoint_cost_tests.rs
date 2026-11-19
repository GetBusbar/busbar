// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-CHECKPOINT: what one accepted usage update and one selected dispatch cost the running unit
//! checkpoint, with a 4 KiB and a 1 MiB (the bound) captured audit.
//!
//! - usage update: what an attempt's usage report does (`NativeAttempt::observe`): copy the
//!   accepted checkpoint, set the attempt's reported count, project the bill, keep a copy for a
//!   refused publication, and stage it in the book (`stage_selected_checkpoint`).
//! - selected dispatch: what the connector handoff does (`NativeRequestMoney::commit`): copy the
//!   accepted prepared checkpoint, mark its last attempt committed, and commit it
//!   (`commit_selected_checkpoint`), one fresh prepared unit per sample.
//!
//! Both are crate-private paths of the book, so they are timed here, in the kernel's test binary,
//! on the shipped allocator (jemalloc) and its per-thread counter. Each prints, for each of
//! `B_CHECKPOINT_RUNS` runs (default 1), the median time and the median bytes allocated per
//! operation over `B_CHECKPOINT_SAMPLES` samples (default 5). Timings mean something only in an
//! optimised build: `cargo test --release -p busbar-kernel --lib b_checkpoint -- --nocapture`.

use std::sync::Arc;
use std::time::Instant;

use super::*;
use crate::governance::unit_checkpoint::partitions::{
    Transport, ValidatedSelectedCheckpoint, MAX_AUDIT_BYTES,
};
use crate::governance::unit_checkpoint::UnitCheckpoint;
use crate::governance::GovState;

fn env_or(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

/// The bytes this thread allocated while `f` ran, and how long it took.
fn cost<T>(f: impl FnOnce() -> T) -> (T, u64, u64) {
    crate::ThreadAllocated::reset();
    let start = Instant::now();
    let out = f();
    let nanos = start.elapsed().as_nanos() as u64;
    (out, nanos, crate::ThreadAllocated::bytes())
}

/// The initial selected checkpoint of unit `n`, carrying `audit` bytes of captured audit facts.
fn initial(n: u32, audit: usize) -> UnitCheckpoint {
    let mut snapshot = initial_selected();
    snapshot.id[..4].copy_from_slice(&n.to_be_bytes());
    snapshot.audit = Some(vec![b'a'; audit].into());
    snapshot
}

/// Unit `n` activated and prepared for its first attempt, as the book accepted it.
fn prepared(gov: &GovState, n: u32, audit: usize) -> Arc<UnitCheckpoint> {
    let initial = gov
        .activate_selected_checkpoint(initial(n, audit), Ok::<_, ()>)
        .unwrap();
    let mut value = json::to_value(&initial_selected()).unwrap();
    let mut attempt = attempt(1, None, "A", source_facts(None, None, None));
    attempt["transport"] = json::json!("prepared");
    attempt["finality"] = json::json!("live");
    value["partitions"]["attempts"] = json::json!([attempt]);
    let mut next = decode(&value);
    next.id = initial.id;
    next.audit = initial.audit.clone();
    gov.stage_selected_checkpoint(next, Some(initial.revision))
        .unwrap()
}

/// The connector handoff: the prepared attempt committed as dispatch 1.
fn dispatch(gov: &GovState, accepted: &Arc<UnitCheckpoint>) -> Arc<UnitCheckpoint> {
    let mut snapshot = accepted.as_ref().clone();
    let attempt = snapshot
        .partitions
        .as_mut()
        .unwrap()
        .attempts
        .last_mut()
        .unwrap();
    attempt.transport = Transport::Committed;
    attempt.dispatch = Some(1);
    gov.commit_selected_checkpoint(snapshot, accepted.revision, || Ok::<_, ()>(()))
        .unwrap()
        .0
}

/// One usage report on the committed attempt: its reported count becomes `count`.
fn usage_update(gov: &GovState, accepted: &Arc<UnitCheckpoint>, count: u64) -> Arc<UnitCheckpoint> {
    let mut snapshot = accepted.as_ref().clone();
    let facts = snapshot
        .partitions
        .as_mut()
        .unwrap()
        .attempts
        .last_mut()
        .unwrap()
        .usage
        .classes
        .values_mut()
        .next()
        .unwrap();
    facts.reported = Some(Count::from(count));
    facts.rate_high_water = Count::from(count);
    snapshot.metered = ValidatedSelectedCheckpoint::try_from(&snapshot)
        .and_then(|checked| checked.project())
        .unwrap()
        .partitions
        .iter()
        .any(|partition| partition.has_bill());
    // A refused publication keeps its successor: the attempt copies it before staging.
    let retained = snapshot.clone();
    let accepted = gov
        .stage_selected_checkpoint(snapshot, Some(accepted.revision))
        .unwrap();
    drop(retained);
    accepted
}

struct Measured {
    update_bytes: u64,
    dispatch_bytes: u64,
}

async fn measure(audit: usize) -> Measured {
    let runs = env_or("B_CHECKPOINT_RUNS", 1);
    let samples = env_or("B_CHECKPOINT_SAMPLES", 5).max(1);
    let mut measured = Measured {
        update_bytes: 0,
        dispatch_bytes: 0,
    };
    for run in 1..=runs {
        let gov = governance().await;
        let units: Vec<_> = (0..=samples as u32)
            .map(|n| prepared(&gov, n, audit))
            .collect();
        // The first unit warms the path; it is not counted.
        let (mut accepted, _, _) = cost(|| dispatch(&gov, &units[0]));
        let (mut times, mut bytes) = (Vec::new(), Vec::new());
        for unit in &units[1..] {
            let (committed, nanos, allocated) = cost(|| dispatch(&gov, unit));
            assert_eq!(
                committed.partitions.as_ref().unwrap().attempts[0].dispatch,
                Some(1)
            );
            times.push(nanos);
            bytes.push(allocated);
        }
        let (dispatch_ns, dispatch_bytes) = (median(&mut times), median(&mut bytes));
        let (mut times, mut bytes) = (Vec::new(), Vec::new());
        accepted = usage_update(&gov, &accepted, 1);
        for count in 2..=samples as u64 + 1 {
            let (next, nanos, allocated) = cost(|| usage_update(&gov, &accepted, count));
            assert_eq!(next.revision, accepted.revision + 1);
            accepted = next;
            times.push(nanos);
            bytes.push(allocated);
        }
        let (update_ns, update_bytes) = (median(&mut times), median(&mut bytes));
        println!(
            "B-CHECKPOINT audit={audit} run {run}: usage update median {update_ns} ns, \
             {update_bytes} bytes allocated; selected dispatch median {dispatch_ns} ns, \
             {dispatch_bytes} bytes allocated (per operation, {samples} samples)"
        );
        measured = Measured {
            update_bytes,
            dispatch_bytes,
        };
    }
    measured
}

#[tokio::test]
async fn b_checkpoint_usage_update_and_selected_dispatch() {
    measure(4 * 1024).await;
    let bound = measure(MAX_AUDIT_BYTES).await;
    // The captured audit never changes between updates: an update or a dispatch shares it and
    // allocates for what it changes, never a copy of the audit.
    assert!(
        bound.update_bytes < MAX_AUDIT_BYTES as u64,
        "a usage update copied the audit: {} bytes",
        bound.update_bytes
    );
    assert!(
        bound.dispatch_bytes < MAX_AUDIT_BYTES as u64,
        "a selected dispatch copied the audit: {} bytes",
        bound.dispatch_bytes
    );
}
