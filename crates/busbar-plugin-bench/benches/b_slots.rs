// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-SLOTS: the slot table against `sharded_slab::Slab` (IF §6.5, §14; owner W1-A3). Round 8: a recorded
//! comparison, the AGREED 209/215 written reason, never a swap trigger: sharded-slab's lookup is two RMWs (the
//! `get` reference CAS and the guard's `release` CAS, sharded-slab 0.1.7 src/page/slot.rs), which I5 forbids on the
//! session lookup; busbar's is one Acquire load of the slot's state word and a compare (0 RMWs).
//!
//! - **Generation-miss lookups** (`B_SLOTS_LOOKUPS`, default 10,000,000), one thread, timed in batches of 1,000:
//!   busbar's lookup uses its unique handle's `take_if` with a generation one bit away from the live one.
//!   This includes handle dispatch plus the production page/slot/Acquire/compare miss, and touches no value.
//!   sharded-slab's comparison is a live `get` plus the guard's drop.
//! - **Insert+remove pairs under contention**: 16 threads on one table (`B_SLOTS_PAIRS` per thread, default
//!   1,000,000), each pair timed; throughput and the worst thread's median and p99.
//!
//! Run on the EC2 bench shape; the output is published with the MR.

use std::hint::black_box;
use std::sync::Barrier;
use std::time::Instant;

use busbar_plugin_abi::slots::Slots;
use sharded_slab::Slab;

const BATCH: usize = 1_000;
const THREADS: usize = 16;
const LIVE: usize = 1_024;

fn main() {
    let lookups = env("B_SLOTS_LOOKUPS", 10_000_000);
    let pairs = env("B_SLOTS_PAIRS", 1_000_000);

    let slots: Slots<u64> = Slots::new();
    let mut keys: Vec<_> = (0..LIVE as u64)
        .map(|value| slots.insert(value).expect("insert"))
        .collect();
    report(
        "B-SLOTS generation miss, busbar OwnedSlot (handle + Acquire load + compare, 0 RMW)",
        batched(lookups, |i| {
            let owned = &mut keys[i % LIVE];
            let (_, generation) = owned.identity().expect("live benchmark slot");
            black_box(owned.take_if(black_box(generation ^ 0x4000_0000)));
        }),
    );
    assert_eq!(slots.count_live(), LIVE as u32, "a lookup touched nothing");

    let slab: Slab<u64> = Slab::new();
    let slab_keys: Vec<usize> = (0..LIVE as u64)
        .map(|value| slab.insert(value).expect("insert"))
        .collect();
    report(
        "B-SLOTS lookup, sharded_slab::Slab::get + guard drop (2 RMW)",
        batched(lookups, |i| {
            black_box(slab.get(black_box(slab_keys[i % LIVE])).map(|entry| *entry));
        }),
    );

    report("clock (an empty timed call)", timed(pairs, || {}));
    contended("B-SLOTS insert+remove, busbar Slots", pairs, |value| {
        let owned = slots.insert(value).expect("insert");
        black_box(owned.take());
    });
    contended(
        "B-SLOTS insert+remove, sharded_slab::Slab",
        pairs,
        |value| {
            let key = slab.insert(value).expect("insert");
            black_box(slab.remove(key));
        },
    );
}

/// Per-op nanoseconds, one sample per batch of `BATCH` ops.
fn batched(ops: usize, mut op: impl FnMut(usize)) -> Vec<u64> {
    let batches = ops.div_ceil(BATCH).max(1);
    let mut samples = Vec::with_capacity(batches);
    let mut i = 0;
    for _ in 0..batches {
        let start = Instant::now();
        for _ in 0..BATCH {
            op(i);
            i += 1;
        }
        samples.push(nanos(start) / BATCH as u64);
    }
    samples
}

/// `THREADS` threads each run `pairs` timed pairs against the same table.
fn contended(name: &str, pairs: usize, pair: impl Fn(u64) + Sync) {
    let start_line = Barrier::new(THREADS);
    let begun = Instant::now();
    let worst = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|thread| {
                let (pair, start_line) = (&pair, &start_line);
                scope.spawn(move || {
                    start_line.wait();
                    let mut value = (thread as u64) << 40;
                    percentiles(timed(pairs, || {
                        pair(value);
                        value += 1;
                    }))
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .fold((0, 0), |worst, (median, p99)| {
                (worst.0.max(median), worst.1.max(p99))
            })
    });
    let seconds = begun.elapsed().as_secs_f64();
    let total = (THREADS * pairs) as f64;
    println!(
        "{name}, {THREADS} threads: worst thread median {} ns, p99 {} ns; {:.1} M pairs/s",
        worst.0,
        worst.1,
        total / seconds / 1e6
    );
}

/// Nanoseconds per call of `call`, one sample per call.
fn timed(calls: usize, mut call: impl FnMut()) -> Vec<u64> {
    let mut samples = Vec::with_capacity(calls);
    for _ in 0..calls {
        let start = Instant::now();
        call();
        samples.push(nanos(start));
    }
    samples
}

fn nanos(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn percentiles(mut samples: Vec<u64>) -> (u64, u64) {
    samples.sort_unstable();
    let at = |q: usize| samples.get(samples.len() * q / 100).copied().unwrap_or(0);
    (at(50), at(99))
}

fn report(name: &str, samples: Vec<u64>) {
    let (median, p99) = percentiles(samples);
    println!("{name}: median {median} ns, p99 {p99} ns");
}

fn env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
