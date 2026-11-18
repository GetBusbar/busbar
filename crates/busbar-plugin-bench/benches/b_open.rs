// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-OPEN, the session-table arm (IF §14, §6.5, §0 I5's stated exception; owner W1-A3). A session open is one
//! CAS on the session table's free list (insert) and an end is one more (remove); under 16-thread contention on
//! one instance that shared head is the only thing §6.5's failure branch changes (a per-thread-sharded free
//! list, the lookup untouched). This arm times exactly that: 16 threads open sessions on **one** table and end
//! them, half on the opening thread and half on its partner (tokio's work-stealing shape), with a 32-byte session
//! state. It prints the worst thread's median and p99 per open and per end, and their sum per pair.
//!
//! The IF §14 gate (median ≤ 120 ns, p99 ≤ 1 µs per plane `request`+`end` or transport `begin`+drop pair) also
//! counts the session handle's `Arc<Instance>` pair and the entry; that end-to-end arm runs through the port's
//! session handle once `kind!` (W1-A4) and the host proxies (W1-H1) land. If this arm alone fails the gate on the
//! free-list CAS, the §6.5 branch is the next step (busbar-ffi's `slots.rs`, an owner-pinned file since UNSAFE-MIN
//! r3.1).
//!
//! `B_OPEN_PAIRS` sets the pairs per thread (default 1,000,000), run in rounds of 1,024 open sessions per thread.

use std::sync::{Barrier, Mutex, PoisonError};
use std::time::Instant;

use busbar_plugin_abi::slots::{OwnedSlot, Slots};

const THREADS: usize = 16;
const ROUND: usize = 1_024;

/// A 32-byte session state.
type Session = [u64; 4];

fn main() {
    let pairs = std::env::var("B_OPEN_PAIRS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000_usize);
    let rounds = pairs.div_ceil(ROUND).max(1);
    let table: Slots<Session> = Slots::new();
    let handoff: Vec<Mutex<Vec<OwnedSlot<'_, Session>>>> =
        (0..THREADS).map(|_| Mutex::new(Vec::new())).collect();
    let barrier = Barrier::new(THREADS);
    let worst = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|thread| {
                let (table, handoff, barrier) = (&table, &handoff, &barrier);
                scope.spawn(move || worker(thread, rounds, table, handoff, barrier))
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .fold([0u64; 4], |worst, thread| {
                [
                    worst[0].max(thread[0]),
                    worst[1].max(thread[1]),
                    worst[2].max(thread[2]),
                    worst[3].max(thread[3]),
                ]
            })
    });
    assert_eq!(table.count_live(), 0, "every session ended once");
    println!(
        "B-OPEN session table, {THREADS} threads on one table, half the ends on another thread \
         ({} pairs per thread): open median {} ns p99 {} ns; end median {} ns p99 {} ns; pair median {} ns p99 {} ns",
        rounds * ROUND,
        worst[0],
        worst[1],
        worst[2],
        worst[3],
        worst[0] + worst[2],
        worst[1] + worst[3]
    );
}

/// One thread: per round, open `ROUND` sessions, hand the second half to its partner, end its first half and the
/// partner's second half. Returns [open median, open p99, end median, end p99].
fn worker<'table>(
    thread: usize,
    rounds: usize,
    table: &'table Slots<Session>,
    handoff: &[Mutex<Vec<OwnedSlot<'table, Session>>>],
    barrier: &Barrier,
) -> [u64; 4] {
    let mut opens = Vec::with_capacity(rounds * ROUND);
    let mut ends = Vec::with_capacity(rounds * ROUND);
    let mut mine = Vec::with_capacity(ROUND);
    let seed = thread as u64;
    for _ in 0..rounds {
        barrier.wait();
        for i in 0..ROUND as u64 {
            let start = Instant::now();
            let token = table.insert([seed, i, 0, 0]);
            opens.push(nanos(start));
            mine.push(token.expect("the session table is exhausted"));
        }
        let given = mine.split_off(ROUND / 2);
        *handoff[thread]
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = given;
        barrier.wait();
        let taken = std::mem::take(
            &mut *handoff[thread ^ 1]
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for owned in mine.drain(..).chain(taken) {
            let start = Instant::now();
            let ended = owned.take();
            ends.push(nanos(start));
            assert!(ended.is_some(), "a session ends once");
        }
    }
    let (open_median, open_p99) = percentiles(opens);
    let (end_median, end_p99) = percentiles(ends);
    [open_median, open_p99, end_median, end_p99]
}

fn nanos(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn percentiles(mut samples: Vec<u64>) -> (u64, u64) {
    samples.sort();
    let at = |q: usize| samples.get(samples.len() * q / 100).copied().unwrap_or(0);
    (at(50), at(99))
}
