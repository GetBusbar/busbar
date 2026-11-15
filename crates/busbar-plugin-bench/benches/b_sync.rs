// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-SYNC: one sync call through the entry guard, incl. its REFUSED arm (IF §10.7, §14, §0 I5); owner W1-H0.
//!
//! The REFUSED arm's text path (round 16/17): an auth `verify` answering REFUSED with a 60-byte text costs one
//! `scrub::fail_text` on the worker: one snapshot load and one automaton scan, no lock, no free, and a `register`
//! rebuild on another thread never blocks it. This bench times that path on an instance with 1,024 bindings
//! registered (about 14 needles each): `Scrub::text` alone on one thread, then `fail_text` on 16 threads while a
//! 17th registers a changing value in a loop (a whole-automaton rebuild each time). It prints the median and p99
//! per call and the clock's own cost per timed call, for the IF §14 gate: median ≤ the OK arm plus `text` alone
//! plus 22 ns, p99 ≤ 2 µs with the rebuild thread running. The OK arm (a no-op `verify` through `entry::guard`)
//! and the RMW counts join this file with the guard (W1-H1) and the auth adapter (W1-L5).
//!
//! `B_SYNC_CALLS` sets the calls per thread (default 1,000,000).

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Instant;

use busbar_plugin_abi::host_side::scrub::{Scrub, fail_text};

const BINDINGS: u32 = 1_024;
const READERS: usize = 16;
/// A REFUSED BAD_CREDENTIAL text, 60 bytes, with no secret in it (the shape of a credential-stuffing flood).
const REFUSED: &str = "credential rejected: the signature does not verify (kid k7).";

fn main() {
    let calls = std::env::var("B_SYNC_CALLS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000_usize);
    let scrub = Arc::new(Scrub::new());
    for slot in 0..BINDINGS {
        let value = format!("binding-{slot:04}-Zq8wLm3vT9xR2kP7");
        scrub.register(slot, &[value.as_bytes()]);
    }

    report("clock (an empty timed call)", timed(calls, || {}));
    report(
        "Scrub::text alone, 60 bytes, 1 thread",
        timed(calls, || {
            black_box(scrub.text(black_box(REFUSED)));
        }),
    );

    let stop = Arc::new(AtomicBool::new(false));
    let rebuilds = Arc::new(AtomicU64::new(0));
    let writer = {
        let (scrub, stop, rebuilds) =
            (Arc::clone(&scrub), Arc::clone(&stop), Arc::clone(&rebuilds));
        std::thread::spawn(move || {
            let mut round = 0_u64;
            while !stop.load(Ordering::Relaxed) {
                let value = format!("rotating-{round:012}");
                scrub.register(BINDINGS, &[value.as_bytes()]);
                scrub.reclaim();
                round += 1;
            }
            rebuilds.store(round, Ordering::Relaxed);
        })
    };
    let start = Arc::new(Barrier::new(READERS));
    let readers: Vec<_> = (0..READERS)
        .map(|_| {
            let (scrub, start) = (Arc::clone(&scrub), Arc::clone(&start));
            std::thread::spawn(move || {
                start.wait();
                timed(calls, || {
                    black_box(fail_text(&scrub, black_box(REFUSED)));
                })
            })
        })
        .collect();
    let mut worst = (0, 0);
    for reader in readers {
        let (median, p99) = percentiles(reader.join().expect("reader thread"));
        worst = (worst.0.max(median), worst.1.max(p99));
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().expect("rebuild thread");
    println!(
        "B-SYNC REFUSED arm, fail_text, {READERS} threads, rebuild thread running: worst thread median {} ns, \
         p99 {} ns ({calls} calls each, {} rebuilds)",
        worst.0,
        worst.1,
        rebuilds.load(Ordering::Relaxed)
    );
}

/// Nanoseconds per call of `call`, one sample per call.
fn timed(calls: usize, mut call: impl FnMut()) -> Vec<u64> {
    let mut samples = Vec::with_capacity(calls);
    for _ in 0..calls {
        let start = Instant::now();
        call();
        samples.push(u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    samples
}

fn percentiles(mut samples: Vec<u64>) -> (u64, u64) {
    samples.sort();
    let at = |q: usize| samples.get(samples.len() * q / 100).copied().unwrap_or(0);
    (at(50), at(99))
}

fn report(name: &str, samples: Vec<u64>) {
    let (median, p99) = percentiles(samples);
    println!("{name}: median {median} ns, p99 {p99} ns");
}
