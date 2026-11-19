// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-SYNC: one sync call through the entry guard, incl. its REFUSED arm (IF §10.7, §14, §0 I5); owners W1-H0 and,
//! for the REFUSED arm through the auth adapter, W1-L5.
//!
//! The REFUSED arm's text path (round 16/17): an auth `verify` answering REFUSED with a 60-byte text costs one
//! `scrub::fail_text` on the worker: one snapshot load and one automaton scan, no lock, no free, and a `register`
//! rebuild on another thread never blocks it. This bench times that path on an instance with 1,024 bindings
//! registered (about 14 needles each): `Scrub::text` alone on one thread, then on 16 threads while a 17th
//! registers a changing value in a loop (a whole-automaton rebuild each time) both `fail_text` alone and the auth
//! adapter's REFUSED BAD_CREDENTIAL mapping to `Verdict::Rejected` (`adapters::auth::rejected`, the exact
//! function the adapter's `verify` runs on that answer). It prints the median and p99 per call and the clock's
//! own cost per timed call, for the IF §14 gate: median ≤ the OK arm plus `text` alone plus 22 ns, p99 ≤ 2 µs
//! with the rebuild thread running. The fixture-driven REFUSED call and the RMW counts join this file later.
//!
//! **The OK arm** (`ok_arm`, run first): a no-op transport `ingest` of 1 KiB through the port core calls (the
//! loader's adapter, the thread's answer loan, the entry guard, the answer's validation and decode), against a
//! mark derived in the same run: the same call straight through busbar-ffi, plus each kept protection timed alone,
//! plus the measured noise (`ok_arm/mod.rs`). The figure is recorded; C-ALLOC is the hard gate.
//!
//! `B_SYNC_CALLS` sets the calls per thread (default 1,000,000).

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Instant;

use busbar_plugin_abi::auth::BAD_CREDENTIAL;
use busbar_plugin_abi::host_side::scrub::{Scrub, fail_text};
use busbar_plugin_abi::transport::{pack, slot};
use busbar_plugin_abi::types::Bytes;
use busbar_plugin_loader::adapters::auth::rejected;
use busbar_ports::transport::TransportOut;

mod ok_arm;

const BINDINGS: u32 = 1_024;
const READERS: usize = 16;
/// A REFUSED BAD_CREDENTIAL text, 60 bytes, with no secret in it (the shape of a credential-stuffing flood).
const REFUSED: &str = "credential rejected: the signature does not verify (kid k7).";

/// B-SYNC's OK arm: one no-op `ingest` through the port, set against the interface floor and the kept protections.
fn ok_arm() {
    let kib = vec![7u8; 1024];
    let mut raw = ok_arm::Raw::open();
    let floor = ok_arm::time(|| {
        raw.with(|_inst, session, lease| {
            black_box(pack::ingest(1, Bytes::new(black_box(&kib)), |call| {
                session.call(slot::ingest, call, lease)
            }));
        });
    });
    let port = ok_arm::Port::open();
    let mut session = port.begin();
    let ok = ok_arm::time(|| {
        port.port
            .ingest(&mut session, black_box(&kib), &mut |_o: TransportOut<
                '_,
            >| {})
            .expect("a no-op ingest answers OK");
    });
    let kept = ok_arm::protections();
    ok_arm::verdict("B-SYNC OK arm, transport ingest 1 KiB", ok, floor, &kept);
}

fn main() {
    ok_arm();
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

    contended("fail_text", &scrub, calls, |scrub| {
        black_box(fail_text(scrub, black_box(REFUSED)));
    });
    contended(
        "auth adapter, REFUSED BAD_CREDENTIAL to Verdict::Rejected",
        &scrub,
        calls,
        |scrub| {
            black_box(rejected(BAD_CREDENTIAL, black_box(REFUSED), scrub));
        },
    );
}

/// `call` on 16 reader threads, `calls` times each, while a 17th thread rebuilds the automaton in a loop.
fn contended(name: &str, scrub: &Arc<Scrub>, calls: usize, call: fn(&Scrub)) {
    let stop = Arc::new(AtomicBool::new(false));
    let rebuilds = Arc::new(AtomicU64::new(0));
    let writer = {
        let (scrub, stop, rebuilds) = (Arc::clone(scrub), Arc::clone(&stop), Arc::clone(&rebuilds));
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
            let (scrub, start) = (Arc::clone(scrub), Arc::clone(&start));
            std::thread::spawn(move || {
                start.wait();
                timed(calls, || call(&scrub))
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
        "B-SYNC REFUSED arm, {name}, {READERS} threads, rebuild thread running: worst thread median {} ns, \
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
