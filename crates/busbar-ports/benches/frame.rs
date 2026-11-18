// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-FRAME: the cost of one request frame cycle, against a fresh allocation of the same value.
//! Prints nanoseconds per cycle.

use busbar_ports::frame::{FramePool, Reset};
use std::hint::black_box;
use std::time::Instant;

/// Four 256-byte buffers: the shape of a request's hand-off data.
#[derive(Default)]
struct Four {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
    d: Vec<u8>,
}

impl Reset for Four {
    fn reset(&mut self) {
        self.a.clear();
        self.b.clear();
        self.c.clear();
        self.d.clear();
    }
}

impl Four {
    fn write(&mut self) {
        let line = [0x5a_u8; 256];
        self.a.extend_from_slice(&line);
        self.b.extend_from_slice(&line);
        self.c.extend_from_slice(&line);
        self.d.extend_from_slice(&line);
    }

    fn len(&self) -> usize {
        self.a.len() + self.b.len() + self.c.len() + self.d.len()
    }
}

const CYCLES: usize = 1_000_000;

fn report(name: &str, took: std::time::Duration, cycles: usize) {
    let ns = took.as_nanos() as f64 / cycles as f64;
    println!("{name:<52} {ns:>9.1} ns/cycle");
}

fn main() {
    // Baseline: a fresh value per request, four buffers grown, dropped.
    let start = Instant::now();
    for _ in 0..CYCLES {
        let mut fresh = Four::default();
        fresh.write();
        black_box(fresh.len());
    }
    report("fresh allocation (4 x 256 B)", start.elapsed(), CYCLES);

    // One thread: take, write, drop.
    let pool = FramePool::<Four>::build(8);
    let start = Instant::now();
    for _ in 0..CYCLES {
        let mut frame = pool.take();
        if let Some(four) = frame.fill() {
            four.write();
        }
        black_box(frame.len());
    }
    report("frame: take + write + drop", start.elapsed(), CYCLES);

    // Two threads: take, share to a second thread, drop both.
    let start = Instant::now();
    for _ in 0..CYCLES / 10 {
        let mut frame = pool.take();
        if let Some(four) = frame.fill() {
            four.write();
        }
        let held = frame.share();
        let worker = std::thread::spawn(move || black_box(held.len()));
        drop(frame);
        let _ = worker.join();
    }
    report(
        "frame: take + share to 2nd thread + drop (spawn incl.)",
        start.elapsed(),
        CYCLES / 10,
    );

    // Eight threads contending on one pool.
    let pool = FramePool::<Four>::build(8);
    let start = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..CYCLES / 8 {
                    let mut frame = pool.take();
                    if let Some(four) = frame.fill() {
                        four.write();
                    }
                    black_box(frame.len());
                }
            });
        }
    });
    report("frame: 8 threads, one pool", start.elapsed(), CYCLES);
}
