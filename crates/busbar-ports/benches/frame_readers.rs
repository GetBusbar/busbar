// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-FRAME: what handing one request's data to three readers costs, in three shapes. Recorded once,
//! before the pool is deleted (hand-offs step 1D).
//!
//! One payload: a value of four 256-byte buffers, handed to three readers (a stage read by a hook
//! worker and two taps). A cycle is one request: make the data, hand it to the three readers, each
//! reads it, drop everything.
//!
//! | shape | one cycle |
//! |---|---|
//! | copy | build the value; clone the whole value for each of the three readers; drop all four |
//! | fresh frame | `Arc::new(value)`; three `Arc::clone`; drop all four |
//! | pool | `pool.take()`, `fill()`, three `share()`; drop all four |
//!
//! Each shape runs on 1 thread and on 8 threads at once. Per shape it prints: nanoseconds per cycle
//! (each thread's own elapsed time over its own cycles, averaged over the threads), allocations per
//! cycle (a counting allocator over the whole process), and the bytes still allocated when the loop
//! has ended and every value is dropped (the pool still alive: it is what a pool keeps).

use busbar_ports::frame::{FramePool, Reset};
use stats_alloc::{StatsAlloc, INSTRUMENTED_SYSTEM};
use std::alloc::System;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

#[global_allocator]
static COUNTING: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Four 256-byte buffers: the shape of a request's hand-off data.
#[derive(Default, Clone)]
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

    fn read(&self) -> usize {
        self.a.len() + self.b.len() + self.c.len() + self.d.len()
    }
}

const CYCLES: usize = 200_000;
const WARM: usize = 2_000;

/// What the readers do: each reads the whole value.
fn readers(first: &Four, second: &Four, third: &Four) -> usize {
    first.read() + second.read() + third.read()
}

fn copy_cycle() {
    let mut value = Four::default();
    value.write();
    let (first, second, third) = (value.clone(), value.clone(), value.clone());
    black_box(readers(&first, &second, &third));
}

fn fresh_cycle() {
    let mut value = Four::default();
    value.write();
    let value = Arc::new(value);
    let (first, second, third) = (Arc::clone(&value), Arc::clone(&value), Arc::clone(&value));
    black_box(readers(&first, &second, &third));
}

fn pool_cycle(pool: &Arc<FramePool<Four>>) {
    let mut frame = pool.take();
    if let Some(four) = frame.fill() {
        four.write();
    }
    let (first, second, third) = (frame.share(), frame.share(), frame.share());
    black_box(readers(&first, &second, &third));
}

/// Run `cycle` on `threads` threads at once, `CYCLES` each: the mean of each thread's own ns per cycle.
fn timed(threads: usize, cycle: &(dyn Fn() + Sync)) -> f64 {
    let sum = std::sync::Mutex::new(0.0_f64);
    let start = std::sync::Barrier::new(threads);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                for _ in 0..WARM {
                    cycle();
                }
                start.wait();
                let begun = Instant::now();
                for _ in 0..CYCLES {
                    cycle();
                }
                let ns = begun.elapsed().as_nanos() as f64 / CYCLES as f64;
                *sum.lock().unwrap() += ns;
            });
        }
    });
    sum.into_inner().unwrap() / threads as f64
}

fn report(shape: &str, threads: usize, cycle: &(dyn Fn() + Sync), held: &dyn Fn() -> isize) {
    // Warm every thread's allocator state first, then count a clean run.
    let before = COUNTING.stats();
    let ns = timed(threads, cycle);
    let after = COUNTING.stats();
    let total = (threads * (CYCLES + WARM)) as f64;
    let allocations = (after.allocations - before.allocations) as f64 / total;
    println!(
        "{shape:<12} {threads} thread(s) {ns:>9.1} ns/cycle {allocations:>6.1} allocs/cycle {:>8} bytes held after",
        held()
    );
}

fn live() -> isize {
    let stats = COUNTING.stats();
    stats.bytes_allocated as isize - stats.bytes_deallocated as isize + stats.bytes_reallocated
}

fn main() {
    for threads in [1, 8] {
        let base = live();
        report("copy", threads, &copy_cycle, &|| live() - base);

        let base = live();
        report("fresh frame", threads, &fresh_cycle, &|| live() - base);

        let base = live();
        let pool = FramePool::<Four>::build(threads * 4);
        report("pool", threads, &|| pool_cycle(&pool), &|| live() - base);
        drop(pool);
    }
}
