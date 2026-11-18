// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-WINDOW: what one outcome costs the breaker cell's sliding window: one `record_success` (a push
//! into the window) plus one `outcomes_in_window` (the trip rule's read), with 16, 256 and 1,024
//! outcomes held. Outcomes are spread over the seconds so a 60-second window covers about a quarter
//! of the held ones.
//!
//! It prints, for each of `B_WINDOW_RUNS` runs (default 5), the median and p99 of
//! `B_WINDOW_SAMPLES` samples (default 500) in ns per push-and-read, timed in batches of
//! `B_WINDOW_BATCH` (default 64). Same allocator as the shipped binary (jemalloc).

use std::hint::black_box;
use std::time::Instant;

use busbar_kernel_breaker::cell::BreakerCell;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let at = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[at.min(sorted.len() - 1)]
}

fn main() {
    let runs: usize = env_or("B_WINDOW_RUNS", 5);
    let samples: usize = env_or("B_WINDOW_SAMPLES", 500);
    let batch: usize = env_or("B_WINDOW_BATCH", 64);
    for held in [16_u64, 256, 1_024] {
        // The cell's window is bounded at 1,024 outcomes, so a steady push-and-read would always run
        // full. Each sample therefore starts from a fresh cell holding `held` outcomes (made untimed)
        // and times `batch` push-and-read pairs, which leave it holding between `held` and
        // `held + batch` (at most 1,024).
        let batch = batch.min(1_024 - held as usize).max(1);
        let fresh = || {
            let cell = BreakerCell::new();
            // `held` outcomes, four to a second.
            let mut now = 1_000_000_u64;
            for at in 0..held {
                now += u64::from(at % 4 == 0);
                let _ = cell.record_success(now);
            }
            (cell, now)
        };
        for run in 1..=runs {
            let mut times = Vec::with_capacity(samples);
            for _ in 0..samples {
                let (cell, now) = fresh();
                let start = Instant::now();
                for _ in 0..batch {
                    let _ = black_box(cell.record_success(black_box(now)));
                    black_box(cell.outcomes_in_window(black_box(now), 60));
                }
                times.push(start.elapsed().as_nanos() as f64 / batch as f64);
            }
            times.sort_by(f64::total_cmp);
            println!(
                "B-WINDOW held {held} run {run}: median {:.1} ns, p99 {:.1} ns per push+read",
                percentile(&times, 0.5),
                percentile(&times, 0.99)
            );
        }
    }
}
