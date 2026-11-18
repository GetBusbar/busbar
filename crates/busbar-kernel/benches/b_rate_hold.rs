// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-RATE-HOLD: one rate hold's whole life against the governor: reserve, commit, observe, finish.
//!
//! The governor runs on a stepped clock (the cycle reads no OS clock), so the figure is the
//! governor's own work. It measures `Bench::cycle` at 1, 8 and 32 rules, 1, 16 and 64 classes, and
//! 0, 1 and 64 earlier minutes in which every scope still has a referenced cell.
//!
//! It prints, for each of `B_RATE_HOLD_RUNS` runs (default 5), the median and p99 of
//! `B_RATE_HOLD_SAMPLES` samples (default 500) in ns per cycle, timed in batches of
//! `B_RATE_HOLD_BATCH` (default 64). Same allocator as the shipped binary (jemalloc).

use std::time::Instant;

use busbar_kernel::test_hooks::rate_hold::Bench;

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
    let runs: usize = env_or("B_RATE_HOLD_RUNS", 5);
    let samples: usize = env_or("B_RATE_HOLD_SAMPLES", 500);
    let batch: usize = env_or("B_RATE_HOLD_BATCH", 64);
    for rules in [1usize, 8, 32] {
        for classes in [1usize, 16, 64] {
            for earlier in [0u64, 1, 64] {
                let mut bench = Bench::new(rules, classes, earlier);
                assert!(bench.cycle(), "the cycle answers Ok");
                for run in 1..=runs {
                    let mut times = Vec::with_capacity(samples);
                    for _ in 0..samples {
                        let start = Instant::now();
                        for _ in 0..batch {
                            std::hint::black_box(bench.cycle());
                        }
                        times.push(start.elapsed().as_nanos() as f64 / batch as f64);
                    }
                    times.sort_by(f64::total_cmp);
                    println!(
                        "B-RATE-HOLD rules={rules} classes={classes} earlier={earlier} run {run}: median {:.1} ns, p99 {:.1} ns per cycle",
                        percentile(&times, 0.5),
                        percentile(&times, 0.99)
                    );
                }
            }
        }
    }
}
