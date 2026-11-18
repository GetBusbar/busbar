// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-LOOKUP: what the lookups of `busbar_contract::lookup` cost against the scans they replace.
//!
//! - `Indexed::get` against a `Vec` scan (`iter().find`) for the last-inserted key, at 1, 3, 16 and
//!   256 rows (the scan's worst case is the last row; the first row is its best).
//! - `ByGroup`: one insert and one remove by key, and one `take_group` of a whole group, at group
//!   sizes 1 and 16, beside 1 and 1,024 rows of other groups.
//! - `Bits<4>::keep_only`.
//!
//! Each operation is timed in batches of `B_LOOKUP_BATCH` (default 256), so the clock's own cost is
//! spread over the batch; a sample is one batch's time divided by its size. It prints, for each of
//! `B_LOOKUP_RUNS` runs (default 5), the median and p99 of `B_LOOKUP_SAMPLES` samples (default
//! 2,000) in ns per operation. Same allocator as the shipped binary (jemalloc).

use std::hint::black_box;
use std::time::Instant;

use busbar_contract::lookup::{Bits, ByGroup, Indexed};

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

struct Plan {
    runs: usize,
    samples: usize,
    batch: usize,
}

/// Time `op` per call: `samples` batches of `batch` calls; median and p99 ns per call, per run.
fn measure(plan: &Plan, name: &str, mut op: impl FnMut()) {
    for _ in 0..plan.samples / 10 {
        op();
    }
    for run in 1..=plan.runs {
        let mut times = Vec::with_capacity(plan.samples);
        for _ in 0..plan.samples {
            let start = Instant::now();
            for _ in 0..plan.batch {
                op();
            }
            times.push(start.elapsed().as_nanos() as f64 / plan.batch as f64);
        }
        times.sort_by(f64::total_cmp);
        println!(
            "B-LOOKUP {name} run {run}: median {:.1} ns, p99 {:.1} ns per op",
            percentile(&times, 0.5),
            percentile(&times, 0.99)
        );
    }
}

fn keyed_rows(plan: &Plan) {
    for rows in [1u64, 3, 16, 256] {
        let mut indexed = Indexed::<u64, u64>::new();
        let mut list: Vec<(u64, u64)> = Vec::new();
        for key in 0..rows {
            // Keys spread out, as era timestamps or ids are.
            let key = key.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            *indexed.row(key, || 0) = key;
            list.push((key, key));
        }
        let last = list[list.len() - 1].0;
        let first = list[0].0;
        measure(plan, &format!("Indexed::get rows={rows}"), || {
            black_box(indexed.get(black_box(&last)));
        });
        measure(plan, &format!("Vec scan last rows={rows}"), || {
            let key = black_box(last);
            black_box(list.iter().find(|(k, _)| *k == key));
        });
        measure(plan, &format!("Vec scan first rows={rows}"), || {
            let key = black_box(first);
            black_box(list.iter().find(|(k, _)| *k == key));
        });
    }
}

fn grouped_rows(plan: &Plan) {
    for others in [1u64, 1024] {
        for size in [1u64, 16] {
            let mut table = ByGroup::<u64, u64, u64>::new();
            // Other groups' rows: 4 rows a group.
            for key in 0..others {
                table.insert(1_000_000 + key, 1_000_000 + key / 4, key);
            }
            let group = 7u64;
            for key in 0..size {
                table.insert(key, group, key);
            }
            let probe = size;
            measure(
                plan,
                &format!("ByGroup insert+remove size={size} others={others}"),
                || {
                    table.insert(black_box(probe), group, probe);
                    black_box(table.remove(black_box(&probe)));
                },
            );
            measure(
                plan,
                &format!("ByGroup take_group (and refill) size={size} others={others}"),
                || {
                    let mut taken = 0u64;
                    table.take_group(black_box(&group), |_, value| taken += value);
                    black_box(taken);
                    for key in 0..size {
                        table.insert(key, group, key);
                    }
                },
            );
        }
    }
}

fn bits(plan: &Plan) {
    let mut set = Bits::<4>::all_below(200).unwrap_or_default();
    let mut other = Bits::<4>::new();
    for id in (0..256).step_by(3) {
        other.insert(id);
    }
    let full = set;
    measure(plan, "Bits<4>::keep_only", || {
        set = full;
        set.keep_only(black_box(&other));
        black_box(set.len());
    });
}

fn main() {
    let plan = Plan {
        runs: env_or("B_LOOKUP_RUNS", 5),
        samples: env_or("B_LOOKUP_SAMPLES", 2_000),
        batch: env_or("B_LOOKUP_BATCH", 256),
    };
    keyed_rows(&plan);
    grouped_rows(&plan);
    bits(&plan);
}
