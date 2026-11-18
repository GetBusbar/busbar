// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-WALK: what one walk step pays to learn its pool's admissible members (`Pool::admissible_members`
//! and one pass over what it answers, as `shape` and `pick` make), over pools of 2, 8 and 64
//! members, without a blocklist, with one that names a member, and with one that names no member.
//!
//! It prints, for each of `B_WALK_RUNS` runs (default 5), the median and p99 of `B_WALK_SAMPLES`
//! samples (default 2,000) in ns per step, timed in batches of `B_WALK_BATCH` (default 256). Same
//! allocator as the shipped binary (jemalloc).

use std::hint::black_box;
use std::time::Instant;

use busbar_kernel_egress::ports::DestinationId;
use busbar_kernel_egress::{Failover, Member, Pool};

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

fn pool(members: u64, blocked: Option<&str>) -> Pool {
    let list = (0..members)
        .map(|i| Member::new(DestinationId::new(i), format!("member-{i}"), 1 + (i % 3) as u32))
        .collect();
    let mut pool = Pool::new("p", list);
    if let Some(name) = blocked {
        // SET-BLOCKLIST
        pool.set_failover(Failover {
            exclusions: vec![name.to_string()],
            ..Failover::default()
        });
    }
    pool
}

fn main() {
    let runs: usize = env_or("B_WALK_RUNS", 5);
    let samples: usize = env_or("B_WALK_SAMPLES", 2_000);
    let batch: usize = env_or("B_WALK_BATCH", 256);
    for members in [2u64, 8, 64] {
        for (label, blocked) in [
            ("no blocklist", None),
            ("blocklist names a member", Some("member-1")),
            ("blocklist names no member", Some("elsewhere")),
        ] {
            let pool = pool(members, blocked);
            for run in 1..=runs {
                let mut times = Vec::with_capacity(samples);
                for _ in 0..samples {
                    let start = Instant::now();
                    for _ in 0..batch {
                        // One step: the admissible list, then one pass over it (the weight sum a
                        // pick makes).
                        let admissible = black_box(&pool).admissible_members();
                        black_box(admissible.iter().map(|m| u64::from(m.weight)).sum::<u64>());
                    }
                    times.push(start.elapsed().as_nanos() as f64 / batch as f64);
                }
                times.sort_by(f64::total_cmp);
                println!(
                    "B-WALK members={members} {label} run {run}: median {:.1} ns, p99 {:.1} ns per step",
                    percentile(&times, 0.5),
                    percentile(&times, 0.99)
                );
            }
        }
    }
}
