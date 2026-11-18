// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-LEDGER: what one pricing lookup in the rate-card history costs, at 1, 16 and 512 entries.
//!
//! - `HistoryView::card_at` (which entry prices an instant), at an instant the NEWEST entry prices
//!   (the present: the request-path case), one an entry half-way through prices, and one the
//!   OPENING entry prices (a walk from the newest entry visits every entry before it finds it).
//! - `FeeEras::charge` then `refund` of an era already recorded, at 1, 3 and 16 eras, and the first
//!   charge of an era on an empty split (the budget bucket's per-request fee count).
//! - `HistoryView::card_for_raw_era` (the card counts accrued under one entry are priced with, any
//!   later amendment applied), for the opening entry's era.
//!
//! The history is the opening entry, then configuration edits each effective from its own later
//! instant, every fourth one bounded, and every eighth entry a back-dated amendment over a window.
//! Lookups are timed in batches of `B_LEDGER_BATCH` (default 256), so the clock's own cost is spread
//! over the batch. It prints, for each of `B_LEDGER_RUNS` runs (default 5), the median and p99 of
//! `B_LEDGER_SAMPLES` samples (default 2,000) in ns per lookup. Same allocator as the shipped binary
//! (jemalloc).

use std::hint::black_box;
use std::time::Instant;

use busbar_kernel_ledger::cost::{Author, CardEntryDraft, History, RateCard, RawRateEra};
use busbar_kernel_ledger::usage::FeeEras;

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
            "B-LEDGER {name} run {run}: median {:.1} ns, p99 {:.1} ns per lookup",
            percentile(&times, 0.5),
            percentile(&times, 0.99)
        );
    }
}

/// A history of `n` entries; instants are thousands of milliseconds apart per entry.
fn history(n: u64) -> History {
    let mut history = History::opening(RateCard::absent(0), 0);
    for i in 1..n {
        let from = 1_000 * i;
        let author = if i % 8 == 0 {
            Author::Amend {
                reason_hash: [i as u8; 32],
            }
        } else {
            Author::Config { policy_epoch: i }
        };
        let (effective_from, effective_until) = match (i % 8, i % 4) {
            (0, _) => (from - 2_500, Some(from - 500)),
            (_, 0) => (from, Some(from + 750)),
            _ => (from, None),
        };
        history.append(CardEntryDraft {
            effective_from,
            effective_until,
            card: RateCard::absent(0),
            appended_at: from,
            author,
        });
    }
    history
}

fn main() {
    let plan = Plan {
        runs: env_or("B_LEDGER_RUNS", 5),
        samples: env_or("B_LEDGER_SAMPLES", 2_000),
        batch: env_or("B_LEDGER_BATCH", 256),
    };
    // FeeEras::charge and refund (P3), at 1, 3 and 16 eras: each call hits an era already recorded,
    // cycling through them (the case a billable request meets), and one charge of an era not yet
    // recorded on a fresh split (the first request of an era).
    for n in [1u64, 3, 16] {
        let mut eras = FeeEras::<u64>::default();
        for era in 1..=n {
            eras.charge(era);
        }
        let mut at = 0u64;
        measure(&plan, &format!("fee_eras charge+refund eras={n}"), || {
            at = at % n + 1;
            eras.charge(black_box(at));
            eras.refund(black_box(at));
        });
        black_box(eras.dated());
    }
    measure(&plan, "fee_eras first charge of an era", || {
        let mut eras = FeeEras::<u64>::default();
        eras.charge(black_box(7));
        black_box(eras);
    });
    for n in [1u64, 16, 512] {
        let history = history(n);
        let view = history.current();
        let opening = &history.entries()[0];
        let era = RawRateEra::entry(opening.effective_from(), opening.id());
        // The opening entry alone prices instant 1 at every size (later entries start at 750 or later).
        let early = 1u64;
        let late = 1_000 * n + 10;
        // An instant an entry half-way through the history prices (the opening one at size 1).
        let middle = 500 * n + 10;
        assert!(
            view.card_at(early).is_some()
                && view.card_at(late).is_some()
                && view.card_at(middle).is_some()
        );
        assert!(view.card_for_raw_era(era, early).is_some());
        measure(&plan, &format!("card_at oldest entries={n}"), || {
            black_box(view.card_at(black_box(early)));
        });
        measure(&plan, &format!("card_at newest entries={n}"), || {
            black_box(view.card_at(black_box(late)));
        });
        measure(&plan, &format!("card_at middle entries={n}"), || {
            black_box(view.card_at(black_box(middle)));
        });
        measure(&plan, &format!("card_for_raw_era entries={n}"), || {
            black_box(view.card_for_raw_era(black_box(era), black_box(early)));
        });
    }
}
