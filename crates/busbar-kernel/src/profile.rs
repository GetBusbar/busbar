// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Fine-grained, ENV-GUARDED hot-path stage profiler — a permanent latency-regression tool.
//!
//! Answers the question "where does the per-request in-process time go — one fat stage or a thousand
//! small cuts?" at line/stage granularity, without perturbing the release hot path: every hook is a
//! single relaxed atomic-bool load ([`enabled`]) that is `false` (and branch-predicted away) unless
//! `BUSBAR_PROFILE` is set in the environment. Same opt-in pattern as `BUSBAR_CAPTURE_METRICS`.
//!
//! Usage on the hot path:
//! ```ignore
//! let _t = crate::profile::start(crate::profile::Stage::Finish);
//! // ... work ...
//! drop(_t); // records elapsed nanos into the Finish bucket (no-op when disabled)
//! ```
//! or the explicit form [`record`] when a scope guard doesn't fit (across `?`/early-return arms).
//!
//! At the end of a profiling run the driver (the `capture_latency_metrics` test) calls [`dump`],
//! which prints one `BUSBAR_PROFILE stage=<name> n=<count> mean=<us> p50=<us> p99=<us>` line per
//! stage that recorded at least one sample. Buckets accumulate across the whole run.
//!
//! Zero cost when unset: `enabled()` reads one `AtomicBool` initialized ONCE from the env; a disabled
//! `start`/`record` does nothing and allocates nothing. The buckets themselves are only ever touched
//! on the enabled path.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// The hot-path stages attributed by the profiler. The report order is [`dump`]'s list; a stage with
/// no call site simply reports zero samples. Nothing counts these variants: a stage's bucket is made
/// the first time it records, so adding one needs no second edit to stay safe.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// `auth_middleware` pre-handler work: carrier token extract + chain/cache verdict + extension
    /// inserts (the span ends BEFORE `next.run`, so downstream time is not attributed here).
    MwAuth,
    /// The ingress `finish` boundary: metrics record + request-log gate + refund check.
    Finish,
}

impl Stage {
    fn name(self) -> &'static str {
        match self {
            Stage::MwAuth => "mw_auth",
            Stage::Finish => "finish",
        }
    }
}

fn enabled_cell() -> &'static AtomicBool {
    static ENABLED: OnceLock<AtomicBool> = OnceLock::new();
    ENABLED.get_or_init(|| AtomicBool::new(std::env::var_os("BUSBAR_PROFILE").is_some()))
}

#[inline]
pub fn enabled() -> bool {
    enabled_cell().load(Ordering::Relaxed)
}
/// One stage's samples: a metrics-util `Summary` (DDSketch, 1% relative error, at most 16 KiB) over
/// every observation, plus the exact count and sum. Memory and the [`dump`] cost stay bounded no
/// matter how long the (enabled) binary runs, and every sample counts (no reservoir).
struct Bucket {
    sketch: metrics_util::storage::Summary,
    seen: u64,
    sum_ns: u64,
}

impl Default for Bucket {
    fn default() -> Self {
        Bucket {
            sketch: metrics_util::storage::Summary::new(0.01, 2048, 1.0),
            seen: 0,
            sum_ns: 0,
        }
    }
}

impl Bucket {
    fn record(&mut self, n: u32) {
        self.seen += 1;
        self.sum_ns += u64::from(n);
        self.sketch.add(f64::from(n));
    }

    /// The `dump` line for this stage, or `None` when it recorded nothing.
    fn line(&self, stage: Stage) -> Option<String> {
        if self.seen == 0 {
            return None;
        }
        let pct = |p: f64| self.sketch.quantile(p).unwrap_or(0.0) / 1000.0;
        Some(format!(
            "BUSBAR_PROFILE stage={} n={} mean={:.3} p50={:.3} p99={:.3}",
            stage.name(),
            self.seen,
            (self.sum_ns as f64 / self.seen as f64) / 1000.0,
            pct(0.50),
            pct(0.99),
        ))
    }
}

fn buckets() -> &'static Mutex<Vec<(Stage, Bucket)>> {
    static BUCKETS: OnceLock<Mutex<Vec<(Stage, Bucket)>>> = OnceLock::new();
    BUCKETS.get_or_init(|| Mutex::new(Vec::new()))
}

fn bucket_for(store: &mut Vec<(Stage, Bucket)>, stage: Stage) -> &mut Bucket {
    let at = match store.iter().position(|(s, _)| *s == stage) {
        Some(at) => at,
        None => {
            store.push((stage, Bucket::default()));
            store.len() - 1
        }
    };
    &mut store[at].1
}

#[inline]
pub(crate) fn record(stage: Stage, nanos: u64) {
    if !enabled() {
        return;
    }
    let n = u32::try_from(nanos).unwrap_or(u32::MAX);
    let mut b = buckets().lock().unwrap_or_else(|p| p.into_inner());
    bucket_for(&mut b, stage).record(n);
}

pub struct Timer {
    stage: Stage,
    start: Instant,
}

impl Drop for Timer {
    #[inline]
    fn drop(&mut self) {
        record(self.stage, self.start.elapsed().as_nanos() as u64);
    }
}

#[inline]
pub fn start(stage: Stage) -> Option<Timer> {
    let start = enabled().then(Instant::now)?;
    Some(Timer { stage, start })
}

pub fn dump() {
    if !enabled() {
        return;
    }
    let mut b = buckets().lock().unwrap_or_else(|p| p.into_inner());

    let order = [Stage::MwAuth, Stage::Finish];
    b.sort_by_key(|(stage, _)| order.iter().position(|s| s == stage).unwrap_or(usize::MAX));
    for line in b.iter().filter_map(|(stage, bucket)| bucket.line(*stage)) {
        eprintln!("{line}");
    }
}

#[cfg(test)]
#[path = "tests/profile_tests.rs"]
mod tests;
