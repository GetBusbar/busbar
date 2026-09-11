// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The LOOP's stage profiler — an env-guarded, permanent latency-regression tool.
//!
//! ## The table is the loop's, not a plane's
//!
//! A stage here is a STEP OF THE LOOP, and the table is `busbar_contract::unit::Step` itself plus
//! one sub-stage: the transport wait, the one await the loop parks on inside Route. There is no
//! plane vocabulary in it and there cannot be — the loop runs the same steps for every kind, so a
//! row here means the same thing whichever plane served the unit, and an operator reading the
//! report is reading the loop rather than one plane's inner shape.
//!
//! That is a deliberate replacement of what this profiler used to be. The old table named an HTTP
//! egress pipeline's internals (`lane_pick`, `client_build`, `rb_finish`, …), so it could only ever
//! describe one plane's Route step, it grew a row per refactor of that plane, and three of its rows
//! — `inbound_parse`, `upstream_send`, `post_send` — had NO call site anywhere in the workspace and
//! were enumerated by the report regardless. A report that promises an attribution the code never
//! makes is an operator surface that lies, so the table is now the one thing every request actually
//! walks, and every row in it is taped from the loop.
//!
//! ## One tap site
//!
//! Every row is recorded from `crate::teller` and from nowhere else. A stage is not something a
//! plane opts into: the loop calls the step, so the loop times the step. A plane that wants finer
//! attribution inside its own Route step uses the per-method timers (`busbar-timing`), which nest
//! inside these stages rather than adding rows to them.
//!
//! ## Cost when unset
//!
//! Every hook is one relaxed atomic load that is `false` — and branch-predicted away — unless
//! `BUSBAR_PROFILE` is present in the environment at first check. A disabled `start` takes no
//! `Instant`, allocates nothing and never touches a bucket, so the design's no-allocation rule for
//! the Teller path holds unchanged in every shipped configuration. With the env set, the profiler
//! allocates bounded per-stage sample vectors once and then reuses them.
//!
//! ## The report
//!
//! [`dump`] prints one `BUSBAR_PROFILE stage=<name> n=<count> mean=<us> p50=<us> p99=<us>` line per
//! stage that recorded a sample, in loop order, on stderr. The composition root calls it at the end
//! of a profiling run.

pub use busbar_contract::unit::Step as LoopStep;

use busbar_contract::unit::Step;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// What one sample is attributed to: a step of the loop, or the wait inside Route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    /// One of the loop's ten steps, timed over the loop's own call to it.
    Step(Step),
    /// The TRANSPORT WAIT: the loop's one await, from the moment the Route leg exists to the moment
    /// it answers. A sub-stage of Route (it is always contained in it), so the report indents it.
    Wait,
}

impl Stage {
    /// Every stage, in the order the loop reaches them — which is the report order.
    pub const ALL: [Stage; STAGE_COUNT] = [
        Stage::Step(Step::Arrival),
        Stage::Step(Step::Decode),
        Stage::Step(Step::Authenticate),
        Stage::Step(Step::Verify),
        Stage::Step(Step::Approve),
        Stage::Step(Step::Admit),
        Stage::Step(Step::Route),
        Stage::Wait,
        Stage::Step(Step::Meter),
        Stage::Step(Step::Audit),
        Stage::Step(Step::Encode),
    ];

    /// The stable report name (the `BUSBAR_PROFILE stage=` value). The step names are the loop's
    /// own words; the wait is indented because it is contained in the row above it.
    pub fn name(self) -> &'static str {
        match self {
            Stage::Step(Step::Arrival) => "arrival",
            Stage::Step(Step::Decode) => "decode",
            Stage::Step(Step::Authenticate) => "authenticate",
            Stage::Step(Step::Verify) => "verify",
            Stage::Step(Step::Approve) => "approve",
            Stage::Step(Step::Admit) => "admit",
            Stage::Step(Step::Route) => "route",
            Stage::Wait => "  wait",
            Stage::Step(Step::Meter) => "meter",
            Stage::Step(Step::Audit) => "audit",
            Stage::Step(Step::Encode) => "encode",
        }
    }

    /// Dense bucket index, for the fixed-size bucket array.
    fn idx(self) -> usize {
        match self {
            Stage::Step(s) => s as usize,
            Stage::Wait => STAGE_COUNT - 1,
        }
    }
}

/// Number of stages: the loop's ten steps, plus the transport wait.
const STAGE_COUNT: usize = 11;

/// Per-stage sample CAP. Buckets are bounded so a long-lived enabled binary cannot grow them without
/// limit (and re-sort an ever-larger `Vec` under the global `Mutex` on every [`dump`]). Once a bucket
/// is full, further samples are admitted by RESERVOIR sampling (see [`Bucket::record`]) so the
/// retained set stays a uniform sample of ALL observations - p50/p99 remain representative rather
/// than being biased toward the first N. 4096 u32s per stage is ~16 KiB/stage: plenty for stable
/// percentiles, trivially bounded memory.
const BUCKET_CAP: usize = 4096;

/// Runtime gate, as a tri-state so it can be forced without touching the process environment.
/// `0` = unread, `1` = off, `2` = on. Read once from `BUSBAR_PROFILE` (any value is on), then cached
/// — the hot path is a single relaxed load.
static ENABLED: AtomicU8 = AtomicU8::new(0);

/// True when stage profiling is enabled (a single relaxed atomic load on the hot path).
#[inline]
pub fn enabled() -> bool {
    match ENABLED.load(Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => {
            let on = std::env::var_os("BUSBAR_PROFILE").is_some();
            ENABLED.store(if on { 2 } else { 1 }, Ordering::Relaxed);
            on
        }
    }
}

/// Force the runtime gate, bypassing the environment. The seam a cell drives one request through the
/// loop with the profiler on, without a process-wide env write that every other test would see.
pub fn set_enabled(on: bool) {
    ENABLED.store(if on { 2 } else { 1 }, Ordering::Relaxed);
}

/// One stage's bounded sample store: up to [`BUCKET_CAP`] retained nanosecond durations plus a count
/// of ALL observations ever offered (`seen`). A `u32` holds up to ~4.29 s, far beyond any in-process
/// step. Bounding the retained `Vec` keeps memory and the per-[`dump`] sort cost fixed no matter how
/// long the (enabled) binary runs; `seen` drives the reservoir admission below.
#[derive(Default, Debug)]
struct Bucket {
    samples: Vec<u32>,
    seen: u64,
}

impl Bucket {
    /// Admit one sample under a fixed [`BUCKET_CAP`] via Algorithm-R reservoir sampling: while below
    /// the cap, append; once full, replace a uniformly random existing slot with probability
    /// `cap / seen`. No allocation once the cap is hit.
    fn record(&mut self, n: u32) {
        self.seen += 1;
        if self.samples.len() < BUCKET_CAP {
            self.samples.push(n);
            return;
        }
        let j = next_rand() % self.seen;
        if let Some(slot) = usize::try_from(j)
            .ok()
            .and_then(|j| self.samples.get_mut(j))
        {
            *slot = n;
        }
    }
}

/// Cheap process-local xorshift64* PRNG for reservoir admission. A deterministic seed is fine: the
/// goal is a uniform sample, not unpredictability, and this path is dev-only. It runs behind the
/// bucket `Mutex` (`record` is its only caller), so the non-atomic state is sound.
fn next_rand() -> u64 {
    static STATE: OnceLock<Mutex<u64>> = OnceLock::new();
    let mut s = STATE
        .get_or_init(|| Mutex::new(0x9E37_79B9_7F4A_7C15))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

/// Per-stage sample store, behind one `Mutex`. The lock is only ever taken on the enabled path.
fn buckets() -> &'static Mutex<Vec<Bucket>> {
    static BUCKETS: OnceLock<Mutex<Vec<Bucket>>> = OnceLock::new();
    BUCKETS.get_or_init(|| Mutex::new((0..STAGE_COUNT).map(|_| Bucket::default()).collect()))
}

/// Record `nanos` against `stage`. No-op when profiling is disabled.
#[inline]
pub fn record(stage: Stage, nanos: u64) {
    if !enabled() {
        return;
    }
    let n = u32::try_from(nanos).unwrap_or(u32::MAX);
    let mut b = buckets().lock().unwrap_or_else(|p| p.into_inner());
    b[stage.idx()].record(n);
}

/// How many samples `stage` has been offered since the last [`reset`]. The reading a cell asserts
/// on, and the `n=` column of the report.
pub fn seen(stage: Stage) -> u64 {
    buckets().lock().unwrap_or_else(|p| p.into_inner())[stage.idx()].seen
}

/// Forget every sample — the open bracket of a measured run.
pub fn reset() {
    for b in buckets()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter_mut()
    {
        b.samples.clear();
        b.seen = 0;
    }
}

/// A running stage timer: records its elapsed time into `stage` when dropped.
#[derive(Debug)]
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

/// Start a scoped [`Timer`] for one STEP of the loop — `Some` only when profiling is enabled, so a
/// disabled run does not even read the clock. Bind it to a `let _t = …;` and let the scope end.
#[inline]
pub fn step(s: Step) -> Option<Timer> {
    start(Stage::Step(s))
}

/// Start a scoped [`Timer`] for the TRANSPORT WAIT — the loop's one await.
#[inline]
pub fn wait() -> Option<Timer> {
    start(Stage::Wait)
}

/// Start a scoped [`Timer`] for any stage.
#[inline]
pub fn start(stage: Stage) -> Option<Timer> {
    enabled().then(|| Timer {
        stage,
        start: Instant::now(),
    })
}

/// Print one `BUSBAR_PROFILE` line per stage that recorded samples, with count, mean, p50 and p99 in
/// microseconds, in loop order. No-op when disabled. Percentiles are nearest-rank on the sorted
/// per-stage samples; `n=` is the TRUE observation count, which diverges from the retained length
/// once a bucket saturates and reservoir sampling takes over.
pub fn dump() {
    if !enabled() {
        return;
    }
    let mut b = buckets().lock().unwrap_or_else(|p| p.into_inner());
    for stage in Stage::ALL {
        let bucket = &mut b[stage.idx()];
        let samples = &mut bucket.samples;
        if samples.is_empty() {
            continue;
        }
        samples.sort_unstable();
        let retained = samples.len();
        let seen = bucket.seen;
        let sum: u64 = samples.iter().map(|&x| u64::from(x)).sum();
        let mean_us = (sum as f64 / retained as f64) / 1000.0;
        let pct = |p: f64| -> f64 {
            let i = (((retained - 1) as f64) * p).round() as usize;
            f64::from(samples[i]) / 1000.0
        };
        eprintln!(
            "BUSBAR_PROFILE stage={} n={} mean={:.3} p50={:.3} p99={:.3}",
            stage.name(),
            seen,
            mean_us,
            pct(0.50),
            pct(0.99),
        );
    }
}

/// Time one STEP of the loop over `f`, and hand back what the step answered.
///
/// The form the loop taps with: a step is a call, so the timer is a wrapper around the call rather
/// than a guard somebody has to remember to scope correctly. Costs one relaxed atomic load and an
/// inlined call when the profiler is off.
#[inline]
pub fn on_step<T>(s: Step, f: impl FnOnce() -> T) -> T {
    let _t = step(s);
    f()
}
