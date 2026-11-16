// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Debug-only, feature-gated per-METHOD micro-timing.
//!
//! # What it answers
//!
//! The stage profiler in `busbar-core::profile` tells you WHICH hot-path stage a request spent its
//! time in, over a closed enum of stages. This tells you, WITHIN a stage, whether a cost is
//! "1000 calls x 500ns" or "1 call x 25us" — the COUNT column is the headline. It is keyed by an
//! OPEN set of `&'static str` method names so any crate can instrument a method with one additive
//! line and no central edit; the timers nest inside the stage profiler rather than replacing it.
//!
//! # Enable model — TWO independent gates
//!
//! 1. **Compile-time (the `timing` cargo feature) — DEFAULT OFF.** With the feature OFF, `timeit!`
//!    expands to `()`, [`Timer`] is a zero-sized type with an empty `Drop`, and there is no
//!    registry, no atomics and no thread-locals in the binary. The instrumented function compiles
//!    byte-identical to the uninstrumented one. This is the always-shipped configuration.
//! 2. **Runtime (`BUSBAR_TIMING` env) — only relevant when the feature is ON.** Mirrors the
//!    `BUSBAR_PROFILE` convention exactly: recording no-ops (one relaxed atomic load) unless
//!    `BUSBAR_TIMING` is present in the environment, so a binary built WITH the feature but run
//!    without the env still pays only a predictable-branch atomic load per call site.
//!
//! # API
//!
//! ```ignore
//! let _t = busbar_kernel::timing::timeit!("govern_admit"); // RAII: records elapsed on drop
//! busbar_kernel::timing::record("hand_rolled", elapsed_ns); // manual
//! let out = busbar_kernel::timing::scope("expensive", || compute()); // fn form
//! ```
//!
//! # Report scopes
//!
//! * **Process-wide:** `BUSBAR_TIMING=1` dumps the full sorted table on demand via [`dump`]. No
//!   exit hook is installed (UNSAFE-MIN ASK-8): a caller that wants the table at exit calls it. It merges every
//!   thread's accumulator INCLUDING the threads that have already exited: accumulation is
//!   thread-local while a thread runs, and a thread MOVES its samples into a process-wide
//!   accumulator as it ends. A short-lived worker's rows therefore still appear in a table printed
//!   after it was joined, and because the hand-off moves rather than copies, a sample lives in
//!   exactly one of the two places and is never counted twice.
//! * **Per-request:** [`reset`] then [`dump_scoped`] bracket ONE request on ONE worker thread and
//!   print its method-by-method breakdown. Accumulation is thread-local, so concurrent requests on
//!   different workers never cross-contaminate.

#[cfg(not(feature = "timing"))]
mod imp {

    #[non_exhaustive]
    pub struct Timer;

    impl Drop for Timer {
        #[inline(always)]
        fn drop(&mut self) {}
    }

    #[inline(always)]
    pub fn timer(_name: &'static str) -> Timer {
        Timer
    }

    #[inline(always)]
    pub fn record(_name: &'static str, _nanos: u64) {}

    #[inline(always)]
    pub fn scope<T>(_name: &'static str, f: impl FnOnce() -> T) -> T {
        f()
    }

    #[inline(always)]
    pub fn dump() {}

    #[inline(always)]
    pub fn dump_scoped() {}

    #[inline(always)]
    pub fn reset() {}

    #[inline(always)]
    pub fn enabled() -> bool {
        false
    }
}

/// The zero-overhead scope timer. With the `timing` feature OFF: `timeit!("name")` expands to `()`.
/// With the feature ON: it expands to a [`Timer`] guard that records the elapsed monotonic nanoseconds into
/// the registry under `"name"` when it drops. Bind it to `let _t = ...;` so the whole scope is timed.
#[cfg(not(feature = "timing"))]
#[macro_export]
macro_rules! timeit {
    ($name:expr) => {
        ()
    };
}

/// See the feature-OFF definition above for the doc. This is the feature-ON expansion.
#[cfg(feature = "timing")]
#[macro_export]
macro_rules! timeit {
    ($name:expr) => {
        $crate::timing::timer($name)
    };
}

pub use imp::{dump, dump_scoped, enabled, record, reset, scope, timer, Timer};

pub use crate::timeit;

#[cfg(feature = "timing")]
mod imp {
    use foldhash::HashMap;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::{Arc, Mutex, OnceLock, Weak};

    /// The profiler's one clock seam: every sample is `now() - start`, both readings taken on the
    /// node's monotonic clock (nanoseconds since its first reading in this process).
    #[inline(always)]
    fn now() -> u64 {
        crate::store::monotonic_ns()
    }

    /// One method's accumulated stats. `count`/`total_ns`/`min_ns`/`max_ns` are exact; the histogram
    /// gives coarse p50/p99. No heap per sample — a fixed `[u64; 65]` of bucket hit counts.
    ///
    /// The buckets are `u64`, the same width as `count`, and that is not spare capacity. They were
    /// `u32` while `count` was already `u64`, so a hot method whose samples cluster in one bucket
    /// overflows a bucket long before it overflows the count — at roughly a million samples a second
    /// on one thread, in about seventy minutes. This crate is debug-only by design, and in a debug
    /// build that overflow is an arithmetic PANIC inside `record`, i.e. the measurement kills the
    /// request it was measuring. In release it silently wraps, and `percentile` then walks the whole
    /// histogram without its cumulative sum ever reaching a `target` derived from the exact `u64`
    /// count, so p50 and p99 both collapse to `max_ns` with nothing saying they are wrong. `merge`
    /// folds the per-thread histograms with the same `+=` and had the same exposure.
    #[derive(Clone)]
    pub(crate) struct MethodStat {
        pub(crate) count: u64,
        pub(crate) total_ns: u64,
        pub(crate) min_ns: u64,
        pub(crate) max_ns: u64,
        sketch: metrics_util::storage::Summary,
    }

    /// 1% relative error; 2048 bins (at most 16 KiB per method) covers 1 ns to well past an hour.
    fn sketch() -> metrics_util::storage::Summary {
        metrics_util::storage::Summary::new(0.01, 2048, 1.0)
    }

    impl Default for MethodStat {
        fn default() -> Self {
            Self {
                count: 0,
                total_ns: 0,
                min_ns: u64::MAX,
                max_ns: 0,
                sketch: sketch(),
            }
        }
    }

    impl MethodStat {
        #[inline(always)]
        fn record(&mut self, ns: u64) {
            self.count += 1;
            self.total_ns += ns;
            if ns < self.min_ns {
                self.min_ns = ns;
            }
            if ns > self.max_ns {
                self.max_ns = ns;
            }
            self.sketch.add(ns as f64);
        }

        fn merge(&mut self, other: &MethodStat) {
            self.count += other.count;
            self.total_ns += other.total_ns;
            self.min_ns = self.min_ns.min(other.min_ns);
            self.max_ns = self.max_ns.max(other.max_ns);
            // Every sketch is built by `sketch()`, so the configurations always match.
            let _ = self.sketch.merge(&other.sketch);
        }

        /// A recorded quantile, held inside the exact extents; 0 when nothing was recorded.
        pub(crate) fn percentile(&self, p: f64) -> u64 {
            self.sketch
                .quantile(p)
                .map_or(0, |v| (v.max(0.0) as u64).clamp(self.min_ns, self.max_ns))
        }
    }

    pub(crate) type ThreadRegistry = HashMap<&'static str, MethodStat>;

    /// Every live thread's accumulator, keyed by its allocation address. A thread removes its own
    /// entry as it ends (see [`LocalHandle`]), so the registry never needs a sweep.
    type Threads = HashMap<usize, Weak<Mutex<ThreadRegistry>>>;

    fn threads() -> &'static Mutex<Threads> {
        static THREADS: OnceLock<Mutex<Threads>> = OnceLock::new();
        THREADS.get_or_init(|| Mutex::new(Threads::default()))
    }

    fn thread_key(registry: &Arc<Mutex<ThreadRegistry>>) -> usize {
        Arc::as_ptr(registry) as usize
    }

    fn accumulated() -> &'static Mutex<ThreadRegistry> {
        static ACCUMULATED: OnceLock<Mutex<ThreadRegistry>> = OnceLock::new();
        ACCUMULATED.get_or_init(|| Mutex::new(ThreadRegistry::default()))
    }

    fn fold_into(dst: &mut ThreadRegistry, src: &ThreadRegistry) {
        for (name, stat) in src.iter() {
            dst.entry(name).or_default().merge(stat);
        }
    }

    /// Folds every live thread's accumulator into `dst`.
    fn fold_live_into(dst: &mut ThreadRegistry) {
        let all = threads().lock().unwrap_or_else(|p| p.into_inner());
        for registry in all.values().filter_map(Weak::upgrade) {
            let g = registry.lock().unwrap_or_else(|p| p.into_inner());
            fold_into(dst, &g);
        }
    }

    struct LocalHandle(Arc<Mutex<ThreadRegistry>>);

    impl Drop for LocalHandle {
        fn drop(&mut self) {
            let mut acc = accumulated().lock().unwrap_or_else(|p| p.into_inner());
            let taken = std::mem::take(&mut *self.0.lock().unwrap_or_else(|p| p.into_inner()));
            fold_into(&mut acc, &taken);
            drop(acc);
            threads()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&thread_key(&self.0));
        }
    }

    thread_local! {
        /// This thread's accumulator. Created lazily and registered into [`threads`] on first touch;
        /// its [`LocalHandle`] wrapper hands the samples off to [`accumulated`] when the thread ends.
        static LOCAL: LocalHandle = {
            let a = Arc::new(Mutex::new(ThreadRegistry::default()));
            threads()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(thread_key(&a), Arc::downgrade(&a));
            LocalHandle(a)
        };
    }

    static ENABLED: AtomicU8 = AtomicU8::new(0);

    #[inline]
    pub fn enabled() -> bool {
        enabled_from(|| std::env::var_os("BUSBAR_TIMING").is_some())
    }

    /// The gate, with the `BUSBAR_TIMING` environment probe as a seam: the probe runs only while
    /// the gate is unresolved, and its answer is cached.
    #[inline]
    fn enabled_from(env_says_on: impl FnOnce() -> bool) -> bool {
        match ENABLED.load(Ordering::Relaxed) {
            2 => true,
            1 => false,
            _ => {
                let on = env_says_on();
                ENABLED.store(if on { 2 } else { 1 }, Ordering::Relaxed);
                on
            }
        }
    }

    pub fn set_enabled(on: bool) {
        ENABLED.store(if on { 2 } else { 1 }, Ordering::Relaxed);
    }

    #[inline]
    pub fn record(name: &'static str, nanos: u64) {
        if !enabled() {
            return;
        }
        let landed = LOCAL.try_with(|h| {
            h.0.lock()
                .unwrap_or_else(|p| p.into_inner())
                .entry(name)
                .or_default()
                .record(nanos);
        });
        if landed.is_err() {
            accumulated()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entry(name)
                .or_default()
                .record(nanos);
        }
    }

    pub struct Timer {
        name: &'static str,
        start: Option<u64>,
    }

    impl Drop for Timer {
        #[inline]
        fn drop(&mut self) {
            if let Some(start) = self.start {
                record(self.name, now().saturating_sub(start));
            }
        }
    }

    #[inline]
    pub fn timer(name: &'static str) -> Timer {
        Timer {
            name,

            start: enabled().then(now),
        }
    }

    #[inline]
    pub fn scope<T>(name: &'static str, f: impl FnOnce() -> T) -> T {
        let _timer = timer(name);
        f()
    }

    pub fn reset() {
        LOCAL.with(|h| h.0.lock().unwrap_or_else(|p| p.into_inner()).clear());
    }

    pub fn dump_scoped() {
        if !enabled() {
            return;
        }
        let snapshot = LOCAL.with(|h| h.0.lock().unwrap_or_else(|p| p.into_inner()).clone());
        crate::off_path::timing::print_table("thread", &snapshot);
    }

    pub fn dump() {
        if !enabled() {
            return;
        }
        crate::off_path::timing::print_table("process", &merged_snapshot());
    }

    fn merged_snapshot() -> ThreadRegistry {
        let acc = accumulated().lock().unwrap_or_else(|p| p.into_inner());
        let mut merged: ThreadRegistry = acc.clone();
        fold_live_into(&mut merged);
        merged
    }

    #[cfg(test)]
    #[path = "tests/imp_tests.rs"]
    mod tests;

    #[cfg(test)]
    #[path = "tests/mutation_hardening_tests.rs"]
    mod mutation_hardening_tests;
}

#[cfg(feature = "timing")]
pub use imp::set_enabled;

#[cfg(feature = "timing")]
pub(crate) use imp::{MethodStat, ThreadRegistry};

#[cfg(all(test, not(feature = "timing")))]
#[path = "tests/zero_cost_when_off_tests.rs"]
mod zero_cost_when_off;
