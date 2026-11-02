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
//! * **Process-wide:** `BUSBAR_TIMING=1` dumps the full sorted table at process exit (an
//!   `atexit(3)` hook, installed once when enabled) and on demand via [`dump`]. It merges every
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
/// With the feature ON: it expands to a [`Timer`] guard that records `Instant::now().elapsed()` into
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
    use std::collections::HashMap;
    use std::panic::catch_unwind;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::sync::{Arc, Mutex, OnceLock, Weak};
    use std::time::Instant;

    const N_BUCKETS: usize = 65;

    #[inline(always)]
    fn bucket_of(ns: u64) -> usize {
        if ns == 0 {
            0
        } else {
            (64 - ns.leading_zeros()) as usize
        }
    }

    #[inline]
    fn bucket_floor(idx: usize) -> u64 {
        if idx == 0 {
            0
        } else {
            1u64 << (idx - 1)
        }
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
    struct MethodStat {
        count: u64,
        total_ns: u64,
        min_ns: u64,
        max_ns: u64,
        buckets: [u64; N_BUCKETS],
    }

    impl Default for MethodStat {
        fn default() -> Self {
            Self {
                count: 0,
                total_ns: 0,
                min_ns: u64::MAX,
                max_ns: 0,
                buckets: [0; N_BUCKETS],
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
            self.buckets[bucket_of(ns)] += 1;
        }

        fn merge(&mut self, other: &MethodStat) {
            self.count += other.count;
            self.total_ns += other.total_ns;
            self.min_ns = self.min_ns.min(other.min_ns);
            self.max_ns = self.max_ns.max(other.max_ns);
            for (a, b) in self.buckets.iter_mut().zip(other.buckets.iter()) {
                *a += *b;
            }
        }

        fn percentile(&self, p: f64) -> u64 {
            if self.count == 0 {
                return 0;
            }
            let target = ((self.count as f64) * p).ceil().max(1.0) as u64;
            let mut cum = 0u64;
            for (idx, &c) in self.buckets.iter().enumerate() {
                cum += c;
                if cum >= target {
                    return bucket_floor(idx);
                }
            }
            self.max_ns
        }
    }

    type ThreadRegistry = HashMap<&'static str, MethodStat>;

    fn threads() -> &'static Mutex<Vec<Weak<Mutex<ThreadRegistry>>>> {
        static THREADS: OnceLock<Mutex<Vec<Weak<Mutex<ThreadRegistry>>>>> = OnceLock::new();
        THREADS.get_or_init(|| Mutex::new(Vec::new()))
    }

    fn accumulated() -> &'static Mutex<ThreadRegistry> {
        static ACCUMULATED: OnceLock<Mutex<ThreadRegistry>> = OnceLock::new();
        ACCUMULATED.get_or_init(|| Mutex::new(ThreadRegistry::new()))
    }

    fn fold_into(dst: &mut ThreadRegistry, src: &ThreadRegistry) {
        for (name, stat) in src.iter() {
            dst.entry(name).or_default().merge(stat);
        }
    }

    fn live_registries() -> Vec<Arc<Mutex<ThreadRegistry>>> {
        let mut all = threads().lock().unwrap_or_else(|p| p.into_inner());
        let mut live = Vec::with_capacity(all.len());
        all.retain(|w| match w.upgrade() {
            Some(a) => {
                live.push(a);
                true
            }
            None => false,
        });
        live
    }

    struct LocalHandle(Arc<Mutex<ThreadRegistry>>);

    impl Drop for LocalHandle {
        fn drop(&mut self) {
            let mut acc = accumulated().lock().unwrap_or_else(|p| p.into_inner());
            let taken = std::mem::take(&mut *self.0.lock().unwrap_or_else(|p| p.into_inner()));
            fold_into(&mut acc, &taken);
        }
    }

    thread_local! {
        /// This thread's accumulator. Created lazily and registered into [`threads`] on first touch;
        /// its [`LocalHandle`] wrapper hands the samples off to [`accumulated`] when the thread ends.
        static LOCAL: LocalHandle = {
            let a = Arc::new(Mutex::new(ThreadRegistry::new()));
            threads()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(Arc::downgrade(&a));
            LocalHandle(a)
        };
    }

    static ENABLED: AtomicU8 = AtomicU8::new(0);
    static ATEXIT_INSTALLED: AtomicBool = AtomicBool::new(false);

    #[inline]
    pub fn enabled() -> bool {
        match ENABLED.load(Ordering::Relaxed) {
            2 => true,
            1 => false,
            _ => {
                let on = std::env::var_os("BUSBAR_TIMING").is_some();
                ENABLED.store(if on { 2 } else { 1 }, Ordering::Relaxed);
                if on {
                    install_atexit();
                }
                on
            }
        }
    }

    pub fn set_enabled(on: bool) {
        ENABLED.store(if on { 2 } else { 1 }, Ordering::Relaxed);
        if on {
            install_atexit();
        }
    }

    fn install_atexit() {
        if ATEXIT_INSTALLED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // SAFETY: `atexit` stores a plain `extern "C"` fn pointer that takes no args and returns
            // nothing; `timing_atexit` matches that ABI and only reads process-global state.
            #[allow(unsafe_code)]
            unsafe {
                libc::atexit(timing_atexit);
            }
        }
    }

    extern "C" fn timing_atexit() {
        let _ = catch_unwind(dump);
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
        start: Option<Instant>,
    }

    impl Drop for Timer {
        #[inline]
        fn drop(&mut self) {
            if let Some(start) = self.start {
                record(self.name, start.elapsed().as_nanos() as u64);
            }
        }
    }

    #[inline]
    pub fn timer(name: &'static str) -> Timer {
        Timer {
            name,

            start: enabled().then(Instant::now),
        }
    }

    #[inline]
    pub fn scope<T>(name: &'static str, f: impl FnOnce() -> T) -> T {
        let start = enabled().then(Instant::now);
        let out = f();
        if let Some(start) = start {
            record(name, start.elapsed().as_nanos() as u64);
        }
        out
    }

    pub fn reset() {
        LOCAL.with(|h| h.0.lock().unwrap_or_else(|p| p.into_inner()).clear());

        drop(live_registries());
    }

    pub fn dump_scoped() {
        if !enabled() {
            return;
        }
        let snapshot = LOCAL.with(|h| h.0.lock().unwrap_or_else(|p| p.into_inner()).clone());
        print_table("thread", &snapshot);
    }

    pub fn dump() {
        if !enabled() {
            return;
        }
        print_table("process", &merged_snapshot());
    }

    fn merged_snapshot() -> ThreadRegistry {
        let acc = accumulated().lock().unwrap_or_else(|p| p.into_inner());
        let mut merged: ThreadRegistry = acc.clone();
        for h in live_registries() {
            let g = h.lock().unwrap_or_else(|p| p.into_inner());
            fold_into(&mut merged, &g);
        }
        merged
    }

    fn print_table(scope: &str, map: &ThreadRegistry) {
        if map.is_empty() {
            eprintln!("BUSBAR_TIMING scope={scope} (no samples)");
            return;
        }
        let mut rows: Vec<(&&'static str, &MethodStat)> = map.iter().collect();
        rows.sort_by_key(|(_, s)| std::cmp::Reverse(s.total_ns));
        eprintln!(
            "BUSBAR_TIMING scope={scope}  {:<28} {:>10} {:>11} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "name", "count", "total", "mean", "p50", "p99", "min", "max"
        );
        for (name, s) in rows {
            let mean = s.total_ns.checked_div(s.count).unwrap_or(0);
            let min = if s.min_ns == u64::MAX { 0 } else { s.min_ns };
            eprintln!(
                "BUSBAR_TIMING scope={scope}  {:<28} {:>10} {:>11} {:>10} {:>10} {:>10} {:>10} {:>10}",
                name,
                s.count,
                fmt_ns(s.total_ns),
                fmt_ns(mean),
                fmt_ns(s.percentile(0.50)),
                fmt_ns(s.percentile(0.99)),
                fmt_ns(min),
                fmt_ns(s.max_ns),
            );
        }
    }

    fn fmt_ns(ns: u64) -> String {
        if ns < 1_000 {
            format!("{ns}ns")
        } else if ns < 1_000_000 {
            format!("{:.2}us", ns as f64 / 1_000.0)
        } else {
            format!("{:.2}ms", ns as f64 / 1_000_000.0)
        }
    }

    #[cfg(test)]
    #[path = "tests/imp_tests.rs"]
    mod tests;

    #[cfg(test)]
    #[allow(unsafe_code)]
    #[path = "tests/mutation_hardening_tests.rs"]
    mod mutation_hardening_tests;
}

#[cfg(feature = "timing")]
pub use imp::set_enabled;

#[cfg(all(test, not(feature = "timing")))]
#[path = "tests/zero_cost_when_off_tests.rs"]
mod zero_cost_when_off;
