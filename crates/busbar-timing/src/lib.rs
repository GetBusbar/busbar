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
//! let _t = busbar_timing::timeit!("govern_admit"); // RAII: records elapsed on drop
//! busbar_timing::record("hand_rolled", elapsed_ns); // manual
//! let out = busbar_timing::scope("expensive", || compute()); // fn form
//! ```
//!
//! # Report scopes
//!
//! * **Process-wide:** `BUSBAR_TIMING=1` dumps the full sorted table at process exit (an
//!   `atexit(3)` hook, installed once when enabled) and on demand via [`dump`]. Merges every
//!   thread's accumulator.
//! * **Per-request:** [`reset`] then [`dump_scoped`] bracket ONE request on ONE worker thread and
//!   print its method-by-method breakdown. Accumulation is thread-local, so concurrent requests on
//!   different workers never cross-contaminate.

// ─────────────────────────────────────────────────────────────────────────────────────────────
// FEATURE OFF (default): everything below is a no-op. `timeit!` -> `()`, `Timer` is a ZST with an
// empty Drop, and the record/scope/dump/reset entry points are `#[inline]` empty fns the optimizer
// deletes at every call site. No registry, no atomics, no thread-locals are compiled in.
// ─────────────────────────────────────────────────────────────────────────────────────────────
#[cfg(not(feature = "timing"))]
mod imp {
    /// Feature-OFF [`Timer`] guard: a ZERO-SIZED type with an empty `Drop`. `size_of::<Timer>() == 0`
    /// (asserted by the `zero_cost_when_off` test) and dropping it does nothing, so an instrumented
    /// `let _t = timeit!(..)` binds a ZST that leaves no trace in codegen.
    #[non_exhaustive]
    pub struct Timer;

    impl Drop for Timer {
        #[inline(always)]
        fn drop(&mut self) {}
    }

    /// Feature-OFF constructor — used by the (rare) explicit-type call site; the `timeit!` macro
    /// does not even reference it (it expands to `()`), but it exists so `Timer` has a public ctor.
    #[inline(always)]
    pub fn timer(_name: &'static str) -> Timer {
        Timer
    }

    /// Feature-OFF [`crate::record`]: no-op.
    #[inline(always)]
    pub fn record(_name: &'static str, _nanos: u64) {}

    /// Feature-OFF [`crate::scope`]: runs `f` with zero timing overhead.
    #[inline(always)]
    pub fn scope<T>(_name: &'static str, f: impl FnOnce() -> T) -> T {
        f()
    }

    /// Feature-OFF [`crate::dump`]: no-op.
    #[inline(always)]
    pub fn dump() {}

    /// Feature-OFF [`crate::dump_scoped`]: no-op.
    #[inline(always)]
    pub fn dump_scoped() {}

    /// Feature-OFF [`crate::reset`]: no-op.
    #[inline(always)]
    pub fn reset() {}

    /// Feature-OFF [`crate::enabled`]: always `false`.
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
        $crate::timer($name)
    };
}

pub use imp::{dump, dump_scoped, enabled, record, reset, scope, timer, Timer};

// ─────────────────────────────────────────────────────────────────────────────────────────────
// FEATURE ON: the real registry.
// ─────────────────────────────────────────────────────────────────────────────────────────────
#[cfg(feature = "timing")]
mod imp {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Instant;

    /// Number of log2 histogram buckets. A duration's bucket is `64 - leading_zeros(ns)` (0 for a
    /// zero-ns sample), i.e. bucket `i` holds `[2^(i-1), 2^i)` ns. 65 buckets cover 0 ns up to
    /// ~1.8e19 ns (584 years) — every conceivable in-process span — with NO per-sample allocation.
    /// The spacing is coarse (a factor of 2 per bucket) but ample to tell 500ns from 25us apart,
    /// which is the whole job of the p50/p99 columns here.
    const N_BUCKETS: usize = 65;

    /// The bucket index for `ns`: `0` for a zero sample, else `64 - ns.leading_zeros()` so the
    /// bucket's lower bound is `1 << (idx - 1)`. Branch-free, a few instructions, no allocation.
    #[inline(always)]
    fn bucket_of(ns: u64) -> usize {
        if ns == 0 {
            0
        } else {
            (64 - ns.leading_zeros()) as usize
        }
    }

    /// The representative (lower-bound) nanosecond value for bucket `idx`, used when a percentile
    /// falls in that bucket. Coarse by construction — a power of two.
    #[inline]
    fn bucket_floor(idx: usize) -> u64 {
        if idx == 0 {
            0
        } else {
            1u64 << (idx - 1)
        }
    }

    /// One method's accumulated stats. `count`/`total_ns`/`min_ns`/`max_ns` are exact; the histogram
    /// gives coarse p50/p99. No heap per sample — a fixed `[u32; 65]` of bucket hit counts.
    #[derive(Clone)]
    struct MethodStat {
        count: u64,
        total_ns: u64,
        min_ns: u64,
        max_ns: u64,
        buckets: [u32; N_BUCKETS],
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

        /// Fold `other` into `self` — the process-wide [`dump`] merge across per-thread registries.
        fn merge(&mut self, other: &MethodStat) {
            self.count += other.count;
            self.total_ns += other.total_ns;
            self.min_ns = self.min_ns.min(other.min_ns);
            self.max_ns = self.max_ns.max(other.max_ns);
            for (a, b) in self.buckets.iter_mut().zip(other.buckets.iter()) {
                *a += *b;
            }
        }

        /// Nearest-rank percentile from the histogram, reported as the bucket's lower bound (ns).
        /// `p` in [0,1]. Coarse: resolution is a factor of two, which is all that is needed to
        /// separate a sub-microsecond method from a tens-of-microseconds one.
        fn percentile(&self, p: f64) -> u64 {
            if self.count == 0 {
                return 0;
            }
            let target = ((self.count as f64) * p).ceil().max(1.0) as u64;
            let mut cum = 0u64;
            for (idx, &c) in self.buckets.iter().enumerate() {
                cum += c as u64;
                if cum >= target {
                    return bucket_floor(idx);
                }
            }
            self.max_ns
        }
    }

    /// One thread's method map. The hot path only ever touches its OWN thread's registry, so the
    /// per-call lock below is uncontended in steady state (contended only briefly during a [`dump`]).
    type ThreadRegistry = HashMap<&'static str, MethodStat>;

    /// The set of every thread's registry, so a process-wide [`dump`] can merge them. Each thread
    /// pushes its `Arc` here once, on first use. `Arc<Mutex<..>>` (not `RefCell`) because [`dump`]
    /// reads another thread's data — the `Arc`/`Mutex` is what makes that sound, not `unsafe`.
    fn threads() -> &'static Mutex<Vec<Arc<Mutex<ThreadRegistry>>>> {
        static THREADS: OnceLock<Mutex<Vec<Arc<Mutex<ThreadRegistry>>>>> = OnceLock::new();
        THREADS.get_or_init(|| Mutex::new(Vec::new()))
    }

    thread_local! {
        /// This thread's accumulator. Created lazily and registered into [`threads`] on first touch.
        static LOCAL: Arc<Mutex<ThreadRegistry>> = {
            let a = Arc::new(Mutex::new(ThreadRegistry::new()));
            threads()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(a.clone());
            a
        };
    }

    /// Runtime enable tri-state cache. `0` = unread, `1` = disabled, `2` = enabled. Read once from
    /// the `BUSBAR_TIMING` env (any value = on), then cached — the hot path is a single relaxed load.
    /// [`set_enabled`] can force it (used by the smoke test to drive a dump without touching the env).
    static ENABLED: AtomicU8 = AtomicU8::new(0);
    static ATEXIT_INSTALLED: AtomicBool = AtomicBool::new(false);

    /// True when method timing should record — one relaxed atomic load in steady state. Mirrors
    /// `busbar_core::profile::enabled`: on iff `BUSBAR_TIMING` was present at first read (or forced).
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

    /// Force the runtime gate on/off, bypassing the env. Test/embedding hook: the smoke test calls
    /// `set_enabled(true)` so it can record and [`dump`] without a `BUSBAR_TIMING` in the process env.
    pub fn set_enabled(on: bool) {
        ENABLED.store(if on { 2 } else { 1 }, Ordering::Relaxed);
        if on {
            install_atexit();
        }
    }

    /// Install the process-exit dump once. `atexit(3)` runs the handler after `main` returns.
    fn install_atexit() {
        if ATEXIT_INSTALLED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // SAFETY: `atexit` stores a plain `extern "C"` fn pointer that takes no args and returns
            // nothing; `timing_atexit` matches that ABI and only reads process-global state.
            unsafe {
                libc::atexit(timing_atexit);
            }
        }
    }

    extern "C" fn timing_atexit() {
        dump();
    }

    /// Record `nanos` against `name`. No-op unless [`enabled`]. The recording cost is: a relaxed
    /// atomic load, a thread-local access, an uncontended mutex lock, a `HashMap` probe and a
    /// handful of integer updates. See `benches`/the report for the measured observer cost.
    #[inline]
    pub fn record(name: &'static str, nanos: u64) {
        if !enabled() {
            return;
        }
        LOCAL.with(|a| {
            a.lock()
                .unwrap_or_else(|p| p.into_inner())
                .entry(name)
                .or_default()
                .record(nanos);
        });
    }

    /// The RAII guard `timeit!` expands to. Holds the `&'static str` name and the start `Instant`;
    /// records its elapsed time on drop. Constructing it always takes an `Instant` (the runtime gate
    /// is re-checked on drop), so prefer it at a method's top where the whole body is the scope.
    pub struct Timer {
        name: &'static str,
        start: Instant,
    }

    impl Drop for Timer {
        #[inline]
        fn drop(&mut self) {
            record(self.name, self.start.elapsed().as_nanos() as u64);
        }
    }

    /// Feature-ON constructor for the `timeit!` macro (and explicit call sites).
    #[inline]
    pub fn timer(name: &'static str) -> Timer {
        Timer {
            name,
            start: Instant::now(),
        }
    }

    /// Time `f` under `name` and return its result — the fn form of `timeit!` for one expression.
    #[inline]
    pub fn scope<T>(name: &'static str, f: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let out = f();
        record(name, start.elapsed().as_nanos() as u64);
        out
    }

    /// Clear THIS thread's accumulator — the open bracket of a per-request measurement. Pair with
    /// [`dump_scoped`] at the end of the request to print only that request's methods.
    pub fn reset() {
        LOCAL.with(|a| a.lock().unwrap_or_else(|p| p.into_inner()).clear());
    }

    /// Print the current thread's table — the per-request view (call after [`reset`] + the request).
    /// No-op when disabled. Header line is tagged `BUSBAR_TIMING scope=thread`.
    pub fn dump_scoped() {
        if !enabled() {
            return;
        }
        let snapshot =
            LOCAL.with(|a| a.lock().unwrap_or_else(|p| p.into_inner()).clone());
        print_table("thread", &snapshot);
    }

    /// Print the process-wide table, merging every thread's accumulator. No-op when disabled.
    /// Called on demand and from the `atexit` hook when `BUSBAR_TIMING` is set. Header line is
    /// tagged `BUSBAR_TIMING scope=process`.
    pub fn dump() {
        if !enabled() {
            return;
        }
        let mut merged: ThreadRegistry = HashMap::new();
        let handles: Vec<Arc<Mutex<ThreadRegistry>>> = {
            threads()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        };
        for h in handles {
            let g = h.lock().unwrap_or_else(|p| p.into_inner());
            for (name, stat) in g.iter() {
                merged.entry(name).or_default().merge(stat);
            }
        }
        print_table("process", &merged);
    }

    /// Render one `name -> MethodStat` map as the sorted table, largest `total` first. `count` is
    /// the headline column. Durations are auto-scaled (ns/us/ms). Emitted on stderr, like the stage
    /// profiler, so it never contaminates stdout.
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

    /// Human-scaled duration: ns under 1us, us under 1ms, else ms. Three significant figures is
    /// plenty for a "where do the 65us go" read.
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
    mod tests {
        use super::*;

        #[test]
        fn bucket_monotonic_and_percentiles_separate_scales() {
            let mut s = MethodStat::default();
            // 1000 samples near 500ns, 1 sample near 25us.
            for _ in 0..1000 {
                s.record(500);
            }
            s.record(25_000);
            assert_eq!(s.count, 1001);
            // p50 sits in the ~500ns band (bucket floor 256), p99 also (only 1/1001 is the outlier),
            // and max captures the 25us outlier exactly.
            assert!(s.percentile(0.50) <= 512, "p50 {}", s.percentile(0.50));
            assert_eq!(s.max_ns, 25_000);
            assert_eq!(s.min_ns, 500);
        }

        #[test]
        fn bucket_of_is_log2() {
            assert_eq!(bucket_of(0), 0);
            assert_eq!(bucket_of(1), 1);
            assert_eq!(bucket_of(2), 2);
            assert_eq!(bucket_of(3), 2);
            assert_eq!(bucket_of(4), 3);
            assert_eq!(bucket_of(1023), 10);
            assert_eq!(bucket_of(1024), 11);
        }

        #[test]
        fn merge_sums_counts_and_extents() {
            let mut a = MethodStat::default();
            a.record(100);
            a.record(300);
            let mut b = MethodStat::default();
            b.record(50);
            b.record(9000);
            a.merge(&b);
            assert_eq!(a.count, 4);
            assert_eq!(a.total_ns, 100 + 300 + 50 + 9000);
            assert_eq!(a.min_ns, 50);
            assert_eq!(a.max_ns, 9000);
        }

        #[test]
        fn scoped_record_and_reset_are_thread_local() {
            set_enabled(true);
            reset();
            record("m_a", 1234);
            record("m_a", 2345);
            record("m_b", 10);
            let snap = LOCAL.with(|a| a.lock().unwrap().clone());
            assert_eq!(snap.get("m_a").unwrap().count, 2);
            assert_eq!(snap.get("m_b").unwrap().count, 1);
            reset();
            let snap2 = LOCAL.with(|a| a.lock().unwrap().clone());
            assert!(snap2.is_empty());
        }
    }
}

/// Feature-ON test/embedding hook to force the runtime gate. Absent (and unreferenced) when the
/// feature is off.
#[cfg(feature = "timing")]
pub use imp::set_enabled;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// ZERO-COST-WHEN-OFF PROOF (always compiled — this is the default build).
// ─────────────────────────────────────────────────────────────────────────────────────────────
#[cfg(all(test, not(feature = "timing")))]
mod zero_cost_when_off {
    //! Method: this test crate is built in the DEFAULT (feature-off) configuration. The proof has
    //! two legs, both machine-checked here:
    //!   1. `Timer` is a ZERO-SIZED TYPE: `size_of::<Timer>() == 0`. A ZST guard with an empty
    //!      `Drop` occupies no stack and its drop lowers to nothing.
    //!   2. The `timeit!` macro expands to `()`. `instrumented()` and `bare()` below are identical
    //!      byte-for-byte except for the `timeit!` line; because that line IS `()`, the two functions
    //!      have the same value and (being `#[inline(never)]`) the same emitted body. The
    //!      `assert_eq!` fixes the observable-equivalence half; the codegen-equivalence half is the
    //!      documented `cargo asm` check in the crate report.
    use super::*;

    #[inline(never)]
    fn instrumented(x: u64) -> u64 {
        let _t = timeit!("zc_probe");
        x.wrapping_mul(2654435761).rotate_left(13)
    }

    #[inline(never)]
    fn bare(x: u64) -> u64 {
        x.wrapping_mul(2654435761).rotate_left(13)
    }

    #[test]
    fn timer_off_is_zero_sized() {
        assert_eq!(core::mem::size_of::<Timer>(), 0, "feature-off Timer must be a ZST");
    }

    #[test]
    fn timeit_off_expands_to_unit() {
        // Binding `timeit!(..)` yields `()` — the macro produced a unit value, not a guard.
        let t: () = timeit!("expands_to_unit");
        assert_eq!(t, ());
    }

    #[test]
    fn instrumented_matches_bare() {
        for x in [0u64, 1, 42, u64::MAX, 1 << 40] {
            assert_eq!(instrumented(x), bare(x), "instrumentation changed the result");
        }
    }

    #[test]
    fn off_entry_points_are_noops() {
        // These compile and do nothing; the point is they exist with the same signatures as the
        // feature-on build so call sites are source-identical across the feature.
        record("noop", 123);
        let v = scope("noop", || 7);
        assert_eq!(v, 7);
        dump();
        dump_scoped();
        reset();
        assert!(!enabled());
    }
}
