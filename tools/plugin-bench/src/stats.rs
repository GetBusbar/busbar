// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Fixed-size latency histograms, the per-op recorder and process measurements (RSS, CPU time).
//!
//! Nothing here allocates once a [`Recorder`] is built: the hot loop only bumps counters.

use std::time::Instant;

use crate::alloc;

/// Sub-buckets per power of two: about 3% resolution.
const SUB_BITS: u32 = 5;
const SUB: usize = 1 << SUB_BITS;
/// Buckets for every `u64` nanosecond value.
const BUCKETS: usize = (64 - SUB_BITS as usize + 1) * SUB;

/// Op-index windows the p50 is also reported over: how the cost moves as the plugin's state grows.
pub const WINDOWS: [u64; 4] = [1_000, 10_000, 100_000, u64::MAX];
/// Call counts RSS is sampled at.
pub const RSS_AT: [u64; 3] = [10_000, 100_000, 1_000_000];
/// Calls per min-of-batches batch.
pub const BATCH: u64 = 1_000;
/// One call in this many is also timed in thread CPU (the clock read is costlier than `Instant`).
pub const CPU_EVERY: u64 = 64;

fn bucket(v: u64) -> usize {
    if v < SUB as u64 {
        return v as usize;
    }
    let e = 63 - v.leading_zeros();
    let m = (v >> (e - SUB_BITS)) as usize & (SUB - 1);
    (e - SUB_BITS + 1) as usize * SUB + m
}

fn lower(b: usize) -> u64 {
    if b < SUB {
        return b as u64;
    }
    let e = (b / SUB) as u32 + SUB_BITS - 1;
    ((SUB + b % SUB) as u64) << (e - SUB_BITS)
}

/// A log-linear histogram of nanoseconds.
#[derive(Clone)]
pub struct Hist {
    counts: Box<[u64]>,
    pub n: u64,
    pub sum: u128,
    pub max: u64,
}

impl Default for Hist {
    fn default() -> Self {
        Self {
            counts: vec![0; BUCKETS].into_boxed_slice(),
            n: 0,
            sum: 0,
            max: 0,
        }
    }
}

impl Hist {
    #[inline]
    pub fn add(&mut self, ns: u64) {
        self.counts[bucket(ns)] += 1;
        self.n += 1;
        self.sum += u128::from(ns);
        self.max = self.max.max(ns);
    }

    pub fn merge(&mut self, other: &Hist) {
        for (a, b) in self.counts.iter_mut().zip(other.counts.iter()) {
            *a += b;
        }
        self.n += other.n;
        self.sum += other.sum;
        self.max = self.max.max(other.max);
    }

    /// The `q` quantile (0..=1), at the bucket's lower bound; `None` when empty.
    #[must_use]
    pub fn quantile(&self, q: f64) -> Option<u64> {
        if self.n == 0 {
            return None;
        }
        let rank = ((self.n as f64 - 1.0) * q).round() as u64;
        let mut seen = 0;
        for (b, c) in self.counts.iter().enumerate() {
            seen += c;
            if seen > rank {
                return Some(lower(b).min(self.max));
            }
        }
        Some(self.max)
    }

    #[must_use]
    pub fn mean(&self) -> Option<f64> {
        (self.n != 0).then(|| self.sum as f64 / self.n as f64)
    }
}

/// One op's measurements on one thread.
#[derive(Clone, Default)]
pub struct OpStats {
    pub all: Hist,
    pub windows: [Hist; 4],
    pub allocs: u64,
    pub bytes: u64,
    /// `(calls, rss bytes)` sampled at [`RSS_AT`] (thread 0 only).
    pub rss: Vec<(u64, u64)>,
    /// The open batch: calls and summed ns.
    batch: (u64, u64),
    /// The lowest mean ns over a full batch of [`BATCH`] calls (min-of-batches: stable on a loaded
    /// host, where percentiles carry other tenants' preemptions).
    pub min_batch_mean: Option<f64>,
    /// Thread CPU ns over the sampled calls (one in [`CPU_EVERY`]), and how many were sampled.
    pub cpu_ns: u64,
    pub cpu_calls: u64,
}

impl OpStats {
    pub fn merge(&mut self, other: &OpStats) {
        self.all.merge(&other.all);
        for (a, b) in self.windows.iter_mut().zip(other.windows.iter()) {
            a.merge(b);
        }
        self.allocs += other.allocs;
        self.bytes += other.bytes;
        self.cpu_ns += other.cpu_ns;
        self.cpu_calls += other.cpu_calls;
        self.min_batch_mean = match (self.min_batch_mean, other.min_batch_mean) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if self.rss.is_empty() {
            self.rss.clone_from(&other.rss);
        }
    }
}

/// The per-thread recorder a scenario times its crossings through.
pub struct Recorder {
    pub ops: Vec<OpStats>,
    /// The op whose count ends the run.
    primary: usize,
    target: u64,
    deadline: Instant,
    /// Calls on this thread are multiplied by this for the RSS checkpoints (N threads share them).
    scale: u64,
    sample_rss: bool,
    pub stopped_by_budget: bool,
}

impl Recorder {
    #[must_use]
    pub fn new(
        ops: usize,
        primary: usize,
        target: u64,
        deadline: Instant,
        scale: u64,
        sample_rss: bool,
    ) -> Self {
        let mut v = Vec::with_capacity(ops);
        for _ in 0..ops {
            v.push(OpStats {
                rss: Vec::with_capacity(RSS_AT.len()),
                ..OpStats::default()
            });
        }
        Self {
            ops: v,
            primary,
            target,
            deadline,
            scale,
            sample_rss,
            stopped_by_budget: false,
        }
    }

    /// Time ONE crossing as op `op`: wall nanoseconds and this thread's allocations inside it.
    #[inline]
    pub fn time<R>(&mut self, op: usize, f: impl FnOnce() -> R) -> R {
        let i = self.ops[op].all.n;
        let cpu = i.is_multiple_of(CPU_EVERY);
        let c0 = if cpu { thread_cpu_ns() } else { 0 };
        let (a0, b0) = alloc::thread_counts();
        let t = Instant::now();
        let r = f();
        let ns = t.elapsed().as_nanos() as u64;
        let (a1, b1) = alloc::thread_counts();
        let s = &mut self.ops[op];
        if cpu {
            s.cpu_ns += thread_cpu_ns().saturating_sub(c0);
            s.cpu_calls += 1;
        }
        s.batch = (s.batch.0 + 1, s.batch.1 + ns);
        if s.batch.0 == BATCH {
            let mean = s.batch.1 as f64 / BATCH as f64;
            s.min_batch_mean = Some(s.min_batch_mean.map_or(mean, |m| m.min(mean)));
            s.batch = (0, 0);
        }
        s.all.add(ns);
        let w = WINDOWS.iter().position(|&w| i < w).unwrap_or(3);
        s.windows[w].add(ns);
        s.allocs += a1 - a0;
        s.bytes += b1 - b0;
        if self.sample_rss {
            let (before, calls) = (i * self.scale, (i + 1) * self.scale);
            if let Some(&at) = RSS_AT.iter().find(|&&c| before < c && c <= calls) {
                s.rss.push((at, rss_bytes()));
            }
        }
        r
    }

    /// Whether the run is over: the primary op reached its target, or the time budget ran out.
    /// Scenarios call this between units of work (never inside one).
    #[must_use]
    pub fn done(&mut self) -> bool {
        if self.ops[self.primary].all.n >= self.target {
            return true;
        }
        if Instant::now() >= self.deadline {
            self.stopped_by_budget = true;
            return true;
        }
        false
    }
}

/// Resident set size now, in bytes (0 when unknown on this platform).
#[must_use]
pub fn rss_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        // SAFETY: a correctly sized, writable buffer for PROC_PIDTASKINFO about this process.
        let n = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTASKINFO,
                0,
                std::ptr::addr_of_mut!(info).cast(),
                size,
            )
        };
        if n == size {
            return info.pti_resident_size;
        }
        0
    }
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
        let pages: u64 = statm
            .split_whitespace()
            .nth(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(0) as u64;
        pages * page
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        0
    }
}

/// This thread's CPU time so far, in nanoseconds.
#[must_use]
pub fn thread_cpu_ns() -> u64 {
    #[cfg(unix)]
    {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: a writable timespec; the thread CPU clock exists on every supported unix.
        if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) } != 0 {
            return 0;
        }
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Process CPU time (user + system) so far, in nanoseconds.
#[must_use]
pub fn cpu_ns() -> u64 {
    #[cfg(unix)]
    {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: a writable rusage for this process.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
            return 0;
        }
        let tv = |t: libc::timeval| t.tv_sec as u64 * 1_000_000_000 + t.tv_usec as u64 * 1_000;
        tv(ru.ru_utime) + tv(ru.ru_stime)
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_monotone_and_tight() {
        let mut last = 0;
        for v in (0..100_000u64).chain([1 << 40, u64::MAX]) {
            let b = bucket(v);
            assert!(b >= last && b < BUCKETS, "{v}");
            last = b;
            let lo = lower(b);
            assert!(lo <= v, "{v} {lo}");
            assert!(v - lo <= v / 32 + 1, "{v} {lo}");
        }
    }

    #[test]
    fn quantiles_read_back() {
        let mut h = Hist::default();
        for v in 1..=1000 {
            h.add(v * 100);
        }
        let p50 = h.quantile(0.5).unwrap();
        assert!((48_000..=50_100).contains(&p50), "{p50}");
        let top = h.quantile(1.0).unwrap();
        assert!((96_875..=100_000).contains(&top), "{top}");
        assert_eq!(h.max, 100_000);
    }
}
