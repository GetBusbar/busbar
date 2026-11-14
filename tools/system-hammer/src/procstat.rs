// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Process CPU time and resident set size of the gateway under test, on Linux and macOS.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One reading of a process.
#[derive(Debug, Clone, Copy, Default)]
pub struct Reading {
    /// User + system CPU time, nanoseconds.
    pub cpu_ns: u64,
    /// Resident set size, bytes.
    pub rss: u64,
    pub threads: u64,
}

#[cfg(target_os = "linux")]
pub fn read(pid: u32) -> Option<Reading> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the parenthesised command name (which may contain spaces).
    let rest = &stat[stat.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // rest[0] is field 3 (state); utime is field 14, stime 15, num_threads 20, rss 24 (pages).
    let num = |i: usize| f.get(i - 3).and_then(|v| v.parse::<u64>().ok());
    // SAFETY: sysconf is always safe to call.
    let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
    Some(Reading {
        cpu_ns: (num(14)? + num(15)?) * 1_000_000_000 / tck,
        rss: num(24)? * page,
        threads: num(20).unwrap_or(0),
    })
}

#[cfg(target_os = "macos")]
pub fn read(pid: u32) -> Option<Reading> {
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: `info` is a properly sized, writable proc_taskinfo.
    let got = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTASKINFO,
            0,
            (&mut info as *mut libc::proc_taskinfo).cast(),
            size,
        )
    };
    if got != size {
        return None;
    }
    let ticks = info.pti_total_user + info.pti_total_system;
    Some(Reading {
        cpu_ns: mach_ticks_to_ns(ticks),
        rss: info.pti_resident_size,
        threads: info.pti_threadnum as u64,
    })
}

#[cfg(target_os = "macos")]
fn mach_ticks_to_ns(ticks: u64) -> u64 {
    // proc_taskinfo reports CPU time in Mach absolute-time units (1 ns on Intel, 125/3 ns on
    // Apple silicon).
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    extern "C" {
        fn mach_timebase_info(info: *mut Timebase) -> libc::c_int;
    }
    let mut tb = Timebase { numer: 1, denom: 1 };
    // SAFETY: writes one Timebase.
    unsafe { mach_timebase_info(&mut tb) };
    (u128::from(ticks) * u128::from(tb.numer) / u128::from(tb.denom.max(1))) as u64
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn read(_pid: u32) -> Option<Reading> {
    None
}

/// CPU time of this process (the hammer: driver plus mocks), nanoseconds.
pub fn self_cpu_ns() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: writes one rusage.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let tv = |t: libc::timeval| t.tv_sec as u64 * 1_000_000_000 + t.tv_usec as u64 * 1_000;
    tv(ru.ru_utime) + tv(ru.ru_stime)
}

/// A background sampler: one RSS reading every `every`, timestamped from `origin`.
pub struct Sampler {
    stop: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<(Duration, u64)>>>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Sampler {
    pub fn start(pid: u32, origin: Instant, every: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let (s2, v2) = (Arc::clone(&stop), Arc::clone(&samples));
        let join = std::thread::Builder::new()
            .name("hammer-sampler".into())
            .spawn(move || {
                while !s2.load(Ordering::Relaxed) {
                    if let Some(r) = read(pid) {
                        v2.lock().unwrap().push((origin.elapsed(), r.rss));
                    }
                    std::thread::sleep(every);
                }
            })
            .ok();
        Self {
            stop,
            samples,
            join,
        }
    }

    /// RSS samples taken in `[from, to)` (offsets from the origin).
    pub fn between(&self, from: Duration, to: Duration) -> Vec<u64> {
        self.samples
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| *t >= from && *t < to)
            .map(|(_, r)| *r)
            .collect()
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_this_process() {
        let r = read(std::process::id()).expect("own process readable");
        assert!(r.rss > 1 << 20, "rss {}", r.rss);
        let spin = Instant::now();
        while spin.elapsed() < Duration::from_millis(30) {}
        let r2 = read(std::process::id()).unwrap();
        assert!(r2.cpu_ns > r.cpu_ns, "cpu advanced");
        assert!(self_cpu_ns() > 0);
    }
}
