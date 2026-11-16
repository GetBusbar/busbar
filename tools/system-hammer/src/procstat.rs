// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Process CPU time, resident set size and listening sockets of the gateway under test, on Linux
//! and macOS.

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
    let tck = rustix::param::clock_ticks_per_second().max(1);
    let page = (rustix::param::page_size() as u64).max(1);
    Some(Reading {
        cpu_ns: (num(14)? + num(15)?) * 1_000_000_000 / tck,
        rss: num(24)? * page,
        threads: num(20).unwrap_or(0),
    })
}

/// macOS: `ps` reports the process's CPU time (`[[hh:]mm:]ss.ff`), resident size (KiB) and, per
/// thread, one line under `-M`. It makes no Mach calls, so this tool needs no foreign code at all; `ps`
/// has a 10 ms CPU-time resolution, which a load report tolerates.
#[cfg(target_os = "macos")]
pub fn read(pid: u32) -> Option<Reading> {
    let ps = |args: &[&str]| -> Option<String> {
        let out = std::process::Command::new("ps").args(args).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let pid = pid.to_string();
    let fields = ps(&["-o", "rss=,time=", "-p", &pid])?;
    let mut fields = fields.split_whitespace();
    let rss_kib: u64 = fields.next()?.parse().ok()?;
    let mut seconds = 0.0_f64;
    for part in fields.next()?.split(':') {
        seconds = seconds * 60.0 + part.parse::<f64>().ok()?;
    }
    let threads = ps(&["-M", "-p", &pid]).map_or(0, |t| t.lines().count().saturating_sub(1) as u64);
    Some(Reading {
        cpu_ns: (seconds * 1e9) as u64,
        rss: rss_kib * 1024,
        threads,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn read(_pid: u32) -> Option<Reading> {
    None
}

/// Whether process `pid` itself holds a listening TCP socket on `port` (the gateway's boot
/// check that the listener answering is the child's, not whoever else got the port).
#[cfg(target_os = "linux")]
pub fn listens_on(pid: u32, port: u16) -> Result<bool, String> {
    let fd_dir = format!("/proc/{pid}/fd");
    let mut inodes = std::collections::HashSet::new();
    for e in std::fs::read_dir(&fd_dir)
        .map_err(|e| format!("{fd_dir}: {e}"))?
        .flatten()
    {
        if let Ok(link) = std::fs::read_link(e.path()) {
            if let Some(inode) = link
                .to_str()
                .and_then(|l| l.strip_prefix("socket:["))
                .and_then(|l| l.strip_suffix(']'))
            {
                inodes.insert(inode.to_string());
            }
        }
    }
    for table in ["tcp", "tcp6"] {
        let path = format!("/proc/{pid}/net/{table}");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            // `sl local_address rem_address st tx:rx tr:tm retrnsmt uid timeout inode ...`: the
            // local address is `HEXADDR:HEXPORT`, state `0A` is LISTEN.
            let f: Vec<&str> = line.split_whitespace().collect();
            let (Some(local), Some(st), Some(inode)) = (f.get(1), f.get(3), f.get(9)) else {
                continue;
            };
            let lport = local
                .rsplit(':')
                .next()
                .and_then(|p| u16::from_str_radix(p, 16).ok());
            if *st == "0A" && lport == Some(port) && inodes.contains(*inode) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Whether process `pid` itself holds a listening TCP socket on `port` (the gateway's boot
/// check that the listener answering is the child's, not whoever else got the port).
#[cfg(target_os = "macos")]
pub fn listens_on(pid: u32, port: u16) -> Result<bool, String> {
    // `-a` ANDs the selections: this pid, a TCP socket on the port, in LISTEN; `-t` prints the
    // matching pids only. No match is exit 1 with empty output.
    let pid_s = pid.to_string();
    let out = std::process::Command::new("lsof")
        .args(["-nP", "-a", "-p", pid_s.as_str()])
        .arg(format!("-iTCP:{port}"))
        .args(["-sTCP:LISTEN", "-t"])
        .output()
        .map_err(|e| format!("lsof: {e}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && !stderr.trim().is_empty() {
        return Err(format!("lsof: {}", stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.trim() == pid_s))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn listens_on(_pid: u32, _port: u16) -> Result<bool, String> {
    Err("no listener ownership check on this OS".into())
}

/// CPU time of this process (the hammer: driver plus mocks), nanoseconds.
pub fn self_cpu_ns() -> u64 {
    read(std::process::id()).map_or(0, |reading| reading.cpu_ns)
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
