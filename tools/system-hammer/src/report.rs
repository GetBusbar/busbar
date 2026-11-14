// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The run report: a plain-text table and one machine-readable JSON file per run. A report, not a
//! gate: nothing here fails a run on a number.

use crate::run::CaseResult;
use serde::Serialize;
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Serialize)]
pub struct Host {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub cpus: usize,
    pub cpu_model: String,
    pub load_avg_1m: f64,
}

impl Host {
    pub fn detect() -> Self {
        let sh = |c: &str, a: &[&str]| {
            Command::new(c)
                .args(a)
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default()
        };
        let cpu_model = if cfg!(target_os = "macos") {
            sh("sysctl", &["-n", "machdep.cpu.brand_string"])
        } else {
            std::fs::read_to_string("/proc/cpuinfo")
                .unwrap_or_default()
                .lines()
                .find(|l| l.starts_with("model name") || l.starts_with("Model"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default()
        };
        let mut load = [0f64; 3];
        // SAFETY: writes three doubles.
        unsafe { libc::getloadavg(load.as_mut_ptr(), 3) };
        Host {
            hostname: sh("hostname", &[]),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            cpus: std::thread::available_parallelism().map_or(1, |n| n.get()),
            cpu_model,
            load_avg_1m: load[0],
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BinaryInfo {
    pub path: String,
    pub sha256: String,
    pub version: String,
    /// `--build-info` (1.6.0+), else empty.
    pub build_info: String,
    /// `pgo=` from the build-info stamp: "true", "false" or "unknown" (a binary without one).
    pub pgo: String,
    /// The busbar source commit: `source-commit=` from build-info when verified, else `--busbar-sha`.
    pub git_sha: String,
}

impl BinaryInfo {
    pub fn of(bin: &Path, sha_override: Option<&str>) -> Self {
        let bytes = std::fs::read(bin).unwrap_or_default();
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        let sha256 = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        let version = crate::gateway::version_text(bin);
        let build_info = Command::new(bin)
            .arg("--build-info")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        let field = |k: &str| {
            build_info
                .split_whitespace()
                .find_map(|w| w.strip_prefix(k))
                .map(str::to_string)
        };
        let pgo = field("pgo=").unwrap_or_else(|| "unknown".into());
        let commit = field("source-commit=").filter(|c| c != "unverified");
        let git_sha = sha_override
            .map(str::to_string)
            .or(commit)
            .unwrap_or_else(|| "unknown".into());
        BinaryInfo {
            path: bin.display().to_string(),
            sha256,
            version: version.lines().next().unwrap_or("").to_string(),
            build_info,
            pgo,
            git_sha,
        }
    }
}

#[derive(Debug, Serialize, Default, Clone, Copy)]
pub struct DriverCeiling {
    pub rps: f64,
    pub p50_us: f64,
    pub p99_us: f64,
    pub concurrency: usize,
}

#[derive(Debug, Serialize)]
pub struct RunReport {
    pub tool: &'static str,
    pub tool_version: &'static str,
    /// The hammer checkout's commit.
    pub hammer_git_sha: String,
    pub started_unix: u64,
    pub label: String,
    pub suite: String,
    pub long: bool,
    pub windows: crate::run::Windows,
    pub host: Host,
    pub binary: BinaryInfo,
    pub driver_threads: usize,
    pub mock_threads: usize,
    pub driver_ceiling: Option<DriverCeiling>,
    pub wall_seconds: f64,
    pub results: Vec<CaseResult>,
}

pub fn hammer_git_sha() -> String {
    Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn f(v: f64) -> String {
    if v == 0.0 {
        "-".into()
    } else if v.abs() >= 100.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}

/// The plain-text table.
pub fn table(r: &RunReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "busbar-system-hammer {} | {} | busbar {} sha {} pgo={} | host {} {} {}x {} (load {:.1}) | suite {}{}",
        r.tool_version,
        r.label,
        r.binary.version.trim_start_matches("busbar "),
        &r.binary.git_sha[..r.binary.git_sha.len().min(12)],
        r.binary.pgo,
        r.host.hostname,
        r.host.arch,
        r.host.cpus,
        r.host.cpu_model,
        r.host.load_avg_1m,
        r.suite,
        if r.long { " (long)" } else { "" },
    );
    if let Some(c) = r.driver_ceiling {
        let best = r
            .results
            .iter()
            .filter(|x| x.status == "ok")
            .map(|x| x.rps)
            .fold(0.0, f64::max);
        let _ = writeln!(
            out,
            "driver ceiling (echo, c={}): {:.0} rps, p50 {:.1} us{}",
            c.concurrency,
            c.rps,
            c.p50_us,
            if best > 0.0 {
                format!(" = {:.1}x the best gateway rps below", c.rps / best)
            } else {
                String::new()
            }
        );
    }
    let head = [
        "scenario",
        "case",
        "shape",
        "rps",
        "ok",
        "body_miss",
        "p50us",
        "p99us",
        "p999us",
        "+p50us",
        "+p99us",
        "cpuus/req",
        "rssMiB idle/steady/peak/post",
        "drift%",
        "errors",
    ];
    let mut rows: Vec<Vec<String>> = vec![head.iter().map(|s| s.to_string()).collect()];
    for x in &r.results {
        if x.status != "ok" {
            rows.push(vec![
                x.scenario.clone(),
                x.case.clone(),
                x.status.to_uppercase(),
                x.note
                    .as_deref()
                    .unwrap_or("")
                    .lines()
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take(110)
                    .collect(),
            ]);
            continue;
        }
        let errs: u64 = x.errors.values().sum();
        rows.push(vec![
            x.scenario.clone(),
            x.case.clone(),
            x.shape.clone(),
            format!("{:.0}", x.rps),
            x.ok.to_string(),
            if x.body_total == 0 {
                "-".into()
            } else {
                crate::run::body_miss_text(x.body_miss, x.body_total)
            },
            f(x.latency_us.p50),
            f(x.latency_us.p99),
            f(x.latency_us.p999),
            x.added_p50_us.map_or("-".into(), f),
            x.added_p99_us.map_or("-".into(), f),
            f(x.cpu_us_per_req),
            format!(
                "{:.0}/{:.0}/{:.0}/{:.0}",
                x.rss.idle_mib, x.rss.steady_mib, x.rss.peak_mib, x.rss.post_mib
            ),
            format!("{:+.0}", x.drift_pct),
            if errs == 0 {
                "0".into()
            } else {
                x.errors
                    .iter()
                    .map(|(k, v)| format!("{k}:{v}"))
                    .collect::<Vec<_>>()
                    .join(",")
            },
        ]);
        if let Some(b) = &x.background {
            rows.push(vec![
                String::new(),
                "  (background)".into(),
                String::new(),
                format!("{:.0}", b.rps),
                b.ok.to_string(),
                String::new(),
                f(b.latency_us.p50),
                f(b.latency_us.p99),
                f(b.latency_us.p999),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                b.errors.values().sum::<u64>().to_string(),
            ]);
        }
    }
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0; cols];
    for row in &rows {
        if row.len() < cols {
            continue;
        }
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    for row in &rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if row.len() < cols && i == row.len() - 1 {
                    c.clone()
                } else {
                    format!("{c:<w$}", w = widths[i])
                }
            })
            .collect();
        let _ = writeln!(out, "{}", line.join("  ").trim_end());
    }
    let _ = writeln!(
        out,
        "rps/latency: the load window; +p50/+p99: gateway minus mock at c=1; cpu: gateway process CPU over the load window per request; drift: last third vs first third of 1 s windows. {:.0} s wall.",
        r.wall_seconds
    );
    out
}
