// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The envelope sink (counting, never formatting), the plain-text table and the JSON file.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use busbar_contract::json::{self, json, Value};
use busbar_plugin_loader::dispatch::{Diagnostic, Dropped, EnvelopeSink, Metric};

use crate::stats::{OpStats, RSS_AT, WINDOWS};
use crate::{Config, Outcome, Target};

/// Counts what a plugin reports per call (metrics, diagnostics) and throws it away.
#[derive(Debug, Default)]
pub struct CountingSink {
    pub metrics: AtomicU64,
    pub diags: AtomicU64,
    pub dropped: AtomicU64,
}

impl EnvelopeSink for CountingSink {
    fn metric(&self, _: Metric<'_>) {
        self.metrics.fetch_add(1, Ordering::Relaxed);
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.diags.fetch_add(1, Ordering::Relaxed);
        if verbose() {
            eprintln!(
                "[plugin diag sev={}] {}",
                d.severity,
                String::from_utf8_lossy(d.text)
            );
        }
    }
    fn dropped(&self, why: Dropped) {
        if verbose() {
            eprintln!("[plugin envelope dropped] {why:?}");
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn ns(v: Option<u64>) -> String {
    match v {
        None => "-".into(),
        Some(v) if v >= 10_000_000 => format!("{:.1}ms", v as f64 / 1e6),
        Some(v) if v >= 10_000 => format!("{:.1}us", v as f64 / 1e3),
        Some(v) => format!("{v}ns"),
    }
}

fn mib(b: u64) -> String {
    format!("{:.1}", b as f64 / (1024.0 * 1024.0))
}

fn per(total: u64, n: u64) -> f64 {
    if n == 0 {
        0.0
    } else {
        total as f64 / n as f64
    }
}

fn rss_at(s: &OpStats, at: u64) -> Option<u64> {
    s.rss.iter().find(|(c, _)| *c == at).map(|(_, b)| *b)
}

/// One progress line as each run finishes (stderr, so stdout stays the table).
pub fn line(o: &Outcome) {
    let ops: Vec<String> = o
        .ops
        .iter()
        .map(|(n, s)| format!("{n}={}x p50={}", s.all.n, ns(s.all.quantile(0.5))))
        .collect();
    eprintln!(
        "[bench] {} threads={} {:.2}s {}{}{}",
        o.scenario,
        o.threads,
        o.wall.as_secs_f64(),
        ops.join(" "),
        if o.stopped_by_budget {
            " (budget hit)"
        } else {
            ""
        },
        o.error
            .as_deref()
            .map(|e| format!(" ERROR: {e}"))
            .unwrap_or_default()
    );
}

pub fn table(outcomes: &[Outcome], counting: bool, target: &Target) {
    println!("\nbusbar-plugin-bench: {}", target.label());
    println!(
        "{:<34} {:<12} {:>3} {:>8} {:>9} {:>9} {:>9} {:>9} {:>9} {:>8} {:>9} {:>7} {:>7} {:>7} {:>6}  p50 by call window (<1k <10k <100k rest)",
        "scenario", "op", "thr", "calls", "p50", "p99", "mean", "minbatch", "cpu/call", "allocs", "bytes", "rss10k", "rss100k", "rss1M", "offcpu"
    );
    for o in outcomes {
        for (name, s) in &o.ops {
            let windows: Vec<String> = s.windows.iter().map(|w| ns(w.quantile(0.5))).collect();
            let rss: Vec<String> = RSS_AT
                .iter()
                .map(|&a| rss_at(s, a).map_or_else(|| "-".into(), mib))
                .collect();
            println!(
                "{:<34} {:<12} {:>3} {:>8} {:>9} {:>9} {:>9} {:>9} {:>9} {:>8} {:>9} {:>7} {:>7} {:>7} {:>6}  {}{}",
                o.scenario,
                name,
                o.threads,
                s.all.n,
                ns(s.all.quantile(0.5)),
                ns(s.all.quantile(0.99)),
                ns(s.all.mean().map(|m| m as u64)),
                ns(s.min_batch_mean.map(|m| m as u64)),
                ns((s.cpu_calls != 0).then(|| s.cpu_ns / s.cpu_calls)),
                if counting {
                    format!("{:.1}", per(s.allocs, s.all.n))
                } else {
                    "n/a".into()
                },
                if counting {
                    format!("{:.0}", per(s.bytes, s.all.n))
                } else {
                    "n/a".into()
                },
                rss[0],
                rss[1],
                rss[2],
                o.off_cpu
                    .map_or_else(|| "-".into(), |f| format!("{:.0}%", f * 100.0)),
                windows.join(" "),
                if o.stopped_by_budget {
                    "  [budget hit]"
                } else {
                    ""
                },
            );
        }
        if let Some(e) = &o.error {
            println!("{:<34} ERROR: {e}", o.scenario);
        }
    }
    println!(
        "\nminbatch = lowest mean over a batch of 1000 calls (stable on a loaded host). cpu/call = thread CPU per call, sampled 1 in 64. ns are wall time per inline crossing (host-mediated Plugin::answer, the plugin's work and the RELEASE of its answer's lease included). \
         allocs/bytes are per call on the calling thread{}. rss in MiB after that many calls (process-wide; \
         start-of-run RSS is in the JSON). offcpu = share of thread wall time not on a CPU (lock waits, \
         preemption): the lock-wait stand-in. Report only: nothing here passes or fails."
        , alloc_note(counting, target)
    );
}

pub fn write_json(
    path: &Path,
    cfg: &Config,
    target: &Target,
    counting: bool,
    outcomes: &[Outcome],
) -> Result<(), String> {
    let runs: Vec<Value> = outcomes
        .iter()
        .map(|o| {
            let ops: Vec<Value> = o
                .ops
                .iter()
                .map(|(name, s)| {
                    json!({
                        "op": name,
                        "calls": s.all.n,
                        "p50_ns": s.all.quantile(0.5),
                        "p90_ns": s.all.quantile(0.9),
                        "p99_ns": s.all.quantile(0.99),
                        "p999_ns": s.all.quantile(0.999),
                        "max_ns": s.all.max,
                        "mean_ns": s.all.mean(),
                        "min_batch_mean_ns": s.min_batch_mean,
                        "batch_calls": crate::stats::BATCH,
                        "thread_cpu_ns_per_call": (s.cpu_calls != 0).then(|| s.cpu_ns as f64 / s.cpu_calls as f64),
                        "thread_cpu_sampled_calls": s.cpu_calls,
                        "allocs_per_call": counting.then(|| per(s.allocs, s.all.n)),
                        "bytes_per_call": counting.then(|| per(s.bytes, s.all.n)),
                        "rss_bytes_after_calls": s.rss.iter().map(|(c, b)| json!({"calls": c, "rss_bytes": b})).collect::<Vec<_>>(),
                        "p50_ns_by_call_window": s.windows.iter().zip(WINDOWS).map(|(w, upto)| json!({
                            "below_call": if upto == u64::MAX { Value::new() } else { json!(upto) },
                            "calls": w.n,
                            "p50_ns": w.quantile(0.5),
                            "p99_ns": w.quantile(0.99),
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            json!({
                "scenario": o.scenario,
                "threads": o.threads,
                "wall_s": o.wall.as_secs_f64(),
                "off_cpu_share": o.off_cpu,
                "rss_bytes_at_start": o.rss_start,
                "stopped_by_budget": o.stopped_by_budget,
                "error": o.error,
                "ops": ops,
            })
        })
        .collect();
    let doc = json!({
        "tool": "busbar-plugin-bench",
        "version": env!("CARGO_PKG_VERSION"),
        "plugin": target.label(),
        "kind": cfg.kind,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "calls_per_op": cfg.ops,
        "budget_s": cfg.budget.as_secs_f64(),
        "allocation_counting": counting,
        "allocation_scope": alloc_scope(counting, target),
        "runs": runs,
    });
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let text = json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

fn alloc_scope(counting: bool, target: &Target) -> &'static str {
    match (counting, target) {
        (false, _) => "none",
        (true, Target::Linked(_)) => "host+plugin",
        (true, Target::Dropped(_)) => "host",
    }
}

fn alloc_note(counting: bool, target: &Target) -> &'static str {
    match alloc_scope(counting, target) {
        "none" => " (n/a: this binary's allocator is not the counting one)",
        "host" => {
            " (HOST SIDE ONLY: a dropped-in cdylib allocates through its own allocator; link the \
             door with bench_main!(door) for the plugin's allocations)"
        }
        _ => ", the plugin's own allocations included",
    }
}

/// `BUSBAR_BENCH_VERBOSE=1`: echo the plugin's diagnostics and log records (debugging a workload;
/// it formats on the measured path, so never measure with it set).
pub(crate) fn verbose() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var_os("BUSBAR_BENCH_VERBOSE").is_some())
}
