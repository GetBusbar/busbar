// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **busbar-plugin-bench**: load ONE plugin and hammer its kind slots, with no gateway in the way.
//!
//! The plugin is a native image, admitted and opened exactly as core does it (`busbar-plugin-loader`'s
//! `admit` and instance registry). No sealing, journal, HTTP or router runs on the measured path.
//!
//! It REPORTS and never gates: ns p50/p99 per op, allocations and bytes per op (the counting
//! allocator), RSS after 10k/100k/1M calls, the p50 per op-index window (state growth), and the
//! off-CPU share under N threads (lock waits park a thread; the share of wall time not on a CPU is
//! the measurable stand-in for lock-wait time). See the README for the command a plugin repo runs.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod alloc;
mod report;
pub mod stats;
mod store;

use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

pub use alloc::CountingAlloc;
use stats::{OpStats, Recorder};

/// A bench binary's whole `main`: install the counting allocator and run the bench over the `--plugin` path.
#[macro_export]
macro_rules! bench_main {
    () => {
        #[global_allocator]
        static BENCH_ALLOC: $crate::CountingAlloc = $crate::CountingAlloc;
        fn main() {
            std::process::exit($crate::run());
        }
    };
}

/// Where the plugin comes from.
#[derive(Clone)]
pub enum Target {
    /// A dropped-in native image.
    Dropped(PathBuf),
}

impl Target {
    fn label(&self) -> String {
        match self {
            Target::Dropped(p) => p.display().to_string(),
        }
    }
}

/// The run's settings, from the command line.
#[derive(Clone)]
pub struct Config {
    pub kind: String,
    pub ops: u64,
    pub threads: Vec<usize>,
    pub budget: Duration,
    pub json: Option<PathBuf>,
    pub only: Vec<String>,
    pub settings: Option<Vec<u8>>,
}

const USAGE: &str = "\
busbar-plugin-bench: load ONE busbar plugin and hammer it (report only, never a gate)

USAGE:
  busbar-plugin-bench --kind store --plugin <path/to/libX.{so,dylib}> [options]

OPTIONS:
  --plugin <path>        a dropped-in native image (required)
  --kind <kind>          store
  --ops <n>              calls per op (default 1000000, split over the threads)
  --threads <list>       thread counts to run, e.g. 1,4 (default 1,4)
  --budget-secs <s>      wall budget per scenario and thread count (default 10); a run that hits
                         it reports how many calls it made
  --only <a,b>           run only scenarios whose name contains one of these
  --json <path>          machine-readable output (default target/plugin-bench/<kind>.json)
  --settings <file>      the instance settings JSON (default: the kind's built-in fixture)
";

fn parse(args: &[String]) -> Result<(Config, Option<PathBuf>), String> {
    let mut cfg = Config {
        kind: String::new(),
        ops: 1_000_000,
        threads: vec![1, 4],
        budget: Duration::from_secs(10),
        json: None,
        only: Vec::new(),
        settings: None,
    };
    let mut plugin = None;
    let mut it = args.iter();
    let list = |v: &str| -> Result<Vec<usize>, String> {
        v.split(',')
            .map(|x| {
                x.trim()
                    .parse()
                    .map_err(|_| format!("not a number list: {v}"))
            })
            .collect()
    };
    while let Some(a) = it.next() {
        let mut val = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{a} needs a value"))
        };
        match a.as_str() {
            "-h" | "--help" => return Err(String::new()),
            "--plugin" => plugin = Some(PathBuf::from(val()?)),
            "--kind" => cfg.kind = val()?,
            "--ops" => cfg.ops = val()?.parse().map_err(|_| "--ops: not a number")?,
            "--threads" => cfg.threads = list(&val()?)?,
            "--budget-secs" => {
                cfg.budget = Duration::from_secs_f64(
                    val()?.parse().map_err(|_| "--budget-secs: not a number")?,
                );
            }
            "--only" => cfg.only = val()?.split(',').map(str::to_string).collect(),
            "--json" => cfg.json = Some(PathBuf::from(val()?)),
            "--settings" => {
                let p = val()?;
                cfg.settings = Some(std::fs::read(&p).map_err(|e| format!("{p}: {e}"))?);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if cfg.kind.is_empty() {
        return Err("--kind is required".into());
    }
    if cfg.threads.is_empty() || cfg.threads.contains(&0) || cfg.ops == 0 {
        return Err("--threads and --ops must be positive".into());
    }
    Ok((cfg, plugin))
}

/// Run the bench from the process arguments; the exit code (0 unless the run could not start or a
/// plugin answered something a workload cannot continue from). Never a performance gate.
#[must_use]
pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cfg, plugin) = match parse(&args) {
        Ok(v) => v,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}\n");
            }
            eprint!("{USAGE}");
            return 2;
        }
    };
    let target = match plugin {
        Some(p) => Target::Dropped(std::fs::canonicalize(&p).unwrap_or(p)),
        None => {
            eprintln!("error: --plugin is required\n");
            eprint!("{USAGE}");
            return 2;
        }
    };
    match run_with(&cfg, &target) {
        Ok(failed) => i32::from(failed),
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// One workload over one opened instance: a unit of work is one or more timed crossings.
pub(crate) trait Scenario {
    /// Do one unit of work, timing each crossing through `rec`.
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String>;
}

/// How a thread builds its scenario (given its thread index).
pub(crate) type Make = Box<dyn Fn(usize) -> Result<Box<dyn Scenario>, String> + Send + Sync>;

/// A named workload: its op names, the op whose count ends it, and how a thread builds it.
pub(crate) struct Spec {
    pub name: String,
    pub ops: Vec<&'static str>,
    pub primary: usize,
    pub make: Make,
}

/// One scenario at one thread count, merged over its threads.
pub(crate) struct Outcome {
    pub scenario: String,
    pub threads: usize,
    pub ops: Vec<(&'static str, OpStats)>,
    pub wall: Duration,
    pub off_cpu: Option<f64>,
    pub rss_start: u64,
    pub stopped_by_budget: bool,
    pub error: Option<String>,
}

fn run_with(cfg: &Config, target: &Target) -> Result<bool, String> {
    let counting = alloc::installed();
    let specs = match cfg.kind.as_str() {
        "store" => store::specs(cfg, target)?,
        other => {
            return Err(format!(
                "kind {other:?} has no workload yet (see the README)"
            ))
        }
    };
    let specs: Vec<Spec> = specs
        .into_iter()
        .filter(|s| cfg.only.is_empty() || cfg.only.iter().any(|o| s.name.contains(o.as_str())))
        .collect();
    let mut outcomes = Vec::new();
    let mut failed = false;
    for spec in &specs {
        for &threads in &cfg.threads {
            let o = run_spec(cfg, spec, threads);
            failed |= o.error.is_some();
            report::line(&o);
            outcomes.push(o);
        }
    }
    let json = cfg
        .json
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("target/plugin-bench/{}.json", cfg.kind)));
    report::table(&outcomes, counting, target);
    report::write_json(&json, cfg, target, counting, &outcomes)?;
    println!("\nmachine-readable: {}", json.display());
    Ok(failed)
}

fn run_spec(cfg: &Config, spec: &Spec, threads: usize) -> Outcome {
    let per_thread = cfg.ops.div_ceil(threads as u64);
    let barrier = Barrier::new(threads + 1);
    let rss_start = stats::rss_bytes();
    let mut results: Vec<Result<Recorder, String>> = Vec::new();
    let mut wall = Duration::ZERO;
    let mut cpu = 0;
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let barrier = &barrier;
                let spec = &spec;
                s.spawn(move || {
                    let made = (spec.make)(t);
                    barrier.wait();
                    let mut scenario = made?;
                    let deadline = Instant::now() + cfg.budget;
                    let mut rec = Recorder::new(
                        spec.ops.len(),
                        spec.primary,
                        per_thread,
                        deadline,
                        threads as u64,
                        t == 0,
                    );
                    while !rec.done() {
                        scenario.unit(&mut rec)?;
                    }
                    Ok(rec)
                })
            })
            .collect();
        barrier.wait();
        let (c0, t0) = (stats::cpu_ns(), Instant::now());
        for h in handles {
            results.push(
                h.join()
                    .unwrap_or_else(|_| Err("a bench thread panicked".into())),
            );
        }
        (wall, cpu) = (t0.elapsed(), stats::cpu_ns().saturating_sub(c0));
    });
    let mut merged: Vec<(&'static str, OpStats)> =
        spec.ops.iter().map(|&n| (n, OpStats::default())).collect();
    let mut error = None;
    let mut stopped_by_budget = false;
    for r in results {
        match r {
            Ok(rec) => {
                stopped_by_budget |= rec.stopped_by_budget;
                for (m, s) in merged.iter_mut().zip(rec.ops.iter()) {
                    m.1.merge(s);
                }
            }
            Err(e) => error = error.or(Some(e)),
        }
    }
    let busy = wall.as_nanos() as f64 * threads as f64;
    Outcome {
        scenario: spec.name.clone(),
        threads,
        ops: merged,
        wall,
        off_cpu: (cpu != 0 && busy > 0.0).then(|| (1.0 - cpu as f64 / busy).clamp(0.0, 1.0)),
        rss_start,
        stopped_by_budget,
        error,
    }
}

pub(crate) fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a setup runtime")
        .block_on(f)
}
