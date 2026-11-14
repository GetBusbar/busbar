// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! busbar-system-hammer: drive a real busbar binary through every plane and plugin kind and
//! report what it costs. A report, not a gate.
//!
//! ```text
//! cargo run -p busbar-system-hammer --release -- --bin <busbar> --suite default
//! cargo run -p busbar-system-hammer --release -- --bin <busbar> --scenario llm-openai-openai --long
//! cargo run -p busbar-system-hammer --release -- selftest
//! cargo run -p busbar-system-hammer --release -- --list
//! ```

mod driver;
mod gateway;
mod mock;
mod procstat;
mod report;
mod run;
mod scenario;

use driver::{Plan, Proto, Req, Shape};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const USAGE: &str = "\
busbar-system-hammer: load the whole busbar gateway (real binary, real plugins) and report.

USAGE:
  busbar-system-hammer --bin <busbar> [--suite <name>] [--scenario <name|file>]...
                       [--long] [--out <dir>] [--label <text>] [--busbar-sha <sha>]
                       [--plugins-dir <dir>] [--scenarios <dir>] [--work <dir>] [--keep-work]
                       [--driver-threads N] [--mock-threads N] [--no-ceiling]
  busbar-system-hammer selftest [--seconds N] [--concurrency N] [--proto h1|h2c]
                       [--driver-threads N] [--mock-threads N]
  busbar-system-hammer --list

  --suite        a suite of scenarios/suites.yaml (default: default)
  --scenario     run these scenarios instead of a suite (repeatable)
  --long         60 s load windows, 30 s post-load settle (default: short 4 s windows)
  --out          where the JSON report goes (default: ./hammer-reports)
  --plugins-dir  plugin tarballs for scenarios that load dynamic plugins (else they are skipped)
  --busbar-sha   the busbar source commit, when the binary's build-info cannot say
";

struct Args {
    bin: Option<PathBuf>,
    suite: String,
    scenarios: Vec<String>,
    long: bool,
    out: PathBuf,
    label: String,
    sha: Option<String>,
    plugins_dir: Option<PathBuf>,
    scenarios_dir: PathBuf,
    work: PathBuf,
    keep_work: bool,
    driver_threads: usize,
    mock_threads: usize,
    ceiling: bool,
    selftest: bool,
    list: bool,
    seconds: f64,
    concurrency: usize,
    proto: Proto,
}

fn parse() -> Result<Args, String> {
    let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
    let quarter = (cpus / 4).clamp(2, 8);
    let mut a = Args {
        bin: None,
        suite: "default".into(),
        scenarios: Vec::new(),
        long: false,
        out: PathBuf::from("hammer-reports"),
        label: String::new(),
        sha: None,
        plugins_dir: None,
        scenarios_dir: scenario::scenarios_dir(),
        work: std::env::temp_dir().join(format!("busbar-system-hammer-{}", std::process::id())),
        keep_work: false,
        driver_threads: quarter,
        mock_threads: quarter,
        ceiling: true,
        selftest: false,
        list: false,
        seconds: 5.0,
        concurrency: 128,
        proto: Proto::H1,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "selftest" => a.selftest = true,
            "--list" => a.list = true,
            "--bin" => a.bin = Some(PathBuf::from(val()?)),
            "--suite" => a.suite = val()?,
            "--scenario" => a.scenarios.push(val()?),
            "--long" => a.long = true,
            "--out" => a.out = PathBuf::from(val()?),
            "--label" => a.label = val()?,
            "--busbar-sha" => a.sha = Some(val()?),
            "--plugins-dir" => a.plugins_dir = Some(PathBuf::from(val()?)),
            "--scenarios" => a.scenarios_dir = PathBuf::from(val()?),
            "--work" => a.work = PathBuf::from(val()?),
            "--keep-work" => a.keep_work = true,
            "--no-ceiling" => a.ceiling = false,
            "--driver-threads" => {
                a.driver_threads = val()?.parse().map_err(|_| "--driver-threads N")?
            }
            "--mock-threads" => a.mock_threads = val()?.parse().map_err(|_| "--mock-threads N")?,
            "--seconds" => a.seconds = val()?.parse().map_err(|_| "--seconds N")?,
            "--concurrency" => a.concurrency = val()?.parse().map_err(|_| "--concurrency N")?,
            "--proto" => {
                a.proto = match val()?.as_str() {
                    "h1" => Proto::H1,
                    "h2c" => Proto::H2c,
                    p => return Err(format!("--proto {p}: h1 or h2c")),
                }
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}\n\n{USAGE}")),
        }
    }
    Ok(a)
}

fn driver_rt(threads: usize) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads.max(1))
        .thread_name("hammer-driver")
        .enable_all()
        .build()
        .expect("driver runtime")
}

/// Drive the in-process echo far end: the driver's own ceiling on this box with this thread
/// budget (the mocks get the same threads they get in a real run).
fn ceiling(
    rt: &tokio::runtime::Runtime,
    mock_threads: usize,
    proto: Proto,
    concurrency: usize,
    seconds: f64,
) -> report::DriverCeiling {
    let m = mock::Mock::start(mock::MockConfig::default(), mock_threads).expect("echo mock");
    let req = Req {
        method: http::Method::GET,
        path: "/__echo".into(),
        headers: Vec::new(),
        body: bytes::Bytes::new(),
        expect_status: 200,
        expect_contains: None,
        weight: 1,
    };
    let plan = Plan {
        addr: m.addr,
        proto,
        reqs: vec![req],
        shape: Shape::Closed { concurrency },
        start: Instant::now() + Duration::from_millis(50),
        warmup: Duration::from_secs_f64(0.5),
        measure: Duration::from_secs_f64(seconds),
        timeout: Duration::from_secs(10),
        h2_streams: 64,
        sample_every: 0,
    };
    let (out, _) = rt.block_on(driver::run(plan));
    report::DriverCeiling {
        rps: out.rps(),
        p50_us: driver::pct_us(&out.latency, 0.5),
        p99_us: driver::pct_us(&out.latency, 0.99),
        concurrency,
    }
}

fn main() {
    let a = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    if a.list {
        let suites = scenario::load_suites(&a.scenarios_dir).unwrap_or_default();
        for (k, v) in &suites {
            println!("suite {k}: {}", v.join(" "));
        }
        for n in scenario::all_names(&a.scenarios_dir) {
            match scenario::load(&a.scenarios_dir, &n) {
                Ok(s) => println!("{n:<28} [{}] {}", s.group, s.description),
                Err(e) => println!("{n:<28} UNREADABLE {e}"),
            }
        }
        return;
    }
    let rt = driver_rt(a.driver_threads);
    if a.selftest {
        let proto = a.proto;
        let c = ceiling(&rt, a.mock_threads, proto, a.concurrency, a.seconds);
        println!(
                "selftest {proto:?} c={} driver_threads={} mock_threads={}: {:.0} rps, p50 {:.1} us, p99 {:.1} us",
                c.concurrency, a.driver_threads, a.mock_threads, c.rps, c.p50_us, c.p99_us
        );
        return;
    }
    let Some(bin) = a.bin.clone() else {
        eprintln!("--bin <busbar> is required\n\n{USAGE}");
        std::process::exit(2);
    };
    let bin = std::fs::canonicalize(&bin).unwrap_or(bin);
    let Some(version) = gateway::version(&bin) else {
        eprintln!("{}: --version did not answer", bin.display());
        std::process::exit(2);
    };
    let names = if a.scenarios.is_empty() {
        match scenario::load_suites(&a.scenarios_dir).map(|s| s.get(&a.suite).cloned()) {
            Ok(Some(v)) => v,
            Ok(None) => {
                eprintln!("no suite {} in scenarios/suites.yaml", a.suite);
                std::process::exit(2);
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        }
    } else {
        a.scenarios.clone()
    };
    let suite_name = if a.scenarios.is_empty() {
        a.suite.clone()
    } else {
        format!("scenarios: {}", a.scenarios.join(","))
    };
    let started = Instant::now();
    let started_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let driver_ceiling = a
        .ceiling
        .then(|| ceiling(&rt, a.mock_threads, Proto::H1, 64, 2.0));
    if let Some(c) = driver_ceiling {
        eprintln!("driver ceiling: {:.0} rps (echo, c=64, h1)", c.rps);
    }
    let env = run::Env {
        bin: bin.clone(),
        version,
        windows: if a.long {
            run::Windows::long()
        } else {
            run::Windows::short()
        },
        plugins_dir: a.plugins_dir.clone(),
        work_root: a.work.clone(),
        mock_threads: a.mock_threads,
        rt,
        keep_work: a.keep_work,
    };
    let mut results = Vec::new();
    for n in &names {
        eprintln!("scenario {n}");
        let s = match scenario::load(&a.scenarios_dir, n) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  {e}");
                results.push(run::CaseResult {
                    scenario: n.clone(),
                    case: "-".into(),
                    status: "failed".into(),
                    note: Some(format!("unreadable scenario: {e}")),
                    ..Default::default()
                });
                continue;
            }
        };
        let rs = run::run_scenario(&env, &s, &mut |m| eprintln!("{m}"));
        for r in &rs {
            if r.status == "ok" {
                eprintln!(
                    "  {}: {:.0} rps p50 {:.0} us p99 {:.0} us cpu {:.0} us/req errors {}",
                    r.case,
                    r.rps,
                    r.latency_us.p50,
                    r.latency_us.p99,
                    r.cpu_us_per_req,
                    r.errors.values().sum::<u64>()
                );
            } else {
                eprintln!(
                    "  {} {}: {}",
                    r.case,
                    r.status,
                    r.note.as_deref().unwrap_or("")
                );
            }
            if let Some(e) = &r.first_error {
                eprintln!(
                    "    first error: {}",
                    e.chars().take(300).collect::<String>()
                );
            }
        }
        results.extend(rs);
    }
    if !a.keep_work {
        let _ = std::fs::remove_dir_all(&a.work);
    }
    let label = if a.label.is_empty() {
        format!("busbar {}.{}.{}", version.0, version.1, version.2)
    } else {
        a.label.clone()
    };
    let rep = report::RunReport {
        tool: "busbar-system-hammer",
        tool_version: env!("CARGO_PKG_VERSION"),
        hammer_git_sha: report::hammer_git_sha(),
        started_unix,
        label,
        suite: suite_name,
        long: a.long,
        windows: env.windows,
        host: report::Host::detect(),
        binary: report::BinaryInfo::of(&bin, a.sha.as_deref()),
        driver_threads: a.driver_threads,
        mock_threads: a.mock_threads,
        driver_ceiling,
        wall_seconds: started.elapsed().as_secs_f64(),
        results,
    };
    let table = report::table(&rep);
    print!("{table}");
    let _ = std::fs::create_dir_all(&a.out);
    let stem = format!(
        "hammer-{}-{}-{}",
        rep.started_unix,
        rep.binary.version.replace(' ', "-"),
        &rep.binary.git_sha[..rep.binary.git_sha.len().min(10)]
    );
    let json_path = a.out.join(format!("{stem}.json"));
    let txt_path = a.out.join(format!("{stem}.txt"));
    match serde_json::to_string_pretty(&rep) {
        Ok(j) => {
            let _ = std::fs::write(&json_path, j);
            let _ = std::fs::write(&txt_path, &table);
            eprintln!("report: {} and {}", json_path.display(), txt_path.display());
        }
        Err(e) => eprintln!("report: {e}"),
    }
}
