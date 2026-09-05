// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COLD-WORKER SCRAPE, proven on the real binary: a `/metrics` scrape that lands in the brief
//! boot window before the process-wide Prometheus recorder finishes installing must never answer
//! `200` with an EMPTY body. It must either answer `200` with the FULL, closed `# HELP`/`# TYPE`
//! set, or REFUSE the scrape (a non-`200`, retriable status) — never something in between.
//!
//! Why the window exists at all: `metrics::configure` starts the recorder install
//! (`PrometheusBuilder::install_recorder`, a one-time ~200ms clock calibration) on a background
//! thread rather than blocking boot on it, so a listener bind is never held hostage by a metrics
//! library's warm-up cost. On the thread-per-core data plane EVERY worker's own SO_REUSEPORT
//! listener starts accepting the instant ITS bind completes, independent of that background
//! install. A high worker count (set below) maximizes the odds that at least one of this test's
//! rapid-fire scrapes, fired the moment the port first answers anything, lands on a connection
//! accepted before the install finished.
//!
//! Driving the shipped binary (not an in-process router) is the point: the recorder is a SINGLE
//! process-wide `OnceLock`, not one per worker, so the only way to observe the real boot-window
//! race is to race the real boot of the real process across its real SO_REUSEPORT sockets.
#![cfg(unix)]
// The fixture boots a REAL busbar with an LLM provider; a `--no-default-features` build has no
// wire codec compiled in and fails closed at boot, which is correct product behavior, not the
// seam under test here.
#![cfg(feature = "proto-llm")]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Workers pinned high enough that the kernel's SO_REUSEPORT fan-out has real odds of routing an
/// immediate connection to a listener whose thread only just bound, well before the shared
/// recorder install (started once, at config-load time, well before any worker binds) completes.
const WORKER_THREADS: usize = 8;
/// How long, after the FIRST scrape gets any response at all, to keep firing scrapes on fresh
/// connections. Generous relative to the ~200ms one-time recorder-install cost the module
/// documents, so the window is covered even on a loaded CI box.
const RACE_WINDOW: Duration = Duration::from_millis(1500);
/// Concurrent scraping threads during the race window — more sockets in flight raises the odds
/// SO_REUSEPORT hands at least one to a still-cold worker.
const RACE_CONCURRENCY: usize = 16;

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-metrics-boot-window-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A free loopback port. Thread-per-core needs a FIXED port: every per-core listener binds the
/// SAME address, so an ephemeral `:0` would hand each socket a different port.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A high worker count + `export.prometheus` + an OPEN auth chain (so `/metrics`, declared
/// `RouteAuth::Key`, is reachable with no bearer at all — see `AuthChain::run_chain_cached`'s
/// `chain.is_empty() && !keys_in_chain` open-front-door arm) — nothing else is topology-specific.
fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
admin_require_mtls: false
auth:
  chain: []
advanced:
  worker_threads: {WORKER_THREADS}
export:
  metrics: {{ module: prometheus, settings: {{ buffer_seconds: 60 }} }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#
        ),
    )
    .unwrap();
}

struct Scrape {
    status: u16,
    body: String,
}

#[test]
fn metrics_scrape_is_never_a_200_with_an_empty_body() {
    let dir = fixture_dir();
    let data_port = free_port();
    let admin_port = free_port();
    write_configs(&dir, data_port, admin_port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("RUST_LOG", "warn")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");

    // Do NOT wait for a "listening" log line first: that line is written from inside a per-core
    // worker thread AFTER its own bind, which is exactly the moment we want to race. Instead poll
    // raw connections directly, and treat the FIRST one that gets any HTTP response at all as the
    // start of the race window.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut first: Option<Scrape> = None;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before answering (status {status:?}); log:\n{}",
                read_to_string(&log_path)
            );
        }
        if let Some(s) = try_scrape(data_port) {
            first = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let first = first.unwrap_or_else(|| {
        panic!(
            "busbar never answered GET /metrics within 30s; log:\n{}",
            read_to_string(&log_path)
        )
    });

    // The race: hammer /metrics on fresh connections from many threads for RACE_WINDOW, starting
    // now — as early as possible relative to boot.
    let collected: Arc<Mutex<Vec<Scrape>>> = Arc::new(Mutex::new(vec![first]));
    let race_deadline = Instant::now() + RACE_WINDOW;
    let handles: Vec<_> = (0..RACE_CONCURRENCY)
        .map(|_| {
            let collected = collected.clone();
            std::thread::spawn(move || {
                while Instant::now() < race_deadline {
                    if let Some(s) = try_scrape(data_port) {
                        collected.lock().unwrap().push(s);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("race thread did not panic");
    }
    let collected = Arc::try_unwrap(collected)
        .unwrap_or_else(|_| panic!("all race threads joined; the Arc must be uniquely owned"))
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());

    // Let the process fully settle, then take one more scrape as the REFERENCE full exposition —
    // the closed `# HELP` name set every genuinely-`200` scrape must match exactly.
    std::thread::sleep(Duration::from_millis(500));
    let reference = wait_for_full_scrape(data_port, Duration::from_secs(10)).unwrap_or_else(|| {
        panic!(
            "busbar never settled to a full /metrics exposition; log:\n{}",
            read_to_string(&log_path)
        )
    });
    let reference_names = help_names(&reference.body);
    assert!(
        !reference_names.is_empty(),
        "the reference scrape itself must carry HELP lines (a broken fixture proves nothing); \
         exposition:\n{}",
        reference.body
    );

    let _ = child.kill();
    let _ = child.wait();

    // The invariant, checked against EVERY scrape collected during the race window (plus the
    // bootstrap probe): a `200` must carry the FULL closed HELP/TYPE set — never an empty or
    // partial body — and anything short of that must be REFUSED (a non-`200`, so a client can
    // tell "not ready" from "nothing to report").
    let mut violations = Vec::new();
    for s in &collected {
        if s.status == 200 {
            let names = help_names(&s.body);
            if names != reference_names {
                violations.push(format!(
                    "200 with an INCOMPLETE exposition (missing: {:?}); body:\n{}",
                    reference_names.difference(&names).collect::<Vec<_>>(),
                    s.body
                ));
            }
        }
        // Non-200 is always acceptable here: it is a refusal, not a silent empty success.
    }
    assert!(
        violations.is_empty(),
        "a /metrics scrape answered 200 without the full HELP/TYPE set (a scrape must be either \
         FULL or REFUSED, never an empty/partial 200) across {} sampled scrapes:\n{}",
        collected.len(),
        violations.join("\n---\n")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Extract the set of `# HELP <name> ...` metric names from a Prometheus exposition — the closed
/// set `describe()` registers, independent of which series happen to have been emitted yet.
fn help_names(body: &str) -> BTreeSet<String> {
    body.lines()
        .filter_map(|l| l.strip_prefix("# HELP "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Poll `GET /metrics` until it answers `200` with a non-empty body carrying at least one `# HELP`
/// line, or `budget` elapses.
fn wait_for_full_scrape(port: u16, budget: Duration) -> Option<Scrape> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(s) = try_scrape(port) {
            if s.status == 200 && !help_names(&s.body).is_empty() {
                return Some(s);
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// One raw `GET /metrics` over a fresh connection. `None` only when the connection itself could
/// not be made/read (the server is not up yet) — a real HTTP response of any status is `Some`.
fn try_scrape(port: u16) -> Option<Scrape> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    if raw.is_empty() {
        return None;
    }
    Some(parse_response(&raw))
}

fn parse_response(raw: &[u8]) -> Scrape {
    let text = String::from_utf8_lossy(raw);
    let Some(split) = text.find("\r\n\r\n") else {
        return Scrape {
            status: 0,
            body: String::new(),
        };
    };
    let (head, rest) = text.split_at(split);
    let body = rest[4..].to_string();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Scrape { status, body }
}

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}
