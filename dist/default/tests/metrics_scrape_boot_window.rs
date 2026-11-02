// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]
#![cfg(linked_axis_export_doors)]

mod common;

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WORKER_THREADS: usize = 8;

const RACE_WINDOW: Duration = Duration::from_millis(1500);

const RACE_CONCURRENCY: usize = 16;

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-metrics-boot-window-{}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
store: {{module: memory}}
admin_require_mtls: false
auth:
  chain: []
advanced:
  allow_destinations: ["127.0.0.1"]
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

    content_type: String,
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
    let mut child = common::boot::Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "warn")
            .stdout(log)
            .stderr(log_err)
            .spawn()
            .expect("spawn busbar"),
    );

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

    std::thread::sleep(Duration::from_millis(500));
    let reference = wait_for_full_scrape(data_port, Duration::from_secs(10)).unwrap_or_else(|| {
        panic!(
            "busbar never settled to a full /metrics exposition; log:\n{}",
            read_to_string(&log_path)
        )
    });
    let reference_metadata = complete_metadata(&reference.body)
        .expect("the settled reference must have one HELP and TYPE per family");
    let reference_names = help_names(&reference.body);
    assert!(
        !reference_names.is_empty(),
        "the reference scrape itself must carry HELP lines (a broken fixture proves nothing); \
         exposition:\n{}",
        reference.body
    );

    for family in LANE_FAMILIES {
        assert!(
            reference_names.contains(*family),
            "the settled exposition lacks the 1.5.5 lane family `{family}`; exposition:\n{}",
            reference.body
        );
    }
    let golden = golden_meta_lines();
    let drifted: Vec<_> = golden
        .iter()
        .filter(|line| reference_names.contains(meta_name(line)))
        .filter(|line| !reference_metadata.contains(line.as_str()))
        .collect();
    assert!(
        drifted.is_empty(),
        "HELP/TYPE lines differ from the 1.5.5 golden (missing or changed):\n{drifted:#?}"
    );

    let _ = child.kill();
    let _ = child.wait();

    let mut violations = Vec::new();
    for s in &collected {
        if s.status == 200 {
            let metadata = complete_metadata(&s.body);
            if metadata.as_ref() != Ok(&reference_metadata) {
                violations.push(format!(
                    "200 with incomplete or changed HELP/TYPE metadata ({metadata:?}); body:\n{}",
                    s.body
                ));
            }
        }
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

const LANE_FAMILIES: &[&str] = &[
    "busbar_lane_state",
    "busbar_lane_available",
    "busbar_lane_inflight",
];

fn meta_lines(body: &str) -> Vec<String> {
    body.lines()
        .filter(|l| l.starts_with("# HELP ") || l.starts_with("# TYPE "))
        .map(str::to_string)
        .collect()
}

fn complete_metadata(body: &str) -> Result<BTreeSet<String>, String> {
    let mut lines = BTreeSet::new();
    let mut help = BTreeSet::new();
    let mut types = BTreeSet::new();
    for line in meta_lines(body) {
        let name = meta_name(&line);
        let names = if line.starts_with("# HELP ") {
            &mut help
        } else {
            &mut types
        };
        let has_value = line[7..]
            .split_once(' ')
            .is_some_and(|(_, value)| !value.trim().is_empty());
        if name.is_empty() || !has_value || !names.insert(name.to_string()) {
            return Err(format!("missing or duplicate metadata family in {line:?}"));
        }
        lines.insert(line);
    }
    if help.is_empty() || help != types {
        return Err(format!(
            "HELP/TYPE families differ: HELP={help:?}, TYPE={types:?}"
        ));
    }
    Ok(lines)
}

#[test]
fn metadata_comparison_refuses_missing_changed_and_duplicate_types() {
    let reference = "# HELP requests Total requests\n# TYPE requests counter\nrequests 1\n";
    let expected = complete_metadata(reference).unwrap();
    assert_eq!(complete_metadata(reference).unwrap(), expected);
    assert!(complete_metadata("# HELP requests Total requests\nrequests 1\n").is_err());
    assert_ne!(
        complete_metadata(&reference.replace("counter", "gauge")).unwrap(),
        expected
    );
    assert!(complete_metadata(&(reference.to_owned() + "# TYPE requests counter\n")).is_err());
    assert!(complete_metadata("# TYPE requests counter\n").is_err());
    assert!(complete_metadata("# HELP requests Total\n# TYPE requests\n").is_err());
    assert!(complete_metadata("").is_err());
}

fn meta_name(line: &str) -> &str {
    line[7..].split(' ').next().unwrap_or("")
}

fn golden_meta_lines() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/golden/1.5.5/cells/ops.scrape__metrics__key.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("the 1.5.5 golden scrape cell must be readable at {path:?}: {e}")
    });
    let cell: serde_json::Value = serde_json::from_str(&raw).expect("the golden cell is JSON");
    let text = cell["body"]["text"]
        .as_str()
        .expect("the golden scrape cell carries its body text");
    let lines = meta_lines(text);
    assert!(
        lines.iter().any(|l| meta_name(l) == LANE_FAMILIES[0]),
        "the golden scrape names no `{}`: the derivation did not bite",
        LANE_FAMILIES[0]
    );
    lines
}

#[test]
fn the_dispatchers_bb_counters_are_not_on_the_customer_scrape() {
    let dir = fixture_dir();
    let data_port = free_port();
    let admin_port = free_port();
    write_configs(&dir, data_port, admin_port);
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = common::boot::Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "warn")
            .stdout(log)
            .stderr(log_err)
            .spawn()
            .expect("spawn busbar"),
    );
    let scrape = wait_for_full_scrape(data_port, Duration::from_secs(30));
    let _ = child.kill();
    let _ = child.wait();
    let scrape = scrape.unwrap_or_else(|| {
        panic!(
            "busbar never answered a full /metrics exposition; log:\n{}",
            read_to_string(&log_path)
        )
    });
    for name in [
        "bb_deadline_without_wake_total",
        "bb_plugin_quarantined_total",
    ] {
        assert!(
            !scrape.body.lines().any(|l| l == name
                || l.starts_with(&format!("{name} "))
                || l.starts_with(&format!("{name}{{"))
                || meta_lines(l).iter().any(|m| meta_name(m) == name)),
            "{name}: a family 1.5.5 never served is on the customer scrape; exposition:\n{}",
            scrape.body
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn help_names(body: &str) -> BTreeSet<String> {
    body.lines()
        .filter_map(|l| l.strip_prefix("# HELP "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

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
            content_type: String::new(),
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
    let content_type = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.trim().to_string())
        .unwrap_or_default();
    Scrape {
        status,
        content_type,
        body,
    }
}

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}

#[test]
fn test_metrics_admitted_in_open_relay_mode() {
    let dir = fixture_dir();
    let data_port = free_port();
    let admin_port = free_port();
    write_configs(&dir, data_port, admin_port);
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = common::boot::Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "warn")
            .stdout(log)
            .stderr(log_err)
            .spawn()
            .expect("spawn busbar"),
    );
    let scraped = wait_for_full_scrape(data_port, Duration::from_secs(30));
    let _ = child.kill();
    let _ = child.wait();
    let Scrape {
        status,
        content_type,
        body,
    } = scraped.unwrap_or_else(|| {
        panic!(
            "busbar never answered a full GET /metrics within 30s; log:\n{}",
            read_to_string(&log_path)
        )
    });
    assert_eq!(
        status, 200,
        "an open chain admits the scrape with no credential"
    );
    assert!(
        content_type.starts_with("text/plain"),
        "content-type was {content_type}"
    );
    assert!(
        body.contains("busbar_lane_state"),
        "exposition should contain a metric; got:\n{body}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
