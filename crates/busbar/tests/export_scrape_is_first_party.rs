// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SCRAPE ROLE IS FIRST-PARTY ONLY (#65, zero trust; K9d): busbar's own `/metrics` is rendered
//! only by a sink the host GRANTS first-party — linked into the binary, or dropped in signed by the
//! release key. A third-party sink may subscribe to the `metrics` stream like any other sink, but
//! it never serves `/metrics`: the host does not put bytes a third party rendered under its own
//! well-known exposition.
//!
//! Driven through the real binary. The third party here is the scrape sink's own `cdylib` (found
//! by what it carries — exactly the `metrics` stream — not by name), packed UNSIGNED under a
//! third-party publisher and dropped into `plugins/`:
//!
//! 1. configured ALONE, subscribed to `metrics`: `/metrics` is not served — exactly 1.5.5, where no
//!    `module: prometheus` instance meant no `/metrics` (RED before the first-party rule: it served
//!    `200` with the third party's rendering);
//! 2. beside the first-party `module: prometheus` instance: `/metrics` is served (`200`, the
//!    exposition's content type) and the third-party instance still boots — the control that keeps
//!    arm 1's `404` from being a boot that failed for some other reason.

#![cfg(unix)]
// The config below serves `providers:`/`models:`, so the build must link the plane that takes body
// ingress — the linked table's answer, never a feature name.
#![cfg(linked_axis_body_ingress)]
// The config names `module: prometheus`, the linked scrape sink on the export-doors axis: a build
// that links no export door (the single-plane rows link only the exports axis) refuses that module at
// boot ("unknown exporter 'prometheus'"), which is correct product behaviour, not what this measures.
#![cfg(linked_axis_export_doors)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The name the third-party tarball's manifest states.
const THIRD_PARTY: &str = "tp-metrics";

/// The in-tree `cdylib` that loads as an export sink carrying exactly the `metrics` stream, in the
/// target directory this test binary lives in (uplifted or under `deps`, newest first). Under CI a
/// missing artifact is a failure, never a skip.
fn metrics_sink_cdylib() -> Option<Vec<u8>> {
    let found = common::plugins::metrics_sink_cdylib();
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "no in-tree metrics-stream export cdylib is built under CI; refusing to skip #65's control"
    );
    found
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-scrape-first-party-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
}

/// `lib` packed UNSIGNED as a third-party `kind: export` tarball.
fn write_third_party(dir: &Path, lib: &[u8]) {
    let bytes = common::plugins::pack_stated("export", THIRD_PARTY, lib, "acme");
    std::fs::write(dir.join("plugins").join("tp.tar.gz"), bytes).unwrap();
}

fn write_configs(dir: &Path, data_port: u16, first_party: bool, third_party: bool) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let scrape = if first_party {
        "  metrics: { module: prometheus, settings: { buffer_seconds: 60 } }\n"
    } else {
        ""
    };
    let tp = if third_party {
        format!(
            "  tp: {{ module: {THIRD_PARTY}, streams: [metrics], settings: {{ buffer_seconds: 60 }} }}\n"
        )
    } else {
        String::new()
    };
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
advanced:
  allow_destinations: ["127.0.0.1"]
admin_require_mtls: false
auth:
  chain: []
plugins:
  enabled: true
  dir: '{plugins}'
  trust:
    allow_unsigned: true
export:
{scrape}{tp}providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            admin_port = free_port(),
            plugins = dir.join("plugins").display()
        ),
    )
    .unwrap();
}

/// Kill the child when the test ends, however it ends.
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `GET /metrics` over a fresh connection: `(status, head, body)`, or `None` before the listener
/// is up.
fn scrape(port: u16) -> Option<(u16, String, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let request = "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, head.to_ascii_lowercase(), body.to_string()))
}

/// Spawn the binary over `dir`, reaped when the returned guard drops.
fn boot(dir: &Path) -> Reap {
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "warn")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    )
}

fn read_log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
}

/// Boot the binary over `dir` and return the first settled `/metrics` answer (anything but the
/// recorder's boot-window `503`), with the log.
fn settled_scrape(dir: &Path, data_port: u16) -> ((u16, String, String), String) {
    let mut child = boot(dir);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!(
                "busbar refused to boot (status {status:?}); log:\n{}",
                read_log(dir)
            );
        }
        match scrape(data_port) {
            Some(answer) if answer.0 != 503 => return (answer, read_log(dir)),
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "/metrics never settled; log:\n{}",
            read_log(dir)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Fire one request through the whole request path over a raw connection (no client crate
/// needed): the provider is unreachable, so it ends as an upstream failure, which is enough to
/// populate both a counter family and a distribution family in the exposition.
fn post_messages(port: u16) {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let body =
        r#"{"model":"test-model","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#;
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(request.as_bytes());
    let mut discard = Vec::new();
    let _ = stream.read_to_end(&mut discard);
}

#[test]
fn a_third_party_metrics_sink_never_serves_metrics() {
    let Some(lib) = metrics_sink_cdylib() else {
        eprintln!("skip: no in-tree metrics-stream export cdylib is built (run under --workspace)");
        return;
    };

    // 1. The third party ALONE, subscribed to `metrics`: no `/metrics`, as 1.5.5 without a
    //    `module: prometheus` instance.
    let dir = fixture_dir("alone");
    write_third_party(&dir, &lib);
    let port = free_port();
    write_configs(&dir, port, false, true);
    let ((status, _, body), log) = settled_scrape(&dir, port);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        status, 404,
        "a third-party sink subscribed to `metrics` must not serve /metrics; body:\n{body}\nlog:\n{log}"
    );

    // 2. Beside the first-party instance: `/metrics` is served, by the host's scrape.
    let dir = fixture_dir("beside");
    write_third_party(&dir, &lib);
    let port = free_port();
    write_configs(&dir, port, true, true);
    let ((status, head, body), log) = settled_scrape(&dir, port);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        status, 200,
        "the first-party sink serves /metrics; log:\n{log}"
    );
    assert!(
        head.contains("content-type: text/plain; version=0.0.4"),
        "{head}"
    );
    assert!(body.contains("# TYPE "), "an exposition: {body}");
}

/// v1.5.5's own FAMILY-KIND rank: counters before gauges before distributions (histogram or
/// summary) — the fixed pass order `metrics-exporter-prometheus::render_to_write` has always used.
fn kind_rank(kind: &str) -> u8 {
    match kind {
        "counter" => 0,
        "gauge" => 1,
        "histogram" | "summary" => 2,
        _ => 3,
    }
}

/// KP-C0: the raw `/metrics` exposition emits every family in v1.5.5's own FAMILY-KIND order —
/// every counter, then every gauge, then every histogram/summary — never a counter after a
/// distribution.
///
/// DERIVATION, not a captured guess (a single 1.5.5 capture cannot pin this: within a kind the
/// order is hash-map order and "varies between runs"). Both v1.5.5
/// (`v1.5.5:crates/busbar/src/metrics.rs`, `render()` at line 691 calling `h.render()`) and this
/// binary (`busbar_kernel::metrics::render()`) hand the SAME `metrics-exporter-prometheus` v0.18.3
/// recorder's `render_to_write` the whole exposition: that function drains its counters map
/// whole, then its gauges map whole, then its distributions (histogram + summary) map whole —
/// three sequential, unconditional passes, in that fixed order, in every release either binary
/// could have linked. WHICH KIND'S BLOCK COMES FIRST is therefore code-determined and identical
/// in both; WHICH FAMILY comes first WITHIN a kind is not (hash order), so this test does not pin
/// that.
///
/// Before the fix this binary's scrape sink (`busbar-export-prometheus`) sorted families by name
/// alone, so a counter whose name sorts after a distribution's — `busbar_requests_total` and
/// `busbar_upstream_attempts_total` both sort after `busbar_request_duration_seconds` — rendered
/// AFTER that summary, which v1.5.5 never does. RED on the parent: the parent's exposition is
/// fully name-sorted across kinds, so this assertion fails on it.
#[test]
fn every_counter_precedes_every_gauge_precedes_every_distribution() {
    let dir = fixture_dir("kind-order");
    let port = free_port();
    write_configs(&dir, port, true, false);

    let mut child = boot(&dir);
    // Wait for boot: the first non-503 scrape (before any request, so possibly a bare
    // exposition with no families yet).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!(
                "busbar refused to boot (status {status:?}); log:\n{}",
                read_log(&dir)
            );
        }
        if scrape(port)
            .map(|(status, _, _)| status != 503)
            .unwrap_or(false)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "/metrics never settled; log:\n{}",
            read_log(&dir)
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // One request through the whole request path: the provider is unreachable, so it ends as an
    // upstream failure, populating `busbar_requests_total` / `busbar_upstream_attempts_total`
    // (counters) alongside `busbar_request_duration_seconds` (the summary) — a counter AND a
    // distribution both present is what makes the ordering assertion non-vacuous.
    post_messages(port);

    let deadline = Instant::now() + Duration::from_secs(15);
    let body = loop {
        if let Some((status, _, body)) = scrape(port) {
            if status == 200 && body.contains("# TYPE ") {
                break body;
            }
        }
        assert!(
            Instant::now() < deadline,
            "metrics for the request never appeared; log:\n{}",
            read_log(&dir)
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = std::fs::remove_dir_all(&dir);

    let kinds: Vec<(String, String)> = body
        .lines()
        .filter_map(|l| l.strip_prefix("# TYPE "))
        .filter_map(|rest| rest.split_once(' '))
        .map(|(name, kind)| (name.to_string(), kind.to_string()))
        .collect();
    assert!(
        kinds.iter().any(|(_, k)| k == "counter"),
        "the exposition must carry at least one counter to make this assertion non-vacuous:\n{body}"
    );
    assert!(
        kinds.iter().any(|(_, k)| k == "summary" || k == "histogram"),
        "the exposition must carry at least one distribution to make this assertion non-vacuous:\n{body}"
    );

    let ranks: Vec<u8> = kinds.iter().map(|(_, k)| kind_rank(k)).collect();
    let mut sorted_ranks = ranks.clone();
    sorted_ranks.sort();
    assert_eq!(
        ranks, sorted_ranks,
        "every counter must precede every gauge, which must precede every histogram/summary \
         (v1.5.5's own render_to_write pass order); families in scrape order: {kinds:?}\n{body}"
    );
}
