// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE REQUEST PATH'S SPANS REACH THE OTLP COLLECTOR AS 1.5.5 NAMED THEM** (status row 173;
//! v1.5.5 `docs/observability.md` l.162-174). 1.5.5 opened, at the hot-path level (DEBUG, the OTLP
//! floor), an ingress entry span with no field around the requests of the dialects it gave one
//! to, and beneath it the unit's `forward` span carrying `pool`, `ingress` and `op` (v1.5.5
//! `proxy/engine/mod.rs:120`).
//!
//! The real binary boots with one `module: otlp` instance pointed at a loopback collector this test
//! stands up and serves one request per row of `fixtures/otlp_request_spans.txt` (their upstream
//! refuses; the spans close anyway). The rows are test data: which entry span each request opens
//! and which `ingress` its `forward` carries are the plane's words, never this crate's. The
//! collector must receive, for each row:
//!
//! - its entry span, once, with no attribute, and a `forward` beneath it in its trace;
//! - for a row naming none, a `forward` under no entry span;
//! - for a row naming an `ingress`, that `forward` carrying it and `op = chat`.
//!
//! RED: with the plane stating no entry span, none reaches the collector and no `forward` has one
//! above it; with the traces producer reading only the fields a span opened with, `forward`
//! carries neither `ingress` nor `op`.

#![cfg(unix)]
// The config serves `providers:`/`models:`, so the build must link the plane door that declares
// `pools:` (`linked_section_pools`): the linked table's answer, never a feature name.
#![cfg(linked_section_pools)]
// The sink is a linked export door: the test is that axis's, and asserts the binary links this one.
#![cfg(linked_axis_export_doors)]

mod common;

use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use opentelemetry_proto::tonic::trace::v1::Span;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// The key of the wire the data door rides.
const WIRE: &str = "tcp";

/// One request of the fixture: the entry span it opens, the `ingress` its `forward` carries, its
/// path and its body.
struct Row {
    entry: Option<&'static str>,
    ingress: Option<&'static str>,
    path: &'static str,
    body: &'static str,
}

/// The fixture's rows (`fixtures/otlp_request_spans.txt`).
fn rows() -> Vec<Row> {
    let some = |field: &'static str| (field != "-").then_some(field);
    include_str!("fixtures/otlp_request_spans.txt")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let f: Vec<&'static str> = l.splitn(4, '\t').collect();
            assert_eq!(f.len(), 4, "a fixture row has four fields: {l}");
            Row {
                entry: some(f[0]),
                ingress: some(f[1]),
                path: f[2],
                body: f[3],
            }
        })
        .collect()
}

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-otlp-request-spans-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, collector: u16) {
    // The provider catalog row is test data (`fixtures/mock_provider.yaml`), not a literal here.
    std::fs::write(
        dir.join("providers.yaml"),
        include_str!("fixtures/mock_provider.yaml"),
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
plugins:
  enabled: true
  dir: '{plugins}'
  trust:
    allow_unsigned: true
  logs: {{ dir: '{logs}' }}
export:
  trace: {{ module: otlp, settings: {{ url: "http://127.0.0.1:{collector}/v1/traces" }} }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            plugins = dir.join("plugins").display(),
            logs = dir.join("plugin-logs").display(),
        ),
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("plugins")).unwrap();
}

/// Kill the child when the test ends, however it ends.
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One HTTP/1.1 POST over a fresh connection: the status, or `None` before the listener is up.
fn post(port: u16, path: &str, body: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .ok()?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// A span's attribute, as the string the sink wrote.
fn attribute(span: &Span, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key == key)
        .and_then(|kv| match kv.value.as_ref()?.value.as_ref()? {
            AnyValue::StringValue(s) => Some(s.clone()),
            other => Some(format!("{other:?}")),
        })
}

/// The `forward` spans whose parent is `entry`, in its trace.
fn forwards_under<'a>(spans: &'a [Span], entry: &Span) -> Vec<&'a Span> {
    spans
        .iter()
        .filter(|s| {
            s.name == "forward" && s.parent_span_id == entry.span_id && s.trace_id == entry.trace_id
        })
        .collect()
}

#[test]
fn the_request_paths_spans_reach_the_collector_as_1_5_5_named_them() {
    let dir = fixture_dir();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    let (collector_port, seen) = common::otlp::collector();
    write_configs(&dir, data_port, admin_port, collector_port);
    // THE WIRE UNDER THE DOOR. A build that does not link the tcp row boots only with it dropped
    // in; one that links it would refuse the tarball as a second row on the same key.
    if !LINKED_TRANSPORTS.iter().any(|w| w.key == WIRE) {
        let (lib, _) = common::plugins::transport_cdylib_under(&[WIRE]).unwrap_or_else(|| {
            common::plugins::missing(&format!("{WIRE} transport"), common::plugins::BUILD_PINNED)
        });
        let bytes = common::plugins::pack("transport", "dropped-wire", &lib, "acme");
        std::fs::write(dir.join("plugins").join("dropped-wire.tar.gz"), bytes).unwrap();
    }

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "info")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();

    // One request per row. Their upstream refuses: the request path's spans open and close
    // regardless.
    let rows = rows();
    let entries: Vec<&str> = rows.iter().filter_map(|r| r.entry).collect();
    assert!(!entries.is_empty(), "the fixture names an entry span");
    let deadline = Instant::now() + Duration::from_secs(60);
    for row in &rows {
        loop {
            if let Some(status) = child.0.try_wait().expect("try_wait") {
                panic!("busbar exited ({status}) before serving:\n{}", read_log());
            }
            assert!(Instant::now() < deadline, "no data door:\n{}", read_log());
            if post(data_port, row.path, row.body).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // Delivery is off the request path, batched: wait for every entry and one forward per row.
    let spans = || common::otlp::spans(&common::otlp::requests(&seen, None));
    let heard = |spans: &[Span]| {
        entries.iter().all(|e| spans.iter().any(|s| s.name == *e))
            && spans.iter().filter(|s| s.name == "forward").count() >= rows.len()
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !heard(&spans()) {
        if Instant::now() >= deadline {
            let names: Vec<String> = spans().iter().map(|s| s.name.clone()).collect();
            panic!(
                "the collector heard {names:?} in 30 s, short of the rows:\n{}",
                read_log()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let spans = spans();
    let _ = std::fs::remove_dir_all(&dir);

    // EACH ROW: its entry span, once, with no attribute (1.5.5's `skip_all`) and a `forward`
    // beneath it; or, naming none, a `forward` under no entry span. Its `forward` carries the
    // row's `ingress` and the operation's name.
    for row in &rows {
        let forward = match row.entry {
            Some(entry) => {
                let opened: Vec<&Span> = spans.iter().filter(|s| s.name == entry).collect();
                assert_eq!(opened.len(), 1, "one request, one `{entry}`: {opened:?}");
                assert!(
                    opened[0].attributes.is_empty(),
                    "`{entry}` carries no attribute: {:?}",
                    opened[0].attributes
                );
                let forwards = forwards_under(&spans, opened[0]);
                assert_eq!(
                    forwards.len(),
                    1,
                    "the unit's `forward` opens beneath `{entry}`: {spans:?}"
                );
                forwards[0]
            }
            None => {
                let ingress = row.ingress.expect("a row with no entry names its ingress");
                let plain: Vec<&Span> = spans
                    .iter()
                    .filter(|s| {
                        s.name == "forward" && attribute(s, "ingress").as_deref() == Some(ingress)
                    })
                    .collect();
                assert_eq!(plain.len(), 1, "{} {spans:?}", row.path);
                assert!(
                    !spans.iter().any(|s| entries.contains(&s.name.as_str())
                        && s.span_id == plain[0].parent_span_id
                        && s.trace_id == plain[0].trace_id),
                    "no entry span above {}'s `forward`: {:?}",
                    row.path,
                    plain[0]
                );
                plain[0]
            }
        };
        if let Some(ingress) = row.ingress {
            assert_eq!(
                (
                    attribute(forward, "ingress").as_deref(),
                    attribute(forward, "op").as_deref()
                ),
                (Some(ingress), Some("chat")),
                "1.5.5's `ingress` and `op` on {}'s `forward`: {:?}",
                row.path,
                forward.attributes
            );
        }
    }
}
