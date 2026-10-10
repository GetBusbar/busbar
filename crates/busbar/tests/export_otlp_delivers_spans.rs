// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE SHIPPED BINARY DELIVERS ITS SPANS TO AN OTLP COLLECTOR** (owner answer Q75: OTLP export
//! never delivered in 1.5.5 — every batch's export thread panicked, "there is no reactor running",
//! and shutdown printed "OTLP tracer shutdown failed" — and 1.6.0 fixes it as a bug fix).
//!
//! The real binary boots with one `module: otlp` instance pointed at a loopback collector this test
//! stands up (a plaintext `http://127.0.0.1` collector — the policy the sink declares allows it, as
//! 1.5.x's guard did), serves model requests that fail upstream (the request path's spans close
//! anyway), and is stopped with SIGTERM. The collector must have received OTLP/HTTP protobuf
//! `ExportTraceServiceRequest`s — decoded by the OpenTelemetry project's own generated types and
//! re-encoding to the very bytes received — carrying the request path's spans, each with a 16-byte
//! trace id, an 8-byte span id and `service.name = busbar`, children joined to their parents. The
//! boot log says `OTLP tracing enabled`, and neither of 1.5.5's two failure lines appears.
//!
//! RED (the 1.5.5 behaviour this fixes): the collector receives nothing.

#![cfg(unix)]
// The config serves `providers:`/`models:`, so the build must link the plane that takes body
// ingress: the linked table's answer, never a feature name.
#![cfg(linked_axis_body_ingress)]
// The sink is a linked export door: the test is that axis's, and asserts the binary links this one.
#![cfg(linked_axis_export_doors)]

mod common;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use prost::Message as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// The key of the wire the data door rides.
const WIRE: &str = "tcp";

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-otlp-delivers-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
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

/// One HTTP/1.1 request over a fresh connection: the status, or `None` before the listener is up.
fn request(port: u16, method: &str, path: &str, body: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .ok()?;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// Is `module: otlp` served by this build? A module on no export axis is refused by `--validate`.
fn otlp_linked(dir: &Path) -> bool {
    let out = Command::new(common::boot::exe())
        .arg("--validate")
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .output()
        .expect("run busbar");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    !text.contains("unknown exporter 'otlp'")
}

#[test]
fn the_shipped_binary_posts_its_spans_to_an_otlp_collector() {
    let dir = fixture_dir();
    let (data_port, admin_port) = (free_port(), free_port());
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
    assert!(
        otlp_linked(&dir),
        "a build on the export door axis refuses `module: otlp` as an unknown exporter"
    );

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

    // Model requests whose upstream refuses: the request path's spans open and close regardless.
    let body =
        r#"{"model":"test-model","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut served = 0;
    while served < 3 {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!("busbar exited ({status}) before serving:\n{}", read_log());
        }
        assert!(Instant::now() < deadline, "no data door:\n{}", read_log());
        match request(data_port, "POST", "/v1/messages", body) {
            Some(_) => served += 1,
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }

    // Delivery is off the request path, batched: wait for the collector to hear the sink's spans.
    let deadline = Instant::now() + Duration::from_secs(30);
    let heard = || common::otlp::spans(&common::otlp::requests(&seen, None)).len();
    while heard() < 3 {
        assert!(
            Instant::now() < deadline,
            "the collector received {} span(s) in 30 s:\n{}",
            heard(),
            read_log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Graceful stop, then read what the process said.
    unsafe_free_sigterm(child.0.id());
    let stop = Instant::now() + Duration::from_secs(30);
    while child.0.try_wait().expect("try_wait").is_none() && Instant::now() < stop {
        std::thread::sleep(Duration::from_millis(50));
    }
    let log = read_log();
    // The sink's own lines are in its own log file (THE DESIGN §11.2), named by its instance.
    let sink_log = std::fs::read_to_string(dir.join("plugin-logs").join("export.trace.log"))
        .unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        sink_log.contains("OTLP tracing enabled"),
        "{sink_log}\n{log}"
    );
    for failure in [
        "no reactor running",
        "OTLP tracer shutdown failed",
        "AlreadyShutdown",
    ] {
        assert!(
            !log.contains(failure),
            "1.5.5's failure `{failure}` in:\n{log}"
        );
    }

    let received = seen.lock().unwrap().clone();
    let mut spans = Vec::new();
    for (head, body) in &received {
        assert!(head.starts_with("post /v1/traces http/1.1\r\n"), "{head}");
        assert!(
            head.contains("\r\ncontent-type: application/x-protobuf"),
            "{head}"
        );
        let request = ExportTraceServiceRequest::decode(&body[..]).expect("an OTLP request");
        assert_eq!(
            request.encode_to_vec(),
            *body,
            "the canonical OTLP encoding"
        );
        for rs in &request.resource_spans {
            let resource = rs.resource.as_ref().expect("a resource");
            let service = resource
                .attributes
                .iter()
                .find(|kv| kv.key == "service.name")
                .and_then(|kv| kv.value.as_ref()?.value.clone());
            assert_eq!(service, Some(AnyValue::StringValue("busbar".into())));
            for ss in &rs.scope_spans {
                spans.extend(ss.spans.iter().cloned());
            }
        }
    }
    assert!(
        !spans.is_empty(),
        "no span in {} request(s)",
        received.len()
    );
    for span in &spans {
        assert_eq!(
            (span.trace_id.len(), span.span_id.len()),
            (16, 8),
            "{span:?}"
        );
        assert!(!span.name.is_empty(), "{span:?}");
        assert!(
            span.end_time_unix_nano >= span.start_time_unix_nano,
            "{span:?}"
        );
    }
    // Every child's parent arrived too, in the same trace.
    let children: Vec<_> = spans
        .iter()
        .filter(|s| !s.parent_span_id.is_empty())
        .collect();
    for child in &children {
        if let Some(parent) = spans.iter().find(|s| s.span_id == child.parent_span_id) {
            assert_eq!(parent.trace_id, child.trace_id, "{child:?}");
        }
    }
}

/// SIGTERM without `libc` in this test's dependencies: the `kill` utility every unix ships.
fn unsafe_free_sigterm(pid: u32) {
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
}
