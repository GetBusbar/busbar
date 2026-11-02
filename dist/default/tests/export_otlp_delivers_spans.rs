// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]
#![cfg(linked_axis_export_doors)]

mod common;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use opentelemetry_proto::tonic::trace::v1::Span;
use prost::Message as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

const WIRE: &str = "tcp";

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("busbar-otlp-delivers-{}-{}", std::process::id(), {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{}-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
            line!(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, collector: u16) {
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

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

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

fn drop_in_wire(dir: &Path) {
    if !LINKED_TRANSPORTS.iter().any(|w| w.key == WIRE) {
        let (lib, _) = common::plugins::transport_cdylib_under(&[WIRE]).unwrap_or_else(|| {
            common::plugins::missing(&format!("{WIRE} transport"), common::plugins::BUILD_PINNED)
        });
        let bytes = common::plugins::pack("transport", "dropped-wire", &lib, "acme");
        std::fs::write(dir.join("plugins").join("dropped-wire.tar.gz"), bytes).unwrap();
    }
}

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
    drop_in_wire(&dir);
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

    unsafe_free_sigterm(child.0.id());
    let stop = Instant::now() + Duration::from_secs(30);
    while child.0.try_wait().expect("try_wait").is_none() && Instant::now() < stop {
        std::thread::sleep(Duration::from_millis(50));
    }
    let log = read_log();

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

    let children: Vec<_> = spans
        .iter()
        .filter(|s| !s.parent_span_id.is_empty())
        .collect();
    for child in &children {
        let parent = spans
            .iter()
            .find(|s| s.span_id == child.parent_span_id)
            .unwrap_or_else(|| panic!("the parent of the exported child is missing: {child:?}"));
        assert_eq!(parent.trace_id, child.trace_id, "{child:?}");
    }
}

fn unsafe_free_sigterm(pid: u32) {
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
}

struct Row {
    entry: Option<&'static str>,
    entry_fields: Vec<(&'static str, &'static str)>,
    ingress: Option<&'static str>,
    head: Vec<(&'static str, &'static str)>,
    path: &'static str,
    body: &'static str,
}

fn rows() -> Vec<Row> {
    let some = |field: &'static str| (field != "-").then_some(field);
    include_str!("fixtures/otlp_request_spans.txt")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let f: Vec<&'static str> = l.splitn(6, '\t').collect();
            assert_eq!(f.len(), 6, "a fixture row has six fields: {l}");
            let pairs = |field: &'static str, sep: &'static str| {
                some(field)
                    .map(|h| {
                        h.split(';')
                            .filter_map(|kv| kv.split_once(sep))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };
            Row {
                entry: some(f[0]),
                entry_fields: pairs(f[1], "="),
                ingress: some(f[2]),
                head: pairs(f[3], ": "),
                path: f[4],
                body: f[5],
            }
        })
        .collect()
}

fn post_with(port: u16, path: &str, head: &[(&str, &str)], body: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .ok()?;
    let fields: String = head.iter().map(|(n, v)| format!("{n}: {v}\r\n")).collect();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\ncontent-type: application/json\r\n{fields}\
         content-length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

fn attribute(span: &Span, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key == key)
        .and_then(|kv| match kv.value.as_ref()?.value.as_ref()? {
            AnyValue::StringValue(s) => Some(s.clone()),
            other => Some(format!("{other:?}")),
        })
}

fn under(spans: &[Span], span: &Span, names: &[&str]) -> bool {
    spans.iter().any(|p| {
        names.contains(&p.name.as_str())
            && p.span_id == span.parent_span_id
            && p.trace_id == span.trace_id
    })
}

#[test]
fn the_request_paths_spans_reach_the_collector_as_1_5_5_named_them() {
    let dir = fixture_dir();
    let (data_port, admin_port) = (free_port(), free_port());
    let (collector_port, seen) = common::otlp::collector();
    write_configs(&dir, data_port, admin_port, collector_port);
    drop_in_wire(&dir);

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

    let rows = rows();
    let mut entries: Vec<&str> = rows.iter().filter_map(|r| r.entry).collect();
    entries.sort_unstable();
    entries.dedup();
    assert!(!entries.is_empty(), "the fixture names an entry span");
    let named = |name: &str| rows.iter().filter(|r| r.entry == Some(name)).count();
    let deadline = Instant::now() + Duration::from_secs(60);
    for row in &rows {
        loop {
            if let Some(status) = child.0.try_wait().expect("try_wait") {
                panic!("busbar exited ({status}) before serving:\n{}", read_log());
            }
            assert!(Instant::now() < deadline, "no data door:\n{}", read_log());
            if post_with(data_port, row.path, &row.head, row.body).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    let spans = || common::otlp::spans(&common::otlp::requests(&seen, None));
    let forwards = rows.iter().filter(|r| r.ingress.is_some()).count();
    let heard = |spans: &[Span]| {
        entries
            .iter()
            .all(|e| spans.iter().filter(|s| s.name == *e).count() >= named(e))
            && spans.iter().filter(|s| s.name == "forward").count() >= forwards
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

    std::thread::sleep(Duration::from_secs(2));
    let spans = spans();
    let _ = std::fs::remove_dir_all(&dir);

    for entry in &entries {
        let mut opened: Vec<Vec<(String, String)>> = spans
            .iter()
            .filter(|s| s.name == *entry)
            .map(|s| {
                s.attributes
                    .iter()
                    .map(|kv| (kv.key.clone(), attribute(s, &kv.key).unwrap_or_default()))
                    .collect()
            })
            .collect();
        let mut wanted: Vec<Vec<(String, String)>> = rows
            .iter()
            .filter(|r| r.entry == Some(*entry))
            .map(|r| {
                r.entry_fields
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect()
            })
            .collect();
        opened.sort();
        wanted.sort();
        assert_eq!(
            opened, wanted,
            "`{entry}` opens once per row naming it, with that row's fields, and for no other row"
        );
    }

    for row in rows.iter().filter(|r| r.ingress.is_some()) {
        let ingress = row.ingress;
        let found = spans.iter().any(|s| {
            s.name == "forward"
                && attribute(s, "ingress").as_deref() == ingress
                && attribute(s, "op").as_deref() == Some("chat")
                && match row.entry {
                    Some(entry) => under(&spans, s, &[entry]),
                    None => !under(&spans, s, &entries),
                }
        });
        assert!(
            found,
            "{}: a `forward` carrying 1.5.5's `ingress` {ingress:?} and `op`, beneath {:?}: {spans:?}",
            row.path, row.entry
        );
    }
}
