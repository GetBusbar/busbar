// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The assembled binary's real tracing producer feeds full records through the linked and
//! dropped OTLP doors. A cross-dialect request drops unsupported sampling controls, producing
//! real warning events within its forward span. Both collectors must retain those events, full
//! attributes, status and the same identity, beyond the projected trace fields.

#![cfg(unix)]
#![cfg(feature = "export-otlp")]
// The config serves `providers:`/`models:`, so the build must link the plane door that declares
// `pools:` (`linked_section_pools`): the linked table's answer, never a feature name.
#![cfg(linked_section_pools)]
// The linked door is an export door: the test is that axis's, and its collector proves the sink.
#![cfg(linked_axis_export_doors)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// The dropped-in door's library: the sink repo's cdylib crate, snake-cased.
const CDYLIB: &str = "busbar_export_otlp_plugin";

/// The name the dropped-in tarball's manifest states.
const DROPPED: &str = "span-record-dropped";

/// The key of the wire the data door rides.
const WIRE: &str = "tcp";

/// The collector paths each door posts to.
const LINKED_PATH: &str = "/linked/v1/traces";
const DROPPED_PATH: &str = "/dropped/v1/traces";

/// `config.yaml` and `providers.yaml` in `dir`: the linked instance, and the dropped one only when
/// `name_dropped`.
fn write_configs(
    dir: &Path,
    data_port: u16,
    admin_port: u16,
    collector: u16,
    upstream: u16,
    name_dropped: bool,
) {
    let dropped = if name_dropped {
        format!(
            "  dropped: {{ module: {DROPPED}, settings: {{ url: \"http://127.0.0.1:{collector}{DROPPED_PATH}\" }} }}\n"
        )
    } else {
        String::new()
    };
    std::fs::write(
        dir.join("providers.yaml"),
        format!("mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:{upstream}\"\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
advanced:
  allow_destinations: ["127.0.0.1"]
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
  linked: {{ module: otlp, settings: {{ url: "http://127.0.0.1:{collector}{LINKED_PATH}" }} }}
{dropped}providers:
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
}

/// Kill the child when the test ends, however it ends.
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One model request over a fresh connection: the status, or `None` before the listener is up.
fn request(port: u16, body: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .ok()?;
    let req = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

#[test]
fn real_producer_span_records_survive_both_otlp_doors() {
    // A both-doors proof never skips: the dropped-in door's cdylib is built or the test fails.
    let lib = common::plugins::cdylib(CDYLIB)
        .unwrap_or_else(|| common::plugins::missing(CDYLIB, common::plugins::BUILD_PINNED));
    let dir = common::plugins::scratch("otlp-span-records");
    std::fs::create_dir_all(dir.join("plugins")).unwrap();
    let mut manifest = common::plugins::manifest("export", DROPPED, "acme");
    common::plugins::state(&mut manifest, &lib);
    assert!(
        manifest.statement.is_some(),
        "the dropped OTLP library must export its memory-ABI door"
    );
    let tarball = common::plugins::seal(manifest, &lib);
    std::fs::write(dir.join("plugins").join("otlp.tar.gz"), tarball).unwrap();
    // THE WIRE UNDER THE DOOR. A build that does not link the wire's row boots only with it dropped
    // in; one that links it would refuse the tarball as a second row on the same key.
    if !LINKED_TRANSPORTS.iter().any(|w| w.key == WIRE) {
        let (lib, _) = common::plugins::transport_cdylib_under(&[WIRE]).unwrap_or_else(|| {
            common::plugins::missing(&format!("{WIRE} transport"), common::plugins::BUILD_PINNED)
        });
        let bytes = common::plugins::pack("transport", "dropped-wire", &lib, "acme");
        std::fs::write(dir.join("plugins").join("dropped-wire.tar.gz"), bytes).unwrap();
    }
    let (collector_port, seen) = common::otlp::collector();
    let upstream = upstream();
    let busbar = || {
        let mut c = Command::new(common::boot::exe());
        c.env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "info");
        c
    };

    // 1. The scan admits the operator-trusted third party's collector: `--validate` skips nothing.
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data_port, admin_port, collector_port, upstream, true);
    let out = busbar().arg("--validate").output().expect("run --validate");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stdout.contains(&format!("skipped: {DROPPED} (otlp.tar.gz)")),
        "{stdout}"
    );

    // 2. Both collectors post the request path's spans.
    let log_path = dir.join("out.log");
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();

    // Anthropic has no seed/frequency_penalty: its real writer logs the dropped controls while
    // the kernel's forward span is active. The local upstream answers a valid whole response.
    let body = r#"{"model":"test-model","max_tokens":1,"seed":17,"frequency_penalty":0.5,"messages":[{"role":"user","content":"hi"}]}"#;
    // The ports step 1 wrote: `free_port` holds each from the moment it chose it.
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Reap(
        busbar()
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut served = 0;
    while served < 3 {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!("busbar exited ({status}) before serving:\n{}", read_log());
        }
        assert!(Instant::now() < deadline, "no data door:\n{}", read_log());
        match request(data_port, body) {
            Some(status) => {
                assert_eq!(
                    status,
                    200,
                    "the request must reach the cross-dialect writer:\n{}",
                    read_log()
                );
                served += 1;
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }

    // Wait for the known closed forward spans, then inspect their payload. Missing metadata is
    // an assertion failure, rather than a timeout waiting for fields the old flag never produced.
    let forwards = |path| {
        common::otlp::spans(&common::otlp::requests(&seen, Some(path)))
            .into_iter()
            .filter(|span| span.name == "forward")
            .collect::<Vec<_>>()
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while forwards(LINKED_PATH).len() < served || forwards(DROPPED_PATH).len() < served {
        assert!(
            Instant::now() < deadline,
            "forward spans did not arrive at both collectors:\n{}",
            read_log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let linked = forwards(LINKED_PATH);
    let dropped = forwards(DROPPED_PATH);
    for span in &linked {
        assert_full_record(span);
        let peer = dropped
            .iter()
            .find(|peer| peer.span_id == span.span_id)
            .expect("the dropped door must receive the same producer span identity");
        assert_eq!(
            span, peer,
            "both doors must preserve the full producer record"
        );
    }
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}

fn upstream() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            if common::upstream::read_request(&mut conn).is_some() {
                common::upstream::respond(
                    &mut conn,
                    200,
                    &serde_json::json!({
                        "id": "span-record-test", "type": "message", "role": "assistant",
                        "model": "test-model", "content": [{"type": "text", "text": "ok"}],
                        "stop_reason": "end_turn", "stop_sequence": null,
                        "usage": {"input_tokens": 1, "output_tokens": 1}
                    }),
                );
            }
        }
    });
    port
}

fn attribute<'a>(
    attrs: &'a [opentelemetry_proto::tonic::common::v1::KeyValue],
    key: &str,
) -> Option<&'a opentelemetry_proto::tonic::common::v1::any_value::Value> {
    attrs
        .iter()
        .find(|attr| attr.key == key)?
        .value
        .as_ref()?
        .value
        .as_ref()
}

fn assert_full_record(span: &opentelemetry_proto::tonic::trace::v1::Span) {
    use opentelemetry_proto::tonic::common::v1::any_value::Value;
    assert_eq!((span.trace_id.len(), span.span_id.len()), (16, 8));
    assert!(span.trace_id.iter().any(|byte| *byte != 0));
    assert!(span.span_id.iter().any(|byte| *byte != 0));
    assert_eq!(span.parent_span_id.len(), 8);
    assert_eq!(span.kind, 1);
    assert!(span.start_time_unix_nano > 0);
    assert!(span.end_time_unix_nano >= span.start_time_unix_nano);
    for key in ["code.file.path", "code.module.name", "target", "request_id"] {
        assert!(
            matches!(attribute(&span.attributes, key), Some(Value::StringValue(value)) if !value.is_empty()),
            "missing typed full-span attribute {key}: {span:?}"
        );
    }
    for key in ["code.line.number", "thread.id", "busy_ns", "idle_ns"] {
        assert!(
            matches!(attribute(&span.attributes, key), Some(Value::IntValue(_))),
            "missing typed full-span attribute {key}: {span:?}"
        );
    }
    assert_eq!(
        attribute(&span.attributes, "op"),
        Some(&Value::StringValue("chat".into()))
    );
    assert_eq!(span.status.as_ref().expect("full span status").code, 0);
    assert_eq!(span.status.as_ref().unwrap().message, "");
    assert!(
        !span.events.is_empty(),
        "cross-dialect warning events were lost: {span:?}"
    );
    assert!(span.events.iter().any(|event| matches!(attribute(&event.attributes, "level"), Some(Value::StringValue(level)) if level == "WARN")), "the writer's warnings did not reach the collector: {span:?}");
    for control in ["seed", "frequency_penalty"] {
        assert!(
            span.events.iter().any(|event| event
                .name
                .contains(&format!("dropping {control} on Anthropic egress"))),
            "the real {control} translation warning was lost: {span:?}"
        );
    }
    for event in &span.events {
        assert!(!event.name.is_empty());
        assert!(event.time_unix_nano >= span.start_time_unix_nano);
        assert!(event.time_unix_nano <= span.end_time_unix_nano);
        assert!(matches!(
            attribute(&event.attributes, "target"),
            Some(Value::StringValue(_))
        ));
        assert!(matches!(
            attribute(&event.attributes, "code.line.number"),
            Some(Value::IntValue(_))
        ));
    }
}
