// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(feature = "export-otlp")]
#![cfg(linked_section_pools)]
#![cfg(linked_axis_export_doors)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

const CDYLIB: &str = "busbar_export_otlp_plugin";

const DROPPED: &str = "span-record-dropped";

const WIRE: &str = "tcp";

const LINKED_PATH: &str = "/linked/v1/traces";
const DROPPED_PATH: &str = "/dropped/v1/traces";

fn write_configs(
    dir: &Path,
    data_port: u16,
    admin_port: u16,
    collector: u16,
    upstream: u16,
    name_dropped: bool,
) {
    let mut plugins = common::plugins::trusted_config_document(&dir.join("plugins"));
    plugins["logs"] = serde_json::json!({ "dir": dir.join("plugin-logs") });
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
plugins: {plugins}
export:
  linked: {{ module: otlp, settings: {{ url: "http://127.0.0.1:{collector}{LINKED_PATH}" }} }}
{dropped}providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
pools:
  span-pool:
    members:
      - model: test-model
"#,
        ),
    )
    .unwrap();
}

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(port: u16, body: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .ok()?;
    // The named pool creates the real arrival parent; bare OpenAI ingress has none.
    let req = format!(
        "POST /span-pool/v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\ncontent-type: application/json\r\n\
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
    let lib = common::plugins::cdylib(CDYLIB)
        .unwrap_or_else(|| common::plugins::missing(CDYLIB, common::plugins::BUILD_PINNED));
    let dir = common::plugins::scratch("otlp-span-records");
    std::fs::create_dir_all(dir.join("plugins")).unwrap();
    let manifest_path = std::env::var_os("BUSBAR_TEST_EXPORT_OTLP_MANIFEST")
        .expect("the actual OTLP package manifest is provided");
    let mut manifest: busbar_plugin_loader::sign::Manifest = serde_json::from_slice(
        &std::fs::read(manifest_path).expect("read the actual OTLP manifest"),
    )
    .expect("the OTLP manifest parses");
    manifest.name = DROPPED.into();
    manifest.alias = DROPPED.into();
    manifest.former_names.clear();
    manifest.publisher = common::plugins::FIXTURE_PUBLISHER.into();
    // This re-publication is operator-trusted third party; reserved BUSBAR codes
    // belong to the original first-party package, whose linked copy keeps them.
    manifest.declares.diagnostics.clear();
    common::plugins::state(&mut manifest, &lib);
    assert!(
        manifest.statement.is_some(),
        "the dropped OTLP library must export its memory-ABI door"
    );
    let tarball = common::plugins::signed(&common::plugins::key(0x5a), manifest, &lib);
    std::fs::write(dir.join("plugins").join("otlp.tar.gz"), tarball).unwrap();

    if !LINKED_TRANSPORTS.iter().any(|w| w.key == WIRE) {
        let (lib, _) = common::plugins::transport_cdylib_under(&[WIRE]).unwrap_or_else(|| {
            common::plugins::missing(&format!("{WIRE} transport"), common::plugins::BUILD_PINNED)
        });
        let mut manifest = common::plugins::manifest(
            "transport",
            "dropped-wire",
            common::plugins::FIXTURE_PUBLISHER,
        );
        common::plugins::state(&mut manifest, &lib);
        let bytes = common::plugins::signed(&common::plugins::key(0x5a), manifest, &lib);
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

    let log_path = dir.join("out.log");
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();

    let body = r#"{"model":"test-model","max_tokens":1,"seed":17,"frequency_penalty":0.5,"messages":[{"role":"user","content":"hi"}]}"#;

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

    let forwards = |path| {
        common::otlp::spans(&common::otlp::requests(&seen, Some(path)))
            .into_iter()
            .filter(|span| span.name == "forward")
            .collect::<Vec<_>>()
    };
    let parents = |path| {
        common::otlp::spans(&common::otlp::requests(&seen, Some(path)))
            .into_iter()
            .filter(|span| span.name == "named")
            .collect::<Vec<_>>()
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while forwards(LINKED_PATH).len() < served
        || forwards(DROPPED_PATH).len() < served
        || parents(LINKED_PATH).len() < served
        || parents(DROPPED_PATH).len() < served
    {
        assert!(
            Instant::now() < deadline,
            "forward spans and their named arrival parents did not reach both collectors:\n{}",
            read_log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let linked = forwards(LINKED_PATH);
    let dropped = forwards(DROPPED_PATH);
    let linked_parents = parents(LINKED_PATH);
    let dropped_parents = parents(DROPPED_PATH);
    for span in &linked {
        assert_full_record(span);
        let parent = linked_parents
            .iter()
            .find(|parent| {
                parent.span_id == span.parent_span_id && parent.trace_id == span.trace_id
            })
            .expect("the forward's parent must be the real named-pool arrival on its trace");
        assert_eq!(
            attribute(&parent.attributes, "pool"),
            Some(
                &opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(
                    "span-pool".into()
                )
            )
        );
        let dropped_parent = dropped_parents
            .iter()
            .find(|peer| peer.span_id == parent.span_id)
            .expect("the dropped door must preserve the same named arrival parent identity");
        assert_eq!(
            parent, dropped_parent,
            "both doors must preserve the full named arrival parent"
        );
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
