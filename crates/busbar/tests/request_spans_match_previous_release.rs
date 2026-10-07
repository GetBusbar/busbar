// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE REQUEST PATH EMITS THE PREVIOUS RELEASE'S SPANS** (ARCHITECT RULING D1 2026-10-06): what a
//! deployment sees of a request's spans is what it exports, so for the same requests the shipped
//! binary emits every span name 1.5.5 emitted, each with the fields 1.5.5 gave it.
//!
//! 1.5.5's request-path spans (all at DEBUG, the hot-path level the export floors at):
//!
//! | span | fields | v1.5.5 site |
//! |---|---|---|
//! | `forward` | `pool`, `ingress`, `op`, `request_id` | `crates/busbar/src/proxy/engine/mod.rs:120-125`, `request_id` recorded at `:152` |
//! | `forward_once` | `lane` | `crates/busbar/src/proxy/engine/walk.rs:382-387` (fallback pool, least-bad, queued slot) |
//! | `named` | `pool` | `crates/busbar/src/ingress/mod.rs:1161` |
//! | `adhoc` | `provider`, `model` | `crates/busbar/src/ingress/mod.rs:1292` |
//! | `gemini_ingress` | — | `crates/busbar/src/ingress/mod.rs:788` |
//! | `bedrock_converse` | — | `crates/busbar/src/ingress/mod.rs:1043` |
//! | `bedrock_converse_stream` | — | `crates/busbar/src/ingress/mod.rs:1070` |
//!
//! The real binary boots with a `module: otlp` trace sink pointed at a loopback collector, and its
//! members point at a closed loopback port, so every attempt fails before an answer (the spans open
//! and close regardless). One request of each shape is sent: a chat completion through a pool whose
//! member fails and which spills into its fallback pool (`forward` + `forward_once`), the same one
//! streamed, the two path-named surfaces, and the three path-model dialect surfaces. The collector's
//! spans must carry the names above, with the fields the export vocabulary carries (`pool`,
//! `ingress`, `op`, `lane`, `provider`, `model`); the correlation id, which the export vocabulary does
//! not carry, is read off the stderr log's span context.
//!
//! `forward` and `forward_once` are the kernel's and the composition root's, and are asserted. The
//! five surface spans are opened plane-side and are dropped by the plugin call capture before they
//! reach the host: that test is ignored as the QUESTION it states.
//!
//! RED (before the ruling): the door opened `forward` with no `op` and recorded its `pool` and
//! `ingress` after the export had read the span's fields, never recorded `request_id` on it, and
//! opened no `forward_once`.

#![cfg(unix)]
// The config serves `providers:`/`models:`/`pools:`, so the build must link the plane that takes
// body ingress: the linked table's answer, never a feature name.
#![cfg(linked_axis_node)]

mod common;

use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use opentelemetry_proto::tonic::trace::v1::Span;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// The span names 1.5.5's request path emitted (module doc).
const PREVIOUS_RELEASE_SPANS: &[&str] = &[
    "forward",
    "forward_once",
    "named",
    "adhoc",
    "gemini_ingress",
    "bedrock_converse",
    "bedrock_converse_stream",
];

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-request-spans-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, collector: u16) {
    // The provider catalog row is test data (`fixtures/mock_provider.yaml`): its `base_url` is the
    // closed loopback port 9, so every attempt is refused before an answer.
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
  logs: {{ dir: '{logs}' }}
export:
  trace: {{ module: otlp, settings: {{ url: "http://127.0.0.1:{collector}/v1/traces" }} }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  m-a:
    provider: mock
  m-b:
    provider: mock
pools:
  main:
    members:
      - model: m-a
    on_exhausted: {{fallback_pool: spare}}
  spare:
    members:
      - model: m-b
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

/// A span's string attribute.
fn attr<'s>(span: &'s Span, key: &str) -> Option<&'s str> {
    span.attributes
        .iter()
        .find(|kv| kv.key == key)
        .and_then(|kv| match kv.value.as_ref()?.value.as_ref()? {
            AnyValue::StringValue(s) => Some(s.as_str()),
            _ => None,
        })
}

/// The spans named `name`.
fn named<'s>(spans: &'s [Span], name: &str) -> Vec<&'s Span> {
    spans.iter().filter(|s| s.name == name).collect()
}

/// The span `child`'s parent is a `forward` span of the same trace.
fn under_forward(spans: &[Span], child: &Span) -> bool {
    spans.iter().any(|p| {
        p.name == "forward" && p.span_id == child.parent_span_id && p.trace_id == child.trace_id
    })
}

/// Boot the shipped binary, send one request of each shape (module doc) and wait until the
/// collector has heard every span named in `wanted`: the spans it heard and the process's log, or
/// `None` when this build cannot run the drive (no tcp wire, no `otlp` module).
fn drive(wanted: &[&str]) -> Option<(Vec<Span>, String)> {
    // The data door rides the tcp wire; a build that does not link it is out of this test's reach.
    if !LINKED_TRANSPORTS.iter().any(|w| w.key == "tcp") {
        return None;
    }
    let dir = fixture_dir();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    let (collector_port, seen) = common::otlp::collector();
    write_configs(&dir, data_port, admin_port, collector_port);
    if !otlp_linked(&dir) {
        return None;
    }

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            // The stderr log at trace, so its span context shows the correlation id the export
            // vocabulary does not carry.
            .env("RUST_LOG", "trace")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();

    let chat = r#"{"model":"main","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
    let chat_streamed = r#"{"model":"main","max_tokens":1,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    let messages = r#"{"max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
    let contents = r#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#;
    let converse = r#"{"messages":[{"role":"user","content":[{"text":"hi"}]}]}"#;
    let requests: &[(&str, &str)] = &[
        ("/v1/chat/completions", chat),
        ("/v1/chat/completions", chat_streamed),
        ("/main/v1/messages", messages),
        ("/mock/m-a/v1/messages", messages),
        ("/v1beta/models/m-a:generateContent", contents),
        ("/model/m-a/converse", converse),
        ("/model/m-a/converse-stream", converse),
    ];

    // The listener first: the first request is retried until the door answers.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!("busbar exited ({status}) before serving:\n{}", read_log());
        }
        assert!(Instant::now() < deadline, "no data door:\n{}", read_log());
        if post(data_port, requests[0].0, requests[0].1).is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    for (path, body) in &requests[1..] {
        assert!(
            post(data_port, path, body).is_some(),
            "{path} was not answered:\n{}",
            read_log()
        );
    }

    // Delivery is off the request path, batched: wait until every wanted name has been heard.
    let deadline = Instant::now() + Duration::from_secs(30);
    let heard = || common::otlp::spans(&common::otlp::requests(&seen, None));
    loop {
        let names: BTreeSet<String> = heard().into_iter().map(|s| s.name).collect();
        if wanted.iter().all(|n| names.contains(*n)) {
            break;
        }
        if Instant::now() >= deadline {
            let missing: Vec<_> = wanted.iter().filter(|n| !names.contains(**n)).collect();
            panic!(
                "the collector never heard {missing:?}; it heard {names:?}\n{}",
                read_log()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let spans = heard();
    let log = read_log();
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
    Some((spans, log))
}

/// The spans the kernel and the composition root open for 1.5.5's request path: `forward` with its
/// `pool`, `ingress`, `op` and `request_id`, and `forward_once` with its `lane` under it.
#[test]
fn the_request_path_emits_the_previous_release_request_spans_with_their_fields() {
    let Some((spans, log)) = drive(&["forward", "forward_once"]) else {
        return;
    };

    // `forward`: the pool, the dialect it arrived in and its operation, for the pooled chat
    // completion (once buffered, once streamed); and an empty pool for an entry named directly.
    let forward = named(&spans, "forward");
    let pooled: Vec<_> = forward
        .iter()
        .filter(|s| {
            attr(s, "pool") == Some("main")
                && attr(s, "ingress") == Some("openai")
                && attr(s, "op") == Some("chat")
        })
        .collect();
    assert!(
        pooled.len() >= 2,
        "the pooled chat completions' forward spans carry pool, ingress and op: {forward:#?}"
    );
    assert!(
        forward.iter().any(|s| attr(s, "pool") == Some("")
            && attr(s, "ingress") == Some("gemini")
            && attr(s, "op") == Some("chat")),
        "a directly named entry's forward span carries an empty pool: {forward:#?}"
    );

    // `forward_once`: the spill into the fallback pool's member, its lane, under the request span.
    let once = named(&spans, "forward_once");
    assert!(
        once.iter().all(|s| attr(s, "lane")
            .is_some_and(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
            && under_forward(&spans, s)),
        "every degraded attempt's span carries its lane and sits under the request span: {once:#?}"
    );

    // `request_id`: the request span's correlation id, a number, in the stderr log's span context.
    let has_request_id = log.lines().any(|line| {
        line.split("forward{").skip(1).any(|ctx| {
            let ctx = ctx.split('}').next().unwrap_or("");
            ctx.split_whitespace().any(|kv| {
                kv.strip_prefix("request_id=")
                    .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            })
        })
    });
    assert!(
        has_request_id,
        "no `forward` span context in the log carries a request_id:\n{log}"
    );
}

/// The spans 1.5.5 opened per surface: `named{pool}`, `adhoc{provider, model}`, `gemini_ingress`,
/// `bedrock_converse` and `bedrock_converse_stream`, each under the request span. The plane opens
/// them in its arrival reader (ARCHITECT RULING D1 2026-10-06: plane-side, so the kernel and the root
/// stay neutral), but every plugin slot body runs under the plugin-log call capture, the thread's
/// scoped dispatcher for the call (`busbar-contract` `abi/sdk/door.rs:409-410`), whose `new_span`
/// keeps nothing (`abi/sdk/capture.rs:147-151`): a span the plane opens never reaches the host's
/// subscriber or its trace export. Carrying it across needs a change to the call capture under
/// `busbar-contract/src/abi`, an ABI decision the ruling does not settle.
#[test]
#[ignore = "QUESTION (ARCHITECT RULING D1 2026-10-06): a plane-side span is dropped by the door's \
            call capture (busbar-contract abi/sdk/capture.rs:147-151) and never reaches the export"]
fn the_request_path_emits_the_previous_release_surface_spans() {
    let Some((spans, _log)) = drive(PREVIOUS_RELEASE_SPANS) else {
        return;
    };
    // The route spans, with the names and the provider and model they carried.
    assert!(
        named(&spans, "named")
            .iter()
            .any(|s| attr(s, "pool") == Some("main") && under_forward(&spans, s)),
        "{:#?}",
        named(&spans, "named")
    );
    assert!(
        named(&spans, "adhoc")
            .iter()
            .any(|s| attr(s, "provider") == Some("mock")
                && attr(s, "model") == Some("m-a")
                && under_forward(&spans, s)),
        "{:#?}",
        named(&spans, "adhoc")
    );
    for name in [
        "gemini_ingress",
        "bedrock_converse",
        "bedrock_converse_stream",
    ] {
        assert!(
            named(&spans, name).iter().any(|s| under_forward(&spans, s)),
            "{name}: {:#?}",
            named(&spans, name)
        );
    }
}
