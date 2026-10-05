// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE `traces` STREAM, BOTH DOORS, TO A COLLECTOR** — K9a S7 (BUSBAR-1.6.0 18b(d)) and K9e-2 end
//! to end through the shipped binary: the kernel's traces producer turns closed request-path spans
//! into `traces` records, and the OTLP sink (`module: otlp`, GetBusbar/busbar-export-otlp at the
//! root's pinned rev) is handed them the same whether it came in LINKED or DROPPED IN — both on the
//! export kind's memory ABI, through the one dispatcher — and posts them through the host's one
//! connector to a collector as OTLP/HTTP protobuf requests.
//!
//! The binary links the sink (its logic crate's door); the same sink's repo `cdylib`, packed with
//! its own Statement rendering under another name, is dropped into `plugins/`. One `export:` block
//! names both, each pointed at its own path on one loopback collector. Every request body must be
//! an OTLP `ExportTraceServiceRequest` by the OpenTelemetry project's own generated types,
//! re-encoding to the very same bytes, and the two doors must deliver the SAME spans byte for byte
//! (each door batches on its own, so spans are compared, not requests).

#![cfg(unix)]
// The config serves `providers:`/`models:`, so the build must link the plane that takes body
// ingress: the linked table's answer, never a feature name.
#![cfg(linked_axis_body_ingress)]

mod common;

use prost::Message as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// The dropped-in door's library: the export-otlp repo's cdylib crate, snake-cased.
const CDYLIB: &str = "busbar_export_otlp_plugin";

/// The name the dropped-in tarball's manifest states.
const DROPPED: &str = "k9e-dropped";

/// The collector paths each door posts to.
const LINKED_PATH: &str = "/linked/v1/traces";
const DROPPED_PATH: &str = "/dropped/v1/traces";

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
  linked: {{ module: otlp, settings: {{ url: "http://127.0.0.1:{collector}{LINKED_PATH}" }} }}
  dropped: {{ module: {DROPPED}, settings: {{ url: "http://127.0.0.1:{collector}{DROPPED_PATH}" }} }}
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
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\ncontent-type: application/json\r\n\
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
fn a_closed_span_reaches_an_otlp_collector_the_same_through_either_door() {
    // The data door rides the tcp wire; a build that does not link it is out of this test's reach.
    if !LINKED_TRANSPORTS.iter().any(|w| w.key == "tcp") {
        return;
    }
    let Some(lib) = common::plugins::cdylib(CDYLIB) else {
        assert!(
            std::env::var_os("CI").is_none(),
            "the {CDYLIB} cdylib is not built under CI; a both-doors proof must not skip"
        );
        return;
    };
    let dir = common::plugins::scratch("traces-both-doors");
    std::fs::create_dir_all(dir.join("plugins")).unwrap();
    let tarball = common::plugins::pack_stated("export", DROPPED, &lib, "acme");
    std::fs::write(dir.join("plugins").join("otlp.tar.gz"), tarball).unwrap();
    let (collector_port, seen) = common::otlp::collector();
    let log_path = dir.join("out.log");
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();

    // Model requests whose upstream refuses: the request path's spans open and close regardless.
    let body =
        r#"{"model":"test-model","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
    // A PORT PICKED IS NOT A PORT HELD: `free_port` claims its number against every other busbar
    // test, but any other socket on the machine (an outbound connection's ephemeral source port, a
    // listener another crate's test bound to `:0`) can take it before the child binds it, and the
    // child then refuses to boot (BUSBAR-9007, address in use) with nothing of this test's wrong.
    // That one refusal, and only it, boots again on freshly picked ports; any other exit fails.
    const BOOTS: usize = 4;
    let mut boot = 0;
    let _child = loop {
        boot += 1;
        let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
        write_configs(&dir, data_port, admin_port, collector_port);
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
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut served = 0;
        let mut collided = false;
        while served < 3 {
            if let Some(status) = child.0.try_wait().expect("try_wait") {
                let out = read_log();
                if boot < BOOTS
                    && out.contains("BUSBAR-9007")
                    && out.contains("Address already in use")
                {
                    collided = true;
                    break;
                }
                panic!("busbar exited ({status}) before serving:\n{out}");
            }
            assert!(Instant::now() < deadline, "no data door:\n{}", read_log());
            match request(data_port, body) {
                Some(_) => served += 1,
                None => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        if !collided {
            break child;
        }
    };

    // Delivery is off the request path, batched per door: wait until both doors' spans settle.
    let spans_at = |path| {
        let mut spans: Vec<Vec<u8>> =
            common::otlp::spans(&common::otlp::requests(&seen, Some(path)))
                .iter()
                .map(|s| s.encode_to_vec())
                .collect();
        spans.sort();
        spans
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (linked, dropped) = (spans_at(LINKED_PATH), spans_at(DROPPED_PATH));
        if linked.len() >= 3 && linked == dropped {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the doors did not deliver the same spans in 30 s: linked {} dropped {}\n{}",
            linked.len(),
            dropped.len(),
            read_log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    for span in common::otlp::spans(&common::otlp::requests(&seen, None)) {
        assert_eq!(
            (span.trace_id.len(), span.span_id.len()),
            (16, 8),
            "{span:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
