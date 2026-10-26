// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE `traces` STREAM TO A COLLECTOR, AND WHICH DOORS MAY CARRY IT** — K9a S7 (BUSBAR-1.6.0
//! 18b(d)) and K9e-2 end to end through the shipped binary: the kernel's traces producer turns
//! closed request-path spans into `traces` records, and the OTLP sink (`module: otlp`,
//! the sink's own repo at the root's pinned rev), LINKED on the export kind's memory ABI,
//! posts them through the host's one connector to a collector as OTLP/HTTP protobuf requests. Every
//! request body must be an OTLP `ExportTraceServiceRequest` by the OpenTelemetry project's own
//! generated types, re-encoding to the very same bytes.
//!
//! The sink's one need is in the `loopback-allowed` egress class. The same sink's repo `cdylib`,
//! dropped into `plugins/` by a third party (`acme`, unsigned) and admitted by the operator's
//! `plugins.trust` opt-in, loads as 1.5.5 loaded it UNVERIFIED (OWNER 2026-10-24, oracle BOOT-W23:
//! the operator's opt-in is the grant): `--validate` does not skip it, and a configuration naming
//! it posts the request path's spans to its collector beside the linked one. (This binary embeds the real release key, whose
//! private half no test holds, so a FIRST-PARTY dropped collector cannot be packed here; the loader's
//! `export_conformance_tests` carry the same span through both doors byte for byte, under a release
//! key of the test's own.)

#![cfg(unix)]
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
const DROPPED: &str = "k9e-dropped";

/// The key of the wire the data door rides.
const WIRE: &str = "tcp";

/// The collector paths each door posts to.
const LINKED_PATH: &str = "/linked/v1/traces";
const DROPPED_PATH: &str = "/dropped/v1/traces";

/// `config.yaml` and `providers.yaml` in `dir`: the linked instance, and the dropped one only when
/// `name_dropped`.
fn write_configs(dir: &Path, data_port: u16, admin_port: u16, collector: u16, name_dropped: bool) {
    let dropped = if name_dropped {
        format!(
            "  dropped: {{ module: {DROPPED}, settings: {{ url: \"http://127.0.0.1:{collector}{DROPPED_PATH}\" }} }}\n"
        )
    } else {
        String::new()
    };
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
fn a_closed_span_reaches_an_otlp_collector_through_either_door() {
    // A both-doors proof never skips: the dropped-in door's cdylib is built or the test fails.
    let lib = common::plugins::cdylib(CDYLIB)
        .unwrap_or_else(|| common::plugins::missing(CDYLIB, common::plugins::BUILD_PINNED));
    let dir = common::plugins::scratch("traces-both-doors");
    std::fs::create_dir_all(dir.join("plugins")).unwrap();
    let tarball = common::plugins::pack_stated("export", DROPPED, &lib, "acme");
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
    write_configs(&dir, data_port, admin_port, collector_port, true);
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

    // Model requests whose upstream refuses: the request path's spans open and close regardless.
    let body =
        r#"{"model":"test-model","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
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
            Some(_) => served += 1,
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }

    // Delivery is off the request path, batched: wait until the spans settle.
    let spans_at = |path| common::otlp::spans(&common::otlp::requests(&seen, Some(path))).len();
    let deadline = Instant::now() + Duration::from_secs(30);
    while spans_at(LINKED_PATH) < 3 || spans_at(DROPPED_PATH) < 3 {
        assert!(
            Instant::now() < deadline,
            "the collectors did not receive the spans in 30 s: linked {}, dropped {}\n{}",
            spans_at(LINKED_PATH),
            spans_at(DROPPED_PATH),
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
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
