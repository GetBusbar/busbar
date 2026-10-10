// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE `traces` STREAM TO A COLLECTOR, AND WHICH DOORS MAY CARRY IT** — K9a S7 (BUSBAR-1.6.0
//! 18b(d)) and K9e-2 end to end through the shipped binary: the kernel's traces producer turns
//! closed request-path spans into `traces` records, and the OTLP sink (`module: otlp`,
//! GetBusbar/busbar-export-otlp at the root's pinned rev), LINKED on the export kind's memory ABI,
//! posts them through the host's one connector to a collector as OTLP/HTTP protobuf requests. Every
//! request body must be an OTLP `ExportTraceServiceRequest` by the OpenTelemetry project's own
//! generated types, re-encoding to the very same bytes.
//!
//! The sink's one need is in the `loopback-allowed` egress class, which the host grants to a
//! FIRST-PARTY plugin only (`BUSBAR-1.6.0.md` §5; ARCHITECT ruling EGRESS-GRANT 2026-10-03). So the
//! same sink's repo `cdylib`, dropped into `plugins/` by a third party (`acme`, unsigned under
//! `allow_unsigned`), is refused at the load: `--validate` lists it skipped in the grant's words,
//! and a configuration that names it does not boot. (This binary embeds the real release key, whose
//! private half no test holds, so a FIRST-PARTY dropped collector cannot be packed here; the loader's
//! `export_conformance_tests` carry the same span through both doors byte for byte, under a release
//! key of the test's own.)

#![cfg(unix)]
// The config serves `providers:`/`models:`, so the build must link the plane that takes body
// ingress: the linked table's answer, never a feature name.
#![cfg(linked_axis_body_ingress)]

mod common;

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

/// The grant's refusal, in the loader's words.
const REFUSED: &str =
    "plugin 'k9e-dropped' declares a `http` need in the `loopback-allowed` egress \
                       class, which the host grants to a first-party plugin only";

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
fn a_closed_span_reaches_an_otlp_collector_and_a_third_party_collector_is_refused() {
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
    let busbar = || {
        let mut c = Command::new(common::boot::exe());
        c.env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "info");
        c
    };

    // 1. The scan refuses the third party's collector: `--validate` lists it skipped, in the
    //    grant's words.
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data_port, admin_port, collector_port, false);
    let out = busbar().arg("--validate").output().expect("run --validate");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(&format!("skipped: {DROPPED} (otlp.tar.gz)")) && stdout.contains(REFUSED),
        "{stdout}"
    );

    // 2. A configuration that names it does not boot.
    write_configs(&dir, data_port, admin_port, collector_port, true);
    let out = busbar().output().expect("run busbar");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "a third-party collector booted:\n{text}"
    );
    assert!(
        text.contains(&format!(
            "export.dropped.module: unknown exporter '{DROPPED}'"
        )),
        "{text}"
    );

    // 3. The linked collector posts the request path's spans, the third party's beside it skipped.
    let log_path = dir.join("out.log");
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();

    // Model requests whose upstream refuses: the request path's spans open and close regardless.
    let body =
        r#"{"model":"test-model","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
    // The ports steps 1 and 2 wrote: `free_port` holds each from the moment it chose it, so no
    // other socket took one while those runs neither bound it.
    write_configs(&dir, data_port, admin_port, collector_port, false);
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
    while spans_at(LINKED_PATH) < 3 {
        assert!(
            Instant::now() < deadline,
            "the linked collector did not receive the spans in 30 s: {}\n{}",
            spans_at(LINKED_PATH),
            read_log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        spans_at(DROPPED_PATH),
        0,
        "nothing reaches the refused collector's path"
    );
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
