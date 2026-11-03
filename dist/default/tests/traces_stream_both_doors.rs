// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
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

const DROPPED: &str = "k9e-dropped";

const WIRE: &str = "tcp";

const LINKED_PATH: &str = "/linked/v1/traces";
const DROPPED_PATH: &str = "/dropped/v1/traces";

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, collector: u16, name_dropped: bool) {
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
plugins: {plugins}
export:
  linked: {{ module: otlp, settings: {{ url: "http://127.0.0.1:{collector}{LINKED_PATH}" }} }}
{dropped}providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
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
    let lib = common::plugins::cdylib(CDYLIB)
        .unwrap_or_else(|| common::plugins::missing(CDYLIB, common::plugins::BUILD_PINNED));
    let dir = common::plugins::scratch("traces-both-doors");
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
    let busbar = || {
        let mut c = Command::new(common::boot::exe());
        c.env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "info");
        c
    };

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

    let log_path = dir.join("out.log");
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();

    let body =
        r#"{"model":"test-model","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;

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
