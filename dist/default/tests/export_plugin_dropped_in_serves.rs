// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ITEM 141's POSITIVE CONTROL, end to end: **a dropped-in export plugin serves.**
//!
//! Before the export axis, `export.<name>.module:` could name only the four built-ins — any other
//! name was refused at boot ("unknown exporter"), `open_export` had no caller and nothing ever
//! handed a loaded sink a batch. This drives the REAL binary with a REAL `kind: export` plugin — the
//! request-log FILE sink's `cdylib` (GetBusbar/busbar-export-file, at the root's pinned rev) — dropped into
//! `plugins.dir` as a third-party tarball under a name this test gives it, an `export:` instance
//! naming it, and the `prometheus` exporter beside it, then proves the whole path over the wire:
//!
//! 1. the boot ACCEPTS the instance (the module resolves through the export axis);
//! 2. a request's `logs` line is DELIVERED to the plugin over the ABI: the sink has the HOST append
//!    it to the destination its manifest declares, and the line is on disk — the line, and no span
//!    (the instance subscribes `logs` only);
//! 3. the host's `/metrics` exposition, read into the recorder snapshot, reaches the dropped-in
//!    sink's render through its memory-ABI door. A sink that serves no metrics renders no body;
//!    the byte-for-byte render is the prometheus sink's own, proven in its repo
//!    (`render_exposition` left the contract SDK for it, ABI-TRIM F10a).
//!
//! RED against the tree before the axis: step 1 fails, the process exits naming the unknown exporter.

#![cfg(unix)]
#![cfg(linked_section_pools)]
#![cfg(linked_axis_export_doors)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const PLUGIN: &str = "dropped-sink";

const CDYLIB: &str = "busbar_export_file_plugin";

fn export_cdylib() -> Vec<u8> {
    common::plugins::cdylib(CDYLIB)
        .unwrap_or_else(|| common::plugins::missing(CDYLIB, common::plugins::BUILD_PINNED))
}

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-export-dropped-in-{}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
}

fn write_tarball_declaring(dir: &Path, lib: &[u8], destinations: &[&str]) {
    let manifest = std::env::var_os("BUSBAR_TEST_EXPORT_FILE_MANIFEST")
        .expect("the actual file sink package manifest is provided");
    let mut m: busbar_plugin_loader::sign::Manifest = serde_json::from_slice(
        &std::fs::read(manifest).expect("read the actual file sink manifest"),
    )
    .expect("the file sink manifest parses");
    m.name = PLUGIN.into();
    m.alias = PLUGIN.into();
    m.former_names.clear();
    m.publisher = common::plugins::FIXTURE_PUBLISHER.into();
    // Republishing as a configured third party cannot claim the first-party diagnostic
    // catalogue. Keep the real Statement and every other package capability intact.
    m.declares.diagnostics.clear();
    m.declares.destinations = destinations.iter().map(|d| d.to_string()).collect();

    common::plugins::state(&mut m, lib);
    let bytes = common::plugins::signed(&common::plugins::key(0x5a), m, lib);
    std::fs::write(dir.join("plugins").join("dropped-sink.tar.gz"), bytes).unwrap();
}

fn write_configs_with(dir: &Path, data_port: u16, admin_port: u16, tail_settings: &str) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
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
  metrics: {{ module: prometheus, settings: {{ buffer_seconds: 60 }} }}
  tail: {{ module: {PLUGIN}, streams: [logs], settings: {tail_settings} }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            plugins = common::plugins::trusted_config_document(&dir.join("plugins"))
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

fn exchange(port: u16, request: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, body.to_string()))
}

fn scrape(port: u16) -> Option<(u16, String)> {
    exchange(
        port,
        "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
}

fn log_of(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
}

#[test]
fn a_dropped_in_export_plugin_serves() {
    let lib = export_cdylib();
    let dir = fixture_dir();
    write_tarball_declaring(&dir, &lib, &["path"]);
    let lines = dir.join("lines.jsonl");
    let (data_port, admin_port) = (free_port(), free_port());
    write_configs_with(
        &dir,
        data_port,
        admin_port,
        &format!("{{ path: '{}' }}", lines.display()),
    );

    let log = std::fs::File::create(dir.join("out.log")).unwrap();
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "warn")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!(
                "busbar refused to boot with an export: instance naming a dropped-in export \
                 plugin (status {status:?}); log:\n{}",
                log_of(&dir)
            );
        }
        if matches!(scrape(data_port), Some((200, _))) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "/metrics never answered 200; log:\n{}",
            log_of(&dir)
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let body =
        r#"{"model":"no-such-model","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    exchange(data_port, &request).expect("the request is answered");

    let read = || -> Vec<serde_json::Value> {
        std::fs::read_to_string(&lines)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).expect("a JSON line"))
            .collect()
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let logged = loop {
        let logged = read();
        if !logged.is_empty() {
            break logged;
        }
        assert!(
            Instant::now() < deadline,
            "the dropped-in export plugin never wrote the request's line; log:\n{}",
            log_of(&dir)
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        logged
            .iter()
            .any(|l| l["ingress_protocol"] == "anthropic" && l["outcome"] == "client_error"),
        "the request's own line: {logged:?}"
    );

    assert!(
        logged
            .iter()
            .all(|l| l.get("trace_id").is_none() && l.get("span_id").is_none()),
        "a sink not subscribed to `traces` was handed spans: {logged:?}"
    );

    let exposition = scrape(data_port).map(|(_, b)| b).unwrap_or_default();
    assert!(!exposition.is_empty(), "the host serves an exposition");
    let settings = format!("{{\"path\":\"{}\"}}", lines.display());
    let rendered = common::plugins::render_snapshot(&lib, PLUGIN, &settings, &exposition);
    assert!(
        rendered
            .as_ref()
            .is_err_and(|e| e.contains(busbar_contract::abi::sdk::export::NO_EXPOSITION)),
        "a sink serving no metrics renders no body: {rendered:?}"
    );

    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_reports_a_dropped_in_sinks_settings_errors_in_its_own_words() {
    let lib = export_cdylib();
    let dir = fixture_dir();
    write_tarball_declaring(&dir, &lib, &[]);
    let validate = |tail_settings: &str| {
        write_configs_with(&dir, free_port(), free_port(), tail_settings);
        Command::new(common::boot::exe())
            .arg("--validate")
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .output()
            .expect("run busbar --validate")
    };
    let refused = validate("{ path: 7 }");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("export.tail.settings: invalid type: integer `7`, expected a string"),
        "stderr:\n{stderr}"
    );
    let accepted = validate(&format!(
        "{{ path: '{}' }}",
        dir.join("tail.jsonl").display()
    ));
    assert!(
        accepted.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
