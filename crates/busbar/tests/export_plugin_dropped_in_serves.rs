// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ITEM 141's POSITIVE CONTROL, end to end: **a dropped-in export plugin serves.**
//!
//! Before the export axis, `export.<name>.module:` could name only the four built-ins — any other
//! name was refused at boot ("unknown exporter"), `open_export` had no caller and nothing ever
//! handed a loaded sink a batch. This drives the REAL binary with a REAL `kind: export` plugin — the
//! request-log FILE sink's `cdylib` (GetBusbar/export-file, at the root's pinned rev) — dropped into
//! `plugins.dir` as a third-party tarball under a name this test gives it, an `export:` instance
//! naming it, and the `prometheus` exporter beside it, then proves the whole path over the wire:
//!
//! 1. the boot ACCEPTS the instance (the module resolves through the export axis);
//! 2. a request's `logs` line is DELIVERED to the plugin over the ABI: the sink has the HOST append
//!    it to the destination its manifest declares, and the line is on disk — the line, and no span
//!    (the instance subscribes `logs` only);
//! 3. the host's `/metrics` exposition, read into the recorder snapshot, renders back byte for byte
//!    through the dropped-in sink.
//!
//! RED against the tree before the axis: step 1 fails, the process exits naming the unknown exporter.

#![cfg(unix)]
#![cfg(linked_axis_body_ingress)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The name the dropped-in export plugin's manifest states — what the `export:` instance's
/// `module:` names, and the provenance label the host attaches to what it reports.
const PLUGIN: &str = "dropped-sink";

/// The dropped-in door's library: the export-file repo's cdylib crate, snake-cased — built into this
/// target dir by this crate's dev-edge on it (under `deps/`, hashed).
const CDYLIB: &str = "busbar_export_file_plugin";

/// The real sink's `cdylib`, newest wins: uplifted by its exact name, or under `deps/` with a metadata
/// hash. Under CI a missing artifact is a hard failure, never a silent skip.
fn export_cdylib() -> Option<Vec<u8>> {
    let found = common::plugins::cdylib(CDYLIB);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the {CDYLIB} cdylib is not built under CI; refusing to silently skip item 141's control"
    );
    found
}

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-export-dropped-in-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
}

/// The export `cdylib` packed as an UNSIGNED `kind: export` tarball (the config below opts into
/// unsigned plugins, as the CLI fixtures do), its manifest declaring `destinations` (K9a S4): the
/// settings keys the host opens a destination for.
fn write_tarball_declaring(dir: &Path, lib: &[u8], destinations: &[&str]) {
    let mut m = common::plugins::manifest("export", PLUGIN, "acme");
    m.declares.destinations = destinations.iter().map(|d| d.to_string()).collect();
    let bytes = common::plugins::seal(m, lib);
    std::fs::write(dir.join("plugins").join("dropped-sink.tar.gz"), bytes).unwrap();
}

/// [`write_configs`] with the plugin instance's `settings:` block spelled `tail_settings`.
fn write_configs_with(dir: &Path, data_port: u16, admin_port: u16, tail_settings: &str) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
admin_require_mtls: false
auth:
  chain: []
plugins:
  enabled: true
  dir: '{plugins}'
  trust:
    allow_unsigned: true
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
            plugins = dir.join("plugins").display()
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

/// One raw HTTP/1.1 exchange over a fresh connection: `(status, body)`, or `None` when no
/// connection could be made or read (the listener is not up yet).
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
    let Some(lib) = export_cdylib() else {
        eprintln!("skip: the {CDYLIB} cdylib is not built");
        return;
    };
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

    // 1. THE BOOT ACCEPTS THE INSTANCE, and the recorder is up: `/metrics` answers 200.
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

    // 2. A REQUEST — refused (no such model), which still finishes through the request-log terminal
    // and so produces the `logs` line the plugin subscribed to.
    let body =
        r#"{"model":"no-such-model","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    exchange(data_port, &request).expect("the request is answered");

    // THE PLUGIN WAS HANDED THE LINE: the host appended what the sink asked it to write to the
    // destination the manifest declares. Delivery is off the request path, so poll briefly.
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
    // A sink subscribed to `logs` only is handed its line and no span.
    assert!(
        logged
            .iter()
            .all(|l| l.get("trace_id").is_none() && l.get("span_id").is_none()),
        "a sink not subscribed to `traces` was handed spans: {logged:?}"
    );

    // 3. THE RECORDER SNAPSHOT (K9a S6): the host's real exposition, read into the snapshot and
    // handed to the dropped-in sink, renders back byte for byte — the render a sink serving
    // `/metrics` would hand the host.
    let exposition = scrape(data_port).map(|(_, b)| b).unwrap_or_default();
    let (content_type, rendered) = common::plugins::render_snapshot(&lib, PLUGIN, &exposition);
    assert_eq!(content_type, "text/plain; version=0.0.4");
    assert_eq!(
        rendered, exposition,
        "the sink's render of the snapshot is the host's exposition"
    );

    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}

/// K9a S2, end to end: `--validate` asks the dropped-in sink to VALIDATE its instance's settings,
/// and a refusal is reported among the configuration's errors in the sink's own words, failing the
/// run — the same moment and shape a built-in module's settings error has. Settings the sink
/// accepts validate clean. RED before the op: the refused settings validated clean (exit 0).
#[test]
fn validate_reports_a_dropped_in_sinks_settings_errors_in_its_own_words() {
    let Some(lib) = export_cdylib() else {
        eprintln!("skip: the {CDYLIB} cdylib is not built");
        return;
    };
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
