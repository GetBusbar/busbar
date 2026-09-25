// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ITEM 141's POSITIVE CONTROL, end to end: **a dropped-in export plugin serves.**
//!
//! Before the export axis, `export.<name>.module:` could name only the four built-ins — any other
//! name was refused at boot ("unknown exporter"), `open_export` had no caller and nothing ever
//! handed a loaded sink a batch. This drives the REAL binary with an in-tree `kind: export` plugin
//! dropped into `plugins.dir` as a tarball, an `export:` instance naming it, and the built-in
//! `prometheus` exporter beside it, then proves the whole path over the wire:
//!
//! 1. the boot ACCEPTS the instance (the module resolves through the export axis);
//! 2. a request's `logs` line is DELIVERED to the plugin over the ABI (the in-tree export plugin
//!    counts every batch it is handed and reports the count on its observability envelope);
//! 3. what the plugin reported reaches the host's `/metrics` exposition, attributed to it by the
//!    host (`plugin="<name>"`) — the envelope folded down the one observability path.
//!
//! The composition root names no plugin (#2, the instance-noun rule): the plugin is found by its
//! KIND — the one in-tree plugin `cdylib` the loader will load as `kind: export` — and dropped in
//! under a name this test gives it.
//!
//! RED against the tree before the axis: step 1 fails, the process exits naming the unknown exporter.

#![cfg(unix)]
#![cfg(linked_axis_body_ingress)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The name the dropped-in export plugin's manifest states — what the `export:` instance's
/// `module:` names, and the provenance label the host attaches to what it reports.
const PLUGIN: &str = "dropped-sink";

/// The in-tree `kind: export` plugin, found by its KIND: of the SDK fixture `cdylib`s (`*_plugin`)
/// in the target directory this test binary lives in — uplifted or under `deps`, newest first — the
/// one the loader LOADS as an export sink (every other kind is refused at the kind check, before its
/// `open` runs). Under CI a missing artifact is a hard failure, never a silent skip — `cargo test
/// --workspace` builds every member `cdylib`.
fn export_cdylib() -> Option<Vec<u8>> {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_busbar"));
    let profile = exe.parent()?;
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> =
        [profile.to_path_buf(), profile.join("deps")]
            .iter()
            .flat_map(|dir| {
                busbar_plugin_loader::list_plugin_files(dir)
                    .into_iter()
                    .map(move |f| dir.join(f))
            })
            .filter(|p| {
                let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
                stem.ends_with("_plugin")
            })
            .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
            .collect();
    candidates.sort_by_key(|(mtime, _)| std::cmp::Reverse(*mtime));
    let found = candidates.into_iter().find_map(|(_, p)| {
        let bytes = std::fs::read(&p).ok()?;
        busbar_plugin_loader::load_export_from_bytes(&bytes, "{}", "probe", "export")
            .ok()
            .map(|_| bytes)
    });
    if found.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "no in-tree kind: export plugin cdylib is built under CI: `cargo test --workspace` \
             must build every member cdylib. Refusing to silently skip item 141's control."
        );
    }
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
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The export `cdylib` packed as an UNSIGNED `kind: export` tarball (the config below opts into
/// unsigned plugins, as the CLI fixtures do).
fn write_tarball(dir: &Path, lib: &[u8]) {
    let m = busbar_plugin_loader::sign::Manifest {
        name: PLUGIN.into(),
        alias: PLUGIN.into(),
        kind: "export".into(),
        version: "1.5.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("export")
            .iter()
            .max()
            .expect("export abi"),
        sha256: busbar_plugin_loader::sign::sha256_hex(lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    };
    let bytes = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();
    std::fs::write(dir.join("plugins").join("dropped-sink.tar.gz"), bytes).unwrap();
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    write_configs_with(dir, data_port, admin_port, "{}");
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
        eprintln!("skip: no in-tree export plugin cdylib is built (run under --workspace)");
        return;
    };
    let dir = fixture_dir();
    write_tarball(&dir, &lib);
    let (data_port, admin_port) = (free_port(), free_port());
    write_configs(&dir, data_port, admin_port);

    let log = std::fs::File::create(dir.join("out.log")).unwrap();
    let mut child = Reap(
        Command::new(env!("CARGO_BIN_EXE_busbar"))
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

    // 3. THE PLUGIN WAS HANDED THE LINE, and what it reported (one delivery) reached the host's
    // exposition, attributed to it by the host. Delivery is off the request path, so poll briefly.
    let expected = format!("{{plugin=\"{PLUGIN}\"}} 1");
    let deadline = Instant::now() + Duration::from_secs(10);
    let exposition = loop {
        let exposition = scrape(data_port).map(|(_, b)| b).unwrap_or_default();
        if exposition.contains(&expected) {
            break exposition;
        }
        assert!(
            Instant::now() < deadline,
            "the dropped-in export plugin never reported its delivery on /metrics (wanted \
             `{expected}`); last exposition:\n{exposition}\nlog:\n{}",
            log_of(&dir)
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    // 4. THE RECORDER SNAPSHOT (K9a S6): the host's real exposition, read into the snapshot and
    // handed to the dropped-in sink, renders back byte for byte — the render a sink serving
    // `/metrics` would hand the host.
    let families = busbar_plugin_loader::scrape::snapshot(&exposition).expect("the snapshot reads");
    let sink = busbar_plugin_loader::load_export_from_bytes(&lib, "{}", PLUGIN, "export")
        .expect("the sink loads");
    let (content_type, rendered) = sink.scrape(families).expect("the sink renders");
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
        eprintln!("skip: no in-tree export plugin cdylib is built (run under --workspace)");
        return;
    };
    let dir = fixture_dir();
    write_tarball(&dir, &lib);
    let validate = |tail_settings: &str| {
        write_configs_with(&dir, free_port(), free_port(), tail_settings);
        Command::new(env!("CARGO_BIN_EXE_busbar"))
            .arg("--validate")
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .output()
            .expect("run busbar --validate")
    };
    let refused = validate("{ series: 7 }");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr
            .contains("export.tail.settings.series: must be a string naming the delivery counter"),
        "stderr:\n{stderr}"
    );
    let accepted = validate("{ series: tail_deliveries_total }");
    assert!(
        accepted.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
