// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SCRAPE ROLE IS FIRST-PARTY ONLY (#65, zero trust; K9d): busbar's own `/metrics` is rendered
//! only by a sink the host GRANTS first-party — linked into the binary, or dropped in signed by the
//! release key. A third-party sink may subscribe to the `metrics` stream like any other sink, but
//! it never serves `/metrics`: the host does not put bytes a third party rendered under its own
//! well-known exposition.
//!
//! Driven through the real binary. The third party here is the scrape sink's own `cdylib` (found
//! by what it carries — exactly the `metrics` stream — not by name), packed UNSIGNED under a
//! third-party publisher and dropped into `plugins/`:
//!
//! 1. configured ALONE, subscribed to `metrics`: `/metrics` is not served — exactly 1.5.5, where no
//!    `module: prometheus` instance meant no `/metrics` (RED before the first-party rule: it served
//!    `200` with the third party's rendering);
//! 2. beside the first-party `module: prometheus` instance: `/metrics` is served (`200`, the
//!    exposition's content type) and the third-party instance still boots — the control that keeps
//!    arm 1's `404` from being a boot that failed for some other reason.

#![cfg(unix)]
// The config below serves `providers:`/`models:`, so the build must link the plane that takes body
// ingress — the linked table's answer, never a feature name.
#![cfg(linked_axis_body_ingress)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The name the third-party tarball's manifest states.
const THIRD_PARTY: &str = "tp-metrics";

/// The in-tree `cdylib` that loads as an export sink carrying exactly the `metrics` stream, in the
/// target directory this test binary lives in (uplifted or under `deps`, newest first). Under CI a
/// missing artifact is a failure, never a skip.
fn metrics_sink_cdylib() -> Option<Vec<u8>> {
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
            .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
            .collect();
    candidates.sort_by_key(|(mtime, _)| std::cmp::Reverse(*mtime));
    let metrics = [busbar_plugin_loader::ExportStream::Metrics];
    let found = candidates.into_iter().find_map(|(_, p)| {
        let bytes = std::fs::read(&p).ok()?;
        let sink =
            busbar_plugin_loader::load_export_from_bytes(&bytes, "{}", "probe", "export").ok()?;
        (sink.streams() == metrics).then_some(bytes)
    });
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "no in-tree metrics-stream export cdylib is built under CI; refusing to skip #65's control"
    );
    found
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-scrape-first-party-{tag}-{}-{}",
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

/// `lib` packed UNSIGNED as a third-party `kind: export` tarball.
fn write_third_party(dir: &Path, lib: &[u8]) {
    let m = busbar_plugin_loader::sign::Manifest {
        name: THIRD_PARTY.into(),
        alias: THIRD_PARTY.into(),
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
    std::fs::write(dir.join("plugins").join("tp.tar.gz"), bytes).unwrap();
}

fn write_configs(dir: &Path, data_port: u16, first_party: bool) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let scrape = if first_party {
        "  metrics: { module: prometheus, settings: { buffer_seconds: 60 } }\n"
    } else {
        ""
    };
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
{scrape}  tp: {{ module: {THIRD_PARTY}, streams: [metrics], settings: {{ buffer_seconds: 60 }} }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            admin_port = free_port(),
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

/// `GET /metrics` over a fresh connection: `(status, head, body)`, or `None` before the listener
/// is up.
fn scrape(port: u16) -> Option<(u16, String, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let request = "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
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
    Some((status, head.to_ascii_lowercase(), body.to_string()))
}

/// Boot the binary over `dir` and return the first settled `/metrics` answer (anything but the
/// recorder's boot-window `503`), with the log.
fn settled_scrape(dir: &Path, data_port: u16) -> ((u16, String, String), String) {
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
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
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!(
                "busbar refused to boot (status {status:?}); log:\n{}",
                read_log()
            );
        }
        match scrape(data_port) {
            Some(answer) if answer.0 != 503 => return (answer, read_log()),
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "/metrics never settled; log:\n{}",
            read_log()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_third_party_metrics_sink_never_serves_metrics() {
    let Some(lib) = metrics_sink_cdylib() else {
        eprintln!("skip: no in-tree metrics-stream export cdylib is built (run under --workspace)");
        return;
    };

    // 1. The third party ALONE, subscribed to `metrics`: no `/metrics`, as 1.5.5 without a
    //    `module: prometheus` instance.
    let dir = fixture_dir("alone");
    write_third_party(&dir, &lib);
    let port = free_port();
    write_configs(&dir, port, false);
    let ((status, _, body), log) = settled_scrape(&dir, port);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        status, 404,
        "a third-party sink subscribed to `metrics` must not serve /metrics; body:\n{body}\nlog:\n{log}"
    );

    // 2. Beside the first-party instance: `/metrics` is served, by the host's scrape.
    let dir = fixture_dir("beside");
    write_third_party(&dir, &lib);
    let port = free_port();
    write_configs(&dir, port, true);
    let ((status, head, body), log) = settled_scrape(&dir, port);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        status, 200,
        "the first-party sink serves /metrics; log:\n{log}"
    );
    assert!(
        head.contains("content-type: text/plain; version=0.0.4"),
        "{head}"
    );
    assert!(body.contains("# TYPE "), "an exposition: {body}");
}
