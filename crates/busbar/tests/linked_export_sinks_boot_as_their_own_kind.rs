// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **EVERY LINKED EXPORT SINK LOADS AS ITS OWN KIND, IN THE SHIPPED BINARY.** Driven through the real
//! binary, with every first-party export sink this build links configured at once, and the tcp wire
//! under the data door (linked where the build links it, dropped in where it does not).
//!
//! The regression this guards: a binary that links several `["cdylib", "rlib"]` plugins used to carry
//! one strong `#[no_mangle] busbar_plugin_kind` per plugin crate. Where the linker kept a single
//! definition (a non-LTO link warns and picks one), a linked entry that answered its kind through that
//! global symbol answered the OTHER plugin's kind, and the boot refused a metrics export with
//! "plugin 'busbar-export-prometheus' exports kind 'transport' but is being loaded as 'export'".
//! The frozen symbols are now defined once, in the plugin SDK, and a binary's linked rows answer
//! through their own entries (`BUSBAR_COLD_ENTRY`). The link-level half of that is proven in
//! `crates/plugin-sdk/tests/one_link_many_plugins.rs` (two plugins in one image compile, their
//! global door answers as no plugin, each linked entry answers as itself). This test holds the
//! shipped binary to the outcome: it boots, every sink loads as `export`, and the scrape sink renders
//! `/metrics`.
//!
//! Which sinks the binary links is the binary's own answer: a module on no export axis is refused
//! by `--validate` as an unknown exporter. No feature name is spelled.

#![cfg(unix)]
// The config serves `providers:`/`models:`, so the build must link the plane that takes body
// ingress: the linked table's answer, never a feature name.
#![cfg(linked_axis_body_ingress)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// Every first-party export module and the instance line that configures it. `{dir}` is the fixture
/// directory (the file sink's path).
const SINKS: &[(&str, &str)] = &[
    (
        "prometheus",
        "  metrics: { module: prometheus, settings: { buffer_seconds: 60 } }\n",
    ),
    (
        "request-log-webhook",
        "  hook: { module: request-log-webhook, settings: { url: \"https://siem.example/in\" } }\n",
    ),
    (
        "request-log-file",
        "  file: { module: request-log-file, settings: { path: '{dir}/requests.jsonl' } }\n",
    ),
];

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-export-kinds-{tag}-{}-{}",
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

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, export: &str) {
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
{export}providers:
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

fn busbar(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_busbar"));
    cmd.env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("RUST_LOG", "warn");
    cmd
}

/// The export modules this binary links: each first-party module configured alone, asked of
/// `--validate`. A module on no export axis is refused as an unknown exporter.
fn linked_sinks() -> Vec<&'static str> {
    SINKS
        .iter()
        .filter(|(module, line)| {
            let dir = fixture_dir("probe");
            let line = line.replace("{dir}", &dir.display().to_string());
            write_configs(&dir, free_port(), free_port(), &line);
            let out = busbar(&dir).arg("--validate").output().expect("run busbar");
            let _ = std::fs::remove_dir_all(&dir);
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            !text.contains(&format!("unknown exporter '{module}'"))
        })
        .map(|(module, _)| *module)
        .collect()
}

/// The in-tree transport `cdylib` and the key it declares, found by KIND beside the binary.
fn transport_cdylib() -> Option<(Vec<u8>, &'static str)> {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_busbar"));
    let profile = exe.parent()?;
    [profile.to_path_buf(), profile.join("deps")]
        .iter()
        .flat_map(|dir| {
            busbar_plugin_loader::list_plugin_files(dir)
                .into_iter()
                .map(move |f| dir.join(f))
        })
        .find_map(|p| {
            let bytes = std::fs::read(&p).ok()?;
            let wire =
                busbar_plugin_loader::load_transport_from_bytes(&bytes, "probe", "transport")
                    .ok()?;
            Some((bytes, wire.key()))
        })
}

/// The transport `cdylib` packed as an UNSIGNED `kind: transport` tarball.
fn drop_in_wire(dir: &Path, lib: &[u8]) {
    let m = busbar_plugin_loader::sign::Manifest {
        name: "dropped-wire".into(),
        alias: "dropped-wire".into(),
        kind: "transport".into(),
        version: "1.6.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("transport")
            .iter()
            .max()
            .expect("a transport abi"),
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
    std::fs::write(dir.join("plugins").join("dropped-wire.tar.gz"), bytes).unwrap();
}

/// Kill the child when the test ends, however it ends.
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `GET path` over a fresh connection: `(status, head, body)`, or `None` before the listener is up.
fn get(port: u16, path: &str) -> Option<(u16, String, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
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

#[test]
fn every_linked_export_sink_loads_as_its_own_kind_in_the_shipped_binary() {
    let sinks = linked_sinks();
    if sinks.is_empty() {
        // A build that links no export sink has no row to load as the wrong kind.
        return;
    }
    let dir = fixture_dir("boot");
    let (data_port, admin_port) = (free_port(), free_port());
    let export: String = SINKS
        .iter()
        .filter(|(module, _)| sinks.contains(module))
        .map(|(_, line)| line.replace("{dir}", &dir.display().to_string()))
        .collect();
    write_configs(&dir, data_port, admin_port, &export);

    // THE WIRE UNDER THE DOOR. A build that does not link the tcp row boots only with it dropped
    // in; one that links it would refuse the tarball as a second row on the same key.
    if !LINKED_TRANSPORTS.iter().any(|w| w.key == "tcp") {
        let Some((lib, _)) = transport_cdylib().filter(|(_, key)| *key == "tcp") else {
            assert!(
                std::env::var_os("CI").is_none(),
                "no in-tree tcp transport cdylib is built beside the binary under CI"
            );
            return;
        };
        drop_in_wire(&dir, &lib);
    }

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Reap(
        busbar(&dir)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();

    // THE NODE BOOTS: the data door answers. A sink loaded as the wrong kind refuses the boot, so
    // an exit here is the regression, and its log names the kind it was loaded as.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!(
                "busbar exited ({status:?}) with {sinks:?} configured; log:\n{}",
                read_log()
            );
        }
        if get(data_port, "/v1/models").is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the data door never answered; log:\n{}",
            read_log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // THE SCRAPE SINK LOADED AS AN EXPORT AND RENDERS: `/metrics` settles to 200 (past the
    // recorder's boot-window 503) with the exposition's content type.
    if sinks.contains(&"prometheus") {
        let deadline = Instant::now() + Duration::from_secs(30);
        let (status, head, _) = loop {
            match get(data_port, "/metrics") {
                Some((503, ..)) | None => {}
                Some(settled) => break settled,
            }
            assert!(
                Instant::now() < deadline,
                "/metrics never settled; log:\n{}",
                read_log()
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        assert_eq!(
            status,
            200,
            "the scrape sink serves /metrics; log:\n{}",
            read_log()
        );
        assert!(
            head.contains("content-type: text/plain"),
            "the exposition's content type: {head}"
        );
    }

    let log_text = read_log();
    assert!(
        !log_text.contains("exports kind"),
        "a linked sink answered another plugin's kind:\n{log_text}"
    );
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
