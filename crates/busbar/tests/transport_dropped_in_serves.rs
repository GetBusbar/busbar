// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A DROPPED-IN TRANSPORT REGISTERS THROUGH THE SAME REGISTRATION AS A LINKED ONE, AND SERVES** —
//! end to end, over the REAL binary (#2 rule (1): same contract, same loading path; #3
//! OWNER-LOCKED: a transport is swappable, compiled in OR dropped in; #30: it rides the HOT lane).
//!
//! The in-tree transport `cdylib` is found by its KIND (the one library beside the binary the loader
//! admits as `kind: transport`) and packed into `plugins.dir` as a tarball. The root names no wire:
//! the key the dropped-in wire declares is read off its own decl, and whether this build links that
//! key is read off the build's linked transport table (`$OUT_DIR/linked_transports.rs`).
//!
//! * In a build that does NOT link the wire's key (that wire's linked-row switch off), the boot seal
//!   folds the dropped-in wire beside the linked ones, the data door rests on it, and a request
//!   served over it answers the bytes the LINKED build answers — both builds are held to one pinned
//!   exchange (`fixtures/transport_dropped_in_exchange.txt`, the `date` value masked). RED ARM, in
//!   the same test: the same build with the tarball removed refuses to boot — the layers above the
//!   wire compose over nothing — so the bytes could only have crossed the dropped-in wire.
//! * In a build that DOES link it (the default), the same tarball is refused at boot exactly as a
//!   second linked row with that key would be: two transport plugins declaring one key. And the
//!   linked build, with nothing dropped in, serves the pinned exchange.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// The one request both builds answer, and the exchange they answer it with.
const REQUEST: &str = "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
const EXCHANGE: &str = include_str!("fixtures/transport_dropped_in_exchange.txt");

/// The in-tree transport `cdylib` and the key it declares, found by KIND beside the binary. Under
/// CI a missing artifact is a hard failure, never a silent skip.
fn transport_cdylib() -> Option<(Vec<u8>, &'static str)> {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_busbar"));
    let profile = exe.parent()?;
    let found = [profile.to_path_buf(), profile.join("deps")]
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
        });
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "no in-tree kind: transport cdylib is built beside the binary under CI"
    );
    found
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-transport-dropped-in-{tag}-{}-{}",
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

/// The transport `cdylib` packed as an UNSIGNED `kind: transport` tarball (the config opts into
/// unsigned plugins, as the CLI fixtures do).
fn drop_in(dir: &Path, lib: &[u8]) {
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

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
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

fn busbar(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_busbar"));
    cmd.env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("RUST_LOG", "warn");
    cmd
}

/// Kill the child when the test ends, however it ends.
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Boot, and answer the one request once the data door is up: the raw exchange, `date` masked, and
/// whether the listener on the door is the KERNEL'S OWN (see [`kernel_socket`]), asked while the node
/// still serves.
fn serve_once(dir: &Path, data_port: u16) -> (String, bool) {
    let log = std::fs::File::create(dir.join("out.log")).unwrap();
    let mut child = Reap(
        busbar(dir)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!(
                "busbar exited ({status:?}) before serving; log:\n{}",
                std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
            );
        }
        if let Some(raw) = exchange(data_port) {
            return (masked(&raw), kernel_socket(data_port));
        }
        assert!(Instant::now() < deadline, "the data door never answered");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// WHO OWNS THE DOOR'S SOCKET. The kernel's data listeners bind with SO_REUSEPORT (one per data
/// worker on one address); a socket a dropped-in wire bound is its own plain bind. So a second
/// SO_REUSEPORT socket on the port binds beside the kernel's and is refused beside the wire's — the
/// witness that a request crossed the dropped-in wire, not a kernel socket that happened to answer.
fn kernel_socket(port: u16) -> bool {
    use socket2::{Domain, Socket, Type};
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    let Ok(probe) = Socket::new(Domain::IPV4, Type::STREAM, None) else {
        return false;
    };
    // Never listened on, so it takes no connection from the node before it is dropped.
    probe.set_reuse_address(true).is_ok()
        && probe.set_reuse_port(true).is_ok()
        && probe.bind(&addr.into()).is_ok()
}

/// Boot, expecting a refusal: the process's exit and what it wrote.
fn refused(dir: &Path) -> Output {
    busbar(dir).output().expect("run busbar")
}

fn exchange(port: u16) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream.write_all(REQUEST.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    (!raw.is_empty()).then_some(raw)
}

/// The exchange with the `date` header's value masked — the only byte that differs by clock.
fn masked(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .split("\r\n")
        .map(|line| match line.split_once(':') {
            Some((name, _)) if name.eq_ignore_ascii_case("date") => format!("{name}: <masked>"),
            _ => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// The pinned exchange, in the wire's own line endings.
fn pinned() -> String {
    EXCHANGE.trim_end_matches('\n').replace('\n', "\r\n")
}

#[test]
fn a_dropped_in_transport_registers_through_the_one_fold_and_serves() {
    let Some((lib, key)) = transport_cdylib() else {
        eprintln!("skip: no in-tree kind: transport cdylib is built (run under --workspace)");
        return;
    };
    let linked = LINKED_TRANSPORTS.iter().any(|w| w.key == key);
    let dir = fixture_dir("serve");
    let (data_port, admin_port) = (free_port(), free_port());
    write_configs(&dir, data_port, admin_port);

    if linked {
        // THE LINKED BUILD SERVES THE PINNED EXCHANGE over its own wire.
        let (served, kernel) = serve_once(&dir, data_port);
        assert_eq!(served, pinned(), "the linked build's exchange");
        assert!(
            kernel,
            "the linked build's data door is the kernel's own socket"
        );
        // RED: the same wire dropped in on a key this build links is refused at boot, as a second
        // linked row with that key is — two transport plugins declaring one key.
        drop_in(&dir, &lib);
        let out = refused(&dir);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
        assert!(
            stderr.contains(&format!("DuplicateKey {{ kind: Transport, key: {key:?} }}")),
            "stderr:\n{stderr}"
        );
    } else {
        // RED: with no wire dropped in, the layers composed over the unlinked key have nothing
        // under them, and the node refuses to boot — so whatever serves below crossed the plugin.
        let out = refused(&dir);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
        assert!(
            stderr.contains(&format!("composes over `{key}`")),
            "stderr:\n{stderr}"
        );
        // THE DROPPED-IN WIRE SERVES: the one request, over the wire in `plugins/`, answers the
        // exchange the linked build answers, byte for byte but the clock.
        drop_in(&dir, &lib);
        let (served, kernel) = serve_once(&dir, data_port);
        assert_eq!(
            served,
            pinned(),
            "the dropped-in build's exchange is the linked build's"
        );
        assert!(
            !kernel,
            "the request crossed the dropped-in wire's own socket, not a kernel listener"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
