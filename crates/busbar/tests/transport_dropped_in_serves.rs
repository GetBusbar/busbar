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
//!   folds the dropped-in wire beside the linked ones and the node serves, answering the bytes the
//!   LINKED build answers — both builds are held to one pinned exchange
//!   (`fixtures/transport_dropped_in_exchange.txt`, the `date` value masked). RED ARM, in the same
//!   test: the same build with the tarball removed refuses to boot — the layers above the wire
//!   compose over nothing — so the node serves only because the dropped-in wire registered. And the
//!   door has the THREAD-PER-CORE shape (ruling K8c) from the one listener source: every
//!   data worker listens through the connector, one listener each on the one address.
//! * In a build that DOES link it (the default), the same tarball is refused at boot exactly as a
//!   second linked row with that key would be: two transport plugins declaring one key. And the
//!   linked build, with nothing dropped in, serves the pinned exchange.

#![cfg(unix)]
// THE PINNED EXCHANGE IS A PROVIDER-LANE ROUTE (`GET /v1/models`, answered from the configured
// provider/model pair), so this proof needs the row carrying the body-ingress axis — the plane that
// owns provider lanes — linked; read off the linked set, as thread_per_core_serves.rs gates. A
// single-plane build without that axis has no wire codec and refuses the provider at boot
// (BUSBAR-9007), which is correct product behaviour, not what this test measures. The dropped-in
// wire itself is proven in every build that links that axis, including the no-tcp feature row.
#![cfg(linked_axis_body_ingress)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// The data workers each build runs: more than one, so the per-core fan-out is observable.
const WORKERS: usize = 2;

/// The line the data door writes, per worker, once the connector's listener has bound that
/// worker's socket (the one listener source, ARCHITECT ruling 2026-09-30; DEBUG).
const THROUGH_THE_CONNECTOR: &str = "data door listening through the connector";

/// The one request both builds answer, and the exchange they answer it with.
const REQUEST: &str = "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
const EXCHANGE: &str = include_str!("fixtures/transport_dropped_in_exchange.txt");

/// The in-tree transport `cdylib` and the key it declares, found by KIND beside the binary
/// (`common::plugins::transport_cdylib_under`). No linked layer composes over another (ARCHITECT
/// ruling Q128 U7: no transport names another), so no key is needed under them and any transport
/// door beside the binary is the proof's subject: a linked key's tarball is refused as a second
/// plugin with that key, an unlinked key's registers through the one fold. Under CI a missing
/// artifact is a hard failure, never a silent skip.
fn transport_cdylib() -> Option<(Vec<u8>, &'static str)> {
    let under: Vec<&str> = LINKED_TRANSPORTS
        .iter()
        .flat_map(|w| w.composes_over.iter().copied())
        .collect();
    let found = common::plugins::transport_cdylib_under(&under);
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
    common::boot::free_port()
}

/// The transport `cdylib` packed as an UNSIGNED `kind: transport` tarball (the config opts into
/// unsigned plugins, as the CLI fixtures do).
fn drop_in(dir: &Path, lib: &[u8]) {
    drop_in_as(dir, lib, "dropped-wire");
}

/// The wire dropped in under the plugin name `name`.
fn drop_in_as(dir: &Path, lib: &[u8], name: &str) {
    let bytes = common::plugins::pack_stated("transport", name, lib, "acme");
    std::fs::write(dir.join("plugins").join(format!("{name}.tar.gz")), bytes).unwrap();
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
store: {{module: memory}}
advanced:
  allow_destinations: ["127.0.0.1"]
  worker_threads: {WORKERS}
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
    let mut cmd = Command::new(common::boot::exe());
    cmd.env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        // A bare level word (the node's stderr filter reads no directives): DEBUG, for the door's
        // per-worker line (`THROUGH_THE_CONNECTOR`).
        .env("RUST_LOG", "debug");
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

/// Boot, and answer the one request once the data door is up: the raw exchange, `date` masked,
/// whether the listener on the door is the KERNEL'S OWN (see [`kernel_socket`]), asked while the node
/// still serves, and how many data workers listen THROUGH THE CONNECTOR (read off the
/// node's log once `expect_through` of them have — or its deadline passes).
fn serve_once(dir: &Path, data_port: u16, expect_through: usize) -> (String, bool, usize) {
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
            let kernel = kernel_socket(data_port);
            let settle = Instant::now() + Duration::from_secs(10);
            let through = loop {
                let n = std::fs::read_to_string(dir.join("out.log"))
                    .unwrap_or_default()
                    .lines()
                    .filter(|l| l.contains(THROUGH_THE_CONNECTOR))
                    .count();
                if n >= expect_through || Instant::now() > settle {
                    break n;
                }
                std::thread::sleep(Duration::from_millis(50));
            };
            return (masked(&raw), kernel, through);
        }
        assert!(Instant::now() < deadline, "the data door never answered");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// THE KERNEL'S OWN DOOR. The kernel's data listeners bind with SO_REUSEPORT (one per data worker on
/// one address), so a second SO_REUSEPORT socket on the port binds beside them. (A dropped-in wire's
/// listeners are SO_REUSEPORT too since airlock minor 28 — the same per-core fan-out — so for that
/// door the witness is the wire's own per-worker line, [`THROUGH_THE_CONNECTOR`].)
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

/// Boot, expecting a refusal: the process's exit and what it wrote. A node that SERVES instead of
/// refusing never exits, so the wait is bounded: past the deadline the node is killed and the test
/// fails naming what it wrote, rather than hanging the run.
fn refused(dir: &Path) -> Output {
    let (out_path, err_path) = (dir.join("refused.out"), dir.join("refused.err"));
    let mut child = Reap(
        busbar(dir)
            .stdout(std::fs::File::create(&out_path).unwrap())
            .stderr(std::fs::File::create(&err_path).unwrap())
            .spawn()
            .expect("spawn busbar"),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "busbar did not refuse to boot within 60s (it is serving); stderr:\n{}",
            std::fs::read_to_string(&err_path).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    Output {
        status,
        stdout: std::fs::read(&out_path).unwrap_or_default(),
        stderr: std::fs::read(&err_path).unwrap_or_default(),
    }
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
        let (served, kernel, through) = serve_once(&dir, data_port, WORKERS);
        assert_eq!(served, pinned(), "the linked build's exchange");
        assert!(
            kernel,
            "the linked build's data door is the kernel's own socket"
        );
        assert_eq!(
            through, WORKERS,
            "each of the {WORKERS} data workers listens through the connector"
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
        // NO TRANSPORT NAMES ANOTHER (ARCHITECT ruling Q128 U7): nothing composes over the unlinked
        // key, so the build boots and serves without it — the carrier under the data door is the
        // connector's choice, not a registered row.
        let (served, _, _) = serve_once(&dir, data_port, WORKERS);
        assert_eq!(served, pinned(), "no layer waits on the unlinked key");
        // THE DROPPED-IN WIRE REGISTERS THROUGH THE ONE FOLD: the build over it serves the
        // exchange the linked build answers, byte for byte but the clock.
        drop_in(&dir, &lib);
        let (served, _, through) = serve_once(&dir, data_port, WORKERS);
        assert_eq!(
            served,
            pinned(),
            "the dropped-in build's exchange is the linked build's"
        );
        // Every data worker's listener is the connector's, whichever wire sits under the door —
        // the thread-per-core door, per core, from the one listener source.
        assert_eq!(
            through, WORKERS,
            "each of the {WORKERS} data workers listens through the connector"
        );
        // RED: and it DID register — a second copy of the same wire is a second transport plugin
        // declaring one key, refused at boot exactly as the linked build refuses the first.
        drop_in_as(&dir, &lib, "dropped-wire-again");
        let out = refused(&dir);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
        assert!(stderr.contains(&format!("{key:?}")), "stderr:\n{stderr}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
