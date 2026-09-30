// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT'S LISTENERS ARE THE CONNECTOR'S (ARCHITECT ruling 2026-09-30): over the REAL
//! binary, the data door and the admin surface are bound from the one list of listeners through the
//! connector's listener — every data worker's socket and the admin socket — and each answers only
//! its own routes: the admin surface is never served on the data bind, nor the data door on the
//! admin bind. With a `tls:` block, the data door's socket still comes from the connector, and a
//! client that never speaks is dropped at the configured handshake bound
//! (`limits.tls_handshake_timeout_secs`), never answered.
#![cfg(unix)]
// The fixture boots a REAL busbar with an LLM provider (`GET /v1/models` answers from it), so the
// proof needs the body-ingress axis linked, as thread_per_core_serves.rs gates.
#![cfg(linked_axis_body_ingress)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The admin surface's token.
const ADMIN_TOKEN: &str = "root-listeners-admin-token";

/// The data workers the node runs: more than one, so every worker's socket is counted.
const WORKERS: usize = 2;

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-root-listeners-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, extra: &str) {
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
advanced:
  worker_threads: {WORKERS}
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain: []
  admin_auth: [admin-tokens]
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
{extra}"#
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

fn boot(dir: &Path) -> Reap {
    let log = std::fs::File::create(dir.join("out.log")).unwrap();
    Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            // DEBUG: the per-listener "listening through the connector" lines are DEBUG-level.
            .env("RUST_LOG", "debug")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    )
}

fn log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
}

fn wait_for(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

/// The status line of one plain `GET path` on `port`, if it answered.
fn status(port: u16, path: &str) -> Option<String> {
    status_as(port, path, "")
}

/// [`status`], carrying the admin token.
fn admin_status(port: u16, path: &str) -> Option<String> {
    status_as(
        port,
        path,
        &format!("Authorization: Bearer {ADMIN_TOKEN}\r\n"),
    )
}

fn status_as(port: u16, path: &str, header: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{header}Connection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    buf.lines().next().map(str::to_owned)
}

fn code(line: Option<String>) -> u16 {
    line.as_deref()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// RED: every data worker's socket and the admin socket are bound through the connector's
/// listener, and the two binds each serve only their own routes.
#[test]
fn the_data_door_and_the_admin_surface_are_the_connectors_and_answer_only_their_own_routes() {
    let dir = fixture_dir("routes");
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data, admin, "");
    let mut node = boot(&dir);
    let up = wait_for(Duration::from_secs(60), || {
        if let Some(s) = node.0.try_wait().expect("try_wait") {
            panic!("busbar exited ({s:?}); log:\n{}", log(&dir));
        }
        code(status(data, "/healthz")) == 200 && code(status(admin, "/v1/models")) != 0
    });
    assert!(up, "the node did not serve both binds; log:\n{}", log(&dir));

    let through = |line: &str| log(&dir).lines().filter(|l| l.contains(line)).count();
    assert!(
        wait_for(Duration::from_secs(10), || {
            through("data door listening through the connector") == WORKERS
        }),
        "each of the {WORKERS} data workers listens through the connector; log:\n{}",
        log(&dir)
    );
    assert_eq!(
        through("admin listening through the connector"),
        1,
        "the admin surface listens through the connector"
    );

    // With the admin credential: the data door answers its routes and not the admin surface's;
    // the admin surface answers its routes and not the data door's.
    for path in ["/api/v1/admin/openapi.json", "/api/v1/admin/usage"] {
        assert_eq!(
            code(admin_status(admin, path)),
            200,
            "{path} on the admin bind"
        );
        assert_eq!(
            code(admin_status(data, path)),
            404,
            "{path} is not on the data bind"
        );
    }
    assert_eq!(
        code(admin_status(data, "/v1/models")),
        200,
        "a data route on the data bind"
    );
    assert_eq!(
        code(admin_status(admin, "/v1/models")),
        404,
        "no data route on the admin bind"
    );
    drop(node);
    let _ = std::fs::remove_dir_all(&dir);
}

/// With a `tls:` block the data door's sockets are still the connector's, and a client that
/// connects and never speaks is dropped at the configured handshake bound, never answered.
#[test]
fn a_silent_client_on_the_tls_data_door_is_dropped_at_the_handshake_bound() {
    let dir = fixture_dir("tls");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    write_configs(
        &dir,
        data,
        admin,
        &format!(
            "tls:\n  cert: {{ file: '{}' }}\n  key: {{ file: '{}' }}\nlimits:\n  tls_handshake_timeout_secs: 1\n",
            dir.join("cert.pem").display(),
            dir.join("key.pem").display()
        ),
    );
    let mut node = boot(&dir);
    let up = wait_for(Duration::from_secs(60), || {
        if let Some(s) = node.0.try_wait().expect("try_wait") {
            panic!("busbar exited ({s:?}); log:\n{}", log(&dir));
        }
        log(&dir)
            .lines()
            .filter(|l| l.contains("data door listening through the connector"))
            .count()
            == WORKERS
            && TcpStream::connect(("127.0.0.1", data)).is_ok()
    });
    assert!(up, "the TLS data door did not come up; log:\n{}", log(&dir));

    let mut silent = TcpStream::connect(("127.0.0.1", data)).unwrap();
    silent
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let at = Instant::now();
    let mut buf = [0_u8; 16];
    let n = silent.read(&mut buf).unwrap_or(0);
    let took = at.elapsed();
    assert_eq!(n, 0, "no byte answered to a client that never spoke");
    assert!(
        took >= Duration::from_millis(800) && took < Duration::from_secs(5),
        "dropped at the 1 s handshake bound, took {took:?}"
    );
    drop(node);
    let _ = std::fs::remove_dir_all(&dir);
}
