// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const ADMIN_TOKEN: &str = "root-listeners-admin-token";

const WORKERS: usize = 2;

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("root-listeners-{tag}-{}-{}", std::process::id(), {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{}-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
            line!(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, extra: &str) {
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
advanced:
  worker_threads: {WORKERS}
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain: []
  admin_auth:
    - admin-tokens
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
            .env("RUST_LOG", "debug")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn the server"),
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

fn status(port: u16, path: &str) -> Option<String> {
    status_as(port, path, "")
}

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

#[test]
fn the_data_door_and_the_admin_surface_are_the_connectors_and_answer_only_their_own_routes() {
    let dir = fixture_dir("routes");
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data, admin, "");
    let mut node = boot(&dir);
    let up = wait_for(Duration::from_secs(60), || {
        if let Some(s) = node.0.try_wait().expect("try_wait") {
            panic!("the server exited ({s:?}); log:\n{}", log(&dir));
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
            panic!("the server exited ({s:?}); log:\n{}", log(&dir));
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
