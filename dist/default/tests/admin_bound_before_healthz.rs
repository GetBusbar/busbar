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

const ADMIN_TOKEN: &str = "admin-bound-before-healthz-token";

const BOOTS: usize = 8;

fn fixture_dir(n: usize) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let d = std::env::temp_dir().join(format!(
        "admin-bound-before-healthz-{}-{n}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
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
"#
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
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn the server"),
    )
}

fn get(port: u16, path: &str, header: &str) -> Result<u16, String> {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{header}Connection: close\r\n\r\n")
                .as_bytes(),
        )
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = String::new();
    stream
        .read_to_string(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    buf.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("no status line in {buf:?}"))
}

#[test]
fn the_admin_api_answers_as_soon_as_healthz_does() {
    for n in 0..BOOTS {
        let dir = fixture_dir(n);
        let (data, admin) = (common::boot::free_port(), common::boot::free_port());
        write_configs(&dir, data, admin);
        let mut node = boot(&dir);
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(s) = node.0.try_wait().expect("try_wait") {
                panic!(
                    "the server exited ({s:?}); log:\n{}",
                    std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
                );
            }
            assert!(
                Instant::now() < deadline,
                "boot {n}: /healthz never answered"
            );
            if get(data, "/healthz", "") == Ok(200) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let answered = get(
            admin,
            "/api/v1/admin/openapi.json",
            &format!("Authorization: Bearer {ADMIN_TOKEN}\r\n"),
        );
        drop(node);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            answered,
            Ok(200),
            "boot {n}: the admin API, called as soon as /healthz answered"
        );
    }
}
