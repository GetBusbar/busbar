// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BINARY BOOTS WITH THE ROOT'S ONE DISPATCHER INSTALLED (`BUSBAR-1.6.0.md` THE DESIGN §11.2:
//! one dispatcher, built by the composition root at boot, one plugin worker per data worker).
//!
//! Boots the REAL binary with `advanced.worker_threads: 3` and counts the dispatcher's threads in
//! `/proc/<pid>/task/*/comm` (a thread name is cut to 15 bytes, so every `busbar-dispatch-<i>` worker
//! and the `busbar-dispatch-watchdog` read `busbar-dispatch`): three workers and the watchdog. RED
//! when `run()` stops building the dispatcher at boot — none is built (0 threads), or a later
//! first use builds the one-worker fallback (2).
#![cfg(target_os = "linux")]
#![cfg(linked_axis_body_ingress)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const WORKERS: usize = 3;

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-root-dispatcher-boot-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let key_hex = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("run --generate-signing-key");
    assert!(key_hex.status.success(), "generate-signing-key failed");
    std::fs::write(dir.join("signing.key"), &key_hex.stdout).unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
admin_require_mtls: false
advanced:
  worker_threads: {WORKERS}
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain:
    - keys
  signing_key: {{ file: "{key}" }}
  admin_auth: [admin-tokens]
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            key = dir.join("signing.key").display(),
        ),
    )
    .unwrap();
}

fn healthz_ok(port: u16) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    if s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf.starts_with("HTTP/1.1 200")
}

fn wait_for(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + budget;
    while Instant::now() < end {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// How many of `pid`'s threads carry the dispatcher's (15-byte) thread name.
fn dispatcher_threads(pid: u32) -> usize {
    let tasks = std::fs::read_dir(format!("/proc/{pid}/task")).expect("the process's threads");
    tasks
        .filter_map(Result::ok)
        .filter_map(|t| std::fs::read_to_string(t.path().join("comm")).ok())
        .filter(|name| name.trim_end() == "busbar-dispatch")
        .count()
}

#[test]
fn the_binary_boots_with_the_root_dispatcher_installed() {
    let dir = fixture_dir();
    let data_port = common::boot::free_port();
    let admin_port = common::boot::free_port();
    write_configs(&dir, data_port, admin_port);
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("BUSBAR_ADMIN_TOKEN", "root-dispatcher-boot-admin-token")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");
    let log_text = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let ready = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!("busbar exited at boot ({status:?}); log:\n{}", log_text());
        }
        healthz_ok(data_port) && healthz_ok(admin_port)
    });
    let threads = dispatcher_threads(child.id());
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        ready,
        "busbar never answered /healthz; log:\n{}",
        log_text()
    );
    assert_eq!(
        threads,
        WORKERS + 1,
        "the booted binary runs the root's dispatcher: {WORKERS} workers and the watchdog"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
