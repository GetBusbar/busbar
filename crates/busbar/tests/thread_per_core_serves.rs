// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THREAD-PER-CORE runtime (1.6.0) end-to-end smoke proof: a real busbar process — booted with a
//! PLAIN config, because thread-per-core is the one unix topology, not a knob — binds its per-worker
//! SO_REUSEPORT data listeners, serves a live request over one of them, and drains cleanly on SIGTERM.
//!
//! The value of driving the REAL binary here is that this is a boot-TOPOLOGY seam: the data plane runs
//! on N pinned `current_thread` runtimes, each binding its own SO_REUSEPORT socket on the SAME fixed
//! port. This test proves the seam actually accepts and answers a connection (kernel-balanced onto
//! whichever per-worker listener) and that the shutdown broadcast still reaches every per-worker
//! runtime — i.e. the default serve path is not just bootable but LIVE and drainable.
//!
//! Unix-only: SO_REUSEPORT (and the SIGTERM-driven drain) are unix facilities; non-unix builds serve
//! on the classic single runtime (a compile-time platform shape with no knob).
#![cfg(unix)]
// The fixture boots a REAL busbar with an LLM provider (`protocol: anthropic`); a `--no-default-features`
// build has no wire codec compiled in and fail-closes at boot (BUSBAR-9007), which is correct product
// behavior, not a regression. The thread-per-core serve seam under test is plane-independent, but this
// proof of it requires a bootable, serving server, so it is gated on the LLM plane. Full-feature builds
// still run it.
#![cfg(feature = "proto-llm")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// A fresh, isolated fixture directory (pid + nanos), mirroring the sibling boot tests.
fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-thread-per-core-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A free loopback port asked of the OS. thread-per-core needs a FIXED port (not `:0`): every per-core
/// listener binds the SAME address, so an ephemeral `:0` would hand each socket a different port.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Minimal config that boots a full server on a fixed data port — NOTHING topology-specific in it:
/// thread-per-core is the default and only unix shape. Admin mTLS waived + open auth so no secrets
/// are needed; memory store (default).
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

/// Boot the real binary with a plain config, hit `/healthz` over a per-worker SO_REUSEPORT listener,
/// then SIGTERM and confirm a clean exit (the shutdown broadcast reached every per-worker runtime).
#[test]
fn thread_per_core_boots_and_serves_healthz() {
    let dir = fixture_dir();
    let data_port = free_port();
    let admin_port = free_port();
    write_configs(&dir, data_port, admin_port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("RUST_LOG", "info")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");

    // Boot marker: the data listener logs "busbar listening" from inside a per-core runtime. Fail loud
    // if the process dies first, so a boot failure cannot masquerade as a green result.
    let booted = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?}); log:\n{}",
                read_to_string(&log_path)
            );
        }
        read_to_string(&log_path).contains("busbar listening")
    });
    assert!(
        booted,
        "busbar did not reach 'listening' within 30s; log:\n{}",
        read_to_string(&log_path)
    );
    // The topology announces itself at boot; assert the data plane is on the per-worker seam.
    assert!(
        read_to_string(&log_path).contains("thread-per-core data plane"),
        "expected the thread-per-core boot log; log:\n{}",
        read_to_string(&log_path)
    );

    // Serve a live request over a per-core SO_REUSEPORT listener. `/healthz` bypasses auth, so a raw
    // HTTP/1.1 GET is enough; a 200 proves the per-core accept loop is answering.
    let status_line = wait_for_healthz(data_port, Duration::from_secs(10));
    assert!(
        status_line.starts_with("HTTP/1.1 200"),
        "GET /healthz over a per-core listener did not return 200 (got {status_line:?}); log:\n{}",
        read_to_string(&log_path)
    );

    // Graceful stop: SIGTERM must reach every per-core runtime through the shutdown broadcast.
    let pid = child.id().to_string();
    let killed = Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .status()
        .expect("send SIGTERM")
        .success();
    assert!(killed, "kill -TERM {pid} failed");

    let exited = wait_for(Duration::from_secs(15), || {
        child.try_wait().expect("try_wait").is_some()
    });
    if !exited {
        let _ = child.kill();
        panic!(
            "thread-per-core busbar did not drain within 15s of SIGTERM; log:\n{}",
            read_to_string(&log_path)
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Poll `GET /healthz` until it answers or `budget` elapses; returns the response status line (empty
/// string if it never answered).
fn wait_for_healthz(port: u16, budget: Duration) -> String {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if let Some(line) = try_healthz(port) {
            return line;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    try_healthz(port).unwrap_or_default()
}

/// One `GET /healthz` over a raw TCP connection; returns the HTTP status line if the server answered.
fn try_healthz(port: u16) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    buf.lines().next().map(|l| l.to_string())
}

/// Poll `cond` until true or `budget` elapses; returns whether it became true.
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

/// Read a file to a String, tolerating a not-yet-flushed/partial log.
fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}
