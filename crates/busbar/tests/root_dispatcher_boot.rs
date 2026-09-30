// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BINARY BOOTS WITH THE ROOT'S ONE DISPATCHER INSTALLED: one dispatcher, built by the
//! composition root at boot, one plugin worker per data worker.
//!
//! Boots the REAL binary with `advanced.worker_threads: 3` and counts the dispatcher's threads in
//! `/proc/<pid>/task/*/comm` (a thread name is cut to 15 bytes, so every `busbar-dispatch-<i>` worker
//! and the `busbar-dispatch-watchdog` read `busbar-dispatch`): three workers and the watchdog. RED
//! when `run()` stops building the dispatcher at boot — none is built (0 threads), or a later
//! first use builds the one-worker fallback (2).
#![cfg(target_os = "linux")]
#![cfg(linked_axis_body_ingress)]

mod common;

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
    // The provider catalog row is test data (`fixtures/mock_provider.yaml`), not a literal here.
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
admin_require_mtls: false
advanced:
  worker_threads: {WORKERS}
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

/// Whether a listener accepts on `port`.
fn listening(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).is_ok()
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

/// Boot the binary with `env`, answer its dispatcher thread count and everything it printed.
fn boot(tag: &str, env: &[(&str, &str)]) -> (usize, String) {
    let dir = fixture_dir();
    let data_port = common::boot::free_port();
    let admin_port = common::boot::free_port();
    write_configs(&dir, data_port, admin_port);
    let log_path = dir.join(format!("{tag}.log"));
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut cmd = Command::new(common::boot::exe());
    cmd.env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env_remove("BUSBAR_WORKER_THREADS")
        .env_remove("TOKIO_WORKER_THREADS");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");
    let log_text = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let ready = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!("busbar exited at boot ({status:?}); log:\n{}", log_text());
        }
        listening(data_port) && listening(admin_port)
    });
    let threads = dispatcher_threads(child.id());
    let _ = child.kill();
    let _ = child.wait();
    assert!(ready, "busbar never listened; log:\n{}", log_text());
    let out = log_text();
    let _ = std::fs::remove_dir_all(&dir);
    (threads, out)
}

#[test]
fn the_binary_boots_with_the_root_dispatcher_installed() {
    let (threads, out) = boot("plain", &[]);
    assert_eq!(
        threads,
        WORKERS + 1,
        "the booted binary runs the root's dispatcher: {WORKERS} workers and the watchdog"
    );
    assert!(
        !out.contains("worker-thread"),
        "no worker-count warning: {out}"
    );
}

/// THE WORKER-COUNT WARNINGS KEEP THEIR BYTES AND THEIR PLACE, now that the count is resolved at the
/// top of `main()` for the dispatcher: an invalid `BUSBAR_WORKER_THREADS` is warned about with the
/// same line, before the boot's own lines, and the configured count still sizes the one dispatcher.
#[test]
fn the_worker_count_warnings_print_as_before_and_the_dispatcher_is_full_size() {
    let (threads, out) = boot("invalid-env", &[("BUSBAR_WORKER_THREADS", "0")]);
    assert_eq!(
        threads,
        WORKERS + 1,
        "the configured count sizes the dispatcher"
    );
    let line = out
        .lines()
        .find(|l| l.contains("BUSBAR_WORKER_THREADS=\"0\""))
        .unwrap_or_else(|| panic!("the invalid-count warning: {out}"));
    assert!(
        line.starts_with("[warn] BUSBAR-")
            && line.ends_with(
                ": BUSBAR_WORKER_THREADS=\"0\" is not a positive integer; ignoring it and using \
                 the default worker-thread count"
            ),
        "{line}"
    );
    let at = out.find(line).unwrap();
    assert!(
        out.find("busbar listening").is_none_or(|l| at < l),
        "the warning prints before the boot's own lines: {out}"
    );
    let (threads, out) = boot("deprecated-env", &[("BUSBAR_WORKER_THREADS", "2")]);
    assert_eq!(
        threads,
        2 + 1,
        "the deprecated knob still wins and sizes the dispatcher"
    );
    let deprecated =
        "[warn] BUSBAR_WORKER_THREADS is DEPRECATED; set `advanced.worker_threads` in \
                      config.yaml instead (it is honored for now).";
    assert!(out.lines().any(|l| l == deprecated), "{out}");
}
