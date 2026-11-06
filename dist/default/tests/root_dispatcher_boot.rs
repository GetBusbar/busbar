// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(target_os = "linux")]
#![cfg(linked_section_pools)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const WORKERS: usize = 3;

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-root-dispatcher-boot-{}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, workers: Option<usize>) {
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
advanced:
  worker_threads: {worker_count}
auth:
  chain: []
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            worker_count = workers.map_or_else(|| "null".to_string(), |n| n.to_string())
        ),
    )
    .unwrap();
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

fn dispatcher_threads(pid: u32) -> usize {
    let tasks = std::fs::read_dir(format!("/proc/{pid}/task")).expect("the process's threads");
    tasks
        .filter_map(Result::ok)
        .filter_map(|t| std::fs::read_to_string(t.path().join("comm")).ok())
        .filter(|name| name.trim_end() == "busbar-dispatch")
        .count()
}

fn boot(tag: &str, env: &[(&str, &str)], workers: Option<usize>) -> (usize, String) {
    let dir = fixture_dir();
    let data_port = common::boot::free_port();
    let admin_port = common::boot::free_port();
    write_configs(&dir, data_port, admin_port, workers);
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
    let mut child = common::boot::Reap(
        cmd.stdout(log)
            .stderr(log_err)
            .spawn()
            .expect("spawn busbar"),
    );
    let log_text = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let ready = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!("busbar exited at boot ({status:?}); log:\n{}", log_text());
        }
        log_text().contains("busbar listening")
    });
    let threads = dispatcher_threads(child.id());
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        ready,
        "busbar never logged its listener; log:\n{}",
        log_text()
    );
    let out = log_text();
    let _ = std::fs::remove_dir_all(&dir);
    (threads, out)
}

#[test]
fn the_binary_boots_with_the_root_dispatcher_installed() {
    let (threads, out) = boot("plain", &[], Some(WORKERS));
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

#[test]
fn the_worker_count_warnings_print_as_before_and_the_dispatcher_is_full_size() {
    let (threads, out) = boot("invalid-env", &[("TOKIO_WORKER_THREADS", "0")], None);
    assert_eq!(
        threads,
        std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(128)
            + 1,
        "invalid Tokio fallback uses the current capped available-worker count and watchdog"
    );
    let line = out
        .lines()
        .find(|l| l.contains("TOKIO_WORKER_THREADS=\"0\""))
        .unwrap_or_else(|| panic!("the invalid-count warning: {out}"));
    assert!(
        line.starts_with("[warn] BUSBAR-")
            && line.ends_with(
                ": TOKIO_WORKER_THREADS=\"0\" is not a positive integer; ignoring it and using \
                 the default worker-thread count"
            ),
        "{line}"
    );
    let at = out.find(line).unwrap();
    assert!(
        out.find("busbar listening").is_none_or(|l| at < l),
        "the warning prints before the boot's own lines: {out}"
    );
    let (threads, out) = boot("supported-env", &[("TOKIO_WORKER_THREADS", "2")], None);
    assert_eq!(
        threads,
        2 + 1,
        "the supported Tokio fallback sizes the dispatcher when config leaves it unset"
    );
    assert!(
        !out.contains("DEPRECATED"),
        "the Tokio fallback is supported: {out}"
    );
}

#[test]
fn retired_worker_environment_never_overrides_the_configured_dispatcher() {
    for (tag, value) in [("retired-invalid", "0"), ("retired-positive", "2")] {
        let (threads, out) = boot(tag, &[("BUSBAR_WORKER_THREADS", value)], Some(WORKERS));
        assert_eq!(
            threads,
            WORKERS + 1,
            "retired environment cannot override configured workers"
        );
        assert!(
            !out.contains("BUSBAR_WORKER_THREADS"),
            "retired runtime input is ignored, not deprecated: {out}"
        );
    }
}
