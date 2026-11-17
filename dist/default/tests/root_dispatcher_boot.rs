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
        .env_remove("BUSBAR_PROVIDERS")
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
fn retired_worker_environment_refuses_even_with_configured_workers() {
    for value in ["0", "2"] {
        let out = refused(&[("BUSBAR_WORKER_THREADS", value)]);
        assert!(out.contains("advanced.worker_threads"), "{out}");
    }
}

fn refused(env: &[(&str, &str)]) -> String {
    let dir = fixture_dir();
    write_configs(&dir, 0, 0, Some(WORKERS));
    let config = dir.join("config.yaml");
    let mut original = std::fs::read(&config).unwrap();
    // The old warning-only implementation must terminate too: its strict config reader
    // refuses this typo, while the wanted refusal happens before that reader or migrator.
    original.extend_from_slice(b"goovernance: {}\n");
    std::fs::write(&config, &original).unwrap();
    let mut command = Command::new(common::boot::exe());
    command.env("BUSBAR_CONFIG", &config).env("MOCK_KEY", "x");
    for name in ["BUSBAR_PROVIDERS", "BUSBAR_WORKER_THREADS", "BUSBAR_UPSTREAM_HTTP1_ONLY", "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE"] {
        command.env_remove(name);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command.output().expect("run refused boot");
    let out = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(1), "{out}");
    assert!(!out.contains("busbar listening"), "{out}");
    assert_eq!(std::fs::read(&config).unwrap(), original, "refusal must precede config migration");
    assert!(!dir.join("config.yaml.1.5.5").exists());
    std::fs::remove_dir_all(dir).unwrap();
    out
}

#[test]
fn every_retired_launch_variable_refuses_boot_and_never_echoes_values() {
    let retired = [
        ("BUSBAR_PROVIDERS", "providers_file"),
        ("BUSBAR_WORKER_THREADS", "advanced.worker_threads"),
        ("BUSBAR_UPSTREAM_HTTP1_ONLY", "advanced.upstream_http1_only"),
        ("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "advanced.upstream_h2_prior_knowledge"),
    ];
    let canary = "retired-launch-env-value-canary";
    let env: Vec<_> = retired.iter().map(|(name, _)| (*name, canary)).collect();
    let out = refused(&env);
    let banner = busbar_kernel::diagnostics::RETIRED_ENV_VAR_IGNORED.banner().to_string();
    let mut last = None;
    for (name, key) in retired {
        let notice = format!("{banner}: startup refused because {name} is set");
        let lines: Vec<_> = out.lines().filter(|line| line.contains(&notice) && line.contains(key)).collect();
        assert_eq!(lines.len(), 1, "one explained refusal per variable: {out}");
        let at = out.find(lines[0]).unwrap();
        assert!(last.is_none_or(|before| before < at), "table order: {out}");
        last = Some(at);
    }
    assert!(!out.contains(canary), "environment values must never be echoed: {out}");
}
