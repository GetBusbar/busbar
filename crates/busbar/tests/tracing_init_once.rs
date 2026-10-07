// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOOT INSTALLS ITS LOGGING ONCE — over the REAL binary, in the two boot shapes the shadow
//! oracle's `BOOT-130` (a refusal raised after logging is up) and `BOOT-W14` (a clean boot's
//! in-memory store warning) cells record.
//!
//! The host's logging is two process-wide installs: the `tracing` subscriber, and `tracing-log`'s
//! `LogTracer` as the `log` logger (`BUSBAR-1.6.0.md` THE DESIGN, "Plugin logging": "the plugin
//! image installs it, and so does the host"). In a build with plugins compiled in, the plugin image
//! IS the host image, so the door macro's call capture and the host share one `log` logger slot.
//! Loading the config runs the configured export instance's door (the oracle baseline configures
//! one, `metrics` over the compiled-in `prometheus` plugin) before the subscriber goes up, so the
//! capture's best-effort install took the slot first and the host's combined install then failed
//! and printed `tracing subscriber already initialized`. Each install now happens once, and a
//! failure of either is reported as itself.
//!
//! RED before the fix: both boots printed the line.
#![cfg(unix)]
#![cfg(linked_axis_node)]
#![cfg(feature = "export-prometheus")]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The line a second install printed.
const DOUBLE_INIT: &str = "tracing subscriber already initialized";
/// The line the `log` bridge prints when another logger already holds the slot.
const BRIDGE_TAKEN: &str = "the `log` bridge is not installed";

/// Kill the child when the test ends, however it ends.
struct Reap(Child);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-tracing-init-once-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A minimal config whose `store:` is `store`, with the oracle baseline's export instance, plus the
/// providers catalog beside it.
fn write_configs(dir: &Path, store: &str) {
    std::fs::write(
        dir.join("providers.yaml"),
        include_str!("fixtures/mock_provider.yaml"),
    )
    .unwrap();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
admin_require_mtls: false
store: {store}
auth:
  chain: []
export:
  metrics: {{ module: prometheus, settings: {{ buffer_seconds: 60 }} }}
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

/// Boot the binary over `dir`'s config with stdout and stderr in one file, and return that file's
/// text once `done` holds for it or the process has exited (at most 60 s), and the exit code if any.
fn boot_until(dir: &Path, done: impl Fn(&str) -> bool) -> (String, Option<i32>) {
    let log = dir.join("out.log");
    let out = std::fs::File::create(&log).unwrap();
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "info")
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .spawn()
            .expect("spawn busbar"),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let exited = child.0.try_wait().expect("try_wait");
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if let Some(status) = exited {
            return (text, status.code());
        }
        if done(&text) {
            return (text, None);
        }
        assert!(
            Instant::now() < deadline,
            "busbar neither exited nor reached the expected line in 60 s; output:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `BOOT-130`'s shape: a plugin store with the plugin subsystem off is refused AFTER logging is up.
/// The refusal is the only error; the logging went up once.
#[test]
fn a_refusal_after_logging_is_up_reports_no_second_init() {
    let dir = fixture_dir("boot-130");
    write_configs(&dir, "{module: durable}");
    let (out, code) = boot_until(&dir, |_| false);
    assert_eq!(code, Some(1), "the boot is refused; output:\n{out}");
    assert!(
        out.contains("store.module: 'durable' requires the plugin subsystem"),
        "the refusal is the store one; output:\n{out}"
    );
    assert!(
        out.contains("busbar starting"),
        "the subscriber is installed (the first INFO line is written); output:\n{out}"
    );
    assert!(
        !out.contains(DOUBLE_INIT) && !out.contains(BRIDGE_TAKEN),
        "the boot installed its logging twice; output:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `BOOT-W14`'s shape: a clean boot over the in-memory store warns that the store is ephemeral, a
/// line written after logging is up, and logs no second init on the way.
#[test]
fn a_clean_boot_reports_no_second_init() {
    const W14: &str = "store: in-memory (ephemeral)";
    let dir = fixture_dir("w14");
    write_configs(&dir, "{module: memory}");
    let (out, code) = boot_until(&dir, |text| text.contains(W14));
    assert_eq!(code, None, "the boot stays up; output:\n{out}");
    assert!(
        out.contains("busbar starting") && out.contains(W14),
        "the subscriber is installed and the W14 warning is written; output:\n{out}"
    );
    assert!(
        !out.contains(DOUBLE_INIT) && !out.contains(BRIDGE_TAKEN),
        "the boot installed its logging twice; output:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
