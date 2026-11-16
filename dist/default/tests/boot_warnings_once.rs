// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A boot prints each configuration warning exactly once, as 1.5.5 does: the effective
//! configuration is validated semantically once, on the one application construction path, so a
//! warning the validator raises (here the heterogeneous-pool notice) is not repeated by a second
//! pass over the same configuration. A fresh-instance boot that initializes its principal baseline
//! and continues serving judges the configuration once, before it writes that baseline, and the
//! application build consumes that one judgement: its warning prints once there too.

#![cfg(all(unix, linked_section_pools))]

mod common;

use busbar_contract::json;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const HETEROGENEOUS: &str = "heterogeneous pool: cross-protocol failover translates via the IR";

#[test]
fn a_heterogeneous_pool_warning_prints_once_per_boot() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-boot-warnings-once-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let data_port = common::boot::free_port();
    let admin_port = common::boot::free_port();
    std::fs::write(
        dir.join("providers.yaml"),
        "first:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n\
         second:\n  protocol: openai\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
admin_require_mtls: false
advanced:
  allow_destinations: ["127.0.0.1"]
store: {{module: memory}}
auth:
  chain: []
providers:
  first:
    api_key: {{ env: BOOT_WARNINGS_ONCE_KEY }}
  second:
    api_key: {{ env: BOOT_WARNINGS_ONCE_KEY }}
models:
  m-first:
    provider: first
  m-second:
    provider: second
pools:
  mixed:
    members:
      - model: m-first
      - model: m-second
"#
        ),
    )
    .unwrap();

    let stderr_path = dir.join("stderr.log");
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("BOOT_WARNINGS_ONCE_KEY", "x")
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .spawn()
        .expect("spawn busbar");
    let read = || std::fs::read_to_string(&stderr_path).unwrap_or_default();

    let deadline = Instant::now() + Duration::from_secs(30);
    while !common::boot::log_shows_data_and_admin_listening(&read()) {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?});\nstderr:\n{}",
                read()
            );
        }
        assert!(
            Instant::now() < deadline,
            "busbar must reach listening within 30s;\nstderr:\n{}",
            read()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();

    let stderr = read();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        stderr.matches(HETEROGENEOUS).count(),
        1,
        "the heterogeneous-pool warning prints exactly once per boot, as in 1.5.5;\nstderr:\n{stderr}"
    );
}

#[test]
fn a_fresh_instance_transition_that_serves_prints_the_warning_once() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-boot-warnings-once-transition-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let data_port = common::boot::free_port();
    let admin_port = common::boot::free_port();
    std::fs::write(
        dir.join("providers.yaml"),
        "first:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n\
         second:\n  protocol: openai\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
admin_require_mtls: false
advanced:
  allow_destinations: ["127.0.0.1"]
store: {{module: memory}}
auth:
  chain: []
providers:
  first:
    api_key: {{ env: BOOT_WARNINGS_ONCE_KEY }}
  second:
    api_key: {{ env: BOOT_WARNINGS_ONCE_KEY }}
models:
  m-first:
    provider: first
  m-second:
    provider: second
pools:
  mixed:
    members:
      - model: m-first
      - model: m-second
"#
        ),
    )
    .unwrap();
    let product = |args: &[&str]| {
        let mut command = Command::new(common::boot::exe());
        command
            .args(args)
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("BOOT_WARNINGS_ONCE_KEY", "x")
            .env("RUST_LOG", "info")
            .stdin(Stdio::null());
        command
    };

    // The real inventory binds the fresh receipt to this configuration's Store and requirements.
    let inspected = product(&[
        "--principal-transition",
        "-",
        "--transition-action",
        "inspect",
    ])
    .output()
    .expect("run the principal inspection");
    assert!(
        inspected.status.success(),
        "principal inspection failed: stdout={} stderr={}",
        String::from_utf8_lossy(&inspected.stdout),
        String::from_utf8_lossy(&inspected.stderr)
    );
    let inventory: json::Value =
        json::parse_value(&inspected.stdout).expect("the inspection report is JSON");
    assert_eq!(
        inventory["store_ephemeral"], true,
        "the memory Store is the ephemeral instance this action initializes"
    );
    let receipt = dir.join("fresh.json");
    std::fs::write(
        &receipt,
        json::to_vec(&json::json!({
            "version": 1,
            "store_config_sha256": inventory["store_config_sha256"],
            "requirements": inventory["requirements"],
            "witness": null,
            "ephemeral_instance": true,
            "exclusive_instance": true,
            "creation_evidence_sha256": "0".repeat(64),
            "newly_created_namespace": true,
            "sender_quiesced": true,
            "backend_quiesced": true,
            "actor": "boot-warnings-once",
            "reason": "a new ephemeral instance initializes and serves",
        }))
        .unwrap(),
    )
    .unwrap();

    let stderr_path = dir.join("stderr.log");
    let mut child = product(&[
        "--principal-transition",
        receipt.to_str().expect("the receipt path is UTF-8"),
        "--transition-action",
        "initialize-fresh-and-serve",
    ])
    .stdout(Stdio::null())
    .stderr(std::fs::File::create(&stderr_path).unwrap())
    .spawn()
    .expect("spawn busbar");
    let read = || std::fs::read_to_string(&stderr_path).unwrap_or_default();

    let deadline = Instant::now() + Duration::from_secs(30);
    while !common::boot::log_shows_data_and_admin_listening(&read()) {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?});\nstderr:\n{}",
                read()
            );
        }
        assert!(
            Instant::now() < deadline,
            "busbar must reach listening within 30s;\nstderr:\n{}",
            read()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();

    let stderr = read();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        stderr.matches(HETEROGENEOUS).count(),
        1,
        "a fresh-instance boot that serves judges its configuration once and prints the \
         heterogeneous-pool warning exactly once;\nstderr:\n{stderr}"
    );
}
