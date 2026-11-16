// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A fresh-instance boot that initializes its principal baseline and continues serving makes ONE
//! semantic pass over its effective configuration. The transition judges that configuration before
//! it writes the baseline, and the application build consumes that judgement instead of judging
//! the same configuration again.
//!
//! The warning a pass raises cannot tell one pass from two on this path: a pass made before the
//! log subscriber is installed logs nothing. So this test counts the passes themselves, through
//! the kernel's test-support probe, which writes one stderr line per pass from process start.

#![cfg(all(unix, linked_section_pools))]

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use busbar_contract::json;
use busbar_kernel::config_validate::SEMANTIC_PASS_PROBE;

#[test]
fn a_fresh_instance_transition_that_serves_judges_its_configuration_once() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-boot-semantic-pass-once-{}-{}",
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
        "first:\n  protocol: openai\n  base_url: \"http://127.0.0.1:9\"\n",
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
    api_key: {{ env: BOOT_SEMANTIC_PASS_ONCE_KEY }}
models:
  m-first:
    provider: first
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
            .env("BOOT_SEMANTIC_PASS_ONCE_KEY", "x")
            .env("BUSBAR_TEST_SEMANTIC_PASS_PROBE", "1")
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
    let inventory = json::parse_value(&inspected.stdout).expect("the inspection report is JSON");
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
            "actor": "boot-semantic-pass-once",
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
    let passes = stderr.matches(SEMANTIC_PASS_PROBE).count();
    assert_ne!(
        passes, 0,
        "the product binary under test carries no semantic-pass probe (built without the kernel's \
         test-support feature), so it cannot count passes;\nstderr:\n{stderr}"
    );
    assert_eq!(
        passes, 1,
        "a fresh-instance boot that serves makes exactly one semantic pass over its effective \
         configuration (the transition's judgement, consumed by the application build);\n\
         stderr:\n{stderr}"
    );
}
