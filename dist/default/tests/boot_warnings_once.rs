// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A boot prints each configuration warning exactly once, as 1.5.5 does: the effective
//! configuration is validated semantically once, on the one application construction path, so a
//! warning the validator raises (here the heterogeneous-pool notice) is not repeated by a second
//! pass over the same configuration.

#![cfg(all(unix, linked_section_pools))]

mod common;

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
