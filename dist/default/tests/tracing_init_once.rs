// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]
#![cfg(feature = "export-prometheus")]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const DOUBLE_INIT: &str = "tracing subscriber already initialized";

const BRIDGE_TAKEN: &str = "the `log` bridge is not installed";

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

#[test]
fn a_refusal_after_logging_is_up_reports_no_second_init() {
    let dir = fixture_dir("boot-130");
    // The Store anchor opens before logging now. Keep it valid and refuse a real
    // listener bind later in boot, while this socket still owns the exact address.
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = occupied.local_addr().unwrap().to_string();
    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "listen": address,
            "admin_listen": format!("127.0.0.1:{}", common::boot::free_port()),
            "admin_require_mtls": false,
            "store": {"module": "memory"},
            "auth": {"chain": []},
            "providers": {}, "models": {},
            "export": {"metrics": {"module": "prometheus", "settings": {"buffer_seconds": 60}}}
        }))
        .unwrap(),
    )
    .unwrap();
    let (out, code) = boot_until(&dir, |_| false);
    assert_eq!(code, Some(1), "the boot is refused; output:\n{out}");
    assert!(
        out.contains("cannot bind") && out.contains(&address),
        "the refusal is the occupied listener address; output:\n{out}"
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
