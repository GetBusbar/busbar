// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const INSTANCE: &str = "metrics";

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-plugin-log-boot-{}-{}",
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
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
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
store: {{ module: memory }}
auth:
  chain: []
plugins:
  enabled: true
  dir: '{plugins}'
  logs:
    dir: '{logs}'
    level: trace
export:
  {INSTANCE}: {{ module: prometheus, settings: {{ buffer_seconds: 60 }} }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            plugins = dir.join("plugins").display(),
            logs = dir.join("plugin-logs").display(),
        ),
    )
    .unwrap();
}

struct Reap(Child);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn scrape_status(port: u16) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    String::from_utf8_lossy(&raw)
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

#[test]
fn a_loaded_plugin_instance_has_its_own_log_file() {
    let dir = fixture_dir();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data_port, admin_port);
    let out = std::fs::File::create(dir.join("out.log")).unwrap();
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "warn")
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .spawn()
            .expect("spawn busbar"),
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!(
                "busbar refused to boot with plugins.logs set (status {status:?}); log:\n{}",
                std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
            );
        }
        if scrape_status(data_port) == Some(200) {
            break;
        }
        assert!(Instant::now() < deadline, "busbar never served /metrics");
        std::thread::sleep(Duration::from_millis(100));
    }

    let file = dir
        .join("plugin-logs")
        .join(format!("export.{INSTANCE}.log"));
    assert!(
        file.is_file(),
        "the loaded `{INSTANCE}` instance has no log file at {}; the plugin-logs directory holds \
         {:?}",
        file.display(),
        std::fs::read_dir(dir.join("plugin-logs"))
            .map(|d| d
                .filter_map(|e| e.ok())
                .map(|e| e.file_name())
                .collect::<Vec<_>>())
            .unwrap_or_default()
    );
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
