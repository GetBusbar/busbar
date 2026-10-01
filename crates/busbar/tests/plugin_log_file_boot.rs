// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A LOADED PLUGIN INSTANCE HAS ITS OWN LOG FILE** — end to end, over the REAL binary
//! (`BUSBAR-1.6.0.md` decision #85 and THE DESIGN, §11.2 "Plugin logging").
//!
//! The binary boots with `plugins.logs.dir` set and one export instance, `metrics`, over the
//! compiled-in `prometheus` plugin. A compiled-in plugin is called through the same door and table
//! as a dropped-in one (BUSBAR-1.6.0.md THE DESIGN, §11.4), so once the instance is loaded, the host has bound it
//! to its own log sink, and opening that sink creates `<plugins.logs.dir>/metrics.log`. The file
//! exists as soon as the instance is bound, whether or not the plugin has logged anything yet.
//!
//! RED IN THIS BUILD, KNOWN, AND OWNED (ARCHITECT ruling 2026-09-28, BOOT-CHAIN (3)): the one load
//! (the loader's `boot::load`, KERNEL<>PLUGINS step 6) binds every memory-ABI instance it
//! loads to `PluginLogConfig::sink` — proven at the loader by
//! `boot::tests::the_one_load_binds_each_selected_instance_to_its_own_log_sink` — but the compiled-in
//! scrape sink is still a cold-ABI plugin, so no memory-ABI instance is loaded here and no file
//! appears. OWNER: that export sibling on `plugin_door!` (`1.6.0-TODO.md` steps
//! 26/27, the export fan-out); its `#[ignore]` comes off in that change.
//!
//! Run it: `cargo test -p busbar --test plugin_log_file_boot -- --ignored`
#![cfg(unix)]
#![cfg(linked_axis_body_ingress)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The export instance the test configures, and so the name of its log file.
const INSTANCE: &str = "metrics";

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-plugin-log-boot-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
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

/// Kill the child when the test ends, however it ends.
struct Reap(Child);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `GET /metrics` over a fresh connection: its status, or `None` while the listener is not up.
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
#[ignore = "RED BY DESIGN: the one load binds every memory-ABI instance to \
            PluginLogConfig::sink (KERNEL<>PLUGINS step 6), but the scrape sink is still a cold-ABI \
            plugin. Owner: the export fan-out's scrape sibling on plugin_door! (1.6.0-TODO \
            steps 26/27), which removes this ignore. Run with --ignored; do not weaken this test \
            to make it green."]
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

    // The instance is loaded and serving: `/metrics` answers 200.
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

    let file = dir.join("plugin-logs").join(format!("{INSTANCE}.log"));
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
