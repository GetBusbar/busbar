// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S ROUTING TABLES, read on the shipped binary: a configured model is what `/v1/models`
//! lists and what the `/metrics` lane families label, in the order the configuration resolves it.
//! Route is the kernel's (spec Part 3, the outbound table, step 1: "KERNEL | route (pool walk, member,
//! breaker)"), so these surfaces read the kernel's own tables whichever plane serves the traffic, and
//! a build whose planes contribute no routing view of their own still answers them.
//!
//! RED: a view with no tables behind it (a build whose routing view was a plane's, with no plane left
//! to state one) lists no model and scrapes no lane family.
#![cfg(unix)]
// The fixture boots a REAL busbar with a configured provider; a `--no-default-features` build has
// no plane to serve it and fails closed at boot, which is correct product behaviour.
#![cfg(linked_axis_node)]
// `module: prometheus` is the linked scrape sink on the export-doors axis.
#![cfg(linked_axis_export_doors)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// Two models, so the order the configuration resolves them in is visible.
const MODELS: [&str; 2] = ["route-model-a", "route-model-b"];

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
store: {{module: memory}}
admin_require_mtls: false
auth:
  chain: []
advanced:
  allow_destinations: ["127.0.0.1"]
export:
  metrics: {{ module: prometheus, settings: {{ buffer_seconds: 60 }} }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  {b}:
    provider: mock
  {a}:
    provider: mock
"#,
            a = MODELS[0],
            b = MODELS[1],
        ),
    )
    .unwrap();
}

/// One `GET path` over a fresh connection: `(status, body)`, or `None` when the server is not up.
fn get(port: u16, path: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())?;
    Some((status, body.to_string()))
}

#[test]
fn the_shipped_binary_lists_and_scrapes_the_configured_models() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-route-tables-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data_port, admin_port);
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("RUST_LOG", "warn")
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("spawn busbar");
    let log = || std::fs::read_to_string(&log_path).unwrap_or_default();

    // The listing, once the node answers it.
    let deadline = Instant::now() + Duration::from_secs(30);
    let models = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!("busbar exited ({status:?}); log:\n{}", log());
        }
        if let Some((200, body)) = get(data_port, "/v1/models") {
            break body;
        }
        assert!(Instant::now() < deadline, "no /v1/models; log:\n{}", log());
        std::thread::sleep(Duration::from_millis(20));
    };
    // The scrape, once the recorder is installed (a 503 until then).
    let scrape = loop {
        if let Some((200, body)) = get(data_port, "/metrics") {
            if body.contains("# HELP") {
                break body;
            }
        }
        assert!(
            Instant::now() < deadline,
            "no full /metrics; log:\n{}",
            log()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    // Every configured model is listed, in the order the configuration resolves the lanes in.
    let at: Vec<usize> = MODELS
        .iter()
        .map(|m| {
            models
                .find(&format!("\"{m}\""))
                .unwrap_or_else(|| panic!("/v1/models lists no `{m}`:\n{models}"))
        })
        .collect();
    assert!(
        at[0] < at[1],
        "the lane order is the resolved one:\n{models}"
    );
    // Every configured model is a lane the scrape labels.
    for m in MODELS {
        for family in [
            "busbar_lane_state",
            "busbar_lane_available",
            "busbar_lane_inflight",
            "busbar_lane_recovery_hint_ms",
        ] {
            assert!(
                scrape.contains(&format!("{family}{{pool=\"{m}\",lane=\"{m}\"}}")),
                "/metrics has no {family} for `{m}`:\n{scrape}"
            );
        }
    }
}
