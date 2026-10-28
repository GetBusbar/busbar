// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A REFUSAL MADE WHILE A PLUGIN BINDS IS ON THE AUDIT CHAIN** (owner rule: every refusal is
//! audited and explained; nothing silent). The webhook request-log sink is configured at a plain
//! `http://` loopback target, which the host's connection table refuses when the sink declares its
//! need at `open` (the oracle's `export|request-log-webhook|loopback-refused` cell). The node still
//! boots, the sink stays inert, and its refusal is in the plugin's own log. RED before BIND-AUDIT:
//! the chain held nothing about it.
//!
//! Driven through the shipped binary: boot, then `GET /api/v1/admin/audit`. Exactly one
//! `plugin.need` record names the sink, `rejected`, by the host, and carries no URL.

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The admin token the config names.
const ADMIN_TOKEN: &str = "bind-refusal-audited-admin-token";

/// The sink's target: plain http, loopback. The host refuses it before any dial.
const REFUSED_URL: &str = "http://127.0.0.1:9/sidecar";

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-bind-refusal-audited-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A 1.5.5-shaped config with an admin token, governance on, and the webhook sink at
/// [`REFUSED_URL`]. No `allow_destinations`: the host's default guard stands.
fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    let key_hex = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("run --generate-signing-key");
    assert!(key_hex.status.success(), "generate-signing-key failed");
    std::fs::write(dir.join("signing.key"), &key_hex.stdout).unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
store: {{module: memory}}
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain:
    - keys
  signing_key: {{ file: "{key}" }}
  admin_auth:
    - admin-tokens
export:
  hook: {{ module: request-log-webhook, settings: {{ url: "{REFUSED_URL}" }} }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            key = dir.join("signing.key").display(),
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

/// `GET path` on the admin listener with the admin token: `(status, body)`, or `None` before it
/// answers.
fn admin_get(port: u16, path: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {ADMIN_TOKEN}\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, body.to_string()))
}

#[test]
fn a_loopback_webhook_refusal_at_boot_is_one_audit_record() {
    let dir = fixture_dir();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data_port, admin_port);
    let log_path = dir.join("out.log");
    let _dump = common::boot::DumpOnPanic(&log_path);
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("RUST_LOG", "warn")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );

    // THE NODE BOOTS: a refused sink is inert, not a boot refusal.
    let deadline = Instant::now() + Duration::from_secs(60);
    let body = loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!("busbar exited ({status:?}) with the refused sink configured");
        }
        if let Some((200, body)) = admin_get(admin_port, "/api/v1/admin/audit?limit=100") {
            break body;
        }
        assert!(
            Instant::now() < deadline,
            "the admin listener never answered"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    let page: serde_json::Value = serde_json::from_str(&body).expect("the audit page is JSON");
    let items = page["items"].as_array().expect("the page lists items");
    let refusals: Vec<&serde_json::Value> = items
        .iter()
        .filter(|i| i["action"] == "plugin.need")
        .collect();
    assert_eq!(
        refusals.len(),
        1,
        "one record for the one refused need: {items:#?}"
    );
    let record = refusals[0];
    assert_eq!(record["outcome"], "rejected");
    assert_eq!(record["principal"], "host");
    let resource = record["resource"].as_str().expect("a resource");
    assert!(
        resource.starts_with("plugin:export/") && resource.ends_with(".refused"),
        "the sink's kind and the host's word: {resource}"
    );
    assert!(
        !resource.contains("127.0.0.1") && !resource.contains("http"),
        "no plugin setting reaches the chain: {resource}"
    );
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
