// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE TWO WELL-KNOWN SCRAPE ROUTES ACROSS A RELOAD, AS 1.5.5 ANSWERED THEM** (ARCHITECT
//! 2026-10-05, Q-U2-4 follow-up). `/metrics` and `/metrics/hooks` are the scrape sink's own routes
//! now (owner law 2026-09-27: they left core), but the owner law moved their OWNER, not their
//! behaviour. Through the shipped binary, booted with a `module: prometheus` instance:
//!
//! * a reload that REMOVES the instance (`config.yaml` edited, `POST /api/v1/admin/config/reload`)
//!   is live and reports
//!   nothing awaiting a restart; `/metrics` then `404`s (1.5.5's plugin route resolved its owner
//!   from the current snapshot) while `/metrics/hooks` keeps answering `200` under its own content
//!   type (1.5.5's core route, mounted with the recorder at boot, answered for the process's life);
//! * a reload that ADDS a prometheus instance back, under another name, serves `/metrics` again —
//!   1.5.5's host-held recorder answered whatever the instance was called — and reports nothing
//!   awaiting a restart, because the path was mounted at boot.

#![cfg(unix)]
#![cfg(linked_axis_export_doors)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const ADMIN_TOKEN: &str = "metrics-routes-reload-admin";

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-metrics-routes-reload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let signing_key = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(signing_key.status.success(), "--generate-signing-key");
    std::fs::write(dir.join("signing.key"), &signing_key.stdout).unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
advanced:
  allow_destinations: ["127.0.0.1"]
store: {{module: memory}}
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain:
    - keys
  signing_key: {{ file: "{signing}" }}
  admin_auth: [admin-tokens]
export:
  metrics: {{ module: prometheus, settings: {{ buffer_seconds: 60 }} }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            signing = dir.join("signing.key").display()
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

/// One answer: status, the `content-type` header, the body.
struct Answer {
    status: u16,
    content_type: String,
    body: String,
}

fn http(addr: &str, method: &str, path: &str, body: Option<&str>, token: Option<&str>) -> Answer {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");
        let url = format!("http://{addr}{path}");
        let mut req = match method {
            "POST" => client.post(url),
            "PUT" => client.put(url),
            "DELETE" => client.delete(url),
            _ => client.get(url),
        };
        if let Some(t) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json")
                .body(b.to_string());
        }
        let resp = req.send().await.expect("request");
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        Answer {
            status,
            content_type,
            body: resp.text().await.unwrap_or_default(),
        }
    })
}

/// `POST /api/v1/admin/config/reload`: applied, and naming no well-known scrape path as awaiting a
/// restart (the removal is live, and `/metrics` was mounted at boot).
fn reload(admin: &str) -> Answer {
    let r = http(
        admin,
        "POST",
        "/api/v1/admin/config/reload",
        None,
        Some(ADMIN_TOKEN),
    );
    assert!(
        (200..300).contains(&r.status),
        "the reload applies: {} {}",
        r.status,
        r.body
    );
    assert!(
        !r.body.contains("/metrics"),
        "no scrape path awaits a restart: {}",
        r.body
    );
    r
}

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}

/// `GET path` until it answers anything but the recorder's boot-window `503`.
fn settled(data: &str, path: &str, token: &str) -> Answer {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let a = http(data, "GET", path, None, Some(token));
        if a.status != 503 || Instant::now() > deadline {
            return a;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

const METRICS_CT: &str = "text/plain; version=0.0.4";
const HOOKS_CT: &str = "text/plain; version=0.0.4; charset=utf-8";

#[test]
fn a_reload_that_removes_the_scrape_sink_keeps_metrics_hooks_and_drops_metrics_as_1_5_5_did() {
    let dir = fixture_dir();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data_port, admin_port);
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("RUST_LOG", "info")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );
    let mut child = child;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !read_to_string(&log_path).contains("busbar listening") {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!("busbar exited ({status}):\n{}", read_to_string(&log_path));
        }
        assert!(
            Instant::now() < deadline,
            "busbar did not listen:\n{}",
            read_to_string(&log_path)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let (data, admin) = (
        format!("127.0.0.1:{data_port}"),
        format!("127.0.0.1:{admin_port}"),
    );
    let minted = http(
        &admin,
        "POST",
        "/api/v1/admin/keys",
        Some(r#"{"name":"metrics-reload"}"#),
        Some(ADMIN_TOKEN),
    );
    let token = minted
        .body
        .split("\"token\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("the admin API mints a key: {}", minted.body))
        .to_string();

    // Booted with the scrape sink: both routes answer, each under its 1.5.5 content type.
    let metrics = settled(&data, "/metrics", &token);
    assert_eq!(
        (metrics.status, metrics.content_type.as_str()),
        (200, METRICS_CT),
        "{}",
        metrics.body
    );
    let hooks = settled(&data, "/metrics/hooks", &token);
    assert_eq!(
        (hooks.status, hooks.content_type.as_str()),
        (200, HOOKS_CT),
        "{}",
        hooks.body
    );

    // THE RELOAD THAT REMOVES IT: config.yaml loses its `export:` block and the admin API reloads
    // it from disk — live, and nothing awaits a restart.
    let config = std::fs::read_to_string(dir.join("config.yaml")).unwrap();
    let without = config.replace(
        "export:\n  metrics: { module: prometheus, settings: { buffer_seconds: 60 } }\n",
        "",
    );
    assert_ne!(without, config, "the fixture names the export block");
    std::fs::write(dir.join("config.yaml"), &without).unwrap();
    reload(&admin);
    let metrics = http(&data, "GET", "/metrics", None, Some(&token));
    assert_eq!(
        metrics.status, 404,
        "/metrics followed the configuration in 1.5.5: removed, it 404s"
    );
    let hooks = http(&data, "GET", "/metrics/hooks", None, Some(&token));
    assert_eq!(
        (hooks.status, hooks.content_type.as_str()),
        (200, HOOKS_CT),
        "/metrics/hooks answered for the process's life in 1.5.5: {}",
        hooks.body
    );

    // THE RELOAD THAT ADDS ONE BACK, under another name: /metrics serves again, and the path was
    // mounted at boot, so nothing awaits a restart.
    std::fs::write(
        dir.join("config.yaml"),
        config.replace(
            "  metrics: { module: prometheus",
            "  metrics2: { module: prometheus",
        ),
    )
    .unwrap();
    reload(&admin);
    let metrics = settled(&data, "/metrics", &token);
    assert_eq!(
        (metrics.status, metrics.content_type.as_str()),
        (200, METRICS_CT),
        "{}",
        metrics.body
    );
    assert!(metrics.body.contains("# TYPE "), "{}", metrics.body);
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
