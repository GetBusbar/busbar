// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
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

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

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

#[test]
fn test_metrics_requires_auth_in_chain_mode() {
    let dir = fixture_dir();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data_port, admin_port);
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Reap(
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
        Some(r#"{"name":"metrics-scrapers"}"#),
        Some(ADMIN_TOKEN),
    );
    let token = minted
        .body
        .split("\"token\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("the admin API mints a key: {}", minted.body))
        .to_string();

    let authed = settled(&data, "/metrics", &token);
    assert_eq!(
        authed.status, 200,
        "/metrics with the configured credential must be admitted: {}",
        authed.body
    );
    assert!(
        authed.body.contains("busbar_lane_state"),
        "authed exposition should contain a metric; got:\n{}",
        authed.body
    );

    let unauthed = http(&data, "GET", "/metrics", None, None);
    assert_eq!(
        unauthed.status, 401,
        "/metrics must require auth in chain mode; a 200 means it was re-exempted like /healthz"
    );
    let healthz = http(&data, "GET", "/healthz", None, None);
    assert!(
        matches!(healthz.status, 200 | 503),
        "/healthz is declared open: the probe answers (200/503), never the chain's 401; got {}",
        healthz.status
    );
    let exchange = http(&data, "GET", "/auth/token?logout=1", None, None);
    assert_eq!(
        exchange.status, 200,
        "/auth/token is declared open and must serve its signed-out page with no credential: {}",
        exchange.body
    );
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
