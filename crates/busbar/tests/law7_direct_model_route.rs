// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAW 7 AND THE DIRECT MODEL ROUTE (BUSBAR-1.6.0.md §2 "A plugin loads if and only if config uses
//! it. There are no special plugins."; §4 "Selection follows the classes"): a 1.5.5 configuration
//! that routes to its models directly — `providers:` and `models:`, no `pools:` — uses the plane
//! serving models, so the boot loads it and `POST /<model>/v1/messages` is served exactly as when
//! the configuration also names the plane's verb. The plane is selected by its `models` section
//! (`SECTION_SELECTS`), read off its rendered Statement, not by opening it.
//!
//! RED before `SECTION_SELECTS` selected: the plane's verb is `pools`, so the direct-routing
//! configuration loaded no plane and the route answered as no plane serves it.
#![cfg(unix)]
// The configuration below is served by the plane door that declares `pools:`; a build without it is
// not the shape this test is about.
#![cfg(linked_section_pools)]

mod common;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const ADMIN_TOKEN: &str = "law7-direct-model-route-admin";

/// The far end's one answer, whatever it is asked: a whole message in the provider's dialect.
fn upstream_answer() -> serde_json::Value {
    serde_json::json!({
        "id": "msg_law7_direct",
        "type": "message",
        "role": "assistant",
        "model": "test-model",
        "content": [{"type": "text", "text": "served"}],
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {"input_tokens": 3, "output_tokens": 1}
    })
}

/// A loopback far end answering every request with [`upstream_answer`], for the test's life.
fn upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the far end");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            std::thread::spawn(move || {
                if common::upstream::read_request(&mut conn).is_some() {
                    common::upstream::respond(&mut conn, 200, &upstream_answer());
                }
            });
        }
    });
    port
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-law7-direct-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The 1.5.5 shape: one provider at the far end, one model, keys on the data plane, an admin token;
/// `pools` appended when given (the plane's verb).
fn write_configs(dir: &Path, upstream: u16, data: u16, admin: u16, pools: &str) {
    // The provider catalog row is test data (`fixtures/mock_provider.yaml`, the far end's dialect),
    // not a literal here; its base URL is pointed at this test's far end.
    let catalog = include_str!("fixtures/mock_provider.yaml");
    assert!(
        catalog.contains("\"http://127.0.0.1:9\""),
        "mock_provider.yaml states the base URL this test repoints"
    );
    std::fs::write(
        dir.join("providers.yaml"),
        catalog.replace(
            "\"http://127.0.0.1:9\"",
            &format!("\"http://127.0.0.1:{upstream}\""),
        ),
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
            r#"listen: "127.0.0.1:{data}"
admin_listen: "127.0.0.1:{admin}"
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
  admin_auth:
    - admin-tokens
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
{pools}"#,
            signing = dir.join("signing.key").display()
        ),
    )
    .unwrap();
}

fn http_request(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> (u16, String) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");
        let mut req = match method {
            "POST" => client.post(format!("http://{addr}{path}")),
            _ => client.get(format!("http://{addr}{path}")),
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
        (status, resp.text().await.unwrap_or_default())
    })
}

fn wait_for(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

/// Boot a node over `pools` (empty: the direct-routing shape), mint a key, ask the direct route
/// once, and answer what it said.
fn direct_route_answer(tag: &str, upstream: u16, pools: &str) -> (u16, String) {
    let dir = fixture_dir(tag);
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, upstream, data, admin, pools);
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");
    let _dump = common::boot::DumpOnPanic(&log_path);
    let read = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let booted = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening ({status:?}); log:\n{}",
                read()
            );
        }
        common::boot::log_shows_data_and_admin_listening(&read())
    });
    assert!(
        booted,
        "busbar did not reach 'listening' in 30s; log:\n{}",
        read()
    );
    let (_, minted) = http_request(
        &format!("127.0.0.1:{admin}"),
        "POST",
        "/api/v1/admin/keys",
        Some(r#"{"name":"law7-direct"}"#),
        Some(ADMIN_TOKEN),
    );
    let token = minted
        .split("\"token\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("the admin API must mint a key: {minted}"))
        .to_string();
    let answer = http_request(
        &format!("127.0.0.1:{data}"),
        "POST",
        "/test-model/v1/messages",
        Some(
            r#"{"model":"test-model","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
        ),
        Some(&token),
    );
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();
    if !wait_for(Duration::from_secs(15), || {
        child.try_wait().expect("try_wait").is_some()
    }) {
        let _ = child.kill();
    }
    let _ = std::fs::remove_dir_all(&dir);
    answer
}

#[test]
fn a_direct_routing_config_is_served_as_one_naming_the_planes_verb() {
    let far = upstream();
    let direct = direct_route_answer("direct", far, "");
    let pooled = direct_route_answer(
        "pooled",
        far,
        "pools:\n  everyone:\n    members:\n      - model: test-model\n",
    );
    assert_eq!(
        direct.0, 200,
        "the direct route is served by the plane its `models:` selects: {direct:?}"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&direct.1).ok(),
        Some(upstream_answer()),
        "the far end's message, as 1.5.5 relayed it: {direct:?}"
    );
    assert_eq!(
        direct, pooled,
        "byte for byte what the same route answers when config also names the plane's verb"
    );
}
