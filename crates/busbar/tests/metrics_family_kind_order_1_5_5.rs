// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KP-C0: the raw `/metrics` exposition emits every family in v1.5.5's own FAMILY-KIND order —
//! every counter, then every gauge, then every histogram/summary — never a counter after a
//! distribution.
//!
//! DERIVATION, not a captured guess (a single 1.5.5 capture cannot pin this: within a kind the
//! order is hash-map order and "varies between runs" — see `scrape_shape_1_5_5.rs`'s sibling
//! discipline of deriving from the golden rather than a capture). Both v1.5.5
//! (`v1.5.5:crates/busbar/src/metrics.rs`, `render()` at line 691 calling `h.render()`) and this
//! binary (`busbar_kernel::metrics::render()`) hand the SAME `metrics-exporter-prometheus` v0.18.3
//! recorder's `render_to_write` the whole exposition: that function drains its counters map
//! whole, then its gauges map whole, then its distributions (histogram + summary) map whole —
//! three sequential, unconditional passes, in that fixed order, in every release either binary
//! could have linked. WHICH KIND'S BLOCK COMES FIRST is therefore code-determined and identical
//! in both; WHICH FAMILY comes first WITHIN a kind is not (hash order), so this test does not pin
//! that.
//!
//! Before the fix this binary's scrape sink (`busbar-export-prometheus`) sorted families by name
//! alone, so a counter whose name sorts after a distribution's — `busbar_requests_total` and
//! `busbar_upstream_attempts_total` both sort after `busbar_request_duration_seconds` — rendered
//! AFTER that summary, which v1.5.5 never does. RED on the parent: the parent's exposition is
//! fully name-sorted across kinds, so this assertion fails on it.

#![cfg(unix)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-metrics-family-kind-order-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
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

const ADMIN_TOKEN: &str = "metrics-family-kind-order-admin";

/// v1.5.5's own FAMILY-KIND rank: counters before gauges before distributions (histogram or
/// summary) — the fixed pass order `metrics-exporter-prometheus::render_to_write` has always used.
fn kind_rank(kind: &str) -> u8 {
    match kind {
        "counter" => 0,
        "gauge" => 1,
        "histogram" | "summary" => 2,
        _ => 3,
    }
}

#[test]
fn every_counter_precedes_every_gauge_precedes_every_distribution() {
    let dir = fixture_dir();
    let data_port = free_port();
    let admin_port = free_port();
    write_configs(&dir, data_port, admin_port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("RUST_LOG", "info")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");

    let booted = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?}); log:\n{}",
                read_to_string(&log_path)
            );
        }
        read_to_string(&log_path).contains("busbar listening")
    });
    assert!(
        booted,
        "busbar did not reach 'listening' within 30s; log:\n{}",
        read_to_string(&log_path)
    );

    let (_, minted) = http_request(
        &format!("127.0.0.1:{admin_port}"),
        "POST",
        "/api/v1/admin/keys",
        Some(r#"{"name":"metrics-family-kind-order"}"#),
        Some(ADMIN_TOKEN),
    );
    let token = minted
        .split("\"token\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("the admin API must mint a key: {minted}"))
        .to_string();

    // One request through the whole request path: the provider is unreachable, so it ends as an
    // upstream failure, populating `busbar_requests_total` / `busbar_upstream_attempts_total`
    // (counters) alongside `busbar_request_duration_seconds` (the summary) — a counter AND a
    // distribution both present is what makes the ordering assertion non-vacuous.
    let _ = http_request(
        &format!("127.0.0.1:{data_port}"),
        "POST",
        "/v1/messages",
        Some(
            r#"{"model":"test-model","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
        ),
        Some(&token),
    );

    let mut attempt = 0;
    let (status, body) = loop {
        let (status, body) = http_request(
            &format!("127.0.0.1:{data_port}"),
            "GET",
            "/metrics",
            None,
            Some(&token),
        );
        if status != 503 || attempt >= 200 {
            break (status, body);
        }
        attempt += 1;
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(status, 200, "GET /metrics must answer 200; got:\n{body}");

    let kinds: Vec<(String, String)> = body
        .lines()
        .filter_map(|l| l.strip_prefix("# TYPE "))
        .filter_map(|rest| rest.split_once(' '))
        .map(|(name, kind)| (name.to_string(), kind.to_string()))
        .collect();
    assert!(
        kinds.iter().any(|(_, k)| k == "counter"),
        "the exposition must carry at least one counter to make this assertion non-vacuous:\n{body}"
    );
    assert!(
        kinds.iter().any(|(_, k)| k == "summary" || k == "histogram"),
        "the exposition must carry at least one distribution to make this assertion non-vacuous:\n{body}"
    );

    let ranks: Vec<u8> = kinds.iter().map(|(_, k)| kind_rank(k)).collect();
    let mut sorted_ranks = ranks.clone();
    sorted_ranks.sort();
    assert_eq!(
        ranks, sorted_ranks,
        "every counter must precede every gauge, which must precede every histogram/summary \
         (v1.5.5's own render_to_write pass order); families in scrape order: {kinds:?}\n{body}"
    );

    let pid = child.id().to_string();
    let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
    let exited = wait_for(Duration::from_secs(15), || {
        child.try_wait().expect("try_wait").is_some()
    });
    if !exited {
        let _ = child.kill();
    }
    let _ = std::fs::remove_dir_all(&dir);
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

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}
