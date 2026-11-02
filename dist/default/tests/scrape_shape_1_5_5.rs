// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_every_plane_door)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-scrape-shape-1-5-5-{}-{}",
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

fn free_port() -> u16 {
    common::boot::free_port()
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
  admin_auth:
    - admin-tokens
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

const ADMIN_TOKEN: &str = "scrape-shape-1-5-5-admin";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root must exist")
}

fn plane_series_prefixes() -> Vec<String> {
    let cells_path = repo_root().join("testing/shadow-oracle/cells.json");
    let raw = std::fs::read_to_string(&cells_path).unwrap_or_else(|e| {
        panic!("the shadow-oracle cell list must be readable at {cells_path:?}: {e}")
    });
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("cells.json must be valid JSON");
    let cells = doc["cells"]
        .as_array()
        .expect("cells.json must carry a `cells` array");

    let mut prefixes: Vec<String> = Vec::new();
    for cell in cells {
        let Some(id) = cell["id"].as_str() else {
            continue;
        };
        let metrics_absence_cell =
            id.starts_with("ops.scrape|metrics") || id.starts_with("neutrality|metrics-");
        if !metrics_absence_cell {
            continue;
        }
        let Some(body_lines) = cell["body_lines"].as_str() else {
            continue;
        };
        for prefix in expand_alternation(body_lines) {
            if !prefixes.contains(&prefix) {
                prefixes.push(prefix);
            }
        }
    }

    assert!(
        prefixes.len() >= 4,
        "derived only {} metric-family prefix(es) from the golden's metrics-absence cells at \
         {cells_path:?} — the derivation did not bite, and an empty list would pass vacuously: {prefixes:?}",
        prefixes.len()
    );
    prefixes
}

fn expand_alternation(pattern: &str) -> Vec<String> {
    let body = pattern.strip_prefix('^').unwrap_or(pattern);
    let Some(open) = body.find('(') else {
        return Vec::new();
    };
    let Some(close) = body.find(')') else {
        return Vec::new();
    };
    if close < open {
        return Vec::new();
    }
    let head = &body[..open];
    let tail = &body[close + 1..];

    if tail.contains(|c: char| "[]{}()*+?|\\^$.".contains(c)) {
        return Vec::new();
    }
    body[open + 1..close]
        .split('|')
        .map(|alt| format!("{head}{alt}{tail}"))
        .collect()
}

#[test]
fn a_1_5_5_shaped_config_exposes_no_plane_series_with_every_plane_compiled_in() {
    let dir = fixture_dir();
    let data_port = free_port();
    let admin_port = free_port();
    write_configs(&dir, data_port, admin_port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = common::boot::Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("RUST_LOG", "info")
            .stdout(log)
            .stderr(log_err)
            .spawn()
            .expect("spawn busbar"),
    );

    let _dump = common::boot::DumpOnPanic(&log_path);

    let booted = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?}); log:\n{}",
                read_to_string(&log_path)
            );
        }
        common::boot::healthz_answers(data_port)
    });
    assert!(
        booted,
        "busbar did not reach 'listening' (data and admin) within 30s; log:\n{}",
        read_to_string(&log_path)
    );

    let (_, minted) = http_request(
        &format!("127.0.0.1:{admin_port}"),
        "POST",
        "/api/v1/admin/keys",
        Some(r#"{"name":"scrape-shape"}"#),
        Some(ADMIN_TOKEN),
    );
    let token = minted
        .split("\"token\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("the admin API must mint a key: {minted}"))
        .to_string();

    let chat = http_request(
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
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    assert_eq!(
        status, 200,
        "GET /metrics must answer 200 on a 1.5.5-shaped config once the recorder is installed; got:\n{body}"
    );
    assert!(
        body.contains("busbar_"),
        "the exposition must carry busbar's own series (a bare 200 proves nothing); chat answered \
         {chat:?}; mint answered {minted}; exposition:\n{body}"
    );

    let plane_series = plane_series_prefixes();
    let leaked: Vec<&str> = body
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter(|l| plane_series.iter().any(|p| l.starts_with(p.as_str())))
        .collect();
    assert!(
        leaked.is_empty(),
        "no {} series may appear on a plane-free 1.5.5-shaped config, even with every plane \
         compiled into the binary; found:\n{}\nfull exposition:\n{body}",
        plane_series
            .iter()
            .map(|p| format!("{p}*"))
            .collect::<Vec<_>>()
            .join("/"),
        leaked.join("\n")
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

#[test]
fn the_absent_series_list_comes_from_the_golden() {
    assert_eq!(
        expand_alternation("^busbar_(ledger|journal|hold|wal)_"),
        vec![
            "busbar_ledger_",
            "busbar_journal_",
            "busbar_hold_",
            "busbar_wal_"
        ],
        "the anchored-alternation expander must turn one golden `body_lines` into its literal prefixes"
    );
    assert!(
        expand_alternation("^busbar_key_budget_remaining_cents").is_empty(),
        "a pattern with no alternation carries no prefix list and must not be guessed at"
    );

    let derived = plane_series_prefixes();
    for expected in [
        "busbar_plane_",
        "busbar_ledger_",
        "busbar_journal_",
        "busbar_hold_",
        "busbar_wal_",
    ] {
        assert!(
            derived.iter().any(|p| p == expected),
            "the golden's metrics-absence cells must yield `{expected}`; derived: {derived:?}"
        );
    }
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
