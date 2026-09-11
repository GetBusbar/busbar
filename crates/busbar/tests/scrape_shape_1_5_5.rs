// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Binding: a pure 1.5.5-shaped config (no `data_dir`, no `peers`, no `keyset_ref`, no plane
//! section at all) exposes NO series named `busbar_plane_*`, `busbar_ledger_*`,
//! `busbar_journal_*`, `busbar_hold_*` or `busbar_wal_*` on `/metrics` — checked against the
//! WHOLE exposition, not a request-path subset — even though the binary this test boots has
//! EVERY plane (LLM, MCP, A2A, voice) compiled in. The plane code being present in the binary
//! must not leak a single series onto a deployment that never configured a plane, which is
//! exactly what distinguishes "compiled in, unmounted" from "mounted and idle".
//!
//! The list of absent families is DERIVED from the shadow-oracle golden's own metrics-absence
//! cells (`ops.scrape|metrics|*` and `neutrality|metrics-*`, whose `body_lines` regex names them)
//! rather than re-typed here, so the gate and the golden cannot drift into checking different sets.
//!
//! This is the closed-set half of the alarm/dispute tripwire in
//! `busbar_core::tests::alarm_silence_tests` (that one captures `tracing` + scans the exposition
//! from in-process; this one boots the real shipped binary end to end so the plane crates'
//! actual `Cargo.toml` feature wiring, not a unit-test fixture, is what is under test).
#![cfg(unix)]
// "Every plane compiled in" requires all four plane-bearing features; a build missing one of
// them is not the shape this test is about, so it skips rather than giving a false pass/fail.
#![cfg(all(
    feature = "proto-llm",
    feature = "plane-mcp",
    feature = "plane-a2a",
    feature = "plane-voice"
))]

mod common;

use common::ReservedPort;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// A fresh, isolated fixture directory (pid + nanos, like the sibling harnesses).
fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-scrape-shape-1-5-5-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The 1.5.5 shape: one provider, one model, keys on the data plane, an admin token, prometheus
/// export, memory store (the default). No plane section (`mcp:`, `agents:`, `voice:`), no
/// `data_dir`, no `peers`, no `keyset_ref` anywhere — nothing 1.6.0-additive.
fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let signing_key = Command::new(env!("CARGO_BIN_EXE_busbar"))
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

const ADMIN_TOKEN: &str = "scrape-shape-1-5-5-admin";

/// The repository root, so the golden can be read from where it lives rather than from the CWD the
/// test runner happened to pick.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root must exist")
}

/// THE GOLDEN is the authority on which metric families a 1.5.5 deployment does not expose, and it
/// already says so in a form a test can read: the shadow-oracle cells that assert an ABSENCE carry a
/// `body_lines` regex naming exactly the families whose lines must not appear. Re-typing those names
/// here as a `const` would fork the claim — the golden could grow a sixth family and this gate would
/// go on checking five, reporting green about a set it no longer describes. So the list is DERIVED.
///
/// The cells consulted are the metrics-absence cells: `ops.scrape|metrics|*` (the scrape family's
/// own ledger check) and `neutrality|metrics-*` (the plane-prefixed extension of it, which the
/// `ops.scrape` cell's `why` explicitly names as the same contract). Their union is what the golden
/// as a whole asserts is absent, and the union is what this gate enforces.
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

    // Non-vacuity: a cells.json whose shape drifted (renamed key, restructured ids) would silently
    // yield an empty list and turn this gate into an assertion about nothing.
    assert!(
        prefixes.len() >= 4,
        "derived only {} metric-family prefix(es) from the golden's metrics-absence cells at \
         {cells_path:?} — the derivation did not bite, and an empty list would pass vacuously: {prefixes:?}",
        prefixes.len()
    );
    prefixes
}

/// Expand a golden `body_lines` anchored alternation into literal prefixes:
/// `^busbar_(ledger|journal|hold|wal)_` becomes `busbar_ledger_`, `busbar_journal_`, ... . Only this
/// one shape is understood; anything else returns nothing, so an unrecognised pattern shows up as a
/// short list and trips the floor above rather than being silently dropped.
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
    // A tail carrying regex metacharacters is not a literal prefix; refuse rather than guess.
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
    let data_reserved = ReservedPort::reserve();
    let admin_reserved = ReservedPort::reserve();
    let data_port = data_reserved.port();
    let admin_port = admin_reserved.port();
    write_configs(&dir, data_port, admin_port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    // Release the reservations immediately before the spawn that binds these numbers (see
    // `ReservedPort`'s doc for why this ordering is the fix).
    data_reserved.release();
    admin_reserved.release();
    let mut child = Command::new(env!("CARGO_BIN_EXE_busbar"))
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

    // Mint one virtual key through the admin API, exactly as an operator would.
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
    // One request through the whole request path first (the provider is unreachable, so it ends
    // as an upstream failure): the exposition then carries the request-path series, which is
    // exactly where a leaked plane series would first register.
    let chat = http_request(
        &format!("127.0.0.1:{data_port}"),
        "POST",
        "/v1/messages",
        Some(
            r#"{"model":"test-model","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
        ),
        Some(&token),
    );
    // The scrape (key-authenticated on the data listener in 1.5.5). Until the recorder is installed
    // the scrape is REFUSED with 503 (never an empty 200); that window is milliseconds, so the test
    // retries through it and then holds the answer to exactly 200 with a full exposition.
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

    // Assert the WHOLE exposition: every non-comment line, checked against every prefix the GOLDEN
    // says is absent — not just the lines the chat request happened to touch.
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

/// SELF-TEST: the derivation actually reads the golden and actually expands it. The boot test above
/// is expensive and answers a different question, so the cheap half — "is the list the golden's, and
/// is it the right list" — is proved separately and always runs.
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

    // The real derivation, over the real cells.json: both metrics-absence cells must contribute, so
    // the union carries the plane family (from `neutrality|metrics-no-plane-series`) as well as the
    // four storage families (from `ops.scrape|metrics|no-ledger-series`).
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

/// One HTTP request against the booted process: (status, body text).
fn http_request(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    bearer: Option<&str>,
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
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
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

/// Poll `cond` until it returns true or `budget` elapses; returns whether it became true.
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

/// Read a file to a String, tolerating a not-yet-flushed/partial log (returns what's there).
fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}
