// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AFTER FIRST BOOT THE RATE CARD CHANGES ONLY THROUGH `PUT /config/settings` (owner ruling
//! 2026-10-25, MONEY-DESIGN section 3a), against a REAL busbar:
//!
//! * a PUT writes the card to the fleet-shared history, and `GET /config/settings` shows the field
//!   it set;
//! * a config file whose card was EDITED after first boot refuses `POST /config/reload` with 409 and
//!   an audit record `card.edit_refused`, and the card in force is unchanged;
//! * `POST /config/apply` carrying another card is refused 409 and audited; one carrying NO card
//!   keeps 1.5.5's exact answer and leaves the card in force.
//!
//! RED on the base: the reload swapped the edited card in (200), the body's card was applied (200),
//! and a card-less apply priced at zero.
#![cfg(unix)]
// The fixture boots a REAL busbar with a configured provider; a build with no wire codec compiled
// in fail-closes at boot, which is correct product behaviour. Full-feature builds run it.
#![cfg(linked_section_pools)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const ADMIN_TOKEN: &str = "card-edits-fixture-admin";

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-card-edits-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn config(dir: &Path, data_port: u16, admin_port: u16, input: u64) -> String {
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
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
rate_card:
  test-model: {{ input_utok: {input}, output_utok: 2, units: {{ {units} }} }}
"#,
        signing = dir.join("signing.key").display(),
        units = UNITS,
    )
}

/// Every billable class the linked planes declare, at 0: the operator upgrade step a 1.6.0 card
/// takes (owner ruling Q42).
const UNITS: &str = "search_units: 0, classifications: 0, web_fetch_requests: 0, unitemized_tokens: 0, images: 0, audio_ms: 0, guardrail_automated_reasoning_policies: 0, guardrail_automated_reasoning_policy_units: 0, guardrail_content_policy_image_units: 0, guardrail_content_policy_units: 0, guardrail_contextual_grounding_policy_units: 0, guardrail_sensitive_information_policy_free_units: 0, guardrail_sensitive_information_policy_units: 0, guardrail_topic_policy_units: 0, guardrail_word_policy_units: 0";

fn http(addr: &str, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");
        let mut req = match method {
            "POST" => client.post(format!("http://{addr}{path}")),
            "PUT" => client.put(format!("http://{addr}{path}")),
            _ => client.get(format!("http://{addr}{path}")),
        };
        req = req.header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {ADMIN_TOKEN}"),
        );
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

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}

/// The audit actions recorded so far.
fn audit_actions(admin: &str) -> Vec<String> {
    let (status, body) = http(admin, "GET", "/api/v1/admin/audit?limit=500", None);
    assert_eq!(status, 200, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("audit JSON");
    let items = doc
        .get("items")
        .or_else(|| doc.get("entries"))
        .or_else(|| doc.get("data"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    items
        .iter()
        .filter_map(|e| e.get("action").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect()
}

/// The config file as the JSON body `POST /config/apply` takes.
fn as_apply_body(yaml: &str, providers: &str) -> String {
    let config: serde_json::Value =
        serde_json::to_value(serde_yaml::from_str::<serde_yaml::Value>(yaml).unwrap()).unwrap();
    let providers: serde_json::Value =
        serde_json::to_value(serde_yaml::from_str::<serde_yaml::Value>(providers).unwrap())
            .unwrap();
    serde_json::json!({ "config": config, "providers": providers }).to_string()
}

#[test]
fn a_card_edit_outside_put_config_settings_is_refused_and_audited() {
    let dir = fixture_dir();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    let providers =
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n";
    std::fs::write(dir.join("providers.yaml"), providers).unwrap();
    let key = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    std::fs::write(dir.join("signing.key"), &key.stdout).unwrap();
    let seed = config(&dir, data_port, admin_port, 1);
    std::fs::write(dir.join("config.yaml"), &seed).unwrap();

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Command::new(common::boot::exe())
        .current_dir(&dir)
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("RUST_LOG", "info")
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("spawn busbar");
    let _dump = common::boot::DumpOnPanic(&log_path);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !common::boot::log_shows_data_and_admin_listening(&read_to_string(&log_path)) {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!("busbar exited ({status:?}):\n{}", read_to_string(&log_path));
        }
        assert!(Instant::now() < deadline, "busbar did not listen in time");
        std::thread::sleep(Duration::from_millis(50));
    }
    let admin = format!("127.0.0.1:{admin_port}");

    // THE ONE CARD PATH: a PUT sets the fee; the GET shows the field it set.
    let (status, body) = http(
        &admin,
        "PUT",
        "/api/v1/admin/config/settings",
        Some(r#"{"per_request_fee":4}"#),
    );
    assert_eq!(status, 200, "{body}");
    let (_, body) = http(&admin, "GET", "/api/v1/admin/config/settings", None);
    let settings: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(settings["settings"]["per_request_fee"], 4, "{body}");
    assert!(
        settings["settings"].get("rate_card").is_none(),
        "a fee-only PUT shows no rate_card: {body}"
    );

    // A FILE EDIT after first boot: the reload is refused 409, audited, and nothing swaps.
    std::fs::write(
        dir.join("config.yaml"),
        config(&dir, data_port, admin_port, 9),
    )
    .unwrap();
    let (status, body) = http(&admin, "POST", "/api/v1/admin/config/reload", None);
    assert_eq!(
        status, 409,
        "an edited file card refuses the reload: {body}"
    );
    assert!(body.contains("PUT /config/settings"), "{body}");
    assert!(audit_actions(&admin)
        .iter()
        .any(|a| a == "card.edit_refused"));

    // A BODY CARD that is neither the seed nor the card in force: 409, audited.
    let edited = config(&dir, data_port, admin_port, 9);
    let (status, body) = http(
        &admin,
        "POST",
        "/api/v1/admin/config/apply",
        Some(&as_apply_body(&edited, providers)),
    );
    assert_eq!(status, 409, "a body card edit is refused: {body}");

    // A CARD-LESS apply: 1.5.5's exact answer, and the card in force stands.
    let cardless: String = seed
        .lines()
        .filter(|l| !l.starts_with("rate_card:") && !l.starts_with("  test-model: {"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(dir.join("config.yaml"), &seed).unwrap();
    let (status, body) = http(
        &admin,
        "POST",
        "/api/v1/admin/config/apply",
        Some(&as_apply_body(&cardless, providers)),
    );
    assert_eq!(status, 200, "{body}");
    let answer: serde_json::Value = serde_json::from_str(&body).unwrap();
    let keys: Vec<&String> = answer.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        vec!["applied", "config_version", "note"],
        "1.5.5's exact answer: {body}"
    );
    let (_, body) = http(&admin, "GET", "/api/v1/admin/config/settings", None);
    let settings: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        settings["settings"]["per_request_fee"], 4,
        "the card in force stands: {body}"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
