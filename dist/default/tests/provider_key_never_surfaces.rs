// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const ADMIN_TOKEN: &str = "provider-key-never-surfaces-admin";

const PROVIDER_KEY: &str = "sk-leakcheck-7f3a9c41d2e8b605";
const CALL_TEXT: &str = "provider-key-witness-7f3a9c41";

fn served_answer() -> serde_json::Value {
    serde_json::json!({
        "id": "msg_leakcheck",
        "type": "message",
        "role": "assistant",
        "model": "ok-model",
        "content": [{"type": "text", "text": "served"}],
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {"input_tokens": 3, "output_tokens": 1}
    })
}

fn far_end(answer: Option<(u16, serde_json::Value)>) -> (u16, Receiver<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the far end");
    let port = listener.local_addr().unwrap().port();
    let (sent, received) = mpsc::channel();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let answer = answer.clone();
            let sent = sent.clone();
            std::thread::spawn(move || {
                if let Some((head, body)) = common::upstream::read_request(&mut conn) {
                    let keyed = head.lines().any(|line| {
                        line.split_once(':').is_some_and(|(name, value)| {
                            name.eq_ignore_ascii_case("x-api-key") && value.trim() == PROVIDER_KEY
                        })
                    });
                    let requested = serde_json::from_slice::<serde_json::Value>(&body)
                        .is_ok_and(|request| request["messages"][0]["content"] == CALL_TEXT);
                    if requested {
                        let _ = sent.send(keyed);
                    }
                    if let Some((status, body)) = answer {
                        common::upstream::respond(&mut conn, status, &body);
                    }
                }
            });
        }
    });
    (port, received)
}

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-provider-key-never-surfaces-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, ok: u16, refusing: u16, dead: u16, data: u16, admin: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        format!(
            "ok:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:{ok}\"\n\
             refusing:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:{refusing}\"\n\
             dead:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:{dead}\"\n"
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
export:
  metrics: {{ module: prometheus, settings: {{ buffer_seconds: 60 }} }}
providers:
  ok:
    api_key: {{ env: LEAKCHECK_KEY }}
  refusing:
    api_key: {{ env: LEAKCHECK_KEY }}
  dead:
    api_key: {{ env: LEAKCHECK_KEY }}
models:
  ok-model:
    provider: ok
  refused-model:
    provider: refusing
  dead-model:
    provider: dead
pools:
  everyone:
    members:
      - model: ok-model
      - model: refused-model
      - model: dead-model
"#,
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
) -> (u16, String, String) {
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
        let head = format!("{:?}", resp.headers());
        (status, head, resp.text().await.expect("the response body"))
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

#[test]
fn a_provider_key_never_appears_in_logs_errors_or_stats() {
    let (ok, ok_received) = far_end(Some((200, served_answer())));
    let (refusing, refused_received) = far_end(Some((
        401,
        serde_json::json!({"type": "error", "error": {"type": "authentication_error",
            "message": "invalid x-api-key"}}),
    )));
    let (dead, dead_received) = far_end(None);
    let dir = fixture_dir();
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, ok, refusing, dead, data, admin);
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("LEAKCHECK_KEY", PROVIDER_KEY)
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("RUST_LOG", "debug")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");
    struct StopChild<'a>(&'a mut std::process::Child);
    impl Drop for StopChild<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let child = StopChild(&mut child);
    let _dump = common::boot::DumpOnPanic(&log_path);
    let read = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let booted = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening ({status:?}); log:\n{}",
                read()
            );
        }
        common::boot::healthz_answers(data) && common::boot::healthz_answers(admin)
    });
    assert!(booted, "busbar did not reach 'listening' in 30s");

    let (data, admin) = (format!("127.0.0.1:{data}"), format!("127.0.0.1:{admin}"));
    let (mint_status, _, minted) = http_request(
        &admin,
        "POST",
        "/api/v1/admin/keys",
        Some(r#"{"name":"leakcheck"}"#),
        Some(ADMIN_TOKEN),
    );
    assert_eq!(mint_status, 201, "the admin API created the caller's key");
    let minted: serde_json::Value = serde_json::from_str(&minted).expect("the minted key response");
    let token = minted["token"]
        .as_str()
        .unwrap_or_else(|| panic!("the admin API must mint a key: {minted}"))
        .to_string();

    let mut surfaces: Vec<(String, u16, String, String)> = Vec::new();
    for model in ["ok-model", "refused-model", "dead-model"] {
        let body = format!(
            r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"{CALL_TEXT}"}}]}}"#
        );
        let path = format!("/{model}/v1/messages");
        let (status, headers, text) = http_request(&data, "POST", &path, Some(&body), Some(&token));
        match model {
            "ok-model" => {
                assert_eq!(status, 200);
                assert_eq!(
                    ok_received.try_recv(),
                    Ok(true),
                    "the serving upstream received the key"
                );
                let answer: serde_json::Value =
                    serde_json::from_str(&text).expect("the served answer");
                assert_eq!(answer["content"][0]["text"], "served");
            }
            "refused-model" => {
                assert_eq!(status, 401);
                assert_eq!(
                    refused_received.try_recv(),
                    Ok(true),
                    "the 401 upstream received the key"
                );
            }
            "dead-model" => {
                assert!(
                    (500..600).contains(&status),
                    "the closed upstream failed the call: {status}"
                );
                assert_eq!(
                    dead_received.try_recv(),
                    Ok(true),
                    "the upstream read the key before closing without a reply"
                );
            }
            _ => unreachable!(),
        }
        assert!(!text.trim().is_empty(), "{model} returned a body to scan");
        surfaces.push((format!("POST {path}"), status, headers, text));
    }
    let pooled =
        r#"{"model":"everyone","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#;
    let (status, headers, text) =
        http_request(&data, "POST", "/v1/messages", Some(pooled), Some(&token));
    assert_eq!(status, 200, "the pool retains its serving member");
    surfaces.push(("POST /v1/messages (pool)".into(), status, headers, text));
    let (status, headers, text) = http_request(
        &data,
        "POST",
        "/ok-model/v1/messages",
        Some(pooled),
        Some("bbk_not_a_real_token"),
    );
    assert_eq!(
        status, 401,
        "the caller's invalid key is refused separately"
    );
    surfaces.push(("POST with a wrong token".into(), status, headers, text));

    let mut attempt = 0;
    let scrape = loop {
        let (status, headers, text) = http_request(&data, "GET", "/metrics", None, Some(&token));
        if status != 503 || attempt >= 200 {
            break (status, headers, text);
        }
        attempt += 1;
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(scrape.0, 200, "the metrics surface was served");
    assert!(
        scrape
            .2
            .lines()
            .any(|line| !line.trim().is_empty() && !line.starts_with('#')),
        "the scrape contains metric samples"
    );
    surfaces.push(("GET /metrics".into(), scrape.0, scrape.1, scrape.2));
    for path in [
        "/api/v1/admin/info",
        "/api/v1/admin/pools?detail=true",
        "/api/v1/admin/pools/everyone",
        "/api/v1/admin/models",
        "/api/v1/admin/providers",
        "/api/v1/admin/config",
        "/api/v1/admin/config/settings",
        "/api/v1/admin/auth",
        "/api/v1/admin/keys",
        "/api/v1/admin/usage",
        "/api/v1/admin/audit",
    ] {
        let (status, headers, text) = http_request(&admin, "GET", path, None, Some(ADMIN_TOKEN));
        assert_eq!(status, 200, "the admin surface {path} was served");
        assert!(
            !text.trim().is_empty(),
            "the admin surface {path} has a body to scan"
        );
        let _: serde_json::Value = serde_json::from_str(&text).expect("an admin JSON response");
        surfaces.push((format!("GET {path}"), status, headers, text));
    }

    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.0.id().to_string())
        .status();
    if !wait_for(Duration::from_secs(30), || {
        child.0.try_wait().expect("try_wait").is_some()
    }) {
        let _ = child.0.kill();
    }
    let _ = child.0.wait();
    let log_text = read();
    assert!(
        log_text.contains("DEBUG"),
        "the node logged at debug, so the log under test is the verbose one"
    );

    assert!(
        !log_text.contains(PROVIDER_KEY),
        "the provider credential appears in the node's log"
    );
    for (surface, status, headers, text) in &surfaces {
        assert!(
            !headers.contains(PROVIDER_KEY) && !text.contains(PROVIDER_KEY),
            "the provider credential appears in {surface} ({status}):\n{text}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
