// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An apply builds the door's model serving and reach from the NEW projection: a reload that moves a
//! model to another provider and serves it through another pool reaches the new upstream, and the
//! boot-time upstream hears nothing after the apply (DIET-BUSBAR MR3 characterisation).

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use busbar_contract::json::{self, JsonValueTrait};

const ADMIN_TOKEN: &str = "apply-serves-new-providers-admin";

fn far_end(text: &'static str) -> (u16, Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the far end");
    let port = listener.local_addr().unwrap().port();
    let (heard, hears) = mpsc::channel();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let heard = heard.clone();
            std::thread::spawn(move || {
                if common::upstream::read_request(&mut conn).is_some() {
                    let _ = heard.send(());
                    let answer = json::json!({
                        "id": "msg_apply", "type": "message", "role": "assistant",
                        "model": "m", "content": [{"type": "text", "text": text}],
                        "stop_reason": "end_turn", "stop_sequence": null,
                        "usage": {"input_tokens": 3, "output_tokens": 1}
                    });
                    common::upstream::respond(&mut conn, 200, &answer);
                }
            });
        }
    });
    (port, hears)
}

fn write_configs(dir: &Path, provider: &str, upstream: u16, pool: &str, data: u16, admin: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        format!(
            "{provider}:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:{upstream}\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data}"
admin_listen: "127.0.0.1:{admin}"
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
  {provider}:
    api_key: {{ env: APPLY_KEY }}
models:
  m:
    provider: {provider}
pools:
  {pool}:
    members:
      - model: m
"#,
            signing = dir.join("signing.key").display()
        ),
    )
    .unwrap();
}

fn http(addr: &str, path: &str, body: Option<&str>, token: &str) -> (u16, String) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");
        let mut req = client
            .post(format!("http://{addr}{path}"))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json")
                .body(b.to_string());
        }
        let resp = req.send().await.expect("request");
        (
            resp.status().as_u16(),
            resp.text().await.unwrap_or_default(),
        )
    })
}

fn call(data: &str, token: &str, model: &str, path: &str) -> (u16, String) {
    let body = format!(
        r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
    );
    http(data, path, Some(&body), token)
}

#[test]
fn an_apply_serves_the_new_providers_and_pools_not_the_boot_ones() {
    let (boot_port, boot_heard) = far_end("boot");
    let (next_port, next_heard) = far_end("applied");
    let dir = std::env::temp_dir().join(format!(
        "busbar-apply-new-providers-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let key = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(key.status.success(), "--generate-signing-key");
    std::fs::write(dir.join("signing.key"), &key.stdout).unwrap();
    let ports = (common::boot::free_port(), common::boot::free_port());
    let (data, admin) = ports;
    write_configs(&dir, "first", boot_port, "boot-pool", data, admin);
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env_remove("BUSBAR_PROVIDERS")
        .env("APPLY_KEY", "x")
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
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
    let deadline = Instant::now() + Duration::from_secs(60);
    while !(common::boot::healthz_answers(data) && common::boot::healthz_answers(admin)) {
        assert!(
            child.0.try_wait().expect("try_wait").is_none(),
            "busbar exited before listening"
        );
        assert!(Instant::now() < deadline, "busbar did not listen in 60s");
        std::thread::sleep(Duration::from_millis(50));
    }
    let (data, admin) = (format!("127.0.0.1:{data}"), format!("127.0.0.1:{admin}"));
    let (status, minted) = http(
        &admin,
        "/api/v1/admin/keys",
        Some(r#"{"name":"apply"}"#),
        ADMIN_TOKEN,
    );
    assert_eq!(
        status, 201,
        "the admin API created the caller's key: {minted}"
    );
    let minted = json::parse_value(minted.as_bytes()).expect("the minted key");
    let token = minted["token"]
        .as_str()
        .expect("a minted token")
        .to_string();

    let (status, text) = call(&data, &token, "m", "/m/v1/messages");
    assert_eq!(status, 200, "boot serves the boot provider: {text}");
    assert!(text.contains("boot"), "{text}");
    let (status, text) = call(&data, &token, "boot-pool", "/v1/messages");
    assert_eq!(status, 200, "boot serves the boot pool: {text}");
    while boot_heard.try_recv().is_ok() {}

    write_configs(&dir, "second", next_port, "applied-pool", ports.0, ports.1);
    let (status, body) = http(&admin, "/api/v1/admin/config/reload", None, ADMIN_TOKEN);
    assert!(
        (200..300).contains(&status),
        "the reload applies: {status} {body}"
    );

    let (status, text) = call(&data, &token, "m", "/m/v1/messages");
    assert_eq!(status, 200, "the apply serves the new provider: {text}");
    assert!(
        text.contains("applied"),
        "the model reached the applied upstream: {text}"
    );
    let (status, text) = call(&data, &token, "applied-pool", "/v1/messages");
    assert_eq!(status, 200, "the apply serves the new pool: {text}");
    assert!(
        text.contains("applied"),
        "the pool reached the applied upstream: {text}"
    );
    assert!(
        next_heard.try_recv().is_ok(),
        "the applied upstream heard the calls"
    );
    assert!(
        boot_heard.try_recv().is_err(),
        "the boot upstream hears nothing after the apply"
    );
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
