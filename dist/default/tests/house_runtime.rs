// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! H01/H02 and the unauthorized-request slice of H03, through the actual executable.
//! The fixture producer supplies the approved configuration and signed plugin cohort;
//! this test never composes an App, installs a test host, or grants plugin admission.
//! H04 settlement requires the real journal/finalizer evidence and is not inferred here.

#![cfg(unix)]

use busbar_contract::json::{self, JsonValueTrait};

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const ANSWER: &str = r#"{"id":"house-response","object":"chat.completion","created":0,"model":"house-model","choices":[{"index":0,"message":{"role":"assistant","content":"house-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
const EVENTS: &str = "data: {\"id\":\"house-response\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"house-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"house-ok\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"house-response\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"house-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\ndata: [DONE]\n\n";

struct Product {
    child: Child,
    config: PathBuf,
}

#[derive(serde::Deserialize)]
struct PilotConfig {
    plugins: busbar_kernel::config::PluginsCfg,
}

impl Drop for Product {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
    }
}

fn required_path(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| {
        panic!("fixture prerequisite missing: {name}; this is not an executed behavior failure")
    }));
    assert!(
        path.is_absolute() && path.exists(),
        "{name} must exist at an absolute path"
    );
    path
}

fn record_hash(path: &Path) {
    let bytes = std::fs::read(path).expect("read exact cohort bytes");
    println!(
        "HOUSE_ARTIFACT {} {}",
        busbar_plugin_loader::sign::sha256_hex(&bytes),
        path.display()
    );
}

#[tokio::test]
async fn house_actual_binary_memory_request_and_unauthorized_refusal() {
    let binary = required_path("BUSBAR_TEST_PRODUCT_BIN");
    let fixture = required_path("BUSBAR_HOUSE_FIXTURE");
    let token = std::fs::read_to_string(fixture.join("client-token"))
        .expect("the fixture producer supplies the valid client credential");
    assert!(
        !token.trim().is_empty(),
        "the fixture credential is nonempty"
    );
    record_hash(&binary);
    let mut archives = 0;
    for entry in std::fs::read_dir(fixture.join("plugins")).expect("signed pilot plugins") {
        let path = entry.expect("plugin directory entry").path();
        if path.to_string_lossy().ends_with(".tar.gz") {
            record_hash(&path);
            archives += 1;
        }
    }
    assert!(
        archives > 0,
        "the actual signed pilot cohort must be present"
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let streaming = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mode = streaming.clone();
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move |body: axum::body::Bytes| {
            let observed = observed.clone();
            let mode = mode.clone();
            async move {
                let request = json::parse_value(&body).expect("the upstream receives valid JSON");
                assert_eq!(request["model"].as_str(), Some("house-model"));
                assert_eq!(
                    request["messages"][0]["content"].as_str(),
                    Some("house-input")
                );
                assert_eq!(
                    request["stream"].as_bool().unwrap_or(false),
                    mode.load(Ordering::SeqCst) == 1
                );
                observed.fetch_add(1, Ordering::SeqCst);
                if mode.load(Ordering::SeqCst) == 0 {
                    ([("content-type", "application/json")], ANSWER)
                } else {
                    ([("content-type", "text/event-stream")], EVENTS)
                }
            }
        }),
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    // Only the upstream is a fixture server. The engine is always a separate product process.
    let data = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let admin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let data_address = data.local_addr().unwrap();
    let admin_address = admin.local_addr().unwrap();
    let template = std::fs::read_to_string(fixture.join("config.template.yaml"))
        .expect("approved native Memory configuration from the cohort producer");
    let mut config = template;
    for (marker, value) in [
        ("@DATA_ADDRESS@", data_address.to_string()),
        ("@ADMIN_ADDRESS@", admin_address.to_string()),
        ("@UPSTREAM_URL@", format!("http://{upstream_address}")),
        ("@FIXTURE_DIR@", fixture.display().to_string()),
    ] {
        assert!(
            config.contains(marker),
            "configuration template must contain {marker}"
        );
        config = config.replace(marker, &value);
    }
    let policy: PilotConfig = busbar_contract::yaml::from_str(&config)
        .expect("the pilot explicitly configures its signed plugin admission policy");
    assert!(
        policy.plugins.enabled,
        "the pilot loads its supplied plugins"
    );
    assert!(
        !policy.plugins.trust.allow_unsigned,
        "the house fixture must not bypass signature verification"
    );
    assert_eq!(
        Path::new(&policy.plugins.dir),
        fixture.join("plugins"),
        "the product must consume the exact hashed pilot directory"
    );
    let config_path = fixture.join(format!("house-config-{}.yaml", std::process::id()));
    std::fs::write(&config_path, config).unwrap();
    record_hash(&config_path);
    drop((data, admin));
    let mut product = Product {
        child: Command::new(&binary)
            .current_dir(&fixture)
            .env("BUSBAR_CONFIG", &config_path)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("launch the actual distributable"),
        config: config_path,
    };
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            product.child.try_wait().unwrap().is_none(),
            "actual product exited before readiness"
        );
        if client
            .get(format!("http://{data_address}/healthz"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "actual product readiness deadline"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let url = format!("http://{data_address}/v1/chat/completions");
    let request = r#"{"model":"house-model","messages":[{"role":"user","content":"house-input"}],"stream":false}"#;
    let denied = client
        .post(&url)
        .header("content-type", "application/json")
        .body(request)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "unauthorized input must never reach upstream"
    );
    for (mode, body) in [
        (0, request.to_owned()),
        (1, request.replace("false", "true")),
    ] {
        streaming.store(mode, Ordering::SeqCst);
        let response = client
            .post(&url)
            .bearer_auth(token.trim())
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body = response.text().await.unwrap();
        if mode == 0 {
            let value = json::parse_value(body.as_bytes()).expect("valid client JSON response");
            assert_eq!(
                value["choices"][0]["message"]["content"].as_str(),
                Some("house-ok")
            );
            assert_eq!(value["model"].as_str(), Some("house-model"));
            assert_eq!(value["usage"]["total_tokens"].as_u64(), Some(2));
        } else {
            assert!(
                body.contains("house-ok"),
                "the stream carries upstream content"
            );
            assert!(
                body.contains("data: [DONE]"),
                "the stream reaches its terminal event"
            );
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            mode + 1,
            "exactly one real upstream call per accepted request"
        );
    }
    let signaled = Command::new("kill")
        .args(["-TERM", &product.child.id().to_string()])
        .status()
        .unwrap();
    assert!(signaled.success(), "request normal product shutdown");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = product.child.try_wait().unwrap() {
            assert!(status.success(), "clean product termination: {status}");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "bounded normal shutdown"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "no delayed forbidden or duplicate upstream call before shutdown"
    );
    let _ = stop.send(());
    upstream_task.await.unwrap();
    println!("HOUSE_PROCESS_REQUEST_AND_UNAUTHORIZED_ASSERTIONS_COMPLETE");
}
