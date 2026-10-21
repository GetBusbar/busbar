// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A 1.5.5 DOCUMENT WITH `providers:` AND `models:` AND NO `pools:` SERVES ITS MODELS** (status row
//! 179; docs/design/BUSBAR-1.6.0.md #47: "`models:` stays its own root key beside `pools`, the 1.5.5
//! shape; the llm plane owns both").
//!
//! The previous release required `providers:` and `models:`; `pools:` was optional (v1.5.5
//! crates/busbar/src/config/mod.rs:2626-2632), and a model no pool names was served on its own
//! lane (v1.5.5 crates/busbar/src/ingress/dispatch.rs:292-319). Such a document is the smallest
//! valid 1.5.5 deployment, and a customer running one must see it serve after the upgrade: a POST
//! naming the model reaches the model's provider, and a dialect path hit with another verb answers
//! that dialect's 405 in its own envelope. The oracle's `neutrality|no-pools|surface` cell records
//! the published 1.5.5 on this document.
//!
//! RED (a plane that opens only on a `pools:` the document writes): nothing claims the model paths,
//! so the POST is the residual 404 and the upstream is never reached.
//! GREEN twin: the same document with a pool written serves the same answers, so the harness itself
//! is not what the RED leg reads.

#![cfg(unix)]
// The document writes `providers:`/`models:`, so the build must link the plane door that declares
// `pools:` (`linked_section_pools`): the linked table's answer, never a feature name.
#![cfg(linked_section_pools)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The far end's one answer: a minimal chat completion.
const COMPLETION: &str = r#"{"id":"chatcmpl-nopools","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"served-without-pools"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

fn fixture_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "busbar-no-pools-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The document: one openai provider on the loopback far end, one model on it, and `pools` only
/// when `pools` is `Some` (the GREEN twin).
fn write_configs(dir: &Path, data_port: u16, admin_port: u16, upstream: u16, pools: Option<&str>) {
    std::fs::write(
        dir.join("providers.yaml"),
        format!("p:\n  protocol: openai\n  base_url: \"http://127.0.0.1:{upstream}\"\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:{data_port}\"\nadmin_listen: \"127.0.0.1:{admin_port}\"\n\
             admin_require_mtls: false\nadvanced:\n  allow_destinations: [\"127.0.0.1\"]\n\
             store: {{module: memory}}\nauth:\n  chain: []\n\
             providers:\n  p:\n    api_key: {{ env: CAP_KEY }}\n\
             models:\n  m:\n    provider: p\n{}",
            pools.unwrap_or_default()
        ),
    )
    .unwrap();
}

/// A far end that counts the requests it receives and answers each with [`COMPLETION`].
fn spawn_upstream(count: Arc<AtomicUsize>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let count = Arc::clone(&count);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
                count.fetch_add(1, Ordering::SeqCst);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    COMPLETION.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(COMPLETION.as_bytes());
                let _ = stream.flush();
            });
        }
    });
    port
}

/// Kill the child when the test ends, however it ends.
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One raw HTTP/1.1 exchange: the status and the body, or `None` when no connection was made.
fn exchange(
    port: u16,
    method: &str,
    path: &str,
    headers: &str,
    body: &str,
) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .ok()?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let body = text
        .split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .to_string();
    Some((status, body))
}

fn log_of(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
}

/// `body` as JSON with the per-request id masked.
fn masked(body: &str) -> serde_json::Value {
    let mut v: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("a JSON body ({e}): {body}"));
    if v.get("request_id").is_some() {
        v["request_id"] = serde_json::json!("<ID>");
    }
    v
}

/// Boot the document (`pools` written or not) and require the 1.5.5 surface: the POST served by the
/// far end, and each dialect path's 405 for another verb in that dialect's envelope.
fn serves_its_models(tag: &str, pools: Option<&str>) {
    let dir = fixture_dir(tag);
    let received = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_upstream(Arc::clone(&received));
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data_port, admin_port, upstream, pools);
    let log = std::fs::File::create(dir.join("out.log")).unwrap();
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("CAP_KEY", "oracle-cred-no-pools-0001")
            .env("RUST_LOG", "warn")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );

    // The data listener is up once it answers anything.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!("busbar exited ({status:?}); log:\n{}", log_of(&dir));
        }
        if exchange(data_port, "GET", "/healthz", "", "").is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the data listener never answered; log:\n{}",
            log_of(&dir)
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // The POST naming the model is served by the model's provider.
    let json = "Content-Type: application/json\r\n";
    let chat = r#"{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#;
    let (status, body) =
        exchange(data_port, "POST", "/v1/chat/completions", json, chat).expect("answers");
    assert_eq!(
        status,
        200,
        "{tag}: POST /v1/chat/completions for a configured model must be served: {body}; log:\n{}",
        log_of(&dir)
    );
    assert!(
        body.contains("served-without-pools"),
        "{tag}: the far end's answer must come back: {body}"
    );
    assert!(
        received.load(Ordering::SeqCst) >= 1,
        "{tag}: the far end was never reached"
    );

    // The chat path read: the openai dialect's 405 (v1.5.5 crates/busbar/src/ingress/dispatch.rs
    // :311-318), in that dialect's envelope.
    let (status, body) =
        exchange(data_port, "GET", "/v1/chat/completions", "", "").expect("answers");
    assert_eq!(status, 405, "{tag}: GET /v1/chat/completions: {body}");
    assert_eq!(
        masked(&body),
        serde_json::json!({"error": {"code": null, "message": "method not allowed for this resource",
            "param": null, "type": "invalid_request_error"}}),
        "{tag}: the openai 405 envelope"
    );

    // The messages path deleted: the anthropic dialect's 405, in its envelope (the bytes the
    // `neutrality|models-empty|surface` golden records for the same request).
    let (status, body) = exchange(data_port, "DELETE", "/v1/messages", "", "").expect("answers");
    assert_eq!(status, 405, "{tag}: DELETE /v1/messages: {body}");
    assert_eq!(
        masked(&body),
        serde_json::json!({"error": {"message": "method not allowed for this resource",
            "type": "invalid_request_error"}, "request_id": "<ID>", "type": "error"}),
        "{tag}: the anthropic 405 envelope"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// RED on a build whose llm plane opens only on a written `pools:`.
#[test]
fn a_1_5_5_document_with_models_and_no_pools_serves_them() {
    serves_its_models("no-pools", None);
}

/// GREEN twin: the same document with a pool written.
#[test]
fn the_same_document_with_a_pool_written_serves_them_too() {
    serves_its_models(
        "with-pool",
        Some("pools:\n  chat:\n    members:\n      - model: m\n"),
    );
}
