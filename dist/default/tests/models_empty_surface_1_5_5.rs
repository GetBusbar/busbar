// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const GOLDEN: &str = include_str!(
    "../../../testing/shadow-oracle/golden/1.5.5/cells/neutrality__models-empty__surface.json"
);

fn golden(request: &str) -> (u16, serde_json::Value) {
    let cell: serde_json::Value = serde_json::from_str(GOLDEN).expect("the golden cell parses");
    let step = cell["body"]["json"]["steps"]
        .as_array()
        .expect("the cell's steps")
        .iter()
        .find(|s| s["request"] == request && s["status"] != 401)
        .unwrap_or_else(|| panic!("the cell records `{request}`"));
    (
        u16::try_from(step["status"].as_u64().expect("a status")).expect("a u16"),
        step["body"]["json"].clone(),
    )
}

fn fixture_dir() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "busbar-models-empty-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn cell_providers() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/shadow-oracle/cells.json"
    );
    let cells: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("the oracle's cells"))
            .expect("the cells parse");
    let cell = cells["cells"]
        .as_array()
        .expect("the cell list")
        .iter()
        .find(|c| c["id"] == CELL)
        .unwrap_or_else(|| panic!("the oracle holds `{CELL}`"));
    cell["capture"]["providers"]
        .as_str()
        .expect("the cell's provider catalog")
        .replace("{CAPTURE_URL}", "http://127.0.0.1:9")
}

const CELL: &str = "neutrality|models-empty|surface";

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(dir.join("providers.yaml"), cell_providers()).unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:{data_port}\"\nadmin_listen: \"127.0.0.1:{admin_port}\"\n\
             admin_require_mtls: false\nstore: {{module: memory}}\nauth:\n  chain: []\n\
             providers:\n  p:\n    api_key: {{ env: CAP_KEY }}\nmodels: {{}}\n"
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

fn exchange(
    port: u16,
    method: &str,
    path: &str,
    headers: &str,
    body: &str,
) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
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

fn masked(body: &str) -> serde_json::Value {
    let mut v: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("a JSON body ({e}): {body}"));
    if v.get("request_id").is_some() {
        v["request_id"] = serde_json::json!("<ID>");
    }
    v
}

#[test]
fn a_document_writing_models_empty_answers_with_the_1_5_5_bytes() {
    let dir = fixture_dir();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data_port, admin_port);
    let log = std::fs::File::create(dir.join("out.log")).unwrap();
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("CAP_KEY", "oracle-cred-models-empty-0001")
            .env("RUST_LOG", "warn")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );
    let json = "Content-Type: application/json\r\n";
    let chat = r#"{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#;

    let deadline = Instant::now() + Duration::from_secs(30);
    let (status, body) = loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!("busbar exited ({status:?}); log:\n{}", log_of(&dir));
        }
        if let Some(answer) = exchange(data_port, "POST", "/v1/chat/completions", json, chat) {
            break answer;
        }
        assert!(
            Instant::now() < deadline,
            "the data listener never answered; log:\n{}",
            log_of(&dir)
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(
        (status, masked(&body)),
        golden("POST /v1/chat/completions"),
        "the unknown model's 404, as 1.5.5 wrote it; log:\n{}",
        log_of(&dir)
    );

    let (status, body) = exchange(data_port, "POST", "/v1/messages", json, chat).expect("answers");
    assert_eq!((status, masked(&body)), golden("POST /v1/messages"));

    let (status, body) = exchange(data_port, "DELETE", "/v1/messages", "", "").expect("answers");
    assert_eq!((status, masked(&body)), golden("DELETE /v1/messages"));

    let (status, body) =
        exchange(data_port, "GET", "/v1/chat/completions", "", "").expect("answers");
    assert_eq!(status, 405, "{body}");
    assert_eq!(
        masked(&body),
        serde_json::json!({"error": {"code": null, "message": "method not allowed for this resource",
            "param": null, "type": "invalid_request_error"}}),
    );

    let (status, body) = exchange(data_port, "GET", "/v2/nothing", "", "").expect("answers");
    assert_eq!((status, masked(&body)), golden("GET /v2/nothing"));
}
