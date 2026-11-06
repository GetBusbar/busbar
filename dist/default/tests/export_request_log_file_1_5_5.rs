// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const GOLDEN: &str = include_str!(
    "../../../testing/shadow-oracle/golden/1.5.5/cells/export__request-log-file__jsonl.json"
);

fn golden_line() -> String {
    let cell: serde_json::Value = serde_json::from_str(GOLDEN).expect("the golden cell parses");
    cell["body"]["json"]["steps"]
        .as_array()
        .expect("the cell's steps")
        .iter()
        .find(|s| s.get("read_file").is_some())
        .and_then(|s| s["body"].as_str())
        .expect("the cell read the file")
        .to_string()
}

fn masked_record(text: &str) -> serde_json::Value {
    fn mask(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(fields) => {
                for (key, value) in fields {
                    if ["latency_ms", "as_of", "ts"].contains(&key.as_str()) {
                        assert!(
                            value.is_number(),
                            "the volatile field {key} must be numeric"
                        );
                        *value = serde_json::Value::String(format!("<{key}>"));
                    } else {
                        mask(value);
                    }
                }
            }
            serde_json::Value::Array(values) => values.iter_mut().for_each(mask),
            _ => {}
        }
    }
    let mut value =
        serde_json::from_str(text).expect("each request-log line is a complete JSON value");
    mask(&mut value);
    value
}

fn golden_record() -> serde_json::Value {
    let mut text = golden_line();
    for key in ["latency_ms", "as_of", "ts"] {
        text = text.replace(&format!(":<{key}>"), &format!(":\"<{key}>\""));
    }
    serde_json::from_str(&text).expect("the golden record's known numeric placeholders parse")
}

fn upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the upstream");
    let port = listener.local_addr().expect("its address").port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || answer(stream));
        }
    });
    port
}

fn answer(stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0; length];
    let _ = reader.read_exact(&mut body);
    let reply = r#"{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m-cap","choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{reply}",
        reply.len()
    );
}

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-request-log-file-{}-{}",
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

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, upstream: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        format!("p:\n  protocol: openai\n  base_url: \"http://127.0.0.1:{upstream}\"\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
admin_require_mtls: false
advanced:
  allow_destinations: ["127.0.0.1"]
store: {{module: memory}}
auth:
  chain: []
providers:
  p:
    api_key: {{ env: CAP_KEY }}
models:
  m-cap:
    provider: p
export:
  al:
    module: request-log-file
    settings: {{ path: '{audit}' }}
"#,
            audit = dir.join("audit.jsonl").display()
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

fn exchange(port: u16, request: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw);
    text.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

fn log_of(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
}

#[test]
fn the_request_log_file_holds_the_1_5_5_line_byte_for_byte() {
    let dir = fixture_dir();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data_port, admin_port, upstream());
    let log = std::fs::File::create(dir.join("out.log")).unwrap();
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("CAP_KEY", "oracle-cred-export-file-0001")
            .env("RUST_LOG", "warn")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );

    let body = r#"{"model":"m-cap","messages":[{"role":"user","content":"ping"}]}"#;
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let audit = dir.join("audit.jsonl");
    let golden = golden_record();

    for n in 1..=2 {
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.0.try_wait().expect("try_wait") {
                panic!("busbar exited ({status:?}); log:\n{}", log_of(&dir));
            }
            if let Some(status) = exchange(data_port, &request) {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "the data listener never answered; log:\n{}",
                log_of(&dir)
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(status, 200, "log:\n{}", log_of(&dir));

        let deadline = Instant::now() + Duration::from_secs(10);
        let written = loop {
            let bytes = std::fs::read(&audit).unwrap_or_default();
            if bytes.iter().filter(|b| **b == b'\n').count() >= n {
                break bytes;
            }
            assert!(
                Instant::now() < deadline,
                "the request-log file sink never wrote request {n}'s line; log:\n{}",
                log_of(&dir)
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        let written = String::from_utf8(written).expect("the file is UTF-8");
        let records = written
            .strip_suffix('\n')
            .expect("every request-log record ends with a newline")
            .split('\n')
            .collect::<Vec<_>>();
        assert_eq!(records.len(), n, "exactly one complete record per request");
        for record in records {
            assert_eq!(
                masked_record(record),
                golden,
                "the complete request-log value must match the golden, including exact numbers"
            );
        }
    }
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_reload_moves_the_open_file_exporter_and_can_move_it_back() {
    const TOKEN: &str = "file-refresh-admin";
    let dir = fixture_dir();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, data_port, admin_port, upstream());
    let key = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .unwrap();
    assert!(key.status.success());
    let key_path = dir.join("signing.key");
    std::fs::write(&key_path, key.stdout).unwrap();
    let config_path = dir.join("config.yaml");
    let mut config = std::fs::read_to_string(&config_path).unwrap().replace(
        "auth:\n  chain: []\n",
        &format!(
            "auth:\n  chain: []\n  signing_key: {{ file: '{}' }}\n  admin_auth: [admin-tokens]\n",
            key_path.display()
        ),
    );
    config.push_str("identity-providers:\n  admin-tokens:\n    module: admin-tokens\n    token: { env: BUSBAR_ADMIN_TOKEN }\n");
    std::fs::write(&config_path, &config).unwrap();
    let log = std::fs::File::create(dir.join("out.log")).unwrap();
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", &config_path)
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("BUSBAR_ADMIN_TOKEN", TOKEN)
            .env("CAP_KEY", "export-reload-provider")
            .env("RUST_LOG", "warn")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let a = dir.join("audit.jsonl");
    let b = dir.join("after-reload.jsonl");
    let body = r#"{"model":"m-cap","messages":[{"role":"user","content":"ping"}]}"#;
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let reload = format!(
        "POST /api/v1/admin/config/reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let mut before_move = Vec::new();
    let mut after_move = Vec::new();
    for (step, destination, count) in [(0, &a, 1), (1, &b, 1), (2, &a, 2)] {
        if step != 0 {
            let next = config.replace(&a.display().to_string(), &destination.display().to_string());
            std::fs::write(&config_path, next).unwrap();
            assert_eq!(exchange(admin_port, &reload), Some(200), "{}", log_of(&dir));
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            assert!(child.0.try_wait().unwrap().is_none(), "{}", log_of(&dir));
            if let Some(status) = exchange(data_port, &request) {
                break status;
            }
            assert!(Instant::now() < deadline, "{}", log_of(&dir));
            std::thread::sleep(Duration::from_millis(25));
        };
        assert_eq!(status, 200, "{}", log_of(&dir));
        let deadline = Instant::now() + Duration::from_secs(10);
        let written = loop {
            let written = std::fs::read(destination).unwrap_or_default();
            if written.iter().filter(|byte| **byte == b'\n').count() == count {
                break written;
            }
            assert!(
                Instant::now() < deadline,
                "reload did not move the real disk destination: {}",
                log_of(&dir)
            );
            std::thread::sleep(Duration::from_millis(25));
        };
        match step {
            0 => before_move = written,
            1 => {
                assert_eq!(std::fs::read(&a).unwrap(), before_move);
                after_move = written;
            }
            _ => assert_eq!(std::fs::read(&b).unwrap(), after_move),
        }
    }
    drop(child);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_mask_replaces_only_the_masked_numbers() {
    let record =
        masked_record(r#"{"a":9007199254740993,"latency_ms":12,"ts":1700000000.5,"x":"ts"}"#);
    assert_eq!(
        record,
        serde_json::from_str::<serde_json::Value>(
            r#"{"x":"ts","ts":"<ts>","a":9007199254740993,"latency_ms":"<latency_ms>"}"#
        )
        .unwrap()
    );
    assert_ne!(record["a"], serde_json::json!(9007199254740992_u64));
}
