// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Bounds the wait for every burst arrival to be accounted for; only a broken
/// cap (or a hung gateway) ever reaches it.
const SETTLE: Duration = Duration::from_secs(30);

const ADMITTED_BUDGET: Duration = Duration::from_secs(5);
const BURST: usize = 8;
const CAP: usize = 2;

const SHED_BODY: &str = r#"{"error":{"type":"rate_limit_error","message":"The gateway is at capacity. Please retry shortly.","param":null,"code":null}}"#;

#[test]
fn inbound_cap_sheds_the_excess_and_serves_the_admitted() {
    let dir = fixture_dir();
    let upstream = Arc::new(Upstream::default());
    let upstream_port = spawn_held_upstream(Arc::clone(&upstream));
    let data_port = free_port();
    let admin_port = free_port();
    write_configs(&dir, data_port, admin_port, upstream_port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("RUST_LOG", "warn")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");

    let mut booted = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?}); log:\n{}",
                read_log(&log_path)
            );
        }
        if healthz_ok(data_port) {
            booted = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        booted,
        "busbar did not start answering on {data_port} within 30s; log:\n{}",
        read_log(&log_path)
    );

    // The upstream holds every admitted request until each burst arrival is
    // accounted for (answered, or held upstream), so no admitted request can
    // finish and free a slot for a later arrival before the cap is judged.
    let started = Instant::now();
    let (answered_tx, answered) = mpsc::channel();
    let handles: Vec<_> = (0..BURST)
        .map(|_| {
            let answered_tx = answered_tx.clone();
            std::thread::spawn(move || {
                let _ = answered_tx.send(post_chat(data_port));
            })
        })
        .collect();
    drop(answered_tx);
    let mut results: Vec<Response> = Vec::with_capacity(BURST);
    let settle = Instant::now() + SETTLE;
    while results.len() + upstream.held.load(Ordering::SeqCst) < BURST && Instant::now() < settle {
        if let Ok(response) = answered.recv_timeout(Duration::from_millis(10)) {
            results.push(response);
        }
    }
    upstream.release();
    results.extend(answered.iter());
    for h in handles {
        h.join().expect("client thread did not panic");
    }
    let burst_elapsed = started.elapsed();

    let _ = child.kill();
    let _ = child.wait();

    let admitted: Vec<&Response> = results.iter().filter(|r| r.status == 200).collect();
    let shed: Vec<&Response> = results.iter().filter(|r| r.status == 503).collect();
    let other: Vec<u16> = results
        .iter()
        .map(|r| r.status)
        .filter(|s| *s != 200 && *s != 503)
        .collect();
    assert!(
        other.is_empty(),
        "the burst produced statuses outside the cap's vocabulary: {other:?} (0 = the client never \
         got a response line at all, i.e. a hang); log:\n{}",
        read_log(&log_path)
    );
    assert_eq!(
        admitted.len(),
        CAP,
        "exactly the configured cap must be admitted, got {} admitted / {} shed",
        admitted.len(),
        shed.len()
    );
    assert_eq!(
        shed.len(),
        BURST - CAP,
        "every arrival over the cap must be shed, got {} admitted / {} shed",
        admitted.len(),
        shed.len()
    );

    assert!(
        burst_elapsed < ADMITTED_BUDGET,
        "the admitted requests must complete promptly; the burst took {burst_elapsed:?}"
    );

    for r in &shed {
        assert_eq!(
            r.header("retry-after").as_deref(),
            Some("1"),
            "a shed must name a concrete backoff so a client can retry sanely; headers={:?}, body={:?}",
            r.headers,
            r.body
        );
        assert_eq!(
            r.header("content-type").as_deref(),
            Some("application/json"),
            "the shed body is JSON"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&r.body).expect("valid refusal JSON"),
            serde_json::from_str::<serde_json::Value>(SHED_BODY).unwrap(),
            "the selected plane renders the complete native refusal envelope"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("busbar-inbound-shed-{}-{}", std::process::id(), {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{}-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
            line!(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, upstream_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        format!("mock:\n  protocol: openai\n  base_url: \"http://127.0.0.1:{upstream_port}\"\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
advanced:
  allow_destinations: ["127.0.0.1"]
store: {{module: memory}}
admin_require_mtls: false
auth:
  chain: []
limits:
  max_inbound_concurrent: {CAP}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#
        ),
    )
    .unwrap();
}

/// An upstream that holds each request it is sent until the test releases it.
#[derive(Default)]
struct Upstream {
    held: AtomicUsize,
    gate: (Mutex<bool>, Condvar),
}

impl Upstream {
    fn hold(&self) {
        self.held.fetch_add(1, Ordering::SeqCst);
        let (open, cv) = &self.gate;
        let mut open = open.lock().unwrap_or_else(|e| e.into_inner());
        while !*open {
            open = cv.wait(open).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn release(&self) {
        let (open, cv) = &self.gate;
        *open.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_all();
    }
}

fn spawn_held_upstream(upstream: Arc<Upstream>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let upstream = Arc::clone(&upstream);
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

                upstream.hold();
                let payload = br#"{"id":"chatcmpl-test","object":"chat.completion","created":0,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(payload);
                let _ = stream.flush();
            });
        }
    });
    port
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }
}

fn healthz_ok(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    if stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    buf.starts_with("HTTP/1.1 200")
}

fn post_chat(port: u16) -> Response {
    let body = br#"{"model":"test-model","messages":[{"role":"user","content":"ping"}]}"#;
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return Response {
            status: 0,
            headers: Vec::new(),
            body: String::new(),
        };
    };
    let _ = stream.set_read_timeout(Some(SETTLE));
    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();

    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Response {
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Response {
            status: 0,
            headers: Vec::new(),
            body: String::new(),
        };
    };
    let head = std::str::from_utf8(&raw[..split]).expect("response headers are UTF-8");
    let body = &raw[split + 4..];
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let encodings: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name == "transfer-encoding")
        .flat_map(|(_, value)| {
            value
                .split(',')
                .map(|coding| coding.trim().to_ascii_lowercase())
        })
        .collect();
    let body = if encodings.is_empty() {
        body.to_vec()
    } else {
        assert_eq!(encodings, ["chunked"], "unsupported transfer coding");
        decode_chunks(body).expect("complete, valid chunked response framing")
    };
    Response {
        status,
        headers,
        body: String::from_utf8(body).expect("response JSON is UTF-8"),
    }
}

fn decode_chunks(mut wire: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut body = Vec::new();
    loop {
        let end = wire
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("missing chunk size")?;
        let size = wire[..end]
            .split(|b| *b == b';')
            .next()
            .ok_or("missing size")?;
        if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
            return Err("invalid chunk size");
        }
        let size =
            usize::from_str_radix(std::str::from_utf8(size).map_err(|_| "invalid size")?, 16)
                .map_err(|_| "chunk size overflow")?;
        wire = &wire[end + 2..];
        if size == 0 {
            loop {
                let end = wire
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .ok_or("incomplete trailers")?;
                if end == 0 {
                    return if wire.len() == 2 {
                        Ok(body)
                    } else {
                        Err("bytes after final chunk")
                    };
                }
                if !wire[..end].contains(&b':') {
                    return Err("invalid trailer");
                }
                wire = &wire[end + 2..];
            }
        }
        let chunk = wire.get(..size).ok_or("truncated chunk")?;
        let rest = wire.get(size..).ok_or("truncated chunk")?;
        if !rest.starts_with(b"\r\n") {
            return Err("missing chunk delimiter");
        }
        body.extend_from_slice(chunk);
        wire = &rest[2..];
    }
}

#[test]
fn response_parser_preserves_chunked_json_and_rejects_truncated_framing() {
    let response = parse_response(b"HTTP/1.1 503 Service Unavailable\r\nTransfer-Encoding: Chunked\r\nContent-Type: application/json\r\n\r\n3;fixture=yes\r\n{\"e\r\n4\r\n\":1}\r\n0\r\nTrace: test\r\n\r\n");
    assert_eq!(response.status, 503);
    assert_eq!(
        response.header("content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(response.body, r#"{"e":1}"#);
    for malformed in [
        b"3\r\n{}".as_slice(),
        b"2\r\n{}XX0\r\n\r\n",
        b"2\r\n{}\r\n",
        b"0\r\n",
        b"0\r\n\r\nextra",
        b"+2\r\n{}\r\n0\r\n\r\n",
        b"FFFFFFFFFFFFFFFFFFFFFFFF\r\n",
    ] {
        assert!(
            decode_chunks(malformed).is_err(),
            "must reject {malformed:?}"
        );
    }
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}
