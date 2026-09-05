// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND-CONCURRENCY SHED, proven on the real binary: with `limits.max_inbound_concurrent: 2`
//! and eight requests arriving at once, exactly two are admitted and complete, and the other six are
//! SHED IMMEDIATELY with the static at-capacity 503 (`Retry-After: 1`).
//!
//! Driving the shipped process (rather than a router in-proc) is the point: the cap is built once at
//! boot and the data plane then runs a per-worker accept loop over that one router, so "is the cap
//! global or per worker?" and "does an admitted request actually finish?" are questions only a real
//! boot can answer. Both were live regressions — a build that parked over-cap arrivals instead of
//! shedding them left the whole burst hanging, which no unit test on the layer alone had caught.
//!
//! The upstream is a hand-rolled, deliberately SLOW HTTP server: the two admitted requests must be
//! in flight (holding both permits) while the other six arrive, or there is no saturation to observe.
#![cfg(unix)]
// Needs a bootable server with an LLM route to send a real request through; a build without a wire
// codec fail-closes at boot. The shed layer itself is plane-independent.
#![cfg(feature = "proto-llm")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// How long the fake upstream holds each admitted request. Long enough that all eight client
/// connections are established and past admission before the first permit is returned.
const UPSTREAM_HOLD: Duration = Duration::from_secs(3);
/// The admitted requests must finish well inside this; it is the assertion the "admitted but hung"
/// regression fails.
const ADMITTED_BUDGET: Duration = Duration::from_secs(5);
const BURST: usize = 8;
const CAP: usize = 2;

const SHED_BODY: &str = r#"{"error":{"type":"overloaded","message":"The gateway is at capacity. Please retry shortly."}}"#;

#[test]
fn inbound_cap_sheds_the_excess_and_serves_the_admitted() {
    let dir = fixture_dir();
    let upstream_port = spawn_slow_upstream();
    let data_port = free_port();
    let admin_port = free_port();
    write_configs(&dir, data_port, admin_port, upstream_port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("RUST_LOG", "warn")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");

    // Wait for the data listener to answer, failing loud if the process died on the way up.
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

    // The burst: eight requests fired at once, each on its own connection.
    let started = Instant::now();
    let handles: Vec<_> = (0..BURST)
        .map(|_| std::thread::spawn(move || post_chat(data_port)))
        .collect();
    let results: Vec<Response> = handles
        .into_iter()
        .map(|h| h.join().expect("client thread did not panic"))
        .collect();
    let burst_elapsed = started.elapsed();

    let _ = child.kill();
    let _ = child.wait();

    // The contract is a MULTISET over the burst, not a per-request outcome: which two connections
    // win the permits is a race the kernel decides, but HOW MANY win is the operator's cap.
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

    // The admitted requests COMPLETE — the whole burst resolves inside the budget, so no admitted
    // request is silently parked behind the cap it already holds a permit for.
    assert!(
        burst_elapsed < ADMITTED_BUDGET,
        "the admitted requests must complete promptly; the burst took {burst_elapsed:?}"
    );

    // The shed response is a fixed, documented artifact: status, backoff, content type, body.
    for r in &shed {
        assert_eq!(
            r.header("retry-after").as_deref(),
            Some("1"),
            "a shed must name a concrete backoff so a client can retry sanely"
        );
        assert_eq!(
            r.header("content-type").as_deref(),
            Some("application/json"),
            "the shed body is JSON"
        );
        assert_eq!(r.body, SHED_BODY, "the shed body is byte-for-byte fixed");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ── fixture ──────────────────────────────────────────────────────────────────────────────────────

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-inbound-shed-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A free loopback port asked of the OS. The data plane binds a FIXED port on every worker socket,
/// so an ephemeral `:0` in the config would not do.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, upstream_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        format!(
            "mock:\n  protocol: openai\n  base_url: \"http://127.0.0.1:{upstream_port}\"\n  api_key_env: MOCK_KEY\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
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

/// A slow upstream: accepts every connection on its own thread, holds the request for
/// [`UPSTREAM_HOLD`], then answers with a minimal chat completion. The hold is what keeps both
/// admission permits occupied while the rest of the burst arrives.
fn spawn_slow_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            std::thread::spawn(move || {
                // Read just far enough to know a full request arrived: headers, then the declared body.
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

                std::thread::sleep(UPSTREAM_HOLD);
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

// ── raw HTTP client ──────────────────────────────────────────────────────────────────────────────

struct Response {
    /// `0` means the client never got a status line at all — a hang or a dropped connection.
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

/// One chat-completion POST on a FRESH connection (so the burst is eight connections, not eight
/// pipelined requests on one). The read timeout is the hang detector: a request that is parked
/// rather than answered comes back with status `0` and fails the assertions above.
fn post_chat(port: u16) -> Response {
    let body = br#"{"model":"test-model","messages":[{"role":"user","content":"ping"}]}"#;
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return Response {
            status: 0,
            headers: Vec::new(),
            body: String::new(),
        };
    };
    let _ = stream.set_read_timeout(Some(ADMITTED_BUDGET));
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
    let text = String::from_utf8_lossy(raw);
    let Some(split) = text.find("\r\n\r\n") else {
        return Response {
            status: 0,
            headers: Vec::new(),
            body: String::new(),
        };
    };
    let (head, rest) = text.split_at(split);
    let body = rest[4..].to_string();
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Response {
        status,
        headers,
        body,
    }
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}
