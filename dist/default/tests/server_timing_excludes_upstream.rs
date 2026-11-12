// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `Server-Timing: busbar;dur=<ms>` is Busbar's OWN added latency (1.5.5's meaning): the request's
//! total wall-clock MINUS the upstream round trip. Proven on the shipped binary through the real
//! listener, plane driver and egress, against an upstream that answers after a fixed delay: the
//! forwarded request's `dur` stays far below that delay, a request that never went upstream reports
//! its full (non-zero) processing time, and with the header off it is absent from both.

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// How long the upstream holds every request before answering. Busbar's own work on a forwarded
/// request is a few milliseconds; the bound below leaves half the delay for a loaded debug build.
const UPSTREAM_DELAY: Duration = Duration::from_millis(1000);

const OWN_TIME_BOUND_MS: f64 = 500.0;

#[test]
fn server_timing_reports_busbars_own_time_excluding_the_upstream_round_trip() {
    let upstream_port = spawn_delayed_upstream();
    let gateway = Gateway::boot(upstream_port, true);

    let started = Instant::now();
    let chat = post_chat(gateway.data_port);
    let observed = started.elapsed();
    assert_eq!(chat.status, 200, "{}", gateway.diagnose(&chat));
    assert!(
        observed >= UPSTREAM_DELAY,
        "the upstream delay must be on the request's path: answered in {observed:?}"
    );
    let dur = chat.dur().unwrap_or_else(|| {
        panic!(
            "a forwarded response carries Server-Timing when enabled: {}",
            gateway.diagnose(&chat)
        )
    });
    assert!(
        dur > 0.0 && dur < OWN_TIME_BOUND_MS,
        "busbar;dur must exclude the {UPSTREAM_DELAY:?} upstream round trip (0 < dur < \
         {OWN_TIME_BOUND_MS} ms), got dur={dur} ms for a request answered in {observed:?}"
    );

    let started = Instant::now();
    let health = get(gateway.data_port, "/healthz");
    let observed_ms = started.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(health.status, 200, "{}", gateway.diagnose(&health));
    let dur = health
        .dur()
        .unwrap_or_else(|| panic!("/healthz carries Server-Timing when enabled: {health:?}"));
    assert!(
        dur > 0.0 && dur <= observed_ms,
        "a request with no upstream call reports its full processing time (0 < dur <= the \
         {observed_ms:.3} ms the client observed), got dur={dur}"
    );
}

#[test]
fn server_timing_is_absent_when_off() {
    let upstream_port = spawn_delayed_upstream();
    let gateway = Gateway::boot(upstream_port, false);

    let chat = post_chat(gateway.data_port);
    assert_eq!(chat.status, 200, "{}", gateway.diagnose(&chat));
    assert_eq!(
        chat.header("server-timing"),
        None,
        "no Server-Timing on a forwarded response when off"
    );
    let health = get(gateway.data_port, "/healthz");
    assert_eq!(health.status, 200, "{}", gateway.diagnose(&health));
    assert_eq!(
        health.header("server-timing"),
        None,
        "no Server-Timing on /healthz when off"
    );
}

struct Gateway {
    child: Child,
    dir: PathBuf,
    data_port: u16,
}

impl Gateway {
    fn boot(upstream_port: u16, server_timing: bool) -> Self {
        let dir = fixture_dir();
        let data_port = common::boot::free_port();
        let admin_port = common::boot::free_port();
        write_configs(&dir, data_port, admin_port, upstream_port, server_timing);
        let log = std::fs::File::create(dir.join("out.log")).unwrap();
        let log_err = log.try_clone().unwrap();
        let child = Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "warn")
            .stdout(log)
            .stderr(log_err)
            .spawn()
            .expect("spawn busbar");
        let mut gateway = Gateway {
            child,
            dir,
            data_port,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = gateway.child.try_wait().expect("try_wait") {
                panic!(
                    "busbar exited before listening (status {status:?}); log:\n{}",
                    gateway.log()
                );
            }
            if common::boot::healthz_answers(data_port) {
                return gateway;
            }
            assert!(
                Instant::now() < deadline,
                "busbar did not answer on {data_port} within 30s; log:\n{}",
                gateway.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("out.log")).unwrap_or_default()
    }

    fn diagnose(&self, response: &Response) -> String {
        format!(
            "status {} headers {:?} body {}; log:\n{}",
            response.status,
            response.headers,
            response.body,
            self.log()
        )
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fixture_dir() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "busbar-server-timing-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(
    dir: &Path,
    data_port: u16,
    admin_port: u16,
    upstream_port: u16,
    server_timing: bool,
) {
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
  response_headers:
    server_timing: {server_timing}
store: {{module: memory}}
admin_require_mtls: false
auth:
  chain: []
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

/// An OpenAI-shaped upstream that answers every request [`UPSTREAM_DELAY`] after reading it.
fn spawn_delayed_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            std::thread::spawn(move || {
                if common::upstream::read_request(&mut stream).is_none() {
                    return;
                }
                std::thread::sleep(UPSTREAM_DELAY);
                common::upstream::respond(
                    &mut stream,
                    200,
                    &serde_json::json!({
                        "id": "chatcmpl-test",
                        "object": "chat.completion",
                        "created": 0,
                        "model": "test-model",
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop"
                        }],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
                    }),
                );
            });
        }
    });
    port
}

#[derive(Debug)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The `dur` (ms) of the `busbar` Server-Timing metric, exactly as the header states it.
    fn dur(&self) -> Option<f64> {
        let value = self.header("server-timing")?;
        let dur = value.strip_prefix("busbar;dur=")?;
        assert!(
            dur.split_once('.').is_some_and(|(_, frac)| frac.len() == 3),
            "dur is milliseconds at microsecond precision: {value}"
        );
        dur.parse().ok()
    }
}

fn post_chat(port: u16) -> Response {
    exchange(
        port,
        "POST",
        "/v1/chat/completions",
        br#"{"model":"test-model","messages":[{"role":"user","content":"ping"}]}"#,
    )
}

fn get(port: u16, path: &str) -> Response {
    exchange(port, "GET", path, b"")
}

fn exchange(port: u16, method: &str, path: &str, body: &[u8]) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to busbar");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| {
            panic!(
                "a complete response head: {:?}",
                String::from_utf8_lossy(&raw)
            )
        });
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
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
        body: String::from_utf8_lossy(&raw[split + 4..]).into_owned(),
    }
}
