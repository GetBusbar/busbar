// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `abi_crossings`: NO SECRET CROSSES THE PLUGIN INTERFACE IN THE CLEAR toward a plugin that does not own
//! it, judged on the real default binary (DESIGN-interface-revision F2; lock checklist G.1 item 7).
//!
//! The binary under test is the default distribution built with `crossing-witness`: the loader arms its
//! one crossing recorder from a plant file and writes a verdict file as traffic crosses. Every call of
//! every kind is made at one place in the loader, and the recorder is the hook on that place, so the
//! verdict covers every byte the engine let any plugin read: each call's numbers, texts and bytes, each
//! lent header list, and the results each parked chain was resumed with.
//!
//! What is planted: the provider credential the engine sends upstream, and the operator's admin token.
//! What the run must show, all of it, for a pass:
//! - the upstream really received the provider credential (so the engine did put it on the wire: a run
//!   in which the credential went nowhere proves nothing);
//! - the verdict's planted count equals what this test wrote;
//! - calls crossed toward a transport, a plane, a store and a secret plugin;
//! - no planted secret was found in any crossing toward an instance that does not own it.
//!
//! Red before the sealed head records: today's engine writes the provider credential into the head it
//! hands the HTTP transport, so this fails naming `provider-key`, the transport instance and the place.

#![cfg(all(unix, feature = "crossing-witness"))]

#[path = "common/boot.rs"]
mod boot;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_plugin_loader::abi_crossings::{plant_line, Verdict, PLANTS_ENV, VERDICT_ENV};

/// Long, random-looking and unlike anything else in the run, so a match is the secret and not chance.
const PROVIDER_KEY: &str = "sk-crossing-witness-4f9c2d71a8e35b06c1d7-provider-key";
const ADMIN_TOKEN: &str = "crossing-witness-operator-token-93be07ac51d24f68";
const MODEL: &str = "crossing-witness-model";

/// The instances allowed to read the provider credential: the secret plugin that resolves it.
const PROVIDER_KEY_OWNERS: [&str; 2] = ["env", "busbar-secret-env"];
/// The instances allowed to read the operator's token: the auth plugin that verifies it.
const ADMIN_TOKEN_OWNERS: [&str; 2] = ["admin-tokens", "busbar-auth-admin-tokens"];

/// The kinds the run must have crossed toward.
const KINDS: [&str; 4] = ["transport", "plane", "store", "secret"];

struct Node {
    process: boot::Reap,
    dir: PathBuf,
    data: u16,
    admin: u16,
}

impl Node {
    fn boot(upstream: u16) -> Self {
        let dir = workdir();
        let (data, admin) = (boot::free_port(), boot::free_port());
        write_configs(&dir, data, admin, upstream);
        std::fs::write(
            dir.join("plants.tsv"),
            plant_line(
                "provider-key",
                PROVIDER_KEY.as_bytes(),
                &PROVIDER_KEY_OWNERS,
            ) + &plant_line("admin-token", ADMIN_TOKEN.as_bytes(), &ADMIN_TOKEN_OWNERS),
        )
        .expect("the plant file");
        let log = std::fs::File::create(dir.join("out.log")).expect("the boot log");
        let process = boot::Reap(
            Command::new(boot::exe())
                .current_dir(&dir)
                .env("BUSBAR_CONFIG", dir.join("config.yaml"))
                .env("MOCK_KEY", PROVIDER_KEY)
                .env(PLANTS_ENV, dir.join("plants.tsv"))
                .env(VERDICT_ENV, dir.join("verdict.tsv"))
                .stdout(log.try_clone().expect("the boot log"))
                .stderr(log)
                .spawn()
                .expect("boot the default binary"),
        );
        let mut node = Node {
            process,
            dir,
            data,
            admin,
        };
        node.wait_ready();
        node
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("out.log")).unwrap_or_default()
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.process.try_wait().expect("try_wait") {
                panic!(
                    "the default binary exited before serving ({status:?}); log:\n{}",
                    self.log()
                );
            }
            assert!(
                Instant::now() < deadline,
                "/healthz never answered on the data listener; log:\n{}",
                self.log()
            );
            if boot::healthz_answers(self.data)
                && TcpStream::connect(("127.0.0.1", self.admin)).is_ok()
                && boot::log_shows_data_and_admin_listening(&self.log())
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The verdict file once it has stopped changing: the witness rewrites it on the loader's watchdog
    /// scan whenever a call crossed since the last write, so two equal reads a few scans apart, after
    /// the last request of the test was answered, are the whole run.
    fn settled_verdict(&self) -> String {
        let path = self.dir.join("verdict.tsv");
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last = String::new();
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let now = std::fs::read_to_string(&path).unwrap_or_default();
            if !now.is_empty() && now == last {
                return now;
            }
            assert!(
                Instant::now() < deadline,
                "the witness wrote no settled verdict (is the binary built with `crossing-witness`?); \
                 last read:\n{now}\nlog:\n{}",
                self.log()
            );
            last = now;
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn workdir() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-abi-crossings-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the test's work directory");
    dir
}

fn write_configs(dir: &Path, data: u16, admin: u16, upstream: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        format!(
            "mock:\n  protocol: openai\n  base_url: \"http://127.0.0.1:{upstream}\"\n  error_map: {{}}\n"
        ),
    )
    .expect("providers.yaml");
    let digest = busbar_contract::redacted::sha256_hex(ADMIN_TOKEN.as_bytes());
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"config_version: 1
listen: "127.0.0.1:{data}"
listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test listener" }}
admin_listen: "127.0.0.1:{admin}"
admin_listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test admin listener" }}
store: {{ module: memory }}
identity-providers:
  admin-tokens: {{ module: admin-tokens, settings: {{ sha256: "{digest}" }} }}
auth:
  chain: []
  admin_auth: [admin-tokens]
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  {MODEL}:
    provider: mock
"#
        ),
    )
    .expect("config.yaml");
}

/// An OpenAI-shaped upstream on loopback. Counts the calls that carried the provider credential: the
/// proof that the engine put the credential on the wire in this run.
fn spawn_upstream() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the upstream");
    let port = listener
        .local_addr()
        .expect("the upstream's address")
        .port();
    let keyed = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&keyed);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let counted = Arc::clone(&counted);
            std::thread::spawn(move || {
                let Some(request) = read_request(&mut stream) else {
                    return;
                };
                let key = PROVIDER_KEY.as_bytes();
                if request.windows(key.len()).any(|w| w == key) {
                    counted.fetch_add(1, Ordering::SeqCst);
                }
                let body = format!(
                    r#"{{"id":"chatcmpl-witness","object":"chat.completion","created":0,"model":"{MODEL}","choices":[{{"index":0,"message":{{"role":"assistant","content":"served"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}}}"#
                );
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                     connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.flush();
            });
        }
    });
    (port, keyed)
}

/// One request's head and body (by content-length), or None when the peer closes first.
fn read_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let len = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Some(buf)
}

/// One HTTP/1.1 exchange: the status and the body text.
fn exchange(port: u16, method: &str, path: &str, headers: &str, body: &[u8]) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to busbar");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Content-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).expect("write the head");
    stream.write_all(body).expect("write the body");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map_or_else(String::new, |(_, body)| body.to_owned());
    (status, body)
}

#[test]
fn no_planted_secret_crosses_toward_a_plugin_that_does_not_own_it() {
    let (upstream, keyed) = spawn_upstream();
    let node = Node::boot(upstream);
    let log_path = node.dir.join("out.log");
    let _dump = boot::DumpOnPanic(&log_path);

    // A provider call: admission, the plane, the dial through the transport, the store's record.
    let (status, body) = exchange(
        node.data,
        "POST",
        "/v1/chat/completions",
        "",
        format!(r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":"ping"}}]}}"#)
            .as_bytes(),
    );
    assert_eq!(status, 200, "the chat call is served: {body}");
    // An operator call: the admin token crosses toward its own auth plugin and toward no other.
    let (status, usage) = exchange(
        node.admin,
        "GET",
        "/api/v1/admin/usage",
        &format!("Authorization: Bearer {ADMIN_TOKEN}\r\n"),
        b"",
    );
    assert_eq!(status, 200, "the operator reads usage: {usage}");

    assert_eq!(
        keyed.load(Ordering::SeqCst),
        1,
        "the upstream received the provider credential exactly once: without that the run proves nothing"
    );

    let verdict = node.settled_verdict();
    let failures = Verdict::failures_of_text(&verdict, 2, &KINDS);
    assert!(
        failures.is_empty(),
        "abi_crossings FAILED:\n{}\nthe verdict the witness wrote:\n{verdict}",
        failures.join("\n")
    );
    let crossings = verdict
        .lines()
        .find_map(|line| line.strip_prefix("crossings\t"))
        .unwrap_or("0");
    println!("abi_crossings: {crossings} crossings scanned, 2 secrets planted, 0 leaks");
}
