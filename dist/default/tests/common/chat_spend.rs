// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Boot the real binary against a mock OpenAI Chat upstream, send one chat request through a minted
//! key and read the spend the admin usage view derives for it. Plain blocking sockets, so a caller
//! inside a tokio test can use it too.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use busbar_contract::json::{self, JsonValueTrait};
use serde_json::Value;

pub const ADMIN_TOKEN: &str = "chat-spend-admin";

/// A mock OpenAI Chat upstream answering every request with one completion carrying `usage`.
pub fn chat_upstream(usage: Value) -> u16 {
    chat_upstream_sequence(vec![usage])
}

/// A mock OpenAI Chat upstream whose n-th answer carries `usages[n]` (the last one repeats).
fn chat_upstream_sequence(usages: Vec<Value>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the mock upstream");
    let port = listener.local_addr().expect("its address").port();
    let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let body = |usage: &Value| {
        serde_json::json!({
            "id": "chatcmpl-cache-write", "object": "chat.completion", "created": 1,
            "model": "test-model",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                         "finish_reason": "stop"}],
            "usage": usage
        })
    };
    let bodies: Vec<Value> = usages.iter().map(body).collect();
    assert!(!bodies.is_empty(), "at least one answer");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let (served, bodies) = (served.clone(), bodies.clone());
            std::thread::spawn(move || {
                let Some((head, _)) = super::upstream::read_request(&mut conn) else {
                    return;
                };
                // Only a chat completion takes the next answer; any probe reads the first.
                let n = if head.contains("chat/completions") {
                    served.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                } else {
                    0
                };
                super::upstream::respond(&mut conn, 200, &bodies[n.min(bodies.len() - 1)]);
            });
        }
    });
    port
}

/// The `providers.yaml` naming `mock` as an OpenAI Chat provider at `upstream`.
pub fn providers_yaml(upstream: u16) -> String {
    format!("mock:\n  protocol: openai\n  base_url: \"http://127.0.0.1:{upstream}\"\n")
}

/// Write a fresh signing key into `dir` and return its path.
pub fn signing_key(dir: &Path) -> PathBuf {
    let out = Command::new(super::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(out.status.success(), "--generate-signing-key");
    let path = dir.join("signing.key");
    std::fs::write(&path, out.stdout).unwrap();
    path
}

/// Set the listeners, the admin token login, key auth and a zero request fee on an authored
/// deployment document, so one chat request's spend is exactly its token classes.
pub fn serve(doc: &mut busbar_contract::yaml::Value, data: u16, admin: u16, signing: &Path) {
    use busbar_contract::yaml::{MappingExt as _, Pairs, Value as Yaml, ValueExt as _};
    let root = doc.as_mapping_mut().expect("the deployment is a mapping");
    let set = |root: &mut Pairs, key: &str, yaml: &str| {
        root.insert_key(
            Yaml::from(key),
            busbar_contract::yaml::from_str(yaml).expect("a fixed YAML value"),
        );
    };
    set(root, "listen", &format!("\"127.0.0.1:{data}\""));
    set(root, "admin_listen", &format!("\"127.0.0.1:{admin}\""));
    set(root, "admin_require_mtls", "false");
    set(root, "per_request_fee", "0");
    set(
        root,
        "identity-providers",
        "{admin-tokens: {module: admin-tokens, token: {env: BUSBAR_ADMIN_TOKEN}}}",
    );
    set(
        root,
        "auth",
        &format!(
            "{{chain: [keys], signing_key: {{file: {}}}, admin_auth: [admin-tokens]}}",
            json::to_string(&signing.display().to_string()).unwrap()
        ),
    );
}

pub struct Gateway {
    pub child: Child,
    pub log: PathBuf,
    pub data: u16,
    pub admin: u16,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Gateway {
    /// Start the binary on `config` and `providers` with `env`; nothing is awaited.
    pub fn spawn(
        dir: &Path,
        config: &Path,
        providers: &Path,
        data: u16,
        admin: u16,
        env: &[(&str, &str)],
    ) -> Gateway {
        let log = dir.join("gateway.log");
        let out = std::fs::File::create(&log).unwrap();
        let mut command = Command::new(super::boot::exe());
        command
            .env("BUSBAR_CONFIG", config)
            .env("BUSBAR_PROVIDERS", providers)
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("MOCK_KEY", "k")
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(out.try_clone().unwrap())
            .stderr(out);
        for (key, value) in env {
            command.env(key, value);
        }
        Gateway {
            child: command.spawn().expect("spawn busbar"),
            log,
            data,
            admin,
        }
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Wait until the data listener answers `/healthz`; `Err` carries the log when the process
    /// exits first (a boot refusal).
    pub fn ready(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if self.child.try_wait().expect("try_wait").is_some() {
                return Err(self.log());
            }
            if super::boot::healthz_answers(self.data) {
                return Ok(());
            }
            assert!(
                Instant::now() < deadline,
                "busbar never became healthy; log:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn admin(&self, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
        http(self.admin, method, path, Some(ADMIN_TOKEN), body)
    }

    /// Mint a key, send one chat request and return the total spend the admin usage view derives
    /// once that request is counted.
    pub fn one_chat_spend_micros(&self) -> i64 {
        let before = self.usage_total();
        let (status, minted) = self.admin("POST", "/api/v1/admin/keys", Some(r#"{"name":"cw"}"#));
        assert!(status < 300, "mint a key: {status} {minted}");
        let token = minted
            .split("\"token\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_else(|| panic!("the admin API must mint a key: {minted}"))
            .to_owned();
        let (status, answer) = http(
            self.data,
            "POST",
            "/v1/chat/completions",
            Some(&token),
            Some(r#"{"model":"test-model","messages":[{"role":"user","content":"hi"}]}"#),
        );
        assert_eq!(
            status,
            200,
            "the chat answer: {answer}\nlog:\n{}",
            self.log()
        );
        let want = before["requests"].as_u64().unwrap_or(0) + 1;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let total = self.usage_total();
            if total["requests"].as_u64() >= Some(want) {
                return total["spend_micros"].as_i64().expect("spend_micros")
                    - before["spend_micros"].as_i64().unwrap_or(0);
            }
            assert!(
                Instant::now() < deadline,
                "the request was never counted: {total}\nlog:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn usage_total(&self) -> json::Value {
        let (status, body) = self.admin("GET", "/api/v1/admin/usage", None);
        assert_eq!(status, 200, "admin usage: {body}");
        let usage = json::parse_value(body.as_bytes()).expect("admin usage is JSON");
        usage["total"].clone()
    }
}

/// One HTTP/1.1 exchange on loopback: the status and the (de-chunked) body.
pub fn http(
    port: u16,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let body = body.unwrap_or("");
    let auth = bearer.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"));
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Content-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("send");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let chunked = head
        .lines()
        .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"));
    if !chunked {
        return (status, rest.to_owned());
    }
    let mut out = String::new();
    let mut rest = rest;
    while let Some((size, tail)) = rest.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size.trim(), 16) else {
            break;
        };
        if size == 0 || tail.len() < size {
            break;
        }
        out.push_str(&tail[..size]);
        rest = tail[size..].trim_start_matches("\r\n");
    }
    (status, out)
}
