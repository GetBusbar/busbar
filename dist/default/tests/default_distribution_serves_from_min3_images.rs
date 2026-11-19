// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DEFAULT DISTRIBUTION'S TRANSPORTS AND STORE ARE ITS LINKED MIN-3 IMAGES, end to end, on the REAL default
//! binary with no plugins directory: whatever serves here is linked into the build.
//!
//! - The data listener answers HTTP/1.1 and HTTP/2 (prior knowledge), and the admin listener answers the operator. Since
//!   4074625463 / 040c52e0cc (PM ruling NATIVE-LISTENER-BINDING-r1) a root listener is served only by an admitted MIN-3
//!   transport that declares the listener's slot (`D_LISTENER_SLOT`), so both answering is the linked http image serving.
//! - The admin API lists `busbar-transport-http`, `busbar-transport-webrtc` and `busbar-store-memory` as opened instances of
//!   their kinds: a door-linked row is never a kind instance; a MIN-3 image is one instance named by its identity.
//! - A chat call reaches a loopback upstream: the provider dial goes out through the linked http image, and the memory store
//!   records the call (the admin usage read names its model).
//!
//! The webrtc image's media rendezvous (an offer answered through the image) joins this file with the webrtc wiring
//! (STATUS-e6.md step 3); until then it is proved here as an opened transport instance.
//!
//! Red before the port (STATUS-e6.md): transport-http and transport-webrtc are door-era rows, so no linked image declares the
//! `listen` slot and the boot refuses the data listener.

#![cfg(unix)]

#[path = "common/boot.rs"]
mod boot;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ADMIN_TOKEN: &str = "min3-images-operator-token";
const MODEL: &str = "min3-test-model";

/// The data chain the boot test writes. `Keys`: the engine's own key verifier, its signing key generated for this run
/// by the binary under test (`--generate-signing-key`), every data request carrying a key the operator minted. `Empty`:
/// `auth.chain: []`, which the engine refuses at boot (BUSBAR-9007, nobody could be admitted).
#[derive(Clone, Copy)]
enum Chain {
    Keys,
    Empty,
}

/// One booted default binary on loopback ports, killed and cleaned up on drop.
struct Node {
    process: boot::Reap,
    dir: PathBuf,
    data: u16,
    admin: u16,
}

impl Node {
    /// Boot on fresh loopback ports. `operator`: bind the admin listener behind the linked admin-tokens image; `upstream`:
    /// route one model to that loopback port.
    fn boot(upstream: Option<u16>, operator: bool) -> Self {
        Self::boot_with_planes(upstream, operator, false)
    }

    /// `planes`: add the data listener's `public_url`, so the routes whose challenge names the plane's public URL
    /// (mcp) are mounted too, and the MCP plane's `canonical_uri`: the audience a key minted for `/mcp` names.
    fn boot_with_planes(upstream: Option<u16>, operator: bool, planes: bool) -> Self {
        let dir = workdir();
        let (data, admin) = (boot::free_port(), boot::free_port());
        let digest = busbar_contract::redacted::sha256_hex(ADMIN_TOKEN.as_bytes());
        let settings = format!("{{ sha256: \"{digest}\" }}");
        let sections = if planes {
            format!(
                "public_url: \"http://127.0.0.1:{data}\"\nmcp:\n  canonical_uri: \"http://127.0.0.1:{data}/mcp\"\n  \
                 authorization_servers: [\"http://127.0.0.1:{admin}\"]\n"
            )
        } else {
            String::new()
        };
        write_configs(
            &dir,
            data,
            admin,
            operator.then_some(settings.as_str()),
            upstream,
            Chain::Keys,
            &sections,
        );
        let log = std::fs::File::create(dir.join("out.log")).expect("the boot log");
        let process = boot::Reap(
            Command::new(boot::exe())
                .current_dir(&dir)
                .env("BUSBAR_CONFIG", dir.join("config.yaml"))
                .env("MOCK_KEY", "mock-upstream-key")
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
            // Ready when both listeners accept: the admin listener is bound after the data
            // listener's workers start, so a data answer alone does not mean the admin side is up.
            if boot::healthz_answers(self.data)
                && TcpStream::connect(("127.0.0.1", self.admin)).is_ok()
                && boot::log_shows_data_and_admin_listening(&self.log())
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn admin_get(&self, path: &str) -> (u16, String) {
        exchange(
            self.admin,
            "GET",
            &format!("/api/v1/admin{path}"),
            &format!("Authorization: Bearer {ADMIN_TOKEN}\r\n"),
            b"",
        )
    }

    /// Mint a data-plane key through the admin API (the `keys` verifier's credential). `audience`: a plane that binds
    /// one (MCP, its `canonical_uri`) admits only a key minted for exactly that audience.
    fn mint(&self, name: &str, audience: Option<&str>) -> String {
        let audience = audience
            .map(|uri| format!(r#","audience":"{uri}""#))
            .unwrap_or_default();
        let (status, minted) = exchange(
            self.admin,
            "POST",
            "/api/v1/admin/keys",
            &format!("Authorization: Bearer {ADMIN_TOKEN}\r\n"),
            format!(r#"{{"name":"{name}"{audience}}}"#).as_bytes(),
        );
        assert!(
            (200..300).contains(&status),
            "the operator mints a key ({status}); log:\n{}",
            self.log()
        );
        minted
            .split("\"token\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("the admin API minted no key token ({status})"))
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
        "busbar-min3-images-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the test's work directory");
    dir
}

/// `operator`: the admin-tokens definition's `settings` (a YAML flow map) when the admin listener sits behind it.
/// `extra`: top-level sections appended as written.
fn write_configs(
    dir: &Path,
    data: u16,
    admin: u16,
    operator: Option<&str>,
    upstream: Option<u16>,
    chain: Chain,
    extra: &str,
) {
    let chain = match chain {
        Chain::Empty => "  chain: []\n".to_owned(),
        Chain::Keys => {
            let key = Command::new(boot::exe())
                .arg("--generate-signing-key")
                .output()
                .expect("generate a signing key");
            assert!(key.status.success(), "--generate-signing-key");
            let file = dir.join("signing.key");
            std::fs::write(&file, &key.stdout).expect("signing.key");
            format!(
                "  chain: [keys]\n  signing_key: {{ file: \"{}\" }}\n",
                file.display()
            )
        }
    };
    let (catalog, routing) = upstream.map_or_else(
        || ("{}\n".to_owned(), String::new()),
        |upstream| {
            (
                format!("mock:\n  protocol: openai\n  base_url: \"http://127.0.0.1:{upstream}\"\n  error_map: {{}}\n"),
                // The upstream is plaintext loopback: only the llm plane's own audited acceptance
                // admits that dial (TRANSPORT-SECURITY-POLICY §4; no loopback exemption).
                format!(
                    "providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\nmodels:\n  {MODEL}:\n    provider: mock\n\
                     llm:\n  insecure_transport: {{ accept: plaintext, reason: \"loopback test upstream\" }}\n"
                ),
            )
        },
    );
    std::fs::write(dir.join("providers.yaml"), catalog).expect("providers.yaml");
    let (operator, admin_auth) = operator.map_or_else(
        || (String::new(), ""),
        |settings| {
            (
                format!("identity-providers:\n  admin-tokens: {{ module: admin-tokens, settings: {settings} }}\n"),
                "  admin_auth: [admin-tokens]\n",
            )
        },
    );
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"config_version: 1
listen: "127.0.0.1:{data}"
listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test listener" }}
admin_listen: "127.0.0.1:{admin}"
admin_listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test admin listener" }}
store: {{ module: memory }}
{operator}auth:
{chain}{admin_auth}{routing}{extra}"#
        ),
    )
    .expect("config.yaml");
}

/// An OpenAI-shaped upstream on loopback that answers every chat call, counting them.
fn spawn_upstream() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the upstream");
    let port = listener
        .local_addr()
        .expect("the upstream's address")
        .port();
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let counted = Arc::clone(&counted);
            std::thread::spawn(move || {
                if read_request(&mut stream).is_none() {
                    return;
                }
                counted.fetch_add(1, Ordering::SeqCst);
                let body = format!(
                    r#"{{"id":"chatcmpl-min3","object":"chat.completion","created":0,"model":"{MODEL}","choices":[{{"index":0,"message":{{"role":"assistant","content":"served"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}}}"#
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
    (port, calls)
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

/// `/healthz` over HTTP/2 with prior knowledge (no TLS, no upgrade): the status.
fn healthz_over_h2(port: u16) -> Result<u16, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(tcp),
        )
        .await
        .map_err(|e| format!("h2 handshake: {e}"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let request = http::Request::get(format!("http://127.0.0.1:{port}/healthz"))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .map_err(|e| e.to_string())?;
        let response = tokio::time::timeout(Duration::from_secs(10), sender.send_request(request))
            .await
            .map_err(|_| "no h2 answer within 10 s".to_owned())?
            .map_err(|e| format!("h2 request: {e}"))?;
        Ok(response.status().as_u16())
    })
}

fn assert_instance(node: &Node, kind: &str, identity: &str) {
    let (status, body) = node.admin_get(&format!("/kinds/{kind}/instances"));
    assert_eq!(
        status,
        200,
        "the operator reads the {kind} instances: {body}; log:\n{}",
        node.log()
    );
    assert!(
        body.contains(&format!("\"{identity}\"")),
        "the linked {identity} image is an opened {kind} instance: {body}"
    );
}

#[test]
fn the_data_listener_is_served_by_the_linked_http_image_over_http1_and_http2() {
    // `Node::boot` waited for HTTP/1.1 `/healthz`; no provider: only the transport is under test. The operator
    // credential is there because the key chain needs one to mint a key (BUSBAR-3115).
    let node = Node::boot(None, true);
    assert!(
        node.log().contains("busbar listening"),
        "the data listener came up; log:\n{}",
        node.log()
    );
    assert_eq!(
        healthz_over_h2(node.data),
        Ok(200),
        "the data listener answers HTTP/2 with prior knowledge; log:\n{}",
        node.log()
    );
}

/// Boot the configuration written in `dir` and expect it refused: neither listener ever accepts, the process exits
/// unsuccessfully, and no listener came up. The boot log.
fn boot_is_refused(dir: &Path, data: u16, admin: u16) -> String {
    let log = std::fs::File::create(dir.join("out.log")).expect("the boot log");
    let mut process = boot::Reap(
        Command::new(boot::exe())
            .current_dir(dir)
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .stdout(log.try_clone().expect("the boot log"))
            .stderr(log)
            .spawn()
            .expect("boot the default binary"),
    );
    let read_log = || std::fs::read_to_string(dir.join("out.log")).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        for (port, which) in [(admin, "admin"), (data, "data")] {
            assert!(
                TcpStream::connect(("127.0.0.1", port)).is_err(),
                "the {which} listener accepted a connection on a boot that must be refused; log:\n{}",
                read_log()
            );
        }
        if let Some(status) = process.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the boot neither served nor stopped; log:\n{}",
            read_log()
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let log = read_log();
    let _ = std::fs::remove_dir_all(dir);
    assert!(!status.success(), "the boot is refused; log:\n{log}");
    assert!(
        !log.contains("busbar listening"),
        "no listener came up; log:\n{log}"
    );
    log
}

/// A configuration with no operator credential (no `identity-providers`, no `auth.admin_auth`) and the key chain is
/// refused at boot: nobody could mint a key, so the data plane would refuse every request (BUSBAR-3115), and the admin
/// plane never serves. (Before 2723c6e305 refused the empty chain this default booted with `chain: []` and answered
/// every admin request 401; neither listener now accepts at all.)
#[test]
fn with_no_operator_credential_the_key_chain_is_refused_and_no_listener_accepts() {
    let dir = workdir();
    let (data, admin) = (boot::free_port(), boot::free_port());
    write_configs(&dir, data, admin, None, None, Chain::Keys, "");
    let log = boot_is_refused(&dir, data, admin);
    assert!(
        log.contains("BUSBAR-3115"),
        "the refusal says no admin credential can mint a key; log:\n{log}"
    );
}

#[test]
fn the_admin_listener_is_served_by_the_linked_http_image_and_lists_it_as_a_transport_instance() {
    let node = Node::boot(None, true);
    assert!(
        boot::log_shows_data_and_admin_listening(&node.log()),
        "both listeners came up; log:\n{}",
        node.log()
    );
    let (wrong, _) = exchange(
        node.admin,
        "GET",
        "/api/v1/admin/openapi.json",
        "Authorization: Bearer not-the-operator-token\r\n",
        b"",
    );
    assert_eq!(
        wrong,
        401,
        "another token is refused on the admin listener; log:\n{}",
        node.log()
    );
    assert_instance(&node, "transport", "busbar-transport-http");
}

#[test]
fn the_linked_webrtc_image_is_an_opened_transport_instance() {
    let node = Node::boot(None, true);
    assert_instance(&node, "transport", "busbar-transport-webrtc");
}

#[test]
fn a_provider_call_dials_out_through_the_linked_http_image_and_the_memory_store_records_it() {
    let (upstream, calls) = spawn_upstream();
    let node = Node::boot(Some(upstream), true);
    assert_instance(&node, "store", "busbar-store-memory");
    let key = node.mint("min3-provider-call", None);
    let (status, body) = exchange(
        node.data,
        "POST",
        "/v1/chat/completions",
        &format!("Authorization: Bearer {key}\r\n"),
        format!(r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":"ping"}}]}}"#)
            .as_bytes(),
    );
    assert_eq!(
        status,
        200,
        "the chat call is served: {body}; log:\n{}",
        node.log()
    );
    assert!(body.contains("served"), "the upstream's answer: {body}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "exactly one dial reached the upstream"
    );
    let (status, usage) = node.admin_get("/usage");
    assert_eq!(status, 200, "the operator reads usage: {usage}");
    assert!(
        usage.contains(MODEL),
        "the memory store recorded the call under its model: {usage}"
    );
}

/// E5's order on the real binary: the operator credential's native admin-tokens instance is opened before the admin
/// chain installs, and the chain installs before any listener binds. A credential whose instance cannot open (a blank
/// 1.5 `token`, which the plugin refuses at open) stops the boot with neither listener having accepted a connection, so
/// no admin request is judged while the instance is unopened.
#[test]
fn an_operator_credential_that_cannot_open_stops_the_boot_before_any_listener_accepts() {
    let dir = workdir();
    let (data, admin) = (boot::free_port(), boot::free_port());
    write_configs(
        &dir,
        data,
        admin,
        Some("{ token: \"\" }"),
        None,
        Chain::Keys,
        "",
    );
    let log = boot_is_refused(&dir, data, admin);
    assert!(
        log.contains("serving auth"),
        "the boot stops at the operator instance's open, before listener assembly; log:\n{log}"
    );
}

/// `auth.chain: []` names no verifier, so nobody could be admitted: the engine refuses the boot (BUSBAR-9007,
/// 2723c6e305) and no listener ever accepts. The boot test's own configuration therefore carries the key verifier.
#[test]
fn an_empty_data_chain_is_refused_at_boot_before_any_listener_accepts() {
    let dir = workdir();
    let (data, admin) = (boot::free_port(), boot::free_port());
    // With the operator credential, so the refusal is the empty chain's and no other.
    let digest = busbar_contract::redacted::sha256_hex(ADMIN_TOKEN.as_bytes());
    let settings = format!("{{ sha256: \"{digest}\" }}");
    write_configs(&dir, data, admin, Some(&settings), None, Chain::Empty, "");
    let log = boot_is_refused(&dir, data, admin);
    assert!(
        log.contains("auth.chain is empty: no verifier"),
        "the refusal names the empty chain (BUSBAR-9007); log:\n{log}"
    );
}

/// The first boot reaches every linked plane: one request per plane (llm, mcp, a2a, decisions, streaming) carrying the
/// operator-minted key. Each is admitted and answered by its plane, or its route is refused at boot with a stated
/// reason (an "is not served" line naming the route in the boot log). A refused plane answer carries its reason.
#[test]
fn each_linked_plane_answers_one_keyed_request_or_states_its_refusal() {
    let (upstream, _calls) = spawn_upstream();
    let node = Node::boot_with_planes(Some(upstream), true, true);
    let key = node.mint("min3-planes", None);
    let mcp_key = node.mint(
        "min3-planes-mcp",
        Some(&format!("http://127.0.0.1:{}/mcp", node.data)),
    );
    let chat = format!(r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":"ping"}}]}}"#);
    let decide = format!(r#"{{"model":"{MODEL}","state":{{"amount":7}}}}"#);
    let mint_session = format!(r#"{{"session":{{"type":"realtime","model":"{MODEL}"}}}}"#);
    let (key, mcp_key) = (key.as_str(), mcp_key.as_str());
    let planes: [(&str, &str, &str, &str, String); 5] = [
        ("llm", "/v1/chat/completions", key, "", chat),
        (
            "mcp",
            "/mcp",
            mcp_key,
            "Accept: application/json, text/event-stream\r\n",
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"min3-planes","version":"1"}}}"#.to_owned(),
        ),
        (
            "a2a",
            "/a2a",
            key,
            "",
            r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"hi"}],"messageId":"m1"}}}"#.to_owned(),
        ),
        ("decisions", "/v1/systemone", key, "", decide),
        ("streaming", "/v1/realtime/client_secrets", key, "", mint_session),
    ];
    // The statuses admission answers: an admitted request is none of them.
    const ADMISSION: [u16; 5] = [401, 403, 404, 405, 413];
    let mut answers = Vec::new();
    let mut failures = Vec::new();
    for (plane, path, token, headers, body) in &planes {
        let (status, text) = exchange(
            node.data,
            "POST",
            path,
            &format!("Authorization: Bearer {token}\r\n{headers}"),
            body.as_bytes(),
        );
        let log = node.log();
        let refused_at_boot = log
            .lines()
            .find(|line| line.contains("is not served") && line.contains(path))
            .map(str::to_owned);
        let short: String = text.chars().take(300).collect();
        answers.push(format!("{plane} POST {path}: {status} {short}"));
        let admitted = status != 0 && !ADMISSION.contains(&status);
        let stated = admitted && ((200..300).contains(&status) || !text.trim().is_empty());
        if !(stated || refused_at_boot.is_some()) {
            failures.push(format!(
                "{plane} POST {path}: {status} is neither a plane's answer nor a stated refusal: {short}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{}\nanswers:\n{}\nlog:\n{}",
        failures.join("\n"),
        answers.join("\n"),
        node.log()
    );
}
