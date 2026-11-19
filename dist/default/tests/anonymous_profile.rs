// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The documented anonymous profile, through the real binary: `auth.chain: [anonymous]` with a
//! scoped `role_bindings.anonymous`. Auth is core's and plane-agnostic (owner directive
//! ANON-PLANES): the node boots with every default plane loaded, and a caller presenting no
//! credential is served, on EVERY plane, exactly what its binding names and refused what it does
//! not, through the same core path; never the admin API. A plane that keeps state per caller (MCP
//! sessions, A2A tasks) keys the anonymous caller's state by the server-issued handle: a session is
//! reached only by presenting its id, and a foreign or guessed id is not found. A binding may grant
//! the scope kinds the loaded plane images state (`allowed_agents`, `allowed_mcp_servers`) before
//! any plane mounts, and a kind no loaded plane states stays refused.

#![cfg(unix)]
#![cfg(all(
    linked_section_pools,
    linked_section_tools,
    linked_section_agents,
    linked_section_decisions,
    linked_section_streams
))]

mod common;
mod e2e_support;

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use e2e_support::{
    bearer, chat_answer, send, streams_section, Reply, Scripted, ADMISSION_STATUSES,
};
use serde_json::{json, Value};

/// The operator's token, and its SHA-256 as the admin-tokens plugin's settings state it (the
/// pair `mcp_open_front_door.rs` boots with).
const ADMIN_TOKEN: &str = "front-door-test-admin-token";
const ADMIN_TOKEN_SHA256: &str = "d321b271cf1b9bdf54eb40c5011b7168a5e8ccb42cb18a60bbc0697fed3e6d84";

/// What the anonymous caller is granted: the pool `e2e`, one agent and one MCP server (`probe`;
/// the node also registers `other`, not granted). The two plane kinds are stated by the a2a and
/// mcp images' routes (`agent`, `mcp_server`).
const BINDING: &str =
    "{ allowed_pools: [e2e], allowed_agents: [conformance-agent], allowed_mcp_servers: [probe] }";

/// The MCP session revision the tests open, and the tool both registrations serve.
const REVISION: &str = "2025-06-18";
const TOOL: &str = "ping";
const TOOL_DESCRIPTION: &str = "Returns the label it was given.";

struct Node {
    child: std::process::Child,
    dir: PathBuf,
    data: u16,
    admin: u16,
    log: PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!("--- the node's log:\n{}", self.log());
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Node {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

fn fixture_dir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-anonymous-profile-{tag}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos()),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("the deployment's directory");
    dir
}

// ── the MCP upstream: a real tool server on a loopback TLS socket (qa_mcp_integrity's shape) ──

fn ping_schema() -> Value {
    json!({
        "type": "object",
        "properties": { "label": { "type": "string" } },
        "additionalProperties": false,
    })
}

fn canonical(value: &Value) -> String {
    if let Some(map) = value.as_object() {
        let mut members: Vec<(&String, &Value)> = map.iter().collect();
        members.sort_by(|a, b| a.0.cmp(b.0));
        let body: Vec<String> = members
            .into_iter()
            .map(|(k, v)| format!("{}:{}", Value::from(k.as_str()), canonical(v)))
            .collect();
        format!("{{{}}}", body.join(","))
    } else if let Some(items) = value.as_array() {
        let body: Vec<String> = items.iter().map(canonical).collect();
        format!("[{}]", body.join(","))
    } else {
        value.to_string()
    }
}

/// The approval digest of a tool (`tools.<server>.tools_allow.<tool>.schema_hash`), pinned by
/// qa_mcp_integrity's cross-language fixture.
fn tool_digest(name: &str, description: &str, schema: &Value) -> String {
    let mut h = busbar_contract::crypto::Sha256::new();
    for part in [name, description, &canonical(schema)] {
        h.update(&(part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    format!("sha256:{}", hex::encode(h.finish()))
}

struct Upstream {
    port: u16,
    calls: Arc<Mutex<Vec<String>>>,
    pin: String,
    ca_pem: String,
}

impl Upstream {
    fn start() -> Upstream {
        use busbar_contract::crypto::testing::rcgen;
        use rcgen::PublicKeyData as _;
        let ca_key = rcgen::KeyPair::generate().expect("a CA key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("CA parameters");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("the CA certificate");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = rcgen::KeyPair::generate().expect("an upstream key");
        let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
            .expect("the upstream SAN")
            .signed_by(&key, &issuer)
            .expect("the upstream certificate");
        let pin = busbar_contract::transport::trust::key_pin(&key.subject_public_key_info());
        let tls = busbar_contract::crypto::tls::server_config(|b| {
            b.with_no_client_auth().with_single_cert(
                vec![leaf.der().clone()],
                rustls_pki_types::PrivateKeyDer::try_from(key.serialize_der())
                    .expect("upstream key DER"),
            )
        })
        .expect("upstream TLS configuration");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the upstream");
        let port = listener.local_addr().expect("its address").port();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let (tls, seen) = (Arc::clone(&tls), Arc::clone(&seen));
                std::thread::spawn(move || {
                    let _ = conn.set_read_timeout(Some(Duration::from_secs(20)));
                    let session = rustls::ServerConnection::new(tls).expect("a TLS session");
                    serve_tool(rustls::StreamOwned::new(session, conn), &seen);
                });
            }
        });
        Upstream {
            port,
            calls,
            pin,
            ca_pem: ca.pem(),
        }
    }

    /// The labels of the `tools/call`s that reached the upstream.
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("the calls").clone()
    }
}

fn serve_tool(
    mut conn: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    calls: &Mutex<Vec<String>>,
) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        if conn.read_exact(&mut byte).is_err() {
            return;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let len = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = vec![0; len];
    if conn.read_exact(&mut body).is_err() {
        return;
    }
    let req: Value = serde_json::from_slice(&body).unwrap_or_default();
    let id = req.get("id").cloned().unwrap_or_default();
    let answer = match req.get("method").and_then(Value::as_str) {
        Some("tools/list") => json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": [{
            "name": TOOL, "description": TOOL_DESCRIPTION, "inputSchema": ping_schema(),
        }] } }),
        Some("tools/call") => {
            let label = req
                .pointer("/params/arguments/label")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            calls.lock().expect("the calls").push(label.clone());
            json!({ "jsonrpc": "2.0", "id": id, "result": {
                "content": [{ "type": "text", "text": format!("ping: {label}") }],
                "isError": false,
            } })
        }
        other => json!({ "jsonrpc": "2.0", "id": id, "error": {
            "code": -32601, "message": format!("unknown method {other:?}"),
        } }),
    };
    let raw = answer.to_string();
    let _ = write!(
        conn,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{raw}",
        raw.len()
    );
    let _ = conn.flush();
}

/// The MCP plane's sections: the `mcp:` block with no issuer (the plane carries no auth policy)
/// and two registrations of the one upstream, `probe` (granted) and `other` (not granted).
fn mcp_sections(data: u16, upstream: &Upstream) -> String {
    let digest = tool_digest(TOOL, TOOL_DESCRIPTION, &ping_schema());
    let ca = serde_json::to_string(&upstream.ca_pem).expect("a YAML-compatible PEM string");
    let registration = |name: &str| {
        format!(
            r#"  {name}:
    url: "https://127.0.0.1:{port}/mcp"
    verify_ttl: "0s"
    pin:
      mechanism: cert_spki
      key: "{pin}"
    tls:
      ca_cert_pem: {ca}
    tools_allow:
      {TOOL}:
        schema_hash: "{digest}"
        description: "{TOOL_DESCRIPTION}"
"#,
            port = upstream.port,
            pin = upstream.pin,
        )
    };
    format!(
        "mcp:\n  canonical_uri: \"http://127.0.0.1:{data}/mcp\"\ntools:\n{}{}",
        registration("probe"),
        registration("other")
    )
}

/// The anonymous deployment: one OpenAI provider at `upstream`, the model `test-model`, the pools
/// `e2e` (granted) and `other` (not granted), the streaming plane, `extra` sections, and `binding`
/// as the anonymous caller's grant.
fn write_config(
    dir: &Path,
    data: u16,
    admin: u16,
    upstream: &Scripted,
    binding: &str,
    extra: &str,
) -> PathBuf {
    std::fs::write(
        dir.join("providers.yaml"),
        format!(
            "mock:\n  protocol: openai\n  base_url: \"{}\"\n  error_map: {{}}\n",
            upstream.url("")
        ),
    )
    .expect("write providers.yaml");
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        format!(
            r#"config_version: 1
listen: "127.0.0.1:{data}"
admin_listen: "127.0.0.1:{admin}"
listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test node" }}
admin_listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test node" }}
admin_require_mtls: false
store: {{module: memory}}
public_url: "http://127.0.0.1:{data}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    settings: {{ sha256: "{ADMIN_TOKEN_SHA256}" }}
auth:
  chain: [anonymous]
  admin_auth: [admin-tokens]
  role_bindings:
    anonymous:
      "*": {binding}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
pools:
  e2e:
    members:
      - {{ model: test-model }}
  other:
    members:
      - {{ model: test-model }}
# The upstream is plaintext loopback: only the llm plane's own audited acceptance admits that dial.
llm:
  insecure_transport: {{ accept: plaintext, reason: "loopback test upstream" }}
{streams}{extra}"#,
            streams = streams_section(""),
        ),
    )
    .expect("write config.yaml");
    path
}

fn busbar(config: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(common::boot::exe());
    command
        .args(args)
        .env("BUSBAR_CONFIG", config)
        .env_remove("BUSBAR_PROVIDERS")
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("MOCK_KEY", "k")
        .env("RUST_LOG", "info");
    command
}

/// Boots the anonymous profile with every plane, the MCP plane's two registrations approved.
fn boot(tag: &str, upstream: &Scripted, tools: &Upstream) -> Node {
    let dir = fixture_dir(tag);
    let data = common::boot::free_port();
    let admin = common::boot::free_port();
    let config = write_config(
        &dir,
        data,
        admin,
        upstream,
        BINDING,
        &mcp_sections(data, tools),
    );
    let log = dir.join("node.log");
    let out = std::fs::File::create(&log).expect("the node's log");
    let child = busbar(&config, &[])
        .stdin(Stdio::null())
        .stdout(out.try_clone().expect("the node's log, twice"))
        .stderr(out)
        .spawn()
        .expect("spawn busbar");
    let mut node = Node {
        child,
        dir,
        data,
        admin,
        log,
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = node.child.try_wait().expect("try_wait") {
            panic!(
                "the anonymous profile did not boot ({status:?}):\n{}",
                node.log()
            );
        }
        if common::boot::log_shows_data_and_admin_listening(&node.log())
            && common::boot::healthz_answers(node.data)
        {
            break;
        }
        assert!(Instant::now() < deadline, "busbar never served");
        std::thread::sleep(Duration::from_millis(50));
    }
    let operator = bearer(ADMIN_TOKEN);
    for server in ["probe", "other"] {
        let connect = send(
            node.admin,
            "POST",
            &format!("/api/v1/admin/tools/{server}/connect"),
            &[("Authorization", operator.as_str())],
            &[],
        );
        assert!(
            connect.text().contains("approved"),
            "the operator approves `{server}`: {} {}",
            connect.status,
            connect.text()
        );
    }
    node
}

fn refused(reply: &Reply) -> bool {
    ADMISSION_STATUSES.contains(&reply.status)
}

fn post(port: u16, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
    let mut all = vec![("Content-Type", "application/json")];
    all.extend_from_slice(headers);
    send(port, "POST", path, &all, body.as_bytes())
}

// ── MCP: one session, through the endpoint, as an anonymous caller ──

const ACCEPT: (&str, &str) = ("Accept", "application/json, text/event-stream");

/// `initialize` at the session revision: the session id the node issued.
fn mcp_open(port: u16) -> String {
    let reply = post(
        port,
        "/mcp",
        &[ACCEPT],
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": REVISION, "capabilities": {},
            "clientInfo": { "name": "anonymous-profile", "version": "1" },
        } })
        .to_string(),
    );
    assert_eq!(
        reply.status,
        200,
        "an anonymous `initialize` is served: {}",
        reply.text()
    );
    let id = reply
        .header("mcp-session-id")
        .unwrap_or_else(|| panic!("the session id is issued: {:?}", reply.headers))
        .to_owned();
    assert!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "a session id is 16 random bytes as hex: {id}"
    );
    id
}

/// One message of session `id`.
fn mcp(port: u16, id: &str, method: &str, params: Value) -> Reply {
    post(
        port,
        "/mcp",
        &[
            ACCEPT,
            ("Mcp-Session-Id", id),
            ("MCP-Protocol-Version", REVISION),
        ],
        &json!({ "jsonrpc": "2.0", "id": 2, "method": method, "params": params }).to_string(),
    )
}

fn call(port: u16, id: &str, tool: &str, label: &str) -> Reply {
    mcp(
        port,
        id,
        "tools/call",
        json!({ "name": tool, "arguments": { "label": label } }),
    )
}

/// EVERY plane linked in the default distribution, one config shape (`chain: [anonymous]` and the
/// one binding): each serves the anonymous caller within its grant and refuses it outside, through
/// the same core path. The admin API is never served to it.
#[test]
fn anonymous_profile_every_plane_serves_within_the_binding_and_refuses_outside_it() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let tools = Upstream::start();
    let node = boot("planes", &upstream, &tools);
    let chat = |pool: &str| {
        json!({ "model": pool, "messages": [{ "role": "user", "content": "hi" }] }).to_string()
    };
    let decide = |pool: &str| json!({ "model": pool, "state": { "amount": 7 } }).to_string();
    let realtime = |pool: &str| json!({ "session": { "type": "realtime", "model": pool } }).to_string();
    let a2a = json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {
        "message": { "role": "user", "parts": [{ "kind": "text", "text": "hi" }], "messageId": "m1" },
    } })
    .to_string();
    // (plane, path, within the grant, outside it): the same request, granted and not.
    let planes: [(&str, String, String, String, String); 4] = [
        (
            "llm",
            "/v1/chat/completions".into(),
            chat("e2e"),
            "/v1/chat/completions".into(),
            chat("other"),
        ),
        (
            "decisions",
            "/v1/systemone".into(),
            decide("e2e"),
            "/v1/systemone".into(),
            decide("other"),
        ),
        (
            "streaming",
            "/v1/realtime/client_secrets".into(),
            realtime("e2e"),
            "/v1/realtime/client_secrets".into(),
            realtime("other"),
        ),
        (
            "a2a",
            "/a2a/agents/conformance-agent".into(),
            a2a.clone(),
            "/a2a/agents/not-granted-agent".into(),
            a2a,
        ),
    ];
    let mut failures = Vec::new();
    for (plane, within_path, within, outside_path, outside) in &planes {
        let served = post(node.data, within_path, &[], within);
        if refused(&served) {
            failures.push(format!(
                "{plane}: within the grant refused: {} {}",
                served.status,
                served.text()
            ));
        }
        let other = post(node.data, outside_path, &[], outside);
        if !refused(&other) {
            failures.push(format!(
                "{plane}: outside the grant served: {} {}",
                other.status,
                other.text()
            ));
        }
    }
    // MCP: the session revision, within the grant (`probe`) and outside it (`other`).
    let session = mcp_open(node.data);
    let listed = mcp(node.data, &session, "tools/list", json!({}));
    if listed.status != 200 || !listed.text().contains("probe") || listed.text().contains("other_")
    {
        failures.push(format!(
            "mcp: tools/list lists only the granted server: {} {}",
            listed.status,
            listed.text()
        ));
    }
    let served = call(node.data, &session, "probe_ping", "anonymous");
    if served.status != 200 || !served.text().contains("ping: anonymous") {
        failures.push(format!(
            "mcp: a granted tools/call is served: {} {}",
            served.status,
            served.text()
        ));
    }
    let other = call(node.data, &session, "other_ping", "outside");
    if other.text().contains("ping: outside") {
        failures.push(format!(
            "mcp: a tools/call outside the grant is refused: {} {}",
            other.status,
            other.text()
        ));
    }
    if tools.calls() != ["anonymous"] {
        failures.push(format!(
            "mcp: only the granted call reached the upstream: {:?}",
            tools.calls()
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // The admin API never admits a caller that presents no credential, on either listener.
    for port in [node.admin, node.data] {
        let admin = send(port, "GET", "/api/v1/admin/keys", &[], &[]);
        assert!(
            refused(&admin),
            "the admin API refuses an anonymous caller on port {port}: {} {}",
            admin.status,
            admin.text()
        );
    }
    let foreign = bearer("not-the-operator-token");
    let admin = send(
        node.admin,
        "GET",
        "/api/v1/admin/keys",
        &[("Authorization", foreign.as_str())],
        &[],
    );
    assert!(
        refused(&admin),
        "the admin API refuses a credential it did not issue: {} {}",
        admin.status,
        admin.text()
    );
    let operator = bearer(ADMIN_TOKEN);
    let admin = send(
        node.admin,
        "GET",
        "/api/v1/admin/keys",
        &[("Authorization", operator.as_str())],
        &[],
    );
    assert_eq!(
        admin.status,
        200,
        "the operator reads keys: {}",
        admin.text()
    );
}

/// Two anonymous MCP sessions are two capabilities: each is served under its own id, a guessed or
/// foreign id is 404, and ending one leaves the other serving while the ended one is 404.
#[test]
fn anonymous_profile_mcp_sessions_are_reached_only_by_their_own_id() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let tools = Upstream::start();
    let node = boot("sessions", &upstream, &tools);
    let first = mcp_open(node.data);
    let second = mcp_open(node.data);
    assert_ne!(first, second, "every session has its own id");
    for id in [&first, &second] {
        let listed = mcp(node.data, id, "tools/list", json!({}));
        assert_eq!(listed.status, 200, "session {id} serves: {}", listed.text());
    }
    let guessed = "0b7e2f4c6a8d4e1f9a3c5b7d9e1f2a4c";
    let foreign = mcp(node.data, guessed, "tools/list", json!({}));
    assert_eq!(
        foreign.status,
        404,
        "a guessed session id is not found: {}",
        foreign.text()
    );
    let ended = send(
        node.data,
        "DELETE",
        "/mcp",
        &[
            ("Mcp-Session-Id", first.as_str()),
            ("MCP-Protocol-Version", REVISION),
        ],
        &[],
    );
    assert!(
        (200..300).contains(&ended.status),
        "the first session ends: {} {}",
        ended.status,
        ended.text()
    );
    let gone = mcp(node.data, &first, "tools/list", json!({}));
    assert_eq!(gone.status, 404, "an ended session is not found: {}", gone.text());
    let kept = call(node.data, &second, "probe_ping", "second");
    assert!(
        kept.status == 200 && kept.text().contains("ping: second"),
        "the other session still serves: {} {}",
        kept.status,
        kept.text()
    );
}

/// An anonymous A2A task is reached only by its id: a task id no anonymous caller holds (guessed,
/// or another's) answers TASK_NOT_FOUND on the JSON-RPC binding, through admission like any other.
#[test]
fn anonymous_profile_a2a_foreign_task_id_is_not_found() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let tools = Upstream::start();
    let node = boot("a2a", &upstream, &tools);
    let reply = post(
        node.data,
        "/a2a/agents/conformance-agent",
        &[],
        &json!({ "jsonrpc": "2.0", "id": 7, "method": "tasks/get",
                 "params": { "id": "a2a-guessed-0123456789abcdef" } })
        .to_string(),
    );
    assert!(
        !refused(&reply) && reply.text().contains("-32001"),
        "a foreign task id is TASK_NOT_FOUND to an anonymous caller: {} {}",
        reply.status,
        reply.text()
    );
}

#[test]
fn anonymous_profile_binding_of_a_kind_no_loaded_plane_states_is_refused() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let validate = |tag: &str, binding: &str| {
        let dir = fixture_dir(tag);
        let config = write_config(
            &dir,
            common::boot::free_port(),
            common::boot::free_port(),
            &upstream,
            binding,
            "",
        );
        let out = busbar(&config, &["--validate"])
            .output()
            .expect("run busbar --validate");
        let _ = std::fs::remove_dir_all(&dir);
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };

    // The kinds the loaded a2a and mcp images state are grantable before any plane mounts (the
    // boot test above serves this binding). `--validate` judges role bindings before it judges
    // secret references, so no binding refusal is what it says of them here.
    let (_, text) = validate("declared", BINDING);
    assert!(
        !text.contains("BUSBAR-3114"),
        "a binding of kinds the loaded planes state is not refused:\n{text}"
    );

    // `allowed_tools` grants the kind `tool`, which no loaded plane states: refused, naming it.
    let (code, text) = validate(
        "undeclared",
        "{ allowed_pools: [e2e], allowed_tools: [search] }",
    );
    assert_ne!(
        code,
        Some(0),
        "a kind no loaded plane states is refused:\n{text}"
    );
    assert!(
        text.contains("allowed_tools") && text.contains("BUSBAR-3114"),
        "the refusal names the field and its code:\n{text}"
    );
}
