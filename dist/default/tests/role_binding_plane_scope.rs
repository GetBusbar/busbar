// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MCP-TOOLKIND: the documented per-tool grant works end to end, least privilege per tool.
//!
//! The MCP plane judges a `tools/call` under two scope kinds: the server (`mcp_server`, the walk
//! kind its routes state) and the tool (`mcp_tool`, which no route states: the plane asks it). The
//! plane declares the kind it checks in its describe (`D_CHECKED_KIND`), and core declares it
//! before it judges role bindings, so:
//!
//! 1. a configuration whose role binding grants `allowed_mcp_tools` validates and boots;
//! 2. a key granted tool A (`allowed_mcp_tools: [probe_ping]`) is served A and refused tool B of
//!    the same server, which never reaches the upstream;
//! 3. a kind no loaded plane states or checks is still refused, in the configuration and at mint.
//!
//! The shipped binary runs against a real upstream MCP server on a loopback TLS socket, as in
//! `qa_mcp_integrity.rs`.

#![cfg(linked_section_tools)]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::json::{self, json, JsonContainerTrait as _, JsonValueTrait, Value};

const PROTOCOL: &str = "2026-07-28";
const DOOR: &str = "/mcp";
const SERVER: &str = "probe";
/// The two tools the upstream serves, both approved by the operator.
const GRANTED: &str = "ping";
const OTHER: &str = "pong";
const DESCRIPTION: &str = "Returns the label it was given.";
/// The binding every test configuration carries: the documented per-tool grant.
/// The operator's admin token (its SHA-256 is the admin-tokens settings).
const ADMIN_TOKEN: &str = "role-binding-plane-scope-admin-token";
const BINDING: &str = "{ allowed_mcp_servers: [probe], allowed_mcp_tools: [probe_ping] }";

fn canonical(value: &Value) -> String {
    if let Some(map) = value.as_object() {
        let mut members: Vec<(&str, &Value)> = map.iter().collect();
        members.sort_by(|a, b| a.0.cmp(b.0));
        let body: Vec<String> = members
            .into_iter()
            .map(|(k, v)| format!("{}:{}", Value::from(k), canonical(v)))
            .collect();
        format!("{{{}}}", body.join(","))
    } else if let Some(items) = value.as_array() {
        let body: Vec<String> = items.iter().map(canonical).collect();
        format!("[{}]", body.join(","))
    } else {
        value.to_string()
    }
}

/// The approval digest (`qa_mcp_integrity.rs` pins it to the plane's cross-language fixture).
fn tool_digest(name: &str) -> String {
    let mut h = busbar_contract::crypto::Sha256::new();
    for part in [name, DESCRIPTION, &canonical(&schema())] {
        h.update(&(part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    format!("sha256:{}", hex::encode(h.finish()))
}

fn schema() -> Value {
    json!({
        "type": "object",
        "properties": { "label": { "type": "string" } },
        "additionalProperties": false,
    })
}

/// The `tools/call` requests that reached the upstream, by tool name.
#[derive(Default)]
struct Served {
    calls: Vec<String>,
}

struct Upstream {
    port: u16,
    served: Arc<Mutex<Served>>,
    pin: String,
    ca_pem: String,
}

impl Upstream {
    fn start() -> Upstream {
        use busbar_contract::crypto::testing::rcgen::PublicKeyData as _;

        let ca_key =
            busbar_contract::crypto::testing::rcgen::KeyPair::generate().expect("a CA key");
        let mut ca_params =
            busbar_contract::crypto::testing::rcgen::CertificateParams::new(Vec::new())
                .expect("CA parameters");
        ca_params.is_ca = busbar_contract::crypto::testing::rcgen::IsCa::Ca(
            busbar_contract::crypto::testing::rcgen::BasicConstraints::Unconstrained,
        );
        let ca = ca_params.self_signed(&ca_key).expect("the CA certificate");
        let issuer = busbar_contract::crypto::testing::rcgen::Issuer::new(ca_params, ca_key);
        let key =
            busbar_contract::crypto::testing::rcgen::KeyPair::generate().expect("an upstream key");
        let leaf = busbar_contract::crypto::testing::rcgen::CertificateParams::new(vec![
            "127.0.0.1".into(),
        ])
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
        let port = listener.local_addr().unwrap().port();
        let served = Arc::new(Mutex::new(Served::default()));
        let state = served.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let state = state.clone();
                let tls = Arc::clone(&tls);
                std::thread::spawn(move || {
                    conn.set_read_timeout(Some(Duration::from_secs(20)))
                        .unwrap();
                    conn.set_write_timeout(Some(Duration::from_secs(20)))
                        .unwrap();
                    let session = rustls::ServerConnection::new(tls).expect("a TLS session");
                    serve_one(rustls::StreamOwned::new(session, conn), &state);
                });
            }
        });
        Upstream {
            port,
            served,
            pin,
            ca_pem: ca.pem(),
        }
    }

    fn url(&self) -> String {
        format!("https://127.0.0.1:{}{DOOR}", self.port)
    }

    fn calls(&self) -> Vec<String> {
        self.served.lock().unwrap().calls.clone()
    }
}

fn read_request(conn: &mut impl Read) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        conn.read_exact(&mut byte).ok()?;
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).ok()?;
    if !head.starts_with("POST ") {
        return None;
    }
    let len = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })?;
    let mut body = vec![0; len];
    conn.read_exact(&mut body).ok()?;
    Some(body)
}

fn serve_one(
    mut conn: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    state: &Mutex<Served>,
) {
    let Some(body) = read_request(&mut conn) else {
        return;
    };
    let req: Value = json::parse_value(&body).unwrap_or_default();
    let id = req.get("id").cloned().unwrap_or_default();
    let answer = match req.get("method").and_then(Value::as_str) {
        Some("tools/list") => {
            let tool = |name: &str| json!({ "name": name, "description": DESCRIPTION, "inputSchema": schema() });
            json!({ "jsonrpc": "2.0", "id": id, "result": {
                "tools": [tool(GRANTED), tool(OTHER)],
            } })
        }
        Some("tools/call") => {
            let name = json::pointer(&req, "/params/name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let label = json::pointer(&req, "/params/arguments/label")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            state.lock().unwrap().calls.push(name.clone());
            json!({ "jsonrpc": "2.0", "id": id, "result": {
                "content": [{ "type": "text", "text": format!("{name}: {label}") }],
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

fn fixture_dir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "busbar-role-binding-plane-scope-{}-{tag}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// One test deployment: the keys chain, the operator's admin token, the MCP plane with `probe`
/// serving two approved tools, and `binding` as the keys' role binding.
fn write_config(dir: &Path, data: u16, admin: u16, upstream: &Upstream, binding: &str) -> PathBuf {
    let (_, key_hex) = common::credentials::generate_signing_key();
    let key_file = dir.join("signing.key");
    std::fs::write(&key_file, &key_hex).unwrap();
    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    let cfg = dir.join("config.yaml");
    std::fs::write(
        &cfg,
        format!(
            r#"config_version: 1
listen: "127.0.0.1:{data}"
listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test listener" }}
admin_listen: "127.0.0.1:{admin}"
admin_listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test admin listener" }}
admin_require_mtls: false
store: {{ module: memory }}
public_url: "http://127.0.0.1:{data}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    settings: {{ sha256: "{admin_sha256}" }}
auth:
  chain: [keys]
  admin_auth: [admin-tokens]
  signing_key: {{ file: "{key}" }}
  role_bindings:
    keys:
      "*": {binding}
mcp:
  canonical_uri: "http://127.0.0.1:{data}{DOOR}"
  format: 2
  resource:
    authorization_servers: ["http://127.0.0.1:{admin}"]
  servers:
   {SERVER}:
    url: "{url}"
    tls:
      trust: {ca_pem}
      pin_spki: ["{pin}"]
    core_upstream: true
    verify_ttl: "0s"
    pin:
      mechanism: cert_spki
    tools_allow:
      {GRANTED}:
        schema_hash: "{granted}"
        description: "{DESCRIPTION}"
      {OTHER}:
        schema_hash: "{other}"
        description: "{DESCRIPTION}"
"#,
            key = key_file.display(),
            admin_sha256 = busbar_contract::redacted::sha256_hex(ADMIN_TOKEN.as_bytes()),
            url = upstream.url(),
            pin = upstream.pin,
            ca_pem = json::to_string(&upstream.ca_pem).expect("a YAML-compatible PEM string"),
            granted = tool_digest(GRANTED),
            other = tool_digest(OTHER),
        ),
    )
    .unwrap();
    cfg
}

fn busbar(config: &Path) -> Command {
    let mut command = Command::new(common::boot::exe());
    command
        .env("BUSBAR_CONFIG", config)
        .env_remove("BUSBAR_PROVIDERS")
        .env("RUST_LOG", "warn");
    command
}

struct Node {
    child: Child,
    dir: PathBuf,
    data: u16,
    admin: u16,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Node {
    fn canonical_uri(&self) -> String {
        format!("http://127.0.0.1:{}{DOOR}", self.data)
    }

    fn admin_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.admin)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("busbar.log")).unwrap_or_default()
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

async fn boot(tag: &str, upstream: &Upstream) -> Node {
    let dir = fixture_dir(tag);
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    let cfg = write_config(&dir, data, admin, upstream, BINDING);
    let log = std::fs::File::create(dir.join("busbar.log")).unwrap();
    let child = busbar(&cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn busbar");
    let mut node = Node {
        child,
        dir,
        data,
        admin,
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = node.child.try_wait().unwrap() {
            panic!(
                "a configuration granting allowed_mcp_tools did not boot ({status}):\n{}",
                node.log()
            );
        }
        let up = |p: u16| {
            TcpStream::connect_timeout(
                &format!("127.0.0.1:{p}").parse().unwrap(),
                Duration::from_millis(300),
            )
            .is_ok()
        };
        if up(node.data) && up(node.admin) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "busbar did not listen within 120s:\n{}",
            node.log()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let view: Value = json::parse_value(
        &client()
            .post(node.admin_url(&format!("/api/v1/admin/tools/{SERVER}/connect")))
            .bearer_auth(ADMIN_TOKEN)
            .send()
            .await
            .expect("POST connect")
            .bytes()
            .await
            .expect("connect answers"),
    )
    .expect("connect answers JSON");
    assert_eq!(
        view["state"],
        "approved",
        "the connect of `{SERVER}` did not land approved: {view}\n{}",
        node.log()
    );
    node
}

/// POST /keys with `body`: the status and the answer.
async fn mint(node: &Node, body: &Value) -> (u16, Value) {
    let resp = client()
        .post(node.admin_url("/api/v1/admin/keys"))
        .bearer_auth(ADMIN_TOKEN)
        .json(body)
        .send()
        .await
        .expect("POST /keys");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (
        status,
        json::parse_value(text.as_bytes()).unwrap_or_else(|_| Value::from(text.as_str())),
    )
}

/// A key granted the server and exactly one of its tools, bound to the MCP plane's audience.
async fn mint_tool_key(node: &Node) -> String {
    let (status, resp) = mint(
        node,
        &json!({
            "name": "toolkind",
            "audience": node.canonical_uri(),
            "allowed_mcp_servers": [SERVER],
            "allowed_mcp_tools": [format!("{SERVER}_{GRANTED}")],
        }),
    )
    .await;
    assert!(
        (200..300).contains(&status),
        "a key granted one MCP tool is minted: {status} {resp}\n{}",
        node.log()
    );
    resp["token"]
        .as_str()
        .unwrap_or_else(|| panic!("/keys minted no token: {resp}"))
        .to_string()
}

async fn call(node: &Node, bearer: &str, tool: &str) -> (u16, String) {
    let name = format!("{SERVER}_{tool}");
    let resp = client()
        .post(node.canonical_uri())
        .bearer_auth(bearer)
        .header("content-type", "application/json")
        .header("mcp-method", "tools/call")
        .header("mcp-protocol-version", PROTOCOL)
        .header("Mcp-Name", name.as_str())
        .body(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": { "label": "scope" },
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": PROTOCOL,
                        "io.modelcontextprotocol/clientCapabilities": {},
                    },
                },
            })
            .to_string(),
        )
        .send()
        .await
        .expect("POST tools/call");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

#[tokio::test(flavor = "multi_thread")]
async fn role_binding_plane_scope_a_key_granted_one_tool_is_refused_another() {
    let upstream = Upstream::start();
    // (1) The configuration grants `allowed_mcp_tools` in a role binding, and boots.
    let node = boot("served", &upstream).await;
    let bearer = mint_tool_key(&node).await;

    // (2) The granted tool is served, and reaches the upstream once.
    let (status, body) = call(&node, &bearer, GRANTED).await;
    assert_eq!(
        status,
        200,
        "the granted tool is served: {body}\n{}",
        node.log()
    );
    assert!(
        body.contains("ping: scope"),
        "the served call carries the upstream's answer: {body}"
    );
    assert_eq!(upstream.calls(), [GRANTED]);

    // The other tool of the same granted server is refused, and never reaches the upstream.
    let (status, body) = call(&node, &bearer, OTHER).await;
    assert!(
        status != 200 || body.contains("\"error\""),
        "a tool the key is not granted is refused: {status} {body}"
    );
    assert!(
        !body.contains("pong: scope"),
        "a refused tool carried an upstream answer: {body}"
    );
    assert_eq!(
        upstream.calls(),
        [GRANTED],
        "a tool the key is not granted reached the upstream"
    );

    // (3) A kind no loaded plane states or checks is refused at mint.
    let (status, resp) = mint(
        &node,
        &json!({ "name": "unknown-kind", "allowed_toolkind_frobs": ["x"] }),
    )
    .await;
    assert!(
        !(200..300).contains(&status),
        "a key of a kind no plane declares is refused: {status} {resp}"
    );
}

#[test]
fn role_binding_plane_scope_an_unknown_kind_is_still_refused_by_validation() {
    let upstream = Upstream::start();
    let validate = |tag: &str, binding: &str| {
        let dir = fixture_dir(tag);
        let cfg = write_config(
            &dir,
            common::boot::free_port(),
            common::boot::free_port(),
            &upstream,
            binding,
        );
        let out = busbar(&cfg)
            .arg("--validate")
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

    // The per-tool grant is not a role-binding refusal.
    let (_, text) = validate("declared", BINDING);
    assert!(
        !text.contains("BUSBAR-3114"),
        "a binding of the kind the MCP plane checks is not refused:\n{text}"
    );

    // A kind no loaded plane states or checks is refused, naming the field.
    let (code, text) = validate(
        "undeclared",
        "{ allowed_mcp_servers: [probe], allowed_toolkind_frobs: [x] }",
    );
    assert_ne!(
        code,
        Some(0),
        "a kind no plane declares is refused:\n{text}"
    );
    assert!(
        text.contains("allowed_toolkind_frobs") && text.contains("BUSBAR-3114"),
        "the refusal names the field and its code:\n{text}"
    );
}
