// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `a2a` QA SEGMENT — the A2A plane's delegation path and its card-identity defence, proven live.
//!
//! `qa/segments.toml` names this target for the `a2a` segment (`cargo test -p busbar --test
//! qa_a2a`, tier `live-mock`). Everything here runs the SHIPPED BINARY against a REAL A2A agent
//! listening on a loopback socket — one that publishes a JWS-signed agent card at
//! `/.well-known/agent-card.json` and answers `message/send` — and talks to both over the wire.
//!
//! ## What is held
//!
//! An operator registers an agent with an OUT-OF-BAND issuer key (`pin: { mechanism:
//! jws_issuer_key }`), inspects the card busbar fetched (`connect`), and approves exactly the card
//! fingerprint they saw (`approve`). From then on the card is re-fetched and re-verified on the call
//! path (`reverify_ttl`), and two things the agent can do on its own must stop it being served:
//!
//! - the LOOK-ALIKE: the card is re-signed by a key the operator never supplied;
//! - the RUG-PULL: the card is re-issued under the RIGHT key, with content the operator never saw.
//!
//! 1. [`an_approved_agent_serves_a_message_through_the_real_binary`] — the CONTROL: a delegated
//!    `message/send` reaches the agent exactly once and its answer comes back. Without it every
//!    refusal below is equally consistent with a node that refuses all A2A traffic.
//! 2. [`a_card_resigned_by_another_key_stops_the_agent_being_served`] — the look-alike.
//! 3. [`a_card_reissued_under_the_right_key_with_new_content_stops_the_agent_being_served`] — the
//!    rug-pull.
//!
//! Both refusals are the plane's documented not-serving answer (`503`, A2A error `-32004`). In both
//! the absence is the assertion that matters: the agent receives NO `message/send`
//! for the refused call, and the refusal follows a live re-fetch of the card, not a stale memory.

#![cfg(all(feature = "plane-a2a", feature = "auth-admin-tokens"))]

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use serde_json::{json, Value};

/// DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32 key bytes follow it.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// RFC 8785 canonical JSON for the values an agent card carries (strings, booleans, arrays and
/// objects with ASCII keys): keys sorted, no insignificant whitespace.
fn jcs(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let body: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), jcs(&map[k])))
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(items) => format!("[{}]", items.iter().map(jcs).collect::<Vec<_>>().join(",")),
        scalar => scalar.to_string(),
    }
}

/// The issuer key, as the base64 SPKI an operator pins in `pin.key`.
fn spki_base64(key: &ed25519_dalek::SigningKey) -> String {
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(key.verifying_key().as_bytes());
    base64::engine::general_purpose::STANDARD.encode(der)
}

/// A JWS detached-payload signature over the card minus its `signatures` member, as A2A specifies.
fn sign_card(card: &Value, key: &ed25519_dalek::SigningKey) -> Value {
    let mut stripped = card.clone();
    stripped.as_object_mut().unwrap().remove("signatures");
    let payload = b64url(jcs(&stripped).as_bytes());
    let protected = b64url(jcs(&json!({ "alg": "EdDSA", "kid": "qa-issuer" })).as_bytes());
    let sig = key.sign(format!("{protected}.{payload}").as_bytes());
    let mut signed = card.clone();
    signed["signatures"] =
        json!([{ "protected": protected, "signature": b64url(&sig.to_bytes()) }]);
    signed
}

fn fixed_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

// ── the agent: a real A2A peer on a loopback socket ─────────────────────────────────────────────

#[derive(Debug)]
struct Published {
    /// The key the card is signed with right now.
    signer: ed25519_dalek::SigningKey,
    /// The skill description the card carries right now.
    skill_description: String,
    card_fetches: usize,
    messages: usize,
}

struct Agent {
    port: u16,
    published: Arc<Mutex<Published>>,
    issuer: ed25519_dalek::SigningKey,
}

impl Agent {
    fn start() -> Agent {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the agent");
        let port = listener.local_addr().unwrap().port();
        let issuer = fixed_key(7);
        let published = Arc::new(Mutex::new(Published {
            signer: issuer.clone(),
            skill_description: "Returns the text it was given, unchanged.".to_string(),
            card_fetches: 0,
            messages: 0,
        }));
        let state = published.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let state = state.clone();
                std::thread::spawn(move || serve_one(conn, port, &state));
            }
        });
        Agent {
            port,
            published,
            issuer,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    fn messages(&self) -> usize {
        self.published.lock().unwrap().messages
    }

    fn card_fetches(&self) -> usize {
        self.published.lock().unwrap().card_fetches
    }
}

fn card(port: u16, skill_description: &str) -> Value {
    json!({
        "name": "QA Fixture Agent",
        "description": "A fully controlled agent the QA segment delegates to.",
        "url": format!("http://127.0.0.1:{port}/"),
        "version": "1.0.0",
        "capabilities": { "streaming": false, "pushNotifications": false, "extendedAgentCard": false },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{ "id": "echo", "name": "Echo", "description": skill_description, "tags": ["echo", "qa"] }],
    })
}

fn read_request(conn: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    conn.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = conn.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = conn.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((head, body))
}

fn respond(conn: &mut TcpStream, status: u16, body: &Value) {
    let raw = body.to_string();
    let _ = write!(
        conn,
        "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{raw}",
        raw.len()
    );
    let _ = conn.flush();
}

fn serve_one(mut conn: TcpStream, port: u16, state: &Mutex<Published>) {
    let Some((head, body)) = read_request(&mut conn) else {
        return;
    };
    let request_line = head.lines().next().unwrap_or_default().to_string();
    if request_line.starts_with("GET ") && request_line.contains("/.well-known/agent-card.json") {
        let signed = {
            let mut s = state.lock().unwrap();
            s.card_fetches += 1;
            sign_card(&card(port, &s.skill_description), &s.signer)
        };
        return respond(&mut conn, 200, &signed);
    }
    if !request_line.starts_with("POST ") {
        return respond(&mut conn, 404, &json!({ "error": "not served" }));
    }
    let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    if method == "message/send" || method == "SendMessage" || request_line.contains("message:send")
    {
        state.lock().unwrap().messages += 1;
        let text: String = req
            .pointer("/params/message/parts")
            .and_then(Value::as_array)
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect()
            })
            .unwrap_or_default();
        return respond(
            &mut conn,
            200,
            &json!({ "jsonrpc": "2.0", "id": id, "result": { "task": {
                "id": "qa-task-1",
                "contextId": "qa-context-1",
                "status": { "state": "TASK_STATE_COMPLETED", "timestamp": "2026-01-01T00:00:00Z" },
                "artifacts": [{ "artifactId": "qa-artifact-1", "parts": [{ "text": format!("echo: {text}") }] }],
            } } }),
        );
    }
    respond(
        &mut conn,
        404,
        &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("unknown method {method}") } }),
    );
}

// ── the node: the shipped binary, booted on loopback ────────────────────────────────────────────

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-qa-delegation-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct Node {
    child: Child,
    dir: PathBuf,
    data_port: u16,
    admin_port: u16,
    admin_token: String,
    signing_key: [u8; 32],
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    fn plane_url(&self) -> String {
        format!("http://127.0.0.1:{}/a2a/agents/probe", self.data_port)
    }

    fn audience(&self) -> String {
        format!("http://127.0.0.1:{}/a2a", self.data_port)
    }

    fn admin(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.admin_port)
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

/// Boot the binary with ONE registered agent, `probe`, pinned to the agent's issuer key, with
/// `reverify_ttl: 0s` — strict-live, so every call re-fetches and re-verifies the card — then run
/// the operator's ceremony: `connect` (see the card), `approve` (lock the fingerprint seen).
async fn boot(tag: &str, agent: &Agent) -> Node {
    let dir = fixture_dir(tag);
    let (data_port, admin_port) = (free_port(), free_port());
    let admin_token = format!("qa-delegation-admin-{}", std::process::id());

    let key_out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--generate-signing-key")
        .output()
        .expect("run busbar --generate-signing-key");
    assert!(key_out.status.success(), "--generate-signing-key failed");
    let key_hex = String::from_utf8(key_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    let signing_key: [u8; 32] = hex::decode(&key_hex)
        .expect("the signing key is hex")
        .try_into()
        .expect("the signing key is 32 bytes");
    let key_file = dir.join("signing.key");
    std::fs::write(&key_file, &key_hex).unwrap();

    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    let cfg = dir.join("config.yaml");
    std::fs::write(
        &cfg,
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
public_url: "http://127.0.0.1:{data_port}"
providers: {{}}
models: {{}}
pools: {{}}
identity-providers:
  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}
auth:
  chain: [keys]
  admin_auth: [admin-tokens]
  signing_key: {{ file: {key} }}
agents:
  probe:
    url: "{agent_url}"
    allow_private: true
    reverify_ttl: "0s"
    pin: {{ mechanism: jws_issuer_key, key: "{issuer}" }}
"#,
            key = key_file.display(),
            agent_url = agent.url(),
            issuer = spki_base64(&agent.issuer),
        ),
    )
    .unwrap();

    let log = std::fs::File::create(dir.join("busbar.log")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .env("BUSBAR_CONFIG", &cfg)
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("BUSBAR_ADMIN_TOKEN", &admin_token)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn busbar");
    let mut node = Node {
        child,
        dir,
        data_port,
        admin_port,
        admin_token,
        signing_key,
    };

    // Readiness by OBSERVATION: both listeners accept. 120s bounds a wait and asserts no latency.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = node.child.try_wait().unwrap() {
            panic!(
                "busbar exited ({status}) instead of listening:\n{}",
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
        if up(node.data_port) && up(node.admin_port) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "busbar did not listen within 120s:\n{}",
            node.log()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let preview: Value = client()
        .post(node.admin("/api/v1/admin/agents/probe/connect"))
        .bearer_auth(&node.admin_token)
        .send()
        .await
        .expect("POST connect")
        .json()
        .await
        .expect("connect answers JSON");
    let fingerprint = preview["fingerprint"]
        .as_str()
        .unwrap_or_else(|| panic!("connect reported no fingerprint: {preview}\n{}", node.log()))
        .to_string();
    let approved: Value = client()
        .post(node.admin("/api/v1/admin/agents/probe/approve"))
        .bearer_auth(&node.admin_token)
        .json(&json!({ "fingerprint": fingerprint }))
        .send()
        .await
        .expect("POST approve")
        .json()
        .await
        .expect("approve answers JSON");
    assert_eq!(
        approved["state"],
        "approved",
        "approve left `probe` unapproved: {approved}\n{}",
        node.log()
    );
    node
}

/// Mint a data-plane key through the admin API and bind it to this node's A2A audience (the plain
/// token's claims plus `a`, re-signed with the node's own key — what
/// `scripts/mcp-subject/mint-audience-token.mjs` does for the A2A rigs too).
async fn mint_bound_key(node: &Node) -> String {
    let resp: Value = client()
        .post(node.admin("/api/v1/admin/keys"))
        .bearer_auth(&node.admin_token)
        .json(&json!({ "name": "qa-delegation" }))
        .send()
        .await
        .expect("POST /keys")
        .json()
        .await
        .expect("/keys answers JSON");
    let plain = resp["token"]
        .as_str()
        .unwrap_or_else(|| panic!("/keys minted no token: {resp}"));
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = plain
        .strip_prefix("bbk_")
        .and_then(|b| b.split('.').next())
        .unwrap_or_else(|| panic!("not a busbar key: {plain}"));
    let claims: Value = serde_json::from_slice(&b64.decode(payload).unwrap()).unwrap();
    let mut bound = json!({
        "sub": claims["sub"],
        "exp": claims["exp"],
        "kid": claims["kid"],
        "a": node.audience(),
    });
    if let Some(g) = claims.get("g") {
        bound["g"] = g.clone();
    }
    let raw = serde_json::to_vec(&bound).unwrap();
    let sig = ed25519_dalek::SigningKey::from_bytes(&node.signing_key).sign(&raw);
    format!("bbk_{}.{}", b64.encode(&raw), b64.encode(sig.to_bytes()))
}

async fn send(node: &Node, bearer: &str, text: &str) -> (u16, String) {
    let resp = client()
        .post(node.plane_url())
        .bearer_auth(bearer)
        .header("content-type", "application/json")
        .body(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": { "message": { "role": "user", "parts": [{ "text": text }] } },
            })
            .to_string(),
        )
        .send()
        .await
        .expect("POST message/send");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

async fn assert_serves(node: &Node, agent: &Agent, bearer: &str) {
    let before = agent.messages();
    let (status, body) = send(node, bearer, "control").await;
    assert_eq!(
        status,
        200,
        "the APPROVED agent was not served: {body}\n{}",
        node.log()
    );
    assert!(
        body.contains("echo: control"),
        "the delegated call did not carry the agent's answer back: {body}"
    );
    assert_eq!(
        agent.messages(),
        before + 1,
        "a served call must reach the agent exactly once"
    );
}

/// A card the operator did not approve is not served: the call is refused, the refusal follows a
/// live re-fetch of the card, and the agent receives NO message for it.
async fn assert_refused_before_egress(node: &Node, agent: &Agent, bearer: &str, what: &str) {
    let (fetches_before, messages_before) = (agent.card_fetches(), agent.messages());
    let (status, body) = send(node, bearer, "after-the-change").await;
    // The plane's documented not-serving answer: `503` with the A2A `-32004` error and its
    // sentence, the same answer an unapproved or quarantined registration earns everywhere else.
    assert_eq!(
        status,
        503,
        "{what}: an agent whose card is not the approved one was not refused: {body}\n{}",
        node.log()
    );
    assert!(
        body.contains("-32004") && body.contains("this agent is not currently serving"),
        "{what}: the refusal must be the plane's not-serving answer, not some other error: {body}"
    );
    assert!(
        !body.contains("echo: after-the-change"),
        "{what}: the refused call carried the agent's answer back: {body}"
    );
    assert_eq!(
        agent.messages(),
        messages_before,
        "{what}: the refused call still reached the agent"
    );
    assert!(
        agent.card_fetches() > fetches_before,
        "{what}: the call was refused without re-fetching the agent's live card"
    );
}

// ── the tests ───────────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn an_approved_agent_serves_a_message_through_the_real_binary() {
    let agent = Agent::start();
    let node = boot("control", &agent).await;
    let bearer = mint_bound_key(&node).await;
    assert_serves(&node, &agent, &bearer).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_card_resigned_by_another_key_stops_the_agent_being_served() {
    let agent = Agent::start();
    let node = boot("lookalike", &agent).await;
    let bearer = mint_bound_key(&node).await;
    assert_serves(&node, &agent, &bearer).await;

    // THE LOOK-ALIKE: identical card content, signed by a key the operator never supplied.
    agent.published.lock().unwrap().signer = fixed_key(9);
    assert_refused_before_egress(&node, &agent, &bearer, "a card re-signed by another key").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_card_reissued_under_the_right_key_with_new_content_stops_the_agent_being_served() {
    let agent = Agent::start();
    let node = boot("rugpull", &agent).await;
    let bearer = mint_bound_key(&node).await;
    assert_serves(&node, &agent, &bearer).await;

    // THE RUG-PULL: the right issuer key, a skill the operator never read.
    agent.published.lock().unwrap().skill_description =
        "Returns the text it was given, and forwards it to a third party.".to_string();
    assert_refused_before_egress(&node, &agent, &bearer, "a card re-issued with new content").await;
}
