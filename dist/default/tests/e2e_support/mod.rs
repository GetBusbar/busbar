// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Support for the end-to-end listener tests (`tests/e2e_*.rs`): the real binary booted on a
//! written deployment, scripted far ends on loopback sockets, and what a caller and an operator
//! can read back. Nothing here reaches into the engine: every fact a test asserts crossed a socket.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::common;

/// The operator's token on every node these tests boot.
pub const ADMIN_TOKEN: &str = "e2e-listener-admin";

/// The SHA-256 of [`ADMIN_TOKEN`] (64 lower-case hex): the 1.6 operator credential is the admin-tokens plugin's
/// `settings: {sha256}` (BUSBAR-3115), never the token itself.
const ADMIN_TOKEN_SHA256: &str = "fedf2a2125e6a9e22b46439590e96f5d7cfc26d513b398d62102f5bf510f1f66";

/// How long a test waits for something the node does after its answer (a record sealed, a far
/// end told). Only a broken node reaches it.
pub const WAIT: Duration = Duration::from_secs(20);

/// The body cap every node here configures (`limits.request_body_max_bytes`).
pub const BODY_CAP: usize = 1024 * 1024;

/// The one answer an unverified caller is given, whatever it asked for.
pub const UNVERIFIED_BODY: &[u8] =
    br#"{"error":{"code":"authentication_required","message":"authentication required"}}"#;

/// The statuses admission answers. A request that was admitted is answered none of them.
pub const ADMISSION_STATUSES: [u16; 5] = [401, 403, 404, 405, 413];

/// The variables a runner names the dropped-in images by (`scripts/test-libs.sh` rows). A
/// distribution that links the image needs none; one that does not is given the image here.
pub const WS_TRANSPORT_IMAGE: &str = "BUSBAR_TEST_TRANSPORT_WS_CDYLIB";
pub const WEBHOOK_SIGNATURE_IMAGE: &str = "BUSBAR_TEST_AUTH_WEBHOOK_SIGNATURE_CDYLIB";
pub const WEBREQUEST_HOOK_IMAGE: &str = "BUSBAR_TEST_HOOK_WEBREQUEST_CDYLIB";

/// One OpenAI chat request for the pool `e2e`.
pub const CHAT: &[u8] = br#"{"model":"e2e","messages":[{"role":"user","content":"hi"}]}"#;

/// An OpenAI chat completion reporting this usage.
pub fn chat_answer(prompt_tokens: u64, completion_tokens: u64) -> Value {
    json!({
        "id": "chatcmpl-e2e", "object": "chat.completion", "created": 1, "model": "test-model",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                  "total_tokens": prompt_tokens + completion_tokens}
    })
}

/// A far end that answers every request with one scripted JSON answer and keeps what it was sent.
pub struct Scripted {
    pub port: u16,
    answer: Arc<Mutex<(u16, String)>>,
    received: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
}

impl Scripted {
    pub fn start(status: u16, body: &Value) -> Scripted {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a scripted far end");
        let port = listener.local_addr().expect("its address").port();
        let answer = Arc::new(Mutex::new((status, body.to_string())));
        let received = Arc::new(Mutex::new(Vec::new()));
        let (answers, requests) = (Arc::clone(&answer), Arc::clone(&received));
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let (answers, requests) = (Arc::clone(&answers), Arc::clone(&requests));
                std::thread::spawn(move || {
                    let mut conn = conn;
                    let Some(request) = common::upstream::read_request(&mut conn) else {
                        return;
                    };
                    requests.lock().expect("the requests").push(request);
                    let (status, body) = answers.lock().expect("the answer").clone();
                    common::upstream::respond(&mut conn, status, &body);
                });
            }
        });
        Scripted {
            port,
            answer,
            received,
        }
    }

    /// What every later request is answered with.
    pub fn set(&self, status: u16, body: &Value) {
        *self.answer.lock().expect("the answer") = (status, body.to_string());
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    /// How many POSTs arrived whose request line names `path_part` (a probe is not a POST).
    pub fn posts(&self, path_part: &str) -> usize {
        self.received
            .lock()
            .expect("the requests")
            .iter()
            .filter(|(head, _)| {
                let line = head.lines().next().unwrap_or("");
                line.starts_with("POST ") && line.contains(path_part)
            })
            .count()
    }
}

/// A loopback port nothing listens on: a dial to it is refused.
pub fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a port to close");
    listener.local_addr().expect("its address").port()
}

/// What one request was answered with.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    /// Names in lower case, in the order sent.
    pub headers: Vec<(String, String)>,
    /// The body with any chunked framing removed.
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("the answer is JSON: {} {}", self.status, self.text()))
    }

    /// Whether admission let the request through: none of the statuses admission answers.
    pub fn admitted(&self) -> bool {
        !ADMISSION_STATUSES.contains(&self.status)
    }

    /// Whether this is the one unverified answer, byte for byte.
    pub fn is_the_unverified_answer(&self) -> bool {
        self.status == 401
            && self.body == UNVERIFIED_BODY
            && self.header("content-type") == Some("application/json")
    }

    /// The header names sent, sorted, without the clock's.
    pub fn header_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .filter(|name| *name != "date")
            .collect();
        names.sort_unstable();
        names
    }

    /// A whole HTTP/1.1 answer as read to the end of its connection.
    pub fn parse(raw: &[u8]) -> Reply {
        let split = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap_or_else(|| {
                panic!(
                    "the node sent no complete answer head: {:?}",
                    String::from_utf8_lossy(raw)
                )
            });
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("the answer has a status line: {head}"));
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        let chunked = headers.iter().any(|(name, value)| {
            name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked")
        });
        let rest = &raw[split + 4..];
        let body = if chunked {
            dechunk(rest).unwrap_or_else(|why| panic!("a chunked answer is whole: {why}"))
        } else {
            rest.to_vec()
        };
        Reply {
            status,
            headers,
            body,
        }
    }
}

/// The bytes of a chunked body that ran to its final chunk.
pub fn dechunk(mut wire: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut body = Vec::new();
    loop {
        let end = wire
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or("a chunk size line is missing")?;
        let size = wire[..end]
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or(&[]);
        let size = std::str::from_utf8(size)
            .ok()
            .and_then(|text| usize::from_str_radix(text.trim(), 16).ok())
            .ok_or("a chunk size is not hexadecimal")?;
        wire = &wire[end + 2..];
        if size == 0 {
            return Ok(body);
        }
        let chunk = wire.get(..size).ok_or("a chunk is cut short")?;
        body.extend_from_slice(chunk);
        wire = wire
            .get(size..)
            .and_then(|rest| rest.strip_prefix(b"\r\n"))
            .ok_or("a chunk does not end in CRLF")?;
    }
}

/// `Authorization: Bearer <token>`'s value.
pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// One HTTP/1.1 request on its own connection, read to the end of the answer.
pub fn send(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the node");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("a read timeout");
    let mut head =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if method != "GET" || !body.is_empty() {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).expect("send the head");
    // A node that answers on the head may close before the body is taken: that is its answer.
    let _ = stream.write_all(body);
    let _ = stream.flush();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    Reply::parse(&raw)
}

/// A JSON POST carrying this bearer.
pub fn post_json(port: u16, path: &str, token: &str, body: &[u8]) -> Reply {
    let authorization = bearer(token);
    send(
        port,
        "POST",
        path,
        &[
            ("Authorization", authorization.as_str()),
            ("Content-Type", "application/json"),
        ],
        body,
    )
}

/// A deployment being written: the fixed part every node here shares, and what one test adds.
pub struct Deployment {
    dir: PathBuf,
    pub data: u16,
    pub admin: u16,
    providers: Vec<(String, String, String)>,
    /// Providers that take no credential (`api_key: none`), by name.
    keyless: Vec<String>,
    identities: String,
    sections: String,
    env: Vec<(String, String)>,
    staged: bool,
}

impl Deployment {
    pub fn new(tag: &str) -> Deployment {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "busbar-e2e-{tag}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos()),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("the deployment's directory");
        Deployment {
            dir,
            data: common::boot::free_port(),
            admin: common::boot::free_port(),
            providers: Vec::new(),
            keyless: Vec::new(),
            identities: String::new(),
            sections: String::new(),
            env: Vec::new(),
            staged: false,
        }
    }

    /// The address callers reach the data listener at, as the deployment publishes it.
    pub fn public_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.data)
    }

    /// A provider of this protocol at this base URL, keyed by the `MOCK_KEY` secret.
    pub fn provider(mut self, name: &str, protocol: &str, base_url: &str) -> Deployment {
        self.providers
            .push((name.to_owned(), protocol.to_owned(), base_url.to_owned()));
        self
    }

    /// A provider of this protocol at this base URL that takes no credential (`api_key: none`):
    /// a loopback plaintext upstream, as the live engine of the kit runs one. A credential is never
    /// presented over plaintext, so a keyed provider there is not dialled.
    pub fn keyless_provider(mut self, name: &str, protocol: &str, base_url: &str) -> Deployment {
        self.keyless.push(name.to_owned());
        self.provider(name, protocol, base_url)
    }

    /// One more `identity-providers` entry: its name and its definition as flow YAML.
    pub fn identity(mut self, name: &str, definition: &str) -> Deployment {
        self.identities
            .push_str(&format!("  {name}: {definition}\n"));
        self
    }

    /// Top-level YAML appended as written (`{data_port}` and `{admin_port}` are filled in).
    pub fn section(mut self, yaml: &str) -> Deployment {
        self.sections.push_str(
            &yaml
                .replace("{data_port}", &self.data.to_string())
                .replace("{admin_port}", &self.admin.to_string()),
        );
        if !self.sections.ends_with('\n') {
            self.sections.push('\n');
        }
        self
    }

    pub fn env(mut self, name: &str, value: &str) -> Deployment {
        self.env.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The image `variable` names, dropped in as a signed archive under the fixture publisher.
    /// With the variable unset the distribution is taken to link the image: a node that neither
    /// links it nor is given it refuses to boot, and the test fails there.
    pub fn plugin(mut self, kind: &str, variable: &str) -> Deployment {
        let Some(path) = std::env::var_os(variable) else {
            return self;
        };
        let library = PathBuf::from(path);
        assert!(
            library.is_absolute() && library.is_file(),
            "{variable} names an existing absolute image: {}",
            library.display()
        );
        let plugins = self.dir.join("plugins");
        std::fs::create_dir_all(&plugins).expect("the plugins directory");
        let manifest =
            common::plugins::native_manifest(kind, &library, common::plugins::FIXTURE_PUBLISHER);
        let name = manifest.name.clone();
        let image = std::fs::read(&library).expect("the image reads");
        let archive = common::plugins::signed(
            &common::credentials::harness_release_key(),
            manifest,
            &image,
        );
        std::fs::write(plugins.join(format!("{name}.tar.gz")), archive)
            .expect("stage the signed archive");
        self.staged = true;
        self
    }

    /// Write the deployment, start the real binary on it and wait until both listeners serve.
    pub fn boot(self) -> Node {
        let signing = common::chat_spend::signing_key(&self.dir);
        let mut catalog = String::new();
        let mut keyed = String::new();
        for (name, protocol, base_url) in &self.providers {
            // `error_map` is required on a resolved entry (the llm plane's D_PROVIDER_SCHEMA); the
            // shipped catalog supplies it for its own providers, a written entry states it.
            catalog.push_str(&format!(
                "{name}:\n  protocol: {protocol}\n  base_url: \"{base_url}\"\n  error_map: {{}}\n"
            ));
            if self.keyless.contains(name) {
                keyed.push_str(&format!("  {name}:\n    api_key: none\n"));
            } else {
                keyed.push_str(&format!("  {name}:\n    api_key: {{ env: MOCK_KEY }}\n"));
            }
        }
        if catalog.is_empty() {
            catalog.push_str("{}\n");
        }
        let providers = if keyed.is_empty() {
            "providers: {}\n".to_owned()
        } else {
            format!("providers:\n{keyed}")
        };
        std::fs::write(self.dir.join("providers.yaml"), catalog).expect("write providers.yaml");
        let plugins = if self.staged {
            format!(
                "plugins: {}\n",
                common::plugins::trusted_config_document(&self.dir.join("plugins"))
            )
        } else {
            String::new()
        };
        let config = self.dir.join("config.yaml");
        std::fs::write(
            &config,
            format!(
                r#"config_version: 1
listen: "127.0.0.1:{data}"
admin_listen: "127.0.0.1:{admin}"
listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test node" }}
admin_listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test node" }}
admin_require_mtls: false
store: {{module: memory}}
public_url: "http://127.0.0.1:{data}"
limits:
  request_body_max_bytes: {BODY_CAP}
{plugins}identity-providers:
  admin-tokens:
    module: admin-tokens
    settings: {{ sha256: "{ADMIN_TOKEN_SHA256}" }}
{identities}auth:
  chain: [keys]
  signing_key: {{ file: "{signing}" }}
  admin_auth: [admin-tokens]
{providers}{sections}"#,
                data = self.data,
                admin = self.admin,
                identities = self.identities,
                signing = signing.display(),
                sections = self.sections,
            ),
        )
        .expect("write config.yaml");
        let log = self.dir.join("node.log");
        let out = std::fs::File::create(&log).expect("the node's log");
        let mut command = Command::new(common::boot::exe());
        command
            .env("BUSBAR_CONFIG", &config)
            .env_remove("BUSBAR_PROVIDERS")
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("MOCK_KEY", "k")
            // `info`: the readiness wait reads the two `busbar listening` lines, logged at info.
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(out.try_clone().expect("the node's log, twice"))
            .stderr(out);
        if self.staged {
            command.env(
                common::credentials::HARNESS_FIRST_PARTY_KEY_ENV,
                common::credentials::harness_release_key_hex(),
            );
        }
        for (name, value) in &self.env {
            command.env(name, value);
        }
        let mut node = Node {
            child: command.spawn().expect("spawn busbar"),
            dir: self.dir,
            data: self.data,
            admin: self.admin,
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = node.child.try_wait().expect("try_wait") {
                panic!("busbar exited before serving ({status:?})");
            }
            if common::boot::log_shows_data_and_admin_listening(&node.log())
                && common::boot::healthz_answers(node.data)
            {
                return node;
            }
            assert!(Instant::now() < deadline, "busbar never served");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// A key the operator minted: its `/keys` id and the token a caller presents.
#[derive(Debug, Clone)]
pub struct Key {
    pub id: String,
    pub token: String,
}

/// A booted node. Dropping it stops the process; a failing test prints the node's log.
pub struct Node {
    child: std::process::Child,
    dir: PathBuf,
    pub data: u16,
    pub admin: u16,
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
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The `config.yaml` this node booted from: a test rewrites it before a `/config/reload`.
    pub fn config_path(&self) -> PathBuf {
        self.dir.join("config.yaml")
    }

    /// One operator request on the admin listener.
    pub fn operator(&self, method: &str, path: &str, body: Option<&Value>) -> Reply {
        let body = body.map(Value::to_string).unwrap_or_default();
        let authorization = bearer(ADMIN_TOKEN);
        send(
            self.admin,
            method,
            path,
            &[
                ("Authorization", authorization.as_str()),
                ("Content-Type", "application/json"),
            ],
            body.as_bytes(),
        )
    }

    /// Mint a key from this request body (`name`, and any of `group`, `audience`, grants).
    pub fn mint(&self, spec: &Value) -> Key {
        let reply = self.operator("POST", "/api/v1/admin/keys", Some(spec));
        assert!(
            reply.status < 300,
            "the operator mints a key: {} {}",
            reply.status,
            reply.text()
        );
        let minted = reply.json();
        let field = |name: &str| {
            minted[name]
                .as_str()
                .unwrap_or_else(|| panic!("a minted key states its `{name}`: {minted}"))
                .to_owned()
        };
        Key {
            id: field("id"),
            token: field("token"),
        }
    }

    /// The sealed unit records of one key, oldest first, as `/records` serves them now.
    pub fn records_of(&self, key: &Key) -> Vec<Value> {
        let reply = self.operator(
            "GET",
            &format!("/api/v1/admin/records?key={}&limit=1000", key.id),
            None,
        );
        assert_eq!(reply.status, 200, "the records read: {}", reply.text());
        reply.json()["items"]
            .as_array()
            .unwrap_or_else(|| panic!("a records page has items: {}", reply.text()))
            .clone()
    }

    /// The key's records once it has at least `count` of them: a unit's record is sealed after
    /// its answer ends, so a test waits for it. A unit that never settles fails here.
    pub fn settled(&self, key: &Key, count: usize) -> Vec<Value> {
        let deadline = Instant::now() + WAIT;
        loop {
            let records = self.records_of(key);
            if records.len() >= count {
                return records;
            }
            assert!(
                Instant::now() < deadline,
                "{count} unit(s) of key {} never settled; sealed so far: {records:?}",
                key.id
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The key's first sealed record that `is` holds for, waited for as [`Node::settled`] waits.
    pub fn settled_where(&self, key: &Key, is: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            let records = self.records_of(key);
            if let Some(found) = records.iter().find(|record| is(record)) {
                return found.clone();
            }
            assert!(
                Instant::now() < deadline,
                "the unit of key {} never settled; sealed so far: {records:?}",
                key.id
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// The `delivery` group of a unit record: its state, its reason, its count of body bytes.
pub fn delivery(record: &Value) -> (String, Option<String>, u64) {
    let group = &record["delivery"];
    (
        group["state"]
            .as_str()
            .unwrap_or_else(|| panic!("a unit record states its delivery: {record}"))
            .to_owned(),
        group["reason"].as_str().map(str::to_owned),
        group["body_bytes"]
            .as_u64()
            .unwrap_or_else(|| panic!("a delivery states its body bytes: {record}")),
    )
}

/// The LLM deployment the HTTP tests share: one OpenAI provider at `upstream`, the model
/// `test-model`, the pool `e2e` over it, and (with `gate`) one gate hook on every pool whose
/// decisions the far end at `gate` makes.
pub fn llm(tag: &str, upstream: &Scripted, gate: Option<&Scripted>) -> Deployment {
    let deployment = Deployment::new(tag)
        .provider("mock", "openai", &upstream.url(""))
        .section("models:\n  test-model:\n    provider: mock\n");
    match gate {
        None => deployment.section("pools:\n  e2e:\n    members:\n      - { model: test-model }\n"),
        Some(gate) => deployment
            .plugin("hook", WEBREQUEST_HOOK_IMAGE)
            .section(&gate_hook(gate))
            .section(
                "pools:\n  hooks: [gate]\n  e2e:\n    members:\n      - { model: test-model }\n",
            ),
    }
}

/// The `hooks:` definition of the gate `gate`, decided by the far end at `target`. A gate that
/// cannot be asked refuses (`on_error: reject`), so an unasked gate never passes for an allow.
pub fn gate_hook(target: &Scripted) -> String {
    format!(
        "hooks:\n  gate:\n    module: webrequest\n    kind: gate\n    prompt: ro\n    \
         timeout_ms: 2000\n    on_error: reject\n    settings: {{ url: \"{}\" }}\n",
        target.url("/decide")
    )
}

/// A gate's answer that has no opinion.
pub fn abstain() -> Value {
    json!({ "abstain": true })
}

/// A gate's refusal with this status and message.
pub fn reject(status: u16, message: &str) -> Value {
    json!({ "reject": { "status": status, "message": message } })
}

/// The streaming plane over one OpenAI Realtime provider at `base_url`, with the model
/// `test-model` its sessions dial.
pub fn realtime(deployment: Deployment, base_url: &str) -> Deployment {
    deployment
        .provider("rt", "openai", base_url)
        .section("models:\n  test-model:\n    provider: rt\n")
}

/// The streaming plane's section the realtime tests share; `extra` is appended inside it. A 1.6
/// plane section is keyed by the admitted plane instance's name (`streaming`), not by the 1.5
/// `streams:` key the plane's own bag still reads (the config recognizer, WP1-GAP-plane-sections).
/// No `media:`: the browser media listener is core route config in 1.6 (`routes.<id>.media`); in
/// the plane section it is the 1.5 shape the plane converts on open, which a 1.6 document refuses.
pub fn streams_section(extra: &str) -> String {
    format!(
        "streaming:\n  session:\n    model: test-model\n  context_window_tokens: 16384\n{extra}"
    )
}
