// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SIGNED-REQUEST INGRESS AT THE BUSBAR BOUNDARY, on the shipped binary: a client that signs
//! each request with a credential busbar minted and holds is ADMITTED when its signature is right,
//! REFUSED when the signed request was altered, and REFUSED, byte for byte the same, when the key
//! id is one busbar never minted. The verify is the linked auth plugin's, reading the minted key's
//! secret through the host's `records.secret` on the serve path; only a booted binary has that
//! wired, so these cells boot it.
//!
//! The suite names no dialect, scheme or vendor header: the wire facts (the dialect, the scheme's
//! tokens and header names, the route, the body, the key fields of the admin mint) are read from
//! `testing/wire-facts/signed-ingress.json`, and the refusal is compared to the 1.5.5 oracle
//! cell it names (`testing/shadow-oracle/golden/1.5.5/cells`): status, body and every recorded
//! header. The plugin's own repository keeps the full both-ways suite at the pinned rev; these are
//! busbar's cells for the same three claims, so the binding that cites them is proven in this tree.
#![cfg(unix)]
#![cfg(all(
    linked_section_pools,
    linked_every_auth,
    linked_operator_auth,
    feature = "root-admin"
))]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

const ADMIN_TOKEN: &str = "signed-ingress-admin";
/// The provider lane's own credential (`ID:SECRET`), handed to busbar through this env var.
const UPSTREAM_CREDS_ENV: &str = "SIGNED_INGRESS_UPSTREAM_CREDS";
/// The client-facing model name.
const MODEL: &str = "test-model";
const BOOT_BUDGET: Duration = Duration::from_secs(60);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The wire facts document.
fn wire() -> &'static serde_json::Value {
    static DOC: OnceLock<serde_json::Value> = OnceLock::new();
    DOC.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testing/wire-facts/signed-ingress.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("the wire facts are readable"))
            .expect("the wire facts are JSON")
    })
}

/// One string fact of the wire document.
fn w(key: &str) -> &'static str {
    wire()[key]
        .as_str()
        .unwrap_or_else(|| panic!("the wire facts carry `{key}`"))
}

/// The 1.5.5 oracle cell the refusals must equal.
fn recorded_refusal() -> &'static serde_json::Value {
    static DOC: OnceLock<serde_json::Value> = OnceLock::new();
    DOC.get_or_init(|| {
        let path = format!(
            "{}/../../testing/shadow-oracle/golden/1.5.5/cells/{}.json",
            env!("CARGO_MANIFEST_DIR"),
            w("refusal_cell")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the oracle cell is readable"))
            .expect("the oracle cell is JSON")
    })
}

/// The route the signed clients post to.
fn route() -> String {
    w("path").replace("{model}", MODEL)
}

/// The request body, and the same body with one byte altered.
fn body() -> Vec<u8> {
    w("request_body").as_bytes().to_vec()
}

fn altered_body() -> Vec<u8> {
    let (from, to) = (w("tamper_from"), w("tamper_to"));
    let text = w("request_body");
    assert_eq!(from.len(), to.len(), "the alteration keeps the length");
    assert!(text.contains(from), "the body carries the altered span");
    text.replacen(from, to, 1).into_bytes()
}

/// What the three cells share: a booted node, its capturing upstream, and one minted key.
struct Rig {
    node: Node,
    upstream: Upstream,
    data_port: u16,
    key_id: String,
    key_secret: String,
}

impl Rig {
    fn boot() -> Self {
        let dir = fixture_dir();
        let upstream = Upstream::spawn();
        let data_port = common::boot::free_port();
        let admin_port = common::boot::free_port();
        write_configs(&dir, data_port, admin_port, upstream.port);

        let log_path = dir.join("out.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let log_err = log.try_clone().unwrap();
        let child = Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env(
                UPSTREAM_CREDS_ENV,
                format!("{}:{}", w("upstream_id"), w("upstream_secret")),
            )
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("RUST_LOG", "warn")
            .stdout(log)
            .stderr(log_err)
            .spawn()
            .expect("spawn busbar");
        let mut node = Node {
            child,
            dir,
            log_path,
        };
        node.wait_listening(data_port, admin_port);
        let minted = node.mint_key(admin_port);
        let field = |name: &str| {
            let key = w(name);
            minted[key]
                .as_str()
                .unwrap_or_else(|| node.fail(&format!("the mint carried no `{key}`: {minted}")))
                .to_string()
        };
        let (key_id, key_secret) = (field("mint_id_field"), field("mint_secret_field"));
        Self {
            node,
            upstream,
            data_port,
            key_id,
            key_secret,
        }
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.data_port)
    }

    /// Post `body` to the route under `headers`.
    fn post(&self, headers: &[(String, String)], body: &[u8]) -> Response {
        send(self.data_port, &self.host(), &route(), headers, body)
    }

    /// `body` signed by the minted key.
    fn signed_by_the_key(&self, body: &[u8]) -> Vec<(String, String)> {
        sign_client_request(&self.key_id, &self.key_secret, &self.host(), &route(), body)
    }
}

#[test]
fn a_correctly_signed_request_is_admitted_at_the_boundary() {
    let rig = Rig::boot();
    let body = body();
    let headers = rig.signed_by_the_key(&body);
    let answer = rig.post(&headers, &body);
    assert_eq!(
        answer.status,
        200,
        "a correctly signed request must be admitted: {}\nlog:\n{}",
        answer.text,
        rig.node.log()
    );
    let seen = rig.upstream.captured();
    assert_eq!(
        seen.len(),
        1,
        "the admitted request reaches the upstream exactly once"
    );
    let outbound = seen[0]
        .header("authorization")
        .expect("the upstream received an authorization");
    assert!(
        outbound.starts_with(&format!(
            "{} Credential={}/",
            w("algorithm"),
            w("upstream_id")
        )),
        "the upstream is signed under the PROVIDER's key id, never the client's: {outbound}"
    );
    assert!(
        !outbound.contains(&rig.key_id),
        "the client's key id is never forwarded: {outbound}"
    );
}

#[test]
fn a_signed_request_with_an_altered_body_is_refused_with_the_recorded_refusal() {
    let rig = Rig::boot();
    let signed_for = body();
    let headers = rig.signed_by_the_key(&signed_for);
    let altered = altered_body();
    assert_eq!(altered.len(), signed_for.len());
    let refused = rig.post(&headers, &altered);
    assert_eq!(
        refused.status,
        recorded_refusal()["status"].as_u64().expect("status") as u16,
        "an altered signed request gets the recorded refusal status: {}\nlog:\n{}",
        refused.text,
        rig.node.log()
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&refused.body).expect("a JSON refusal"),
        recorded_refusal()["body"]["json"],
        "the refusal body is the 1.5.5 oracle cell's"
    );
    for (name, want) in recorded_refusal()["headers"].as_object().expect("headers") {
        let want = want.as_str().expect("a header value");
        let got = refused.header(name);
        if want == "<UUID>" {
            assert!(
                got.is_some(),
                "the refusal carries `{name}`: {}",
                refused.text
            );
        } else {
            assert_eq!(
                got,
                Some(want),
                "the refusal's `{name}` is the oracle cell's"
            );
        }
    }
    assert!(
        rig.upstream.captured().is_empty(),
        "a refused request never reaches the upstream"
    );
}

#[test]
fn a_signature_by_an_unknown_key_id_is_refused_byte_identically_to_a_bad_signature() {
    let rig = Rig::boot();
    let body = body();
    let unknown = sign_client_request(
        w("unknown_id"),
        w("unknown_secret"),
        &rig.host(),
        &route(),
        &body,
    );
    let no_key = rig.post(&unknown, &body);
    assert_eq!(
        no_key.status,
        recorded_refusal()["status"].as_u64().expect("status") as u16,
        "an unknown key id gets the recorded refusal status: {}\nlog:\n{}",
        no_key.text,
        rig.node.log()
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&no_key.body).expect("a JSON refusal"),
        recorded_refusal()["body"]["json"],
        "the refusal body is the 1.5.5 oracle cell's"
    );
    // The same refusal a bad signature gets: no oracle between "no such key" and "wrong signature".
    let signed_for = rig.signed_by_the_key(&body);
    let bad_signature = rig.post(&signed_for, &altered_body());
    assert_eq!(
        no_key.masked(),
        bad_signature.masked(),
        "an unknown key id and a bad signature are refused byte-identically (only the per-response \
         request id and date may differ)"
    );
    assert!(
        rig.upstream.captured().is_empty(),
        "a refused request never reaches the upstream"
    );
}

// ── the client-side signer ───────────────────────────────────────────────────────────────────────

/// Sign a POST the way the dialect's SDK does: `host;<hash header>;<date header>`, the path
/// double-encoded as the canonical URI. Returns every header to send.
fn sign_client_request(
    id: &str,
    secret: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> Vec<(String, String)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (stamp, datestamp) = format_time(now);
    let (date_header, hash_header) = (w("date_header"), w("hash_header"));
    let payload_hash = sha256_hex(body);
    let signed_headers = format!("host;{hash_header};{date_header}");
    let canonical_request = format!(
        "POST\n{}\n\nhost:{host}\n{hash_header}:{payload_hash}\n{date_header}:{stamp}\n\n\
         {signed_headers}\n{payload_hash}",
        uri_encode(path)
    );
    let scope = format!(
        "{datestamp}/{}/{}/{}",
        w("region"),
        w("service"),
        w("terminator")
    );
    let string_to_sign = format!(
        "{}\n{stamp}\n{scope}\n{}",
        w("algorithm"),
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac_sha256(
        format!("{}{secret}", w("key_prefix")).as_bytes(),
        datestamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, w("region").as_bytes());
    let k_service = hmac_sha256(&k_region, w("service").as_bytes());
    let k_signing = hmac_sha256(&k_service, w("terminator").as_bytes());
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    vec![
        (
            "authorization".to_string(),
            format!(
                "{} Credential={id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
                w("algorithm")
            ),
        ),
        (date_header.to_string(), stamp),
        (hash_header.to_string(), payload_hash),
        ("content-type".to_string(), "application/json".to_string()),
    ]
}

/// HMAC-SHA256 (RFC 2104) over `sha2`.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let inner = Sha256::new()
        .chain_update(&ipad)
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(&opad)
        .chain_update(inner)
        .finalize()
        .to_vec()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// URI encoding of a path: unreserved bytes and `/` pass, every other byte is `%XX`.
fn uri_encode(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `(YYYYMMDDTHHMMSSZ, YYYYMMDD)` for a Unix time, in UTC (civil-from-days).
fn format_time(epoch: u64) -> (String, String) {
    let days = (epoch / 86_400) as i64;
    let sod = epoch % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let date = format!("{y:04}{m:02}{d:02}");
    let stamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    );
    (stamp, date)
}

// ── the node ─────────────────────────────────────────────────────────────────────────────────────

struct Node {
    child: Child,
    dir: PathBuf,
    log_path: PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

impl Node {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    fn fail(&self, why: &str) -> ! {
        panic!("{why}\nbusbar log:\n{}", self.log())
    }

    /// Both listeners accept, failing loud (with the log) if the process dies or the budget runs out.
    fn wait_listening(&mut self, data_port: u16, admin_port: u16) {
        let deadline = Instant::now() + BOOT_BUDGET;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                self.fail(&format!(
                    "busbar exited before listening (status {status:?})"
                ));
            }
            let up = |p: u16| {
                TcpStream::connect_timeout(
                    &format!("127.0.0.1:{p}").parse().unwrap(),
                    Duration::from_millis(300),
                )
                .is_ok()
            };
            if up(data_port) && up(admin_port) {
                return;
            }
            if Instant::now() >= deadline {
                self.fail(&format!("busbar did not listen within {BOOT_BUDGET:?}"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `POST /api/v1/admin/keys` with the signed-credential flag, under the admin token, retried
    /// only while the admin listener is not yet answering (bounded).
    fn mint_key(&self, admin_port: u16) -> serde_json::Value {
        let host = format!("127.0.0.1:{admin_port}");
        let mut fields = serde_json::Map::new();
        fields.insert("name".to_string(), "signed-ingress-cells".into());
        fields.insert(w("mint_flag").to_string(), true.into());
        let body = serde_json::Value::Object(fields).to_string().into_bytes();
        let headers = vec![
            ("authorization".to_string(), format!("Bearer {ADMIN_TOKEN}")),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            let r = send(admin_port, &host, "/api/v1/admin/keys", &headers, &body);
            if r.status == 201 || r.status == 200 {
                return serde_json::from_slice(&r.body).unwrap_or_else(|e| {
                    self.fail(&format!("the mint answered non-JSON ({e}): {}", r.text))
                });
            }
            if Instant::now() >= deadline {
                self.fail(&format!(
                    "the admin API did not mint a signing key within {IO_TIMEOUT:?}; last answer \
                     {}:\n{}",
                    r.status, r.text
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

fn fixture_dir() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "busbar-signed-ingress-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, upstream_port: u16) {
    let fill = |template: &str, signing: &str| {
        template
            .replace("{dialect}", w("dialect"))
            .replace("{upstream_port}", &upstream_port.to_string())
            .replace("{data_port}", &data_port.to_string())
            .replace("{admin_port}", &admin_port.to_string())
            .replace("{operator}", &common::operator_module())
            .replace("{signing}", signing)
            .replace("{creds_env}", UPSTREAM_CREDS_ENV)
            .replace("{model}", MODEL)
            .replace("{wire_model}", w("wire_model"))
    };
    let signing_key = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(signing_key.status.success(), "--generate-signing-key");
    let key_path = dir.join("signing.key");
    std::fs::write(&key_path, &signing_key.stdout).unwrap();
    let key_path = key_path.display().to_string();
    std::fs::write(
        dir.join("providers.yaml"),
        fill(w("providers_template"), &key_path),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        fill(w("config_template"), &key_path),
    )
    .unwrap();
}

// ── the capturing upstream ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Captured {
    /// Lowercased names, values as received.
    headers: Vec<(String, String)>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The provider's stand-in on loopback: records every request it receives and answers each with the
/// recorded reply, one request per connection.
struct Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<Captured>>>,
}

impl Upstream {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(stream) = conn else { continue };
                let sink = sink.clone();
                std::thread::spawn(move || serve_one(stream, &sink));
            }
        });
        Self { port, seen }
    }

    fn captured(&self) -> Vec<Captured> {
        self.seen.lock().unwrap().clone()
    }
}

fn serve_one(mut stream: TcpStream, sink: &Mutex<Vec<Captured>>) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 {
            return;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let find = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v): &(String, String)| v.clone())
    };
    let mut body = Vec::new();
    if find("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        loop {
            let mut size = String::new();
            if reader.read_line(&mut size).unwrap_or(0) == 0 {
                return;
            }
            let n = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
                .unwrap_or(0);
            let mut chunk = vec![0u8; n + 2];
            if reader.read_exact(&mut chunk).is_err() {
                return;
            }
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    } else {
        let n: usize = find("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        body.resize(n, 0);
        if reader.read_exact(&mut body).is_err() {
            return;
        }
    }
    sink.lock().unwrap().push(Captured { headers });
    let payload = w("reply").as_bytes();
    let head = format!(
        "{} 200 OK\r\nContent-Type: application/json\r\n{}: 00000000-0000-4000-8000-000000000000\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        w("http_version"),
        w("request_id_header"),
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(payload);
    let _ = stream.flush();
}

// ── raw client ──────────────────────────────────────────────────────────────────────────────

struct Response {
    /// `0` means no status line arrived at all.
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// The whole response as text, for failure messages and the byte-identity check.
    text: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The raw response with the two values that legitimately differ per response, the request id
    /// and the date, blanked; everything else is compared byte for byte.
    fn masked(&self) -> String {
        let request_id = format!("{}:", w("request_id_header"));
        self.text
            .split("\r\n")
            .map(|l| {
                let lower = l.to_ascii_lowercase();
                if lower.starts_with(&request_id) || lower.starts_with("date:") {
                    l.split(':').next().unwrap_or_default().to_string() + ": <masked>"
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\r\n")
    }
}

/// One POST on a fresh connection with exactly `headers` (plus Host, Content-Length, close).
fn send(port: u16, host: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> Response {
    let empty = Response {
        status: 0,
        headers: Vec::new(),
        body: Vec::new(),
        text: String::new(),
    };
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return empty;
    };
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let mut head = format!("POST {path} {}\r\nHost: {host}\r\n", w("http_version"));
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Response {
            text: String::from_utf8_lossy(&raw).into_owned(),
            ..empty
        };
    };
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    let rest = &raw[split + 4..];
    Response {
        status,
        headers,
        body: if chunked {
            dechunk(rest)
        } else {
            rest.to_vec()
        },
        text: String::from_utf8_lossy(&raw).into_owned(),
    }
}

/// The payload of a chunked body (the whole body was read to EOF first).
fn dechunk(mut rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") {
        let size = String::from_utf8_lossy(&rest[..eol]);
        let n =
            usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16).unwrap_or(0);
        rest = &rest[eol + 2..];
        if n == 0 || rest.len() < n {
            break;
        }
        out.extend_from_slice(&rest[..n]);
        rest = rest.get(n + 2..).unwrap_or_default();
    }
    out
}
