// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! H01/H02, the unauthorized slice of H03 and the dropped-response/shutdown slice of H04,
//! through the actual executable.
//!
//! Only the upstream is a fixture server: the engine is always a separate product process. This
//! test never composes an App, installs a test host, signs a plugin, or grants plugin admission:
//! it consumes the signed pilot cohort the CI job built and lets the product admit it. H04 audit
//! confirmation, lost ACK and restart recovery need the real journal/finalizer evidence and are
//! not inferred here.
//!
//! Inputs. The test is one of the oracle package's binaries (testing/oracle/Cargo.toml), so
//! busbar-release ci/qa.yml `oracle` runs it and root-tests leaves it to that job. It reads the
//! cohort from the `launch.env` that job writes beside `BUSBAR_TEST_PRODUCT_BIN`
//! (testing/oracle/launch.sh); each value may instead be given directly:
//! * `BUSBAR_HOUSE_CORE` (else `ORACLE_CORE`): the actual `busbar` binary, never a wrapper;
//! * `BUSBAR_HOUSE_PACKS` (else `ORACLE_PLUGINS`): the signed pilot packs (`*.tar.gz`);
//! * `BUSBAR_HOUSE_PINS` (else `ORACLE_FETCH`): their `plugins.fetch` pins, one
//!   `    - { url, sha256 }` line per pack;
//! * `BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY` (else `ORACLE_FIRST_PARTY_KEY`): the key the packs
//!   were signed with, which a test-harness core admits as first-party. That is the CI test root,
//!   never production trust; the run prints its exact trust, profile and hashes.
//!
//! A missing input is a named prerequisite failure, never a skip.

#![cfg(unix)]

use busbar_contract::json::{self, JsonValueTrait};
use busbar_contract::yaml;

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ANSWER: &str = r#"{"id":"house-response","object":"chat.completion","created":0,"model":"house-model","choices":[{"index":0,"message":{"role":"assistant","content":"house-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
const FIRST_EVENT: &str = "data: {\"id\":\"house-response\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"house-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"house-ok\"},\"finish_reason\":null}]}\n\n";
const EVENTS: &str = "data: {\"id\":\"house-response\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"house-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"house-ok\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"house-response\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"house-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\ndata: [DONE]\n\n";

/// The documented supported Memory configuration the house boots. Memory Store is ephemeral:
/// this configuration proves nothing about persistent data (H05/H06 use SQLite).
const CONFIG: &str = r#"listen: "@DATA_ADDRESS@"
admin_listen: "@ADMIN_ADDRESS@"
providers_file: "@FIXTURE_DIR@/providers.yaml"
store: { module: memory }
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { file: "@FIXTURE_DIR@/admin-token" }
auth:
  chain: [keys]
  signing_key: { file: "@FIXTURE_DIR@/signing.key" }
  admin_auth: [admin-tokens]
providers:
  house:
    api_key: { file: "@FIXTURE_DIR@/upstream-key" }
models:
  house-model:
    provider: house
plugins:
  enabled: true
  dir: "@FIXTURE_DIR@/plugins"
  trust:
    allow_untrusted: false
  fetch:
@FETCH_PINS@"#;

/// The providers catalog: the controllable LLM upstream fixture this test starts.
const PROVIDERS: &str = "house:\n  protocol: openai\n  base_url: \"@UPSTREAM_URL@\"\n";

/// How the controllable upstream answers the next call.
const WHOLE: usize = 0;
const STREAM: usize = 1;
/// Streamed head and first event, then held open until the test releases it.
const STALL: usize = 2;

/// The cohort under test, as the CI job built and signed it.
struct Cohort {
    core: PathBuf,
    packs: PathBuf,
    pins: String,
    first_party_key: Option<String>,
}

impl Cohort {
    fn from_environment() -> Self {
        let launch = std::env::var_os("BUSBAR_TEST_PRODUCT_BIN")
            .map(PathBuf::from)
            .and_then(|product| product.parent().map(|dir| dir.join("launch.env")))
            .and_then(|path| std::fs::read_to_string(path).ok())
            .map(|text| launch_env(&text))
            .unwrap_or_default();
        let value = |direct: &str, oracle: &str| {
            std::env::var(direct)
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| launch.get(oracle).cloned())
        };
        let path = |direct: &str, oracle: &str| {
            let path = PathBuf::from(value(direct, oracle).unwrap_or_else(|| {
                panic!(
                    "fixture prerequisite missing: {direct} (or {oracle} in the oracle launch.env); \
                     this is not an executed behavior failure"
                )
            }));
            assert!(
                path.is_absolute() && path.exists(),
                "{direct} must exist at an absolute path: {}",
                path.display()
            );
            path
        };
        let core = path("BUSBAR_HOUSE_CORE", "ORACLE_CORE");
        let packs = path("BUSBAR_HOUSE_PACKS", "ORACLE_PLUGINS");
        let pins = std::fs::read_to_string(path("BUSBAR_HOUSE_PINS", "ORACLE_FETCH"))
            .expect("read the signed packs' plugins.fetch pins");
        let mut magic = [0u8; 2];
        std::fs::File::open(&core)
            .and_then(|mut file| file.read_exact(&mut magic))
            .expect("read the product binary");
        assert!(
            core.is_file() && magic != *b"#!",
            "the house runs the actual product binary, not a wrapper: {}",
            core.display()
        );
        Self {
            core,
            packs,
            pins,
            first_party_key: value(
                "BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY",
                "ORACLE_FIRST_PARTY_KEY",
            ),
        }
    }
}

/// `KEY='value'` lines, as ci/qa.yml `oracle` writes launch.env.
fn launch_env(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let value = value.strip_prefix('\'')?.strip_suffix('\'')?;
            Some((key.trim().to_owned(), value.to_owned()))
        })
        .collect()
}

/// The per-run house directory: copies of the signed packs and this run's credentials.
struct House {
    dir: PathBuf,
}

impl Drop for House {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl House {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let dir = std::env::temp_dir().join(format!("busbar-house-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(dir.join("plugins")).expect("create the house directory");
        Self { dir }
    }

    fn secret(&self, name: &str, value: &[u8]) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.dir.join(name))
            .unwrap_or_else(|error| panic!("write house {name}: {error}"));
        std::io::Write::write_all(&mut file, value).expect("write house secret");
    }
}

fn random_hex() -> String {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .expect("read the OS CSPRNG");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Product {
    child: Child,
}

impl Drop for Product {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The controllable LLM upstream: counts every call it actually receives and records any
/// request that differs from what the client sent, so a panic inside a connection task cannot
/// hide a fault.
#[derive(Default)]
struct Upstream {
    calls: AtomicUsize,
    mode: AtomicUsize,
    faults: Mutex<Vec<String>>,
    release: tokio::sync::Notify,
    stall_closed_by_product: AtomicBool,
}

impl Upstream {
    fn fault(&self, fault: String) {
        self.faults.lock().unwrap().push(fault);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn sha256_of(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("read exact cohort bytes");
    busbar_plugin_loader::sign::sha256_hex(&bytes)
}

fn record_hash(path: &Path) -> String {
    let sum = sha256_of(path);
    println!("HOUSE_ARTIFACT {sum} {}", path.display());
    sum
}

/// The `plugins:` section of the rendered configuration, read as the product's own type.
fn plugins_policy(config: &str) -> busbar_kernel::config::PluginsCfg {
    let document: yaml::Value = yaml::from_str(config).expect("the rendered config is YAML");
    let section = document
        .as_map()
        .and_then(|entries| {
            entries
                .iter()
                .find(|(key, _)| key.as_text() == Some("plugins"))
        })
        .map(|(_, value)| value.clone())
        .expect("the pilot explicitly configures its signed plugin admission policy");
    yaml::from_value(section).expect("the plugins section is the product's PluginsCfg")
}

async fn read_request(conn: &mut tokio::net::TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = conn.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let mut rest = buf[end..].to_vec();
    let header = |name: &str| {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_ascii_lowercase())
        })
    };
    if header("transfer-encoding").is_some_and(|value| value.contains("chunked")) {
        let mut body = Vec::new();
        loop {
            let line_end = loop {
                if let Some(i) = rest.windows(2).position(|w| w == b"\r\n") {
                    break i;
                }
                let n = conn.read(&mut chunk).await.ok()?;
                if n == 0 {
                    return None;
                }
                rest.extend_from_slice(&chunk[..n]);
            };
            let size_text = String::from_utf8_lossy(&rest[..line_end]).to_string();
            let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
            rest.drain(..line_end + 2);
            while rest.len() < size + 2 {
                let n = conn.read(&mut chunk).await.ok()?;
                if n == 0 {
                    return None;
                }
                rest.extend_from_slice(&chunk[..n]);
            }
            if size == 0 {
                return Some((head, body));
            }
            body.extend_from_slice(&rest[..size]);
            rest.drain(..size + 2);
        }
    }
    let length = header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while rest.len() < length {
        let n = conn.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        rest.extend_from_slice(&chunk[..n]);
    }
    rest.truncate(length);
    Some((head, rest))
}

fn check_request(head: &str, body: &[u8], streamed: bool) -> Result<(), String> {
    let line = head.lines().next().unwrap_or_default();
    if !(line.starts_with("POST ") && line.contains("/chat/completions")) {
        return Err(format!("unexpected upstream request line: {line}"));
    }
    let request = json::parse_value(body)
        .map_err(|error| format!("the upstream receives valid JSON: {error}"))?;
    if request["model"].as_str() != Some("house-model") {
        return Err(format!("upstream model: {:?}", request["model"].as_str()));
    }
    if request["messages"][0]["content"].as_str() != Some("house-input") {
        return Err("upstream input content differs from the client's".to_owned());
    }
    if request["stream"].as_bool().unwrap_or(false) != streamed {
        return Err(format!("upstream stream flag differs: expected {streamed}"));
    }
    Ok(())
}

async fn answer(conn: &mut tokio::net::TcpStream, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = conn.write_all(response.as_bytes()).await;
    let _ = conn.flush().await;
}

async fn serve_upstream(upstream: Arc<Upstream>, mut conn: tokio::net::TcpStream) {
    let Some((head, body)) = read_request(&mut conn).await else {
        return;
    };
    let mode = upstream.mode.load(Ordering::SeqCst);
    upstream.calls.fetch_add(1, Ordering::SeqCst);
    if let Err(fault) = check_request(&head, &body, mode != WHOLE) {
        upstream.fault(fault);
    }
    match mode {
        WHOLE => answer(&mut conn, "application/json", ANSWER).await,
        STREAM => answer(&mut conn, "text/event-stream", EVENTS).await,
        _ => {
            let first = format!("{:x}\r\n{FIRST_EVENT}\r\n", FIRST_EVENT.len());
            let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
            if conn.write_all(head.as_bytes()).await.is_err()
                || conn.write_all(first.as_bytes()).await.is_err()
                || conn.flush().await.is_err()
            {
                upstream
                    .stall_closed_by_product
                    .store(true, Ordering::SeqCst);
                return;
            }
            let mut sink = [0u8; 1024];
            tokio::select! {
                () = upstream.release.notified() => {}
                read = conn.read(&mut sink) => {
                    if matches!(read, Ok(0) | Err(_)) {
                        upstream.stall_closed_by_product.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
    }
}

fn token_in(minted: &str) -> String {
    minted
        .split("\"token\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .filter(|token| !token.is_empty())
        .unwrap_or_else(|| panic!("the admin API must mint a client key: {minted}"))
        .to_owned()
}

#[tokio::test]
async fn house_actual_binary_memory_request_and_unauthorized_refusal() {
    let cohort = Cohort::from_environment();
    let house = House::new();
    let fixture = house.dir.clone();
    let binary = cohort.core.clone();
    let core_sum = record_hash(&binary);
    let mut archives = 0;
    let mut packs = Vec::new();
    for entry in std::fs::read_dir(&cohort.packs).expect("signed pilot plugins") {
        let path = entry.expect("plugin directory entry").path();
        if path.to_string_lossy().ends_with(".tar.gz") {
            let sum = record_hash(&path);
            assert!(
                cohort.pins.contains(&sum),
                "every supplied pack is pinned by SHA-256 in plugins.fetch: {}",
                path.display()
            );
            let name = path.file_name().expect("pack file name").to_owned();
            std::fs::copy(&path, fixture.join("plugins").join(&name))
                .expect("copy the exact signed pack");
            packs.push(name);
            archives += 1;
        }
    }
    assert!(
        archives > 0,
        "the actual signed pilot cohort must be present"
    );
    for name in &packs {
        let copied = fixture.join("plugins").join(name);
        assert!(
            cohort.pins.contains(&sha256_of(&copied)),
            "the product consumes the exact hashed pilot bytes"
        );
    }
    println!(
        "HOUSE_TRUST core={core_sum} profile=as-built-by-the-job first_party_key={} \
         trust=harness-key signed under test-harness (CI test root; not production trust)",
        if cohort.first_party_key.is_some() {
            "supplied"
        } else {
            "absent"
        }
    );

    // This run's credentials: the operator's admin token, the deployment signing key minted by
    // the product itself, and the provider credential the upstream receives.
    let operator = random_hex();
    house.secret("admin-token", operator.as_bytes());
    house.secret("upstream-key", random_hex().as_bytes());
    let signing = Command::new(&binary)
        .arg("--generate-signing-key")
        .output()
        .expect("the product mints its deployment signing key");
    assert!(
        signing.status.success() && !signing.stdout.is_empty(),
        "--generate-signing-key: {}",
        String::from_utf8_lossy(&signing.stderr)
    );
    house.secret("signing.key", &signing.stdout);

    let upstream = Arc::new(Upstream::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = listener.local_addr().unwrap();
    let accepting = Arc::clone(&upstream);
    let upstream_task = tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            tokio::spawn(serve_upstream(Arc::clone(&accepting), conn));
        }
    });

    let data = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let admin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let data_address = data.local_addr().unwrap();
    let admin_address = admin.local_addr().unwrap();
    let mut config = CONFIG.replace("@FETCH_PINS@", cohort.pins.trim_end_matches('\n'));
    for (marker, value) in [
        ("@DATA_ADDRESS@", data_address.to_string()),
        ("@ADMIN_ADDRESS@", admin_address.to_string()),
        ("@FIXTURE_DIR@", fixture.display().to_string()),
    ] {
        assert!(
            config.contains(marker),
            "configuration must contain {marker}"
        );
        config = config.replace(marker, &value);
    }
    let policy = plugins_policy(&config);
    assert!(policy.enabled, "the pilot loads its supplied plugins");
    assert!(
        !policy.trust.allow_untrusted,
        "the house fixture must not bypass signature verification"
    );
    assert_eq!(
        Path::new(&policy.dir),
        fixture.join("plugins"),
        "the product must consume the exact hashed pilot directory"
    );
    assert!(
        policy.fetch.len() >= archives,
        "every supplied pack is pinned in plugins.fetch"
    );
    let config_path = fixture.join("config.yaml");
    let providers_path = fixture.join("providers.yaml");
    std::fs::write(
        &providers_path,
        PROVIDERS.replace("@UPSTREAM_URL@", &format!("http://{upstream_address}")),
    )
    .unwrap();
    std::fs::write(&config_path, &config).unwrap();
    record_hash(&providers_path);
    record_hash(&config_path);
    println!("HOUSE_CONFIG_BEGIN\n{config}\nHOUSE_CONFIG_END");
    drop((data, admin));
    println!(
        "HOUSE_COMMAND cd {} && BUSBAR_CONFIG={} {}",
        fixture.display(),
        config_path.display(),
        binary.display()
    );
    let mut command = Command::new(&binary);
    command
        .current_dir(&fixture)
        .env("BUSBAR_CONFIG", &config_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(key) = &cohort.first_party_key {
        command.env("BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY", key);
    }
    let mut product = Product {
        child: command.spawn().expect("launch the actual distributable"),
    };
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    // H01: readiness of the actual product.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        assert!(
            product.child.try_wait().unwrap().is_none(),
            "actual product exited before readiness"
        );
        if client
            .get(format!("http://{data_address}/healthz"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "actual product readiness deadline"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!("HOUSE_READY {data_address} {admin_address}");

    // H03: unauthorized operator and client inputs are refused with no upstream call.
    let keys = format!("http://{admin_address}/api/v1/admin/keys");
    let refused = client
        .post(&keys)
        .header("content-type", "application/json")
        .body(r#"{"name":"house-client"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "an operator write without a credential is refused"
    );
    let url = format!("http://{data_address}/v1/chat/completions");
    let request = r#"{"model":"house-model","messages":[{"role":"user","content":"house-input"}],"stream":false}"#;
    let denied = client
        .post(&url)
        .header("content-type", "application/json")
        .body(request)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::UNAUTHORIZED);
    let forged = client
        .post(&url)
        .bearer_auth("house-not-a-minted-key")
        .header("content-type", "application/json")
        .body(request)
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        upstream.calls(),
        0,
        "unauthorized input must never reach upstream"
    );

    // The operator mints the client's key over the real admin socket.
    let minted = client
        .post(&keys)
        .bearer_auth(&operator)
        .header("content-type", "application/json")
        .body(r#"{"name":"house-client"}"#)
        .send()
        .await
        .unwrap();
    let minted_status = minted.status();
    let minted = minted.text().await.unwrap();
    assert!(
        minted_status.is_success(),
        "mint a client key: {minted_status} {minted}"
    );
    let token = token_in(&minted);

    // H02: nonstreamed and streamed data through the configured upstream.
    for (mode, body) in [
        (WHOLE, request.to_owned()),
        (STREAM, request.replace("false", "true")),
    ] {
        upstream.mode.store(mode, Ordering::SeqCst);
        let response = client
            .post(&url)
            .bearer_auth(&token)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body = response.text().await.unwrap();
        if mode == WHOLE {
            let value = json::parse_value(body.as_bytes()).expect("valid client JSON response");
            assert_eq!(
                value["choices"][0]["message"]["content"].as_str(),
                Some("house-ok")
            );
            assert_eq!(value["model"].as_str(), Some("house-model"));
            assert_eq!(value["usage"]["total_tokens"].as_u64(), Some(2));
        } else {
            assert!(
                body.contains("house-ok"),
                "the stream carries upstream content"
            );
            assert!(
                body.contains("data: [DONE]"),
                "the stream reaches its terminal event"
            );
        }
        assert_eq!(
            upstream.calls(),
            mode + 1,
            "exactly one real upstream call per accepted request"
        );
    }

    // H04 slice: the client drops a streamed response mid-stream. The product keeps serving,
    // makes no duplicate upstream call, and still shuts down cleanly and within its bound.
    upstream.mode.store(STALL, Ordering::SeqCst);
    let mut dropped = client
        .post(&url)
        .bearer_auth(&token)
        .header("content-type", "application/json")
        .body(request.replace("false", "true"))
        .send()
        .await
        .unwrap();
    assert_eq!(dropped.status(), reqwest::StatusCode::OK);
    let first = tokio::time::timeout(Duration::from_secs(30), dropped.chunk())
        .await
        .expect("the first streamed event arrives while the upstream holds the stream")
        .expect("streamed body read")
        .expect("a first streamed chunk");
    assert!(
        String::from_utf8_lossy(&first).contains("house-ok"),
        "the first event carries upstream content"
    );
    drop(dropped);
    assert_eq!(
        upstream.calls(),
        3,
        "the dropped stream was one upstream call"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    upstream.release.notify_waiters();
    upstream.mode.store(WHOLE, Ordering::SeqCst);
    let after = client
        .post(&url)
        .bearer_auth(&token)
        .header("content-type", "application/json")
        .body(request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        reqwest::StatusCode::OK,
        "the product keeps serving after a dropped response"
    );
    assert!(after.text().await.unwrap().contains("house-ok"));
    println!(
        "HOUSE_DROPPED_STREAM upstream_closed_by_product={}",
        upstream.stall_closed_by_product.load(Ordering::SeqCst)
    );

    let signaled = Command::new("kill")
        .args(["-TERM", &product.child.id().to_string()])
        .status()
        .unwrap();
    assert!(signaled.success(), "request normal product shutdown");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = product.child.try_wait().unwrap() {
            assert!(status.success(), "clean product termination: {status}");
            println!("HOUSE_TERMINATED {status}");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "bounded normal shutdown"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        upstream.calls(),
        4,
        "no delayed forbidden or duplicate upstream call before shutdown"
    );
    let faults = upstream.faults.lock().unwrap().clone();
    assert!(faults.is_empty(), "upstream observed: {faults:?}");
    upstream_task.abort();
    println!("HOUSE_PROCESS_REQUEST_AND_UNAUTHORIZED_ASSERTIONS_COMPLETE");
}
