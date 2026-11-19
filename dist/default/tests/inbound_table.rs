// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `inbound_table`: every route the product serves, asked by four callers, against the real
//! binary with every plane linked. One row of `inbound_table/routes.tsv` per route; one cell per
//! caller: no credential, a credential nobody issued, a good unrestricted key, and a good key
//! whose grant names nothing the route reaches. The table is the proof of inbound admission:
//!
//! - every v1.5.5 route answers something other than 401 to a valid key;
//! - an unverified caller receives the same answer on every route and on none (status, body
//!   bytes; only `WWW-Authenticate` is a route's own, where the table says `+challenge`);
//! - a verified caller on an unknown path is told 404, on a wrong method 405 with `Allow`;
//! - a restricted key is refused 403 where the route judges a grant, and only there;
//! - no "is not served" line in the boot log gives the engine's own reason.
//!
//! A cell that expects 200 is checked as ADMITTED: the status is none of the statuses admission
//! answers (401, 403, 404, 405, 413). What the plane then makes of a generic mock upstream is
//! the plane's own suite's subject, not this table's.

#![cfg(unix)]
#![cfg(linked_every_plane_door)]

mod common;

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const ROUTES: &str = include_str!("inbound_table/routes.tsv");
const PLANE_SECTIONS: &str = include_str!("fixtures/law7_plane_sections.yaml");
const ADMIN_TOKEN: &str = "inbound-table-admin";

/// The statuses admission answers: a cell that expects to be served must be none of them.
const ADMISSION_STATUSES: [u16; 5] = [401, 403, 404, 405, 413];

/// What one cell of the table expects.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Expect {
    status: u16,
    /// `+challenge`: the 401 carries a `WWW-Authenticate` naming `resource_metadata`.
    challenge: bool,
    /// `+Allow`: the 405 carries an `Allow` header.
    allow: bool,
}

impl Expect {
    fn parse(cell: &str) -> Expect {
        let (status, extra) = cell.split_once('+').unwrap_or((cell, ""));
        Expect {
            status: status
                .parse()
                .unwrap_or_else(|_| panic!("routes.tsv: `{cell}` is not a status")),
            challenge: extra == "challenge",
            allow: extra == "Allow",
        }
    }
}

/// One row of the table.
#[derive(Debug, Clone)]
struct Row {
    id: String,
    method: String,
    path: String,
    body: String,
    /// In caller order: no credential, bad credential, good key, key without the grant.
    cells: [Expect; 4],
}

const CALLERS: [&str; 4] = [
    "no credential",
    "bad credential",
    "good key",
    "key without the grant",
];

fn rows() -> Vec<Row> {
    let mut lines = ROUTES.lines();
    let header: Vec<&str> = lines.next().expect("a header").split('\t').collect();
    let at = |name: &str| {
        header
            .iter()
            .position(|column| *column == name)
            .unwrap_or_else(|| panic!("routes.tsv has no `{name}` column"))
    };
    let (id, method, path, body) = (at("row"), at("method"), at("path"), at("body"));
    let cells = [
        at("no_credential"),
        at("bad_credential"),
        at("good_key"),
        at("key_without_the_grant"),
    ];
    lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), header.len(), "routes.tsv: `{line}`");
            Row {
                id: fields[id].to_owned(),
                method: fields[method].to_owned(),
                path: fields[path].to_owned(),
                body: fields[body].to_owned(),
                cells: cells.map(|cell| Expect::parse(fields[cell])),
            }
        })
        .collect()
}

/// The request a row's `body` word stands for: its content type and bytes (and, for the
/// trailers word, that the request ends in a trailer section). Every model body names
/// `test-model`, the one model the fixture configures.
fn body_of(word: &str, cap: usize) -> (Option<&'static str>, Vec<u8>, bool) {
    const JSON: Option<&str> = Some("application/json");
    let text = |s: &str| s.as_bytes().to_vec();
    match word {
        "-" => (None, Vec::new(), false),
        "form" => (
            Some("application/x-www-form-urlencoded"),
            text("grant_type=client_credentials"),
            false,
        ),
        "anthropic-chat" | "bedrock-chat" | "bedrock-invoke" => (
            JSON,
            text(
                r#"{"model":"test-model","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
            ),
            false,
        ),
        "openai-chat" | "cohere-chat" => (
            JSON,
            text(r#"{"model":"test-model","messages":[{"role":"user","content":"hi"}]}"#),
            false,
        ),
        "openai-responses" | "gemini-interaction" => {
            (JSON, text(r#"{"model":"test-model","input":"hi"}"#), false)
        }
        "openai-embeddings" => (JSON, text(r#"{"model":"test-model","input":"hi"}"#), false),
        "openai-moderation" => (JSON, text(r#"{"model":"test-model","input":"hi"}"#), false),
        "openai-image" => (
            JSON,
            text(r#"{"model":"test-model","prompt":"a dot"}"#),
            false,
        ),
        "openai-speech" => (
            JSON,
            text(r#"{"model":"test-model","input":"hi","voice":"alloy"}"#),
            false,
        ),
        "multipart-audio" => (
            Some("multipart/form-data; boundary=inb"),
            text(
                "--inb\r\ncontent-disposition: form-data; name=\"model\"\r\n\r\ntest-model\r\n\
                 --inb\r\ncontent-disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\n\
                 content-type: audio/wav\r\n\r\nRIFF\r\n--inb--\r\n",
            ),
            false,
        ),
        "cohere-embed" => (
            JSON,
            text(r#"{"model":"test-model","texts":["hi"],"input_type":"search_document"}"#),
            false,
        ),
        "cohere-rerank" => (
            JSON,
            text(r#"{"model":"test-model","query":"hi","documents":["a","b"]}"#),
            false,
        ),
        "gemini-chat" | "gemini-image" => (
            JSON,
            text(r#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#),
            false,
        ),
        "gemini-embed" => (
            JSON,
            text(r#"{"content":{"parts":[{"text":"hi"}]}}"#),
            false,
        ),
        "mcp-initialize" => (
            JSON,
            text(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"inbound-table","version":"1"}}}"#,
            ),
            false,
        ),
        "a2a-send" => (
            JSON,
            text(
                r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"hi"}],"messageId":"m1"}}}"#,
            ),
            false,
        ),
        "nanojev" | "jev" | "classify" => (
            JSON,
            text(r#"{"model":"test-model","state":{"amount":7}}"#),
            false,
        ),
        "realtime-mint" => (
            JSON,
            text(r#"{"session":{"type":"realtime","model":"test-model"}}"#),
            false,
        ),
        // One byte past the configured cap, with its length declared.
        "oversized" => (JSON, vec![b' '; cap + 1], false),
        "trailers" => (
            JSON,
            text(r#"{"model":"test-model","messages":[{"role":"user","content":"hi"}]}"#),
            true,
        ),
        other => panic!("routes.tsv: unknown body word `{other}`"),
    }
}

struct Booted {
    child: Child,
    dir: PathBuf,
    data: String,
    admin: String,
    log: PathBuf,
}

impl Drop for Booted {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The body cap the fixture configures (`limits.request_body_max_bytes`).
const BODY_CAP: usize = 64 * 1024;

fn boot(upstream: &str) -> Booted {
    let dir = std::env::temp_dir().join(format!(
        "busbar-inbound-table-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    let key = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(key.status.success(), "--generate-signing-key");
    std::fs::write(dir.join("signing.key"), &key.stdout).unwrap();
    let planes = PLANE_SECTIONS
        .replace("{data_port}", &data_port.to_string())
        .replace("{admin_port}", &admin_port.to_string());
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
store: {{module: memory}}
public_url: "http://127.0.0.1:{data_port}"
limits:
  request_body_max_bytes: {BODY_CAP}
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain: [keys]
  signing_key: {{ file: "{signing}" }}
  admin_auth: [admin-tokens]
providers:
  mock:
    protocol: anthropic
    base_url: "{upstream}"
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
{planes}"#,
            signing = dir.join("signing.key").display()
        ),
    )
    .unwrap();
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env_remove("BUSBAR_PROVIDERS")
        .env("MOCK_KEY", "x")
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("spawn busbar");
    let mut booted = Booted {
        child,
        dir,
        data: format!("127.0.0.1:{data_port}"),
        admin: format!("127.0.0.1:{admin_port}"),
        log: log_path,
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let log = read_to_string(&booted.log);
        if log.matches("busbar listening").count() >= 2 {
            break;
        }
        if let Some(status) = booted.child.try_wait().expect("try_wait") {
            panic!("busbar exited before listening ({status:?}):\n{log}");
        }
        assert!(Instant::now() < deadline, "busbar did not listen:\n{log}");
        std::thread::sleep(Duration::from_millis(50));
    }
    booted
}

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}

/// What one request was answered with.
#[derive(Debug, Clone)]
struct Answered {
    status: u16,
    body: Vec<u8>,
    challenge: Option<String>,
    allow: Option<String>,
    content_type: Option<String>,
}

fn send(
    rt: &tokio::runtime::Runtime,
    addr: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: (Option<&'static str>, Vec<u8>, bool),
) -> Answered {
    let (content_type, bytes, trailers) = body;
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");
        let method = reqwest::Method::from_bytes(method.as_bytes()).expect("method");
        let mut req = client.request(method, format!("http://{addr}{path}"));
        if let Some(token) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(content_type) = content_type {
            req = req.header(reqwest::header::CONTENT_TYPE, content_type);
        }
        if trailers {
            // A chunked body announcing a trailer section; the listener answers 400 for it.
            req = req.header("trailer", "x-checksum").header("te", "trailers");
        }
        let resp = req
            .body(bytes)
            .send()
            .await
            .expect("the request is answered, not cut");
        let header = |name: reqwest::header::HeaderName| {
            resp.headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        Answered {
            status: resp.status().as_u16(),
            challenge: header(reqwest::header::WWW_AUTHENTICATE),
            allow: header(reqwest::header::ALLOW),
            content_type: header(reqwest::header::CONTENT_TYPE),
            body: resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default(),
        }
    })
}

/// Mint a key through the admin API: unrestricted, or restricted to one pool that no route of
/// the table reaches (so the grant it holds names nothing a row asks for).
fn mint(rt: &tokio::runtime::Runtime, booted: &Booted, name: &str, restricted: bool) -> String {
    let body = if restricted {
        format!(r#"{{"name":"{name}","allowed_pools":["a-pool-no-row-names"]}}"#)
    } else {
        format!(r#"{{"name":"{name}"}}"#)
    };
    let minted = send(
        rt,
        &booted.admin,
        "POST",
        "/api/v1/admin/keys",
        Some(ADMIN_TOKEN),
        (Some("application/json"), body.into_bytes(), false),
    );
    let text = String::from_utf8_lossy(&minted.body).into_owned();
    text.split("\"token\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("the admin API must mint a key: {text}"))
        .to_owned()
}

/// Why a cell failed, or `None`.
fn judge(expect: &Expect, got: &Answered) -> Option<String> {
    if expect.status == 200 || expect.status == 101 {
        if ADMISSION_STATUSES.contains(&got.status) {
            return Some(format!(
                "expected to be admitted, was answered {}",
                got.status
            ));
        }
        return None;
    }
    if got.status != expect.status {
        return Some(format!(
            "expected {}, was answered {}",
            expect.status, got.status
        ));
    }
    if expect.status == 401 && got.challenge.is_none() {
        return Some("a 401 without WWW-Authenticate".into());
    }
    if expect.challenge
        && !got
            .challenge
            .as_deref()
            .is_some_and(|challenge| challenge.contains("resource_metadata=\"http"))
    {
        return Some(format!(
            "expected the route's challenge, got {:?}",
            got.challenge
        ));
    }
    if expect.allow && got.allow.is_none() {
        return Some("a 405 without Allow".into());
    }
    None
}

#[test]
fn every_route_answers_every_caller_as_the_table_says() {
    let upstream = common::upstream::Responder::start(BTreeMap::new());
    let booted = boot(&upstream.url());
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let good = mint(&rt, &booted, "inbound-table-good", false);
    let narrow = mint(&rt, &booted, "inbound-table-narrow", true);
    let tokens: [Option<&str>; 4] = [
        None,
        Some("bb_not_a_key_anyone_issued"),
        Some(&good),
        Some(&narrow),
    ];
    let mut failures: Vec<String> = Vec::new();
    // The one unverified answer: every 401 with no declared challenge has these exact bytes.
    let mut unverified: Option<(Vec<u8>, Option<String>, Option<String>)> = None;
    let rows = rows();
    assert!(rows.len() >= 40, "routes.tsv lost rows: {}", rows.len());
    for row in &rows {
        for (caller, (token, expect)) in tokens.iter().zip(&row.cells).enumerate() {
            let got = send(
                &rt,
                &booted.data,
                &row.method,
                &row.path,
                *token,
                body_of(&row.body, BODY_CAP),
            );
            if let Some(why) = judge(expect, &got) {
                failures.push(format!(
                    "{} {} {} [{}]: {why}",
                    row.id, row.method, row.path, CALLERS[caller]
                ));
                continue;
            }
            if got.status == 401 && !expect.challenge {
                let this = (
                    got.body.clone(),
                    got.challenge.clone(),
                    got.content_type.clone(),
                );
                match &unverified {
                    None => unverified = Some(this),
                    Some(first) if *first == this => {}
                    Some(_) => failures.push(format!(
                        "{} {} {} [{}]: its 401 is not the one unverified answer",
                        row.id, row.method, row.path, CALLERS[caller]
                    )),
                }
            }
        }
    }
    let (body, challenge, content_type) = unverified.expect("the table has unverified cells");
    assert_eq!(content_type.as_deref(), Some("application/json"));
    assert_eq!(challenge.as_deref(), Some("Bearer"));
    assert_eq!(
        body,
        br#"{"error":{"code":"authentication_required","message":"authentication required"}}"#
    );
    // No route is left unserved for a reason that is the engine's: the only lines permitted
    // name the operator's configuration (a ticket or signature verifier this fixture has none of).
    let log = read_to_string(&booted.log);
    for line in log.lines().filter(|line| line.contains("is not served")) {
        let operators = [
            "no configured auth instance reads",
            "no signature verifier is configured",
            "no transport on this listener can carry an upgrade",
            "the chain admits the shared anonymous caller",
            "none is configured",
        ];
        if !operators.iter().any(|reason| line.contains(reason)) {
            failures.push(format!(
                "an unserved route gives the engine's own reason: {line}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cells failed:\n{}",
        failures.len(),
        rows.len() * 4,
        failures.join("\n")
    );
}

/// The table itself is well formed without a binary: every row parses, ids are unique, every
/// body word is known, and an unverified cell is 401 on every row that is not public.
#[test]
fn the_table_parses() {
    let rows = rows();
    let mut ids: Vec<&str> = rows.iter().map(|row| row.id.as_str()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), rows.len(), "a row id is repeated");
    for row in &rows {
        let _ = body_of(&row.body, BODY_CAP);
        assert!(row.path.starts_with('/'), "{}", row.id);
        let [none, bad, good, _] = &row.cells;
        assert_eq!(
            none.status, bad.status,
            "{}: a credential nobody issued",
            row.id
        );
        if none.status != 401 {
            assert_eq!(none.status, good.status, "{}: a public route", row.id);
        }
    }
}
