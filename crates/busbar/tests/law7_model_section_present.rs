// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAW 7: PRESENT, NOT NON-EMPTY, END TO END (spec Part 1 Law 7: "Core loads a plugin **iff** its
//! configuration section is present"; coordinator ruling 2026-10-07 on D2-PROTO). The model-serving
//! verb's section (`models:` / `pools:`) written EMPTY loads the plane that serves it, the plane
//! every request no other claim takes falls through to. So its refusals, its listing and its "no
//! such model" answer in the dialect the path names. With no such section the plane is not loaded,
//! and the kernel answers in its listener's own words.
//!
//! The shipped binary is booted on each of three documents (`tests/fixtures/law7_model_section/`).
//! The same nine requests go to each, and every answer (status, `x-amzn-errortype`, body with the
//! request id masked) is held to the bytes MEASURED from a reference binary on the same document:
//! * `empty_models` (`models: {}`): the published v1.5.5 binary;
//! * `decisions_with_empty_models` (a decisions model beside `models: {}`): predev 6afec149aa;
//! * `no_model_section` (a decisions model and no model-serving section): this release, per the
//!   ruling. Predev refuses that document at parse (`missing field models`), so there is no earlier
//!   answer to hold it to.
#![cfg(unix)]
#![cfg(linked_every_plane)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const ADMIN_TOKEN: &str = "law7-model-section-admin";
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/law7_model_section"
);

struct Booted {
    child: Child,
    dir: PathBuf,
    data: String,
    admin: String,
}

impl Drop for Booted {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}

/// Boot the shipped binary on the fixture document `case`.
fn boot(case: &str) -> Booted {
    let dir = std::env::temp_dir().join(format!(
        "busbar-law7-models-{case}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    let key = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(key.status.success(), "--generate-signing-key");
    let signing = dir.join("signing.key");
    std::fs::write(&signing, &key.stdout).unwrap();
    let config = std::fs::read_to_string(format!("{FIXTURES}/{case}.yaml"))
        .expect("the case's document")
        .replace("{data_port}", &data_port.to_string())
        .replace("{admin_port}", &admin_port.to_string())
        .replace("{signing}", &signing.display().to_string());
    std::fs::write(dir.join("config.yaml"), config).unwrap();
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", format!("{FIXTURES}/providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .current_dir(&dir)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("spawn busbar");
    let mut booted = Booted {
        child,
        dir,
        data: format!("127.0.0.1:{data_port}"),
        admin: format!("127.0.0.1:{admin_port}"),
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let log = read_to_string(&log_path);
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

/// Every `req_<id>` in `text` masked to `req_X`: the one byte run that differs per request.
fn masked(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("req_") {
        out.push_str(&rest[..at]);
        out.push_str("req_X");
        rest = &rest[at + 4..];
        let id_len = rest
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(rest.len());
        rest = &rest[id_len..];
    }
    out.push_str(rest);
    out
}

/// One request: its method, path, head fields and body.
type Probe<'a> = (&'a str, &'a str, Vec<(&'a str, &'a str)>, Option<&'a str>);

/// The nine requests, each answered as `<n>\t<status>\t<x-amzn-errortype or ->\t<masked body>`.
fn answers(b: &Booted) -> Vec<String> {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");
        let minted: serde_json::Value = client
            .post(format!("http://{}/api/v1/admin/keys", b.admin))
            .bearer_auth(ADMIN_TOKEN)
            .json(&serde_json::json!({"name": "k"}))
            .send()
            .await
            .expect("mint a key")
            .json()
            .await
            .expect("the minted key");
        let token = minted["token"].as_str().expect("a token").to_string();
        let bearer = format!("Bearer {token}");
        let body = r#"{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#;
        let probes: [Probe<'_>; 9] = [
            ("GET", "/v1/models", vec![("authorization", &bearer)], None),
            (
                "GET",
                "/v1/models",
                vec![("x-api-key", &token), ("anthropic-version", "2023-06-01")],
                None,
            ),
            (
                "GET",
                "/v1beta/models",
                vec![("x-goog-api-key", &token)],
                None,
            ),
            (
                "POST",
                "/v1/messages",
                vec![("x-api-key", &token), ("content-type", "application/json")],
                Some(body),
            ),
            (
                "POST",
                "/v1/chat/completions",
                vec![
                    ("authorization", &bearer),
                    ("content-type", "application/json"),
                ],
                Some(body),
            ),
            (
                "POST",
                "/v1/messages",
                vec![("x-api-key", "wrong")],
                Some("{}"),
            ),
            (
                "POST",
                "/model/m/converse",
                vec![("authorization", "Bearer wrong")],
                Some("{}"),
            ),
            ("GET", "/v2/nothing", vec![("authorization", &bearer)], None),
            ("DELETE", "/v1/messages", vec![("x-api-key", &token)], None),
        ];
        let mut out = Vec::new();
        for (n, (method, path, fields, body)) in probes.into_iter().enumerate() {
            let method = reqwest::Method::from_bytes(method.as_bytes()).expect("method");
            let mut req = client.request(method, format!("http://{}{path}", b.data));
            for (name, value) in fields {
                req = req.header(name, value);
            }
            if let Some(body) = body {
                req = req.body(body.to_string());
            }
            let resp = req.send().await.expect("request");
            let status = resp.status().as_u16();
            let errortype = resp
                .headers()
                .get("x-amzn-errortype")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_string();
            let text = resp.text().await.unwrap_or_default();
            out.push(format!("{n}\t{status}\t{errortype}\t{}", masked(&text)));
        }
        out
    })
}

fn expected(case: &str) -> Vec<String> {
    std::fs::read_to_string(format!("{FIXTURES}/{case}.expected"))
        .expect("the case's measured answers")
        .lines()
        .map(str::to_string)
        .collect()
}

fn holds(case: &str) {
    let b = boot(case);
    assert_eq!(answers(&b), expected(case), "{case}");
}

/// `models: {}` is the verb's section present and empty: the plane loads, and every answer is the
/// published v1.5.5 binary's on the same document (401 `invalid x-api-key`, 403
/// AccessDeniedException, 405, the dialect 404s, the empty listings in each dialect's envelope).
#[test]
fn an_empty_models_section_answers_as_1_5_5_did() {
    holds("empty_models");
}

/// A decisions deployment that writes `models: {}` answers as predev answered it.
#[test]
fn a_decisions_document_with_an_empty_models_section_answers_as_predev_did() {
    holds("decisions_with_empty_models");
}

/// With no model-serving section the plane is not loaded (Law 7): every answer is the kernel
/// listener's own, in no dialect, and the listing is the empty object.
#[test]
fn no_model_section_loads_no_model_plane_and_the_listener_answers() {
    holds("no_model_section");
}
