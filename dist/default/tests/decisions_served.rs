// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECISIONS PLANE, SERVED BY THE SHIPPED BINARY: a booted busbar whose config holds one
//! `decisions.models` entry serves `POST /v1/systemone`, the plane's one jev claim, over that model's
//! provider. The jev conformance suite (busbar-plane-decisions `testing/conformance/jev.sh`) judges
//! the served bytes in depth; this test holds the one fact every other check stands on: the route is
//! served, the far end is asked at the plane's path with the caller's bytes, and its answer reaches
//! the caller. The last jev verdict (2026-09-28) read `404`, the absence code, on this request.
#![cfg(unix)]
// The configuration below is served by the plane door that declares `decisions:`; a build without
// it is not the shape this test is about.
#![cfg(linked_section_decisions)]

mod common;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ADMIN_TOKEN: &str = "decisions-served-admin";
const PROVIDER_KEY: &str = "decisions-served-provider-key";

/// The caller's request, odd spacing kept: a relay forwards these bytes as written.
const REQUEST: &str = "{ \"state\" : {\"session\":\"served\",\"n\":[1, 2 ,3]},\n  \"context\":{} }";
/// The far end's success, stating the units the plane meters.
const SUCCESS: &str =
    "{\"request_id\" : \"req_served\", \"usage\":{\"units\":42},\"answers\":{\"decision\":\"approve\"}}";

/// What the far end received: each request's head and body.
type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// A loopback far end answering every request with [`SUCCESS`], recording what it was asked.
fn far_end() -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the far end");
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let log = seen.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let log = log.clone();
            std::thread::spawn(move || {
                if let Some(req) = common::upstream::read_request(&mut conn) {
                    log.lock().unwrap().push(req);
                    use std::io::Write as _;
                    let _ = write!(
                        conn,
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{SUCCESS}",
                        SUCCESS.len()
                    );
                }
            });
        }
    });
    (port, seen)
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-decisions-served-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// One jev provider at the far end, one decisions model over it, keys on the data plane, an admin
/// token, the far end's loopback address declared as an allowed destination.
fn write_configs(dir: &Path, upstream: u16, data: u16, admin: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        format!("typesafe:\n  protocol: jev\n  base_url: \"http://127.0.0.1:{upstream}\"\n"),
    )
    .unwrap();
    let signing_key = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(signing_key.status.success(), "--generate-signing-key");
    std::fs::write(dir.join("signing.key"), &signing_key.stdout).unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data}"
admin_listen: "127.0.0.1:{admin}"
advanced:
  allow_destinations: ["127.0.0.1"]
store: {{module: memory}}
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain:
    - keys
  signing_key: {{ file: "{signing}" }}
  admin_auth:
    - admin-tokens
providers:
  typesafe:
    api_key: {{ env: JEV_PROVIDER_KEY }}
models: {{}}
decisions:
  models:
    jev-1:
      provider: typesafe
  rate_card:
    jev-1: {{ units: {{ decision: 1, input_tokens: 0, output_tokens: 0 }} }}
"#,
            signing = dir.join("signing.key").display()
        ),
    )
    .unwrap();
}

fn http_request(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> (u16, String) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");
        let mut req = match method {
            "POST" => client.post(format!("http://{addr}{path}")),
            _ => client.get(format!("http://{addr}{path}")),
        };
        if let Some(t) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json")
                .body(b.to_string());
        }
        let resp = req.send().await.expect("request");
        let status = resp.status().as_u16();
        (status, resp.text().await.unwrap_or_default())
    })
}

fn wait_for(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

#[test]
fn a_booted_busbar_serves_post_v1_systemone() {
    let (far, seen) = far_end();
    let dir = fixture_dir("one-model");
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    write_configs(&dir, far, data, admin);
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("JEV_PROVIDER_KEY", PROVIDER_KEY)
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");
    let _dump = common::boot::DumpOnPanic(&log_path);
    let read = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let booted = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening ({status:?}); log:\n{}",
                read()
            );
        }
        common::boot::healthz_answers(data)
    });
    assert!(
        booted,
        "busbar did not reach 'listening' in 30s; log:\n{}",
        read()
    );
    let (_, minted) = http_request(
        &format!("127.0.0.1:{admin}"),
        "POST",
        "/api/v1/admin/keys",
        Some(r#"{"name":"decisions-served"}"#),
        Some(ADMIN_TOKEN),
    );
    let token = minted
        .split("\"token\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("the admin API must mint a key: {minted}"))
        .to_string();
    let data_addr = format!("127.0.0.1:{data}");
    let absent = http_request(
        &data_addr,
        "POST",
        "/.decisions-served/no-such-route-any-plane-could-own",
        Some("{}"),
        Some(&token),
    );
    let served = http_request(
        &data_addr,
        "POST",
        "/v1/systemone",
        Some(REQUEST),
        Some(&token),
    );
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();
    if !wait_for(Duration::from_secs(15), || {
        child.try_wait().expect("try_wait").is_some()
    }) {
        let _ = child.kill();
    }
    let seen = seen.lock().unwrap().clone();
    let _ = std::fs::remove_dir_all(&dir);

    assert_ne!(
        served.0, absent.0,
        "POST /v1/systemone answers {}, the absence code a path no plane owns answers on this boot: \
         one decisions model is configured and no route serves its operation: {served:?}",
        absent.0
    );
    assert_eq!(
        served,
        (200, SUCCESS.to_string()),
        "the caller receives the far end's 200 bytes"
    );
    assert_eq!(seen.len(), 1, "exactly one request reached the far end");
    let (head, body) = &seen[0];
    assert!(
        head.starts_with("POST /v1/systemone "),
        "the far end is asked at the plane's path: {head}"
    );
    assert_eq!(
        body.as_slice(),
        REQUEST.as_bytes(),
        "the far end receives the caller's bytes"
    );
}
