// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAW 7, END TO END — a 1.5.5 config served by the shipped binary sees 1.5.5's surface, with every
//! plane compiled in (items 39/40/45). docs/design/BUSBAR-1.6.0.md Law 7: "Core loads a plugin
//! **iff** its configuration section is present"; Part 0: the new planes are "purely additive and
//! off by default". Part 2 #17 keeps every plane in `default`, so this is config gating, not removal.
//!
//! Before the gate, a 1.5.5 config (with its ordinary `public_url:`) booted with eleven admin paths
//! 1.5.5 never had (`/tools`, `/tools/{name}`, `/tools/{name}/settings`, the three MCP trust verbs,
//! the same CRUD for `/agents` and its two verbs), `DELETE /overlay/{section}` listing `tools` and
//! `agents`, and the voice plane's `/v1/realtime` doors mounted and audience-checked. The control
//! boots the SAME binary with each plane section present and requires every one of those back.
#![cfg(unix)]
#![cfg(linked_every_plane)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const ADMIN_TOKEN: &str = "law7-served-surface-admin";

/// The eleven plane-owned admin paths (method, path under `/api/v1/admin`).
const PLANE_ADMIN_PATHS: &[(&str, &str)] = &[
    ("GET", "/tools"),
    ("GET", "/tools/x"),
    ("PATCH", "/tools/x/settings"),
    ("POST", "/tools/x/connect"),
    ("GET", "/tools/x/changes"),
    ("GET", "/tools/x/health"),
    ("GET", "/agents"),
    ("GET", "/agents/x"),
    ("PATCH", "/agents/x/settings"),
    ("POST", "/agents/x/connect"),
    ("POST", "/agents/x/approve"),
];

/// The plane sections a configured deployment adds (plus `public_url`, which a 1.5.5 config may
/// already carry and which on its own must configure nothing).
const PLANE_SECTIONS: &str = include_str!("fixtures/law7_plane_sections.yaml");

/// The plane doors, as DATA (`tests/fixtures/law7_plane_doors.txt`): `(path, probed configured)`.
fn plane_doors() -> Vec<(&'static str, bool)> {
    let rows: Vec<(&'static str, bool)> = include_str!("fixtures/law7_plane_doors.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (path, when) = l.split_once(' ').expect("`<path> <when>`");
            match when.trim() {
                "both" => (path, true),
                "unconfigured" => (path, false),
                other => panic!("law7_plane_doors.txt: unknown <when> `{other}`"),
            }
        })
        .collect();
    assert_eq!(rows.len(), 4, "the plane-door fixture lost or gained a row");
    rows
}

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Boot the shipped binary on a 1.5.5-shaped config (one provider, one model, keys, an admin token,
/// `public_url:`), with every plane section appended when `with_planes`.
fn boot(tag: &str, with_planes: bool) -> Booted {
    let dir = std::env::temp_dir().join(format!(
        "busbar-law7-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (data_port, admin_port) = (free_port(), free_port());
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let key = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(key.status.success(), "--generate-signing-key");
    std::fs::write(dir.join("signing.key"), &key.stdout).unwrap();
    let extra = if with_planes {
        PLANE_SECTIONS
            .replace("{data_port}", &data_port.to_string())
            .replace("{admin_port}", &admin_port.to_string())
    } else {
        String::new()
    };
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
public_url: "http://127.0.0.1:{data_port}"
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
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
{extra}"#,
            signing = dir.join("signing.key").display()
        ),
    )
    .unwrap();
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
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

fn request(addr: &str, method: &str, path: &str, token: Option<&str>) -> (u16, String) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");
        let method = reqwest::Method::from_bytes(method.as_bytes()).expect("method");
        let mut req = client.request(method, format!("http://{addr}{path}"));
        if let Some(t) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let resp = req.send().await.expect("request");
        (
            resp.status().as_u16(),
            resp.text().await.unwrap_or_default(),
        )
    })
}

fn admin(b: &Booted, method: &str, path: &str) -> (u16, String) {
    request(
        &b.admin,
        method,
        &format!("/api/v1/admin{path}"),
        Some(ADMIN_TOKEN),
    )
}

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}

/// The shape a mounted plane door answers an unauthenticated caller with (RFC 6750), as opposed to
/// the LLM catch-all's protocol-native envelope.
fn is_plane_door(body: &str) -> bool {
    body.contains("error_description")
}

#[test]
fn a_1_5_5_config_serves_the_1_5_5_surface_and_each_configured_plane_serves_its_own() {
    // ── A 1.5.5 CONFIG: every plane-owned admin path answers exactly what an unmounted path does.
    let b = boot("155", false);
    let unmounted = admin(&b, "GET", "/no-such-path");
    assert_eq!(
        unmounted.0, 404,
        "the unmounted-path control: {unmounted:?}"
    );
    for (method, path) in PLANE_ADMIN_PATHS
        .iter()
        .copied()
        .chain([("POST", "/tools"), ("GET", "/tools/x/connect")])
    {
        assert_eq!(
            admin(&b, method, path),
            unmounted,
            "{method} {path} must be indistinguishable from an unmounted path on a 1.5.5 config"
        );
    }
    let (status, body) = admin(&b, "DELETE", "/overlay/limits");
    assert_eq!(status, 400, "{body}");
    assert!(
        !body.contains("`tools`") && !body.contains("`agents`"),
        "the overlay-section list must not name an unconfigured plane's section: {body}"
    );
    assert_eq!(admin(&b, "DELETE", "/overlay/tools").0, 400);
    for (door, _) in plane_doors() {
        let (_, body) = request(&b.data, "POST", door, None);
        assert!(
            !is_plane_door(&body),
            "POST {door} must fall to the fallback catch-all on a 1.5.5 config, not a plane door: {body}"
        );
    }
    drop(b);

    // ── THE CONTROL: the same binary with every plane section present serves every plane again.
    let b = boot("planes", true);
    let unmounted = admin(&b, "GET", "/no-such-path");
    for (method, path) in PLANE_ADMIN_PATHS {
        assert_ne!(
            admin(&b, method, path),
            unmounted,
            "{method} {path} must be served once its plane is configured"
        );
    }
    assert_eq!(admin(&b, "GET", "/tools").0, 200);
    assert_eq!(admin(&b, "GET", "/agents").0, 200);
    let (_, body) = admin(&b, "DELETE", "/overlay/limits");
    assert!(
        body.contains("`tools`") && body.contains("`agents`"),
        "a configured plane's section is an overlay section: {body}"
    );
    for door in plane_doors()
        .into_iter()
        .filter_map(|(door, configured)| configured.then_some(door))
    {
        let (status, body) = request(&b.data, "POST", door, None);
        assert!(
            status == 401 && is_plane_door(&body),
            "POST {door} must reach the configured plane's door: {status} {body}"
        );
    }
}

/// Boot on the oracle's BOOT-181 mutation (listener TLS material that does not parse) and return the
/// whole of what the refused boot printed.
fn boot_181_output(extra: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "busbar-law7-boot181-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{port}"
admin_listen: "127.0.0.1:0"
tls:
  cert: {{ env: LAW7_TLS_CERT }}
  key: {{ env: LAW7_TLS_KEY }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
{extra}"#,
            port = free_port()
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("LAW7_TLS_CERT", "not-a-pem-certificate")
        .env("LAW7_TLS_KEY", "not-a-pem-key")
        .output()
        .expect("run busbar");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(1), "the TLS mutation refuses boot");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Oracle cell `boot.refusal|BOOT-181|boot`: on the default (all-planes) build a 1.5.5 config's
/// boot output carries nothing from a plane it did not configure — the voice plane's root
/// listener-slot provisioning ran and WARNed on every boot. Control: `streams:` configured, it runs.
#[test]
fn a_1_5_5_config_boot_prints_nothing_from_an_unconfigured_plane() {
    const PLANE_LINE: &str = "listener slots were not provisioned";
    let out = boot_181_output("");
    assert!(
        out.contains("TLS configuration error for '") && !out.contains(PLANE_LINE),
        "a 1.5.5 config must print no plane line on BOOT-181:\n{out}"
    );
    let out = boot_181_output(include_str!("fixtures/law7_streams_section.yaml"));
    assert!(
        out.contains(PLANE_LINE),
        "with `streams:` configured the plane root's provisioning runs:\n{out}"
    );
}
