// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHIPPED SAMPLE CONFIG, end to end, on the REAL default binary: the repository's `config.yaml` validates,
//! boots, and its operator credential (the linked `admin-tokens` image) answers an admin call made with the
//! operator token. Only what a test host must change is changed: the listen addresses (free loopback ports, the
//! admin listener named) and the signing key's path (a key this test generates). The operator line, the secret
//! references and every other key are the file as shipped.
//!
//! Red before the default binary's images were whole after the MIN-3 moves (D-OPERATOR, CAUSES-engine.md):
//! `{ env: .. }` refused as undeclared (BUSBAR-3121), the linked admin-tokens image not judged as the operator
//! (no admitted auth plugin "states the operator credential"), and the sample's 1.5 `token:` form (BUSBAR-3115).

#![cfg(unix)]

#[path = "common/boot.rs"]
mod boot;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const SAMPLE: &str = include_str!("../../../config.yaml");
const PROVIDERS: &str = include_str!("../../../providers.yaml");
const ADMIN_TOKEN: &str = "shipped-sample-operator-token";
const PROVIDER_KEYS: &[&str] = &[
    "ANTHROPIC_KEY",
    "OPENAI_KEY",
    "GEMINI_KEY",
    "ZAI_KEY",
    "AWS_BEDROCK_CREDS",
];

fn workdir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let d = std::env::temp_dir().join(format!(
        "shipped-sample-operator-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The sample with the host-specific lines replaced; panics if a line this test replaces is gone, so a reworded
/// sample fails here rather than silently testing something else.
fn hosted(dir: &Path, data: u16, admin: u16) -> String {
    let listen = "listen: \"0.0.0.0:8080\"";
    let signing = "{ file: /var/lib/busbar/signing.key }";
    assert!(SAMPLE.contains(listen), "the sample's listen line moved");
    assert!(
        SAMPLE.contains(signing),
        "the sample's signing key line moved"
    );
    SAMPLE
        .replacen(
            listen,
            &format!("listen: \"127.0.0.1:{data}\"\nadmin_listen: \"127.0.0.1:{admin}\""),
            1,
        )
        .replacen(
            signing,
            &format!("{{ file: \"{}\" }}", dir.join("signing.key").display()),
            1,
        )
}

fn command(dir: &Path) -> Command {
    let mut command = Command::new(boot::exe());
    command
        .current_dir(dir)
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env(
            "BUSBAR_ADMIN_TOKEN_SHA256",
            busbar_contract::redacted::sha256_hex(ADMIN_TOKEN.as_bytes()),
        );
    for key in PROVIDER_KEYS {
        command.env(key, "x");
    }
    command
}

fn get(port: u16, path: &str, header: &str) -> Result<u16, String> {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{header}Connection: close\r\n\r\n")
                .as_bytes(),
        )
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = String::new();
    stream
        .read_to_string(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    buf.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("no status line in {buf:?}"))
}

#[test]
fn the_shipped_sample_validates_boots_and_its_operator_token_reaches_the_admin_api() {
    let dir = workdir();
    let (data, admin) = (boot::free_port(), boot::free_port());
    let key = Command::new(boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(key.status.success(), "--generate-signing-key");
    std::fs::write(dir.join("signing.key"), &key.stdout).unwrap();
    std::fs::write(dir.join("config.yaml"), hosted(&dir, data, admin)).unwrap();
    std::fs::write(dir.join("providers.yaml"), PROVIDERS).unwrap();

    let validated = command(&dir)
        .args(["--validate", "--config"])
        .arg(dir.join("config.yaml"))
        .output()
        .expect("run --validate");
    assert!(
        validated.status.success(),
        "the shipped sample validates; stderr:\n{}",
        String::from_utf8_lossy(&validated.stderr)
    );

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut node = boot::Reap(
        command(&dir)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("boot the shipped sample"),
    );
    let _dump = boot::DumpOnPanic(&log_path);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = node.0.try_wait().expect("try_wait") {
            panic!(
                "the shipped sample's server exited ({status:?}); log:\n{}",
                std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
            );
        }
        assert!(Instant::now() < deadline, "/healthz never answered");
        if boot::healthz_answers(data) {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let with_token = get(
        admin,
        "/api/v1/admin/openapi.json",
        &format!("Authorization: Bearer {ADMIN_TOKEN}\r\n"),
    );
    let wrong_token = get(
        admin,
        "/api/v1/admin/openapi.json",
        "Authorization: Bearer not-the-operator-token\r\n",
    );
    let log = std::fs::read_to_string(dir.join("out.log")).unwrap_or_default();
    let listening = boot::log_shows_data_and_admin_listening(&log);
    drop(node);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(listening, "both listeners came up; log:\n{log}");
    assert_eq!(
        with_token,
        Ok(200),
        "the operator token reaches the admin API; log:\n{log}"
    );
    assert_eq!(
        wrong_token,
        Ok(401),
        "another token is refused; log:\n{log}"
    );
}
