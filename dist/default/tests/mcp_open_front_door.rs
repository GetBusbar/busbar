// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(linked_section_tools)]

mod common;

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-open-front-door-{}-{tag}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
}

const PLANE_SECTION: &str = include_str!("fixtures/front_door_plane_section.yaml");

fn plane_section(data_port: u16, admin_port: u16) -> String {
    PLANE_SECTION
        .replace("{data_port}", &data_port.to_string())
        .replace("{admin_port}", &admin_port.to_string())
}

fn section_key() -> &'static str {
    PLANE_SECTION
        .lines()
        .next()
        .expect("the plane-section fixture is not empty")
}

fn write_config(dir: &Path, data_port: u16, admin_port: u16, auth_block: &str) -> PathBuf {
    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    let catalog = if cfg!(linked_section_pools) {
        "providers: {}\nmodels: {}\n"
    } else {
        ""
    };
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
store: {{module: memory}}
{catalog}pools: {{}}
{auth_block}
{section}"#,
            section = plane_section(data_port, admin_port),
        ),
    )
    .unwrap();
    path
}

const AUTH_OPEN: &str = r#"auth:
  admin_auth: []
"#;

const AUTH_CLOSED: &str = r#"auth:
  chain: [keys]
  admin_auth: []
  signing_key: { env: BUSBAR_SIGNING_KEY }
"#;

fn busbar(cfg: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(common::boot::exe());
    c.args(args)
        .env("BUSBAR_CONFIG", cfg)
        .env(
            "BUSBAR_PROVIDERS",
            cfg.parent().unwrap().join("providers.yaml"),
        )
        .env("BUSBAR_ADMIN_TOKEN", "front-door-test-admin-token")
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
    c
}

fn assert_names_both_keys(where_: &str, text: &str) {
    assert!(
        text.contains(section_key()),
        "{where_} must name the door's own config key; got:\n{text}"
    );
    assert!(
        text.contains("auth.chain"),
        "{where_} must name the `auth.chain` key; got:\n{text}"
    );
}

#[test]
fn a_front_door_config_with_no_auth_chain_fails_validate_naming_both_keys() {
    let dir = fixture_dir("validate");
    let cfg = write_config(&dir, free_port(), free_port(), AUTH_OPEN);
    let out = busbar(&cfg, &["--validate"]).output().expect("run busbar");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(
        out.status.code(),
        Some(0),
        "`--validate` accepted a deployment with an anonymous front door:\n{text}"
    );
    assert_names_both_keys("the --validate error", &text);
}

#[test]
fn a_front_door_config_with_no_auth_chain_does_not_boot() {
    let dir = fixture_dir("boot");
    let cfg = write_config(&dir, free_port(), free_port(), AUTH_OPEN);

    let mut child = busbar(&cfg, &[])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn busbar");

    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(s) => break s,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let mut seen = String::new();
                if let Some(mut o) = child.stdout.take() {
                    let _ = o.read_to_string(&mut seen);
                }
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut seen);
                }
                let cfg_text = std::fs::read_to_string(&cfg).unwrap_or_default();
                panic!(
                    "busbar did not exit within 120s with the door configured and an empty \
                     auth.chain.\n\
                     If the output below carries the refusal, the guard fired and this test's \
                     wait is wrong; if it does not, the plane is being served anonymously.\n\
                     ── what busbar said ──\n{seen}\n── the config it was given ──\n{cfg_text}"
                );
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };
    let mut text = String::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_string(&mut text);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut text);
    }
    assert_ne!(status.code(), Some(0), "boot exited 0:\n{text}");
    assert_names_both_keys("the boot refusal", &text);
}

#[test]
fn the_control_a_front_door_config_with_a_closed_chain_still_boots() {
    let dir = fixture_dir("control");
    let data_port = free_port();
    let cfg = write_config(&dir, data_port, free_port(), AUTH_CLOSED);

    let out = busbar(&cfg, &["--validate"]).output().expect("run busbar");
    assert_eq!(
        out.status.code(),
        Some(0),
        "the control config did not validate:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let mut child = busbar(&cfg, &[])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn busbar");
    let addr = format!("127.0.0.1:{data_port}");
    let deadline = Instant::now() + Duration::from_secs(60);
    let listening = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            let mut text = String::new();
            if let Some(mut o) = child.stdout.take() {
                let _ = o.read_to_string(&mut text);
            }
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut text);
            }
            panic!("the control busbar exited ({status}) instead of listening:\n{text}");
        }
        if std::net::TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(500))
            .is_ok()
        {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        listening,
        "the door with `chain: [keys]` must still boot and listen on {addr}; a guard that refuses \
         every such config is vacuous in the other direction"
    );
}
