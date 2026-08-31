// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN MCP DEPLOYMENT MAY NOT HAVE AN OPEN FRONT DOOR, proven at the OUTERMOST surface: the real
//! binary, a real config file, `--validate` and an actual BOOT.
//!
//! ## What is being pinned, and why a unit test on the validator would not have been enough
//!
//! `mcp:` present with an empty data-plane `auth.chain` admits every request with NO principal. The
//! MCP plane decides both of its questions from the caller's grant — what a caller may SEE
//! (`tools_for(&grant)`) and what busbar may SPEND on its behalf (`upstream::authorise` binds the
//! outbound credential to the inbound principal's grant) — and a request that carries no key is
//! never narrowed by one. The grant predicate then answers `true` for every pair it is asked about,
//! so "anonymous" is not "no access", it is WILDCARD access, and the confused-deputy defence has no
//! principal left to bind to. Both properties go vacuous at once.
//!
//! The refusal is a CONFIG-VALIDATION error rather than a per-request check on purpose: dispatch
//! admission on this plane has exactly one owner, and a second opinion on the request path is the
//! shape that was already removed from here once. It therefore has to hold at the two places an
//! operator meets a config — `--validate` and boot — and those are two different code paths in
//! `main.rs`. This file drives both, through the shipped binary, because a validator that agrees
//! with itself in a unit test and disagrees with boot is precisely the drift worth catching.
//!
//! The CONTROL is not optional. Four refusals and no successful boot are equally consistent with a
//! busbar that refuses every MCP config, which would make the guard vacuous in the other direction,
//! so `chain: [keys]` must still start and listen.

// GATED ON `plane-mcp` as a whole file: every test here feeds the binary an `mcp:` config, and the
// open-front-door refusal under test lives in `busbar-mcp`, compiled out with the plane. A
// `--no-default-features` binary has no MCP front door to leave open, so neither the refusal nor
// the control can mean anything there. Same shape as `docs_examples.rs` gating its whole file on
// `auth-admin-tokens`, and the same reasoning as the `plane-mcp` gate in `cli_validate.rs`.
#![cfg(feature = "plane-mcp")]

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A fresh, isolated fixture directory. Per-test, so nothing shares a config or a port.
fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-mcp-front-door-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A free loopback port, asked of the OS rather than hard-coded: a hard-coded port is a red that is
/// not a defect the first time this machine happens to have something on it.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// The smallest config that makes a deployment an MCP server, with `auth_block` spliced in
/// verbatim. Everything absent is absent on purpose: no providers, no models, no pools — the MCP
/// plane needs none of them, and a fixture that also carried an LLM fleet could fail for a reason
/// that is about the fleet.
fn write_config(dir: &Path, data_port: u16, admin_port: u16, auth_block: &str) -> PathBuf {
    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
providers: {{}}
models: {{}}
pools: {{}}
{auth_block}
mcp:
  canonical_uri: "http://127.0.0.1:{data_port}/mcp"
  authorization_servers:
    - "http://127.0.0.1:{admin_port}"
"#
        ),
    )
    .unwrap();
    path
}

// BOTH BLOCKS USE `admin_auth: []`, AND THE `admin-tokens` IDENTITY PROVIDER IS GONE FROM THE
// CONFIG ABOVE, ON PURPOSE. Configuring an admin-tokens token is itself a boot refusal in a binary
// built without the `auth-admin-tokens` feature ("the admin API would be silently disabled"), so
// the scaffolding was failing the control before the property under test was ever reached.
//
// The alternative was to gate this file on that feature. That would have been wrong: an MCP
// deployment answering anonymously with wildcard grants is a security property that must hold in
// EVERY build, and `--no-default-features` is exactly the build where quietly dropping the check
// would go unnoticed. The admin plane is scaffolding here; the data plane is the subject.
/// The OPEN front door: an `auth:` block with no data-plane chain at all.
const AUTH_OPEN: &str = r#"auth:
  admin_auth: []
"#;

/// The CLOSED control: the built-in signed-key verifier, and the signing key it requires.
const AUTH_CLOSED: &str = r#"auth:
  chain: [keys]
  admin_auth: []
  signing_key: { env: BUSBAR_SIGNING_KEY }
"#;

fn busbar(cfg: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_busbar"));
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

/// Both keys must be NAMED. A refusal that says "invalid configuration" sends an operator reading
/// the whole file; this one has to point at the two lines whose combination is the defect, because
/// neither is wrong on its own — `mcp:` alone is fine and an empty chain alone is a documented
/// dev-mode posture.
fn assert_names_both_keys(where_: &str, text: &str) {
    assert!(
        text.contains("mcp:"),
        "{where_} must name the `mcp:` key; got:\n{text}"
    );
    assert!(
        text.contains("auth.chain"),
        "{where_} must name the `auth.chain` key; got:\n{text}"
    );
}

#[test]
fn an_mcp_config_with_no_auth_chain_fails_validate_naming_both_keys() {
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
        "`--validate` accepted an MCP deployment with an anonymous front door:\n{text}"
    );
    assert_names_both_keys("the --validate error", &text);
}

#[test]
fn an_mcp_config_with_no_auth_chain_does_not_boot() {
    let dir = fixture_dir("boot");
    let cfg = write_config(&dir, free_port(), free_port(), AUTH_OPEN);
    // No `--validate`: this is the REAL boot path, which is a different code path in `main.rs` from
    // the one above and is the one that would actually serve the plane.
    let mut child = busbar(&cfg, &[])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn busbar");

    // 120s, and the size is deliberate. This deadline BOUNDS A WAIT; it does not assert a latency.
    // The property is "busbar exits rather than serving the plane", and how long it takes to decide
    // that is not part of the claim — so a generous bound costs nothing and a tight one buys
    // nothing. (Contrast a test that asserts an operation finishes within N: there the deadline IS
    // the property, and raising it to stop a flake deletes the test.)
    //
    // 30s was marginal in practice, and not for any reason in busbar: on macOS a freshly linked
    // debug binary is stalled inside `_dyld_start` by the code-signing scan before `main` runs at
    // all — sampled and confirmed, the child sat entirely in dyld while producing no output. That
    // is a property of the developer's machine, not of the engine, and the test should not be
    // reporting a security regression because the linker was busy.
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(s) => break s,
            None if Instant::now() >= deadline => {
                // The verdict has to carry its EVIDENCE. This arm used to panic with the headline
                // alone, which is indistinguishable between "the guard is gone" and "the fixture
                // never reached the guard" — and the second is what it actually was. Kill first,
                // then drain both pipes, so the message names which one happened.
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
                    "busbar did not exit within 120s with `mcp:` and an empty auth.chain.\n\
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
fn the_control_an_mcp_config_with_a_closed_chain_still_boots() {
    let dir = fixture_dir("control");
    let data_port = free_port();
    let cfg = write_config(&dir, data_port, free_port(), AUTH_CLOSED);

    // `--validate` first: the cheap half of the control, and the one that localises a failure. If
    // this is red the fixture is wrong, not the guard.
    let out = busbar(&cfg, &["--validate"]).output().expect("run busbar");
    assert_eq!(
        out.status.code(),
        Some(0),
        "the control config did not validate:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // And then the half that actually matters: it LISTENS. Readiness is proven by observation —
    // a completed TCP connect — rather than by the process merely not having exited yet, which a
    // process on its way to a panic also satisfies.
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
        "`mcp:` with `chain: [keys]` must still boot and listen on {addr}; a guard that refuses \
         every MCP config is vacuous in the other direction"
    );
}
