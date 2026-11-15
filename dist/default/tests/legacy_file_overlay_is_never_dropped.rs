// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A 1.5.5 file overlay is never silently dropped on upgrade (UPG-A30b). 1.6 serving never reads
//! file overlays: the Store is the only runtime overlay. So the real binary refuses to serve while
//! the overlay 1.5.5 would have read still holds settings this Store has not imported, and says so
//! (with a remedy the current code can carry out from that state). A selector, variable or file
//! that holds nothing boots with a warning that names it. Every assertion is on the real process:
//! its exit status, `/healthz`, and its stderr.

#![cfg(unix)]

mod common;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use busbar_plugin_loader::sign::{Manifest, SigningKey};

/// The overlay shape 1.5.5 wrote for one admin-API settings change (the evidence run).
const L: &str = r#"{"version":1,"root":{"advanced":{"response_headers":{"server_timing":true}}}}"#;
const ADMIN: &str = "legacy-overlay-admin";

struct Work(PathBuf);
impl Drop for Work {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn workdir(tag: &str) -> Work {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-legacy-overlay-{tag}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(dir.join("plugins")).unwrap();
    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    Work(dir)
}

/// A minimal mutable 1.6 deployment on the memory Store, plus `extra` top-level YAML.
fn memory_config(dir: &Path, data: u16, admin: u16, extra: &str) {
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:{data}\"\nadmin_listen: \"127.0.0.1:{admin}\"\n\
             store: {{module: memory}}\nadmin_require_mtls: false\nauth:\n  chain: []\n\
             providers: {{}}\nmodels: {{}}\n{extra}"
        ),
    )
    .unwrap();
}

/// The current native SQLite Store image, signed and staged as `startup_upgrade_sqlite` does,
/// so the Store confirms durable persistence across restarts.
fn stage_sqlite(work: &Path) -> serde_json::Value {
    let library = PathBuf::from(
        std::env::var_os("BUSBAR_TEST_SQLITE_CDYLIB")
            .expect("BUSBAR_TEST_SQLITE_CDYLIB is the current native SQLite Store image"),
    );
    assert!(library.is_absolute() && library.is_file());
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library)
        .unwrap()
        .expect("the actual SQLite image declares its door");
    let facts = busbar_contract::abi::mechanism::rendering::read(&statement).unwrap();
    let image = std::fs::read(library).unwrap();
    let key = SigningKey::from_bytes(&[0x5b; 32]);
    let manifest = Manifest {
        name: facts.name.clone(),
        alias: "sqlite".into(),
        kind: "store".into(),
        version: facts.version,
        publisher: "legacy-overlay-fixture".into(),
        abi_version: facts.kind_abi,
        statement: Some(hex::encode(statement)),
        ..Default::default()
    };
    let archive = busbar_plugin_loader::tarball::package(
        &busbar_plugin_loader::sign::sign(&key, manifest, &image),
        "lib.so",
        &image,
    )
    .unwrap();
    std::fs::write(work.join("plugins/sqlite.tar.gz"), &archive).unwrap();
    serde_json::json!({
        "enabled": true, "dir": work.join("plugins"),
        "fetch": [{"url":"https://legacy-overlay-fixtures.invalid/sqlite.tar.gz", "sha256":hex::encode(busbar_contract::crypto::sha256(&archive))}],
        "trust": {"allow_unsigned":false, "allow_third_party":true, "publishers":[{"name":"legacy-overlay-fixture", "public_key":hex::encode(key.verifying_key().as_bytes())}]}
    })
}

/// A mutable 1.6 deployment on a durable SQLite Store with an admin token.
fn durable_config(dir: &Path, data: u16, admin: u16) {
    let plugins = stage_sqlite(dir);
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data}"
admin_listen: "127.0.0.1:{admin}"
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain: []
  admin_auth: [admin-tokens]
plugins: {plugins}
store:
  module: sqlite
  settings: {{ db_path: {database} }}
providers: {{}}
models: {{}}
"#,
            database = serde_json::to_string(&dir.join("store.sqlite")).unwrap()
        ),
    )
    .unwrap();
}

fn command(dir: &Path, args: &[&str], env: &[(&str, &Path)]) -> Command {
    let mut command = Command::new(common::boot::exe());
    command
        .current_dir(dir)
        .args(args)
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("BUSBAR_ADMIN_TOKEN", ADMIN)
        .env_remove("BUSBAR_CONFIG_OVERLAY")
        .env("RUST_LOG", "info")
        .stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command
}

struct Run {
    child: common::boot::Reap,
    stderr: PathBuf,
}

impl Run {
    fn start(dir: &Path, tag: &str, args: &[&str], env: &[(&str, &Path)]) -> Self {
        let stdout = dir.join(format!("{tag}.stdout"));
        let stderr = dir.join(format!("{tag}.stderr"));
        let child = command(dir, args, env)
            .stdout(std::fs::File::create(&stdout).unwrap())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .expect("spawn busbar");
        Self {
            child: common::boot::Reap(child),
            stderr,
        }
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    /// The node exits 1 within 30 s and `/healthz` never answers meanwhile. Returns stderr.
    fn refused(mut self, data: u16) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        let status: ExitStatus = loop {
            assert!(
                !common::boot::healthz_answers(data),
                "a node that must refuse answered /healthz: {}",
                self.stderr()
            );
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "the node must refuse to serve within 30 s, but is still running: {}",
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        let stderr = self.stderr();
        assert_eq!(status.code(), Some(1), "refusal exit status: {stderr}");
        stderr
    }

    /// The node answers `/healthz` within 60 s. Returns stderr up to that point; the node keeps running.
    fn healthy(&mut self, data: u16) -> String {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !common::boot::healthz_answers(data) {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "the node exited {status:?} before serving: {}",
                    self.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "the node did not answer /healthz within 60 s: {}",
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        self.stderr()
    }

    /// Graceful stop, so a durable Store is closed before the next boot opens it.
    fn stop(mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "graceful stop exceeded 30 s");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn boots(dir: &Path, data: u16, args: &[&str], env: &[(&str, &Path)]) -> String {
    let mut run = Run::start(dir, "boot", args, env);
    let stderr = run.healthy(data);
    run.stop();
    stderr
}

/// One HTTP/1.1 exchange; returns the status, the lower-cased header block and the body.
fn http(
    port: u16,
    method: &str,
    path: &str,
    body: &str,
    token: Option<&str>,
) -> (u16, String, String) {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let auth = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{auth}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, head.to_ascii_lowercase(), body.to_owned())
}

fn ports() -> (u16, u16) {
    (common::boot::free_port(), common::boot::free_port())
}

#[test]
fn default_overlay_beside_config_with_settings_refuses_to_serve() {
    let work = workdir("default");
    let (data, admin) = ports();
    memory_config(&work.0, data, admin, "");
    std::fs::write(work.0.join("busbar-overlay.json"), L).unwrap();
    let stderr = Run::start(&work.0, "boot", &[], &[]).refused(data);
    for needle in [
        "busbar-overlay.json",
        "This Store is ephemeral",
        "move the file away",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?}: {stderr}");
    }
}

#[test]
fn selected_overlay_file_with_settings_refuses_to_serve() {
    let work = workdir("selected");
    let (data, admin) = ports();
    memory_config(
        &work.0,
        data,
        admin,
        "config:\n  overlay:\n    file: old.json\n",
    );
    std::fs::write(work.0.join("old.json"), L).unwrap();
    let stderr = Run::start(&work.0, "boot", &[], &[]).refused(data);
    let named = work.0.join("old.json").display().to_string();
    for needle in [
        named.as_str(),
        "config.overlay.file",
        "This Store is ephemeral",
        "move the file away",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?}: {stderr}");
    }
}

#[test]
fn env_selected_overlay_with_settings_refuses_to_serve() {
    let work = workdir("env");
    let (data, admin) = ports();
    memory_config(&work.0, data, admin, "");
    let selected = work.0.join("env.json");
    std::fs::write(&selected, L).unwrap();
    let stderr = Run::start(
        &work.0,
        "boot",
        &[],
        &[("BUSBAR_CONFIG_OVERLAY", selected.as_path())],
    )
    .refused(data);
    for needle in ["BUSBAR_CONFIG_OVERLAY", "env.json", "move the file away"] {
        assert!(stderr.contains(needle), "missing {needle:?}: {stderr}");
    }
}

#[test]
fn selector_to_nothing_boots_and_says_so() {
    let work = workdir("selector-nothing");
    let (data, admin) = ports();
    memory_config(
        &work.0,
        data,
        admin,
        "config:\n  overlay:\n    file: /dev/null/oracle-overlay.json\n",
    );
    let stderr = boots(&work.0, data, &[], &[]);
    for needle in [
        "config.overlay",
        "not read",
        "/dev/null/oracle-overlay.json",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?}: {stderr}");
    }
}

#[test]
fn retired_env_to_nothing_boots_and_says_so() {
    let work = workdir("env-nothing");
    let (data, admin) = ports();
    memory_config(&work.0, data, admin, "");
    let absent = work.0.join("absent.json");
    let stderr = boots(
        &work.0,
        data,
        &[],
        &[("BUSBAR_CONFIG_OVERLAY", absent.as_path())],
    );
    for needle in ["BUSBAR_CONFIG_OVERLAY", "not read"] {
        assert!(stderr.contains(needle), "missing {needle:?}: {stderr}");
    }
}

#[test]
fn locked_config_with_a_settings_overlay_beside_it_boots() {
    let work = workdir("locked");
    let (data, admin) = ports();
    memory_config(&work.0, data, admin, "config:\n  locked: true\n");
    std::fs::write(work.0.join("busbar-overlay.json"), L).unwrap();
    boots(&work.0, data, &[], &[]);
}

#[test]
fn an_overlay_that_holds_no_settings_boots() {
    let work = workdir("empty");
    let (data, admin) = ports();
    memory_config(&work.0, data, admin, "");
    std::fs::write(
        work.0.join("busbar-overlay.json"),
        r#"{"version":1,"hooks":{},"groups":{}}"#,
    )
    .unwrap();
    boots(&work.0, data, &[], &[]);
}

#[test]
fn no_overlay_and_no_variable_boots_with_no_legacy_line() {
    let work = workdir("none");
    let (data, admin) = ports();
    memory_config(&work.0, data, admin, "");
    let stderr = boots(&work.0, data, &[], &[]);
    for needle in ["1.5.5 config overlay", "BUSBAR_CONFIG_OVERLAY"] {
        assert!(!stderr.contains(needle), "unexpected {needle:?}: {stderr}");
    }
}

#[test]
fn store_overlay_present_without_receipt_refuses_with_manual_remedy() {
    let work = workdir("store-head");
    let (data, admin) = ports();
    durable_config(&work.0, data, admin);

    // A 1.6 admin-API write creates a Store overlay HEAD and no 1.5.5 import receipt.
    let mut first = Run::start(&work.0, "first", &[], &[]);
    first.healthy(data);
    let (status, _, body) = http(
        admin,
        "PUT",
        "/api/v1/admin/config/settings",
        r#"{"advanced":{"response_headers":{"server_timing":false}}}"#,
        Some(ADMIN),
    );
    assert_eq!(status, 200, "the settings write: {body}");
    assert!(
        body.contains(r#""applied":true"#),
        "the settings write: {body}"
    );
    first.stop();

    // The kept-volume shape: a 1.5.5 overlay with settings beside the config.
    std::fs::write(work.0.join("busbar-overlay.json"), L).unwrap();
    let stderr = Run::start(&work.0, "second", &[], &[]).refused(data);
    for needle in [
        "busbar-overlay.json",
        "already holds a 1.6 config overlay",
        "cannot be folded into it",
        "Reconcile by hand",
        "move the file away",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?}: {stderr}");
    }
    assert!(
        !stderr.contains("Import them once with"),
        "an import that cannot succeed is offered: {stderr}"
    );

    // The stated way out works.
    std::fs::rename(
        work.0.join("busbar-overlay.json"),
        work.0.join("busbar-overlay.json.kept"),
    )
    .unwrap();
    let stderr = boots(&work.0, data, &[], &[]);
    assert!(!stderr.contains("1.5.5 config overlay"), "{stderr}");
}

#[test]
fn safe_mode_with_unimported_overlay_boots_and_warns_that_writes_block_import() {
    let work = workdir("safe-mode");
    let (data, admin) = ports();
    durable_config(&work.0, data, admin);
    std::fs::write(work.0.join("busbar-overlay.json"), L).unwrap();
    let stderr = boots(&work.0, data, &["--safe-mode"], &[]);
    for needle in [
        "busbar-overlay.json",
        "create a Store overlay",
        "re-apply this file's settings",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?}: {stderr}");
    }
}
