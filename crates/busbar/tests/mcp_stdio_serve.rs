// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! END-TO-END: `busbar --mcp-stdio` as a REAL CHILD PROCESS — spawned from `CARGO_BIN_EXE_busbar`,
//! driven over its actual stdin/stdout pipes, exactly as an MCP host (a Claude Desktop-class
//! client) runs a stdio server.
//!
//! What only THIS battery can prove, and what it therefore owns:
//!
//! * the BOOT-TIME GOVERNANCE POSTURES as **process exit codes**: an `mcp:` block with an empty
//!   `auth.chain` refuses to BOOT (the same config validation every transport runs); a configured
//!   chain with no `BUSBAR_MCP_STDIO_CREDENTIAL`, or with one the admission refuses, **exits
//!   nonzero without serving a single frame** — the stdio spelling of the HTTP door's `401`;
//! * a GOVERNED SESSION end to end: the credential — a JWT a local issuer signed — is verified by a
//!   REAL token-verifying auth plugin (GetBusbar/busbar-auth-oidc, on the auth kind's door) loaded
//!   over the REAL plugin pipeline, the issuer's JWKS on a certificate-verified loopback endpoint
//!   fetched for it by the child's OWN connector over the plugin's declared need (the plugin holds
//!   no socket and no TLS; `advanced.allow_destinations` lets the loopback through the destination
//!   guard), `role_bindings` binds the session to a budget-capped group,
//!   the operator's `ask_caller` is driven as LIVE `elicitation/create` requests over the pipes,
//!   and **the call over budget is refused with the budget named** — governance applied to a
//!   child process, watched from outside it;
//! * the transport MUSTs against the real pipes: stdout carries ONLY newline-delimited JSON-RPC
//!   (`STDIO.STDOUT-ONLY-MCP`, asserted on every line read), and EOF on stdin ends the process
//!   promptly with exit 0 (`STDIO.EXIT-ON-EOF`) — including with a subscription still open.
//!
//! The in-process companion is `mcp::stdio_serve::stdio_serve_tests`, which drives the same
//! `serve_io` loop against `TestApp` fixtures for the per-method behaviours; this file is the
//! process boundary those tests cannot cross.

// The `--mcp-stdio` serve mode exists only when the MCP plane is compiled in: with `plane-mcp` off
// the flag falls through to the listener path (main.rs, "a build without MCP falls through to its
// listener path"), so the spawned child is a normal HTTP server that never emits a stdio frame and
// never exits on stdin EOF. These end-to-end tests drive that stdio channel, so they belong to the
// same feature as the mode they exercise — matching the binary's own `#[cfg(feature = "plane-mcp")]`
// on the serve block.
// The plane under test is the linked row carrying the `stdio-serve` axis (build.rs emits
// `linked_axis_stdio_serve` from `[package.metadata.busbar.linked-axes]`).
#![cfg(linked_axis_stdio_serve)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The stdio serve mode's operator surface, as DATA (`tests/fixtures/stdio_serve.txt`).
fn surface(key: &str) -> &'static str {
    include_str!("fixtures/stdio_serve.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim())
        })
        .unwrap_or_else(|| panic!("tests/fixtures/stdio_serve.txt has no `{key}` row"))
}

/// The audience every credential in this battery is bound to — the deployment's canonical URI.
fn canonical() -> &'static str {
    surface("canonical_uri")
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-stdio-serve-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

/// THE LOCAL ISSUER, one per test process (the loader's `test_issuer`): an ES256 key, its JWKS
/// served over a certificate-verified loopback endpoint the module trusts through `ca_cert_pem`, and
/// genuinely signed tokens. The child `busbar` process's connector fetches the JWKS over the
/// dropped-in module's declared need, and the module does the whole verification.
fn issuer() -> &'static busbar_plugin_loader::test_issuer::Issuer {
    static ONE: std::sync::OnceLock<busbar_plugin_loader::test_issuer::Issuer> =
        std::sync::OnceLock::new();
    ONE.get_or_init(|| {
        busbar_plugin_loader::test_issuer::Issuer::start("https://issuer.e2e.invalid", "e2e-issuer")
    })
}

/// A JWT for principal `e2e` with role `tester`, bound to `aud` and signed by the local issuer —
/// what the audience pre-filter reads and the auth module verifies.
fn token_for(aud: &str) -> String {
    issuer().mint("e2e", &["tester"], aud)
}

/// RECORD A SKIP, LOUDLY AND DURABLY — never a silent pass.
///
/// `libtest` has no "skipped" outcome: a test that returns early reports the same green as a test
/// that asserted everything it claims to. `eprintln!` does not close that gap, because libtest
/// captures a passing test's output and never shows it — so the operator sees a green suite and no
/// indication that four end-to-end coverages did not run.
///
/// So a missing prerequisite does two things here. Under CI it PANICS: coverage that CI is supposed
/// to be providing must not be quietly absent. Everywhere else it appends a row to a skip ledger and
/// writes the banner to the process's real stderr, bypassing libtest's capture — so the skip is
/// visible in the moment AND readable afterwards by whatever collates the run.
///
/// The ledger path comes from `BUSBAR_TEST_SKIP_LEDGER`, defaulting beside the test binary; a
/// ledger that cannot be written is itself reported rather than swallowed.
fn record_skip(reason: &str) {
    let test = std::thread::current()
        .name()
        .unwrap_or(env!("CARGO_CRATE_NAME"))
        .to_string();

    if std::env::var_os("CI").is_some() {
        panic!(
            "SKIP REFUSED UNDER CI: {test} cannot run because {reason}. CI is where this coverage \
             is supposed to exist, so an absent prerequisite is a failure, not a skip."
        );
    }

    let ledger = std::env::var_os("BUSBAR_TEST_SKIP_LEDGER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|e| e.parent().map(Path::to_path_buf))
                .unwrap_or_else(std::env::temp_dir)
                .join("busbar-test-skips.ledger")
        });

    let row = format!("{}\t{test}\t{reason}\n", env!("CARGO_CRATE_NAME"));
    let wrote = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ledger)
        .and_then(|mut f| std::io::Write::write_all(&mut f, row.as_bytes()));

    // Straight to the process's stderr, not through libtest's captured `eprintln!`.
    let mut err = std::io::stderr().lock();
    let _ = std::io::Write::write_all(
        &mut err,
        format!(
            "\n=== SKIPPED (NOT PASSED): {test} ===\n  reason: {reason}\n  ledger: {}\n{}\n",
            ledger.display(),
            match &wrote {
                Ok(()) => "  this skip is recorded; the assertions below did NOT run".to_string(),
                Err(e) => format!("  WARNING: the skip ledger could not be written ({e})"),
            }
        )
        .as_bytes(),
    );
}

/// Package the REAL `busbar-auth-oidc-plugin` cdylib (GetBusbar/busbar-auth-oidc, a pinned git
/// dev-dependency of this crate, so the build leaves it under `deps/` with a metadata hash) into an
/// unsigned `kind: auth` tarball in the fixture's plugins dir, its manifest stating the door's
/// Statement as the pack tool renders it. `false` when the cdylib is not built —
/// a skip locally, a hard failure under CI, the same posture busbar-kernel's
/// `auth/tests/plugin_chain_tests.rs` takes for the same artifact.
fn install_auth_plugin(dir: &Path) -> bool {
    let Some(lib) = common::plugins::cdylib("busbar_auth_oidc_plugin") else {
        record_skip("auth-oidc plugin cdylib not built (cargo test -p busbar builds it)");
        return false;
    };
    let mut m = common::plugins::manifest("auth", "e2e-idp-module", "e2e");
    m.alias = "e2e-idp".into();
    let path = std::env::temp_dir().join(format!(
        "busbar-stdio-idp-{}{}",
        std::process::id(),
        std::env::consts::DLL_SUFFIX
    ));
    std::fs::write(&path, &lib).expect("stage the library");
    m.statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
        .expect("the auth-oidc cdylib states its door")
        .map(hex::encode);
    let _ = std::fs::remove_file(&path);
    let bytes = common::plugins::seal(m, &lib);
    std::fs::write(dir.join("plugins").join("e2e-idp-module.tar.gz"), bytes).unwrap();
    true
}

/// The config skeleton every scenario shares: the MCP resource, `extra` verbatim, and the minimal
/// provider/model pair ONLY when a linked row carries the body-ingress axis — the plane that owns
/// provider lanes. Whether to write them is read off the linked set (`linked_axis_body_ingress`, as
/// `thread_per_core_serves.rs` gates), never off a plane's name: a build without that axis has no
/// wire codec and refuses a provider at boot (BUSBAR-9007), so its scenarios died before their first
/// frame. Without the axis neither key is written: only a linked plane that requires a section makes
/// it required.
fn write_configs(dir: &Path, extra: &str) {
    let provider_lanes = cfg!(linked_axis_body_ingress);
    std::fs::write(
        dir.join("providers.yaml"),
        if provider_lanes {
            "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n"
        } else {
            "{}\n"
        },
    )
    .unwrap();
    let providers = if provider_lanes {
        "providers:\n  mock:\n    api_key: { env: MOCK_KEY }\nmodels:\n  test-model:\n    provider: mock\n"
    } else {
        ""
    };
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:0"
admin_listen: "127.0.0.1:0"
advanced:
  allow_destinations: ["127.0.0.1"]
{providers}{section}{extra}"#,
            section = include_str!("fixtures/stdio_plane_section.yaml")
                .replace("{canonical}", canonical()),
        ),
    )
    .unwrap();
}

/// The governed deployment: the dropped-in auth module (provider `idp`) verifies tokens the local
/// issuer signed for the canonical audience and admits principal `e2e` with role `tester`;
/// `bindings` decides what that role earns.
fn governed_config(dir: &Path, bindings_and_more: &str) -> String {
    let settings: String = issuer()
        .settings(canonical())
        .into_iter()
        .map(|(k, v)| format!("      {k}: {v}\n"))
        .collect();
    format!(
        r#"plugins:
  enabled: true
  dir: '{plugins}'
  trust:
    allow_unsigned: true
identity-providers:
  idp:
    module: e2e-idp-module
    settings:
{settings}auth:
  chain: [idp]
  signing_key: {{ env: BUSBAR_SIGNING_KEY }}
{bindings_and_more}"#,
        plugins = dir.join("plugins").display(),
    )
}

/// The child, its pipes, and a line-reader thread per output stream.
struct StdioChild {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    stdout: mpsc::Receiver<String>,
    stderr: mpsc::Receiver<String>,
}

fn spawn(dir: &Path, credential: Option<&str>) -> StdioChild {
    let mut cmd = Command::new(common::boot::exe());
    cmd.arg(surface("serve_flag"))
        .env("MOCK_KEY", "test-key-value")
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env_remove(surface("credential_env"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(c) = credential {
        cmd.env(surface("credential_env"), c);
    }
    let mut child = cmd.spawn().expect("spawn busbar in its stdio serve mode");
    let stdin = child.stdin.take();
    let (out_tx, out_rx) = mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = out_tx.send(line);
        }
    });
    let (err_tx, err_rx) = mpsc::channel();
    let stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = err_tx.send(line);
        }
    });
    StdioChild {
        child,
        stdin,
        stdout: out_rx,
        stderr: err_rx,
    }
}

impl StdioChild {
    fn send(&mut self, value: &serde_json::Value) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        stdin.write_all(&bytes).unwrap();
        stdin.flush().unwrap();
    }

    /// The next stdout line, which MUST be one JSON-RPC message (`STDIO.STDOUT-ONLY-MCP` asserted
    /// on every read this battery makes).
    fn recv(&self) -> serde_json::Value {
        let line = self
            .stdout
            // A hang detector, not a latency assertion: a debug child on a saturated host has
            // taken most of thirty seconds just to answer, so the bound is well past that.
            .recv_timeout(Duration::from_secs(120))
            .expect("the child must answer within the bound");
        serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!("every stdout line must be one JSON-RPC message ({e}): {line:?}")
        })
    }

    /// EOF on stdin, then the exit code — bounded, so a child that ignores EOF fails the test
    /// rather than hanging it.
    fn eof_and_wait(mut self) -> i32 {
        drop(self.stdin.take());
        wait_bounded(&mut self.child, Duration::from_secs(60))
    }

    /// Everything stderr has said so far. Drained with a short grace per line, because the reader
    /// thread can still be flushing the child's final sentences when the exit code lands.
    fn stderr_so_far(&self) -> String {
        let mut all = String::new();
        while let Ok(line) = self.stderr.recv_timeout(Duration::from_millis(300)) {
            all.push_str(&line);
            all.push('\n');
        }
        all
    }
}

fn wait_bounded(child: &mut Child, bound: Duration) -> i32 {
    let deadline = Instant::now() + bound;
    loop {
        if let Some(status) = child.try_wait().expect("wait on the child") {
            return status.code().unwrap_or(-1);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("the child did not exit within {bound:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn meta() -> serde_json::Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": { "elicitation": {} },
    })
}

/// CONFIG-REQ (ARCHITECT 2026-09-27, Law 7): `providers:` and `models:` are required only by a linked
/// plane that declares it requires them. This file's builds all link the plane serving this door;
/// with the plane that owns `models:` linked too (`linked_axis_body_ingress`: the default build),
/// a document carrying neither is refused with the published v1.5.5 line — measured on that
/// binary: `[error] config.yaml: invalid YAML: missing field `providers`` — carrying only 1.6.0's
/// diagnostic-code stamp (`BUSBAR-3015: `; accepted difference D-1, "the text after the code is
/// byte-identical to 1.5.5"). Without it (the single-plane row of this door's plane) the same
/// document validates.
///
/// RED ARM: before CONFIG-REQ that single-plane build refused the document with the same
/// `providers` line, so the arm expecting exit 0 fails on it.
#[test]
fn the_catalog_sections_are_required_only_when_a_linked_plane_requires_them() {
    const PROVIDERS_1_5_5: &str = "[error] config.yaml: invalid YAML: missing field `providers`";
    const STAMP: &str = "BUSBAR-3015: ";
    let dir = fixture_dir("catalog");
    std::fs::write(dir.join("providers.yaml"), "").unwrap();
    std::fs::write(dir.join("config.yaml"), "listen: \"127.0.0.1:0\"\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--validate")
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .output()
        .expect("run busbar --validate");
    let _ = std::fs::remove_dir_all(&dir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if cfg!(linked_axis_body_ingress) {
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        let stamped = PROVIDERS_1_5_5.replacen("[error] ", &format!("[error] {STAMP}"), 1);
        assert!(
            stderr
                .lines()
                .any(|l| l == stamped && l.replacen(STAMP, "", 1) == PROVIDERS_1_5_5),
            "the 1.5.5 missing-field line, byte for byte: {stderr}"
        );
    } else {
        assert_eq!(
            out.status.code(),
            Some(0),
            "no linked plane requires either section: {stderr}"
        );
    }
}

/// `mcp:` WITH AN OPEN CHAIN DOES NOT EXIST, on any transport: the boot refuses the combination
/// outright, in the stdio mode exactly as on the listeners — so there is no "unauthenticated stdio
/// session" to have a posture about; the open-relay warning the HTTP door earns for an empty chain
/// is, on an MCP deployment, a boot refusal instead.
#[test]
fn a_door_deployment_with_an_empty_chain_refuses_to_boot() {
    let dir = fixture_dir("open-refused");
    write_configs(&dir, "");
    let mut child = spawn(&dir, None);
    let code = wait_bounded(&mut child.child, Duration::from_secs(80));
    assert_ne!(
        code, 0,
        "the endpoint door + empty auth.chain must not boot"
    );
    let stderr = child.stderr_so_far();
    assert!(
        stderr.contains("auth.chain is empty"),
        "the refusal names the empty chain: {stderr}"
    );
    assert!(child.stdout.try_recv().is_err(), "nothing may be served");
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED, END TO END: on a deployment whose `auth.chain` is configured, a stdio session with
/// NO credential refuses to serve — nonzero exit, the remedy named on stderr, and NOT ONE frame
/// served first. The stdio spelling of the HTTP door's `401`.
#[test]
fn a_governed_deployment_refuses_an_uncredentialed_stdio_session() {
    let dir = fixture_dir("denied-absent");
    if !install_auth_plugin(&dir) {
        return;
    }
    write_configs(&dir, &governed_config(&dir, ""));
    let mut child = spawn(&dir, None);
    let code = wait_bounded(&mut child.child, Duration::from_secs(120));
    assert_ne!(code, 0, "a governed deployment must not serve unattributed");
    let stderr = child.stderr_so_far();
    assert!(
        stderr.contains(surface("credential_env")),
        "the refusal names the remedy: {stderr}"
    );
    assert!(
        child.stdout.try_recv().is_err(),
        "not one frame may be served before the refusal"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// ...and a PRESENTED credential bound to the WRONG audience is the same nonzero exit, with the
/// audience named — the RFC 8707 boundary holds on the pipe exactly as it does on the socket.
#[test]
fn a_governed_deployment_refuses_a_wrong_audience_credential() {
    let dir = fixture_dir("denied-aud");
    if !install_auth_plugin(&dir) {
        return;
    }
    write_configs(&dir, &governed_config(&dir, ""));
    // Signed by the SAME issuer the module trusts — only the audience is wrong, so the refusal can
    // only be the audience rule's.
    let wrong = token_for(surface("wrong_audience_uri"));
    let mut child = spawn(&dir, Some(&wrong));
    let code = wait_bounded(&mut child.child, Duration::from_secs(120));
    assert_ne!(code, 0);
    let stderr = child.stderr_so_far();
    assert!(
        stderr.contains("audience"),
        "the refusal names the audience rule: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE GOVERNED SESSION, END TO END: the credential is admitted by a REAL auth plugin, the session
/// is bound to a budget-capped group through `role_bindings`, the operator's confirmation gate is
/// driven as LIVE `elicitation/create` requests over the real pipes — and the call over budget is
/// REFUSED with the budget named, while the ones within budget completed. Then EOF exits 0.
#[test]
fn a_budgeted_stdio_session_serves_within_budget_and_refuses_over_it() {
    let dir = fixture_dir("budget");
    if !install_auth_plugin(&dir) {
        return;
    }
    let token = token_for(canonical());
    write_configs(
        &dir,
        &governed_config(&dir, include_str!("fixtures/stdio_budget_bindings.yaml")),
    );
    let mut child = spawn(&dir, Some(&token));

    // Drive prompts/get until the budget bites. Each admitted call asks first — a LIVE
    // `elicitation/create` request on the channel — and is answered; a refused call asks nothing.
    let mut successes = 0;
    let mut elicitations = 0;
    let mut refusal: Option<serde_json::Value> = None;
    for i in 0..4 {
        child.send(&serde_json::json!({
            "jsonrpc": "2.0", "id": format!("call-{i}"), "method": "prompts/get",
            "params": { "_meta": meta(), "name": "ws_greet" }
        }));
        let mut line = child.recv();
        if line.get("method").and_then(|m| m.as_str()) == Some("elicitation/create") {
            elicitations += 1;
            assert_eq!(
                line.pointer("/params/message").and_then(|v| v.as_str()),
                Some("Render the greeting?"),
                "the operator's text, verbatim, as a real request: {line}"
            );
            child.send(&serde_json::json!({
                "jsonrpc": "2.0", "id": line["id"],
                "result": { "action": "accept", "content": { "ok": true } },
            }));
            line = child.recv();
        }
        assert_eq!(line["id"], format!("call-{i}"), "{line}");
        if line.get("result").is_some() {
            successes += 1;
            let rendered = serde_json::to_string(&line).unwrap();
            assert!(
                rendered.contains("Hello from the operator."),
                "the admitted call renders the operator's prompt: {line}"
            );
        } else {
            refusal = Some(line);
            break;
        }
    }
    assert!(
        successes >= 1,
        "the within-budget calls must have served; first non-result: {refusal:?}"
    );
    // THE ELICITATION HALF, which until now lived entirely inside an `if` with no `else` and no
    // counter. This battery's own header claims it owns proving that the operator's `ask_caller` is
    // driven as LIVE `elicitation/create` requests over the pipes -- but if the server stopped
    // emitting them (the confirmation gate regressing to auto-accept, a GOVERNANCE regression),
    // every iteration took the fall-through path, `successes` still incremented, the budget still
    // bit on the third call, and the test was green having driven zero elicitations.
    assert_eq!(
        elicitations, successes,
        "every ADMITTED call must ask first: {successes} served but only {elicitations} \
         elicitation/create request(s) crossed the pipes"
    );
    let refusal = refusal.expect("the over-budget call must be refused");
    let message = serde_json::to_string(&refusal).unwrap();
    assert!(
        message.contains("budget"),
        "the refusal names the budget: {refusal}"
    );

    let code = child.eof_and_wait();
    assert_eq!(code, 0, "EOF on stdin is a clean shutdown");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A ROLELESS admitted principal — the chain identifies it, but no `role_bindings` row binds its
/// role, so it earns NO enforcement key — is REFUSED at boot (item 144: an identified principal
/// with no key is refused, never admitted ungoverned with spend booked to `anonymous`). The stdio
/// spelling of the HTTP door's `403 insufficient_scope`: nonzero exit, the reason on stderr, and not
/// one frame served first.
#[test]
fn a_roleless_admitted_credential_is_refused_without_serving_a_frame() {
    let dir = fixture_dir("roleless");
    if !install_auth_plugin(&dir) {
        return;
    }
    let token = token_for(canonical());
    write_configs(&dir, &governed_config(&dir, ""));
    let mut child = spawn(&dir, Some(&token));
    let code = wait_bounded(&mut child.child, Duration::from_secs(120));
    assert_ne!(
        code, 0,
        "an admitted credential that earned no key must not serve"
    );
    let stderr = child.stderr_so_far();
    assert!(
        stderr.contains("role_bindings") && stderr.contains("insufficient_scope"),
        "the refusal names the missing binding and its HTTP twin: {stderr}"
    );
    assert!(
        !stderr.contains("UNGOVERNED"),
        "a keyless principal is refused, never served ungoverned: {stderr}"
    );
    assert!(
        child.stdout.try_recv().is_err(),
        "not one frame may be served before the refusal"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A GOVERNED session whose role is bound (all pools, no group) speaks initialize/discover/
/// subscription over the real pipes, and EOF with the subscription still open exits 0 promptly
/// (`STDIO.EXIT-ON-EOF`).
#[test]
fn a_bound_session_serves_and_eof_with_a_live_subscription_exits_promptly() {
    let dir = fixture_dir("bound");
    if !install_auth_plugin(&dir) {
        return;
    }
    let token = token_for(canonical());
    write_configs(
        &dir,
        &governed_config(
            &dir,
            r#"  role_bindings:
    idp:
      tester: {}
"#,
        ),
    );
    let mut child = spawn(&dir, Some(&token));

    // A LEGACY-era opening: `initialize`, no `_meta` — the stdio dual-era negotiation.
    child.send(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": { "name": "e2e", "version": "0" } }
    }));
    let init = child.recv();
    assert_eq!(
        init.pointer("/result/protocolVersion")
            .and_then(|v| v.as_str()),
        Some("2026-07-28"),
        "{init}"
    );
    child.send(&serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));

    child.send(&serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "server/discover", "params": { "_meta": meta() }
    }));
    let discover = child.recv();
    assert_eq!(discover["id"], 2, "{discover}");
    assert!(
        discover.pointer("/result/supportedVersions").is_some(),
        "{discover}"
    );

    child.send(&serde_json::json!({
        "jsonrpc": "2.0", "id": "sub", "method": "subscriptions/listen",
        "params": { "_meta": meta(), "notifications": { "toolsListChanged": true } }
    }));
    let ack = child.recv();
    assert_eq!(
        ack.get("method").and_then(|m| m.as_str()),
        Some("notifications/subscriptions/acknowledged"),
        "{ack}"
    );

    let stderr = child.stderr_so_far();
    assert!(
        !stderr.contains("UNGOVERNED"),
        "a bound session is governed, and does not say otherwise: {stderr}"
    );

    let code = child.eof_and_wait();
    assert_eq!(code, 0, "EOF with a live subscription still exits promptly");
    let _ = std::fs::remove_dir_all(&dir);
}
