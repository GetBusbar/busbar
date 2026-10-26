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
// build that links the plane that serves it.
// The plane under test is the door `plane-mcp` carries, served on the root's line carrier (SEAM-S1)
// through the stdio claim its door states; gated on `linked_section_tools`, set exactly when the
// linked door declaring `tools:` is in the build.
// It also needs the `test-harness` build: the dropped-in OIDC module
// is signed first-party, and only a `test-harness` child takes the first-party key a test holds
// (`root::boot::HARNESS_FIRST_PARTY_KEY_ENV`). So this battery runs in the root test-harness row and
// no longer in the single-plane or plain workspace rows.
#![cfg(all(linked_section_tools, feature = "test-harness"))]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

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
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

/// A JWT for principal `e2e` with role `tester`, bound to `aud` and signed by the local issuer
/// (`common::credentials`) — what the audience pre-filter reads and the auth module verifies.
fn token_for(aud: &str) -> String {
    common::credentials::token_for("e2e", &["tester"], aud)
}

/// The REAL token-verifying `kind: auth` plugin, signed first-party into the fixture's plugins dir
/// (`common::credentials::install_auth_plugin`).
fn install_auth_plugin(dir: &Path) {
    common::credentials::install_auth_plugin(
        &dir.join("plugins"),
        "e2e-idp-module",
        "e2e-idp",
        true,
    );
}

/// The plane's section every scenario writes, its canonical resource filled in.
fn plane_section() -> String {
    include_str!("fixtures/stdio_plane_section.yaml").replace("{canonical}", canonical())
}

/// The config skeleton every scenario shares: the MCP resource, `extra` verbatim, and the minimal
/// provider/model pair ONLY when the linked door that declares `pools:` is linked — the plane that owns
/// provider lanes. Whether to write them is read off the linked set (`linked_section_pools`, as
/// `thread_per_core_serves.rs` gates), never off a plane's name: a build without that door has no
/// wire codec and refuses a provider at boot (BUSBAR-9007), so its scenarios died before their first
/// frame. Without the door neither key is written: only a linked plane that requires a section makes
/// it required.
fn write_configs(dir: &Path, extra: &str) {
    let provider_lanes = cfg!(linked_section_pools);
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
store: {{module: memory}}
{providers}{section}{extra}"#,
            section = plane_section(),
        ),
    )
    .unwrap();
}

/// The governed deployment: the dropped-in auth module (provider `idp`) verifies tokens the local
/// issuer signed for the canonical audience and admits principal `e2e` with role `tester`;
/// `bindings` decides what that role earns.
fn governed_config(dir: &Path, bindings_and_more: &str) -> String {
    let settings = common::credentials::issuer_settings_yaml(canonical(), 6);
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

/// The line-served child (`common::lines`).
type StdioChild = common::lines::LineChild;

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
        .env(
            common::credentials::HARNESS_FIRST_PARTY_KEY_ENV,
            common::credentials::harness_release_key_hex(),
        )
        .env_remove(surface("credential_env"));
    if let Some(c) = credential {
        cmd.env(surface("credential_env"), c);
    }
    common::lines::spawn(cmd)
}

fn wait_bounded(child: &mut std::process::Child, bound: Duration) -> i32 {
    common::lines::wait_bounded(child, bound)
}

fn meta() -> serde_json::Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": { "elicitation": {} },
    })
}

/// CONFIG-REQ: `providers:` and `models:` are required only by a linked
/// plane that declares it requires them. This file's builds all link the plane serving this door;
/// with the plane that owns `models:` linked too (`linked_section_pools`: the default build),
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
    std::fs::write(
        dir.join("config.yaml"),
        "listen: \"127.0.0.1:0\"\nstore: {module: memory}\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--validate")
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .output()
        .expect("run busbar --validate");
    let _ = std::fs::remove_dir_all(&dir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if cfg!(linked_section_pools) {
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
    install_auth_plugin(&dir);
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
    install_auth_plugin(&dir);
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
    install_auth_plugin(&dir);
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

    let code = child.eof_and_wait(Duration::from_secs(60));
    assert_eq!(code, 0, "EOF on stdin is a clean shutdown");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 1.5.5 PARITY: an admitted credential under a module with no `role_bindings`
/// table earns NO enforcement key and is served UNGOVERNED, as 1.5.5 admitted it (v1.5.5
/// crates/busbar/src/auth/mod.rs:1543): the session binds with the UNGOVERNED warning on stderr,
/// is never refused `insufficient_scope`, and EOF on stdin is a clean shutdown.
#[test]
fn a_keyless_admitted_credential_is_served_ungoverned_as_1_5_5_served_it() {
    let dir = fixture_dir("roleless");
    install_auth_plugin(&dir);
    let token = token_for(canonical());
    write_configs(&dir, &governed_config(&dir, ""));
    let mut child = spawn(&dir, Some(&token));
    let mut stderr = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while !stderr.contains("UNGOVERNED") && std::time::Instant::now() < deadline {
        stderr.push_str(&child.stderr_so_far());
        if let Ok(Some(status)) = child.child.try_wait() {
            stderr.push_str(&child.stderr_so_far());
            panic!("the session exited ({status}) instead of serving ungoverned: {stderr}");
        }
    }
    assert!(
        stderr.contains("UNGOVERNED"),
        "the keyless session is served ungoverned, and says so: {stderr}"
    );
    assert!(
        !stderr.contains("insufficient_scope"),
        "a keyless principal under an unbound module is not refused: {stderr}"
    );
    let code = child.eof_and_wait(Duration::from_secs(60));
    assert_eq!(code, 0, "EOF on stdin is a clean shutdown");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A GOVERNED session whose role is bound (all pools, no group) speaks initialize/discover/
/// subscription over the real pipes, and EOF with the subscription still open exits 0 promptly
/// (`STDIO.EXIT-ON-EOF`).
#[test]
fn a_bound_session_serves_and_eof_with_a_live_subscription_exits_promptly() {
    let dir = fixture_dir("bound");
    install_auth_plugin(&dir);
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

    // A SESSION-era opening on this child: `initialize`, no `_meta`. The carrier answers in the session
    // revision the client asked for (revision by negotiation, THE DESIGN section 2); a line that
    // states the stateless `_meta` after it is still served as it is.
    child.send(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": { "name": "e2e", "version": "0" } }
    }));
    let init = child.recv();
    assert_eq!(
        init.pointer("/result/protocolVersion")
            .and_then(|v| v.as_str()),
        Some("2025-06-18"),
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

    let code = child.eof_and_wait(Duration::from_secs(60));
    assert_eq!(code, 0, "EOF with a live subscription still exits promptly");
    let _ = std::fs::remove_dir_all(&dir);
}

/// SEAM-S1 RED ARM, THE GRANT PER CALL ON THE LINE CARRIER: every line is its own unit with its own
/// scope check, so a principal whose role reaches only another pool (never this server) is refused
/// EACH `tools/call` it sends,
/// in the data listener's words (`not_granted`), while the session goes on serving what it may.
#[test]
fn an_ungranted_tool_is_refused_per_call_on_the_line() {
    let dir = fixture_dir("ungranted");
    install_auth_plugin(&dir);
    let token = token_for(canonical());
    write_configs(
        &dir,
        &governed_config(
            &dir,
            r#"  role_bindings:
    idp:
      tester: { allowed_pools: [elsewhere] }
tools:
  ws:
    url: "http://127.0.0.1:9/rpc"
    allow_private: true
    pin: { mechanism: cert_spki, key: "sha256/UNUSED=" }
    tools_allow:
      read: { schema_hash: "sha256:0000" }
"#,
        ),
    );
    let mut child = spawn(&dir, Some(&token));
    for i in 0..2 {
        child.send(&serde_json::json!({
            "jsonrpc": "2.0", "id": format!("call-{i}"), "method": "tools/call",
            "params": { "_meta": meta(), "name": "ws_read", "arguments": {} }
        }));
        let line = child.recv();
        assert_eq!(line["id"], format!("call-{i}"), "{line}");
        assert_eq!(
            line.pointer("/error/data/reason").and_then(|v| v.as_str()),
            Some("not_granted"),
            "each call is refused on its own scope check: {line}"
        );
    }
    // The session still serves what the principal may: the refusals ended their units, not it.
    child.send(&serde_json::json!({
        "jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": { "_meta": meta() }
    }));
    let list = child.recv();
    assert_eq!(list["id"], "list", "{list}");
    assert!(list.get("result").is_some(), "{list}");
    let code = child.eof_and_wait(Duration::from_secs(60));
    assert_eq!(code, 0, "EOF on stdin is a clean shutdown");
    let _ = std::fs::remove_dir_all(&dir);
}

/// ASKED FOR THE LINE CARRIER, NO PLANE CLAIMING IT: the launch is refused, never turned into a
/// network server its supervisor did not ask for. With the plane's section left out, no served
/// plane claims the line carrier (Law 7: the plane is not loaded), so the child exits nonzero with
/// the line carrier's own refusal on stderr and binds neither listener.
///
/// RED ARM: before the fix boot fell through to the listener path, bound `listen` and
/// `admin_listen`, and ran until killed, so the bounded wait fails.
#[test]
fn the_line_flag_with_no_plane_claiming_the_carrier_refuses_and_binds_nothing() {
    let dir = fixture_dir("unclaimed");
    write_configs(&dir, "");
    // The same deployment with the plane's section taken out: nothing claims the line carrier.
    let section = plane_section();
    let config = std::fs::read_to_string(dir.join("config.yaml")).unwrap();
    assert!(
        config.contains(&section),
        "the fixture writes the plane's section"
    );
    std::fs::write(dir.join("config.yaml"), config.replace(&section, "")).unwrap();
    let mut child = spawn(&dir, None);
    let exited = common::lines::try_wait_bounded(&mut child.child, Duration::from_secs(80));
    let stderr = child.stderr_so_far();
    let _ = std::fs::remove_dir_all(&dir);
    let code = exited.unwrap_or_else(|e| {
        panic!("a line-carrier launch no plane claims must refuse, not serve: {e}\n{stderr}")
    });
    assert_ne!(code, 0, "the refusal exits nonzero: {stderr}");
    assert!(
        stderr.contains("nothing to serve on stdin"),
        "the line carrier's refusal names why: {stderr}"
    );
    assert!(
        !stderr.contains("busbar listening"),
        "no listener is bound on a line-carrier launch: {stderr}"
    );
    assert!(
        child.stdout.try_recv().is_err(),
        "nothing is written to stdout"
    );
}

/// A SHUTDOWN SIGNAL STOPS THE LINE CARRIER: the signal busbar catches in every mode (SIGTERM, the
/// way a supervisor stops its child) ends a live line session with stdin still open, runs the one
/// shutdown tail and exits 0, as the listener path does on the same signal.
///
/// RED ARM: before the fix the handler was installed and nothing awaited it in this mode, so the
/// child kept serving until stdin closed and the bounded wait fails.
#[cfg(unix)]
#[test]
fn a_shutdown_signal_ends_a_live_line_session_cleanly() {
    let dir = fixture_dir("sigterm");
    install_auth_plugin(&dir);
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
    // A served answer first: boot is over and the signal handler is installed.
    child.send(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": { "_meta": meta() }
    }));
    let discover = child.recv();
    assert_eq!(discover["id"], 1, "{discover}");
    let killed = Command::new("kill")
        .arg("-TERM")
        .arg(child.child.id().to_string())
        .status()
        .expect("run kill");
    assert!(killed.success(), "SIGTERM delivered");
    // stdin stays open: only the signal can end the session.
    let exited = common::lines::try_wait_bounded(&mut child.child, Duration::from_secs(60));
    let stderr = child.stderr_so_far();
    let _ = std::fs::remove_dir_all(&dir);
    let code = exited.unwrap_or_else(|e| {
        panic!("SIGTERM must end the line session with stdin still open: {e}\n{stderr}")
    });
    assert_eq!(code, 0, "a signalled stop is a clean shutdown: {stderr}");
    assert!(child.stdin.is_some(), "stdin was never closed by the test");
}
