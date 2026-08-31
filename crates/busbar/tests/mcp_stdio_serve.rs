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
//! * a GOVERNED SESSION end to end: the credential is admitted by a REAL auth-chain plugin loaded
//!   over the REAL plugin pipeline, `role_bindings` binds the session to a budget-capped group,
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
#![cfg(feature = "plane-mcp")]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The audience every credential in this battery is bound to — the deployment's canonical URI.
const CANONICAL: &str = "http://127.0.0.1:18080/mcp";

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-mcp-stdio-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

/// A structurally-valid JWT bound to `aud` — what the audience pre-filter reads. The signature is
/// junk on purpose: the CHAIN is what verifies possession here (the static-auth plugin compares
/// the whole string), and the pre-filter only ever narrows.
fn jwt_with_aud(aud: &str) -> String {
    use base64::Engine as _;
    let b64 = |v: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    };
    format!(
        "{}.{}.e2e-sig",
        b64(&serde_json::json!({ "alg": "none" })),
        b64(&serde_json::json!({ "aud": aud, "sub": "e2e" })),
    )
}

/// Package the REAL `busbar-auth-static-plugin` cdylib (built into this workspace's target dir)
/// into an unsigned `kind: auth` tarball in the fixture's plugins dir. `false` when the cdylib is
/// not built — a skip locally, a hard failure under CI, the same posture
/// `auth/tests/plugin_chain_tests.rs` takes for the same artifact.
fn install_static_auth_plugin(dir: &Path) -> bool {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_auth_static_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    let Some(path) = candidate else {
        if std::env::var_os("CI").is_some() {
            panic!(
                "the static-auth plugin cdylib is not built under CI; refusing to silently skip \
                 the governed stdio-serve end-to-end coverage"
            );
        }
        eprintln!(
            "skip: static-auth plugin cdylib not built (cargo build -p busbar-auth-static-plugin)"
        );
        return false;
    };
    let lib = std::fs::read(&path).expect("read the static-auth cdylib");
    let m = busbar_plugin_sign::Manifest {
        name: "e2e-auth-static".into(),
        alias: "e2e-idp".into(),
        kind: "auth".into(),
        version: "1.6.0".into(),
        publisher: "e2e".into(),
        abi_version: *busbar_plugin_loader::supported_abi("auth")
            .iter()
            .max()
            .expect("auth abi"),
        sha256: busbar_plugin_sign::sha256_hex(&lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    let bytes = busbar_plugin_loader::tarball::package(&m, "lib.so", &lib).unwrap();
    std::fs::write(dir.join("plugins").join("e2e-auth-static.tar.gz"), bytes).unwrap();
    true
}

/// The config skeleton every scenario shares: the minimal provider/model pair (required sections),
/// the MCP resource, and `extra` verbatim.
fn write_configs(dir: &Path, extra: &str) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:0"
admin_listen: "127.0.0.1:0"
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
mcp:
  canonical_uri: "{CANONICAL}"
  authorization_servers: ["https://login.example.com"]
{extra}"#
        ),
    )
    .unwrap();
}

/// The governed deployment: the static-auth plugin admits `token` as principal `e2e` with role
/// `tester`; `bindings` decides what that role earns.
fn governed_config(dir: &Path, token: &str, bindings_and_more: &str) -> String {
    format!(
        r#"plugins:
  enabled: true
  dir: '{plugins}'
  trust:
    allow_unsigned: true
identity-providers:
  statauth:
    module: e2e-auth-static
    settings:
      token: "{token}"
      id: e2e
      roles: [tester]
auth:
  chain: [statauth]
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
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_busbar"));
    cmd.arg("--mcp-stdio")
        .env("MOCK_KEY", "test-key-value")
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env_remove("BUSBAR_MCP_STDIO_CREDENTIAL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(c) = credential {
        cmd.env("BUSBAR_MCP_STDIO_CREDENTIAL", c);
    }
    let mut child = cmd.spawn().expect("spawn busbar --mcp-stdio");
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
            .recv_timeout(Duration::from_secs(30))
            .expect("the child must answer within the bound");
        serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!("every stdout line must be one JSON-RPC message ({e}): {line:?}")
        })
    }

    /// EOF on stdin, then the exit code — bounded, so a child that ignores EOF fails the test
    /// rather than hanging it.
    fn eof_and_wait(mut self) -> i32 {
        drop(self.stdin.take());
        wait_bounded(&mut self.child, Duration::from_secs(15))
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

/// `mcp:` WITH AN OPEN CHAIN DOES NOT EXIST, on any transport: the boot refuses the combination
/// outright, in the stdio mode exactly as on the listeners — so there is no "unauthenticated stdio
/// session" to have a posture about; the open-relay warning the HTTP door earns for an empty chain
/// is, on an MCP deployment, a boot refusal instead.
#[test]
fn an_mcp_deployment_with_an_empty_chain_refuses_to_boot() {
    let dir = fixture_dir("open-refused");
    write_configs(&dir, "");
    let mut child = spawn(&dir, None);
    let code = wait_bounded(&mut child.child, Duration::from_secs(20));
    assert_ne!(code, 0, "mcp + empty auth.chain must not boot");
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
    if !install_static_auth_plugin(&dir) {
        return;
    }
    let token = jwt_with_aud(CANONICAL);
    write_configs(&dir, &governed_config(&dir, &token, ""));
    let mut child = spawn(&dir, None);
    let code = wait_bounded(&mut child.child, Duration::from_secs(30));
    assert_ne!(code, 0, "a governed deployment must not serve unattributed");
    let stderr = child.stderr_so_far();
    assert!(
        stderr.contains("BUSBAR_MCP_STDIO_CREDENTIAL"),
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
    if !install_static_auth_plugin(&dir) {
        return;
    }
    let token = jwt_with_aud(CANONICAL);
    write_configs(&dir, &governed_config(&dir, &token, ""));
    let wrong = jwt_with_aud("https://some-other-resource.example.com/mcp");
    let mut child = spawn(&dir, Some(&wrong));
    let code = wait_bounded(&mut child.child, Duration::from_secs(30));
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
    if !install_static_auth_plugin(&dir) {
        return;
    }
    let token = jwt_with_aud(CANONICAL);
    write_configs(
        &dir,
        &governed_config(
            &dir,
            &token,
            r#"  role_bindings:
    statauth:
      tester: { group: tiny }
groups:
  tiny:
    limits:
      - { requests: 2, per: hour }
tools:
  ws:
    url: "http://127.0.0.1:9/mcp"
    allow_private: true
    pin: { mechanism: cert_spki, key: "sha256/UNUSED=" }
    prompts_allow:
      greet:
        description: "a greeting"
        template: "Hello from the operator."
        ask_caller:
          - confirm:
              method: elicitation/create
              params:
                message: "Render the greeting?"
                requestedSchema: { type: object, properties: { ok: { type: boolean } } }
"#,
        ),
    );
    let mut child = spawn(&dir, Some(&token));

    // Drive prompts/get until the budget bites. Each admitted call asks first — a LIVE
    // `elicitation/create` request on the channel — and is answered; a refused call asks nothing.
    let mut successes = 0;
    let mut refusal: Option<serde_json::Value> = None;
    for i in 0..4 {
        child.send(&serde_json::json!({
            "jsonrpc": "2.0", "id": format!("call-{i}"), "method": "prompts/get",
            "params": { "_meta": meta(), "name": "ws_greet" }
        }));
        let mut line = child.recv();
        if line.get("method").and_then(|m| m.as_str()) == Some("elicitation/create") {
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

/// A ROLELESS admitted principal (no `role_bindings` for its module) serves UNGOVERNED — warned in
/// so many words on stderr — the session speaks initialize/discover/subscription over the real
/// pipes, and EOF with the subscription still open exits 0 promptly.
#[test]
fn a_roleless_session_serves_ungoverned_and_eof_with_a_live_subscription_exits_promptly() {
    let dir = fixture_dir("roleless");
    if !install_static_auth_plugin(&dir) {
        return;
    }
    let token = jwt_with_aud(CANONICAL);
    write_configs(&dir, &governed_config(&dir, &token, ""));
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
        stderr.contains("UNGOVERNED"),
        "an ungoverned session says so on stderr: {stderr}"
    );

    let code = child.eof_and_wait();
    assert_eq!(code, 0, "EOF with a live subscription still exits promptly");
    let _ = std::fs::remove_dir_all(&dir);
}
