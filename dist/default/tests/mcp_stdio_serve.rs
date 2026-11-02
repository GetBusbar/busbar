// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(all(linked_section_tools, feature = "test-harness"))]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

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

fn token_for(aud: &str) -> String {
    common::credentials::token_for("e2e", &["tester"], aud)
}

fn install_auth_plugin(dir: &Path) {
    common::credentials::install_auth_plugin(
        &dir.join("plugins"),
        "e2e-idp-module",
        "e2e-idp",
        true,
    );
}

fn plane_section() -> String {
    include_str!("fixtures/stdio_plane_section.yaml").replace("{canonical}", canonical())
}

fn write_configs(dir: &Path, extra: &str) {
    let provider_lanes = cfg!(linked_section_pools);
    std::fs::write(
        dir.join("providers.yaml"),
        if provider_lanes {
            "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n"
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

type StdioChild = common::lines::LineChild;

fn spawn(dir: &Path, credential: Option<&str>) -> StdioChild {
    common::lines::spawn(command(dir, credential))
}

fn command(dir: &Path, credential: Option<&str>) -> Command {
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
    cmd
}

#[test]
fn a_broken_stdout_ends_the_line_session_without_waiting_for_stdin_eof() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = fixture_dir("broken-output");
    install_auth_plugin(&dir);
    write_configs(
        &dir,
        &governed_config(&dir, include_str!("fixtures/stdio_budget_bindings.yaml")),
    );
    let token = token_for(canonical());
    let mut child = common::boot::Reap(
        command(&dir, Some(&token))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("line child"),
    );
    drop(child.stdout.take());
    let mut input = child.stdin.take().unwrap();
    writeln!(input, "{}", serde_json::json!({"jsonrpc":"2.0","id":"broken-output","method":"ping","params":{"_meta":meta()}})).unwrap();
    let code = wait_bounded(&mut child, Duration::from_secs(120));
    drop(input);
    let mut stderr = Vec::new();
    std::io::Read::read_to_end(&mut child.stderr.take().expect("stderr piped"), &mut stderr)
        .expect("read the exited child stderr");
    let error = String::from_utf8_lossy(&stderr);
    assert_ne!(code, 0, "a failed output is not EOF: {error}");
    assert!(
        error.contains("line output failed"),
        "must reach the actual writer: {error}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn a_stdin_read_error_is_not_a_successful_eof() {
    use std::process::Stdio;
    let dir = fixture_dir("broken-input");
    install_auth_plugin(&dir);
    write_configs(
        &dir,
        &governed_config(&dir, include_str!("fixtures/stdio_budget_bindings.yaml")),
    );
    let token = token_for(canonical());
    let mut child = common::boot::Reap(
        command(&dir, Some(&token))
            .stdin(Stdio::from(std::fs::File::open(&dir).unwrap()))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("line child"),
    );
    let code = wait_bounded(&mut child, Duration::from_secs(120));
    let mut stderr = Vec::new();
    std::io::Read::read_to_end(&mut child.stderr.take().expect("stderr piped"), &mut stderr)
        .expect("read the exited child stderr");
    let error = String::from_utf8_lossy(&stderr);
    assert_ne!(code, 0, "read error is not EOF: {error}");
    assert!(
        error.contains("line input failed"),
        "must reach the actual reader: {error}"
    );
    let _ = std::fs::remove_dir_all(dir);
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

#[test]
fn a_governed_deployment_refuses_a_wrong_audience_credential() {
    let dir = fixture_dir("denied-aud");
    install_auth_plugin(&dir);
    write_configs(&dir, &governed_config(&dir, ""));

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

#[test]
fn a_keyless_admitted_credential_with_no_grant_is_refused() {
    let dir = fixture_dir("roleless");
    install_auth_plugin(&dir);
    let token = token_for(canonical());
    write_configs(&dir, &governed_config(&dir, ""));
    let mut child = spawn(&dir, Some(&token));
    let code = wait_bounded(&mut child.child, Duration::from_secs(120));
    assert_ne!(code, 0, "a keyless principal must not be served");
    let stderr = child.stderr_so_far();
    let refusal = format!(
        "busbar: mcp stdio serve refused to start: the credential in {} authenticated, but its \
         roles earned no enforcement key under `role_bindings`, and an ungoverned admission would \
         widen its access. The same request over HTTP answers `insufficient_scope`.",
        surface("credential_env")
    );
    assert!(
        stderr.lines().any(|l| l == refusal),
        "the NoGrant refusal, line for line: {stderr}"
    );
    assert!(
        !stderr.contains("UNGOVERNED"),
        "a keyless principal is never served ungoverned: {stderr}"
    );
    assert!(
        child.stdout.try_recv().is_err(),
        "not one frame may be served before the refusal"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

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

#[test]
fn the_line_flag_with_no_plane_claiming_the_carrier_refuses_and_binds_nothing() {
    let dir = fixture_dir("unclaimed");
    write_configs(&dir, "");

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

    let exited = common::lines::try_wait_bounded(&mut child.child, Duration::from_secs(60));
    let stderr = child.stderr_so_far();
    let _ = std::fs::remove_dir_all(&dir);
    let code = exited.unwrap_or_else(|e| {
        panic!("SIGTERM must end the line session with stdin still open: {e}\n{stderr}")
    });
    assert_eq!(code, 0, "a signalled stop is a clean shutdown: {stderr}");
    assert!(child.stdin.is_some(), "stdin was never closed by the test");
}
