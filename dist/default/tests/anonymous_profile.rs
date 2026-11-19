// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The documented anonymous profile, through the real binary: `auth.chain: [anonymous]` with a
//! scoped `role_bindings.anonymous`. The node boots with the default planes loaded; a caller
//! presenting no credential is served exactly what its binding names and nothing else: not a pool
//! it does not name, not a plane it grants nothing of, and never the admin API. A binding may
//! grant the scope kinds the loaded plane images state (`allowed_agents`, `allowed_mcp_servers`)
//! before any plane mounts, and a kind no loaded plane states stays refused.

#![cfg(unix)]
#![cfg(all(
    linked_section_pools,
    linked_section_tools,
    linked_section_agents,
    linked_section_decisions,
    linked_section_streams
))]

mod common;
mod e2e_support;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use e2e_support::{
    bearer, chat_answer, send, streams_section, Reply, Scripted, ADMISSION_STATUSES,
};

/// The operator's token, and its SHA-256 as the admin-tokens plugin's settings state it (the
/// pair `mcp_open_front_door.rs` boots with).
const ADMIN_TOKEN: &str = "front-door-test-admin-token";
const ADMIN_TOKEN_SHA256: &str = "d321b271cf1b9bdf54eb40c5011b7168a5e8ccb42cb18a60bbc0697fed3e6d84";

/// What the anonymous caller is granted: the pool `e2e`, one agent and one MCP server. The two
/// plane kinds are stated by the a2a and mcp images' routes (`agent`, `mcp_server`).
const BINDING: &str =
    "{ allowed_pools: [e2e], allowed_agents: [conformance-agent], allowed_mcp_servers: [github] }";

struct Node {
    child: std::process::Child,
    dir: PathBuf,
    data: u16,
    admin: u16,
    log: PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!("--- the node's log:\n{}", self.log());
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Node {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

fn fixture_dir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-anonymous-profile-{tag}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos()),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("the deployment's directory");
    dir
}

/// The anonymous deployment: one OpenAI provider at `upstream`, the model `test-model`, the pools
/// `e2e` (granted) and `other` (not granted), the streaming plane, and `binding` as the anonymous
/// caller's grant.
fn write_config(dir: &Path, data: u16, admin: u16, upstream: &Scripted, binding: &str) -> PathBuf {
    std::fs::write(
        dir.join("providers.yaml"),
        format!(
            "mock:\n  protocol: openai\n  base_url: \"{}\"\n  error_map: {{}}\n",
            upstream.url("")
        ),
    )
    .expect("write providers.yaml");
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        format!(
            r#"listen: "127.0.0.1:{data}"
admin_listen: "127.0.0.1:{admin}"
listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test node" }}
admin_listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test node" }}
admin_require_mtls: false
store: {{module: memory}}
public_url: "http://127.0.0.1:{data}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    settings: {{ sha256: "{ADMIN_TOKEN_SHA256}" }}
auth:
  chain: [anonymous]
  admin_auth: [admin-tokens]
  role_bindings:
    anonymous:
      "*": {binding}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
pools:
  e2e:
    members:
      - {{ model: test-model }}
  other:
    members:
      - {{ model: test-model }}
# The upstream is plaintext loopback: only the llm plane's own audited acceptance admits that dial.
llm:
  insecure_transport: {{ accept: plaintext, reason: "loopback test upstream" }}
{streams}"#,
            streams = streams_section(""),
        ),
    )
    .expect("write config.yaml");
    path
}

fn busbar(config: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(common::boot::exe());
    command
        .args(args)
        .env("BUSBAR_CONFIG", config)
        .env_remove("BUSBAR_PROVIDERS")
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("MOCK_KEY", "k")
        .env("RUST_LOG", "info");
    command
}

fn boot(tag: &str, upstream: &Scripted) -> Node {
    let dir = fixture_dir(tag);
    let data = common::boot::free_port();
    let admin = common::boot::free_port();
    let config = write_config(&dir, data, admin, upstream, BINDING);
    let log = dir.join("node.log");
    let out = std::fs::File::create(&log).expect("the node's log");
    let child = busbar(&config, &[])
        .stdin(Stdio::null())
        .stdout(out.try_clone().expect("the node's log, twice"))
        .stderr(out)
        .spawn()
        .expect("spawn busbar");
    let mut node = Node {
        child,
        dir,
        data,
        admin,
        log,
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = node.child.try_wait().expect("try_wait") {
            panic!(
                "the anonymous profile did not boot ({status:?}):\n{}",
                node.log()
            );
        }
        if common::boot::log_shows_data_and_admin_listening(&node.log())
            && common::boot::healthz_answers(node.data)
        {
            return node;
        }
        assert!(Instant::now() < deadline, "busbar never served");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn chat(port: u16, pool: &str) -> Reply {
    let body = format!(r#"{{"model":"{pool}","messages":[{{"role":"user","content":"hi"}}]}}"#);
    send(
        port,
        "POST",
        "/v1/chat/completions",
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    )
}

fn refused(reply: &Reply) -> bool {
    ADMISSION_STATUSES.contains(&reply.status)
}

#[test]
fn anonymous_profile_boots_and_serves_only_what_its_binding_names() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let node = boot("serve", &upstream);

    // The bound pool is served to a caller that presents nothing.
    let served = chat(node.data, "e2e");
    assert_eq!(
        served.status,
        200,
        "the pool the anonymous binding names is served: {}",
        served.text()
    );
    assert_eq!(
        upstream.posts(""),
        1,
        "the bound request reached its provider"
    );

    // A pool the binding does not name is refused, and never reaches the provider.
    let other = chat(node.data, "other");
    assert!(
        refused(&other),
        "a pool the anonymous binding does not name is refused: {} {}",
        other.status,
        other.text()
    );

    // A plane the binding grants nothing of is refused.
    let streaming = send(
        node.data,
        "POST",
        "/v1/realtime/client_secrets",
        &[("Content-Type", "application/json")],
        br#"{"session":{"type":"realtime","model":"test-model"}}"#,
    );
    assert!(
        refused(&streaming),
        "a plane the anonymous binding grants nothing of is refused: {} {}",
        streaming.status,
        streaming.text()
    );

    // The MCP session keeps state per caller: it is never served to the subject every anonymous
    // caller shares, whatever the binding grants.
    let mcp = send(
        node.data,
        "POST",
        "/mcp",
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
        ],
        br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
    );
    assert!(
        refused(&mcp),
        "a per-caller session is not served to the shared anonymous subject: {} {}",
        mcp.status,
        mcp.text()
    );
    assert_eq!(
        upstream.posts(""),
        1,
        "nothing the binding does not name reached a provider"
    );

    // The admin API never admits a caller that presents no credential, on either listener.
    for port in [node.admin, node.data] {
        let admin = send(port, "GET", "/api/v1/admin/keys", &[], &[]);
        assert!(
            refused(&admin),
            "the admin API refuses an anonymous caller on port {port}: {} {}",
            admin.status,
            admin.text()
        );
    }
    let foreign = bearer("not-the-operator-token");
    let admin = send(
        node.admin,
        "GET",
        "/api/v1/admin/keys",
        &[("Authorization", foreign.as_str())],
        &[],
    );
    assert!(
        refused(&admin),
        "the admin API refuses a credential it did not issue: {} {}",
        admin.status,
        admin.text()
    );

    // The operator still reaches it.
    let operator = bearer(ADMIN_TOKEN);
    let admin = send(
        node.admin,
        "GET",
        "/api/v1/admin/keys",
        &[("Authorization", operator.as_str())],
        &[],
    );
    assert_eq!(
        admin.status,
        200,
        "the operator reads keys: {}",
        admin.text()
    );
}

#[test]
fn anonymous_profile_binding_of_a_kind_no_loaded_plane_states_is_refused() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let validate = |tag: &str, binding: &str| {
        let dir = fixture_dir(tag);
        let config = write_config(
            &dir,
            common::boot::free_port(),
            common::boot::free_port(),
            &upstream,
            binding,
        );
        let out = busbar(&config, &["--validate"])
            .output()
            .expect("run busbar --validate");
        let _ = std::fs::remove_dir_all(&dir);
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };

    // The kinds the loaded a2a and mcp images state are grantable before any plane mounts (the
    // boot test above serves this binding). `--validate` judges role bindings before it judges
    // secret references, so no binding refusal is what it says of them here.
    let (_, text) = validate("declared", BINDING);
    assert!(
        !text.contains("BUSBAR-3114"),
        "a binding of kinds the loaded planes state is not refused:\n{text}"
    );

    // `allowed_tools` grants the kind `tool`, which no loaded plane states: refused, naming it.
    let (code, text) = validate(
        "undeclared",
        "{ allowed_pools: [e2e], allowed_tools: [search] }",
    );
    assert_ne!(
        code,
        Some(0),
        "a kind no loaded plane states is refused:\n{text}"
    );
    assert!(
        text.contains("allowed_tools") && text.contains("BUSBAR-3114"),
        "the refusal names the field and its code:\n{text}"
    );
}
