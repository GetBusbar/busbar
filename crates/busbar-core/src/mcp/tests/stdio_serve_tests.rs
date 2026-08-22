// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STDIO SERVE MODE, judged from the CLIENT'S SIDE OF THE PIPES — the coverage instruments for
//! the `mcp|stdio|server|*` family.
//!
//! Every test here drives [`crate::mcp::stdio_serve::serve_io`] — the same loop `busbar
//! --mcp-stdio` runs on the process's real stdin/stdout — over an in-memory duplex, against a REAL
//! `App` built by `TestApp`, a REAL fake upstream peer, and (where the subject is governance) a
//! REAL `GovState` with a minted key in a budget-capped group. Assertions read what a CLIENT
//! receives on the channel, never internal state: the whole claim of the serve mode is that a
//! local client gets the same MCP server the HTTP door serves, so the client's view is the only
//! honest instrument.
//!
//! The end-to-end companion — the REAL child process, spawned binary, environment credential,
//! process exit codes — is `crates/busbar/tests/mcp_stdio_serve.rs`. The split is deliberate: a
//! spawned binary cannot carry an in-process governed fixture, and an in-process fixture cannot
//! prove an exit code.

use crate::mcp::connect::connect_support::{
    approved_hash, gov_with_key, mcp_cfg, server_cfg, wire_tool, Peer,
};
use crate::mcp::envelope::{META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION, PROTOCOL_VERSION};
use crate::mcp::stdio_serve::SessionIdentity;
use crate::test_support::TestApp;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

const TOOL: &str = "probe";
const NAMESPACED: &str = "ws_probe";
const DESCRIPTION: &str = "probes the workspace";
const RESOURCE_URI: &str = "docs://guide";

fn schema() -> serde_json::Value {
    serde_json::json!({ "type": "object", "properties": { "path": { "type": "string" } } })
}

/// One well-formed modern request: `params._meta` carries the revision and the full capability
/// declaration, exactly as a conformant client of `2026-07-28` sends on every transport.
fn frame(
    id: impl Into<serde_json::Value>,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let mut params = match params {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    params.insert(
        "_meta".into(),
        serde_json::json!({
            META_PROTOCOL_VERSION: PROTOCOL_VERSION,
            META_CLIENT_CAPABILITIES: {
                "sampling": {}, "elicitation": {}, "roots": { "listChanged": true },
            },
        }),
    );
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.into(),
        "method": method,
        "params": serde_json::Value::Object(params),
    })
}

/// THE CLIENT'S SIDE OF THE PIPES.
struct Client {
    stdin: tokio::io::DuplexStream,
    stdout: tokio::io::BufReader<tokio::io::DuplexStream>,
    serve: tokio::task::JoinHandle<()>,
    /// The live session — held so the seam-level instruments (the task watcher) can attach to it
    /// exactly as `deliver` does.
    session: Arc<super::Session<tokio::io::DuplexStream>>,
}

impl Client {
    /// Boot a session over duplex pipes, as the given identity.
    fn open(app: Arc<crate::state::App>, gov: crate::governance::GovCtx) -> Self {
        let handle = Arc::new(crate::state::AppHandle::new(app));
        Self::open_on(handle, gov)
    }

    /// The same, on a caller-held handle — for the tests that swap a second `App` mid-session.
    fn open_on(handle: Arc<crate::state::AppHandle>, gov: crate::governance::GovCtx) -> Self {
        let (stdin_client, stdin_server) = tokio::io::duplex(1 << 16);
        let (stdout_server, stdout_client) = tokio::io::duplex(1 << 16);
        let identity = SessionIdentity {
            principal: crate::auth::AuthPrincipal(None),
            gov,
        };
        let session = super::new_session(handle, identity, stdout_server);
        let serve = tokio::spawn(super::run_session(session.clone(), stdin_server));
        Client {
            stdin: stdin_client,
            stdout: tokio::io::BufReader::new(stdout_client),
            serve,
            session,
        }
    }

    async fn send(&mut self, value: &serde_json::Value) {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        self.stdin.write_all(&bytes).await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    /// The next frame the server wrote, bounded. Every line MUST parse as one JSON-RPC message —
    /// that is `STDIO.STDOUT-ONLY-MCP` and `STDIO.NO-EMBEDDED-NEWLINES` asserted on every read.
    async fn recv(&mut self) -> serde_json::Value {
        let mut line = String::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.stdout.read_line(&mut line),
        )
        .await
        .expect("the server must answer within the bound")
        .expect("the channel must stay readable");
        assert!(read > 0, "the server closed its stdout mid-conversation");
        serde_json::from_str(line.trim_end()).unwrap_or_else(|e| {
            panic!("every line on stdout must be one JSON-RPC message ({e}): {line:?}")
        })
    }

    /// Assert NOTHING arrives for `ms` — the instrument for "a notification is not answered" and
    /// "a cancelled request sends no further messages".
    async fn expect_quiet(&mut self, ms: u64) {
        let mut line = String::new();
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(ms),
            self.stdout.read_line(&mut line),
        )
        .await;
        assert!(
            got.is_err(),
            "expected silence on the channel, got: {line:?}"
        );
    }

    /// Close stdin — the client half of the shutdown sequence — and wait for the loop to end.
    async fn eof(self) {
        drop(self.stdin);
        tokio::time::timeout(std::time::Duration::from_secs(5), self.serve)
            .await
            .expect("EOF on stdin must end the serve loop promptly")
            .expect("the serve loop must end cleanly, not by panic");
    }
}

/// A deployment fronting one approved tool and one operator-declared resource, ungoverned.
async fn plain_deployment() -> (Peer, Arc<crate::state::App>) {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool(TOOL, DESCRIPTION, schema())]).await;
    let mut cfg = server_cfg(
        &peer,
        &[(TOOL, Some(approved_hash(TOOL, DESCRIPTION, schema())))],
    );
    let entry = cfg.tools_allow.get_mut(TOOL).unwrap();
    entry.description = Some(DESCRIPTION.to_string());
    entry.input_schema = Some(schema());
    cfg.resources_allow.insert(
        RESOURCE_URI.to_string(),
        crate::mcp::config::ResourceAllowCfg {
            name: Some("guide".to_string()),
            description: None,
            mime_type: Some("text/plain".to_string()),
            text: Some("original text".to_string()),
            blob: None,
        },
    );
    let app = TestApp::new().mcp(&mcp_cfg()).mcp_server("ws", cfg).build();
    (peer, app)
}

// ═══ THE CLIENT-DIRECTION METHODS: the same table, the same answers, this transport ═════════════

/// `server/discover`, `tools/list` and `tools/call` through the stdio binding: one pathway, the
/// HTTP method table, answers on stdout correlated by the caller's own ids — and the upstream's
/// own counter proving the call genuinely dispatched.
#[tokio::test]
async fn the_http_method_table_serves_the_stdio_channel_unchanged() {
    let (peer, app) = plain_deployment().await;
    let mut client = Client::open(app, crate::governance::GovCtx::default());

    client
        .send(&frame(1, "server/discover", serde_json::json!({})))
        .await;
    let discover = client.recv().await;
    assert_eq!(discover["id"], 1, "{discover}");
    assert!(
        discover.pointer("/result/supportedVersions").is_some(),
        "a modern discover result: {discover}"
    );

    client
        .send(&frame(2, "tools/list", serde_json::json!({})))
        .await;
    let list = client.recv().await;
    assert_eq!(
        list.pointer("/result/tools/0/name")
            .and_then(|v| v.as_str()),
        Some(NAMESPACED),
        "{list}"
    );

    client
        .send(&frame(
            3,
            "tools/call",
            serde_json::json!({ "name": NAMESPACED, "arguments": { "path": "src" } }),
        ))
        .await;
    let call = client.recv().await;
    assert_eq!(call["id"], 3, "{call}");
    assert_eq!(
        call.pointer("/result/content/0/text")
            .and_then(|v| v.as_str()),
        Some("UPSTREAM RESULT"),
        "{call}"
    );
    assert_eq!(peer.calls(), 1, "the call must have reached the upstream");

    // AND THE REFUSALS ARE THE SAME REFUSALS. A request with no `_meta` earns the identical
    // `-32602` the HTTP door answers — the body defect is not converted into a transport defect.
    client
        .send(&serde_json::json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}
        }))
        .await;
    let bare = client.recv().await;
    assert_eq!(
        bare.pointer("/error/code").and_then(|v| v.as_i64()),
        Some(-32602),
        "{bare}"
    );

    // A method the vocabulary does not carry is `-32601`, from the shared core arm.
    client
        .send(&frame(5, "no/such", serde_json::json!({})))
        .await;
    let missing = client.recv().await;
    assert_eq!(
        missing.pointer("/error/code").and_then(|v| v.as_i64()),
        Some(-32601),
        "{missing}"
    );

    client.eof().await;
}

/// `initialize` (the stdio dual-era trigger), `notifications/initialized` (accepted, never
/// answered), `ping`, and EOF shutdown — the session verbs of a transport that has a session.
#[tokio::test]
async fn initialize_negotiates_the_one_revision_and_eof_ends_the_session() {
    let (_peer, app) = plain_deployment().await;
    let mut client = Client::open(app, crate::governance::GovCtx::default());

    // A LEGACY-era opening: no `_meta` at all, exactly what an installed stdio client sends first.
    client
        .send(&serde_json::json!({
            "jsonrpc": "2.0", "id": "init-1", "method": "initialize",
            "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } }
        }))
        .await;
    let init = client.recv().await;
    assert_eq!(init["id"], "init-1", "{init}");
    assert_eq!(
        init.pointer("/result/protocolVersion")
            .and_then(|v| v.as_str()),
        Some(PROTOCOL_VERSION),
        "the negotiation names the one revision this server speaks: {init}"
    );

    // The acknowledgement is a NOTIFICATION: accepted, and answered by NOTHING.
    client
        .send(&serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await;
    client.expect_quiet(300).await;

    // `ping` — liveness on a transport where the session is real.
    client
        .send(&frame("p1", "ping", serde_json::json!({})))
        .await;
    let pong = client.recv().await;
    assert_eq!(pong["id"], "p1", "{pong}");
    assert!(pong.get("result").is_some(), "{pong}");

    client.eof().await;
}

/// `logging/setLevel` sets a SESSION floor and the records become observable on the channel:
/// after it, an ordinary request's handling arrives as `notifications/message` lines AHEAD of the
/// response — and before it, the same request produces no records at all.
#[tokio::test]
async fn logging_set_level_makes_the_sessions_records_ride_the_channel() {
    let (_peer, app) = plain_deployment().await;
    let mut client = Client::open(app, crate::governance::GovCtx::default());

    // BEFORE: no level anywhere, a single response line and nothing else.
    client
        .send(&frame(1, "tools/list", serde_json::json!({})))
        .await;
    let only = client.recv().await;
    assert_eq!(only["id"], 1, "{only}");
    client.expect_quiet(200).await;

    client
        .send(&frame(
            2,
            "logging/setLevel",
            serde_json::json!({ "level": "debug" }),
        ))
        .await;
    let ok = client.recv().await;
    assert_eq!(ok["id"], 2, "{ok}");
    assert!(ok.get("result").is_some(), "{ok}");

    // AFTER: the same request now arrives with its records first, response last.
    client
        .send(&frame(3, "tools/list", serde_json::json!({})))
        .await;
    let mut messages = 0;
    loop {
        let line = client.recv().await;
        if line.get("method").and_then(|m| m.as_str()) == Some("notifications/message") {
            messages += 1;
            continue;
        }
        assert_eq!(line["id"], 3, "the response ends the sequence: {line}");
        break;
    }
    assert!(
        messages >= 1,
        "the session level must make busbar's own records observable on the channel"
    );

    client.eof().await;
}

/// `notifications/cancelled` aborts the in-flight dispatch and SUPPRESSES its answer
/// (`CANCEL.NO-FURTHER-MESSAGES`) — and the session keeps serving afterwards.
#[tokio::test]
async fn a_cancelled_request_is_aborted_and_never_answered() {
    crate::metrics::init();
    // A deployment whose one tool ASKS the caller first: the dispatch parks on the live ask, which
    // is the honest way to hold a request in flight long enough to cancel it.
    let peer = Peer::start(vec![wire_tool(TOOL, DESCRIPTION, schema())]).await;
    let mut cfg = server_cfg(
        &peer,
        &[(TOOL, Some(approved_hash(TOOL, DESCRIPTION, schema())))],
    );
    {
        let entry = cfg.tools_allow.get_mut(TOOL).unwrap();
        entry.description = Some(DESCRIPTION.to_string());
        entry.input_schema = Some(schema());
        let mut round = crate::mcp::config::AskRoundCfg::new();
        round.insert(
            "confirm".to_string(),
            crate::mcp::config::AskEntryCfg {
                method: "elicitation/create".to_string(),
                params: Some(serde_json::json!({
                    "message": "Proceed?",
                    "requestedSchema": { "type": "object", "properties": { "ok": { "type": "boolean" } } },
                })),
            },
        );
        entry.ask_caller = vec![round];
    }
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("ws", cfg)
        .governance(signing_governance())
        .build();
    let gov = gov_with_key(
        "vk_cancel",
        &[("mcp_server", "ws"), ("mcp_tool", NAMESPACED)],
    );
    let mut client = Client::open(app, gov);

    client
        .send(&frame(
            "call-1",
            "tools/call",
            serde_json::json!({ "name": NAMESPACED, "arguments": { "path": "src" } }),
        ))
        .await;
    // The live ask arrives as a REAL request busbar originated.
    let ask = client.recv().await;
    assert_eq!(
        ask.get("method").and_then(|m| m.as_str()),
        Some("elicitation/create"),
        "{ask}"
    );

    // The caller cancels ITS request instead of answering the ask.
    client
        .send(&serde_json::json!({
            "jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": { "requestId": "call-1", "reason": "the user closed the panel" },
        }))
        .await;
    client.expect_quiet(500).await;
    assert_eq!(
        peer.calls(),
        0,
        "a cancelled call must never reach the upstream"
    );

    // The session is undamaged: the next request is served.
    client
        .send(&frame("p", "ping", serde_json::json!({})))
        .await;
    let pong = client.recv().await;
    assert_eq!(pong["id"], "p", "{pong}");

    client.eof().await;
}

fn signing_governance() -> Arc<crate::governance::GovState> {
    Arc::new(
        crate::governance::GovState::new_with_signer(
            Arc::new(crate::governance::MemoryStore::new()),
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[7u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .expect("a governance state with a signer"),
    )
}

// ═══ THE SERVER DIRECTION: the asks and the notifications the channel makes real ════════════════

/// THE LIVE MRTR EXCHANGE: an operator-configured ask is issued as a real `elicitation/create`
/// REQUEST on the channel, the client's response becomes `inputResponses`, the sealed
/// `requestState` is redeemed through the full dispatch sequence, and the caller's ORIGINAL id
/// gets the finished result — with the upstream contacted exactly once, after the answer.
#[tokio::test]
async fn a_caller_ask_is_driven_live_over_the_channel_and_the_call_completes() {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool(TOOL, DESCRIPTION, schema())]).await;
    let mut cfg = server_cfg(
        &peer,
        &[(TOOL, Some(approved_hash(TOOL, DESCRIPTION, schema())))],
    );
    {
        let entry = cfg.tools_allow.get_mut(TOOL).unwrap();
        entry.description = Some(DESCRIPTION.to_string());
        entry.input_schema = Some(schema());
        let mut round = crate::mcp::config::AskRoundCfg::new();
        round.insert(
            "confirm".to_string(),
            crate::mcp::config::AskEntryCfg {
                method: "elicitation/create".to_string(),
                params: Some(serde_json::json!({
                    "message": "Proceed?",
                    "requestedSchema": { "type": "object", "properties": { "ok": { "type": "boolean" } } },
                })),
            },
        );
        entry.ask_caller = vec![round];
    }
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("ws", cfg)
        .governance(signing_governance())
        .build();
    let gov = gov_with_key("vk_ask", &[("mcp_server", "ws"), ("mcp_tool", NAMESPACED)]);
    let mut client = Client::open(app, gov);

    client
        .send(&frame(
            "call-9",
            "tools/call",
            serde_json::json!({ "name": NAMESPACED, "arguments": { "path": "src" } }),
        ))
        .await;

    let ask = client.recv().await;
    assert_eq!(
        ask.get("method").and_then(|m| m.as_str()),
        Some("elicitation/create"),
        "the ask travels as a REAL request on this transport: {ask}"
    );
    assert_eq!(
        ask.pointer("/params/message").and_then(|v| v.as_str()),
        Some("Proceed?"),
        "the operator's text, verbatim: {ask}"
    );
    assert_eq!(
        peer.calls(),
        0,
        "nothing reaches the upstream before the answer"
    );

    // ANSWER the ask, as a response correlated to busbar's own id.
    client
        .send(&serde_json::json!({
            "jsonrpc": "2.0", "id": ask["id"],
            "result": { "action": "accept", "content": { "ok": true } },
        }))
        .await;

    let done = client.recv().await;
    assert_eq!(
        done["id"], "call-9",
        "the finished result belongs to the CALLER's id: {done}"
    );
    assert_eq!(
        done.pointer("/result/content/0/text")
            .and_then(|v| v.as_str()),
        Some("UPSTREAM RESULT"),
        "{done}"
    );
    assert_eq!(
        peer.calls(),
        1,
        "the redeemed exchange dispatched exactly once"
    );

    client.eof().await;
}

/// GOVERNANCE THROUGH THE PIPE: the same budget plane that meters an HTTP `tools/call` refuses the
/// call over budget on stdio — a key in a one-request group is served once and refused the second
/// time, with `budget_exhausted` named, and the refused call never contacts the upstream.
#[tokio::test]
async fn a_budgeted_key_is_refused_over_budget_through_the_stdio_binding() {
    use crate::governance::{GovState, MemoryStore};
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool(TOOL, DESCRIPTION, schema())]).await;
    let mut cfg = server_cfg(
        &peer,
        &[(TOOL, Some(approved_hash(TOOL, DESCRIPTION, schema())))],
    );
    {
        let entry = cfg.tools_allow.get_mut(TOOL).unwrap();
        entry.description = Some(DESCRIPTION.to_string());
        entry.input_schema = Some(schema());
    }
    let store = Arc::new(MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[3u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    let gov_state =
        Arc::new(GovState::new_with_signer(store, None, Some(signer)).expect("gov state"));
    let (key, _secret) = gov_state
        .mint_signed(
            crate::governance::NewKeySpec {
                name: "tiny-agent".to_string(),
                allowed_pools: None,
                group: Some("tiny".to_string()),
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .expect("a minted key");
    let tiny: crate::config::GroupCfg =
        serde_yaml::from_str("limits:\n  - { requests: 1, per: hour }\n").expect("group parses");
    let mut groups = std::collections::BTreeMap::new();
    groups.insert("tiny".to_string(), tiny);
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("ws", cfg)
        .governance(gov_state)
        .groups_tree(groups)
        .build();
    let gov = crate::governance::GovCtx {
        key: Some(Arc::new(key)),
    };
    let mut client = Client::open(app, gov);

    // WITHIN BUDGET: served, and the upstream saw it.
    client
        .send(&frame(
            1,
            "tools/call",
            serde_json::json!({ "name": NAMESPACED, "arguments": { "path": "a" } }),
        ))
        .await;
    let first = client.recv().await;
    assert_eq!(first["id"], 1, "{first}");
    assert!(
        first.get("result").is_some(),
        "within budget must serve: {first}"
    );
    assert_eq!(peer.calls(), 1);

    // OVER BUDGET: refused, named, and the upstream never contacted.
    client
        .send(&frame(
            2,
            "tools/call",
            serde_json::json!({ "name": NAMESPACED, "arguments": { "path": "b" } }),
        ))
        .await;
    let second = client.recv().await;
    assert_eq!(second["id"], 2, "{second}");
    let message = second
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("over budget must be an error: {second}"));
    assert!(
        message.contains("budget"),
        "the refusal names the budget: {second}"
    );
    assert_eq!(
        peer.calls(),
        1,
        "the refused call must never reach the upstream"
    );

    client.eof().await;
}

/// THE SUBSCRIPTION CHANNEL ON STDIO: `subscriptions/listen` is acknowledged FIRST, a real
/// catalogue change (the production `AppHandle::swap` seam) arrives as a list-changed notification
/// line tagged with the subscription's id, and `resources/subscribe` makes a subscribed resource's
/// registration change arrive as `notifications/resources/updated`.
#[tokio::test]
async fn subscriptions_and_resource_watches_ride_the_channel() {
    let (_peer, app) = plain_deployment().await;
    let handle = Arc::new(crate::state::AppHandle::new(app));
    let mut client = Client::open_on(handle.clone(), crate::governance::GovCtx::default());

    client
        .send(&frame(
            "sub-1",
            "subscriptions/listen",
            serde_json::json!({ "notifications": { "toolsListChanged": true } }),
        ))
        .await;
    let ack = client.recv().await;
    assert_eq!(
        ack.get("method").and_then(|m| m.as_str()),
        Some("notifications/subscriptions/acknowledged"),
        "the acknowledgement is the FIRST message: {ack}"
    );
    assert!(
        ack.pointer("/params/_meta").is_some(),
        "the subscription id rides `_meta` on every frame: {ack}"
    );

    client
        .send(&frame(
            "sub-2",
            "resources/subscribe",
            serde_json::json!({ "uri": format!("ws_{RESOURCE_URI}") }),
        ))
        .await;
    let subscribed = client.recv().await;
    assert_eq!(subscribed["id"], "sub-2", "{subscribed}");
    assert!(subscribed.get("result").is_some(), "{subscribed}");

    // THE CHANGE, through the production mutation seam: a second App with a second tool and a
    // rewritten resource.
    let peer2 = Peer::start(vec![
        wire_tool(TOOL, DESCRIPTION, schema()),
        wire_tool("extra", "a second tool", schema()),
    ])
    .await;
    let mut cfg2 = server_cfg(
        &peer2,
        &[
            (TOOL, Some(approved_hash(TOOL, DESCRIPTION, schema()))),
            (
                "extra",
                Some(approved_hash("extra", "a second tool", schema())),
            ),
        ],
    );
    {
        let entry = cfg2.tools_allow.get_mut(TOOL).unwrap();
        entry.description = Some(DESCRIPTION.to_string());
        entry.input_schema = Some(schema());
    }
    cfg2.resources_allow.insert(
        RESOURCE_URI.to_string(),
        crate::mcp::config::ResourceAllowCfg {
            name: Some("guide".to_string()),
            description: None,
            mime_type: Some("text/plain".to_string()),
            text: Some("REWRITTEN text".to_string()),
            blob: None,
        },
    );
    let app2 = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("ws", cfg2)
        .build();
    handle.swap(app2);

    // Both consequences arrive, in whichever order the two watchers observe the swap.
    let mut saw_tools_changed = false;
    let mut saw_resource_updated = false;
    for _ in 0..2 {
        let line = client.recv().await;
        match line.get("method").and_then(|m| m.as_str()) {
            Some("notifications/tools/list_changed") => saw_tools_changed = true,
            Some("notifications/resources/updated") => {
                assert_eq!(
                    line.pointer("/params/uri").and_then(|v| v.as_str()),
                    Some(format!("ws_{RESOURCE_URI}").as_str()),
                    "{line}"
                );
                saw_resource_updated = true;
            }
            other => panic!("unexpected frame {other:?}: {line}"),
        }
    }
    assert!(
        saw_tools_changed,
        "the subscription must report the tool change"
    );
    assert!(
        saw_resource_updated,
        "the resource watch must report the rewrite"
    );

    client.eof().await;
}

/// EACH OF THE THREE ASKS busbar may make of its caller — `elicitation/create`, `roots/list`,
/// `sampling/createMessage` — is issued as its OWN live request on the channel, and the client's
/// answer redeems the exchange. One loop over the closed set `callerask` admits, so a fourth
/// method cannot be added to the transport without appearing in the filter first.
#[tokio::test]
async fn each_of_the_three_asks_is_issued_as_its_own_request() {
    crate::metrics::init();
    for (ask_method, params, answer) in [
        (
            "elicitation/create",
            serde_json::json!({ "message": "Proceed?", "requestedSchema": { "type": "object" } }),
            serde_json::json!({ "action": "accept", "content": { "ok": true } }),
        ),
        (
            "roots/list",
            serde_json::json!({}),
            serde_json::json!({ "roots": [{ "uri": "file:///home/user/project" }] }),
        ),
        (
            "sampling/createMessage",
            serde_json::json!({ "messages": [], "maxTokens": 8 }),
            serde_json::json!({ "role": "assistant", "content": { "type": "text", "text": "ok" },
                                 "model": "m", "stopReason": "endTurn" }),
        ),
    ] {
        let peer = Peer::start(vec![wire_tool(TOOL, DESCRIPTION, schema())]).await;
        let mut cfg = server_cfg(
            &peer,
            &[(TOOL, Some(approved_hash(TOOL, DESCRIPTION, schema())))],
        );
        {
            let entry = cfg.tools_allow.get_mut(TOOL).unwrap();
            entry.description = Some(DESCRIPTION.to_string());
            entry.input_schema = Some(schema());
            let mut round = crate::mcp::config::AskRoundCfg::new();
            round.insert(
                "ask".to_string(),
                crate::mcp::config::AskEntryCfg {
                    method: ask_method.to_string(),
                    params: Some(params),
                },
            );
            entry.ask_caller = vec![round];
        }
        let app = TestApp::new()
            .mcp(&mcp_cfg())
            .mcp_server("ws", cfg)
            .governance(signing_governance())
            .build();
        let gov = gov_with_key("vk_asks", &[("mcp_server", "ws"), ("mcp_tool", NAMESPACED)]);
        let mut client = Client::open(app, gov);
        client
            .send(&frame(
                "c",
                "tools/call",
                serde_json::json!({ "name": NAMESPACED, "arguments": { "path": "src" } }),
            ))
            .await;
        let ask = client.recv().await;
        assert_eq!(
            ask.get("method").and_then(|m| m.as_str()),
            Some(ask_method),
            "{ask}"
        );
        // A `notifications/progress` about the exchange is ACCEPTED SILENTLY mid-flight — the
        // client reporting on work busbar asked for — and disturbs nothing.
        client
            .send(&serde_json::json!({
                "jsonrpc": "2.0", "method": "notifications/progress",
                "params": { "progressToken": ask["id"], "progress": 0.5 },
            }))
            .await;
        client
            .send(&serde_json::json!({ "jsonrpc": "2.0", "id": ask["id"], "result": answer }))
            .await;
        let done = client.recv().await;
        assert_eq!(done["id"], "c", "{ask_method}: {done}");
        assert!(done.get("result").is_some(), "{ask_method}: {done}");
        assert_eq!(peer.calls(), 1, "{ask_method}: redeemed once");
        client.eof().await;
    }
}

/// SEP-1036's OUT-OF-BAND elicitation reply — refused over HTTP because nothing binds it, and
/// admissible here because the ONE authenticated single-caller channel is the binding: the
/// notification names the id of an elicitation busbar itself issued on this channel, and it
/// resolves the pending ask exactly as a direct response would.
#[tokio::test]
async fn an_out_of_band_elicitation_response_redeems_the_pending_ask() {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool(TOOL, DESCRIPTION, schema())]).await;
    let mut cfg = server_cfg(
        &peer,
        &[(TOOL, Some(approved_hash(TOOL, DESCRIPTION, schema())))],
    );
    {
        let entry = cfg.tools_allow.get_mut(TOOL).unwrap();
        entry.description = Some(DESCRIPTION.to_string());
        entry.input_schema = Some(schema());
        let mut round = crate::mcp::config::AskRoundCfg::new();
        round.insert(
            "confirm".to_string(),
            crate::mcp::config::AskEntryCfg {
                method: "elicitation/create".to_string(),
                params: Some(serde_json::json!({ "message": "Proceed?" })),
            },
        );
        entry.ask_caller = vec![round];
    }
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("ws", cfg)
        .governance(signing_governance())
        .build();
    let gov = gov_with_key("vk_oob", &[("mcp_server", "ws"), ("mcp_tool", NAMESPACED)]);
    let mut client = Client::open(app, gov);
    client
        .send(&frame(
            "c1",
            "tools/call",
            serde_json::json!({ "name": NAMESPACED, "arguments": { "path": "src" } }),
        ))
        .await;
    let ask = client.recv().await;
    assert_eq!(
        ask.get("method").and_then(|m| m.as_str()),
        Some("elicitation/create"),
        "{ask}"
    );
    client
        .send(&serde_json::json!({
            "jsonrpc": "2.0", "method": "notifications/elicitation/response",
            "params": {
                "requestId": ask["id"],
                "response": { "action": "accept", "content": { "ok": true } },
            },
        }))
        .await;
    let done = client.recv().await;
    assert_eq!(done["id"], "c1", "{done}");
    assert!(done.get("result").is_some(), "{done}");
    assert_eq!(peer.calls(), 1);
    client.eof().await;
}

/// `resources/unsubscribe` STOPS the updates: after it, the same registration change that fired a
/// notification before moves nothing on the channel.
#[tokio::test]
async fn unsubscribe_stops_the_resource_updates() {
    let (_peer, app) = plain_deployment().await;
    let handle = Arc::new(crate::state::AppHandle::new(app));
    let mut client = Client::open_on(handle.clone(), crate::governance::GovCtx::default());
    let uri = format!("ws_{RESOURCE_URI}");
    client
        .send(&frame(
            1,
            "resources/subscribe",
            serde_json::json!({ "uri": uri }),
        ))
        .await;
    let ok = client.recv().await;
    assert!(ok.get("result").is_some(), "{ok}");
    client
        .send(&frame(
            2,
            "resources/unsubscribe",
            serde_json::json!({ "uri": uri }),
        ))
        .await;
    let ok = client.recv().await;
    assert!(ok.get("result").is_some(), "{ok}");
    // The registration change that WOULD have notified.
    let peer2 = Peer::start(vec![wire_tool(TOOL, DESCRIPTION, schema())]).await;
    let mut cfg2 = server_cfg(
        &peer2,
        &[(TOOL, Some(approved_hash(TOOL, DESCRIPTION, schema())))],
    );
    cfg2.resources_allow.insert(
        RESOURCE_URI.to_string(),
        crate::mcp::config::ResourceAllowCfg {
            name: Some("guide".to_string()),
            description: None,
            mime_type: Some("text/plain".to_string()),
            text: Some("CHANGED".to_string()),
            blob: None,
        },
    );
    handle.swap(
        TestApp::new()
            .mcp(&mcp_cfg())
            .mcp_server("ws", cfg2)
            .build(),
    );
    client.expect_quiet(700).await;
    client.eof().await;
}

/// A SUBSCRIPTION CLOSED EARLY — the key revoked underneath it — is ANNOUNCED: the error close
/// arrives correlated to the listen request, and `notifications/cancelled` names it, because on
/// stdio there is no stream whose closure could carry the fact. The one purpose the revision
/// permits a server-originated cancellation for.
#[tokio::test]
async fn an_early_closed_subscription_is_announced_with_cancelled() {
    use crate::governance::{GovState, MemoryStore};
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[9u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    let gov_state =
        Arc::new(GovState::new_with_signer(store, None, Some(signer)).expect("gov state"));
    let (key, _secret) = gov_state
        .mint_signed(
            crate::governance::NewKeySpec {
                name: "sub-agent".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .expect("a minted key");
    let (_peer, app) = plain_deployment().await;
    // Rebind the fixture app onto the governed state so the stream's per-poll re-resolution reads
    // the registry the key lives in.
    let peer2 = Peer::start(vec![wire_tool(TOOL, DESCRIPTION, schema())]).await;
    let mut cfg = server_cfg(
        &peer2,
        &[(TOOL, Some(approved_hash(TOOL, DESCRIPTION, schema())))],
    );
    {
        let entry = cfg.tools_allow.get_mut(TOOL).unwrap();
        entry.description = Some(DESCRIPTION.to_string());
        entry.input_schema = Some(schema());
    }
    drop(app);
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("ws", cfg)
        .governance(gov_state.clone())
        .build();
    let sub_key = Arc::new(key);
    let gov = crate::governance::GovCtx {
        key: Some(sub_key.clone()),
    };
    let mut client = Client::open(app, gov);
    client
        .send(&frame(
            "sub-x",
            "subscriptions/listen",
            serde_json::json!({ "notifications": { "toolsListChanged": true } }),
        ))
        .await;
    let ack = client.recv().await;
    assert_eq!(
        ack.get("method").and_then(|m| m.as_str()),
        Some("notifications/subscriptions/acknowledged"),
        "{ack}"
    );
    gov_state
        .revoke(&sub_key.id, "test revocation")
        .expect("revoke");
    // The error close, correlated to the listen request; then the cancellation naming it.
    let close = client.recv().await;
    assert_eq!(close["id"], "sub-x", "{close}");
    assert!(
        close.get("error").is_some(),
        "a lapsed permission is a refusal: {close}"
    );
    let cancelled = client.recv().await;
    assert_eq!(
        cancelled.get("method").and_then(|m| m.as_str()),
        Some("notifications/cancelled"),
        "{cancelled}"
    );
    assert_eq!(
        cancelled.pointer("/params/requestId"),
        Some(&serde_json::json!("sub-x")),
        "{cancelled}"
    );
    client.eof().await;
}

/// A TASK'S TRANSITIONS ARE PUSHED: a session that was handed a `resultType: "task"` result gets
/// the registry's later status changes as `notifications/tasks` lines — the push the HTTP plane
/// records as impossible for want of a carrier, and the persistent channel simply has.
#[tokio::test]
async fn a_tasks_transition_is_pushed_over_the_channel() {
    // Driven at the seam the serve loop itself uses: a REAL registry task for this session's
    // principal, watched off a real task-result envelope, transitioned through the registry's own
    // verb. The tasks METHODS' behaviour is `tasks_tests.rs`' subject, not re-proven here.
    let (_peer, app) = plain_deployment().await;
    let mut client = Client::open(app, crate::governance::GovCtx::default());
    // The session's actor is `anonymous` (ungoverned fixture); create its task in the registry.
    let task = crate::mcp::tasks::TASKS.create("anonymous");
    // Attach the watcher exactly as `deliver` does when it hands the caller a task result.
    client.session.watch_task_result(&serde_json::json!({
        "jsonrpc": "2.0", "id": "t0",
        "result": { "resultType": "task", "taskId": task.id, "status": "submitted" },
    }));
    crate::mcp::tasks::TASKS
        .cancel(&task.id, "anonymous")
        .expect("cancel the task");
    let pushed = client.recv().await;
    assert_eq!(
        pushed.get("method").and_then(|m| m.as_str()),
        Some("notifications/tasks"),
        "{pushed}"
    );
    assert_eq!(
        pushed.pointer("/params/status").and_then(|v| v.as_str()),
        Some("cancelled"),
        "{pushed}"
    );
    client.eof().await;
}

/// THE KEEPALIVE OF AN IDLE SUBSCRIPTION BECOMES A SERVER→CLIENT `ping`. Driven at the seam the
/// serve loop itself uses — a real stream delivery carrying the SSE comment the subscription
/// writes at its keepalive interval — because waiting out the real fifteen-second idle interval
/// would make this battery a clock test. The comment is the stream's liveness statement, and the
/// ping is the only vocabulary this framing has for one; the client's pong resolves it.
#[tokio::test]
async fn an_idle_subscriptions_keepalive_becomes_a_server_ping() {
    let (_peer, app) = plain_deployment().await;
    let mut client = Client::open(app, crate::governance::GovCtx::default());
    let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/subscriptions/acknowledged\",\"params\":{\"_meta\":{}}}\n\n: keepalive\n\n";
    let response = axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("content-type", "text/event-stream")
        .body(axum::body::Body::from(body))
        .unwrap();
    let session = client.session.clone();
    tokio::spawn(async move {
        session
            .deliver(Some(serde_json::json!("sub-k")), Vec::new(), response, 0)
            .await;
    });
    let ack = client.recv().await;
    assert_eq!(
        ack.get("method").and_then(|m| m.as_str()),
        Some("notifications/subscriptions/acknowledged"),
        "{ack}"
    );
    // Two more frames arrive in whichever order the two tasks won: the ping the keepalive became,
    // and — because this synthetic stream then ENDS without its graceful result — the
    // `notifications/cancelled` an early close is announced with.
    let (a, b) = (client.recv().await, client.recv().await);
    let ping = [&a, &b]
        .into_iter()
        .find(|f| f.get("method").and_then(|m| m.as_str()) == Some("ping"))
        .unwrap_or_else(|| panic!("one frame is the keepalive's ping: {a} / {b}"))
        .clone();
    assert!(
        [&a, &b]
            .into_iter()
            .any(|f| f.get("method").and_then(|m| m.as_str()) == Some("notifications/cancelled")),
        "the early close is announced: {a} / {b}"
    );
    assert!(
        ping.get("id").is_some(),
        "a ping is a REQUEST the client answers: {ping}"
    );
    // The pong is consumed by the session's reply router and answered by nothing further.
    client
        .send(&serde_json::json!({ "jsonrpc": "2.0", "id": ping["id"], "result": {} }))
        .await;
    client.expect_quiet(300).await;
    client.eof().await;
}
