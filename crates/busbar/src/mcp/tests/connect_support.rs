// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A REAL fake MCP peer whose TOOL LIST CAN CHANGE UNDER A LIVE CACHE.
//!
//! That mutability is the whole reason this fixture exists rather than the upstream leg's. A
//! rug-pull is not "a tool list that is wrong"; it is a tool list that WAS right, was approved, and
//! then changed. Proving the defence therefore needs the same running endpoint to answer one thing,
//! be approved for it, and then answer another — which a fixed fixture cannot express.
//!
//! It serves both methods on one route, exactly as a real MCP server does: `tools/list` from the
//! swappable list, and `tools/call` with a fixed result. Serving both from one endpoint matters,
//! because the property under test spans them — the list is what gets hashed, and the call is what
//! must then be refused.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use std::sync::{Arc, Mutex};

/// The capabilities a handler-level test declares on the caller's behalf.
///
/// ALL THREE, deliberately. These tests are asserting on something else — the grant matrix, the
/// envelope, the upstream leg — and a narrower declaration would silently change what the
/// caller-ask capability filter admits, turning an unrelated test red for a reason that is about
/// this constant. The filter has its own tests, in `callerask_tests.rs`, which declare narrowly on
/// purpose.
/// NO CUSTOM `Mcp-Param-*` HEADERS. Every `Ctx` built here drives a method directly rather than
/// through the HTTP ingress, so there is no header map to inherit and an empty one is the honest
/// stand-in. The SEP-2243 custom-param validation this field feeds is a header/body agreement
/// check: with no headers and no annotated tool it has nothing to compare and correctly passes.
static NO_HEADERS: std::sync::LazyLock<axum::http::HeaderMap> =
    std::sync::LazyLock::new(axum::http::HeaderMap::new);

static ALL_CAPABILITIES: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(
    || serde_json::json!({ "sampling": {}, "elicitation": {}, "roots": { "listChanged": true } }),
);

/// What the peer currently offers, and what it has been asked.
#[derive(Debug, Default)]
pub(crate) struct PeerState {
    /// The `tools` array `tools/list` answers with. Swapped by the test mid-flight.
    pub(super) tools: Vec<serde_json::Value>,
    /// Methods received, in order. Read to prove a refused dispatch never reached the wire.
    pub(super) methods: Vec<String>,
    /// The `params.arguments` of every `tools/call` that reached this peer, in order.
    ///
    /// Recorded because "the call carried out after an approval is the call the question was about"
    /// is a claim about WHAT THE UPSTREAM WAS TOLD TO DO, and no assertion about busbar's own return
    /// value can make it. The peer's own bookkeeping is the only witness that is not the accused.
    pub(super) call_arguments: Vec<serde_json::Value>,
    /// When set, `tools/list` answers with this JSON-RPC error code instead of a result.
    pub(super) list_error: Option<i64>,
}

#[derive(Clone)]
struct Shared(Arc<Mutex<PeerState>>);

/// A running fake peer. Dropping it aborts the server task.
pub(crate) struct Peer {
    pub(crate) base: String,
    state: Arc<Mutex<PeerState>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Peer {
    /// Start a peer offering `tools`.
    pub(crate) async fn start(tools: Vec<serde_json::Value>) -> Self {
        let state = Arc::new(Mutex::new(PeerState {
            tools,
            ..PeerState::default()
        }));
        let router = axum::Router::new()
            .route("/mcp", post(endpoint))
            .with_state(Shared(state.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Peer {
            base: format!("http://{addr}"),
            state,
            task,
        }
    }

    pub(crate) fn mcp_url(&self) -> String {
        format!("{}/mcp", self.base)
    }

    /// THE RUG-PULL: replace what this endpoint offers, under a cache that already approved the old
    /// answer.
    pub(crate) fn reserve(&self, tools: Vec<serde_json::Value>) {
        self.state.lock().unwrap().tools = tools;
    }

    /// Make `tools/list` answer a JSON-RPC error.
    pub(crate) fn fail_list(&self, code: i64) {
        self.state.lock().unwrap().list_error = Some(code);
    }

    /// Every method this peer was asked, in order.
    pub(crate) fn methods(&self) -> Vec<String> {
        self.state.lock().unwrap().methods.clone()
    }

    /// How many `tools/call` requests reached the wire. The load-bearing number for "a refused
    /// dispatch never contacted the upstream": read from the PEER's own bookkeeping, never inferred
    /// from busbar's status code.
    pub(crate) fn calls(&self) -> usize {
        self.methods().iter().filter(|m| *m == "tools/call").count()
    }

    /// The arguments of every `tools/call` this peer was actually told to run, in order.
    pub(crate) fn call_arguments(&self) -> Vec<serde_json::Value> {
        self.state.lock().unwrap().call_arguments.clone()
    }

    /// How many `tools/list` requests reached the wire — i.e. how many times this peer was actually
    /// REFRESHED. The load-bearing number for "the refresh timer honours the operator's cadence":
    /// a sweep that ignored `refresh_ttl:` would contact every registered upstream on every tick,
    /// and no assertion about busbar's own return value could tell you that it had.
    pub(crate) fn list_calls(&self) -> usize {
        self.methods().iter().filter(|m| *m == "tools/list").count()
    }
}

async fn endpoint(
    State(shared): State<Shared>,
    _headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let id = parsed.get("id").cloned().unwrap_or(serde_json::json!(0));
    let method = parsed
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string();
    let (tools, list_error) = {
        let mut st = shared.0.lock().unwrap();
        st.methods.push(method.clone());
        if method == "tools/call" {
            st.call_arguments.push(
                parsed
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            );
        }
        (st.tools.clone(), st.list_error)
    };
    let value = match method.as_str() {
        "tools/list" => match list_error {
            Some(code) => serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": code, "message": "the upstream declined to list" },
            }),
            None => serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "tools": tools },
            }),
        },
        "tools/call" => serde_json::json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "content": [{ "type": "text", "text": "UPSTREAM RESULT" }] },
        }),
        other => serde_json::json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32601, "message": format!("no such method `{other}`") },
        }),
    };
    axum::Json(value)
}

/// One `tools/list` entry, as an upstream serves it.
pub(crate) fn wire_tool(
    name: &str,
    description: &str,
    schema: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({ "name": name, "description": description, "inputSchema": schema })
}

/// The digest busbar will compute for that same entry — the value an operator writes into
/// `schema_hash:` when they approve it.
///
/// Derived through the SAME function the observation path uses, deliberately. A test that hard-coded
/// the hex would pass while the digest function changed underneath it, which is the one thing this
/// battery must not do.
pub(crate) fn approved_hash(name: &str, description: &str, schema: serde_json::Value) -> String {
    crate::mcp::client::catalogue::tool_digest(&crate::mcp::client::catalogue::ToolDef {
        name: name.to_string(),
        description: description.to_string(),
        input_schema: schema,
    })
}

/// A registration pointing at `peer`, approving exactly `tools_allow`.
///
/// No token exchange and no passthrough: the credential posture is not what this battery is about,
/// and an exchange would put a second endpoint between the test and the property.
pub(crate) fn server_cfg(
    peer: &Peer,
    tools_allow: &[(&str, Option<String>)],
) -> crate::mcp::config::McpServerDefCfg {
    use crate::mcp::config::{McpPinMechanism, McpServerDefCfg, ServerPinCfg, ToolAllowCfg};
    let mut allow = indexmap::IndexMap::new();
    for (tool, hash) in tools_allow {
        allow.insert(
            (*tool).to_string(),
            ToolAllowCfg {
                schema_hash: hash.clone(),
                description: None,
                input_schema: None,
                ask_caller: Vec::new(),
                ..ToolAllowCfg::default()
            },
        );
    }
    McpServerDefCfg {
        refresh_ttl: None,
        timeout: None,
        url: peer.mcp_url(),
        pin: ServerPinCfg {
            mechanism: McpPinMechanism::CertSpki,
            key: Some("sha256/PEER=".to_string()),
        },
        tools_allow: allow,
        prompts_allow: indexmap::IndexMap::new(),
        resources_allow: indexmap::IndexMap::new(),
        resource_templates_allow: Default::default(),
        transport: None,
        aud: None,
        grants: crate::mcp::config::ServerRequestGrants::default(),
        max_input_required_rounds: None,
        max_caller_ask_rounds: None,
        // The peer is on loopback, which every fail-closed default refuses until an operator says
        // the estate is internal.
        allow_private: true,
        token_exchange: None,
        upstream_credentials: None,
        hooks: Vec::new(),
    }
}

/// The MCP resource config these tests serve under.
pub(crate) fn mcp_cfg() -> crate::mcp::McpCfg {
    crate::mcp::McpCfg {
        canonical_uri: "https://gateway.example.com/mcp".to_string(),
        authorization_servers: vec!["https://login.example.com".to_string()],
        scopes_supported: Vec::new(),
        allowed_origins: Vec::new(),
    }
}

/// A `GovCtx` holding a key granted exactly `pairs`.
pub(crate) fn gov_with_scopes(pairs: &[(&str, &str)]) -> crate::governance::GovCtx {
    let scopes = pairs
        .iter()
        .map(|(kind, value)| busbar_api::ScopeRef {
            kind: (*kind).to_string(),
            value: (*value).to_string(),
        })
        .collect();
    crate::governance::GovCtx {
        key: Some(std::sync::Arc::new(busbar_api::VirtualKey {
            id: "k-connect".to_string(),
            name: "k-connect".to_string(),
            generation_hash: String::new(),
            enabled: true,
            allowed_scopes: Some(scopes),
            group: None,
            labels: Default::default(),
            expires_at: None,
            deleted_at: None,
            created_at: 0,
            revision: 0,
        })),
    }
}

/// Drive one JSON-RPC method against the built app, exactly as the ingress does.
pub(crate) async fn call(
    app: &std::sync::Arc<crate::state::App>,
    gov: &crate::governance::GovCtx,
    method: &str,
    params: serde_json::Value,
) -> (u16, serde_json::Value) {
    let handle = std::sync::Arc::new(crate::state::AppHandle::new(app.clone()));
    let ctx = crate::mcp::method::Ctx {
        app,
        handle: &handle,
        gov,
        actor: "test-principal",
        capabilities: &ALL_CAPABILITIES,
        headers: &NO_HEADERS,
    };
    let response = crate::mcp::method::dispatch(&ctx, method, Some(&params), Some(1.into()))
        .await
        .unwrap_or_else(|| panic!("`{method}` must be in the method table"));
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}
