// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STATELESS REVISION'S BYTES, PINNED (compat slot, ARCHITECT approval 2026-09-29 condition 4).
//!
//! Serving the session revisions on the same endpoint must not move one byte of what the stateless
//! `2026-07-28` revision answers. This test drives a fixed corpus of stateless requests (well formed,
//! malformed in each way the envelope checks, the verbs the revision retired, a stray session
//! header) at a real router and compares the transcript (status, content type, every response
//! header in the protocol's own prefix, body) with `golden/stateless_capture.txt`, which was captured from the tree
//! BEFORE the session revisions landed (the fold's A6 tip, ad7890382). A difference is a change to the
//! stateless path.
//!
//! `STATELESS_CAPTURE_WRITE=<path>` writes the transcript instead of comparing, which is how the
//! golden was made and how a deliberate change to the stateless path re-pins it.

use super::super::test_engine::*;
use super::super::McpCfg as Cfg;
use super::{
    H_MCP_METHOD as METHOD, H_MCP_NAME as NAME, H_PROTOCOL_VERSION as VERSION, PROTOCOL_VERSION,
};
use crate::testkit::TestAppMcpExt as _;
use busbar_plane_mcp::adapt::H_SESSION_ID as SID;

const GOLDEN: &str = include_str!("golden/stateless_capture.txt");
/// The mount path the corpus is posted to.
const ENDPOINT: &str = "/mcp";

fn cfg() -> Cfg {
    Cfg {
        canonical_uri: format!("https://gateway.example.com{ENDPOINT}"),
        authorization_servers: vec!["https://login.example.com".to_string()],
        scopes_supported: Vec::new(),
        allowed_origins: Vec::new(),
    }
}

fn meta() -> serde_json::Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

fn call(method: &str) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": { "_meta": meta() } })
}

struct Case {
    name: &'static str,
    verb: reqwest::Method,
    headers: Vec<(&'static str, String)>,
    body: Option<Vec<u8>>,
}

fn post(name: &'static str, body: &serde_json::Value, headers: &[(&'static str, &str)]) -> Case {
    Case {
        name,
        verb: reqwest::Method::POST,
        headers: headers
            .iter()
            .map(|(k, v)| (*k, (*v).to_string()))
            .collect(),
        body: Some(serde_json::to_vec(body).unwrap()),
    }
}

fn corpus() -> Vec<Case> {
    let v = PROTOCOL_VERSION;
    let ok = |m: &'static str| vec![(VERSION, v), (METHOD, m)];
    let mut cases = vec![
        post("tools/list", &call("tools/list"), &ok("tools/list")),
        post("prompts/list", &call("prompts/list"), &ok("prompts/list")),
        post(
            "resources/list",
            &call("resources/list"),
            &ok("resources/list"),
        ),
        post(
            "server/discover",
            &call("server/discover"),
            &ok("server/discover"),
        ),
        post(
            "unimplemented",
            &call("logging/setLevel"),
            &ok("logging/setLevel"),
        ),
        post(
            "initialize with the stateless marker",
            &call("initialize"),
            &ok("initialize"),
        ),
        post(
            "tools/call of an unknown tool",
            &serde_json::json!({ "jsonrpc": "2.0", "id": 8, "method": "tools/call",
                "params": { "name": "nope", "arguments": {}, "_meta": meta() } }),
            &[(VERSION, v), (METHOD, "tools/call"), (NAME, "nope")],
        ),
        post(
            "no _meta",
            &serde_json::json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {} }),
            &ok("tools/list"),
        ),
        post(
            "no params",
            &serde_json::json!({ "jsonrpc": "2.0", "id": 10, "method": "tools/list" }),
            &ok("tools/list"),
        ),
        post(
            "no capabilities",
            &serde_json::json!({ "jsonrpc": "2.0", "id": 11, "method": "tools/list",
                "params": { "_meta": { "io.modelcontextprotocol/protocolVersion": v } } }),
            &ok("tools/list"),
        ),
        post(
            "method header disagrees",
            &call("tools/list"),
            &[(VERSION, v), (METHOD, "prompts/list")],
        ),
        post("no method header", &call("tools/list"), &[(VERSION, v)]),
        post(
            "no version header",
            &call("tools/list"),
            &[(METHOD, "tools/list")],
        ),
        post(
            "unsupported version",
            &serde_json::json!({ "jsonrpc": "2.0", "id": 12, "method": "tools/list",
                "params": { "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2025-06-18",
                    "io.modelcontextprotocol/clientCapabilities": {} } } }),
            &[(VERSION, "2025-06-18"), (METHOD, "tools/list")],
        ),
        post(
            "a session header is ignored",
            &call("tools/list"),
            &[
                (VERSION, v),
                (METHOD, "tools/list"),
                (SID, "0123456789abcdef0123456789abcdef"),
            ],
        ),
        post(
            "a notification",
            &serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed",
                "params": { "_meta": meta() } }),
            &ok("notifications/roots/list_changed"),
        ),
        post(
            "an event-stream answer",
            &call("tools/list"),
            &[
                (VERSION, v),
                (METHOD, "tools/list"),
                ("accept", "text/event-stream, application/json"),
            ],
        ),
        post(
            "wrong jsonrpc",
            &serde_json::json!({ "jsonrpc": "1.0", "id": 1, "method": "tools/list" }),
            &ok("tools/list"),
        ),
        post(
            "a batch",
            &serde_json::json!([call("tools/list")]),
            &ok("tools/list"),
        ),
    ];
    cases.push(Case {
        name: "not json",
        verb: reqwest::Method::POST,
        headers: vec![("content-type", "application/json".to_string())],
        body: Some(b"{".to_vec()),
    });
    for verb in [reqwest::Method::GET, reqwest::Method::DELETE] {
        cases.push(Case {
            name: "retired verb",
            verb: verb.clone(),
            headers: Vec::new(),
            body: None,
        });
        cases.push(Case {
            name: "retired verb with a version header",
            verb,
            headers: vec![(VERSION, v.to_string())],
            body: None,
        });
    }
    cases
}

#[tokio::test]
async fn the_stateless_revision_answers_byte_for_byte_as_before() {
    metrics_init();
    let app = test_app().mcp(&cfg()).build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = build_router(app);
    let h = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let url = format!("http://{addr}{ENDPOINT}");
    let client = reqwest::Client::new();
    let mut transcript = String::new();
    for case in corpus() {
        let mut req = client.request(case.verb.clone(), &url);
        if case.body.is_some() {
            req = req.header("content-type", "application/json");
        }
        for (k, v) in &case.headers {
            req = req.header(*k, v.clone());
        }
        if let Some(b) = case.body {
            req = req.body(b);
        }
        let resp = req.send().await.unwrap();
        transcript.push_str(&format!("== {} {}\n", case.verb, case.name));
        transcript.push_str(&format!("status {}\n", resp.status().as_u16()));
        let mut names: Vec<String> = resp
            .headers()
            .keys()
            .map(|k| k.as_str().to_string())
            .filter(|k| {
                k == "content-type" || k == "allow" || k == "cache-control" || k.starts_with("mcp-")
            })
            .collect();
        names.sort();
        for n in names {
            let v = resp
                .headers()
                .get(&n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            transcript.push_str(&format!("{n}: {v}\n"));
        }
        let body = resp.bytes().await.unwrap();
        transcript.push_str(&String::from_utf8_lossy(&body));
        transcript.push_str("\n\n");
    }
    h.abort();
    if let Ok(path) = std::env::var("STATELESS_CAPTURE_WRITE") {
        std::fs::write(path, &transcript).unwrap();
        return;
    }
    if transcript != GOLDEN {
        let first = transcript
            .lines()
            .zip(GOLDEN.lines())
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        panic!(
            "the stateless path's answers moved (first differing line {first}):\n--- now\n{}\n--- golden\n{}",
            transcript.lines().skip(first).take(6).collect::<Vec<_>>().join("\n"),
            GOLDEN.lines().skip(first).take(6).collect::<Vec<_>>().join("\n"),
        );
    }
}
