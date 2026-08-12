// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `2026-07-28` outbound wire: the mirrored headers, `params._meta`, and the un-namespacing.
//!
//! The strongest assertion here is the SYMMETRY one: a request this module builds is fed to
//! `crate::mcp::ingress`'s own reader, and must be accepted. busbar refusing a request busbar sent
//! would be a silent, mutual misunderstanding that no single-direction test can see.

use crate::mcp::client::jsonrpc::{
    parse_response, tools_call, tools_list, RpcOutcome, META_CLIENT_CAPABILITIES,
    META_PROTOCOL_VERSION,
};
use crate::mcp::client::support::tkey;

fn body_of(req: &crate::mcp::client::jsonrpc::OutboundRequest) -> serde_json::Value {
    serde_json::from_slice(&req.body).expect("the body we build must be JSON")
}

fn header<'a>(
    req: &'a crate::mcp::client::jsonrpc::OutboundRequest,
    name: &str,
) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

#[test]
fn the_outbound_name_is_the_un_namespaced_tool() {
    let req = tools_call(
        "https://u.example/mcp",
        &tkey("filesystem", "read_file"),
        &serde_json::json!({"path": "/tmp/x"}),
        1,
        None,
    );
    let body = body_of(&req);
    // The upstream has never heard of `filesystem_read_file` and would answer -32602 to it.
    assert_eq!(body["params"]["name"], "read_file");
    assert_eq!(header(&req, "mcp-name"), Some("read_file"));
    // ...and the namespaced form appears nowhere on the wire.
    assert!(!String::from_utf8_lossy(&req.wire_bytes()).contains("filesystem_read_file"));
}

#[test]
fn meta_lives_at_params_meta_and_not_at_the_top_level() {
    // This is the exact defect the third-party conformance suite caught on the ingress side, where
    // every one of our own tests had agreed with the reader that read the top level. Building the
    // client against the same wrong shape would have made both halves agree and both halves wrong.
    let req = tools_list("https://u.example/mcp", 1, None);
    let body = body_of(&req);
    assert!(body.get("_meta").is_none(), "no top-level `_meta`");
    assert_eq!(
        body["params"]["_meta"][META_PROTOCOL_VERSION],
        crate::mcp::ingress::PROTOCOL_VERSION
    );
    // Capabilities are declared EMPTY: busbar will refuse sampling/elicitation/roots unless the
    // operator granted them, and declaring a capability we then refuse invites a call sequence
    // built around it.
    assert_eq!(
        body["params"]["_meta"][META_CLIENT_CAPABILITIES],
        serde_json::json!({})
    );
}

#[test]
fn the_mirrored_headers_agree_with_the_body_they_mirror() {
    let req = tools_call(
        "https://u.example/mcp",
        &tkey("fs", "read"),
        &serde_json::json!({}),
        9,
        Some("tok"),
    );
    let body = body_of(&req);
    assert_eq!(header(&req, "mcp-method"), body["method"].as_str());
    assert_eq!(header(&req, "mcp-name"), body["params"]["name"].as_str());
    assert_eq!(
        header(&req, "mcp-protocol-version"),
        body["params"]["_meta"][META_PROTOCOL_VERSION].as_str()
    );
}

#[test]
fn tools_list_carries_no_mcp_name_because_it_has_no_target() {
    let req = tools_list("https://u.example/mcp", 1, None);
    assert_eq!(header(&req, "mcp-method"), Some("tools/list"));
    assert!(header(&req, "mcp-name").is_none());
}

#[test]
fn there_is_no_session_header_on_any_request() {
    // `2026-07-28` deleted sessions. Sending `Mcp-Session-Id` would be busbar claiming a protocol
    // feature that does not exist.
    for req in [
        tools_list("https://u.example/mcp", 1, Some("t")),
        tools_call(
            "https://u.example/mcp",
            &tkey("fs", "read"),
            &serde_json::json!({}),
            2,
            Some("t"),
        ),
    ] {
        assert!(header(&req, "mcp-session-id").is_none());
        assert!(header(&req, "last-event-id").is_none());
    }
}

#[test]
fn the_authorization_header_is_present_exactly_when_a_credential_was_planned() {
    let with = tools_list("https://u.example/mcp", 1, Some("abc"));
    assert_eq!(header(&with, "authorization"), Some("Bearer abc"));
    let without = tools_list("https://u.example/mcp", 1, None);
    assert!(header(&without, "authorization").is_none());
}

// ── THE SOURCE SCAN THAT USED TO LIVE HERE ──────────────────────────────────────────────────────
//
// `the_client_and_the_ingress_agree_on_every_wire_literal` `include_str!`-ed `../../ingress.rs` and
// checked that the five shared wire words — the two `_meta` keys and the three header names —
// appeared on BOTH sides. It was comparing two copies, and a disagreement between them was silent
// and mutual: busbar would have refused a request busbar sent, and no single-direction test could
// see it, because each side was internally consistent with its own copy.
//
// There is now ONE copy. `mcp::ingress` owns all five constants and `mcp::client::jsonrpc` `use`s
// them, so the two directions cannot disagree — the module header there already claimed this was
// true, and until 2026-08-12 it was true as a claim and false as code. Nothing is left to compare,
// so the comparison is gone rather than ported.
//
// What replaces it is not a symmetry check but a SINGULARITY check: `scripts/structure-lint.sh`'s
// declaration census requires each of the five literals to occur EXACTLY ONCE in production code.
// A second spelling anywhere in the tree is RED — that is the drift this test existed to catch, now
// caught without naming a file — and ZERO occurrences is RED too, reported as SUBJECT-MISSING
// rather than as a pass. Both arms were proven: re-typing `"mcp-method"` in `client/jsonrpc.rs`
// reported WIRE-WORD-RESPELT with both sites, and renaming `"mcp-name"` to `"mcp-target-name"`
// reported SUBJECT-MISSING.

#[test]
fn a_jsonrpc_error_is_not_reported_as_a_result() {
    let out = parse_response(
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}"#,
        1,
    );
    assert_eq!(
        out,
        RpcOutcome::Error {
            code: -32601,
            message: "no such method".into()
        }
    );
}

#[test]
fn a_result_is_returned_verbatim() {
    let out = parse_response(br#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#, 1);
    assert_eq!(out, RpcOutcome::Result(serde_json::json!({"content": []})));
}

#[test]
fn every_malformed_shape_is_refused_rather_than_guessed_at() {
    let bad: [&[u8]; 5] = [
        b"not json",
        br#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#,
        br#"{"jsonrpc":"1.0","id":1,"result":{}}"#,
        br#"{"jsonrpc":"2.0","id":1}"#,
        b"",
    ];
    assert_eq!(bad.len(), 5, "the malformed set must not shrink");
    for body in bad {
        assert!(
            matches!(parse_response(body, 1), RpcOutcome::Malformed(_)),
            "{:?} must be malformed",
            String::from_utf8_lossy(body)
        );
    }
}
