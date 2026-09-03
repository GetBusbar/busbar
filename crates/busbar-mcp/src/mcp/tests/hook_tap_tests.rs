// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTANCE TEST FOR "THE TAP/TRANSFORM HALF OF THE HOOK SURFACE FIRES ON THIS NON-LLM
//! PROTOCOL": `tools.hooks: [rewrite]` is configured with a `prompt: rw` gate, a real `tools/call`
//! is dispatched at the real method table against a real upstream, and the ARGUMENTS THE PEER
//! RECEIVES are the ones the hook rewrote them to — not the ones the caller sent.
//!
//! This closes `hooks-tap × {mcp-client, mcp-server}`: one transform wiring at `mcp/method.rs`
//! covers both directions (the same "one battery covers both directions" fact the `hooks-gate` MCP
//! cells rely on — the pass sits before the client leg, so there is no ungated entry).
//!
//! ## Why against a REAL peer, and why the assertion is on the PEER's bytes
//!
//! A rewrite is only real if the thing downstream saw the rewritten value. A test that inspected
//! busbar's own in-memory `arguments` would prove the code CAN mutate a `Value`, not that the
//! mutation reaches the wire. So the fixture is the same real fake peer the gate battery uses, and
//! the assertion reads `peer.last_mcp()` — the JSON-RPC envelope the upstream actually received.
//!
//! ## The control makes it falsifiable
//!
//! The sibling half runs the identical call against the identical deployment with the rewrite hook
//! REMOVED, and it must reach the peer carrying the caller's ORIGINAL arguments. Without that half a
//! green here could be satisfied by the fixture sending that value for any reason. It is also the
//! byte-identical-when-unconfigured guarantee, exercised: no rewrite hook ⇒ the caller's bytes.

use super::upstream_support::{
    call_as, exchanging_server, gov_with_scopes, mcp_cfg, Behaviour, Peer,
};
use crate::testkit::TestAppMcpExt;
use busbar_core::config::{HookCfg, HookKind, PromptAccess, UserAccess};
use busbar_core::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";

/// A `prompt: rw` REWRITE gate backed by the hermetic test cdylib. `raw_transform_reply` drives its
/// `transform` reply verbatim, so a test states the exact replacement `arguments` object the hook
/// returns — the invoke-family apply seam then swaps it in for the caller's arguments.
fn rewrite(raw_transform_reply: serde_json::Value) -> HookCfg {
    HookCfg {
        kind: HookKind::Gate,
        plugin: "test-hook".to_string(),
        // Not the 1 ms default — under parallel-suite load the deadline fires on scheduling delay
        // alone and the rewrite would silently abstain; the rewrite is under test, not the deadline.
        timeout_ms: 10_000,
        on_error: "weighted".to_string(),
        // `rw` is the resolution ticket: `resolve_container_rewrites` files only EFFECTIVE-rw gates.
        prompt: PromptAccess::Rw,
        user: UserAccess::Ro,
        priority: 0,
        settings: serde_json::json!({ "raw_transform_reply": raw_transform_reply })
            .as_object()
            .cloned()
            .unwrap_or_default(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

/// A screening `prompt: rw` gate that REJECTS on a token in the content projection — proves a rewrite
/// gate can also stop a call (reject > rewrite), and that the content it screens is the arguments.
fn screen(reject_if_contains: &str) -> HookCfg {
    HookCfg {
        settings: serde_json::json!({ "reject_if_contains": reject_if_contains, "reject_status": 451 })
            .as_object()
            .cloned()
            .unwrap_or_default(),
        ..rewrite(serde_json::Value::Null)
    }
}

/// The env that loads the test cdylib under the alias `test-hook`, declaring the `prompt: rw` /
/// `user: ro` manifest intent the operator grant is met against. ABSENCE IS A HARD FAILURE, never a
/// skip: with no gate to load every assertion below is vacuous. The panic names the fix.
fn hook_env() -> busbar_core::hooks::HookEnv {
    busbar_core::test_support::test_hook_env(
        &["test-hook"],
        busbar_plugin_sign::HookNeeds {
            prompt: busbar_plugin_sign::NeedLevel::Rw,
            user: busbar_plugin_sign::NeedLevel::Ro,
        },
    )
    .expect(
        "the busbar-hook-test-plugin cdylib is not built. This battery is the acceptance test for \
         \"the rewrite half of the hook surface fires on a non-LLM protocol\" and it CANNOT be \
         skipped. Build it: `cargo build -p busbar-hook-test-plugin`.",
    )
}

/// THE ACCEPTANCE TEST. `tools.hooks: [rewrite]` with a `prompt: rw` gate whose rewrite replaces the
/// tool-call `arguments`, and a `tools/call` whose ORIGINAL arguments the upstream must NEVER see.
#[tokio::test]
async fn a_rewrite_hook_edits_the_tool_call_arguments_before_they_go_upstream() {
    let env = hook_env();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let params = serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } });

    // ── THE CONTROL: no rewrite hook, so the caller's arguments reach the peer VERBATIM. This is the
    //    byte-identical-when-unconfigured guarantee, exercised. ───────────────────────────────────
    let ungated = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let (status, body) = call_as(&ungated, &g, "tap-control", "tools/call", params.clone()).await;
    assert_eq!(status, 200, "the control must serve the call: {body}");
    assert_eq!(
        peer.last_mcp().json()["params"]["arguments"]["path"],
        "/etc/hosts",
        "with no rewrite hook the upstream must receive the caller's ORIGINAL arguments, byte for \
         byte — this is the no-op-absent-hooks guarantee",
    );

    // ── THE TEST: `tools.hooks: [rewrite]`, same call. The upstream must receive the REWRITTEN
    //    arguments, and the caller's `/etc/hosts` must appear nowhere on the wire it went out on. ──
    let gated = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .tools_hooks(&["rewrite"])
        .hook(
            "rewrite",
            rewrite(serde_json::json!({
                "rewrite": {
                    "messages": [
                        { "role": "user", "content": { "path": "/srv/rewritten-by-hook" } }
                    ]
                }
            })),
        )
        .hook_env(env)
        .build();
    let (status, body) = call_as(&gated, &g, "tap-rewritten", "tools/call", params).await;
    assert_eq!(status, 200, "the rewritten call must still be served: {body}");

    let seen = peer.last_mcp().json();
    assert_eq!(
        seen["params"]["arguments"]["path"], "/srv/rewritten-by-hook",
        "the upstream must have received the arguments THE HOOK REWROTE THEM TO. A `/etc/hosts` \
         here is the whole finding: the rewrite fired in memory but never reached the wire. Body \
         the peer saw: {seen}",
    );
    // The pre-rewrite value must not survive anywhere on the request the peer received — headers or
    // body — so this is a statement about the payload, not just about one JSON field.
    let wire = String::from_utf8_lossy(&peer.last_mcp().wire()).into_owned();
    assert!(
        !wire.contains("/etc/hosts"),
        "the caller's ORIGINAL argument must not appear anywhere on the wire once a rewrite hook \
         replaced it: {wire}",
    );
}

/// A `prompt: rw` gate that SCREENS may also REJECT (reject > rewrite): the same content that a plain
/// gate rejects on, reached through the rewrite pass. Proves the transform pass sees the arguments and
/// that its reject stops the call before the upstream is reached.
#[tokio::test]
async fn a_rewrite_gate_can_reject_on_the_arguments_it_screens() {
    let env = hook_env();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .tools_hooks(&["screen"])
        .hook("screen", screen("/etc/shadow"))
        .hook_env(env)
        .build();

    // Clean arguments: the rewrite pass abstains (no `raw_transform_reply`, no token) and the call is
    // served with the arguments untouched.
    let (status, body) = call_as(
        &app,
        &g,
        "tap-clean",
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } }),
    )
    .await;
    assert_eq!(status, 200, "a clean payload must be served: {body}");
    let hits_before = peer.mcp_hits();

    // The token inside `arguments` — reachable only if the transform pass was sent the arguments.
    let (status, _body) = call_as(
        &app,
        &g,
        "tap-blocked",
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/shadow" } }),
    )
    .await;
    assert_eq!(
        status, 451,
        "the rewrite gate's reject must fire on the arguments it screened, with the upstream never \
         reached",
    );
    assert_eq!(
        peer.mcp_hits(),
        hits_before,
        "a rejected call must NOT reach the upstream — a rewrite gate that rejects after the call \
         went out stopped nothing",
    );
}
