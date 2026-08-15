// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTANCE TEST FOR "A HOOK FIRES ON A NON-LLM PROTOCOL": `tools.hooks: [reject-all]` is
//! configured, a real `tools/call` is dispatched at the real method table against a real upstream,
//! and the call is REJECTED before that upstream is reached.
//!
//! ## Why it is written against a REAL peer rather than a stub
//!
//! The claim is that the hook STOPPED something. A test with no upstream cannot distinguish "the
//! gate rejected the call" from "the call could not have been made anyway" — both answer with an
//! error and neither proves a gate ran. So the fixture is the same real fake peer the upstream-leg
//! batteries use, the same registration, and the same dispatcher; the only difference between the
//! two halves of each test is whether a hook is attached. `peer.mcp_hits() == 0` is what makes the
//! rejection a REFUSAL rather than a failure, and the sibling with no hooks (which reaches the peer
//! and answers `200`) is what makes the fixture falsifiable.
//!
//! ## Why the gate is a real `dlopen`ed plugin
//!
//! The hook seam is a C ABI. A test double implementing `RoutingPolicy` in-process would prove that
//! this file can construct a rejection, not that an operator's signed gate binary receives an MCP
//! projection and can act on it. The plugin here is the hermetic `busbar-hook-test-plugin` cdylib
//! loaded through the real scan/trust/load pipeline, and it makes its verdict by READING THE
//! PROJECTION busbar sent it — which is what turns `mcp_content_reaches_the_gate` below into
//! evidence about content rather than about plumbing.

use super::upstream_support::{
    call_as, exchanging_server, gov_with_scopes, mcp_cfg, Behaviour, Peer,
};
use crate::config::{HookCfg, HookKind, PromptAccess, UserAccess};
use crate::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";

/// The `hooks:` DEFINITION a test attaches: a `kind: gate` backed by the hermetic test cdylib,
/// holding the `prompt: ro` grant so the content projection is sent.
fn gate(settings: serde_json::Value) -> HookCfg {
    HookCfg {
        kind: HookKind::Gate,
        plugin: "test-hook".to_string(),
        // NOT `DEFAULT_POLICY_TIMEOUT_MS` (1 ms) — same reasoning as the A2A twin
        // (`a2a/tests/hook_gate_tests.rs`): under parallel-suite load the 1 ms deadline fires on
        // scheduling delay alone, and `on_error: "weighted"` turns the timed-out gate into a
        // PROCEED, flaking every verdict assertion here. The verdict is under test, not the
        // deadline; 10 s cannot fire for an in-process dlopen call.
        timeout_ms: 10_000,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::Ro,
        user: UserAccess::Ro,
        priority: 0,
        at: None,
        settings: settings.as_object().cloned().unwrap_or_default(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

/// The env that loads the test cdylib under the alias `test-hook`, declaring the manifest intent
/// (`prompt: rw`, `user: ro`) the operator grant is met against.
///
/// ITS ABSENCE IS A HARD FAILURE HERE, never a skip, and that is not the shared helper's default —
/// it skips off CI. This battery refuses it for the reason `calllog_dispatch_tests` refuses it: a
/// "skip: cdylib not built" line is how the coverage that would have caught the defect silently
/// stops running while the run stays green and nobody reads the line. It is not hypothetical for
/// THIS file: with the firing sites reverted and the cdylib missing, all four tests here reported
/// `ok`. The panic names the command that fixes it.
fn hook_env() -> crate::hooks::HookEnv {
    crate::test_support::test_hook_env(
        &["test-hook"],
        busbar_plugin_sign::HookNeeds {
            prompt: busbar_plugin_sign::NeedLevel::Rw,
            user: busbar_plugin_sign::NeedLevel::Ro,
        },
    )
    .expect(
        "the busbar-hook-test-plugin cdylib is not built. This battery is the acceptance test for \
         \"a hook fires on a non-LLM protocol\" and it CANNOT be skipped: with no gate to load, \
         every assertion below is vacuous and reports a green. Build it: `cargo build -p \
         busbar-hook-test-plugin`.",
    )
}

/// THE ACCEPTANCE TEST. `tools.hooks: [reject-all]` — the SECTION-level attach, which applies to
/// every registered server — and a `tools/call` that is refused, with the upstream never contacted.
///
/// The control half runs the identical call against the identical deployment with the attach
/// REMOVED, and it must reach the peer and answer `200`. Without that half a green here would be
/// satisfied by any refusal for any reason.
#[tokio::test]
async fn tools_hooks_reject_all_rejects_a_tools_call() {
    let env = hook_env();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let params = serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } });

    // ── THE CONTROL: no hook attached, so this deployment serves the call. ───────────────────────
    let ungated = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let (status, body) = call_as(
        &ungated,
        &g,
        "hook-gate-control",
        "tools/call",
        params.clone(),
    )
    .await;
    assert_eq!(
        status, 200,
        "the fixture must SERVE this call with no hook attached, or the rejection below proves \
         nothing: {body}"
    );
    assert_eq!(peer.mcp_hits(), 1, "the control reached the upstream");

    // ── THE TEST: `tools.hooks: [reject-all]`, same call, same deployment otherwise. ─────────────
    let gated = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .tools_hooks(&["reject-all"])
        .hook(
            "reject-all",
            gate(serde_json::json!({
                "raw_decide_reply": {"reject": {"status": 403, "message": "no tool calls today"}}
            })),
        )
        .hook_env(env)
        .build();
    let (status, body) = call_as(&gated, &g, "hook-gate-rejected", "tools/call", params).await;

    assert_eq!(
        status, 403,
        "`tools.hooks: [reject-all]` must REFUSE the call. A 200 here is the whole finding: the \
         key validates and then does nothing. Body: {body}"
    );
    assert_eq!(
        body["error"]["message"], "no tool calls today",
        "the hook's own message must reach the caller, so an operator can tell WHICH control \
         refused: {body}"
    );
    assert_eq!(
        peer.mcp_hits(),
        1,
        "the upstream must NOT have been contacted a second time — a gate that rejects after the \
         call has gone out is a gate that stopped nothing"
    );
}

/// WHAT THE HOOK ACTUALLY SEES. The gate rejects only when the projection it was sent CONTAINS a
/// token that appears nowhere except inside the `tools/call` arguments — so a pass here is a
/// statement about content delivery, not about a hook having been invoked.
///
/// This is the half that stops an empty projection from counting: a gate that fires with nothing in
/// it would abstain here and the call would succeed.
#[tokio::test]
async fn mcp_content_reaches_the_gate() {
    let env = hook_env();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .tools_hooks(&["screen"])
        .hook(
            "screen",
            gate(serde_json::json!({ "reject_if_contains": "/etc/shadow" })),
        )
        .hook_env(env)
        .build();

    // An argument the screen does not object to: served.
    let (status, body) = call_as(
        &app,
        &g,
        "hook-gate-content-clean",
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } }),
    )
    .await;
    assert_eq!(status, 200, "a clean payload must still be served: {body}");

    // The SAME call with the token inside `arguments` — reachable only if the arguments were
    // projected to the gate.
    let (status, body) = call_as(
        &app,
        &g,
        "hook-gate-content-blocked",
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/shadow" } }),
    )
    .await;
    assert_eq!(
        status, 403,
        "the gate's verdict was driven by the tool call's ARGUMENTS, so the projection must carry \
         them. A 200 here means the hook fired with an empty projection, which is worse than not \
         firing: a screening gate would pass a payload it never saw. Body: {body}"
    );
}
