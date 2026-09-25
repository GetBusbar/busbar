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
use crate::mcp::test_engine::*;
use crate::testkit::TestAppMcpExt;

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";

/// A `prompt: rw` REWRITE gate backed by the hermetic test cdylib. `raw_transform_reply` drives its
/// `transform` reply verbatim, so a test states the exact replacement `arguments` object the hook
/// returns — the invoke-family apply seam then swaps it in for the caller's arguments.
fn rewrite(raw_transform_reply: serde_json::Value) -> serde_json::Value {
    // The `hooks.<name>:` DOCUMENT as an operator writes it — the engine's own parser turns it into
    // its config type, so the grammar under test is the file grammar, not a struct literal.
    serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
        // Not the 1 ms default — under parallel-suite load the deadline fires on scheduling delay
        // alone and the rewrite would silently abstain; the rewrite is under test, not the deadline.
        "timeout_ms": 10_000,
        "on_error": "weighted",
        // `rw` is the resolution ticket: `resolve_container_rewrites` files only EFFECTIVE-rw gates.
        "prompt": "rw",
        "user": "ro",
        "priority": 0,
        "settings": { "raw_transform_reply": raw_transform_reply },
        "global": false,
        "default": false,
        "signals": [],
        "groups": [],
        "phase": [],
    })
}

/// A screening `prompt: rw` gate that REJECTS on a token in the content projection — proves a rewrite
/// gate can also stop a call (reject > rewrite), and that the content it screens is the arguments.
fn screen(reject_if_contains: &str) -> serde_json::Value {
    let mut def = rewrite(serde_json::Value::Null);
    def["settings"] =
        serde_json::json!({ "reject_if_contains": reject_if_contains, "reject_status": 451 });
    def
}

/// The env that loads the test cdylib under the alias `test-hook`, declaring the `prompt: rw` /
/// `user: ro` manifest intent the operator grant is met against. ABSENCE IS A HARD FAILURE, never a
/// skip: with no gate to load every assertion below is vacuous. The panic names the fix.
///
/// The acceptance criterion this battery answers, verbatim: "the rewrite half of the hook surface
/// fires on a non-LLM protocol".
fn hook_env() -> HookEnvHandle {
    engine()
        .hook_env(&["test-hook"], HookNeed::Rw, HookNeed::Ro)
    .expect(
        "the busbar-hook-test-plugin cdylib is not built. This battery is the acceptance test for \
         the rewrite half of the hook surface firing on the MCP plane (the criterion is quoted on \
         `hook_env`) and it CANNOT be skipped. Build it: `cargo build -p busbar-hook-test-plugin`.",
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
    let ungated = test_app()
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
    let gated = test_app()
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
    assert_eq!(
        status, 200,
        "the rewritten call must still be served: {body}"
    );

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
    let app = test_app()
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

/// A COMMITTED REWRITE BUSBAR CANNOT READ BACK REFUSES THE CALL — it does not fall back to the
/// arguments the hook said it had replaced.
///
/// The apply site read the verdict's bytes with `if let Ok(v) = …`, so a hook that reported
/// `applied` and produced bytes busbar could not read left `arguments` holding the ORIGINAL values
/// and the call went on to dispatch them. For the hook class this seam exists for that is fail-OPEN
/// in the precise sense: a redaction hook says "I have removed the secret from these arguments", its
/// output is unreadable, and busbar sends the arguments WITH the secret still in them.
///
/// Driven at the DECISION rather than through a hook chain, because the plane cannot make the host
/// seam emit unreadable bytes and the rule under test is what the PLANE does when it does. The
/// dispatch-side consequence — a refusal, never a dispatch — is the `Err` arm's only caller, and the
/// scan below pins that there is no second, lenient reader of the same bytes.
#[test]
fn a_committed_rewrite_busbar_cannot_read_back_is_refused_rather_than_silently_undone() {
    use crate::mcp::method::committed_arguments;

    let ok = committed_arguments(br#"{"path":"/srv/rewritten-by-hook"}"#)
        .expect("an ordinary rewrite is read back and used");
    assert_eq!(
        ok["path"], "/srv/rewritten-by-hook",
        "the control: a readable rewrite still lands, so the rule refuses unusable output rather \
         than refusing rewrites"
    );

    for unusable in [
        &b"not json at all"[..],
        &b""[..],
        &b"{\"path\": "[..],
        // Well-formed JSON that is not an arguments object. Admitting it would only move the
        // failure to the upstream, having already told the hook its rewrite landed.
        &b"7"[..],
        &b"[1,2,3]"[..],
        &b"null"[..],
        &b"\"/etc/hosts\""[..],
    ] {
        assert!(
            committed_arguments(unusable).is_err(),
            "a committed rewrite busbar cannot use must REFUSE the call; falling back to the \
             caller's original arguments silently undoes a redaction the hook reported as applied: \
             {:?}",
            String::from_utf8_lossy(unusable)
        );
    }
}

/// THE APPLY SITE HAS NO LENIENT READER OF THE SAME BYTES — a source scan, because the behavioural
/// half above covers only the shapes somebody thought of and this covers the shape a future
/// convenience would re-add.
///
/// The defect was one `if let Ok(v) = serde_json::from_slice…` inside the `applied` branch: a
/// conditional that keeps the ORIGINAL arguments when the parse fails and says nothing. The rule is
/// that the committed bytes are read in exactly one place, through `committed_arguments`, whose
/// `Err` arm returns a refusal.
///
/// The COMPANION half is what makes the scan falsifiable: the predicate is run against a string that
/// WOULD be a violation, so the scan cannot be passing because it never matches anything.
#[test]
fn the_rewrite_apply_site_never_falls_back_to_the_caller_s_original_arguments() {
    /// Does this source text read the committed bytes with a conditional that can silently keep the
    /// originals? One predicate, used on the real file and on the companion.
    fn has_lenient_reader(src: &str) -> bool {
        src.lines().any(|l| {
            let l = l.trim();
            !l.starts_with("//")
                && (l.contains("if let Ok(") || l.contains("while let Ok("))
                && l.contains("from_slice")
        })
    }

    let src = include_str!("../method.rs");
    assert!(
        !has_lenient_reader(src),
        "`mcp/method.rs` reads deserialized bytes through a conditional that drops the error. On \
         the rewrite apply site that is the fail-open this case exists for: the hook committed a \
         rewrite, busbar could not read it, and the ORIGINAL arguments went upstream."
    );
    assert!(
        src.contains("committed_arguments(&args_json)"),
        "the committed rewrite must be read through `committed_arguments`, whose `Err` arm refuses \
         the call"
    );
    assert!(
        has_lenient_reader("if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&x) {"),
        "the scan's predicate must match a line that WOULD be a violation, or a green scan is \
         evidence of nothing"
    );
}

/// **WHAT A PANICKING `prompt: rw` HOOK ACTUALLY PRODUCES — and it is not a join failure.**
///
/// This is the reachability leg for [`crate::mcp::method::tap_join_verdict`], and it is driven
/// through the REAL cdylib rather than asserted from the source, because the whole disposition
/// question at that join turns on what can arrive there. A missing check is not a vulnerability
/// until the line is shown to execute.
///
/// A `kind: hook` plugin's panic is caught THREE times before it could reach a plane: the SDK's
/// mandatory export-boundary `catch_unwind` (→ `STATUS_PANIC`), the engine's `ffi_guard` inside
/// `transport_call`, and `DlopenPolicy::call`'s own belt-and-braces guard. It therefore arrives at
/// `transform_over_over` as `TransformOutcome::Failed` — **the seam RAN and produced a verdict** —
/// and the operator's `on_error` decides what happens next. Both halves are here because the pair
/// is the point:
///
/// * `on_error: weighted` — the call is SERVED and the upstream receives the caller's ORIGINAL
///   `arguments`. That answer is only possible if the panic never reached the plane's
///   `spawn_blocking` join, which now REFUSES. This half is the falsifier.
/// * `on_error: reject` — the same panic refuses the call. The operator's declared disposition is
///   consulted, which is exactly the lever a join failure takes away, since on a join failure the
///   chain never ran for `on_error` to be applied to.
#[tokio::test]
async fn a_hook_that_panics_is_the_seams_own_failed_verdict_never_a_join_failure() {
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let params = serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } });

    // ── `on_error: weighted`: a panicking rewrite hook is a hook that could not answer, and the
    //    operator did not declare it load-bearing, so the call proceeds UNCHANGED. ───────────────
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let mut cfg = rewrite(serde_json::Value::Null);
    cfg["settings"] = serde_json::json!({ "panic_transform": true });
    let app = test_app()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .tools_hooks(&["panicky"])
        .hook("panicky", cfg)
        .hook_env(hook_env())
        .build();
    let (status, body) =
        call_as(&app, &g, "tap-panic-weighted", "tools/call", params.clone()).await;
    assert_eq!(
        status, 200,
        "a PANICKING rewrite hook is caught at the ABI boundary and reaches the seam as a FAILED \
         call, which `on_error: weighted` proceeds through. A 503 here would mean the panic had \
         reached the plane's join instead — the arm this test exists to prove is NOT the \
         hook-panic path: {body}"
    );
    assert_eq!(peer.mcp_hits(), 1, "the call was dispatched exactly once");
    assert_eq!(
        peer.last_mcp().json()["params"]["arguments"]["path"],
        "/etc/hosts",
        "and it carried the caller's ORIGINAL arguments: the seam's own fail-safe arm, chosen by \
         the operator, not the plane's join",
    );

    // ── `on_error: reject`: the SAME panic, declared load-bearing. The operator's disposition is
    //    applied — which is the lever a join failure removes, because the chain never ran. ───────
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let mut cfg = rewrite(serde_json::Value::Null);
    cfg["on_error"] = serde_json::json!("reject");
    cfg["settings"] = serde_json::json!({ "panic_transform": true });
    let app = test_app()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .tools_hooks(&["panicky-required"])
        .hook("panicky-required", cfg)
        .hook_env(hook_env())
        .build();
    let (status, _body) = call_as(&app, &g, "tap-panic-reject", "tools/call", params).await;
    assert_eq!(
        status,
        busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
        "a load-bearing rewrite hook that panicked refuses the call on the seam's own 'a required \
         gate could not complete' verdict"
    );
    assert_eq!(
        peer.mcp_hits(),
        0,
        "and nothing was dispatched: the refusal precedes the hop"
    );
}

/// **A REWRITE LEG THAT DID NOT JOIN REFUSES THE CALL, AND IS NEVER SILENT.**
///
/// The `spawn_blocking` join for the `prompt: rw` tap was `.unwrap_or(Proceed { applied: false, .. })`
/// — the one disposition on this seam that left NO TRACE AT ALL (`transform_over_over` logs its own
/// `Failed` arm and the gate leg logs its refusal), and the one that answers an UNKNOWN verdict with
/// "dispatch the caller's `arguments`". Those arguments are `params.arguments` off the caller's own
/// `tools/call` — UNTRUSTED input, the exact bytes a screening hook is attached to read — so
/// proceeding forwards to an upstream MCP server, over the credential busbar leases on the caller's
/// behalf, exactly the payload a hook was installed to inspect and possibly reject. Unknown is not
/// allow.
///
/// **The premise of the arm it replaces was false.** "The gate already admitted the request"
/// conflates two gates: admission decided whether the CALLER may call; this chain decides whether
/// THESE BYTES may be relayed. The second gate not running is not made safe by the first one having
/// run — and the gate leg's own join, one block up in the same function, already refuses.
///
/// Driven at the DECISION rather than through a hook chain for the reason
/// [`crate::mcp::method::committed_arguments`] is: the plane cannot make the host seam misbehave,
/// and the rule under test is what the PLANE does when it does. The
/// `a_hook_that_panics_is_the_seams_own_failed_verdict_never_a_join_failure` cell above is the other
/// leg — what CAN arrive here — and the `JoinError` below is real, produced by an actual panicked
/// blocking task, never a constructed stand-in.
#[tokio::test]
async fn a_rewrite_leg_that_did_not_join_refuses_the_call_and_is_never_silent() {
    use busbar_kernel::plane_host::TransformVerdict;
    use busbar_substrate_values::testkit::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    // A REAL `JoinError`: exactly the value the tap leg receives when its blocking task panics.
    let joined: Result<TransformVerdict, tokio::task::JoinError> =
        tokio::task::spawn_blocking(|| -> TransformVerdict { panic!("the rewrite leg blew up") })
            .await;
    assert!(
        joined.is_err(),
        "the fixture must actually be a panicked join"
    );

    // THE CONTROL, first: a leg that DID join is passed through untouched, so the rule refuses a
    // missing verdict rather than refusing rewrites.
    let passed = crate::mcp::method::tap_join_verdict(
        Ok(TransformVerdict::Proceed {
            applied: false,
            args_json: Vec::new(),
        }),
        "fs",
        "fs.fs_read",
    );
    assert!(
        matches!(passed, TransformVerdict::Proceed { applied: false, .. }),
        "a verdict that arrived is the verdict"
    );

    let cap = WarnCapture::default();
    let verdict =
        tracing::subscriber::with_default(tracing_subscriber::registry().with(cap.clone()), || {
            crate::mcp::method::tap_join_verdict(joined, "fs", "fs.fs_read")
        });

    match verdict {
        TransformVerdict::Reject {
            status,
            message,
            hook,
        } => {
            assert_eq!(
                status,
                busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
                "a leg that never answered is the seam's own 'a required gate could not complete' \
                 condition, minted at the one status every other firing site renders for it"
            );
            assert_eq!(
                message,
                busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
                "and the one content-free message, so a client learns nothing about the operator's \
                 hook topology from a leg that fell over"
            );
            assert!(
                !hook.is_empty(),
                "the refusal names the subject the plane's own reject arm logs; a blank here is \
                 the silence this fix removes, one field further in"
            );
        }
        TransformVerdict::Proceed { applied, .. } => panic!(
            "a rewrite leg that did not join must REFUSE the call — proceeding dispatches the \
             caller's UNTRUSTED `params.arguments` to the upstream server with the hook chain's \
             verdict unknown, which is the whole reason this seam exists. Got: \
             Proceed {{ applied: {applied} }}"
        ),
    }

    // AND THE SILENCE IS GONE. Every one of these is load-bearing for an operator reading the log:
    // what failed, whose chain, which verb, the error, and what busbar did about it.
    let lines = cap.messages().join("\n");
    assert!(
        cap.contains("did not join"),
        "the join failure must be logged at all — it was the only hook-failure mode on this seam \
         with no line: {lines}"
    );
    assert!(
        cap.contains("prompt: rw"),
        "and it must name the CONTROL that went unanswered: {lines}"
    );
    assert!(
        cap.contains("tools/call"),
        "and the VERB it went unanswered on: {lines}"
    );
    assert!(
        cap.contains("server=fs") && cap.contains("tool=fs.fs_read"),
        "and the subject: whose chain it is, and which tool it was called on: {lines}"
    );
    assert!(
        cap.contains("the rewrite leg blew up"),
        "and the underlying error, so the line is a diagnosis and not a notification: {lines}"
    );
    assert!(
        cap.contains("REFUSED"),
        "and what busbar did about it — silence and success must never be the same output at the \
         hook seam: {lines}"
    );
}
