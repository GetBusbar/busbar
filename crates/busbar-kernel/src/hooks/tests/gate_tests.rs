// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL-BLIND GATE SEAM, asserted on the two things a firing site trusts it for: the exact
//! JSON a hook receives, and the verdict it returns.
//!
//! The wire assertion is deliberately WHOLE-DOCUMENT rather than field-by-field. A projection is a
//! disclosure decision, and a test that checks the fields it remembers to name is a test that says
//! nothing about the field somebody adds next. Comparing the entire object means a new key cannot
//! reach a hook without this file being edited, which is where the decision belongs.

use crate::hooks::gate::{decide, GateSubject, GateVerdict};
use crate::hooks::{
    Candidate, PolicyResult, ResolvedPolicy, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest,
};
use busbar_contract::ir::invoke::InvokeReq;
use std::sync::{Arc, Mutex};

/// A gate that ANSWERS a fixed decision and RECORDS the exact wire document it was handed — built
/// through the engine's own `wire::build`, so what this test reads is what a plugin would receive
/// across the ABI rather than a second rendering of the same struct.
struct Spy {
    reply: RoutingDecision,
    seen: Mutex<Option<serde_json::Value>>,
}

#[async_trait::async_trait]
impl RoutingPolicy for Spy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        let doc = serde_json::to_value(crate::hooks::wire::build(
            crate::hooks::wire::OP_DECIDE,
            req,
            candidates,
            ctx,
        ))
        .expect("the hook wire projection serializes");
        *self.seen.lock().unwrap() = Some(doc);
        Ok(self.reply.clone())
    }

    fn name(&self) -> &'static str {
        "spy"
    }
}

/// A gate that cannot answer — the shape a hook takes when its own dependency is down.
struct Broken;

#[async_trait::async_trait]
impl RoutingPolicy for Broken {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        Err("the gate's backend is unreachable".into())
    }

    fn name(&self) -> &'static str {
        "broken"
    }
}

/// A gate that answers a raw hook REPLY (the 1.5.5 JSON a plugin returns): the hook fixture, loaded
/// through the hook axis on the one dispatcher and told to answer `reply` verbatim
/// (`raw_decide_reply`). The SDK lowers the reply on the plugin side and the kernel's hook seam
/// lowers the fixed answer back, so this drives the shipped path whole: a reply that fails to parse
/// yields `Err(..)` (→ the gate's `on_error`), a reply that parses to "no opinion" yields
/// `Ok(Abstain)` (→ proceed). Nothing here re-implements the normalizer.
fn reply_gate(reply: serde_json::Value) -> Arc<dyn RoutingPolicy> {
    let env = crate::test_support::test_hook_env(&["reply-gate"], Default::default())
        .expect("the hook fixture cdylib");
    let mut settings = serde_json::Map::new();
    settings.insert("raw_decide_reply".into(), reply);
    env.open("reply-gate", &settings, "reply-gate", 5_000)
        .expect("the hook fixture opens through the axis")
}

/// A reply carrying a VALID `reject` beside a WRONG-TYPED sibling (`order` must be an array of
/// integers) fails to parse into `HookResponse` — and with `on_error: reject` that MUST refuse the
/// request, never route it. This is the exact CF4 fail-open: the malformed reply used to be
/// swallowed to `Abstain` (proceed), bypassing both the hook's `reject` and the operator's on_error.
#[tokio::test]
async fn a_valid_reject_with_a_wrong_typed_sibling_rejects_under_on_error_reject() {
    let facts = tool_call();
    // `reject` is untyped (fail-closed by design); `order` is strictly `Vec<usize>`, so a string
    // aborts the WHOLE parse.
    let gates = gate(
        reply_gate(serde_json::json!({
            "reject": { "status": 403, "message": "screened" },
            "order": "not-an-array",
        })),
        crate::config::PolicyOnError::Reject,
        true,
        false,
    );
    let subject = GateSubject {
        facts: &facts,
        container: "filesystem",
        ingress_protocol: "example-protocol",
        request_id: 1,
        key: None,
        session: None,
        incremental: None,
    };
    assert!(
        matches!(decide(&gates, &subject).await, GateVerdict::Reject { .. }),
        "a malformed reply carrying a valid reject must fail CLOSED to on_error, not proceed"
    );
}

/// A TOTALLY malformed reply (not even an object) fails to parse → the gate's `on_error` decides.
#[tokio::test]
async fn a_totally_malformed_reply_applies_on_error() {
    let facts = tool_call();
    let subject = GateSubject {
        facts: &facts,
        container: "filesystem",
        ingress_protocol: "example-protocol",
        request_id: 1,
        key: None,
        session: None,
        incremental: None,
    };

    let closed = gate(
        reply_gate(serde_json::json!("garbage")),
        crate::config::PolicyOnError::Reject,
        false,
        false,
    );
    assert!(
        matches!(decide(&closed, &subject).await, GateVerdict::Reject { .. }),
        "`on_error: reject` refuses a request whose gate returned an unparseable reply"
    );
}

/// `on_error: weighted` (the advisory posture) HONORS the operator's choice: a malformed reply from
/// an advisory gate does NOT refuse — the fix routes a parse failure to `on_error`, whatever the
/// operator set it to, so a non-reject terminal still proceeds.
#[tokio::test]
async fn a_malformed_reply_honors_a_non_reject_on_error() {
    let facts = tool_call();
    let open = gate(
        reply_gate(serde_json::json!({
            "reject": { "status": 403 },
            "order": "not-an-array",
        })),
        crate::config::PolicyOnError::Weighted,
        true,
        false,
    );
    let subject = GateSubject {
        facts: &facts,
        container: "filesystem",
        ingress_protocol: "example-protocol",
        request_id: 1,
        key: None,
        session: None,
        incremental: None,
    };
    assert!(
        matches!(decide(&open, &subject).await, GateVerdict::Proceed),
        "the operator chose `weighted`: a failed advisory gate proceeds, it does not refuse"
    );
}

/// A GENUINE no-opinion reply still Abstains. An empty `{}` parses cleanly to a `HookResponse` with
/// no signals → `Ok(Abstain)` → proceed, even under `on_error: reject`: a hook that legitimately has
/// nothing to say is NOT turned into a hard failure by this fix.
#[tokio::test]
async fn an_empty_reply_still_abstains_even_under_on_error_reject() {
    let facts = tool_call();
    let subject = GateSubject {
        facts: &facts,
        container: "filesystem",
        ingress_protocol: "example-protocol",
        request_id: 1,
        key: None,
        session: None,
        incremental: None,
    };
    for reply in [
        serde_json::json!({}),
        serde_json::json!({ "abstain": true }),
        // An absent `order` with unknown diagnostic fields is still a clean parse → Abstain.
        serde_json::json!({ "note": "looked, nothing to flag" }),
    ] {
        let gates = gate(
            reply_gate(reply.clone()),
            crate::config::PolicyOnError::Reject,
            true,
            false,
        );
        assert!(
            matches!(decide(&gates, &subject).await, GateVerdict::Proceed),
            "a genuine no-opinion reply {reply} must proceed, not fail closed"
        );
    }
}

/// A well-formed `reject` (the common case) still rejects through this seam — the parse-OK path is
/// untouched, proving the fix narrowed only the parse-FAILURE case.
#[tokio::test]
async fn a_well_formed_reject_still_rejects() {
    let facts = tool_call();
    let gates = gate(
        reply_gate(serde_json::json!({ "reject": { "status": 451, "message": "no" } })),
        // Even with an advisory on_error, a PARSED reject wins — it is the hook's own verdict, not an
        // error.
        crate::config::PolicyOnError::Weighted,
        true,
        false,
    );
    let subject = GateSubject {
        facts: &facts,
        container: "filesystem",
        ingress_protocol: "example-protocol",
        request_id: 1,
        key: None,
        session: None,
        incremental: None,
    };
    match decide(&gates, &subject).await {
        GateVerdict::Reject { status, .. } => assert_eq!(status, 451),
        GateVerdict::Proceed => panic!("a well-formed reject must stop the request"),
    }
}

/// One resolved gate around `policy`, with the grants and terminal a test wants.
fn gate(
    policy: Arc<dyn RoutingPolicy>,
    on_error: crate::config::PolicyOnError,
    send_prompt: bool,
    send_user: bool,
) -> Vec<(u16, ResolvedPolicy)> {
    vec![(
        0,
        ResolvedPolicy::Policy {
            policy,
            on_error,
            on_error_chain: Vec::new(),
            timeout: std::time::Duration::from_secs(5),
            send_prompt,
            send_user,
            on_empty: crate::config::PolicyOnError::Reject,
        },
    )]
}

fn tool_call() -> InvokeReq {
    InvokeReq {
        tool: "fs_read".to_string(),
        arguments: serde_json::json!({ "path": "/etc/hosts" }),
        extra: Default::default(),
    }
}

fn key() -> busbar_contract::records::VirtualKey {
    busbar_contract::records::VirtualKey {
        id: "k-1".to_string(),
        name: "reporting".to_string(),
        generation_hash: String::new(),
        enabled: true,
        allowed_scopes: None,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        created_at: 0,
        revision: 0,
        ..Default::default()
    }
}

/// THE PROJECTION, WHOLE. What a `prompt: ro` + `user: ro` gate is handed for one tool invocation (`tools/call`)
/// — and the reason this is the headline rather than the verdict test below it: a gate that fires
/// with an empty projection is worse than a gate that does not fire, because a screening hook would
/// pass a payload it never saw.
#[tokio::test]
async fn an_invocation_is_projected_whole() {
    let spy = Arc::new(Spy {
        reply: RoutingDecision::Abstain,
        seen: Mutex::new(None),
    });
    let facts = tool_call();
    let k = key();
    let gates = gate(
        spy.clone(),
        crate::config::PolicyOnError::Weighted,
        true,
        true,
    );
    let verdict = decide(
        &gates,
        &GateSubject {
            facts: &facts,
            container: "filesystem",
            ingress_protocol: "example-protocol",
            request_id: 7,
            key: Some(&k),
            session: None,
            incremental: None,
        },
    )
    .await;
    assert!(
        matches!(verdict, GateVerdict::Proceed),
        "an abstain proceeds"
    );

    let seen = spy
        .seen
        .lock()
        .unwrap()
        .clone()
        .expect("the gate was fired");
    assert_eq!(
        seen,
        serde_json::json!({
            "op": "decide",
            "request": {
                "request_id": 7,
                // The CONTAINER, which on this plane is the registered tool server.
                "pool": "filesystem",
                "ingress_protocol": "example-protocol",
                "message_count": 1,
                "has_tools": true,
                // The chars of everything shown below — one number, one walk.
                "total_chars": 21,
                "stream": false,
                // THE CONTENT. One entry, carrying the arguments the upstream would receive.
                "messages": [{ "role": "user", "text": "{\"path\":\"/etc/hosts\"}" }],
                "user": { "key_id": "k-1", "key_name": "reporting" }
            },
            "candidates": [],
            "context": {}
        }),
        "the projection a hook receives for a tool call, in full"
    );
}

/// The `prompt: no` default withholds the content and sends the shape — the same bidirectional
/// grant the model plane enforces, enforced by the same seam rather than by a second rule.
#[tokio::test]
async fn a_grantless_gate_sees_shape_and_no_content() {
    let spy = Arc::new(Spy {
        reply: RoutingDecision::Abstain,
        seen: Mutex::new(None),
    });
    let facts = tool_call();
    let gates = gate(
        spy.clone(),
        crate::config::PolicyOnError::Weighted,
        false,
        false,
    );
    let _ = decide(
        &gates,
        &GateSubject {
            facts: &facts,
            container: "filesystem",
            ingress_protocol: "example-protocol",
            request_id: 1,
            key: Some(&key()),
            session: None,
            incremental: None,
        },
    )
    .await;
    let seen = spy
        .seen
        .lock()
        .unwrap()
        .clone()
        .expect("the gate was fired");
    assert!(
        seen["request"].get("messages").is_none() && seen["request"].get("user").is_none(),
        "no content and no identity without the grants: {seen}"
    );
    assert_eq!(
        seen["request"]["total_chars"], 21,
        "the SIZE signal is not a grant — a shape-only gate still learns how big the request is"
    );
}

/// The verdict. A `reject` stops the request and carries the hook's own message and name; the
/// status is re-clamped to the 4xx band at the seam that ACTS on it, not merely at the one that
/// parsed it.
#[tokio::test]
async fn a_reject_stops_the_request_with_a_clamped_status() {
    let facts = tool_call();
    // The out-of-band values a hook can send are bounded by the wire's own `u16`, so the interesting
    // pair is a success status and a 5xx — the two a gate must not be able to mint through a reject.
    for (replied, expected) in [(403u16, 403u16), (200, 400), (503, 499), (65_535, 499)] {
        let gates = gate(
            Arc::new(Spy {
                reply: RoutingDecision::Reject {
                    status: replied,
                    message: "screened".to_string(),
                },
                seen: Mutex::new(None),
            }),
            crate::config::PolicyOnError::Weighted,
            true,
            false,
        );
        match decide(
            &gates,
            &GateSubject {
                facts: &facts,
                container: "filesystem",
                ingress_protocol: "example-protocol",
                request_id: 1,
                key: None,
                session: None,
                incremental: None,
            },
        )
        .await
        {
            GateVerdict::Reject {
                status,
                message,
                hook,
            } => {
                assert_eq!(status, expected, "a hook replied {replied}");
                assert_eq!(message, "screened");
                assert_eq!(hook, "spy", "the verdict names which control refused");
            }
            GateVerdict::Proceed => panic!("a reject must stop the request"),
        }
    }
}

/// A gate that CANNOT ANSWER is not a gate that agrees. Its own `on_error` decides, and `reject` is
/// what an operator writes when the control is load-bearing.
#[tokio::test]
async fn a_broken_gate_applies_its_own_on_error() {
    let facts = tool_call();

    let open = gate(
        Arc::new(Broken),
        crate::config::PolicyOnError::Weighted,
        false,
        false,
    );
    let closed = gate(
        Arc::new(Broken),
        crate::config::PolicyOnError::Reject,
        false,
        false,
    );
    let subject = GateSubject {
        facts: &facts,
        container: "filesystem",
        ingress_protocol: "example-protocol",
        request_id: 1,
        key: None,
        session: None,
        incremental: None,
    };
    assert!(
        matches!(decide(&open, &subject).await, GateVerdict::Proceed),
        "`on_error: weighted` is the advisory posture: a failed ordering gate does not refuse"
    );
    assert!(
        matches!(decide(&closed, &subject).await, GateVerdict::Reject { .. }),
        "`on_error: reject` must NOT be skippable by the gate being broken"
    );
}

/// NOTHING ATTACHED, NOTHING BUILT. The default deployment's cost is the empty check, and the
/// projection is never walked — asserted by a facts implementation that counts its own walks.
#[tokio::test]
async fn no_attached_gate_builds_no_projection() {
    struct Counting {
        inner: InvokeReq,
        walks: std::sync::atomic::AtomicUsize,
    }
    impl busbar_contract::ir::facts::IrFacts for Counting {
        fn verb(&self) -> crate::operation::OpVerb {
            crate::operation::OpVerb::INVOKE
        }
        fn wants_stream(&self) -> bool {
            false
        }
        fn end_user(&self) -> Option<&str> {
            None
        }
        fn shape(&self) -> busbar_contract::ir::facts::Shape {
            busbar_contract::ir::facts::IrFacts::shape(&self.inner)
        }
        fn content(&self) -> Vec<busbar_contract::ir::facts::ContentItem<'_>> {
            self.walks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            busbar_contract::ir::facts::IrFacts::content(&self.inner)
        }
    }
    let facts = Counting {
        inner: tool_call(),
        walks: std::sync::atomic::AtomicUsize::new(0),
    };
    let verdict = decide(
        &[],
        &GateSubject {
            facts: &facts,
            container: "filesystem",
            ingress_protocol: "example-protocol",
            request_id: 1,
            key: None,
            session: None,
            incremental: None,
        },
    )
    .await;
    assert!(matches!(verdict, GateVerdict::Proceed));
    assert_eq!(
        facts.walks.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a deployment that attached no hook must not pay for a projection"
    );
}

// ── Incremental scan (session-substrate tenant) ─────────────────────────────────────────────────

use crate::hooks::gate::IncrementalScan;
use crate::session::{SessionKey, SessionStore};

/// A long session re-screens only NEW content: a piece cleared on one turn is not sent to the hook
/// again on the next turn of the same session, and the gate proceeds without a sidecar call.
#[tokio::test]
async fn incremental_scan_skips_a_piece_already_cleared_this_session() {
    let store = SessionStore::new(64, None);
    let session = SessionKey(999);
    let facts = tool_call();

    // Turn 1: the piece is new — the spy sees it and abstains (clean), so it is cached.
    let spy1 = Arc::new(Spy {
        reply: RoutingDecision::Abstain,
        seen: Mutex::new(None),
    });
    let g1 = gate(
        spy1.clone(),
        crate::config::PolicyOnError::Weighted,
        true,
        true,
    );
    let v1 = decide(
        &g1,
        &GateSubject {
            facts: &facts,
            container: "filesystem",
            ingress_protocol: "example-protocol",
            request_id: 1,
            key: None,
            session: None,
            incremental: Some(IncrementalScan {
                store: &store,
                session,
                now_ms: 0,
            }),
        },
    )
    .await;
    assert!(matches!(v1, GateVerdict::Proceed));
    assert!(
        spy1.seen.lock().unwrap().is_some(),
        "turn 1 screens the new piece"
    );

    // Turn 2: same session, same content — the piece is already cleared, so the spy is NOT called.
    let spy2 = Arc::new(Spy {
        reply: RoutingDecision::Abstain,
        seen: Mutex::new(None),
    });
    let g2 = gate(
        spy2.clone(),
        crate::config::PolicyOnError::Weighted,
        true,
        true,
    );
    let v2 = decide(
        &g2,
        &GateSubject {
            facts: &facts,
            container: "filesystem",
            ingress_protocol: "example-protocol",
            request_id: 2,
            key: None,
            session: None,
            incremental: Some(IncrementalScan {
                store: &store,
                session,
                now_ms: 0,
            }),
        },
    )
    .await;
    assert!(matches!(v2, GateVerdict::Proceed));
    assert!(
        spy2.seen.lock().unwrap().is_none(),
        "turn 2's piece was already cleared this session — no redundant sidecar call"
    );
}

/// A BLOCKED piece is never cached, so it is re-screened on retry — the security-critical rule.
#[tokio::test]
async fn a_rejected_piece_is_not_cached_and_is_rescreened() {
    let store = SessionStore::new(64, None);
    let session = SessionKey(7);
    let facts = tool_call();

    // Turn 1: the gate REJECTS — the piece must NOT be recorded as cleared.
    let spy1 = Arc::new(Spy {
        reply: RoutingDecision::Reject {
            status: 403,
            message: "blocked".to_string(),
        },
        seen: Mutex::new(None),
    });
    let g1 = gate(
        spy1.clone(),
        crate::config::PolicyOnError::Weighted,
        true,
        true,
    );
    let v1 = decide(
        &g1,
        &GateSubject {
            facts: &facts,
            container: "filesystem",
            ingress_protocol: "example-protocol",
            request_id: 1,
            key: None,
            session: None,
            incremental: Some(IncrementalScan {
                store: &store,
                session,
                now_ms: 0,
            }),
        },
    )
    .await;
    assert!(matches!(v1, GateVerdict::Reject { .. }));

    // Turn 2: same session/content — because the block was never cached, it is screened again.
    let spy2 = Arc::new(Spy {
        reply: RoutingDecision::Abstain,
        seen: Mutex::new(None),
    });
    let g2 = gate(
        spy2.clone(),
        crate::config::PolicyOnError::Weighted,
        true,
        true,
    );
    let v2 = decide(
        &g2,
        &GateSubject {
            facts: &facts,
            container: "filesystem",
            ingress_protocol: "example-protocol",
            request_id: 2,
            key: None,
            session: None,
            incremental: Some(IncrementalScan {
                store: &store,
                session,
                now_ms: 0,
            }),
        },
    )
    .await;
    assert!(matches!(v2, GateVerdict::Proceed));
    assert!(
        spy2.seen.lock().unwrap().is_some(),
        "a blocked piece is re-screened on retry, never skipped"
    );
}

/// IG1 (security): the incremental cleared-set identity is BOUND to the caller PRINCIPAL and the
/// hook-config GENERATION, not the client-chosen `x-session-id` alone. `derive_session_key` yields a
/// DIFFERENT `SessionKey` when either the principal or the generation differs — so a clearance cannot
/// cross principals (confused deputy) or survive a policy tightening (stale clearance) — while staying
/// stable for identical inputs.
#[test]
fn derive_session_key_partitions_by_principal_and_generation() {
    let base = IncrementalScan::derive_session_key("sid", "alice", 1);
    // Identical inputs are stable.
    assert_eq!(base, IncrementalScan::derive_session_key("sid", "alice", 1));
    // A DIFFERENT principal on the same session id + generation: different key (confused-deputy fix).
    assert_ne!(base, IncrementalScan::derive_session_key("sid", "bob", 1));
    // A generation bump (policy tightened) on the same principal + session id: different key
    // (stale-clearance fix).
    assert_ne!(base, IncrementalScan::derive_session_key("sid", "alice", 2));
    // Domain separation: the principal/sid field boundary cannot alias into another split.
    assert_ne!(
        IncrementalScan::derive_session_key("b", "a", 1),
        IncrementalScan::derive_session_key("", "ab", 1),
    );
}

/// IG1 end-to-end through `decide`: a piece cleared for principal ALICE at generation G is
/// RE-SCREENED for a DIFFERENT principal BOB on the SAME session id, and RE-SCREENED for ALICE again
/// after a generation bump — the two invalidations the old `fnv1a(sid)`-only key silently skipped.
#[tokio::test]
async fn incremental_scan_reclears_across_principal_and_generation() {
    let store = SessionStore::new(64, None);
    let facts = tool_call();
    let sid = "shared-session";

    // Run one turn under a derived session key; returns whether the hook SAW the content (i.e. it was
    // re-screened rather than skipped as already-cleared). A clean Abstain caches the piece.
    async fn turn(store: &SessionStore, facts: &InvokeReq, session: SessionKey) -> bool {
        let spy = Arc::new(Spy {
            reply: RoutingDecision::Abstain,
            seen: Mutex::new(None),
        });
        let g = gate(
            spy.clone(),
            crate::config::PolicyOnError::Weighted,
            true,
            true,
        );
        let v = decide(
            &g,
            &GateSubject {
                facts,
                container: "filesystem",
                ingress_protocol: "example-protocol",
                request_id: 1,
                key: None,
                session: None,
                incremental: Some(IncrementalScan {
                    store,
                    session,
                    now_ms: 0,
                }),
            },
        )
        .await;
        assert!(matches!(v, GateVerdict::Proceed));
        let saw = spy.seen.lock().unwrap().is_some();
        saw
    }

    let alice_g1 = IncrementalScan::derive_session_key(sid, "alice", 1);
    let bob_g1 = IncrementalScan::derive_session_key(sid, "bob", 1);
    let alice_g2 = IncrementalScan::derive_session_key(sid, "alice", 2);

    // ALICE screens the piece clean at generation 1.
    assert!(
        turn(&store, &facts, alice_g1).await,
        "first sight is screened"
    );
    // Same principal + generation: the piece is now cleared (the mechanism still caches within a key).
    assert!(
        !turn(&store, &facts, alice_g1).await,
        "re-cleared for the same principal + generation"
    );
    // BOB, SAME session id, must NOT inherit ALICE's clearance — re-screened.
    assert!(
        turn(&store, &facts, bob_g1).await,
        "a different principal on the same session id must re-screen (confused-deputy fix)"
    );
    // ALICE again, but after a policy tightening (generation bump) — re-screened.
    assert!(
        turn(&store, &facts, alice_g2).await,
        "a policy-generation bump must invalidate the clearance (stale-clearance fix)"
    );
}

use crate::audit::amend;

/// The access amendments sealed for one operation label, oldest first. The journal is
/// process-wide, so each test below fires under a label no other test uses and reads only its own.
fn accesses_under(op: &str) -> Vec<amend::Access> {
    amend::node_recent()
        .into_iter()
        .filter_map(|a| match a.body {
            amend::AmendBody::Access(x) if x.op_class.as_str() == op => Some(x),
            _ => None,
        })
        .collect()
}

/// A HOOK THAT IS HANDED CONTENT LEAVES EXACTLY ONE AMENDMENT (item 404): who read it (the hook, by
/// name), whose it was (the caller's key) and which fields — never what they said. A shape-only
/// gate (`prompt: no`) is handed no content, so it leaves none.
#[tokio::test]
async fn a_gate_handed_content_leaves_exactly_one_access_amendment() {
    let facts = tool_call();
    let k = key();
    for (op, send_prompt) in [("p2-404-shape-only", false), ("p2-404-hook-read", true)] {
        let spy = Arc::new(Spy {
            reply: RoutingDecision::Abstain,
            seen: Mutex::new(None),
        });
        let gates = gate(spy, crate::config::PolicyOnError::Reject, send_prompt, true);
        let subject = GateSubject {
            facts: &facts,
            container: "filesystem",
            ingress_protocol: op,
            request_id: 1,
            key: Some(&k),
            session: None,
            incremental: None,
        };
        assert!(matches!(
            decide(&gates, &subject).await,
            GateVerdict::Proceed
        ));
    }
    assert!(accesses_under("p2-404-shape-only").is_empty());

    let rows = accesses_under("p2-404-hook-read");
    assert_eq!(rows.len(), 1, "one content read, one amendment: {rows:?}");
    assert_eq!(rows[0].reader, amend::Reader::Hook);
    assert_eq!(rows[0].name, "spy");
    assert_eq!(rows[0].subject, amend::Subject::PrincipalId("k-1".into()));
    assert_eq!(
        rows[0].fields,
        vec!["content".to_string(), "identity".into()]
    );
}

// ── The door path: the session the plane's `project` names (ARCHITECT RULING 2026-10-03) ──────

use crate::hooks::gate::{decide_door, DoorSubject, ScanSubstrate};

/// A gate that abstains and records the session each call's request view named.
#[derive(Default)]
struct SessionSpy {
    seen: Mutex<Vec<Option<Vec<u8>>>>,
}

#[async_trait::async_trait]
impl RoutingPolicy for SessionSpy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        self.seen
            .lock()
            .unwrap()
            .push(req.session.map(<[u8]>::to_vec));
        Ok(RoutingDecision::Abstain)
    }

    fn name(&self) -> &'static str {
        "session-spy"
    }
}

/// What a door plane's `project` answers for an invocation: the invoke document.
const PROJECTED: &[u8] =
    br#"{"tool":"message/send","arguments":{"message":{"parts":[{"text":"hi"}]}}}"#;

/// THE DOOR PATH'S INCREMENTAL SCAN KEYS ON THE VIEW'S SESSION (ARCHITECT RULING 2026-10-03,
/// Q-FOLD-A2A-2-PROJECT-POOL session half; predev's contextId-keyed scan is the baseline): the hook
/// sees the session; a piece cleared under one session is not screened again under it; another
/// session, no session, an empty session, another caller, a new hook generation and a node that
/// did not opt in each screen it again.
#[tokio::test]
async fn the_door_paths_incremental_scan_keys_on_the_views_session() {
    let store = SessionStore::new(64, None);
    let spy = Arc::new(SessionSpy::default());
    let gates = gate(
        spy.clone(),
        crate::config::PolicyOnError::Weighted,
        true,
        true,
    );
    let alice = key();
    let bob = busbar_contract::records::VirtualKey {
        id: "k-2".to_string(),
        ..key()
    };
    let calls = || spy.seen.lock().unwrap().len();
    let fire = |session: Option<&'static [u8]>,
                who: &'static busbar_contract::records::VirtualKey,
                generation: Option<u64>| {
        let gates = &gates;
        let store = &store;
        async move {
            let door = DoorSubject {
                projected: PROJECTED,
                container: "planner",
                dialect: "door-dialect",
                request_id: 1,
                key: Some(who),
                session,
                scan: generation.map(|generation| ScanSubstrate {
                    store,
                    generation,
                    now_ms: 0,
                }),
            };
            matches!(decide_door(gates, &door).await, GateVerdict::Proceed)
        }
    };
    let alice: &'static busbar_contract::records::VirtualKey = Box::leak(Box::new(alice));
    let bob: &'static busbar_contract::records::VirtualKey = Box::leak(Box::new(bob));

    assert!(fire(Some(b"ctx-1"), alice, Some(1)).await);
    assert_eq!(calls(), 1, "a new session's piece is screened");
    assert_eq!(
        spy.seen.lock().unwrap()[0].as_deref(),
        Some(&b"ctx-1"[..]),
        "the hook sees the session the view names"
    );
    assert!(fire(Some(b"ctx-1"), alice, Some(1)).await);
    assert_eq!(calls(), 1, "cleared under this session: not screened again");
    assert!(fire(Some(b"ctx-2"), alice, Some(1)).await);
    assert_eq!(calls(), 2, "another session screens it again");
    assert!(fire(None, alice, Some(1)).await);
    assert!(fire(None, alice, Some(1)).await);
    assert_eq!(calls(), 4, "no session: screened whole, every time");
    assert!(fire(Some(b""), alice, Some(1)).await);
    assert_eq!(calls(), 5, "an empty session is no session");
    assert_eq!(spy.seen.lock().unwrap()[4], None, "and the hook sees none");
    assert!(fire(Some(b"ctx-1"), bob, Some(1)).await);
    assert_eq!(
        calls(),
        6,
        "another caller on the same session screens it again"
    );
    assert!(fire(Some(b"ctx-1"), alice, Some(2)).await);
    assert_eq!(calls(), 7, "a new hook generation screens it again");
    assert!(fire(Some(b"ctx-1"), alice, None).await);
    assert_eq!(calls(), 8, "a node that did not opt in screens it whole");
}

/// The door path's session key is the engine's: a UTF-8 session keys exactly as its string did, so
/// a clearance made on one path is the same slot on the other.
#[test]
fn an_octet_session_keys_as_its_string() {
    assert_eq!(
        IncrementalScan::derive_session_key_octets(b"ctx-1", "alice", 3),
        IncrementalScan::derive_session_key("ctx-1", "alice", 3)
    );
    assert_ne!(
        IncrementalScan::derive_session_key_octets(b"ctx-1", "alice", 3),
        IncrementalScan::derive_session_key_octets(b"ctx-1\xff", "alice", 3)
    );
}
