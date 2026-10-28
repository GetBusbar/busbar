// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL-BLIND GATE SEAM, asserted on the two things a firing site trusts it for: the exact
//! JSON a hook receives, and the verdict it returns.
//!
//! The wire assertion is deliberately WHOLE-DOCUMENT rather than field-by-field. A projection is a
//! disclosure decision, and a test that checks the fields it remembers to name is a test that says
//! nothing about the field somebody adds next. Comparing the entire object means a new key cannot
//! reach a hook without this file being edited, which is where the decision belongs.

use crate::hooks::gate::{decide_over, GateSubject, GateVerdict};
use crate::hooks::{
    Candidate, PolicyResult, ResolvedPolicy, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest,
};
use busbar_contract::ir::invoke::InvokeReq;
use std::sync::{Arc, Mutex};

/// A firing site's access-amendment seat that records nowhere: the tests that read no journal.
fn no_reads(_: &str, _: Option<&str>, _: &str, _: bool) {}

/// The gate pass over a request whose content was read: the cells below drive the one pass the door
/// path runs (`decide_door` reaches it the same way), shown readable content.
async fn decide(gates: &[(u16, ResolvedPolicy)], subject: &GateSubject<'_>) -> GateVerdict {
    decide_over(gates, subject, true, &mut Vec::new()).await
}

/// A gate that ANSWERS a fixed decision and RECORDS the exact wire document it was handed — built
/// through the contract's own `hook_wire::build`, so what this test reads is what a plugin would receive
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
        let doc = serde_json::to_value(busbar_contract::hook_wire::build(
            busbar_contract::hook_wire::OP_DECIDE,
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

/// A gate that answers a raw hook REPLY (the 1.5.5 JSON a hook returns): the hook double
/// (`test_support::hook_double`), opened through the kernel's hook axis port and told to answer
/// `reply` verbatim (`raw_decide_reply`). The reply is lowered into the call's frame as the SDK
/// lowers it, and the kernel's hook seam lowers the fixed answer back, so this drives the kernel's
/// path whole: a reply the hook got wrong (its typed fields do not parse) is `Ok(Abstain)`, as
/// 1.5.5's host read it (v1.5.5 `crates/busbar/src/hooks/plugin.rs:51-56`); only a hook that SAYS it
/// could not answer is `Err(..)` (→ the gate's `on_error`). Nothing here re-implements the
/// normalizer.
fn reply_gate(reply: serde_json::Value) -> Arc<dyn RoutingPolicy> {
    double_gate("raw_decide_reply", reply)
}

/// The hook double, opened with the one setting `key: value`.
fn double_gate(key: &str, value: serde_json::Value) -> Arc<dyn RoutingPolicy> {
    let env = crate::test_support::test_hook_env(&["reply-gate"], Default::default());
    let mut settings = serde_json::Map::new();
    settings.insert(key.into(), value);
    env.open("reply-gate", &settings, "reply-gate", 5_000)
        .expect("the hook double opens through the axis")
}

fn tool_subject(facts: &InvokeReq) -> GateSubject<'_> {
    GateSubject {
        facts,
        container: "filesystem",
        ingress_protocol: "example-protocol",
        request_id: 1,
        key: None,
        session: None,
        incremental: None,
        reads: &no_reads,
    }
}

/// A reply the hook got wrong is read as 1.5.5's host read it: a failed parse of the reply is
/// ABSTAIN (v1.5.5 `crates/busbar/src/hooks/plugin.rs:51-56`, `Err(_) => RoutingDecision::Abstain`),
/// so the request PROCEEDS even under `on_error: reject`. That includes a valid `reject` beside a
/// wrong-typed sibling: 1.5.5's `HookResponse` types `order` as `Vec<usize>` and `abstain` as
/// `bool` (v1.5.5 `crates/busbar/src/hooks/wire.rs:431,433`), so the whole parse failed and the
/// reject was never read. (This cell asserted the opposite, `on_error`, before the hook SDK's
/// lowering was brought back to 1.5.5: that was the divergence, not 1.5.5's behaviour.)
#[tokio::test]
async fn a_reply_the_hook_got_wrong_abstains_as_1_5_5_read_it_even_under_on_error_reject() {
    let facts = tool_call();
    for reply in [
        serde_json::json!({ "reject": { "status": 403, "message": "screened" }, "order": "x" }),
        serde_json::json!({ "reject": { "status": 403 }, "abstain": "yes" }),
        serde_json::json!({ "order": "x" }),
        serde_json::json!({ "abstain": "yes" }),
        serde_json::json!("garbage"),
        serde_json::json!(null),
        serde_json::json!([1]),
    ] {
        let gates = gate(
            reply_gate(reply.clone()),
            crate::config::PolicyOnError::Reject,
            true,
            false,
        );
        assert!(
            matches!(
                decide(&gates, &tool_subject(&facts)).await,
                GateVerdict::Proceed
            ),
            "1.5.5's host read the out-of-shape reply {reply} as abstain: the request proceeds"
        );
    }
}

/// A hook that SAYS it could not answer (`decide_result` → `Err`, the hook double's `fail_decide`)
/// is FAILED, and `on_error: reject` refuses, as 1.5.5's host did (v1.5.5
/// `crates/plugin-loader/src/hook.rs:173-175`, `HookReply::Failed` → `Err` → `on_error`). This is
/// the one road to `on_error` from a hook that answered; an out-of-shape reply is not it.
#[tokio::test]
async fn a_hook_that_says_it_failed_resolves_on_error_reject() {
    let facts = tool_call();
    let gates = gate(
        double_gate("fail_decide", serde_json::json!("the screen is down")),
        crate::config::PolicyOnError::Reject,
        true,
        false,
    );
    assert!(
        matches!(
            decide(&gates, &tool_subject(&facts)).await,
            GateVerdict::Reject { .. }
        ),
        "`on_error: reject` refuses a request whose gate said it could not answer"
    );
}

/// A GENUINE no-opinion reply still Abstains. An empty `{}` parses cleanly to a reply with
/// no verbs → `Ok(Abstain)` → proceed, even under `on_error: reject`: a hook that legitimately has
/// nothing to say is not a failure (v1.5.5 `crates/busbar/src/hooks/wire.rs:687-692`).
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
        reads: &no_reads,
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

/// A well-formed `reject` (the common case) rejects through this seam — the parse-OK path is
/// 1.5.5's (v1.5.5 `crates/busbar/src/hooks/wire.rs:670-675`), and a parsed reject is the hook's own
/// verdict, never `on_error`'s.
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
        reads: &no_reads,
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
            reads: &no_reads,
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
            reads: &no_reads,
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
/// status is re-clamped at the seam that ACTS on it, not merely at the one that parsed it, by the
/// ONE shared rule 1.5.5's `map_decision` applied (outside 400..=499 is 403), and the message is
/// re-sanitized by the one shared sanitizer (audit Q128 p15#5; THE DESIGN §11.7 l.1357-1358).
/// RED before: a saturating clamp answered 400 for a 200 and 499 for a 5xx, and the message
/// reached the caller with its control characters.
#[tokio::test]
async fn a_reject_stops_the_request_with_the_shared_clamp_and_sanitizer() {
    let facts = tool_call();
    // The out-of-band values a hook can send are bounded by the wire's own `u16`, so the interesting
    // pair is a success status and a 5xx — the two a gate must not be able to mint through a reject.
    for (replied, expected) in [
        (403u16, 403u16),
        (451, 451),
        (200, 403),
        (503, 403),
        (65_535, 403),
    ] {
        let gates = gate(
            Arc::new(Spy {
                reply: RoutingDecision::Reject {
                    status: replied,
                    message: "scr\r\neened".to_string(),
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
                reads: &no_reads,
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
                assert_eq!(message, "screened", "the shared sanitizer strips the CR LF");
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
        reads: &no_reads,
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
            reads: &no_reads,
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

/// The screen-cache key of a session named by a string, as the door path keys its octets.
fn derive_session_key(sid: &str, principal_id: &str, hook_generation: u64) -> SessionKey {
    IncrementalScan::derive_session_key_octets(sid.as_bytes(), principal_id, hook_generation)
}

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
            reads: &no_reads,
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
            reads: &no_reads,
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
            reads: &no_reads,
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
            reads: &no_reads,
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
    let base = derive_session_key("sid", "alice", 1);
    // Identical inputs are stable.
    assert_eq!(base, derive_session_key("sid", "alice", 1));
    // A DIFFERENT principal on the same session id + generation: different key (confused-deputy fix).
    assert_ne!(base, derive_session_key("sid", "bob", 1));
    // A generation bump (policy tightened) on the same principal + session id: different key
    // (stale-clearance fix).
    assert_ne!(base, derive_session_key("sid", "alice", 2));
    // Domain separation: the principal/sid field boundary cannot alias into another split.
    assert_ne!(
        derive_session_key("b", "a", 1),
        derive_session_key("", "ab", 1),
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
                reads: &no_reads,
            },
        )
        .await;
        assert!(matches!(v, GateVerdict::Proceed));
        let saw = spy.seen.lock().unwrap().is_some();
        saw
    }

    let alice_g1 = derive_session_key(sid, "alice", 1);
    let bob_g1 = derive_session_key(sid, "bob", 1);
    let alice_g2 = derive_session_key(sid, "alice", 2);

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

/// The access amendments `journal` sealed for one operation label, oldest first.
fn accesses_under(journal: &amend::NodeAmendments, op: &str) -> Vec<amend::Access> {
    journal
        .recent()
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
    // The node's journal, as the firing site's seat on it records: this test's own.
    let journal = amend::NodeAmendments::new();
    let reads = |hook: &str, principal: Option<&str>, op: &str, identity: bool| {
        amend::hook_read(&journal, hook, principal, op, identity);
    };
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
            reads: &reads,
        };
        assert!(matches!(
            decide(&gates, &subject).await,
            GateVerdict::Proceed
        ));
    }
    assert!(accesses_under(&journal, "p2-404-shape-only").is_empty());

    let rows = accesses_under(&journal, "p2-404-hook-read");
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

use crate::hooks::gate::{decide_door, DoorShape, DoorSubject, ScanSubstrate};

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
const PROJECTED: &[u8] = br#"{"tool":"lookup","arguments":{"query":{"parts":[{"text":"hi"}]}}}"#;

/// THE DOOR PATH'S INCREMENTAL SCAN KEYS ON THE VIEW'S SESSION (ARCHITECT RULING 2026-10-03, the
/// session half; the engine's session-keyed scan is the baseline): the hook
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
                projected: Some(PROJECTED),
                container: "entry",
                dialect: "door-dialect",
                request_id: 1,
                key: Some(who),
                session,
                scan: generation.map(|generation| ScanSubstrate {
                    store,
                    generation,
                    now_ms: 0,
                }),
                reads: &no_reads,
                plane: DoorShape::default(),
            };
            matches!(
                decide_door(gates, &door, &mut Vec::new()).await,
                GateVerdict::Proceed
            )
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
        derive_session_key("ctx-1", "alice", 3)
    );
    assert_ne!(
        IncrementalScan::derive_session_key_octets(b"ctx-1", "alice", 3),
        IncrementalScan::derive_session_key_octets(b"ctx-1\xff", "alice", 3)
    );
}

/// THE DOOR GATE'S FAILED-CALL REFUSAL IS EVERY SEAT'S (audit kernel-K4 #7). A load-bearing gate
/// that cannot answer refuses with the one client-facing refusal the shared seat answers — the same
/// status and the same words — so a broken required gate is one retryable condition on every
/// plane, never a 503 on one and a non-retryable 403 on the door-served planes.
#[tokio::test]
async fn a_broken_load_bearing_door_gate_answers_the_shared_refusal() {
    let facts = tool_call();
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
        reads: &no_reads,
    };
    match decide(&closed, &subject).await {
        GateVerdict::Reject {
            status, message, ..
        } => {
            assert!(
                crate::hooks::failed_call_refuses(&crate::config::PolicyOnError::Reject),
                "the shared rule refuses this disposition too"
            );
            assert_eq!(status, crate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS);
            assert_eq!(message, crate::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE);
        }
        _ => panic!("`on_error: reject` must refuse a broken gate"),
    }
}

/// THE DOOR GATE APPLIES THE HOOK CONTENT CEILING (audit kernel-K4 #8), the one rule every seat
/// that hands a hook the prompt applies: content over the ceiling is omitted whole, the grant
/// still honoured (an empty projection, never an absent one).
#[tokio::test]
async fn the_door_gate_projection_is_under_the_hook_content_ceiling() {
    let _lock = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::hooks::set_hook_content_max_bytes(crate::hooks::DEFAULT_HOOK_CONTENT_MAX_BYTES);
        }
    }
    let _restore = Restore;
    crate::hooks::set_hook_content_max_bytes(8);

    let spy = Arc::new(Spy {
        reply: RoutingDecision::Abstain,
        seen: Mutex::new(None),
    });
    let facts = tool_call();
    let gates = gate(
        spy.clone(),
        crate::config::PolicyOnError::Weighted,
        true,
        false,
    );
    let verdict = decide(
        &gates,
        &GateSubject {
            facts: &facts,
            container: "filesystem",
            ingress_protocol: "example-protocol",
            request_id: 7,
            key: None,
            session: None,
            incremental: None,
            reads: &no_reads,
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
    let messages = seen["request"]["messages"].clone();
    assert!(
        messages.as_array().is_none_or(|m| m.is_empty()),
        "21 bytes of arguments reached a gate whose ceiling is 8: {messages}"
    );
}

// ── The on_error chain, the container-bound clearance and the plane's projection (audit Q128 p15) ──

/// A spy answering `reply`.
fn spying(reply: RoutingDecision) -> Arc<Spy> {
    Arc::new(Spy {
        reply,
        seen: Mutex::new(None),
    })
}

/// A spy that abstains.
fn abstaining() -> Arc<Spy> {
    spying(RoutingDecision::Abstain)
}

/// One `on_error` fallback link around `policy`, with the grants a test wants.
fn link(
    policy: Arc<dyn RoutingPolicy>,
    send_prompt: bool,
    send_user: bool,
) -> crate::hooks::FallbackHook {
    crate::hooks::FallbackHook {
        policy,
        timeout: std::time::Duration::from_secs(5),
        send_prompt,
        send_user,
        on_empty: crate::config::PolicyOnError::Reject,
    }
}

/// [`gate`] with an `on_error` fallback chain in front of its terminal.
fn chained(
    policy: Arc<dyn RoutingPolicy>,
    chain: Vec<crate::hooks::FallbackHook>,
    terminal: crate::config::PolicyOnError,
    send_prompt: bool,
    send_user: bool,
) -> Vec<(u16, ResolvedPolicy)> {
    vec![(
        0,
        ResolvedPolicy::Policy {
            policy,
            on_error: terminal,
            on_error_chain: chain,
            timeout: std::time::Duration::from_secs(5),
            send_prompt,
            send_user,
            on_empty: crate::config::PolicyOnError::Reject,
        },
    )]
}

fn subject_on<'a>(facts: &'a InvokeReq, container: &'a str) -> GateSubject<'a> {
    GateSubject {
        facts,
        container,
        ingress_protocol: "example-protocol",
        request_id: 1,
        key: None,
        session: None,
        incremental: None,
        reads: &no_reads,
    }
}

/// A FAILED GATE WALKS ITS `on_error` CHAIN BEFORE ITS TERMINAL, as 1.5.5's `run_on_error_chain`
/// did (v1.5.5 `crates/busbar/src/proxy/hooks.rs:1119-1180`; THE DESIGN §11.7 l.1357-1358, audit
/// Q128 p15#1). `a: on_error: b`, `b: on_error: weighted`: a broken `a` asks `b`, and `b`'s reject
/// stops the request under `b`'s name. RED before: the door gate applied the terminal alone, so the
/// request proceeded without `b` ever being asked.
#[tokio::test]
async fn a_failed_gate_asks_its_fallback_and_the_fallbacks_reject_stops_the_request() {
    let facts = tool_call();
    let fallback = spying(RoutingDecision::Reject {
        status: 403,
        message: "fallback screened".to_string(),
    });
    let gates = chained(
        Arc::new(Broken),
        vec![link(fallback.clone(), true, true)],
        crate::config::PolicyOnError::Weighted,
        false,
        false,
    );
    match decide(&gates, &subject_on(&facts, "filesystem")).await {
        GateVerdict::Reject {
            status,
            message,
            hook,
        } => {
            assert_eq!((status, message.as_str()), (403, "fallback screened"));
            assert_eq!(hook, "spy", "the link that answered is the one named");
        }
        GateVerdict::Proceed => panic!("the fallback gate was skipped: the chain was not walked"),
    }
    let seen = fallback
        .seen
        .lock()
        .unwrap()
        .clone()
        .expect("the fallback was asked");
    assert!(
        seen["request"].get("messages").is_none() && seen["request"].get("user").is_none(),
        "a link sees at most what the failed gate was granted (1.5.5): {seen}"
    );
}

/// The first link that ANSWERS decides: a broken link is passed over, and a link that abstains
/// lets the request proceed even under a `reject` terminal. RED before: the terminal alone answered
/// the shared 503 although a fallback would have answered.
#[tokio::test]
async fn the_first_link_that_answers_decides_before_the_terminal() {
    let facts = tool_call();
    let abstains = abstaining();
    let gates = chained(
        Arc::new(Broken),
        vec![
            link(Arc::new(Broken), false, false),
            link(abstains.clone(), false, false),
        ],
        crate::config::PolicyOnError::Reject,
        false,
        false,
    );
    assert!(
        matches!(
            decide(&gates, &subject_on(&facts, "filesystem")).await,
            GateVerdict::Proceed
        ),
        "the second link answered: the terminal does not decide"
    );
    assert!(
        abstains.seen.lock().unwrap().is_some(),
        "the second link was asked"
    );

    // Every link failing lands on the terminal: the shared refusal.
    let gates = chained(
        Arc::new(Broken),
        vec![link(Arc::new(Broken), false, false)],
        crate::config::PolicyOnError::Reject,
        false,
        false,
    );
    match decide(&gates, &subject_on(&facts, "filesystem")).await {
        GateVerdict::Reject { status, .. } => {
            assert_eq!(status, crate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS);
        }
        GateVerdict::Proceed => panic!("every link failed: the reject terminal refuses"),
    }
}

/// A CLEARANCE IS BOUND TO THE CONTAINER (audit Q128 p15#2): a piece one hook cleared for the
/// caller's session on container A is screened again when the same caller sends it to container B,
/// which the same hook guards (its verdict may read `pool`); on A it is still skipped. RED before:
/// the cleared set was keyed by the hook alone, so B's call was skipped unscreened.
#[tokio::test]
async fn a_piece_cleared_on_one_container_is_screened_again_on_another() {
    let store = SessionStore::new(64, None);
    let session = SessionKey(4242);
    let facts = tool_call();
    let spy = abstaining();
    let gates = gate(
        spy.clone(),
        crate::config::PolicyOnError::Weighted,
        true,
        false,
    );
    let on = |container: &'static str| GateSubject {
        incremental: Some(IncrementalScan {
            store: &store,
            session,
            now_ms: 0,
        }),
        ..subject_on(&facts, container)
    };
    let fired = || spy.seen.lock().unwrap().take().is_some();

    assert!(matches!(
        decide(&gates, &on("server-a")).await,
        GateVerdict::Proceed
    ));
    assert!(fired(), "a new piece is screened on A");
    assert!(matches!(
        decide(&gates, &on("server-a")).await,
        GateVerdict::Proceed
    ));
    assert!(!fired(), "cleared on A: not screened again on A");
    assert!(matches!(
        decide(&gates, &on("server-b")).await,
        GateVerdict::Proceed
    ));
    assert!(fired(), "a clearance on A is not a clearance on B");
}

/// One door request over `projected`, the plane's own fields `plane`.
fn door_on<'a>(projected: Option<&'a [u8]>, plane: DoorShape<'a>) -> DoorSubject<'a> {
    DoorSubject {
        projected,
        container: "entry",
        dialect: "door-dialect",
        request_id: 1,
        key: None,
        session: None,
        scan: None,
        plane,
        reads: &no_reads,
    }
}

/// A DOOR BODY THE GATE CANNOT READ IS NOT EMPTY CONTENT (audit Q128 p15#3; THE DESIGN Appendix
/// B.9 l.5436-5437). A plane that states no body, or one that is not JSON, gives a content-granted
/// gate nothing to screen: it is a gate that could not answer, and its `on_error` decides (here
/// `reject`, the shared refusal), never a gate shown `null` that abstains. A shape-only gate reads
/// no content and still fires. RED before: both bodies were screened as an unnamed call with
/// `null` arguments, the spy abstained, and the unit proceeded.
#[tokio::test]
async fn an_unreadable_door_body_applies_a_content_gates_on_error() {
    for body in [None, Some(&b"\xff not json"[..])] {
        let spy = abstaining();
        let gates = gate(
            spy.clone(),
            crate::config::PolicyOnError::Reject,
            true,
            false,
        );
        match decide_door(
            &gates,
            &door_on(body, DoorShape::default()),
            &mut Vec::new(),
        )
        .await
        {
            GateVerdict::Reject { status, .. } => {
                assert_eq!(status, crate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS);
            }
            GateVerdict::Proceed => panic!("a content gate passed a body it never saw: {body:?}"),
        }
        assert!(
            spy.seen.lock().unwrap().is_none(),
            "the gate was not shown empty content"
        );

        let shape_only = abstaining();
        let gates = gate(
            shape_only.clone(),
            crate::config::PolicyOnError::Reject,
            false,
            false,
        );
        assert!(matches!(
            decide_door(
                &gates,
                &door_on(body, DoorShape::default()),
                &mut Vec::new()
            )
            .await,
            GateVerdict::Proceed
        ));
        assert!(
            shape_only.seen.lock().unwrap().is_some(),
            "a shape-only gate fires"
        );
    }
}

/// A door body that is JSON but not the invoke document is screened WHOLE, never as `null`; and
/// the plane's own `max_tokens`, stream flag and end user reach the hook's view (THE DESIGN
/// Appendix B.9 l.5436-5437). RED before: the content was `null` and the plane's fields were
/// dropped for the kernel's own reading.
#[tokio::test]
async fn a_door_gate_sees_the_planes_document_and_the_planes_own_fields() {
    let spy = abstaining();
    let gates = gate(
        spy.clone(),
        crate::config::PolicyOnError::Reject,
        true,
        true,
    );
    let plane = DoorShape {
        max_tokens: Some(64),
        stream: true,
        end_user: Some("end-user-1"),
    };
    let body = br#"{"message":{"text":"the secret"}}"#;
    assert!(matches!(
        decide_door(&gates, &door_on(Some(&body[..]), plane), &mut Vec::new()).await,
        GateVerdict::Proceed
    ));
    let seen = spy
        .seen
        .lock()
        .unwrap()
        .clone()
        .expect("the gate was fired");
    let request = &seen["request"];
    assert!(
        request["messages"].to_string().contains("the secret"),
        "the plane's document is screened whole: {seen}"
    );
    assert_eq!(request["max_tokens"], 64, "{seen}");
    assert_eq!(request["stream"], true, "{seen}");
    assert_eq!(request["user"]["user"], "end-user-1", "{seen}");
}

/// THE HOOKS APPLIED INCLUDE THE `on_error` WALK (THE DESIGN §1: the audit record's "controls (...
/// hooks applied)"; §11.7 l.1357-1358, the chain is 1.5.5's): a failed gate is recorded first, its
/// head what its chain made of it and its failure kept, then every link the walk asked, in order,
/// each as it ran. One record: the list the gate pushes is the one the hook report carries.
#[tokio::test]
async fn the_hooks_applied_carry_the_failed_gate_and_every_link_its_walk_asked() {
    use busbar_kernel_audit::record::{HookApplied, HookHead};
    let ran_as = |hook: &str, head: HookHead, failed: bool| HookApplied {
        hook: hook.to_string(),
        head,
        failed,
    };

    // A broken link is passed over; the next link abstains: the unit proceeds.
    let gates = chained(
        Arc::new(Broken),
        vec![
            link(Arc::new(Broken), false, false),
            link(abstaining(), false, false),
        ],
        crate::config::PolicyOnError::Reject,
        false,
        false,
    );
    let mut ran = Vec::new();
    assert!(matches!(
        decide_door(
            &gates,
            &door_on(Some(PROJECTED), DoorShape::default()),
            &mut ran
        )
        .await,
        GateVerdict::Proceed
    ));
    assert_eq!(
        ran,
        vec![
            ran_as("broken", HookHead::Pass, true),
            ran_as("broken", HookHead::Pass, true),
            ran_as("spy", HookHead::Pass, false),
        ]
    );

    // A link that rejects closes the failed gate: both carry the veto.
    let gates = chained(
        Arc::new(Broken),
        vec![link(
            spying(RoutingDecision::Reject {
                status: 403,
                message: "fallback screened".to_string(),
            }),
            false,
            false,
        )],
        crate::config::PolicyOnError::Weighted,
        false,
        false,
    );
    let mut ran = Vec::new();
    assert!(matches!(
        decide_door(
            &gates,
            &door_on(Some(PROJECTED), DoorShape::default()),
            &mut ran
        )
        .await,
        GateVerdict::Reject { .. }
    ));
    assert_eq!(
        ran,
        vec![
            ran_as("broken", HookHead::Veto, true),
            ran_as("spy", HookHead::Veto, false),
        ]
    );
}
