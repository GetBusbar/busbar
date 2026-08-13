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
use crate::ir::invoke::InvokeReq;
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

fn key() -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
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
    }
}

/// THE PROJECTION, WHOLE. What a `prompt: ro` + `user: ro` gate is handed for one MCP `tools/call`
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
            ingress_protocol: "mcp",
            request_id: 7,
            key: Some(&k),
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
                // The CONTAINER, which on this plane is the registered MCP server.
                "pool": "filesystem",
                "ingress_protocol": "mcp",
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
            ingress_protocol: "mcp",
            request_id: 1,
            key: Some(&key()),
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
                ingress_protocol: "mcp",
                request_id: 1,
                key: None,
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
        ingress_protocol: "mcp",
        request_id: 1,
        key: None,
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
    impl crate::ir::facts::IrFacts for Counting {
        fn verb(&self) -> crate::operation::Operation {
            crate::operation::Operation::Invoke
        }
        fn wants_stream(&self) -> bool {
            false
        }
        fn end_user(&self) -> Option<&str> {
            None
        }
        fn shape(&self) -> crate::ir::facts::Shape {
            crate::ir::facts::IrFacts::shape(&self.inner)
        }
        fn content(&self) -> Vec<crate::ir::facts::ContentItem<'_>> {
            self.walks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            crate::ir::facts::IrFacts::content(&self.inner)
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
            ingress_protocol: "mcp",
            request_id: 1,
            key: None,
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
