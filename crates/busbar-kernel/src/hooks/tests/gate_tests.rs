// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::hooks::gate::{decide_over, GateSubject, GateVerdict};
use crate::hooks::{
    Candidate, PolicyResult, ResolvedPolicy, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest,
};
use busbar_contract::ir::invoke::InvokeReq;
use std::sync::{Arc, Mutex};

#[test]
fn projected_invocations_keep_exact_arguments_and_unnamed_documents() {
    use serde_json::json;
    let named = super::read_projected(Some(
        br#"{"tool":"private-tool","arguments":{"private-key":["private-value"]},"unused":{"private":"discarded"}}"#,
    ))
    .unwrap();
    assert_eq!(named.tool, "private-tool");
    assert_eq!(named.arguments, json!({"private-key": ["private-value"]}));
    assert!(named.extra.is_empty());

    let unnamed = super::read_projected(Some(br#"{"private-key":["private-value"]}"#)).unwrap();
    assert!(unnamed.tool.is_empty());
    assert_eq!(unnamed.arguments, json!({"private-key": ["private-value"]}));
    assert!(super::read_projected(None).is_none());
    assert!(super::read_projected(Some(b"invalid JSON")).is_none());
}

fn no_reads(_: &str, _: Option<&str>, _: &str, _: bool) {}

async fn decide(gates: &[(u16, ResolvedPolicy)], subject: &GateSubject<'_>) -> GateVerdict {
    decide_over(gates, subject, true, &mut Vec::new()).await
}

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

fn reply_gate(reply: serde_json::Value) -> Arc<dyn RoutingPolicy> {
    double_gate("raw_decide_reply", reply)
}

fn double_gate(key: &str, value: serde_json::Value) -> Arc<dyn RoutingPolicy> {
    let env = crate::test_support::test_hook_env(&["reply-gate"], Default::default());
    let mut settings = crate::config::secret::ResolvedSettings::default();
    settings.map_mut().insert(key.into(), value);
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

#[tokio::test]
async fn a_well_formed_reject_still_rejects() {
    let facts = tool_call();
    let gates = gate(
        reply_gate(serde_json::json!({ "reject": { "status": 451, "message": "no" } })),
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

#[tokio::test]
async fn an_invocation_is_projected_whole() {
    let _lock = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
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

#[tokio::test]
async fn a_reject_stops_the_request_with_the_shared_clamp_and_sanitizer() {
    let facts = tool_call();

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

use crate::hooks::gate::IncrementalScan;
use crate::session::{SessionKey, SessionStore};

fn derive_session_key(sid: &str, principal_id: &str, hook_generation: u64) -> SessionKey {
    IncrementalScan::derive_session_key_octets(sid.as_bytes(), principal_id, hook_generation)
}

#[tokio::test]
async fn incremental_scan_skips_a_piece_already_cleared_this_session() {
    let _lock = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
    let store = SessionStore::new(64, None);
    let session = SessionKey(999);
    let facts = tool_call();

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

#[tokio::test]
async fn a_rejected_piece_is_not_cached_and_is_rescreened() {
    let store = SessionStore::new(64, None);
    let session = SessionKey(7);
    let facts = tool_call();

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

#[test]
fn derive_session_key_partitions_by_principal_and_generation() {
    let base = derive_session_key("sid", "alice", 1);

    assert_eq!(base, derive_session_key("sid", "alice", 1));

    assert_ne!(base, derive_session_key("sid", "bob", 1));

    assert_ne!(base, derive_session_key("sid", "alice", 2));

    assert_ne!(
        derive_session_key("b", "a", 1),
        derive_session_key("", "ab", 1),
    );
}

#[tokio::test]
async fn incremental_scan_reclears_across_principal_and_generation() {
    let _lock = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
    let store = SessionStore::new(64, None);
    let facts = tool_call();
    let sid = "shared-session";

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

    assert!(
        turn(&store, &facts, alice_g1).await,
        "first sight is screened"
    );

    assert!(
        !turn(&store, &facts, alice_g1).await,
        "re-cleared for the same principal + generation"
    );

    assert!(
        turn(&store, &facts, bob_g1).await,
        "a different principal on the same session id must re-screen (confused-deputy fix)"
    );

    assert!(
        turn(&store, &facts, alice_g2).await,
        "a policy-generation bump must invalidate the clearance (stale-clearance fix)"
    );
}

use crate::audit::amend;

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

#[tokio::test]
async fn a_gate_handed_content_leaves_exactly_one_access_amendment() {
    let facts = tool_call();
    let k = key();

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

const PROJECTED: &[u8] = br#"{"tool":"lookup","arguments":{"query":{"parts":[{"text":"hi"}]}}}"#;

#[tokio::test]
async fn the_door_paths_incremental_scan_keys_on_the_views_session() {
    let _lock = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
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

struct CeilingChangingSpy {
    spy: Arc<Spy>,
    next_ceiling: usize,
}

#[async_trait::async_trait]
impl RoutingPolicy for CeilingChangingSpy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: std::time::Duration,
    ) -> PolicyResult {
        crate::hooks::set_hook_content_max_bytes(self.next_ceiling);
        self.spy.decide(req, candidates, ctx, budget).await
    }

    fn name(&self) -> &str {
        RoutingPolicy::name(self.spy.as_ref())
    }
}

#[tokio::test]
async fn incremental_door_clearance_tracks_the_delivered_prompt_across_ceiling_changes() {
    let _lock = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
    struct Restore(usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::hooks::set_hook_content_max_bytes(self.0);
        }
    }
    let _restore = Restore(crate::hooks::hook_content_max_bytes());
    const OMIT_CONTENT_CEILING_BYTES: usize = 1;
    const RETAIN_CONTENT_CEILING_BYTES: usize = PROJECTED.len();
    const SESSION_CAPACITY: usize = 1;
    const HOOK_GENERATION: u64 = 1;
    const SESSION: &[u8] = b"ceiling-session";

    for on_error in [
        crate::config::PolicyOnError::Weighted,
        crate::config::PolicyOnError::First,
        crate::config::PolicyOnError::Reject,
    ] {
        for (ceiling, next_ceiling, delivered) in [
            (
                OMIT_CONTENT_CEILING_BYTES,
                crate::hooks::DEFAULT_HOOK_CONTENT_MAX_BYTES,
                false,
            ),
            (
                RETAIN_CONTENT_CEILING_BYTES,
                OMIT_CONTENT_CEILING_BYTES,
                true,
            ),
        ] {
            let store = SessionStore::new(SESSION_CAPACITY, None);
            let spy = abstaining();
            let gates = gate(spy.clone(), on_error.clone(), true, false);
            let mut door = door_on(Some(PROJECTED), DoorShape::default());
            door.session = Some(SESSION);

            crate::hooks::set_hook_content_max_bytes(crate::hooks::DEFAULT_HOOK_CONTENT_MAX_BYTES);
            assert!(matches!(
                decide_door(&gates, &door, &mut Vec::new()).await,
                GateVerdict::Proceed
            ));
            let baseline = spy.seen.lock().unwrap().take().expect("baseline was sent");
            door.scan = Some(ScanSubstrate {
                store: &store,
                generation: HOOK_GENERATION,
                now_ms: 0,
            });
            let changing = gate(
                Arc::new(CeilingChangingSpy {
                    spy: spy.clone(),
                    next_ceiling,
                }),
                on_error.clone(),
                true,
                false,
            );
            crate::hooks::set_hook_content_max_bytes(ceiling);
            assert!(matches!(
                decide_door(&changing, &door, &mut Vec::new()).await,
                GateVerdict::Proceed
            ));
            let seen = spy.seen.lock().unwrap().take().expect("new piece was sent");
            let mut expected = baseline.clone();
            if !delivered {
                expected["request"]["messages"] = serde_json::json!([]);
            }
            assert_eq!(
                seen, expected,
                "ceiling omission preserves the payload and grant"
            );

            crate::hooks::set_hook_content_max_bytes(crate::hooks::DEFAULT_HOOK_CONTENT_MAX_BYTES);
            assert!(matches!(
                decide_door(&gates, &door, &mut Vec::new()).await,
                GateVerdict::Proceed
            ));
            let seen = spy.seen.lock().unwrap().take();
            if delivered {
                assert!(seen.is_none(), "delivered clean content remains cleared");
            } else {
                assert_eq!(
                    seen,
                    Some(baseline),
                    "omitted content must be screened later"
                );
            }
            assert!(matches!(
                decide_door(&gates, &door, &mut Vec::new()).await,
                GateVerdict::Proceed
            ));
            assert!(
                spy.seen.lock().unwrap().is_none(),
                "the clean delivered piece is skipped"
            );
        }
    }
}

#[tokio::test]
async fn incremental_system_clearance_distinguishes_empty_content_from_ceiling_omission() {
    use busbar_contract::ir::facts::{ContentItem, IrFacts, Shape, Slot};
    struct SystemOnly(&'static str);
    impl IrFacts for SystemOnly {
        fn verb(&self) -> crate::operation::OpVerb {
            crate::operation::OpVerb::INVOKE
        }
        fn wants_stream(&self) -> bool {
            false
        }
        fn end_user(&self) -> Option<&str> {
            None
        }
        fn shape(&self) -> Shape {
            Shape {
                text_chars: self.0.chars().count(),
                system_chars: self.0.chars().count(),
                ..Shape::EMPTY
            }
        }
        fn content(&self) -> Vec<ContentItem<'_>> {
            vec![ContentItem::Text {
                author: "system",
                slot: Slot::System,
                text: self.0.into(),
            }]
        }
    }

    let _lock = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
    struct Restore(usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::hooks::set_hook_content_max_bytes(self.0);
        }
    }
    let _restore = Restore(crate::hooks::hook_content_max_bytes());
    const OMIT_SYSTEM_CEILING_BYTES: usize = 1;
    const SESSION_CAPACITY: usize = 1;
    const HOOK_GENERATION: u64 = 1;
    let invoke = tool_call();
    for text in ["", "system content"] {
        let facts = SystemOnly(text);
        let store = SessionStore::new(SESSION_CAPACITY, None);
        let spy = abstaining();
        let gates = gate(
            spy.clone(),
            crate::config::PolicyOnError::Reject,
            true,
            false,
        );
        let subject = GateSubject {
            facts: &facts,
            incremental: Some(IncrementalScan {
                store: &store,
                session: derive_session_key("system-session", "", HOOK_GENERATION),
                now_ms: 0,
            }),
            ..tool_subject(&invoke)
        };
        crate::hooks::set_hook_content_max_bytes(OMIT_SYSTEM_CEILING_BYTES);
        assert!(matches!(
            decide(&gates, &subject).await,
            GateVerdict::Proceed
        ));
        let seen = spy
            .seen
            .lock()
            .unwrap()
            .take()
            .expect("system piece was sent");
        assert!(seen["request"].get("system").is_none());
        assert_eq!(seen["request"]["messages"], serde_json::json!([]));

        crate::hooks::set_hook_content_max_bytes(crate::hooks::DEFAULT_HOOK_CONTENT_MAX_BYTES);
        assert!(matches!(
            decide(&gates, &subject).await,
            GateVerdict::Proceed
        ));
        let seen = spy.seen.lock().unwrap().take();
        if text.is_empty() {
            assert!(
                seen.is_none(),
                "an originally empty system piece remains cleared"
            );
        } else {
            let seen = seen.expect("omitted system content must be screened later");
            assert_eq!(seen["request"]["system"], text);
        }
    }
}

fn spying(reply: RoutingDecision) -> Arc<Spy> {
    Arc::new(Spy {
        reply,
        seen: Mutex::new(None),
    })
}

fn abstaining() -> Arc<Spy> {
    spying(RoutingDecision::Abstain)
}

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

#[tokio::test]
async fn a_piece_cleared_on_one_container_is_screened_again_on_another() {
    let _lock = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
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

#[tokio::test]
async fn a_door_gate_sees_the_planes_document_and_the_planes_own_fields() {
    let _lock = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
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

#[tokio::test]
async fn the_hooks_applied_carry_the_failed_gate_and_every_link_its_walk_asked() {
    use busbar_kernel_audit::record::{HookApplied, HookHead};
    let ran_as = |hook: &str, head: HookHead, failed: bool| HookApplied {
        hook: hook.to_string(),
        head,
        failed,
    };

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

#[tokio::test]
async fn incremental_scan_does_not_skip_a_shape_gate_without_content() {
    use busbar_contract::ir::facts::{IrFacts, NeutralFacts};
    let store = SessionStore::new(64, None);
    let facts = NeutralFacts(tool_call().verb());
    let spy = Arc::new(Spy {
        reply: RoutingDecision::Reject {
            status: 403,
            message: "shape refused".into(),
        },
        seen: Mutex::new(None),
    });
    let gates = gate(
        spy.clone(),
        crate::config::PolicyOnError::Reject,
        false,
        false,
    );
    let verdict = decide(
        &gates,
        &GateSubject {
            facts: &facts,
            container: "filesystem",
            ingress_protocol: "example-protocol",
            request_id: 1,
            key: None,
            session: None,
            incremental: Some(IncrementalScan {
                store: &store,
                session: SessionKey(91),
                now_ms: 0,
            }),
            reads: &no_reads,
        },
    )
    .await;
    assert!(matches!(verdict, GateVerdict::Reject { status: 403, .. }));
    let seen = spy.seen.lock().unwrap().clone().expect("shape gate fired");
    assert!(seen["request"].get("messages").is_none());
    assert!(seen["request"].get("user").is_none());
}

#[tokio::test]
async fn incremental_scan_rechecks_shape_and_identity_with_unchanged_content() {
    let store = SessionStore::new(64, None);
    let body = br#"{"tool":"fs_read","arguments":{"path":"/etc/hosts"}}"#;
    for (max_tokens, stream, end_user, reject) in [
        (32, false, "first-user", false),
        (64, true, "second-user", true),
    ] {
        let spy = Arc::new(Spy {
            reply: if reject {
                RoutingDecision::Reject {
                    status: 403,
                    message: "new shape refused".into(),
                }
            } else {
                RoutingDecision::Abstain
            },
            seen: Mutex::new(None),
        });
        let gates = gate(
            spy.clone(),
            crate::config::PolicyOnError::Reject,
            false,
            true,
        );
        let mut subject = door_on(
            Some(body),
            DoorShape {
                max_tokens: Some(max_tokens),
                stream,
                end_user: Some(end_user),
            },
        );
        subject.session = Some(b"same-session");
        subject.scan = Some(crate::hooks::gate::ScanSubstrate {
            store: &store,
            generation: 1,
            now_ms: 0,
        });
        let verdict = decide_door(&gates, &subject, &mut Vec::new()).await;
        if reject {
            assert!(matches!(verdict, GateVerdict::Reject { status: 403, .. }));
        } else {
            assert!(matches!(verdict, GateVerdict::Proceed));
        }
        let seen = spy
            .seen
            .lock()
            .unwrap()
            .clone()
            .expect("each shape gate fired");
        assert_eq!(seen["request"]["max_tokens"], max_tokens);
        assert_eq!(seen["request"]["stream"], stream);
        assert_eq!(seen["request"]["user"]["user"], end_user);
        assert!(seen["request"].get("messages").is_none());
    }
}
