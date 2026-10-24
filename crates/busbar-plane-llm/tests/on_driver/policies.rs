// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.5.5 hook tests' own in-process policies: a capturing policy, a canned gate, a rewriting
//! gate, an erroring policy and a capturing tap.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::hooks::{
    Candidate, PolicyResult, RewriteReply, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest, TransformOutcome,
};
use busbar_kernel::config::PolicyOnError;
use busbar_kernel::hooks::{ResolvedPolicy, TapEntry};
use serde_json::Value;

/// The prompt as the policy saw it: (flattened system, [(role, text)]).
pub type SeenPrompt = (Option<String>, Vec<(String, String)>);
/// The identity as the policy saw it: (key_id, key_name, end-user).
pub type SeenIdentity = (Option<String>, Option<String>, Option<String>);

/// What the policy saw through the seam.
#[derive(Clone, Default, Debug)]
pub struct CapturedReq {
    pub prompt: Option<SeenPrompt>,
    pub identity: Option<SeenIdentity>,
    pub max_tokens: Option<u32>,
    pub message_count: usize,
    pub total_chars: usize,
    pub request_id: u64,
}

/// A policy that records the projection it was handed and returns a fixed decision.
pub struct CapturingPolicy {
    pub seen: Arc<Mutex<Option<CapturedReq>>>,
    pub reject: Option<(u16, String)>,
}

#[async_trait::async_trait]
impl RoutingPolicy for CapturingPolicy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        *self.seen.lock().unwrap() = Some(CapturedReq {
            prompt: req.prompt.as_ref().map(|p| {
                (
                    p.system.as_deref().map(str::to_string),
                    p.messages
                        .iter()
                        .map(|(r, t)| (r.to_string(), t.to_string()))
                        .collect(),
                )
            }),
            identity: req
                .identity
                .as_ref()
                .map(|i| (i.key_id.clone(), i.key_name.clone(), i.user.clone())),
            max_tokens: req.max_tokens,
            message_count: req.message_count,
            total_chars: req.total_chars,
            request_id: req.request_id,
        });
        Ok(match &self.reject {
            Some((status, message)) => RoutingDecision::Reject {
                status: *status,
                message: message.clone(),
            },
            None => RoutingDecision::Abstain,
        })
    }
    fn name(&self) -> &'static str {
        "capture"
    }
}

/// A capturing policy as a resolved hook, with the grants given.
pub fn capturing(
    send_prompt: bool,
    send_user: bool,
    reject: Option<(u16, String)>,
) -> (Arc<Mutex<Option<CapturedReq>>>, ResolvedPolicy) {
    let seen = Arc::new(Mutex::new(None));
    (
        seen.clone(),
        ResolvedPolicy::Policy {
            policy: Arc::new(CapturingPolicy { seen, reject }),
            on_error: PolicyOnError::default(),
            on_error_chain: Vec::new(),
            timeout: Duration::from_millis(500),
            send_prompt,
            send_user,
            on_empty: PolicyOnError::Reject,
        },
    )
}

/// A canned decision.
pub enum Canned {
    Order(Vec<usize>),
    Restrict(Vec<String>),
    Reject(u16, &'static str),
}

/// A gate returning a fixed decision.
pub struct CannedGate {
    pub canned: Canned,
    pub name: &'static str,
}

#[async_trait::async_trait]
impl RoutingPolicy for CannedGate {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(match &self.canned {
            Canned::Order(order) => RoutingDecision::Prefer(order.clone()),
            Canned::Restrict(tags) => RoutingDecision::Restrict {
                tags_any: tags.clone(),
            },
            Canned::Reject(status, message) => RoutingDecision::Reject {
                status: *status,
                message: (*message).to_string(),
            },
        })
    }
    fn name(&self) -> &'static str {
        self.name
    }
}

/// A canned decision as a resolved gate (shape-only, fail-closed defaults).
pub fn canned_gate(canned: Canned, name: &'static str) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy: Arc::new(CannedGate { canned, name }),
        on_error: PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: PolicyOnError::Reject,
    }
}

/// A rewrite gate: abstains as a decision, rewrites the messages on transform.
pub struct RewritingGate(pub Vec<Value>);

#[async_trait::async_trait]
impl RoutingPolicy for RewritingGate {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "rewriter"
    }
    async fn transform(&self, _req: &RoutingRequest<'_>, _budget: Duration) -> TransformOutcome {
        TransformOutcome::Rewrite(RewriteReply {
            messages: self.0.clone(),
            tools: vec![],
        })
    }
}

/// A rewrite gate replacing the turns with one user turn.
pub fn rewriting(content: &str) -> (Duration, Arc<dyn RoutingPolicy>) {
    (
        Duration::from_millis(500),
        Arc::new(RewritingGate(vec![
            serde_json::json!({"role": "user", "content": content}),
        ])),
    )
}

/// A policy whose decide always errors.
pub struct ErroringPolicy;

#[async_trait::async_trait]
impl RoutingPolicy for ErroringPolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Err("deliberately broken".into())
    }
    fn name(&self) -> &'static str {
        "erroring"
    }
}

/// A tap whose `notify` records the delivered projection.
pub struct CaptureTap {
    pub last: Mutex<Option<Vec<u8>>>,
}

#[async_trait::async_trait]
impl RoutingPolicy for CaptureTap {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _cands: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "capture-tap"
    }
    async fn notify(
        &self,
        tap: Arc<busbar_contract::abi::host::hook::NotifyFrame>,
        _budget: Duration,
    ) {
        let projection = serde_json::to_vec(&tap.projection_json()).expect("the tap's JSON");
        *self.last.lock().unwrap() = Some(projection);
    }
}

/// An in-process tap capture and its tap entry.
pub fn webhook_tap() -> (Arc<CaptureTap>, TapEntry) {
    let cap = Arc::new(CaptureTap {
        last: Mutex::new(None),
    });
    let policy: Arc<dyn RoutingPolicy> = cap.clone();
    (cap, (Duration::from_millis(500), false, policy, Vec::new()))
}

/// The tap's delivered projection (taps are detached tasks).
pub async fn wait_for_tap_body(cap: &CaptureTap) -> Value {
    for _ in 0..200 {
        if let Some(body) = cap.last.lock().unwrap().clone() {
            return serde_json::from_slice(&body).expect("tap payload is JSON");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("tap was never delivered");
}
