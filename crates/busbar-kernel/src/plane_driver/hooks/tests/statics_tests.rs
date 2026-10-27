// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KEPT STATIC CANDIDATE HALF (Q128 contract C7): a `decide` reuses the static half of a
//! candidate set it was already handed, and a reload that changes the candidates is never answered
//! with the old ones.

use super::*;
use busbar_contract::abi::hook::{DecideOut, TransformOut};
use busbar_contract::hook_calls::Pending;
use busbar_contract::hook_wire::OP_DECIDE;
use busbar_contract::SignalBag;
use std::sync::Mutex;

/// A hook that writes down the models of every candidate set it was asked to rank, and abstains.
#[derive(Default)]
struct Seen(Mutex<Vec<Vec<String>>>);

impl HookCalls for Seen {
    fn name(&self) -> &str {
        "c7-seen"
    }
    fn decide(&self, frame: Arc<DecideFrame>, _: Duration) -> Pending<Answered<DecideOut>> {
        let models = frame.projection_json(OP_DECIDE)["candidates"]
            .as_array()
            .map(|cs| {
                cs.iter()
                    .map(|c| c["model"].as_str().unwrap_or_default().to_string())
                    .collect()
            })
            .unwrap_or_default();
        self.0.lock().unwrap().push(models);
        // The answer is built inside the future: an out-record holds the call's raw out-pointers
        // and is not `Send`, so a future that carries a built one is not either.
        Box::pin(async move {
            let (outcome, out) =
                frame.answer_decide(&busbar_contract::abi::sdk::hook::Verdict::Abstain);
            Answered::Answer {
                outcome,
                out,
                error: None,
                frame,
            }
        })
    }
    fn transform(&self, _: Arc<DecideFrame>, _: Duration) -> Pending<Answered<TransformOut>> {
        Box::pin(async { Answered::TimedOut })
    }
    fn notify(&self, _: Arc<NotifyFrame>, _: Duration) -> Pending<()> {
        Box::pin(std::future::ready(()))
    }
    fn configure(&self, _: &str, _: &str, _: u64, _: Duration) -> Pending<Result<(), String>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn status(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(std::future::ready(None))
    }
    fn describe(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(std::future::ready(None))
    }
}

fn candidate(model: &str) -> Candidate<'_> {
    Candidate {
        idx: 0,
        model,
        provider: "prov",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
        signals: SignalBag::new(),
    }
}

fn request() -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "c7-pool",
        ingress_protocol: "",
        requested_model: None,
        message_count: 0,
        tool_count: 0,
        has_tools: false,
        total_chars: 0,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: SignalBag::new(),
        session: None,
    }
}

/// The same candidates reuse one static half; a reload that renames the candidate's model is
/// answered with the new model, and switching back is answered with the old one again, never a
/// stale set. RED before the fix: there was no kept half to reuse (every call built its own).
#[tokio::test]
async fn after_a_reload_the_hook_sees_the_new_candidates_never_stale_ones() {
    let seen = Arc::new(Seen::default());
    let policy = HookPolicy {
        calls: seen.clone(),
        name: "c7-seen".into(),
        statics: std::sync::Mutex::new(Vec::new()),
    };
    let ctx = RoutingContext {
        pool: "c7-pool",
        budget_remaining: None,
        budget: &[],
    };
    let budget = Duration::from_secs(5);
    let old = [candidate("m-old")];
    let new = [candidate("m-new")];
    assert!(
        Arc::ptr_eq(&policy.statics_for(&old), &policy.statics_for(&old)),
        "the same candidates reuse their static half"
    );
    for set in [&old, &new, &old] {
        policy
            .decide(&request(), set, &ctx, budget)
            .await
            .expect("the hook answers");
    }
    assert_eq!(
        *seen.0.lock().unwrap(),
        vec![vec!["m-old"], vec!["m-new"], vec!["m-old"]],
        "each call was answered over the candidates it was handed"
    );
}
