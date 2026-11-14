// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHICH POLICIES READ THE REQUEST (hook screening, canonical forwarding, G2): only a built-in
//! ranking strategy, sent no prompt and given no fallback chain, is content-blind.

use super::*;

struct Ranks;

#[async_trait::async_trait]
impl RoutingPolicy for Ranks {
    async fn decide(
        &self,
        _: &RoutingRequest<'_>,
        _: &[Candidate<'_>],
        _: &RoutingContext<'_>,
        _: std::time::Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "ranks"
    }
}

fn link() -> FallbackHook {
    FallbackHook {
        policy: Arc::new(Ranks),
        timeout: std::time::Duration::from_secs(1),
        send_prompt: false,
        send_user: false,
        on_empty: crate::config::PolicyOnError::Reject,
    }
}

fn policy(content_blind: bool, send_prompt: bool, chained: bool) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy: Arc::new(Ranks),
        on_error: crate::config::PolicyOnError::default(),
        on_error_chain: if chained { vec![link()] } else { Vec::new() },
        timeout: std::time::Duration::from_secs(1),
        send_prompt,
        send_user: false,
        on_empty: crate::config::PolicyOnError::Reject,
        content_blind,
    }
}

#[test]
fn reads_request_truth_table() {
    for content_blind in [false, true] {
        for send_prompt in [false, true] {
            for chained in [false, true] {
                let blind = content_blind && !send_prompt && !chained;
                assert_eq!(
                    policy(content_blind, send_prompt, chained).reads_request(),
                    !blind,
                    "content_blind {content_blind}, send_prompt {send_prompt}, chain {chained}"
                );
            }
        }
    }
}

#[test]
fn ranked_policy_is_content_blind() {
    // `resolve_policy` and `try_resolve_pool_ordering` both answer a built-in strategy through
    // `ranked_policy`, and nothing else constructs a content-blind policy.
    let ranked = ranked_policy(Arc::new(Ranks), std::time::Duration::from_secs(1));
    assert!(!ranked.reads_request(), "a ranking strategy only observes");
    let ResolvedPolicy::Policy {
        content_blind,
        send_prompt,
        send_user,
        on_error_chain,
        ..
    } = &ranked;
    assert!(*content_blind && !*send_prompt && !*send_user && on_error_chain.is_empty());
}
