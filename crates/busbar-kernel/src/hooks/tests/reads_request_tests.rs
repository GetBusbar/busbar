// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHICH POLICIES READ THE REQUEST (hook screening, canonical forwarding, G2): only a built-in
//! ranking strategy, sent no prompt and given no fallback chain, is content-blind. Blindness is
//! the policy's own answer ([`RoutingPolicy::content_blind`]), never a field a constructor sets.

use super::*;
use busbar_contract::abi::hook::{DecideOut, TransformOut};
use busbar_contract::abi::host::hook::{DecideFrame, NotifyFrame};
use busbar_contract::hook_calls::{Answered, HookCalls, Pending};
use std::time::Duration;

/// A policy that answers `content_blind` as told.
struct Ranks(bool);

#[async_trait::async_trait]
impl RoutingPolicy for Ranks {
    async fn decide(
        &self,
        _: &RoutingRequest<'_>,
        _: &[Candidate<'_>],
        _: &RoutingContext<'_>,
        _: Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "ranks"
    }
    fn content_blind(&self) -> bool {
        self.0
    }
}

/// A hook plugin that is never called: the tests only ask the policy built over it what it is.
struct Idle;

impl HookCalls for Idle {
    fn name(&self) -> &str {
        "idle"
    }
    fn decide(&self, _: Arc<DecideFrame>, _: Duration) -> Pending<Answered<DecideOut>> {
        Box::pin(async { Answered::TimedOut })
    }
    fn transform(&self, _: Arc<DecideFrame>, _: Duration) -> Pending<Answered<TransformOut>> {
        Box::pin(async { Answered::TimedOut })
    }
    fn notify(&self, _: Arc<NotifyFrame>, _: Duration) -> Pending<()> {
        Box::pin(std::future::ready(()))
    }
    fn configure(
        &self,
        _: &str,
        _: &busbar_contract::plugin_settings::ResolvedSettings,
        _: u64,
        _: Duration,
    ) -> Pending<Result<(), String>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn status(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(std::future::ready(None))
    }
    fn describe(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(std::future::ready(None))
    }
}

fn link() -> FallbackHook {
    FallbackHook {
        policy: Arc::new(Ranks(true)),
        timeout: Duration::from_secs(1),
        send_prompt: false,
        send_user: false,
        on_empty: crate::config::PolicyOnError::Reject,
    }
}

fn over(policy: Arc<dyn RoutingPolicy>, send_prompt: bool, chained: bool) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy,
        on_error: crate::config::PolicyOnError::default(),
        on_error_chain: if chained { vec![link()] } else { Vec::new() },
        timeout: Duration::from_secs(1),
        send_prompt,
        send_user: false,
        on_empty: crate::config::PolicyOnError::Reject,
    }
}

#[test]
fn reads_request_truth_table() {
    for content_blind in [false, true] {
        for send_prompt in [false, true] {
            for chained in [false, true] {
                let blind = content_blind && !send_prompt && !chained;
                assert_eq!(
                    over(Arc::new(Ranks(content_blind)), send_prompt, chained).reads_request(),
                    !blind,
                    "content_blind {content_blind}, send_prompt {send_prompt}, chain {chained}"
                );
            }
        }
    }
}

#[test]
fn a_policy_is_not_content_blind_unless_it_says_so() {
    struct Silent;
    #[async_trait::async_trait]
    impl RoutingPolicy for Silent {
        async fn decide(
            &self,
            _: &RoutingRequest<'_>,
            _: &[Candidate<'_>],
            _: &RoutingContext<'_>,
            _: Duration,
        ) -> PolicyResult {
            Ok(RoutingDecision::Abstain)
        }
        fn name(&self) -> &'static str {
            "silent"
        }
    }
    assert!(
        !Silent.content_blind(),
        "the trait default reads the request"
    );
    assert!(over(Arc::new(Silent), false, false).reads_request());
}

#[test]
fn ranked_policy_is_content_blind() {
    // `resolve_policy` and `try_resolve_pool_ordering` both answer a built-in strategy with
    // `ranked_policy` over `ranking_on_axis`'s `HookPolicy::ranking`; the same hook opened as a
    // gate transport (`HookPolicy::policy`, no signals, no child, prompt no) still reads.
    let ranking =
        crate::plane_driver::hooks::policy::HookPolicy::ranking(Arc::new(Idle), "cheapest");
    assert!(ranking.content_blind());
    let ranked = ranked_policy(ranking, Duration::from_secs(1));
    assert!(!ranked.reads_request(), "a ranking strategy only observes");
    let ResolvedPolicy::Policy {
        send_prompt,
        send_user,
        on_error_chain,
        ..
    } = &ranked;
    assert!(!*send_prompt && !*send_user && on_error_chain.is_empty());

    let gate =
        crate::plane_driver::hooks::policy::HookPolicy::policy(Arc::new(Idle), "cheapest", &[]);
    assert!(!gate.content_blind());
    assert!(
        over(gate, false, false).reads_request(),
        "a gate transport screens even when it is sent no prompt"
    );
}
