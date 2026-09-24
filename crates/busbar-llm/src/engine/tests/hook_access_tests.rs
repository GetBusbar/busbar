//! A hook plugin handed a request's content leaves exactly ONE access amendment on the node journal,
//! through the kernel's one seam (`audit::amend::hook_read`), at every call site this plane fires a
//! hook from: the decision gate, its on_error fallback chain, the rewrite pass, and the global tap.
//! A hook handed only the request's shape leaves none.
//!
//! The node journal is process-wide, so every hook here carries a name no other test uses and each
//! assertion counts that name's accesses only.
use super::*;
use crate::engine::WeightedLane;
use crate::test_support::{LaneSpec, TestApp};
use busbar_api::{Candidate, PolicyResult, RoutingContext, RoutingDecision, RoutingRequest};
use busbar_kernel::{
    audit::amend::{node_recent, Access, AmendBody, Reader},
    config::PolicyOnError,
    hooks::{FallbackHook, ResolvedPolicy},
};

/// Every hook access the node journal holds for `name`.
fn accesses(name: &str) -> Vec<Access> {
    node_recent()
        .into_iter()
        .filter_map(|a| match a.body {
            AmendBody::Access(access) if access.reader == Reader::Hook && access.name == name => {
                Some(access)
            }
            _ => None,
        })
        .collect()
}

/// A hook that abstains on decide, rewrites nothing, and swallows a tap: only its name matters.
struct Named {
    name: &'static str,
    fails: bool,
}

#[async_trait::async_trait]
impl busbar_api::RoutingPolicy for Named {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        if self.fails {
            return Err("deliberately broken".into());
        }
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        self.name
    }
    async fn transform(
        &self,
        _req: &RoutingRequest<'_>,
        _budget: std::time::Duration,
    ) -> busbar_api::TransformOutcome {
        busbar_api::TransformOutcome::Abstain
    }
}

fn named(name: &'static str) -> Arc<dyn busbar_api::RoutingPolicy> {
    Arc::new(Named { name, fails: false })
}

fn body() -> Value {
    serde_json::json!({
        "model": "m0",
        "system": "sys prompt",
        "metadata": {"user_id": "alice"},
        "messages": [{"role": "user", "content": "hello"}]
    })
}

async fn decide(resolved: ResolvedPolicy) -> PolicyOutcome {
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://localhost",
        ))
        .pool("p", &[(0, 1)])
        .build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    let cands = vec![WeightedLane {
        reasoning: None,
        idx: 0,
        weight: 1,
        attempt_timeout_ms: None,
    }];
    decide_policy_order(
        &host,
        &rt,
        &resolved,
        &cands,
        &RequestCtx::new(60, 1),
        &body(),
        &[],
        crate::engine::APPLICATION_JSON,
        "p",
        "anthropic",
        busbar_api::operation::Operation::CHAT,
        false,
        None,
        None,
    )
    .await
}

fn policy(
    primary: Arc<dyn busbar_api::RoutingPolicy>,
    send_prompt: bool,
    send_user: bool,
    on_error_chain: Vec<FallbackHook>,
) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy: primary,
        on_error: PolicyOnError::Weighted,
        on_error_chain,
        timeout: std::time::Duration::from_millis(500),
        send_prompt,
        send_user,
        on_empty: PolicyOnError::Reject,
    }
}

#[tokio::test]
async fn a_decision_gate_handed_the_prompt_leaves_exactly_one_access_amendment() {
    crate::testkit::install_test_seams();
    decide(policy(
        named("access-decide-prompt"),
        true,
        true,
        Vec::new(),
    ))
    .await;
    let seen = accesses("access-decide-prompt");
    assert_eq!(seen.len(), 1, "one access per hand-over: {seen:?}");
    assert_eq!(seen[0].op_class.as_str(), "anthropic");
    assert_eq!(
        seen[0].fields,
        vec!["content".to_string(), "identity".to_string()],
        "field NAMES that crossed, never their values"
    );
}

#[tokio::test]
async fn a_decision_gate_handed_only_the_shape_leaves_no_access_amendment() {
    crate::testkit::install_test_seams();
    decide(policy(
        named("access-decide-shape"),
        false,
        true,
        Vec::new(),
    ))
    .await;
    assert!(accesses("access-decide-shape").is_empty());
}

#[tokio::test]
async fn an_on_error_fallback_handed_the_prompt_leaves_its_own_access_amendment() {
    crate::testkit::install_test_seams();
    let primary: Arc<dyn busbar_api::RoutingPolicy> = Arc::new(Named {
        name: "access-primary-fails",
        fails: true,
    });
    let fallback = |name, send_prompt| FallbackHook {
        policy: named(name),
        timeout: std::time::Duration::from_millis(500),
        send_prompt,
        send_user: false,
        on_empty: PolicyOnError::Reject,
    };
    // The primary fails, so its one granted fallback runs and is handed the prompt too.
    decide(policy(
        primary,
        true,
        false,
        vec![fallback("access-fallback-prompt", true)],
    ))
    .await;
    assert_eq!(accesses("access-primary-fails").len(), 1);
    let seen = accesses("access-fallback-prompt");
    assert_eq!(
        seen.len(),
        1,
        "the fallback was handed the prompt: {seen:?}"
    );
    assert_eq!(seen[0].fields, vec!["content".to_string()]);
}

#[tokio::test]
async fn an_on_error_fallback_without_the_prompt_grant_leaves_no_access_amendment() {
    crate::testkit::install_test_seams();
    let primary: Arc<dyn busbar_api::RoutingPolicy> = Arc::new(Named {
        name: "access-primary-fails-2",
        fails: true,
    });
    decide(policy(
        primary,
        true,
        false,
        vec![FallbackHook {
            policy: named("access-fallback-shape"),
            timeout: std::time::Duration::from_millis(500),
            send_prompt: false,
            send_user: false,
            on_empty: PolicyOnError::Reject,
        }],
    ))
    .await;
    assert!(accesses("access-fallback-shape").is_empty());
}

#[tokio::test]
async fn a_rewrite_hook_handed_the_prompt_leaves_exactly_one_access_amendment() {
    crate::testkit::install_test_seams();
    let hooks = vec![(
        std::time::Duration::from_millis(500),
        named("access-rewrite"),
    )];
    let mut v = body();
    let (host, _rt) = crate::engine::test_host_rt(&TestApp::new().build());
    apply_global_rewrites(
        &*host,
        &hooks,
        &mut v,
        "p",
        "anthropic",
        busbar_api::operation::Operation::CHAT,
        false,
        1,
    )
    .await
    .expect("an abstaining rewrite rejects nothing");
    let seen = accesses("access-rewrite");
    assert_eq!(seen.len(), 1, "one access per hand-over: {seen:?}");
    assert_eq!(seen[0].fields, vec!["content".to_string()]);
}

#[tokio::test]
async fn a_global_tap_leaves_an_access_amendment_only_when_handed_the_prompt() {
    crate::testkit::install_test_seams();
    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .build();
    let ms = std::time::Duration::from_millis(500);
    Arc::get_mut(&mut app).expect("sole owner").tap_hooks = vec![
        (ms, true, named("access-tap-prompt"), Vec::new()),
        (ms, false, named("access-tap-shape"), Vec::new()),
    ];
    let body = serde_json::to_vec(&serde_json::json!({
        "model": "p",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 10
    }))
    .unwrap();
    let _ = forward_with_pool(
        &app,
        vec![WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "p",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(accesses("access-tap-prompt").len(), 1);
    assert!(accesses("access-tap-shape").is_empty());
}
