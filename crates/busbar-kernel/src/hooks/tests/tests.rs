use super::*;
use std::collections::HashSet;

#[test]
fn from_ranked_drops_unknown_and_dedups() {
    let valid: HashSet<usize> = [0usize, 1, 2].into_iter().collect();

    let d = RoutingDecision::from_ranked([2usize, 9, 1, 1, 0], &valid);
    assert_eq!(d, RoutingDecision::Prefer(vec![2, 1, 0]));
}

use crate::config::{HookCfg, HookKind, PolicyOnError, PoolPolicy, PromptAccess, UserAccess};
use std::collections::HashMap;

#[path = "resolution_tests.rs"]
mod resolution_tests;

const EXTRA_STRATEGY: &str = "operator-order";

struct ReceivingCalls {
    calls: Arc<dyn busbar_contract::hook_calls::HookCalls>,
    seen: Arc<std::sync::atomic::AtomicUsize>,
    routes: Vec<busbar_contract::abi::mechanism::route::Route>,
}

impl busbar_contract::hook_calls::HookCalls for ReceivingCalls {
    fn name(&self) -> &str {
        "receiver"
    }
    fn routes(&self) -> &[busbar_contract::abi::mechanism::route::Route] {
        &self.routes
    }
    fn serve(
        &self,
        _: busbar_contract::abi::mechanism::endpoint::EndpointRequest,
        _: std::time::Duration,
    ) -> busbar_contract::hook_calls::Pending<
        Result<busbar_contract::abi::mechanism::endpoint::EndpointResponse, String>,
    > {
        self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async {
            Ok(
                busbar_contract::abi::mechanism::endpoint::EndpointResponse {
                    status: 202,
                    headers: Vec::new(),
                    body: Vec::new(),
                },
            )
        })
    }
    fn decide(
        &self,
        _: Arc<busbar_contract::abi::host::hook::DecideFrame>,
        _: std::time::Duration,
    ) -> busbar_contract::hook_calls::Pending<
        busbar_contract::hook_calls::Answered<busbar_contract::abi::hook::DecideOut>,
    > {
        let count = self.seen.load(std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            busbar_contract::hook_calls::Answered::Broken(format!("feedback={count}"))
        })
    }
    fn transform(
        &self,
        f: Arc<busbar_contract::abi::host::hook::DecideFrame>,
        b: std::time::Duration,
    ) -> busbar_contract::hook_calls::Pending<
        busbar_contract::hook_calls::Answered<busbar_contract::abi::hook::TransformOut>,
    > {
        self.calls.transform(f, b)
    }
    fn notify(
        &self,
        f: Arc<busbar_contract::abi::host::hook::NotifyFrame>,
        b: std::time::Duration,
    ) -> busbar_contract::hook_calls::Pending<()> {
        self.calls.notify(f, b)
    }
    fn configure(
        &self,
        n: &str,
        s: &str,
        v: u64,
        b: std::time::Duration,
    ) -> busbar_contract::hook_calls::Pending<Result<(), String>> {
        self.calls.configure(n, s, v, b)
    }
    fn status(
        &self,
        b: std::time::Duration,
    ) -> busbar_contract::hook_calls::Pending<Option<Vec<u8>>> {
        self.calls.status(b)
    }
    fn describe(
        &self,
        b: std::time::Duration,
    ) -> busbar_contract::hook_calls::Pending<Option<Vec<u8>>> {
        self.calls.describe(b)
    }
}

struct ReceivingAxis;

fn receiving_route() -> busbar_contract::abi::mechanism::route::Route {
    busbar_contract::abi::mechanism::route::Route {
        path: "/hooks/receiver/feedback".into(),
        method: busbar_contract::abi::mechanism::route::RouteMethod::Post,
        auth: busbar_contract::abi::mechanism::route::RouteAuth::Key,
    }
}

impl busbar_contract::hook_calls::HookAxis for ReceivingAxis {
    fn routes(
        &self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<Vec<busbar_contract::abi::mechanism::route::Route>, String> {
        Ok(vec![receiving_route()])
    }
    fn probe(
        &self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Option<busbar_contract::hook_calls::Probed> {
        Some((
            Some(busbar_contract::hook_calls::HookFacts {
                name: "receiver".into(),
                ..Default::default()
            }),
            Vec::new(),
        ))
    }
    fn open(
        &self,
        _: &str,
        name: &str,
        _: &serde_json::Value,
        budget: std::time::Duration,
    ) -> Result<Arc<dyn busbar_contract::hook_calls::HookCalls>, String> {
        let calls = crate::test_support::hook_double::HookAxisDouble::new(&["receiver"]).open(
            "receiver",
            name,
            &serde_json::json!({}),
            budget,
        )?;
        Ok(Arc::new(ReceivingCalls {
            calls,
            seen: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            routes: vec![receiving_route()],
        }))
    }
    fn linked(&self, _: &str) -> bool {
        true
    }
    fn first_party(&self, _: &str) -> bool {
        true
    }
    fn call_budget(&self) -> std::time::Duration {
        std::time::Duration::from_secs(1)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_feedback_reaches_the_policy_instance_and_reload_keeps_old_state_separate() {
    let definitions = HashMap::from([(
        "receiver".into(),
        serde_json::from_value::<HookCfg>(
            serde_json::json!({"kind": "gate", "module": "receiver-module"}),
        )
        .unwrap(),
    )]);
    let build = || {
        let mut env = HookEnv::with_axis(
            crate::test_support::rows::empty(),
            Arc::new(ReceivingAxis),
            Arc::new(crate::config::secret::SecretResolver::builtins_only()),
        );
        let routes = env.route_decls(&definitions).unwrap();
        let (policy, _) =
            gate_transport_named("receiver", &definitions["receiver"], &env, 0).unwrap();
        (env, routes, policy)
    };
    let (_old_env, mut old_routes, old_policy) = build();
    let old_dispatch = old_routes.remove(0).dispatch;
    let response = tokio::task::spawn_blocking(move || {
        old_dispatch.handle_http(
            &busbar_contract::abi::mechanism::endpoint::EndpointRequest {
                method: "POST".into(),
                path: receiving_route().path,
                query: String::new(),
                headers: Vec::new(),
                body: Vec::new(),
            },
        )
    })
    .await
    .unwrap();
    assert_eq!(response.status, 202);
    let (_new_env, _new_routes, new_policy) = build();
    let request = RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "x",
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
    };
    let context = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    assert!(old_policy
        .decide(&request, &[], &context, std::time::Duration::from_secs(1))
        .await
        .unwrap_err()
        .to_string()
        .contains("feedback=1"));
    assert!(new_policy
        .decide(&request, &[], &context, std::time::Duration::from_secs(1))
        .await
        .unwrap_err()
        .to_string()
        .contains("feedback=0"));
}

struct StrategyAxis {
    facts: busbar_contract::hook_calls::HookFacts,
    fail_open: bool,
}

impl busbar_contract::hook_calls::HookAxis for StrategyAxis {
    fn probe(
        &self,
        module: &str,
        _: &str,
        settings: &serde_json::Value,
    ) -> Option<busbar_contract::hook_calls::Probed> {
        assert_eq!(module, EXTRA_STRATEGY);
        assert_eq!(settings, &serde_json::json!({"policy": EXTRA_STRATEGY}));
        Some((Some(self.facts.clone()), Vec::new()))
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
        budget: std::time::Duration,
    ) -> Result<Arc<dyn busbar_contract::hook_calls::HookCalls>, String> {
        assert_eq!(module, EXTRA_STRATEGY);
        assert_eq!(label, EXTRA_STRATEGY);
        assert_eq!(settings, &serde_json::json!({"policy": EXTRA_STRATEGY}));
        if self.fail_open {
            return Err("strategy constructor refused".into());
        }

        crate::test_support::hook_double::HookAxisDouble::new(&["strategy-double"]).open(
            "strategy-double",
            label,
            &serde_json::json!({"order": [1, 0]}),
            budget,
        )
    }

    fn linked(&self, _: &str) -> bool {
        false
    }
    fn call_budget(&self) -> std::time::Duration {
        std::time::Duration::from_secs(1)
    }
    fn first_party(&self, _: &str) -> bool {
        false
    }
}

fn strategy_env(infallible: bool, words: Vec<String>, fail_open: bool) -> HookEnv {
    HookEnv::with_axis(
        crate::test_support::rows::empty(),
        Arc::new(StrategyAxis {
            facts: busbar_contract::hook_calls::HookFacts {
                name: "strategy-double".into(),
                class: busbar_contract::abi::hook::CLASS_GATE,
                infallible,
                words,
                ..Default::default()
            },
            fail_open,
        }),
        Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    )
}

#[tokio::test]
async fn plugin_strategy_word_survives_parse_and_uses_the_admitted_axis() {
    let pool = pool_policy(crate::config::parse_strategy(EXTRA_STRATEGY));
    assert_eq!(pool.policy.native_name(), Some(EXTRA_STRATEGY));
    let env = strategy_env(false, vec![EXTRA_STRATEGY.into()], false);
    let resolved = resolve_pool_ordering(&pool, &HashMap::new(), &env, None, 0);
    let Some(ResolvedPolicy::Policy { policy, .. }) = resolved else {
        panic!("the admitted plugin strategy must not become weighted");
    };
    assert_eq!(policy.name(), EXTRA_STRATEGY);
    let order = policy
        .decide(
            &dreq("hi"),
            &[dcand(0), dcand(1)],
            &dctx(),
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("strategy decision");
    assert_eq!(order, RoutingDecision::Prefer(vec![1, 0]));
}

#[test]
fn plugin_strategy_requires_a_declared_word() {
    let pool = pool_policy(crate::config::parse_strategy(EXTRA_STRATEGY));
    for env in [
        strategy_env(false, vec!["different-word".into()], false),
        strategy_env(true, Vec::new(), false),
    ] {
        assert!(resolve_pool_ordering(&pool, &HashMap::new(), &env, None, 0).is_none());
    }
    let mut tap = strategy_env(true, vec![EXTRA_STRATEGY.into()], false);
    tap.axis = Some(Arc::new(StrategyAxis {
        facts: busbar_contract::hook_calls::HookFacts {
            class: busbar_contract::abi::hook::CLASS_TAP,
            words: vec![EXTRA_STRATEGY.into()],
            ..Default::default()
        },
        fail_open: false,
    }));
    assert!(resolve_pool_ordering(&pool, &HashMap::new(), &tap, None, 0).is_none());
}

#[test]
fn plugin_strategy_open_failure_refuses_pool_construction() {
    let pool = pool_policy(crate::config::parse_strategy(EXTRA_STRATEGY));
    let env = strategy_env(true, vec![EXTRA_STRATEGY.into()], true);
    let error = try_resolve_pool_ordering(&pool, &HashMap::new(), &env, None, 0)
        .err()
        .expect("a constructor failure must refuse boot/reload");
    assert!(error.contains("strategy constructor refused"));
}

fn test_env_needs(alias: &str, needs: crate::test_support::HookNeeds) -> HookEnv {
    crate::test_support::test_hook_env(&[alias], needs)
}

fn test_env() -> HookEnv {
    test_env_needs(
        "test-hook",
        crate::test_support::HookNeeds {
            prompt: busbar_contract::plugin_rows::NeedLevel::Rw,
            user: busbar_contract::plugin_rows::NeedLevel::Ro,
        },
    )
}

fn empty_env() -> HookEnv {
    HookEnv::new(
        crate::test_support::rows::empty(),
        std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    )
    .expect("the registry's hook axis")
}

#[test]
fn preresolve_hook_secrets_fails_closed_on_unresolvable_secret() {
    let env = empty_env();

    let mut settings = serde_json::Map::new();
    settings.insert(
        "licenseKey".to_string(),
        serde_json::json!({ "env": "BUSBAR_TEST_DEFINITELY_UNSET_SECRET_B1" }),
    );
    let mut hook = base_gate();
    hook.settings = settings;
    let mut hooks = HashMap::new();
    hooks.insert("compliance-gate".to_string(), hook);
    let err = env
        .preresolve_hook_secrets(&hooks)
        .expect_err("an unresolvable hook secret must fail the pre-resolve pass CLOSED");
    assert!(
        err.contains("compliance-gate"),
        "the error names the offending hook: {err}"
    );

    let mut plain = base_gate();
    plain
        .settings
        .insert("mode".to_string(), serde_json::json!("strict"));
    let mut ok_hooks = HashMap::new();
    ok_hooks.insert("plain-gate".to_string(), plain);
    assert!(env.preresolve_hook_secrets(&ok_hooks).is_ok());
}

#[test]
fn preopen_gate_hooks_aborts_on_a_broken_gate_but_never_a_broken_tap() {
    let env = test_env();

    let mut settings = serde_json::Map::new();
    settings.insert(
        "licenseKey".to_string(),
        serde_json::json!({ "env": "BUSBAR_TEST_DEFINITELY_UNSET_SECRET_PREOPEN" }),
    );

    let mut broken_tap = base_gate();
    broken_tap.kind = HookKind::Tap;
    broken_tap.settings = settings.clone();
    let tap_hooks = registry("broken-tap", broken_tap);
    assert!(
        env.preopen_gate_hooks(&tap_hooks).is_ok(),
        "a broken TAP must never abort boot/reload (taps fail-open)"
    );

    let mut broken_gate = base_gate();
    broken_gate.settings = settings;
    let gate_hooks = registry("broken-gate", broken_gate);
    let err = env
        .preopen_gate_hooks(&gate_hooks)
        .expect_err("a gate whose settings/open() fails must abort boot/reload CLOSED");
    assert!(
        err.contains("broken-gate"),
        "the error names the offending gate: {err}"
    );

    let ok_hooks = registry("ok-gate", base_gate());
    assert!(
        env.preopen_gate_hooks(&ok_hooks).is_ok(),
        "a gate with valid settings must pre-open without error"
    );
}

fn pool_policy(policy: PoolPolicy) -> crate::config::PoolCfg {
    crate::config::PoolCfg {
        upstream_credentials: None,
        members: vec![],
        breaker: None,
        failover: None,
        on_exhausted: None,
        affinity: None,
        policy,
        gates: Vec::new(),
        base_named: true,
        ..Default::default()
    }
}

fn pool_with_hook(name: &str) -> crate::config::PoolCfg {
    crate::config::PoolCfg {
        upstream_credentials: None,
        members: vec![],
        breaker: None,
        failover: None,
        on_exhausted: None,
        affinity: None,
        policy: PoolPolicy::Weighted,
        gates: vec![name.to_string()],
        base_named: false,
        ..Default::default()
    }
}

fn base_gate() -> HookCfg {
    HookCfg {
        kind: HookKind::Gate,
        plugin: "test-hook".to_string(),
        timeout_ms: crate::config::DEFAULT_POLICY_TIMEOUT_MS,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new(),
        at: None,
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

fn registry(name: &str, hook: HookCfg) -> HashMap<String, HookCfg> {
    let mut m = HashMap::new();
    m.insert(name.to_string(), hook);
    m
}

#[test]
fn native_policy_resolves_constructed_policy() {
    for (policy, name) in [
        (PoolPolicy::Cheapest, "cheapest"),
        (PoolPolicy::Fastest, "fastest"),
        (PoolPolicy::LeastBusy, "least_busy"),
        (PoolPolicy::Usage, "usage"),
    ] {
        let cfg = pool_policy(policy);
        match resolve_policy(&cfg) {
            Some(ResolvedPolicy::Policy { policy, .. }) => {
                assert_eq!(
                    policy.name(),
                    name,
                    "resolved native policy name must round-trip"
                );
            }
            other => panic!(
                "policy: {name} must resolve to a Policy, got none={}",
                other.is_none()
            ),
        }
    }
}

#[test]
fn default_hook_resolves_as_base_for_unnamed_pools() {
    let env = test_env();
    let mut def = base_gate();
    def.default = true;
    let mut hooks = registry("def", def);

    hooks.insert("h".to_string(), base_gate());

    assert_eq!(default_hook_name(&hooks), Some("def"));

    let mut unnamed = pool_with_hook("x");
    unnamed.gates.clear();
    assert!(
        resolve_pool_ordering(&unnamed, &hooks, &env, Some("def"), 0).is_some(),
        "an unnamed-base pool inherits the default hook as its ordering"
    );

    assert!(
        resolve_pool_ordering(
            &pool_policy(PoolPolicy::Weighted),
            &hooks,
            &env,
            Some("def"),
            0
        )
        .is_none(),
        "a pool that named its base keeps it; the default does not override"
    );

    let gated = pool_with_hook("h");
    assert!(
        resolve_pool_ordering(&gated, &hooks, &env, Some("def"), 0).is_some(),
        "an unnamed-base pool with its own gate still inherits the default as base"
    );
    assert_eq!(
        resolve_pool_gates(&gated, &hooks, &env, 0).len(),
        1,
        "the pool's own gate resolves separately, on top of the inherited base"
    );

    assert!(
        resolve_pool_ordering(&unnamed, &HashMap::new(), &env, None, 0).is_none(),
        "no default hook ⇒ the compiled-in weighted backstop (None)"
    );
}

#[test]
fn default_rw_hook_is_not_the_base_ordering() {
    let env = test_env();

    let mut rw = base_gate();
    rw.prompt = PromptAccess::Rw;
    rw.default = true;
    let hooks = registry("def", rw);
    let mut unnamed = pool_with_hook("x");
    unnamed.gates.clear();
    assert!(
        resolve_pool_ordering(&unnamed, &hooks, &env, Some("def"), 0).is_none(),
        "a prompt:rw default hook must not become the base ordering — it can never return an order"
    );

    let mut tap = base_gate();
    tap.kind = HookKind::Tap;
    tap.default = true;
    let hooks = registry("deftap", tap);
    let mut unnamed2 = pool_with_hook("x");
    unnamed2.gates.clear();
    assert!(
        resolve_pool_ordering(&unnamed2, &hooks, &env, Some("deftap"), 0).is_none(),
        "a tap default hook must not become the base ordering — it has no decision arm"
    );
}

#[test]
fn weighted_policy_resolves_none_zero_cost() {
    assert!(
        resolve_policy(&pool_policy(PoolPolicy::Weighted)).is_none(),
        "the weighted native must collapse to the zero-cost default path"
    );
}

#[test]
fn unknown_hook_ref_falls_back_to_none() {
    let hooks = HashMap::new();
    assert!(resolve_pool_gates(&pool_with_hook("nonexistent"), &hooks, &empty_env(), 0).is_empty());
}

#[test]
fn plugin_gate_resolves_constructed_policy() {
    let env = test_env();
    let hooks = registry("h", base_gate());
    match resolve_pool_gates(&pool_with_hook("h"), &hooks, &env, 0)
        .into_iter()
        .next()
    {
        Some((
            _,
            ResolvedPolicy::Policy {
                policy, timeout, ..
            },
        )) => {
            assert_eq!(
                policy.name(),
                "h",
                "the HookPolicy carries the hook's registry name"
            );
            assert_eq!(
                timeout,
                std::time::Duration::from_millis(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
                "a gate with the default timeout resolves to the documented deadline, not 0ms",
            );
        }
        None => panic!("plugin gate must resolve to a Policy"),
    }

    assert!(resolve_pool_gates(&pool_with_hook("h"), &hooks, &empty_env(), 0).is_empty());
}

#[test]
fn weighted_default_resolves_none() {
    assert!(resolve_policy(&pool_policy(PoolPolicy::Weighted)).is_none());
}

#[test]
fn on_error_chain_resolves_gates_and_terminals() {
    let env = test_env();

    let mut a = base_gate();
    a.on_error = "b".to_string();
    let mut b = base_gate();
    b.on_error = "reject".to_string();
    let mut hooks = registry("a", a);
    hooks.insert("b".to_string(), b);

    let resolved = resolve_pool_gates(&pool_with_hook("a"), &hooks, &env, 0);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolved.into_iter().next()
    else {
        panic!("gate a must resolve");
    };
    assert_eq!(on_error_chain.len(), 1, "one fallback link (gate b)");
    assert_eq!(on_error_chain[0].policy.name(), "b");
    assert_eq!(
        on_error,
        PolicyOnError::Reject,
        "the chain bottoms out on b's reject terminal"
    );

    let mut n = base_gate();
    n.on_error = "nothing".to_string();
    let hooks_n = registry("n", n);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("n"), &hooks_n, &env, 0)
        .into_iter()
        .next()
    else {
        panic!("gate n must resolve");
    };
    assert!(on_error_chain.is_empty());
    assert_eq!(
        on_error,
        PolicyOnError::Weighted,
        "nothing = the non-participating terminal"
    );

    let mut c = base_gate();
    c.on_error = "first".to_string();
    let hooks = registry("c", c);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("c"), &hooks, &env, 0)
        .into_iter()
        .next()
    else {
        panic!("gate c must resolve");
    };
    assert!(on_error_chain.is_empty(), "a terminal name has no chain");
    assert_eq!(on_error, PolicyOnError::First);
}

#[test]
fn on_error_chain_strategy_terminates() {
    let env = test_env();
    let mut g = base_gate();
    g.on_error = "cheapest".to_string();
    let hooks = registry("g", g);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("g"), &hooks, &env, 0)
        .into_iter()
        .next()
    else {
        panic!("gate g must resolve");
    };
    assert_eq!(on_error_chain.len(), 1);
    assert_eq!(on_error_chain[0].policy.name(), "cheapest");
    assert_eq!(on_error, PolicyOnError::Weighted);
}

#[test]
fn pool_rw_gate_resolves_as_rewrite_not_decision() {
    let env = test_env();
    let mut rw = base_gate();
    rw.prompt = PromptAccess::Rw;
    let hooks = registry("rw", rw);
    let pool = pool_with_hook("rw");
    assert!(
        resolve_pool_gates(&pool, &hooks, &env, 0).is_empty(),
        "an rw gate must not resolve as a decision gate"
    );
    assert_eq!(
        resolve_pool_rewrites(&pool, &hooks, &env, 0).len(),
        1,
        "an rw gate must resolve into the pool rewrite chain"
    );

    let hooks = registry("plain", base_gate());
    let pool = pool_with_hook("plain");
    assert_eq!(resolve_pool_gates(&pool, &hooks, &env, 0).len(), 1);
    assert!(resolve_pool_rewrites(&pool, &hooks, &env, 0).is_empty());
}

#[test]
fn missing_plugin_gate_is_absent_not_stranded() {
    let hooks = registry("h", base_gate());

    assert!(resolve_pool_gates(&pool_with_hook("h"), &hooks, &empty_env(), 0).is_empty());
}

#[test]
fn a_reused_registry_address_never_inherits_a_dead_registrys_resolution() {
    let env = test_env();
    let hooks = registry("h", base_gate());

    assert_eq!(
        resolve_pool_gates(&pool_with_hook("h"), &hooks, &env, 0).len(),
        1,
        "the plugin-backed gate resolves against the registry that carries it"
    );
    let freed = std::sync::Arc::as_ptr(&env.registry) as *const u8 as usize;
    drop(env);

    let mut keepalive: Vec<std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>> =
        Vec::new();
    for _ in 0..4096 {
        let reg = crate::test_support::rows::empty();
        if std::sync::Arc::as_ptr(&reg) as *const u8 as usize == freed {
            let reused = HookEnv::new(
                reg,
                std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
            )
            .expect("the registry's hook axis");
            assert!(
                resolve_pool_gates(&pool_with_hook("h"), &hooks, &reused, 0).is_empty(),
                "a registry that does not carry the plugin must resolve to gate-absent even when \
                 it was allocated on a dead registry's address — a resolution is identified by \
                 WHICH registry it came out of, and an address is not an identity"
            );
            return;
        }
        keepalive.push(reg);
    }
}

#[test]
fn resolve_rewrite_hooks_admits_only_prompt_rw_gates() {
    let env = test_env();
    let mk = |kind: HookKind, prompt: PromptAccess| HookCfg {
        kind,
        prompt,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("rw-gate".to_string(), mk(HookKind::Gate, PromptAccess::Rw));
    hooks.insert("ro-gate".to_string(), mk(HookKind::Gate, PromptAccess::Ro));
    hooks.insert("no-gate".to_string(), mk(HookKind::Gate, PromptAccess::No));

    hooks.insert("rw-tap".to_string(), mk(HookKind::Tap, PromptAccess::Rw));
    let global = vec![
        "rw-gate".to_string(),
        "ro-gate".to_string(),
        "no-gate".to_string(),
        "rw-tap".to_string(),
    ];
    let resolved = resolve_rewrite_hooks(&hooks, &global, &env, 0);
    assert_eq!(
        resolved.len(),
        1,
        "only the prompt:rw GATE is a rewrite hook; ro/no gates + the tap are excluded"
    );
}

/// CLASS INVARIANT: REWRITE admission goes through the SAME belt-and-suspenders meet
/// as the read projections — `hooks::effective_access`. A `prompt: rw` OPERATOR grant is not
/// sufficient on its own; the plugin's SIGNED manifest must also declare `needs: { prompt: rw }`.
///
/// One assertion covers BOTH halves of the bypass, because admission is what carries them:
///  * CONFIDENTIALITY — a hook admitted to a rewrite chain is handed the FULL flattened prompt
///    projection (`proxy::hooks::apply_global_rewrites` passes `with_prompt = true`
///    unconditionally, which is sound ONLY because of this gate);
///  * INTEGRITY — an admitted hook may return a `RewriteReply` that is spliced into the upstream
///    request body (messages replaced, `tools` appended).
///
/// The matrix is {manifest need} × {both rewrite resolvers}, with the operator grant pinned at `rw`
/// throughout, so the signed intent is the only variable. Pre-fix, both resolvers keyed admission
/// on `hook.prompt.can_rewrite()` alone and every row admitted.
#[test]
fn rewrite_admission_requires_the_signed_manifest_rewrite_need() {
    use crate::test_support::HookNeeds;
    use busbar_contract::plugin_rows::NeedLevel;

    for (need, admitted) in [
        (NeedLevel::No, false),
        (NeedLevel::Ro, false),
        (NeedLevel::Rw, true),
    ] {
        let needs = HookNeeds {
            prompt: need,
            user: NeedLevel::No,
        };
        let env = test_env_needs("test-hook", needs);

        let mut rw = base_gate();
        rw.prompt = PromptAccess::Rw;
        rw.global = true;
        let hooks = registry("rw", rw);

        let global = resolve_rewrite_hooks(&hooks, &["rw".to_string()], &env, 0);
        assert_eq!(
            !global.is_empty(),
            admitted,
            "global rewrite chain: `prompt: rw` + manifest `needs.prompt: {need:?}` must \
             {} admit — the operator grant alone is not the ticket",
            if admitted { "" } else { "NOT " }
        );
        let pool = resolve_pool_rewrites(&pool_with_hook("rw"), &hooks, &env, 0);
        assert_eq!(
            !pool.is_empty(),
            admitted,
            "pool rewrite chain: `prompt: rw` + manifest `needs.prompt: {need:?}` must {} admit \
             — the per-pool resolver is a SIBLING of the global one and must not diverge",
            if admitted { "" } else { "NOT " }
        );

        let (send_prompt, _) = projection_grants("rw", hooks.get("rw").unwrap(), &env);
        assert!(
            !admitted || send_prompt,
            "an admitted rewrite hook must also be cleared to READ the prompt it rewrites"
        );
        assert_eq!(
            send_prompt,
            need.wants_read(),
            "the read half stays the meet of grant and manifest, unchanged by this fix"
        );
    }
}

#[test]
fn hook_inert_gate_banner_fires_only_for_a_gate_with_the_chain_killing_mismatch() {
    use busbar_contract::plugin_rows::NeedLevel;

    let banner = hook_inert_gate_banner(
        "compliance-gate",
        "acme.compliance",
        HookKind::Gate,
        NeedLevel::Ro,
    )
    .expect("a gate with a manifest-denied rw grant must produce a banner");
    assert!(
        banner.contains("compliance-gate") && banner.contains("acme.compliance"),
        "banner must name the offending hook and plugin: {banner}"
    );
    assert!(
        banner.contains("INERT")
            && banner.contains("decision-gate chain")
            && banner.contains("rewrite chain"),
        "banner must explain BOTH exclusions, not just one: {banner}"
    );

    assert!(hook_inert_gate_banner("g", "p", HookKind::Gate, NeedLevel::No).is_some());

    assert!(
        hook_inert_gate_banner("t", "p", HookKind::Tap, NeedLevel::Ro).is_none(),
        "a tap never joins an admission chain, so it must not get the gate-outage banner"
    );
}

struct LineCapturingSubscriber(std::sync::Arc<std::sync::Mutex<Vec<u32>>>);
impl tracing::Subscriber for LineCapturingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let level = *event.metadata().level();
        if level == tracing::Level::WARN || level == tracing::Level::ERROR {
            if let Some(line) = event.metadata().line() {
                self.0.lock().unwrap().push(line);
            }
        }
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

#[test]
fn effective_access_warns_on_inert_read_grants_only() {
    use busbar_contract::plugin_rows::NeedLevel;

    let events: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub = LineCapturingSubscriber(events.clone());

    let env = test_env_needs(
        "inert-prompt",
        crate::test_support::HookNeeds {
            prompt: NeedLevel::No,
            user: NeedLevel::No,
        },
    );
    let mut h = base_gate();
    h.plugin = "inert-prompt".to_string();
    h.prompt = PromptAccess::Ro;
    tracing::subscriber::with_default(sub, || {
        let _ = effective_access("h", &h, &env);
    });
    let seen = events.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        1,
        "a prompt grant the manifest never declared must warn exactly once: {seen:?}"
    );

    let events2: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub2 = LineCapturingSubscriber(events2.clone());
    let env2 = test_env_needs(
        "matched-prompt",
        crate::test_support::HookNeeds {
            prompt: NeedLevel::Ro,
            user: NeedLevel::No,
        },
    );
    let mut h2 = base_gate();
    h2.plugin = "matched-prompt".to_string();
    h2.prompt = PromptAccess::Ro;
    tracing::subscriber::with_default(sub2, || {
        let _ = effective_access("h2", &h2, &env2);
    });
    assert!(
        events2.lock().unwrap().is_empty(),
        "a grant the manifest DOES declare must not warn: {:?}",
        events2.lock().unwrap()
    );

    let events3: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub3 = LineCapturingSubscriber(events3.clone());
    let env3 = test_env_needs(
        "inert-user",
        crate::test_support::HookNeeds {
            prompt: NeedLevel::No,
            user: NeedLevel::No,
        },
    );
    let mut h3 = base_gate();
    h3.plugin = "inert-user".to_string();
    h3.user = UserAccess::Ro;
    tracing::subscriber::with_default(sub3, || {
        let _ = effective_access("h3", &h3, &env3);
    });
    let seen3 = events3.lock().unwrap().clone();
    assert_eq!(
        seen3.len(),
        1,
        "a user grant the manifest never declared must warn exactly once: {seen3:?}"
    );

    let events4: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub4 = LineCapturingSubscriber(events4.clone());
    let env4 = test_env_needs(
        "matched-user",
        crate::test_support::HookNeeds {
            prompt: NeedLevel::No,
            user: NeedLevel::Ro,
        },
    );
    let mut h4 = base_gate();
    h4.plugin = "matched-user".to_string();
    h4.user = UserAccess::Ro;
    tracing::subscriber::with_default(sub4, || {
        let _ = effective_access("h4", &h4, &env4);
    });
    assert!(
        events4.lock().unwrap().is_empty(),
        "a user grant the manifest DOES declare must not warn: {:?}",
        events4.lock().unwrap()
    );
}

#[test]
fn effective_access_inert_gate_rewrite_banner_fires_once_per_hook_name() {
    use busbar_contract::plugin_rows::NeedLevel;

    let events: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub = LineCapturingSubscriber(events.clone());

    let env = test_env_needs(
        "inert-rewrite",
        crate::test_support::HookNeeds {
            prompt: NeedLevel::Ro,
            user: NeedLevel::No,
        },
    );
    let mut h = base_gate();
    h.plugin = "inert-rewrite".to_string();
    h.prompt = PromptAccess::Rw;

    assert!(
        !env.banner_seen.lock().unwrap().contains("h"),
        "banner_seen must start empty for this name"
    );
    tracing::subscriber::with_default(sub, || {
        let _ = effective_access("h", &h, &env);
    });
    assert!(
        env.banner_seen.lock().unwrap().contains("h"),
        "the FIRST call for an inert-rewrite gate must record the hook name in banner_seen \
         (proves the dedup guard's `.insert()` actually ran)"
    );
    let banner_events = events.lock().unwrap().clone();
    assert_eq!(
        banner_events.len(),
        1,
        "the first call for an inert-rewrite gate must emit exactly one banner-adjacent event: \
         {banner_events:?}"
    );

    let events2: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub2 = LineCapturingSubscriber(events2.clone());
    tracing::subscriber::with_default(sub2, || {
        let _ = effective_access("h", &h, &env);
    });
    assert!(
        events2.lock().unwrap().is_empty(),
        "a hook already in banner_seen must not re-banner on a second resolution: {:?}",
        events2.lock().unwrap()
    );

    let events3: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub3 = LineCapturingSubscriber(events3.clone());
    let env3 = test_env_needs(
        "matched-rewrite",
        crate::test_support::HookNeeds {
            prompt: NeedLevel::Rw,
            user: NeedLevel::No,
        },
    );
    let mut h3 = base_gate();
    h3.plugin = "matched-rewrite".to_string();
    h3.prompt = PromptAccess::Rw;
    tracing::subscriber::with_default(sub3, || {
        let _ = effective_access("clean", &h3, &env3);
    });
    assert!(
        !env3.banner_seen.lock().unwrap().contains("clean"),
        "a gate whose manifest matches its grant must never enter banner_seen"
    );
    assert!(
        events3.lock().unwrap().is_empty(),
        "a matched-rewrite gate must emit no banner-adjacent event: {:?}",
        events3.lock().unwrap()
    );
}

#[test]
fn resolve_gate_hooks_admits_only_decision_gates() {
    let env = test_env();
    let mk = |kind: HookKind, prompt: PromptAccess| HookCfg {
        kind,
        prompt,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("rw-gate".to_string(), mk(HookKind::Gate, PromptAccess::Rw));
    hooks.insert("ro-gate".to_string(), mk(HookKind::Gate, PromptAccess::Ro));
    hooks.insert("no-gate".to_string(), mk(HookKind::Gate, PromptAccess::No));
    hooks.insert("a-tap".to_string(), mk(HookKind::Tap, PromptAccess::Ro));
    let global = vec![
        "rw-gate".to_string(),
        "ro-gate".to_string(),
        "no-gate".to_string(),
        "a-tap".to_string(),
    ];
    let resolved = resolve_gate_hooks(&hooks, &global, &env, 0);
    assert_eq!(
        resolved.len(),
        2,
        "decision gates = the ro + no gates; the rw (rewrite) gate and the tap are excluded"
    );
}

#[test]
fn resolve_tap_hooks_admits_only_request_stage_taps() {
    use crate::config::HookStage;
    let env = test_env();
    let mk = |kind: HookKind, phase: Vec<HookStage>| HookCfg {
        kind,
        phase,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert(
        "tap-req".to_string(),
        mk(HookKind::Tap, vec![HookStage::Request]),
    );

    hooks.insert("tap-unset".to_string(), mk(HookKind::Tap, Vec::new()));
    hooks.insert(
        "tap-completion".to_string(),
        mk(HookKind::Tap, vec![HookStage::Response]),
    );
    hooks.insert("a-gate".to_string(), mk(HookKind::Gate, Vec::new()));
    let global = vec![
        "tap-req".to_string(),
        "tap-unset".to_string(),
        "tap-completion".to_string(),
        "a-gate".to_string(),
    ];
    let resolved = resolve_tap_hooks(&hooks, &global, &env, 0, crate::config::HookStage::Request);
    assert_eq!(
        resolved.len(),
        2,
        "only the two REQUEST-stage taps resolve; the gate and the completion-stage tap are excluded"
    );

    let completion =
        resolve_tap_hooks(&hooks, &global, &env, 0, crate::config::HookStage::Response);
    assert_eq!(
        completion.len(),
        2,
        "the explicit response-stage tap AND the unset tap (omitted = the four core stages)"
    );

    assert_eq!(
        resolve_tap_hooks(&hooks, &global, &env, 0, crate::config::HookStage::Routing).len(),
        1,
        "only the phase-unset tap observes the routing stage (omitted = the four core stages)"
    );

    assert!(
        resolved.iter().all(|(_, send_prompt, _, _)| !*send_prompt),
        "a prompt:no tap must not carry the prompt-content grant"
    );
}

#[test]
fn resolve_tap_hooks_honors_phase_list() {
    use crate::config::HookStage;
    let env = test_env();
    let mk = |phase: Vec<HookStage>| HookCfg {
        kind: HookKind::Tap,
        global: true,
        phase,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("resp-only".to_string(), mk(vec![HookStage::Response]));
    hooks.insert(
        "req-and-resp".to_string(),
        mk(vec![HookStage::Request, HookStage::Response]),
    );
    let global = vec!["resp-only".to_string(), "req-and-resp".to_string()];

    assert_eq!(
        resolve_tap_hooks(&hooks, &global, &env, 0, HookStage::Response).len(),
        2,
        "both taps declare the response phase"
    );

    assert_eq!(
        resolve_tap_hooks(&hooks, &global, &env, 0, HookStage::Request).len(),
        1,
        "phase: [response] does not fire at the request stage"
    );

    assert!(resolve_tap_hooks(&hooks, &global, &env, 0, HookStage::Candidate).is_empty());
    assert!(resolve_tap_hooks(&hooks, &global, &env, 0, HookStage::Routing).is_empty());
}

#[test]
fn resolve_tap_hooks_carries_prompt_grant() {
    let env = test_env();
    let mk = |prompt: PromptAccess| HookCfg {
        kind: HookKind::Tap,
        prompt,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("ro-tap".to_string(), mk(PromptAccess::Ro));
    hooks.insert("no-tap".to_string(), mk(PromptAccess::No));
    let resolved = resolve_tap_hooks(
        &hooks,
        &["ro-tap".to_string(), "no-tap".to_string()],
        &env,
        0,
        crate::config::HookStage::Request,
    );
    assert_eq!(resolved.len(), 2);

    let ro = resolve_tap_hooks(
        &hooks,
        &["ro-tap".to_string()],
        &env,
        0,
        crate::config::HookStage::Request,
    );
    let no = resolve_tap_hooks(
        &hooks,
        &["no-tap".to_string()],
        &env,
        0,
        crate::config::HookStage::Request,
    );
    assert!(ro[0].1, "prompt:ro tap carries send_prompt = true");
    assert!(!no[0].1, "prompt:no tap carries send_prompt = false");
}

#[test]
fn policy_timeout_treats_zero_as_default() {
    assert_eq!(
        policy_timeout(0),
        std::time::Duration::from_millis(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
        "0ms must be coerced to the documented default policy timeout, never 0"
    );
    assert_eq!(
        policy_timeout(42),
        std::time::Duration::from_millis(42),
        "a non-zero timeout must be honored verbatim"
    );
}

#[test]
fn from_ranked_empty_is_abstain() {
    let valid: HashSet<usize> = [0usize].into_iter().collect();
    assert_eq!(
        RoutingDecision::from_ranked([7usize, 8], &valid),
        RoutingDecision::Abstain,
        "all-unknown ranked list collapses to Abstain"
    );
    assert_eq!(
        RoutingDecision::from_ranked(std::iter::empty(), &valid),
        RoutingDecision::Abstain,
    );
}

#[test]
fn native_resolve_forces_opt_in_flags_off() {
    match resolve_policy(&pool_policy(PoolPolicy::Cheapest)) {
        Some(ResolvedPolicy::Policy {
            send_prompt,
            send_user,
            ..
        }) => {
            assert!(!send_prompt, "native must force send_prompt off");
            assert!(!send_user, "native must force send_user off");
        }
        None => panic!("native pool must resolve to a policy"),
    }
}

#[test]
fn gate_grants_pass_through_as_projection_flags() {
    let env = test_env();
    let hooks = registry(
        "h",
        HookCfg {
            prompt: PromptAccess::Ro,
            user: UserAccess::Ro,
            ..base_gate()
        },
    );
    match resolve_pool_gates(&pool_with_hook("h"), &hooks, &env, 0)
        .into_iter()
        .next()
    {
        Some((
            _,
            ResolvedPolicy::Policy {
                send_prompt,
                send_user,
                ..
            },
        )) => {
            assert!(
                send_prompt,
                "prompt:ro grant + manifest need must pass send_prompt through"
            );
            assert!(
                send_user,
                "user:ro grant + manifest need must pass send_user through"
            );
        }
        None => panic!("gate must resolve to a policy"),
    }
}

#[test]
fn manifest_intent_and_grant_projection_matrix() {
    use busbar_contract::plugin_rows::NeedLevel;

    let prompt_cases = [
        (NeedLevel::No, PromptAccess::No, false),
        (NeedLevel::No, PromptAccess::Ro, false),
        (NeedLevel::No, PromptAccess::Rw, false),
        (NeedLevel::Ro, PromptAccess::No, false),
        (NeedLevel::Ro, PromptAccess::Ro, true),
        (NeedLevel::Ro, PromptAccess::Rw, true),
        (NeedLevel::Rw, PromptAccess::No, false),
        (NeedLevel::Rw, PromptAccess::Ro, true),
        (NeedLevel::Rw, PromptAccess::Rw, true),
    ];
    for (idx, (need, grant, want_prompt)) in prompt_cases.into_iter().enumerate() {
        let alias = format!("mtx-{idx}");
        let env = test_env_needs(
            &alias,
            crate::test_support::HookNeeds {
                prompt: need,
                user: NeedLevel::No,
            },
        );
        let hooks = registry(
            "h",
            HookCfg {
                plugin: alias.clone(),
                prompt: grant,
                ..base_gate()
            },
        );
        let Some(ResolvedPolicy::Policy { send_prompt, .. }) =
            resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0)
        else {
            panic!("gate must resolve for case {idx}");
        };
        assert_eq!(
            send_prompt, want_prompt,
            "case {idx}: manifest {need:?} × grant {grant:?} → send_prompt {want_prompt}"
        );
    }

    let user_cases = [
        (NeedLevel::No, UserAccess::No, false),
        (NeedLevel::No, UserAccess::Ro, false),
        (NeedLevel::Ro, UserAccess::No, false),
        (NeedLevel::Ro, UserAccess::Ro, true),
    ];
    for (idx, (need, grant, want_user)) in user_cases.into_iter().enumerate() {
        let alias = format!("mtx-user-{idx}");
        let env = test_env_needs(
            &alias,
            crate::test_support::HookNeeds {
                prompt: NeedLevel::No,
                user: need,
            },
        );
        let hooks = registry(
            "h",
            HookCfg {
                plugin: alias.clone(),
                user: grant,
                ..base_gate()
            },
        );
        let Some(ResolvedPolicy::Policy { send_user, .. }) =
            resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0)
        else {
            panic!("gate must resolve for user case {idx}");
        };
        assert_eq!(
            send_user, want_user,
            "user case {idx}: manifest {need:?} × grant {grant:?} → send_user {want_user}"
        );
    }
}

#[test]
fn from_ranked_never_produces_reject() {
    let valid: HashSet<usize> = [0usize, 1, 2].into_iter().collect();
    for ranked in [
        vec![0usize, 1, 2],
        vec![2, 2, 2],
        vec![9, 8, 7],
        vec![],
        vec![1],
        vec![0, 9, 1, 0, 2, 2],
    ] {
        let d = RoutingDecision::from_ranked(ranked.clone(), &valid);
        assert!(
            !matches!(d, RoutingDecision::Reject { .. }),
            "from_ranked({ranked:?}) must never yield Reject"
        );
    }
}

#[test]
fn opt_in_projections_redact_debug() {
    let p = PromptProjection {
        system: Some("SECRET-SYSTEM-PROMPT".into()),
        messages: vec![("user".into(), "SECRET-MESSAGE-TEXT".into())],
    };
    let dbg = format!("{p:?}");
    assert!(
        !dbg.contains("SECRET-SYSTEM-PROMPT"),
        "leaked system: {dbg}"
    );
    assert!(
        !dbg.contains("SECRET-MESSAGE-TEXT"),
        "leaked message: {dbg}"
    );

    let i = CallerIdentity {
        key_id: Some("k-1".into()),
        key_name: Some("sales-team".into()),
        user: Some("alice@example.com".into()),
    };
    let dbg = format!("{i:?}");
    assert!(
        !dbg.contains("alice@example.com"),
        "leaked end-user id: {dbg}"
    );

    assert!(dbg.contains("sales-team"));
}

fn resolve_one(env: &HookEnv, settings: serde_json::Value) -> Option<Arc<dyn RoutingPolicy>> {
    let mut hook = base_gate();
    hook.prompt = PromptAccess::Ro;
    hook.settings = settings.as_object().cloned().unwrap_or_default();
    let hooks = registry("h", hook);
    match resolve_gate_transport("h", &hooks["h"], &hooks, env, 0)? {
        ResolvedPolicy::Policy { policy, .. } => Some(policy),
    }
}

fn dreq(text: &str) -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "acme",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: text.len(),
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: Some(PromptProjection {
            system: None,
            messages: vec![("user".into(), text.to_string().into())],
        }),
        identity: None,
        signals: Default::default(),
        session: None,
    }
}

fn dcand(idx: usize) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
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
        signals: Default::default(),
    }
}

fn dctx() -> RoutingContext<'static> {
    RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    }
}

#[tokio::test]
async fn dlopen_decide_order_and_abstain() {
    let env = test_env();
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0), dcand(1)];

    let policy = resolve_one(&env, serde_json::json!({"order": [9, 1, 0]})).expect("resolve");
    let d = policy
        .decide(&dreq("hi"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(
        d,
        RoutingDecision::Prefer(vec![1, 0]),
        "unknown idx 9 dropped by the real normalizer"
    );

    let policy = resolve_one(&env, serde_json::json!({})).expect("resolve");
    let d = policy
        .decide(&dreq("hi"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(d, RoutingDecision::Abstain);
}

#[tokio::test]
async fn dlopen_decide_reject_from_opt_in_prompt() {
    let env = test_env();
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0)];
    let policy = resolve_one(
        &env,
        serde_json::json!({"order": [0], "reject_if_contains": "BLOCKME"}),
    )
    .expect("resolve");

    let d = policy
        .decide(&dreq("clean prompt"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(d, RoutingDecision::Prefer(vec![0]));

    let d = policy
        .decide(&dreq("please BLOCKME"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(
        d,
        RoutingDecision::Reject {
            status: 403,
            message: "blocked by test gate".to_string()
        }
    );
}

#[tokio::test]
async fn dlopen_transform_rewrite_and_reject() {
    use busbar_contract::hooks::TransformOutcome;
    let env = test_env();
    let budget = std::time::Duration::from_secs(5);
    let policy =
        resolve_one(&env, serde_json::json!({"reject_if_contains": "BLOCKME"})).expect("resolve");

    match policy.transform(&dreq("hello"), budget).await {
        TransformOutcome::Rewrite(rw) => assert_eq!(rw.messages.len(), 1),
        other => panic!("expected Rewrite, got {other:?}"),
    }
    match policy.transform(&dreq("BLOCKME"), budget).await {
        TransformOutcome::Reject { status, .. } => assert_eq!(status, 451),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn dlopen_notify_is_fire_and_forget() {
    let env = test_env();
    let budget = std::time::Duration::from_secs(5);
    let policy = resolve_one(&env, serde_json::json!({})).expect("resolve");

    async fn taps(policy: &Arc<dyn RoutingPolicy>) -> f64 {
        let status = policy
            .status(std::time::Duration::from_secs(5))
            .await
            .expect("status");
        let metrics = status.metrics.expect("metrics");
        let tap = metrics
            .iter()
            .find(|m| m["name"] == "test_notifies_total")
            .expect("test_notifies_total metric");
        tap["value"].as_f64().expect("counter value")
    }

    assert_eq!(taps(&policy).await, 0.0, "no tap dispatched yet");
    let tap = || busbar_contract::abi::host::hook::NotifyFrame::build(&dreq("hello"), None, false);
    policy.notify(tap(), budget).await;
    assert_eq!(
        taps(&policy).await,
        1.0,
        "a tap view must actually reach the plugin's `notify` over the ABI"
    );
    policy.notify(tap(), budget).await;
    assert_eq!(taps(&policy).await, 2.0, "each tap is one dispatch");

    match policy.transform(&dreq("hello"), budget).await {
        busbar_contract::hooks::TransformOutcome::Rewrite(rw) => assert_eq!(rw.messages.len(), 1),
        other => panic!("seam unusable after notify: expected Rewrite, got {other:?}"),
    }
}

#[tokio::test]
async fn dlopen_status_and_schema_reads() {
    let env = test_env();
    let hook = {
        let mut h = base_gate();
        h.settings = serde_json::json!({"order": [0]})
            .as_object()
            .cloned()
            .unwrap();
        h
    };

    let hooks = registry("h", hook.clone());
    let ResolvedPolicy::Policy { policy, .. } =
        resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0).expect("resolve");
    let _ = policy
        .decide(
            &dreq("x"),
            &[dcand(0)],
            &dctx(),
            std::time::Duration::from_secs(5),
        )
        .await;

    let status = fetch_status("h", &hook, 0, &env).await.expect("status");
    let metrics = status.metrics.expect("metrics");
    assert_eq!(metrics[0]["name"], "test_decides_total");

    let schema = fetch_schema("h", &hook, 0, &env).await.expect("schema");

    assert_eq!(schema["type"], "object");
}

#[tokio::test]
async fn dlopen_configure_acks_exact_version() {
    let env = test_env();
    let hook = base_gate();
    let key = resolution::key("h", &hook, &env)
        .expect("the loadable hook is eligible for transport publication");
    let mut failed_loads = 0;
    for attempt in 0..24 {
        if resolution::published(key) {
            break;
        }
        if gate_transport_offloaded("h", &hook, &env, 0).await.is_some() {
            break;
        }
        // A timed-out resolver retains its claim until it publishes. Only a finished,
        // unpublished load counts as a failure; retries retain the production deadline.
        if !resolution::in_flight(key) {
            failed_loads += 1;
            if failed_loads >= 3 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            attempt < 23,
            "the loader never published a transport for hook 'h' after 24 resolve attempts; \
             that is a HANG in plugin resolution, not a slow machine"
        );
    }
    assert!(
        resolution::published(key),
        "the loader must publish a transport for a loadable hook plugin"
    );

    const ATTEMPTS: usize = 4;
    let mut last = String::new();
    for _ in 0..ATTEMPTS {
        match push_configure(&hook, "h", 7, &env).await {
            Ok(()) => return,
            Err(e) if e.contains("deadline") || e.contains("unresolvable") => last = e,
            Err(e) => panic!("the plugin must ack the pushed version exactly: {e}"),
        }
    }
    panic!(
        "push_configure hit its shipped 5s deadline {ATTEMPTS} times in a row ({last}); that is a \
         wedged plugin or a hang, not scheduling delay"
    );
}

#[tokio::test]
async fn one_load_serves_every_resolution_of_the_same_hook() {
    let env = test_env();
    let hook = base_gate();
    let (first, _) = gate_transport_named("h", &hook, &env, 0).expect("first resolve");
    let (second, _) = gate_transport_named("h", &hook, &env, 0).expect("second resolve");
    assert!(
        std::sync::Arc::ptr_eq(&first, &second),
        "a second resolution of the same hook+settings+registry must reuse the published load, \
         not open a second image"
    );

    let mut other = base_gate();
    other
        .settings
        .insert("order".to_string(), serde_json::json!([0]));
    let (third, _) = gate_transport_named("h", &other, &env, 0).expect("third resolve");
    assert!(
        !std::sync::Arc::ptr_eq(&first, &third),
        "a change of settings must resolve a NEW transport, never reuse the old one"
    );
}

#[test]
fn a_hook_carrying_a_secret_ref_is_never_reused() {
    let env = test_env();
    let mut with_secret = base_gate();
    with_secret.settings.insert(
        "licenseKey".to_string(),
        serde_json::json!({ "env": "BUSBAR_TEST_HOOK_LICENSE_KEY" }),
    );
    assert_eq!(
        super::resolution::key("h", &with_secret, &env),
        None,
        "a SecretRef-carrying hook must be resolved fresh every time, never published for reuse"
    );
    assert!(
        super::resolution::key("h", &base_gate(), &env).is_some(),
        "a hook with no secret indirection is eligible"
    );
}

#[tokio::test]
async fn dlopen_on_error_chain_link_is_live_plugin() {
    let env = test_env();
    let mut a = base_gate();
    a.on_error = "b".to_string();
    let mut b = base_gate();
    b.on_error = "reject".to_string();
    let mut hooks = registry("a", a);
    hooks.insert("b".to_string(), b);
    let ResolvedPolicy::Policy {
        on_error,
        on_error_chain,
        ..
    } = resolve_gate_transport("a", &hooks["a"], &hooks, &env, 0).expect("gate a resolves");
    assert_eq!(on_error_chain.len(), 1);
    assert_eq!(
        on_error_chain[0].policy.name(),
        "b",
        "the fallback link is a live HookPolicy"
    );
    assert_eq!(on_error, PolicyOnError::Reject);

    let cands = [dcand(0)];
    let d = on_error_chain[0]
        .policy
        .decide(
            &dreq("x"),
            &cands,
            &dctx(),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("the fallback link decides");
    assert!(matches!(
        d,
        RoutingDecision::Abstain | RoutingDecision::Prefer(_)
    ));
}

#[tokio::test]
async fn dlopen_prompt_no_grant_withholds_content() {
    let env = test_env();

    let mut hook = base_gate();
    hook.settings = serde_json::json!({"order": [0], "reject_if_contains": "BLOCKME"})
        .as_object()
        .cloned()
        .unwrap();
    let hooks = registry("h", hook);
    let ResolvedPolicy::Policy {
        policy,
        send_prompt,
        ..
    } = resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0).expect("resolve");
    assert!(
        !send_prompt,
        "prompt:no grant → no content projected, regardless of manifest intent"
    );

    let mut req = dreq("please BLOCKME");
    req.prompt = None;
    let d = policy
        .decide(
            &req,
            &[dcand(0)],
            &dctx(),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("decide");
    assert_eq!(
        d,
        RoutingDecision::Prefer(vec![0]),
        "no content reached the gate → it ranks, never rejects"
    );
}

#[tokio::test]
async fn dlopen_decide_reject_status_is_clamped() {
    let env = test_env();
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0)];
    for (sent, want) in [
        (400, 400),
        (451, 451),
        (499, 499),
        (200, 403),
        (302, 403),
        (500, 403),
        (0, 403),
        (70000, 403),
    ] {
        let policy = resolve_one(
            &env,
            serde_json::json!({"reject_if_contains": "X", "reject_status": sent}),
        )
        .expect("resolve");
        match policy
            .decide(&dreq("X please"), &cands, &dctx(), budget)
            .await
            .expect("decide")
        {
            RoutingDecision::Reject { status, .. } => {
                assert_eq!(status, want, "sent {sent} must clamp to {want}")
            }
            other => panic!("expected Reject for sent {sent}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn dlopen_decide_restrict_and_fail_closed() {
    let env = test_env();
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0), dcand(1)];

    let policy = resolve_one(
        &env,
        serde_json::json!({"order": [1, 0], "restrict_tags": ["baa"]}),
    )
    .expect("resolve");
    match policy
        .decide(&dreq("x"), &cands, &dctx(), budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Restrict { tags_any } => assert_eq!(tags_any, vec!["baa".to_string()]),
        other => panic!("expected Restrict, got {other:?}"),
    }

    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"restrict": {"tags_any": []}}}),
    )
    .expect("resolve");
    match policy
        .decide(&dreq("x"), &cands, &dctx(), budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Restrict { tags_any } => assert!(
            tags_any.is_empty(),
            "malformed restrict stays Restrict (fail-closed → on_empty), got {tags_any:?}"
        ),
        other => panic!("malformed restrict must stay Restrict, got {other:?}"),
    }
}

#[tokio::test]
async fn dlopen_decide_raw_reply_is_fail_closed() {
    let env = test_env();
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0)];

    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"reject": {"status": "451"}}}),
    )
    .expect("resolve");
    match policy
        .decide(&dreq("x"), &cands, &dctx(), budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Reject { status, .. } => assert_eq!(status, 403),
        other => panic!("malformed reject must stay a 403 Reject, got {other:?}"),
    }

    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"unknown_field": true}}),
    )
    .expect("resolve");
    assert_eq!(
        policy
            .decide(&dreq("x"), &cands, &dctx(), budget)
            .await
            .expect("decide"),
        RoutingDecision::Abstain
    );

    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"reject": false, "order": [0]}}),
    )
    .expect("resolve");
    assert_eq!(
        policy
            .decide(&dreq("x"), &cands, &dctx(), budget)
            .await
            .expect("decide"),
        RoutingDecision::Prefer(vec![0])
    );
}

#[tokio::test]
async fn dlopen_user_identity_projection_rides_the_wire() {
    use crate::test_support::HookNeeds;
    use busbar_contract::plugin_rows::NeedLevel;
    let env = test_env_needs(
        "user-hook",
        HookNeeds {
            prompt: NeedLevel::No,
            user: NeedLevel::Ro,
        },
    );
    let hooks = registry(
        "h",
        HookCfg {
            plugin: "user-hook".to_string(),
            user: UserAccess::Ro,
            ..base_gate()
        },
    );
    let Some(ResolvedPolicy::Policy {
        send_user,
        send_prompt,
        ..
    }) = resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0)
    else {
        panic!("gate must resolve");
    };
    assert!(send_user, "user:ro grant + manifest user need → send_user");
    assert!(
        !send_prompt,
        "no prompt grant/need → prompt content stays withheld"
    );
}

#[tokio::test]
async fn dlopen_decide_deadline_cuts_off_a_slow_gate() {
    let env = test_env();
    let policy =
        resolve_one(&env, serde_json::json!({"order": [0], "sleep_ms": 2000})).expect("resolve");
    let started = std::time::Instant::now();
    let r = policy
        .decide(
            &dreq("x"),
            &[dcand(0)],
            &dctx(),
            std::time::Duration::from_millis(100),
        )
        .await;
    assert!(r.is_err(), "a slow gate must exceed the deadline → Err");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "the deadline must cut the exchange off promptly, not wait out the sleep"
    );
}

#[tokio::test]
async fn dlopen_slow_gate_hits_the_deadline() {
    let env = test_env();
    let policy =
        resolve_one(&env, serde_json::json!({"order": [0], "sleep_ms": 2000})).expect("resolve");
    let started = std::time::Instant::now();
    let r = policy
        .decide(
            &dreq("x"),
            &[dcand(0)],
            &dctx(),
            std::time::Duration::from_millis(100),
        )
        .await;
    assert!(r.is_err(), "a slow gate must exceed the deadline");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "the deadline must cut off promptly"
    );
}

#[tokio::test]
async fn dlopen_empty_management_reads_are_fail_open_none() {
    let env = test_env();
    let mut hook = base_gate();
    hook.settings = serde_json::json!({"empty_management": true})
        .as_object()
        .cloned()
        .unwrap();
    assert!(
        fetch_status("h", &hook, 0, &env).await.is_none(),
        "an empty status reply is fail-open None"
    );
    assert!(
        fetch_schema("h", &hook, 0, &env).await.is_none(),
        "an empty describe reply is fail-open None"
    );
}

#[tokio::test]
async fn dlopen_configure_nack_does_not_commit() {
    let env = test_env();
    let mut hook = base_gate();
    hook.settings = serde_json::json!({"nack_configure": true})
        .as_object()
        .cloned()
        .unwrap();
    assert!(
        push_configure(&hook, "h", 7, &env).await.is_err(),
        "a hook that refuses to ack must fail the configure push (no commit)"
    );
}

#[test]
fn offload_bounded_returns_none_when_the_work_outlives_the_deadline() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let out: Option<()> = offload_bounded_with_deadline(
            "slow-hook",
            std::time::Duration::from_millis(20),
            || {
                std::thread::sleep(std::time::Duration::from_millis(500));
                Some(())
            },
        )
        .await;
        assert!(
            out.is_none(),
            "work that outlives the deadline must resolve to None, not block the caller forever"
        );
    });
}

#[test]
fn offload_bounded_logs_when_the_blocking_task_panics() {

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let output = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(output.clone())
        .finish();

    let out: Option<()> = tracing::subscriber::with_default(subscriber, || {
        rt.block_on(offload_bounded("panicky-hook", || {
            panic!("plugin constructor blew up");
        }))
    });

    assert!(
        out.is_none(),
        "a panicking resolve must still resolve to None, not propagate the panic to the caller"
    );
    let captured = String::from_utf8(output.lock().unwrap().clone()).expect("UTF-8 diagnostics");
    assert!(
        captured.contains("panicky-hook") && captured.contains("panicked"),
        "the panic must be logged, naming the hook and distinct from the ordinary unresolvable \
         case: {:?}",
        captured
    );
}

#[test]
fn settings_drift_reports_only_key_names_and_never_resolves_a_secret() {
    let var = "BUSBAR_TEST_HOOK_DRIFT_SECRET";

    std::env::set_var(var, "hunter2-resolved");
    let mut hook: HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
        "timeout_ms": 5,
        "on_error": "weighted"
    }))
    .unwrap();
    hook.settings = serde_json::json!({
        "api_token": { "env": var },
        "ratio": 0.4,
        // The `{ literal: … }` escape hatch is NOT a reference: the plugin receives the inner value,
        // so the read path must compare against the inner value too.
        "db": { "literal": { "file": "/var/lib/db" } }
    })
    .as_object()
    .unwrap()
    .clone();

    let in_sync = serde_json::json!({
        "api_token": "hunter2-resolved",
        "ratio": 0.4,
        "db": { "file": "/var/lib/db" }
    })
    .as_object()
    .unwrap()
    .clone();
    assert!(
        crate::hooks::settings_drift_keys(&hook, Some(&in_sync)).is_empty(),
        "a hook running EXACTLY the pushed settings is not drifting — comparing the resolved echo \
         against the unresolved `SecretRef` made every secret-bearing hook report drift forever"
    );

    let drifted = serde_json::json!({
        "api_token": "hunter2-resolved",
        "ratio": 0.9,
        "db": { "file": "/var/lib/db" },
        "self_managed": "not drift"
    })
    .as_object()
    .unwrap()
    .clone();
    let keys = crate::hooks::settings_drift_keys(&hook, Some(&drifted));
    assert_eq!(
        keys,
        vec!["ratio".to_string()],
        "drift is reported as DESIRED key names only (an extra self-managed key is not drift)"
    );
    assert!(
        !format!("{keys:?}").contains("hunter"),
        "no value from either bag may ride out on the drift signal: {keys:?}"
    );

    let literal_drift = serde_json::json!({
        "api_token": "hunter2-resolved",
        "ratio": 0.4,
        "db": { "file": "/somewhere/else" }
    })
    .as_object()
    .unwrap()
    .clone();
    assert_eq!(
        crate::hooks::settings_drift_keys(&hook, Some(&literal_drift)),
        vec!["db".to_string()],
        "`{{ literal: … }}` is ordinary data, compared against its INNER value"
    );

    assert!(crate::hooks::settings_drift_keys(&hook, None).is_empty());
}

#[test]
fn settings_drift_never_compares_a_secret_ref_field() {
    let var = "BUSBAR_TEST_HOOK_DRIFT_NO_RESOLVE";
    std::env::set_var(var, "the-real-secret");
    let mut hook: HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
        "timeout_ms": 5,
        "on_error": "weighted"
    }))
    .unwrap();
    hook.settings = serde_json::json!({
        // A built-in `env` reference (resolvable), and a `kind: secret` PLUGIN reference — the arm
        // that is a blocking FFI call, and the one no read path may ever touch.
        "api_token": { "env": var },
        "licenseKey": { "module": "vault", "settings": { "path": "secret/busbar" } },
        "ratio": 0.4
    })
    .as_object()
    .unwrap()
    .clone();

    for echoed in [
        serde_json::json!({ "api_token": "the-real-secret", "licenseKey": "lic-1", "ratio": 0.4 }),
        serde_json::json!({ "api_token": "a-stale-secret", "licenseKey": "lic-2", "ratio": 0.4 }),
    ] {
        let observed = echoed.as_object().unwrap().clone();
        assert!(
            crate::hooks::settings_drift_keys(&hook, Some(&observed)).is_empty(),
            "a SecretRef-valued field is never compared on the read path (and resolving it to \
             compare would be blocking FFI on a polled async GET): {observed:?}"
        );
    }

    let observed = serde_json::json!({
        "api_token": "the-real-secret",
        "licenseKey": "lic-1",
        "ratio": 0.9
    })
    .as_object()
    .unwrap()
    .clone();
    assert_eq!(
        crate::hooks::settings_drift_keys(&hook, Some(&observed)),
        vec!["ratio".to_string()],
        "an ordinary field still drifts — the fix must not blind the endpoint"
    );
}

fn parking_secret_env(park: std::time::Duration) -> HookEnv {
    HookEnv::new(
        crate::test_support::rows::empty(),
        std::sync::Arc::new(crate::config::secret::SecretResolver::with_plugin(
            Box::new(move |_module: &str, _settings: &str| {
                std::thread::sleep(park);
                Ok(busbar_contract::redacted::Secret::new(b"resolved".to_vec()))
            }),
        )),
    )
    .expect("the registry's hook axis")
}

fn hook_with_plugin_secret() -> HookCfg {
    let mut hook = base_gate();
    hook.settings.insert(
        "licenseKey".to_string(),
        serde_json::json!({ "module": "vault", "settings": { "path": "kv/busbar" } }),
    );
    hook
}

fn assert_runtime_still_polls(
    rt: &tokio::runtime::Runtime,
    budget: std::time::Duration,
    msg: &str,
) {
    let canary = rt.spawn(async {});
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if canary.is_finished() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("{msg}");
}

#[test]
fn concurrent_push_configure_does_not_starve_the_runtime() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime");
    let env = parking_secret_env(std::time::Duration::from_secs(3));
    let hook = hook_with_plugin_secret();
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let (h, e) = (hook.clone(), env.clone());
            rt.spawn(
                async move { crate::hooks::push_configure(&h, "compliance-gate", 1, &e).await },
            )
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_runtime_still_polls(
        &rt,
        std::time::Duration::from_millis(750),
        "the runtime stopped polling while four hook settings pushes sat inside the `kind: secret` \
         plugin's synchronous resolve: every Tokio worker is parked in FFI",
    );
    for t in tasks {
        assert!(rt.block_on(async { t.await.expect("task") }).is_err());
    }
}

#[test]
fn any_content_hook_is_true_iff_some_hook_is_granted_prompt_content() {
    assert!(
        !any_content_hook(&HashMap::new()),
        "no hooks at all ⇒ the IR is never built"
    );

    let shape_only = |kind: HookKind| HookCfg {
        kind,
        prompt: PromptAccess::No,
        ..base_gate()
    };
    let mut shape_registry = registry("gate", shape_only(HookKind::Gate));
    shape_registry.insert("tap".to_string(), shape_only(HookKind::Tap));
    assert!(
        !any_content_hook(&shape_registry),
        "every hook shape-only ⇒ still the zero-cost path"
    );

    for (kind, prompt) in [
        (HookKind::Gate, PromptAccess::Ro),
        (HookKind::Gate, PromptAccess::Rw),
        (HookKind::Tap, PromptAccess::Ro),
    ] {
        let granted = HookCfg {
            kind,
            prompt,
            ..base_gate()
        };
        assert!(
            any_content_hook(&registry("granted", granted.clone())),
            "a {kind:?} holding {prompt:?} must open the gate"
        );

        let mut mixed = shape_registry.clone();
        mixed.insert("granted".to_string(), granted);
        assert!(any_content_hook(&mixed));
    }
}

#[test]
fn any_content_hook_ignores_whether_the_granted_hook_is_wired() {
    let granted = HookCfg {
        prompt: PromptAccess::Ro,
        global: false,
        ..base_gate()
    };
    assert!(any_content_hook(&registry("unwired", granted)));
}

fn resolve_rewrite_pair(
    env: &HookEnv,
    settings: &serde_json::Value,
    on_error: &str,
) -> Option<(Arc<dyn RoutingPolicy>, Arc<dyn RoutingPolicy>)> {
    let mut hook = base_gate();
    hook.prompt = PromptAccess::Rw;
    hook.global = true;
    hook.on_error = on_error.to_string();
    hook.settings = settings.as_object().cloned().unwrap_or_default();
    let hooks = registry("h", hook);
    let global = resolve_rewrite_hooks(&hooks, &["h".to_string()], env, 0)
        .into_iter()
        .next()?
        .1;
    let pool = resolve_pool_rewrites(&pool_with_hook("h"), &hooks, env, 0)
        .into_iter()
        .next()?
        .1;
    Some((global, pool))
}

#[tokio::test]
async fn rewrite_call_failure_takes_the_configured_disposition() {
    use busbar_contract::hooks::TransformOutcome;
    let env = test_env();
    let budget = std::time::Duration::from_secs(5);
    let failed = serde_json::json!({"fail_transform": "classifier unreachable"});
    let answered = serde_json::json!({});

    for (on_error, call_failed, expect_refusal) in [
        ("weighted", true, false),
        ("reject", true, true),
        ("weighted", false, false),
        ("reject", false, false),
    ] {
        let settings = if call_failed { &failed } else { &answered };
        let Some((global, pool)) = resolve_rewrite_pair(&env, settings, on_error) else {
            panic!("the rw gate must resolve into both rewrite chains");
        };
        for (which, policy) in [("global", &global), ("pool", &pool)] {
            let outcome = policy.transform(&dreq("hello"), budget).await;
            match (&outcome, expect_refusal, call_failed) {
                (TransformOutcome::Reject { status, message }, true, _) => {
                    assert_eq!(
                        *status,
                        busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
                        "{which}: a failed load-bearing hook refuses with the shared status"
                    );
                    assert_eq!(
                        message,
                        busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
                        "{which}: and the shared, content-free message"
                    );
                }

                (TransformOutcome::Failed { .. }, false, true) => {}

                (TransformOutcome::Rewrite(_), false, false) => {}
                (other, _, _) => panic!(
                    "{which}: on_error={on_error} call_failed={call_failed} \
                     expect_refusal={expect_refusal} got {other:?}"
                ),
            }
        }
    }
}

#[test]
fn only_reject_refuses_a_failed_call() {
    use crate::config::PolicyOnError;
    assert!(busbar_kernel::hooks::failed_call_refuses(
        &PolicyOnError::Reject
    ));
    assert!(!busbar_kernel::hooks::failed_call_refuses(
        &PolicyOnError::Weighted
    ));
    assert!(!busbar_kernel::hooks::failed_call_refuses(
        &PolicyOnError::First
    ));
}

#[test]
fn hook_resolution_reopens_for_a_changed_effective_timeout() {
    struct BudgetAxis {
        inner: Arc<dyn busbar_contract::hook_calls::HookAxis>,
        opened: Arc<std::sync::Mutex<Vec<std::time::Duration>>>,
    }
    impl busbar_contract::hook_calls::HookAxis for BudgetAxis {
        fn probe(
            &self,
            module: &str,
            instance: &str,
            settings: &serde_json::Value,
        ) -> Option<busbar_contract::hook_calls::Probed> {
            self.inner.probe(module, instance, settings)
        }
        fn open(
            &self,
            module: &str,
            instance: &str,
            settings: &serde_json::Value,
            budget: std::time::Duration,
        ) -> Result<Arc<dyn busbar_contract::hook_calls::HookCalls>, String> {
            self.opened.lock().unwrap().push(budget);
            self.inner.open(module, instance, settings, budget)
        }
        fn linked(&self, module: &str) -> bool {
            self.inner.linked(module)
        }
        fn first_party(&self, module: &str) -> bool {
            self.inner.first_party(module)
        }
        fn call_budget(&self) -> std::time::Duration {
            self.inner.call_budget()
        }
    }
    let mut env = test_env();
    let opened = Arc::new(std::sync::Mutex::new(Vec::new()));
    env.axis = Some(Arc::new(BudgetAxis {
        inner: env.axis.clone().unwrap(),
        opened: opened.clone(),
    }));
    let mut hook = base_gate();
    hook.timeout_ms = 41;
    let (first, _) = gate_transport_named("budget", &hook, &env, 0).unwrap();
    let (same, _) = gate_transport_named("budget", &hook, &env, 0).unwrap();
    assert!(Arc::ptr_eq(&first, &same));
    hook.timeout_ms = 84;
    let (changed, _) = gate_transport_named("budget", &hook, &env, 0).unwrap();
    assert!(!Arc::ptr_eq(&first, &changed));
    assert_eq!(
        *opened.lock().unwrap(),
        vec![policy_timeout(41), policy_timeout(84)]
    );

    hook.timeout_ms = 0;
    let (implicit_default, _) = gate_transport_named("budget", &hook, &env, 0).unwrap();
    hook.timeout_ms = crate::limits::default_policy_timeout_ms();
    let (explicit_default, _) = gate_transport_named("budget", &hook, &env, 0).unwrap();
    assert!(Arc::ptr_eq(&implicit_default, &explicit_default));
    assert_eq!(
        *opened.lock().unwrap(),
        vec![policy_timeout(41), policy_timeout(84), policy_timeout(0)]
    );
}
