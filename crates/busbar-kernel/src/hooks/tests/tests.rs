use super::*;
use std::collections::HashSet;

#[test]
fn from_ranked_drops_unknown_and_dedups() {
    let valid: HashSet<usize> = [0usize, 1, 2].into_iter().collect();

    let d = RoutingDecision::from_ranked([2usize, 9, 1, 1, 0], &valid);
    assert_eq!(d, RoutingDecision::Prefer(vec![2, 1, 0]));
}

use crate::config::{HookCfg, HookKind, PoolPolicy, PromptAccess, UserAccess};
use std::collections::HashMap;

#[path = "resolution_tests.rs"]
mod resolution_tests;

const EXTRA_STRATEGY: &str = "operator-order";

#[test]
fn inbound_feedback_reaches_the_policy_instance_and_reload_keeps_old_state_separate() {
    // Arbitrary inbound routes are host-boundary metadata, not an advertised
    // webrequest/ranking product capability. Keep the actual route reuse rule
    // and response forwarding here; actual product transport identity is also
    // exercised by distribution::hooks_runtime_replies.
    let settings = serde_json::Map::new();
    type Identity<'a> = (
        &'a str,
        &'a serde_json::Map<String, serde_json::Value>,
        std::time::Duration,
    );
    let identity: Identity<'_> = (
        "receiver-module",
        &settings,
        std::time::Duration::from_secs(1),
    );
    let matches = |actual: Identity<'_>, requested: Identity<'_>| {
        same_call_inputs(
            actual.0,
            actual.1,
            actual.2,
            requested.0,
            requested.1,
            || requested.2,
        )
    };
    let old_generation = Arc::new(1usize);
    let new_generation = Arc::new(0usize);
    let old_routes = HashMap::from([("receiver".to_owned(), (identity, old_generation.clone()))]);
    let selected = retained_route(&old_routes, "receiver", |entry| matches(entry.0, identity))
        .expect("the route and policy select the retained instance");
    assert!(Arc::ptr_eq(&selected.1, &old_generation));
    let response = hook_route_response(
        "receiver",
        Ok(
            busbar_contract::abi::mechanism::endpoint::EndpointResponse {
                status: 202,
                headers: Vec::new(),
                body: Vec::new(),
            },
        ),
    );
    assert_eq!(response.status, 202);
    let new_routes = HashMap::from([("receiver".to_owned(), (identity, new_generation.clone()))]);
    let old = retained_route(&old_routes, "receiver", |entry| matches(entry.0, identity)).unwrap();
    let new = retained_route(&new_routes, "receiver", |entry| matches(entry.0, identity)).unwrap();
    assert_eq!(
        *old.1, 1,
        "the retained old generation remains selected for its old route"
    );
    assert_eq!(
        *new.1, 0,
        "a new environment selects its independent new instance"
    );
    assert!(!Arc::ptr_eq(&old.1, &new.1));
    assert!(retained_route(&old_routes, "receiver", |entry| matches(
        entry.0,
        ("replacement", identity.1, identity.2)
    ))
    .is_none());
    assert!(retained_route(&old_routes, "receiver", |entry| matches(
        entry.0,
        (identity.0, identity.1, std::time::Duration::from_secs(2)),
    ))
    .is_none());
    let changed = serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(
        serde_json::json!({"url":"changed"}),
    )
    .unwrap();
    assert!(retained_route(&old_routes, "receiver", |entry| matches(
        entry.0,
        (identity.0, &changed, identity.2)
    ))
    .is_none());
}

#[test]
fn plugin_strategy_word_survives_parse_and_uses_the_admitted_axis() {
    let pool = pool_policy(crate::config::parse_strategy(EXTRA_STRATEGY));
    assert_eq!(pool.policy.native_name(), Some(EXTRA_STRATEGY));
    let facts = busbar_contract::hook_calls::HookFacts {
        name: "strategy".into(),
        class: busbar_contract::abi::hook::CLASS_GATE,
        infallible: false,
        words: vec![EXTRA_STRATEGY.into()],
        ..Default::default()
    };
    let settings =
        crate::preflight::ranking_settings_from(EXTRA_STRATEGY, Some((Some(facts), Vec::new())))
            .expect("the advertised strategy word is admitted");
    let (name, _) = crate::preflight::open_ranked(
        EXTRA_STRATEGY,
        &settings,
        std::time::Duration::from_secs(1),
        |module, label, settings, budget| {
            assert_eq!(module, EXTRA_STRATEGY);
            assert_eq!(label, EXTRA_STRATEGY);
            assert_eq!(settings, &serde_json::json!({"policy":EXTRA_STRATEGY}));
            assert_eq!(budget, std::time::Duration::from_secs(1));
            Ok(label.to_owned())
        },
    )
    .expect("admitted strategy construction succeeds");
    assert_eq!(name, EXTRA_STRATEGY);
    // The old synthetic Prefer([1,0]) answer is preserved through actual HTTP
    // in distribution::hooks_runtime_replies, alongside unknown-index filtering.
}

#[test]
fn plugin_strategy_requires_a_declared_word() {
    for (class, infallible, words) in [
        (
            busbar_contract::abi::hook::CLASS_GATE,
            false,
            vec!["different-word".into()],
        ),
        (busbar_contract::abi::hook::CLASS_GATE, true, Vec::new()),
        (
            busbar_contract::abi::hook::CLASS_TAP,
            true,
            vec![EXTRA_STRATEGY.into()],
        ),
    ] {
        let facts = busbar_contract::hook_calls::HookFacts {
            class,
            infallible,
            words,
            ..Default::default()
        };
        assert!(crate::preflight::ranking_settings_from(
            EXTRA_STRATEGY,
            Some((Some(facts), Vec::new()))
        )
        .is_err());
    }
}

#[test]
fn plugin_strategy_open_failure_refuses_pool_construction() {
    let settings = crate::preflight::ranking_settings_from(
        EXTRA_STRATEGY,
        Some((
            Some(busbar_contract::hook_calls::HookFacts {
                class: busbar_contract::abi::hook::CLASS_GATE,
                words: vec![EXTRA_STRATEGY.into()],
                ..Default::default()
            }),
            Vec::new(),
        )),
    )
    .expect("the strategy word is admitted before its constructor runs");
    let error = crate::preflight::open_ranked::<()>(
        EXTRA_STRATEGY,
        &settings,
        std::time::Duration::from_secs(1),
        |module, label, settings, _| {
            assert_eq!(module, EXTRA_STRATEGY);
            assert_eq!(label, EXTRA_STRATEGY);
            assert_eq!(settings, &serde_json::json!({"policy":EXTRA_STRATEGY}));
            Err("strategy constructor refused".into())
        },
    )
    .expect_err("a constructor failure must refuse boot/reload");
    assert!(error.contains("strategy constructor refused"));
}

fn empty_env() -> HookEnv {
    HookEnv::new(
        std::sync::Arc::new(busbar_plugin_loader::PluginRegistry::empty()),
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
    let resolver = crate::config::secret::SecretResolver::builtins_only();
    let open = |_: &str, hook: &HookCfg| {
        crate::config::secret::resolve_settings(
            &hook.settings,
            &[],
            &[],
            &hook.plugin,
            &resolver,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map(|_| ())
    };

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
        preopen_definitions(&tap_hooks, |_| true, open, |_, _, ()| Ok(())).is_ok(),
        "a broken TAP must never abort boot/reload (taps fail-open)"
    );

    let mut broken_gate = base_gate();
    broken_gate.settings = settings;
    let gate_hooks = registry("broken-gate", broken_gate);
    let err = preopen_definitions(&gate_hooks, |_| true, open, |_, _, ()| Ok(()))
        .expect_err("a gate whose settings/open() fails must abort boot/reload CLOSED");
    assert!(
        err.contains("broken-gate"),
        "the error names the offending gate: {err}"
    );

    let ok_hooks = registry("ok-gate", base_gate());
    assert!(
        preopen_definitions(&ok_hooks, |_| true, open, |_, _, ()| Ok(())).is_ok(),
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
fn default_hook_resolves_as_base_for_unnamed_pools() {
    let mut def = base_gate();
    def.default = true;
    let mut hooks = registry("def", def);

    hooks.insert("h".to_string(), base_gate());

    assert_eq!(default_hook_name(&hooks), Some("def"));

    let mut unnamed = pool_with_hook("x");
    unnamed.gates.clear();
    assert!(
        inherited_ordering(&unnamed, &hooks, Some("def")).is_some(),
        "an unnamed-base pool inherits the default hook as its ordering"
    );

    assert!(
        inherited_ordering(&pool_policy(PoolPolicy::Weighted), &hooks, Some("def")).is_none(),
        "a pool that named its base keeps it; the default does not override"
    );

    let gated = pool_with_hook("h");
    assert!(
        inherited_ordering(&gated, &hooks, Some("def")).is_some(),
        "an unnamed-base pool with its own gate still inherits the default as base"
    );
    assert_eq!(
        decision_definitions(&hooks, &gated.gates).len(),
        1,
        "the pool's own gate resolves separately, on top of the inherited base"
    );

    assert!(
        inherited_ordering(&unnamed, &HashMap::new(), None).is_none(),
        "no default hook ⇒ the compiled-in weighted backstop (None)"
    );
}

#[test]
fn default_rw_hook_is_not_the_base_ordering() {
    let mut rw = base_gate();
    rw.prompt = PromptAccess::Rw;
    rw.default = true;
    let hooks = registry("def", rw);
    let mut unnamed = pool_with_hook("x");
    unnamed.gates.clear();
    assert!(
        inherited_ordering(&unnamed, &hooks, Some("def")).is_none(),
        "a prompt:rw default hook must not become the base ordering — it can never return an order"
    );

    let mut tap = base_gate();
    tap.kind = HookKind::Tap;
    tap.default = true;
    let hooks = registry("deftap", tap);
    let mut unnamed2 = pool_with_hook("x");
    unnamed2.gates.clear();
    assert!(
        inherited_ordering(&unnamed2, &hooks, Some("deftap")).is_none(),
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
fn weighted_default_resolves_none() {
    assert!(resolve_policy(&pool_policy(PoolPolicy::Weighted)).is_none());
}

// resolution::Entry and resolution::Paths retain Weak references to their registry.
// The Weak control block retains that allocation until the last Weak is dropped;
// a live cache entry therefore cannot observe an allocator-recycled registry address.
// Missing-row behavior remains asserted below; replacement identity is asserted by
// resolution_tests::replacing_the_public_registry_cannot_reuse_a_stale_path_snapshot,
// and actual transport reuse/change is asserted in distribution::hooks_runtime_replies.
#[test]
fn missing_plugin_gate_is_absent_not_stranded() {
    let hooks = registry("h", base_gate());

    assert!(resolve_pool_gates(&pool_with_hook("h"), &hooks, &empty_env(), 0).is_empty());
}

#[test]
fn resolve_rewrite_hooks_admits_only_prompt_rw_gates() {
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
    let resolved = rewrite_definitions(&hooks, &global, |name, hook| {
        access_from_intent(
            name,
            hook,
            Needs {
                prompt: busbar_contract::plugin_rows::NeedLevel::Rw,
                user: busbar_contract::plugin_rows::NeedLevel::Ro,
            },
            &std::sync::Mutex::new(HashSet::new()),
        )
        .0
        .can_rewrite()
    });
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
    use busbar_contract::plugin_rows::NeedLevel;

    for (need, admitted) in [
        (NeedLevel::No, false),
        (NeedLevel::Ro, false),
        (NeedLevel::Rw, true),
    ] {
        let needs = Needs {
            prompt: need,
            user: NeedLevel::No,
        };
        let banners = std::sync::Mutex::new(HashSet::new());

        let mut rw = base_gate();
        rw.prompt = PromptAccess::Rw;
        rw.global = true;
        let hooks = registry("rw", rw);

        let global_names = ["rw".to_string()];
        let global = rewrite_definitions(&hooks, &global_names, |name, hook| {
            access_from_intent(name, hook, needs, &banners)
                .0
                .can_rewrite()
        });
        assert_eq!(
            !global.is_empty(),
            admitted,
            "global rewrite chain: `prompt: rw` + manifest `needs.prompt: {need:?}` must \
             {} admit — the operator grant alone is not the ticket",
            if admitted { "" } else { "NOT " }
        );
        let pool_cfg = pool_with_hook("rw");
        let pool = rewrite_definitions(&hooks, &pool_cfg.gates, |name, hook| {
            access_from_intent(name, hook, needs, &banners)
                .0
                .can_rewrite()
        });
        assert_eq!(
            !pool.is_empty(),
            admitted,
            "pool rewrite chain: `prompt: rw` + manifest `needs.prompt: {need:?}` must {} admit \
             — the per-pool resolver is a SIBLING of the global one and must not diverge",
            if admitted { "" } else { "NOT " }
        );

        let send_prompt = access_from_intent("rw", &hooks["rw"], needs, &banners)
            .0
            .sends_prompt();
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

    let env_needs = Needs {
        prompt: NeedLevel::No,
        user: NeedLevel::No,
    };
    let env_banners = std::sync::Mutex::new(HashSet::new());
    let mut h = base_gate();
    h.plugin = "inert-prompt".to_string();
    h.prompt = PromptAccess::Ro;
    tracing::subscriber::with_default(sub, || {
        let _ = access_from_intent("h", &h, env_needs, &env_banners);
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
    let env2_needs = Needs {
        prompt: NeedLevel::Ro,
        user: NeedLevel::No,
    };
    let env2_banners = std::sync::Mutex::new(HashSet::new());
    let mut h2 = base_gate();
    h2.plugin = "matched-prompt".to_string();
    h2.prompt = PromptAccess::Ro;
    tracing::subscriber::with_default(sub2, || {
        let _ = access_from_intent("h2", &h2, env2_needs, &env2_banners);
    });
    assert!(
        events2.lock().unwrap().is_empty(),
        "a grant the manifest DOES declare must not warn: {:?}",
        events2.lock().unwrap()
    );

    let events3: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub3 = LineCapturingSubscriber(events3.clone());
    let env3_needs = Needs {
        prompt: NeedLevel::No,
        user: NeedLevel::No,
    };
    let env3_banners = std::sync::Mutex::new(HashSet::new());
    let mut h3 = base_gate();
    h3.plugin = "inert-user".to_string();
    h3.user = UserAccess::Ro;
    tracing::subscriber::with_default(sub3, || {
        let _ = access_from_intent("h3", &h3, env3_needs, &env3_banners);
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
    let env4_needs = Needs {
        prompt: NeedLevel::No,
        user: NeedLevel::Ro,
    };
    let env4_banners = std::sync::Mutex::new(HashSet::new());
    let mut h4 = base_gate();
    h4.plugin = "matched-user".to_string();
    h4.user = UserAccess::Ro;
    tracing::subscriber::with_default(sub4, || {
        let _ = access_from_intent("h4", &h4, env4_needs, &env4_banners);
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

    let env_needs = Needs {
        prompt: NeedLevel::Ro,
        user: NeedLevel::No,
    };
    let env_banners = std::sync::Mutex::new(HashSet::new());
    let mut h = base_gate();
    h.plugin = "inert-rewrite".to_string();
    h.prompt = PromptAccess::Rw;

    assert!(
        !env_banners.lock().unwrap().contains("h"),
        "banner_seen must start empty for this name"
    );
    tracing::subscriber::with_default(sub, || {
        let _ = access_from_intent("h", &h, env_needs, &env_banners);
    });
    assert!(
        env_banners.lock().unwrap().contains("h"),
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
        let _ = access_from_intent("h", &h, env_needs, &env_banners);
    });
    assert!(
        events2.lock().unwrap().is_empty(),
        "a hook already in banner_seen must not re-banner on a second resolution: {:?}",
        events2.lock().unwrap()
    );

    let events3: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub3 = LineCapturingSubscriber(events3.clone());
    let env3_needs = Needs {
        prompt: NeedLevel::Rw,
        user: NeedLevel::No,
    };
    let env3_banners = std::sync::Mutex::new(HashSet::new());
    let mut h3 = base_gate();
    h3.plugin = "matched-rewrite".to_string();
    h3.prompt = PromptAccess::Rw;
    tracing::subscriber::with_default(sub3, || {
        let _ = access_from_intent("clean", &h3, env3_needs, &env3_banners);
    });
    assert!(
        !env3_banners.lock().unwrap().contains("clean"),
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
    let resolved = decision_definitions(&hooks, &global);
    assert_eq!(
        resolved.len(),
        2,
        "decision gates = the ro + no gates; the rw (rewrite) gate and the tap are excluded"
    );
}

#[test]
fn resolve_tap_hooks_admits_only_request_stage_taps() {
    use crate::config::HookStage;
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
    let resolved = tap_definitions(&hooks, &global, crate::config::HookStage::Request);
    assert_eq!(
        resolved.len(),
        2,
        "only the two REQUEST-stage taps resolve; the gate and the completion-stage tap are excluded"
    );

    let completion = tap_definitions(&hooks, &global, crate::config::HookStage::Response);
    assert_eq!(
        completion.len(),
        2,
        "the explicit response-stage tap AND the unset tap (omitted = the four core stages)"
    );

    assert_eq!(
        tap_definitions(&hooks, &global, crate::config::HookStage::Routing).len(),
        1,
        "only the phase-unset tap observes the routing stage (omitted = the four core stages)"
    );

    assert!(
        resolved.iter().all(|(name, hook)| !access_from_intent(
            name,
            hook,
            Needs {
                prompt: busbar_contract::plugin_rows::NeedLevel::Rw,
                user: busbar_contract::plugin_rows::NeedLevel::Ro
            },
            &std::sync::Mutex::new(HashSet::new())
        )
        .0
        .sends_prompt()),
        "a prompt:no tap must not carry the prompt-content grant"
    );
}

#[test]
fn resolve_tap_hooks_honors_phase_list() {
    use crate::config::HookStage;
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
        tap_definitions(&hooks, &global, HookStage::Response).len(),
        2,
        "both taps declare the response phase"
    );

    assert_eq!(
        tap_definitions(&hooks, &global, HookStage::Request).len(),
        1,
        "phase: [response] does not fire at the request stage"
    );

    assert!(tap_definitions(&hooks, &global, HookStage::Candidate).is_empty());
    assert!(tap_definitions(&hooks, &global, HookStage::Routing).is_empty());
}

#[test]
fn resolve_tap_hooks_carries_prompt_grant() {
    let mk = |prompt: PromptAccess| HookCfg {
        kind: HookKind::Tap,
        prompt,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("ro-tap".to_string(), mk(PromptAccess::Ro));
    hooks.insert("no-tap".to_string(), mk(PromptAccess::No));
    let names = ["ro-tap".to_string(), "no-tap".to_string()];
    let resolved = tap_definitions(&hooks, &names, crate::config::HookStage::Request);
    assert_eq!(resolved.len(), 2);

    let ro_names = ["ro-tap".to_string()];
    let ro = tap_definitions(&hooks, &ro_names, crate::config::HookStage::Request);
    let no_names = ["no-tap".to_string()];
    let no = tap_definitions(&hooks, &no_names, crate::config::HookStage::Request);
    let needs = Needs {
        prompt: busbar_contract::plugin_rows::NeedLevel::Rw,
        user: busbar_contract::plugin_rows::NeedLevel::Ro,
    };
    let banners = std::sync::Mutex::new(HashSet::new());
    assert!(
        access_from_intent(ro[0].0, ro[0].1, needs, &banners)
            .0
            .sends_prompt(),
        "prompt:ro tap carries send_prompt = true"
    );
    assert!(
        !access_from_intent(no[0].0, no[0].1, needs, &banners)
            .0
            .sends_prompt(),
        "prompt:no tap carries send_prompt = false"
    );
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
fn gate_grants_pass_through_as_projection_flags() {
    let hook = HookCfg {
        prompt: PromptAccess::Ro,
        user: UserAccess::Ro,
        ..base_gate()
    };
    let (prompt, user) = access_from_intent(
        "h",
        &hook,
        Needs {
            prompt: busbar_contract::plugin_rows::NeedLevel::Rw,
            user: busbar_contract::plugin_rows::NeedLevel::Ro,
        },
        &std::sync::Mutex::new(HashSet::new()),
    );
    assert!(
        prompt.sends_prompt(),
        "prompt:ro grant + manifest need must pass send_prompt through"
    );
    assert!(
        user.sends_user(),
        "user:ro grant + manifest need must pass send_user through"
    );
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
        let needs = Needs {
            prompt: need,
            user: NeedLevel::No,
        };
        let hooks = registry(
            "h",
            HookCfg {
                plugin: alias.clone(),
                prompt: grant,
                ..base_gate()
            },
        );
        let (prompt, _) = access_from_intent(
            "h",
            &hooks["h"],
            needs,
            &std::sync::Mutex::new(HashSet::new()),
        );
        let send_prompt = prompt.sends_prompt();
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
        let needs = Needs {
            prompt: NeedLevel::No,
            user: need,
        };
        let hooks = registry(
            "h",
            HookCfg {
                plugin: alias.clone(),
                user: grant,
                ..base_gate()
            },
        );
        let (_, user) = access_from_intent(
            "h",
            &hooks["h"],
            needs,
            &std::sync::Mutex::new(HashSet::new()),
        );
        let send_user = user.sends_user();
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

#[tokio::test]
async fn dlopen_user_identity_projection_rides_the_wire() {
    use busbar_contract::plugin_rows::NeedLevel;
    let hook = HookCfg {
        plugin: "user-hook".into(),
        user: UserAccess::Ro,
        ..base_gate()
    };
    let (prompt, user) = access_from_intent(
        "h",
        &hook,
        Needs {
            prompt: NeedLevel::No,
            user: NeedLevel::Ro,
        },
        &std::sync::Mutex::new(HashSet::new()),
    );
    assert!(
        user.sends_user(),
        "user:ro grant + manifest user need → send_user"
    );
    assert!(
        !prompt.sends_prompt(),
        "no prompt grant/need → prompt content stays withheld"
    );
}

#[test]
fn dlopen_empty_management_reads_are_fail_open_none() {
    // The actual product always publishes its own status/schema. Empty replies
    // exercise the wire documents HookPolicy consumes, without a fake plugin.
    let status = serde_json::from_slice::<busbar_contract::hook_wire::reply::StatusEnvelope>(b"")
        .ok()
        .and_then(|reply| reply.status);
    assert!(status.is_none(), "an empty status reply is fail-open None");
    let schema = serde_json::from_slice::<busbar_contract::hook_wire::reply::DescribeReply>(b"")
        .ok()
        .and_then(|reply| reply.schema);
    assert!(
        schema.is_none(),
        "an empty describe reply is fail-open None"
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
    struct Output(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let writing = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || Output(writing.clone()))
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
        std::sync::Arc::new(busbar_plugin_loader::PluginRegistry::empty()),
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
