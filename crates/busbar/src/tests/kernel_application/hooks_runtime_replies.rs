// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

/// Ordinary hook wire, deadline, cache and configure oracles through actual products.
#[tokio::test]
async fn runtime_replies_and_control_plane_use_the_actual_webrequest_product() {
    crate::dist_root_install::install();
    let response = Arc::new(std::sync::Mutex::new((
        serde_json::json!({}),
        0u64,
        axum::http::StatusCode::OK,
    )));
    let recorded = Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
    let returning = response.clone();
    let recording = recorded.clone();
    let routes = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            let (reply, delay, status) = returning.lock().unwrap().clone();
            recording.lock().unwrap().push(body);
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                (status, axum::Json(reply))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/hook", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, routes).await.unwrap();
    });
    let directory = plugins::scratch(&format!(
        "kernel-runtime-replies-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let mut store_module = None;
    let mut hook_module = None;
    for (kind, variable) in [
        ("store", "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN"),
        ("hook", "BUSBAR_TEST_WEBREQUEST_CDYLIB"),
    ] {
        let path = PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
            panic!("{variable} must name the actual built product cdylib; this test never skips")
        }));
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
            .expect("the actual product statement reads")
            .expect("the actual product exports its statement");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual product statement is valid");
        let mut manifest = plugins::manifest(
            kind,
            &facts.name,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        if kind == "hook" {
            // These are the actual webrequest product's declared content needs,
            // signed alongside its exact door rendering, not a synthetic hook tail.
            manifest.needs.prompt = busbar_contract::plugin_rows::NeedLevel::Rw;
            manifest.needs.user = busbar_contract::plugin_rows::NeedLevel::Ro;
            hook_module = Some(facts.name);
        } else {
            store_module = Some(facts.name);
        }
        let library = std::fs::read(&path).expect("the actual product library reads");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join(format!("{kind}-product.tar.gz")), archive)
            .expect("stage the signed actual product archive");
    }
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let hook_module = hook_module.expect("the actual hook was staged");
    let credential = directory.join("upstream-credential");
    std::fs::write(&credential, b"pool-admission-unused-upstream-credential")
        .expect("write the normal file-backed upstream credential");
    let document = serde_json::json!({
        "providers": {
            "local": {"protocol": "anthropic", "base_url": "http://127.0.0.1:1",
                      "api_key": {"file": credential}}
        },
        "models": {"local-model": {"provider": "local"}},
        "auth": {"chain": [], "admin_auth": []},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
        "store": {"module": store_module.expect("the actual store was staged"), "settings": settings},
        "hooks": {
            "a": {"module": hook_module, "kind": "gate", "timeout_ms":5000, "on_error":"b", "settings":{"url":endpoint}},
            "b": {"module": hook_module, "kind": "gate", "timeout_ms":5000, "on_error":"reject", "settings":{"url":endpoint}},
            "n": {"module": hook_module, "kind": "gate", "timeout_ms":5000, "on_error":"nothing", "settings":{"url":endpoint}},
            "c": {"module": hook_module, "kind": "gate", "timeout_ms":5000, "on_error":"first", "settings":{"url":endpoint}},
            "g": {"module": hook_module, "kind": "gate", "timeout_ms":5000, "on_error":"cheapest", "settings":{"url":endpoint}},
            "closedrw": {"module": hook_module, "kind":"gate", "timeout_ms":5000,
                         "prompt":"rw", "on_error":"reject", "settings":{"url":endpoint}},
            "rw": {"module": hook_module, "kind": "gate", "timeout_ms": 5000, "prompt": "rw",
                   "settings": {"url": endpoint}},
            "read": {"module": hook_module, "kind": "gate", "timeout_ms": 5000, "prompt": "ro",
                     "settings": {"url": endpoint}},
            "plain": {"module": hook_module, "kind": "gate", "timeout_ms": 5000, "prompt": "no",
                      "settings": {"url": endpoint}}
        },
        "pools": {
            "hooks": ["rw","closedrw"],
            "closedrw": {"members":["local-model"],"hooks":["closedrw"]},
            "a": {"members":["local-model"], "hooks":["a"]},
            "n": {"members":["local-model"], "hooks":["n"]},
            "c": {"members":["local-model"], "hooks":["c"]},
            "g": {"members":["local-model"], "hooks":["g"]},
            "read": {"members": ["local-model"], "hooks": ["read"]},
            "rewrite": {"members": ["local-model"], "hooks": ["rw"]},
            "decision": {"members": ["local-model"], "hooks": ["plain"]}
        }
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual product deployment resolves");
    let plugins = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugins,
        None,
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual root opens the signed products and builds the pool chains");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }

    use busbar_contract::hooks::{
        Candidate, PromptProjection, RoutingContext, RoutingDecision, RoutingRequest,
    };
    use busbar_kernel::hooks::ResolvedPolicy;
    let request = |text: &'static str| RoutingRequest {
        request_id: 1,
        pool: "read",
        ingress_protocol: "anthropic",
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
            messages: vec![("user".into(), text.into())],
        }),
        identity: None,
        signals: Default::default(),
        session: None,
    };
    let candidate = |idx| Candidate {
        idx,
        model: "local-model",
        provider: "local",
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
    };
    let candidates = [candidate(0), candidate(1)];
    let context = RoutingContext {
        pool: "read",
        budget_remaining: None,
        budget: &[],
    };
    let budget = std::time::Duration::from_secs(5);
    let ResolvedPolicy::Policy { policy, .. } = &app.pool_gates("read")[0].1;

    // dlopen_decide_order_and_abstain: actual host normalization still drops unknown idx9.
    response.lock().unwrap().0 = serde_json::json!({"order": [9,1,0]});
    assert_eq!(
        policy
            .decide(&request("hi"), &candidates, &context, budget)
            .await
            .expect("decide"),
        RoutingDecision::Prefer(vec![1, 0]),
        "unknown idx 9 dropped by the real normalizer"
    );
    response.lock().unwrap().0 = serde_json::json!({});
    assert_eq!(
        policy
            .decide(&request("hi"), &candidates, &context, budget)
            .await
            .expect("decide"),
        RoutingDecision::Abstain
    );

    // dlopen_decide_reject_status_is_clamped: preserve all eight sent/status cells.
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
        response.lock().unwrap().0 =
            serde_json::json!({"reject": {"status": sent, "message": "blocked"}});
        match policy
            .decide(&request("X please"), &candidates[..1], &context, budget)
            .await
            .expect("decide")
        {
            RoutingDecision::Reject { status, .. } => {
                assert_eq!(status, want, "sent {sent} must clamp to {want}")
            }
            other => panic!("expected Reject for sent {sent}, got {other:?}"),
        }
    }
    // dlopen_decide_restrict_and_fail_closed: narrowing wins over order; empty stays Restrict.
    response.lock().unwrap().0 =
        serde_json::json!({"order":[1,0], "restrict":{"tags_any":["baa"]}});
    match policy
        .decide(&request("x"), &candidates, &context, budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Restrict { tags_any } => assert_eq!(tags_any, vec!["baa".to_string()]),
        other => panic!("expected Restrict, got {other:?}"),
    }
    response.lock().unwrap().0 = serde_json::json!({"restrict":{"tags_any":[]}});
    match policy
        .decide(&request("x"), &candidates, &context, budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Restrict { tags_any } => assert!(
            tags_any.is_empty(),
            "malformed restrict stays Restrict (fail-closed → on_empty), got {tags_any:?}"
        ),
        other => panic!("malformed restrict must stay Restrict, got {other:?}"),
    }
    // dlopen_decide_raw_reply_is_fail_closed: exact malformed reject/unknown/false cases.
    response.lock().unwrap().0 = serde_json::json!({"reject":{"status":"451"}});
    match policy
        .decide(&request("x"), &candidates[..1], &context, budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Reject { status, .. } => assert_eq!(status, 403),
        other => panic!("malformed reject must stay a 403 Reject, got {other:?}"),
    }
    for (reply, want) in [
        (
            serde_json::json!({"unknown_field":true}),
            RoutingDecision::Abstain,
        ),
        (
            serde_json::json!({"reject":false,"order":[0]}),
            RoutingDecision::Prefer(vec![0]),
        ),
    ] {
        response.lock().unwrap().0 = reply;
        assert_eq!(
            policy
                .decide(&request("x"), &candidates[..1], &context, budget)
                .await
                .expect("decide"),
            want
        );
    }
    // Both original deadline tests retain their independent Err + less-than-one-second oracles.
    for which in [
        "dlopen_decide_deadline_cuts_off_a_slow_gate",
        "dlopen_slow_gate_hits_the_deadline",
    ] {
        *response.lock().unwrap() = (
            serde_json::json!({"order":[0]}),
            2000,
            axum::http::StatusCode::OK,
        );
        let started = std::time::Instant::now();
        let result = policy
            .decide(
                &request("x"),
                &candidates[..1],
                &context,
                std::time::Duration::from_millis(100),
            )
            .await;
        assert!(
            result.is_err(),
            "{which}: a slow gate must exceed the deadline"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "{which}: the deadline must cut the exchange off promptly, not wait out the sleep"
        );
    }
    response.lock().unwrap().1 = 0;
    response.lock().unwrap().0 = serde_json::json!({"order":[0]});
    // Actual no-grant transport receives no messages and cannot screen withheld content.
    let ResolvedPolicy::Policy {
        policy: plain,
        send_prompt,
        ..
    } = &app.pool_gates("decision")[0].1;
    assert!(
        !send_prompt,
        "prompt:no grant → no content projected, regardless of manifest intent"
    );
    let mut withheld = request("please BLOCKME");
    withheld.prompt = None;
    assert_eq!(
        plain
            .decide(&withheld, &candidates[..1], &context, budget)
            .await
            .expect("decide"),
        RoutingDecision::Prefer(vec![0]),
        "no content reached the gate → it ranks, never rejects"
    );
    assert!(recorded.lock().unwrap().last().unwrap()["request"]
        .get("messages")
        .is_none());

    // The resolved fallback graph carries actual live products, not synthetic policy objects.
    use busbar_kernel::config::PolicyOnError;
    let ResolvedPolicy::Policy {
        on_error,
        on_error_chain,
        ..
    } = &app.pool_gates("a")[0].1;
    assert_eq!(on_error_chain.len(), 1, "one fallback link (gate b)");
    assert_eq!(
        on_error_chain[0].policy.name(),
        "b",
        "the fallback link is a live HookPolicy"
    );
    assert_eq!(
        *on_error,
        PolicyOnError::Reject,
        "the chain bottoms out on b's reject terminal"
    );
    let answer = on_error_chain[0]
        .policy
        .decide(&request("x"), &candidates[..1], &context, budget)
        .await
        .expect("the fallback link decides");
    assert!(matches!(
        answer,
        RoutingDecision::Abstain | RoutingDecision::Prefer(_)
    ));
    let ResolvedPolicy::Policy {
        on_error,
        on_error_chain,
        ..
    } = &app.pool_gates("n")[0].1;
    assert!(on_error_chain.is_empty());
    assert_eq!(
        *on_error,
        PolicyOnError::Weighted,
        "nothing = the non-participating terminal"
    );
    let ResolvedPolicy::Policy {
        on_error,
        on_error_chain,
        ..
    } = &app.pool_gates("c")[0].1;
    assert!(on_error_chain.is_empty(), "a terminal name has no chain");
    assert_eq!(*on_error, PolicyOnError::First);
    let ResolvedPolicy::Policy {
        on_error,
        on_error_chain,
        ..
    } = &app.pool_gates("g")[0].1;
    assert_eq!(on_error_chain.len(), 1);
    assert_eq!(on_error_chain[0].policy.name(), "cheapest");
    assert_eq!(*on_error, PolicyOnError::Weighted);

    // Re-resolving identical admitted row+instance+settings reuses the actual product transport.
    let pool = busbar_kernel::config::PoolCfg {
        gates: vec!["read".into()],
        ..Default::default()
    };
    let first =
        busbar_kernel::hooks::resolve_pool_gates(&pool, &app.hook_registry, &app.hook_env, 0);
    let second =
        busbar_kernel::hooks::resolve_pool_gates(&pool, &app.hook_registry, &app.hook_env, 0);
    let ResolvedPolicy::Policy { policy: first, .. } = &first[0].1;
    let ResolvedPolicy::Policy { policy: second, .. } = &second[0].1;
    assert!(Arc::ptr_eq(first,second),
        "a second resolution of the same hook+settings+registry must reuse the published load, not open a second image");
    let mut changed = app.hook_registry.clone();
    changed
        .get_mut("read")
        .unwrap()
        .settings
        .insert("timeout_ms".into(), serde_json::json!(2000));
    let third = busbar_kernel::hooks::resolve_pool_gates(&pool, &changed, &app.hook_env, 0);
    let ResolvedPolicy::Policy { policy: third, .. } = &third[0].1;
    assert!(
        !Arc::ptr_eq(first, third),
        "a change of settings must resolve a NEW transport, never reuse the old one"
    );

    // The normal root has already published the product before the control-plane push.
    assert!(
        matches!(
            busbar_kernel::hooks::transport_publication_for_test(
                "read",
                &app.hook_registry["read"],
                &app.hook_env
            ),
            Some((true, _))
        ),
        "the loader must publish a transport for a loadable hook plugin"
    );
    let mut acknowledged = false;
    let mut last = String::new();
    for _ in 0..4 {
        match busbar_kernel::hooks::push_configure(
            &app.hook_registry["read"],
            "read",
            7,
            &app.hook_env,
        )
        .await
        {
            Ok(()) => {
                acknowledged = true;
                break;
            }
            Err(error) if error.contains("deadline") || error.contains("unresolvable") => {
                last = error
            }
            Err(error) => panic!("the plugin must ack the pushed version exactly: {error}"),
        }
    }
    assert!(acknowledged,"push_configure hit its shipped 5s deadline 4 times in a row ({last}); that is a wedged plugin or a hang, not scheduling delay");
    let before = policy.status(budget).await.expect("status").settings;
    let invalid = serde_json::json!({"url":""}).as_object().unwrap().clone();
    assert!(
        policy.configure("read", &invalid, 8, budget).await.is_err(),
        "a hook that refuses to ack must fail the configure push (no commit)"
    );
    assert_eq!(
        policy
            .status(budget)
            .await
            .expect("status after NACK")
            .settings,
        before,
        "a rejected actual product push must not commit new settings"
    );
    // Secret indirection is never eligible for publication; plain settings are.
    let mut with_secret = app.hook_registry["read"].clone();
    with_secret.settings.insert(
        "licenseKey".into(),
        serde_json::json!({"env":"BUSBAR_TEST_HOOK_LICENSE_KEY"}),
    );
    assert_eq!(
        busbar_kernel::hooks::transport_publication_for_test("read", &with_secret, &app.hook_env),
        None,
        "a SecretRef-carrying hook must be resolved fresh every time, never published for reuse"
    );
    assert!(
        busbar_kernel::hooks::transport_publication_for_test(
            "read",
            &app.hook_registry["read"],
            &app.hook_env
        )
        .is_some(),
        "a hook with no secret indirection is eligible"
    );

    // Actual policy identities and returned deadlines replace BudgetAxis call bookkeeping.
    let mut budget_hooks = app.hook_registry.clone();
    budget_hooks.get_mut("read").unwrap().timeout_ms = 41;
    let first = busbar_kernel::hooks::resolve_pool_gates(&pool, &budget_hooks, &app.hook_env, 0);
    let same = busbar_kernel::hooks::resolve_pool_gates(&pool, &budget_hooks, &app.hook_env, 0);
    let ResolvedPolicy::Policy {
        policy: first,
        timeout: first_budget,
        ..
    } = &first[0].1;
    let ResolvedPolicy::Policy { policy: same, .. } = &same[0].1;
    assert!(Arc::ptr_eq(first, same));
    budget_hooks.get_mut("read").unwrap().timeout_ms = 84;
    let changed = busbar_kernel::hooks::resolve_pool_gates(&pool, &budget_hooks, &app.hook_env, 0);
    let ResolvedPolicy::Policy {
        policy: changed,
        timeout: changed_budget,
        ..
    } = &changed[0].1;
    assert!(!Arc::ptr_eq(first, changed));
    assert_eq!(
        [*first_budget, *changed_budget],
        [
            std::time::Duration::from_millis(41),
            std::time::Duration::from_millis(84)
        ]
    );
    budget_hooks.get_mut("read").unwrap().timeout_ms = 0;
    let implicit = busbar_kernel::hooks::resolve_pool_gates(&pool, &budget_hooks, &app.hook_env, 0);
    budget_hooks.get_mut("read").unwrap().timeout_ms =
        busbar_kernel::config::DEFAULT_POLICY_TIMEOUT_MS;
    let explicit = busbar_kernel::hooks::resolve_pool_gates(&pool, &budget_hooks, &app.hook_env, 0);
    let ResolvedPolicy::Policy {
        policy: implicit,
        timeout: default_budget,
        ..
    } = &implicit[0].1;
    let ResolvedPolicy::Policy {
        policy: explicit, ..
    } = &explicit[0].1;
    assert!(Arc::ptr_eq(implicit, explicit));
    assert_eq!(
        [*first_budget, *changed_budget, *default_budget],
        [
            std::time::Duration::from_millis(41),
            std::time::Duration::from_millis(84),
            std::time::Duration::from_millis(busbar_kernel::config::DEFAULT_POLICY_TIMEOUT_MS)
        ]
    );

    // A real policy has the configured instance name and documented default deadline.
    let mut named = app.hook_registry["read"].clone();
    named.timeout_ms = busbar_kernel::config::DEFAULT_POLICY_TIMEOUT_MS;
    let definitions = std::collections::HashMap::from([("h".into(), named)]);
    let named_pool = busbar_kernel::config::PoolCfg {
        gates: vec!["h".into()],
        ..Default::default()
    };
    let named =
        busbar_kernel::hooks::resolve_pool_gates(&named_pool, &definitions, &app.hook_env, 0);
    let ResolvedPolicy::Policy {
        policy: named,
        timeout,
        ..
    } = &named[0].1;
    assert_eq!(
        named.name(),
        "h",
        "the HookPolicy carries the hook's registry name"
    );
    assert_eq!(
        *timeout,
        std::time::Duration::from_millis(busbar_kernel::config::DEFAULT_POLICY_TIMEOUT_MS),
        "a gate with the default timeout resolves to the documented deadline, not 0ms"
    );
    let empty = busbar_kernel::hooks::HookEnv::new(
        Arc::new(busbar_plugin_loader::PluginRegistry::empty()),
        Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
    )
    .expect("the actual empty registry's hook axis");
    assert!(
        busbar_kernel::hooks::resolve_pool_gates(&named_pool, &definitions, &empty, 0).is_empty()
    );
    // Both actual global and pool wrappers preserve all four failed-call dispositions.
    use busbar_contract::hooks::TransformOutcome;
    for (on_error, call_failed, expect_refusal) in [
        ("weighted", true, false),
        ("reject", true, true),
        ("weighted", false, false),
        ("reject", false, false),
    ] {
        let name = if on_error == "reject" {
            "closedrw"
        } else {
            "rw"
        };
        {
            let mut reply = response.lock().unwrap();
            reply.0 =
                serde_json::json!({"rewrite":{"messages":[{"role":"user","content":"rewritten"}]}});
            reply.2 = if call_failed {
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            } else {
                axum::http::StatusCode::OK
            };
        }
        let global = app
            .rewrite_hooks
            .iter()
            .find(|(_, policy)| policy.name() == name)
            .expect("global rw gate");
        let pool = app
            .pool_rewrites(if on_error == "reject" {
                "closedrw"
            } else {
                "rewrite"
            })
            .first()
            .expect("pool rw gate");
        for (which, policy) in [("global", &global.1), ("pool", &pool.1)] {
            let outcome = policy.transform(&request("hello"), budget).await;
            match (&outcome,expect_refusal,call_failed) {
                (TransformOutcome::Reject {status,message},true,_)=>{
                    assert_eq!(*status,busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
                        "{which}: a failed load-bearing hook refuses with the shared status");
                    assert_eq!(message,busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
                        "{which}: and the shared, content-free message");
                }
                (TransformOutcome::Failed {..},false,true)=>{},
                (TransformOutcome::Rewrite(_),false,false)=>{},
                (other,_,_)=>panic!("{which}: on_error={on_error} call_failed={call_failed} expect_refusal={expect_refusal} got {other:?}"),
            }
        }
    }
    // Native ranking construction belongs to the distribution's actual linked product axis.
    for (strategy, name) in [
        (busbar_kernel::config::PoolPolicy::Cheapest, "cheapest"),
        (busbar_kernel::config::PoolPolicy::Fastest, "fastest"),
        (busbar_kernel::config::PoolPolicy::LeastBusy, "least_busy"),
        (busbar_kernel::config::PoolPolicy::Usage, "usage"),
    ] {
        let pool = busbar_kernel::config::PoolCfg {
            policy: strategy,
            ..Default::default()
        };
        match busbar_kernel::hooks::resolve_policy(&pool) {
            Some(ResolvedPolicy::Policy {
                policy,
                send_prompt,
                send_user,
                ..
            }) => {
                assert_eq!(
                    policy.name(),
                    name,
                    "resolved native policy name must round-trip"
                );
                if name == "cheapest" {
                    assert!(!send_prompt, "native must force send_prompt off");
                    assert!(!send_user, "native must force send_user off");
                }
            }
            None => panic!("policy: {name} must resolve to a Policy, got none=true"),
        }
    }
    server.abort();
}
