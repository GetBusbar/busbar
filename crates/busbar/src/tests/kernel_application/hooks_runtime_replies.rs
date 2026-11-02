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
    let response = Arc::new(std::sync::Mutex::new((serde_json::json!({}), 0u64)));
    let recorded = Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
    let returning = response.clone();
    let recording = recorded.clone();
    let routes = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            let (reply, delay) = returning.lock().unwrap().clone();
            recording.lock().unwrap().push(body);
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                axum::Json(reply)
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
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
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
            "rw": {"module": hook_module, "kind": "gate", "timeout_ms": 5000, "prompt": "rw",
                   "settings": {"url": endpoint}},
            "read": {"module": hook_module, "kind": "gate", "timeout_ms": 5000, "prompt": "ro",
                     "settings": {"url": endpoint}},
            "plain": {"module": hook_module, "kind": "gate", "timeout_ms": 5000, "prompt": "no",
                      "settings": {"url": endpoint}}
        },
        "pools": {
            "read": {"members": ["local-model"], "hooks": ["read"]},
            "rewrite": {"members": ["local-model"], "hooks": ["rw"]},
            "decision": {"members": ["local-model"], "hooks": ["plain"]}
        }
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual product deployment resolves");
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
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
        *response.lock().unwrap() = (serde_json::json!({"order":[0]}), 2000);
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
    server.abort();
}
