// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

/// Migrates the four pool_rw_gate_resolves_as_rewrite_not_decision oracles through
/// the actual root, loader, signed webrequest product and committed App chains.
#[tokio::test]
async fn pool_rw_gate_resolves_as_rewrite_not_decision() {
    crate::dist_root_install::install();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/hook", listener.local_addr().unwrap());
    let received = Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
    let recorded = received.clone();
    let endpoint_routes = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            let recorded = recorded.clone();
            async move {
                let blocked = body["request"]["messages"].to_string().contains("BLOCKME");
                let transform = body["op"] == "transform";
                recorded.lock().unwrap().push(body);
                axum::Json(if blocked {
                    serde_json::json!({"reject": {
                        "status": if transform { 451 } else { 403 },
                        "message": "blocked by test gate"
                    }})
                } else if transform {
                    serde_json::json!({"rewrite": {"messages": [
                        {"role": "user", "content": "rewritten"}
                    ]}})
                } else {
                    serde_json::json!({"order": [0]})
                })
            }
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, endpoint_routes).await.unwrap();
    });
    let directory = plugins::scratch(&format!(
        "kernel-pool-admission-{}",
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
    let providers = std::collections::HashMap::from([(
        "local".to_owned(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": "anthropic", "base_url": "http://127.0.0.1:1"
        }))
        .expect("the actual provider catalog entry parses"),
    )]);
    let config = busbar_kernel::config::resolve(&deploy, &providers)
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
    assert!(
        app.pool_gates("rewrite").is_empty(),
        "an rw gate must not resolve as a decision gate"
    );
    assert_eq!(
        app.pool_rewrites("rewrite").len(),
        1,
        "an rw gate must resolve into the pool rewrite chain"
    );
    assert_eq!(app.pool_gates("decision").len(), 1);
    assert!(app.pool_rewrites("decision").is_empty());

    // Original dlopen_decide_reject_from_opt_in_prompt and
    // dlopen_transform_rewrite_and_reject oracles, now through the actual
    // webrequest door and a real HTTP endpoint supplying only response data.
    use busbar_contract::hooks::{
        Candidate, PromptProjection, RoutingContext, RoutingDecision, RoutingRequest,
        TransformOutcome,
    };
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
    let candidates = [Candidate {
        idx: 0,
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
    }];
    let context = RoutingContext {
        pool: "read",
        budget_remaining: None,
        budget: &[],
    };
    let budget = std::time::Duration::from_secs(5);
    let busbar_kernel::hooks::ResolvedPolicy::Policy { policy, .. } = &app.pool_gates("read")[0].1;
    assert_eq!(
        policy
            .decide(&request("clean prompt"), &candidates, &context, budget)
            .await
            .expect("decide"),
        RoutingDecision::Prefer(vec![0])
    );
    assert_eq!(
        policy
            .decide(&request("please BLOCKME"), &candidates, &context, budget)
            .await
            .expect("decide"),
        RoutingDecision::Reject {
            status: 403,
            message: "blocked by test gate".into()
        }
    );
    let rewrite = &app.pool_rewrites("rewrite")[0].1;
    match rewrite.transform(&request("hello"), budget).await {
        TransformOutcome::Rewrite(rw) => assert_eq!(rw.messages.len(), 1),
        other => panic!("expected Rewrite, got {other:?}"),
    }
    match rewrite.transform(&request("BLOCKME"), budget).await {
        TransformOutcome::Reject { status, .. } => assert_eq!(status, 451),
        other => panic!("expected Reject, got {other:?}"),
    }
    assert_eq!(
        received.lock().unwrap().len(),
        4,
        "all four calls crossed actual HTTP"
    );
    // Replace fixture-only test_notifies_total with observed real HTTP dispatches.
    let notify_count = || {
        received
            .lock()
            .unwrap()
            .iter()
            .filter(|body| body["op"] == "notify")
            .count()
    };
    assert_eq!(notify_count(), 0, "no tap dispatched yet");
    let tap =
        || busbar_contract::abi::host::hook::NotifyFrame::build(&request("hello"), None, false);
    policy.notify(tap(), budget).await;
    assert_eq!(
        notify_count(),
        1,
        "a tap view must reach the actual product over the ABI and HTTP"
    );
    policy.notify(tap(), budget).await;
    assert_eq!(notify_count(), 2, "each tap is one dispatch");
    match policy.transform(&request("hello"), budget).await {
        TransformOutcome::Rewrite(rw) => assert_eq!(rw.messages.len(), 1),
        other => panic!("seam unusable after notify: expected Rewrite, got {other:?}"),
    }

    // The product reports actual target state and its published schema; fake
    // test_decides_total instrumentation is deliberately not a product contract.
    let status = policy.status(budget).await.expect("status");
    assert_eq!(
        status.metrics.expect("metrics"),
        Vec::<serde_json::Value>::new()
    );
    assert_eq!(
        status.settings.expect("settings")["target_host"],
        "127.0.0.1"
    );
    let schema = policy.describe(budget).await.expect("schema");
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["required"], serde_json::json!(["url"]));
    assert!(schema["properties"]["timeout_ms"].is_object());
    assert_eq!(
        received.lock().unwrap().len(),
        7,
        "management reads are local product state, not forwarded HTTP"
    );
    server.abort();
}
