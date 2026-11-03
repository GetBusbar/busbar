// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use crate::root::test_plugins as plugins;

#[tokio::test]
async fn timeout_only_admin_put_refreshes_the_actual_policy_atomically() {
    const CHILD: &str = "BUSBAR_ADMIN_HOOK_TIMEOUT_ACTUAL";
    const WITNESS: &str =
        "actual hook case timeout_only_admin_put_refreshes_the_actual_policy_atomically completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(
        "timeout_only_admin_put_refreshes_the_actual_policy_atomically-actual-store",
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let hook_path = plugins::cdylib_path("busbar_hook_webrequest_plugin")
        .expect("the actual built webrequest hook product is required");
    let hook_statement = busbar_plugin_loader::dispatch::rendering_of_library(&hook_path)
        .expect("actual hook statement reads")
        .expect("the actual hook states its door");
    let hook_module = busbar_contract::abi::mechanism::rendering::read(&hook_statement)
        .expect("valid actual hook statement")
        .name;
    let mut hook_manifest = plugins::manifest(
        "hook",
        &hook_module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    hook_manifest.alias = "test-hook".to_string();
    hook_manifest.statement = Some(hex::encode(hook_statement));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        hook_manifest,
        &std::fs::read(hook_path).unwrap(),
    );
    std::fs::write(directory.join("hook.tar.gz"), archive)
        .expect("stage actual signed hook product");
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert!(
        app.hook_env.registry.resolve("test-hook").is_some(),
        "the actual signed hook is admitted and resolves through its alias"
    );
    // The original retained-export oracle now uses the actual Prometheus door,
    // hosted through the existing production snapshot adapter, never a fake SERVE.
    app.plugin_routes = metrics_routes();
    let (data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let data_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data_address = data_listener.local_addr().unwrap();
    let data_serving = tokio::spawn(async move { axum::serve(data_listener, data).await.unwrap() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move { axum::serve(listener, admin).await.unwrap() });
    let client = reqwest::Client::new();
    let endpoint = format!("http://{address}/api/v1/admin/hooks/receiver");
    let metrics = format!("http://{data_address}/metrics");
    let first_metrics = client.get(&metrics).send().await.unwrap();
    assert_eq!(first_metrics.status().as_u16(), 200);
    let first_metrics = first_metrics.text().await.unwrap();
    assert!(
        first_metrics.contains("# HELP") || first_metrics.contains("# TYPE"),
        "the retained endpoint is served by the actual exporter: {first_metrics}"
    );
    let mut definition = serde_json::json!({
        "kind": "gate", "module": "test-hook", "timeout_ms": 11, "global": true,
        "settings": {"url": "http://127.0.0.1:1/"}
    });
    let created = client
        .post(format!("http://{address}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "receiver", "config": definition}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "the real gate opens");
    let old = handle.load();
    let (old_policy, old_timeout) = policy(&old);
    assert_eq!(old_timeout, std::time::Duration::from_millis(11));

    definition["timeout_ms"] = 29.into();
    let changed = client
        .put(&endpoint)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"config": definition}))
        .send()
        .await
        .unwrap();
    assert_eq!(changed.status().as_u16(), 200);
    let next = handle.load();
    assert!(
        !Arc::ptr_eq(&old, &next),
        "the accepted candidate publishes atomically"
    );
    let retained_metrics = client.get(&metrics).send().await.unwrap();
    assert_eq!(
        retained_metrics.status().as_u16(),
        200,
        "timeout-only hook updates retain the real export dispatcher on the same listener"
    );
    let retained_metrics = retained_metrics.text().await.unwrap();
    assert!(retained_metrics.contains("# HELP") || retained_metrics.contains("# TYPE"));
    let retained_export = next
        .plugin_routes
        .descriptors()
        .into_iter()
        .find(|route| route.path == "/metrics")
        .expect("the real exporter remains registered");
    assert_eq!(
        retained_export.kind,
        busbar_kernel::plugin_routes::RouteKind::Export
    );
    assert!(retained_export.persistent);
    assert_eq!(retained_export.source_instance, "sink-instance");
    let (next_policy, next_timeout) = policy(&next);
    assert_eq!(next.hook_registry["receiver"].timeout_ms, 29);
    assert_eq!(next_timeout, std::time::Duration::from_millis(29));
    assert!(
        !Arc::ptr_eq(&old_policy, &next_policy),
        "a changed effective budget opens a new policy"
    );
    let (retained_policy, retained_timeout) = policy(&old);
    assert!(Arc::ptr_eq(&old_policy, &retained_policy));
    assert_eq!(
        retained_timeout, old_timeout,
        "in-flight readers retain their original generation"
    );
    assert_eq!(old.hook_registry["receiver"].timeout_ms, 11);

    // A genuine webrequest open refusal replaces the former Axis::refuse switch.
    // Neither its changed timeout nor its invalid settings may reach the live App.
    definition["timeout_ms"] = 47.into();
    definition["settings"]["url"] = "".into();
    let refused = client
        .put(&endpoint)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"config": definition}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status().as_u16(), 400);
    assert!(
        Arc::ptr_eq(&next, &handle.load()),
        "an unopened candidate never publishes"
    );
    assert_eq!(policy(&handle.load()).1, next_timeout);
    assert_eq!(handle.load().hook_registry["receiver"].timeout_ms, 29);
    definition["settings"]["url"] = "http://127.0.0.1:1/".into();

    definition["timeout_ms"] = 0.into();
    let defaulted = client
        .put(&endpoint)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"config": definition}))
        .send()
        .await
        .unwrap();
    assert_eq!(defaulted.status().as_u16(), 200);
    let implicit = handle.load();
    let (implicit_policy, implicit_timeout) = policy(&implicit);
    assert_eq!(
        implicit_timeout.as_millis() as u64,
        busbar_kernel::config::default_policy_timeout_ms()
    );
    definition["timeout_ms"] = (implicit_timeout.as_millis() as u64).into();
    let explicit = client
        .put(&endpoint)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"config": definition}))
        .send()
        .await
        .unwrap();
    assert_eq!(explicit.status().as_u16(), 200);
    let (explicit_policy, explicit_timeout) = policy(&handle.load());
    assert_eq!(explicit_timeout, implicit_timeout);
    assert!(
        Arc::ptr_eq(&implicit_policy, &explicit_policy),
        "zero and explicit default resolve the same actual cached policy"
    );
    serving.abort();
    data_serving.abort();
    println!("{WITNESS}");
}

fn policy(
    app: &busbar_kernel::state::App,
) -> (
    Arc<dyn busbar_kernel::hooks::RoutingPolicy>,
    std::time::Duration,
) {
    assert_eq!(
        app.global_gates.len(),
        1,
        "the real configured gate resolves exactly once"
    );
    let busbar_kernel::hooks::ResolvedPolicy::Policy {
        policy, timeout, ..
    } = &app.global_gates[0].1;
    (policy.clone(), *timeout)
}

fn metrics_routes() -> std::sync::Arc<busbar_kernel::plugin_routes::PluginRouteTable> {
    use crate::root::loader::dispatch::{
        kinds::export::{Export, ExportFacts},
        load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
    };
    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_TEST_PROMETHEUS_CDYLIB")
            .expect("BUSBAR_TEST_PROMETHEUS_CDYLIB names the actual built metrics exporter"),
    );
    let statement = rendering_of_library(&path)
        .expect("the actual exporter statement reads")
        .expect("the actual exporter carries its statement");
    crate::dist_root_install::install();
    let connector = crate::root::connector::installed()
        .expect("the normal root installs the actual transport connector");
    let dispatcher = std::sync::Arc::new(Dispatcher::new(DispatchConfig::default()));
    crate::root::connector::install_io(&dispatcher);
    let plugin = load_dropped::<Export>(
        &path,
        &statement,
        Bind {
            instance: "serve-http-metrics".into(),
            max_inflight_cap: 64,
            sink: std::sync::Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(std::sync::Arc::clone(connector)
                as std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>),
        },
    )
    .expect("the actual HTTP exporter loads through its memory ABI");
    let routes = plugin
        .context::<ExportFacts>()
        .expect("the actual exporter declares its routes")
        .routes
        .clone();
    assert!(
        routes.iter().any(|route| route.path == "/metrics"),
        "the actual exporter declares the scrape route"
    );
    let exporter = std::sync::Arc::new(
        crate::root::loader::export_door::ExportInstance::open(
            plugin,
            dispatcher,
            br#"{"buffer_seconds":60}"#,
        )
        .expect("the actual HTTP exporter opens"),
    );
    let dispatch = busbar_kernel::export::serve_test_sink(exporter);
    let declarations = routes
        .into_iter()
        .map(|route| busbar_kernel::plugin_routes::RouteDecl {
            owner: "serve-http-metrics".into(),
            source_instance: "sink-instance".into(),
            dispatch_available: true,
            kind: busbar_kernel::plugin_routes::RouteKind::Export,
            scrape: matches!(route.path.as_str(), "/metrics" | "/metrics/hooks"),
            persistent: true,
            route,
            dispatch: dispatch.clone(),
        })
        .collect();
    std::sync::Arc::new(
        busbar_kernel::plugin_routes::build_route_table(declarations)
            .expect("the actual export routes obey the product namespace rules"),
    )
}
