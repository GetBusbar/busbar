// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::groups::{LimitMetric, LimitWindow};
use busbar_kernel::config::{GroupCfg, LimitCfg};
use busbar_kernel::governance::VirtualKey;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[derive(Debug, serde::Deserialize)]
struct GroupUsageRead {
    group: String,
    enabled: bool,
    buckets: Vec<GroupBucketRead>,
    as_of: u64,
}
#[derive(Debug, serde::Deserialize)]
struct GroupBucketRead {
    window: String,
    #[serde(rename = "pool")]
    scope: Option<String>,
    requests: u64,
    tokens: u64,
    spend_cents: i64,
    requests_cap: Option<u64>,
    budget_cap: Option<i64>,
    budget_remaining_cents: Option<i64>,
}

fn usage_group_cfg() -> GroupCfg {
    let limit = |metric, amount, per, pool: Option<&str>| LimitCfg {
        metric,
        amount,
        per: Some(per),
        scope: pool.map(busbar_contract::records::ScopeRef::pool),
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    };
    GroupCfg {
        limits: vec![
            limit(LimitMetric::Requests, 5, LimitWindow::Day, None),
            limit(LimitMetric::Budget, 1_000, LimitWindow::Month, None),
            limit(
                LimitMetric::Budget,
                500,
                LimitWindow::Month,
                Some("frontier"),
            ),
        ],
        ..Default::default()
    }
}

fn usage_cost(
    groups: &std::collections::BTreeMap<String, GroupCfg>,
) -> busbar_kernel::cost::CostModel {
    let card = std::collections::BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 10.0,
            output_utok: 10.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    busbar_kernel::cost::CostModel::resolve_parts(Some(&card), 0, groups)
}

fn usage_key(group: &str) -> VirtualKey {
    VirtualKey {
        id: "vk_usage_probe".to_string(),
        generation_hash: "h:vk_usage_probe".to_string(),
        name: "usage-probe".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: Some(group.to_string()),
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

fn input_toks(n: u64) -> std::collections::BTreeMap<String, u64> {
    let mut m = std::collections::BTreeMap::new();
    if n != 0 {
        m.insert(busbar_contract::records::UNIT_INPUT.to_string(), n);
    }
    m
}

#[tokio::test]
async fn get_group_usage_splits_window_pool_buckets_and_derives_remaining() {
    const CHILD: &str = "BUSBAR_SERVICE_GROUP_USAGE_CHILD";
    const WITNESS: &str = "actual service group usage assertions completed";
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
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-group-usage-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "rate_card": BTreeMap::from([("m", busbar_kernel::config::RateEntryCfg {
            input_utok: 10.0, output_utok: 10.0, ..Default::default()
        })]),
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds the node book and rates");
    limits
        .keep()
        .expect("the product limits commit after the actual book opens");
    if let Some(rotate) = rotate {
        rotate();
    }
    app.cost = Arc::new(usage_cost(&groups));
    app.groups_registry = groups;
    let gov = app
        .governance
        .clone()
        .expect("the actual root built governance");
    let k = usage_key("acme");
    let now = busbar_kernel::store::now();
    gov.try_admit(&app.cost, &k, "frontier", now)
        .expect("frontier request admits");
    gov.record_usage(&app.cost, &k, "frontier", "m", &input_toks(100_000), now);
    gov.try_admit(&app.cost, &k, "value", now)
        .expect("value request admits");
    gov.record_usage(&app.cost, &k, "value", "m", &input_toks(50_000), now);

    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{addr}/api/v1/admin/groups/acme/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let view: GroupUsageRead = response.json().await.expect("usage read");
    assert_eq!(view.group, "acme");
    assert!(view.enabled);
    assert!(view.as_of >= now, "as_of is the read instant");
    assert_eq!(
        view.buckets.len(),
        3,
        "three (window, pool?) buckets: {:?}",
        view.buckets
    );
    let find = |window: &str, pool: Option<&str>| {
        view.buckets
            .iter()
            .find(|b| b.window == window && b.scope.as_deref() == pool)
            .unwrap_or_else(|| panic!("bucket ({window}, {pool:?}) missing: {:?}", view.buckets))
    };

    let day = find("day", None);
    assert_eq!(day.requests, 2);
    assert_eq!(day.tokens, 150_000);
    assert_eq!(day.requests_cap, Some(5));
    assert_eq!(day.budget_cap, None);
    assert_eq!(day.budget_remaining_cents, None);

    let month = find("month", None);
    assert_eq!(month.requests, 2);
    assert_eq!(month.tokens, 150_000);
    assert_eq!(month.spend_cents, 150, "150k tokens at 1c/1k tokens");
    assert_eq!(month.budget_cap, Some(1_000));
    assert_eq!(month.budget_remaining_cents, Some(850));

    let frontier = find("month", Some("frontier"));
    assert_eq!(frontier.requests, 1);
    assert_eq!(frontier.tokens, 100_000);
    assert_eq!(frontier.spend_cents, 100);
    assert_eq!(frontier.budget_cap, Some(500));
    assert_eq!(frontier.budget_remaining_cents, Some(400));
    server.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn get_group_usage_unknown_group_not_found() {
    const CHILD: &str = "BUSBAR_SERVICE_GROUP_USAGE_CHILD";
    const WITNESS: &str = "actual service group usage assertions completed";
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
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-group-usage-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "rate_card": BTreeMap::from([("m", busbar_kernel::config::RateEntryCfg {
            input_utok: 10.0, output_utok: 10.0, ..Default::default()
        })]),
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds the node book and rates");
    limits
        .keep()
        .expect("the product limits commit after the actual book opens");
    if let Some(rotate) = rotate {
        rotate();
    }
    app.cost = Arc::new(usage_cost(&groups));
    app.groups_registry = groups;
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{addr}/api/v1/admin/groups/ghost/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "not_found");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ghost"),
        "{error}"
    );
    server.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn get_group_usage_governance_off_zero_usage_caps_projected() {
    const CHILD: &str = "BUSBAR_SERVICE_GROUP_USAGE_CHILD";
    const WITNESS: &str = "actual service group usage assertions completed";
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
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-group-usage-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "rate_card": BTreeMap::from([("m", busbar_kernel::config::RateEntryCfg {
            input_utok: 10.0, output_utok: 10.0, ..Default::default()
        })]),
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds the node book and rates");
    limits
        .keep()
        .expect("the product limits commit after the actual book opens");
    if let Some(rotate) = rotate {
        rotate();
    }
    app.cost = Arc::new(usage_cost(&groups));
    app.groups_registry = groups;
    app.governance = None;
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{addr}/api/v1/admin/groups/acme/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let view: GroupUsageRead = response.json().await.expect("usage read");
    assert_eq!(
        view.buckets.len(),
        3,
        "caps still projected: {:?}",
        view.buckets
    );
    for b in &view.buckets {
        assert_eq!(b.requests, 0, "governance off = zero usage ({b:?})");
        assert_eq!(b.tokens, 0);
        assert_eq!(b.spend_cents, 0);
        assert_eq!(
            b.budget_remaining_cents, b.budget_cap,
            "nothing spent ⇒ the whole cap remains ({b:?})"
        );
    }

    assert!(view.buckets.iter().any(|b| b.requests_cap == Some(5)));
    assert!(view
        .buckets
        .iter()
        .any(|b| b.budget_cap == Some(500) && b.scope.as_deref() == Some("frontier")));
    server.abort();
    println!("{WITNESS}");
}
