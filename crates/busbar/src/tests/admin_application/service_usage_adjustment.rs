// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use busbar_contract::records::VirtualKey;
use busbar_kernel::governance::{AdjustRefused, Adjustment, GovState};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const LANE: &str = "m-priced-chat";
const PROVIDER: &str = "priced-chat";
const TOKENS: u64 = 1_000;
const RATE_EARNED: f64 = 2.5;
const RATE_CURRENT: f64 = 1.0;

#[tokio::test]
async fn an_adjust_of_a_units_counts_moves_the_served_usage_figure() {
    const CHILD: &str = "BUSBAR_SERVICE_ADJUST_USAGE_CHILD";
    const WITNESS: &str = "actual durable adjustment assertions completed";
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
    const ADJUSTED_KEY: &str = "vk_adjust_404";
    let day = busbar_kernel::governance::metering_bucket(busbar_kernel::store::now())
        - 3 * busbar_kernel::governance::METERING_BUCKET_SECS;
    let served_at = day + 5;
    crate::dist_root_install::install();
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
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
        "admin-service-adjust-usage-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
        "rate_card": BTreeMap::from([(LANE, busbar_kernel::config::RateEntryCfg {
            input_utok: RATE_EARNED, output_utok: 0.0, ..Default::default()
        })]),
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let provider_defs = super::admin_usage_history::complete_usage_fixture(
        &mut document,
        &directory,
        &[(LANE, PROVIDER)],
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &provider_defs)
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config.clone(),
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
        .expect("the actual Store binds the node book and rate history");
    limits
        .keep()
        .expect("the actual boot card commits after the book opens");
    if let Some(rotate) = rotate {
        rotate();
    }
    document["rate_card"] = serde_json::to_value(BTreeMap::from([(
        LANE,
        busbar_kernel::config::RateEntryCfg {
            input_utok: RATE_CURRENT,
            ..Default::default()
        },
    )]))
    .unwrap();
    let provider_defs = super::admin_usage_history::complete_usage_fixture(
        &mut document,
        &directory,
        &[(LANE, PROVIDER)],
    );
    let current = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the current deployment parses");
    let current = busbar_kernel::config::resolve(&current, &provider_defs)
        .expect("the current deployment resolves");
    let (next, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        current,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&app),
        &rules,
        None,
        false,
    )
    .expect("the actual current configuration rebuilds against the same Store");
    limits.keep().expect("the actual current rates commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    app = next;
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store opened governance")
        .clone();
    let store = gov.store();
    assert!(
        store.supports_usage_correction(),
        "the actual Store supports atomic usage correction"
    );
    let calls = gov
        .store_calls()
        .expect("the actual Store calls remain attached");
    let key = VirtualKey {
        id: ADJUSTED_KEY.into(),
        generation_hash: format!("h:{ADJUSTED_KEY}"),
        name: "adjusted".into(),
        enabled: true,
        revision: 1,
        ..Default::default()
    };
    store
        .put_key(&key)
        .expect("the actual Store persists the key");
    store
        .add_metering(&busbar_contract::records::MeteringDelta {
            key_id: ADJUSTED_KEY.into(),
            bucket: day,
            model: LANE.into(),
            provider: PROVIDER.into(),
            tokens_input: TOKENS,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
            priced_from_ms: 0,
            usage_units: Default::default(),
        })
        .expect("the actual Store retains the metering delta");
    gov.refresh().expect("the actual key refreshes");
    let cost = app.cost.clone();
    let units = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.to_string(), TOKENS)]);
    gov.record_usage_served_in_era(
        &cost,
        &key,
        "",
        LANE,
        None,
        &units,
        served_at,
        busbar_kernel::cost::RawRateEra::legacy(0),
    );
    assert!(
        gov.flush_budgets_final() > 0,
        "the actual Store confirms the recorded budget before correction"
    );
    let (router, handle) =
        busbar_kernel::build_router_with_limits(Arc::new(app), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    async fn total(
        client: &reqwest::Client,
        addr: std::net::SocketAddr,
        day: u64,
    ) -> serde_json::Value {
        let response = client
            .get(format!("http://{addr}/api/v1/admin/usage?window={day}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        response.json::<serde_json::Value>().await.unwrap()["total"].clone()
    }
    let before = total(&client, addr, day).await;
    assert_eq!(
        (
            before["tokens_input"].as_u64().unwrap(),
            before["spend_micros"].as_i64().unwrap()
        ),
        (1_000, 2_500)
    );
    let adjust = |key_id: &'static str, by: i64| {
        let delta = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.to_string(), by)]);
        gov.adjust_usage(
            &cost,
            &Adjustment {
                key_id,
                pool: "",
                model: LANE,
                entry_era: 0,
                entry_id: None,
                card_epoch_ms: served_at * 1_000,
                delta: &delta,
                now: busbar_kernel::store::now(),
            },
        )
        .expect("the actual Store reads")
    };
    assert!(
        matches!(
            adjust(ADJUSTED_KEY, -1_001),
            Err(AdjustRefused::Exceeds { .. })
        ),
        "an adjustment past the metered count is refused"
    );
    assert_eq!(
        total(&client, addr, day).await["spend_micros"],
        2_500,
        "a refused adjustment moves nothing"
    );
    assert_eq!(adjust(ADJUSTED_KEY, -200), Ok(()));
    let after = total(&client, addr, day).await;
    assert_eq!(
        (
            after["tokens_input"].as_u64().unwrap(),
            after["spend_micros"].as_i64().unwrap()
        ),
        (800, 2_000),
        "the served figure prices the adjusted counts: 800 x 2.5"
    );
    let restarted = Arc::new(
        GovState::new_with_signer(store, None, None)
            .expect("governance restarts against the same actual Store"),
    );
    assert!(restarted.attach_store_calls(calls));
    let mut next = (*handle.load()).clone();
    next.governance = Some(restarted);
    handle.swap(Arc::new(next));
    let again = total(&client, addr, day).await;
    assert_eq!(
        (
            again["tokens_input"].as_u64().unwrap(),
            again["spend_micros"].as_i64().unwrap()
        ),
        (800, 2_000),
        "the adjustment row is durable: a restart serves the same figure"
    );
    server.abort();
    println!("{WITNESS}");
}
