// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::records::MeteringDelta;
use busbar_kernel::governance::METERING_BUCKET_SECS;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

const LANE: &str = "m-dated-read";
const PROVIDER: &str = "dated-read";
const TOKENS: u64 = 1_000;

// These usage fixtures price token counts and declare the other classes in the actual pools
// Statement explicitly free. The model/provider names remain the names their recorded rows use.
pub(super) fn complete_usage_fixture(
    document: &mut serde_json::Value,
    directory: &std::path::Path,
    model_providers: &[(&str, &str)],
) {
    const UNUSED_CLASSES: &[&str] = &[
        "search_units",
        "classifications",
        "web_fetch_requests",
        "unitemized_tokens",
        "images",
        "audio_ms",
        "guardrail_automated_reasoning_policies",
        "guardrail_automated_reasoning_policy_units",
        "guardrail_content_policy_image_units",
        "guardrail_content_policy_units",
        "guardrail_contextual_grounding_policy_units",
        "guardrail_sensitive_information_policy_free_units",
        "guardrail_sensitive_information_policy_units",
        "guardrail_topic_policy_units",
        "guardrail_word_policy_units",
    ];
    let credential = directory.join("usage-upstream-credential");
    std::fs::write(&credential, b"unused-usage-fixture-upstream-credential")
        .expect("the usage fixture writes its file-backed upstream credential");
    for (model, provider) in model_providers {
        document["providers"][*provider] = serde_json::json!({
            "protocol": "openai", "base_url": "http://127.0.0.1:1", "api_key": {"file":credential},
        });
        document["models"][*model] = serde_json::json!({"provider":provider});
    }
    let card = document["rate_card"]
        .as_object_mut()
        .expect("the usage fixture has a rate card");
    assert_eq!(
        card.len(),
        model_providers.len(),
        "every original priced model is declared"
    );
    for (model, _) in model_providers {
        let row = card
            .get_mut(*model)
            .expect("the original model's token rates remain");
        let units = row
            .as_object_mut()
            .expect("a rate entry is an object")
            .entry("units")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .expect("explicit named unit rates");
        for class in UNUSED_CLASSES {
            units
                .entry((*class).to_string())
                .or_insert_with(|| serde_json::json!(0));
        }
    }
}

#[tokio::test]
async fn the_usage_read_prices_through_the_kernels_rate_dater() {
    const CHILD: &str = "BUSBAR_ADMIN_DATED_READ_CHILD";
    const WITNESS: &str = "actual root dated usage read completed";
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
    crate::dist_root_install::install();
    assert!(
        crate::root::kernel::ROOT_CARD.history().is_none(),
        "the isolated product process starts without a dated card"
    );

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
    let directory = plugins::scratch("admin-dated-usage-actual-store");
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
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "rate_card": BTreeMap::from([(
            LANE,
            busbar_kernel::config::RateEntryCfg { input_utok: 10.0, ..Default::default() },
        )]),
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    complete_usage_fixture(&mut document, &directory, &[(LANE, PROVIDER)]);
    let mut current_document = document.clone();
    current_document["rate_card"][LANE]["input_utok"] = serde_json::json!(1.0);
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let current_deploy = busbar_kernel::config::deploy_from_deserializer(current_document)
        .expect("the current lower-rate deployment parses");
    let current_config = busbar_kernel::config::resolve(&current_deploy, &Default::default())
        .expect("the current lower-rate deployment resolves");
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
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config.clone(),
        Some(overlay.clone()),
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
        .expect("the actual Store binds the opening rate and usage recovery");
    limits
        .keep()
        .expect("the historical boot card activates in its Store");
    let dated_key = crate::root::kernel::ROOT_CARD
        .history()
        .expect("the actual Store-backed dated history is loaded")
        .head_key()
        .expect("the historical boot card has a stable entry key");
    if let Some(rotate) = rotate {
        rotate();
    }
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        current_config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        Some(&app),
        &rules,
        None,
        false,
    )
    .expect("the normal reload builds the current lower rate on the same actual Store");
    limits
        .keep()
        .expect("the current card activates after the historical card");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert_ne!(
        crate::root::kernel::ROOT_CARD.history().unwrap().head_key(),
        Some(dated_key),
        "the current rate has its own entry; the old bucket must still price through the earlier card"
    );
    let bucket = busbar_kernel::governance::metering_bucket(busbar_kernel::store::now())
        - METERING_BUCKET_SECS;
    app.governance
        .as_ref()
        .expect("the actual Store opened governance")
        .store()
        .add_metering(&MeteringDelta {
            usage_units: Default::default(),
            key_id: "vk_dated_read".into(),
            bucket,
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
        })
        .expect("the real Store accepts the metering delta");
    let (_data, admin, _handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let addr = listener.local_addr().expect("an address");
    let serving = tokio::spawn(async move { axum::serve(listener, admin).await });
    let response = reqwest::get(format!("http://{addr}/api/v1/admin/usage?window={bucket}"))
        .await
        .expect("the surface answers");
    assert_eq!(response.status().as_u16(), 200, "the usage read answers");
    let body: serde_json::Value = response.json().await.expect("a JSON body");
    assert_eq!(
        body["total"]["spend_micros"],
        serde_json::json!(10 * TOKENS),
        "the row prices at the card the kernel's dated history holds for its instant (10 a \
         token), not the current card (1 a token): {body}"
    );
    assert_eq!(
        body["rate_card_version"],
        serde_json::json!(dated_key.hex()),
        "the response names the history entry that priced it: {body}"
    );
    let key = dated_key.hex();
    let replay = reqwest::get(format!(
        "http://{addr}/api/v1/admin/usage?window={bucket}&as_of={key}"
    ))
    .await
    .expect("the keyed usage replay answers");
    assert_eq!(replay.status().as_u16(), 200);
    let replay: serde_json::Value = replay.json().await.expect("a JSON replay");
    assert_eq!(replay["total"], body["total"]);
    assert_eq!(replay["rate_card_version"], body["rate_card_version"]);
    assert!(
        replay["as_of"].is_u64(),
        "response freshness remains numeric"
    );
    for invalid in [
        "0",
        "1",
        "42",
        "not-a-key",
        "gggggggggggggggggggggggggggggggggggggggg",
        "ffffffffffffffffffffffffffffffffffffffff",
    ] {
        let response = reqwest::get(format!(
            "http://{addr}/api/v1/admin/usage?window={bucket}&as_of={invalid}"
        ))
        .await
        .expect("an invalid snapshot request answers");
        assert_eq!(
            response.status().as_u16(),
            400,
            "invalid boundary {invalid} must be refused"
        );
    }
    serving.abort();
    println!("{WITNESS}");
}
