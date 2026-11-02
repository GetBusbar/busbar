// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::records::{MeteringDelta, RecordStore};
use busbar_kernel::cost::{RateCard, TierRates};
use busbar_kernel::governance::METERING_BUCKET_SECS;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

const LANE: &str = "m-dated-read";
const PROVIDER: &str = "dated-read";
const TOKENS: u64 = 1_000;

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
    crate::root::kernel::ROOT_CARD.apply(
        RateCard::from_config(
            Some([(
                LANE,
                TierRates {
                    input: Some(10 * 1_000),
                    ..Default::default()
                },
            )]),
            0,
        ),
        0,
    );

    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch("admin-dated-usage-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "rate_card": BTreeMap::from([(
            LANE,
            busbar_kernel::config::RateEntryCfg { input_utok: 1.0, ..Default::default() },
        )]),
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
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
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
    )
    .expect("the real root composes the configured Store and admin application");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
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
        serde_json::json!(crate::root::kernel::ROOT_CARD.history().unwrap().entries()[0].key().hex()),
        "the response names the history entry that priced it: {body}"
    );
    let key = crate::root::kernel::ROOT_CARD.history().unwrap().entries()[0].key().hex();
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
