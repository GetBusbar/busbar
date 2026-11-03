// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::{MeteringDelta, VirtualKey, UNIT_INPUT};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::{Adjustment, GovState};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

const KEY: &str = "adjustment-range-key";
const LANE: &str = "adjustment-range-model";
const PROVIDER: &str = "adjustment-range-provider";
const DISPLAY_NAME: &str = "adjustment range";

fn zero_cost() -> CostModel {
    let rates = BTreeMap::from([(
        LANE.into(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 0.0,
            output_utok: 0.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    CostModel::resolve_parts(Some(&rates), 0, &BTreeMap::new())
}

struct Fixture {
    gov: Arc<GovState>,
    key: VirtualKey,
    cost: CostModel,
    app: Arc<busbar_kernel::state::App>,
    day: u64,
    epoch: u64,
    era: u64,
}

impl Fixture {
    fn new(initial: u64) -> Self {
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
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch("usage-adjustment-range");
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "rate_card": { (LANE): {"input_utok":0.0,"output_utok":0.0,"cache_read_utok":0.0,"cache_write_utok":0.0} },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the product deployment resolves");
        let plugin_config = busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (app, rotate, limits) = busbar_kernel::build_app_from_config(
            config,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the actual product builds the usage range deployment");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let app = Arc::new(app);
        let gov = app
            .governance
            .as_ref()
            .expect("the actual Store opened governance")
            .clone();
        let store = gov.store();
        let key = VirtualKey {
            id: KEY.into(),
            name: DISPLAY_NAME.into(),
            enabled: true,
            ..Default::default()
        };
        store.put_key(&key).expect("key");
        let epoch = busbar_kernel::store::now_ms();
        let now = std::time::Duration::from_millis(epoch).as_secs();
        let era = busbar_kernel::rate_apply::effective_from_at(epoch);
        let day = busbar_kernel::governance::metering_bucket(now);
        store
            .add_metering(&MeteringDelta {
                key_id: KEY.into(),
                bucket: day,
                model: LANE.into(),
                provider: PROVIDER.into(),
                tokens_input: initial,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: 1,
                billable_requests: 1,
                key_group_at_use: String::new(),
                pricing_version: String::new(),
                priced_from_ms: era,
                usage_units: BTreeMap::new(),
            })
            .expect("metering row");

        let cost = zero_cost();
        gov.record_usage(
            &cost,
            &key,
            "",
            LANE,
            &BTreeMap::from([(UNIT_INPUT.into(), initial)]),
            now,
        );
        Self {
            gov,
            key,
            cost,
            app,
            day,
            epoch,
            era,
        }
    }

    fn adjust(&self, change: i64) {
        let delta = BTreeMap::from([(UNIT_INPUT.into(), change)]);
        self.gov
            .adjust_usage(
                &self.cost,
                &Adjustment {
                    key_id: &self.key.id,
                    pool: "",
                    model: LANE,
                    entry_era: self.era,
                    entry_id: None,
                    card_epoch_ms: self.epoch,
                    delta: &delta,
                    now: busbar_kernel::store::now(),
                },
            )
            .expect("store accepts exact correction")
            .expect("valid correction");
    }

    async fn read(&self) -> Result<serde_json::Value, reqwest::Error> {
        let (_data, admin, _handle) =
            busbar_kernel::build_split_routers_with_limits(self.app.clone(), 1 << 20, 0, false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let address = listener.local_addr().expect("an address");
        let serving = tokio::spawn(async move { axum::serve(listener, admin).await });
        let result = reqwest::get(format!(
            "http://{address}/api/v1/admin/usage?window={}",
            self.day
        ))
        .await?
        .error_for_status()?
        .json()
        .await;
        serving.abort();
        result
    }
}

fn assert_totals(view: &serde_json::Value, count: u64) {
    assert_eq!(view["total"]["tokens_input"].as_u64(), Some(count));
    assert_eq!(view["total"]["spend_micros"].as_u64(), Some(0));
    assert_eq!(view["by_model"].as_array().unwrap().len(), 1);
    assert_eq!(view["by_model"][0]["tokens_input"].as_u64(), Some(count));
    assert_eq!(view["by_key"].as_array().unwrap().len(), 1);
    assert_eq!(view["by_key"][0]["tokens_input"].as_u64(), Some(count));
    let json = serde_json::to_value(view).expect("usage wire view");
    assert_eq!(json["total"]["tokens_input"].as_u64(), Some(count));
}

#[tokio::test]
async fn cumulative_positive_corrections_reach_u64_max_in_every_admin_total() {
    const CHILD: &str = "BUSBAR_ADMIN_USAGE_RANGE_CHILD";
    const WITNESS: &str = "actual root usage range completed";
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

    let fixture = Fixture::new(0);
    for change in [i64::MAX, i64::MAX, 1] {
        fixture.adjust(change);
    }
    let adjustments = fixture
        .gov
        .usage_adjustments(fixture.day)
        .expect("wide view");
    assert_eq!(adjustments[0].delta[UNIT_INPUT], i128::from(u64::MAX));
    assert_totals(
        &fixture.read().await.expect("full range admin read"),
        u64::MAX,
    );
    println!("{WITNESS}");
}

#[tokio::test]
async fn minimum_signed_delta_and_full_unsigned_downward_net_keep_their_magnitudes() {
    const CHILD: &str = "BUSBAR_ADMIN_USAGE_RANGE_CHILD";
    const WITNESS: &str = "actual root usage range completed";
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

    let fixture = Fixture::new(u64::MAX);
    fixture.adjust(i64::MIN);
    assert_eq!(
        fixture
            .gov
            .usage_adjustments(fixture.day)
            .expect("minimum signed view")[0]
            .delta[UNIT_INPUT],
        i128::from(i64::MIN)
    );
    assert_totals(
        &fixture.read().await.expect("minimum signed admin read"),
        i64::MAX as u64,
    );
    fixture.adjust(-i64::MAX);
    assert_eq!(
        fixture
            .gov
            .usage_adjustments(fixture.day)
            .expect("unsigned magnitude view")[0]
            .delta[UNIT_INPUT],
        -i128::from(u64::MAX)
    );
    assert_totals(
        &fixture.read().await.expect("fully corrected admin read"),
        0,
    );
    println!("{WITNESS}");
}

#[tokio::test]
async fn reversal_changes_the_sign_without_repricing_the_historical_row() {
    const CHILD: &str = "BUSBAR_ADMIN_USAGE_RANGE_CHILD";
    const WITNESS: &str = "actual root usage range completed";
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

    let fixture = Fixture::new(1);
    fixture.adjust(i64::MAX);
    assert_totals(
        &fixture.read().await.expect("upward read"),
        i64::MIN.unsigned_abs(),
    );
    fixture.adjust(i64::MIN);
    let adjustments = fixture
        .gov
        .usage_adjustments(fixture.day)
        .expect("reversed view");
    assert_eq!(adjustments[0].era, fixture.era);
    assert_eq!(adjustments[0].delta[UNIT_INPUT], -1);
    assert_totals(&fixture.read().await.expect("reversed read"), 0);
    println!("{WITNESS}");
}
