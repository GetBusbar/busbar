// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::{UsageLedger, VirtualKey};
use busbar_kernel::governance::{
    GovState, MeteringDelta, MeteringRow, RecordStore, RecordStoreError, RecordStoreResult,
};
use busbar_kernel::snapshot::{
    refresh_scrape_gauges, LANE_AVAILABLE, LANE_AVAILABLE_PERMITS, LANE_INFLIGHT,
    LANE_RECOVERY_HINT_MS, LANE_STATE, POOL_QUEUED,
};
use busbar_kernel::store::now;
use std::sync::Arc;

fn register_planes() {
    crate::dist_root_install::install();
}

#[path = "../../../../crates/busbar/src/root/tests/test_plugins.rs"]
mod plugins;

fn init() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(60));
}

fn render() -> String {
    use busbar_contract::export_calls::ExportAxis as _;
    let sink = crate::root::exports::EXPORTS
        .open(
            "prometheus",
            "metrics-cross-plane",
            &serde_json::json!({ "buffer_seconds": 60 }),
        )
        .expect("the actual linked scrape sink opens");
    let families = busbar_kernel::snapshot::snapshot().expect("the product recorder is installed");
    String::from_utf8(sink.scrape(&families).expect("the product sink scrapes"))
        .expect("the scrape is UTF-8")
}

fn app(model: &str, pools: &[&str], cap: Option<usize>) -> busbar_kernel::state::App {
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
    let mut manifest = plugins::manifest("store", &module, plugins::FIXTURE_PUBLISHER);
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "metrics-cross-plane-{}",
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
    let credential = directory.join("upstream-credential");
    std::fs::write(&credential, b"metrics-unused-upstream-credential")
        .expect("write the normal file-backed upstream credential");
    let pools: serde_json::Map<String, serde_json::Value> = pools
        .iter()
        .map(|pool| {
            (
                (*pool).to_string(),
                serde_json::json!({ "members": [model] }),
            )
        })
        .collect();
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": { "local": {
            "api_key": { "file": credential },
        } },
        "models": { (model): { "provider": "local", "max_concurrent": cap } },
        "pools": pools,
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let providers = busbar_kernel::config::providers::catalog_from_str(
        "local:\n  protocol: openai\n  base_url: http://127.0.0.1:1\n",
    )
    .expect("the metrics fixture declares its actual provider protocol and endpoint");
    let config = busbar_kernel::config::resolve(&deploy, &providers)
        .expect("the product deployment resolves");
    let plugin_config = plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    drop(limits);
    drop(rotate);
    app.governance = None;
    app
}

fn sample_vkey(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("hash-{id}"),
        name: format!("key-{id}"),
        allowed_scopes: None,
        enabled: true,
        created_at: 1_700_000_000,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

fn gauge_value(out: &str, metric: &str, pool: &str) -> Option<f64> {
    let needle = format!("{metric}{{");
    out.lines()
        .find(|l| {
            !l.starts_with('#') && l.starts_with(&needle) && l.contains(&format!("pool=\"{pool}\""))
        })
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.trim().parse::<f64>().ok())
}

#[test]
fn test_scrape_gauges_lane_state_no_governance() {
    register_planes();
    init();

    let app = app("model-x", &["pool-x"], None);

    refresh_scrape_gauges(&app);

    let out = render();
    assert!(
        out.contains(LANE_STATE),
        "lane_state gauge must appear in exposition; got:\n{out}"
    );
    assert!(
        out.contains("pool=\"pool-x\""),
        "pool label must appear; got:\n{out}"
    );
}

#[test]
fn test_scrape_gauges_lane_available_flips_on_saturation() {
    register_planes();
    init();

    let app = app("cap-model", &["cap-pool"], Some(1));
    let sem = app
        .store
        .lane_semaphore(0)
        .expect("the product lane's semaphore");

    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE, "cap-pool"),
        Some(1.0),
        "an idle bounded lane must report available=1; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE_PERMITS, "cap-pool"),
        Some(1.0),
        "an idle max_concurrent=1 lane has 1 available permit; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_INFLIGHT, "cap-pool"),
        Some(0.0),
        "an idle lane has 0 inflight; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_RECOVERY_HINT_MS, "cap-pool"),
        Some(0.0),
        "an available lane has recovery_hint_ms=0; got:\n{out}"
    );

    assert!(
        !out.contains("busbar_lane_at_capacity"),
        "the ad-hoc busbar_lane_at_capacity gauge must be removed; got:\n{out}"
    );

    let _held = sem
        .clone()
        .try_acquire_owned()
        .expect("hold the only permit");
    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE, "cap-pool"),
        Some(0.0),
        "a saturated bounded lane must report available=0; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE_PERMITS, "cap-pool"),
        Some(0.0),
        "a saturated bounded lane must report 0 available permits; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_INFLIGHT, "cap-pool"),
        Some(1.0),
        "the held permit is 1 inflight; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_RECOVERY_HINT_MS, "cap-pool"),
        Some(2000.0),
        "an at-capacity lane's recovery hint floors at 2000ms; got:\n{out}"
    );
}

#[test]
fn test_scrape_gauges_unbounded_lane_omits_available_permits() {
    register_planes();
    init();

    let app = app("unb-model", &["unb-pool"], None);

    refresh_scrape_gauges(&app);
    let out = render();

    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE, "unb-pool"),
        Some(1.0),
        "an unbounded lane is still scraped and reports available=1; got:\n{out}"
    );

    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE_PERMITS, "unb-pool"),
        None,
        "an unbounded lane must emit NO busbar_lane_available_permits sample; got:\n{out}"
    );
}

#[test]
fn test_scrape_gauges_breaker_open_lane_unavailable() {
    register_planes();
    init();

    let app = app("brk-model", &["brk-pool"], None);

    let t = now();
    app.store.force_open_in("brk-pool", 0, t + 30);

    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE, "brk-pool"),
        Some(0.0),
        "a breaker-Open lane must classify unavailable; got:\n{out}"
    );

    assert_eq!(
        gauge_value(&out, LANE_STATE, "brk-pool"),
        Some(2.0),
        "the independent breaker gauge must read tripped; got:\n{out}"
    );

    assert_eq!(
        gauge_value(&out, LANE_RECOVERY_HINT_MS, "brk-pool"),
        Some(30000.0),
        "recovery hint must be the breaker's until, ~30000ms; got:\n{out}"
    );
}

#[test]
fn test_scrape_gauges_pool_queued_defined_reads_zero() {
    register_planes();
    init();
    let app = app("q-model", &["q-pool"], None);
    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, POOL_QUEUED, "q-pool"),
        Some(0.0),
        "busbar_pool_queued must be defined and read 0 for each pool; got:\n{out}"
    );
}

struct ScrapeTimeBrokenKeyListStore {
    inner: Arc<dyn RecordStore>,
    calls: std::sync::atomic::AtomicUsize,
}
impl RecordStore for ScrapeTimeBrokenKeyListStore {
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            self.inner.list_keys()
        } else {
            Err(RecordStoreError(
                "governance store unavailable (simulated scrape-time outage)".into(),
            ))
        }
    }
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

#[test]
fn test_scrape_gauges_lane_state_survives_governance_all_keys_failure() {
    register_planes();
    init();

    let key = sample_vkey("vk_broken_store01");
    let store = Arc::new(ScrapeTimeBrokenKeyListStore {
        inner: crate::root::real_store::records(),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    store.put_key(&key).unwrap();

    let gov = Arc::new(GovState::new(store, None).unwrap());

    let mut app = app("model-broken", &["pool-broken"], None);
    app.governance = Some(gov);

    refresh_scrape_gauges(&app);

    let out = render();

    let lane_line = out.lines().find(|l| {
        l.contains(LANE_STATE) && l.contains("pool=\"pool-broken\"") && !l.starts_with('#')
    });
    assert!(
        lane_line.is_some(),
        "busbar_lane_state for pool-broken must still be emitted despite the governance \
             all_keys() failure; got:\n{out}"
    );

    assert!(
        !out.contains("vk_broken_store01"),
        "the failed key's id must not appear as a per-key gauge label; got:\n{out}"
    );
}

#[test]
fn test_lane_state_healthy_is_zero() {
    register_planes();
    init();

    let app = app("model-h", &["pool-h"], None);

    refresh_scrape_gauges(&app);

    let out = render();

    let lane_line = out
        .lines()
        .find(|l| l.contains(LANE_STATE) && l.contains("pool=\"pool-h\"") && !l.starts_with('#'));
    assert!(
        lane_line.is_some(),
        "lane_state metric line for pool-h must be present; got:\n{out}"
    );
    let line = lane_line.unwrap();
    assert!(
        line.ends_with(" 0") || line.ends_with(" 0.0"),
        "healthy lane must have state 0; got:\n{line}"
    );

    assert!(
        line.contains("lane=\"model-h\""),
        "lane label must be the model string, not a numeric index; got:\n{line}"
    );
}

#[test]
fn test_lane_state_tripped_pool_reads_two_despite_healthy_sibling_pool() {
    register_planes();
    init();

    let app = app("model-ho", &["pool-tripped", "pool-sibling"], None);
    let store = app.store.clone();

    let t = now();

    let _ = store.cooldown_remaining_in("pool-sibling", 0, t);
    store.force_open_in("pool-tripped", 0, t + 600);

    refresh_scrape_gauges(&app);
    let out = render();

    assert_eq!(
        gauge_value(&out, LANE_STATE, "pool-tripped"),
        Some(2.0),
        "a pool whose own cell is Open reads 2 (tripped) whatever a sibling pool's cell on the \
         same lane says; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE, "pool-tripped"),
        Some(0.0),
        "the tripped pool admits nothing; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_STATE, "pool-sibling"),
        Some(0.0),
        "the sibling pool's own healthy cell reads 0; got:\n{out}"
    );
}

#[test]
fn test_lane_state_by_model_tripped_default_cell_reads_two_despite_healthy_pool_cell() {
    register_planes();
    init();

    let app = app("model-by", &["some-pool"], None);
    let store = app.store.clone();

    let t = now();
    let _ = store.cooldown_remaining_in("some-pool", 0, t);
    store.force_open_in("", 0, t + 600);

    refresh_scrape_gauges(&app);
    let out = render();

    assert_eq!(
        gauge_value(&out, LANE_STATE, "model-by"),
        Some(2.0),
        "the direct path's own default cell is Open: the by_model gauge reads 2; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_STATE, "some-pool"),
        Some(0.0),
        "the untouched pool cell reads 0; got:\n{out}"
    );
}

#[test]
fn test_lane_state_half_open_probe_on_own_cell_reads_one() {
    register_planes();
    init();

    let app = app("model-probe", &["pool-probe", "pool-probe-sib"], None);
    let store = app.store.clone();

    let t = now();
    let _ = store.cooldown_remaining_in("pool-probe-sib", 0, t);

    store.force_open_in("pool-probe", 0, t.saturating_sub(1));

    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, LANE_STATE, "pool-probe"),
        Some(0.0),
        "an Open cell whose cooldown elapsed admits the next request as its probe: reads 0; \
         got:\n{out}"
    );

    let probe = store
        .try_admit_breaker("pool-probe", 0, now())
        .expect("an elapsed Open cell admits the probe");
    assert!(
        probe.is_some(),
        "the admit must have WON the recovery probe"
    );

    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, LANE_STATE, "pool-probe"),
        Some(1.0),
        "a half-open probe in flight on the pool's own cell reads 1; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_STATE, "pool-probe-sib"),
        Some(0.0),
        "the sibling pool's own cell is not probing and reads 0; got:\n{out}"
    );
}

#[test]
fn test_lane_state_by_model_default_cell_untouched_zero_cooldown_reports_healthy() {
    register_planes();
    init();

    let app = app("model-zero", &["poolX", "poolY"], None);
    let store = app.store.clone();

    let t = now();

    store.force_open_in("poolX", 0, t + 600);
    store.force_open_in("poolY", 0, t + 600);

    refresh_scrape_gauges(&app);
    let out = render();

    let model_line = out.lines().find(|l| {
        l.contains(LANE_STATE) && l.contains("pool=\"model-zero\"") && !l.starts_with('#')
    });
    assert!(
        model_line.is_some(),
        "lane_state for the by_model entry must be present; got:\n{out}"
    );
    let line = model_line.unwrap();
    assert!(
        line.ends_with(" 0") || line.ends_with(" 0.0"),
        "the untouched default cell (cooldown == 0) must report state 0 for the direct-routing \
             gauge regardless of unrelated pool cells being broken; got:\n{line}"
    );
}

#[test]
fn the_scrapes_pool_queued_gauge_reads_the_live_depth() {
    use busbar_kernel::plane_driver::route_tables::{
        set_pool_queued_depth, ConfigTables, EngineTablesView,
    };
    register_planes();
    init();

    let pool = "q-live-pool";

    let app = app("q-live-model", &[pool], None);
    let door_tables = ConfigTables::default();

    set_pool_queued_depth(pool, 1);
    assert_eq!(
        door_tables.queued_depth(pool),
        1,
        "the door read seam must reflect the live park depth (1 while parked)"
    );
    refresh_scrape_gauges(&app);
    let out = render();
    let live = app.engine_tables_view().queued_depth(pool) as f64;
    assert_eq!(
        gauge_value(&out, POOL_QUEUED, pool),
        Some(live),
        "busbar_pool_queued must render the live depth its read seam reports; got:\n{out}"
    );

    set_pool_queued_depth(pool, 0);
    assert_eq!(
        door_tables.queued_depth(pool),
        0,
        "the door read seam must return to 0 once the parked request leaves"
    );
    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, POOL_QUEUED, pool),
        Some(0.0),
        "busbar_pool_queued must return to 0 once the parked request leaves; got:\n{out}"
    );
}
