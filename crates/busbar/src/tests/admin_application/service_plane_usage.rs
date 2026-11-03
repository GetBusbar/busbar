// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::records::VirtualKey;
use busbar_kernel::cost::{CostModel, PlaneFees};
use busbar_kernel::governance::PLANE_LANE_SEP;

use crate::root::test_plugins as plugins;

const KEY: &str = "vk_plane_fees";
const POOLS_MODEL: &str = "m";
const POOLS_PROVIDER: &str = "priced-chat";
const MICROS_PER_MINOR: i64 = 10_000;

fn isolated() -> bool {
    const CHILD: &str = "BUSBAR_ADMIN_PLANE_USAGE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let name = std::thread::current().name().unwrap().to_string();
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("start the isolated actual admin usage test"),
    );
    let until = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            use std::io::Read as _;
            let mut output = String::new();
            child
                .0
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut output)
                .unwrap();
            assert!(status.success(), "{name}: {status}: {output}");
            assert!(output.contains("1 passed"), "the exact test ran: {output}");
            return false;
        }
        assert!(std::time::Instant::now() < until, "{name} timed out");
        std::thread::park_timeout(std::time::Duration::from_millis(5));
    }
}

struct PlaneKeys {
    pools: &'static str,
    fee: &'static str,
    free: &'static str,
}

fn planes() -> &'static PlaneKeys {
    static KEYS: std::sync::OnceLock<PlaneKeys> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        crate::dist_root_install::install();
        use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
        let mut rows = busbar_kernel::plane_driver::registry::plane_decls().to_vec();
        for (index, door) in crate::LINKED.plane_doors.iter().enumerate() {
            let row = busbar_kernel::plane_driver::door::fold(
                registration(linked_probe(*door, &format!("admin-plane-usage-{index}")))
                    .expect("the actual linked plane declares its metadata through its ABI"),
            )
            .expect("the actual linked plane metadata folds");
            if !rows.iter().any(|installed| installed.key == row.key) {
                rows.push(row);
            }
        }
        rows.sort_by_key(|row| row.key);
        let pools = rows
            .iter()
            .find(|row| row.fallback)
            .expect("an actual fallback plane")
            .key;
        let mut nonfallback = rows.iter().filter(|row| !row.fallback);
        let fee = nonfallback.next().expect("an actual nonfallback plane").key;
        let free = nonfallback
            .next()
            .expect("a second actual nonfallback plane")
            .key;
        busbar_kernel::plane_driver::registry::publish_planes(&rows);
        PlaneKeys { pools, fee, free }
    })
}

fn app(cost: CostModel) -> busbar_kernel::state::App {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(&format!(
        "admin-plane-usage-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    std::fs::write(
        directory.join("store.tar.gz"),
        plugins::signed(&crate::dist_root_install::release_key(), manifest, &library),
    )
    .unwrap();
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(settings.is_object());
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the actual usage deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        crate::root::test_plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual root builds the Store and admin application");
    // These read-seam cases deliberately precede rate-history publication: two cases assert
    // that no source exists, and the dated case supplies its own history below. Stage the actual
    // configured root without activating a history that would invalidate that fixture state.
    // This is the pre-activation read seam; normal boot publication is covered separately.
    limits.stage_boot();
    drop(limits);
    if let Some(rotate) = rotate {
        rotate();
    }
    app.cost = Arc::new(cost);
    app
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
struct ClassUsage {
    count: u64,
    cost: i64,
}

#[derive(Debug, serde::Deserialize)]
struct BreakdownRead {
    spend_micros: i64,
    #[serde(default)]
    classes: BTreeMap<String, ClassUsage>,
    #[serde(skip)]
    wire: serde_json::Value,
}

#[derive(Debug, serde::Deserialize)]
struct ModelRead {
    #[serde(rename = "provider")]
    upstream: String,
    model: String,
    #[serde(flatten)]
    usage: BreakdownRead,
}

#[derive(Debug, serde::Deserialize)]
struct KeyRead {
    id: String,
    #[serde(flatten)]
    usage: BreakdownRead,
}

impl serde::Serialize for BreakdownRead {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.wire, serializer)
    }
}

impl serde::Serialize for ModelRead {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.usage.wire, serializer)
    }
}

impl serde::Serialize for KeyRead {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.usage.wire, serializer)
    }
}

#[derive(Debug, serde::Deserialize)]
struct UsageRead {
    total: BreakdownRead,
    by_model: Vec<ModelRead>,
    by_key: Vec<KeyRead>,
    rate_card_version: Option<String>,
}

async fn read(app: busbar_kernel::state::App, bucket: Option<u64>) -> UsageRead {
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let query = bucket
        .map(|bucket| format!("?window={bucket}"))
        .unwrap_or_default();
    let response = reqwest::get(format!("http://{addr}/api/v1/admin/usage{query}"))
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let wire: serde_json::Value = response.json().await.unwrap();
    server.abort();
    let mut view: UsageRead =
        serde_json::from_value(wire.clone()).expect("the actual usage response");
    view.total.wire = wire["total"].clone();
    for (row, wire) in view
        .by_model
        .iter_mut()
        .zip(wire["by_model"].as_array().unwrap())
    {
        row.usage.wire = wire.clone();
    }
    for (row, wire) in view
        .by_key
        .iter_mut()
        .zip(wire["by_key"].as_array().unwrap())
    {
        row.usage.wire = wire.clone();
    }
    view
}

fn key() -> VirtualKey {
    VirtualKey {
        id: KEY.to_string(),
        generation_hash: format!("h:{KEY}"),
        name: "plane-fees".to_string(),
        enabled: true,
        revision: 1,
        ..Default::default()
    }
}

fn cost() -> CostModel {
    CostModel::resolve_parts(None, 5, &BTreeMap::new()).with_plane_fees(&BTreeMap::from([(
        planes().fee.to_string(),
        PlaneFees {
            per_request: 3,
            per_session: 0,
        },
    )]))
}

#[tokio::test]
async fn with_no_history_source_the_read_is_the_previous_release_to_the_byte() {
    if !isolated() {
        return;
    }
    const LANE: &str = "m-priced-chat";
    const PROVIDER: &str = "priced-chat";
    const KEY: &str = "vk_payg";
    let rates = BTreeMap::from([(
        LANE.to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 10_000_000.0,
            output_utok: 20_000_000.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    let app = app(CostModel::resolve_parts(Some(&rates), 3, &BTreeMap::new()));
    assert!(crate::root::kernel::ROOT_CARD.history().is_none());
    let gov = app.governance.as_ref().unwrap();
    let now = busbar_kernel::store::now();
    let usage = busbar_contract::billing::TokenUsage {
        input: 11,
        output: 7,
        ..Default::default()
    };
    for _ in 0..3 {
        gov.record_metering(KEY, LANE, PROVIDER, Some(&usage), now);
    }
    gov.flush_metering();
    let view = read(app, None).await;
    assert_eq!(
        view.total.spend_micros, 750_090_000,
        "with no history installed the read is the published 1.5.5 figure"
    );
}

#[tokio::test]
async fn an_old_served_entry_prices_both_the_row_and_its_itemized_classes() {
    if !isolated() {
        return;
    }
    const TOOL_SUBJECT: &str = "srv.read";
    const TOOL_CLASS: &str = "tool_calls";
    const CALLS: u64 = 3;
    const OLD_CALL_MICROS: u64 = 70_000;
    const NEW_CALL_MICROS: u64 = 10_000;
    const OLD_REQUEST_MINOR: i64 = 3;
    const NEW_REQUEST_MINOR: i64 = 1;
    let fee_plane = planes().fee;
    let bucket = busbar_kernel::governance::metering_bucket(busbar_kernel::store::now());
    let day = busbar_kernel::governance::METERING_BUCKET_SECS;
    let old_era = (bucket - day) * 1_000;
    let activated = (bucket - day / 2) * 1_000;
    let old_cost = carded_cost(OLD_CALL_MICROS, OLD_REQUEST_MINOR, 0);
    let new_cost = carded_cost(NEW_CALL_MICROS, NEW_REQUEST_MINOR, 0);
    let app = app(new_cost);
    assert!(crate::root::kernel::ROOT_CARD.history().is_none());
    crate::root::kernel::ROOT_CARD.apply(app.cost.card().clone(), 0);
    crate::root::kernel::ROOT_CARD.apply(old_cost.card().clone(), old_era);
    let history = crate::root::kernel::ROOT_CARD.history().unwrap();
    let old_seq = history.head_key().expect("the appended entry has a key");
    let old_version = history.entries()[1].id().metering_version();
    crate::root::kernel::ROOT_CARD.apply(app.cost.card().clone(), activated);
    app.governance
        .as_ref()
        .unwrap()
        .store()
        .add_metering(&busbar_contract::records::MeteringDelta {
            key_id: KEY.to_string(),
            bucket,
            model: TOOL_SUBJECT.to_string(),
            provider: fee_plane.to_string(),
            tokens_input: 0,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: CALLS,
            billable_requests: CALLS,
            key_group_at_use: String::new(),
            pricing_version: old_version,
            priced_from_ms: old_era,
            usage_units: BTreeMap::from([(TOOL_CLASS.to_string(), CALLS)]),
        })
        .unwrap();
    let view = read(app, Some(bucket)).await;
    let call_count = i64::try_from(CALLS).unwrap();
    let class_cost = call_count * i64::try_from(OLD_CALL_MICROS).unwrap();
    let request_cost = call_count * OLD_REQUEST_MINOR * MICROS_PER_MINOR;
    assert_eq!(view.total.spend_micros, class_cost + request_cost);
    assert_eq!(view.total.classes[TOOL_CLASS].cost, class_cost);
    assert_eq!(view.by_model[0].usage.classes[TOOL_CLASS].cost, class_cost);
    assert_eq!(view.rate_card_version, Some(old_seq.hex()));
}

async fn serve(pool_calls: usize, plane: &str, calls: usize) -> (i64, i64) {
    let app = app(cost());
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store opened governance");
    gov.store().put_key(&key()).unwrap();
    let now = busbar_kernel::store::now();
    for _ in 0..pool_calls {
        assert!(
            gov.try_admit(&app.cost, &key(), "", now).is_ok(),
            "a pools call"
        );
        gov.record_metering(KEY, POOLS_MODEL, POOLS_PROVIDER, None, now);
    }
    for _ in 0..calls {
        let pool = format!("{plane}{PLANE_LANE_SEP}srv.read");
        assert!(
            gov.try_admit(&app.cost, &key(), &pool, now).is_ok(),
            "a plane call"
        );
        gov.record_metering(KEY, "srv.read", plane, None, now);
    }
    gov.flush_metering();
    let book = gov
        .usage_for(&app.cost, KEY, now)
        .unwrap()
        .expect("the key's usage")
        .spend_cents;
    let view = read(app, None).await;
    (book, view.total.spend_micros)
}

fn carded_cost(
    per_call_micros: u64,
    per_request: i64,
    per_session: i64,
) -> busbar_kernel::cost::CostModel {
    let fee_plane = planes().fee;

    let entry = |units: &[(&str, u64)]| -> busbar_kernel::config::RateEntryCfg {
        let units: serde_json::Map<String, serde_json::Value> = units
            .iter()
            .map(|(c, r)| (c.to_string(), serde_json::json!(r)))
            .collect();
        serde_json::from_value(serde_json::json!({ "units": units })).expect("a rate entry")
    };
    let mut pools = entry(&[("search_units", 3)]);
    pools.input_utok = 1.0;
    pools.output_utok = 2.0;
    let card = std::collections::BTreeMap::from([
        (POOLS_MODEL.to_string(), pools),
        (PLANE_LANE_SEP.to_string(), Default::default()),
        (format!("{fee_plane}{PLANE_LANE_SEP}"), Default::default()),
        (
            format!("{fee_plane}{PLANE_LANE_SEP}srv.read"),
            entry(&[("tool_calls", per_call_micros)]),
        ),
    ]);
    let fees = busbar_kernel::config::PlaneFeesMap::from([(
        fee_plane.to_string(),
        PlaneFees {
            per_request,
            per_session,
        },
    )]);
    busbar_kernel::cost::CostModel::resolve_parts(
        Some(&card),
        5,
        &std::collections::BTreeMap::new(),
    )
    .with_plane_fees(&fees)
}

enum Call {
    Tokens { input: u64, output: u64 },
    Rerank { search_units: u64 },
    Session,
    Tool,
}

async fn serve_calls(cost: fn() -> CostModel, calls: &[Call]) -> (i64, i64) {
    let (book, view) = serve_calls_view(cost, calls).await;
    (book, view.total.spend_micros)
}

async fn serve_calls_view(cost: fn() -> CostModel, calls: &[Call]) -> (i64, UsageRead) {
    use busbar_kernel::cost::{plane_fee_lane, PER_SESSION};
    let fee_plane = planes().fee;
    let app = app(cost());
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store opened governance");
    gov.store().put_key(&key()).unwrap();
    let cost = cost();
    let now = busbar_kernel::store::now();
    let key = key();
    let units = |pairs: &[(&str, u64)]| -> BTreeMap<String, u64> {
        pairs.iter().map(|(c, n)| (c.to_string(), *n)).collect()
    };
    let tool_lane = format!("{fee_plane}{PLANE_LANE_SEP}srv.read");
    for call in calls {
        match call {
            Call::Tokens { input, output } => {
                assert!(gov.try_admit(&cost, &key, "", now).is_ok());
                let t = busbar_contract::billing::TokenUsage {
                    input: *input,
                    output: *output,
                    ..Default::default()
                };
                gov.record_usage(
                    &cost,
                    &key,
                    "",
                    POOLS_MODEL,
                    &units(&[("input", *input), ("output", *output)]),
                    now,
                );
                gov.record_metering(KEY, POOLS_MODEL, POOLS_PROVIDER, Some(&t), now);
            }
            Call::Rerank { search_units } => {
                assert!(gov.try_admit(&cost, &key, "", now).is_ok());
                gov.record_usage(
                    &cost,
                    &key,
                    "",
                    POOLS_MODEL,
                    &units(&[("search_units", *search_units)]),
                    now,
                );
                gov.record_metering(KEY, POOLS_MODEL, POOLS_PROVIDER, None, now);
            }
            Call::Session => {
                gov.record_usage(
                    &cost,
                    &key,
                    "sessions",
                    &plane_fee_lane(fee_plane),
                    &units(&[(PER_SESSION, 1)]),
                    now,
                );
            }
            Call::Tool => {
                assert!(gov.try_admit(&cost, &key, &tool_lane, now).is_ok());
                gov.record_metering(KEY, "srv.read", fee_plane, None, now);
                gov.record_usage(
                    &cost,
                    &key,
                    "srv.read",
                    &tool_lane,
                    &units(&[("tool_calls", 1)]),
                    now,
                );
            }
        }
    }

    gov.flush_metering();
    let book = gov
        .usage_for(&cost, KEY, now)
        .unwrap()
        .expect("the key's usage")
        .spend_cents;
    let view = read(app, None).await;
    (book, view)
}

#[tokio::test]
async fn a_planes_rows_price_at_its_own_fee_and_admin_usage_agrees_with_the_budget_book() {
    if !isolated() {
        return;
    }

    let fee_plane = planes().fee;

    let (book, admin) = serve(2, fee_plane, 3).await;
    assert_eq!(book, 19, "the budget book: 2 pools × 5 + 3 tools × 3");
    assert_eq!(
        admin,
        19 * MICROS_PER_MINOR,
        "/admin/usage prices the tools rows at tools.fees.per_request, not the flat fee \
             (before: 25), and agrees with the budget book"
    );
    assert_eq!(admin, book * MICROS_PER_MINOR);
}

#[tokio::test]
async fn a_plane_without_fees_reads_zero_fee_on_admin_usage() {
    if !isolated() {
        return;
    }

    let free_plane = planes().free;

    let (book, admin) = serve(0, free_plane, 4).await;
    assert_eq!(book, 0, "the budget book: a fee-less plane bills no fee");
    assert_eq!(
        admin, 0,
        "/admin/usage: 4 calls on a fee-less plane (before: 20)"
    );
}

#[tokio::test]
async fn a_pools_row_keeps_the_flat_fee() {
    if !isolated() {
        return;
    }

    let fee_plane = planes().fee;
    let pools_plane = planes().pools;

    let (book, admin) = serve(2, pools_plane, 0).await;
    assert_eq!((book, admin), (10, 10 * MICROS_PER_MINOR));
    assert_eq!(
        busbar_core_admin::v1::service::row_lane(POOLS_MODEL, pools_plane),
        POOLS_MODEL,
        "the fallback plane's key is a pools row"
    );
    assert_eq!(
        busbar_core_admin::v1::service::row_lane(POOLS_MODEL, POOLS_PROVIDER),
        POOLS_MODEL
    );
    assert_eq!(
        busbar_core_admin::v1::service::row_lane("srv.read", fee_plane),
        format!("{fee_plane}{PLANE_LANE_SEP}srv.read")
    );
}

#[tokio::test]
async fn two_sessions_price_their_session_fee_on_admin_usage() {
    if !isolated() {
        return;
    }

    let (book, admin) = serve_calls(
        || carded_cost(70_000, 0, 40),
        &[Call::Session, Call::Session],
    )
    .await;
    assert_eq!(book, 80, "the budget book: 2 sessions × 40");
    assert_eq!(
        admin,
        80 * MICROS_PER_MINOR,
        "/admin/usage agrees (before: 0)"
    );
}

#[tokio::test]
async fn a_planes_ledgered_class_prices_on_admin_usage() {
    if !isolated() {
        return;
    }

    let calls = [Call::Tool, Call::Tool, Call::Tool];
    let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 0), &calls).await;
    assert_eq!(book, 30, "the budget book: 3 × fee 3 + 3 × tool_calls 7");
    assert_eq!(
        admin,
        30 * MICROS_PER_MINOR,
        "/admin/usage agrees (before: 9)"
    );
}

#[tokio::test]
async fn a_planes_class_rides_its_usage_row_with_its_count_and_its_cost() {
    if !isolated() {
        return;
    }

    let fee_plane = planes().fee;

    let calls = [Call::Tool, Call::Tool, Call::Tool];
    let (_, view) = serve_calls_view(|| carded_cost(70_000, 3, 0), &calls).await;
    let want = std::collections::BTreeMap::from([(
        "tool_calls".to_string(),
        ClassUsage {
            count: 3,
            cost: 21 * MICROS_PER_MINOR,
        },
    )]);
    let row = view
        .by_model
        .iter()
        .find(|r| r.upstream == fee_plane)
        .expect("the plane's row");
    assert_eq!(row.usage.classes, want, "the row carries its class");
    assert_eq!(view.total.classes, want, "the total sums it");
    assert_eq!(
        view.total.spend_micros,
        30 * MICROS_PER_MINOR,
        "the class's cost is part of spend_micros, not added to it"
    );
    let wire = serde_json::to_value(row).expect("the row serializes");
    assert_eq!(
        wire["classes"]["tool_calls"],
        serde_json::json!({"count": 3, "cost": 21 * MICROS_PER_MINOR}),
        "the wire shape: classes keyed by class name, each {{count, cost}}"
    );
}

#[tokio::test]
async fn a_token_only_row_carries_no_classes_key_as_on_1_5_5() {
    if !isolated() {
        return;
    }

    let t = Call::Tokens {
        input: 1_000_000,
        output: 500_000,
    };
    let (_, view) = serve_calls_view(|| carded_cost(70_000, 3, 0), &[t]).await;
    let row = view.by_model.first().expect("the pools row");
    assert!(row.usage.classes.is_empty());
    let wire = serde_json::to_value(row).expect("the row serializes");
    assert!(
        wire.get("classes").is_none(),
        "a token-only row is 1.5.5's shape: {wire}"
    );
    let total = serde_json::to_value(&view.total).expect("the total serializes");
    assert!(total.get("classes").is_none());
}

#[tokio::test]
async fn a_pools_open_class_prices_on_admin_usage() {
    if !isolated() {
        return;
    }

    let calls = [
        Call::Rerank {
            search_units: 1_000_000,
        },
        Call::Rerank {
            search_units: 1_000_000,
        },
    ];
    let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 0), &calls).await;
    assert_eq!(book, 610, "the budget book: 2 × 5 + 6,000,000 micro-units");
    assert_eq!(
        admin,
        610 * MICROS_PER_MINOR,
        "/admin/usage agrees (before: 10)"
    );
}

#[tokio::test]
async fn a_pools_open_class_is_priced_but_never_itemized_on_the_usage_read() {
    if !isolated() {
        return;
    }

    let calls = [
        Call::Rerank {
            search_units: 1_000_000,
        },
        Call::Rerank {
            search_units: 1_000_000,
        },
    ];
    let (_, view) = serve_calls_view(|| carded_cost(70_000, 3, 0), &calls).await;
    assert_eq!(view.total.spend_micros, 610 * MICROS_PER_MINOR);
    assert_eq!(
        view.by_model
            .iter()
            .map(|r| r.usage.spend_micros)
            .sum::<i64>(),
        610 * MICROS_PER_MINOR,
        "the model rows still price the open class"
    );
    let mut wires = vec![(
        "total".to_string(),
        serde_json::to_value(&view.total).expect("the total serializes"),
    )];
    for r in &view.by_model {
        wires.push((
            format!("model row {}/{}", r.model, r.upstream),
            serde_json::to_value(r).expect("the row serializes"),
        ));
    }
    for r in &view.by_key {
        wires.push((
            format!("key row {}", r.id),
            serde_json::to_value(r).expect("the key row serializes"),
        ));
    }
    assert!(
        wires.len() >= 3,
        "a total, a model row and a key row: {wires:?}"
    );
    for (what, wire) in wires {
        assert!(
            wire.get("classes").is_none(),
            "a pools {what} keeps 1.5.5's usage shape: {wire}"
        );
    }
}

#[tokio::test]
async fn pools_only_token_traffic_is_unchanged() {
    if !isolated() {
        return;
    }

    let t = || Call::Tokens {
        input: 1_000_000,
        output: 500_000,
    };
    let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 0), &[t(), t()]).await;
    assert_eq!(book, 410);
    assert_eq!(admin, 410 * MICROS_PER_MINOR);
}

mod dated_pricing {
    use super::{PlaneFees, MICROS_PER_MINOR, PLANE_LANE_SEP, POOLS_MODEL};
    const FEE_PLANE: &str = "tp";
    const FREE_PLANE: &str = "np";
    fn cost() -> busbar_kernel::cost::CostModel {
        let fees = busbar_kernel::config::PlaneFeesMap::from([(
            FEE_PLANE.to_string(),
            PlaneFees {
                per_request: 3,
                per_session: 0,
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(None, 5, &std::collections::BTreeMap::new())
            .with_plane_fees(&fees)
    }
    fn carded_cost(
        per_call_micros: u64,
        per_request: i64,
        per_session: i64,
    ) -> busbar_kernel::cost::CostModel {
        let entry = |units: &[(&str, u64)]| -> busbar_kernel::config::RateEntryCfg {
            let units: serde_json::Map<String, serde_json::Value> = units
                .iter()
                .map(|(c, r)| (c.to_string(), serde_json::json!(r)))
                .collect();
            serde_json::from_value(serde_json::json!({ "units": units })).expect("a rate entry")
        };
        let mut pools = entry(&[("search_units", 3)]);
        pools.input_utok = 1.0;
        pools.output_utok = 2.0;
        let card = std::collections::BTreeMap::from([
            (POOLS_MODEL.to_string(), pools),
            (PLANE_LANE_SEP.to_string(), Default::default()),
            (format!("{FEE_PLANE}{PLANE_LANE_SEP}"), Default::default()),
            (
                format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read"),
                entry(&[("tool_calls", per_call_micros)]),
            ),
        ]);
        let fees = busbar_kernel::config::PlaneFeesMap::from([(
            FEE_PLANE.to_string(),
            PlaneFees {
                per_request,
                per_session,
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(
            Some(&card),
            5,
            &std::collections::BTreeMap::new(),
        )
        .with_plane_fees(&fees)
    }

    #[test]
    fn the_dated_read_prices_a_planes_row_at_its_own_fee() {
        use busbar_core_admin::v1::contract::UsageBreakdown;
        let cost = cost();
        let history = busbar_kernel::cost::History::opening(cost.card().clone(), 0);
        let view = history.current();
        let (_, card) = view.card_at(0).expect("the opening card");
        let price = |lane: &str, requests: u64| {
            let b = UsageBreakdown {
                requests,
                ..Default::default()
            };
            busbar_core_admin::v1::service::derive_spend_micros_row_at_card(
                &view, 0, card, &cost, lane, &b,
            )
            .expect("priced")
        };
        let tools = format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read");
        let free = format!("{FREE_PLANE}{PLANE_LANE_SEP}srv.read");
        assert_eq!(price(&tools, 3), 9 * MICROS_PER_MINOR, "3 × tools fee 3");
        assert_eq!(
            price(POOLS_MODEL, 2),
            10 * MICROS_PER_MINOR,
            "2 × flat fee 5"
        );
        assert_eq!(price(&free, 4), 0, "a fee-less plane bills no fee");
        assert_eq!(
            busbar_core_admin::v1::service::derive_spend_micros_row(
                &cost,
                &tools,
                &UsageBreakdown {
                    requests: 3,
                    ..Default::default()
                }
            )
            .expect("priced"),
            9 * MICROS_PER_MINOR,
            "the no-history fallback agrees"
        );
    }

    #[test]
    fn the_dated_read_prices_a_rows_classes_as_the_fallback_does() {
        use busbar_core_admin::v1::contract::UsageBreakdown;
        use busbar_kernel::cost::PER_SESSION;
        let cost = carded_cost(70_000, 3, 40);
        let history = busbar_kernel::cost::History::opening(cost.card().clone(), 0);
        let view = history.current();
        let (_, card) = view.card_at(0).expect("the opening card");
        let classes = |pairs: &[(&str, u64)]| -> std::collections::BTreeMap<String, u64> {
            pairs.iter().map(|(c, n)| (c.to_string(), *n)).collect()
        };
        let fee_row = format!("{FEE_PLANE}{PLANE_LANE_SEP}");
        let tool_row = format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read");
        for (lane, requests, units, minor) in [
            (fee_row.as_str(), 0, classes(&[(PER_SESSION, 2)]), 80),
            (tool_row.as_str(), 3, classes(&[("tool_calls", 3)]), 30),
            (POOLS_MODEL, 1, classes(&[("search_units", 1_000_000)]), 305),
        ] {
            let b = UsageBreakdown {
                requests,
                ..Default::default()
            };
            let dated = busbar_core_admin::v1::service::derive_spend_micros_row_classes_at_card(
                &view, 0, card, &cost, lane, &b, &units,
            )
            .expect("priced");
            let fallback = busbar_core_admin::v1::service::derive_spend_micros_row_classes(
                &cost, lane, &b, &units,
            )
            .expect("priced");
            assert_eq!(
                (dated, fallback),
                (minor * MICROS_PER_MINOR, minor * MICROS_PER_MINOR)
            );
        }
    }
}

#[tokio::test]
async fn mixed_traffic_agrees_with_the_budget_book() {
    if !isolated() {
        return;
    }

    let calls = [
        Call::Tokens {
            input: 1_000_000,
            output: 500_000,
        },
        Call::Rerank {
            search_units: 1_000_000,
        },
        Call::Session,
        Call::Tool,
        Call::Tool,
    ];
    let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 40), &calls).await;
    assert_eq!(book, 200 + 5 + 300 + 5 + 40 + 2 * (3 + 7));
    assert_eq!(admin, book * MICROS_PER_MINOR);
}
