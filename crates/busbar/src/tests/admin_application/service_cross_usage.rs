// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use busbar_kernel::cost::{
    self as ledger_cost, Author, CardEntryDraft, History, LedgerEntry, RateCard, TierRates,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const LANE: &str = "m-priced-chat";
const PROVIDER: &str = "priced-chat";
const KEY: &str = "vk_auditor";

const TOKENS: u64 = 1_000;
const DAY: u64 = busbar_kernel::governance::METERING_BUCKET_SECS;

const RATE_EARNED: f64 = 27.0;

const RATE_CURRENT: f64 = 12.0;

fn card(micro_per_token: f64) -> RateCard {
    RateCard::from_config(
        Some([(
            LANE,
            TierRates {
                input: Some((micro_per_token * 1000.0).round() as u64),
                ..Default::default()
            },
        )]),
        0,
    )
}

fn current_cost() -> busbar_kernel::cost::CostModel {
    let rates = std::collections::BTreeMap::from([(
        LANE.to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: RATE_CURRENT,
            output_utok: 0.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    busbar_kernel::cost::CostModel::resolve_parts(
        Some(&rates),
        0,
        &std::collections::BTreeMap::new(),
    )
}

fn history(edit_ms: u64) -> History {
    let mut history = History::opening(card(RATE_EARNED), 0);
    history.append(CardEntryDraft {
        effective_from: edit_ms,
        effective_until: None,
        card: card(RATE_CURRENT),
        appended_at: edit_ms,
        author: Author::Config { policy_epoch: 1 },
    });
    history
}

fn enforcement_key() -> busbar_contract::records::VirtualKey {
    busbar_contract::records::VirtualKey {
        id: KEY.to_string(),
        generation_hash: format!("h:{KEY}"),
        enabled: true,
        ..Default::default()
    }
}

fn one_function_slice(bucket: u64, edit_ms: u64) -> Vec<LedgerEntry> {
    [bucket.saturating_mul(1_000), edit_ms]
        .into_iter()
        .map(|arrived_ms| {
            LedgerEntry::new(LANE, arrived_ms)
                .with_whole(busbar_contract::records::UNIT_INPUT, TOKENS)
        })
        .collect()
}

const MICROS_PER_CENT: i64 = 10_000;

fn row(label: &str, figure: impl std::fmt::Display) {
    eprintln!("  {label:<56} {figure:>18}");
}

#[tokio::test]
async fn one_recorded_usage_is_one_number_on_every_surface() {
    const CHILD: &str = "BUSBAR_SERVICE_CROSS_USAGE_CHILD";
    const WITNESS: &str = "actual cross surface usage assertions completed";
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
    let now = busbar_kernel::store::now();
    let bucket = busbar_kernel::governance::metering_bucket(now) - DAY;

    let edit_ms = bucket.saturating_add(DAY / 2).saturating_mul(1_000);

    let hist = history(edit_ms);
    let cost = current_cost();

    let one = ledger_cost::price_ledger(&one_function_slice(bucket, edit_ms), &hist)
        .expect("both postings are priced by the card in force at their own instant");
    let one_micros = i64::try_from(one.micros()).expect("the figure fits");

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
        "admin-service-cross-usage-{}",
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
    super::admin_usage_history::complete_usage_fixture(
        &mut document,
        &directory,
        &[(LANE, PROVIDER)],
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
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
    super::admin_usage_history::complete_usage_fixture(
        &mut document,
        &directory,
        &[(LANE, PROVIDER)],
    );
    let current = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the current deployment parses");
    let current = busbar_kernel::config::resolve(&current, &Default::default())
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
    let historical = busbar_kernel::config::card::CardFields {
        rate_card: Some(BTreeMap::from([(
            LANE.to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: RATE_CURRENT,
                ..Default::default()
            },
        )])),
        ..Default::default()
    };
    crate::root::kernel::ROOT_CARD
        .card_store()
        .expect("the actual Store-backed rate history is loaded")
        .amend(
            edit_ms,
            (bucket + DAY) * 1_000,
            historical,
            [7u8; 32],
            "cross-surface historical posting",
        )
        .expect("the actual Store confirms the historical rate window");
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store opened governance")
        .clone();
    let store = gov.store();
    store
        .put_key(&enforcement_key())
        .expect("the actual Store retains the key needed for hydration");
    for priced_from_ms in [0, edit_ms] {
        store
            .add_metering(&busbar_contract::records::MeteringDelta {
                usage_units: Default::default(),
                key_id: KEY.into(),
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
                priced_from_ms,
            })
            .expect("the actual Store retains the metering delta");
    }
    let ledger = busbar_contract::records::UsageLedger {
        requests: 2,
        billable_requests: 2,
        models: vec![busbar_contract::records::ModelTokens {
            model: LANE.into(),
            usage_units: BTreeMap::from([(
                busbar_contract::records::UNIT_INPUT.into(),
                TOKENS * 2,
            )]),
        }],
    };
    for window in [
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_TOTAL, now),
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, now),
    ] {
        store
            .put_usage(KEY, window, &ledger)
            .expect("the actual Store retains the usage ledger");
    }
    gov.refresh().expect("the actual keys refresh");
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let response = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/admin/usage?window={bucket}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let view: serde_json::Value = response.json().await.expect("usage read");
    let admin = view["total"]["spend_micros"]
        .as_i64()
        .expect("the usage figure");
    gov.hydrate_budgets(&cost, now)
        .expect("the key ledger hydrates");

    let group_cents = gov
        .derived_bucket_usage(&cost, KEY, busbar_kernel::governance::WINDOW_DAY, true, now)
        .expect("the group bucket reads")
        .spend_cents;

    let key_cents = gov
        .derived_bucket_usage(
            &cost,
            KEY,
            busbar_kernel::governance::WINDOW_TOTAL,
            true,
            now,
        )
        .expect("the key bucket reads")
        .spend_cents;

    let scrape_cents = gov
        .viewed_bucket_usage(
            &cost,
            KEY,
            busbar_kernel::governance::WINDOW_TOTAL,
            true,
            now,
        )
        .expect("the metrics bucket reads")
        .spend_cents;

    let hook_micros = gov
        .budget_state(&cost, &enforcement_key(), now)
        .into_iter()
        .find(|bucket| bucket.bucket_id == KEY)
        .expect("the key budget state is present")
        .spend_micros_at_current_rate;

    eprintln!("\n── ONE RECORDED USAGE: 2 x {TOKENS} input tokens on `{LANE}`, one posting");
    eprintln!("   under a {RATE_EARNED} card and one under a {RATE_CURRENT} card ────────────");
    row(
        "THE ONE FUNCTION   price(ledger, history)  [micro]",
        one_micros,
    );
    row("GET /admin/usage                           [micro]", admin);
    row(
        "GET /groups/{g}/usage                      [cents]",
        group_cents,
    );
    row(
        "GET /keys/{id}/usage                       [cents]",
        key_cents,
    );
    row(
        "the metrics money view                    [cents]",
        scrape_cents,
    );
    row(
        "the hook seam    budget_state              [micro]",
        hook_micros,
    );
    eprintln!("   ─── the same five, in ONE unit (micro-units) ───");
    row("THE ONE FUNCTION", one_micros);
    row("GET /admin/usage", admin);
    row("GET /groups/{g}/usage", group_cents * MICROS_PER_CENT);
    row("GET /keys/{id}/usage", key_cents * MICROS_PER_CENT);
    row("the metrics money view", scrape_cents * MICROS_PER_CENT);
    row("the hook seam", hook_micros);

    assert_eq!(
        i128::from(admin),
        one.micros(),
        "the dated admin read and the one function are the same function"
    );
    assert_eq!(
        one_micros,
        39_000,
        "one posting at the {RATE_EARNED} card it was earned under ({}) plus one at the \
         {RATE_CURRENT} card in force now ({}) — #79 `BUSBAR-1.6.0.md:423`",
        (RATE_EARNED as i64) * (TOKENS as i64),
        (RATE_CURRENT as i64) * (TOKENS as i64),
    );

    let flat_micros = (RATE_CURRENT as i64) * (TOKENS as i64) * 2;
    assert_eq!(
        hook_micros, flat_micros,
        "the enforcement fold prices both postings at the card in force NOW"
    );
    assert_eq!(flat_micros, 24_000);
    for (surface, cents) in [
        ("GET /groups/{g}/usage", group_cents),
        ("GET /keys/{id}/usage", key_cents),
        ("the metrics money view", scrape_cents),
    ] {
        assert_eq!(
            cents, 2,
            "{surface} reads the enforcement book, which carries no instant, and then \
             projects to WHOLE MINOR UNITS — so {flat_micros} micro-units is served as 2 \
             cents and the remaining 4000 is dropped by the projection on top of the 15000 \
             dropped by pricing flat. PARKED."
        );
    }

    let served = group_cents * MICROS_PER_CENT;
    assert_eq!(
        one_micros - served,
        19_000,
        "the dated book says {one_micros}; the enforcement surfaces say {served}"
    );
    server.abort();
    println!("{WITNESS}");
}
