// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::records::{MeteringDelta, RecordStore};
use busbar_kernel::cost::{CostModel, History, RateCard, TierRates};
use busbar_kernel::governance::{GovState, METERING_BUCKET_SECS};
use busbar_kernel::rate_apply::RateEpoch;
use busbar_kernel_testkit::test_support::rate_holders::install_rate_epoch;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;

const LANE: &str = "m-dated-read";
const PROVIDER: &str = "dated-read";

const TOKENS: u64 = 1_000;

struct Holder(Arc<History>);

impl RateEpoch for Holder {
    fn effective_from_at(&self, _at_ms: u64) -> u64 {
        0
    }

    fn history(&self) -> Option<Arc<History>> {
        Some(Arc::clone(&self.0))
    }
}

fn card(micro_per_token: u64) -> RateCard {
    RateCard::from_config(
        Some([(
            LANE,
            TierRates {
                input: Some(micro_per_token * 1_000),
                ..Default::default()
            },
        )]),
        0,
    )
}

fn current_cost() -> CostModel {
    let rates = BTreeMap::from([(
        LANE.to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 1.0,
            ..Default::default()
        },
    )]);
    CostModel::resolve_parts(Some(&rates), 0, &BTreeMap::new())
}

fn governance(bucket: u64) -> Arc<GovState> {
    let store = Arc::new(MemoryStore::new());
    RecordStore::add_metering(
        store.as_ref(),
        &MeteringDelta {
            usage_units: Default::default(),
            key_id: "vk_dated_read".to_string(),
            bucket,
            model: LANE.to_string(),
            provider: PROVIDER.to_string(),
            tokens_input: TOKENS,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
            priced_from_ms: 0,
        },
    )
    .expect("the memory store accepts a metering delta");
    Arc::new(GovState::new(store, None).expect("governance builds"))
}

#[tokio::test]
async fn the_usage_read_prices_through_the_kernels_rate_dater() {
    let holder: &'static Holder =
        Box::leak(Box::new(Holder(Arc::new(History::opening(card(10), 0)))));
    install_rate_epoch(holder);

    busbar_kernel_testkit::test_support::metrics::init();
    busbar_core_admin::install();
    let bucket = busbar_kernel::governance::metering_bucket(busbar_kernel::store::now())
        - METERING_BUCKET_SECS;

    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .governance(governance(bucket))
        .cost(current_cost())
        .admin_chain(vec![])
        .build();
    let (_data, admin, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
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
        serde_json::json!(0),
        "the response names the history entry that priced it: {body}"
    );
    serving.abort();
}
