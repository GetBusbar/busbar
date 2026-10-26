// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `GET /api/v1/admin/usage` PRICES THROUGH THE PROCESS'S DATED HISTORY, the one the kernel's rate
//! dater holds (`busbar_kernel::rate_apply`), and through no seam of the admin crate's own.
//!
//! R6 (BUSBAR-1.6.0.md, l.1472-1476): the cleanliness crates keep EXACTLY their two `OnceLock`
//! seams; l.1558: "add no new kernel `OnceLock` seam beyond the two R6 exempts". The usage read
//! used to reach the history through a static of its own that the composition root filled by name;
//! the history it needs is the one the kernel's rate dater already hands the budget book. So the
//! only install this test makes is the kernel's: if the read priced off anything else, a row earned
//! under the opening card would read back at the current one.
//!
//! A test BINARY of its own: the rate dater is process-wide, and the crate's unit tests read usage
//! with no dater installed.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::records::{MeteringDelta, RecordStore};
use busbar_kernel::cost::{CostModel, History, RateCard, TierRates};
use busbar_kernel::governance::{GovState, MemoryStore, METERING_BUCKET_SECS};
use busbar_kernel::rate_apply::RateEpoch;
use busbar_kernel::test_support::rate_holders::install_rate_epoch;

/// The one priced lane: a metering row's `model` and the card's lane, spelled once.
const LANE: &str = "m-dated-read";
const PROVIDER: &str = "dated-read";
/// One thousand input tokens, so N micro-units a token reads back as `N * 1_000`.
const TOKENS: u64 = 1_000;

/// The deployment's dated history, as the composition root's rate holder hands it over.
struct Holder(Arc<History>);

impl RateEpoch for Holder {
    fn effective_from_at(&self, _at_ms: u64) -> u64 {
        0
    }

    fn history(&self) -> Option<Arc<History>> {
        Some(Arc::clone(&self.0))
    }
}

/// A one-lane card at `micro_per_token` micro-units per input token, no flat fee.
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

/// The CURRENT cost model: one micro-unit a token, so a read that fell back to it answers 1,000
/// where the dated history answers 10,000.
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

/// Governance holding one metering row in `bucket`, earned under the opening entry.
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

/// RED while the usage read priced through a seam of the admin crate's own: with only the kernel's
/// rate dater installed, it fell back to the current card (1,000) and named no rate-card version.
#[tokio::test]
async fn the_usage_read_prices_through_the_kernels_rate_dater() {
    let holder: &'static Holder =
        Box::leak(Box::new(Holder(Arc::new(History::opening(card(10), 0)))));
    install_rate_epoch(holder);

    busbar_kernel::snapshot::init();
    busbar_core_admin::install();
    let bucket = busbar_kernel::governance::metering_bucket(busbar_kernel::store::now())
        - METERING_BUCKET_SECS;
    // An OPEN admin posture: the read reaches its handler rather than an authentication refusal.
    let app = busbar_kernel::test_support::TestApp::new()
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
