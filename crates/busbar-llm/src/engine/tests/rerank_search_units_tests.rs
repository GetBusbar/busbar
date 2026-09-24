// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ITEM 134 — A RERANK'S SEARCH UNITS REACH THE PRICE.
//!
//! `RerankResp::billing()` hardcoded `Billing::Flat`, discarding the `search_units` the Cohere reader
//! had correctly read, and the accrual dropped every non-token `Billing`: a 5,000-document rerank
//! (50 search units) billed exactly like a 1-document one. The count now leaves the codec as the
//! open class `search_units` and is ledgered verbatim, where the card prices it (#71, item 123).
//! #42's three arms, on the one wire body: a card that prices the class charges it; a card present
//! and silent about it REFUSES; no card reads 0.
use super::*;
use busbar_kernel::governance::NewKeySpec;
use busbar_kernel::test_support::engine_kit::EngineTestKit as _;

/// Cohere v2 rerank, `billed_units.search_units` = `units`.
fn cohere_rerank_body(units: u64) -> String {
    format!(
        r#"{{"id":"rr-1","results":[{{"index":0,"relevance_score":0.9}}],"meta":{{"billed_units":{{"search_units":{units}}}}}}}"#
    )
}

/// Read `body` with the real Cohere rerank reader, accrue its billing through the one accrual seam,
/// and return the key's derived spend in cents (`Err` = the read refused, #42).
fn spend_cents_after(card_yaml: Option<&str>, body: &str) -> Result<i64, String> {
    crate::testkit::install_test_seams();
    let store = Arc::new(busbar_store_memory::MemoryStore::new());
    let gov = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, None)
        .expect("gov");
    let card: Option<std::collections::BTreeMap<String, busbar_kernel::config::RateEntryCfg>> =
        card_yaml.map(|y| serde_yaml::from_str(y).expect("the card parses"));
    let cost = crate::test_support::engine_kit::CORE_ENGINE_KIT.cost_parts(
        card.as_ref(),
        0,
        &Default::default(),
    );
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let charged_at: u64 = 1_700_000_000;
    let sink = Some(UsageSink {
        pin: busbar_kernel::plane_host::MeterPin::new(
            busbar_kernel::plane_host::GovHandle(gov.clone()),
            busbar_kernel::plane_host::CostHandle(cost.clone()),
        ),
        key: Arc::new(key.clone()),
        pool: Arc::from(""),
        charged_at,
        admit: None,
    });
    let app = crate::test_support::TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "rerank-v3.5",
            crate::proto_codec::PROTO_COHERE,
            "http://127.0.0.1:1",
        ))
        .pool("pr", &[(0, 1)])
        .build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    let resp = busbar_llm_codec::cohere::handler::read_rerank_response(body.as_bytes())
        .expect("the rerank body reads");
    record_resp_usage(
        &host,
        resp.billing(),
        &sink,
        EngineTables::new(&rt).lanes().first(),
    );
    gov.usage_for(cost.as_ref(), &key.id, charged_at)
        .map(|u| u.expect("the key exists").spend_cents)
        .map_err(|e| format!("{e:?}"))
}

#[test]
fn a_reranks_search_units_reach_the_price() {
    let priced = Some("rerank-v3.5: { units: { search_units: 2000 } }\n");
    // 2000 micro-units per search unit = 0.2 cents. At the pin every row below read 0.
    assert_eq!(spend_cents_after(priced, &cohere_rerank_body(50)), Ok(10));
    assert_eq!(
        spend_cents_after(priced, &cohere_rerank_body(1)),
        Ok(0),
        "one search unit is 0.2 cents: a 5,000-document rerank no longer bills like a 1-document one"
    );
    assert!(
        spend_cents_after(
            Some("rerank-v3.5: { input_utok: 1 }\n"),
            &cohere_rerank_body(50)
        )
        .is_err(),
        "a present card silent about search_units REFUSES (#42), never a silent 0"
    );
    assert_eq!(
        spend_cents_after(None, &cohere_rerank_body(50)),
        Ok(0),
        "no card: billing off reads 0"
    );
}
