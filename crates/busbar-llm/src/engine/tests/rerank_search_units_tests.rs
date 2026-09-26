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
use crate::test_support::engine_kit::EngineTestKit as _;
use busbar_kernel::governance::{budget_window, NewKeySpec, WINDOW_TOTAL};
use busbar_kernel::plane_host::{CostHandle, GovHandle, MeterPin};
use busbar_kernel::store::BreakerCfg;

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
    let store = crate::test_support::engine_kit::CORE_ENGINE_KIT.scratch_store();
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
        pin: MeterPin::new(GovHandle(gov.clone()), CostHandle(cost.clone())),
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

/// A same-protocol rerank's search units, as they reached each of the two books: the GOVERNANCE
/// ledger (the key's bucket, flushed to its store and read back — the invoice and `/usage` read it)
/// and the TAP REPORT (the counts the late reading hands the durable, second book).
struct TwoBooks {
    governance: Option<u64>,
    tap: Option<u64>,
}

/// Drive ONE same-protocol, non-stream rerank body through the real `FirstByteBody` to its end, on a
/// `protocol` lane with that protocol's own rerank cell, exactly as the relay serves it: Cohere relays
/// verbatim, Bedrock through the body translator its writer installs for every same-protocol
/// non-stream response. Return what each book holds of `search_units`.
async fn same_protocol_rerank_books(protocol: &'static str, body: &str) -> TwoBooks {
    use bytes::Bytes;
    use http_body_util::BodyExt as _;
    crate::testkit::install_test_seams();
    busbar_kernel::metrics::init();
    let store = crate::test_support::engine_kit::CORE_ENGINE_KIT.scratch_store();
    let gov = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, None)
        .expect("gov");
    let cost = crate::test_support::engine_kit::CORE_ENGINE_KIT.cost_flat(0);
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
        pin: MeterPin::new(GovHandle(gov.clone()), CostHandle(cost.clone())),
        key: Arc::new(key.clone()),
        pool: Arc::from(""),
        charged_at,
        admit: None,
    });
    let app = crate::test_support::TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "rerank-v3.5",
            protocol,
            "http://127.0.0.1:1",
        ))
        .pool("pr", &[(0, 1)])
        .build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    let op = op_for(
        protocol,
        busbar_contract::operation::OpVerb::RERANK,
        busbar_contract::transport::transport::Transport::Http,
    )
    .expect("the protocol serves rerank");
    // The same-protocol non-stream translator the protocol's writer installs (Bedrock's body
    // translator; none for Cohere, whose same-protocol body relays verbatim).
    let translate: Option<Box<dyn busbar_contract::protocol::StreamTranslator>> =
        if protocol == crate::proto_codec::PROTO_BEDROCK {
            Some(Box::new(
                busbar_llm_codec::bedrock::BedrockConverseBodyTranslator::new(),
            ))
        } else {
            None
        };
    let tap = TapCell::new();
    let inner = futures::stream::iter(vec![Ok::<Bytes, hyper::Error>(Bytes::from(
        body.to_string(),
    ))]);
    let fbb = FirstByteBody::new(
        inner,
        false, // same-protocol NON-STREAM application/json
        protocol,
        op,
        (),
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        host,
        rt,
        0,
        Arc::new(BreakerCfg::default()),
        "pr",
        translate,
        None,
        sink,
        false,
        tap.clone(),
    );
    let served = fbb.into_body().collect().await.expect("drain").to_bytes();
    assert_eq!(
        served.as_ref(),
        body.as_bytes(),
        "the rerank body relays verbatim"
    );
    gov.flush_budgets();
    let ledger = gov
        .store()
        .get_usage(&key.id, budget_window(WINDOW_TOTAL, charged_at))
        .expect("the governance ledger reads");
    let governance = ledger
        .models
        .iter()
        .find(|m| m.model == "rerank-v3.5")
        .and_then(|m| {
            m.usage_units
                .get(busbar_llm_codec::ir::rerank::SEARCH_UNITS_CLASS)
        })
        .copied()
        .filter(|n| *n > 0);
    let tap = tap
        .get()
        .expect("the tap reported the end the body reached")
        .open_units
        .get(busbar_llm_codec::ir::rerank::SEARCH_UNITS_CLASS)
        .copied();
    TwoBooks { governance, tap }
}

/// **A SAME-PROTOCOL RERANK PUTS IDENTICAL SEARCH UNITS ON BOTH BOOKS** (Q29, completing item 134).
///
/// Cohere → Cohere and Bedrock → Bedrock reranks billed their search units on NEITHER book: the
/// Cohere rerank cell did not tap usage (the verbatim relay kept no copy, so nothing read the body),
/// Bedrock's body translator answered no usage for a `results` body, and the same-protocol tap read
/// token usage only. Both now ledger the counted class the upstream billed on the governance ledger
/// AND report it on the tap, from the one projection.
#[tokio::test]
async fn a_same_protocol_rerank_puts_identical_search_units_on_both_books() {
    for protocol in [
        crate::proto_codec::PROTO_COHERE,
        crate::proto_codec::PROTO_BEDROCK,
    ] {
        let books = same_protocol_rerank_books(protocol, &cohere_rerank_body(50)).await;
        assert_eq!(
            books.governance,
            Some(50),
            "{protocol} → {protocol}: the governance ledger holds the rerank's search units"
        );
        assert_eq!(
            books.tap,
            Some(50),
            "{protocol} → {protocol}: the tap reports the rerank's search units to the durable book"
        );
    }
    // CONTROL: a rerank body that bills no search units puts none on either book.
    let none = r#"{"id":"rr-0","results":[{"index":0,"relevance_score":0.9}]}"#;
    for protocol in [
        crate::proto_codec::PROTO_COHERE,
        crate::proto_codec::PROTO_BEDROCK,
    ] {
        let books = same_protocol_rerank_books(protocol, none).await;
        assert_eq!(
            (books.governance, books.tap),
            (None, None),
            "{protocol}: no units, none booked"
        );
    }
}
