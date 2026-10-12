// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OWNER LEDGER-100 (docs/design/1.6.0-QUESTIONS.md, 2026-10-03): "anything ledger wise needs to be
//! 100%". Every unit a far end reports is a ledger line under its meter class and its price comes
//! from the ratecard (money = f(ledger, ratecard), integer only, no stored price).
//!
//! For EVERY open class the LLM plane declares (read off `open_class::OPEN_CLASSES`, never spelled
//! here), one delivery reporting 3 of it goes through the one accrual seam (`record_resp_usage`)
//! and #42's three arms hold: a card pricing the class at 0.01 (10,000 micro-units) per unit charges
//! 3 cents and the governance ledger holds exactly one line, `{class: 3}`; a present card silent
//! about the class REFUSES (never a silent 0); no card reads 0 and still keeps the line.
use super::*;
use crate::test_support::engine_kit::EngineTestKit as _;
use busbar_contract::billing::{Billing, TokenUsage};
use busbar_kernel::governance::{budget_window, NewKeySpec, WINDOW_TOTAL};
use busbar_kernel::plane_host::{CostHandle, GovHandle, MeterPin};
use busbar_plane_llm::codec::ir::open_class::{AUDIO_MS_CLASS, IMAGES_CLASS, OPEN_CLASSES};

/// The delivery that reports 3 of `class`, in the shape its far end reports it: a per-image answer,
/// a transcription's duration (3 ms), a counted rerank unit, or a token usage carrying the class
/// beside its tokens (the open counts the chat readers put on `TokenUsage::open_units`).
fn three_of(class: &str) -> Billing {
    match class {
        c if c == IMAGES_CLASS => Billing::Images {
            count: 3,
            size: None,
            quality: None,
        },
        c if c == AUDIO_MS_CLASS => Billing::Duration {
            seconds: busbar_contract::Count::parse("0.003").expect("a decimal"),
        },
        c if c == busbar_plane_llm::codec::ir::rerank::SEARCH_UNITS_CLASS => Billing::Counted {
            class: c.to_string(),
            count: 3,
        },
        c => Billing::Tokens(TokenUsage {
            open_units: std::collections::BTreeMap::from([(c.to_string(), 3)]),
            ..Default::default()
        }),
    }
}

/// Accrue `billing` on lane `m` under `card_yaml`, and return the key's derived spend in cents
/// (`Err` = the read refused, #42) and the governance ledger's class map for `m`.
fn accrue(
    card_yaml: Option<&str>,
    billing: Billing,
) -> (Result<i64, String>, std::collections::BTreeMap<String, u64>) {
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
        request_id: 0,
        admit: None,
    });
    let app = crate::test_support::TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "m",
            crate::proto_codec::PROTO_COHERE,
            "http://127.0.0.1:1",
        ))
        .pool("pm", &[(0, 1)])
        .build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    record_resp_usage(
        &host,
        Some(billing),
        &sink,
        EngineTables::new(&rt).lanes().first(),
    );
    let spend = gov
        .usage_for(cost.as_ref(), &key.id, charged_at)
        .map(|u| u.expect("the key exists").spend_cents)
        .map_err(|e| format!("{e:?}"));
    gov.flush_budgets();
    let lines = gov
        .store()
        .get_usage(&key.id, budget_window(WINDOW_TOTAL, charged_at))
        .expect("the governance ledger reads")
        .models
        .iter()
        .find(|m| m.model == "m")
        .map(|m| {
            m.usage_units
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(c, n)| (c.clone(), *n))
                .collect()
        })
        .unwrap_or_default();
    (spend, lines)
}

/// EVERY DECLARED OPEN CLASS: one line, priced by the card; #42's absent-rate rule unchanged. RED
/// before LEDGER-100 for `classifications`, `web_fetch_requests`, `unitemized_tokens`, `images`,
/// `audio_ms` and every guardrail class: the count was warned, a residual, or dropped, so the
/// priced arm read 0 and the ledger held no line.
#[test]
fn every_open_class_ledgers_one_line_priced_by_the_card() {
    for (class, _) in OPEN_CLASSES {
        let one_line = std::collections::BTreeMap::from([(class.to_string(), 3)]);
        let priced = format!("m: {{ units: {{ {class}: 10000 }} }}\n");
        let (spend, lines) = accrue(Some(&priced), three_of(class));
        assert_eq!(spend, Ok(3), "{class}: 3 units at 1 cent each");
        assert_eq!(lines, one_line, "{class}: exactly one ledger line");

        let (spend, _) = accrue(Some("m: { input_utok: 1 }\n"), three_of(class));
        assert!(
            spend.is_err(),
            "{class}: a present card silent about the class REFUSES (#42), never a silent 0"
        );

        let (spend, lines) = accrue(None, three_of(class));
        assert_eq!(spend, Ok(0), "{class}: no card, billing off reads 0");
        assert_eq!(lines, one_line, "{class}: the line is still the record");
    }
}

/// 1.5.5's billed counts are untouched: a chat turn whose tokens 1.5.5 billed prices exactly as
/// before when it reports no open class, and an open class beside the tokens adds only its own
/// line (the token lines and their price do not move).
#[test]
fn an_open_class_beside_the_tokens_moves_no_token_line() {
    let card = "m: { input_utok: 10000, output_utok: 20000, units: { classifications: 10000 } }\n";
    let tokens = TokenUsage {
        input: 2,
        output: 1,
        ..Default::default()
    };
    let (spend, lines) = accrue(Some(card), Billing::Tokens(tokens.clone()));
    assert_eq!(spend, Ok(4), "2 in at 1 cent + 1 out at 2 cents");
    assert_eq!(
        lines,
        std::collections::BTreeMap::from([("input".to_string(), 2), ("output".to_string(), 1)])
    );
    let with_open = TokenUsage {
        open_units: std::collections::BTreeMap::from([("classifications".to_string(), 5)]),
        ..tokens
    };
    let (spend, lines) = accrue(Some(card), Billing::Tokens(with_open));
    assert_eq!(
        spend,
        Ok(9),
        "the same 4 cents plus 5 classifications at 1 cent"
    );
    assert_eq!(
        lines,
        std::collections::BTreeMap::from([
            ("classifications".to_string(), 5),
            ("input".to_string(), 2),
            ("output".to_string(), 1),
        ])
    );
}
