// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/metrics/money.rs`: the `model` label a money row's ledger
//! lane key is scraped under.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use super::*;
use crate::governance::{GovState, MemoryStore, RecordStore, VirtualKey};
use crate::metrics::door_cells::DoorBreaker;

/// THE RULE: a stated label is rendered as stated; an unstated plain name (1.5.5's bare model) is
/// its own label, byte for byte; an unstated key carrying the plane separator or any control byte,
/// and a stated label carrying one, emit no series.
#[test]
fn the_model_label_is_stated_or_plain_and_never_an_internal_key() {
    let sep = PLANE_LANE_SEP;
    let stated = HashMap::from([
        (format!("door{sep}e"), "sec/e".to_string()),
        (format!("door{sep}"), "sec".to_string()),
        (format!("bad{sep}e"), "bad\u{7}label".to_string()),
    ]);
    assert_eq!(model_label(&stated, &format!("door{sep}e")), Some("sec/e"));
    assert_eq!(
        model_label(&stated, &format!("door{sep}")),
        Some("sec"),
        "the plane's fee lane: its scope alone"
    );
    assert_eq!(
        model_label(&stated, "gpt-5"),
        Some("gpt-5"),
        "the llm plane's bare model keeps its 1.5.5 bytes"
    );
    assert_eq!(
        model_label(&stated, "claude-3.5/sonnet:v2"),
        Some("claude-3.5/sonnet:v2")
    );
    assert_eq!(
        model_label(&stated, &format!("other{sep}e")),
        None,
        "an unstated separator-bearing key is suppressed"
    );
    assert_eq!(
        model_label(&stated, &format!("other{sep}")),
        None,
        "an unstated fee lane is suppressed"
    );
    assert_eq!(model_label(&stated, "tab\there"), None, "a control byte");
    assert_eq!(
        model_label(&stated, &format!("bad{sep}e")),
        None,
        "a stated label carrying a control byte is suppressed too"
    );
}

fn key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("hash-{id}"),
        name: format!("key-{id}"),
        enabled: true,
        created_at: 1_700_000_000,
        revision: 1,
        ..Default::default()
    }
}

/// ON THE SCRAPE: a door plane's rows are `busbar_bucket_tokens` series under the labels it stated,
/// kept after a newer generation stops stating them (the ledger keeps the history); an unstated
/// internal key is no series; the llm plane's bare model is its own label; no money series carries
/// the separator. RED: the ledger key rendered verbatim (`model="door\u{1f}e"`).
#[test]
fn a_door_planes_money_rows_are_scraped_under_its_stated_labels() {
    crate::metrics::init();
    let sep = PLANE_LANE_SEP;
    let vk = key("vk_money_label_scrape");
    let store = Arc::new(MemoryStore::new());
    store.put_key(&vk).expect("the key");
    let gov = Arc::new(GovState::new(store, None).expect("governance"));
    let cost = crate::cost::CostModel::flat(1);
    let input = |n: u64| BTreeMap::from([(busbar_contract::records::UNIT_INPUT.to_string(), n)]);
    for (lane, n) in [
        ("gpt-5-money-label".to_string(), 11),
        (format!("door{sep}e"), 12),
        (format!("door{sep}"), 13),
        (format!("unstated{sep}x"), 14),
    ] {
        gov.record_usage(&cost, &vk, "", &lane, &input(n), 1_700_000_000);
    }
    let app = crate::test_support::TestApp::new()
        .governance(gov)
        .cost(cost)
        .build();
    let models = |pairs: &[(String, &str)]| -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.clone(), (*v).to_string()))
            .collect()
    };
    let breaker = |stated: HashMap<String, String>| DoorBreaker {
        unit: Arc::new(busbar_kernel_breaker::BreakerUnit::new()),
        pools: HashMap::new(),
        lanes: HashMap::new(),
        models: stated,
    };
    app.door_cells.publish_breaker(
        "door",
        breaker(models(&[
            (format!("door{sep}e"), "sec/e"),
            (format!("door{sep}"), "sec"),
        ])),
    );
    // A newer generation states only the fee lane: the entry's label is still known.
    app.door_cells
        .publish_breaker("door", breaker(models(&[(format!("door{sep}"), "sec")])));
    crate::metrics::refresh_scrape_gauges(&app);
    let out = crate::metrics::render();
    let ours: Vec<&str> = out
        .lines()
        .filter(|l| {
            l.starts_with("busbar_bucket_tokens{")
                && l.contains("bucket=\"vk_money_label_scrape\"")
                && l.contains("tier=\"input\"")
        })
        .collect();
    let value = |model: &str| {
        ours.iter()
            .find(|l| l.contains(&format!("model=\"{model}\"")))
            .and_then(|l| l.rsplit(' ').next())
            .map(str::to_string)
    };
    assert_eq!(
        value("gpt-5-money-label").as_deref(),
        Some("11"),
        "the bare model: {ours:?}"
    );
    assert_eq!(value("sec/e").as_deref(), Some("12"), "the entry: {ours:?}");
    assert_eq!(
        value("sec").as_deref(),
        Some("13"),
        "the fee lane: {ours:?}"
    );
    assert_eq!(
        ours.len(),
        3,
        "the unstated internal key is no series: {ours:?}"
    );
    for line in out
        .lines()
        .filter(|l| l.starts_with("busbar_bucket_tokens{"))
    {
        assert!(
            !line.contains(sep),
            "no money series carries the separator: {line}"
        );
    }
}
