// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Selected partition records use the actual signed checkpoint Store fixture. Serialized
//! input keeps the regression runnable against the predecessor that rejects this variant.

use super::*;
use crate::governance::GovState;
use busbar_contract::json::JsonValueMutTrait as _;

fn source_facts(reported: Option<u64>, floor: Option<u64>, estimated: Option<u64>) -> json::Value {
    let high_water = reported
        .into_iter()
        .chain(floor)
        .chain(estimated)
        .max()
        .unwrap_or(0);
    json::json!({
        "reported": reported.map(Count::from),
        "floor": floor.map(Count::from),
        "estimated": estimated.map(Count::from),
        "rate_high_water": Count::from(high_water),
    })
}

fn attempt(
    preparation: u32,
    dispatch: Option<u32>,
    model: &str,
    facts: json::Value,
) -> json::Value {
    json::json!({
        "preparation": preparation,
        "dispatch": dispatch,
        "kind": "model",
        "instance": "plane",
        "selected_pool": "plane\u{1f}pool",
        "resource": model,
        "usage": {
            "lane": format!("plane\u{1f}{model}"),
            "provider": format!("provider-{model}"),
            "classes": { "work": facts },
        },
        "transport": if dispatch.is_some() { "committed" } else { "no_send" },
        "finality": if dispatch.is_some() { "complete" } else { "unknown" },
    })
}

fn selected_value() -> json::Value {
    let mut value = json::to_value(&unit(1)).unwrap();
    value["lane"] = json::json!("");
    value["provider"] = json::json!(null);
    value["units"] = json::json!({});
    value["ended"] = json::json!(true);
    value["partitions"] = json::json!({
        "version": 1,
        "request_pool": "plane\u{1f}pool",
        "routing_generation": 0,
        "attempt_limit": 3,
        "declared_classes": ["work"],
        "attempt_classes": ["work"],
        "physical_classes": ["work"],
        "session_origin": { "instance": "plane", "lane": "plane\u{1f}", "provider": null },
        "session": null,
        "attempts": [
            attempt(1, None, "declined", source_facts(None, None, None)),
            attempt(2, Some(1), "A", source_facts(Some(12), Some(18), Some(20))),
            attempt(3, Some(2), "B", source_facts(Some(8), None, None)),
        ],
        "far_end_answered": true,
        "caller_bytes_committed": true,
        "disposition": "end",
        "final_target": 3,
    });
    value
}

fn decode(value: &json::Value) -> UnitCheckpoint {
    let snapshot: UnitCheckpoint = json::from_value(value)
        .expect("the signed checkpoint variant must retain all selected partitions");
    snapshot.validate().unwrap();
    snapshot
}

async fn governance() -> GovState {
    GovState::new_with_core(crate::real_store::core().await, None, None)
        .await
        .unwrap()
}

fn meter_events(
    gov: &GovState,
    snapshot: &UnitCheckpoint,
) -> Vec<busbar_contract::records::MeteringDelta> {
    gov.unit_terminal_events(snapshot)
        .unwrap()
        .iter()
        .filter(|event| event.kind == RecoveryKind::Metering)
        .flat_map(|event| GovState::legacy_metering_values(event).unwrap())
        .collect()
}

#[tokio::test]
async fn selected_signed_snapshot_replays_all_sources_and_preparation_identity() {
    let fixture = fixture().await;
    let snapshot = decode(&selected_value());
    fixture.sink.persist(&snapshot).await.unwrap();
    let replay = fixture.sink.replay().await.unwrap();
    assert_eq!(replay, vec![snapshot.clone()]);
    fixture.sink.persist(&snapshot).await.unwrap();
    assert_eq!(fixture.sink.replay().await.unwrap(), replay);
    let encoded = json::to_value(&replay[0]).unwrap();
    assert_eq!(encoded["partitions"]["final_target"].as_u64(), Some(3));
    assert_eq!(
        encoded["partitions"]["attempts"][1]["dispatch"].as_u64(),
        Some(1)
    );
    assert_eq!(
        encoded["partitions"]["attempts"][2]["dispatch"].as_u64(),
        Some(2)
    );
    assert_eq!(
        encoded["partitions"]["attempts"][1]["usage"]["classes"]["work"],
        source_facts(Some(12), Some(18), Some(20))
    );
}

#[tokio::test]
async fn selected_events_keep_both_providers_and_only_one_logical_request() {
    let gov = governance().await;
    let snapshot = decode(&selected_value());
    let events = gov.unit_terminal_events(&snapshot).unwrap();
    let identities: std::collections::BTreeSet<_> =
        events.iter().map(|event| event.operation_id).collect();
    assert_eq!(identities.len(), events.len());
    let meters = meter_events(&gov, &snapshot);
    assert_eq!(meters.len(), 3);
    assert_eq!(meters[0].model, "plane\u{1f}A");
    assert_eq!(meters[0].provider, "provider-A");
    assert_eq!(meters[0].usage_units["work"], Count::from(12u64).micros());
    assert_eq!(meters[0].requests, 0);
    assert_eq!(meters[1].model, "plane\u{1f}B");
    assert_eq!(meters[1].usage_units["work"], Count::from(8u64).micros());
    assert_eq!(meters[1].requests, 0);
    assert_eq!(meters[2].model, "plane\u{1f}B");
    assert_eq!(meters[2].provider, "provider-B");
    assert_eq!(meters[2].requests, 1);
    assert!(meters[2].usage_units.is_empty());
    assert!(meters
        .iter()
        .all(|row| row.priced_from_ms == snapshot.era_at));
}

#[tokio::test]
async fn selected_estimates_never_become_terminal_or_recovery_usage_debt() {
    let gov = governance().await;
    for disposition in ["end", "recovered_running"] {
        let mut value = selected_value();
        value["partitions"]["disposition"] = json::json!(disposition);
        value["partitions"]["attempts"] = json::json!([attempt(
            1,
            Some(1),
            "A",
            source_facts(None, None, Some(500))
        )]);
        value["partitions"]["attempts"][0]["finality"] = json::json!("unknown");
        value["partitions"]["final_target"] = json::json!(null);
        value["metered"] = json::json!(false);
        let snapshot = decode(&value);
        assert!(gov.unit_terminal_events(&snapshot).unwrap().is_empty());
        let encoded = json::to_value(&snapshot).unwrap();
        assert_eq!(
            encoded["partitions"]["attempts"][0]["usage"]["classes"]["work"],
            source_facts(None, None, Some(500))
        );
    }
}

#[tokio::test]
async fn selected_cancel_preserves_the_independent_no_upstream_head_arm() {
    let gov = governance().await;
    for (answered, committed, expected_usage) in [
        (false, false, 0),
        (false, true, 0),
        (true, false, 0),
        (true, true, 2),
    ] {
        let mut value = selected_value();
        value["partitions"]["disposition"] = json::json!({ "cancel": { "reason": "client_gone" } });
        value["partitions"]["far_end_answered"] = json::json!(answered);
        value["partitions"]["caller_bytes_committed"] = json::json!(committed);
        value["partitions"]["final_target"] = json::json!(null);
        value["metered"] = json::json!(expected_usage != 0);
        let meters = meter_events(&gov, &decode(&value));
        assert_eq!(
            meters
                .iter()
                .filter(|row| !row.usage_units.is_empty())
                .count(),
            expected_usage
        );
    }
}

#[tokio::test]
async fn selected_no_winner_recovery_uses_the_captured_host_request_origin() {
    let gov = governance().await;
    let mut value = selected_value();
    value["partitions"]["disposition"] = json::json!("recovered_running");
    value["partitions"]["final_target"] = json::json!(null);
    value["partitions"]["attempts"][2]["usage"]["classes"]["work"] = source_facts(None, None, None);
    value["partitions"]["attempts"][2]["finality"] = json::json!("unknown");
    let meters = meter_events(&gov, &decode(&value));
    assert_eq!(meters.len(), 2);
    assert_eq!(meters[0].model, "plane\u{1f}A");
    assert_eq!(meters[0].usage_units["work"], Count::from(12u64).micros());
    assert_eq!(meters[1].model, "plane\u{1f}");
    assert!(meters[1].provider.is_empty());
    assert_eq!(meters[1].requests, 1);
    assert!(meters[1].usage_units.is_empty());
}
