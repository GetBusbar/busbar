// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{MeteringDelta, MeteringRow};
use crate::json;

fn selected(role: &str) -> json::Value {
    let pricing = if role == "fee" {
        json::json!({"version":1,"role":"fee","lane":"plane\u{1f}pool",
            "charged":1,"refunded":0,"unknown":0})
    } else {
        json::json!({"version":1,"role":role})
    };
    json::json!({"scale":6,"key_id":"key","bucket":0,"model":"plane\u{1f}",
        "provider":"","tokens_input":0,"tokens_output":0,"tokens_cache_read":0,
        "tokens_cache_write":0,"requests":0,"billable_requests":0,"pricing":pricing})
}

#[test]
fn selected_meter_pricing_survives_exact_roundtrip() {
    for role in ["usage", "request", "fee"] {
        let wire = selected(role);
        let delta: MeteringDelta = json::from_value(&wire).unwrap();
        let back = json::to_value(&delta).unwrap();
        assert_eq!(back["pricing"], wire["pricing"]);
    }
}

#[test]
fn selected_meter_rejects_unknown_versions_and_role_fields() {
    let mut wire = selected("usage");
    wire["pricing"]["version"] = json::json!(2);
    assert!(json::from_value::<MeteringDelta>(&wire).is_err());
    wire = selected("request");
    wire["pricing"]["charged"] = json::json!(1);
    assert!(json::from_value::<MeteringDelta>(&wire).is_err());
}

#[test]
fn selected_meter_rejects_request_as_usage_and_fee_overflow_atomically() {
    let mut wire = selected("usage");
    wire["requests"] = json::json!(1);
    let mut delta: MeteringDelta = json::from_value(&wire).unwrap();
    assert!(delta.normalize_scale6().is_err());
    wire = selected("fee");
    wire["pricing"]["charged"] = json::json!(u64::MAX);
    let mut row: MeteringRow = json::from_value(&wire).unwrap();
    let before = row.clone();
    let delta: MeteringDelta = json::from_value(&selected("fee")).unwrap();
    assert!(row.checked_add_delta(&delta).is_err());
    assert_eq!(row, before);
}
