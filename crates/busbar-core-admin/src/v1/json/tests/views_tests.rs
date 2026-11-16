// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 §5.5 and §5.9: view descriptors over closed vocabularies, positional rows and
//! one wire encoding per field type.

use super::*;
use busbar_contract::json::json;

fn descriptor() -> Value {
    json!({
        "view": "lanes",
        "title": "Lanes",
        "shape": "table",
        "fields": [
            {"name": "lane", "label": "Lane", "type": "string", "role": "id"},
            {"name": "pool", "label": "Pool", "type": "string", "role": "dimension"},
            {"name": "inflight", "label": "In flight", "type": "int", "unit": "count", "role": "measure"},
            {"name": "served", "label": "Served", "type": "int", "format": "u64", "unit": "count", "role": "measure"},
            {"name": "ratio", "label": "Error ratio", "type": "float", "unit": "ratio", "role": "measure"},
            {"name": "spend", "label": "Spend", "type": "money_micros", "unit": "micros", "role": "measure"},
            {"name": "at", "label": "Last trip", "type": "time", "role": "time"},
            {"name": "up", "label": "Usable", "type": "bool", "role": "status"}
        ],
        "default_sort": "lane",
        "filters": ["pool", "lane"],
        "time": "at",
        "step_options": [60, 3600]
    })
}

#[test]
fn view_rows_positional() {
    let d = validate(&descriptor()).expect("the descriptor is valid");
    let row = row(
        &d,
        &json!({"up": true, "lane": "a/m1", "pool": "main", "inflight": 2, "served": 7,
                "ratio": 0.5, "spend": "12.345", "at": 1_700_000_000_000_u64, "extra": "x"}),
    );
    assert_eq!(
        row,
        json!([
            "a/m1",
            "main",
            2,
            "7",
            0.5,
            "12.345",
            1_700_000_000_000_u64,
            true
        ]),
        "one cell per field, in `fields` order; members outside the fields are not served"
    );
    let sparse = super::row(&d, &json!({"lane": "b/m2"}));
    assert_eq!(
        sparse,
        json!(["b/m2", null, null, null, null, null, null, null])
    );
}

#[test]
fn view_wire_encodings() {
    let d = validate(&descriptor()).expect("valid");
    let row = row(
        &d,
        &json!({"lane": 5, "pool": "p", "inflight": "3", "served": 18_446_744_073_709_551_615_u64,
                "ratio": "0.5", "spend": 1200, "at": "1700000000000", "up": "yes"}),
    );
    assert_eq!(
        row,
        json!([
            null,
            "p",
            3,
            "18446744073709551615",
            null,
            "1200",
            1_700_000_000_000_u64,
            null
        ]),
        "a u64 int is a decimal string, money is the exact decimal string, a time is integer \
         milliseconds, and a cell not held in its type is null"
    );
    let bad_money = super::row(&d, &json!({"spend": "1.2345"}));
    assert_eq!(bad_money[5], json!(null), "money has at most three places");
}

#[test]
fn view_measure_unit_required() {
    let mut no_unit = descriptor();
    no_unit["fields"][2] =
        json!({"name": "inflight", "label": "In flight", "type": "int", "role": "measure"});
    let refused = validate(&no_unit).expect_err("a measure with no unit is invalid");
    assert!(refused.0.contains("inflight"), "{refused:?}");

    let mut odd_unit = descriptor();
    odd_unit["fields"][2]["unit"] = json!("parsecs");
    assert!(
        validate(&odd_unit).is_err(),
        "a unit outside the closed list is invalid"
    );

    let mut dimension = descriptor();
    dimension["fields"][1]["unit"] = json!("furlongs");
    assert!(
        validate(&dimension).is_err(),
        "any unit present is from the closed list"
    );
}

#[test]
fn view_descriptor_invalid_drops_view() {
    let mut bad_shape = descriptor();
    bad_shape["view"] = json!("broken");
    bad_shape["shape"] = json!("pie");
    let mut bad_type = descriptor();
    bad_type["view"] = json!("typed");
    bad_type["fields"][0]["type"] = json!("uuid");
    let mut bad_role = descriptor();
    bad_role["view"] = json!("roled");
    bad_role["fields"][0]["role"] = json!("colour");
    let mut bad_id = descriptor();
    bad_id["view"] = json!("Not-An-Id");
    let mut bad_filter = descriptor();
    bad_filter["view"] = json!("filtered");
    bad_filter["filters"] = json!(["inflight"]);
    let (kept, dropped) = admitted(&[
        descriptor(),
        bad_shape,
        bad_type,
        bad_role,
        bad_id,
        bad_filter,
        descriptor(),
    ]);
    assert_eq!(
        kept.iter().map(|d| d.view.as_str()).collect::<Vec<_>>(),
        vec!["lanes"],
        "only the valid descriptor is kept"
    );
    assert_eq!(
        dropped.len(),
        6,
        "each invalid or repeated view is dropped: {dropped:?}"
    );
}

#[test]
fn view_filters_name_dimension_and_id_fields() {
    let d = validate(&descriptor()).expect("valid");
    let pairs = vec![
        ("filter".to_string(), "pool:main".to_string()),
        ("limit".to_string(), "5".to_string()),
    ];
    let parsed = filters(&d, &pairs).expect("pool is a dimension");
    assert_eq!(parsed, vec![(1, "main".to_string())]);
    let main = row(&d, &json!({"lane": "a", "pool": "main"}));
    let other = row(&d, &json!({"lane": "b", "pool": "spare"}));
    assert!(matches(&main, &parsed));
    assert!(!matches(&other, &parsed));
    assert!(filters(&d, &[("filter".to_string(), "inflight:2".to_string())]).is_err());
    assert!(filters(&d, &[("filter".to_string(), "pool".to_string())]).is_err());
}
