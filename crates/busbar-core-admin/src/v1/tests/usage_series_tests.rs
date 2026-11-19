// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 11: the `/usage` series, its dimensions and its range rules.

use super::operations::{
    parse_utc_day, project_usage_rows_exact, project_usage_series, SeriesSpec, UsageDim,
};
use super::*;
use busbar_kernel::governance::MeteringRow;

const LANE: &str = "m-series-chat";
const PROVIDER: &str = "series-chat";
const DAY: u64 = busbar_kernel::governance::METERING_BUCKET_SECS;
const D1: u64 = 19_723 * DAY;
const D2: u64 = D1 + DAY;

fn cost() -> Arc<busbar_kernel::cost::CostModel> {
    let rates = std::collections::BTreeMap::from([(
        LANE.to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 1.0,
            output_utok: 0.0,
            cache_read_utok: 0.0,
            cache_write_utok: Some(0.0),
            ..Default::default()
        },
    )]);
    Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
        Some(&rates),
        0,
        &std::collections::BTreeMap::new(),
    ))
}

fn row(
    key: &str,
    group: &str,
    model: &str,
    provider: &str,
    requests: u64,
    tokens: i128,
) -> MeteringRow {
    MeteringRow {
        pricing: None,
        scale: 0,
        usage_units: Default::default(),
        key_id: key.into(),
        model: model.into(),
        provider: provider.into(),
        tokens_input: tokens,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests,
        billable_requests: requests,
        key_group_at_use: group.into(),
        pricing_version: String::new(),
        priced_from_ms: 0,
    }
}

fn spec(from: u64, to: u64, group_by: &[UsageDim]) -> SeriesSpec {
    SeriesSpec {
        from,
        to,
        group_by: group_by.to_vec(),
        filters: Vec::new(),
        as_of: None,
    }
}

fn series(
    days: Vec<(u64, Vec<MeteringRow>)>,
    spec: &SeriesSpec,
) -> Result<crate::v1::contract::UsageSeries, AdminError> {
    let days = days
        .into_iter()
        .map(|(bucket, rows)| (bucket, ((rows, HashMap::new(), Vec::new()), Vec::new())))
        .collect();
    project_usage_series(cost(), None, None, DAY * 20_000, days, spec)
}

fn two_days() -> Vec<(u64, Vec<MeteringRow>)> {
    vec![
        (D1, vec![row("ka", "g1", LANE, PROVIDER, 3, 1_000)]),
        (
            D2,
            vec![
                row("kb", "g2", LANE, PROVIDER, 5, 2_000),
                row("ka", "g1", LANE, PROVIDER, 1, 500),
            ],
        ),
    ]
}

#[test]
fn usage_series_equals_daily_sum() {
    let all = series(two_days(), &spec(D1, D2, &[])).unwrap();
    assert_eq!(all.items.len(), 1);
    let (mut requests, mut spend, mut tokens) = (0u64, 0i64, Count::default());
    for (bucket, rows) in two_days() {
        let day = project_usage_rows_exact(
            cost(),
            None,
            None,
            UsageWindow {
                start: bucket,
                end: bucket + DAY,
            },
            0,
            (rows, HashMap::new(), Vec::new()),
        )
        .unwrap();
        requests += day.total.requests;
        spend += day.total.spend_micros;
        tokens = tokens.checked_add(day.total.tokens_input).unwrap();
    }
    let item = &all.items[0].usage;
    assert_eq!(item.requests, requests);
    assert_eq!(item.spend_micros, Some(spend));
    assert_eq!(item.tokens_input, tokens);
    assert!(item.priced);
}

#[test]
fn usage_group_by_each_dim() {
    let rows = vec![(
        D1,
        vec![
            row("ka", "g1", LANE, PROVIDER, 1, 10),
            row("kb", "g2", LANE, PROVIDER, 1, 10),
            row("kb", "g2", "m-other", "other-prov", 1, 10),
        ],
    )];
    let by = |dim| series(rows.clone(), &spec(D1, D1, &[dim])).unwrap().items;
    assert_eq!(by(UsageDim::Key).len(), 2);
    assert_eq!(by(UsageDim::Group).len(), 2);
    assert_eq!(by(UsageDim::Model).len(), 2);
    assert_eq!(by(UsageDim::Provider).len(), 2);
    let bucket = by(UsageDim::Bucket);
    assert_eq!((bucket.len(), bucket[0].bucket_start), (1, Some(D1)));
    let keys = by(UsageDim::Key);
    assert_eq!(keys[0].key.as_deref(), Some("ka"));
    assert!(keys[0].model.is_none() && keys[0].group.is_none());
    let instance = by(UsageDim::Instance);
    assert_eq!(instance.len(), 1);
    assert!(instance[0]
        .instance
        .as_deref()
        .is_some_and(|i| !i.is_empty()));
    let kind = by(UsageDim::Kind);
    assert_eq!((kind.len(), kind[0].kind.as_deref()), (1, Some("plane")));
}

#[test]
fn usage_instance_derived_matches_metering_lane() {
    busbar_kernel::plane_driver::registry::publish_planes(&[&SERIES_PLANE]);
    let plane = busbar_kernel::plane_driver::registry::plane_decl_for(SERIES_PLANE.key)
        .expect("the non-fallback plane is registered");
    let lane = busbar_kernel::governance::metering_lane(LANE, plane.key);
    assert_ne!(lane.as_ref(), LANE, "the plane provider qualifies the lane");
    let rows = vec![(
        D1,
        vec![
            row("ka", "g1", LANE, plane.key, 1, 10),
            row("ka", "g1", LANE, PROVIDER, 1, 10),
        ],
    )];
    let items = series(rows, &spec(D1, D1, &[UsageDim::Instance]))
        .unwrap()
        .items;
    assert_eq!(items.len(), 2);
    assert!(items
        .iter()
        .any(|i| i.instance.as_deref() == Some(plane.key)));
}

#[test]
fn usage_by_key_not_truncated() {
    let rows = (0..1_001)
        .map(|n| row(&format!("k{n:05}"), "g", LANE, PROVIDER, 1, 1))
        .collect();
    let all = series(vec![(D1, rows)], &spec(D1, D1, &[UsageDim::Key])).unwrap();
    assert_eq!(all.items.len(), 1_001);
    let sorts: Vec<_> = all.items.iter().map(|i| i.sort.clone()).collect();
    let mut sorted = sorts.clone();
    sorted.sort();
    assert_eq!(sorts, sorted, "rows come in keyset order");
}

#[test]
fn usage_range_unpriced_row_not_409() {
    let rows = vec![(
        D1,
        vec![
            row("ka", "g", LANE, PROVIDER, 1, 10),
            row("ka", "g", "m-unpriced-lane", PROVIDER, 1, 10),
        ],
    )];
    let items = series(rows, &spec(D1, D1, &[UsageDim::Model]))
        .expect("a range read never refuses on an unpriced class")
        .items;
    let unpriced = items
        .iter()
        .find(|i| i.model.as_deref() == Some("m-unpriced-lane"));
    let unpriced = unpriced.expect("the unpriced model still has its row");
    assert!(!unpriced.usage.priced);
    assert_eq!(unpriced.usage.spend_micros, None);
    assert_eq!(unpriced.usage.requests, 1);
    let priced = items
        .iter()
        .find(|i| i.model.as_deref() == Some(LANE))
        .unwrap();
    assert!(priced.usage.priced && priced.usage.spend_micros.is_some());
}

#[test]
fn usage_series_filters_apply_before_grouping() {
    let mut s = spec(D1, D2, &[UsageDim::Key]);
    s.filters = vec![(UsageDim::Group, "g1".into())];
    let items = series(two_days(), &s).unwrap().items;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].usage.requests, 4);
}

#[test]
fn usage_day_parse_is_strict_utc() {
    assert_eq!(parse_utc_day("1970-01-01"), Some(0));
    assert_eq!(parse_utc_day("2024-02-29"), Some(1_709_164_800));
    assert_eq!(parse_utc_day("2023-02-29"), None);
    assert_eq!(parse_utc_day("2024-2-29"), None);
    assert_eq!(parse_utc_day("2024-13-01"), None);
    assert_eq!(parse_utc_day("1969-12-31"), None);
    assert_eq!(parse_utc_day("2024-02-29T00:00"), None);
}

static SERIES_PLANE: busbar_kernel::plane_driver::registry::PlaneDecl =
    busbar_kernel::plane_driver::registry::PlaneDecl {
        declaration: busbar_kernel::plane_driver::registry::PlaneDeclaration {
            key: "series-plane",
            fallback: false,
            config_section: "series_plane",
            scope_kinds: &[],
            subject_noun: "series",
            admin_noun: "series",
            audit_kind: "series",
            card_signing_domain: None,
            card_kid_prefix: None,
            owned_config_sections: &[],
            billable_classes: &[],
            class_parents: &[],
            fee_units: &[],
            metric_families: &[],
            record_kinds: &[],
            required_config_sections: &[],
            trust_keys: &[],
            served_op_classes: &[],
            caller_credential_refusal: None,
        },
        wire_format_names: |_| &[],
        provider_dialects: |_| &[],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_, _| None,
        routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
        resolve_provider: None,
        door: None,
    };
