// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn group_yaml_round_trips_exactly() {
    let src = "\
parent: team-payments
enabled: true
limits:
  - { budget: 1000, per: month }
  - { requests: 500, per: minute }
  - { tokens: 20000000, per: day }
  - { concurrent: 5 }
child_default:
  limits:
    - { budget: 2000, per: month }
";
    let g1: GroupCfg = busbar_contract::yaml::from_str(src).expect("parse group");
    assert!(
        g1.child_default
            .as_ref()
            .is_some_and(|c| c.limits.len() == 1),
        "child_default template parses"
    );

    let out = busbar_contract::yaml::to_string(&g1).expect("serialize group");
    let g2: GroupCfg = busbar_contract::yaml::from_str(&out).expect("re-parse serialized group");
    assert_eq!(
        g1, g2,
        "group must survive a serialize/deserialize round-trip"
    );

    assert!(
        out.contains("budget: 1000"),
        "budget metric key preserved: {out}"
    );
    assert!(out.contains("per: month"), "window preserved: {out}");
    assert!(
        out.contains("concurrent: 5"),
        "windowless concurrent preserved: {out}"
    );
    assert!(
        !out.contains("per: null"),
        "concurrent must not emit a null `per`: {out}"
    );
    assert!(
        out.contains("child_default"),
        "child_default preserved: {out}"
    );
}

#[test]
fn group_without_child_default_omits_it() {
    let g: GroupCfg =
        busbar_contract::yaml::from_str("limits: [ { budget: 10, per: day } ]").unwrap();
    let out = busbar_contract::yaml::to_string(&g).unwrap();
    assert!(
        !out.contains("child_default"),
        "no spurious child_default key: {out}"
    );

    assert_eq!(
        GroupCfg {
            limits: g.limits.clone(),
            ..Default::default()
        },
        g,
        "Default-based construction equals the parsed bare group"
    );
}

#[test]
fn limit_serialize_shape_matches_deserialize() {
    let concurrent: LimitCfg = busbar_contract::yaml::from_str("{ concurrent: 3 }").unwrap();
    assert_eq!(
        busbar_contract::yaml::to_string(&concurrent)
            .unwrap()
            .trim(),
        "concurrent: 3"
    );

    let budget: LimitCfg = busbar_contract::yaml::from_str("{ budget: 5000, per: month }").unwrap();
    let out = busbar_contract::yaml::to_string(&budget).unwrap();
    let back: LimitCfg = busbar_contract::yaml::from_str(&out).unwrap();
    assert_eq!(budget, back);
}

#[test]
fn every_limit_metric_serde_round_trips() {
    fn spelling(m: LimitMetric) -> &'static str {
        match m {
            LimitMetric::Requests => "requests",
            LimitMetric::Tokens => "tokens",
            LimitMetric::Budget => "budget",
            LimitMetric::Concurrent => "concurrent",
        }
    }
    let all = [
        LimitMetric::Requests,
        LimitMetric::Tokens,
        LimitMetric::Budget,
        LimitMetric::Concurrent,
    ];
    for m in all {
        let key = spelling(m);

        assert_eq!(m.as_str(), key, "as_str spelling for {m:?}");

        let src = if m == LimitMetric::Concurrent {
            format!("{{ {key}: 7 }}")
        } else {
            format!("{{ {key}: 7, per: minute }}")
        };
        let parsed: LimitCfg =
            busbar_contract::yaml::from_str(&src).unwrap_or_else(|e| panic!("parse `{src}`: {e}"));
        assert_eq!(parsed.metric, m, "deserialize `{key}` -> variant");

        let out = busbar_contract::yaml::to_string(&parsed).expect("serialize");
        let back: LimitCfg = busbar_contract::yaml::from_str(&out).expect("re-parse");
        assert_eq!(parsed, back, "round-trip for `{key}`");
        assert!(
            out.contains(key),
            "serialized form keeps the metric key `{key}`: {out}"
        );
    }
}

#[test]
fn limit_pool_and_downgrade_to_wire_shape_is_byte_identical_to_pre_generalization() {
    let l: LimitCfg = busbar_contract::yaml::from_str(
        "{ budget: 5000, per: month, pool: frontier, on_exhaust: downgrade, \
             downgrade_to: value }",
    )
    .expect("pool + downgrade_to parse");
    assert_eq!(l.scope, Some(ScopeRef::pool("frontier")));
    assert_eq!(l.downgrade_to, Some(ScopeRef::pool("value")));

    let out = busbar_contract::yaml::to_string(&l).expect("serializes");
    assert!(
        out.contains("pool: frontier"),
        "wire key stays the bare `pool: <name>`, no {{kind, value}} wrapper: {out}"
    );
    assert!(
        out.contains("downgrade_to: value"),
        "wire key stays the bare `downgrade_to: <name>`, no {{kind, value}} wrapper: {out}"
    );
    assert!(
        !out.contains("kind") && !out.contains("value:"),
        "no ScopeRef {{kind, value}} shape may leak onto the wire: {out}"
    );

    let back: LimitCfg = busbar_contract::yaml::from_str(&out).expect("reparses");
    assert_eq!(
        back, l,
        "round-trip must be byte-for-byte behaviorally exact"
    );
}

fn tree() -> BTreeMap<String, GroupCfg> {
    busbar_contract::yaml::from_str(
        "
acme:
  limits: [ { budget: 5000000, per: month } ]
  child_default: { limits: [ { budget: 500, per: month } ] }
engineering:
  parent: acme
  child_default: { limits: [ { budget: 2000, per: month } ] }
accounting:
  parent: acme
isolated:
  limits: [ { requests: 10, per: minute } ]
",
    )
    .expect("tree parses")
}

#[test]
fn resolve_child_default_walks_to_nearest_ancestor() {
    let g = tree();

    assert_eq!(
        resolve_child_default(&g, "engineering").unwrap().limits[0].amount,
        2000
    );

    assert_eq!(
        resolve_child_default(&g, "accounting").unwrap().limits[0].amount,
        500
    );

    assert!(resolve_child_default(&g, "isolated").is_none());

    assert!(resolve_child_default(&g, "nonexistent").is_none());
}

#[test]
fn provision_child_builds_leaf_from_nearest_default() {
    let g = tree();

    let eng = provision_child(&g, "engineering");
    assert_eq!(eng.parent.as_deref(), Some("engineering"));
    assert_eq!(eng.limits.len(), 1);
    assert_eq!(eng.limits[0].metric, LimitMetric::Budget);
    assert_eq!(eng.limits[0].amount, 2000);
    assert!(
        eng.child_default.is_none(),
        "a provisioned leaf is not itself a template source"
    );
    assert!(eng.enabled, "a provisioned leaf is enabled");

    let acct = provision_child(&g, "accounting");
    assert_eq!(acct.parent.as_deref(), Some("accounting"));
    assert_eq!(acct.limits[0].amount, 500);

    let iso = provision_child(&g, "isolated");
    assert_eq!(iso.parent.as_deref(), Some("isolated"));
    assert!(
        iso.limits.is_empty(),
        "inherit-only leaf carries no own limits"
    );

    let unknown = provision_child(&g, "nope");
    assert_eq!(unknown.parent.as_deref(), Some("nope"));
    assert!(unknown.limits.is_empty());
}

#[test]
fn distinct_groups_cannot_share_a_generated_enforcement_identity() {
    let mut groups: BTreeMap<String, GroupCfg> = busbar_contract::yaml::from_str(
        r#"
a:
  limits:
    - { requests: 2, per: day, pool: 'x@day' }
    - { tokens: 9, per: day, pool: 'x@day' }
'a@day#pool:x':
  limits: [{ budget: 4, per: day }]
"#,
    )
    .unwrap();
    let mut errors = Vec::new();
    validate_groups(&groups, &|p| p == "x@day", &mut errors);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("group:a@day#pool:x@day"), "{errors:?}");

    let other = groups.remove("a@day#pool:x").unwrap();
    groups.insert("a@day#pool:other".into(), other);
    errors.clear();
    validate_groups(&groups, &|p| p == "x@day", &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    let cost = crate::cost::CostModel::resolve_parts(None, 0, &groups);
    let bucket = &cost.group_named("a").unwrap().buckets[0];
    assert_eq!(bucket.bucket_id, "group:a@day#pool:x@day");
    assert_eq!(cost.group_named("a").unwrap().buckets.len(), 1);
}
