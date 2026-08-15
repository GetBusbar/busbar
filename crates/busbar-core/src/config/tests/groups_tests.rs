// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/config/groups.rs`.

use super::*;

/// A group round-trips through YAML (deserialize -> serialize -> deserialize) unchanged. This is
/// the property the config OVERLAY relies on: an Admin-API-applied group budget must re-parse
/// identically at boot. Exercises every limit shape: windowed metrics, the windowless `concurrent`,
/// a per-pool budget (future `pool:` qualifier is additive; this covers today's shape), and the
/// parent chain.
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
    let g1: GroupCfg = serde_yaml::from_str(src).expect("parse group");
    assert!(
        g1.child_default
            .as_ref()
            .is_some_and(|c| c.limits.len() == 1),
        "child_default template parses"
    );
    // Serialize back out, then parse again — the two parsed values must be identical.
    let out = serde_yaml::to_string(&g1).expect("serialize group");
    let g2: GroupCfg = serde_yaml::from_str(&out).expect("re-parse serialized group");
    assert_eq!(
        g1, g2,
        "group must survive a serialize/deserialize round-trip"
    );

    // Spot-check the serialized shape is the canonical `{ <metric>: <amount>, per: <window> }`,
    // not some derived tagged form — a drift here would silently corrupt the overlay format.
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

/// A group with no `child_default` omits it from the serialized form (skip_serializing_if) — an
/// overlay-written group must not carry a spurious `child_default: null` that then fails re-parse.
#[test]
fn group_without_child_default_omits_it() {
    let g: GroupCfg = serde_yaml::from_str("limits: [ { budget: 10, per: day } ]").unwrap();
    let out = serde_yaml::to_string(&g).unwrap();
    assert!(
        !out.contains("child_default"),
        "no spurious child_default key: {out}"
    );
    // ..Default::default() construction matches a bare parse (the anti-smell property).
    assert_eq!(
        GroupCfg {
            limits: g.limits.clone(),
            ..Default::default()
        },
        g,
        "Default-based construction equals the parsed bare group"
    );
}

/// The windowless `concurrent` limit serializes WITHOUT a `per` key (len 1 map), and windowed
/// limits serialize WITH it (len 2) — the custom Serialize mirrors the custom Deserialize.
#[test]
fn limit_serialize_shape_matches_deserialize() {
    let concurrent: LimitCfg = serde_yaml::from_str("{ concurrent: 3 }").unwrap();
    assert_eq!(
        serde_yaml::to_string(&concurrent).unwrap().trim(),
        "concurrent: 3"
    );

    let budget: LimitCfg = serde_yaml::from_str("{ budget: 5000, per: month }").unwrap();
    let out = serde_yaml::to_string(&budget).unwrap();
    let back: LimitCfg = serde_yaml::from_str(&out).unwrap();
    assert_eq!(budget, back);
}

/// THE `LimitCfg` wire-compat contract test: `pool: <name>` / `downgrade_to:
/// <name>` in YAML — the entire existing config surface — decodes to `scope`/`downgrade_to:
/// Some(ScopeRef { kind: "pool", value: <name> })` in memory, and serializes back out as the
/// EXACT SAME bare `pool: <name>` / `downgrade_to: <name>` YAML keys, byte-for-byte — no
/// `kind`/`value` object ever appears on the wire. This is the property that makes the
/// `ScopeRef` generalization invisible to every existing `groups.yaml`.
#[test]
fn limit_pool_and_downgrade_to_wire_shape_is_byte_identical_to_pre_generalization() {
    let l: LimitCfg = serde_yaml::from_str(
        "{ budget: 5000, per: month, pool: frontier, on_exhaust: downgrade, \
             downgrade_to: value }",
    )
    .expect("pool + downgrade_to parse");
    assert_eq!(l.scope, Some(ScopeRef::pool("frontier")));
    assert_eq!(l.downgrade_to, Some(ScopeRef::pool("value")));

    let out = serde_yaml::to_string(&l).expect("serializes");
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

    let back: LimitCfg = serde_yaml::from_str(&out).expect("reparses");
    assert_eq!(
        back, l,
        "round-trip must be byte-for-byte behaviorally exact"
    );
}

/// An org → team tree where engineering sets its own child_default, accounting inherits the org's,
/// and an isolated group has none anywhere up the chain.
fn tree() -> BTreeMap<String, GroupCfg> {
    serde_yaml::from_str(
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
    // engineering sets its own → used directly.
    assert_eq!(
        resolve_child_default(&g, "engineering").unwrap().limits[0].amount,
        2000
    );
    // accounting has none → nearest ancestor with a template is acme (500).
    assert_eq!(
        resolve_child_default(&g, "accounting").unwrap().limits[0].amount,
        500
    );
    // no template anywhere up the chain → None (inherit-only).
    assert!(resolve_child_default(&g, "isolated").is_none());
    // unknown parent → None, not a panic.
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

    // accounting inherits acme's company-wide default.
    let acct = provision_child(&g, "accounting");
    assert_eq!(acct.parent.as_deref(), Some("accounting"));
    assert_eq!(acct.limits[0].amount, 500);

    // isolated: no ancestor template → inherit-only leaf (empty limits, capped only by the chain).
    let iso = provision_child(&g, "isolated");
    assert_eq!(iso.parent.as_deref(), Some("isolated"));
    assert!(
        iso.limits.is_empty(),
        "inherit-only leaf carries no own limits"
    );

    // unknown parent → graceful inherit-only leaf bound to that (to-be-created) parent.
    let unknown = provision_child(&g, "nope");
    assert_eq!(unknown.parent.as_deref(), Some("nope"));
    assert!(unknown.limits.is_empty());
}
