// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn groups(amount: u64) -> BTreeMap<String, GroupCfg> {
    busbar_contract::yaml::from_str(&format!("team:\n  limits:\n    - {{id: rpm, upstream_resource: p/r, requests: {amount}, per: minute, per_key: true, enforcement: process}}" )).unwrap()
}

fn target(resource: Option<&str>, tokens: bool) -> SelectedTargetConfig<'_> {
    SelectedTargetConfig {
        instance: "p",
        pool: "actual-pool",
        member: "p\u{1f}member",
        kind: SelectedTargetKind::Model,
        resource,
        attempt_accounting: tokens,
    }
}

fn compiled(
    groups: &BTreeMap<String, GroupCfg>,
    previous: Option<&SelectedPolicy>,
) -> PendingSelectedPolicy {
    let cost = Arc::new(CostModel::resolve_parts(None, 0, groups));
    SelectedPolicy::compile(groups, cost, &[target(Some("r"), true)], previous).unwrap()
}

#[test]
fn amount_reload_preserves_activation_but_reintroduction_has_new_coverage() {
    let first = compiled(&groups(2), None).activate(None, 1, 10).unwrap();
    let changed = compiled(&groups(7), Some(&first))
        .activate(Some(&first), 2, 11)
        .unwrap();
    let rule = &changed.groups["team"][0];
    assert_eq!(rule.threshold, 7);
    assert_eq!(rule.activated_minute.unwrap(), 10);
    let removed = compiled(&BTreeMap::new(), Some(&changed))
        .activate(Some(&changed), 3, 12)
        .unwrap();
    let restored = compiled(&groups(3), Some(&removed))
        .activate(Some(&removed), 4, 13)
        .unwrap();
    assert!(restored.groups["team"][0].activated_minute.is_none());
    assert_eq!(restored.activated_minute, 13);
    assert_eq!(first.groups["team"][0].threshold, 2);
}

#[test]
fn publication_rejects_wrong_predecessor_revision_and_clock_regression() {
    let first = compiled(&groups(2), None).activate(None, 1, 10).unwrap();
    assert!(compiled(&groups(3), Some(&first))
        .activate(None, 2, 11)
        .is_err());
    assert!(compiled(&groups(3), Some(&first))
        .activate(Some(&first), 1, 11)
        .is_err());
    assert!(compiled(&groups(3), Some(&first))
        .activate(Some(&first), 2, 9)
        .is_err());
}

#[test]
fn unknown_target_and_unsupported_tokens_refuse_compilation() {
    let groups = groups(1);
    let cost = Arc::new(CostModel::resolve_parts(None, 0, &groups));
    assert!(SelectedPolicy::compile(&groups, cost.clone(), &[target(None, true)], None).is_err());
    let tokens = busbar_contract::yaml::from_str("team:\n  limits:\n    - {id: tpm, upstream_resource: p/r, tokens: 3, per: minute, per_key: true, enforcement: process}").unwrap();
    let cost = Arc::new(CostModel::resolve_parts(None, 0, &tokens));
    assert!(SelectedPolicy::compile(&tokens, cost, &[target(Some("r"), false)], None).is_err());
}

#[test]
fn conflicting_actual_target_labels_refuse_and_shared_labels_are_allowed() {
    let groups = groups(1);
    let cost = Arc::new(CostModel::resolve_parts(None, 0, &groups));
    assert!(SelectedPolicy::compile(
        &groups,
        cost.clone(),
        &[target(Some("r"), true), target(Some("other"), true)],
        None
    )
    .is_err());
    let mut other = target(Some("r"), true);
    other.member = "p\u{1f}other";
    assert!(
        SelectedPolicy::compile(&groups, cost, &[target(Some("r"), true), other], None).is_ok()
    );
}

#[test]
fn ancestor_and_child_template_rule_counts_are_checked_without_truncation() {
    let row = |id: usize| {
        format!("    - {{id: r{id}, upstream_resource: p/r, requests: 1, per: minute, per_key: true, enforcement: process}}\n")
    };
    let mut source = "root:\n  limits:\n".to_owned();
    for id in 0..32 {
        source.push_str(&row(id));
    }
    let groups: BTreeMap<String, GroupCfg> = busbar_contract::yaml::from_str(&source).unwrap();
    assert_eq!(compiled(&groups, None).groups["root"].len(), 32);
    source.push_str("child:\n  parent: root\n  limits:\n");
    source.push_str(&row(32));
    let too_many = busbar_contract::yaml::from_str(&source).unwrap();
    let cost = Arc::new(CostModel::resolve_parts(None, 0, &too_many));
    assert!(SelectedPolicy::compile(&too_many, cost, &[target(Some("r"), true)], None).is_err());
    let mut template_source = "root:\n  child_default:\n    limits:\n".to_owned();
    for id in 0..33 {
        template_source.push_str(&format!("  {}", row(id)));
    }
    let template = busbar_contract::yaml::from_str(&template_source).unwrap();
    let cost = Arc::new(CostModel::resolve_parts(None, 0, &template));
    assert!(SelectedPolicy::compile(&template, cost, &[target(Some("r"), true)], None).is_err());
}
