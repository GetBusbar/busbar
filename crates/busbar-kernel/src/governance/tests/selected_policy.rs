use super::*;

#[tokio::test]
async fn initial_install_requires_the_exact_unpublished_app_and_shared_governor() {
    let groups = groups(2);
    let mut app = crate::inbound::native::tests::app();
    let app = Arc::get_mut(&mut app).unwrap();
    app.cost = Arc::new(CostModel::resolve_parts(None, 0, &groups));
    let pending =
        |cost| SelectedPolicy::compile(&groups, cost, &[target(Some("r"), true)], None).unwrap();
    assert!(pending(app.cost.clone()).install_initial(app).is_err());
    assert!(
        app.selected_policy.is_none(),
        "missing governance cannot publish an unclocked policy"
    );
    let store = crate::real_store::core().await;
    let gov = Arc::new(
        super::super::GovState::new_with_core(store, None, None)
            .await
            .unwrap(),
    );
    app.governance = Some(gov.clone());
    let different_cost = Arc::new(CostModel::resolve_parts(None, 0, &groups));
    assert!(pending(different_cost).install_initial(app).is_err());
    assert!(
        app.selected_policy.is_none(),
        "equal group config is not the compiled App cost identity"
    );
    let before = gov.selected_rates().activation_minute().unwrap();
    pending(app.cost.clone()).install_initial(app).unwrap();
    let after = gov.selected_rates().activation_minute().unwrap();
    let installed = app.selected_policy.as_ref().unwrap().clone();
    assert_eq!(installed.revision(), 1);
    assert!((before..=after).contains(&installed.activated_minute()));
    assert!(Arc::ptr_eq(&installed.cost, &app.cost));
    assert!(pending(app.cost.clone()).install_initial(app).is_err());
    assert!(Arc::ptr_eq(
        app.selected_policy.as_ref().unwrap(),
        &installed
    ));
}

#[test]
fn target_compatibility_compares_retained_destination_policy_across_reopen() {
    use crate::config::min3::UpstreamCfg;
    use crate::upstreams::{UpstreamAuth, UpstreamDef};
    let original = UpstreamDef::from_config(
        "catalog-1",
        &busbar_contract::json::json!({"url": "https://example.com"}),
        &UpstreamCfg {
            resource: Some("r".into()),
            ..Default::default()
        },
        &crate::plugin_config::upstream_anchor,
    )
    .unwrap();
    let mut current = original.clone();
    current.name = "catalog-4".into();
    assert!(
        compatible_definition(&original, &current),
        "an unrelated allocation shift does not change the selected destination"
    );
    for changed in [
        {
            let mut value = current.clone();
            value.url = Some("https://other.example".into());
            value
        },
        {
            let mut value = current.clone();
            value.allow_private = !value.allow_private;
            value
        },
        {
            let mut value = current.clone();
            value.resource = Some("new".into());
            value
        },
        {
            let mut value = current.clone();
            value.tls.pin_spki.push([1; 32]);
            value
        },
        {
            let mut value = current.clone();
            value.tls.client_identity = Some(busbar_contract::secret_ref::SecretRef::None);
            value
        },
        {
            let mut value = current.clone();
            value.tls.trust = Some(Arc::new(crate::plugin_config::TrustAnchor {
                der: vec![vec![1]],
                sha256: [2; 32],
            }));
            value
        },
        {
            let mut value = current.clone();
            value.auth = Some(UpstreamAuth {
                instance: "auth".into(),
                cache_max_s: None,
                connect_callback: None,
                caller: true,
                scoped: false,
                per_request: false,
            });
            value
        },
    ] {
        assert!(!compatible_definition(&original, &changed));
    }
    let mut anchored = original.clone();
    anchored.tls.trust = Some(Arc::new(crate::plugin_config::TrustAnchor {
        der: vec![vec![1]],
        sha256: [2; 32],
    }));
    let mut same = anchored.clone();
    same.tls.trust = Some(Arc::new(crate::plugin_config::TrustAnchor {
        der: vec![vec![1]],
        sha256: [2; 32],
    }));
    assert!(compatible_definition(&anchored, &same));
    same.tls.trust = Some(Arc::new(crate::plugin_config::TrustAnchor {
        der: vec![vec![3]],
        sha256: [2; 32],
    }));
    assert!(
        !compatible_definition(&anchored, &same),
        "trust bytes cannot be replaced by a claimed digest"
    );
}

#[test]
fn current_rows_follow_current_ancestors_and_keep_per_rule_coverage() {
    let groups: BTreeMap<String, GroupCfg> = busbar_contract::yaml::from_str(
        "parent:\n  limits:\n    - {id: shared, upstream_resource: p/r, requests: 2, per: minute, per_key: true, enforcement: process}\nchild:\n  parent: parent\n  limits:\n    - {id: shared, upstream_resource: p/r, tokens: 8, per: minute, per_key: true, enforcement: process}",
    ).unwrap();
    let first = compiled(&groups, None).activate(None, 1, 10).unwrap();
    let key = busbar_contract::records::VirtualKey {
        id: "original-key".into(),
        enabled: true,
        group: Some("child".into()),
        ..Default::default()
    };
    let rows = first.applicable_rows(&key, "p", Some("r")).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].group_id(), "child");
    assert_eq!(rows[0].metric(), RateMetric::Tokens);
    assert_eq!(rows[1].group_id(), "parent");
    assert_eq!(rows[1].threshold(), 2);
    assert!(rows.iter().all(|row| row.activated_minute() == 10));

    let mut changed = groups.clone();
    changed.get_mut("parent").unwrap().limits.clear();
    let second = compiled(&changed, Some(&first))
        .activate(Some(&first), 2, 11)
        .unwrap();
    let current = second.applicable_rows(&key, "p", Some("r")).unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].policy_revision(), 2);
    assert_eq!(current[0].activated_minute(), 10);
    assert_eq!(
        first.applicable_rows(&key, "p", Some("r")).unwrap().len(),
        2
    );
}

#[test]
fn unlabelled_and_nonmatching_targets_still_require_an_enabled_current_chain() {
    let mut groups = groups(2);
    let key = busbar_contract::records::VirtualKey {
        id: "original-key".into(),
        enabled: true,
        group: Some("team".into()),
        ..Default::default()
    };
    let policy = compiled(&groups, None).activate(None, 1, 10).unwrap();
    assert!(policy.applicable_rows(&key, "p", None).unwrap().is_empty());
    assert!(policy
        .applicable_rows(&key, "other", Some("r"))
        .unwrap()
        .is_empty());
    groups.get_mut("team").unwrap().enabled = false;
    let disabled = compiled(&groups, Some(&policy))
        .activate(Some(&policy), 2, 11)
        .unwrap();
    assert!(matches!(
        disabled.applicable_rows(&key, "p", None),
        Err(SelectedPolicyRefusal::CurrentAuthority)
    ));
    let removed = compiled(&BTreeMap::new(), Some(&disabled))
        .activate(Some(&disabled), 3, 12)
        .unwrap();
    assert!(matches!(
        removed.applicable_rows(&key, "p", None),
        Err(SelectedPolicyRefusal::CurrentAuthority)
    ));
    assert_eq!(
        key.group.as_deref(),
        Some("team"),
        "current resolution cannot rewrite the original key"
    );
}

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
    let unrelated = compiled(&groups(2), None).activate(None, 1, 10).unwrap();
    assert!(compiled(&groups(3), Some(&first))
        .activate(Some(&unrelated), 2, 11)
        .is_err());
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
fn rule_rename_metric_change_and_resource_move_start_new_coverage() {
    let first = compiled(&groups(2), None).activate(None, 1, 10).unwrap();
    for (id, metric, resource) in [
        ("renamed", "requests", "r"),
        ("rpm", "tokens", "r"),
        ("rpm", "requests", "other"),
    ] {
        let changed: BTreeMap<String, GroupCfg> = busbar_contract::yaml::from_str(&format!("team:\n  limits:\n    - {{id: {id}, upstream_resource: p/{resource}, {metric}: 2, per: minute, per_key: true, enforcement: process}}" )).unwrap();
        let cost = Arc::new(CostModel::resolve_parts(None, 0, &changed));
        let changed = SelectedPolicy::compile(
            &changed,
            cost,
            &[target(Some(resource), true)],
            Some(&first),
        )
        .unwrap()
        .activate(Some(&first), 2, 11)
        .unwrap();
        assert!(changed.groups["team"][0].activated_minute.is_none());
        assert_eq!(changed.activated_minute(), 11);
    }
    assert_eq!(first.groups["team"][0].id.as_ref(), "rpm");
    assert_eq!(first.activated_minute(), 10);
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
