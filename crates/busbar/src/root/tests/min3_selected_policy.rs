// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::config::min3::UpstreamCfg;
use busbar_kernel::upstreams::UpstreamDef;

fn definitions() -> ConfiguredUpstreams {
    ConfiguredUpstreams::from_definitions(
        [("one", Some("shared")), ("two", None)]
            .into_iter()
            .map(|(name, resource)| {
                let entry = busbar_contract::json::json!({"url": "https://example.com"});
                let definition = UpstreamDef::from_config(
                    name,
                    &entry,
                    &UpstreamCfg {
                        resource: resource.map(Box::from),
                        ..Default::default()
                    },
                    &busbar_kernel::plugin_config::upstream_anchor,
                )
                .unwrap();
                (name.into(), Arc::new(definition))
            })
            .collect(),
    )
}

#[test]
fn registration_capture_uses_actual_walk_members_and_optional_labels() {
    let definitions = definitions();
    let pool = SeatPool::of("seat", &definitions).unwrap();
    let targets = registration_targets("seat", &pool, &definitions, false).unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].pool, "seat");
    assert_eq!(targets[0].member, "seat\u{1f}one");
    assert_eq!(targets[0].resource.as_deref(), Some("shared"));
    assert_eq!(targets[1].member, "seat\u{1f}two");
    assert_eq!(targets[1].resource, None);
    assert!(!targets[0].attempt_accounting);
    assert!(registration_targets("other", &pool, &definitions, true).is_err());
    assert!(registration_targets(
        "seat",
        &pool,
        &ConfiguredUpstreams::from_definitions(BTreeMap::new()),
        true,
    )
    .is_err());
}

#[test]
fn captured_targets_compile_with_the_late_cost_generation_and_actual_capability() {
    let groups: BTreeMap<String, GroupCfg> = busbar_contract::yaml::from_str(
        "g:\n  limits:\n    - {id: tpm, upstream_resource: seat/shared, tokens: 3, per: minute, per_key: true, enforcement: process}",
    )
    .unwrap();
    let definitions = definitions();
    let pool = SeatPool::of("seat", &definitions).unwrap();
    let cost = Arc::new(CostModel::resolve_parts(None, 0, &groups));
    let captured = |attempt_accounting| CapturedSelectedPolicy {
        groups: groups.clone(),
        targets: registration_targets("seat", &pool, &definitions, attempt_accounting).unwrap(),
    };
    assert!(captured(false).compile(cost.clone(), None).is_err());
    let policy = captured(true)
        .compile(cost.clone(), None)
        .unwrap()
        .activate(None, 1, 10)
        .unwrap();
    assert!(Arc::ptr_eq(policy.cost_generation(), &cost));
    let wrong_cost = Arc::new(CostModel::resolve_parts(None, 0, &BTreeMap::new()));
    assert!(captured(true).compile(wrong_cost, Some(&policy)).is_err());
}
