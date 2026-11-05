// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn parsed_pools(text: &str) -> PoolsCfg {
    let document: serde_yaml::Value = serde_yaml::from_str(text).unwrap();
    let section = busbar_contract::section::split_section::<_, super::super::PoolCfg>(
        document["pools"].clone(),
        "pools",
        "pool",
        |_, _| Ok(()),
    )
    .unwrap();
    PoolsCfg {
        all_pool_hooks: section.hooks,
        all_pool_upstream_credentials: section.upstream_credentials,
        pools: section.entries.into_iter().collect(),
    }
}

#[test]
fn authored_routing_preserves_sequence_forms_order_and_hidden_markers() {
    let text = r#"
pools:
  hooks: [shared-gate]
  'west/~':
    members:
      - alpha
      - model: beta
        weight: 7
        tags: [PRIVATE_TAG_CANARY]
    hooks: [local-gate, {strategy: fastest}, shared-gate]
"#;
    let parsed = parsed_pools(text);
    let raw = serde_json::to_value(capture(text, &parsed).unwrap()).unwrap();
    assert_eq!(raw["state"], "available");
    let pool = &raw["definitions"]["west/~"];
    assert_eq!(pool["path"], "/pools/west~1~0");
    assert_eq!(pool["members"]["entries"][0]["form"], "bare");
    assert_eq!(pool["members"]["entries"][0]["model"], "alpha");
    assert_eq!(pool["members"]["entries"][1]["form"], "object");
    assert_eq!(
        pool["members"]["entries"][1]["path"],
        "/pools/west~1~0/members/1"
    );
    assert_eq!(pool["members"]["entries"][1]["values"]["weight"], 7);
    assert_eq!(
        pool["members"]["entries"][1]["tags"],
        json!({"state":"hidden","count":1})
    );
    assert!(!raw.to_string().contains("PRIVATE_TAG_CANARY"));
    assert_eq!(pool["hooks"]["entries"][0]["entry"], "local-gate");
    assert_eq!(
        pool["hooks"]["entries"][1]["entry"],
        json!({"strategy":"fastest"})
    );
    assert_eq!(pool["hooks"]["entries"][2]["entry"], "shared-gate");
    // This is the actual resolution transformation whose result must never be used as source.
    assert_eq!(
        super::super::entity_only_hook_refs(&parsed.all_pool_hooks, &parsed.pools["west/~"].gates),
        vec!["local-gate"]
    );
    assert_eq!(parsed.pools["west/~"].policy.native_name(), Some("fastest"));
}

#[test]
fn authored_routing_distinguishes_absent_null_and_empty_lists() {
    let text = "pools:\n  absent: {}\n  nulls: {members: null, hooks: null}\n  empty: {members: [], hooks: []}\n  null_pool: null\n";
    let raw = serde_json::to_value(capture(text, &parsed_pools(text)).unwrap()).unwrap();
    for (pool, state) in [("absent", "absent"), ("nulls", "null"), ("empty", "list")] {
        assert_eq!(raw["definitions"][pool]["members"]["state"], state);
        assert_eq!(raw["definitions"][pool]["hooks"]["state"], state);
    }
    assert_eq!(raw["definitions"]["null_pool"]["state"], "null");
    let absent =
        serde_json::to_value(capture("providers: {}\nmodels: {}\n", &PoolsCfg::default()).unwrap())
            .unwrap();
    assert_eq!(absent["section_state"], "absent");
}

#[test]
fn authored_routing_ignores_unrelated_values_without_changing_boot_acceptance() {
    let text = "providers: {}\nmodels: {}\npublic_url: 184467440737095516160000000000000000000000000000000001\nsecrets:\n  vault:\n    settings:\n      token: PRIVATE_UNRELATED_CANARY\n";
    let deploy =
        super::super::deploy_from_yaml_str(text).expect("normal boot parser remains authoritative");
    let view = serde_json::to_value(deploy.authored_routing.as_ref().unwrap()).unwrap();
    assert_eq!(view["section_state"], "absent");
    assert!(!view.to_string().contains("PRIVATE_UNRELATED_CANARY"));
    assert!(!view.to_string().contains("18446744073709551616"));
    // Projection failures stay optional; callers never turn them into boot errors.
    assert!(capture("pools: [not-a-map]", &PoolsCfg::default()).is_none());
    let generic =
        super::super::deploy_from_deserializer(serde_json::json!({"providers":{},"models":{}}))
            .unwrap();
    assert!(
        generic.authored_routing.is_none(),
        "no source, no invented provenance"
    );
}
