use serde_json::json;

use super::providers::{merge_tables, ProviderTable, CORE_PROVIDER_KEYS};
use super::{ProviderDef, ProviderDeploy, ResolvedProvider};

fn table(value: serde_json::Value) -> ProviderTable {
    match value {
        serde_json::Value::Object(map) => map,
        other => panic!("a table is an object, not {other}"),
    }
}

#[test]
fn the_resolved_provider_carries_the_plane_keys_as_one_table_merged_by_the_neutral_rule() {
    let def: ProviderDef = serde_yaml::from_str(
        "protocol: proto-a\nbase_url: https://api.example.com\n\
         error_map: {a: x, b: y}\n\
         model_capabilities: [{models: [m1*], native_structured_output: true}]\n",
    )
    .expect("a catalog entry");
    let dep: ProviderDeploy = serde_yaml::from_str(
        "api_key: {env: K}\nerror_map: {b: z, c: w}\n\
         model_capabilities: [{models: [m2*]}]\npath: /v1/x\n",
    )
    .expect("a deployment");

    let p = ResolvedProvider::merge(&def, &dep);
    assert_eq!(
        serde_json::Value::Object(p.table.clone()),
        json!({
            "protocol": "proto-a",
            "error_map": {"a": "x", "b": "z", "c": "w"},
            "model_capabilities": [{"models": ["m2*"]}],
        })
    );

    assert_eq!(p.base_url, "https://api.example.com");
    assert_eq!(p.path.as_deref(), Some("/v1/x"));
    assert_eq!(p.api_key.env_var(), Some("K"));
    for key in CORE_PROVIDER_KEYS {
        assert!(
            !p.table.contains_key(*key),
            "`{key}` is the kernel's, never in the table"
        );
    }
}

#[test]
fn the_neutral_merge_rule_is_stated_by_shape_alone() {
    let merged = merge_tables(
        table(json!({
            "k1": {"a": "1", "b": "2"},
            "k2": {"a": {"deep": "1"}},
            "k3": [1, 2],
            "k4": "catalog",
            "k5": true,
        })),
        table(json!({
            "k1": {"b": "3", "c": "4"},
            "k2": {"b": {"deep": "2"}},
            "k3": [3],
            "k4": "deployment",
            "k6": 7,
        })),
    );
    assert_eq!(
        serde_json::Value::Object(merged),
        json!({
            "k1": {"a": "1", "b": "3", "c": "4"},
            "k2": {"b": {"deep": "2"}},
            "k3": [3],
            "k4": "deployment",
            "k5": true,
            "k6": 7,
        })
    );
}

#[test]
fn an_unset_or_empty_deployment_leaves_the_catalog_table() {
    let catalog = table(json!({"protocol": "proto-a", "error_map": {"429": "rate_limit"}}));
    assert_eq!(merge_tables(catalog.clone(), ProviderTable::new()), catalog);
    assert_eq!(
        merge_tables(catalog.clone(), table(json!({"error_map": {}}))),
        catalog
    );
}
