//! THE RESOLVED PROVIDER (row 155 B1b; ARCHITECT ruling, option (b)): a catalog definition merged
//! with its deployment carries the keys the kernel owns typed and every other key of the entry as
//! ONE opaque table, merged by the neutral rule (a string map merges member by member, the
//! deployment's member winning; every other value the deployment sets replaces the catalog's).
//! BUSBAR-1.6.0.md #49 (the kernel names no plane string), THE DESIGN §4 ("its dialect fields go to
//! the planes that use the provider").

use std::collections::HashMap;

use serde_json::json;

use super::providers::{merge_tables, ProviderTable, CORE_PROVIDER_KEYS};
use super::{resolve, ProviderDef, ProviderDeploy};

fn table(value: serde_json::Value) -> ProviderTable {
    match value {
        serde_json::Value::Object(map) => map,
        other => panic!("a table is an object, not {other}"),
    }
}

/// RED (base: the resolved provider typed every plane key, so there was no table to read): the
/// plane keys of a catalog entry and its deployment arrive as one table, merged by the neutral
/// rule, and no kernel-owned key is in it.
#[test]
fn the_resolved_provider_carries_the_plane_keys_as_one_table_merged_by_the_neutral_rule() {
    let def: ProviderDef = serde_yaml::from_str(
        "protocol: proto-a\nbase_url: https://api.example.com\n\
         error_map: {a: x, b: y}\norganization: org-1\n\
         model_capabilities: [{models: [m1*], native_structured_output: true}]\n",
    )
    .expect("a catalog entry");
    let dep: ProviderDeploy = serde_yaml::from_str(
        "api_key: {env: K}\nerror_map: {b: z, c: w}\nproject: proj-1\n\
         model_capabilities: [{models: [m2*]}]\npath: /v1/x\n",
    )
    .expect("a deployment");
    let mut deploy = super::tests::base_deploy();
    deploy.providers.insert("p".to_string(), dep);
    let cfg = resolve(&deploy, &HashMap::from([("p".to_string(), def)])).expect("it resolves");
    let p = &cfg.providers["p"];
    assert_eq!(
        serde_json::Value::Object(p.table.clone()),
        json!({
            "protocol": "proto-a",
            "error_map": {"a": "x", "b": "z", "c": "w"},
            "organization": "org-1",
            "project": "proj-1",
            "model_capabilities": [{"models": ["m2*"]}],
        })
    );
    // The kernel-owned keys stay typed, merged as 1.5.5 merged them.
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

/// The neutral rule names no key: a string map merges member by member, the deployment's member
/// winning; a map that is not a string map, a list and a scalar are replaced whole; a key only one
/// side sets is kept.
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

/// A deployment that sets none of the plane keys leaves the catalog's table as written; one that
/// sets an empty string map leaves the catalog's map whole (1.5.5: the deployment's entries were
/// added to the catalog's, and none is none).
#[test]
fn an_unset_or_empty_deployment_leaves_the_catalog_table() {
    let catalog = table(json!({"protocol": "proto-a", "error_map": {"429": "rate_limit"}}));
    assert_eq!(merge_tables(catalog.clone(), ProviderTable::new()), catalog);
    assert_eq!(
        merge_tables(catalog.clone(), table(json!({"error_map": {}}))),
        catalog
    );
}
