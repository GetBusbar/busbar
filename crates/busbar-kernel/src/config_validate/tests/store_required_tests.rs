// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config;

const NO_STORE: &str = "listen: \"127.0.0.1:8080\"\nproviders:\n  acme:\n    api_key: { env: ACME_KEY }\nmodels:\n  m:\n    provider: acme\n";

#[test]
fn a_config_without_a_store_block_is_refused() {
    // Store presence is host metadata validation; no executable store is required.
    let deploy: config::DeployCfg = serde_yaml::from_str(
        "providers: {}\nmodels: {}\nstore: {module: inert-store-metadata}\nauth: {chain: [], admin_auth: []}\n",
    )
    .expect("host-only fixture parses");
    let mut cfg = config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("host-only fixture resolves");
    assert!(
        validate(&cfg).is_ok(),
        "the fixture validates with its store"
    );
    cfg.store = None;
    let errs = validate(&cfg).expect_err("a config with no store: block must be refused");
    assert_eq!(
        errs,
        vec![config::store_required()],
        "the absent store is the one refusal"
    );
    let line = config::store_required();
    for part in [
        "store is required",
        "`store: {module: memory}`",
        "busbar --migrate-config <config.yaml>",
    ] {
        assert!(line.contains(part), "the refusal names `{part}`: {line}");
    }
}

#[test]
fn migrate_inserts_the_memory_store_into_a_config_without_one() {
    let out = config::migrate::migrate_config(NO_STORE).expect("the no-store document migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("the output is YAML");
    let store = doc.get("store").expect("the migrated config names a store");
    let want: serde_yaml::Value = serde_yaml::from_str("module: memory").expect("yaml");
    assert_eq!(store, &want, "exactly `store: {{module: memory}}`");
    assert!(
        out.changes
            .iter()
            .any(|c| c.starts_with("store: inserted `store: {module: memory}`")),
        "the change is recorded: {:?}",
        out.changes
    );
    assert!(
        out.todos.is_empty() && out.warnings.is_empty(),
        "nothing to decide"
    );
    assert!(
        !out.yaml.starts_with('#'),
        "no banner on a migration with nothing to decide"
    );

    let again = config::migrate::migrate_config(&out.yaml).expect("the output migrates");
    assert_eq!(again.yaml, out.yaml, "a migrated config migrates to itself");
    assert!(
        !again.changes.iter().any(|c| c.starts_with("store")),
        "a config that names its store gains nothing: {:?}",
        again.changes
    );

    let deploy: config::DeployCfg = serde_yaml::from_str(&out.yaml).expect("the output parses");
    assert_eq!(
        deploy.store.map(|s| s.module),
        Some(config::migrated_store_module().to_string())
    );
}

#[test]
fn migrate_names_the_module_of_a_store_block_without_one_and_leaves_a_named_one() {
    let unnamed = format!("{NO_STORE}store:\n  settings: {{ k: v }}\n");
    let out = config::migrate::migrate_config(&unnamed).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("yaml");
    let want: serde_yaml::Value =
        serde_yaml::from_str("settings: { k: v }\nmodule: memory").expect("yaml");
    assert_eq!(doc.get("store"), Some(&want));

    let named = format!("{NO_STORE}store:\n  module: acme-durable\n");
    let out = config::migrate::migrate_config(&named).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("yaml");
    let want: serde_yaml::Value = serde_yaml::from_str("module: acme-durable").expect("yaml");
    assert_eq!(doc.get("store"), Some(&want));
    assert!(!out.changes.iter().any(|c| c.starts_with("store")));
}

#[test]
fn the_store_double_answers_to_the_migrated_store_module() {
    assert_eq!(
        crate::config::migrated_store_module(),
        crate::config::migration_table::text("store_1_5_default")
    );
    assert!(!crate::config::migrated_store_module().is_empty());
    let refusal = crate::config::store_required();
    assert!(
        refusal.contains(&format!(
            "store: {{module: {}}}",
            crate::config::migrated_store_module()
        )),
        "{refusal}"
    );
}
