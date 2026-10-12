// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Q-STORE = (B) (owner ruling 2026-09-27, BUSBAR-1.6.0.md Appendix B; THE DESIGN §4): 1.6.0
//! REQUIRES an explicit `store:` block, even for memory. A config without one is refused at
//! validation (boot and `--validate` alike), and `busbar --migrate-config` inserts
//! `store: {module: memory}` — the store a 1.5.x config without one ran on.

use super::*;
use crate::config;

/// A 1.5.5-shaped document with no `store:` block (the no-store fixture's shape).
const NO_STORE: &str = "listen: \"127.0.0.1:8080\"\nproviders:\n  acme:\n    api_key: { env: ACME_KEY }\nmodels:\n  m:\n    provider: acme\n";

/// RED (Q-STORE = (B)): a config with no `store:` block is REFUSED, with the one refusal line that
/// names the fix — the store to write and the migration that writes it.
///
/// Without the refusal arm in `validate` the config validates and the first assertion fails.
#[test]
fn a_config_without_a_store_block_is_refused() {
    let mut cfg =
        crate::test_support::cfg_with_provider_api_key(config::SecretRef::env("ACME_KEY"));
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

/// RED (Q-STORE = (B)): the migration inserts `store: {module: memory}` into a config that has
/// none, records the change, and is idempotent: the migrated document migrates to itself.
///
/// Without `migrate_store_required` the migrated document has no `store:` and the first assertion
/// fails.
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
        Some(config::MIGRATED_STORE_MODULE.to_string())
    );
}

/// A `store:` block that names no module read as the memory store in 1.5.5 (serde's default); the
/// migration names it and keeps the operator's settings. A block that names its module is left
/// exactly as written.
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
