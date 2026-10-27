// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plugin's declared setting renames, on both paths: the load moves the old key to the new one
//! and says so once; the migrator writes the same move into the document; a block that sets both
//! names is refused on either path.

use super::*;

/// A table where the export plugin `sink` renamed `signing-secret` to `signing_secret` in 1.6.0,
/// and the store plugin `kv` renamed `addr` to `url` in 1.6.1.
struct Table;

impl SettingRenames for Table {
    fn renames(&self, kind: Kind, module: &str) -> Vec<SettingRename> {
        let r = |from: &str, to: &str, since: &str| SettingRename {
            from: from.into(),
            to: to.into(),
            since: since.into(),
        };
        match (kind, module) {
            (Kind::Export, "sink") => vec![r("signing-secret", "signing_secret", "1.6.0")],
            (Kind::Store, "kv") => vec![r("addr", "url", "1.6.1")],
            _ => Vec::new(),
        }
    }
}

fn deploy(sections: &str) -> crate::config::DeployCfg {
    crate::config::deploy_from_yaml_str(&format!("providers: {{}}\nmodels: {{}}\n{sections}"))
        .expect("the document parses")
}

#[test]
fn the_load_moves_a_renamed_key_and_names_it_once() {
    let mut d = deploy(
        "export:\n  audit:\n    module: sink\n    settings:\n      signing-secret: s\n      url: u\n  \
         other:\n    module: elsewhere\n    settings:\n      signing-secret: kept\n\
         store:\n  module: kv\n  settings:\n    addr: a\n",
    );
    let made = apply_with(&mut d, &Table).expect("renames apply");
    let audit = &d.export["audit"].settings;
    assert_eq!(audit.get("signing_secret"), Some(&serde_json::json!("s")));
    assert!(!audit.contains_key("signing-secret"));
    assert_eq!(audit.get("url"), Some(&serde_json::json!("u")));
    assert_eq!(
        d.export["other"].settings.get("signing-secret"),
        Some(&serde_json::json!("kept")),
        "another plugin's key of the same name is its own"
    );
    let store = &d.store.as_ref().expect("a store").settings;
    assert_eq!(store.get("url"), Some(&serde_json::json!("a")));
    let lines: Vec<String> = made.iter().map(Renamed::deprecation).collect();
    assert_eq!(
        lines,
        [
            "export.audit.settings.signing-secret is deprecated: the plugin renamed it \
             `signing_secret` in 1.6.0. The old name keeps working until the next major version; \
             `busbar --migrate-config` rewrites it.",
            "store.settings.addr is deprecated: the plugin renamed it `url` in 1.6.1. The old name \
             keeps working until the next major version; `busbar --migrate-config` rewrites it.",
        ]
    );
    // Already in the new spelling: nothing moves and nothing is said.
    assert!(apply_with(&mut d, &Table)
        .expect("renames apply")
        .is_empty());
}

#[test]
fn a_block_setting_both_names_is_refused_on_load_and_in_the_migrator() {
    let both =
        "export:\n  audit:\n    module: sink\n    settings:\n      signing-secret: a\n      \
                signing_secret: b\n";
    let mut d = deploy(both);
    let want = "export.audit.settings: `signing-secret` was renamed `signing_secret` in 1.6.0; \
                set `signing_secret` alone, not both";
    assert_eq!(apply_with(&mut d, &Table), Err(want.to_string()));
    let serde_yaml::Value::Mapping(mut root) =
        serde_yaml::from_str(&format!("providers: {{}}\n{both}")).expect("yaml")
    else {
        panic!("a mapping");
    };
    assert_eq!(migrate_with(&mut root, &Table), Err(want.to_string()));
}

#[test]
fn the_migrator_writes_the_same_move_into_the_document() {
    let serde_yaml::Value::Mapping(mut root) = serde_yaml::from_str(
        "export:\n  audit:\n    module: sink\n    settings:\n      signing-secret: s\n\
         store:\n  module: kv\n  settings:\n    addr: a\n",
    )
    .expect("yaml") else {
        panic!("a mapping");
    };
    let made = migrate_with(&mut root, &Table).expect("renames apply");
    let changes: Vec<String> = made.iter().map(Renamed::change).collect();
    assert_eq!(
        changes,
        [
            "export.audit.settings: `signing-secret` -> `signing_secret` (renamed by the plugin in \
             1.6.0)",
            "store.settings: `addr` -> `url` (renamed by the plugin in 1.6.1)",
        ]
    );
    let out = serde_yaml::to_string(&serde_yaml::Value::Mapping(root)).expect("yaml");
    assert!(out.contains("signing_secret: s"), "{out}");
    assert!(out.contains("url: a"), "{out}");
    assert!(!out.contains("signing-secret"), "{out}");
}
