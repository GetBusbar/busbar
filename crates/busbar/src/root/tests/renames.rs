// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The root's table of plugin setting renames: a plugin's rename is found under every word it
//! answers to and its kind alone, and the kernel's load over the table moves an operator's old key
//! to the new one. (The Statement reading is the loader's, proven over a stub plugin there:
//! `setting_renames_tests`.)

use super::*;

fn table() -> Table {
    Table(vec![Row {
        name: "stub-renames".into(),
        kind: Kind::Secret,
        words: vec!["stub-alias".into(), "stub-renames".into()],
        renames: vec![SettingRename {
            from: "signing-secret".into(),
            to: "signing_secret".into(),
            since: "1.6.0".into(),
        }],
    }])
}

#[test]
fn a_plugins_rename_is_found_under_its_words_and_its_kind_alone() {
    let t = table();
    assert_eq!(t.renames(Kind::Secret, "stub-renames").len(), 1);
    assert_eq!(t.renames(Kind::Secret, "stub-alias").len(), 1);
    assert!(t.renames(Kind::Auth, "stub-renames").is_empty());
    assert!(t.renames(Kind::Secret, "elsewhere").is_empty());
}

#[test]
fn the_kernels_load_over_the_table_moves_the_operators_old_key() {
    let mut deploy = busbar_kernel::config::deploy_from_yaml_str(
        "providers: {}\nmodels: {}\nsecrets:\n  stub-renames:\n    settings:\n      \
         signing-secret: {env: TOKEN}\n",
    )
    .expect("the document parses");
    let made = busbar_kernel::config::plugin_renames::apply_with(&mut deploy, &table())
        .expect("the rename applies");
    assert_eq!(made.len(), 1);
    let settings = &deploy.secrets["stub-renames"].settings;
    assert!(settings.contains_key("signing_secret"), "{settings:?}");
    assert!(!settings.contains_key("signing-secret"), "{settings:?}");
}
