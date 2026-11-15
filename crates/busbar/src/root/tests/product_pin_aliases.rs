// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PINNED PLUGIN IS PACKED UNDER ITS REGISTERED ALIAS. CI packs every product row of
//! `scripts/ci-product-pins.json` with `pack --alias <row alias>`, and the signed manifest folds that
//! word into the plugin's `former_names` (ABI-MIN3-INTERFACE §7.1). The loader keeps one name space
//! for every kind: a word that two admitted plugins answer to is a `NameConflict` (§11.2, §16.90;
//! MIGRATE-ON-BOOT §2 "a word equal to another registered identity or word"). So a pin row whose
//! alias drifts from `plugins.yaml` ships a tarball that answers to a word the plugin never declared.
//! When that word belongs to another shipped plugin, the two refuse each other in one plugins dir:
//! busbar-export-file packed as `file` collided with busbar-secret-file's `file`.

use busbar_contract::yaml::ValueExt;
use std::collections::BTreeMap;

const PINS: &str = include_str!("../../../../../scripts/ci-product-pins.json");
const REGISTRY: &str = include_str!("../../../../../plugins.yaml");

/// `(repo, alias)` for each item of `list` under `key` in `text`.
fn aliases(text: &str, key: &str, what: &str) -> Vec<(String, String)> {
    let doc: busbar_contract::yaml::Value =
        busbar_contract::yaml::from_str(text).unwrap_or_else(|e| panic!("{what} parses: {e}"));
    let items = doc
        .at(key)
        .as_sequence()
        .unwrap_or_else(|| panic!("{what}: `{key}` is a list"));
    items
        .iter()
        .map(|p| {
            let field = |k: &str| {
                p.at(k)
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| panic!("{what}: every `{key}` item names its {k}"))
            };
            (field("repo"), field("alias"))
        })
        .collect()
}

#[test]
fn every_pinned_plugin_is_packed_under_its_registered_alias_and_no_word_is_claimed_twice() {
    let registered: BTreeMap<String, String> = aliases(REGISTRY, "plugins", "plugins.yaml")
        .into_iter()
        .collect();
    let pinned = aliases(PINS, "products", "scripts/ci-product-pins.json");
    assert!(!pinned.is_empty(), "ci-product-pins.json pins no product");
    let mut wrong = Vec::new();
    let mut owner: BTreeMap<&str, &str> = BTreeMap::new();
    for (repo, alias) in &pinned {
        match registered.get(repo) {
            None => wrong.push(format!("{repo}: pinned, but plugins.yaml has no entry for it")),
            Some(want) if want != alias => wrong.push(format!(
                "{repo}: pinned with alias `{alias}`, but plugins.yaml registers `{want}`; CI would \
                 pack it to answer to a word it never declared"
            )),
            Some(_) => {}
        }
        if let Some(first) = owner.insert(alias, repo) {
            wrong.push(format!(
                "`{alias}` is the pinned alias of both {first} and {repo}: the loader refuses the \
                 pair NameConflict in one plugins dir, whatever their kinds"
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
