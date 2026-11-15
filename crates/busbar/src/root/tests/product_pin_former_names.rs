// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DROPPED-IN PLUGIN ANSWERS TO ITS 1.5.5 MANIFEST NAME. `plugins.yaml` declares each first-party
//! plugin's `former_names` (the signed manifest names its earlier releases carried), and a 1.5.5
//! config naming `module: busbar-store-mysql-plugin` must still resolve to the 1.6.0 plugin
//! (MIGRATE-ON-BOOT §A9). The drop pack steps read `scripts/ci-product-pins.json` and pass each row's
//! `former_names` to `busbar-plugin-pack pack --former-name`; a row that omits or drifts from
//! `plugins.yaml` ships a tarball that refuses the name its 1.5.5 config uses.

use busbar_contract::yaml::ValueExt;
use std::collections::BTreeMap;

const PINS: &str = include_str!("../../../../../scripts/ci-product-pins.json");
const REGISTRY: &str = include_str!("../../../../../plugins.yaml");

/// `repo -> former_names` for each item of `key` in `text`; a missing field is no former name.
fn former_names(text: &str, key: &str, what: &str) -> BTreeMap<String, Vec<String>> {
    let doc: busbar_contract::yaml::Value =
        busbar_contract::yaml::from_str(text).unwrap_or_else(|e| panic!("{what} parses: {e}"));
    let items = doc
        .at(key)
        .as_sequence()
        .unwrap_or_else(|| panic!("{what}: `{key}` is a list"));
    items
        .iter()
        .map(|p| {
            let repo = p
                .at("repo")
                .as_str()
                .unwrap_or_else(|| panic!("{what}: every `{key}` item names its repo"))
                .to_string();
            let names = match p.at("former_names").as_sequence() {
                None => Vec::new(),
                Some(seq) => seq
                    .iter()
                    .map(|n| {
                        n.as_str()
                            .unwrap_or_else(|| panic!("{what}: {repo} former_names are strings"))
                            .to_string()
                    })
                    .collect(),
            };
            (repo, names)
        })
        .collect()
}

#[test]
fn every_pinned_plugin_carries_the_former_names_plugins_yaml_declares() {
    let registered = former_names(REGISTRY, "plugins", "plugins.yaml");
    let pinned = former_names(PINS, "products", "scripts/ci-product-pins.json");
    assert!(!pinned.is_empty(), "ci-product-pins.json pins no product");
    let mut wrong = Vec::new();
    for (repo, got) in &pinned {
        match registered.get(repo) {
            None => wrong.push(format!("{repo}: pinned, but plugins.yaml has no entry for it")),
            Some(want) if want != got => wrong.push(format!(
                "{repo}: pinned with former_names {got:?}, but plugins.yaml declares {want:?}; the \
                 dropped-in tarball would not answer to its 1.5.5 manifest name"
            )),
            Some(_) => {}
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
