// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Advanced settings that stopped being settings: the engine does the one right thing. An old
//! configuration that still carries one is converted, never refused: the configuration file (boot),
//! `PUT /config/settings` (a settings patch, and the overlay it persists) and the admin document edit
//! all accept the key, drop it, and never write it back.

use std::collections::HashMap;

use super::tests::base_deploy;
use super::*;

/// Every removed `advanced` key, with a value an old configuration carried.
const REMOVED: [(&str, &str); 2] = [("rate_sweep_interval", "64"), ("worker_threads", "3")];

/// The `advanced` block as a 1.5.5 configuration wrote it (1.5.5's own keys beside the removed one).
fn v1_5_5(key: &str, value: &str) -> String {
    format!(
        "providers: {{}}\nmodels: {{}}\nadvanced:\n  {key}: {value}\n  usage_flush_interval_ms: 100\n"
    )
}

/// The `advanced` block as a 1.6 development configuration wrote it (keys 1.5.5 never had).
fn v1_6_dev(key: &str, value: &str) -> String {
    format!(
        "providers: {{}}\nmodels: {{}}\nadvanced:\n  {key}: {value}\n  block_private_addresses: true\n  trusted_proxies: [10.0.0.0/8]\n"
    )
}

/// An admin document edit, read as the admin API reads a request body.
pub(super) fn document_edit(body: &str) -> crate::config::document_patch::DocumentPatch {
    crate::config::document_patch::DocumentPatch::deserialize_request(
        &mut busbar_contract::json::Deserializer::from_str(body),
    )
    .expect("a document edit")
}

fn boots(text: &str) -> DeployCfg {
    let parsed = deploy_from_yaml_str(text, &Grammar::empty())
        .unwrap_or_else(|e| panic!("an old configuration must load: {e:?}\n{text}"));
    let mut deploy = base_deploy();
    deploy.advanced = parsed.advanced;
    resolve(&deploy, &HashMap::new())
        .unwrap_or_else(|e| panic!("an old configuration must resolve: {e:?}\n{text}"));
    deploy
}

#[test]
fn a_configuration_file_carrying_a_removed_advanced_key_boots_and_drops_it() {
    for (key, value) in REMOVED {
        for text in [v1_5_5(key, value), v1_6_dev(key, value)] {
            let deploy = boots(&text);
            let written = busbar_contract::yaml::to_string(&deploy.advanced).expect("serializes");
            assert!(
                !written.contains(key),
                "{key} is dropped, never written back: {written}"
            );
        }
    }
}

#[test]
fn a_settings_put_carrying_a_removed_advanced_key_applies_and_drops_it() {
    for (key, value) in REMOVED {
        let body = format!("{{\"advanced\": {{\"{key}\": {value}}}}}");
        let settings: crate::config::overlay::RootSettings =
            busbar_contract::json::parse_str(&body).unwrap_or_else(|e| {
                panic!("PUT /config/settings with {key} must be accepted: {e}")
            });
        let mut deploy = base_deploy();
        settings.apply_to_deploy(&mut deploy);
        resolve(&deploy, &HashMap::new()).expect("the applied configuration resolves");
        let persisted = busbar_contract::json::to_string(&settings.advanced).expect("serializes");
        assert!(
            !persisted.contains(key),
            "{key} is not persisted into the overlay: {persisted}"
        );
        let merged = settings
            .advanced
            .clone()
            .expect("advanced patch")
            .merge(crate::config::patch::AdvancedPatch::default());
        let merged = busbar_contract::json::to_string(&merged).expect("serializes");
        assert!(!merged.contains(key), "{key} survives no merge: {merged}");
    }
}

#[test]
fn an_admin_document_edit_setting_a_removed_advanced_key_applies_and_drops_it() {
    for (key, value) in REMOVED {
        let edit = document_edit(&format!("{{\"set\": {{\"/advanced/{key}\": {value}}}}}"));
        for text in ["providers: {}\nmodels: {}\n".to_owned(), v1_5_5(key, value)] {
            let edited = edit
                .parse_deploy_yaml(&text)
                .unwrap_or_else(|e| panic!("the document edit setting {key} must apply: {e}"));
            let mut deploy = base_deploy();
            deploy.advanced = edited.advanced;
            resolve(&deploy, &HashMap::new()).expect("the edited configuration resolves");
            let written = busbar_contract::yaml::to_string(&deploy.advanced).expect("serializes");
            assert!(!written.contains(key), "{key} is dropped: {written}");
        }
    }
}

/// Each removed key an old configuration carries is named, so `config::resolve` says its one line.
#[test]
fn every_removed_key_carried_is_named_with_its_line() {
    for (key, value) in REMOVED {
        let deploy = boots(&v1_5_5(key, value));
        let named: Vec<&str> = deploy.advanced.removed().collect();
        assert_eq!(named, [key], "{key} is named once");
        let line = sections::removed_advanced_line(key).expect("a line for every removed key");
        assert!(line.starts_with(&format!("advanced.{key} ")), "{line}");
    }
}
