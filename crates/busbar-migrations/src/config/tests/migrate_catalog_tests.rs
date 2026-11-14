// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{catalog_keys, migrate_catalog};
use busbar_contract::yaml::{self, prelude::*};

#[test]
fn the_catalog_grammars_keys_are_read_off_the_grammar() {
    let keys = catalog_keys();
    for k in ["protocol", "base_url", "error_map", "health", "token_url"] {
        assert!(keys.contains(&k), "{k} in {keys:?}");
    }
    assert!(!keys.contains(&"colour"));
}

#[test]
fn a_stray_catalog_key_is_removed_and_reported_and_the_rest_stays() {
    let raw = "\
mock:
  protocol: anthropic
  base_url: https://mock.example
  colour: blue
  error_map: { \"400\": client_error }
other:
  protocol: openai
  base_url: https://other.example
";
    let m = migrate_catalog(raw, "providers.yaml")
        .expect("reads")
        .expect("a stray key to remove");
    let doc: Value = yaml::from_str(&m.yaml).expect("YAML");
    assert!(doc.at("mock").at("colour").is_null(), "{}", m.yaml);
    assert_eq!(
        doc.at("mock").at("base_url"),
        &Value::from("https://mock.example")
    );
    assert_eq!(
        doc.at("mock").at("error_map").at("400"),
        &Value::from("client_error")
    );
    assert_eq!(doc.at("other").at("protocol"), &Value::from("openai"));
    assert_eq!(
        m.changes,
        vec![
            "providers.yaml: mock.colour: removed (1.5.5 ignored this catalog key; \
             removing it preserves the legacy behavior)"
                .to_string()
        ]
    );

    assert!(migrate_catalog(&m.yaml, "providers.yaml")
        .expect("reads")
        .is_none());
}
