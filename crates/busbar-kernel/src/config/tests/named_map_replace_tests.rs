// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The overlay's named-map entries REPLACE the entry of the same name WHOLE, as 1.5.5 applied them
//! (v1.5.5 crates/busbar/src/config/overlay.rs:887-904; parity, Q128 arch u29): the stored
//! definition is the entry. These are the parity cells for the base/overlay same-name case.

use crate::config::overlay::{apply_named_maps_to_deploy, OverlayDoc};
use crate::config::DeployCfg;
use std::collections::BTreeMap;

fn deploy_with_a_base_provider() -> DeployCfg {
    serde_yaml::from_str(
        r#"
providers: {}
models: {}
pools: {}
identity-providers:
  corp:
    module: test-idp-double
    max_admin_scope: read-only
    settings:
      issuer: "https://idp.example.com"
      client_id: "abc"
"#,
    )
    .expect("base config parses")
}

fn overlay_with(section: &str, name: &str, def: serde_json::Value) -> OverlayDoc {
    OverlayDoc {
        named_maps: BTreeMap::from([(
            section.to_string(),
            BTreeMap::from([(name.to_string(), def)]),
        )]),
        ..OverlayDoc::default()
    }
}

/// RED (Q128 arch u29): an overlay entry for a name base config also defines REPLACES the base
/// entry whole, so a field the overlay entry does not name never leaks in from the base. RED before:
/// the entry was merged onto the base, so the base's `settings.client_id` survived beside the
/// overlay's own settings.
#[test]
fn an_overlay_entry_replaces_the_same_named_base_entry_whole() {
    crate::test_support::register_neutral_test_plane();
    let mut deploy = deploy_with_a_base_provider();
    let doc = overlay_with(
        "identity-providers",
        "corp",
        serde_json::json!({
            "module": "test-idp-double",
            "max_admin_scope": "full",
            "settings": { "issuer": "https://other.example.com" }
        }),
    );
    apply_named_maps_to_deploy(&mut deploy, &doc);

    let corp = deploy.identity_providers.get("corp").expect("present");
    assert_eq!(corp.max_admin_scope.as_deref(), Some("full"));
    assert_eq!(
        corp.settings.get("issuer").and_then(|v| v.as_str()),
        Some("https://other.example.com")
    );
    assert!(
        corp.settings.get("client_id").is_none(),
        "a base field the overlay entry does not name must not leak in: {:?}",
        corp.settings
    );
}

/// RED (Q128 arch u29): an explicit `null` inside an overlay definition's opaque bag reaches the
/// entry as the operator PUT it, every time the overlay is applied. RED before: the merge read the
/// `null` as "remove this key", so it was dropped on every restart and rebuild.
#[test]
fn an_explicit_null_in_an_overlay_definition_is_delivered() {
    crate::test_support::register_neutral_test_plane();
    let mut deploy = deploy_with_a_base_provider();
    let doc = overlay_with(
        "identity-providers",
        "runtime-added",
        serde_json::json!({
            "module": "test-idp-double",
            "settings": { "issuer": "https://other.example.com", "audience": null }
        }),
    );
    apply_named_maps_to_deploy(&mut deploy, &doc);
    apply_named_maps_to_deploy(&mut deploy, &doc);

    let added = deploy
        .identity_providers
        .get("runtime-added")
        .expect("the runtime entry landed");
    assert_eq!(
        added.settings.get("audience"),
        Some(&serde_json::Value::Null),
        "the explicit null is part of the definition: {:?}",
        added.settings
    );
}

/// A definition this binary cannot parse is dropped whole, and the base entry of the same name is
/// left exactly as `config.yaml` wrote it (1.5.5's behaviour for an unparseable stored definition).
#[test]
fn an_unparseable_overlay_definition_leaves_the_base_entry() {
    crate::test_support::register_neutral_test_plane();
    let mut deploy = deploy_with_a_base_provider();
    let doc = overlay_with(
        "identity-providers",
        "corp",
        serde_json::json!({ "module": "test-idp-double", "max_admin_scop": "full" }),
    );
    apply_named_maps_to_deploy(&mut deploy, &doc);

    let corp = deploy.identity_providers.get("corp").expect("present");
    assert_eq!(corp.max_admin_scope.as_deref(), Some("read-only"));
    assert_eq!(
        corp.settings.get("client_id").and_then(|v| v.as_str()),
        Some("abc")
    );
}

/// Applying the overlay twice equals applying it once: it is replayed on every boot and rebuild.
#[test]
fn replaying_the_overlay_is_idempotent() {
    crate::test_support::register_neutral_test_plane();
    let doc = overlay_with(
        "identity-providers",
        "corp",
        serde_json::json!({ "module": "test-idp-double", "settings": { "client_id": "rotated" } }),
    );
    let mut once = deploy_with_a_base_provider();
    apply_named_maps_to_deploy(&mut once, &doc);
    let mut twice = deploy_with_a_base_provider();
    apply_named_maps_to_deploy(&mut twice, &doc);
    apply_named_maps_to_deploy(&mut twice, &doc);
    assert_eq!(
        once.identity_providers.get("corp"),
        twice.identity_providers.get("corp")
    );
}
