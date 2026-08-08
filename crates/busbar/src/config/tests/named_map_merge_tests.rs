// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The overlay's named-map entries are PATCHES over base config, merged per field.
//!
//! Before this, an overlay entry was a whole document that replaced the base entry outright, so
//! recording one derived fact about an entry meant restating every operator-authored field beside
//! it, and a partial document did not survive its own typed parse at all: it was dropped at boot
//! with a log line. That is the limitation the 1.5.4 ruling calls out as a thing to FIX in the
//! overlay rather than route around by putting the state somewhere else.

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
    module: oidc
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

/// THE POINT OF THE CHANGE: an overlay entry naming ONE field patches that field of the base entry
/// and leaves every other field exactly as `config.yaml` wrote it.
///
/// Before, this document did not even survive its own parse (`module` is required), so it was
/// dropped at boot with a log line and the operator's API call had silently done nothing.
#[test]
fn an_overlay_patch_merges_onto_the_base_entry_it_names() {
    let mut deploy = deploy_with_a_base_provider();
    let doc = overlay_with(
        "identity-providers",
        "corp",
        serde_json::json!({ "max_admin_scope": "full" }),
    );
    apply_named_maps_to_deploy(&mut deploy, &doc);

    let corp = deploy
        .identity_providers
        .get("corp")
        .expect("the base entry is still there");
    assert_eq!(corp.max_admin_scope.as_deref(), Some("full"), "patched");
    assert_eq!(corp.module, "oidc", "an unnamed field keeps its base value");
    assert_eq!(
        corp.settings.get("issuer").and_then(|v| v.as_str()),
        Some("https://idp.example.com"),
        "and so does an unnamed field inside the opaque bag"
    );
}

/// A NESTED patch reaches one key of the opaque settings bag without restating its siblings. The bag
/// is the field most likely to hold something long and secret-bearing, so restating it to change one
/// key is exactly the rewrite this exists to avoid.
#[test]
fn a_nested_patch_reaches_one_key_of_the_settings_bag() {
    let mut deploy = deploy_with_a_base_provider();
    let doc = overlay_with(
        "identity-providers",
        "corp",
        serde_json::json!({ "settings": { "client_id": "rotated" } }),
    );
    apply_named_maps_to_deploy(&mut deploy, &doc);

    let corp = deploy.identity_providers.get("corp").expect("present");
    assert_eq!(
        corp.settings.get("client_id").and_then(|v| v.as_str()),
        Some("rotated")
    );
    assert_eq!(
        corp.settings.get("issuer").and_then(|v| v.as_str()),
        Some("https://idp.example.com"),
        "the sibling key is untouched"
    );
}

/// `null` UNSETS a field the base config set. Without it a patch overlay could only ever grow a
/// document, so a value written in the file could never be cleared at runtime.
#[test]
fn a_null_patch_unsets_a_field_the_base_config_set() {
    let mut deploy = deploy_with_a_base_provider();
    let doc = overlay_with(
        "identity-providers",
        "corp",
        serde_json::json!({ "max_admin_scope": null }),
    );
    apply_named_maps_to_deploy(&mut deploy, &doc);

    let corp = deploy.identity_providers.get("corp").expect("present");
    assert_eq!(
        corp.max_admin_scope, None,
        "the field is unset, which is the most restrictive default"
    );
    assert_eq!(corp.module, "oidc", "and nothing else moved");
}

/// BACK-COMPAT, and it is what makes this change safe to ship over existing overlays: for a name
/// with NO base entry, merging a whole document onto nothing is byte-identical to the replace that
/// used to happen. Every overlay on disk today is exactly this case, because the admin API refuses
/// to write an entry that shadows a base one.
#[test]
fn a_full_document_for_an_unshadowed_name_lands_exactly_as_it_used_to() {
    let mut deploy = deploy_with_a_base_provider();
    let doc = overlay_with(
        "identity-providers",
        "runtime-added",
        serde_json::json!({
            "module": "oidc",
            "max_admin_scope": "read-only",
            "settings": { "issuer": "https://other.example.com" }
        }),
    );
    apply_named_maps_to_deploy(&mut deploy, &doc);

    let added = deploy
        .identity_providers
        .get("runtime-added")
        .expect("the runtime entry landed");
    assert_eq!(added.module, "oidc");
    assert_eq!(added.max_admin_scope.as_deref(), Some("read-only"));
    assert!(deploy.identity_providers.contains_key("corp"), "base kept");
}

/// The MERGED document is what faces the typed `deny_unknown_fields` parse, so a patch carrying a
/// typo is still refused and the base entry is left exactly as it was. The grammar did not move: a
/// patch is judged by the same structs `config.yaml` is.
#[test]
fn a_patch_with_an_unknown_field_is_refused_and_the_base_entry_survives() {
    let mut deploy = deploy_with_a_base_provider();
    let doc = overlay_with(
        "identity-providers",
        "corp",
        serde_json::json!({ "max_admin_scop": "full" }),
    );
    apply_named_maps_to_deploy(&mut deploy, &doc);

    let corp = deploy.identity_providers.get("corp").expect("present");
    assert_eq!(
        corp.max_admin_scope.as_deref(),
        Some("read-only"),
        "the typo'd patch is dropped whole; it never half-applies"
    );
    assert_eq!(corp.module, "oidc");
}

/// A patch that would make the merged document INVALID by a value-level rule (not merely by serde)
/// is refused too, because the merged document goes through the one `parse_def` both the API and
/// the file are judged by. An unknown ceiling token is a hard boot error, so it must not reach boot
/// through the overlay either.
#[test]
fn a_patch_that_breaks_a_value_level_rule_is_refused() {
    let mut deploy = deploy_with_a_base_provider();
    let doc = overlay_with(
        "identity-providers",
        "corp",
        serde_json::json!({ "max_admin_scope": "superuser" }),
    );
    apply_named_maps_to_deploy(&mut deploy, &doc);

    let corp = deploy.identity_providers.get("corp").expect("present");
    assert_eq!(corp.max_admin_scope.as_deref(), Some("read-only"));
}

/// Applying the same patch twice equals applying it once. The overlay is replayed on every boot and
/// every rebuild, so anything else would make effective config depend on how many times busbar had
/// reloaded.
#[test]
fn replaying_a_patch_is_idempotent() {
    let doc = overlay_with(
        "identity-providers",
        "corp",
        serde_json::json!({ "settings": { "client_id": "rotated" } }),
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
