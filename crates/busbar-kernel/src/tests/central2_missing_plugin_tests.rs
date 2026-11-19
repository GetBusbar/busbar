// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn unknown_store_name_is_a_clear_boot_error() {
    let available =
        crate::tests::dropped("acme-store-x", "x", busbar_contract::kinds::codes::STORE);
    let store_ref = "dynamo";
    let err = super::missing_plugin_error(
        "plugins",
        super::PluginRef {
            kind: "store",
            names: format!("store.module: '{store_ref}'"),
            matched: format!("store.module: '{store_ref}' matches"),
            missing: format!("no plugin matching store.module: '{store_ref}'"),
            must_be: "a store plugin",
            label: "",
            remedy: "install a signed plugin of kind store and select it with store.module set to its name",
        },
        &[available],
    );
    assert!(err.contains("'dynamo'"), "names the missing store: {err}");
    assert!(
        err.contains("acme-store-x"),
        "lists what is available: {err}"
    );
}

/// BUSBAR-6009 guidance must be true for a drop-in deployment: the published binary links no memory
/// store, so no store refusal may tell the operator to select one.
#[test]
fn store_guidance_does_not_claim_a_linked_memory_store() {
    let disabled = super::store_needs_plugins_error("dynamo", "plugins");
    assert!(!disabled.contains("memory"), "{disabled}");
    assert!(
        !super::STORE_REMEDY.contains("memory"),
        "{}",
        super::STORE_REMEDY
    );
}
