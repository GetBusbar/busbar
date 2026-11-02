// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn unknown_store_name_is_a_clear_boot_error() {
    // Actual available metadata and operator input passed to the production error policy.
    let available = crate::tests::dropped(
        "acme-store-x",
        "x",
        busbar_contract::abi::mechanism::kind::STORE,
    );
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
            remedy: "set store.module: memory",
        },
        &[available],
    );
    assert!(err.contains("'dynamo'"), "names the missing store: {err}");
    assert!(
        err.contains("acme-store-x"),
        "lists what is available: {err}"
    );
}
