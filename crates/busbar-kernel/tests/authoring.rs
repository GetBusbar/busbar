// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::*;
use serde_json::json;

#[test]
fn authoring_views_preserve_nested_settings_references_and_omitted_overlay_fields() {
    let reference = json!({"module":"source-owner","settings":{"slot":"descriptor-canary"}});
    let authored = json!({
        "tls":{"cert":reference,"key":{"module":"none","settings":{}},"client_ca":null},
        "store":{"module":"store-owner","settings":{"nested":{"password":reference},"opaque":[null,7,true]}},
        "per_request_fee":0
    });
    let root: overlay::RootSettings = serde_json::from_value(authored.clone()).unwrap();
    let seal = busbar_kernel::seal::acquire();
    assert_eq!(
        serde_json::to_value(root.authoring(&seal)).unwrap(),
        authored
    );
    assert_eq!(
        serde_json::to_value(overlay::RootSettings::default().authoring(&seal)).unwrap(),
        json!({})
    );
    assert!(!format!("{root:?}").contains("descriptor-canary"));
    let doc = overlay::OverlayDoc {
        version: overlay::OVERLAY_VERSION,
        root: Some(root),
        ..Default::default()
    };
    let expected = json!({"version":overlay::OVERLAY_VERSION,"hooks":{},"global_hooks":[],"deleted":[],"groups":{},"deleted_groups":[],"root":authored});
    let wire = serde_json::to_value(doc.authoring(&seal)).unwrap();
    assert_eq!(wire, expected);
    let roundtrip: overlay::OverlayDoc = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(roundtrip.authoring(&seal)).unwrap(),
        wire
    );
}

#[test]
fn auth_authoring_retains_null_options_and_exact_owner_document() {
    let expected = json!({
        "module":"auth-owner","max_admin_scope":null,"token":null,
        "browser_login":{"client_secret":{"module":"source-owner","settings":{"slot":"client-canary"}},"client_id":null},
        "settings":{"owner-specific":{"nested":[true,null,"opaque"]}}
    });
    let provider: IdentityProviderCfg = serde_json::from_value(expected.clone()).unwrap();
    let seal = busbar_kernel::seal::acquire();
    assert_eq!(
        serde_json::to_value(provider.authoring(&seal)).unwrap(),
        expected
    );
    assert!(!format!("{provider:?}").contains("client-canary"));
}
