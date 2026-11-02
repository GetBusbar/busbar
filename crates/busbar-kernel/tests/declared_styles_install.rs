// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Boot metadata is installed once in this process, so unrelated config tests cannot change it.

use busbar_contract::abi::auth::{STYLE_ENDPOINT_FROM_CREDENTIAL, STYLE_ENDPOINT_TOKEN_URL};
use busbar_contract::auth_calls::DeclaredStyle;
use busbar_kernel::config::ProviderAuth;
use busbar_kernel::preflight::{declared_styles, install_declared_styles, style_flags};

#[test]
fn boot_style_data_preserves_config_words_order_flags_and_the_first_inventory() {
    // Boot has already ordered the linked and dropped-in admitted declarations. The kernel
    // retains precisely these values; it neither opens a plugin nor retains a root callback.
    let styles = vec![
        DeclaredStyle {
            name: "linked-style".into(),
            flags: STYLE_ENDPOINT_TOKEN_URL,
        },
        DeclaredStyle {
            name: "dropped-style".into(),
            flags: STYLE_ENDPOINT_FROM_CREDENTIAL,
        },
    ];
    install_declared_styles(styles.clone());
    assert_eq!(declared_styles(), styles);
    for style in &styles {
        let parsed: ProviderAuth = serde_json::from_value(serde_json::json!(style.name)).unwrap();
        assert_eq!(parsed.as_str(), style.name);
        assert_eq!(style_flags(&style.name), style.flags);
    }
    let unknown =
        serde_json::from_value::<ProviderAuth>(serde_json::json!("unloaded-style")).unwrap_err();
    assert_eq!(
        unknown.to_string(),
        "unknown variant `unloaded-style`, expected `linked-style` or `dropped-style`"
    );
    assert_eq!(style_flags("unloaded-style"), 0);

    // Mutating a returned copy and attempting another install cannot change the inventory a
    // later configuration parse/reload reads. The process plugin registry is itself immutable.
    let mut copy = declared_styles();
    copy[0].name = "changed".into();
    install_declared_styles(copy);
    assert_eq!(declared_styles(), styles);
    assert!(serde_json::from_str::<ProviderAuth>("\"changed\"").is_err());
}
