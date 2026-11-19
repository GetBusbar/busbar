// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::auth_calls::codes::{
    STYLE_ENDPOINT_FROM_CREDENTIAL, STYLE_ENDPOINT_TOKEN_URL,
};
use busbar_contract::auth_calls::DeclaredStyle;
use busbar_kernel::config::ProviderAuth;
use busbar_kernel::preflight::{declared_styles, install_declared_styles, style_flags};

#[test]
fn boot_style_data_preserves_config_words_order_flags_and_the_first_inventory() {
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
        let parsed: ProviderAuth =
            busbar_contract::json::from_value(&busbar_contract::json::json!(style.name)).unwrap();
        assert_eq!(parsed.as_str(), style.name);
        assert_eq!(style_flags(&style.name), style.flags);
    }
    // Since d3dc7a93fd a provider `auth` word may name a style or an explicit auth instance; the
    // native binding pass resolves it, so the word parses and an undeclared style has no flags.
    let unknown = busbar_contract::json::from_value::<ProviderAuth>(&busbar_contract::json::json!(
        "unloaded-style"
    ))
    .expect("an undeclared word parses; binding resolves its owner");
    assert_eq!(unknown.as_str(), "unloaded-style");
    assert_eq!(style_flags("unloaded-style"), 0);

    let mut copy = declared_styles();
    copy[0].name = "changed".into();
    install_declared_styles(copy);
    assert_eq!(declared_styles(), styles);
    assert_eq!(
        style_flags("changed"),
        0,
        "a second install changes no inventory"
    );
}
