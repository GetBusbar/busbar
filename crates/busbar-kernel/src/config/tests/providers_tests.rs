// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::provider_auth_from_declared_word;

#[test]
fn test_provider_auth_style_is_a_declared_word() {
    let declared: Vec<_> = [
        "bearer",
        "api-key",
        "jwt-bearer",
        "oauth-client-credentials",
        "x-double-mint",
    ]
    .into_iter()
    .map(|name| busbar_contract::auth_calls::DeclaredStyle {
        name: name.to_string(),
        flags: 0,
    })
    .collect();
    for word in [
        "bearer",
        "api-key",
        "jwt-bearer",
        "oauth-client-credentials",
        "x-double-mint",
    ] {
        let style = provider_auth_from_declared_word(
            serde_yaml::from_str::<String>(word).expect("style is a YAML string"),
            &declared,
        )
        .unwrap_or_else(|e| panic!("declared style '{word}' must parse: {e}"));
        assert_eq!(style.as_str(), word);
    }
    let refused = provider_auth_from_declared_word(
        serde_yaml::from_str::<String>("oauth2").expect("style is a YAML string"),
        &declared,
    )
    .expect_err("'oauth2' is declared by no plugin and must fail to deserialize")
    .to_string();
    assert!(
        refused.starts_with(
            "unknown variant `oauth2`, expected one of `bearer`, `api-key`, `jwt-bearer`, \
         `oauth-client-credentials`, `x-double-mint`"
        ),
        "an undeclared style is refused in serde's words over the declared list: {refused}"
    );
}
