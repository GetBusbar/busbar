// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

fn probe() -> busbar_contract::secret_ref::Sugars {
    use busbar_contract::abi::mechanism::door::{REWRITE_SUGAR, REWRITE_SUGAR_NAMES};
    let mut sugars = busbar_contract::secret_ref::Sugars::default();
    sugars
        .declare(
            "busbar-secret-probe",
            &[
                (REWRITE_SUGAR, "probe".to_string(), "slot".to_string()),
                (
                    REWRITE_SUGAR_NAMES,
                    "probe".to_string(),
                    "the probe slot".to_string(),
                ),
            ],
        )
        .expect("the probe declares its shorthand");
    sugars
}

fn reference(module: &str, settings: serde_json::Value) -> crate::config::SecretRef {
    crate::config::SecretRef {
        module: module.to_string(),
        settings: settings.as_object().cloned().unwrap_or_default(),
    }
}

#[test]
fn a_declared_shorthand_routes_its_settings_key_and_words() {
    let sugars = probe();
    assert_eq!(
        super::declared_setting_refusal(
            &sugars,
            "x.key",
            &reference("probe", serde_json::json!({}))
        ),
        Some("x.key: secret module 'probe' requires settings.slot (the probe slot)".to_string())
    );
    assert_eq!(
        super::declared_setting_refusal(
            &sugars,
            "x.key",
            &reference("probe", serde_json::json!({ "slot": "  " }))
        ),
        Some(
            "x.key: secret module 'probe' requires a NON-EMPTY settings.slot (the probe slot)"
                .to_string()
        )
    );
    assert_eq!(
        super::declared_setting_refusal(
            &sugars,
            "x.key",
            &reference("probe", serde_json::json!({ "slot": "a" }))
        ),
        None
    );
}

#[test]
fn an_undeclared_module_is_left_to_the_registry() {
    let sugars = probe();
    assert_eq!(
        super::declared_setting_refusal(
            &sugars,
            "x.key",
            &reference("slot", serde_json::json!({}))
        ),
        None
    );
    assert_eq!(
        super::declared_setting_refusal(
            &busbar_contract::secret_ref::Sugars::default(),
            "x.key",
            &reference("probe", serde_json::json!({}))
        ),
        None,
        "with no plugin declaring it, the kernel knows no shorthand"
    );
}
