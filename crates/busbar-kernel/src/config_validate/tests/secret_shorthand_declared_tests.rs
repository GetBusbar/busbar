// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET SHORTHAND IS THE PLUGINS' DECLARATION, NOT THE KERNEL'S VOCABULARY (audit
//! contract-admin #10, MEDIUM; BUSBAR-1.6.0.md Part 1, Laws 0 and 1: core names kinds, never
//! instances). Which reference keys a secret source answers to, the settings key a shorthand value
//! lands under and what a refusal says that value names are stated by each secret plugin in its
//! own Statement (`REWRITE_SUGAR`, `REWRITE_SUGAR_NAMES`); config validation reads them off the
//! loaded plugins and holds no source's name, settings key or wording.

/// A source no shipped plugin is: its Statement declares the shorthand `probe`, its value landing
/// under `slot`. The kernel learns all three words from the declaration alone.
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

/// A declared shorthand routes: a reference to its module must set the key the declaration names,
/// non-empty, refused in the declaration's own words.
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

/// A module no loaded plugin declares a shorthand for is not judged here: its existence is the
/// registry's to prove at plugin pre-flight, which refuses an unknown module in 1.5.5's words.
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
