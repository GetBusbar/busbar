// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Canonical opening settings of the instances that already own the bootstrap Store.

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(module: &str, value: &str) -> busbar_kernel::config::SecretModuleCfg {
        busbar_contract::yaml::from_str(&format!(
            "module: {module}\nsettings: {{token: {value}}}\n"
        ))
        .unwrap()
    }

    #[test]
    fn secret_identity_and_settings_cannot_change_beneath_an_open_store() {
        let original = secret("first", "do-not-print-me");
        let mut next = original.clone();
        next.module = "second".into();
        assert!(!same_secret(&original, &next));
        assert!(!same_secret(&original, &secret("first", "different")));
        assert!(same_secret(&original, &original));
    }

    #[test]
    fn instance_addition_removal_and_changes_report_only_paths() {
        let boot = BootInstances {
            store: None,
            secrets: [("vault".into(), secret("first", "do-not-print-me"))].into(),
        };
        let candidate = BootInstances {
            store: None,
            secrets: [("new".into(), secret("other", "another-secret"))].into(),
        };
        assert_eq!(
            boot.differences(&candidate),
            ["secrets.new", "secrets.vault"]
        );
        assert!(boot.differences(&boot).is_empty());
    }

    #[test]
    fn store_settings_are_compared_canonically() {
        let a = busbar_contract::yaml::from_str("module: store\nsettings: {a: 1, b: 2}\n").unwrap();
        let b = busbar_contract::yaml::from_str("module: store\nsettings: {b: 2, a: 1}\n").unwrap();
        assert!(same_store(&Some(a), &Some(b)));
    }
}
