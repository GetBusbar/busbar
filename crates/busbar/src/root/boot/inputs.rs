// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Canonical opening settings of the instances that already own the bootstrap Store.

use busbar_kernel::config::{RootCfg, SecretModuleCfg, StoreCfg};
use std::collections::{BTreeMap, BTreeSet};

/// The instance portion of the protected boot projection. Image and bootstrap network
/// dependencies require separate admission and connector comparisons.
pub(crate) struct BootInstances {
    store: Option<StoreCfg>,
    secrets: BTreeMap<String, SecretModuleCfg>,
}

fn same_yaml(
    a: &Option<busbar_contract::yaml::Value>,
    b: &Option<busbar_contract::yaml::Value>,
) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => busbar_contract::yaml::same_tree(a, b),
        (None, None) => true,
        _ => false,
    }
}

fn same_secret(a: &SecretModuleCfg, b: &SecretModuleCfg) -> bool {
    a.module == b.module
        && a.settings == b.settings
        && same_yaml(&a.limits, &b.limits)
        && same_yaml(&a.insecure_transport, &b.insecure_transport)
}

fn same_store(a: &Option<StoreCfg>, b: &Option<StoreCfg>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            a.module == b.module
                && a.settings == b.settings
                && same_yaml(&a.limits, &b.limits)
                && same_yaml(&a.insecure_transport, &b.insecure_transport)
        }
        (None, None) => true,
        _ => false,
    }
}

impl BootInstances {
    pub(crate) fn capture(cfg: &RootCfg) -> Self {
        Self {
            store: cfg.store.clone(),
            secrets: cfg.secrets.clone(),
        }
    }

    fn differences(&self, candidate: &Self) -> Vec<String> {
        let mut paths = Vec::new();
        if !same_store(&self.store, &candidate.store) {
            paths.push("store".to_owned());
        }
        let names: BTreeSet<_> = self
            .secrets
            .keys()
            .chain(candidate.secrets.keys())
            .collect();
        for name in names {
            match (self.secrets.get(name), candidate.secrets.get(name)) {
                (Some(a), Some(b)) if same_secret(a, b) => {}
                _ => paths.push(format!("secrets.{name}")),
            }
        }
        paths
    }

    pub(crate) fn check(&self, cfg: &RootCfg) -> Result<(), String> {
        let paths = self.differences(&Self::capture(cfg));
        if paths.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "protected boot instance inputs changed at {}; edit the file and restart",
                paths.join(", ")
            ))
        }
    }
}

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
