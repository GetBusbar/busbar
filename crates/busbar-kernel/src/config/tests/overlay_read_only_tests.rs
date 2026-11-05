// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
#[test]
fn current_management_serialization_contains_only_locked_policy() {
    for locked in [false, true] {
        let policy = ConfigMgmtCfg { locked };
        let encoded = serde_yaml::to_value(&policy).unwrap();
        let expected: serde_yaml::Value =
            serde_yaml::from_str(&format!("locked: {locked}\n")).unwrap();
        assert_eq!(encoded, expected);
        let restored: ConfigMgmtCfg = serde_yaml::from_value(encoded).unwrap();
        let resolution = resolve_backend(&restored);
        assert_eq!(resolution.locked, locked);
        assert_eq!(resolution.enabled, !locked);
    }
}

#[test]
fn current_management_grammar_refuses_all_old_overlay_selectors() {
    for locked in [false, true] {
        for selector in ["false", "true", "{file: /old/overlay.json}", "{}", "null"] {
            let yaml = format!("locked: {locked}\noverlay: {selector}\n");
            let error = serde_yaml::from_str::<ConfigMgmtCfg>(&yaml)
                .unwrap_err()
                .to_string();
            assert!(error.contains("overlay"), "{error}");
            assert!(error.contains("locked"), "{error}");
        }
    }
}
