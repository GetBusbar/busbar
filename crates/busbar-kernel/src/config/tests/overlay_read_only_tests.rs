// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
#[test]
fn missing_or_readonly_input_paths_never_probe_or_degrade_store_management() {
    for probe in [false, true] {
        let resolution = resolve_backend(
            &ConfigMgmtCfg::default(),
            Path::new("/nonexistent/read-only/config.yaml"),
            probe,
        )
        .unwrap();
        assert!(resolution.enabled);
        assert!(!resolution.locked);
    }
}
#[test]
fn retired_environment_argument_is_ignored_without_filesystem_access() {
    for locked in [false, true] {
        let resolution = resolve_backend_with_env(
            &ConfigMgmtCfg { locked },
            Path::new("/config.yaml"),
            Some(Path::new("/also/nonexistent")),
            true,
        )
        .unwrap();
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
