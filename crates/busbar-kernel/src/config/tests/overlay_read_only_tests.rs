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
fn legacy_file_selectors_are_accepted_without_filesystem_access() {
    let cfg = ConfigMgmtCfg {
        locked: false,
        overlay: Some(OverlayCfg::Backend(crate::config::OverlayBackend {
            file: Some("/nonexistent/legacy.json".into()),
        })),
    };
    assert!(
        resolve_backend_with_env(
            &cfg,
            Path::new("/config.yaml"),
            Some(Path::new("/also/nonexistent")),
            true
        )
        .unwrap()
        .enabled
    );
}
#[test]
fn explicit_disable_requires_locked_management() {
    for value in [false, true] {
        let cfg = ConfigMgmtCfg {
            locked: false,
            overlay: Some(OverlayCfg::Disabled(value)),
        };
        assert!(resolve_backend(&cfg, Path::new("/config.yaml"), false).is_err());
    }
}
