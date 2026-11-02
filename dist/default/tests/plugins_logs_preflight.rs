// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::PluginsCfg;

fn install() {
    crate::dist_root_install::install();
    assert!(
        busbar_kernel::preflight::root_rows().plugin_logs.is_some(),
        "the actual composition root installs its plugin logs preflight"
    );
}

#[test]
fn a_bad_plugins_logs_value_is_refused_naming_its_key() {
    install();
    let mut cfg = PluginsCfg::default();
    cfg.logs.level = Some("loud".into());
    let run = |cfg: &PluginsCfg| {
        busbar_kernel::plugins_preflight(
            None,
            None,
            &Default::default(),
            &Default::default(),
            cfg,
            &Default::default(),
        )
    };
    let err = run(&cfg).unwrap_err();
    assert!(err.contains("plugins.logs.level"), "{err}");
    cfg.logs.level = Some("debug".into());
    cfg.logs.rotate_mb = Some(0);
    let err = run(&cfg).unwrap_err();
    assert!(err.contains("plugins.logs.rotate_mb"), "{err}");
    cfg.logs.rotate_mb = Some(8);
    assert!(run(&cfg).is_ok(), "a good block passes");
}
