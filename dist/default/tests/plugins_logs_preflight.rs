// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::PluginsCfg;

fn plugin_logs(p: &PluginsCfg) -> Result<(), String> {
    let l = &p.logs;
    busbar_plugin_loader::dispatch::PluginLogConfig::from_words(
        l.dir.as_deref(),
        l.level.as_deref(),
        &l.levels,
        l.rotate_mb,
        l.keep,
    )
    .map(|_| ())
}

fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        busbar_kernel_testkit::test_support::install_test_root(
            busbar_kernel::preflight::RootInstall {
                plugin_logs: Some(plugin_logs),
                ..busbar_kernel_testkit::test_support::root::composed()
            },
        );
    });
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
