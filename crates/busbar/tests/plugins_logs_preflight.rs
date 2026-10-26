// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plugins.logs` IS REFUSED AT THE ONE PRE-FLIGHT SEAM, in the loader's words.
//!
//! Moved here from busbar-kernel's `src/tests/tests.rs`: the plugin log sinks are the loader's, so
//! the kernel's pre-flight runs the composition root's reading of the block
//! (`busbar_kernel::preflight::RootInstall::plugin_logs`) and names no loader itself (THE DESIGN
//! l.322). This binary installs that reading as the root composes it — the loader's
//! `PluginLogConfig::from_words` over the block's words — through the kernel's test seam
//! (`install_test_root`, read ahead of the stand-in), and asks the kernel's pre-flight.

use busbar_kernel::config::PluginsCfg;

/// The root's `plugins.logs` check, restated over the loader (an integration test cannot call the
/// root's code): the block's words resolve, or the refusal names the key.
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

/// Install the check over the kernel's stand-in (the first install stands).
fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        busbar_kernel::test_support::install_test_root(busbar_kernel::preflight::RootInstall {
            plugin_logs: Some(plugin_logs),
            ..busbar_kernel::preflight::root_rows()
        });
    });
}

/// `plugins.logs` is refused at the one pre-flight seam every path runs (boot, `--validate`, reload,
/// apply), naming its key: a level word that names no level, and a zero rotation size.
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
