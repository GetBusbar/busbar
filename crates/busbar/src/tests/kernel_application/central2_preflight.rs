// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::root::test_plugins as plugins;
#[test]
fn store_plugin_with_plugins_disabled_is_boot_error_naming_the_flag() {
    const CHILD: &str = "BUSBAR_CENTRAL2_PREFLIGHT_CHILD";
    const WITNESS: &str = "actual root disabled plugin refusal completed";
    isolated!(CHILD, WITNESS, witness = "usage");
    crate::dist_root_install::install();
    let dir = plugins::scratch("central2-disabled-store");
    let err = busbar_kernel::preflight::plugins_preflight(
        Some(&gov_with_store("durable-kv")),
        None,
        &Default::default(),
        &Default::default(),
        &plugins_cfg(&dir, false),
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("plugins.enabled"), "names the flag: {err}");
    assert!(err.contains("durable-kv"), "names the store: {err}");

    let err = busbar_kernel::preflight::plugins_preflight(
        Some(&gov_with_store("durable-kv")),
        None,
        &Default::default(),
        &Default::default(),
        &busbar_kernel::config::PluginsCfg::default(),
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("plugins.enabled"), "absent block: {err}");
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}
fn plugins_cfg(dir: &std::path::Path, enabled: bool) -> busbar_kernel::config::PluginsCfg {
    busbar_kernel::config::PluginsCfg {
        enabled,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    }
}
fn gov_with_store(store: &str) -> busbar_kernel::config::StoreCfg {
    busbar_kernel::config::StoreCfg {
        module: store.into(),
        settings: Default::default(),
        insecure_transport: None,
    }
}
