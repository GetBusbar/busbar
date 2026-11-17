// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::root::test_plugins as plugins;
fn plugins_cfg(dir: &std::path::Path, enabled: bool) -> busbar_kernel::config::PluginsCfg {
    busbar_kernel::config::PluginsCfg {
        enabled,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    }
}
fn linked_hook_name() -> &'static str {
    "cheapest"
}
#[test]
fn a_linked_hook_named_in_config_passes_preflight_and_an_unknown_one_is_refused() {
    const CHILD: &str = "BUSBAR_CENTRAL2_LINKED_CHILD";
    const WITNESS: &str = "actual linked product assertions completed";
    isolated!(CHILD, WITNESS, witness = "usage");
    crate::dist_root_install::install();
    let hook = |module: &str| {
        let cfg: busbar_kernel::config::HookCfg =
            busbar_contract::yaml::from_str(&format!("kind: gate\nmodule: {module}\n"))
                .expect("a hook");
        std::collections::HashMap::from([("h".to_string(), cfg)])
    };
    let dir = plugins::scratch("linked-hook");
    let run = |module: &str, enabled: bool| {
        busbar_kernel::preflight::plugins_preflight(
            None,
            None,
            &Default::default(),
            &hook(module),
            &plugins_cfg(&dir, enabled),
            &Default::default(),
        )
    };
    let linked = linked_hook_name();
    for enabled in [false, true] {
        run(linked, enabled).unwrap_or_else(|e| {
            panic!("the linked hook '{linked}' passes (plugins.enabled: {enabled}): {e}")
        });
    }
    let err = run("oracle-hook", true).expect_err("an unknown hook is refused");
    assert!(
        err.starts_with(&format!(
            "no plugin matching the hook reference 'oracle-hook' is installed in '{}' (plugins ARE \
             enabled; loadable: []). Two things to check: is the plugin subsystem enabled? (it is) \
             — and is the signed `kind: hook` tarball actually IN the folder?",
            dir.display()
        )),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}
