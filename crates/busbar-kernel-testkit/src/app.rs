// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub fn build_once(
    cfg: busbar_kernel::config::RootCfg,
    prior: Option<&busbar_kernel::state::App>,
) -> Result<busbar_kernel::state::App, String> {
    build_once_under(
        cfg,
        prior,
        &(std::sync::Arc::new(busbar_kernel::appbuild::AcceptAll)
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>),
    )
}

pub fn build_once_under(
    cfg: busbar_kernel::config::RootCfg,
    prior: Option<&busbar_kernel::state::App>,
    rules: &std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>,
) -> Result<busbar_kernel::state::App, String> {
    crate::test_support::root::ensure();

    let _limits_lock = loop {
        if let Ok(guard) = limits_lock().try_lock() {
            break guard;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };

    let (app, gov_rotate, limits) = busbar_kernel::build_app_from_config(
        cfg,
        busbar_kernel::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        prior,
        rules,
    )?;

    limits.keep()?;
    if let Some(rotate) = gov_rotate {
        rotate();
    }
    Ok(app)
}

#[must_use]
pub fn from_cfg(cfg: busbar_kernel::config::RootCfg) -> std::sync::Arc<busbar_kernel::state::App> {
    std::sync::Arc::new(
        build_once(cfg, None).unwrap_or_else(|e| panic!("the fixture's configuration builds: {e}")),
    )
}

fn limits_lock() -> &'static tokio::sync::Mutex<()> {
    &crate::test_support::fixture_limits::LIMITS_TEST_LOCK
}
