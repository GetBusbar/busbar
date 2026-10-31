// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN APP BUILT THE PRODUCTION WAY: a test's `RootCfg` run through the kernel's own
//! `build_app_from_config`, as a configuration apply builds a generation, with no composition root's
//! rules to judge it (or a test's double of them), no plugins directory and no persist step.

/// Build `cfg` (over `prior`, as a reload does) and keep it: its limits stay installed and any
/// governance-credential rotation it resolved fires, as the live generation's would.
///
/// # Errors
/// Why the build refused `cfg`, in the build's own words.
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

/// [`build_once`] judged by `rules` (a composition root's, or a test's double), which the kept
/// build's commit is raised to as a shipped build's is.
pub fn build_once_under(
    cfg: busbar_kernel::config::RootCfg,
    prior: Option<&busbar_kernel::state::App>,
    rules: &std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>,
) -> Result<busbar_kernel::state::App, String> {
    // The build installs `cfg.limits` process-wide and KEEPS them (below), so it is a writer of the
    // slot `LIMITS_TEST_LOCK` serializes: without the lock, a build in a sibling test lands mid-way
    // through a test that holds it (e.g. the root listener's total-deadline test, which installs a
    // 2 KiB cap and reads it live for seconds) and swaps the value it is asserting on. Spun on
    // `try_lock`, not `blocking_lock`, because callers run inside a tokio runtime as often as not.
    let _limits_lock = loop {
        if let Ok(guard) = busbar_kernel::config::limits::LIMITS_TEST_LOCK.try_lock() {
            break guard;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    // Test-only direct call: there is no outer admin transaction / persist step here, so firing any
    // resolved governance-credential rotation immediately is correct
    // and keeps this helper's callers (which assert on rotation taking effect) unchanged.
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
    // Same reasoning for the limits: no persist step follows, so this build IS the live generation
    // and its limits stay installed — the behaviour every caller of this helper has always had.
    limits.keep();
    if let Some(rotate) = gov_rotate {
        rotate();
    }
    Ok(app)
}

/// [`build_once`] with no prior generation, shared: the App a test drives.
///
/// # Panics
/// If the build refuses `cfg`: a fixture's configuration must build.
#[must_use]
pub fn from_cfg(cfg: busbar_kernel::config::RootCfg) -> std::sync::Arc<busbar_kernel::state::App> {
    std::sync::Arc::new(
        build_once(cfg, None).unwrap_or_else(|e| panic!("the fixture's configuration builds: {e}")),
    )
}
