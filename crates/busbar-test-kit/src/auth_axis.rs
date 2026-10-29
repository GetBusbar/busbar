// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth axis's TEST STAND-IN: a build with no composition root opens its auth rows on a
//! dispatcher of its own.

use std::sync::Arc;

use busbar_contract::conn::DeclaredConns;
use busbar_plugin_loader::auth_axis::AuthRows;
use busbar_plugin_loader::dispatch::{DispatchConfig, Dispatcher};
use busbar_plugin_loader::PluginRegistry;

/// TEST STAND-IN: one build's auth axis over `registry` on a dispatcher of its own, for a build
/// with no composition root to hold the process's one dispatcher (a test binary), lent `seal` (the
/// kernel's, so a verify reveals the credential it lends the plugin as a booted node's does; Part
/// 2 #54). The first call's seal is the one lent. Never shipped.
#[must_use]
pub fn stand_in(
    registry: Arc<PluginRegistry>,
    seal: impl busbar_contract::plugin::KernelSeal + Send + Sync + 'static,
) -> Arc<dyn busbar_contract::auth_calls::AuthAxis> {
    static DISPATCHER: std::sync::OnceLock<Arc<Dispatcher>> = std::sync::OnceLock::new();
    let dispatcher = DISPATCHER.get_or_init(|| {
        let d = Dispatcher::new(DispatchConfig::default());
        let _ = d.lend_seal(seal);
        Arc::new(d)
    });
    let rows = AuthRows::new(registry, dispatcher.clone());
    let table = STAND_IN_CONNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Arc::new(match table {
        Some(table) => rows.with_table(table),
        None => rows,
    })
}

/// The connection table the TEST STAND-IN's opened instances are bound to, when a test installed
/// one ([`stand_in_conns`]).
static STAND_IN_CONNS: std::sync::Mutex<Option<Arc<dyn DeclaredConns>>> =
    std::sync::Mutex::new(None);

/// TEST STAND-IN: bind every instance the stand-in axis opens from now on to `conns` (a test's
/// stand-in for the process's connector, e.g. [`crate::https_conns::HttpsConns`]). Never shipped.
pub fn stand_in_conns(conns: Arc<dyn DeclaredConns>) {
    *STAND_IN_CONNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(conns);
}
