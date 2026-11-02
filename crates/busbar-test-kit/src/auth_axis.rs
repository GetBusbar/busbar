// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::conn::DeclaredConns;
use busbar_plugin_loader::auth_axis::AuthRows;
use busbar_plugin_loader::dispatch::{DispatchConfig, Dispatcher};
use busbar_plugin_loader::PluginRegistry;

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

static STAND_IN_CONNS: std::sync::Mutex<Option<Arc<dyn DeclaredConns>>> =
    std::sync::Mutex::new(None);

pub fn stand_in_conns(conns: Arc<dyn DeclaredConns>) {
    *STAND_IN_CONNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(conns);
}
