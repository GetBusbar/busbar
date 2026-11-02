// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::conn::DeclaredConns;
use busbar_contract::hook_calls::HookAxis;
use std::sync::Arc;

use busbar_contract::plugin_rows::PluginRows;

use crate::root::loader::{hook_door::HookRows, rows::registry_of};

fn conns() -> Arc<dyn DeclaredConns> {
    crate::root::connector::the().clone()
}

pub fn axis(registry: &Arc<dyn PluginRows>) -> Result<Arc<dyn HookAxis>, String> {
    let rows = HookRows::new(
        crate::LINKED.hook_doors,
        registry_of(registry.as_ref()),
        crate::root::dispatch::dispatcher(),
    )?
    .with_former_names(busbar_kernel::config::migration_table::former_names)?
    .with_logs(crate::root::boot::plugin_logs().clone())
    .with_conns(conns);
    Ok(Arc::new(rows))
}
