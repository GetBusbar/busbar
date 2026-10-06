// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK AXIS, THE ROOT'S (SWITCH-OVER, the hook root axis; ARCHITECT ruling 2026-09-29, the
//! opener seam: a kind's `<Kind>Axis` is the contract's, implemented over the ONE dispatcher and
//! the registry, and installed through the kernel's `RootInstall`). [`axis`] answers the contract's
//! `HookAxis` over one configuration's plugin registry and this build's linked hook doors
//! (`LINKED.hook_doors`; a linked row answers ahead of a dropped-in one): every `kind: hook` row, bound
//! through the loader's one load (`load_linked` / `load_dropped`) on the process's one dispatcher
//! (`root::dispatch`), each OPENED instance logging to its own file under `plugins.logs` and
//! declaring its needs on the process's one connector (`root::connector::the()`), read when the
//! instance opens. A dropped-in hook whose manifest states no Statement (a 1.5.5 JSON hook plugin)
//! is refused here, and with it the configuration.

use busbar_contract::conn::DeclaredConns;
use busbar_contract::hook_calls::HookAxis;
use std::sync::Arc;

use crate::root::loader::{hook_door::HookRows, PluginRegistry};

/// The process's one connection table, as an opened hook instance declares its needs on it.
fn conns() -> Arc<dyn DeclaredConns> {
    crate::root::connector::the().clone()
}

/// The hook axis over `registry` (`busbar_kernel::preflight::RootInstall::hook_axis`).
///
/// # Errors
/// A `kind: hook` row that will not state itself, named.
pub fn axis(registry: &Arc<PluginRegistry>) -> Result<Arc<dyn HookAxis>, String> {
    let rows = HookRows::new(
        crate::LINKED.hook_doors,
        Some(registry.as_ref()),
        crate::root::dispatch::dispatcher(),
    )?
    .with_former_names(busbar_kernel::config::legacy::former_names)?
    .with_logs(crate::root::boot::plugin_logs().clone())
    .with_conns(conns);
    Ok(Arc::new(rows))
}
