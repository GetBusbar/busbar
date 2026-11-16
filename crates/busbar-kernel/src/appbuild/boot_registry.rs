// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot's use of the MIN-3 `Registry` (ABI-MIN3-INTERFACE §11.2, §12.10; W2-BOOT, W2-SW-STORE).
//!
//! `install_kernel_sides` hands the registry the kernel's side of the adapters (the store seal factory, the
//! auth core); the registry itself is the `StoreOpener` a caller of `appbuild::bootstrap_config_store` is handed, so the
//! store opens through `Registry::open_store`. `boot` plans (core's own secret references are 2a roots) and walks.

use std::sync::Arc;

use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::instance::{BootPlan, InstanceSpec, OpenError, Registry, StoreSeal};

use super::boot_walk::{walk, BootRefused, BootSteps, Booted};

/// Installs the kernel's sides on `registry`. Called once, before the first `open_store`.
pub fn install_kernel_sides<N: Needs + 'static>(registry: Arc<Registry<N>>, seal: StoreSeal) {
    registry.set_store_seal(seal);
}

/// Plan the boot over `instances` (core's own secret modules as 2a roots), then walk it.
pub async fn boot<N: Needs, S: BootSteps>(
    registry: &Registry<N>,
    instances: &[(KindCode, InstanceSpec<'_>)],
    sugars: &busbar_contract::secret_ref::Sugars,
    core_modules: &[&str],
    steps: &S,
) -> Result<Booted<S::Opened>, BootRefused> {
    let plan: BootPlan = registry
        .boot_plan_with_core(instances, sugars, core_modules)
        .map_err(|error: OpenError| BootRefused::Plan(format!("{error:?}")))?;
    walk(&plan, steps).await
}
