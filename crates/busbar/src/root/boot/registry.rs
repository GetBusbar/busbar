// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot's use of the MIN-3 `Registry` (ABI-MIN3-INTERFACE §11.2, §12.10; W2-BOOT, W2-SW-STORE).
//!
//! Root plans the complete registry boot and walks its dependency order.

use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::instance::{BootPlan, InstanceSpec, OpenError, Registry};

use super::walk::{walk, BootRefused, BootSteps, Booted};

/// Plan the boot over `instances` (core's own secret modules as 2a roots), then walk it.
pub async fn boot<S: BootSteps>(
    registry: &Registry,
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
