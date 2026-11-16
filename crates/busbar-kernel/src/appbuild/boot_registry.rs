// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot's use of the MIN-3 `Registry` (ABI-MIN3-INTERFACE §11.2, §12.10; W2-BOOT, W2-SW-STORE).
//!
//! `install_kernel_sides` hands the registry the kernel's side of the adapters (the store seal factory, the
//! auth core) and installs the registry as the process's store opener, so `appbuild::open_config_store` opens the
//! store through `Registry::open_store`. `boot` plans (core's own secret references are 2a roots) and walks.

use std::sync::Arc;
use std::time::Duration;

use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::adapters::auth::AuthCore;
use busbar_plugin_loader::instance::{BootPlan, InstanceSpec, OpenError, Registry, StoreSeal};

use super::boot_walk::{walk, BootRefused, BootSteps, Booted};

/// Installs the kernel's sides on `registry`, then the registry as the store opener (the first one installed
/// stays). Called once, before the first `open_store`. Returns whether this call installed the opener.
pub fn install_kernel_sides<N: Needs + 'static>(
    registry: Arc<Registry<N>>,
    seal: StoreSeal,
    auth_core: Arc<dyn AuthCore>,
    unknown_key_refresh: Duration,
) -> bool {
    registry.set_store_seal(seal);
    registry.set_auth_core(auth_core, unknown_key_refresh);
    crate::preflight::install_store_opener(registry)
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

/// The kernel's side of the auth adapter (IF §12.8, §12.11): the issued-credential lookup over `I` and the replay
/// claim over `G`. A claim the guard cannot answer is `None`, which the adapter treats as unavailable (fail closed).
pub struct KernelAuthCore<I: crate::issued::IssuedCredentials, G: crate::plane_grants::ReplayGuard>
{
    issued: I,
    replay: G,
}

impl<I: crate::issued::IssuedCredentials, G: crate::plane_grants::ReplayGuard>
    KernelAuthCore<I, G>
{
    pub fn new(issued: I, replay: G) -> Self {
        Self { issued, replay }
    }
}

impl<I: crate::issued::IssuedCredentials, G: crate::plane_grants::ReplayGuard> AuthCore
    for KernelAuthCore<I, G>
{
    fn issued<'a>(
        &'a self,
        auth_instance: u64,
        kind: &'a str,
        id: &'a str,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'a, busbar_contract::secure::SecureVec> {
        self.issued.lookup(auth_instance, kind, id)
    }

    fn claim<'a>(
        &'a self,
        who: &'a busbar_plugin_abi::host_side::caller::Caller<'_>,
        key: &'a [u8],
        ttl_s: u64,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'a, Option<bool>> {
        Box::pin(async move { self.replay.claim(who, key, ttl_s).await.ok() })
    }
}
