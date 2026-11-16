// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config;
use std::sync::Arc;

/// Root-only store opener with complete per-open custody and store authority.
pub(crate) struct RegistryStore<N: busbar_plugin_abi::host_side::needs::Needs> {
    pub(crate) registry: Arc<busbar_plugin_loader::instance::Registry>,
    pub(crate) needs: Arc<N>,
    pub(crate) seal: busbar_plugin_loader::instance::StoreSeal,
}

impl<N: busbar_plugin_abi::host_side::needs::Needs> StoreOpener for RegistryStore<N> {
    fn open_store<'a>(
        &'a self,
        spec: &'a busbar_plugin_loader::instance::InstanceSpec<'a>,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<busbar_ports::store::StoreHandle, busbar_plugin_loader::instance::OpenError>,
    > {
        self.registry
            .open_store(spec, &self.needs, Arc::clone(&self.seal))
    }
}

/// The store's MIN-3 open (W2-SW-STORE; IF §11.2 `Registry::open_store`, §11.3): the one way the kernel's store
/// boot opens its configured store. The answer's backend is the store adapter, the kernel's own
/// `PersistenceBackend` over the proxy (on the store lane for a blocking-file store); there is no other store
/// port. The store converts its own bag in that `open` (WBS rule 12): no migrate call is made here.
pub trait StoreOpener: Send + Sync {
    /// `Registry::open_store` for `spec`.
    fn open_store<'a>(
        &'a self,
        spec: &'a busbar_plugin_loader::instance::InstanceSpec<'a>,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<busbar_ports::store::StoreHandle, busbar_plugin_loader::instance::OpenError>,
    >;
}

/// The opener of a caller that holds no MIN-3 registry (a tool, a fixture): every open refuses, so a store is
/// never opened through a registry that was not handed over.
pub struct Unopened;

impl StoreOpener for Unopened {
    fn open_store<'a>(
        &'a self,
        _spec: &'a busbar_plugin_loader::instance::InstanceSpec<'a>,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<busbar_ports::store::StoreHandle, busbar_plugin_loader::instance::OpenError>,
    > {
        Box::pin(core::future::ready(Err(
            busbar_plugin_loader::instance::OpenError::Unknown(
                "no store registry is installed".into(),
            ),
        )))
    }
}

pub async fn bootstrap_config_store(
    cfg: &config::RootCfg,
    plugins: &config::PluginsCfg,
    opener: &dyn StoreOpener,
    resolver: &config::secret::SecretResolver,
) -> Result<busbar_contract::persistence::axis::OpenedBackend, String> {
    // The root supplies its opened S5 view; this projection never opens secret instances.
    busbar_kernel::appbuild::bootstrap_store_inputs(cfg, plugins, resolver).await?;
    open_config_store(cfg, opener).await
}
/// The configured store, opened through the MIN-3 registry (W2-SW-STORE; IF §11.2 `Registry::open_store`).
/// The bag goes in operator form (secret references with their `module`): the registry's binder binds it, the
/// store converts an older shape inside its own `open` and the registry keeps the settled bag for the boot's
/// write-back (`Registry::take_settled`, step 5 / 5W). The instance name is the section key, `store`.
async fn open_config_store(
    cfg: &config::RootCfg,
    opener: &dyn StoreOpener,
) -> Result<busbar_contract::persistence::axis::OpenedBackend, String> {
    let store = cfg.store.as_ref().ok_or_else(config::store_required)?;
    let failed = |error: String| format!("store '{}' plugin load failed: {error}", store.module);
    let config_json = store
        .settings
        .encode()
        .map_err(|error| failed(error.to_string()))?
        .into_exposed(&busbar_kernel::seal::lend());
    let spec = busbar_plugin_loader::instance::InstanceSpec {
        purpose: busbar_plugin_loader::instance::OpenPurpose::Canonical,
        identity: &store.module,
        name: busbar_kernel::appbuild::STORE_INSTANCE,
        config_json: &config_json,
        limits: busbar_kernel::appbuild::instance_limits(
            cfg,
            busbar_kernel::appbuild::STORE_INSTANCE,
            busbar_kernel::appbuild::STORE_INSTANCE,
        ),
        public_url: None,
        caller_upstreams: &[],
    };
    opener
        .open_store(&spec)
        .await
        .map(|handle| handle.backend)
        .map_err(|error| failed(store_open_refusal(&error)))
}

/// Core's own words for a refused store open, with the code only (IF §12.16: the plugin's text is never
/// interpolated into a core message).
fn store_open_refusal(error: &busbar_plugin_loader::instance::OpenError) -> String {
    use busbar_plugin_loader::instance::OpenError;
    match error {
        OpenError::Refused { refusal, .. } => format!("refused: {refusal}"),
        OpenError::Config { code, .. } => format!("its settings were refused (code {code})"),
        OpenError::Failed { code, .. } => format!("its open failed (code {code})"),
        OpenError::Call(_) => "its open faulted".to_owned(),
        OpenError::Unknown(what) => format!("unknown store open answer: {what}"),
    }
}
