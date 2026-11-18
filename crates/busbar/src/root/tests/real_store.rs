// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::PathBuf;
use std::sync::Arc;

pub(crate) use crate::root::test_plugins::core_over;

#[path = "../../../../busbar-kernel/src/tests/memory_backend.rs"]
mod memory_backend;

/// A fresh primitive store for one test: core's in-tree in-memory backend, the contract
/// busbar-store-memory serves, with no plugin loaded (core is built and tested solo).
pub(crate) async fn native_backend() -> Arc<dyn busbar_contract::persistence::PersistenceBackend> {
    Arc::new(memory_backend::MemoryBackend::default())
}

/// Shared store clock for multi-process crash/lease conformance, without wall-clock sleeps.
pub(crate) fn clocked_native_backend() -> (
    Arc<dyn busbar_contract::persistence::PersistenceBackend>,
    impl Fn(u64),
) {
    use busbar_contract::persistence::conformance::Subject;
    let backend = Arc::new(memory_backend::MemoryBackend::default());
    let clock = Arc::clone(&backend);
    (backend, move |seconds| {
        assert!(clock.jump_clock(seconds));
    })
}

pub(crate) async fn core() -> Arc<busbar_kernel::persistence::facade::CoreStore> {
    core_over(native_backend().await).await
}

/// A Store that loses its state with the process: delegates every call to `inner` and reports
/// `BackendInfo.durability == Ephemeral`, as the in-memory Store does (BUSBAR-8016).
pub(crate) struct EphemeralInfo(
    pub(crate) Arc<dyn busbar_contract::persistence::PersistenceBackend>,
);

impl busbar_contract::persistence::PersistenceBackend for EphemeralInfo {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        busbar_contract::persistence::BackendInfo {
            durability: busbar_contract::persistence::Durability::Ephemeral,
            ..self.0.info()
        }
    }
    fn read(
        &self,
        request: Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        self.0.read(request)
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        self.0.scan(request)
    }
    fn commit(
        &self,
        candidate: busbar_contract::persistence::PreparedCandidate,
        key: busbar_contract::persistence::CommitKey,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        self.0.commit(candidate, key)
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.0.clock(dataset)
    }
}

pub(crate) async fn admin_scoped() -> Arc<busbar_kernel::persistence::scoped::ScopedStore> {
    Arc::new(
        busbar_core_admin::idempotency::durable::scoped_store(core().await)
            .expect("private admin scope"),
    )
}

/// Complete normal startup restoration on the exact App a fixture will serve.
/// Call after binding its book and activating rates, before arming operation faults.
pub(crate) async fn hydrated(
    app: Arc<busbar_kernel::state::App>,
) -> Arc<busbar_kernel::state::App> {
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("the actual serving App completes normal startup hydration");
    app
}

/// Build a test App through the actual native Store admission used at boot. Reloads
/// reuse their carrier's admitted CoreStore, including its writer and pending custody.
pub(crate) async fn build_app(
    cfg: busbar_kernel::config::RootCfg,
    plugins: busbar_kernel::config::PluginsCfg,
    overlay: Option<Arc<busbar_kernel::config::overlay::OverlayStore>>,
    base_hooks: std::collections::HashSet<String>,
    base_groups: std::collections::HashSet<String>,
    paths: (Option<PathBuf>, Option<PathBuf>),
    prior: Option<&busbar_kernel::state::App>,
    rules: &Arc<dyn busbar_kernel::appbuild::RootRules>,
) -> Result<
    (
        busbar_kernel::state::App,
        Option<busbar_kernel::GovCredentialRotation>,
        busbar_kernel::InstalledLimits,
    ),
    String,
> {
    let (core, rules) = if let Some(prior) = prior {
        (
            prior
                .governance
                .as_ref()
                .ok_or("test reload has no admitted governance")?
                .core_store_handle()
                .map_err(|error| error.to_string())?,
            crate::root::min3_boot::fixture::carry(prior.root_rules.clone(), rules.clone()),
        )
    } else if let Some(overlay) = &overlay {
        (overlay.core_store_handle()?, rules.clone())
    } else {
        let opened = crate::root::min3_boot::fixture::open(&cfg, &plugins, rules.clone())
            .await?
            .admit()
            .await;
        (opened.core, opened.rules)
    };
    busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(cfg),
        plugins,
        overlay,
        base_hooks,
        base_groups,
        paths,
        prior,
        &rules,
        Some(core),
        false,
    )
    .await
}
