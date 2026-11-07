// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::PathBuf;
use std::sync::Arc;

pub(crate) use crate::root::test_plugins::core_over;

use crate::root::loader::dispatch::{
    load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
};

pub(crate) async fn native_backend() -> Arc<dyn busbar_contract::persistence::PersistenceBackend> {
    let path = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN").expect(
            "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN must name the freshly built product store",
        ),
    );
    let stated = rendering_of_library(&path)
        .expect("the product store library's statement is readable")
        .expect("the product store library carries its statement");
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_dropped::<crate::root::loader::dispatch::kinds::store_v4::StoreV4>(
        &path,
        &stated,
        Bind {
            instance: format!("governance-test-{}", busbar_kernel::door::op_id().counter()).into(),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("the product store loads through its actual ABI");
    let settings =
        std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".to_string());
    let _: serde_json::Value =
        serde_json::from_str(&settings).expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    let backend = crate::root::loader::store_v4::LoadedPersistence::open(
        plugin,
        dispatcher,
        settings.as_bytes(),
        crate::root::loader::store_v4::Limits {
            descriptor_bytes: 32 * 1024 * 1024,
            output_items: 4096,
            output_bytes: 32 * 1024 * 1024,
            decode_bytes: 32 * 1024 * 1024,
        },
    )
    .await
    .expect("the primitive product store opens with supplied settings");
    Arc::new(backend)
}

pub(crate) async fn core() -> Arc<busbar_kernel::persistence::facade::CoreStore> {
    core_over(native_backend().await).await
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
#[allow(clippy::too_many_arguments)]
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
    let core = if let Some(prior) = prior {
        prior
            .governance
            .as_ref()
            .ok_or("test reload has no admitted governance")?
            .core_store_handle()
            .map_err(|error| error.to_string())?
    } else if let Some(overlay) = &overlay {
        overlay.core_store_handle()?
    } else {
        core_over(busbar_kernel::appbuild::bootstrap_config_store(&cfg, &plugins).await?).await
    };
    busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        plugins,
        overlay,
        base_hooks,
        base_groups,
        paths,
        prior,
        rules,
        Some(core),
        false,
    )
    .await
}
