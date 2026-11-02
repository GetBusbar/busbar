// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use crate::config::{AsIdentity, OauthAsCfg};
#[cfg(test)]
use busbar_kernel::state::App;
use busbar_kernel_testkit::test_support::TestApp;

use crate::plane::AsPlane;

#[cfg(test)]
pub(crate) fn oauth_as_plane(app: &App) -> Option<Arc<AsPlane>> {
    app.oauth_as_any()?.clone().downcast::<AsPlane>().ok()
}

pub trait TestAppOauthExt {
    fn oauth_as(self, cfg: &OauthAsCfg) -> Self;
}

impl TestAppOauthExt for TestApp {
    fn oauth_as(self, cfg: &OauthAsCfg) -> Self {
        install_test_seam();
        let identity = AsIdentity::from_cfg(cfg).expect("test oauth_as config must be valid");
        let plane = AsPlane::build(identity, None, Vec::new(), crate::cimd::unconnected())
            .expect("test oauth_as plane must build");
        self.oauth_as_plane(Arc::new(plane))
    }
}

pub(crate) fn install_test_seam() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(crate::install::<crate::NoConnections>);
}

// Private owner-unit storage. This is the supplied real product store loaded
// through its normal ABI, not a Store implementation manufactured by a kit.
pub(crate) fn store_calls() -> Arc<dyn busbar_contract::store_calls::StoreCalls> {
    loaded_store()
}

pub(crate) fn loaded_store() -> Arc<busbar_plugin_loader::store_v3::LoadedStore> {
    use busbar_plugin_loader::dispatch::kinds::store::Store;
    use busbar_plugin_loader::dispatch::{
        load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
    };

    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let stated = rendering_of_library(&path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_dropped::<Store>(
        &path,
        &stated,
        Bind {
            instance: format!("oauth-unit-{}", busbar_kernel::door::op_id().counter()).into(),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("the actual store loads through its ABI");
    let settings =
        std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into());
    let _: serde_json::Value =
        serde_json::from_str(&settings).expect("the actual store settings are JSON");
    Arc::new(
        busbar_plugin_loader::store_v3::LoadedStore::open(
            plugin,
            dispatcher,
            settings.as_bytes(),
            busbar_kernel::door::op_id,
        )
        .expect("the actual store opens with its supplied settings"),
    )
}
