// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::PathBuf;
use std::sync::Arc;

use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;

pub(crate) fn store() -> Arc<LoadedStore> {
    let path = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN").expect(
            "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN must name the freshly built product store",
        ),
    );
    let stated = rendering_of_library(&path)
        .expect("the product store library's statement is readable")
        .expect("the product store library carries its statement");
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_dropped::<Store>(
        &path,
        &stated,
        Bind {
            instance: format!("governance-test-{}", crate::door::op_id().counter()).into(),
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
    Arc::new(
        LoadedStore::open(plugin, dispatcher, settings.as_bytes(), crate::door::op_id)
            .expect("the product store opens with its supplied settings"),
    )
}
