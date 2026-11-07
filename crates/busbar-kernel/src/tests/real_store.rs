// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::PathBuf;
use std::sync::Arc;

use busbar_plugin_loader::dispatch::{
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
    let plugin = load_dropped::<busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4>(
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
    let backend = busbar_plugin_loader::store_v4::LoadedPersistence::open(
        plugin,
        dispatcher,
        settings.as_bytes(),
        busbar_plugin_loader::store_v4::Limits {
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

pub(crate) async fn core() -> Arc<crate::persistence::facade::CoreStore> {
    core_over(native_backend().await).await
}

pub(crate) async fn core_over(
    backend: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
) -> Arc<crate::persistence::facade::CoreStore> {
    let mut startup = crate::persistence::startup::Startup::new(
        backend,
        crate::persistence::facade::Limits {
            pending_operations: 1024,
            conflict_retries: 8,
            scan_items: 128,
            scan_bytes: 1024 * 1024,
        },
        true,
    )
    .expect("valid native test storage authority");
    loop {
        use crate::persistence::startup::Progress;
        match startup.advance().await.expect("native storage startup") {
            Progress::Advanced => {}
            Progress::Admitted => break,
            other => panic!("test startup did not admit: {other:?}"),
        }
    }
    startup.store().expect("admitted core store")
}
