// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LR-118's store cases (`abi::sdk::store::v4::conformance`) over the actual memory product
//! store, through its actual ABI. Red until STORE-TRANSACTIONS N8 deletes the 24 h receipts.
//! Its own test binary: the memory store holds what this process holds, so nothing else may
//! allocate beside the cases.

use std::path::PathBuf;
use std::sync::Arc;

use busbar_contract::abi::sdk::store::v4::conformance::{self, Subject};
use busbar_contract::persistence::PersistenceBackend;
use busbar_plugin_loader::dispatch::{
    load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
};
use busbar_plugin_loader::store_v4::{Limits, LoadedPersistence};

struct Memory(Arc<dyn PersistenceBackend>);

impl Memory {
    async fn fresh(instance: &str) -> Self {
        let path = PathBuf::from(
            std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN").expect(
                "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN must name the freshly built product store",
            ),
        );
        let stated = rendering_of_library(&path)
            .expect("the product store library's statement is readable")
            .expect("the product store library carries its statement");
        let dispatcher = Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        ));
        let plugin = load_dropped::<busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4>(
            &path,
            &stated,
            Bind {
                instance: Arc::from(instance),
                max_inflight_cap: 1024,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("the product store loads through its actual ABI");
        let backend = LoadedPersistence::open(
            plugin,
            dispatcher,
            b"{}",
            Limits {
                descriptor_bytes: 32 * 1024 * 1024,
                output_items: 4096,
                output_bytes: 32 * 1024 * 1024,
                decode_bytes: 32 * 1024 * 1024,
            },
        )
        .await
        .expect("the primitive product store opens");
        Self(Arc::new(backend))
    }
}

impl Subject for Memory {
    fn store(&self) -> Arc<dyn PersistenceBackend> {
        self.0.clone()
    }
    fn retained(&self) -> u64 {
        conformance::resident_bytes()
    }
    /// The memory product reads no host clock (`clock.now`): it is opened with no host. Its own
    /// OS reads (`v4.rs` receipt aging and its dataset clock) are R7's to refuse, and the aging
    /// goes with STORE-TRANSACTIONS N8.
    fn jump(&self, _: std::time::Duration) {}
    /// Allocator and page noise; 1M receipts are about 274 MiB (STORE-TRANSACTIONS §1).
    fn noise(&self) -> u64 {
        32 * 1024 * 1024
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn memory_store_state_does_not_grow_over_commits() {
    conformance::state_does_not_grow_over_commits(&Memory::fresh("lr118-growth").await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn memory_store_nothing_changes_after_clock_jump() {
    conformance::nothing_changes_after_clock_jump(&Memory::fresh("lr118-clock").await).await;
}
