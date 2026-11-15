// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

#[path = "memory_backend.rs"]
mod memory_backend;

/// A fresh primitive store for one test: the in-tree in-memory backend (`memory_backend.rs`), the
/// contract busbar-store-memory serves, with no plugin loaded (core is built and tested solo).
pub(crate) async fn native_backend() -> Arc<dyn busbar_contract::persistence::PersistenceBackend> {
    Arc::new(memory_backend::MemoryBackend::default())
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
