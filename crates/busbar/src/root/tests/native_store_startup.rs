// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared native admission for fixture-owned backends; no application or plugin wiring.
use std::sync::Arc;

pub(crate) async fn core_over(
    backend: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
) -> Arc<busbar_kernel::persistence::facade::CoreStore> {
    let mut startup = busbar_kernel::persistence::startup::Startup::new(
        backend,
        busbar_kernel::persistence::facade::Limits {
            pending_operations: 1024,
            conflict_retries: 8,
            scan_items: 128,
            scan_bytes: 1024 * 1024,
        },
        true,
    )
    .expect("valid native test storage authority");
    loop {
        use busbar_kernel::persistence::startup::Progress;
        match startup.advance().await.expect("native storage startup") {
            Progress::Advanced => {}
            Progress::Admitted => break,
            other => panic!("test startup did not admit: {other:?}"),
        }
    }
    startup.store().expect("admitted core store")
}
