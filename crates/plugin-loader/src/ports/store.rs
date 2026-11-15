// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store port (IF §11.3): no store vocabulary of its own, the adapter is the kernel's
//! `busbar_contract::persistence::PersistenceBackend`. W0-ABI stub: frozen signatures, `todo!()` bodies; L3 fills it.

use std::sync::Arc;

pub struct StoreHandle {
    pub backend: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
}
