// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store adapter: the kernel's `busbar_contract::persistence::PersistenceBackend` over the store kind's `Proxy`
//! (IF §11.3). W0-ABI stub: the adapter type only; L3 fills it.

use busbar_plugin_abi::kinds::store::store::Proxy;

/// The store port over one instance's proxy.
pub struct StoreAdapter {
    proxy: Proxy,
}

// W0-ABI: the IF's `pub(crate) struct StoreLane` and `StoreLane::run` (§11.3, round 11) are crate-private and
// would be dead code in the stub; they land with W1-L3.

// W0-ABI: impl PersistenceBackend for StoreAdapter lands with W1-L3.
impl StoreAdapter {
    // W0-ABI: not in the IF (the IF names no adapter type); a minimal seam so the stub is warning-free. W1-L3
    // replaces it with the real constructor and state.
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }
}
