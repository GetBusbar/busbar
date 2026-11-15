// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane adapter: `PlanePort` over the plane kind's `Proxy` (IF §11.3). W0-ABI stub: the adapter type only; L8
//! fills it.

use busbar_plugin_abi::kinds::plane::plane::Proxy;

/// The plane port over one instance's proxy.
pub struct PlaneAdapter {
    proxy: Proxy,
}

// W0-ABI: impl PlanePort for PlaneAdapter lands with W1-L8.
impl PlaneAdapter {
    // W0-ABI: not in the IF (the IF names no adapter type); a minimal seam so the stub is warning-free. W1-L8
    // replaces it with the real constructor and state.
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }
}
