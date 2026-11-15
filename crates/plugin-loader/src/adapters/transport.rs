// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport adapter: `TransportPort` over the transport kind's `Proxy` (IF §11.3). W0-ABI stub: the adapter
//! type only; L9 fills it.

use busbar_plugin_abi::kinds::transport::transport::Proxy;

/// The transport port over one instance's proxy.
pub struct TransportAdapter {
    proxy: Proxy,
}

// W0-ABI: impl TransportPort for TransportAdapter lands with W1-L9.
impl TransportAdapter {
    // W0-ABI: not in the IF (the IF names no adapter type); a minimal seam so the stub is warning-free. W1-L9
    // replaces it with the real constructor and state.
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }
}
