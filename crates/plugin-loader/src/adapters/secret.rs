// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret adapter: `SecretPort` over the secret kind's `Proxy` (IF §11.3). W0-ABI stub: the adapter type only;
//! L4 fills it.

use busbar_plugin_abi::kinds::secret::secret::Proxy;

/// The secret port over one instance's proxy.
pub struct SecretAdapter {
    proxy: Proxy,
}

// W0-ABI: impl SecretPort for SecretAdapter lands with W1-L4.
impl SecretAdapter {
    // W0-ABI: not in the IF (the IF names no adapter type); a minimal seam so the stub is warning-free. W1-L4
    // replaces it with the real constructor and state.
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }
}
