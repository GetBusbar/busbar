// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth adapter: `AuthPort` over the auth kind's `Proxy` (IF §11.3). W0-ABI stub: the adapter type only; L5
//! fills it.

use busbar_plugin_abi::kinds::auth::auth::Proxy;

/// The auth port over one instance's proxy.
pub struct AuthAdapter {
    proxy: Proxy,
}

// W0-ABI: impl AuthPort for AuthAdapter lands with W1-L5.
impl AuthAdapter {
    // W0-ABI: not in the IF (the IF names no adapter type); a minimal seam so the stub is warning-free. W1-L5
    // replaces it with the real constructor and state.
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }
}
