// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook adapter: `HookPort` over the hook kind's `Proxy` (IF §11.3). W0-ABI stub: the adapter type only; L6
//! fills it.

use busbar_plugin_abi::kinds::hook::hook::Proxy;

/// The hook port over one instance's proxy.
pub struct HookAdapter {
    proxy: Proxy,
}

// W0-ABI: impl HookPort for HookAdapter lands with W1-L6.
impl HookAdapter {
    // W0-ABI: not in the IF (the IF names no adapter type); a minimal seam so the stub is warning-free. W1-L6
    // replaces it with the real constructor and state.
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }
}
