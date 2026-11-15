// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export adapter: `ExportPort` over the export kind's `Proxy` (IF §11.3). W0-ABI stub: the adapter type only;
//! L7 fills it.

use busbar_plugin_abi::kinds::export::export::Proxy;

/// The export port over one instance's proxy.
pub struct ExportAdapter {
    proxy: Proxy,
}

// W0-ABI: the ten-stream const block (STREAM_* == `busbar_contract::export_stream::ExportStream as u32` for all 10,
// `ALL.len() == STREAM_COUNT`) lands with W1-L7, after W1-K8C adds `ExportStream::Content`.

// W0-ABI: impl ExportPort for ExportAdapter lands with W1-L7.
impl ExportAdapter {
    // W0-ABI: not in the IF (the IF names no adapter type); a minimal seam so the stub is warning-free. W1-L7
    // replaces it with the real constructor and state.
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }
}
