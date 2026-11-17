// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::ffi_thread`.

/// Boot: names the new FFI worker thread the pool grows by.
#[cold]
pub(crate) fn worker_builder() -> std::thread::Builder {
    std::thread::Builder::new().name("busbar-plugin-ffi".to_string())
}
