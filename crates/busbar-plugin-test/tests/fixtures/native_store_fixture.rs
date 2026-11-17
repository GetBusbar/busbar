// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's MIN-3 store fixture as a cdylib: the `native_store` body, exported.

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

mod native_store;

busbar_plugin_abi::export!(native_store::PLUGIN);
