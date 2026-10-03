// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PUBLISHED 1.5.5 JSON-CONTRACT PLUGIN, reduced to its entry: the one symbol every 1.5.5 loader
//! looked up first, `busbar_abi` (v1.5.5 `crates/plugin-abi/src/lib.rs`, `symbol::ABI`), answering
//! the 1.5.5 mechanism version (`TRANSPORT_VERSION`, 1), and no `busbar_plugin_door`. The one loader
//! must refuse it as a 1.5.5 JSON-contract plugin, naming the rebuild against the 1.6.0 SDK (THE
//! DESIGN §11.8; TODO ABI-b6). It depends on nothing: the refusal is read off the symbols alone and
//! no code in it ever runs. An example, not a crate: `cargo test` builds it and it never ships.

/// The 1.5.5 handshake: the mechanism version v1.5.5 shipped.
#[no_mangle]
pub extern "C" fn busbar_abi() -> u32 {
    1
}
