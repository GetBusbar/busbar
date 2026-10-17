// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR MACRO'S SYMBOL BASELINE: a `cdylib` that links `busbar-contract` and invokes neither
//! `plugin_door!` nor `export_door!`. Whatever it exports, the contract exports; what
//! `sdk_door_plugin` exports beyond it is exactly what the macros emit (`tests/sdk_door_cdylib.rs`).

extern crate busbar_contract;
