// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The in-tree HTTP-calling hook (`http_hook_plugin.rs`) as a droppable `kind: hook` cdylib, for
//! core's tests that drive a hook over a real HTTP target.

#[path = "http_hook_plugin.rs"]
pub mod http_hook_plugin;

busbar_contract::export_door!(http_hook_plugin::door);
