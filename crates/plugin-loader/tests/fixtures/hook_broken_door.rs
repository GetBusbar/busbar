// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook kind's both-ways fixture (broken), DROPPED IN: the one source the test build compiles
//! in as a module, behind the plugin shape's one `export_door!` line.

#[path = "hook_door_plugin.rs"]
mod hook_door_plugin;

busbar_contract::export_door!(hook_door_plugin::broken::door);
