// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret kind's both-ways fixture (broken), DROPPED IN: the one source the test build compiles
//! in as a module, behind the plugin shape's one `export_door!` line.

#[path = "secret_door_plugin.rs"]
mod secret_door_plugin;

busbar_contract::export_door!(secret_door_plugin::broken::door);
