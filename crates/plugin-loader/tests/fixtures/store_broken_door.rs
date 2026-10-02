// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store kind's both-ways fixture (broken), DROPPED IN: the one source the test build compiles
//! in as a module, behind the plugin shape's one `export_door!` line.

#[path = "store_broken_plugin.rs"]
mod store_broken_plugin;

busbar_contract::export_door!(store_broken_plugin::door);
