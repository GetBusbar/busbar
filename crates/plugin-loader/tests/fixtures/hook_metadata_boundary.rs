// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(test)]
use crate::hook_door_conformance_tests::hook_door_plugin;

#[cfg(not(test))]
#[path = "hook_door_plugin.rs"]
mod hook_door_plugin;

// The same SDK lifecycle and route declaration are compiled independently in
// the linked test and dropped image. No product supplies this loader witness.
pub use hook_door_plugin::conforming::door;

#[cfg(not(test))]
busbar_contract::export_door!(door);
