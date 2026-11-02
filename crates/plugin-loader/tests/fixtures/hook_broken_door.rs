// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "hook_door_plugin.rs"]
mod hook_door_plugin;

busbar_contract::export_door!(hook_door_plugin::broken::door);
