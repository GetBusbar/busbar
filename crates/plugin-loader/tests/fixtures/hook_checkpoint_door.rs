// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "hook_checkpoint_plugin.rs"]
mod hook_checkpoint_plugin;

busbar_contract::export_door!(hook_checkpoint_plugin::door);
