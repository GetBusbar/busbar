// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "log_witness_plugin.rs"]
mod log_witness_plugin;

busbar_contract::export_door!(log_witness_plugin::a::door);
