// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "open_reason_plugins.rs"]
mod open_reason_plugins;

busbar_contract::export_door!(open_reason_plugins::store::door);
