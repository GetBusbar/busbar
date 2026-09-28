// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The open-reason store witness, DROPPED IN: the one source the test build compiles in as a
//! module, behind the plugin shape's one `export_door!` line.

#[path = "open_reason_plugins.rs"]
mod open_reason_plugins;

busbar_contract::export_door!(open_reason_plugins::store::door);
