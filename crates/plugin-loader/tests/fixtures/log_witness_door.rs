// TRANSITIONAL (NO-TEST-PLUGINS, QUESTIONS CONF-SUITE-DEL): the DROPPED half of the plugin-logging witness (a separate image's own `tracing`/`log` copies); no in-test replacement without a binary.
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-logging witness, DROPPED IN: the one source the test build compiles in as a module,
//! behind the plugin shape's one `export_door!` line.

#[path = "log_witness_plugin.rs"]
mod log_witness_plugin;

busbar_contract::export_door!(log_witness_plugin::a::door);
