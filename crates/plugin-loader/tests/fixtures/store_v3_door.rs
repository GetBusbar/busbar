// TRANSITIONAL (NO-TEST-PLUGINS, QUESTIONS CONF-SUITE-DEL): `busbar-store-memory`'s door DROPPED IN for store_money_acceptance's dropped leg (a money proof, kept); replaced when the money acceptance runs over an in-test store door or moves to store-memory's own suite run.
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The build's store, DROPPED IN on the store v3 table: the same `door` the compiled-in row holds,
//! behind the plugin shape's one `export_door!` line.

busbar_contract::export_door!(busbar_store_memory::door);
