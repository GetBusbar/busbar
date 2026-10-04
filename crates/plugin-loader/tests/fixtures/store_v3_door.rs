// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The build's store, DROPPED IN on the store v3 table: the same `door` the compiled-in row holds,
//! behind the plugin shape's one `export_door!` line. The store is reached BY KIND: `build.rs`
//! writes the line from the `[package.metadata.busbar.both-ways] store` row.

include!(concat!(env!("OUT_DIR"), "/store_door.rs"));
