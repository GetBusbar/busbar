// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The build's store, DROPPED IN on the store v3 table: the same `door` the compiled-in row holds,
//! behind the plugin shape's one `export_door!` line.

/// The build's store, reached by KIND: `Cargo.toml`'s `[package.metadata.busbar.both-ways]` row
/// `store`, alone (`build.rs` writes `fixture_store.rs`), so this door links that one fixture.
mod fixture {
    include!(concat!(env!("OUT_DIR"), "/fixture_store.rs"));
}

busbar_contract::export_door!(fixture::store_fixture::door);
