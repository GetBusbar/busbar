// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: store` plugin** — a `cdylib` exporting the store C ABI, wrapping the
//! in-tree `MemoryStore`. It is the in-tree ABI-crossing coverage for the `kind: store` seam (the
//! store-seam analogue of `busbar-secret-example-plugin`). It does no real persistence beyond
//! `MemoryStore`'s own in-process map; its
//! job is to be a real, loadable, signable store plugin for the ABI to round-trip through, both in
//! this crate's own boundary tests and as the fixture `plugin-ci.yml`'s install-and-serve CI step
//! packs and installs against a real running busbar.

use busbar_api::Store;
use busbar_store_memory::MemoryStore;

/// Construct the module. No config is read (the wrapped `MemoryStore` takes none); malformed JSON in
/// `cfg` is accepted and ignored rather than a load error, since there is nothing in this plugin's
/// config shape that could be malformed — this mirrors `busbar-auth-static-plugin`'s posture for a
/// config-less module, not `busbar-secret-example-plugin`'s (which has a real config to validate).
fn open(_cfg: &str) -> Result<Box<dyn Store>, String> {
    Ok(Box::new(MemoryStore::new()))
}

busbar_plugin_sdk::export_store_plugin!(open);
