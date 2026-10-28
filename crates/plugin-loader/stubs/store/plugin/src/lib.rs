// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **in-memory store as a droppable busbar plugin**: the `cdylib` a signed tarball of the store
//! carries (`kind: store`, key `memory`). The logic crate is re-exported whole, and its door
//! (`busbar_store_memory::door`) is this image's ONE symbol, `busbar_plugin_door`, under this
//! crate's `dropped-in` feature, which switches on the logic crate's own `export_door!`
//! (`busbar_store_memory::door_export`). The door is exported in ONE place, so the library carries
//! exactly the door a busbar build links, and no build defines the symbol twice.
//!
//! No `unsafe` code lives in this crate: the export macro's `#[unsafe(no_mangle)]` item is the
//! logic crate's, in the one module it allows it in.

#![forbid(unsafe_code)]

pub use busbar_stub_store::*;
