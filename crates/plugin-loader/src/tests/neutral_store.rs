// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The same SDK STORE witness linked directly and loaded as an independent image.
#[path = "../../tests/fixtures/neutral_store_plugin.rs"]
mod witness;
pub(crate) use witness::door;

pub(crate) fn path() -> std::path::PathBuf {
    crate::both_ways::example_cdylib("neutral_store_door")
}
pub(crate) fn settings() -> Vec<u8> {
    br#"{"witness":"settings-crossing"}"#.to_vec()
}
