// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The same SDK witness linked into the host and built as a separate native image.
#[path = "../../tests/fixtures/neutral_plane_plugin.rs"]
mod witness;
pub(crate) use witness::{door, MACRO_DOOR, NAME, SECTION};
pub(crate) fn cdylib() -> std::path::PathBuf {
    crate::both_ways::example_cdylib("neutral_plane_door")
}
