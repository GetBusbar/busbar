// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "../../tests/fixtures/neutral_export_plugin.rs"]
mod witness;
pub(crate) use witness::{door, NAME, STREAMS};
pub(crate) fn cdylib() -> std::path::PathBuf {
    crate::both_ways::example_cdylib("neutral_export_door")
}
