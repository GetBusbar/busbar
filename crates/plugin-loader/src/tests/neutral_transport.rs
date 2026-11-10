// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
#[path = "../../tests/fixtures/neutral_transport_plugin.rs"]
mod witness;
pub(crate) use witness::{door, framer, CLAIM};
pub(crate) fn cdylib() -> std::path::PathBuf {
    crate::both_ways::example_cdylib("neutral_transport_door")
}
