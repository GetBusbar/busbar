// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One SDK witness compiled into the test binary and its independent dropped image.

#[path = "../../tests/fixtures/neutral_auth_plugin.rs"]
mod witness;

pub(crate) use witness::{door, NAME};

pub(crate) fn cdylib() -> std::path::PathBuf {
    crate::both_ways::example_cdylib("neutral_auth_door")
}
