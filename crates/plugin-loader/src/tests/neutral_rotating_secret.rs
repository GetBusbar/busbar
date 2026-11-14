// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The rotating-credential secret witness compiled into the test binary, and its dropped image.

#[path = "../../tests/fixtures/neutral_rotating_secret_plugin.rs"]
mod witness;

pub(crate) use witness::{answer_for, door, CREDENTIAL, NAME, TICKED};

pub(crate) fn cdylib() -> std::path::PathBuf {
    crate::both_ways::example_cdylib("neutral_rotating_secret_door")
}
