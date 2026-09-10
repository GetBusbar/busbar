// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `config::patch` in the scope its proofs expect.
#![allow(unused_imports)]
pub use busbar_core_config::config::patch::*;
#[path = "entry_patch_tests.rs"]
mod entry_patch_tests;
#[path = "patch_tests.rs"]
mod tests;
