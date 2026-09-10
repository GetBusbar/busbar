// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `config::overlay` in the scope its proofs expect.
#![allow(unused_imports)]

pub use busbar_core_config::config::overlay::*;
pub use busbar_core_config::config::*;
pub use std::collections::{BTreeMap, HashMap};
pub use std::path::{Path, PathBuf};
#[path = "config_consolidation_tests.rs"]
mod config_consolidation_tests;
#[path = "overlay_read_only_tests.rs"]
mod overlay_read_only_tests;
#[path = "overlay_tests.rs"]
mod tests;
#[path = "version_gate_tests.rs"]
mod version_gate_tests;
