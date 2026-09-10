// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `config::migrate` in the scope its proofs expect.
#![allow(unused_imports)]

pub use busbar_core_config::config::migrate::*;
pub use serde_yaml::{Mapping, Value};
#[path = "migrate_tests.rs"]
mod tests;
