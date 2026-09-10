// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `config::named_map` in the scope its proofs expect.
#![allow(unused_imports)]

pub use busbar_core_config::config::named_map::*;
pub use busbar_core_config::config::{DeployCfg, ExportDefCfg, IdentityProviderCfg};
#[path = "named_map_tests.rs"]
mod named_map_tests;
