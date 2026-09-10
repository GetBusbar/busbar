// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `config_validate::secret_refs` in the scope its proofs expect.
#![allow(unused_imports)]

pub use busbar_core_config::config::RootCfg;
pub use busbar_core_config::config_validate::secret_refs::*;
#[path = "secret_ref_coverage.rs"]
mod secret_ref_coverage;
