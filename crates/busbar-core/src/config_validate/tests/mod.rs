// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VALIDATOR'S PROOFS, hosted in the engine's test binary at their unmoved paths — see
//! `config/tests/mod.rs` for why the config layer's tests stay here when the layer itself left.

#![allow(unused_imports)]

pub use busbar_core_config::config::{DeployCfg, GroupCfg, HookCfg, RootCfg};
pub use std::collections::{BTreeMap, HashMap, HashSet};

pub use busbar_core_config::config_validate::*;
// The alternate-IPv4 expander moved to the substrate with the guards; its unit tests still name it
// through this scope.
pub use busbar_substrate::net_guard::expand_alternate_ipv4;

#[path = "tests.rs"]
mod tests;

/// `config_validate::secret_refs`'s proofs, in the scope the file expects.
#[path = "secret_refs_scope.rs"]
mod secret_refs_scope;
