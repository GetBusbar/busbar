// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The config binder: secret, trust, dest and reference bindings of one instance's operator config (IF §12.7).
//! The frozen types and the trait are below; [`Binder`] (binder.rs) is core's one implementation of the trait.

mod binder;
mod pem;
mod pointer;
#[cfg(test)]
mod tests;

pub use binder::{Binder, RefSource, MAX_BINDINGS, MAX_UNIX_PATHS};

use busbar_plugin_abi::host_side::caller::BoxFut;

/// One instance's bindings. Index 0 is unused (handle 0 = none); handles are 1-based, ≤ 65,535.
/// Round 13: `refs` = (JSON Pointer of the concrete node, reference) for every D_REF_PATH node written as a reference.
pub struct Bindings {
    pub secrets: Vec<busbar_contract::secret_ref::SecretRef>,
    pub trust: Vec<TrustAnchor>,
    pub dests: Vec<std::sync::Arc<DestDef>>,
    pub refs: Vec<(Box<str>, busbar_contract::secret_ref::SecretRef)>,
}

// ROOT-BOOT: the interface is the loader's (IF §12.7, round 35 R7b): `Registry::new` names it and the Need
// handlers take it, so there is one `ConfigBinder`, and this module re-exports it with its types.
pub use busbar_plugin_loader::binder::{BindError, ConfigBinder, DestDef, TrustAnchor};
