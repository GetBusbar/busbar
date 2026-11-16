// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret port (IF §11.3) and `SugarDecl` (IF §11.2, defined with the ports per §8.8).

use std::sync::Arc;

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::BoxFut;

use crate::{CallCx, PortError};

// The IF types `value` as `zeroize::Zeroizing<Vec<u8>>`; the workspace bans `Zeroizing` crate-wide
// (clippy-crate-wide/clippy.toml, owner 2026-11-14), so the stub uses its named replacement `SecureVec`.
pub struct SecretAnswer {
    pub value: SecureVec,
    pub lease_s: Option<u64>,
}

pub trait SecretPort: Send + Sync + 'static {
    fn resolve<'a>(
        &'a self,
        cx: CallCx,
        reference: &'a [u8],
    ) -> BoxFut<'a, Result<SecretAnswer, PortError>>;
}

/// One D_SUGAR item (§8.2), tagged with the declaring plugin's verified identity (core-internal; never shown to
/// any plugin).
#[derive(Clone)]
pub struct SugarDecl {
    pub identity: Arc<str>,
    pub role: u32,
    pub alias: bool,
    pub word: Box<str>,
    pub key: Box<str>,
    pub shown: Box<str>,
    pub names: Box<str>,
}
