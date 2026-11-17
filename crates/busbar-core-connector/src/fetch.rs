// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.fetch` DOWNLOAD (BUSBAR-1.6.0.md THE DESIGN §3 boot stage 3c,

use std::sync::Arc;

use busbar_contract::conn::{DeclaredConns, InstanceId, NeedId, PollConns};

// The download itself runs once, at boot stage 3c: it lives off the request path.
pub use crate::off_path::egress::fetch::download;

/// The connection table a download rides: whose need, the need its URL rides (https only, SEC-2 /
/// #297: there is no plaintext download), where it is declared, where it is opened and read.
#[derive(Clone)]
pub struct Table {
    /// The identity the download's needs are declared and opened under.
    pub owner: InstanceId,
    /// The need a (secured) download URL rides.
    pub secured_need: NeedId,
    /// Where the needs are declared.
    pub declared: Arc<dyn DeclaredConns>,
    /// Where the connection is opened and read.
    pub conns: Arc<dyn PollConns>,
}

impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Table")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}
