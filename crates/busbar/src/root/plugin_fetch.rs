// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.fetch` DOWNLOAD, WIRED: the connector's download
//! (`busbar_core_connector::fetch`) over the process's one connector, under the root's own identity
//! ([`crate::root::connector::ROOT_OWNER`]; `NeedId(0)` there is the authorization server's, the
//! download rides `NeedId(1)` for a secured URL and `NeedId(2)` for a plaintext one).

use std::sync::Arc;

use busbar_contract::conn::{DeclaredConns, NeedId, PollConns};
use busbar_core_connector::fetch::{self, Table};

/// The process's one connector, under the root's own identity.
fn the_table() -> Table {
    let one = crate::root::connector::the();
    Table {
        owner: crate::root::connector::ROOT_OWNER,
        secured_need: NeedId(1),
        plain_need: NeedId(2),
        declared: Arc::clone(one) as Arc<dyn DeclaredConns>,
        conns: Arc::clone(one) as Arc<dyn PollConns>,
    }
}

/// The `plugins.fetch` download the root's fetch hands the loader: through the process's one
/// connector, under the operator's extra metadata denylist `blocked`, capped at
/// `config::DEFAULT_PLUGIN_FETCH_MAX_BYTES`.
pub fn downloader(blocked: &[String]) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    let blocked: Vec<String> = blocked.to_vec();
    move |url: &str| {
        fetch::download(
            &the_table(),
            url,
            &blocked,
            busbar_kernel::config::DEFAULT_PLUGIN_FETCH_MAX_BYTES,
        )
    }
}
