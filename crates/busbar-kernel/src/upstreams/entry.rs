// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One `upstreams.<name>` entry typed into an [`UpstreamDef`] (IF §12.1, §12.18 upstream bindings).
//!
//! The entry is core config: an operator writes it, and a 1.5.x plane's `migrate` hands its members over as
//! CORE_CFG(UPSTREAM) fragments in the same grammar (§12.10). The `auth` and `upstream_credentials` keys are the
//! config grammar's ([`UpstreamCfg`], W1-K7); this module types the rest and applies the rules that moved to core
//! with the stdio command (plane-mcp tools_config.rs `validate_endpoint`/`validate_local_program`):
//!
//! ```yaml
//! upstreams:
//!   <name>:
//!     url: https://agent.example/a2a          # a network upstream, or
//!     command:                                # a stdio upstream core spawns
//!       argv: [/opt/mcp/server, --flag]       # argv[0] absolute, never resolved through PATH
//!       env: {API_KEY: <secret ref>}          # resolved through custody at spawn
//!       cwd: /srv/mcp                         # absolute; absent = inherit busbar's
//!       pin: {mechanism: local_program, key: /opt/mcp/server}   # or {mechanism: unpinned}; absent = unpinned
//!       idle_s: 300
//!     tls:                                    # network upstreams over https:// only
//!       pin_spki: [sha256:<64 hex>]           # any match passes
//!       client_identity: <secret ref>         # PEM chain + key presented as the client certificate
//!       trust: <PEM>                          # an operator CA for this upstream only
//!     auth: ...                               # config grammar (W1-K7), resolved by W1-K6
//!     upstream_credentials: ...               # config grammar (W1-K7), checked by W1-K6
//! ```
//!
//! Every refusal is core text naming `upstreams.<name>` and the key, and never repeats a URL's userinfo or a
//! secret value (URLs are shown through `abi::host::scrub::mask_url`).

use std::sync::Arc;

use serde_json::Value;

use super::{UpstreamAuth, UpstreamDef};
use crate::config::min3::{UpstreamAuthCfg, UpstreamCfg};
use crate::plugin_config::TrustAnchor;

/// A stdio child's idle time before core closes it, when `command.idle_s` is absent (IF §12.4 channels).
pub const DEFAULT_IDLE_S: u64 = 300;
/// The longest upstream name: the CORE_CFG name grammar `[a-z0-9_.-]{1,64}` (§3 `CoreCfgRec`).
pub const MAX_NAME: usize = 64;

/// The implicit outbound auth instance W1-K6 opens for an upstream whose `auth` is a core-vocabulary form
/// (`auth.upstream-<name>-outbound`, §12.18): its configured name.
pub fn implicit_instance(upstream: &str) -> Box<str> {
    let _ = upstream;
    todo!("W1-K1")
}

impl UpstreamDef {
    /// Types the `upstreams.<name>` entry `entry` over the keys the config grammar parsed for it (`cfg`).
    pub fn from_config(
        name: &str,
        entry: &Value,
        cfg: &UpstreamCfg,
        anchor: &dyn Fn(&str) -> Result<Arc<TrustAnchor>, String>,
    ) -> Result<Self, Vec<String>> {
        let _ = (name, entry, cfg, anchor);
        todo!("W1-K1")
    }
}

impl UpstreamAuth {
    /// The binding `upstreams.<name>.auth` names, before W1-K6 resolves it (§12.18).
    pub fn from_config(upstream: &str, cfg: &UpstreamAuthCfg) -> Self {
        let _ = (upstream, cfg);
        todo!("W1-K1")
    }
}
