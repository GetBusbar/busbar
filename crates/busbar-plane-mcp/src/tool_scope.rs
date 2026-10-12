// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SCOPE A `token_exchange:` REGISTRATION'S TOKEN IS ASKED FOR (ARCHITECT round 5
//! Q-L3B-EXCHANGE (B)): derived, never configured — a configured scope list would be a second
//! statement of what a caller may reach, and the wider would win.
//!
//! * [`caller_downscope`]: a relayed call's — exactly the tools the CALLER is granted on the
//!   member's server (its `mcp_tool` grants), and for a caller whose grant is a wildcard, exactly
//!   the one tool being called: a wildcard is the absence of a constraint on the inbound side and
//!   must not become a grant of everything on the outbound one (the previous release's
//!   `egress::downscope`).
//! * [`registration_scope`]: the door's own fetch's (verify-on-call, `connect`), which serves no
//!   caller — every tool the operator approved on the registration (the previous release's
//!   `connect::refresh_scope`).
//!
//! Both are sorted and deduplicated, so one grant asks for one scope string every time (an exchange
//! whose request varied by iteration order could neither be cached nor compared). The plane states
//! the scope on the request it hands the host (`abi::auth::SCOPE_REQUEST_FIELD`); the host carries
//! it into the member binding's auth call and the wire never sees it.

use crate::catalogue::Catalogue;
use crate::tools_config::McpServerDefCfg;

/// The down-scope of a call to the tool `called` (its published name on `server`, the member the
/// call is sent to), for a caller whose `mcp_tool` grant `granted` answers per published name, or
/// whose grant is a `wildcard`.
#[must_use]
pub fn caller_downscope(
    catalogue: &Catalogue,
    server: &str,
    called: &str,
    wildcard: bool,
    granted: &impl Fn(&str) -> bool,
) -> String {
    let mut scopes: Vec<&str> = if wildcard {
        vec![called]
    } else {
        catalogue
            .tools_for(&|kind: &str, name: &str| {
                if kind == crate::door::SCOPE {
                    name == server
                } else {
                    granted(name)
                }
            })
            .into_iter()
            .map(|t| t.namespaced.as_str())
            .collect()
    };
    scopes.sort_unstable();
    scopes.dedup();
    scopes.join(" ")
}

/// The scope of the door's own fetch from the registration `server` (`def`): every tool it approves
/// at a digest, `{server}_{tool}`.
#[must_use]
pub fn registration_scope(server: &str, def: &McpServerDefCfg) -> String {
    let mut scopes: Vec<String> = def
        .tools_allow
        .iter()
        .filter(|(_, allow)| {
            allow
                .schema_hash
                .as_deref()
                .is_some_and(|h| !h.trim().is_empty())
        })
        .map(|(tool, _)| format!("{server}_{tool}"))
        .collect();
    scopes.sort_unstable();
    scopes.dedup();
    scopes.join(" ")
}

/// Whether the registration `def` is bound to the token exchange: it states a `token_exchange:`
/// block and its credentials are not the caller's (a `passthrough` registration lends the caller's
/// own; the grammar refuses the two together).
#[must_use]
pub fn exchanges(
    def: &McpServerDefCfg,
    upstream: Option<busbar_contract::config::UpstreamCreds>,
) -> bool {
    def.token_exchange.is_some()
        && upstream != Some(busbar_contract::config::UpstreamCreds::Passthrough)
}

#[cfg(test)]
#[path = "tests/tool_scope.rs"]
mod tests;
