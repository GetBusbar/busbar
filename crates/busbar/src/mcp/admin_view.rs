// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE'S ADMIN PROJECTION — one `tools:` entry as the shared named-definition view.
//!
//! It lives with the plane rather than beside the other sections' projections in
//! `admin::v1::service`, for the reason `docs/code-layout.md` gives: the thing a reader is looking
//! for when they ask "what does the admin API say about an MCP server" is MCP, and this is where
//! every other answer about MCP already is. The generic CRUD handler, the overlay persistence and
//! the OpenAPI emission stay entirely generic and know nothing about this file.

use crate::admin::v1::contract::NamedDefView;

/// Project one `tools:` entry — one registered MCP server — onto the shared named-definition view.
///
/// `module` carries the PIN MECHANISM rather than a plugin name, and that is the honest projection
/// rather than a hack: an MCP server has no backing plugin (see
/// [`crate::config::named_map::NamedMapSection::requires_module`]), and the field a UI renders as
/// "what is behind this entry" is, for a remote endpoint, the authenticity root it is bound to. An
/// empty string there would render as a blank column on the one screen an operator uses to spot an
/// `unpinned` registration.
///
/// `settings_keys` carries the APPROVED CAPABILITY NAMES, sorted. Names only, never their hashes or
/// schemas — same rule the settings-bag projection follows and for the same reason: this surface is
/// reachable at read-only scope. The full detail is the `GET` of the definition itself.
pub(crate) fn mcp_server_view(
    name: &str,
    cfg: &crate::mcp::config::McpServerDefCfg,
) -> NamedDefView {
    let mut keys: Vec<String> = cfg
        .tools_allow
        .keys()
        .chain(cfg.prompts_allow.keys())
        .chain(cfg.resources_allow.keys())
        .cloned()
        .collect();
    keys.sort();
    keys.dedup();
    NamedDefView {
        name: name.to_string(),
        module: cfg.pin.mechanism.token().to_string(),
        settings_keys: keys,
        max_admin_scope: None,
        token_configured: None,
        browser_login_configured: None,
        // THE A2A PLANE'S TRUST COLUMNS, absent here rather than filled in, and that is a merge
        // decision rather than an omission. `agents:` added `pin_mechanism`/`fingerprint_pinned`/
        // `reverify_ttl` to this shared view; this projection predates them and already answers the
        // mechanism question through `module` above. Populating them here as well would put one
        // fact in two fields of one response, and which one a reader trusts would be undefined.
        // Converging the two projections on the typed columns is a change to THIS plane's wire
        // shape and belongs to that plane's owner, not to the merge that made it possible.
        pin_mechanism: None,
        fingerprint_pinned: None,
        reverify_ttl: None,
        unparseable: None,
    }
}

/// Every registered MCP server, as the shared named-definition view. The read half of
/// `GET /api/v1/admin/tools`.
pub(crate) fn list(app: &crate::state::App) -> Vec<NamedDefView> {
    app.mcp_servers
        .servers
        .iter()
        .map(|(name, cfg)| mcp_server_view(name, cfg))
        .collect()
}

/// One registered MCP server, or `None`. The read half of `GET /api/v1/admin/tools/{name}`.
pub(crate) fn get(app: &crate::state::App, name: &str) -> Option<NamedDefView> {
    app.mcp_servers
        .servers
        .get(name)
        .map(|cfg| mcp_server_view(name, cfg))
}
