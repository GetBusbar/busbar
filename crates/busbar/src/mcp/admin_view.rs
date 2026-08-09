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

// ── THE TRUST SURFACE: `connect`, `changes`, `health` ───────────────────────────────────────────
//
// These projections live here rather than beside the other sections' in `admin::v1::service` for
// the reason the header gives, and for a second one: that file is near its size cap and a plane's
// own vocabulary does not belong in the generic service anyway.
//
// Every value below is DERIVED on read from the operator's standing approval and the last sighting.
// Nothing here stores a state, and nothing here takes a transition — the transitions are
// `crate::trust`'s and this is the window onto them.

/// ONE CAPABILITY'S STANDING STATUS, the three-way answer a trust view has to render.
///
/// Three and not two: `approved at a digest`, `rejected`, and `allowed but never ruled on`. The
/// third is `pending` and it is the one a queue exists to drain, so collapsing it into "not
/// approved" would hide the operator's whole worklist.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct McpCapabilityView {
    /// The bare tool name, as the upstream spells it.
    pub(crate) tool: String,
    /// `approved`, `rejected` or `pending`.
    pub(crate) status: &'static str,
    /// The digest the operator approved, when there is one. A rejected or pending capability has
    /// none, and reporting the last OBSERVED digest here would read as an approval.
    pub(crate) approved_digest: Option<String>,
}

/// THE TRUST VIEW of one registered MCP server — `POST /tools/{name}/connect` and
/// `GET /tools/{name}/changes` answer with this.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct McpTrustView {
    pub(crate) name: String,
    /// `pending`, `approved`, `quarantined`, `suspended` or `error`. DERIVED from the approval and
    /// the last sighting on every read, so there is no stored state to go stale.
    pub(crate) state: &'static str,
    /// The operator's word for the authenticity root. Never interpreted by the machine.
    pub(crate) pin_mechanism: &'static str,
    /// The presented identity is not the locked one. Its own axis: adopting a new identity is a
    /// different act from adopting new content.
    pub(crate) pin_changed: bool,
    /// Offered now, never ruled on.
    pub(crate) added: Vec<String>,
    /// Approved, but offered at a DIFFERENT digest. THIS IS THE RUG-PULL ROW.
    pub(crate) changed: Vec<String>,
    /// Approved, and no longer offered.
    pub(crate) removed: Vec<String>,
    /// How many tools the last successful observation carried.
    pub(crate) observed_tools: usize,
    /// Why the last contact failed, when it did.
    pub(crate) failure: Option<String>,
    /// Every capability's standing status, in name order.
    pub(crate) capabilities: Vec<McpCapabilityView>,
}

/// THE HEALTH VIEW — `GET /tools/{name}/health`. Deliberately smaller than the trust view: health
/// answers "can busbar use this server right now, and if not why", and a dashboard polling it should
/// not be re-rendering the whole changes queue to find out.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct McpHealthView {
    pub(crate) name: String,
    pub(crate) state: &'static str,
    /// Whether this server currently SERVES: `state == approved`. Named separately from `state`
    /// because it is the one bit a caller usually wants and deriving it from a word is how a client
    /// ends up hard-coding a spelling.
    pub(crate) serving: bool,
    /// `false` until a refresh has ever landed. A server that has never been contacted is not
    /// unhealthy, and reporting it as such would page somebody for a declarative deployment.
    pub(crate) contacted: bool,
    pub(crate) failure: Option<String>,
    pub(crate) observed_tools: usize,
}

/// Project a connect/refresh report and the server's standing approval onto the trust view.
pub(crate) fn trust_view(
    report: &crate::mcp::connect::ConnectReport,
    server: &crate::mcp::catalogue::ServerEntry,
    cfg: &crate::mcp::config::McpServerDefCfg,
) -> McpTrustView {
    McpTrustView {
        name: report.server.clone(),
        state: report.state_word(),
        pin_mechanism: server.pin_mechanism,
        pin_changed: report.drift.pin_changed,
        added: report.drift.added.clone(),
        changed: report.drift.changed.clone(),
        removed: report.drift.removed.clone(),
        observed_tools: report.observed,
        failure: report.failure.clone(),
        capabilities: capability_views(server, cfg),
    }
}

/// Project a report onto the health view.
pub(crate) fn health_view(report: &crate::mcp::connect::ConnectReport) -> McpHealthView {
    McpHealthView {
        name: report.server.clone(),
        state: report.state_word(),
        serving: report.state == crate::trust::TrustState::Approved,
        contacted: report.observed > 0 || report.failure.is_some(),
        failure: report.failure.clone(),
        observed_tools: report.observed,
    }
}

/// Every capability's standing status, in name order.
///
/// The union of what the approval has ruled on and what the registration allows, because those are
/// two different sets and the difference between them IS the pending queue: a tool the operator
/// allowed in config and approved no digest for is absent from the approval entirely.
fn capability_views(
    server: &crate::mcp::catalogue::ServerEntry,
    cfg: &crate::mcp::config::McpServerDefCfg,
) -> Vec<McpCapabilityView> {
    use crate::trust::CapabilityApproval;
    let mut out: std::collections::BTreeMap<String, McpCapabilityView> =
        std::collections::BTreeMap::new();
    for (tool, capability) in server.approval.capabilities() {
        let (status, approved_digest) = match capability {
            CapabilityApproval::At(digest) => ("approved", Some(digest.clone())),
            CapabilityApproval::Rejected => ("rejected", None),
        };
        out.insert(
            tool.to_string(),
            McpCapabilityView {
                tool: tool.to_string(),
                status,
                approved_digest,
            },
        );
    }
    // The PENDING rows: allowed by the registration, never ruled on. Inserted only where the
    // approval has no entry, so a rejection can never be overwritten by the allow-list it was a
    // refusal of.
    for tool in cfg.tools_allow.keys() {
        out.entry(tool.clone())
            .or_insert_with(|| McpCapabilityView {
                tool: tool.clone(),
                status: "pending",
                approved_digest: None,
            });
    }
    out.into_values().collect()
}
