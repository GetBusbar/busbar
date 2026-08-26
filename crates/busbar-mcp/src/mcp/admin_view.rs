// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE'S ADMIN PROJECTION — one `tools:` entry as the shared named-definition view.
//!
//! It lives with the plane rather than beside the other sections' projections in
//! `admin::v1::service`, for the reason `docs/code-layout.md` gives: the thing a reader is looking
//! for when they ask "what does the admin API say about an MCP server" is MCP, and this is where
//! every other answer about MCP already is. The generic CRUD handler, the overlay persistence and
//! the OpenAPI emission stay entirely generic and know nothing about this file.
//!
//! ## THE TRUST VERBS live here too, and this is where the plane's half of them stops
//!
//! `connect` is NOT here. It is [`busbar_core::admin::planeverbs::connect`], written once and
//! parameterised by plane, because "resolve the registration, go and look, audit whatever you
//! found" is one sequence and it was written down twice. What this file supplies is the plane's
//! half of that contract — [`McpServers`], which says where an MCP registration is resolved from
//! and what looking at one means — plus the two verbs that contact NOTHING:
//!
//! - `GET /tools/{name}/changes` — the trust view, computed from the LAST observation. Safe to poll.
//! - `GET /tools/{name}/health` — can busbar use this server right now, and if not, why.
//!
//! Those two are `GET`s that read the recorded sighting, so they have no shared sequence to belong
//! to: there is no upstream contact to audit and nothing that can change a trust state. A plane's
//! own derived reads staying with the plane's own views is the layout rule working, not an exception
//! to the unification.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use busbar_core::admin::planeverbs::{self, PlaneTrust};
use busbar_core::admin::v1::contract::{AdminError, NamedDefView};
use busbar_core::state::AppHandle;

/// Project one `tools:` entry — one registered MCP server — onto the shared named-definition view.
///
/// `module` carries the PIN MECHANISM rather than a plugin name, and that is the honest projection
/// rather than a hack: an MCP server has no backing plugin (see
/// [`busbar_core::config::named_map::NamedMapSection::requires_module`]), and the field a UI renders as
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
pub(crate) fn list(app: &busbar_core::state::App) -> Vec<NamedDefView> {
    super::runtime(app)
        .servers
        .servers
        .iter()
        .map(|(name, cfg)| mcp_server_view(name, cfg))
        .collect()
}

/// One registered MCP server, or `None`. The read half of `GET /api/v1/admin/tools/{name}`.
pub(crate) fn get(app: &busbar_core::state::App, name: &str) -> Option<NamedDefView> {
    super::runtime(app)
        .servers
        .servers
        .get(name)
        .map(|cfg| mcp_server_view(name, cfg))
}

/// Attach the MCP trust verbs' typed success-body schemas — the MCP half of
/// [`busbar_core::plane::registry::PlaneDecl::openapi_schemas`]. Registers `McpTrustView`/`McpHealthView`
/// into the SHARED response generator and attaches their `$ref`s onto the paths this plane's
/// `openapi()` fragment inserted, byte-identically to the inline `typed!` calls it replaced (same
/// types, same order, same generator).
#[cfg(feature = "openapi-schema")]
pub(crate) fn openapi_schemas(
    schema_gen: &mut schemars::SchemaGenerator,
    _req_gen: &mut schemars::SchemaGenerator,
    paths: &mut serde_json::Map<String, serde_json::Value>,
) {
    use busbar_core::admin::v1::json::ap;
    use busbar_core::admin::v1::json::set_response_schema;
    let connect = serde_json::to_value(schema_gen.subschema_for::<McpTrustView>())
        .unwrap_or_else(|_| serde_json::json!({}));
    set_response_schema(paths, &ap("/tools/{name}/connect"), "post", "200", connect);
    let changes = serde_json::to_value(schema_gen.subschema_for::<McpTrustView>())
        .unwrap_or_else(|_| serde_json::json!({}));
    set_response_schema(paths, &ap("/tools/{name}/changes"), "get", "200", changes);
    let health = serde_json::to_value(schema_gen.subschema_for::<McpHealthView>())
        .unwrap_or_else(|_| serde_json::json!({}));
    set_response_schema(paths, &ap("/tools/{name}/health"), "get", "200", health);
}

/// Is `name` a live registered MCP server on this snapshot — the membership check the admin write
/// path consults through the plane's `registry_contains` seam, so core names no `crate::mcp` runtime
/// type.
pub(crate) fn contains(
    slots: &dyn busbar_substrate::plane_host::PlaneSlots,
    name: &str,
) -> bool {
    super::runtime_slots(slots).servers.servers.contains_key(name)
}

/// RE-RESOLVE THE MCP PLANE'S PER-SERVER HOOK GATES against the next snapshot — the MCP half of the
/// config-swap gate rebuild, moved HERE so `admin::v1::service::reresolve_plane_gates` names no
/// `crate::mcp` runtime type. Reads this plane's own registry off the snapshot and writes its own
/// gate field back.
pub(crate) fn reresolve_gates(
    next: &mut dyn busbar_substrate::plane_host::ContainerGateSink,
) {
    // Read this plane's own registry off the neutral slot seam (owned `Arc` clone, so the immutable
    // borrow ends before the `&mut` store), then resolve-and-store host-side through the neutral sink
    // under the MCP gate key (`0`) — so this plane names neither `&mut App` nor the core container-gate
    // resolver. Byte-identical to the old inline `next.mcp_server_gates = next.resolve_container_gates(...)`.
    let servers = std::sync::Arc::clone(&super::runtime_slots(next).servers);
    let containers: Vec<(&str, &[String])> = servers
        .servers
        .iter()
        .map(|(n, d)| (n.as_str(), d.hooks.as_slice()))
        .collect();
    next.reresolve_container_gates(0, &containers, &servers.all_server_hooks);
}

// ── THE TRUST SURFACE: `connect`, `changes`, `health` ───────────────────────────────────────────
//
// These projections live here rather than beside the other sections' in `admin::v1::service` for
// the reason the header gives, and for a second one: that file is near its size cap and a plane's
// own vocabulary does not belong in the generic service anyway.
//
// Every value below is DERIVED on read from the operator's standing approval and the last sighting.
// Nothing here stores a state, and nothing here takes a transition — the transitions are
// `busbar_substrate::trust`'s and this is the window onto them.

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
        serving: report.state == busbar_substrate::trust::TrustState::Approved,
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
    use busbar_substrate::trust::CapabilityApproval;
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

// ══ THE TRUST VERBS: this plane's half of the ONE surface in `busbar_core::admin::planeverbs` ══════════

/// Everything the MCP look needs, cloned out of the live snapshot.
///
/// Both halves are required and a missing EITHER is the same `404`. The catalogue ENTRY carries the
/// standing approval; the config DEFINITION carries the allow-list the pending rows come from. A
/// server present in one and absent from the other is not a state the build can produce, so
/// distinguishing them in the refusal would tell a caller which names exist and nothing else.
pub(crate) struct McpSubject {
    entry: crate::mcp::catalogue::ServerEntry,
    cfg: crate::mcp::config::McpServerDefCfg,
    pool: Arc<crate::mcp::client::pool::McpConnectionPool>,
    sightings: Arc<crate::mcp::client::catalogue::CatalogueCache>,
}

/// THE MCP PLANE'S TRUST SURFACE. Three items, and the surface owns everything else.
pub(crate) struct McpServers;

impl PlaneTrust for McpServers {
    const PLANE: &'static str = "mcp";
    type Subject = McpSubject;
    type View = McpTrustView;

    fn resolve(
        host: &Arc<dyn busbar_substrate::plane_host::EngineHost>,
        name: &str,
    ) -> Result<McpSubject, AdminError> {
        // The bound-snapshot runtime, read once off the neutral host seam (K1) — byte-identical to the
        // four `super::runtime(app)` reads it replaced, all off the one admitted snapshot.
        let rt = super::runtime_of(host);
        planeverbs::registered("mcp", name, || {
            match (rt.catalogue.server(name), rt.servers.servers.get(name)) {
                (Some(entry), Some(cfg)) => Some(McpSubject {
                    entry: entry.clone(),
                    cfg: cfg.clone(),
                    pool: rt.pool.clone(),
                    sightings: rt.sightings.clone(),
                }),
                _ => None,
            }
        })
    }

    async fn look(
        subject: McpSubject,
        host: Arc<dyn busbar_substrate::plane_host::EngineHost>,
        _name: String,
    ) -> Result<McpTrustView, AdminError> {
        let report =
            crate::mcp::connect::refresh(&subject.pool, &subject.sightings, &subject.entry)
                .await
                // A refusal here means the refresh was never attempted — a registration busbar
                // cannot name, or a credential posture an operator-driven refresh cannot honour.
                // Both are the operator's own configuration, so both are `invalid_request` rather
                // than a 404 or a 5xx.
                .map_err(|refusal| AdminError::Validation(refusal.to_string()))?;
        // THE SAME RULE THE SWEEP SETTLES BY, and reached through the same function. An operator
        // pressing this button is taking exactly the observation the sweep takes; if only one of
        // the two wrote the durable record, an operator's own remedy would be the one act that
        // could not clear a quarantine.
        // Settle the durable demotion through the host `drift_quarantine` slot, which carries the
        // observed state and pulls the demotion store host-side — the same one settle rule the
        // verify-on-call path reaches, so an operator's `approved` clears what the sweep demoted. The
        // settle is fire-and-forget, so the durability bool is not a refusal.
        let _ = host.quarantine_settle(&subject.entry.id, report.state);
        // AND THE SAME LEDGER STAMP, for the same one-observation-one-set-of-books reason. Without
        // it a registration the operator just looked at was still `NeverChecked` to the unattended
        // timer, which re-fetched it on its very next tick — a second contact the operator's look
        // had already satisfied, landing at a moment nobody chose. A refusal above stamps nothing:
        // nothing was contacted, exactly as the sweep records it.
        crate::mcp::connect::stamp(
            &subject.sightings,
            &subject.entry.id,
            // D1: the ledger stamp's clock through the neutral host seam handed in by the driver.
            host.clock_now_ms(),
            !report.drift.is_empty(),
        );
        Ok(trust_view(&report, &subject.entry, &subject.cfg))
    }
}

/// `GET /api/v1/admin/tools/{name}/changes` — the changes queue, derived, contacting nothing.
pub(crate) async fn changes(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let host = busbar_core::plane_host::engine_host_from_handle(&handle);
    let subject = match McpServers::resolve(&host, &name) {
        Ok(v) => v,
        Err(e) => return busbar_core::admin::v1::json::err_json(&e),
    };
    let report = crate::mcp::connect::changes(&subject.sightings, &subject.entry);
    busbar_core::admin::v1::json::ok_json(
        StatusCode::OK,
        &trust_view(&report, &subject.entry, &subject.cfg),
    )
}

/// `GET /api/v1/admin/tools/{name}/health` — can busbar use this server right now.
pub(crate) async fn health(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let host = busbar_core::plane_host::engine_host_from_handle(&handle);
    let subject = match McpServers::resolve(&host, &name) {
        Ok(v) => v,
        Err(e) => return busbar_core::admin::v1::json::err_json(&e),
    };
    let report = crate::mcp::connect::changes(&subject.sightings, &subject.entry);
    busbar_core::admin::v1::json::ok_json(StatusCode::OK, &health_view(&report))
}

// Driven over the REAL router, because "mounted and reachable at the right scope" is the claim.
//
// GATED ON `auth-admin-tokens`, WHICH IS WHAT MAKES THE CLAIM TESTABLE AT ALL. Every test in here
// authenticates with `x-admin-token`, and the only thing that verifies that header is the
// `admin-tokens` module this feature compiles in. Under `--no-default-features` there is no admin
// auth module at all, so the chain fails closed and every request is a 401 before it reaches a
// verb — the tests were asserting 200/404/400 and getting 401.
//
// THE COVERAGE GAP, STATED RATHER THAN LEFT TO BE FOUND: with this feature off, the trust verbs
// have no test coverage. That is not a hole in the verbs — it is that a build with no admin auth
// module cannot admit an admin request by design, so there is no authenticated caller to test
// with. Covering it would mean standing up an external admin auth module in the fixture, which is
// a different test than this one and belongs with the plugin suite.
#[cfg(all(test, feature = "auth-admin-tokens"))]
#[path = "tests/adminverbs_tests.rs"]
pub(crate) mod adminverbs_tests;
