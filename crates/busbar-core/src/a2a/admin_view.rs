// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE'S ADMIN READ VIEWS — the `agents:` half of the generic named-definition admin
//! surface, projected HERE so core admin (`admin::v1::service`, `admin::v1::named_def_views`) reads a
//! registered agent through the plane's view seam and names no `crate::a2a` config type. The MCP-plane
//! counterpart is `crate::mcp::admin_view`; the seam that reaches both is
//! [`crate::plane::registry::PlaneDecl::named_def_list`] / `named_def_get`.

use crate::admin::v1::contract::NamedDefView;

/// Project one `agents:` DEFINITION onto the shared named-map view.
///
/// The backend `url:` is NOT projected. It is the real remote endpoint, this surface is reachable
/// at read-only admin scope, and "which third party is behind this name" is exactly the fact the
/// rewrite-through-busbar posture exists to keep on the server side. What IS projected is what an
/// operator auditing trust needs and cannot get anywhere else: which root the entry is pinned to,
/// whether a fingerprint has been approved yet, and how often it is re-checked.
fn agent_def_view(name: &str, cfg: &crate::a2a::config::AgentDefCfg) -> NamedDefView {
    NamedDefView {
        name: name.to_string(),
        module: String::new(),
        settings_keys: Vec::new(),
        max_admin_scope: None,
        token_configured: None,
        browser_login_configured: None,
        pin_mechanism: Some(
            serde_json::to_value(cfg.pin.mechanism)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
        ),
        fingerprint_pinned: Some(cfg.pin.fingerprint.is_some()),
        reverify_ttl: Some(
            cfg.reverify_ttl
                .clone()
                .unwrap_or_else(|| crate::a2a::config::DEFAULT_REVERIFY_TTL.to_string()),
        ),
        unparseable: None,
    }
}

/// Every registered agent, as the shared named-definition view. The read half of
/// `GET /api/v1/admin/agents`.
pub(crate) fn list(app: &crate::state::App) -> Vec<NamedDefView> {
    crate::a2a::agent_cfg(app)
        .agents
        .iter()
        .map(|(name, cfg)| agent_def_view(name, cfg))
        .collect()
}

/// One registered agent, or `None`. The read half of `GET /api/v1/admin/agents/{name}`.
pub(crate) fn get(app: &crate::state::App, name: &str) -> Option<NamedDefView> {
    crate::a2a::agent_cfg(app)
        .agents
        .get(name)
        .map(|cfg| agent_def_view(name, cfg))
}

/// Attach the A2A trust verbs' typed schemas — the A2A half of
/// [`crate::plane::registry::PlaneDecl::openapi_schemas`]. Registers `A2aTrustView` (response) and
/// `ApproveReq` (request body) into the SHARED generators and attaches their `$ref`s onto the paths
/// this plane's `openapi()` fragment inserted, byte-identically to the inline `typed!`/`body!` calls
/// it replaced (same types, same order, same generators).
#[cfg(feature = "openapi-schema")]
pub(crate) fn openapi_schemas(
    schema_gen: &mut schemars::SchemaGenerator,
    req_gen: &mut schemars::SchemaGenerator,
    paths: &mut serde_json::Map<String, serde_json::Value>,
) {
    use crate::admin::v1::json::ap;
    use crate::admin::v1::json::{set_request_body, set_response_schema};
    let connect = serde_json::to_value(schema_gen.subschema_for::<super::verbs::A2aTrustView>())
        .unwrap_or_else(|_| serde_json::json!({}));
    set_response_schema(paths, &ap("/agents/{name}/connect"), "post", "200", connect);
    let approve = serde_json::to_value(schema_gen.subschema_for::<super::verbs::A2aTrustView>())
        .unwrap_or_else(|_| serde_json::json!({}));
    set_response_schema(paths, &ap("/agents/{name}/approve"), "post", "200", approve);
    let body = serde_json::to_value(req_gen.subschema_for::<super::verbs::ApproveReq>())
        .unwrap_or_else(|_| serde_json::json!({}));
    set_request_body(paths, &ap("/agents/{name}/approve"), "post", body);
}

/// Is `name` a live registered agent on this snapshot — the membership check the admin write path
/// consults through the plane's `registry_contains` seam, so core names no `crate::a2a` registry type.
pub(crate) fn contains(app: &crate::state::App, name: &str) -> bool {
    crate::a2a::agent_cfg(app).agents.contains_key(name)
}

/// RE-RESOLVE THE A2A PLANE'S PER-AGENT HOOK GATES against the next snapshot — the A2A half of the
/// config-swap gate rebuild, moved HERE so `admin::v1::service::reresolve_plane_gates` names no
/// `crate::a2a` registry type. Reads this plane's own registry off the snapshot and writes its own
/// gate field back.
pub(crate) fn reresolve_gates(next: &mut crate::state::App) {
    let agents = crate::a2a::agent_cfg(next).clone();
    next.a2a_agent_gates = crate::hooks::resolve_container_gates(
        agents
            .agents
            .iter()
            .map(|(n, d)| (n.as_str(), d.hooks.as_slice())),
        &agents.all_agent_hooks,
        &next.hook_registry,
        &next.hook_env,
        next.config_version,
    );
}
