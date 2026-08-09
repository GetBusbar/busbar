// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP TRUST VERBS on the admin API — `connect`, `changes`, `health`.
//!
//! They live here rather than in the generic admin service for two reasons. The first is layout: the
//! thing a reader looks for when they ask "what does the admin API say about an MCP server" is MCP.
//! The second is a hard constraint — the generic service file is near its size cap, and a plane's own
//! vocabulary is exactly what should not be growing it.
//!
//! ## What each verb is, in one line
//!
//! - `POST /tools/{name}/connect` — fetch the upstream's LIVE tool list, hash it, record the
//!   observation, and answer with the derived trust state and changes queue. THIS is the verb that
//!   gives the dispatch gate a right-hand side to compare against; without it the gate compares the
//!   operator's configured hash with itself and a rug-pull is undetectable by construction.
//! - `GET /tools/{name}/changes` — the same view, computed from the LAST observation, contacting
//!   nothing. Safe to poll.
//! - `GET /tools/{name}/health` — can busbar use this server right now, and if not, why.
//!
//! ## `connect` is a POST because it reaches the network
//!
//! It takes no body and returns a projection, which makes it look like a read. It is not: it makes
//! busbar open a connection to an operator-named endpoint and it replaces the recorded observation,
//! which can move a server from `approved` to `quarantined`. Both of those are effects, so it takes
//! the mutation scope (`full`) that every non-GET admin route takes, and it is audited.
//!
//! ## What it does NOT do: approve anything
//!
//! A refresh records what was SEEN. Adopting what was seen is a separate, explicit operator act —
//! `crate::trust::Approval::approve` and friends — precisely so that a poisoned tool list cannot be
//! adopted by the same call that fetched it. The connect verb landing a drift and the operator
//! working it are two decisions, and this file only owns the first.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::admin::v1::contract::AdminError;
use crate::state::AppHandle;

/// The audit action word for every verb here, named once so a new verb cannot invent a spelling.
const AUDIT_ACTION: &str = "mcp_server.connect";

/// Look one registered server up on the live snapshot, or produce the 404.
///
/// Both the catalogue ENTRY (which carries the standing approval) and the config DEFINITION (which
/// carries the allow-list the pending rows come from) are needed, and a server present in one and
/// absent from the other is not a state the build can produce — so a missing either way is the same
/// `not_found`, rather than two answers a caller would have to distinguish.
fn registered(
    app: &Arc<crate::state::App>,
    name: &str,
) -> Result<
    (
        crate::mcp::catalogue::ServerEntry,
        crate::mcp::config::McpServerDefCfg,
    ),
    AdminError,
> {
    match (
        app.mcp_catalogue.server(name),
        app.mcp_servers.servers.get(name),
    ) {
        (Some(entry), Some(cfg)) => Ok((entry.clone(), cfg.clone())),
        _ => Err(AdminError::not_found(format!("MCP server `{name}`"))),
    }
}

/// `POST /api/v1/admin/tools/{name}/connect` — fetch the live tool list and record the observation.
pub(crate) async fn connect(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
) -> Response {
    let app = handle.load();
    let (entry, cfg) = match registered(&app, &name) {
        Ok(v) => v,
        Err(e) => return crate::admin::v1::json::err_json(&e),
    };
    let report = match crate::mcp::connect::refresh(&app.mcp_pool, &app.mcp_sightings, &entry).await
    {
        Ok(report) => report,
        Err(refusal) => {
            // A refusal here means the refresh was never attempted — a registration busbar
            // cannot name, or a credential posture an operator-driven refresh cannot honour.
            // Both are the operator's own configuration, so both are `invalid_request` rather
            // than a 404 or a 5xx.
            crate::admin::audit::AUDIT.record_by(
                AUDIT_ACTION,
                &format!("mcp_server:{name}"),
                crate::admin::audit::OUTCOME_REJECTED,
                principal.actor_id(),
            );
            return crate::admin::v1::json::err_json(&AdminError::Validation(refusal.to_string()));
        }
    };
    // AUDITED WHATEVER IT FOUND. A refresh that landed a quarantine is the single most
    // operator-relevant thing this surface does, and recording only the successful ones would make
    // the audit trail silent at exactly the moment it matters.
    crate::admin::audit::AUDIT.record_by(
        AUDIT_ACTION,
        &format!("mcp_server:{name}"),
        crate::admin::audit::OUTCOME_APPLIED,
        principal.actor_id(),
    );
    crate::admin::v1::json::ok_json(
        StatusCode::OK,
        &crate::mcp::admin_view::trust_view(&report, &entry, &cfg),
    )
}

/// `GET /api/v1/admin/tools/{name}/changes` — the changes queue, derived, contacting nothing.
pub(crate) async fn changes(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let app = handle.load();
    let (entry, cfg) = match registered(&app, &name) {
        Ok(v) => v,
        Err(e) => return crate::admin::v1::json::err_json(&e),
    };
    let report = crate::mcp::connect::changes(&app.mcp_sightings, &entry);
    crate::admin::v1::json::ok_json(
        StatusCode::OK,
        &crate::mcp::admin_view::trust_view(&report, &entry, &cfg),
    )
}

/// `GET /api/v1/admin/tools/{name}/health` — can busbar use this server right now.
pub(crate) async fn health(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let app = handle.load();
    let (entry, _cfg) = match registered(&app, &name) {
        Ok(v) => v,
        Err(e) => return crate::admin::v1::json::err_json(&e),
    };
    let report = crate::mcp::connect::changes(&app.mcp_sightings, &entry);
    crate::admin::v1::json::ok_json(
        StatusCode::OK,
        &crate::mcp::admin_view::health_view(&report),
    )
}

// Driven over the REAL router, because "mounted and reachable at the right scope" is the claim.
#[cfg(test)]
#[path = "tests/adminverbs_tests.rs"]
pub(crate) mod adminverbs_tests;
