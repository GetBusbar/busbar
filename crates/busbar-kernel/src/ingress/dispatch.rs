// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The data router's catch-all: `protocol_dispatch`, the answer to a request no route took.

use super::*;

/// THE CATCH-ALL: a request no route took. Every claimant serves its own paths through its door,
/// mounted ahead of this fallback, so what reaches here is unclaimed: the listener's wrong-method
/// answer when a claimant's line answers the path under another method, and otherwise its no-route
/// answer, each rendered by the matched line's claimant from the target, or in the listener's own
/// default envelope when no claimant's line answers (`fallback_error_response`). The kernel names
/// no protocol and picks no dialect here.
pub(crate) async fn protocol_dispatch(
    axum::extract::State(handle): axum::extract::State<std::sync::Arc<crate::state::AppHandle>>,
    OriginalUri(uri): OriginalUri,
    method: axum::http::Method,
    axum::extract::Extension(_gov): axum::extract::Extension<crate::governance::GovCtx>,
    _consumed: Option<axum::extract::Extension<crate::auth::ConsumedCredentials>>,
    // The body is read, as the listener always read it: an oversized request is the body cap's
    // 413 (`router::reshape_body_limit_413`), never a no-route answer that skipped the cap.
    _body: axum::body::Bytes,
) -> Response {
    let app = handle.load();
    let lines = handle.listener_lines().map(|l| l.as_ref());
    let path = uri.path();
    // A path a claimant's line answers under another method is a wrong-method answer on that line
    // (405, never no-route: the guest list's MATCH rule); any other unclaimed path is the honest
    // no-route 404. A plane serves its own paths through its door, mounted ahead of this fallback,
    // so no arrival answers here.
    let miss = lines
        .and_then(|l| l.facts(method.as_str(), path))
        .is_some_and(|f| !f.admits_method);
    let (status, reason, kind, message) = if miss {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            busbar_contract::caps::ReasonCode::WrongMethod,
            crate::taxonomy::ERR_TYPE_INVALID_REQUEST,
            "method not allowed for this resource",
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            busbar_contract::caps::ReasonCode::NoRoute,
            crate::taxonomy::ERR_TYPE_NOT_FOUND,
            "the requested resource was not found",
        )
    };
    crate::fallback_error_response(
        lines,
        &app.planes,
        method.as_str(),
        path,
        status,
        reason,
        kind,
        message,
    )
}
