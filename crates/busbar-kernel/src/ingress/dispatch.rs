// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The catch-all dispatch: the axum fallback every path no route, mount or plane claimed reaches.
//! A child of `route` so it shares the ingress core's private helpers without widening their
//! visibility.

use super::*;

/// THE CATCH-ALL (the axum fallback). Every path a plane serves is claimed before this runs — by its
/// mount, its door's claims or the explicit routes for busbar's own API — so what reaches here is a
/// path nothing serves, and it is answered with the not-found envelope the residual plane wears.
///
/// It used to identify a wire dialect from `(path, headers)` through the kernel's protocol registry
/// and hand the request to that dialect's arrival. The kernel holds no dialect any more (a dialect is
/// a thing inside its plane, Q128 contract p11 finding 1), and production installed no protocol
/// declaration into that registry, so the identification always found none and this answer is the
/// one every such request already got. The extractors stay exactly as they were, so a request that
/// fails one (an over-limit body, a missing governance context) is answered as it was before.
pub(crate) async fn protocol_dispatch(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    OriginalUri(uri): OriginalUri,
    _method: axum::http::Method,
    axum::extract::Extension(_gov): axum::extract::Extension<crate::governance::GovCtx>,
    _consumed: Option<axum::extract::Extension<crate::auth::ConsumedCredentials>>,
    _headers: HeaderMap,
    _body: Bytes,
) -> Response {
    crate::fallback_error_response(
        &app.planes,
        uri.path(),
        StatusCode::NOT_FOUND,
        crate::taxonomy::ERR_TYPE_NOT_FOUND,
        "the requested resource was not found",
    )
}
