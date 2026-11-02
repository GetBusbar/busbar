// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

pub(crate) async fn protocol_dispatch(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    OriginalUri(uri): OriginalUri,
    _body: axum::body::Bytes,
) -> Response {
    crate::fallback_error_response(
        &app.planes,
        uri.path(),
        StatusCode::NOT_FOUND,
        busbar_contract::protocol::ERR_TYPE_NOT_FOUND,
        "the requested resource was not found",
    )
}
