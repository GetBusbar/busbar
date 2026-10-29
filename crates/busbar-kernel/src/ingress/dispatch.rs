// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The data plane's catch-all: the answer to a path no route claims.
//!
//! A plane matches its own claimed routes (BUSBAR-1.6.0.md l.5303, item 1: detection is
//! plane-internal; kernel-side detection over declarations goes away). Every claim a door plane
//! states is mounted as a route, and every verb its claims leave open on a claimed path is
//! answered by the router's 405, rendered by the door that owns the path. So a request reaching
//! this fallback is on a path no claimed row owns, and the kernel answers it itself: the 404 in the
//! shape the mount table gives the path.
//!
//! THE BODY CAP TRIPS FIRST. The fallback buffers the request body before it refuses the path, so a
//! body over `limits.request_body_max_bytes` is the reshaped 413 on every path, claimed or not, and
//! never the 404. v1.5.5 did the same: its catch-all took the body as an extractor
//! (`crates/busbar/src/ingress/dispatch.rs:299` at v1.5.5) before it identified or refused the path
//! (`:302-319`), under the `DefaultBodyLimit` layer (`crates/busbar/src/main.rs:3877`).

use super::*;

/// THE UNCLAIMED-PATH ANSWER: the 404 for a path no claimed row owns. The kernel identifies no
/// protocol here; it names the path's shape only through the mount table
/// ([`crate::fallback_error_response`]). The body is read and dropped: the read is where the body
/// cap trips, ahead of the refusal (module docs).
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
