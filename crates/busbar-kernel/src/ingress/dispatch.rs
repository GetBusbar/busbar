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

use super::*;

/// THE UNCLAIMED-PATH ANSWER: the 404 for a path no claimed row owns. The kernel identifies no
/// protocol here; it names the path's shape only through the mount table
/// ([`crate::fallback_error_response`]).
///
/// THE BODY IS READ, AND LAST, so the body cap answers first: axum's `DefaultBodyLimit` fires only
/// when an extractor reads the body, and 1.5.5 answered an oversized body with 413 before any 404.
/// Dropping the read would turn that 413 into this 404.
pub(crate) async fn protocol_dispatch(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    OriginalUri(uri): OriginalUri,
    _body: axum::body::Bytes,
) -> Response {
    crate::fallback_error_response(
        &app.planes,
        uri.path(),
        StatusCode::NOT_FOUND,
        crate::taxonomy::ERR_TYPE_NOT_FOUND,
        "the requested resource was not found",
    )
}
