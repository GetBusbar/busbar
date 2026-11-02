// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::state::CurrentApp;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

pub(crate) async fn observe(CurrentApp(app): CurrentApp, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let plane = app.planes.mounted_plane_of(path);

    let labels = plane.zip(app.planes.wire_format_of(path));
    let Some((plane, wire)) = labels else {
        return next.run(req).await;
    };
    let started = Instant::now();
    let resp = next.run(req).await;

    if resp.extensions().get::<Counted>().is_some() {
        return resp;
    }
    crate::telemetry::request_finished(
        &app,
        plane,
        wire,
        crate::telemetry::POOL_LABEL_UNRESOLVED,
        crate::telemetry::outcome_of(resp.status().as_u16()),
        started.elapsed().as_secs_f64(),
    );
    resp
}

/// A MARKER A PLANE'S HANDLER PUTS ON A RESPONSE IT HAS ALREADY LABELLED.
///
/// It carries nothing, and carrying nothing is the point: this is not a channel for the handler to
/// pass its labels up through, which would put the emit back in one place and the label vocabulary
/// in another. The handler emits its own series with the binding only it knows, and this says so, so
/// core's `ingress::observe` can cover exactly the requests no handler saw without counting anything
/// twice.
///
/// A response extension rather than a request one, because the answer is what carries the fact and
/// the boundary reads it after the handler has run.
#[derive(Clone, Copy)]
pub struct Counted;
