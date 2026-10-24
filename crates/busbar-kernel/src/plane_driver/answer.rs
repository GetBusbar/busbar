// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ANSWER SHAPE a unit's response is handed back in ([`PlaneAnswer`], DECISIONS #28): a buffered
//! answer or a live body, served by the outer async handler. It moved here from the kernel's retired
//! plane hosting (`plane_host`, status row 82) beside the driver that serves door planes.

/// THE LOOP'S ANSWER SHAPE at the unified boundary (DECISIONS #28), plane-neutral.
///
/// When a rider runs on the kernel Teller loop (`busbar_kernel::teller::run_unit`), the loop returns
/// only the money/lifecycle `Ended`; the request's ANSWER bytes are read back out of the plane's own
/// `ctx.key`-keyed binding table (the admin template — `AdminUnitTable`). `PlaneAnswer` is what a
/// rider stashes into that table and the outer async handler serves. Two shapes, per #28:
///
/// - [`PlaneAnswer::Unary`] — buffered status + headers + body, crosses the sync channel and settles
///   at Encode on the final byte count (the admin cleanliness caller and every unary verb, including
///   an SSE body materialised after dispatch).
/// - [`PlaneAnswer::Live`] — a live body the outer handler serves directly, governed at admit
///   (auth/verify/approve/admit/audit ran unary), bypassing the Encode-emits-bytes path (the llm
///   RouteLeg emits this).
///
/// NEUTRAL BY CONSTRUCTION: nothing here names a plane, a dialect or a verb.
pub enum PlaneAnswer {
    /// Buffered: status, headers, body bytes. Settles at Encode on the final byte count.
    Unary(
        axum::http::StatusCode,
        axum::http::HeaderMap,
        axum::body::Bytes,
    ),
    /// A live body the outer async handler serves directly, governed at admit.
    Live(axum::response::Response),
}

impl PlaneAnswer {
    /// Materialise either shape into the one response the outer handler serves. `Unary` is rebuilt
    /// status-for-header-for-byte so a buffered answer serves byte-identically to the response the
    /// plane shaped; `Live` is handed through untouched.
    pub fn into_response(self) -> axum::response::Response {
        match self {
            PlaneAnswer::Unary(status, headers, body) => {
                let mut resp = axum::response::Response::new(axum::body::Body::from(body));
                *resp.status_mut() = status;
                *resp.headers_mut() = headers;
                resp
            }
            PlaneAnswer::Live(resp) => resp,
        }
    }
}

#[cfg(test)]
#[path = "tests/answer_tests.rs"]
mod tests;
