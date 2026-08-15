// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE INGRESS BOUNDARY: one request-observability seam, every mounted plane, no plane
//! comparison anywhere in it.
//!
//! ## What was wrong
//!
//! `busbar_requests_total` and `busbar_request_duration_seconds` were emitted from
//! `ingress::finish_inner`, and `finish_inner` is the MODEL plane's ingress. A tool call and an
//! agent task therefore produced NOTHING on `/metrics` — not an under-labelled series, no series.
//! Governance already spans the three planes (one key, one budget tree) and so does audit; metrics
//! did not, so an operator watching a dashboard saw model traffic and had no signal at all that the
//! tool or agent plane was refusing every request.
//!
//! ## Why a layer on the door rather than a call in each handler
//!
//! `mcp::envelope::invoke` and `a2a::receive::invoke` each have upwards of a dozen `return`s — envelope
//! defects, header mismatches, governance refusals, egress-gate refusals. A call at the bottom of
//! each handler would miss every one of them, and a call at each `return` is thirty call sites two
//! planes have to keep in agreement. Worse, either shape needs a per-plane symbol to hang itself
//! on, and a concern that grows one implementation per plane is the exact shape that produced this
//! release's duplicated hash chains and duplicated SSRF guards.
//!
//! So this is a LAYER, and it belongs to the MOUNT. That is the argument
//! [`super::PlaneAdmission`] already makes for keeping the RFC 8707 audience check beside the door
//! instead of in a handler: a property of the door is inherited by every path behind it, and a
//! handler added later cannot forget it. A refusal the auth middleware issues before any handler
//! runs is counted here too, which is the case an operator most needs to see and the one a
//! handler-level emit could never reach.
//!
//! ## Why there is no `match plane` in here
//!
//! Two questions could have been answered by comparing planes, and both are answered by the spine
//! instead:
//!
//! * *Which dialect was spoken?* — [`super::PlaneDispatch::wire_format_of`], off the CLAIM the path
//!   matched. A plane whose binding has a door of its own is labelled here with that binding's name
//!   whatever else the plane speaks, because the door declares what is spoken at it. The LLM plane
//!   still cannot be labelled here: not "it is the LLM plane", but "it has no door at all" — it is
//!   the residual, it claims no path, and it labels its own requests from inside its handler.
//! * *Did this request's own handler already label it?* — [`Counted`], a marker the handler puts on
//!   the response it is labelling. Needed as well as the claim, because two of the A2A plane's three
//!   bindings SHARE the `/a2a` door: the claim can say `jsonrpc` there, and only the reader knows
//!   whether the request line or a body member named the operation. See below.
//! * *Which plane is this?* — [`super::PlaneDispatch::mounted_plane_of`], off the mount table the
//!   router was built from.
//!
//! Add a fourth plane and it is observed by this file without an edit.
//!
//! ## THE ONE-DIALECT TEST WAS THE WRONG QUESTION, AND A SECOND BINDING SHOWED WHY
//!
//! This layer used to skip any plane whose `sole_wire_format` was `None`, on the reasoning that a
//! plane with several dialects cannot be labelled before its reader has decided which one spoke.
//! That reasoning is right about the LABEL and wrong about the SKIP, and the difference only became
//! visible when the A2A plane armed its second binding: the plane's handler could then label the
//! requests it handles, but a refusal issued BEFORE any handler — the audience-bound `401`, the
//! `413` reshape, a `404` — reaches no reader at all, so skipping the plane here meant those stopped
//! being counted entirely. That is precisely the hole this whole file was written to close, re-opened
//! by a rule that fired correctly.
//!
//! So the question is now *did the handler already count this one*, answered by a marker the handler
//! sets, and a request that reached no handler is counted HERE under the binding ITS DOOR declares —
//! the same answer `ingress::native` shapes its body in, so a door refusal's metric label and its
//! envelope name the same binding rather than disagreeing.
//!
//! The two mechanisms are not alternatives and the A2A plane needs both. Its gRPC binding has a door
//! of its own, so a `401` there is counted `grpc` from the claim without any handler running; its
//! JSON-RPC and HTTP+JSON bindings share `/a2a`, where no claim can say which spoke, so their
//! requests are labelled by `a2a::receive::invoke` and marked [`Counted`] so this layer stands down.

use crate::state::AppHandle;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;
use std::time::Instant;

/// A MARKER A PLANE'S HANDLER PUTS ON A RESPONSE IT HAS ALREADY LABELLED.
///
/// It carries nothing, and carrying nothing is the point: this is not a channel for the handler to
/// pass its labels up through, which would put the emit back in one place and the label vocabulary
/// in another. The handler emits its own series with the binding only it knows, and this says so, so
/// [`observe`] can cover exactly the requests no handler saw without counting anything twice.
///
/// A response extension rather than a request one, because the answer is what carries the fact and
/// the boundary reads it after the handler has run.
#[derive(Clone, Copy)]
pub(crate) struct Counted;

/// Emit `busbar_requests_total` + `busbar_request_duration_seconds` for one request served by a
/// MOUNTED plane, labelled with the plane it arrived on.
///
/// The same two families, the same `outcome` vocabulary and the same emit helper the model plane
/// uses (`crate::telemetry::request_finished`) — a plane label, not a parallel vocabulary. An
/// operator's existing panel keeps working and `sum by (plane) (rate(busbar_requests_total[5m]))`
/// starts answering "which plane is this traffic on".
///
/// A path on the RESIDUAL plane passes straight through: `/healthz`, `/metrics`, `/stats`, the
/// admin surface and every protocol endpoint. The protocol endpoints emit their own, richer
/// labelling from `ingress::finish_inner` — which also owns the non-2xx flat-fee REFUND and so
/// cannot simply be replaced by this — and double-counting them here would silently double every
/// number on every existing model-plane dashboard.
pub(crate) async fn observe(
    State(handle): State<Arc<AppHandle>>,
    req: Request,
    next: Next,
) -> Response {
    let app = handle.load();
    // The mount table this router was built from decides, so an unmounted plane cannot be counted
    // and a sibling path (`/mcpx` beside a `/mcp` mount) cannot be attributed to a plane whose
    // grants are inadmissible everywhere else.
    let path = req.uri().path();
    let plane = app.planes.mounted_plane_of(path);
    // Resolved BEFORE the request is consumed, and both facts together, so the emit below needs no
    // second decision: either this boundary can label the request or it cannot.
    //
    // The dialect comes off the CLAIM, not off the plane. A plane that speaks one dialect answers
    // the same either way; a plane that speaks several — A2A, since HTTP+JSON and gRPC armed — is
    // still labelled here, with the binding the DOOR declares. Asking the plane would answer `None`
    // for exactly those planes and silently stop counting them. Where several bindings share one
    // door the claim names the canonical one, which is also the binding `ingress::native` shapes a
    // door refusal's body in, so the label and the envelope agree about what was refused.
    let labels = plane.zip(app.planes.wire_format_of(path));
    let Some((plane, wire)) = labels else {
        return next.run(req).await;
    };
    let started = Instant::now();
    let resp = next.run(req).await;
    // THE HANDLER'S OWN LABEL WINS, and this is the only thing that keeps the two emits from
    // double-counting. A plane whose handler knows which binding spoke says so itself, with the
    // right binding; this layer then stands down for that request and covers only what never
    // reached a handler.
    if resp.extensions().get::<Counted>().is_some() {
        return resp;
    }
    crate::telemetry::request_finished(
        &app,
        plane.key(),
        wire,
        // The plane's routing TARGET is not resolved at the door. On the model plane that
        // resolution happens in the handler, and the sentinel is exactly the value the model plane
        // already stamps when a request never resolved one (`ingress::pool_label`) — so this is the
        // established spelling for "no target resolved", not a new one. Handing a plane's raw,
        // client-supplied target through here instead would be an unbounded label: one valid
        // credential could mint a new time series per distinct tool name, which is the
        // memory-exhaustion DoS `pool_label` exists to close. Narrowing this to the configured
        // tool-server / agent name is the next step and it belongs where the target is resolved.
        crate::proxy::POOL_LABEL_UNRESOLVED,
        crate::telemetry::outcome_of(resp.status().as_u16()),
        started.elapsed().as_secs_f64(),
    );
    resp
}

#[cfg(test)]
#[path = "tests/observe_tests.rs"]
mod observe_tests;
