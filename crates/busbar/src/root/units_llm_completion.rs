// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RE-ENTRY, ON THE LOOP — the root-side completion entry the composition root installs into
//! the neutral resolved-completion seam.
//!
//! A completion busbar itself asks for is still a request busbar serves. The sampling bridge reaches
//! `CompletionHost::synthesize_completion`, core threads the ask back out through
//! `busbar_substrate::ingress::arrival`'s resolved-completion seam, and whatever is installed there
//! is what serves it. Until this file that was the plane's OWN shell — the same shell its
//! `BODY_INGRESS` arrivals take when the root leg is off — so a shipped binary served its arrivals
//! through the kernel's one loop and its re-entries through a second path beside it. Two ways in,
//! one of them around the loop.
//!
//! This is the re-entry's twin of the arrivals' own body table, and deliberately the SAME four
//! lines that table's `body_arrival` is: read the payload, name the dialect, build a
//! [`WalkArrival`], and hand it to [`LlmNode::answer`]. There is no completion step, no completion
//! meter and no completion door, because a re-entrant completion is not a second kind of unit — it
//! is one unit, admitted at the same door, priced off the same pinned history, metered on the same
//! accrual and audited through the same two doors as the arrival it is indistinguishable from once
//! it is inside.
//!
//! ## What the seam hands in, and what this turns it into
//!
//! | the seam's `CompletionArrival` | where it goes |
//! |---|---|
//! | `ctx` (the neutral `ArrivalPayload`: host, gov, caller token) | the walk's `host` / `gov` / `caller_token`, downcast exactly as the body arrivals downcast it |
//! | `model` — the OPERATOR'S declared model, resolved before the ask reached core | `model_hint`, which is rung 1 of the model ladder: the caller already named the model, so nothing in the body overrides it |
//! | `headers` | the walk's headers (core mints them fresh — a re-entry never replays the caller's) |
//! | `body` | the walk's body |
//!
//! `path: None`, because a synthesized completion carries no URL: the model rides the hint, not a
//! segment, which is the body-model shape.
//!
//! ## The dialect is the registry's, and this file spells none
//!
//! The chat protocol the completion is driven as is the registry's residual-default, read BY NAME —
//! the same read the retired shell made, for the same reason: a composition root that hard-coded a
//! dialect here would make the re-entry answer in a dialect the deployment may not even serve.
//! `None` is the all-planes-off configuration, and it is answered with the honest error rather than
//! a synthesized completion, byte-for-byte the sentence the shell returned.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use busbar_llm::unit::walk::WalkArrival;
use busbar_substrate::ingress::arrival::{ArrivalPayload, CompletionArrival};

use busbar_api::{operation::Operation, PlaneRequestCtx};

use super::units_llm::{node, unavailable, LlmNode};

/// ONE RE-ENTRANT COMPLETION, DRIVEN THROUGH THE LOOP.
///
/// Matches the seam's `CompletionIngress` fn-pointer shape, so the composition root installs it
/// where it installed the plane's shell and core reaches it through the same one call.
///
/// Nothing is spawned: the loop is awaited on the task the sampling bridge is already running on,
/// so a bridge whose own caller hangs up drops this future and the unit ends at its one terminal,
/// exactly as a dropped arrival does.
pub fn synthesize_completion(
    a: CompletionArrival,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
    Box::pin(drive(a))
}

/// The body of [`synthesize_completion`], written as an `async fn` so the boxing above is the only
/// thing the fn-pointer shape costs. The process's one node, named rather than assumed.
async fn drive(a: CompletionArrival) -> Response {
    complete_on(node(), a).await
}

/// THE SAME DRIVE, WITH THE NODE HANDED IN rather than taken — the re-entry's twin of
/// [`LlmNode::answer_arriving_at`], split out for the same reason.
///
/// "A sampled completion is served through the mounted leg" is a claim about WHICH node ran it,
/// and a claim about a process-wide static is not a claim a test can make: the count it would read
/// is every unit the binary ever served, in whatever order the harness chose. Handed a node, the
/// figure is this completion's.
pub(super) async fn complete_on(node: &LlmNode, a: CompletionArrival) -> Response {
    let CompletionArrival {
        ctx,
        model,
        headers,
        body,
    } = a;
    // THE DEFAULT CHAT PROTOCOL the synthesized completion is driven as — the registry's
    // residual-default protocol, read by NAME so no dialect literal appears here. `None` is the
    // all-planes-off configuration with no chat dialect to drive; the caller reads the non-2xx body
    // as an unsatisfiable ask. The status, the body and the fact that this answer is NOT accounted
    // are the retired shell's, unchanged: a deployment with no chat dialect has no unit to open, so
    // there is nothing for a door to admit or a meter to read.
    let Some(proto) = busbar_substrate::proto::residual_default_protocol() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "no default chat protocol is installed",
        )
            .into_response();
    };
    // The neutral arrival payload core boxed for the re-entry: the minted engine host, the caller's
    // governance context and the caller's bearer token. A context carrying anything else is a wiring
    // bug rather than a runtime input, and it is answered rather than unwrapped — the same arm the
    // body arrivals take.
    let Some(payload) = ctx.downcast_ref::<ArrivalPayload>() else {
        return unavailable(proto);
    };
    // THE OPERATION. The retired shell asked the registry for it (`handlers::chat`), which resolves
    // `Operation::CHAT` and hands back the op handler beside it. The loop looks the handler up
    // itself at step 1, off the same `request_handler(proto)`, so all this entry owes the walk is
    // the operation — and the registry returns the operation it was ASKED for. Naming it is the
    // same value through two fewer reaches into a retiring crate.
    //
    // One arm differs, and it differs in the direction of the loop: a residual-default dialect that
    // declares no chat verb made the shell PANIC, and makes this a 404 out of the decode step, which
    // is what an arrival naming an unsupported operation already gets. No shipped configuration
    // reaches either — the residual default is the chat dialect by definition — and of the two, the
    // one the arrivals give is the one the re-entry should give.
    let arrival = WalkArrival {
        host: std::sync::Arc::clone(&payload.host),
        gov: PlaneRequestCtx {
            key: payload.gov.key.clone(),
        },
        proto,
        operation: Operation::CHAT,
        caller_token: payload.caller_token.clone(),
        headers,
        body,
        // A synthesized completion has no URL: the model was handed in, so there is no path fact to
        // carry and no dialect miss-copy this surface owns.
        path: None,
    };
    // THE MODEL, AS RUNG 1. The operator declared it before the ask reached core, so it is handed in
    // as the hint the URL-model surfaces hand in — which is what makes "the body cannot override the
    // operator's model" a property of the ladder rather than of this file.
    node.answer(arrival, Some(model)).await
}

// THE CELLS live beside the arrivals' own, in the node's test file: the claim is that this entry and
// the retired shell leave the SAME bytes and the SAME money, and the instrument that makes that
// comparable — the two-deployment rig, the `Observed` field set, the normalizer — is that file's.
