// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol catch-all dispatch (design: web server listens for anything → Router IDs the
//! protocol → that protocol's `RequestHandler` decides the operation → its OperationHandler). Holds
//! `protocol_dispatch` (the axum fallback) and the generic `operation_ingress` for the 1.2 operations.
//! A child of `route` so it shares the ingress core's private helpers (`finish*`, `governance_guard`)
//! without widening their visibility.

use super::*;

// (The per-operation axum wrappers are gone: the protocol catch-all `protocol_dispatch` resolves the
// operation via the RequestHandler and calls `operation_ingress` directly.)

/// THE PROTOCOL CATCH-ALL (design: web server listens for anything). One axum fallback replaces the
/// per-path protocol routes: the Router does DUMB protocol identification from (path, headers); the
/// identified protocol's RequestHandler reads path+body and decides the operation; the operation's
/// OperationHandler does the rest. `main.rs` keeps explicit routes ONLY for busbar's own API (health/metrics/
/// admin/discovery + the named/adhoc conveniences) — a new protocol touches the Router ID ladder, a
/// RequestHandler, and its OperationHandlers, never this dispatch and never `main.rs`.
///
/// Path-model protocols delegate to their own protocol arms wholesale (path-model parsing, streaming
/// variants, native unsupported-action envelopes live there); the body-model protocols split here:
/// every operation → `operation_ingress` (the universal core). Unknown paths/methods keep the
/// pre-collapse fallback shaping (native 404/405 envelopes, no proxy tells).
pub(crate) async fn protocol_dispatch(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    OriginalUri(uri): OriginalUri,
    method: axum::http::Method,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    consumed: Option<axum::extract::Extension<crate::auth::ConsumedCredentials>>,
    mut headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_string();
    let Some(proto) = crate::proto::detect_protocol(&path, &headers) else {
        // Not a protocol endpoint: the pre-collapse 404 fallback shape (native envelope by path).
        return crate::fallback_error_response(
            &app.planes,
            &path,
            StatusCode::NOT_FOUND,
            crate::taxonomy::ERR_TYPE_NOT_FOUND,
            "the requested resource was not found",
        );
    };
    if method != axum::http::Method::POST {
        // A protocol endpoint hit with the wrong method: the pre-collapse 405 shape.
        return crate::fallback_error_response(
            &app.planes,
            &path,
            StatusCode::METHOD_NOT_ALLOWED,
            crate::taxonomy::ERR_TYPE_INVALID_REQUEST,
            "method not allowed for this resource",
        );
    }
    // THE UNIVERSAL RULE — we only process operations for which the protocol HOLDS an
    // OperationHandler; otherwise 404 in the caller's dialect. No operation is special — every
    // operation gets the same consult, same terminal. Delete any protocol's handler for any
    // operation (its registry arm) and that operation dies HERE while everything else keeps working.
    // (`resolve_operation` = the RequestHandler naming the operation; `None` falls through to the
    // protocol arms, which own their native unknown-action envelopes.)
    if let Some(rh) = crate::handlers::request_handler(proto) {
        if let Some(op) = rh.resolve_operation(&path, &body) {
            if rh.operation_handler(op).is_none() {
                return crate::plane_driver::refusal::ingress_error(
                    proto,
                    StatusCode::NOT_FOUND,
                    busbar_contract::protocol::KIND_NOT_FOUND,
                    "This endpoint does not support that operation.",
                );
            }
        }
    }
    // THE BODY-MODEL ARRIVAL, resolved by protocol name off the core-owned side-table a plane
    // registered it in. A dialect whose model rides the URL has no kernel arrival: recognising a
    // model in the URL is the plane's own logic, and its door claims and serves those paths
    // (ARCHITECT 2026-10-16 ruling 3 item 1). The arrival is a `fn` pointer to a BOXED future, so
    // its size stays on the requests that take it rather than inflating every request's future.
    // No plane linked (core booted plane-agnostic) → the honest no-handler 404 below.
    let ingress = crate::ingress::body_ingress_for(proto);
    if let Some(ingress) = ingress {
        // Mint the neutral arrival the dialect crate receives: its own URL-parsing reads
        // `path`/`uri`/`headers`/`body` directly, and it reaches core's resolution/forward pipeline
        // through `host`, threading the core-only `App`/`GovCtx`/`CallerToken` back opaquely as `ctx`
        // — so it names no `busbar_kernel::` item and core names no dialect.
        let ctx = busbar_kernel::ingress::arrival::ArrivalCtx::new(
            crate::ingress::arrival_host::ArrivalPayload {
                host: crate::plane_driver::engine_host(&app),
                gov,
                caller_token: consumed.as_ref().and_then(|c| c.caller.clone()),
            },
        );
        // Identified (above, off the request as it arrived), the plane never sees the credential
        // the gate consumed — it carries the ref in the payload instead (#65, #40(b)).
        crate::auth::ConsumedCredentials::strip_from(consumed.as_deref(), &mut headers);
        // The plane ANSWERS (#28); this handler is the outer one that serves the answer.
        return ingress(busbar_kernel::ingress::arrival::Arrival {
            host: std::sync::Arc::new(crate::ingress::arrival_host::CoreArrivalHost),
            ctx,
            path,
            model_hint: None,
            uri,
            headers,
            body,
        })
        .await
        .into_response();
    }
    crate::fallback_error_response(
        &app.planes,
        &path,
        StatusCode::NOT_FOUND,
        crate::taxonomy::ERR_TYPE_NOT_FOUND,
        "the requested resource was not found",
    )
}
