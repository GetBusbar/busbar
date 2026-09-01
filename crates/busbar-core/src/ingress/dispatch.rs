// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol catch-all dispatch (design: web server listens for anything → Router IDs the
//! protocol → that protocol's `RequestHandler` decides the operation → its OperationHandler). Holds
//! `protocol_dispatch` (the axum fallback), the generic `operation_ingress` for the 1.2 operations,
//! and the bedrock InvokeModel arm. A child of `route` so it shares the ingress core's private
//! helpers (`finish*`, `governance_guard`) without widening their visibility.

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
/// Gemini and Bedrock delegate to their protocol arms wholesale (path-model parsing, streaming
/// variants, native unsupported-action envelopes live there); the body-model protocols split here:
/// every operation → `operation_ingress` (the universal core). Unknown paths/methods keep the
/// pre-collapse fallback shaping (native 404/405 envelopes, no proxy tells).
pub(crate) async fn protocol_dispatch(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    OriginalUri(uri): OriginalUri,
    method: axum::http::Method,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_string();
    let Some(proto) = crate::proto::detect::protocol_id(&path, &headers) else {
        // Not a protocol endpoint: the pre-collapse 404 fallback shape (native envelope by path).
        return crate::fallback_error_response(
            &app.planes,
            &path,
            StatusCode::NOT_FOUND,
            crate::admin::ERR_TYPE_NOT_FOUND,
            "the requested resource was not found",
        );
    };
    if method != axum::http::Method::POST {
        // A protocol endpoint hit with the wrong method: the pre-collapse 405 shape.
        return crate::fallback_error_response(
            &app.planes,
            &path,
            StatusCode::METHOD_NOT_ALLOWED,
            crate::admin::ERR_TYPE_INVALID_REQUEST,
            "method not allowed for this resource",
        );
    }
    // THE UNIVERSAL RULE — we only process operations for which the protocol HOLDS an
    // OperationHandler; otherwise 404 in the caller's dialect. No operation is special: chat,
    // embeddings, audio — same consult, same terminal. Delete any protocol's handler for any
    // operation (its registry arm) and that operation dies HERE while everything else keeps working.
    // (`resolve_operation` = the RequestHandler naming the operation; `None` falls through to the
    // protocol arms, which own their native unknown-action envelopes.)
    if let Some(rh) = crate::handlers::request_handler(proto) {
        if let Some(op) = rh.resolve_operation(&path, &body) {
            if rh.operation_handler(op).is_none() {
                return crate::proxy::ingress_error(
                    proto,
                    StatusCode::NOT_FOUND,
                    crate::proxy::KIND_NOT_FOUND,
                    "This endpoint does not support that operation.",
                );
            }
        }
    }
    // THE PATH-MODEL ARRIVAL, RESOLVED FROM THE DECLARATION rather than from the protocol's NAME.
    //
    // This was `match proto { PROTO_GEMINI => …, PROTO_BEDROCK => … }` — the last two protocol-name
    // comparisons left in core after `proto::registry` turned the protocol axis into data. They
    // survived the registry unit because removing them needs an INGRESS on the declaration, which
    // is a mount-table question, and the mount table is what `crate::ingress::protocol` settled.
    // A protocol that parses its model out of the URL now DECLARES the function that does it; core
    // reads `path_ingress` and calls it, and a seventh dialect with a path model joins by
    // declaring one.
    //
    // THE FUTURE IS STILL BOXED, and for the reason the arms were: in a `match`, every arm's future
    // is inlined into the dispatch coroutine's union, so the gemini/bedrock arms (~5.7 KB each)
    // inflated the future EVERY request carried even when the traffic was another dialect. A
    // function pointer returning a boxed future keeps that allocation on the requests that take it
    // and nowhere else — and it is now the DECLARATION's boxing rather than this function's.
    // The arrival is resolved from the core-owned, protocol-name-keyed side-table rather than off the
    // declaration: `path_ingress` split off `ProtocolDecl` when the decl relocated to
    // `busbar-substrate` (it named the core-only `Arrival`, which the neutral leaf cannot). Same fn
    // pointer, same boxing, same by-name resolution — see `crate::ingress::path_ingress`.
    if let Some(path_ingress) = crate::ingress::path_ingress::path_ingress_for(proto) {
        // Mint the neutral arrival the dialect crate (`busbar-llm`) receives: its own URL-parsing
        // reads `path`/`uri`/`headers`/`body` directly, and it reaches core's resolution/forward
        // pipeline through `host`, threading the core-only `App`/`GovCtx`/`CallerToken` back opaquely
        // as `ctx` — so it names no `busbar_core::` item and core names no dialect.
        let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(
            crate::ingress::arrival_host::ArrivalPayload {
                app,
                gov,
                caller_token: caller.0.clone(),
            },
        );
        return path_ingress(busbar_substrate::ingress::arrival::Arrival {
            host: std::sync::Arc::new(crate::ingress::arrival_host::CoreArrivalHost),
            ctx,
            path,
            uri,
            headers,
            body,
        })
        .await;
    }
    // Body-model protocols keep the model IN THE BODY, so the universal resolution + forward tail
    // (the generic `operation_ingress` → the one engine) reads the LLM routing tables and RELOCATED
    // into the LLM plane (`busbar-llm`). Resolve that plane's universal body-arrival by protocol name
    // and hand it the neutral arrival, exactly like the path-model arm above — core names no LLM
    // type. No plane linked (core booted plane-agnostic) → the honest no-handler 404.
    if let Some(body_ingress) = busbar_substrate::ingress::arrival::body_ingress_for(proto) {
        let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(
            crate::ingress::arrival_host::ArrivalPayload {
                app,
                gov,
                caller_token: caller.0.clone(),
            },
        );
        return body_ingress(busbar_substrate::ingress::arrival::Arrival {
            host: std::sync::Arc::new(crate::ingress::arrival_host::CoreArrivalHost),
            ctx,
            path,
            uri,
            headers,
            body,
        })
        .await;
    }
    crate::fallback_error_response(
        &app.planes,
        &path,
        StatusCode::NOT_FOUND,
        crate::admin::ERR_TYPE_NOT_FOUND,
        "the requested resource was not found",
    )
}

#[cfg(test)]
#[path = "tests/multipart_model_tests.rs"]
mod multipart_model_tests;
