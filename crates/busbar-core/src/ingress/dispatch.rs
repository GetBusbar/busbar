// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol catch-all dispatch (design: web server listens for anything → Router IDs the
//! protocol → that protocol's `RequestHandler` decides the operation → its OperationHandler). Holds
//! `protocol_dispatch` (the axum fallback), the generic `operation_ingress` for the 1.2 operations,
//! and the bedrock InvokeModel arm. A child of `route` so it shares the ingress core's private
//! helpers (`finish*`, `governance_guard`) without widening their visibility.

use super::*;

/// Minimal `model` form-field extractor for multipart transcription. Scans only the HEAD of the
/// body (byte-level, no allocation) rather than lossy-converting the ENTIRE body: the `model` text
/// part sits before the (potentially multi-MiB binary) audio part in a well-formed request, so a
/// bounded head window finds it without allocating a full-body String per transcription. If it is
/// not in the head (a pathologically-ordered body), it resolves to `None` → a clean routing 404,
/// same as a genuinely-absent model.
fn multipart_model(body: &[u8]) -> Option<String> {
    // 64 KiB is far larger than any plausible run of text form fields preceding the audio blob.
    const HEAD: usize = 64 * 1024;
    let head = &body[..body.len().min(HEAD)];
    let find = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).position(|w| w == needle);
    let idx = find(head, b"name=\"model\"")?;
    let sep = find(&head[idx..], b"\r\n\r\n")? + idx + 4;
    let val = &head[sep..];
    let end = find(val, b"\r\n").unwrap_or(val.len());
    let m = String::from_utf8_lossy(&val[..end]).trim().to_string();
    (!m.is_empty()).then_some(m)
}

/// Ingress for the NEW operations (embeddings/moderations/images/audio, 1.2), for EVERY dialect that
/// speaks the op. Resolves the (protocol, operation) OperationHandler — absent ⇒ no-handler 404 in the CALLER's
/// dialect — then forwards through `proxy::forward_with_pool_parsed` (same-proto
/// passthrough or the cross-protocol IR bridge). Model resolution: `model_hint` for path-model dialects (gemini/bedrock —
/// their route handler parsed it from the URL), else the JSON body `model` (openai/cohere) or the
/// multipart form (openai transcription).
// 8 args: the (proto, operation, model_hint) triple is destined to collapse into the unified
// catch-all dispatch (Router → RequestHandler decides operation+model); grouping them into a
// one-shot struct now would be churn that collapse immediately deletes.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn operation_ingress(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    caller: &crate::auth::CallerToken,
    headers: &HeaderMap,
    body: Bytes,
    proto: &'static str,
    operation: crate::operation::Operation,
    model_hint: Option<String>,
) -> Response {
    let caller_token = caller.0.as_deref();
    let started = Instant::now();
    let charged_at = crate::store::now();

    let Some(rh) = crate::handlers::request_handler(proto) else {
        return finish_rejected(
            app,
            gov,
            proto,
            crate::proxy::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::proxy::KIND_NOT_FOUND,
                "This protocol does not support that operation.",
            ),
        );
    };
    let Some(op_handler) = rh.operation_handler(operation) else {
        return finish_rejected(
            app,
            gov,
            proto,
            crate::proxy::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::proxy::KIND_NOT_FOUND,
                "This endpoint does not support that operation.",
            ),
        );
    };

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // VALIDATE ONCE, before model extraction, so a malformed JSON body gets the parse 400 (below),
    // never a misleading missing-model 400. `LazyBody::parse` preserves the exact malformed-body
    // reject set of the old eager `parse::<Value>` (same depth guard, same parser, full-body scan)
    // but builds NO DOM — only the top-level head projection the passthrough path reads. The full
    // `Value` tree is materialized downstream ONLY on the paths that need it (cross-protocol
    // translation, hooks, taps, gates, failover hops 2+).
    let parsed_v: Option<crate::proxy::LazyBody> = if ct.starts_with("application/json")
        || ct.is_empty()
    {
        match crate::proxy::LazyBody::parse(&body) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::debug!(detail = %crate::json::parse_err_log(body.len()), "request body JSON parse failed");
                return finish_rejected(
                    app,
                    gov,
                    proto,
                    crate::proxy::POOL_LABEL_UNRESOLVED,
                    started,
                    charged_at,
                    ingress_error(
                        proto,
                        StatusCode::BAD_REQUEST,
                        crate::proxy::KIND_INVALID_REQUEST,
                        "We could not parse the JSON body of your request.",
                    ),
                );
            }
        }
    } else {
        None
    };
    let model = if let Some(m) = model_hint {
        Some(m)
    } else if ct.starts_with("multipart/") {
        multipart_model(&body)
    } else {
        // `model` is a captured head key: this point read never materializes the DOM and returns
        // exactly what the full `Value` returned (missing / non-string / non-object body -> None).
        parsed_v.as_ref().and_then(|v| {
            v.probe()
                .get("model")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
    };
    let model = match model {
        Some(m) if !m.is_empty() => m,
        _ => {
            return finish_rejected(
                app,
                gov,
                proto,
                crate::proxy::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::proxy::KIND_INVALID_REQUEST,
                    "Missing required parameter: 'model'.",
                ),
            );
        }
    };

    operation_resolved(
        app,
        gov,
        proto,
        operation,
        op_handler,
        &model,
        headers,
        body,
        parsed_v,
        caller_token,
        started,
        charged_at,
        None,
    )
    .await
}

/// THE UNIVERSAL RESOLVED CORE — every operation, chat included, from the moment the model is known:
/// governance → candidates → affinity → the one engine. `gemini_api_version` shapes the gemini
/// dialect's model-not-found echo; everything else is operation- and protocol-blind.
///
/// THE ONE GAUNTLET (1.6 vision): this is the single canonical entry every arrival converges on once
/// the model is resolved. It is surfaced as [`crate::operation::run`] — the name the plane hooks
/// (M2–M5) grow onto — while [`operation_resolved`] remains a thin delegator preserving the existing
/// ingress call surface. Today the two are byte-identical; the gauntlet body lives here.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    operation: crate::operation::Operation,
    op_handler: &'static dyn crate::handlers::OperationHandler,
    model: &str,
    headers: &HeaderMap,
    body: Bytes,
    parsed_v: Option<crate::proxy::LazyBody>,
    caller_token: Option<&str>,
    started: Instant,
    charged_at: u64,
    gemini_api_version: Option<&str>,
) -> Response {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (admit, downgraded) = match governance_guard(app, gov, proto, model, started, charged_at) {
        Err(resp) => return *resp,
        Ok(admitted) => admitted,
    };
    let charged = admit.is_some();
    // A budget downgrade re-pooled the admission: dispatch through the pool the charge
    // actually landed on, not the one the client asked for.
    let model = downgraded.as_deref().unwrap_or(model);

    let (cands, pool_name): (Vec<WeightedLane>, &str) = if let Some(c) = app.pools.get(model) {
        (c.clone(), model)
    } else if let Some(&i) = app.by_model.get(model) {
        (
            vec![WeightedLane {
                reasoning: None,
                idx: i,
                weight: 1,
                attempt_timeout_ms: None,
            }],
            "",
        )
    } else {
        return finish_admitted(
            app,
            gov,
            proto,
            pool_label(app, model),
            started,
            charged_at,
            ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::proxy::KIND_NOT_FOUND,
                &not_found_message(model, gemini_api_version),
            ),
            charged,
        );
    };

    // THE ONE ENGINE: every operation — chat included — forwards through the same failover/breaker/
    // policy pipeline. JSON bodies ride parsed (`Some(v)`, parsed once by the caller); opaque bodies
    // (multipart/binary) ride `None` and relay/translate at the byte level via the operation codecs.
    let v = parsed_v;
    // Session affinity: the pool's configured affinity header, read generically for EVERY operation
    // (sticky routing is an engine capability, not a chat feature).
    let affinity_key: Option<String> = headers
        .get(affinity_header_for(app, model))
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);
    let resp = crate::proxy::forward_with_pool_parsed(
        app,
        cands,
        body,
        v,
        // `ct` borrows `headers` (a caller-held reference that outlives this call) — no per-request
        // `to_string` copy is needed to thread the Content-Type through.
        if ct.is_empty() {
            crate::proxy::APPLICATION_JSON
        } else {
            ct
        },
        caller_token,
        // The key the auth layer resolved/synthesized for this caller — lets the routing-signal
        // path project rate_headroom/identity for group/SSO principals whose token is not a
        // virtual-key secret (so a token `lookup` would miss).
        gov.key.as_ref(),
        pool_name,
        affinity_key.as_deref(),
        proto,
        // THE THIRD AXIS IS DECIDED AT THE ARRIVAL, which is the only place that knows it. This is
        // an axum handler: the exchange came in on one HTTP request and leaves on its response, so
        // the transport is `Http` and saying so is a statement of fact, not a default. The stdio
        // and gRPC arrivals get their own entry points and frame the same codecs.
        crate::handlers::frame(crate::transport::Transport::Http, operation, op_handler),
        usage_sink(app, gov, pool_name, charged_at, admit),
    )
    .await;
    finish_admitted(app, gov, proto, model, started, charged_at, resp, charged)
}

/// The stable ingress name for the resolved-operation gauntlet, retained as a thin delegator to the
/// canonical [`run`] (surfaced as [`crate::operation::run`]). Signature- and behavior-identical to
/// `run`: its three callers — `operation_ingress`, the ingress core's chat entry, and the
/// MCP-sampling veneer in `plane_host` — plus the `pub use dispatch::operation_resolved` re-export
/// keep their exact call surface while `run` becomes the single entry the plane hooks grow onto.
#[allow(clippy::too_many_arguments)]
pub async fn operation_resolved(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    operation: crate::operation::Operation,
    op_handler: &'static dyn crate::handlers::OperationHandler,
    model: &str,
    headers: &HeaderMap,
    body: Bytes,
    parsed_v: Option<crate::proxy::LazyBody>,
    caller_token: Option<&str>,
    started: Instant,
    charged_at: u64,
    gemini_api_version: Option<&str>,
) -> Response {
    run(
        app,
        gov,
        proto,
        operation,
        op_handler,
        model,
        headers,
        body,
        parsed_v,
        caller_token,
        started,
        charged_at,
        gemini_api_version,
    )
    .await
}

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
            crate::ingress::arrival_host::ArrivalPayload { app, gov, caller },
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
    // Body-model protocols: the RequestHandler names the operation; every operation → the generic
    // operation ingress. (`anthropic` bare `/v1/messages` is served here — an Anthropic SDK pointed
    // at busbar root works like every other dialect; the named/adhoc prefix routes remain for
    // URL-pinned model selection.)
    let op =
        crate::handlers::request_handler(proto).and_then(|rh| rh.resolve_operation(&path, &body));
    match op {
        // EVERY operation — chat included — takes the same universal ingress. No chat match, no
        // chat cores: body-model dialects resolve the model from the body inside
        // `operation_ingress`, exactly like embeddings or speech.
        Some(op) => operation_ingress(&app, &gov, &caller, &headers, body, proto, op, None).await,
        None => crate::fallback_error_response(
            &app.planes,
            &path,
            StatusCode::NOT_FOUND,
            crate::admin::ERR_TYPE_NOT_FOUND,
            "the requested resource was not found",
        ),
    }
}

#[cfg(test)]
#[path = "tests/multipart_model_tests.rs"]
mod multipart_model_tests;
