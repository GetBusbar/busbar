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

/// THE NATIVE (LLM) PLANE — the pool/engine routing that lives in-core today (the path an LLM arrival
/// takes), now expressed as a sibling on the NEUTRAL gauntlet seam
/// ([`busbar_substrate::plane_host::GauntletPlane`]) so it rides the exact SAME shared sequence as the
/// extracted MCP/A2A planes. Named plane-neutrally so the neutral core spells no plane-family type
/// (per the freeze and purity law). Holds this request's owned + borrowed payload; `drive` moves it
/// into the one engine.
///
/// The two hooks are today's inline gauntlet logic, VERBATIM: `verify_destination` is the
/// pre-admission [`destination_guard`] (pool ACL, fallback-pool ACL, unpriced-model gate); `drive` is
/// the single budget-admission door ([`admission_door`]) → pool/lane candidate selection →
/// `forward_with_pool_parsed` (THE ONE ENGINE, streaming) → [`finish_admitted`]. Byte-identical to
/// the pre-seam `operation_resolved`: same order, same errors, same `model_not_found_message`/not-found
/// shaping, same budget-door position, same stream-end metering. A later milestone relocates this
/// impl into its plane crate; M3 only makes it a sibling on the shared seam.
struct NativePlane<'a> {
    app: &'a Arc<App>,
    proto: &'static str,
    operation: crate::operation::Operation,
    op_handler: &'static dyn crate::handlers::OperationHandler,
    headers: &'a HeaderMap,
    body: Bytes,
    parsed_v: Option<crate::proxy::LazyBody>,
    caller_token: Option<&'a str>,
    /// A dialect's PRE-SHAPED model-not-found body, or `None` for the neutral copy. The dialect that
    /// owns the request built this at arrival (a path-model dialect that echoes its own not-found
    /// vocabulary); `drive` uses it verbatim on a model miss, opaque to every other stage — core names
    /// no dialect here.
    model_not_found_message: Option<&'a str>,
}

#[async_trait::async_trait]
impl busbar_substrate::plane_host::GauntletPlane for NativePlane<'_> {
    fn verify_destination(
        &self,
        req: &busbar_substrate::plane_host::GauntletRequest<'_>,
    ) -> busbar_substrate::plane_host::VerifyOutcome {
        use busbar_substrate::plane_host::VerifyOutcome;
        // STAGE 2 — the pre-admission destination guard, verbatim. Its `Err` is the already-finished,
        // protocol-native rejection; the seam returns it as `Refuse` (byte-identical shaping).
        match destination_guard(
            self.app,
            req.gov,
            self.proto,
            req.destination,
            req.started,
            req.charged_at,
        ) {
            Ok(()) => VerifyOutcome::Proceed,
            Err(resp) => VerifyOutcome::Refuse(*resp),
        }
    }

    async fn drive(
        self: Box<Self>,
        req: busbar_substrate::plane_host::GauntletRequest<'_>,
    ) -> Response {
        // Move the owned per-request payload out of the box; the borrowed fields ride along.
        let NativePlane {
            app,
            proto,
            operation,
            op_handler,
            headers,
            body,
            parsed_v,
            caller_token,
            model_not_found_message,
        } = *self;

        // STAGE 3–4 — THE single budget-admission door charges the chain buckets. On rejection
        // nothing was charged (the door finished it).
        let (admit, downgraded) = match admission_door(
            app,
            req.gov,
            proto,
            req.destination,
            req.started,
            req.charged_at,
        ) {
            Err(resp) => return *resp,
            Ok(admitted) => admitted,
        };
        let charged = admit.is_some();
        // A budget downgrade re-pooled the admission: dispatch through the pool the charge actually
        // landed on, not the one the client asked for.
        let model = downgraded.as_deref().unwrap_or(req.destination);

        // STAGE 5 — candidate selection + THE ONE ENGINE.
        let (cands, pool_name): (Vec<WeightedLane>, &str) =
            if let Some(c) = app.engine_tables().pools().get(model) {
                (c.clone(), model)
            } else if let Some(&i) = app.engine_tables().by_model().get(model) {
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
                // The destination did not resolve — the dialect-shaped not-found, finished through the
                // SAME stage-6 tail as a served request (so the pre-seam not-found accounting is exact).
                let resp = ingress_error(
                    proto,
                    StatusCode::NOT_FOUND,
                    crate::proxy::KIND_NOT_FOUND,
                    &not_found_message(model, model_not_found_message),
                );
                return finish_admitted(
                    app,
                    req.gov,
                    proto,
                    pool_label(app, model),
                    req.started,
                    req.charged_at,
                    resp,
                    charged,
                );
            };

        // THE ONE ENGINE: every operation — chat included — forwards through the same failover/
        // breaker/policy pipeline. JSON bodies ride parsed (`Some(v)`, parsed once by the caller);
        // opaque bodies (multipart/binary) ride `None` and relay/translate at the byte level via the
        // operation codecs.
        let ct = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Session affinity: the pool's configured affinity header, read generically for EVERY
        // operation (sticky routing is an engine capability, not a chat feature).
        let affinity_key: Option<String> = headers
            .get(affinity_header_for(app, model))
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let resp = crate::proxy::forward_with_pool_parsed(
            app,
            cands,
            body,
            parsed_v,
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
            req.gov.key.as_ref(),
            pool_name,
            affinity_key.as_deref(),
            proto,
            // THE THIRD AXIS IS DECIDED AT THE ARRIVAL, which is the only place that knows it. This is
            // an axum handler: the exchange came in on one HTTP request and leaves on its response, so
            // the transport is `Http` and saying so is a statement of fact, not a default. The stdio
            // and gRPC arrivals get their own entry points and frame the same codecs.
            crate::handlers::frame(crate::transport::Transport::Http, operation, op_handler),
            usage_sink(app, req.gov, pool_name, req.charged_at, admit),
        )
        .await;

        // STAGE 6 — audit + finish/metrics/refund. `pool_label` bounds the metric label — the
        // effective model is a configured pool/lane on the served path — so this reproduces the
        // pre-seam served tail exactly.
        finish_admitted(
            app,
            req.gov,
            proto,
            pool_label(app, model),
            req.started,
            req.charged_at,
            resp,
            charged,
        )
    }
}

/// THE UNIVERSAL RESOLVED CORE — every operation, chat included, from the moment the model is known:
/// governance → candidates → affinity → the one engine. `model_not_found_message` is a dialect's
/// PRE-SHAPED model-not-found body (built by the arrival that owns the request), used verbatim on a
/// model miss; everything else is operation- and protocol-blind, and core names no dialect.
///
/// THE ONE GAUNTLET (1.6 vision): this is the single canonical entry every arrival converges on once
/// the model is resolved. It is surfaced as [`crate::operation::run`] — while [`operation_resolved`]
/// remains a thin delegator preserving the existing ingress call surface. The body assembles the LLM
/// [`NativePlane`] and rides the NEUTRAL shared sequence
/// [`busbar_substrate::plane_host::run_gauntlet`]: stage 1 identity (via `gov`) → the plane's
/// `verify_destination` (stage 2, pre-admission) → the plane's `drive` (stages 3–6, the one engine +
/// finish). The MCP/A2A planes ride the SAME sequence as siblings. Byte-identical to the pre-seam
/// `operation_resolved`.
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
    model_not_found_message: Option<&str>,
) -> Response {
    let plane = NativePlane {
        app,
        proto,
        operation,
        op_handler,
        headers,
        body,
        parsed_v,
        caller_token,
        model_not_found_message,
    };
    // The shared sequence owns only stage 1 (identity, via `gov`) and the verify-before-admit order;
    // the LLM plane's `drive` owns admission/route/metering/finish byte-identically. `correlation_id`
    // is `0` here: the LLM engine stamps its own per-request id inside `forward_with_pool_parsed`
    // (`App::next_request_id`), so the shared field is unused on this path and must NOT pre-stamp one
    // (that would double-advance the counter and shift every request id).
    let req = busbar_substrate::plane_host::GauntletRequest {
        gov,
        destination: model,
        correlation_id: 0,
        charged_at,
        started,
    };
    busbar_substrate::plane_host::run_gauntlet(req, Box::new(plane)).await
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
    model_not_found_message: Option<&str>,
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
        model_not_found_message,
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
