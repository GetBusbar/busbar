// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PATH-MODEL DIALECT ARRIVALS — Gemini and Bedrock keep their model in the URL, so each parses
//! ITS OWN model out of the path (its statement about its own URL space) and then runs the SAME
//! resolution + forward every dialect runs. RELOCATED here from `busbar-core` (it named the dialects
//! and was the last piece of core→plane entanglement): the arrivals now live in the dialect crate and
//! reach the `App`/`GovCtx`/`CallerToken`-bound core pipeline through the neutral
//! [`busbar_substrate::ingress::arrival::ArrivalHost`] seam, crossing those core handles as the opaque
//! [`ArrivalCtx`] and the neutral `Operation`/`Response`/`HeaderMap`/`Bytes` directly. So this crate
//! names no `busbar_core::` item and core names no dialect — byte-identical to the arms these replaced.
//!
//! The composition root registers these two through [`crate::PATH_INGRESS`] beside [`crate::DECLS`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use busbar_substrate::handlers::RequestHandler;
use busbar_substrate::ingress::arrival::{Arrival, ArrivalCtx, ArrivalHost};
use busbar_substrate::proxy::POOL_LABEL_UNRESOLVED;

use crate::proto_codec::{PROTO_BEDROCK, PROTO_GEMINI};

type Fut = Pin<Box<dyn Future<Output = Response> + Send>>;

/// The dialect's own installed `RequestHandler`, resolved through the neutral protocol registry (the
/// byte-identical equivalent of core's old `handlers::request_handler(proto)`).
fn request_handler(proto: &str) -> Option<&'static dyn RequestHandler> {
    busbar_substrate::proto::registry()
        .decl(proto)
        .and_then(|d| d.handler)
}

// ── GEMINI ────────────────────────────────────────────────────────────────────────────────────────

/// The Gemini API version token to echo in the native error envelope, derived from the actual ingress
/// path the client used. busbar mounts the Gemini surface at both the stable `/v1/models/...` and the
/// `/v1beta/models/...` prefixes; the real Gemini API echoes whichever the caller sent. Matching the
/// prefix verbatim keeps the error indistinguishable from the native API. Unknown shapes fall back to
/// "v1beta" (the historical default and the documented full surface).
fn gemini_api_version(path: &str) -> &'static str {
    if path.starts_with("/v1beta/") {
        "v1beta"
    } else if path.starts_with("/v1/") {
        "v1"
    } else {
        "v1beta"
    }
}

/// True when the raw query string carries an `alt=sse` pair (the Gemini SSE-streaming selector). Scans
/// `&`-separated `key=value` pairs so it is not fooled by another param whose value contains the
/// substring `alt=sse`.
fn query_has_alt_sse(query: &str) -> bool {
    query
        .split('&')
        .any(|pair| matches!(pair.split_once('='), Some(("alt", "sse"))))
}

/// GEMINI'S PATH-MODEL ARRIVAL, as it is DECLARED on `crate::gemini::DECL` / registered via
/// [`crate::PATH_INGRESS`]. Percent-decode the tail that axum's `{*rest}` wildcard decoded before the
/// route collapse, and hand it to this dialect's own ingress.
pub fn gemini_arrival(a: Arrival) -> Fut {
    let rest = a
        .host
        .percent_decode(a.path.split("/models/").nth(1).unwrap_or(""));
    Box::pin(gemini_ingress(
        a.host, a.ctx, rest, a.uri, a.headers, a.body,
    ))
}

#[tracing::instrument(level = "debug", name = "gemini_ingress", skip_all)]
async fn gemini_ingress(
    host: Arc<dyn ArrivalHost>,
    ctx: ArrivalCtx,
    rest: String,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The native Gemini error envelope echoes the API version the client actually used in its path.
    let api_version = gemini_api_version(uri.path());

    // Captured BEFORE the path-parse guards so a malformed-path / unsupported-action rejection (which
    // never reaches the path-model core, where `started` is otherwise taken) is still counted through
    // `finish_rejected` — the same pre-routing observability invariant the body/path cores enforce.
    let started = Instant::now();
    let charged_at = busbar_substrate::store::now();

    // `rest` is everything after `/{version}/models/`, e.g. `foo:generateContent`. Split on the LAST
    // colon into (model, action). A missing colon (or an empty model/action) is NOT necessarily a
    // malformed Gemini path: the stable `/v1/models/{id}` prefix is SHARED with the OpenAI SDK's
    // `model.retrieve`, which carries no `:<action>`. Resolve the error ENVELOPE protocol from the same
    // canonical classifier the fallback/405 handlers use so a colon-less hit gets the shape its
    // most-likely client expects: `/v1beta/...` (Gemini-only) stays Gemini; a colon-less
    // `/v1/models/...` gets the canonical OpenAI `not_found_error` envelope.
    let (model, action) = match rest.rsplit_once(':') {
        Some((m, a)) if !m.is_empty() && !a.is_empty() => (m, a),
        _ => {
            let envelope_proto = host.envelope_dialect(&ctx, uri.path());
            if busbar_substrate::proto::registry()
                .decl(envelope_proto)
                .is_some_and(|d| d.has_native_path_not_found)
            {
                return host.finish_rejected(
                    &ctx,
                    envelope_proto,
                    POOL_LABEL_UNRESOLVED,
                    started,
                    charged_at,
                    host.ingress_error(
                        envelope_proto,
                        StatusCode::NOT_FOUND,
                        host.kind_not_found(),
                        &format!(
                "Invalid resource path: models/{rest} is not found for API version {api_version}."
            ),
                    ),
                );
            }
            // Non-Gemini (ambiguous `/v1/models/...` without a Gemini action suffix): emit the
            // canonical OpenAI-shaped 404 the fallback handler uses for this path.
            return host.finish_rejected(
                &ctx,
                envelope_proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                host.ingress_error(
                    envelope_proto,
                    StatusCode::NOT_FOUND,
                    host.kind_not_found(),
                    "the requested resource was not found",
                ),
            );
        }
    };

    // The gemini RequestHandler resolves WHICH operation this request is — ONE resolution, and every
    // operation takes the SAME flow below.
    let operation =
        request_handler(PROTO_GEMINI).and_then(|rh| rh.resolve_operation(uri.path(), &body));

    // Only the two generate actions are proxied. Any other action is an intentional limitation and
    // returns a NOT_FOUND envelope whose SHAPE matches the same `ingress_of` resolver the no-colon
    // branch (and the fallback/405 handlers) use.
    let stream = match (operation.is_some(), action) {
        (true, "streamGenerateContent") => true,
        (true, _) => false, // generateContent / embedContent / predict — non-stream in 1.2
        (false, other) => {
            let envelope_proto = host.envelope_dialect(&ctx, uri.path());
            if busbar_substrate::proto::registry()
                .decl(envelope_proto)
                .is_some_and(|d| d.has_native_path_not_found)
            {
                return host.finish_rejected(
                    &ctx,
                    envelope_proto,
                    POOL_LABEL_UNRESOLVED,
                    started,
                    charged_at,
                    host.ingress_error(
                        envelope_proto,
                        StatusCode::NOT_FOUND,
                        host.kind_not_found(),
                        &format!(
                            "models/{model} is not found for API version {api_version}, \
                             or is not supported for {other}."
                        ),
                    ),
                );
            }
            return host.finish_rejected(
                &ctx,
                envelope_proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                host.ingress_error(
                    envelope_proto,
                    StatusCode::NOT_FOUND,
                    host.kind_not_found(),
                    "the requested resource was not found",
                ),
            );
        }
    };

    // `?alt=sse` selects SSE framing for a STREAMING request; its ABSENCE means the native client
    // expects the JSON-array streaming format. Only a streaming request without `alt=sse` engages it.
    let alt_sse = uri.query().map(query_has_alt_sse).unwrap_or(false);
    let gemini_json_array = stream && !alt_sse;

    // `operation` is Some here (a None already returned the unsupported-action envelope above); bail
    // with the standard no-handler 404 rather than assume any operation.
    let Some(operation) = operation else {
        return host.finish_rejected(
            &ctx,
            PROTO_GEMINI,
            POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            host.ingress_error(
                PROTO_GEMINI,
                StatusCode::NOT_FOUND,
                host.kind_not_found(),
                "This endpoint does not support that operation.",
            ),
        );
    };
    crate::native_ingress::ingress_path_model(
        &ctx,
        headers,
        body,
        model.to_string(),
        operation,
        stream,
        gemini_json_array,
        PROTO_GEMINI,
        // The native Gemini model-not-found body, SHAPED HERE — this dialect owns its own not-found
        // vocabulary (versioned with the path-derived api_version, no OpenAI "does not exist" copy) and
        // core uses it verbatim on a model miss. Core names no dialect; the shaping lives with the dialect.
        Some(format!(
            "models/{model} is not found for API version {api_version}, \
             or is not supported for the task you are trying to perform."
        )),
    )
    .await
}

// ── BEDROCK ─────────────────────────────────────────────────────────────────────────────────────

/// BEDROCK'S PATH-MODEL ARRIVAL, as it is DECLARED on `crate::bedrock::DECL`. Three shapes under one
/// model path — `converse`, `converse-stream` and `invoke` — plus the native 404 for anything else.
pub fn bedrock_arrival(a: Arrival) -> Fut {
    // axum's Path extractor percent-decoded {model_id} before the collapse; match it.
    let model = request_handler(PROTO_BEDROCK)
        .and_then(|rh| rh.path_model(&a.path))
        .map(|m| a.host.percent_decode(&m))
        .unwrap_or_default();
    let Arrival {
        host,
        ctx,
        path,
        model_hint: _,
        uri,
        headers,
        body,
    } = a;
    if path.ends_with("/converse") {
        Box::pin(bedrock_converse(host, ctx, model, headers, body))
    } else if path.ends_with("/converse-stream") {
        Box::pin(bedrock_converse_stream(host, ctx, model, headers, body))
    } else if path.ends_with("/invoke") {
        Box::pin(bedrock_invoke(host, ctx, model, uri, headers, body))
    } else {
        Box::pin(async move {
            host.fallback_not_found(
                &ctx,
                &path,
                StatusCode::NOT_FOUND,
                host.err_type_not_found(),
                "the requested resource was not found",
            )
        })
    }
}

#[tracing::instrument(level = "debug", name = "bedrock_converse", skip_all)]
async fn bedrock_converse(
    host: Arc<dyn ArrivalHost>,
    ctx: ArrivalCtx,
    model_id: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Pre-routing accounting, mirroring `bedrock_invoke` and the gemini arrival: a pre-charge exit
    // must flow through `finish_rejected` so it stays visible to Prometheus/the webhook. The reject
    // arm below is provably unreachable today (bedrock `resolve_operation` returns `Some(CHAT)`
    // unconditionally for a `/converse` path — see `handler.rs`), but routing it consistently means a
    // future resolver that CAN yield `None` accounts for the rejection instead of silently
    // `ingress_error`-ing it, matching every other pre-routing reject in this file.
    let started = Instant::now();
    let charged_at = busbar_substrate::store::now();
    let Some(op) = request_handler(PROTO_BEDROCK)
        .and_then(|rh| rh.resolve_operation(&format!("/model/{model_id}/converse"), &body))
    else {
        return host.finish_rejected(
            &ctx,
            PROTO_BEDROCK,
            POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            host.ingress_error(
                PROTO_BEDROCK,
                StatusCode::NOT_FOUND,
                host.kind_not_found(),
                "This endpoint does not support that operation.",
            ),
        );
    };
    bedrock_ingress(host, ctx, model_id, op, false, headers, body).await
}

#[tracing::instrument(level = "debug", name = "bedrock_converse_stream", skip_all)]
async fn bedrock_converse_stream(
    host: Arc<dyn ArrivalHost>,
    ctx: ArrivalCtx,
    model_id: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // See `bedrock_converse`: the reject arm is unreachable today (converse-stream also resolves to
    // `Some(CHAT)` unconditionally) but is routed through `finish_rejected` for pre-routing accounting
    // consistency with `bedrock_invoke` and the gemini arrival.
    let started = Instant::now();
    let charged_at = busbar_substrate::store::now();
    let Some(op) = request_handler(PROTO_BEDROCK)
        .and_then(|rh| rh.resolve_operation(&format!("/model/{model_id}/converse-stream"), &body))
    else {
        return host.finish_rejected(
            &ctx,
            PROTO_BEDROCK,
            POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            host.ingress_error(
                PROTO_BEDROCK,
                StatusCode::NOT_FOUND,
                host.kind_not_found(),
                "This endpoint does not support that operation.",
            ),
        );
    };
    bedrock_ingress(host, ctx, model_id, op, true, headers, body).await
}

/// Shared body for both Bedrock converse routes: delegate to the path-model core with the
/// route-selected stream intent. The `modelId` segment arrives ALREADY percent-decoded by axum, so it
/// is used verbatim (decoding twice corrupts ids whose first decode yields a literal `%XX`).
async fn bedrock_ingress(
    host: Arc<dyn ArrivalHost>,
    ctx: ArrivalCtx,
    model_id: String,
    operation: busbar_api::operation::Operation,
    stream: bool,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Bedrock never uses the gemini JSON-array framing, and a model-not-found 404 uses the canonical
    // (non-gemini) message, so no api_version is threaded.
    crate::native_ingress::ingress_path_model(
        &ctx,
        headers,
        body,
        model_id,
        operation,
        stream,
        false,
        PROTO_BEDROCK,
        None,
    )
    .await
}

/// POST /model/{model_id}/invoke — Bedrock `InvokeModel` ingress. The path names the model; the bedrock
/// RequestHandler reads the BODY and decides the operation. An unrecognized body is a clean 400 in the
/// Bedrock dialect.
async fn bedrock_invoke(
    host: Arc<dyn ArrivalHost>,
    ctx: ArrivalCtx,
    model_id: String,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Mirror the path-model core's pre-routing accounting: every pre-charge exit must flow through
    // `finish_rejected`, or the request is invisible to Prometheus/the webhook.
    let started = Instant::now();
    let charged_at = busbar_substrate::store::now();
    let Some(operation) =
        request_handler(PROTO_BEDROCK).and_then(|rh| rh.resolve_operation(uri.path(), &body))
    else {
        return host.finish_rejected(
            &ctx,
            PROTO_BEDROCK,
            POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            host.ingress_error(
                PROTO_BEDROCK,
                StatusCode::BAD_REQUEST,
                host.kind_invalid_request(),
                "InvokeModel body is not a supported operation (expected inputText or textToImageParams).",
            ),
        );
    };
    crate::native_ingress::operation_ingress(
        &ctx,
        headers,
        body,
        PROTO_BEDROCK,
        operation,
        Some(model_id),
    )
    .await
}

// ── BODY-MODEL DIALECT ARRIVALS ─────────────────────────────────────────────────────────────────
// The four body-model dialects (anthropic/openai/cohere/responses) — and the body variants of the
// URL-model pair — keep the model IN THE BODY: the convenience surfaces (`named`/`adhoc` `/v1/messages`)
// and the generic `protocol_dispatch` body-model arm resolve them by protocol name through
// `busbar_substrate::ingress::arrival::body_ingress_for(proto)`. This SIDE-TABLE is the body-axis twin
// of [`crate::PATH_INGRESS`]: it maps each dialect NAME to a `BodyIngress` fn that resolves the
// operation off the endpoint (its own `RequestHandler::resolve_operation`) and runs the universal
// [`crate::native_ingress::operation_ingress`] forward. Registered by the composition root
// (`register_protocols` → `install_body_ingress`) and by the test-kit ([`crate::testkit::install_test_seams`]
// → `set_test_body_ingress`), the byte-identical successor to the pre-relocation in-core body arrival.

/// Shared body-model arrival: resolve the operation for `proto` off the endpoint, then run the one
/// engine. A body whose operation the dialect does not serve is the honest pre-routing 404 (accounted
/// through `finish_rejected`, like every other pre-routing reject).
async fn body_arrival(proto: &'static str, a: Arrival) -> Response {
    let Arrival {
        host,
        ctx,
        path: _,
        model_hint,
        uri,
        headers,
        body,
    } = a;
    let started = Instant::now();
    let charged_at = busbar_substrate::store::now();
    let Some(operation) =
        request_handler(proto).and_then(|rh| rh.resolve_operation(uri.path(), &body))
    else {
        return host.finish_rejected(
            &ctx,
            proto,
            POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            host.ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                host.kind_not_found(),
                "This endpoint does not support that operation.",
            ),
        );
    };
    // `model_hint` carries the busbar convenience surfaces' PATH-borne routing name (`named`/`adhoc`);
    // `None` for a dialect-native body-model arrival, where the model rides the body.
    crate::native_ingress::operation_ingress(&ctx, headers, body, proto, operation, model_hint).await
}

/// Generate one `BodyIngress` fn-pointer target per dialect (a bare `fn(Arrival) -> Fut`, since the
/// registry seam is a fn pointer that cannot capture the protocol name).
macro_rules! body_arrivals {
    ($(($name:ident, $proto:expr)),+ $(,)?) => {
        $(
            pub fn $name(a: Arrival) -> Fut {
                Box::pin(body_arrival($proto, a))
            }
        )+
    };
}

body_arrivals! {
    (anthropic_body_arrival, crate::proto_codec::PROTO_ANTHROPIC),
    (openai_body_arrival, crate::proto_codec::PROTO_OPENAI),
    (gemini_body_arrival, crate::proto_codec::PROTO_GEMINI),
    (bedrock_body_arrival, crate::proto_codec::PROTO_BEDROCK),
    (responses_body_arrival, crate::proto_codec::PROTO_RESPONSES),
    (cohere_body_arrival, crate::proto_codec::PROTO_COHERE),
}

#[cfg(test)]
#[path = "tests/arrival_tests.rs"]
mod arrival_tests;
