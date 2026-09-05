// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PATH-MODEL DIALECT ARRIVALS — Gemini and Bedrock keep their model in the URL, so each parses
//! ITS OWN model out of the path (its statement about its own URL space) and then runs the SAME
//! resolution + forward every dialect runs. RELOCATED here from `busbar-core` (it named the dialects
//! and was the last piece of core→plane entanglement): the arrivals now live in the dialect crate and
//! reach the `App`/`GovCtx`/`CallerToken`-bound core pipeline through the neutral
//! [`busbar_substrate::ingress::arrival::ArrivalHost`] seam, crossing those core handles as the opaque
//! [`ArrivalCtx`] and the neutral `Operation`/`Response`/`HeaderMap`/`Bytes` directly. So this crate
//! names no core item and core names no dialect — byte-identical to the arms these replaced.
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

// ── THE URL PARSE, AS A VALUE ────────────────────────────────────────────────────────────────────
// The two dialects below keep their model in the URL, and reading it out is the dialect's statement
// about its own URL space — the path-axis twin of the operation resolution a body-model arrival runs
// before it hands anything on. What USED to make that statement unreachable was that it was spelled
// INSIDE the same function that then resolved and forwarded: there was no seam between "what the URL
// says" and "what is done about it", so a second driver of the same surface had to either copy the
// parse or reach past it. The parse is a function now, and what it answers with is a value.

/// WHAT A PATH-MODEL DIALECT'S URL SAYS, once that dialect's own parse has read it.
///
/// Every field is a fact about the REQUEST rather than a decision about it: the model the URL named,
/// the operation the dialect resolved, whether the URL asked for a stream, whether that stream is the
/// JSON-array framing rather than SSE, and the dialect's own model-miss copy where it has one. What
/// is DONE with them is the caller's, which is the whole point of the split.
pub struct PathModelFacts {
    /// The model the URL named, percent-decoded exactly once.
    pub model: String,
    /// The operation this dialect resolved off its own endpoint.
    pub operation: busbar_api::operation::Operation,
    /// Whether the URL asked for a streamed answer.
    pub stream: bool,
    /// A streaming request that is NOT `alt=sse` and must be framed as a JSON array.
    pub gemini_json_array: bool,
    /// This dialect's own model-not-found copy, versioned from the path the caller used, or `None`
    /// where the dialect uses the neutral sentence.
    pub model_not_found_message: Option<String>,
}

impl std::fmt::Debug for PathModelFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathModelFacts")
            .field("model", &self.model)
            .field("operation", &self.operation.name())
            .field("stream", &self.stream)
            .field("gemini_json_array", &self.gemini_json_array)
            .finish_non_exhaustive()
    }
}

/// WHAT A PATH-MODEL DIALECT'S URL PARSE ANSWERS WITH.
///
/// Three answers and there is no fourth: the URL named a model and a stream intent, or it named a
/// model and left the operation to the body, or it is not a request this dialect answers at all.
pub enum PathArrivalFacts {
    /// The URL named the model AND the stream intent — the path-model surfaces proper.
    PathModel(PathModelFacts),
    /// The URL named only the model and the BODY names the operation: Bedrock's `invoke`, which runs
    /// the ordinary body-model forward with the URL's model as its routing hint.
    BodyModel {
        /// The operation the dialect resolved off the body.
        operation: busbar_api::operation::Operation,
        /// The model the URL named.
        model_hint: String,
    },
    /// Not a request this dialect answers. The bytes are the dialect's own — already shaped, and
    /// already accounted wherever the dialect accounts them — so both drivers of this surface return
    /// them unchanged rather than each deciding again what a bad URL looks like.
    Refused(Response),
}

/// GEMINI'S PATH-MODEL ARRIVAL, as it is DECLARED on `crate::gemini::DECL` / registered via
/// [`crate::PATH_INGRESS`]. Percent-decode the tail that axum's `{*rest}` wildcard decoded before the
/// route collapse, and hand it to this dialect's own ingress.
pub fn gemini_arrival(a: Arrival) -> Fut {
    let rest = gemini_rest(&a.host, &a.path);
    Box::pin(gemini_ingress(
        a.host, a.ctx, rest, a.uri, a.headers, a.body,
    ))
}

/// The tail axum's `{*rest}` wildcard carried, percent-decoded once. Split out so the two drivers of
/// this surface decode it the same way rather than each spelling the split.
pub fn gemini_rest(host: &Arc<dyn ArrivalHost>, path: &str) -> String {
    host.percent_decode(path.split("/models/").nth(1).unwrap_or(""))
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
    // Captured BEFORE the path-parse guards so a malformed-path / unsupported-action rejection (which
    // never reaches the path-model core, where `started` is otherwise taken) is still counted through
    // `finish_rejected` — the same pre-routing observability invariant the body/path cores enforce.
    let started = Instant::now();
    let charged_at = busbar_substrate::store::now();
    let facts = match gemini_path_parse(&host, &ctx, &rest, &uri, &body, started, charged_at) {
        PathArrivalFacts::PathModel(facts) => facts,
        PathArrivalFacts::Refused(resp) => return resp,
        // Gemini's parse never leaves the operation to the body: every action it answers is named in
        // the URL. Answered rather than unreachable-panicked, because an arm that cannot be taken
        // still has to say something if it is.
        PathArrivalFacts::BodyModel { .. } => {
            return host.fallback_not_found(
                &ctx,
                uri.path(),
                StatusCode::NOT_FOUND,
                host.err_type_not_found(),
                "the requested resource was not found",
            )
        }
    };
    crate::native_ingress::ingress_path_model(
        &ctx,
        headers,
        body,
        facts.model,
        facts.operation,
        facts.stream,
        facts.gemini_json_array,
        PROTO_GEMINI,
        // The native Gemini model-not-found body, SHAPED BY THE PARSE — this dialect owns its own
        // not-found vocabulary (versioned with the path-derived api_version, no OpenAI "does not
        // exist" copy) and core uses it verbatim on a model miss. Core names no dialect; the shaping
        // lives with the dialect.
        facts.model_not_found_message,
    )
    .await
}

/// GEMINI'S URL PARSE, as a value.
///
/// Everything `gemini_ingress` used to decide before it forwarded, and nothing it decided after. The
/// rejections it can answer with are built here, through the same `finish_rejected` the inline arms
/// used, because a pre-routing rejection is accounted where it is DECIDED — a caller that had to
/// re-account it would be a caller that could account it differently.
pub fn gemini_path_parse(
    host: &Arc<dyn ArrivalHost>,
    ctx: &ArrivalCtx,
    rest: &str,
    uri: &Uri,
    body: &Bytes,
    started: Instant,
    charged_at: u64,
) -> PathArrivalFacts {
    // The native Gemini error envelope echoes the API version the client actually used in its path.
    let api_version = gemini_api_version(uri.path());

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
            let envelope_proto = host.envelope_dialect(ctx, uri.path());
            if busbar_substrate::proto::registry()
                .decl(envelope_proto)
                .is_some_and(|d| d.has_native_path_not_found)
            {
                return PathArrivalFacts::Refused(host.finish_rejected(
                    ctx,
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
                ));
            }
            // Non-Gemini (ambiguous `/v1/models/...` without a Gemini action suffix): emit the
            // canonical OpenAI-shaped 404 the fallback handler uses for this path.
            return PathArrivalFacts::Refused(host.finish_rejected(
                ctx,
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
            ));
        }
    };

    // The gemini RequestHandler resolves WHICH operation this request is — ONE resolution, and every
    // operation takes the SAME flow below.
    let operation =
        request_handler(PROTO_GEMINI).and_then(|rh| rh.resolve_operation(uri.path(), body));

    // Only the two generate actions are proxied. Any other action is an intentional limitation and
    // returns a NOT_FOUND envelope whose SHAPE matches the same `ingress_of` resolver the no-colon
    // branch (and the fallback/405 handlers) use.
    let stream = match (operation.is_some(), action) {
        (true, "streamGenerateContent") => true,
        (true, _) => false, // generateContent / embedContent / predict — non-stream in 1.2
        (false, other) => {
            let envelope_proto = host.envelope_dialect(ctx, uri.path());
            if busbar_substrate::proto::registry()
                .decl(envelope_proto)
                .is_some_and(|d| d.has_native_path_not_found)
            {
                return PathArrivalFacts::Refused(host.finish_rejected(
                    ctx,
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
                ));
            }
            return PathArrivalFacts::Refused(host.finish_rejected(
                ctx,
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
            ));
        }
    };

    // `?alt=sse` selects SSE framing for a STREAMING request; its ABSENCE means the native client
    // expects the JSON-array streaming format. Only a streaming request without `alt=sse` engages it.
    let alt_sse = uri.query().map(query_has_alt_sse).unwrap_or(false);
    let gemini_json_array = stream && !alt_sse;

    // `operation` is Some here (a None already returned the unsupported-action envelope above); bail
    // with the standard no-handler 404 rather than assume any operation.
    let Some(operation) = operation else {
        return PathArrivalFacts::Refused(host.finish_rejected(
            ctx,
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
        ));
    };
    PathArrivalFacts::PathModel(PathModelFacts {
        model: model.to_string(),
        operation,
        stream,
        gemini_json_array,
        // The native Gemini model-not-found body, SHAPED HERE — this dialect owns its own not-found
        // vocabulary (versioned with the path-derived api_version, no OpenAI "does not exist" copy) and
        // core uses it verbatim on a model miss. Core names no dialect; the shaping lives with the dialect.
        model_not_found_message: Some(format!(
            "models/{model} is not found for API version {api_version}, \
             or is not supported for the task you are trying to perform."
        )),
    })
}

// ── BEDROCK ─────────────────────────────────────────────────────────────────────────────────────

/// BEDROCK'S PATH-MODEL ARRIVAL, as it is DECLARED on `crate::bedrock::DECL`. Three shapes under one
/// model path — `converse`, `converse-stream` and `invoke` — plus the native 404 for anything else.
pub fn bedrock_arrival(a: Arrival) -> Fut {
    let Arrival {
        host,
        ctx,
        path,
        model_hint: _,
        uri,
        headers,
        body,
    } = a;
    // Pre-routing accounting, mirroring the gemini arrival: a pre-charge exit must flow through
    // `finish_rejected` so it stays visible to Prometheus/the webhook, and the epoch it is finished
    // against is pinned before the parse rather than after it.
    let started = Instant::now();
    let charged_at = busbar_substrate::store::now();
    match bedrock_path_parse(&host, &ctx, &path, &uri, &body, started, charged_at) {
        PathArrivalFacts::PathModel(facts) => Box::pin(bedrock_converse(ctx, facts, headers, body)),
        PathArrivalFacts::BodyModel {
            operation,
            model_hint,
        } => Box::pin(bedrock_invoke(ctx, model_hint, operation, headers, body)),
        PathArrivalFacts::Refused(resp) => Box::pin(async move { resp }),
    }
}

/// THE MODEL BEDROCK'S URL NAMED. axum's Path extractor percent-decoded `{model_id}` before the route
/// collapse; match it.
pub fn bedrock_path_model(host: &Arc<dyn ArrivalHost>, path: &str) -> String {
    request_handler(PROTO_BEDROCK)
        .and_then(|rh| rh.path_model(path))
        .map(|m| host.percent_decode(&m))
        .unwrap_or_default()
}

/// BEDROCK'S URL PARSE, as a value.
///
/// Three shapes under one model path — `converse`, `converse-stream` and `invoke` — plus the native
/// 404 for anything else. The first two name the stream intent in the URL and are path-model proper;
/// `invoke` names only the model and leaves the operation to the body, which is the body-model shape
/// with a routing hint.
pub fn bedrock_path_parse(
    host: &Arc<dyn ArrivalHost>,
    ctx: &ArrivalCtx,
    path: &str,
    uri: &Uri,
    body: &Bytes,
    started: Instant,
    charged_at: u64,
) -> PathArrivalFacts {
    let model_id = bedrock_path_model(host, path);
    // The reject arms below are provably unreachable today (bedrock `resolve_operation` returns
    // `Some(CHAT)` unconditionally for a converse path — see `handler.rs`), but routing them
    // consistently means a future resolver that CAN yield `None` accounts for the rejection instead
    // of silently `ingress_error`-ing it, matching every other pre-routing reject in this file.
    let unsupported = || {
        PathArrivalFacts::Refused(host.finish_rejected(
            ctx,
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
        ))
    };
    // Bedrock never uses the gemini JSON-array framing, and a model-not-found 404 uses the canonical
    // (non-gemini) message, so no api_version is threaded.
    let converse = |operation, stream| {
        PathArrivalFacts::PathModel(PathModelFacts {
            model: model_id.clone(),
            operation,
            stream,
            gemini_json_array: false,
            model_not_found_message: None,
        })
    };
    if path.ends_with("/converse") {
        return match request_handler(PROTO_BEDROCK)
            .and_then(|rh| rh.resolve_operation(&format!("/model/{model_id}/converse"), body))
        {
            Some(op) => converse(op, false),
            None => unsupported(),
        };
    }
    if path.ends_with("/converse-stream") {
        return match request_handler(PROTO_BEDROCK).and_then(|rh| {
            rh.resolve_operation(&format!("/model/{model_id}/converse-stream"), body)
        }) {
            Some(op) => converse(op, true),
            None => unsupported(),
        };
    }
    if path.ends_with("/invoke") {
        // POST /model/{model_id}/invoke — Bedrock `InvokeModel`. The path names the model; the
        // bedrock RequestHandler reads the BODY and decides the operation. An unrecognized body is a
        // clean 400 in the Bedrock dialect.
        let Some(operation) =
            request_handler(PROTO_BEDROCK).and_then(|rh| rh.resolve_operation(uri.path(), body))
        else {
            return PathArrivalFacts::Refused(host.finish_rejected(
                ctx,
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
            ));
        };
        return PathArrivalFacts::BodyModel {
            operation,
            model_hint: model_id,
        };
    }
    PathArrivalFacts::Refused(host.fallback_not_found(
        ctx,
        path,
        StatusCode::NOT_FOUND,
        host.err_type_not_found(),
        "the requested resource was not found",
    ))
}

/// Both Bedrock converse routes: the path-model core with the route-selected stream intent. The
/// `modelId` segment arrives ALREADY percent-decoded by axum, so it is used verbatim (decoding twice
/// corrupts ids whose first decode yields a literal `%XX`).
#[tracing::instrument(level = "debug", name = "bedrock_converse", skip_all)]
async fn bedrock_converse(
    ctx: ArrivalCtx,
    facts: PathModelFacts,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    crate::native_ingress::ingress_path_model(
        &ctx,
        headers,
        body,
        facts.model,
        facts.operation,
        facts.stream,
        facts.gemini_json_array,
        PROTO_BEDROCK,
        facts.model_not_found_message,
    )
    .await
}

/// POST /model/{model_id}/invoke — the ordinary body-model forward with the URL's model as its
/// routing hint.
#[tracing::instrument(level = "debug", name = "bedrock_invoke", skip_all)]
async fn bedrock_invoke(
    ctx: ArrivalCtx,
    model_id: String,
    operation: busbar_api::operation::Operation,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
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
/// engine. A path the dialect names NO operation for is not a request at all: it gets the plain
/// path-shaped 404 the catch-all uses and is never accounted (1.5.5 did exactly this; the
/// dialect-shaped "does not support that operation" reject is reserved for a RESOLVED operation
/// the dialect holds no handler for, inside `operation_ingress`).
async fn body_arrival(proto: &'static str, a: Arrival) -> Response {
    let Arrival {
        host,
        ctx,
        path,
        model_hint,
        uri,
        headers,
        body,
    } = a;
    let Some(operation) =
        request_handler(proto).and_then(|rh| rh.resolve_operation(uri.path(), &body))
    else {
        return host.fallback_not_found(
            &ctx,
            &path,
            StatusCode::NOT_FOUND,
            host.err_type_not_found(),
            "the requested resource was not found",
        );
    };
    // `model_hint` carries the busbar convenience surfaces' PATH-borne routing name (`named`/`adhoc`);
    // `None` for a dialect-native body-model arrival, where the model rides the body.
    crate::native_ingress::operation_ingress(&ctx, headers, body, proto, operation, model_hint)
        .await
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
