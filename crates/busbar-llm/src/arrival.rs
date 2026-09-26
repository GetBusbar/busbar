// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PATH-MODEL DIALECT PARSES — Gemini and Bedrock keep their model in the URL, so each parses
//! ITS OWN model out of the path (its statement about its own URL space) before any step runs.
//! RELOCATED here from `busbar-core` (it named the dialects and was the last piece of core→plane
//! entanglement): the parses live in the dialect crate and read the request through the neutral
//! [`busbar_kernel::ingress::arrival::ArrivalHost`] seam, crossing core's handles as the opaque
//! [`ArrivalCtx`] and the neutral `Operation`/`Response`/`Bytes` directly. So this crate names no
//! core item and core names no dialect.
//!
//! What a parse answers with is a VALUE ([`PathArrivalFacts`](crate::arrival::PathArrivalFacts)); the arrivals that drive it — and
//! hand the unit it describes to the node — are the loop's (`crate::unit::node`), registered through
//! [`crate::PATH_INGRESS`] beside [`crate::DECLS`].

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use busbar_contract::codec::RequestHandler;
use busbar_kernel::ingress::arrival::{ArrivalCtx, ArrivalHost};

use crate::proto_codec::{PROTO_BEDROCK, PROTO_GEMINI};
// The refusal a parse NAMES, one level up (see `unit/mod.rs`) rather than by the audit step's own
// module path — the kind-isolation matrix counts that path as the plane growing its coupling to the
// teller steps, and a pre-routing refusal is this dialect's own to name.
use crate::unit::RefusalOutcome;

/// The dialect's own installed `RequestHandler`, resolved through the neutral protocol registry (the
/// byte-identical equivalent of core's old `handlers::request_handler(proto)`).
pub(crate) fn request_handler(proto: &str) -> Option<&'static dyn RequestHandler> {
    busbar_kernel::proto::registry()
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
    pub operation: busbar_contract::operation::OpVerb,
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
/// Four answers: the URL named a model and a stream intent; or it named a model and left the
/// operation to the body; or it is not a request this dialect answers at all and its own already-
/// shaped fallback bytes stand; or it is a NAMED pre-routing refusal the terminal still has to render
/// and post.
pub enum PathArrivalFacts {
    /// The URL named the model AND the stream intent — the path-model surfaces proper.
    PathModel(PathModelFacts),
    /// The URL named only the model and the BODY names the operation: Bedrock's `invoke`, which runs
    /// the ordinary body-model forward with the URL's model as its routing hint.
    BodyModel {
        /// The operation the dialect resolved off the body.
        operation: busbar_contract::operation::OpVerb,
        /// The model the URL named.
        model_hint: String,
    },
    /// Not a request this dialect answers, and its bytes are the dialect's own FALLBACK 404
    /// (`fallback_not_found`) — a different terminal from the counted pre-routing turn-away: already
    /// shaped, and NOT posted through the metrics/webhook door. Both drivers of this surface return it
    /// unchanged; routing it through the audit door would change its bytes and add accounting it does
    /// not carry, so it stays a pre-rendered `Response` rather than a named outcome.
    Refused(Response),
    /// A NAMED pre-routing refusal — a malformed path, an unsupported action, a body that resolves to
    /// no operation. It is not bytes yet: the envelope dialect it is shaped in, and the dialect-neutral
    /// outcome (status, kind word, sentence). The consumer renders it at the audit terminal
    /// (`render_refusal`) and posts it through the rejected door — the one place
    /// a named refusal on this plane becomes bytes. This is the shape the pre-routing `finish_rejected`
    /// sites used to build inline; naming it here and posting it at the terminal is what keeps the door
    /// call off this file.
    RefusedNeutral {
        /// The dialect the refusal envelope is shaped in — the same value the site read off the host.
        envelope_proto: &'static str,
        /// The named refusal: status, dialect-neutral kind word, and the sentence the client reads.
        outcome: RefusalOutcome,
    },
}

/// The tail axum's `{*rest}` wildcard carried, percent-decoded once. Split out so the two drivers of
/// this surface decode it the same way rather than each spelling the split.
pub fn gemini_rest(host: &Arc<dyn ArrivalHost>, path: &str) -> String {
    host.percent_decode(path.split("/models/").nth(1).unwrap_or(""))
}

/// GEMINI'S URL PARSE, as a value.
///
/// Everything `gemini_ingress` used to decide before it forwarded, and nothing it decided after. The
/// rejections it can answer with are NAMED here — status, kind word, sentence, and the envelope
/// dialect they are shaped in — and RENDERED-and-posted by the consumer at the audit terminal. The
/// parse decides the refusal; the terminal turns it into bytes and counts it, which is the one place
/// a named refusal on this plane becomes a posted record.
pub fn gemini_path_parse(
    host: &Arc<dyn ArrivalHost>,
    ctx: &ArrivalCtx,
    rest: &str,
    uri: &Uri,
    body: &Bytes,
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
            if busbar_kernel::proto::registry()
                .decl(envelope_proto)
                .is_some_and(|d| d.has_native_path_not_found)
            {
                return PathArrivalFacts::RefusedNeutral {
                    envelope_proto,
                    outcome: RefusalOutcome::new(
                        StatusCode::NOT_FOUND,
                        host.kind_not_found(),
                        format!(
                "Invalid resource path: models/{rest} is not found for API version {api_version}."
            ),
                    ),
                };
            }
            // Non-Gemini (ambiguous `/v1/models/...` without a Gemini action suffix): emit the
            // canonical OpenAI-shaped 404 the fallback handler uses for this path.
            return PathArrivalFacts::RefusedNeutral {
                envelope_proto,
                outcome: RefusalOutcome::new(
                    StatusCode::NOT_FOUND,
                    host.kind_not_found(),
                    "the requested resource was not found",
                ),
            };
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
            if busbar_kernel::proto::registry()
                .decl(envelope_proto)
                .is_some_and(|d| d.has_native_path_not_found)
            {
                return PathArrivalFacts::RefusedNeutral {
                    envelope_proto,
                    outcome: RefusalOutcome::new(
                        StatusCode::NOT_FOUND,
                        host.kind_not_found(),
                        format!(
                            "models/{model} is not found for API version {api_version}, \
                             or is not supported for {other}."
                        ),
                    ),
                };
            }
            return PathArrivalFacts::RefusedNeutral {
                envelope_proto,
                outcome: RefusalOutcome::new(
                    StatusCode::NOT_FOUND,
                    host.kind_not_found(),
                    "the requested resource was not found",
                ),
            };
        }
    };

    // `?alt=sse` selects SSE framing for a STREAMING request; its ABSENCE means the native client
    // expects the JSON-array streaming format. Only a streaming request without `alt=sse` engages it.
    let alt_sse = uri.query().map(query_has_alt_sse).unwrap_or(false);
    let gemini_json_array = stream && !alt_sse;

    // `operation` is Some here (a None already returned the unsupported-action envelope above); bail
    // with the standard no-handler 404 rather than assume any operation.
    let Some(operation) = operation else {
        return PathArrivalFacts::RefusedNeutral {
            envelope_proto: PROTO_GEMINI,
            outcome: RefusalOutcome::new(
                StatusCode::NOT_FOUND,
                host.kind_not_found(),
                crate::engine::DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
            ),
        };
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
) -> PathArrivalFacts {
    let model_id = bedrock_path_model(host, path);
    // The reject arms below are provably unreachable today (bedrock `resolve_operation` returns
    // `Some(CHAT)` unconditionally for a converse path — see `handler.rs`), but routing them
    // consistently means a future resolver that CAN yield `None` accounts for the rejection instead
    // of silently `ingress_error`-ing it, matching every other pre-routing reject in this file.
    let unsupported = || PathArrivalFacts::RefusedNeutral {
        envelope_proto: PROTO_BEDROCK,
        outcome: RefusalOutcome::new(
            StatusCode::NOT_FOUND,
            host.kind_not_found(),
            crate::engine::DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
        ),
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
            return PathArrivalFacts::RefusedNeutral {
                envelope_proto: PROTO_BEDROCK,
                outcome: RefusalOutcome::new(
                    StatusCode::BAD_REQUEST,
                    host.kind_invalid_request(),
                    "InvokeModel body is not a supported operation (expected inputText or textToImageParams).",
                ),
            };
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

#[cfg(test)]
#[path = "tests/arrival_tests.rs"]
mod arrival_tests;
