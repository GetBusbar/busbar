// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHELL, KEPT AS A WITNESS — the arrivals this plane answered with before every request on it
//! became a unit the composition root's node drives over the step files, and the two entry points
//! they funnelled through (`operation_ingress`, `ingress_path_model`).
//!
//! NO BUILD INSTALLS IT. The plane's arrivals ([`crate::PATH_INGRESS`], [`crate::BODY_INGRESS`]) are
//! the loop's, and the composition root's `proto-llm` turns the loop on whenever it links this plane
//! (ARCHITECT R7(b): the node-off build path is dropped). What is left is the witness a test
//! reads the loop against — the leg the root's loop tests compare field for field, on the same
//! fixtures — and the ingress a test binary that links this plane WITHOUT a composition root is
//! seeded with ([`super::install_test_seams`]): it has no node to hand a unit to, so it keeps the
//! answers it always had.
//!
//! The bodies are the shell's own, moved verbatim; the one change is where they reach two neutral
//! values (`store::now`, `POOL_LABEL_UNRESOLVED`): at their substrate home, which is where the
//! kernel's re-exports of them resolve.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use busbar_kernel::{
    ingress::arrival::{Arrival, ArrivalCtx, ArrivalHost, BodyIngress, PathIngress},
    plane_host::{EngineHost, PlaneAnswer},
    proto::array_stream_shim_key_for,
    proxy::ingress_error,
};
use busbar_substrate_values::proxy::POOL_LABEL_UNRESOLVED;
use serde_json::Value;

use crate::arrival::{PathArrivalFacts, PathModelFacts};
use crate::proto_codec::{PROTO_BEDROCK, PROTO_GEMINI};
use crate::unit::{finish_rejected_via_audit, finish_rejected_via_audit_arrival, render_refusal};

type Fut = Pin<Box<dyn Future<Output = PlaneAnswer> + Send>>;

/// The seam's answer shape (#28): the shell's response, handed back as it stands.
fn live(answer: impl Future<Output = Response> + Send + 'static) -> Fut {
    Box::pin(async move { PlaneAnswer::Live(answer.await) })
}

/// THE SHELL'S PATH-MODEL ARRIVALS, by dialect name — the witness twin of [`crate::PATH_INGRESS`].
pub static PATH_INGRESS: &[(&str, PathIngress)] = &[
    (PROTO_GEMINI, gemini_arrival),
    (PROTO_BEDROCK, bedrock_arrival),
];

/// THE SHELL'S BODY-MODEL ARRIVALS, by dialect name — the witness twin of [`crate::BODY_INGRESS`].
pub static BODY_INGRESS: &[(&str, BodyIngress)] = &[
    (crate::proto_codec::PROTO_ANTHROPIC, anthropic_body_arrival),
    (crate::proto_codec::PROTO_OPENAI, openai_body_arrival),
    (PROTO_GEMINI, gemini_body_arrival),
    (PROTO_BEDROCK, bedrock_body_arrival),
    (crate::proto_codec::PROTO_RESPONSES, responses_body_arrival),
    (crate::proto_codec::PROTO_COHERE, cohere_body_arrival),
];

// ── THE TWO ENTRY POINTS THE SHELL FUNNELLED THROUGH ──────────────────────────────────────────────

/// BODY-MODEL UNIVERSAL INGRESS -- every operation whose model rides IN THE BODY.
pub async fn operation_ingress(
    ctx: &ArrivalCtx,
    headers: HeaderMap,
    body: Bytes,
    proto: &'static str,
    operation: busbar_contract::operation::OpVerb,
    model_hint: Option<String>,
) -> Response {
    let p = crate::native_ingress::payload(ctx);
    operation_ingress_inner(
        &p.host,
        &p.gov,
        p.caller_token.as_deref(),
        &headers,
        body,
        proto,
        operation,
        model_hint,
    )
    .await
}

/// THE SHELL'S BODY-MODEL CORE: the handler lookup, the one parse, the model ladder, then the
/// resolved-op funnel.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn operation_ingress_inner(
    host: &Arc<dyn EngineHost>,
    gov: &busbar_contract::records::PlaneRequestCtx,
    caller_token: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    proto: &'static str,
    operation: busbar_contract::operation::OpVerb,
    model_hint: Option<String>,
) -> Response {
    let started = Instant::now();
    // C10 (state/store port): the header-arrival epoch is read off the HOST's clock port
    // (`ClockHost::clock_now_secs`, inherited through `EngineHost`) rather than the ambient free
    // function. Value-identical — the wired `clock_now` slot is `store::now_ms()` scaled to nanos and
    // divided back down, i.e. the same `SystemTime` epoch seconds `store::now()` returns — so the
    // money path (`charged_at`) is byte-identical; the plane now takes its clock from the port.
    let charged_at = host.clock_now_secs();
    // App-retype WEDGE 3: the pre-routing finish/label/guard capabilities route through the `host`
    // threaded in (the arrival's `Arc<dyn EngineHost>`), so this plane names no core ingress module.

    let Some(rh) = busbar_substrate_values::handlers::request_handler(proto) else {
        return finish_rejected_via_audit(
            host,
            gov,
            proto,
            POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::engine::KIND_NOT_FOUND,
                "This protocol does not support that operation.",
            ),
        );
    };
    let Some(op_handler) = rh.operation_handler(operation) else {
        return finish_rejected_via_audit(
            host,
            gov,
            proto,
            POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::engine::KIND_NOT_FOUND,
                crate::engine::DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
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
    let parsed_v: Option<crate::engine::LazyBody> = if ct.starts_with("application/json")
        || ct.is_empty()
    {
        match crate::engine::LazyBody::parse(&body) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::debug!(detail = %busbar_substrate_values::json::parse_err_log(body.len()), "request body JSON parse failed");
                return finish_rejected_via_audit(
                    host,
                    gov,
                    proto,
                    POOL_LABEL_UNRESOLVED,
                    started,
                    charged_at,
                    ingress_error(
                        proto,
                        StatusCode::BAD_REQUEST,
                        crate::engine::KIND_INVALID_REQUEST,
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
        crate::native_ingress::multipart_model(ct, &body)
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
            return finish_rejected_via_audit(
                host,
                gov,
                proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::engine::KIND_INVALID_REQUEST,
                    "Missing required parameter: 'model'.",
                ),
            );
        }
    };

    crate::native_ingress::operation_resolved(
        host,
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

/// PATH-MODEL UNIVERSAL INGRESS -- gemini/bedrock keep their model in the URL.
#[allow(clippy::too_many_arguments)]
pub async fn ingress_path_model(
    ctx: &ArrivalCtx,
    headers: HeaderMap,
    body: Bytes,
    model: String,
    operation: busbar_contract::operation::OpVerb,
    stream: bool,
    gemini_json_array: bool,
    proto: &'static str,
    model_not_found_message: Option<String>,
) -> Response {
    let p = crate::native_ingress::payload(ctx);
    ingress_path_model_inner(
        &p.host,
        &p.gov,
        p.caller_token.as_deref(),
        &headers,
        body,
        &model,
        operation,
        stream,
        gemini_json_array,
        proto,
        model_not_found_message.as_deref(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn ingress_path_model_inner(
    host: &Arc<dyn EngineHost>,
    gov: &busbar_contract::records::PlaneRequestCtx,
    caller_token: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    model: &str,
    operation: busbar_contract::operation::OpVerb,
    stream: bool,
    gemini_json_array: bool,
    proto: &'static str,
    model_not_found_message: Option<&str>,
) -> Response {
    let started = Instant::now();
    // Header-arrival epoch pinned once and reused for both the per-request and token fees (#29).
    // C10: read off the host's clock port (`ClockHost::clock_now_secs`), value-identical to the
    // ambient `store::now()` it replaces.
    let charged_at = host.clock_now_secs();
    // App-retype WEDGE 3: the pre-routing finish seam routes through the threaded `host` (the body-model
    // twin does the same).
    let mut v: Value = match busbar_substrate_values::json::parse(&body) {
        Ok(v) => v,
        Err(_) => {
            // Log a SANITIZED note for operators (just the byte length), never the parser's raw error:
            // with sonic-rs it embeds a fragment of the malformed body, which can contain secrets/PII.
            // The client gets only the generic, vendor-plausible message.
            tracing::debug!(detail = %busbar_substrate_values::json::parse_err_log(body.len()), "request body JSON parse failed");
            // Pre-routing failure (model never resolved): route through `finish_rejected` with the
            // bounded `"unresolved"` label so the malformed-body request is still counted in REQUESTS_TOTAL /
            // REQUEST_DURATION_SECONDS and fires the request-log webhook, mirroring the model-miss
            // path. A raw early-return made it invisible to Prometheus and the webhook.
            return finish_rejected_via_audit(
                host,
                gov,
                proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::engine::KIND_INVALID_REQUEST,
                    "We could not parse the JSON body of your request.",
                ),
            );
        }
    };

    // Inject model+stream so the shared resolution/forward plumbing (which reads both from the
    // body) works for protocols whose native wire carries them in the URL instead. A native client
    // body is always a JSON object; if it is not, return a protocol-shaped 400 rather than panic.
    match v.as_object_mut() {
        Some(obj) => {
            obj.insert("model".to_string(), Value::String(model.to_string()));
            obj.insert("stream".to_string(), Value::Bool(stream));
            // Signal a non-`alt=sse` streaming request so the response is framed as a JSON array
            // rather than SSE (only Gemini's writer carries such a key today). The marker key is
            // resolved through the writer vtable by protocol NAME — ingress names no protocol
            // submodule, so "delete proto/gemini → app is gemini-free" holds. The shim is stripped
            // before the upstream call (`proxy::strip_router_shim_keys`); cross-protocol egress
            // drops it via the IR.
            if gemini_json_array {
                if let Some(shim_key) = array_stream_shim_key_for(proto) {
                    obj.insert(shim_key.to_string(), Value::Bool(true));
                }
            }
        }
        None => {
            // Pre-routing failure (body is not a JSON object → model never resolved): route through
            // `finish_rejected` with the bounded `"unresolved"` label so it is observable in metrics +
            // the webhook, not a silent early-return — and never charged, so nothing to refund.
            return finish_rejected_via_audit(
                host,
                gov,
                proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::engine::KIND_INVALID_REQUEST,
                    "Request body must be a JSON object.",
                ),
            );
        }
    }

    // Re-serializing a `serde_json::Value` we just parsed (with only `String`/`Bool` keys spliced
    // in) cannot fail in practice — `to_vec` on an in-memory `Value` has no fallible component. The
    // `Err` arm is kept as a non-panicking, protocol-shaped guard (never `unwrap`) so the request
    // path stays panic-free even if a future change introduces a non-serializable injected value;
    // it is effectively unreachable today, hence not exercised by a dedicated test.
    let injected: Bytes = match busbar_substrate_values::json::to_vec(&v) {
        Ok(b) => b.into(),
        Err(_e) => {
            // Same leak class as the parse arms above: the JSON library's error Display is a
            // busbar-internal tell (on the parse side it embeds raw body fragments), so we never echo
            // it — a bare operator breadcrumb only, consistent with the `parse_err_log` policy used at
            // every deserialize site. (Serialization errors don't carry body bytes today, but aligning
            // here closes the latent leak class if that ever changes.)
            tracing::debug!("injected request body re-serialization failed");
            // Pre-routing failure (model never reached resolution): route through `finish_rejected`
            // with the bounded `"unresolved"` label so it is observable in metrics + the webhook. This
            // arm is effectively unreachable today (see the comment above), but keeping it on
            // `finish_rejected` preserves the observability invariant for every pre-routing exit.
            return finish_rejected_via_audit(
                host,
                gov,
                proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::engine::KIND_INVALID_REQUEST,
                    "The request body could not be processed.",
                ),
            );
        }
    };

    // UNIVERSAL: the caller (that protocol's routing arm) already resolved WHICH operation this is
    // (`RequestHandler::resolve_operation`); look its handler up through the registry — identical
    // for every protocol and operation. This arm's only per-protocol work was the URL parsing above.
    let Some(op_handler) = busbar_substrate_values::handlers::request_handler(proto)
        .and_then(|rh| rh.operation_handler(operation))
    else {
        return finish_rejected_via_audit(
            host,
            gov,
            proto,
            POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::engine::KIND_NOT_FOUND,
                crate::engine::DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
            ),
        );
    };
    crate::native_ingress::operation_resolved(
        host,
        gov,
        proto,
        operation,
        op_handler,
        model,
        headers,
        injected,
        // Path-model ingress already parsed (and shim-injected into) the body — carry the DOM
        // eagerly; the engine's pristine head check reads it directly and behaves as before.
        Some(crate::engine::LazyBody::from_value(v)),
        caller_token,
        started,
        charged_at,
        model_not_found_message,
    )
    .await
}

// ── THE SHELL'S ARRIVALS ──────────────────────────────────────────────────────────────────────────

/// GEMINI'S PATH-MODEL ARRIVAL, as the shell answered it: the dialect's own URL parse, then the
/// shell's path-model forward. Percent-decode the tail that axum's `{*rest}` wildcard decoded before the
/// route collapse, and hand it to this dialect's own ingress.
fn gemini_arrival(a: Arrival) -> Fut {
    let rest = crate::arrival::gemini_rest(&a.host, &a.path);
    live(gemini_ingress(
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
    // Captured BEFORE the path-parse guards so a malformed-path / unsupported-action rejection (which
    // never reaches the path-model core, where `started` is otherwise taken) is still counted through
    // `finish_rejected` — the same pre-routing observability invariant the body/path cores enforce.
    let started = Instant::now();
    let charged_at = busbar_substrate_values::store::now();
    let facts = match crate::arrival::gemini_path_parse(&host, &ctx, &rest, &uri, &body) {
        PathArrivalFacts::PathModel(facts) => facts,
        // A pre-rendered fallback 404 (a different terminal): return its bytes unchanged.
        PathArrivalFacts::Refused(resp) => return resp,
        // A NAMED pre-routing refusal: render it at the audit terminal and post it through the
        // rejected door — the same not-charged finish, and the same bytes, the inline site produced,
        // now spelled at the one place the door is called.
        PathArrivalFacts::RefusedNeutral {
            envelope_proto,
            outcome,
        } => {
            return finish_rejected_via_audit_arrival(
                &host,
                &ctx,
                envelope_proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                render_refusal(envelope_proto, &outcome),
            )
        }
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
    ingress_path_model(
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

/// BEDROCK'S PATH-MODEL ARRIVAL, as the shell answered it. Three shapes under one
/// model path — `converse`, `converse-stream` and `invoke` — plus the native 404 for anything else.
fn bedrock_arrival(a: Arrival) -> Fut {
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
    let charged_at = busbar_substrate_values::store::now();
    match crate::arrival::bedrock_path_parse(&host, &ctx, &path, &uri, &body) {
        PathArrivalFacts::PathModel(facts) => live(bedrock_converse(ctx, facts, headers, body)),
        PathArrivalFacts::BodyModel {
            operation,
            model_hint,
        } => live(bedrock_invoke(ctx, model_hint, operation, headers, body)),
        // A pre-rendered fallback 404 (a different terminal): return its bytes unchanged.
        PathArrivalFacts::Refused(resp) => live(async move { resp }),
        // A NAMED pre-routing refusal: render it at the audit terminal and post it through the
        // rejected door — byte- and accounting-identical to the inline finish the site once spelled.
        PathArrivalFacts::RefusedNeutral {
            envelope_proto,
            outcome,
        } => {
            let resp = finish_rejected_via_audit_arrival(
                &host,
                &ctx,
                envelope_proto,
                POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                render_refusal(envelope_proto, &outcome),
            );
            live(async move { resp })
        }
    }
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
    ingress_path_model(
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
    operation: busbar_contract::operation::OpVerb,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    operation_ingress(
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
// URL-model pair — keep the model IN THE BODY. The shell mapped each dialect NAME to a `BodyIngress`
// fn that resolves the operation off the endpoint (its own `RequestHandler::resolve_operation`) and
// runs the universal [`operation_ingress`] forward; [`BODY_INGRESS`] above is that table.

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
    let Some(operation) = crate::arrival::request_handler(proto)
        .and_then(|rh| rh.resolve_operation(uri.path(), &body))
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
    operation_ingress(&ctx, headers, body, proto, operation, model_hint).await
}

/// Generate one `BodyIngress` fn-pointer target per dialect (a bare `fn(Arrival) -> Fut`, since the
/// registry seam is a fn pointer that cannot capture the protocol name).
macro_rules! body_arrivals {
    ($(($name:ident, $proto:expr)),+ $(,)?) => {
        $(
            fn $name(a: Arrival) -> Fut {
                live(body_arrival($proto, a))
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
