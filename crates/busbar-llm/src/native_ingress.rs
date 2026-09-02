// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NATIVE-PLANE UNIVERSAL INGRESS, relocated from busbar-core (1.6.0 money-path Phase 3-4 C).
//!
//! Pool/model resolution + governance admission + the-one-engine forward every LLM arrival runs once
//! its model is known. It reads the LLM routing tables (now in `crate::engine`) so it lives in the
//! plane; it calls DOWN into core for the neutral accounting -- the allowed plane->core edge. The two
//! entry points downcast the opaque `ArrivalCtx` to core's `ArrivalPayload`.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde_json::Value;

use busbar_core::state::App;
use busbar_substrate::ingress::arrival::ArrivalCtx;
// The neutral host seam — brings the `finish_rejected`/`finish_admitted`/`pool_label`/
// `destination_guard` methods into scope on the borrowed `engine_host_value` carrier.
use busbar_substrate::plane_host::EngineHost as _;

use crate::engine::{AppEngineExt, WeightedLane};

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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn operation_ingress_inner(
    app: &Arc<App>,
    gov: &busbar_api::PlaneRequestCtx,
    caller_token: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    model_hint: Option<String>,
) -> Response {
    let started = Instant::now();
    let charged_at = busbar_substrate::store::now();
    // The alloc-free borrowed host carrier (1.6.0 KEYSTONE): one Arc::clone, stack value coerced to
    // `&dyn EngineHost`. The pre-routing finish/label/guard capabilities route through its narrow seam
    // methods so this plane names no core ingress module. Not on the measured forward alloc path.
    let host = busbar_core::plane_host::engine_host_value(app);

    let Some(rh) = busbar_substrate::handlers::request_handler(proto) else {
        return host.finish_rejected(
            gov,
            proto,
            crate::engine::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            busbar_substrate::proxy::ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::engine::KIND_NOT_FOUND,
                "This protocol does not support that operation.",
            ),
        );
    };
    let Some(op_handler) = rh.operation_handler(operation) else {
        return host.finish_rejected(
            gov,
            proto,
            crate::engine::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            busbar_substrate::proxy::ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::engine::KIND_NOT_FOUND,
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
    let parsed_v: Option<crate::engine::LazyBody> = if ct.starts_with("application/json")
        || ct.is_empty()
    {
        match crate::engine::LazyBody::parse(&body) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::debug!(detail = %busbar_substrate::json::parse_err_log(body.len()), "request body JSON parse failed");
                return host.finish_rejected(
                    gov,
                    proto,
                    crate::engine::POOL_LABEL_UNRESOLVED,
                    started,
                    charged_at,
                    busbar_substrate::proxy::ingress_error(
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
            return host.finish_rejected(
                gov,
                proto,
                crate::engine::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                busbar_substrate::proxy::ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::engine::KIND_INVALID_REQUEST,
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
    operation: busbar_api::operation::Operation,
    op_handler: &'static dyn busbar_substrate::handlers::OperationHandler,
    headers: &'a HeaderMap,
    body: Bytes,
    parsed_v: Option<crate::engine::LazyBody>,
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
        let host = busbar_core::plane_host::engine_host_value(self.app);
        match host.destination_guard(
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
        // The alloc-free borrowed host carrier — the finish/label seam methods route through it so
        // this served-path tail names no core ingress module. Off the measured forward alloc path.
        let host = busbar_core::plane_host::engine_host_value(app);

        // STAGE 3–4 — THE single budget-admission door charges the chain buckets. On rejection
        // nothing was charged (the door finished it).
        let (admit, downgraded) = match busbar_core::ingress::admission_door(
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
                let resp = busbar_substrate::proxy::ingress_error(
                    proto,
                    StatusCode::NOT_FOUND,
                    crate::engine::KIND_NOT_FOUND,
                    &busbar_substrate::ingress::not_found_message(model, model_not_found_message),
                );
                return host.finish_admitted(
                    req.gov,
                    proto,
                    host.pool_label(model),
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
        let resp = crate::engine::forward_with_pool_parsed(
            app,
            cands,
            body,
            parsed_v,
            // `ct` borrows `headers` (a caller-held reference that outlives this call) — no per-request
            // `to_string` copy is needed to thread the Content-Type through.
            if ct.is_empty() {
                crate::engine::APPLICATION_JSON
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
            busbar_substrate::handlers::frame(
                busbar_substrate::transport::Transport::Http,
                operation,
                op_handler,
            ),
            usage_sink(app, req.gov, pool_name, req.charged_at, admit),
        )
        .await;

        // STAGE 6 — audit + finish/metrics/refund. `pool_label` bounds the metric label — the
        // effective model is a configured pool/lane on the served path — so this reproduces the
        // pre-seam served tail exactly.
        host.finish_admitted(
            req.gov,
            proto,
            host.pool_label(model),
            req.started,
            req.charged_at,
            resp,
            charged,
        )
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn run(
    app: &Arc<App>,
    gov: &busbar_api::PlaneRequestCtx,
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    op_handler: &'static dyn busbar_substrate::handlers::OperationHandler,
    model: &str,
    headers: &HeaderMap,
    body: Bytes,
    parsed_v: Option<crate::engine::LazyBody>,
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
    gov: &busbar_api::PlaneRequestCtx,
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    op_handler: &'static dyn busbar_substrate::handlers::OperationHandler,
    model: &str,
    headers: &HeaderMap,
    body: Bytes,
    parsed_v: Option<crate::engine::LazyBody>,
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
fn usage_sink(
    app: &Arc<App>,
    gov: &busbar_api::PlaneRequestCtx,
    pool: &str,
    charged_at: u64,
    admit: Option<busbar_core::governance::AdmitGrant>,
) -> Option<crate::engine::UsageSink> {
    match (&app.governance, &gov.key) {
        (Some(g), Some(key)) => Some(crate::engine::UsageSink {
            gov: g.clone(),
            // The resolved cost model rides along (an Arc bump) so the stream-end accrual can walk
            // the key's budget-group chain without reaching back into the App snapshot.
            cost: app.cost.clone(),
            // Share the resolved key by `Arc`: no per-request `id` String clone; it is read
            // through `sink.key` at charge time.
            key: key.clone(),
            // The admitted pool: the accounting scope for pool-qualified limits (accrual mirrors
            // the admission charge).
            pool: std::sync::Arc::from(pool),
            // The header-arrival epoch this request was admitted at — reused for the token fee so it
            // shares the flat per-request fee's window (#29). See `UsageSink::charged_at`.
            charged_at,
            // The admission's in-flight HOLDS (the `concurrent` limit gauges) ride the sink so
            // they release when the response stream completes / the request context unwinds - the
            // sink is the one per-request object that provably lives to stream end. Arc'd because
            // the sink clones per failover attempt; the LAST clone dropping releases the gauges.
            admit: admit.map(std::sync::Arc::new),
        }),
        // No governance/key = nothing was admitted through the limit engine; a grant cannot exist.
        _ => None,
    }
}

/// The default affinity header name used when a pool's `affinity` config does not specify a custom
/// header. Both the `Some`-arm fallback and the `None`-arm of `affinity_header_for` must agree on
/// this spelling; a single const prevents them from silently diverging.
const DEFAULT_AFFINITY_HEADER: &str = "x-session-id";

/// The request header that pins a session to a lane for a pool. Defaults to `x-session-id`; a
/// pool's `affinity` config (mode `session`) may name a different header (e.g. `x-user-id`).
pub(crate) fn affinity_header_for<'a>(app: &'a Arc<App>, pool: &str) -> &'a str {
    match app
        .engine_tables()
        .pool_runtime()
        .get(pool)
        .and_then(|r| r.affinity.as_ref())
    {
        // The affinity block's presence IS the `session` mode fact (the only supported mode, so the
        // neutral AffinityInput carries no mode enum); honour the configured header name.
        Some(a) => a.header_name.as_deref().unwrap_or(DEFAULT_AFFINITY_HEADER),
        None => DEFAULT_AFFINITY_HEADER,
    }
}

#[allow(clippy::too_many_arguments)]
async fn ingress_path_model_inner(
    app: &Arc<App>,
    gov: &busbar_api::PlaneRequestCtx,
    caller_token: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    model: &str,
    operation: busbar_api::operation::Operation,
    stream: bool,
    gemini_json_array: bool,
    proto: &'static str,
    model_not_found_message: Option<&str>,
) -> Response {
    let started = Instant::now();
    // Header-arrival epoch pinned once and reused for both the per-request and token fees (#29).
    let charged_at = busbar_substrate::store::now();
    // Alloc-free borrowed host carrier — the pre-routing finish seam routes through it (see the body-
    // model twin). Off the measured forward alloc path.
    let host = busbar_core::plane_host::engine_host_value(app);
    let mut v: Value = match busbar_substrate::json::parse(&body) {
        Ok(v) => v,
        Err(_) => {
            // Log a SANITIZED note for operators (just the byte length), never the parser's raw error:
            // with sonic-rs it embeds a fragment of the malformed body, which can contain secrets/PII.
            // The client gets only the generic, vendor-plausible message.
            tracing::debug!(detail = %busbar_substrate::json::parse_err_log(body.len()), "request body JSON parse failed");
            // Pre-routing failure (model never resolved): route through `finish_rejected` with the
            // bounded `"unresolved"` label so the malformed-body request is still counted in REQUESTS_TOTAL /
            // REQUEST_DURATION_SECONDS and fires the request-log webhook, mirroring the model-miss
            // path. A raw early-return made it invisible to Prometheus and the webhook.
            return host.finish_rejected(
                gov,
                proto,
                crate::engine::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                busbar_substrate::proxy::ingress_error(
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
                if let Some(shim_key) = busbar_substrate::proto::array_stream_shim_key_for(proto) {
                    obj.insert(shim_key.to_string(), Value::Bool(true));
                }
            }
        }
        None => {
            // Pre-routing failure (body is not a JSON object → model never resolved): route through
            // `finish_rejected` with the bounded `"unresolved"` label so it is observable in metrics +
            // the webhook, not a silent early-return — and never charged, so nothing to refund.
            return host.finish_rejected(
                gov,
                proto,
                crate::engine::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                busbar_substrate::proxy::ingress_error(
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
    let injected: Bytes = match busbar_substrate::json::to_vec(&v) {
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
            return host.finish_rejected(
                gov,
                proto,
                crate::engine::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                busbar_substrate::proxy::ingress_error(
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
    let Some(op_handler) = busbar_substrate::handlers::request_handler(proto)
        .and_then(|rh| rh.operation_handler(operation))
    else {
        return host.finish_rejected(
            gov,
            proto,
            crate::engine::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            busbar_substrate::proxy::ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::engine::KIND_NOT_FOUND,
                "This endpoint does not support that operation.",
            ),
        );
    };
    operation_resolved(
        app,
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

fn payload(ctx: &ArrivalCtx) -> &busbar_core::ingress::arrival_host::ArrivalPayload {
    ctx.downcast_ref::<busbar_core::ingress::arrival_host::ArrivalPayload>()
        .expect("ArrivalCtx must carry core's ArrivalPayload -- a wiring bug otherwise")
}

/// BODY-MODEL UNIVERSAL INGRESS -- every operation whose model rides IN THE BODY.
pub async fn operation_ingress(
    ctx: &ArrivalCtx,
    headers: HeaderMap,
    body: Bytes,
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    model_hint: Option<String>,
) -> Response {
    let p = payload(ctx);
    operation_ingress_inner(
        &p.app,
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

/// PATH-MODEL UNIVERSAL INGRESS -- gemini/bedrock keep their model in the URL.
#[allow(clippy::too_many_arguments)]
pub async fn ingress_path_model(
    ctx: &ArrivalCtx,
    headers: HeaderMap,
    body: Bytes,
    model: String,
    operation: busbar_api::operation::Operation,
    stream: bool,
    gemini_json_array: bool,
    proto: &'static str,
    model_not_found_message: Option<String>,
) -> Response {
    let p = payload(ctx);
    ingress_path_model_inner(
        &p.app,
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

#[cfg(test)]
#[path = "multipart_model_tests.rs"]
mod multipart_model_tests;
