// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUFFERED — the non-streaming CROSS-protocol 2xx: buffer the whole upstream body under the
//! translation cap, translate egress → IR → ingress through the one neutral codec entrypoint, and
//! bill ONLY from the exit that actually hands a completion to the client. The mirror of
//! `translate_request_cross_protocol` on the response side; every path reaches it through
//! [`super::respond`], so there is one copy of the decision tree (transport failure / cap
//! exceeded / opaque-vs-JSON / bedrock frame synthesis / gemini array wrap).

use crate::engine::*;

use busbar_substrate::diag_debug;
use busbar_substrate::diagnostics::{
    CROSSPROTO_BINARY_CODEC_FAILED, CROSSPROTO_JSON_CODEC_FAILED,
    CROSSPROTO_NONSTREAM_MIDTRANSFER_FAILED, CROSSPROTO_RESPONSE_NOT_TRANSLATABLE,
    CROSSPROTO_RESPONSE_NOT_TRANSLATABLE_DEGRADED, CROSSPROTO_TRANSLATION_CAP_EXCEEDED,
};
use busbar_substrate::handlers::TranslateCodec;

/// RAII refund for the headers-time `spend_budget` unit across the BUFFERED path's spend →
/// `read_capped(...).await` window. A client disconnect parked at that await drops the future
/// without resuming it, so a plain local bool consulted only AFTER the await never runs the refund —
/// the streaming path has `FirstByteBody::drop` for this; the buffered path has no such body
/// wrapper, so it needs its own guard.
///
/// Mirrors `select::ProbeGuard`: armed by default, refunds on `Drop` unless disarmed first. Every
/// exit that must KEEP the charge (a delivered completion, or our own translation-cap truncation)
/// calls `disarm()` before returning; the exits that must refund (a transport failure, or an
/// untranslatable 2xx) simply leave it armed and let the `return` unwind through it.
pub(crate) struct BudgetSpendGuard<'a> {
    pub(crate) store: &'a dyn busbar_substrate::store::LaneRuntime,
    pub(crate) lane: usize,
    pub(crate) armed: bool,
}

impl BudgetSpendGuard<'_> {
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BudgetSpendGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.store.refund_budget(self.lane);
        }
    }
}

/// The token figures out of a delivery's neutral billing carrier, for the report-back.
///
/// A flat-fee operation reports a non-token `Billing` (or none at all) and answers `None` here, which
/// is the honest report: that response consumed no tokens to account for, and the metering series
/// still counts its request through the accrual seam.
fn token_usage_of(
    usage: &Option<busbar_substrate::billing::Billing>,
) -> Option<busbar_substrate::billing::TokenUsage> {
    match usage {
        Some(busbar_substrate::billing::Billing::Tokens(t)) => Some(t.clone()),
        _ => None,
    }
}

/// Where a translated body goes and how it is labelled: the parts every delivery exit shares.
struct Delivery<'a> {
    rt: &'a Arc<NativeRuntime>,
    i: usize,
    ingress_protocol: &'a str,
    status: StatusCode,
    chosen_policy_name: Option<&'static str>,
}

impl Delivery<'_> {
    /// A delivered body under `content_type`, with the ingress-native request id (synthesized —
    /// this is the cross-protocol path, so there is no upstream id to forward) and the routing
    /// policy transparency header.
    fn respond<V, B>(&self, content_type: V, body: B) -> Response
    where
        V: TryInto<axum::http::HeaderValue>,
        <V as TryInto<axum::http::HeaderValue>>::Error: Into<axum::http::Error>,
        B: Into<Body>,
    {
        let rb = Response::builder()
            .status(self.status)
            .header(CONTENT_TYPE, content_type);
        let rb = maybe_attach_response_request_id(rb, self.ingress_protocol, None);
        let rb = maybe_attach_route_policy(
            rb,
            self.chosen_policy_name,
            &EngineTables::new(self.rt).lanes()[self.i].model,
        );
        rb.body(body.into())
            .unwrap_or_else(|_| self.status.into_response())
    }
}

/// Takes ownership of `r` (consumed by the capped read), `permit` (dropped once the whole body is
/// in hand — a buffered response holds no permit) and `usage_sink` (billed at most once, from
/// whichever exit actually delivers a completion). `budget_guard` is the caller's own guard,
/// borrowed so it is armed/disarmed here rather than duplicated (a second guard off the same spend
/// would refund independently). `chosen_policy_name` is `None` on a degraded hop (no routing-policy
/// decision there), which the header attach already treats as a no-op. `degraded` selects the
/// degraded-path diagnostics.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn translate_response_cross_protocol(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
    pool: &str,
    breaker_cfg: &busbar_substrate::store::BreakerCfg,
    r: axum::http::Response<hyper::body::Incoming>,
    read_deadline: tokio::time::Instant,
    permit: Permit,
    budget_guard: &mut BudgetSpendGuard<'_>,
    usage_sink: Option<UsageSink>,
    status: StatusCode,
    wants_stream: bool,
    gemini_json_array: bool,
    upstream_started: std::time::Instant,
    chosen_policy_name: Option<&'static str>,
    degraded: bool,
    // The ORIGINAL ingress request body, parsed once by the caller (owned, not borrowed — this fn
    // is async and awaits across it). Threaded to `TranslateCodec::translate_response` so a dialect
    // whose response spec requires certain members to MIRROR the request (OpenAI Responses) can
    // answer with the client's actual values instead of the spec's bare defaults. `None` when the
    // caller has no parsed ingress body.
    ingress_request_body: Option<Value>,
    // THE REPORT-BACK CELL, filled at whichever exit below actually ends this response. A buffered
    // body is read whole before it is translated, so unlike the streaming tap this one has finished
    // by the time the caller returns — the lane, the usage and the finish class are all known here.
    tap: &TapCell,
) -> Response {
    let egress_name = EngineTables::new(rt).lanes()[i].protocol;
    // Every exit below that is NOT a delivery is a transfer that FAILED after the upstream's 2xx
    // headers, and every one of them bills zero (the not-billed arms the older release already had).
    // The client is handed an ingress-native error and no completion at all, so the end is `Error`
    // rather than `Partial`: nothing of the answer was ever relayed. Named once so the four failure
    // exits report one end rather than four spellings of it.
    let failed_transfer = || TapReport {
        lane: i,
        usage: None,
        billing_failed: true,
        finish: TapFinish::Error,
    };

    // Size-capped buffer under the COMPLETION cap (a legitimate 2xx can far exceed the error-body
    // cap and must be buffered WHOLE to parse+translate). `truncated` distinguishes "too large to
    // translate" from "genuinely unparseable". Bounded by the caller's deadline; expiry is a failed
    // transfer, compensated exactly like a mid-body cut.
    let (bytes, read_end) = {
        use http_body_util::BodyExt;
        let read = read_capped(
            r.into_body().into_data_stream(),
            max_translated_body_bytes(),
        );
        match tokio::time::timeout_at(read_deadline, read).await {
            Ok(pair) => pair,
            Err(_elapsed) => (Bytes::new(), ReadEnd::TransportError),
        }
    };
    // Re-record the upstream RTT now that the WHOLE body has arrived: on this buffered path busbar
    // awaits the entire upstream response before it can translate, so the download is upstream cost.
    record_upstream_rtt(upstream_started.elapsed());
    drop(permit);
    if read_end == ReadEnd::TransportError {
        // The 2xx headers optimistically recorded a success and spent the budget, but the body never
        // arrived intact: charge no tokens, record a compensating transient failure, and let the
        // still-armed guard refund the request budget unit.
        diag_debug!(
            CROSSPROTO_NONSTREAM_MIDTRANSFER_FAILED,
            ingress = %ingress_protocol,
            egress = %egress_name,
            "cross-protocol non-stream upstream body failed mid-transfer; \
             not recording success/usage, refunding budget, returning ingress-native error"
        );
        let tripped =
            host.lane_store()
                .record_transient_in(pool, i, ERR_NET_TRANSPORT, breaker_cfg, None);
        if tripped {
            emit_breaker_trip(host, rt, pool, i);
        }
        tap.report(failed_transfer());
        return ingress_error(
            ingress_protocol,
            StatusCode::BAD_GATEWAY,
            KIND_API_ERROR,
            GENERIC_RESPONSE_ERROR_DETAIL,
        );
    }
    if read_end == ReadEnd::Truncated {
        // OUR translation cap, not an upstream fault: no tokens charged (the client receives no
        // completion), but the optimistic success stands and the budget unit is kept.
        diag_debug!(
            CROSSPROTO_TRANSLATION_CAP_EXCEEDED,
            ingress = %ingress_protocol,
            egress = %egress_name,
            cap = max_translated_body_bytes(),
            "cross-protocol non-stream success body exceeded the translation cap; \
             cannot translate, not charging tokens, returning ingress-native error"
        );
        budget_guard.disarm();
        tap.report(failed_transfer());
        return ingress_error(
            ingress_protocol,
            StatusCode::INTERNAL_SERVER_ERROR,
            KIND_API_ERROR,
            GENERIC_RESPONSE_ERROR_DETAIL,
        );
    }
    let egress_op = busbar_substrate::handlers::request_handler(egress_name)
        .and_then(|rh| rh.operation_handler(op.operation));
    let ingress_op = busbar_substrate::handlers::request_handler(ingress_protocol)
        .and_then(|rh| rh.operation_handler(op.operation));
    let delivery = Delivery {
        rt,
        i,
        ingress_protocol,
        status,
        chosen_policy_name,
    };
    // Parse the 2xx body ONCE, then branch: an OPAQUE (non-JSON) egress body — binary speech audio —
    // bridges at the byte level through the operation codecs; a JSON body takes the Value path.
    // Token accounting happens ONLY inside an exit that actually delivers a body (a 2xx whose usage
    // parses but whose shape is unmodeled falls through to the ingress-native 500 and bills nothing).
    let body_json = busbar_substrate::json::parse::<Value>(&bytes);
    if body_json.is_err() {
        if let Some(eh) = egress_op {
            match eh.translate_response(
                busbar_substrate::handlers::TranslateRespInput::Opaque(&bytes),
                ingress_op.is_some(),
                ingress_protocol,
                &EngineTables::new(rt).lanes()[i].model,
                now(),
                false,
                None,
                ingress_request_body.as_ref(),
            ) {
                Err(ref e) => {
                    diag_debug!(
                        CROSSPROTO_BINARY_CODEC_FAILED,
                        ingress = %ingress_protocol,
                        egress = %egress_name,
                        error = ?e,
                        degraded,
                        "cross-protocol binary response failed the egress codec (read_response); returning ingress-native 500",
                    );
                }
                Ok((usage, delivered)) => {
                    if let busbar_substrate::wire::TranslatedResponse::Typed(wire) = delivered {
                        // Delivered: bill and keep the lane unit (never refund out from under an
                        // already-billed request).
                        // THE REPORT-BACK, on the opaque delivery: the whole answer is in hand and
                        // is about to be relayed, so the tap knows all four figures before the
                        // client has any of them. Read from the SAME `usage` the accrual is made
                        // from, before it moves.
                        tap.report(TapReport {
                            lane: i,
                            usage: token_usage_of(&usage),
                            billing_failed: false,
                            finish: TapFinish::Complete,
                        });
                        record_resp_usage(
                            host,
                            usage,
                            &usage_sink,
                            EngineTables::new(rt).lanes().get(i),
                        );
                        budget_guard.disarm();
                        return delivery.respond(wire.content_type, wire.bytes);
                    }
                    // `Untranslatable`: no client body could be written — fall through to the 500,
                    // unbilled, guard left armed so the budget unit is refunded.
                }
            }
        }
    }
    if let (Ok(rv), Some(eh)) = (&body_json, egress_op) {
        // Gate translation on the ingress having a codec at all.
        if busbar_substrate::proto::decl_for(ingress_protocol).is_some_and(|d| d.codec.is_some()) {
            if let Some(resp) = deliver_json(
                host,
                &delivery,
                eh,
                ingress_op.is_some(),
                rv,
                &usage_sink,
                budget_guard,
                wants_stream,
                gemini_json_array,
                upstream_started,
                egress_name,
                degraded,
                ingress_request_body.as_ref(),
                tap,
            ) {
                return resp;
            }
        }
    }
    // Not translatable (non-JSON / unexpected-but-valid shape / unknown ingress). Relaying the
    // upstream body verbatim would leak the egress provider's native wire format to a
    // different-protocol client, so return an ingress-native 500 instead.
    if degraded {
        diag_debug!(
            CROSSPROTO_RESPONSE_NOT_TRANSLATABLE_DEGRADED,
            ingress = %ingress_protocol,
            egress = %egress_name,
            status = status.as_u16(),
            "degraded cross-protocol response not translatable; returning ingress-native error"
        );
    } else {
        diag_debug!(
            CROSSPROTO_RESPONSE_NOT_TRANSLATABLE,
            ingress = %ingress_protocol,
            egress = %egress_name,
            status = status.as_u16(),
            "cross-protocol response not translatable; returning ingress-native error \
             instead of leaking the upstream's native body"
        );
    }
    // An undecodable body is exactly as much a lane fault as a transport failure: without this a
    // lane returning undecodable 200s forever never trips. The guard is still armed, so the return
    // refunds the headers-time budget unit.
    let tripped =
        host.lane_store()
            .record_transient_in(pool, i, "untranslatable-2xx", breaker_cfg, None);
    if tripped {
        emit_breaker_trip(host, rt, pool, i);
    }
    tap.report(failed_transfer());
    ingress_error(
        ingress_protocol,
        StatusCode::INTERNAL_SERVER_ERROR,
        KIND_API_ERROR,
        GENERIC_RESPONSE_ERROR_DETAIL,
    )
}

/// The JSON-body delivery: translate, bill on a delivering variant, and build the client response.
/// `None` when the codec rejected the body or the delivery is `Untranslatable` (the caller's 500).
#[allow(clippy::too_many_arguments)]
fn deliver_json(
    host: &Arc<dyn EngineHost>,
    d: &Delivery<'_>,
    eh: &dyn busbar_substrate::handlers::OperationHandler,
    ingress_serves_op: bool,
    rv: &Value,
    usage_sink: &Option<UsageSink>,
    budget_guard: &mut BudgetSpendGuard<'_>,
    wants_stream: bool,
    gemini_json_array: bool,
    upstream_started: std::time::Instant,
    egress_name: &str,
    degraded: bool,
    ingress_request_body: Option<&Value>,
    tap: &TapCell,
) -> Option<Response> {
    let (rt, i, ingress_protocol) = (d.rt, d.i, d.ingress_protocol);
    // One elapsed read for the wants-stream frame-synthesis fork (a Bedrock ConverseStream client
    // served a buffered Converse body); the JSON arm reads its own fresh elapsed below.
    let stream_elapsed_ms = u64::try_from(upstream_started.elapsed().as_millis()).ok();
    // A Gemini `:streamGenerateContent` (no `?alt=sse`) client owns ITS OWN buffered-to-stream
    // shape below (a one-element JSON array under `application/json` — Gemini's real non-SSE
    // streaming wire contract), so the generic IR-frame-synthesis fork must not run for it: that
    // fork produces `text/event-stream`, which is not what a native Gemini SDK expects here.
    let (usage, delivered) = match eh.translate_response(
        busbar_substrate::handlers::TranslateRespInput::Json(rv),
        ingress_serves_op,
        ingress_protocol,
        &EngineTables::new(rt).lanes()[i].model,
        now(),
        wants_stream && !gemini_json_array,
        stream_elapsed_ms,
        ingress_request_body,
    ) {
        Err(ref e) => {
            diag_debug!(
                CROSSPROTO_JSON_CODEC_FAILED,
                ingress = %ingress_protocol,
                egress = %egress_name,
                error = ?e,
                degraded,
                "cross-protocol JSON response failed the egress codec (read_response_value); returning ingress-native 500",
            );
            return None;
        }
        Ok(pair) => pair,
    };
    // The reader just discarded any vendor-scoped response metadata the caller's protocol has no
    // shape for; this is the one place that still holds the upstream body and knows the hop crossed.
    busbar_substrate::proto::warn_untranslatable_response_metadata(
        egress_name,
        ingress_protocol,
        rv,
    );
    // Bill ONLY when the resolved delivery hands bytes to the client. `IngressUnsupported` (a 404)
    // and `Untranslatable` (the 500) deliver no completion: leave the guard armed so the budget unit
    // is refunded, mirroring the streaming wrapper's refund-on-non-delivery.
    if matches!(
        delivered,
        busbar_substrate::wire::TranslatedResponse::StreamFrames(_)
            | busbar_substrate::wire::TranslatedResponse::Typed(_)
            | busbar_substrate::wire::TranslatedResponse::Json(_)
    ) {
        // THE REPORT-BACK, on the JSON delivery, gated by the SAME predicate the accrual is: an
        // exit that hands the client bytes is `Complete` and bills, and the two that hand it an
        // error (`IngressUnsupported`, `Untranslatable`) fall through to the caller's failed-transfer
        // report instead. One predicate, so the charge and the recorded end can never disagree.
        tap.report(TapReport {
            lane: i,
            usage: token_usage_of(&usage),
            billing_failed: false,
            finish: TapFinish::Complete,
        });
        record_resp_usage(
            host,
            usage,
            usage_sink,
            EngineTables::new(rt).lanes().get(i),
        );
        budget_guard.disarm();
    }
    match delivered {
        // A bedrock ingress that asked for ConverseStream but got a buffered 2xx: a native AWS SDK
        // decoder expects binary eventstream frames under the eventstream content type.
        busbar_substrate::wire::TranslatedResponse::StreamFrames(frames) => Some(
            d.respond(
                crate::engine::ingress_stream_content_type(ingress_protocol)
                    .unwrap_or(crate::engine::TEXT_EVENT_STREAM),
                frames,
            ),
        ),
        busbar_substrate::wire::TranslatedResponse::IngressUnsupported => {
            // The caller's dialect has no shape for this operation at all: no completion is
            // relayed, nothing is billed, and the end the record seals is an error rather than a
            // truncated answer.
            tap.report(TapReport {
                lane: i,
                usage: None,
                billing_failed: true,
                finish: TapFinish::Error,
            });
            Some(ingress_error(
                ingress_protocol,
                StatusCode::NOT_FOUND,
                KIND_NOT_FOUND,
                DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
            ))
        }
        // The ingress dialect's response is not JSON (binary speech): relay bytes + their CT.
        busbar_substrate::wire::TranslatedResponse::Typed(wire) => {
            Some(d.respond(wire.content_type, wire.bytes))
        }
        busbar_substrate::wire::TranslatedResponse::Json(mut translated) => {
            // A native Bedrock Converse response always populates `metrics.latencyMs`; inject the
            // real elapsed (omit rather than fabricate a `0` if timing is missing).
            if let Some(dialect) =
                busbar_substrate::proto::decl_for(ingress_protocol).and_then(|d| d.dialect())
            {
                dialect.inject_response_metrics(
                    &mut translated,
                    u64::try_from(upstream_started.elapsed().as_millis()).ok(),
                );
            }
            // Gemini JSON-array streaming answered by a buffered non-SSE 2xx: the native endpoint
            // returns a JSON ARRAY of chunk objects, so wrap the single object in a one-element array.
            if gemini_json_array && wants_stream {
                let arr = Value::Array(vec![translated]);
                let rb = Response::builder()
                    .status(d.status)
                    .header(CONTENT_TYPE, APPLICATION_JSON);
                let rb = maybe_attach_route_policy(
                    rb,
                    d.chosen_policy_name,
                    &EngineTables::new(rt).lanes()[i].model,
                );
                return Some(
                    rb.body(Body::from(
                        busbar_substrate::json::to_vec(&arr)
                            .unwrap_or_else(|_| arr.to_string().into_bytes()),
                    ))
                    .unwrap_or_else(|_| d.status.into_response()),
                );
            }
            // The body is now in the client's native non-stream shape: the ingress JSON CT.
            let body_bytes = busbar_substrate::json::to_vec(&translated)
                .unwrap_or_else(|_| translated.to_string().into_bytes());
            Some(d.respond(APPLICATION_JSON, body_bytes))
        }
        // Opaque-only terminal; unreachable on the JSON path — the caller's 500.
        busbar_substrate::wire::TranslatedResponse::Untranslatable => None,
    }
}
