// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUFFERED — the non-streaming CROSS-protocol 2xx: buffer the whole upstream body under the
//! translation cap, translate egress → IR → ingress through the one neutral codec entrypoint, and
//! bill ONLY from the exit that actually hands a completion to the client. The mirror of
//! `translate_request_cross_protocol` on the response side; every path reaches it through
//! [`super::respond`], so there is one copy of the decision tree (transport failure / cap
//! exceeded / opaque-vs-JSON / bedrock frame synthesis / gemini array wrap).

use crate::engine::*;

use crate::engine::xchg::reply::whole::{self, Whole, WholeCtx, WholeEnd};
use busbar_contract::diag_debug;
use busbar_kernel::store::BreakerCfg;

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
    pub(crate) store: &'a dyn busbar_kernel::store::LaneRuntime,
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

use crate::engine::xchg::reply::wire::{open_units_of, token_usage_of};

/// Takes ownership of `r` (consumed by the capped read), `permit` (dropped once the whole body is
/// in hand — a buffered response holds no permit) and `usage_sink` (billed at most once, from
/// whichever exit actually delivers a completion). `budget_guard` is the caller's own guard,
/// borrowed so it is armed/disarmed here rather than duplicated (a second guard off the same spend
/// would refund independently). `chosen_policy_name` is `None` on a degraded hop (no routing-policy
/// decision there), which the header attach already treats as a no-op. `degraded` selects the
/// degraded-path diagnostics.
///
/// The bytes are the plane's (`crate::engine::xchg::reply::whole`): the decision tree
/// (opaque bridge / JSON translate / failed generation / ingress-unsupported 404 / untranslatable
/// 500) and every answer it writes. This function keeps the I/O around it and the side effects
/// each end carries (the tap, the accrual, the budget guard, the breaker).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn translate_response_cross_protocol(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    ingress_protocol: &str,
    op: Op,
    pool: &str,
    breaker_cfg: &BreakerCfg,
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
    // is async and awaits across it), so a dialect whose response spec requires certain members to
    // MIRROR the request (OpenAI Responses) answers with the client's actual values.
    ingress_request_body: Option<Value>,
    // THE REPORT-BACK CELL, filled at whichever exit below actually ends this response.
    tap: &TapCell,
) -> Response {
    let lane = &EngineTables::new(rt).lanes()[i];
    let egress_name = lane.protocol;
    let bytes = match read_capped_body(
        host,
        rt,
        i,
        pool,
        ingress_protocol,
        egress_name,
        breaker_cfg,
        r,
        read_deadline,
        permit,
        budget_guard,
        upstream_started,
        tap,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(resp) => return resp,
    };
    let ctx = WholeCtx {
        ingress: ingress_protocol,
        egress: egress_name,
        operation: op.operation,
        model: &lane.model,
        wants_stream,
        json_array: gemini_json_array,
        request: ingress_request_body.as_ref(),
        now_s: now(),
        elapsed_ms: u64::try_from(upstream_started.elapsed().as_millis()).ok(),
    };
    let w = whole::translate(&ctx, status.as_u16(), &bytes);
    let Whole {
        end,
        usage,
        answer,
        refused,
    } = w;
    match end {
        WholeEnd::Delivered => {
            // THE REPORT-BACK, on the delivery: the whole answer is in hand and is about to be
            // relayed, and the tap reads the SAME `usage` the accrual is made from.
            tap.report(TapReport {
                lane: i,
                usage: token_usage_of(&usage),
                open_units: open_units_of(&usage),
                finish: TapFinish::Complete,
            });
            record_resp_usage(
                host,
                usage,
                &usage_sink,
                EngineTables::new(rt).lanes().get(i),
            );
            budget_guard.disarm();
            let model = &lane.model;
            return rendered_response_via(answer, |rb| {
                maybe_attach_route_policy(rb, chosen_policy_name, model)
            });
        }
        WholeEnd::FailedGeneration => {
            failed_generation(
                host,
                rt,
                i,
                pool,
                breaker_cfg,
                usage,
                &usage_sink,
                budget_guard,
                tap,
            );
        }
        WholeEnd::IngressUnsupported => {
            // The caller's dialect has no shape for this operation at all: no completion is
            // relayed, nothing is billed, and the end the record seals is an error.
            tap.report(TapReport {
                lane: i,
                usage: None,
                open_units: Default::default(),
                finish: TapFinish::Error,
            });
        }
        // The capped read above answered these two before any translate ran.
        WholeEnd::OverCap | WholeEnd::Cut => {}
        WholeEnd::NotTranslatable => {
            match refused {
                Some(r) if r.opaque => diag_debug!(
                    CROSSPROTO_BINARY_CODEC_FAILED,
                    ingress = %ingress_protocol,
                    egress = %egress_name,
                    error = %r.detail,
                    degraded,
                    "cross-protocol binary response failed the egress codec (read_response); returning ingress-native 500",
                ),
                Some(r) => diag_debug!(
                    CROSSPROTO_JSON_CODEC_FAILED,
                    ingress = %ingress_protocol,
                    egress = %egress_name,
                    error = %r.detail,
                    degraded,
                    "cross-protocol JSON response failed the egress codec (read_response_value); returning ingress-native 500",
                ),
                None => {}
            }
            not_translatable(
                host,
                rt,
                i,
                pool,
                ingress_protocol,
                egress_name,
                breaker_cfg,
                status,
                degraded,
                tap,
            );
        }
    }
    rendered_response(answer)
}

/// Every exit that is NOT a delivery is a transfer that FAILED after the upstream's 2xx headers,
/// and every one bills zero — because nothing of it was delivered, so no usage is reported.
/// (A cut STREAM bills what it streamed, #62; a buffered transfer streams nothing until it is
/// whole.) The client is handed an ingress-native error and no completion at all,
/// so the end is `Error` rather than `Partial`: nothing of the answer was ever relayed. Named once
/// so the failure exits report one end rather than several spellings of it.
fn failed_transfer(i: usize) -> TapReport {
    TapReport {
        lane: i,
        usage: None,
        open_units: Default::default(),
        finish: TapFinish::Error,
    }
}

/// Phases 2-4: buffer the whole 2xx body under the translation cap, then take the two failure exits
/// that a buffered read can end in. `Ok(bytes)` is a fully-buffered body ready to translate; `Err`
/// is the ingress-native error a transport failure or an over-cap truncation returns (each having
/// already reported the tap and recorded the compensating breaker/budget outcome). Pure extraction
/// of the capped-read block of [`translate_response_cross_protocol`]; `permit` is consumed (dropped
/// once the body is in hand) exactly where the inline code dropped it.
// `result_large_err`: `Err` is the plane's own finished `Response`, returned as-is (see `assemble.rs`).
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
async fn read_capped_body(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    pool: &str,
    ingress_protocol: &str,
    egress_name: &str,
    breaker_cfg: &BreakerCfg,
    r: axum::http::Response<hyper::body::Incoming>,
    read_deadline: tokio::time::Instant,
    permit: Permit,
    budget_guard: &mut BudgetSpendGuard<'_>,
    upstream_started: std::time::Instant,
    tap: &TapCell,
) -> Result<Bytes, Response> {
    // `truncated` distinguishes "too large to translate" from "genuinely unparseable". Bounded by
    // the caller's deadline; expiry is a failed transfer, compensated exactly like a mid-body cut.
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
        tap.report(failed_transfer(i));
        return Err(rendered_response(whole::cut(ingress_protocol).answer));
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
        tap.report(failed_transfer(i));
        return Err(rendered_response(whole::over_cap(ingress_protocol).answer));
    }
    Ok(bytes)
}

/// Phase 8: the not-translatable tail (non-JSON / unexpected-but-valid shape / unknown ingress).
/// Relaying the upstream body verbatim would leak the egress provider's native wire format to a
/// different-protocol client, so record the lane fault (an undecodable body is as much a lane fault
/// as a transport failure — without this a lane returning undecodable 200s forever never trips),
/// and report the failed transfer; the caller returns the plane's ingress-native 500. The guard is still armed, so the
/// caller's return refunds the headers-time budget unit. Pure extraction of the tail of
/// [`translate_response_cross_protocol`].
#[allow(clippy::too_many_arguments)]
fn not_translatable(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    pool: &str,
    ingress_protocol: &str,
    egress_name: &str,
    breaker_cfg: &BreakerCfg,
    status: StatusCode,
    degraded: bool,
    tap: &TapCell,
) {
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
    let tripped =
        host.lane_store()
            .record_transient_in(pool, i, "untranslatable-2xx", breaker_cfg, None);
    if tripped {
        emit_breaker_trip(host, rt, pool, i);
    }
    tap.report(failed_transfer(i));
}

/// The failed-generation exit (owner ruling Q31). The upstream answered 2xx with a whole body whose
/// stop reason says the generation FAILED (the plane's reply reads it):
/// - the CHARGE is what the upstream reported it used — ledgered through the same seam, from the
///   same `usage`, a delivery bills from (#62 applied to the buffered arm), and the headers-time
///   budget unit is kept, because the upstream did serve (and charge for) the request;
/// - the END is `Error`, with that usage riding it as the charge;
/// - the lane's BREAKER records a transient fault, compensating the optimistic success recorded
///   at headers time, exactly as the stream-end arm does for a stream's terminal error;
/// - the CLIENT gets the plane's ingress-native 502 and no completion.
#[allow(clippy::too_many_arguments)]
fn failed_generation(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    pool: &str,
    breaker_cfg: &BreakerCfg,
    usage: Option<busbar_contract::billing::Billing>,
    usage_sink: &Option<UsageSink>,
    budget_guard: &mut BudgetSpendGuard<'_>,
    tap: &TapCell,
) {
    tap.report(TapReport {
        lane: i,
        usage: token_usage_of(&usage),
        open_units: open_units_of(&usage),
        finish: TapFinish::Error,
    });
    record_resp_usage(
        host,
        usage,
        usage_sink,
        EngineTables::new(rt).lanes().get(i),
    );
    budget_guard.disarm();
    let tripped = host.lane_store().record_transient_in(
        pool,
        i,
        "upstream-generation-failed",
        breaker_cfg,
        None,
    );
    if tripped {
        emit_breaker_trip(host, rt, pool, i);
    }
}
