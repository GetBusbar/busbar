// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LEGACY DEGRADED-PATH TWIN, kept VERBATIM under test as the identity baseline for
//! `engine::attempt::attempt`. This is `forward_once` exactly as `engine/walk.rs` shipped it before
//! the one-attempt seam replaced it (only the two `super::` paths were re-pointed at the engine
//! namespace, and the visibility narrowed to this test tree). It is never compiled into the
//! product; `attempt_identity_tests` drives it side by side with `attempt()` on identical apps and
//! asserts the two agree everywhere except the registered, owner-signed differences.

#![allow(clippy::all)]
#![allow(dead_code)]

use crate::engine::*;

use busbar_substrate::diag_debug;
use busbar_substrate::diagnostics::ATTEMPT_TIMEOUT_DEGRADED;
use busbar_substrate::observability::HOTPATH_LEVEL;

/// Forward one request to a specific lane and relay the response. Shared by the degraded
/// last-resort exhaustion paths (FallbackPool routing + LeastBad). Unlike the main forward
/// loop these paths do NOT apply breaker disposition/failover classification — they relay
/// whatever the upstream returns verbatim. On a pre-response transport error the lane's
/// transient counter is recorded and `Err(())` is returned so the caller can try another
/// candidate (or give up). The concurrency `permit` is held for the lifetime of a streamed
/// success body (invariant) and dropped on error.
///
/// Cross-protocol translation: this degraded path translates BOTH directions symmetrically with the
/// main `forward_with_pool` path — the request body is translated egress-side (via the superset IR)
/// and the 2xx response is translated back to the ingress protocol (buffered for non-stream, framed
/// via `StreamTranslate` for SSE). Non-2xx responses are reshaped to the ingress error envelope on a
/// crossed boundary. Same-protocol targets pass through verbatim.
#[allow(clippy::too_many_arguments)]
// plumbing: each arg is an independent request input
// `level = busbar_substrate::observability::HOTPATH_LEVEL` (the tracing seam): this span fires on EVERY
// degraded-path attempt (fallback-pool routing + least-bad), so it must be filtered off at the
// default `RUST_LOG=info` the same as the main `forward` span in `engine/mod.rs` — routed through
// the ONE named constant rather than a second hand-picked `"debug"` literal, so the hot-path level
// policy stays a one-spot change and `scripts/tracing-lint.sh` cannot see this as a rogue,
// level-less `#[instrument]`.
#[tracing::instrument(
    level = HOTPATH_LEVEL,
    name = "forward_once",
    skip_all,
    fields(lane = i)
)]
pub(super) async fn forward_once(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    permit: Permit,
    body: &Bytes,
    caller_token: Option<&str>,
    timeout_secs: u64,
    ingress_protocol: &str,
    // The routing POOL cell this degraded attempt was selected against (fallback-pool member or
    // least-bad member). ALL breaker recordings here (success/transient) must target THIS cell, not
    // the default `""` cell: the degraded callers select via the POOL cell and (for fallback) CAS-win
    // a single-flight HalfOpen probe on it, so recording on `""` left the pool cell wedged HalfOpen +
    // `probe_in_flight` forever. An empty `pool` means the lane-default cell (direct/ad-hoc routes).
    pool: &str,
    // Owner token for the single-flight recovery probe this dispatch owns on the `(pool, i)` cell.
    // `Some(epoch)` = this dispatch WON a probe (captured at the win: `Admit.probe_epoch` from
    // `pick_among`, or the epoch from `try_admit_breaker`); a RAII `ProbeGuard` is armed to release
    // that probe OWNER-CHECKED if this future is DROPPED mid-dispatch (client disconnect) — see the
    // guard construction. `None` = this dispatch OWNS NO PROBE (the least-bad path bypasses the breaker
    // and wins nothing), so NO guard is built and this call can never release/revert any probe — in
    // particular it can never revert a probe a concurrent PEER legitimately won on the same cell.
    probe_epoch: Option<u64>,
    op: busbar_substrate::handlers::Op,
    req_content_type: &str,
    usage_sink: Option<UsageSink>,
    // The selected pool member's `reasoning` override (`WeightedLane.reasoning`), resolved by the
    // caller from its candidate slice. `None` = no member override → fall back to the lane flag. The
    // degraded path has no `cands` in scope, so the caller passes the already-resolved override here
    // (mirrors the hot path's `effective_reasoning`).
    reasoning_override: Option<bool>,
    // The allowlisted client beta/version headers the caller actually sent (from
    // `RequestCtx::forwarded_client_headers`). Forwarded to the upstream SCOPED to this lane's egress
    // dialect (no cross-dialect leak), mirroring the hot path. Empty ⇒ byte-identical egress here too.
    client_fwd: &[(axum::http::HeaderName, axum::http::HeaderValue)],
) -> Result<Response, ()> {
    // App-retype WEDGE 3: this degraded-path dispatch's upstream-failure/failover telemetry and every
    // other host reach drive through the threaded `host: &Arc<dyn EngineHost>` — no per-call mint.
    // RAII probe release covering the WHOLE dispatch window, built ONLY when
    // this dispatch actually won a probe (`probe_epoch == Some`). The caller won a single-flight
    // recovery probe on the `(pool, i)` cell before entering here; if THIS future is dropped mid-`.await`
    // (client disconnects while the upstream call is in flight) none of the explicit early-return paths
    // below run, so without a Drop guard the cell would stay HalfOpen + `probe_in_flight` forever and the
    // lane would be benched until the slow out-of-band prober reset it. `ProbeGuard::drop` releases it
    // OWNER-CHECKED (keyed on the captured `epoch`, so a stale drop never reverts a NEWER probe won by a
    // peer). It stays ARMED across every early-return error path (those paths record a transient first,
    // which already transitions the cell, making the guard's release a safe no-op) and is DISARMED
    // exactly once the request records a legitimate SUCCESS outcome (`record_success_in` below) — from
    // that point the dispatched request/stream owns the probe through its recorded outcome, so the guard
    // must not also release it. Idempotent, owner-checked: never a double-release. This supersedes the
    // previous scattered unowned `release_probe_in` calls.
    //
    // `probe_epoch == None` (the least-bad path, which bypasses the breaker and owns NO probe) builds NO
    // guard at all: there is nothing to release, so this dispatch can never revert a probe a concurrent
    // PEER legitimately won on the same cell. Representing "no probe" as `None` — rather than passing the
    // cell's CURRENT epoch to an armed guard — is what makes that safe: an epoch-equality release keyed
    // on a peer's live epoch would otherwise revert the peer's in-flight probe on a dropped future.
    let mut probe_guard = probe_epoch.map(|epoch| crate::engine::select::ProbeGuard {
        store: host.lane_store(),
        pool,
        lane: i,
        armed: true,
        probe_epoch: epoch,
    });
    // Re-parse body for per-lane model rewriting. An OPAQUE (non-JSON) body — multipart/binary
    // operations — parses to `None` and relays/translates at the byte level, exactly like the main
    // path; only a JSON-Content-Type body that FAILS to parse is the caller's 400.
    let v: Option<Value> = match busbar_substrate::json::parse(body) {
        Ok(v) => Some(v),
        Err(_) if !req_content_type.starts_with(APPLICATION_JSON) => None,
        Err(_) => {
            // See the main forward path: log a sanitized note for operators; never the parser's raw
            // error (with sonic-rs it embeds a fragment of the input body — secrets/PII) nor leak it
            // into the client 400 body.
            tracing::debug!(detail = %busbar_substrate::json::parse_err_log(body.len()), "request body JSON parse failed");
            // Pre-dispatch bail (no breaker outcome recorded): the armed `probe_guard` above releases
            // the POOL-cell single-flight probe on drop (owner-checked, idempotent, a no-op on the
            // default `""` / a non-HalfOpen cell), so the cell never wedges HalfOpen on this early exit.
            return Ok(ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "We could not parse the JSON body of your request.",
            ));
        }
    };

    // stream intent for the stream-aware upstream path (Gemini).
    let wants_stream = v
        .as_ref()
        .and_then(|v| v.get("stream"))
        .and_then(|s| s.as_bool())
        .unwrap_or(false);
    // Gemini ingress streaming WITHOUT `?alt=sse` → JSON-array streamed body (see main path). GATED
    // on `uses_array_stream_shim()` (true only for GeminiWriter) so a body-model client cannot
    // smuggle the shim key to force JSON-array reframing of its SSE stream.
    let ingress_decl = busbar_substrate::proto::decl_for(ingress_protocol);
    let gemini_json_array = ingress_decl.is_some_and(|d| d.uses_array_stream_shim)
        && ingress_decl
            .and_then(|d| d.dialect())
            .map(|di| {
                v.as_ref()
                    .map(|v| di.wants_array_stream(v))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
    let egress_name = EngineTables::new(rt).lanes()[i].protocol;

    // Breaker config for THIS degraded attempt's routing pool cell — resolved the same way the main
    // forward path resolves `breaker_cfg` (per-pool settings, ADR-0002 default fallback). All breaker
    // recordings below target the `pool` cell with this cfg so the degraded path trips/cools the pool
    // cell against its own thresholds, not a one-size default. Wrapped in an `Arc` so the streaming
    // `FirstByteBody` guard can record mid-stream failures with the SAME thresholds the synchronous
    // path used (mirrors `forward_with_pool`).
    let forward_once_cfg: std::sync::Arc<busbar_substrate::store::BreakerCfg> =
        resolve_breaker_cfg(rt, pool);

    // Cross-protocol request shaping through the SINGLE shared seam (read→clear-extra→write, shim-key
    // strip, model rewrite, serialize) — the SAME function the hot `forward_with_pool` path uses, so
    // this degraded route cannot drift from it. Sharing the seam is what keeps them aligned (this path
    // previously lacked the `ir.extra.clear()` the hot path had, leaking source-only keys like OpenAI
    // `logprobs`/`top_logprobs`/`n` to a foreign backend): the clear now lives in the one shared fn,
    // so neither path can be missing it.
    let body_is_json = v.is_some();
    let payload = match translate_request_cross_protocol(
        host,
        rt,
        i,
        ingress_protocol,
        op,
        v,
        req_content_type,
        // Honor the pool member's `reasoning` override (as the hot path does via
        // `effective_reasoning`), falling back to the lane-level flag.
        reasoning_override.unwrap_or(EngineTables::new(rt).lanes()[i].reasoning),
        body,
        // This degraded/fallback path resolves no governance key (and `caller_token` is a raw bearer
        // secret, never a principal id), so the audit principal is `"anonymous"`.
        "anonymous",
    ) {
        Ok(p) => p,
        Err(resp) => {
            // Pre-dispatch bail on a translation failure (no breaker outcome recorded): the armed
            // `probe_guard` releases the POOL-cell single-flight probe on drop (owner-checked).
            return Ok(*resp);
        }
    };

    // Mode-aware key selection: passthrough uses caller token, others use lane's api_key.
    let key = match EngineTables::new(rt).pool_upstream_creds(pool) {
        // Passthrough forwards the CALLER's credential upstream. When the caller presents NO
        // credential, fall back to an EMPTY credential — NOT the lane operator's `api_key`
        // (a SECURITY boundary): borrowing the operator key would let an unauthenticated caller
        // silently spend on the operator's upstream account. An empty credential makes the
        // provider return its own 401/403, attributed to the caller (a client-auth fault, no
        // lane penalty), matching the documented passthrough contract. No-op in canonical
        // keyless passthrough (lane.api_key already empty); only changes the misconfigured
        // passthrough+configured-key case.
        busbar_api::UpstreamCreds::Passthrough => caller_token.unwrap_or(""),
        busbar_api::UpstreamCreds::Own => EngineTables::new(rt).lanes()[i].api_key.expose_secret(),
    };

    // per-request auth (SigV4 for Bedrock; static otherwise). The (operation × stream) egress
    // target — wire URL + SigV4 canonical URI — is the lane's boot-precomputed table (mirrors the
    // main forward path; see `egress::build_egress_targets` for the sign-what-you-send encoding
    // rule). A lookup miss is the old `upstream_path` `None` arm: unreachable for chat (the router
    // filters unsupported lanes before the degraded path is reached); bail safely — the armed
    // `probe_guard` releases any single-flight probe this lane won on drop (same probe contract as
    // forward_once's other pre-dispatch exits).
    let Some(target) = EngineTables::new(rt).lanes()[i].egress_target(op.operation, wants_stream)
    else {
        return Ok(ingress_error(
            ingress_protocol,
            StatusCode::INTERNAL_SERVER_ERROR,
            KIND_API_ERROR,
            DETAIL_INTERNAL_ERROR,
        ));
    };
    let signing_ctx = busbar_substrate::proto::SigningContext {
        host: &EngineTables::new(rt).lanes()[i].signing_host,
        canonical_uri: &target.canonical_uri,
        body: &payload,
        timestamp_epoch: now(),
        upstream_creds: EngineTables::new(rt).upstream_creds(),
    };
    // Mirrors the main forward path: Own-mode on a lane-constant credential clones the
    // boot-prebuilt map; Passthrough / non-constant credentials build live.
    let egress_auth = match (
        &EngineTables::new(rt).lanes()[i].prebuilt_auth,
        EngineTables::new(rt).pool_upstream_creds(pool),
    ) {
        (Some(pre), busbar_api::UpstreamCreds::Own) => pre.clone(),
        _ => convert_headers(lane_auth_headers(
            &EngineTables::new(rt).lanes()[i],
            key,
            &signing_ctx,
        )),
    };

    // Egress Content-Type — mirror the main forward path exactly (it was hardcoded APPLICATION_JSON
    // here, which sent an opaque multipart transcription / binary body upstream as application/json,
    // a guaranteed 400). JSON body -> JSON; same-protocol opaque -> the caller's own CT (boundary
    // preserved); cross-protocol opaque -> the egress operation handler's declared wire CT.
    let egress_ct: &str = if body_is_json {
        APPLICATION_JSON
    } else if ingress_protocol == egress_name {
        req_content_type
    } else {
        busbar_substrate::handlers::request_handler(egress_name)
            .and_then(|rh| rh.operation_handler(op.operation))
            .map(|h| h.egress_request_content_type())
            .unwrap_or(APPLICATION_JSON)
    };
    // Egress header map (mirrors the main forward path): the auth map IS the base — prebuilt clone
    // or live-built above — then CT/UA/Accept in the same insertion order.
    let mut egress_headers = egress_auth;
    let ct_value = if body_is_json {
        // `from_static`: declaration constant — static bytes, no per-request alloc.
        axum::http::HeaderValue::from_static(APPLICATION_JSON)
    } else {
        // The caller's own CT (same-protocol opaque) / the egress handler's wire CT: runtime
        // strings, validated here exactly as the main path does — an unencodable CT is an
        // internal fault, never a panic on the request path.
        match axum::http::HeaderValue::from_str(egress_ct) {
            Ok(v) => v,
            Err(_) => {
                return Ok(ingress_error(
                    ingress_protocol,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    KIND_API_ERROR,
                    DETAIL_INTERNAL_ERROR,
                ));
            }
        }
    };
    egress_headers.insert(CONTENT_TYPE, ct_value);
    // Native-SDK User-Agent for the egress protocol (mirrors the main forward path).
    egress_headers.insert(
        USER_AGENT,
        axum::http::HeaderValue::from_static(crate::engine::egress_user_agent(egress_name)),
    );
    // Native-SDK Accept for the egress protocol — a declaration constant, chosen by the operation.
    egress_headers.insert(
        ACCEPT,
        axum::http::HeaderValue::from_static(op.egress_accept(egress_name, wants_stream)),
    );
    // CLIENT-HEADER FIDELITY (mirrors the main forward path): forward the allowlisted client
    // beta/version headers, scoped to THIS lane's egress dialect (no cross-dialect leak) via the
    // plane's per-destination allowlist. No-op on an empty set, so this degraded route stays
    // byte-identical when the caller sent none.
    busbar_substrate::proxy::apply_client_headers(
        &mut egress_headers,
        client_fwd,
        &crate::engine::client_header_names_for_egress(egress_name),
    );
    // The precomputed egress `http::Uri` (mirrors the main forward path): hand-assembled request,
    // no builder machinery, no per-request compose + WHATWG parse.
    let hreq = crate::engine::egress_request(target.uri.clone(), egress_headers, payload);
    // TIMEOUT RE-PROVISION (mirrors the main forward path EXACTLY — the re-audit caught this
    // path keeping the pre-fix shape, the F1 hole's second home): ONE deadline per attempt.
    // Non-stream: the failover deadline. Stream: the client-level ceiling — bounding a stream
    // with the (short) failover wall-clock would truncate healthy generations, but bounding it
    // with NOTHING let a black-holed upstream hang the degraded send forever — and the degraded
    // walk fires precisely when lanes are unhealthy, exactly where black-holing upstreams live.
    let send_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(if wants_stream {
            EngineTables::new(rt)
                .client_settings()
                .upstream_request_timeout_secs
                .max(1)
        } else {
            timeout_secs.max(1)
        });
    // Wall-clock start of the upstream call, for the `metrics.latencyMs` a native bedrock
    // ConverseStream `metadata` frame carries on the buffered-synthesis path below.
    let upstream_started = std::time::Instant::now();
    // Per-attempt time-to-headers cap on the DEGRADED path too (lane-level only: this path selects
    // by pool cell, not a member row, so the member override does not apply here). Expiry = the same
    // transport-timeout handling as the transport error below. The non-stream budget deadline wraps
    // BOTH send arms (the attempt cap, when smaller, still fires first inside).
    let send_fut = async {
        let send = EngineTables::new(rt).client().get().request(hreq);
        match EngineTables::new(rt).lanes()[i].attempt_timeout_ms {
            Some(ms) => {
                let cap = attempt_cap(ms, timeout_secs);
                match tokio::time::timeout(cap, send).await {
                    Ok(r) => SendOutcome::Sent(r),
                    Err(_elapsed) => SendOutcome::AttemptTimeout(ms),
                }
            }
            None => SendOutcome::Sent(send.await),
        }
    };
    let outcome = match tokio::time::timeout_at(send_deadline, send_fut).await {
        Ok(o) => o,
        Err(_elapsed) => SendOutcome::BudgetTimeout,
    };
    let res = match outcome {
        SendOutcome::Sent(r) => r.map_err(EgressSendError::Client),
        SendOutcome::BudgetTimeout => Err(EgressSendError::Timeout),
        SendOutcome::AttemptTimeout(ms) => {
            record_upstream_rtt(upstream_started.elapsed());
            diag_debug!(
                ATTEMPT_TIMEOUT_DEGRADED,
                pool = %pool,
                lane = %EngineTables::new(rt).lanes()[i].model,
                attempt_timeout_ms = ms,
                "no response headers within the attempt cap (degraded path)"
            );
            // Mirror the transport-error handling: record transient on the POOL cell and
            // signal the caller to try the next degraded candidate.
            let tripped = host.lane_store().record_transient_in(
                pool,
                i,
                ERR_NET_TIMEOUT,
                forward_once_cfg.as_ref(),
                None,
            );
            if tripped {
                emit_breaker_trip(host, rt, pool, i);
            }
            // `record_transient_in` above already transitioned the cell; the armed `probe_guard`
            // releases the probe on drop (owner-checked no-op after the transient). Record
            // BEFORE release preserved (the guard drops at return, after this recording).
            host.telemetry_upstream_failure(pool, i, DISPOSITION_ATTEMPT_TIMEOUT);
            // Parity with the organic path: a degraded-path attempt-timeout is a failover
            // (the caller tries the next candidate), so count it under FAILOVERS_TOTAL too.
            host.telemetry_failover(pool, DISPOSITION_ATTEMPT_TIMEOUT);
            return Err(());
        }
    };
    record_upstream_rtt(upstream_started.elapsed());
    // Every buffered read of this response rides the SAME deadline as the send (mirrors the
    // main forward path): one instant, one envelope.
    let read_deadline = send_deadline;

    match res {
        Ok(r) => {
            let status = r.status();
            let ct = r.headers().get(CONTENT_TYPE).cloned();
            // Capture the upstream relayed request-id-class headers before `r` is consumed, keyed off
            // the ingress writer's `ingress_relayed_response_header_names` so this names no protocol
            // module. For a bedrock ingress this captures `x-amzn-requestid` (the PRIMARY id —
            // forwarded verbatim on a same-protocol passthrough, or replaced by a synthesized id
            // cross-protocol below) followed by `x-amzn-errortype` (a native ConverseStream/Converse
            // error always carries it; AWS SDKs dispatch the typed exception from this header FIRST,
            // before the body `__type`; its absence is a detectable proxy tell). For an anthropic
            // ingress it captures `request-id` (the primary id). Empty for non-relaying ingress.
            let bedrock_relay_headers: Vec<(&'static str, String)> =
                ingress_relayed_response_header_names(ingress_protocol)
                    .iter()
                    .filter_map(|name| {
                        let v = r.headers().get(*name)?.to_str().ok()?.to_string();
                        Some((*name, v))
                    })
                    .collect();
            // The PRIMARY relayed id is the FIRST relayed header (x-amzn-requestid for bedrock,
            // request-id for anthropic); the writer vtable picks the correct response header to attach
            // it under on the 2xx success path. The bedrock-only second header (`x-amzn-errortype`) is
            // forwarded verbatim alongside it from `bedrock_relay_headers` on the error relay below.
            let upstream_relay_id = bedrock_relay_headers.first().map(|(_, v)| v.clone());
            let cross_protocol = ingress_protocol != egress_name;

            if !status.is_success() {
                let bytes = read_capped_body(r, read_deadline).await;
                // PX1 (availability): classify the upstream disposition BEFORE penalizing the
                // breaker. Both degraded relay branches below previously recorded a transient
                // failure (`record_transient_in`) on ANY non-2xx — counting deterministic
                // client-error 4xx (400/401/403/404/422) and deliberate 429 rate-limits as
                // transient upstream FAULTS, tripping the breaker against a HEALTHY upstream (a
                // self-inflicted outage). Reuse the SAME two-stage classifier the main
                // `forward_with_pool` path uses (op cell `extract_error` → `normalize_raw_error`
                // over the lane's `error_map` → `breaker::classify`), so ONLY a genuine upstream
                // fault (5xx / overload / timeout / network → `TransientUpstream`) feeds the
                // breaker. Every other disposition — client fault (4xx), auth/billing HardDown,
                // ContextLength — relays verbatim with NO transient penalty; the still-armed
                // `probe_guard` releases any won HalfOpen probe on drop (mirrors the main path's
                // ClientFault/ContextLength arms). Body-only classification here (no headers);
                // `retry_after` only floors the cooldown, not the disposition, so it is omitted.
                let penalize_breaker = {
                    let raw = busbar_substrate::handlers::op_for(
                        egress_name,
                        op.operation,
                        busbar_substrate::transport::Transport::Http,
                    )
                    .map(|cell| cell.extract_error(status.as_u16(), &bytes))
                    .unwrap_or_else(|| {
                        busbar_substrate::breaker::RawUpstreamError::from_status(status.as_u16())
                    });
                    let sig = busbar_substrate::breaker::normalize_raw_error(
                        &raw,
                        &EngineTables::new(rt).lanes()[i].error_map,
                    );
                    matches!(
                        busbar_substrate::breaker::classify(&sig),
                        busbar_substrate::breaker::Disposition::TransientUpstream
                    )
                };
                // Cross-protocol: relaying the EGRESS provider's native error body+Content-Type to a
                // different-protocol client is a foreign-format leak. Reshape to the ingress
                // protocol's native error envelope, lifting the upstream's human message where
                // present. Same-protocol passthrough relays verbatim (already the client's shape).
                if cross_protocol {
                    // Shared finalizer: the kind→native-envelope mapping (401→authentication_error,
                    // 403→permission_error, 429→rate_limit_error, 5xx→api_error, else
                    // invalid_request_error) is now IDENTICAL to the main `forward_with_pool` path, so
                    // this degraded route can no longer drift (the bug it fixes: a 401/403 on the
                    // degraded path was labeled `invalid_request_error`, the wrong typed-exception
                    // discriminant for an Anthropic SDK and a proxy tell).
                    // Probe-leak guard: a non-fault non-2xx (client 4xx / auth / context-length)
                    // records no breaker outcome on this degraded relay path (it relays verbatim),
                    // so the single-flight HalfOpen probe this fallback attempt CAS-won on the POOL
                    // cell is still in flight. Release it before returning or the cell stays HalfOpen
                    // + `probe_in_flight` forever. Idempotent; no-op off a HalfOpen / default cell.
                    //
                    // Cooldown-backoff fix: on a genuine upstream FAULT (`penalize_breaker`, see the
                    // PX1 classification above), record a transient failure BEFORE releasing the
                    // probe, so a non-2xx on a HalfOpen probe bumps the cooldown (exponential
                    // backoff) exactly like the MAIN forward path's non-2xx branch. Releasing alone
                    // left the cooldown at its original expiry, so the lane re-probed at the base
                    // interval with no backoff. A threshold re-trip here is a breaker trip too (#29).
                    // On a NON-fault (client 4xx, auth/billing, context-length) `penalize_breaker`
                    // is false: the `&&` short-circuits so `record_transient_in` is NEVER called, and
                    // the still-armed `probe_guard` releases the probe on drop — no breaker penalty.
                    let tripped = penalize_breaker
                        && host.lane_store().record_transient_in(
                            pool,
                            i,
                            ERR_DEGRADED_NON2XX,
                            forward_once_cfg.as_ref(),
                            None,
                        );
                    if tripped {
                        emit_breaker_trip(host, rt, pool, i);
                    }
                    // On a fault, `record_transient_in` above transitioned the cell (cooldown-backoff
                    // preserved); the armed `probe_guard` releases the probe on drop (owner-checked
                    // no-op after). On a non-fault, the guard is the SOLE releaser.
                    return Ok(shape_cross_protocol_error(ingress_protocol, status, &bytes));
                }
                // Same-protocol degraded path: relay the upstream error verbatim (no classification).
                let mut rb = Response::builder().status(status);
                if let Some(ct) = ct {
                    rb = rb.header(CONTENT_TYPE, ct);
                }
                if ingress_relays_amzn_headers(ingress_protocol) {
                    // Bedrock-ingress same-protocol error relay: forward BOTH `x-amzn-requestid` and
                    // `x-amzn-errortype` VERBATIM (no synth), mirroring the main `forward_with_pool`
                    // path. Without them a native AWS SDK's `request_id()` returns None and the
                    // typed-exception dispatch falls back from header-first to body `__type` — both
                    // detectable tells. (This degraded route previously captured the id but never
                    // attached it, and dropped the errortype.) The header NAMES + VALUES come from the
                    // vtable-keyed `bedrock_relay_headers` capture, so this names no protocol module.
                    for (name, value) in &bedrock_relay_headers {
                        rb = rb.header(*name, value);
                    }
                } else {
                    // Anthropic-ingress same-protocol error relay: forward the upstream `request-id`
                    // (a native Anthropic error always carries it; the SDK reads it into
                    // `APIError.request_id`), synthesizing one if the upstream omitted it. The writer
                    // vtable selects the `request-id` header name and the upstream-or-synth value.
                    rb = maybe_attach_response_request_id(
                        rb,
                        ingress_protocol,
                        upstream_relay_id.as_deref(),
                    );
                }
                // Probe-leak guard: same as the cross-protocol non-2xx branch above —
                // a non-fault verbatim same-protocol error relay records no breaker outcome, so
                // release the POOL-cell single-flight probe this fallback attempt CAS-won before
                // returning, or the cell stays HalfOpen + `probe_in_flight` forever. Idempotent;
                // no-op off a HalfOpen / default cell.
                //
                // Cooldown-backoff fix: on a genuine upstream FAULT (`penalize_breaker`, see the PX1
                // classification above), record a transient failure BEFORE releasing the probe, so a
                // non-2xx on a HalfOpen probe bumps the cooldown (exponential backoff) like the MAIN
                // forward path's non-2xx branch. Without it the cooldown stayed at its original expiry
                // and the lane re-probed at the base interval with no backoff. A threshold re-trip
                // here is a breaker trip too (#29). On a NON-fault (client 4xx, auth/billing,
                // context-length) `penalize_breaker` is false: the `&&` short-circuits so
                // `record_transient_in` is NEVER called and the armed `probe_guard` alone releases the
                // probe — a healthy upstream's deterministic 4xx no longer trips the breaker.
                let tripped = penalize_breaker
                    && host.lane_store().record_transient_in(
                        pool,
                        i,
                        ERR_DEGRADED_NON2XX,
                        forward_once_cfg.as_ref(),
                        None,
                    );
                if tripped {
                    emit_breaker_trip(host, rt, pool, i);
                }
                // On a fault, `record_transient_in` above transitioned the cell (cooldown-backoff
                // preserved); the armed `probe_guard` releases the probe on drop (owner-checked no-op
                // after). On a non-fault, the guard is the SOLE releaser.
                return Ok(rb
                    .body(Body::from(bytes))
                    .unwrap_or_else(|_| status.into_response()));
            }

            // SUCCESS: the degraded path served a 2xx. Mirror the main forward loop
            // (forward_with_pool) — record the lane success against the ROUTING POOL cell (feeds the
            // breaker success window so a HalfOpen lane served via fallback/least-bad recovers the
            // POOL cell to Closed and clears its single-flight probe) and consume one unit of its
            // lifetime request budget. The degraded callers select via the pool cell, so recording on
            // the default `""` cell left the pool cell wedged HalfOpen + probe_in_flight forever.
            host.lane_store().record_success_in(pool, i);
            // DISARM the probe guard: `record_success_in` recorded this dispatch's legitimate outcome
            // (HalfOpen→Closed, probe cleared), so the request now owns the probe through to that
            // outcome. From here the streamed/buffered success body (or its own mid-stream failure
            // recording) is responsible for the cell, and the guard must NOT also release on drop. No-op
            // when no guard was built (least-bad path, `probe_epoch == None`).
            if let Some(g) = probe_guard.as_mut() {
                g.armed = false;
            }
            // Mirror the main path: fold time-to-headers into the lane's latency EWMA (routing
            // `fastest` signal). Lane-global; off the selection path.
            host.lane_store().record_latency_in(
                pool,
                i,
                upstream_started.elapsed().as_secs_f64() * 1000.0,
            );
            // BIND the spend result (#21): a paired post-headers body TransportError below refunds the
            // budget, but `refund_budget` UNCONDITIONALLY fetch_adds — so refunding a spend that was a
            // no-op (budget already 0) would raise the budget ABOVE its cap. Only refund if this spend
            // actually decremented. `budget_spent` is `true` for an unlimited lane (spend is a no-op
            // success there), so an unlimited lane never refunds (refund_budget is also a no-op there).
            let budget_spent = host.lane_store().spend_budget(i);
            // Guards the buffered path's spend→`read_capped(...).await` window (#21): armed now,
            // disarmed at every exit below that must KEEP the charge. Disarmed (without refunding)
            // just before the streaming builder, which hands `budget_spent` to `FirstByteBody` for
            // its own cancellation-safe refund. See `engine::mod::BudgetSpendGuard`.
            let mut budget_guard = crate::engine::BudgetSpendGuard {
                store: host.lane_store(),
                lane: i,
                armed: budget_spent,
            };

            // SUCCESS: stream the response body incrementally (permit held for stream life).
            let is_sse = ct
                .as_ref()
                .map(|h| is_streaming_content_type(h.to_str().unwrap_or("")))
                .unwrap_or(false);

            // Non-streaming cross-protocol response: buffer + translate egress→IR→ingress, mirroring
            // the main forward_with_pool path so this degraded route does not leak the egress wire
            // format to a different-protocol client.
            if cross_protocol && !is_sse {
                return Ok(crate::engine::translate_response_cross_protocol(
                    host,
                    rt,
                    i,
                    ingress_protocol,
                    op,
                    pool,
                    forward_once_cfg.as_ref(),
                    r,
                    read_deadline,
                    permit,
                    &mut budget_guard,
                    usage_sink,
                    status,
                    wants_stream,
                    gemini_json_array,
                    upstream_started,
                    // The degraded (FallbackPool/LeastBad) path has no `chosen_policy_name` in scope —
                    // there is no routing-policy decision on this hop — and `maybe_attach_route_policy`
                    // is already a no-op on `None`, so this reproduces the prior behavior (no
                    // `x-busbar-route-*` headers on this path) exactly.
                    None,
                    true, // degraded path: selects the "degraded"-labeled warn strings
                    None,
                )
                .await);
            }

            // Streaming (or same-protocol non-stream): stream with first-byte boundary tracking. On a
            // cross-protocol SSE response, translate egress frames → ingress frames, matching the main
            // path. Mid-stream breaker failures must record against the ROUTING POOL cell with this
            // pool's resolved breaker cfg (mirrors `forward_with_pool`) — NOT the default `""` cell —
            // so a fallback/least-bad stream that fails mid-flight reopens the pool cell it was
            // selected against, never the unrelated default cell.
            // ONE registry-resolved factory, IDENTICAL to the hot `forward_with_pool` path (extracted
            // so the two cannot drift): cross-protocol SSE builds the reframing translator,
            // same-protocol SSE the verbatim same-proto translator (byte-exact re-emit + IR usage
            // A-tap), `!is_sse`/unknown-protocol yields `None` → legacy passthrough. Named directly
            // from this crate rather than through the substrate's installable pointer, for the
            // reason given at the hot-path site: an uninstalled pointer yields `None` and silently
            // drops both the reframing and the stream-end metering.
            let translate =
                crate::proto_stream::new_stream_translator(ingress_protocol, egress_name, is_sse);
            let json_array = (gemini_json_array && is_sse)
                .then(|| {
                    busbar_substrate::proto::decl_for(ingress_protocol)
                        .and_then(|d| d.dialect())
                        .and_then(|dc| dc.make_array_stream_framer())
                })
                .flatten();
            // Handing the budget-refund decision to `FirstByteBody` (via `budget_spent` below) —
            // disarm the local guard so it does not ALSO refund when this frame unwinds.
            budget_guard.disarm();
            let upstream_stream = {
                use http_body_util::BodyExt;
                r.into_body().into_data_stream()
            };
            let guarded_body = FirstByteBody::new(
                upstream_stream,
                is_sse,
                ingress_protocol,
                op,
                permit,
                read_deadline,
                host.clone(),
                rt.clone(),
                i,
                forward_once_cfg.clone(),
                pool, // degraded path: the routing pool's breaker cell
                translate,
                json_array,
                usage_sink,
                budget_spent,
            );
            let mut rb = Response::builder().status(status);
            // Cross-protocol streaming: the body is reframed to the client's format, so the CT must
            // describe the ingress client's wire, not the upstream's. Same-protocol keeps the upstream
            // CT verbatim.
            if gemini_json_array && is_sse {
                rb = rb.header(CONTENT_TYPE, APPLICATION_JSON);
            } else {
                match (cross_protocol && is_sse)
                    .then(|| ingress_stream_content_type(ingress_protocol))
                    .flatten()
                {
                    Some(client_ct) => {
                        rb = rb.header(CONTENT_TYPE, client_ct);
                    }
                    None => {
                        if let Some(ct) = ct {
                            rb = rb.header(CONTENT_TYPE, ct);
                        }
                    }
                }
            }
            // Bedrock-ingress 2xx carries `x-amzn-RequestId`; anthropic-ingress 2xx carries
            // `request-id`: forward the captured upstream id verbatim on a same-protocol passthrough,
            // else synthesize. The writer vtable selects the correct header name + upstream-or-synth
            // value per protocol; non-relaying ingress: omit.
            rb = maybe_attach_response_request_id(
                rb,
                ingress_protocol,
                upstream_relay_id.as_deref(),
            );
            Ok(rb
                .body(guarded_body.into_body())
                .unwrap_or_else(|_| status.into_response()))
        }
        Err(e) => {
            // Pre-response transport error: record transient against the ROUTING POOL cell, drop the
            // permit, signal "try next". The degraded callers selected via the pool cell (fallback CAS
            // -wins a HalfOpen probe on it), so this transport failure must reopen the POOL cell — not
            // the default `""` cell, which would leave the pool cell wedged HalfOpen forever.
            // BREAKER_TRIPS_TOTAL is emitted here too, gated on the trip bool, mirroring the sibling
            // degraded arms (the two non-2xx relays and the post-headers transport arm) so a logical
            // Closed→Open trip is counted exactly once regardless of which degraded failure shape hit
            // it. (`tripped` is false for a HalfOpen reopen / already-Open no-op, so it is not
            // inflated.) Keeps the cross-arm counters symmetric.
            let err_type = if e.is_timeout() {
                ERR_NET_TIMEOUT
            } else {
                ERR_NET_CONNECT
            };
            let tripped = host.lane_store().record_transient_in(
                pool,
                i,
                err_type,
                forward_once_cfg.as_ref(),
                None,
            );
            if tripped {
                emit_breaker_trip(host, rt, pool, i);
            }
            drop(permit);
            Err(())
        }
    }
}
