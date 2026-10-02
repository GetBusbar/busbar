// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ASSEMBLE — turn this hop's body view into the exact egress request: the cross-protocol
//! translate (with the huge-body offload), the streaming-usage injection an OpenAI Chat egress
//! needs to be billable, credential selection, the per-request auth build (SigV4 for Bedrock),
//! and the egress header map. Every rule here applies to the hot loop and the degraded paths alike
//! because there is only one copy of it.

use super::Hop;
use crate::engine::*;

/// Bodies at or above this size run the (pure, synchronous) cross-protocol translate on the
/// blocking pool instead of inline on the single-threaded worker — see the offload comment at the
/// call site. 128 KiB: the inline worst case at the boundary is ~1-2 ms (inside the p99 envelope),
/// and real chat bodies are two orders of magnitude smaller, so the offload branch is statically
/// dead on the happy path. A constant, not a knob.
pub(crate) const TRANSLATE_OFFLOAD_THRESHOLD: usize = 128 * 1024;

/// The fully assembled egress request. `Err` is the ingress-native internal-error response for a
/// pre-send failure (nothing has been sent, nothing is recorded against the breaker).
///
/// (`result_large_err`: the `Err` is the plane's OWN finished response, carried by value because the
/// caller does nothing with it but hand it straight back to the client. Boxing it would only add an
/// allocation on a path that already gave up on the request.)
#[allow(clippy::result_large_err)]
pub(super) async fn build(
    hop: &Hop<'_>,
    hop_v: Option<Value>,
) -> Result<http::Request<http_body_util::Full<Bytes>>, Response> {
    let rt = hop.rt;
    let _xlate = busbar_kernel::profile::start(busbar_kernel::profile::Stage::TranslateReq);
    let payload = translate(hop, hop_v).await?;
    let payload = inject_stream_usage(hop, payload)?;
    drop(_xlate);

    let _cbuild = busbar_kernel::profile::start(busbar_kernel::profile::Stage::ClientBuild);

    // The (operation × stream) egress target — wire URL and SigV4 canonical URI — precomputed at
    // boot on the lane (see `egress::build_egress_targets` for the sign-what-you-send rule). A
    // lookup miss means this lane's protocol has no handler for the operation: unreachable for chat
    // and filtered by the router, but bail safely rather than dispatch to a wrong path.
    let Some(target) = hop
        .lane_row()
        .egress_target(hop.op.operation, hop.wants_stream)
    else {
        return Err(internal_error(hop.ingress_protocol));
    };
    // Busbar is invisible to upstreams: a same-dialect hop carries the caller's own URL query, the
    // plane's dialect data deciding which parameters go. `None` (the common case) keeps the
    // boot-built target untouched.
    let with_query: Option<axum::http::Uri> = (hop.ingress_protocol == hop.egress_name)
        .then_some(hop.client_fwd.query.as_deref())
        .flatten()
        .and_then(|q| {
            let pq = target.uri.path_and_query()?.as_str();
            let joined = crate::engine::xchg::attempt::with_caller_query(hop.egress_name, pq, q)?;
            let mut parts = target.uri.clone().into_parts();
            parts.path_and_query = Some(joined.parse().ok()?);
            axum::http::Uri::from_parts(parts).ok()
        });
    let _cb_auth = busbar_kernel::profile::start(busbar_kernel::profile::Stage::CbAuth);
    // The SigV4 timestamp is taken here, inside the attempt, per attempt (the five-minute-skew rule).
    let signing_ctx = busbar_kernel::proto::SigningContext {
        host: &hop.lane_row().signing_host,
        canonical_uri: &target.canonical_uri,
        body: &payload,
        timestamp_epoch: now(),
        upstream_creds: EngineTables::new(rt).upstream_creds(),
    };
    // Mode-aware credential: own-mode presents the lane's api_key; a lane-constant one takes the
    // boot-prebuilt header map (one buffer copy, byte-identical to the live build), a non-constant
    // one (OAuth / SigV4) reads the request, so builds live. PASSTHROUGH presents the CALLER's
    // credential, and the HOST presents it: this plane carries only the ref the gate handed it and
    // never holds the plaintext (#65, #40(b)). No caller credential presents nothing — never the
    // operator's key (borrowing it would let an unauthenticated caller spend on the operator's
    // upstream account); the provider then returns its own 401/403, attributed to the caller.
    let egress_auth = match (&hop.lane_row().prebuilt_auth, hop.upstream_creds) {
        (_, busbar_contract::config::UpstreamCreds::Passthrough) => {
            convert_headers(crate::engine::present_caller(
                hop.lane_row().credential.as_ref(),
                hop.caller_token,
                &signing_ctx,
            ))
        }
        (Some(pre), busbar_contract::config::UpstreamCreds::Own) => pre.clone(),
        (None, busbar_contract::config::UpstreamCreds::Own) => convert_headers(lane_auth_headers(
            hop.lane_row(),
            hop.lane_row().api_key.expose_secret(),
            &signing_ctx,
        )),
    };
    drop(_cb_auth);

    // Egress Content-Type: JSON bodies stay JSON. An OPAQUE body relays the caller's own CT
    // same-protocol (multipart boundary preserved verbatim) and uses the egress operation handler's
    // declared wire CT cross-protocol.
    let egress_ct: &str = if hop.body_is_json {
        APPLICATION_JSON
    } else if hop.ingress_protocol == hop.egress_name {
        hop.req_content_type
    } else {
        request_handler(hop.egress_name)
            .and_then(|rh| rh.operation_handler(hop.op.operation))
            .map(|h| h.egress_request_content_type())
            .unwrap_or(APPLICATION_JSON)
    };
    let _cb_reqwest = busbar_kernel::profile::start(busbar_kernel::profile::Stage::CbReqwest);
    // The auth map IS the base of the header map, extended in place with the three per-request
    // constants in the same order as always (auth, then CT/UA/Accept).
    let mut egress_headers = egress_auth;
    let ct_value = if hop.body_is_json {
        axum::http::HeaderValue::from_static(APPLICATION_JSON)
    } else {
        // The two rare opaque-relay arms carry bytes that arrived as a validated inbound header, so
        // the parse cannot fail in practice — a hostile impossibility is an internal error, never a
        // panic on the request path.
        match axum::http::HeaderValue::from_str(egress_ct) {
            Ok(v) => v,
            Err(_) => return Err(internal_error(hop.ingress_protocol)),
        }
    };
    egress_headers.insert(CONTENT_TYPE, ct_value);
    // Native-SDK User-Agent for the egress protocol: without it the backend sees a UA-less request,
    // a proxy fingerprint (1.5.5's bytes). A same-dialect caller's own user-agent replaces it below
    // with the rest of its forwarded headers.
    egress_headers.insert(
        USER_AGENT,
        axum::http::HeaderValue::from_static(crate::engine::egress_user_agent(hop.egress_name)),
    );
    // Native-SDK Accept for the egress protocol (eventstream/json/SSE by stream intent), chosen by
    // the operation; not part of SigV4 SignedHeaders.
    egress_headers.insert(
        ACCEPT,
        axum::http::HeaderValue::from_static(
            hop.op.egress_accept(hop.egress_name, hop.wants_stream),
        ),
    );
    // Busbar is invisible to upstreams: a same-dialect hop forwards every client header it
    // collected (none of them governed), the client's value winning over busbar's native defaults.
    // A translated hop forwards none: no header maps between dialects.
    if hop.ingress_protocol == hop.egress_name {
        busbar_kernel::proxy::apply_client_headers(&mut egress_headers, &hop.client_fwd.headers);
    }
    let uri = with_query.unwrap_or_else(|| target.uri.clone());
    let hreq = crate::engine::egress_request(uri, egress_headers, payload);
    drop(_cb_reqwest);
    Ok(hreq)
}

/// The ingress-native internal-error response every pre-send bail returns.
fn internal_error(ingress_protocol: &str) -> Response {
    ingress_error(
        ingress_protocol,
        StatusCode::INTERNAL_SERVER_ERROR,
        KIND_API_ERROR,
        DETAIL_INTERNAL_ERROR,
    )
}

/// The egress payload bytes for this hop: the retained bytes verbatim on a pristine same-protocol
/// hop, else the shared cross-protocol request-shaping seam (read → clear-extra → write, shim-key
/// strip, model rewrite, serialize). A maximum-size body runs the same pure call on the blocking
/// pool so a single-threaded worker is not head-of-line-blocked for hundreds of milliseconds.
///
/// (`result_large_err`: same reason as `build` — the `Err` is a finished response that only travels
/// upward to the client.)
#[allow(clippy::result_large_err)]
async fn translate(hop: &Hop<'_>, hop_v: Option<Value>) -> Result<Bytes, Response> {
    if hop.pristine {
        // `Bytes::clone` is a refcount bump; the exact bytes the translate seam's own pristine
        // short-circuit would emit.
        return Ok(hop.body.clone());
    }
    let reasoning = effective_reasoning(hop.cands, hop.lane, hop.lane_row().reasoning);
    let caller_key_id = hop
        .resolved_gov_key
        .map(|k| k.id.as_str())
        .unwrap_or("anonymous");
    let translated = if hop.body.len() >= TRANSLATE_OFFLOAD_THRESHOLD {
        // Owned host/rt clones (Arc bumps) move into the blocking task so no borrowed reference
        // crosses the `spawn_blocking` boundary.
        let host2 = hop.host.clone();
        let rt2 = hop.rt.clone();
        let body2 = hop.body.clone();
        let ip: String = hop.ingress_protocol.to_string();
        let ct: String = hop.req_content_type.to_string();
        let key: String = caller_key_id.to_string();
        let (i, op) = (hop.lane, hop.op);
        match tokio::task::spawn_blocking(move || {
            translate_request_cross_protocol(
                &host2, &rt2, i, &ip, op, hop_v, &ct, reasoning, &body2, &key,
            )
        })
        .await
        {
            Ok(r) => r,
            // The blocking task itself failed (panic/cancel): internal error, same exit shape as a
            // parse failure.
            Err(_) => return Err(internal_error(hop.ingress_protocol)),
        }
    } else {
        translate_request_cross_protocol(
            hop.host,
            hop.rt,
            hop.lane,
            hop.ingress_protocol,
            hop.op,
            hop_v,
            hop.req_content_type,
            reasoning,
            hop.body,
            caller_key_id,
        )
    };
    translated.map_err(|resp| *resp)
}

/// STREAMING-USAGE UPSTREAM INJECTION: busbar bills a streaming chat call from the token usage it
/// decodes off the upstream stream, but an OpenAI Chat Completions upstream only emits that usage
/// (in a trailing chunk) when the request carried `stream_options.include_usage: true`. A client
/// that did not opt in would otherwise leave the upstream silent on tokens and busbar would bill
/// ZERO — so the flag is forced on every streaming request to such an egress, on every path.
///
/// Two gates keep the pristine same-protocol passthrough parse-free: a client that already opted in
/// needs no injection at all; a body with no top-level `stream_options` takes the byte-splice
/// injector. Only the rare body that carries a non-opted-in `stream_options` pays the DOM injector.
/// The client-facing trailing chunk is then gated on the client's OWN opt-in at the framing seam, so
/// this never leaks an unsolicited usage chunk to an opted-out client.
///
/// A body whose `stream_options` is present but can carry no `include_usage` flag (a string, number,
/// bool or array) is REFUSED here with an ingress-native 400, before any send (item 362). Forwarding
/// it verbatim relied on the upstream rejecting it; an OpenAI-compatible upstream that tolerates the
/// wrong type streams a real answer with no usage chunk and the ledger records ZERO tokens for it.
/// Busbar will not reshape the caller's value, so it refuses the request it could not meter. A JSON
/// `null` is the documented "no options" spelling and is upgraded like an absent key.
#[allow(clippy::result_large_err)]
fn inject_stream_usage(hop: &Hop<'_>, payload: Bytes) -> Result<Bytes, Response> {
    if !(hop.wants_stream
        && hop.body_is_json
        && busbar_kernel::proto::decl_for(hop.egress_name)
            .is_some_and(|d| d.stream_usage_requires_opt_in)
        && !hop.client_include_usage)
    {
        return Ok(payload);
    }
    let injected = if hop.client_has_stream_options {
        try_inject_openai_stream_include_usage(payload)
    } else {
        try_inject_openai_stream_include_usage_pristine(payload)
    };
    injected.map_err(|_unmeterable| {
        ingress_error(
            hop.ingress_protocol,
            StatusCode::BAD_REQUEST,
            KIND_INVALID_REQUEST,
            DETAIL_STREAM_OPTIONS_NOT_OBJECT,
        )
    })
}

pub(crate) use crate::engine::xchg::attempt::DETAIL_STREAM_OPTIONS_NOT_OBJECT;

/// Ask a streamed request for its usage (the plane's
/// `xchg::attempt::try_inject_stream_include_usage`, over this engine's bytes).
pub(crate) fn try_inject_openai_stream_include_usage(payload: Bytes) -> Result<Bytes, Bytes> {
    crate::engine::xchg::attempt::try_inject_stream_include_usage(payload.to_vec())
        .map(Bytes::from)
        .map_err(Bytes::from)
}

#[cfg(test)]
pub(crate) fn inject_openai_stream_include_usage(payload: Bytes) -> Bytes {
    try_inject_openai_stream_include_usage(payload).unwrap_or_else(|verbatim| verbatim)
}

#[cfg(test)]
pub(crate) fn inject_openai_stream_include_usage_pristine(payload: Bytes) -> Bytes {
    try_inject_openai_stream_include_usage_pristine(payload).unwrap_or_else(|verbatim| verbatim)
}

/// The same ask without a parse when the bytes provably carry no `stream_options` (the plane's
/// `xchg::attempt::try_inject_stream_include_usage_pristine`).
pub(crate) fn try_inject_openai_stream_include_usage_pristine(
    payload: Bytes,
) -> Result<Bytes, Bytes> {
    crate::engine::xchg::attempt::try_inject_stream_include_usage_pristine(payload.to_vec())
        .map(Bytes::from)
        .map_err(Bytes::from)
}

#[cfg(test)]
#[path = "tests/assemble.rs"]
mod tests;
