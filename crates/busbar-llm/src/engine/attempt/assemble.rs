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
    let _xlate = busbar_substrate::profile::start(busbar_substrate::profile::Stage::TranslateReq);
    let payload = translate(hop, hop_v).await?;
    let payload = inject_stream_usage(hop, payload);
    drop(_xlate);

    let _cbuild = busbar_substrate::profile::start(busbar_substrate::profile::Stage::ClientBuild);
    let _t = busbar_timing::timeit!("egress_client_build");
    // MEASUREMENT ONLY (busbar-timing, additive): `egress_assemble` sub-scopes everything below
    // that is NOT the network send — credential select, path/URI build, auth-header build (itself
    // sub-timed as `egress_sigv4`), and request construction.
    let _asm = busbar_timing::timeit!("egress_assemble");

    // Mode-aware key selection: passthrough uses the caller's token, own-mode the lane's api_key.
    // Passthrough with NO caller credential sends an EMPTY credential — never the operator's key
    // (a security boundary: borrowing it would let an unauthenticated caller spend on the operator's
    // upstream account). The provider then returns its own 401/403, attributed to the caller.
    let key = match hop.upstream_creds {
        busbar_api::UpstreamCreds::Passthrough => hop.caller_token.unwrap_or(""),
        busbar_api::UpstreamCreds::Own => hop.lane_row().api_key.expose_secret(),
    };

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
    let _cb_auth = busbar_substrate::profile::start(busbar_substrate::profile::Stage::CbAuth);
    // The SigV4 timestamp is taken here, inside the attempt, per attempt (the five-minute-skew rule).
    let signing_ctx = busbar_substrate::proto::SigningContext {
        host: &hop.lane_row().signing_host,
        canonical_uri: &target.canonical_uri,
        body: &payload,
        timestamp_epoch: now(),
        upstream_creds: EngineTables::new(rt).upstream_creds(),
    };
    // Own-mode dispatch on a lane-constant credential takes the boot-prebuilt header map (one
    // buffer copy, byte-identical to the live build). Passthrough carries the caller's key and a
    // non-constant credential (OAuth / SigV4) reads the request, so both build live.
    let egress_auth = match (&hop.lane_row().prebuilt_auth, hop.upstream_creds) {
        (Some(pre), busbar_api::UpstreamCreds::Own) => pre.clone(),
        _ => convert_headers(busbar_timing::scope("egress_sigv4", || {
            lane_auth_headers(hop.lane_row(), key, &signing_ctx)
        })),
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
        busbar_substrate::handlers::request_handler(hop.egress_name)
            .and_then(|rh| rh.operation_handler(hop.op.operation))
            .map(|h| h.egress_request_content_type())
            .unwrap_or(APPLICATION_JSON)
    };
    let _cb_reqwest = busbar_substrate::profile::start(busbar_substrate::profile::Stage::CbReqwest);
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
    // a proxy fingerprint.
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
    // Forward the allowlisted client beta/version headers the caller actually sent, scoped to THIS
    // egress dialect (no cross-dialect leak). A no-op when the caller sent none.
    busbar_substrate::proxy::apply_client_headers(
        &mut egress_headers,
        hop.client_fwd,
        &crate::engine::client_header_names_for_egress(hop.egress_name),
    );
    let hreq = crate::engine::egress_request(target.uri.clone(), egress_headers, payload);
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
fn inject_stream_usage(hop: &Hop<'_>, payload: Bytes) -> Bytes {
    if hop.wants_stream
        && hop.body_is_json
        && busbar_substrate::proto::decl_for(hop.egress_name)
            .is_some_and(|d| d.stream_usage_requires_opt_in)
        && !hop.client_include_usage
    {
        if hop.client_has_stream_options {
            inject_openai_stream_include_usage(payload)
        } else {
            inject_openai_stream_include_usage_pristine(payload)
        }
    } else {
        payload
    }
}

/// Force `stream_options.include_usage: true` on an OpenAI Chat Completions streaming request body so
/// the upstream emits token usage busbar can bill. Parses `payload`, sets the nested flag
/// (creating `stream_options` if absent, overwriting a `false`), and re-serializes. On any parse/shape
/// failure the ORIGINAL bytes are returned unchanged — a malformed body is the upstream's to reject,
/// not busbar's to mangle, and the worst case is the pre-existing zero-usage billing gap rather than a
/// corrupted request. A body that already opted in re-serializes identically in effect.
pub(crate) fn inject_openai_stream_include_usage(payload: Bytes) -> Bytes {
    let mut v: Value = match busbar_substrate::json::parse(&payload) {
        Ok(v) => v,
        Err(_) => return payload,
    };
    let Some(obj) = v.as_object_mut() else {
        return payload;
    };
    let so = obj
        .entry("stream_options".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Some(so_obj) = so.as_object_mut() else {
        // `stream_options` present but not an object: leave the body untouched (the upstream will 400
        // on the malformed field; busbar must not silently reshape a caller's value).
        return payload;
    };
    so_obj.insert("include_usage".to_string(), Value::Bool(true));
    match busbar_substrate::json::to_vec(&v) {
        Ok(bytes) => Bytes::from(bytes),
        Err(_) => payload,
    }
}

/// Cheap forward substring scan (needle is a short constant `"stream_options"` key literal). Avoids
/// pulling a dependency for the one idempotency check below; the haystack is a request body scanned
/// at most once, so the naive O(n*m) walk is well within the byte-level path's budget.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// PRISTINE-PRESERVING variant of [`inject_openai_stream_include_usage`] for a body the head
/// projection already proved carries NO top-level `stream_options` key. Splices
/// `"stream_options":{"include_usage":true},` in immediately after the opening `{` instead of
/// parsing + re-serializing the whole DOM, so a same-protocol pristine passthrough body stays
/// parse-free while still forcing the upstream to emit billable token usage.
///
/// SOUNDNESS: the caller gates entry on `!client_has_stream_options`, but that decision was captured
/// off the PRE-rewrite ingress body; a `prompt: rw` hook that injects a top-level `stream_options`
/// key leaves it STALE (`false`), and a blind leading-member splice would then produce a DUPLICATE
/// top-level `stream_options`. Under JSON last-wins the rewrite's copy would be honored and busbar's
/// injected `include_usage` silently discarded, so the upstream emits no usage and busbar bills ZERO
/// tokens for the stream. To stay correct regardless of what a rewrite did, this injector is itself
/// IDEMPOTENT: it first scans the (post-any-rewrite) body being sent for the `"stream_options"` key
/// bytes and, if present, defers to the DOM injector [`inject_openai_stream_include_usage`], which is
/// duplicate-safe via `entry()` (it upgrades the existing object in place). The substring scan is
/// conservative: a body that merely mentions `stream_options` inside a string value would also defer
/// (a rare, harmless extra DOM parse, never a correctness or duplicate-key issue). The common
/// no-rewrite pristine path carries no such bytes, so it still takes the cheap byte-splice with no
/// DOM parse. The splice is a LEADING member, so it never lands after the object's final key without
/// a comma, and the object is known non-empty on the streaming path (`stream` at minimum). Any body
/// that is not a JSON object starting with `{` (or the degenerate empty `{}`) falls back to the DOM
/// injector, which itself returns the bytes unchanged on a non-object - so a malformed/edge body is
/// never corrupted.
pub(crate) fn inject_openai_stream_include_usage_pristine(payload: Bytes) -> Bytes {
    const INSERT: &[u8] = br#""stream_options":{"include_usage":true},"#;
    // IDEMPOTENCY GUARD: if the body being sent already carries a `stream_options` key (e.g. a rewrite
    // hook injected one after the caller's has-stream_options decision was captured), a blind splice
    // would duplicate the top-level key and last-wins would drop busbar's include_usage, billing
    // zero. Defer to the duplicate-safe DOM injector. Cheap byte scan; the no-rewrite fast path (no
    // such bytes present) is unaffected and still takes the splice below.
    if contains_subslice(&payload, br#""stream_options""#) {
        return inject_openai_stream_include_usage(payload);
    }
    // Find the first `{`, skipping only leading ASCII whitespace (the sole bytes JSON permits before
    // the top-level value). Anything else at the front is not a plain object body - defer to the DOM
    // injector rather than splice blindly.
    let mut i = 0usize;
    while i < payload.len() && payload[i].is_ascii_whitespace() {
        i += 1;
    }
    // The byte AFTER the brace must begin a KEY (`"`) for the leading-member splice to stay valid
    // JSON; on `{}` (next non-space is `}`) or any non-object body, fall back to the DOM path.
    let opens_object = payload.get(i) == Some(&b'{');
    let next = {
        let mut j = i + 1;
        while j < payload.len() && payload[j].is_ascii_whitespace() {
            j += 1;
        }
        payload.get(j).copied()
    };
    if !opens_object || next != Some(b'"') {
        return inject_openai_stream_include_usage(payload);
    }
    // Splice: [ .. up to and including `{` ] + INSERT + [ first key .. end ]. `i+1` is the byte just
    // past the brace; the retained tail is byte-for-byte the caller's, so nothing else is disturbed.
    let brace_end = i + 1;
    let mut out = Vec::with_capacity(payload.len() + INSERT.len());
    out.extend_from_slice(&payload[..brace_end]);
    out.extend_from_slice(INSERT);
    out.extend_from_slice(&payload[brace_end..]);
    Bytes::from(out)
}
