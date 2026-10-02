use super::*;

/// The plane's sans-I/O exchange: the byte steps this engine shares with the plane's door. It is
/// re-exported to the whole engine by `engine`'s `wire::*` glob, so the plane crate is named from
/// this one file, not from each step that reaches it.
pub(crate) use busbar_plane_llm::exchange as xchg;

/// Record the upstream round-trip (to response headers) for the current request so the
/// `server_timing` middleware can subtract it from the total and report Busbar's own added latency.
/// On failover the LAST attempt's value wins (recorded after every `send`, before success/error
/// classification) — so a success overwrites a prior failed hop; on an all-hops-fail exhaustion the
/// last failed hop's (typically short) RTT is what remains, which can mildly inflate the reported
/// `busbar;dur` on that error response. Telemetry only; never affects translation. No-op outside the
/// unit tests and the admin/health routes that never dispatch upstream simply don't record one.
pub(crate) fn record_upstream_rtt(rtt: std::time::Duration) {
    let us = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX);
    let _ = UPSTREAM_RTT_US.try_with(|slot| slot.store(us, std::sync::atomic::Ordering::Relaxed));
}

/// Attach the protocol's request-id RESPONSE HEADER to a SUCCESS / relay response builder, dispatched
/// through `ProtocolWriter::ingress_response_request_id` so the agnostic forward path names no
/// protocol module for request-id synthesis. A genuine Bedrock 2xx ALWAYS carries `x-amzn-RequestId`
/// (the SDK surfaces it via `*Output::request_id()`); a genuine Anthropic response ALWAYS carries
/// `request-id` (the official SDK reads it into `APIError.request_id` / `Message._request_id`, NOT the
/// body). Omitting either makes the SDK's id `None` — impossible against the real API and a
/// deterministic proxy tell. The writer forwards the captured UPSTREAM id verbatim on a same-protocol
/// passthrough and synthesizes otherwise; protocols that emit no such header return `None` (no-op).
/// Best-effort: if synthesis (entropy) fails the header is simply omitted (never panics on the request
/// path).
pub(crate) fn maybe_attach_response_request_id(
    rb: axum::http::response::Builder,
    ingress_protocol: &str,
    upstream_request_id: Option<&str>,
) -> axum::http::response::Builder {
    match crate::engine::xchg::reply::wire::response_request_id(
        ingress_protocol,
        upstream_request_id,
    ) {
        Some((name, id)) => rb.header(name, id),
        None => rb,
    }
}

/// Whether a caller's dialect relays the far end's `x-amzn-*` head fields, and which far-end head
/// field names it relays verbatim on a same-protocol answer: the plane's reply reads.
pub(crate) use crate::engine::xchg::reply::wire::ingress_relayed_response_header_names;
#[cfg(test)]
pub(crate) use crate::engine::xchg::reply::wire::ingress_relays_amzn_headers;

/// TRANSPARENCY: stamp which routing POLICY chose which TARGET onto a successful response, mirroring
/// the `x-busbar-*` header convention (e.g. the bedrock/anthropic request-id headers above):
/// `x-busbar-route-policy: <policy name>` and `x-busbar-route-target: <chosen lane model>`. Emitted
/// ONLY when BOTH gates pass:
///   1. OUTER: the operator opted in via `advanced.response_headers.route_policy`
///      (default `false`) — [`crate::engine::route_policy_headers_enabled`]. Before this gate existed
///      the header fired unconditionally whenever a non-default policy chose the lane, with no config
///      toggle at all; it is a fingerprintable observable (same class as `Server-Timing: busbar`), so
///      it now defaults off.
///   2. INNER (unchanged): a non-default policy actually produced the order (`policy_name == Some`);
///      a default `route: weighted` pool (or a policy that Abstained → SWRR) attaches NOTHING even
///      when the outer gate is on, so the zero-cost path adds no header.
///
/// Both values are bounded, operator-defined strings (a fixed policy enumeration + a configured model
/// name), never request-derived data.
pub(crate) fn maybe_attach_route_policy(
    rb: axum::http::response::Builder,
    policy_name: Option<&'static str>,
    target_model: &str,
) -> axum::http::response::Builder {
    maybe_attach_route_policy_gated(
        rb,
        crate::engine::route_policy_headers_enabled(),
        policy_name,
        target_model,
    )
}

/// The pure, DETERMINISTICALLY-testable core of [`maybe_attach_route_policy`], with the outer gate
/// passed in as a plain `bool` instead of read from the process-wide `OnceLock`. Split out so unit
/// tests can drive all four (`enabled` × `policy_name`) combinations directly, without mutating
/// [`crate::engine::ROUTE_POLICY_HEADERS_ENABLED`] — a global `OnceLock` can be set at most ONCE for
/// the life of the test binary, so exercising both the `true` and `false` outer-gate outcomes through
/// the real accessor within one process is inherently order-dependent (see the `OnceLock` handling in
/// `observability.rs`'s own tests, which uses the same "test the pure core, not the global" split).
fn maybe_attach_route_policy_gated(
    rb: axum::http::response::Builder,
    route_policy_headers_enabled: bool,
    policy_name: Option<&'static str>,
    target_model: &str,
) -> axum::http::response::Builder {
    if !route_policy_headers_enabled {
        return rb;
    }
    match policy_name {
        Some(name) => rb
            .header(HDR_ROUTE_POLICY, name)
            .header(HDR_ROUTE_TARGET, target_model),
        None => rb,
    }
}

// The canonical per-protocol error-response builder (`ingress_error`) and core's own dialect-free
// envelope (`agnostic_error_envelope`) are NEUTRAL vocabulary that STAYS in core
// (`busbar_kernel::proxy::proxy_vocab`); the engine names them at their historical short paths through
// this re-export. `ingress_reject_response` (LLM-specific — it maps an `IngressReject`) delegates to
// the re-exported `ingress_error`.
pub(crate) use busbar_kernel::proxy::ingress_error;

/// Project an [`busbar_contract::codec::IngressReject`] into the caller-dialect error response
/// (`ingress_error`). The one place that decides what each reject arm renders as, so the two
/// `read_request`/`read_request_value` call sites (the opaque-body branch and the JSON branch)
/// cannot drift on shape: `BadRequest` is today's generic 400; `UnsupportedSubOp` is the second
/// 404 (`ImageIr.op` unsupported for `model`), distinct from the no-handler 404 and naming both the
/// operation and the model so the caller knows what to stop asking for.
#[cfg(test)]
pub(crate) fn ingress_reject_response(
    ingress_protocol: &str,
    reject: &busbar_contract::codec::IngressReject,
) -> Response {
    answer_response(
        ingress_protocol,
        &crate::engine::xchg::attempt::ingress_reject("", reject),
    )
}

/// A refusal the plane's exchange answered, rendered in `ingress_protocol`'s envelope.
pub(crate) fn answer_response(
    ingress_protocol: &str,
    a: &crate::engine::xchg::attempt::Answer,
) -> Response {
    ingress_error(
        ingress_protocol,
        StatusCode::from_u16(a.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        a.kind,
        &a.message,
    )
}

/// An answer the plane rendered (its status, head fields in order, and body) as the client's
/// response.
pub(crate) fn rendered_response(r: crate::engine::xchg::refuse::Rendered) -> Response {
    rendered_response_via(r, |rb| rb)
}

/// [`rendered_response`], with `more` head fields appended after the plane's.
pub(crate) fn rendered_response_via(
    r: crate::engine::xchg::refuse::Rendered,
    more: impl FnOnce(axum::http::response::Builder) -> axum::http::response::Builder,
) -> Response {
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut rb = Response::builder().status(status);
    // A relayed far-end answer's per-connection fields are this answer's to re-derive.
    let mut fields = r.fields;
    strip_answer_mechanics(&mut fields);
    for (name, value) in fields {
        rb = rb.header(name, value);
    }
    more(rb)
        .body(Body::from(r.body))
        .unwrap_or_else(|_| status.into_response())
}

/// The canonical kind for a cross-protocol non-2xx, the plane's reply table.
#[cfg(test)]
pub(crate) use crate::engine::xchg::reply::wire::cross_protocol_error_kind;

/// Shared finalizer for a cross-protocol NON-2xx upstream response, used by BOTH `forward_with_pool`
/// and `forward_once`: the plane's reply picks the kind and lifts the message
/// (`crate::engine::xchg::reply::wire::cross_protocol_error`), rendered here in the ingress
/// protocol's native error envelope. A crossed boundary NEVER relays verbatim.
#[cfg(test)]
pub(crate) fn shape_cross_protocol_error(
    ingress_protocol: &str,
    status: StatusCode,
    bytes: &[u8],
) -> Response {
    let (kind, msg) =
        crate::engine::xchg::reply::wire::cross_protocol_error(status.as_u16(), bytes);
    ingress_error(ingress_protocol, status, kind, &msg)
}

/// Remove the router-internal SHIM KEYS the route layer injects into the request body for PATH-MODEL
/// ingress protocols (`gemini`, `bedrock`), where the native wire carries the model in the URL and
/// stream intent in the path, not the body. Two keys, handled differently relative to `rewrite_model`
/// because their correct egress treatment differs:
///
///   - The gemini JSON-array key is NEVER a native egress body field for ANY backend (it only
///     influences RESPONSE framing), so it is stripped UNCONDITIONALLY on every branch and for every
///     egress.
///   - `stream` is a body field only for the BODY-MODEL protocols (openai/anthropic/cohere/responses),
///     where the egress writer authoritatively writes `"stream": <ir.stream>` and the backend reads it
///     to decide streaming. It is a PATH shim only for the PATH-MODEL egress protocols
///     (`gemini`/`bedrock`), whose native wire conveys stream intent via the URL/path, never the body.
///     So `stream` is stripped iff the EGRESS is gemini/bedrock — NOT based on the ingress. The old
///     ingress-gated strip deleted the writer-authored `"stream": true` on a gemini/bedrock-ingress →
///     body-model-egress streaming hop, so the backend saw no stream flag, answered non-streaming, and
///     the client got a wrong (buffered / mis-framed) response. Gating on egress keeps the writer's
///     authoritative `stream` for body-model backends and still strips it for path-model backends
///     (where the URL carries the intent and a body `stream` would be a router fingerprint).
///   - `model` is stripped ONLY on the same-protocol branch (by [`strip_same_protocol_model_shim`],
///     after `rewrite_model`), never cross-protocol: a body-model egress REQUIRES `model` and
///     `rewrite_model` installs the authoritative one.
///
/// The gemini array key is stripped for body-model ingress too (it is never native to any protocol).
///
/// Returns whether the body actually CHANGED (a key was present and removed). This is invalidation
/// set entries #1 (gemini JSON-array key) and #2 (`stream` for path-model egress) of the request
/// short-circuit safety contract: a `true` here makes a same-protocol request NON-pristine. A
/// same-proto request that carries NEITHER of these keys is left byte-for-byte untouched and can
/// short-circuit to its retained original bytes.
#[cfg(test)]
pub use busbar_plane_llm::codec::wire_shim::strip_router_shim_keys;

/// Remove the SHIM `model` key on the SAME-PROTOCOL gemini/bedrock passthrough path, AFTER
/// `rewrite_model` has run. On same-protocol gemini/bedrock the model rides the URL, not the body, so
/// a native Converse / generateContent backend must NOT see a body `model`; but the gemini writer's
/// `rewrite_model` re-inserts one, so this strip must run AFTER it to remove both the route layer's
/// shim and the re-inserted copy. NEVER call this on the cross-protocol branch: there the body-model
/// egress requires the `model` that `rewrite_model` installed. No-op for body-model ingress.
///
/// Thin wrapper: dispatches through `ProtocolWriter::has_model_in_url` so the per-protocol decision
/// (gemini/bedrock → strip; all others → keep) lives in the writer vtable, not in this agnostic
/// function. An unknown future url-model protocol only needs an override in its writer.
///
/// Returns whether the body actually CHANGED (a `model` key was present and removed). This is
/// invalidation set entry #4 of the request short-circuit safety contract: on a same-protocol
/// gemini/bedrock passthrough a body that carried `model` is made NON-pristine (the retained
/// original carries a `model` the native backend must not see). A same-proto path-model request that
/// arrived without a body `model` is left untouched and stays pristine.
#[cfg(test)]
pub(crate) use crate::engine::xchg::attempt::strip_same_protocol_model_shim;

/// The SINGLE source of truth for shaping an ingress request body into the bytes sent to one egress
/// lane. Both the hot path ([`forward_with_pool`], per failover hop) and the degraded last-resort
/// path ([`forward_once`], FallbackPool/LeastBad) call THIS function so the two cannot drift apart on
/// any translation step — historically they did (`ir.extra.clear()` was added to the hot path only,
/// and `forward_once` lacked it, leaking OpenAI `logprobs`/`top_logprobs`/`n` onto an Anthropic
/// or Gemini backend). Unifying the seam makes that whole class of "one path is missing a step"
/// regressions structurally impossible: there is now exactly one step list.
///
/// `body` is the per-hop parsed request `Value` (the caller owns deriving it fresh from the pristine
/// body so a failover hop never re-translates a previous hop's egress-shaped body). It is consumed
/// and the shaped egress bytes are returned. The full step list, in order:
///   1. CROSS-protocol only (`ingress_protocol != egress`): read_request → `IrReq::prepare_for_egress`
///      → `ir.extra.clear()` → egress `write_request`. Clearing `extra` at this single seam, before
///      any writer runs, is what stops every source-protocol-only passthrough key from leaking to a
///      foreign backend — no individual writer can miss it.
///   2. Strip the never-native router shim keys (gemini JSON-array key always; `stream` for path-model
///      EGRESS) on every branch.
///   3. `rewrite_model` installs the authoritative lane model.
///   4. SAME-protocol only: strip the body `model` shim (path-model gemini/bedrock carry the model in
///      the URL; a body `model` there is an indistinguishability leak).
///   5. Serialize to bytes.
///
/// The step list itself is the plane's (`xchg::attempt::translate_request`);
/// this adapter keeps the engine's side effects around it (the translation counter, the audit
/// record of each control the far end cannot represent) and renders a refusal in the caller's
/// envelope.
#[allow(clippy::too_many_arguments)]
pub(crate) fn translate_request_cross_protocol(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    ingress_protocol: &str,
    op: Op,
    body: Option<Value>,
    req_content_type: &str,
    reasoning_allowed: bool,
    hop_bytes: &Bytes,
    caller_key_id: &str,
) -> Result<Bytes, Box<Response>> {
    let lane = &EngineTables::new(rt).lanes()[i];
    let egress_name = lane.protocol;
    // The translation counter's event, counted when a JSON request is read for another dialect,
    // before the read can refuse (as it always was).
    if body.is_some() && ingress_protocol != egress_name {
        host.telemetry_translation(ingress_protocol, egress_name);
    }
    let far = crate::engine::xchg::shaping::FarShape {
        dialect: egress_name,
        wire_model: lane.wire_model(),
        default_max_tokens: lane.default_max_tokens,
        prompt_caching: lane.prompt_caching,
        caps: lane.lane_caps,
        path_base: lane.path_base.as_deref(),
    };
    let t = crate::engine::xchg::attempt::translate_request(
        ingress_protocol,
        op.operation,
        far,
        rt.global_default_max_tokens,
        rt.reasoning_budgets,
        reasoning_allowed,
        body,
        req_content_type,
        hop_bytes,
    );
    for control in t.dropped_controls {
        host.audit_record(
            "egress.control_unrepresentable",
            &format!("{control} on {egress_name}"),
            busbar_contract::vocab::OUTCOME_DEGRADED,
            caller_key_id,
        );
    }
    match t.outcome {
        Ok(translated) if translated.pristine => Ok(hop_bytes.clone()),
        Ok(translated) => Ok(Bytes::from(translated.bytes.into_owned())),
        Err(a) => Err(Box::new(answer_response(ingress_protocol, &a))),
    }
}

pub(crate) use busbar_kernel::proxy::max_upstream_buffered_bytes;

/// Upper bound on a buffered cross-protocol non-stream SUCCESS (2xx) body that must be parsed and
/// translated egress→IR→ingress. A real completion (large `max_tokens` output, big tool-call
/// arguments, embedded content) can far exceed the tight error-body cap; truncating it would make
/// `serde_json` parsing fail and the request would be reported to the client as a spurious 500 for
/// what was actually an upstream success (the caller may even have been token-charged). This cap is
/// COUPLED with the inbound request-body limit so any completion the gateway would accept inbound
/// can also be buffered for translation, while still bounding the per-response allocation. ONE knob
/// (`limits.request_body_max_bytes`) drives BOTH the inbound `DefaultBodyLimit` and this egress cap
/// (core's `limits::translate_body_max_bytes` returns the same value), so they can never diverge.
/// A function (not a `const`) so the installed value is read at each use site; falls back to the
/// historical 32 MiB default when the limits aren't installed (e.g. unit tests).
pub(crate) use busbar_plane_llm::codec::wire_shim::max_translated_body_bytes;

// THE CAPPED READ and its `ReadEnd` outcome moved DOWN into the neutral `busbar-substrate` crate in
// Phase-B B0-b (both core's proxy engine and the egress/auth paths read upstream bodies this way,
// and a plane crate names them without reaching into core). Re-exported here so every
// `crate::engine::{read_capped, ReadEnd}` call site — via `proxy/mod.rs`'s `pub(crate) use wire::*`
// — resolves unchanged.
pub use busbar_kernel::proxy::{read_capped, ReadEnd};

/// Read an upstream ERROR / verbatim-relay body under the tight [`max_upstream_buffered_bytes()`] cap
/// and the caller's wall-clock deadline. A truncated error body still classifies/relays correctly
/// (error envelopes are well under the cap, and a body that overruns it can only be
/// malformed/hostile), so the truncation flag is discarded. The deadline re-provides reqwest's
/// client-level total timeout on this read (a stalled hostile upstream could otherwise hold the
/// error-body read open forever); expiry yields an empty body — classification keys off the status,
/// and the message lift from the body is best-effort by contract.
pub(crate) async fn read_capped_body(
    r: http::Response<hyper::body::Incoming>,
    deadline: tokio::time::Instant,
) -> Bytes {
    use http_body_util::BodyExt;
    let read = read_capped(
        r.into_body().into_data_stream(),
        max_upstream_buffered_bytes(),
    );
    match tokio::time::timeout_at(deadline, read).await {
        Ok((bytes, _end)) => bytes,
        Err(_elapsed) => Bytes::new(),
    }
}

/// The client-fault kind by class and the far-end error message lift: the plane's reply reads.
#[cfg(test)]
pub(crate) use crate::engine::xchg::reply::wire::{client_fault_kind, extract_error_message};

/// Vendor-neutral, infrastructure-free detail used for EVERY client-facing mid-stream / pre-first-byte
/// transport-error frame. The raw `reqwest::Error` Display embeds hyper/reqwest/tokio internals and the
/// egress backend URL (hostname, region, port) — both a protocol-indistinguishability tell (no native
/// AI vendor emits hyper/reqwest strings) and an infrastructure-disclosure leak. The real cause is
/// logged server-side via `tracing`; only this static string ever reaches the client. Single source of
/// truth so a future edit cannot reintroduce `e.to_string()` at one site unnoticed.
///
/// The phrasing must also be VENDOR-PLAUSIBLE: the word "upstream" (and "proxy"/"gateway"/"backend"/
/// "lane") is itself busbar-internal reverse-proxy vocabulary that a native vendor SDK would never
/// emit in an error body or stream exception frame. A real Bedrock `ConverseStream` exception, an
/// SSE `error` event, or a Gemini `google.rpc.Status` element carries generic service phrasing, never
/// the word "upstream" — leaking it is a protocol-indistinguishability tell on the most-exercised
/// cross-protocol error path. Keep this generic and free of any intermediary/translation vocabulary.
pub(crate) use crate::engine::xchg::reply::wire::MID_STREAM_GENERIC_DETAIL;

/// Vendor-neutral fallback `error.message` for a NON-2xx response whose body carried no extractable
/// human message. Rendered into the CLIENT's native error envelope via `ingress_error`, so it must
/// read like copy a real single-vendor API would emit — NOT reverse-proxy vocabulary like "upstream".
/// The real status/cause is logged server-side; only this generic string reaches the client.
#[cfg(test)]
pub(crate) use crate::engine::xchg::reply::wire::GENERIC_REJECTED_DETAIL;

/// Client-visible fallback `detail` strings each repeated across several ingress-error sites —
/// hoisted so the copy cannot drift between them. Same vendor-neutral rules as
/// `GENERIC_REJECTED_DETAIL`: generic service phrasing, no proxy/translation vocabulary.
///
/// "Cannot drift" is a claim about the RENDERING sites, and it only holds while every one of them
/// reads from here. The exception is deliberate and is the golden tests: a test that compares the
/// rendered bytes against this const would agree with any edit to it, so the assertions that pin the
/// 1.5.5 wire copy spell the sentence out and are the thing that makes an edit here visible.
pub(crate) const DETAIL_INTERNAL_ERROR: &str =
    "We received an unexpected internal error. Please try again.";
pub(crate) const DETAIL_MODEL_UNSUPPORTED_OPERATION: &str =
    "This model does not support that operation.";
pub(crate) const DETAIL_ENDPOINT_UNSUPPORTED_OPERATION: &str =
    "This endpoint does not support that operation.";
pub(crate) const DETAIL_REQUEST_TIMEOUT: &str = "The request timed out. Please retry shortly.";

/// Vendor-neutral fallback detail for a cross-protocol response that could not be relayed (a body
/// transfer failure mid-read, an over-cap body, or an untranslatable shape). Rendered into the
/// client's native error envelope, so it must NOT disclose the existence of a translating
/// intermediary ("translate"/"untranslatable") or proxy vocabulary ("upstream"); a native vendor
/// returns a generic internal-error message here. The precise cause is logged server-side.
#[cfg(test)]
pub(crate) use crate::engine::xchg::reply::wire::GENERIC_RESPONSE_ERROR_DETAIL;

/// Build the bytes for a mid-stream error to send to the CLIENT, framed in the INGRESS protocol.
///
/// After the first byte has reached the client, failover is no longer possible, so an upstream
/// transport failure must terminate the stream with an in-band error in the client's own framing:
///   - Bedrock ingress (native AWS SDK, binary `application/vnd.amazon.eventstream`): a real
///     modeled-exception frame (`:message-type: exception`, `:exception-type: InternalServerException`)
///     with valid CRC32. Writing SSE `event:`/`data:` text into a binary eventstream body produces an
///     undecodable prelude/CRC for the SDK's decoder — the bug this guards against.
///   - SSE ingress (openai/anthropic/gemini/cohere/responses): the ingress writer's OWN streaming
///     error event (`write_response_event(&IrStreamEvent::Error(..))`), framed exactly as the
///     happy-path SSE framer does — bare `data:` for openai/cohere/gemini (no `event:` line, which
///     native streams of those protocols never emit), `event: error` for anthropic, and
///     `event: response.failed` for responses whose payload is the SDK-required
///     `{"response":{...,"error":{...}}}` STREAM shape (NOT the non-stream `{"error":...}` HTTP
///     envelope), so the official SDK's stream decoder finds `event.response` instead of crashing.
///
/// `translate` is the LIVE translator for this stream when there is one, so the failure event
/// continues the stream's identity. The frame is the plane's reply's.
#[cfg(test)]
pub(crate) use crate::engine::xchg::reply::wire::mid_stream_error_bytes;

/// Deterministic FNV-1a hash of a string — stable across processes/restarts (unlike the
/// std `DefaultHasher`, whose seed is randomized), so session affinity pins consistently.
pub(crate) fn stable_hash(s: &str) -> u64 {
    busbar_kernel::store::fnv1a_u64(s)
}

#[cfg(test)]
#[path = "tests/wire_tests.rs"]
mod tests;
