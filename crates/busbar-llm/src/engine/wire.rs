use super::*;
use busbar_core::handlers::TranslateCodec;

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
    match busbar_core::proto::decl_for(ingress_protocol)
        .and_then(|d| d.dialect())
        .and_then(|di| di.ingress_response_request_id(upstream_request_id))
    {
        Some((name, id)) => rb.header(name, id),
        None => rb,
    }
}

/// True when `ingress_protocol`'s writer signals that EVERY response — 2xx, streaming, and error —
/// must carry `x-amzn-RequestId` (and, on error paths, `x-amzn-errortype`). Dispatches through the
/// `ProtocolWriter::ingress_relays_amzn_headers()` vtable instead of branching on the provider name
/// `"bedrock"`, so the agnostic forward path never contains a hard-coded protocol string for this
/// decision. Unknown protocols fall back to `false` (no `x-amzn-*` headers emitted).
pub(crate) fn ingress_relays_amzn_headers(ingress_protocol: &str) -> bool {
    busbar_core::proto::decl_for(ingress_protocol)
        .map(|d| d.ingress_relays_amzn_headers)
        .unwrap_or(false)
}

/// The UPSTREAM response header NAMES this ingress protocol forwards VERBATIM on a same-protocol
/// passthrough — read from the upstream response and re-emitted on the client response (Bedrock's
/// `x-amzn-requestid` + `x-amzn-errortype`; Anthropic's `request-id`). Dispatched through the
/// `ProtocolWriter::ingress_relayed_response_header_names()` vtable so the agnostic forward path reads
/// and forwards these by NAME without naming any protocol module. Unknown protocols: `&[]`.
pub(crate) fn ingress_relayed_response_header_names(
    ingress_protocol: &str,
) -> &'static [&'static str] {
    busbar_core::proto::decl_for(ingress_protocol)
        .map(|d| d.ingress_relayed_response_header_names)
        .unwrap_or(&[])
}

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
// (`busbar_core::proxy::proxy_vocab`); the engine names them at their historical short paths through
// this re-export. `ingress_reject_response` (LLM-specific — it maps an `IngressReject`) delegates to
// the re-exported `ingress_error`.
pub(crate) use busbar_core::proxy::{agnostic_error_envelope, ingress_error};

/// Project an [`busbar_core::handlers::IngressReject`] into the caller-dialect error response
/// (`ingress_error`). The one place that decides what each reject arm renders as, so the two
/// `read_request`/`read_request_value` call sites (the opaque-body branch and the JSON branch)
/// cannot drift on shape: `BadRequest` is today's generic 400; `UnsupportedSubOp` is the second
/// 404 (`ImageIr.op` unsupported for `model`), distinct from the no-handler 404 and naming both the
/// operation and the model so the caller knows what to stop asking for.
pub(crate) fn ingress_reject_response(
    ingress_protocol: &str,
    reject: &busbar_core::handlers::IngressReject,
) -> Response {
    match reject {
        busbar_core::handlers::IngressReject::BadRequest(_) => ingress_error(
            ingress_protocol,
            StatusCode::BAD_REQUEST,
            KIND_INVALID_REQUEST,
            "We could not process the content of your request.",
        ),
        // NAMED WITH `Operation::name`, NOT WITH `{op:?}`. The Debug rendering of a core type is a
        // by-product of a derive, and this string is on the wire in front of a customer: before
        // 1.6.0 it read `Image`, which was the enum variant's identifier leaking out of the
        // process, and the moment the axis grew a field it would have read
        // `Verb { op: Invoke, name: "image" }`. `name()` is the identifier this project publishes
        // and pins — the same word the metric label and the `paths:` key use.
        busbar_core::handlers::IngressReject::UnsupportedSubOp { op, model } => ingress_error(
            ingress_protocol,
            StatusCode::NOT_FOUND,
            KIND_NOT_FOUND,
            &format!("{} is not supported for model \"{model}\".", op.name()),
        ),
    }
}

/// CANONICAL mapping from an upstream HTTP status to the protocol-agnostic error `kind`, for shaping
/// a CROSS-PROTOCOL non-2xx upstream response into the ingress protocol's native error envelope.
/// Shared by BOTH the main forward loop (`forward_with_pool`) and the degraded last-resort path
/// (`forward_once`) so they cannot drift on which kind a given status maps to (the bug this closes:
/// the degraded path labeled a 401/403 `invalid_request_error` while the main path correctly used
/// `authentication_error`/`permission_error`, an SDK-visible typed-exception mismatch and an
/// indistinguishability leak). The mapping mirrors the native discriminant a real vendor uses for
/// each status.
pub(crate) fn cross_protocol_error_kind(status: StatusCode) -> &'static str {
    if status == StatusCode::UNAUTHORIZED {
        KIND_AUTHENTICATION
    } else if status == StatusCode::FORBIDDEN {
        KIND_PERMISSION
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        KIND_RATE_LIMIT
    } else if status == StatusCode::SERVICE_UNAVAILABLE {
        // A genuine upstream 503 carries the unavailable/overloaded distinction — collapsing it into
        // `api_error` would emit, on a bedrock ingress, the status(503)/InternalServerException
        // pairing the real AWS runtime NEVER produces (503 pairs with ServiceUnavailableException).
        // Use `overloaded` — the SAME kind busbar already uses for its OWN 503s, mapping to
        // ServiceUnavailableException (bedrock) / UNAVAILABLE (gemini).
        KIND_OVERLOADED
    } else if status == StatusCode::GATEWAY_TIMEOUT {
        // 504 maps to the timeout class (bedrock ModelTimeoutException), not a generic server error.
        KIND_TIMEOUT
    } else if status.is_server_error() {
        KIND_API_ERROR
    } else {
        KIND_INVALID_REQUEST
    }
}

/// Shared finalizer for a cross-protocol NON-2xx upstream response, used by BOTH `forward_with_pool`
/// and `forward_once`. Lifts the upstream's human message where present, maps the status to the
/// canonical ingress `kind` (`cross_protocol_error_kind`), and reshapes into the ingress protocol's
/// native error envelope via `ingress_error`. Relaying the EGRESS provider's native error body to a
/// different-protocol client is a foreign-format leak the SDK cannot decode into its typed
/// exception — an immediate proxy tell — so a crossed boundary NEVER relays verbatim.
pub(crate) fn shape_cross_protocol_error(
    ingress_protocol: &str,
    status: StatusCode,
    bytes: &[u8],
) -> Response {
    let kind = cross_protocol_error_kind(status);
    let msg = extract_error_message(bytes).unwrap_or_else(|| GENERIC_REJECTED_DETAIL.to_string());
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
pub fn strip_router_shim_keys(v: &mut Value, egress_protocol: &str) -> bool {
    let mut changed = false;
    if let Some(obj) = v.as_object_mut() {
        // A protocol's array-stream shim key is never native to ANY backend wire → strip every
        // registered protocol's key unconditionally (also closes the leak where a body-model client
        // smuggles a key in its own controlled body). Iterating the cached registry set keeps this
        // strip from naming any shim-key literal (and from re-sweeping `protocol_for` per request).
        // `remove` returns the previous value iff the key was present → a real mutation (#1).
        for &key in busbar_core::proto::array_stream_shim_keys() {
            if obj.remove(key).is_some() {
                changed = true;
            }
        }
        // `stream` is a path-model shim for the EGRESS protocols gemini/bedrock (stream intent and
        // model both ride the URL there; `has_model_in_url()` covers both). For body-model egress
        // `stream` is the writer-authored field the backend needs to start streaming, so it must be
        // PRESERVED. Gate on egress, never ingress.
        if busbar_core::proto::decl_for(egress_protocol)
            .map(|d| d.has_model_in_url)
            .unwrap_or(false)
            && obj.remove("stream").is_some()
        {
            // #2: `stream` was present AND the egress is path-model → real mutation.
            changed = true;
        }
    }
    changed
}

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
pub(crate) fn strip_same_protocol_model_shim(v: &mut Value, ingress_protocol: &str) -> bool {
    let model_in_url = busbar_core::proto::decl_for(ingress_protocol)
        .map(|d| d.has_model_in_url)
        .unwrap_or(false);
    if model_in_url {
        if let Some(obj) = v.as_object_mut() {
            return obj.remove("model").is_some();
        }
    }
    false
}

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
/// Returns `Err(Response)` — an ingress-native error envelope with the right status — on the only two
/// shaping failures (unknown ingress protocol, request translation error) and on the effectively
/// infallible re-serialization, so neither caller can panic on the request path.
///
/// Project a [`busbar_core::handlers::TranslateReqReject`] — the codec entrypoint's terminal outcome — into
/// the caller-dialect error response. The ONE place that maps each reject arm to an HTTP shape, so the
/// opaque and JSON request branches cannot drift: a refused body renders `ingress_reject_response`
/// (its own 400/404 split); an egress that does not serve the operation is the 404
/// (`DETAIL_MODEL_UNSUPPORTED_OPERATION`); an unrepresentable request is a 400 carrying the reason.
fn map_translate_req_reject(
    ingress_protocol: &str,
    reject: busbar_core::handlers::TranslateReqReject,
) -> Response {
    match reject {
        busbar_core::handlers::TranslateReqReject::Ingress(reject) => {
            ingress_reject_response(ingress_protocol, &reject)
        }
        busbar_core::handlers::TranslateReqReject::EgressUnsupported => ingress_error(
            ingress_protocol,
            StatusCode::NOT_FOUND,
            KIND_NOT_FOUND,
            DETAIL_MODEL_UNSUPPORTED_OPERATION,
        ),
        busbar_core::handlers::TranslateReqReject::Unrepresentable(reason) => ingress_error(
            ingress_protocol,
            StatusCode::BAD_REQUEST,
            KIND_INVALID_REQUEST,
            &reason,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn translate_request_cross_protocol(
    app: &Arc<App>,
    i: usize,
    ingress_protocol: &str,
    op: busbar_core::handlers::Op,
    body: Option<Value>,
    req_content_type: &str,
    // The EFFECTIVE per-lane reasoning capability for this attempt (pool-member override wins over
    // the model flag) — computed by the caller because only it holds the candidate rows. Gates the
    // reasoning ask at `prepare_for_egress`; see `ModelCfg::reasoning`.
    reasoning_allowed: bool,
    // The PRISTINE source bytes `body` was parsed from THIS hop (the retained original). On a
    // same-protocol passthrough where no same-proto-reachable mutation fired (the request
    // short-circuit), these exact bytes are re-emitted verbatim instead of re-serializing
    // the `Value` — keeping the upstream payload byte-identical and skipping the serialize hot spot.
    // `&Bytes` (not `&[u8]`) so the short-circuit re-emit is a REFCOUNT BUMP (`Bytes::clone`), never
    // an O(body) `to_vec` memcpy — the return type is `Bytes` for the same reason.
    hop_bytes: &Bytes,
    // The resolved caller/governance key id (or `"anonymous"`) — the PRINCIPAL recorded on any
    // `egress.control_unrepresentable` audit event this translation emits (audit-and-allow: a dropped
    // caller control is a first-class, hash-chained event, not just a log warn).
    caller_key_id: &str,
) -> Result<Bytes, Box<Response>> {
    let egress_name = app.engine_tables().lanes()[i].protocol;
    // ONE declaration resolution for the four decl facts the prep bag reads below (this used to be
    // four separate registry scans of the same name).
    let egress_decl = busbar_core::proto::decl_for(egress_name);
    // The neutral cross-protocol egress-preparation param bag, built ONCE from RESOLVED lane
    // primitives and ONLY on a cross-protocol hop (`.then` is lazy, so a same-protocol passthrough
    // pays nothing). Shared by the opaque and JSON request branches below so the two cannot drift on
    // which lane facts gate `prepare_for_egress`, and the SINGLE site outside `ir/` that names
    // `EgressPrep` — `egress_prep.is_some()` is exactly "this hop is cross-protocol".
    let egress_prep =
        (ingress_protocol != egress_name).then(|| busbar_core::ir::egress_prep::EgressPrep {
            ingress_protocol,
            egress_requires_max_tokens: egress_decl.is_some_and(|d| d.requires_max_tokens),
            lane_default_max_tokens: app.engine_tables().lanes()[i].default_max_tokens,
            global_default_max_tokens: app.default_max_tokens,
            reasoning_allowed,
            reasoning_budgets: app.reasoning_effort_budgets,
            // The cache twin of `reasoning_allowed`: a lane whose dialect's cache marker is model-gated
            // (Bedrock) must assert `prompt_caching` to receive breakpoints.
            prompt_caching_allowed: app.engine_tables().lanes()[i].prompt_caching
                || !egress_decl.is_some_and(|d| d.cache_markers_model_gated),
            cache_control_cap: egress_decl.and_then(|d| d.max_cache_control_breakpoints),
            // thoughtSignature sentinel fill — the DIALECT declares whether it fills one
            // (`ProtocolDecl::fills_thought_signature`), ANDed with the LANE's URL shape: NEVER a
            // Vertex-style path-model lane (`path_base.is_some()`), which is not confirmed to honor the
            // sentinel bypass and has real reports of rejecting it.
            thought_signature_fill: egress_decl.is_some_and(|d| d.fills_thought_signature)
                && app.engine_tables().lanes()[i].path_base.is_none(),
        });
    // OPAQUE ingress body (multipart/binary — `None`): translate at the BYTE level through the
    // operation codecs (cross-protocol) or relay the pristine bytes verbatim (same-protocol) —
    // exactly the contract the JSON branch below implements at the Value level.
    let Some(mut body) = body else {
        if let Some(prep) = &egress_prep {
            let ingress_handler = busbar_core::handlers::request_handler(ingress_protocol)
                .and_then(|rh| rh.operation_handler(op.operation));
            let egress_handler = busbar_core::handlers::request_handler(egress_name)
                .and_then(|rh| rh.operation_handler(op.operation));
            let (Some(ih), Some(_eh)) = (ingress_handler, egress_handler) else {
                return Err(Box::new(ingress_error(
                    ingress_protocol,
                    StatusCode::NOT_FOUND,
                    KIND_NOT_FOUND,
                    DETAIL_MODEL_UNSUPPORTED_OPERATION,
                )));
            };
            // OPAQUE cross-protocol: read→prepare_for_egress→set_model→write through the single
            // translate entrypoint (byte codecs). Both codecs were 404-checked above, so the entrypoint
            // never surfaces `EgressUnsupported` here; a refused body still renders as its reject.
            let translated = ih
                .translate_request(
                    busbar_core::handlers::TranslateReqInput::Opaque {
                        bytes: hop_bytes,
                        content_type: req_content_type,
                    },
                    Some(egress_name),
                    prep,
                    app.engine_tables().lanes()[i].wire_model(),
                )
                .map_err(|e| Box::new(map_translate_req_reject(ingress_protocol, e)))?;
            return match translated.wire {
                busbar_core::handlers::EgressWire::Bytes(b) => Ok(b),
                // An opaque egress wire is always bytes; a JSON here is structurally impossible, but
                // serialize it rather than panic on the request path.
                busbar_core::handlers::EgressWire::Json(v) => {
                    Ok(Bytes::from(busbar_core::json::to_vec(&v).unwrap_or_default()))
                }
            };
        }
        // Same-protocol opaque relay: the retained bytes go upstream verbatim — refcount bump only.
        return Ok(hop_bytes.clone());
    };
    // Request short-circuit pristine-tracking. Starts true; flips false the moment ANY
    // same-protocol-reachable mutation actually changes the body. The cross-protocol branch below
    // always rebuilds the body from the IR (read_request → write_request), so it is never pristine.
    // The invalidation contract is EXACTLY entries #1-#4 of the invalidation set — strip_router_shim_keys
    // (#1,#2), rewrite_model_if_needed (#3), strip_same_protocol_model_shim (#4) — each of which now
    // reports whether it truly changed the body.
    let mut pristine = true;
    if let Some(prep) = &egress_prep {
        // one cross-protocol translation hop for this request (telemetry bank: per-thread cell,
        // fixed protocol×protocol slot table — no label allocation on the hop). `egress_prep.is_some()`
        // is exactly `ingress_protocol != egress_name`.
        busbar_core::telemetry::translation(ingress_protocol, egress_name);
        // Cross-protocol: translate the request body through the superset IR.
        let Some(ingress_dialect) =
            busbar_core::proto::decl_for(ingress_protocol).and_then(|d| d.dialect())
        else {
            return Err(Box::new(ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                DETAIL_INTERNAL_ERROR,
            )));
        };
        // Multi-candidate cross-protocol degrade (v1.5.4-restored). The busbar IR (`IrResponse`)
        // models exactly ONE assistant turn, so a cross-protocol hop's response reader keeps
        // candidate [0] and drops the rest. A same-protocol route never reaches here (it relays the
        // backend body verbatim), so an `n>1` / `candidateCount>1` request served same-protocol is
        // untouched and keeps returning all N. On a cross-protocol route we forward the request and
        // return the FIRST candidate at HTTP 200, exactly as v1.5.4 did, rather than rejecting with a
        // 400 (fail-loud is a deliberate opt-in for a future plane, not a 1.6.0 default). The
        // `ProtocolWriter::requested_candidate_count` detection machinery is retained for that future
        // opt-in; only the outcome here reverts to the silent 1-of-N degrade.
        let _ = ingress_dialect.requested_candidate_count(&body);
        // OPERATION-BLIND translate: the INGRESS operation handler parses its dialect into the
        // neutral IR; the IR applies its own cross-protocol semantics (`prepare_for_egress` — chat's
        // max-tokens default, tool-id decode, and the extra-key leak guard live INSIDE the IR,
        // not here); the EGRESS handler writes its dialect. The engine names no operation.
        // Codec roles resolve from PROTOCOL IDENTITY, not from the threaded handle: the ingress
        // dialect is (ingress_protocol, operation)'s handler; the egress dialect is the lane's.
        // (`op` supplies the operation tag + capabilities; its instance is registry-identical to
        // this lookup on every production path.)
        let ingress_handler = busbar_core::handlers::request_handler(ingress_protocol)
            .and_then(|rh| rh.operation_handler(op.operation));
        let egress_handler = busbar_core::handlers::request_handler(egress_name)
            .and_then(|rh| rh.operation_handler(op.operation));
        let Some(ingress_handler) = ingress_handler else {
            return Err(Box::new(ingress_error(
                ingress_protocol,
                StatusCode::NOT_FOUND,
                KIND_NOT_FOUND,
                DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
            )));
        };
        // OPERATION-BLIND translate through the single entrypoint: `ingress_handler` reads its dialect
        // into the neutral IR, the IR applies its own cross-protocol semantics (`prepare_for_egress`),
        // and the egress dialect writes. The representability guard + dropped-controls collection live
        // BEHIND the entrypoint; the seam keeps telemetry (above), the audit-and-allow emission, and
        // the error shaping (`map_translate_req_reject`) — none of which are the codec's business.
        let translated = match ingress_handler.translate_request(
            busbar_core::handlers::TranslateReqInput::Json(&body),
            egress_handler.map(|_| egress_name),
            prep,
            app.engine_tables().lanes()[i].wire_model(),
        ) {
            Ok(t) => t,
            Err(e) => return Err(Box::new(map_translate_req_reject(ingress_protocol, e))),
        };
        // AUDIT-AND-ALLOW: a caller control the egress dialect cannot natively represent is STILL
        // forwarded (behavior unchanged), but each drop is recorded as a first-class, hash-chained
        // audit event — not just the writer's `warn!` — so the degradation is visible in the audit
        // trail. Emitted before the body is consumed; forwarding proceeds.
        for control in translated.dropped_controls {
            busbar_core::admin::audit::AUDIT.record_by(
                "egress.control_unrepresentable",
                &format!("{control} on {egress_name}"),
                busbar_core::admin::audit::OUTCOME_DEGRADED,
                caller_key_id,
            );
        }
        match translated.wire {
            busbar_core::handlers::EgressWire::Json(written) => body = written,
            // The EGRESS wire is not JSON (multipart transcription): the IR carried the resolved model
            // in-band, and the JSON-only post-shaping below (shim strips, model rewrite) does not
            // apply — emit the handler's bytes directly.
            busbar_core::handlers::EgressWire::Bytes(b) => return Ok(b),
        }
        // The body was fully rebuilt from the IR (read_request → write_request), so it bears no fixed
        // relationship to `hop_bytes` — a cross-protocol hop is NEVER pristine and must serialize the
        // rewritten `Value`, never short-circuit to the original bytes.
        pristine = false;
    }
    // Remove the never-native shim keys (gemini JSON-array key on every protocol; `stream` for
    // path-model EGRESS) on EVERY branch — same- AND cross-protocol. `model` is handled below,
    // ordered relative to `rewrite_model`. Each helper reports whether it ACTUALLY changed the body;
    // any true makes a same-protocol hop non-pristine (`&` accumulates into `pristine`). This is the
    // structural coupling: a future same-proto-reachable mutation added to these helpers automatically
    // invalidates the short-circuit (it cannot be silently missed).
    pristine &= !strip_router_shim_keys(&mut body, egress_name); // invalidators #1, #2
                                                                 // `rewrite_model_if_needed` installs the authoritative lane model. ORDERING (critical): on a
                                                                 // cross-protocol hop to a BODY-MODEL egress (gemini/bedrock → openai/anthropic/cohere/responses)
                                                                 // the backend REQUIRES this `model` body field, so `model` is stripped ONLY on the same-protocol
                                                                 // passthrough (below), where the model rides the URL and a body `model` is an indistinguishability
                                                                 // leak. Reports a change only when the written model differs from the body's existing one (#3).
                                                                 // Resolve the lane's DialectCodec ONCE and reuse it for BOTH the model rewrite (#3) and the
                                                                 // path-base reshape below. `decl_for(..).dialect()` allocates a fresh `Box<dyn DialectCodec>` per
                                                                 // call, so resolving it twice on the request hot path was a redundant allocation. Behavior/output
                                                                 // are identical: same dialect, same two mutations, same order.
    let lane_dialect =
        busbar_core::proto::decl_for(app.engine_tables().lanes()[i].protocol).and_then(|d| d.dialect());
    pristine &= !lane_dialect
        .as_ref()
        .map(|dc| {
            dc.rewrite_model_if_needed(&mut body, app.engine_tables().lanes()[i].wire_model())
        })
        .unwrap_or(false); // invalidator #3
                           // PATH-BASE BODY RESHAPE. A lane with a `path_base` carries the model in the URL, and some
                           // dialects must reshape the body for that form (Claude-on-Vertex drops `model` and adds
                           // `anthropic_version`). WHICH reshape, and whether there is one at all, is the writer's;
                           // this path only knows the lane's URL shape. A reshape necessarily mutates the body, so such
                           // a same-protocol passthrough is (correctly) no longer pristine.
    if app.engine_tables().lanes()[i].path_base.is_some()
        && lane_dialect
            .as_ref()
            .map(|dc| dc.reshape_for_path_base(&mut body))
            .unwrap_or(false)
    {
        pristine = false;
    }
    if ingress_protocol == egress_name {
        pristine &= !strip_same_protocol_model_shim(&mut body, ingress_protocol);
        // invalidator #4
    }
    // Request SHORT-CIRCUIT: a same-protocol passthrough that triggered none of the
    // invalidators #1-#4 left `body` byte-for-byte equivalent to the retained `hop_bytes`, so re-emit
    // those exact bytes verbatim — byte-identical to the old re-serialize path, minus the serialize
    // cost (and minus any key-ordering / float-formatting drift a round-trip could introduce). Cross-
    // protocol hops set `pristine = false` above and always fall through to the serialize arm.
    // `Bytes::clone` is a refcount bump — the pristine passthrough copies ZERO body bytes.
    if ingress_protocol == egress_name && pristine {
        return Ok(hop_bytes.clone());
    }
    // sonic-rs: SIMD serialize of the (large, string-heavy) upstream body — the request-path hot spot.
    match busbar_core::json::to_vec(&body) {
        Ok(p) => Ok(Bytes::from(p)),
        // Re-serializing a Value parsed from valid JSON and rewritten only with serde_json values is
        // effectively infallible; return a shaped 500 rather than panic a worker on the request path
        // (the layer's no-unwrap/expect rule).
        Err(_) => Err(Box::new(ingress_error(
            ingress_protocol,
            StatusCode::INTERNAL_SERVER_ERROR,
            KIND_API_ERROR,
            DETAIL_INTERNAL_ERROR,
        ))),
    }
}

// The TIGHT upstream-error-body buffer cap (`max_upstream_buffered_bytes`) is NEUTRAL vocabulary that
// STAYS in core (`busbar_core::proxy::proxy_vocab`); the engine names it at its historical short path
// through this re-export. (`max_translated_body_bytes` below is the SEPARATE, wider translate cap and
// stays here.)
pub(crate) use busbar_core::proxy::max_upstream_buffered_bytes;

/// Upper bound on a buffered cross-protocol non-stream SUCCESS (2xx) body that must be parsed and
/// translated egress→IR→ingress. A real completion (large `max_tokens` output, big tool-call
/// arguments, embedded content) can far exceed the tight error-body cap; truncating it would make
/// `serde_json` parsing fail and the request would be reported to the client as a spurious 500 for
/// what was actually an upstream success (the caller may even have been token-charged). This cap is
/// COUPLED with the inbound request-body limit so any completion the gateway would accept inbound
/// can also be buffered for translation, while still bounding the per-response allocation. ONE knob
/// (`limits.request_body_max_bytes`) drives BOTH the inbound `DefaultBodyLimit` and this egress cap
/// (`busbar_core::limits::translate_body_max_bytes` returns the same value), so they can never diverge.
/// A function (not a `const`) so the installed value is read at each use site; falls back to the
/// historical 32 MiB default when the limits aren't installed (e.g. unit tests).
pub(crate) fn max_translated_body_bytes() -> usize {
    busbar_core::limits::translate_body_max_bytes()
}

// THE CAPPED READ and its `ReadEnd` outcome moved DOWN into the neutral `busbar-substrate` crate in
// Phase-B B0-b (both core's proxy engine and the egress/auth paths read upstream bodies this way,
// and a plane crate names them without reaching into core). Re-exported here so every
// `crate::engine::{read_capped, ReadEnd}` call site — via `proxy/mod.rs`'s `pub(crate) use wire::*`
// — resolves unchanged.
pub use busbar_substrate::proxy::{read_capped, ReadEnd};

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

/// Map the classified `StatusClass` of a CLIENT-fault upstream 4xx to a protocol-agnostic error
/// `kind` for `ingress_error` (the per-protocol writer maps it to its native error type/category).
/// Exhaustive over `StatusClass` — no `_` wildcard (the no-catch-all rule for disposition matches).
pub(crate) fn client_fault_kind(class: StatusClass) -> &'static str {
    match class {
        StatusClass::ContextLength => PROVIDER_CODE_CONTEXT_LENGTH,
        StatusClass::ClientError => KIND_INVALID_REQUEST,
        // The other classes are not reached on the ClientFault arm (they classify as
        // TransientUpstream / HardDown / ContextLength), but the match must be exhaustive; treat
        // them as a generic invalid-request shape rather than panicking on the request path.
        StatusClass::RateLimit
        | StatusClass::Overloaded
        | StatusClass::ServerError
        | StatusClass::Timeout
        | StatusClass::Network
        | StatusClass::Auth
        | StatusClass::Billing => KIND_INVALID_REQUEST,
    }
}

/// Best-effort human-readable message from an upstream error body, across the vendor error shapes
/// (`error.message`, top-level `message`, Gemini `error.message`). Returns `None` when the body is
/// not JSON or carries no recognizable message field, so the caller substitutes a generic detail
/// rather than leaking the raw foreign body.
pub(crate) fn extract_error_message(bytes: &[u8]) -> Option<String> {
    let v: Value = busbar_core::json::parse(bytes).ok()?;
    v.get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .or_else(|| v.get("message").and_then(|m| m.as_str()))
        .map(|s| s.to_string())
}

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
pub(crate) const MID_STREAM_GENERIC_DETAIL: &str = busbar_core::proto::STREAM_ABORT_DETAIL;

/// Vendor-neutral fallback `error.message` for a NON-2xx response whose body carried no extractable
/// human message. Rendered into the CLIENT's native error envelope via `ingress_error`, so it must
/// read like copy a real single-vendor API would emit — NOT reverse-proxy vocabulary like "upstream".
/// The real status/cause is logged server-side; only this generic string reaches the client.
pub(crate) const GENERIC_REJECTED_DETAIL: &str = "The request could not be processed.";

/// Client-visible fallback `detail` strings each repeated across several ingress-error sites —
/// hoisted so the copy cannot drift between them. Same vendor-neutral rules as
/// `GENERIC_REJECTED_DETAIL`: generic service phrasing, no proxy/translation vocabulary.
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
pub(crate) const GENERIC_RESPONSE_ERROR_DETAIL: &str =
    "An internal error occurred while processing the response.";

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
pub(crate) fn mid_stream_error_bytes(
    ingress_protocol: &str,
    ingress_eventstream: bool,
    message: &str,
) -> Vec<u8> {
    // The error is a mid-stream transport failure ≈ internal/5xx. Resolve the ingress protocol
    // ONCE. An unknown ingress resolves to no writer at all and takes the dialect-free terminal
    // frame at the bottom of this function — the same ruling `ingress_error` makes, for the same
    // reason: every LLM dialect is a droppable plugin now, so there is no resident writer to borrow
    // a shape from, and inventing one would put a foreign dialect's bytes on the wire.
    let err = busbar_core::proto::IrError {
        class: busbar_core::breaker::StatusClass::ServerError,
        provider_signal: Some(message.to_string()),
        retry_after: None,
    };
    let Some(dialect) = busbar_core::proto::decl_for(ingress_protocol).and_then(|d| d.dialect()) else {
        return agnostic_stream_error_frame(message);
    };
    if ingress_eventstream {
        // Binary eventstream client (a native AWS SDK): a mid-stream failure is a MODELED-EXCEPTION
        // frame, not an SSE event. The exception NAME comes from the ingress writer's vtable
        // (`write_response_exception`) — so proxy engine names no protocol's wire shape;
        // `encode_exception_frame` is the generic binary framer. A protocol that reports
        // `ingress_is_eventstream` but declines an exception mapping (a contradiction) falls through.
        if let Some((exc_name, msg)) = dialect.write_response_exception(&err) {
            return busbar_core::eventstream::encode_exception_frame(&exc_name, &msg);
        }
    }
    // SSE client: build the terminal error frame through the ingress protocol writer's STREAMING
    // error seam (`write_error_frame`), NOT the non-stream `write_error()` HTTP envelope. The two are
    // genuinely different shapes for some protocols and a native SDK decodes the STREAM event, not the
    // HTTP body:
    //   - Responses: the stream `response.failed` event wraps the error in a `response` object
    //     (`{"response":{...,"error":{...}}}`); the HTTP envelope is a top-level `{"error":...}` the
    //     SDK's stream decoder cannot locate via `event.response` (it would crash / silently swallow).
    //   - Anthropic: the stream `error` event is `{"type":"error","error":{...}}` (no HTTP-only
    //     `request_id`); the writer's event arm produces exactly that.
    //   - OpenAI/Cohere/Gemini: bare `data:` frame in each protocol's native in-band error shape.
    // `write_error_frame` is the NEUTRAL seam: it returns `(event_type, data)` without core naming any
    // concrete stream-event type, and we frame it identically to the happy-path SSE framer
    // (`proto::reframe_sse`): a non-empty `event_type` becomes an `event:` line, an empty one is a
    // bare `data:` frame. This guarantees the mid-stream error is byte-for-byte the same framing the
    // ingress protocol uses for every other event. The error carries `StatusClass::ServerError`
    // (mid-stream transport failure ≈ internal/5xx) with the human detail as `provider_signal`, which
    // each writer maps to its native error `type`/`message`.
    //
    // Every SSE-framed writer (openai/anthropic/gemini/cohere/responses) returns `Some`; the `None`
    // fallback only guards a hypothetical future writer that declines to frame errors in-band, in
    // which case we still emit a decodable bare `data:` error.
    match dialect.write_error_frame(&err) {
        Some((event_type, data)) => {
            let data = busbar_core::json::to_string(&data).unwrap_or_else(|_| {
                serde_json::json!({ "error": { "message": message, "type": KIND_API_ERROR } })
                    .to_string()
            });
            if event_type.is_empty() {
                format!("data: {data}\n\n").into_bytes()
            } else {
                format!("event: {event_type}\ndata: {data}\n\n").into_bytes()
            }
        }
        None => agnostic_stream_error_frame(message),
    }
}

/// CORE'S OWN TERMINAL STREAM ERROR FRAME — the streaming sibling of [`agnostic_error_envelope`],
/// for the two cases with no ingress writer to ask: an ingress name that resolves to no protocol,
/// and a writer that declines to frame errors in-band. A bare `data:` SSE frame is the lowest
/// common denominator every SSE decoder accepts, and it is core's to emit precisely because no LLM
/// dialect is guaranteed linked into the binary any more.
fn agnostic_stream_error_frame(message: &str) -> Vec<u8> {
    let data = agnostic_error_envelope(KIND_API_ERROR, message).to_string();
    format!("data: {data}\n\n").into_bytes()
}

/// Deterministic FNV-1a hash of a string — stable across processes/restarts (unlike the
/// std `DefaultHasher`, whose seed is randomized), so session affinity pins consistently.
pub(crate) fn stable_hash(s: &str) -> u64 {
    busbar_core::store::fnv1a_u64(s)
}

#[cfg(test)]
#[path = "proxy_tests/wire_tests.rs"]
mod tests;
