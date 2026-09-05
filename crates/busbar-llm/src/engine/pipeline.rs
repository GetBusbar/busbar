use super::*;
// The tracing seam: the ONE named level constant every hot-path `#[tracing::instrument]`
// in this file references, so a `#[tracing::instrument(level = "debug")]` hand-picked literal never
// re-forks the policy. `tracing::instrument`'s `level = <path>` form rejects a leading `crate`
// keyword segment (it parses a bare `Ident`/`Path`, and `crate` is not one), so the constant is
// imported here and referenced unqualified at each instrument site instead.
use busbar_substrate::observability::HOTPATH_LEVEL;
// The single neutral translate entrypoint (G6 step 4): the non-stream cross-protocol response arm
// routes its read→prepare_for_ingress→write core through `TranslateCodec::translate_response`.
use busbar_substrate::diagnostics::{
    DECISION_GATE_REJECTED, DECISION_GATE_RESTRICT_REJECT, DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE,
    REWRITE_BODY_MATERIALIZE_FAILED, REWRITE_GATE_REJECTED, REWRITE_RESERIALIZE_FAILED,
    ROUTING_POLICY_REJECTED, ROUTING_POLICY_RESTRICT_REJECT,
    ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
};
use busbar_substrate::{diag_debug, diag_error};

/// Forward with pool name context for on_exhausted config lookup.
/// Thin wrapper: parse the body ONCE for callers that only hold bytes (tests, ad-hoc routes), then
/// delegate. The ingress hot path (`ingress::forward_resolved`) instead calls
/// [`forward_with_pool_parsed`] directly with the `Value` it ALREADY parsed to resolve the model —
/// so a normal request parses the body once across the route+forward layers, not twice.
///
/// Carries NO pre-resolved governance key — a virtual-key caller still resolves via the token
/// `lookup` inside `decide_policy_order`. Real ingress routes that hold a `GovCtx` (whose key may be
/// a SYNTHESIZED group/SSO principal key the token can't resolve to) must call
/// [`forward_with_pool_keyed`] and pass `gov.key.as_ref()` so the routing-signal path is not blind.
///
/// Test-only convenience now: every production ingress route holds a `GovCtx` and goes through
/// [`forward_with_pool_keyed`]; this bytes-only, key-less form survives solely for the many tests
/// that construct a request from raw bytes.
// App-retype WEDGE 3 (THE FLIP): the two bytes-in, key-less/keyed TEST-ONLY convenience entries live
// in a `#[cfg(test)] mod` and take the built test App GENERICALLY, through the neutral built-app seam
// (`busbar_substrate::testkit::BuiltAppSeam`, which core implements for its `App`) — so the ~81 test
// call sites are unchanged and nothing here names a core type. Each mints the neutral `host`/`rt` the
// production forward path threads (one `engine_host` Arc + the alloc-free `native_runtime_arc` slot
// read) and delegates to the production `forward_with_pool_parsed`. Production ingress never routes
// through here (it holds a host already and calls `forward_with_pool_parsed` directly), so nothing
// ships this mint.
#[cfg(test)]
pub(crate) use test_forward_entry::{forward_with_pool, forward_with_pool_keyed};

#[cfg(test)]
mod test_forward_entry {
    use super::*;

    use busbar_substrate::testkit::BuiltAppSeam;

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn forward_with_pool<A: BuiltAppSeam + ?Sized>(
        app: &Arc<A>,
        cands: Vec<WeightedLane>,
        body: Bytes,
        caller_token: Option<&str>,
        pool_name: &str,
        affinity_key: Option<&str>,
        ingress_protocol: &str,
        op: busbar_substrate::handlers::Op,
        usage_sink: Option<UsageSink>,
    ) -> Response {
        forward_with_pool_keyed(
            app,
            cands,
            body,
            caller_token,
            None,
            pool_name,
            affinity_key,
            ingress_protocol,
            op,
            usage_sink,
            // No inbound `HeaderMap` on this bytes-only test entry ⇒ nothing to forward. The
            // production ingress path collects the allowlist from the real client headers.
            Vec::new(),
        )
        .await
    }

    /// [`forward_with_pool`] plus the caller's pre-resolved governance key (`GovCtx.key`), so a
    /// GROUP/SSO principal still projects `rate_headroom` / `identity` into a pool's routing policy.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn forward_with_pool_keyed<A: BuiltAppSeam + ?Sized>(
        app: &Arc<A>,
        cands: Vec<WeightedLane>,
        body: Bytes,
        caller_token: Option<&str>,
        resolved_gov_key: Option<&std::sync::Arc<busbar_api::VirtualKey>>,
        pool_name: &str,
        affinity_key: Option<&str>,
        ingress_protocol: &str,
        op: busbar_substrate::handlers::Op,
        usage_sink: Option<UsageSink>,
        // The allowlisted client beta/version headers to forward (opt-in). A test entry that exercises
        // the forwarding path passes a collected set; every other test passes an empty Vec.
        client_fwd: Vec<(axum::http::HeaderName, axum::http::HeaderValue)>,
    ) -> Response {
        // Mint the neutral host/rt the production path threads (see the module note).
        let host = busbar_substrate::testkit::engine_host(app);
        let rt = crate::engine::native_runtime_arc(host.as_ref());
        // Validate + head-project WITHOUT building a DOM (same malformed-body 400 contract as the
        // production entry — identical `LazyBody::parse` guard + parser).
        let v: LazyBody = match LazyBody::parse(&body) {
            Ok(v) => v,
            Err(_) => {
                tracing::debug!(detail = %busbar_substrate::json::parse_err_log(body.len()), "request body JSON parse failed");
                return ingress_error(
                    ingress_protocol,
                    StatusCode::BAD_REQUEST,
                    KIND_INVALID_REQUEST,
                    "We could not parse the JSON body of your request.",
                );
            }
        };
        forward_with_pool_parsed(
            &host,
            &rt,
            cands,
            body,
            Some(v),
            APPLICATION_JSON,
            caller_token,
            resolved_gov_key,
            pool_name,
            affinity_key,
            ingress_protocol,
            op,
            usage_sink,
            client_fwd,
        )
        .await
    }
}

/// The forward implementation. `v` is the request body ALREADY parsed by the caller (the ingress
/// layer parses it to resolve the model; tests/ad-hoc go through [`forward_with_pool`] which parses).
/// The retained `body` bytes are re-parsed only on failover hops 2+, preserving the per-hop pristine
/// re-parse the mixed-protocol-pool correctness depends on.
//
// Plumbing function: each parameter is an independent request input (state, candidates, body, parsed
// body, caller token, pool name, affinity key, ingress protocol, usage sink) with no natural grouping.
#[allow(clippy::too_many_arguments)]
// THE "forward" SPAN, HAND-ROLLED (wave-8a future-shrink): this is a plain fn returning an
// `.instrument(span)`-wrapped async block rather than `#[tracing::instrument]` on an async fn.
// Behavior is identical — same span name/level/fields, created before the first poll, entered on
// every poll — but the macro's expansion nests an async move block INSIDE the async fn, storing
// every parameter TWICE in the coroutine (once as the outer async fn's slots, once as the inner
// block's captures): a measured +376 bytes of per-request state-machine memcpy on the hot path.
// Here the parameters move into the async block exactly once.
//
// `HOTPATH_LEVEL` (the tracing seam): at the default info filter this span is DISABLED at the
// callsite (one relaxed atomic check) instead of allocating a span + formatting three fields on
// every request. The info-level events on the rejection paths carry their own pool/policy fields,
// so no info-level log line loses context; run with `RUST_LOG=busbar=debug` to get the span back.
// Routed through the named constant (not a hand-picked `"debug"` literal) so the hot-path level is
// set in exactly one place — see `observability::HOTPATH_LEVEL`'s doc for why it is DEBUG and not
// the `TRACE` variant.
// `request_id`: declared `Empty` here (no value at span-open time — the id isn't stamped until the
// async block runs, see the `Span::current().record` call below) and filled in as a native `u64`
// field, NEVER `format!`'d into a string: `tracing`'s field-recording writes the integer straight
// into the span, so tagging every event this span covers (including the debug-disabled default —
// the record call is a no-op there, the same one-relaxed-atomic-check cost) costs no per-request
// allocation.
pub(crate) fn forward_with_pool_parsed<'a>(
    host: &'a Arc<dyn EngineHost>,
    rt: &'a Arc<NativeRuntime>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    mut v: Option<LazyBody>,
    req_content_type: &'a str,
    caller_token: Option<&'a str>,
    resolved_gov_key: Option<&'a std::sync::Arc<busbar_api::VirtualKey>>,
    pool_name: &'a str,
    affinity_key: Option<&'a str>,
    ingress_protocol: &'a str,
    op: busbar_substrate::handlers::Op,
    usage_sink: Option<UsageSink>,
    // The allowlisted client beta/version headers the caller ACTUALLY SENT (captured at ingress by the
    // neutral `busbar_substrate::proxy::collect_client_headers`), threaded to the egress assembly sites
    // where they are forwarded scoped to the matching egress dialect. Empty ⇒ byte-identical egress.
    client_fwd: Vec<(axum::http::HeaderName, axum::http::HeaderValue)>,
) -> impl std::future::Future<Output = Response> + 'a {
    use tracing::Instrument;
    let span = tracing::span!(
        HOTPATH_LEVEL,
        "forward",
        pool = %pool_name,
        ingress = %ingress_protocol,
        op = op.name(),
        transport = op.transport().name(),
        request_id = tracing::field::Empty
    );
    async move {
        // The per-request correlation id (settled design: a single `u64` off a boot-seeded monotonic
        // atomic — see `App::next_request_id`/`state::seed_request_id_counter` — never a UUID/String).
        // Stamped ONCE here, the earliest per-request point (before `RequestCtx` is even built), and
        // threaded into `forward_with_pool_parsed_inner` (which stores it on `RequestCtx::request_id`
        // for the whole failover walk) AND kept as this plain local so the COMPLETION tap fired below —
        // after `inner` has returned and `RequestCtx` has gone out of scope — stamps the SAME value. That
        // identity (pre-forward routing message vs. post-response tap) is the whole join-key contract.
        let _wrap = busbar_substrate::profile::start(busbar_substrate::profile::Stage::WrapSetup);
        let request_id = host.next_request_id();
        // Tag every event this span covers with the correlation id — a native `u64` `record`, not a
        // `format!`, so this costs nothing beyond what the (already debug-gated) span pays. A no-op at
        // the default info filter: `record` on a disabled span is the same single relaxed check
        // `#[tracing::instrument(level = "debug")]` already costs on the hot path.
        tracing::Span::current().record("request_id", request_id);
        // ── STAGE TAPS: response ── capture the shape BEFORE `v` moves into the dispatch core, fire
        // AFTER the response head is known. `outcome`: a gate-produced rejection (marker extension) is
        // the SYNTHETIC `rejected_by_gate`; else 2xx = `ok`, anything else = `failed`. For a STREAMING
        // response this fires at response-HEAD time (status known, body still flowing) — stream-tail
        // outcomes are a later increment. ZERO COST when no response tap is configured.
        let completion_shape = if host.tap_hooks_response().is_empty() {
            None
        } else {
            // `stream` is a captured head key — read it via `probe` (no DOM needed); the SHAPE capture
            // reads arbitrary body fields, so materialize the DOM (taps are configured — the DOM was
            // going to be built for the request stages anyway).
            let stream = v
                .as_ref()
                .and_then(|b| b.probe().get("stream"))
                .and_then(|s| s.as_bool())
                .unwrap_or(false);
            let dom: Option<&Value> = match v.as_mut() {
                Some(l) => l.ensure_dom().ok().map(|m| &*m),
                None => None,
            };
            Some(capture_stage_shape(
                dom,
                &body,
                req_content_type,
                pool_name,
                ingress_protocol,
                Some(op.operation),
                stream,
                request_id,
            ))
        };
        drop(_wrap);
        let resp = forward_with_pool_parsed_inner(
            host,
            rt,
            cands,
            body,
            v,
            req_content_type,
            caller_token,
            resolved_gov_key,
            pool_name,
            affinity_key,
            ingress_protocol,
            op,
            usage_sink,
            request_id,
            client_fwd,
        )
        .await;
        if let Some(shape) = completion_shape {
            let outcome = if resp.extensions().get::<GateRejected>().is_some() {
                "rejected_by_gate"
            } else if resp.status().is_success() {
                "ok"
            } else {
                "failed"
            };
            fire_stage_taps(
                host.tap_hooks_response(),
                &shape,
                busbar_substrate::hooks::wire::HookStageProjection {
                    at: "response",
                    model: None,
                    attempt_number: None,
                    remaining_candidates: None,
                    previous_failure: None,
                    outcome: Some(outcome),
                    status: Some(resp.status().as_u16()),
                },
                resolved_gov_key.and_then(|k| k.group.as_deref()),
                &**host,
            );
        }
        resp
    }
    .instrument(span)
}

/// The dispatch core behind [`forward_with_pool_parsed`] (the thin wrapper exists only to fire the
/// response-stage taps around the whole request).
//
// Plumbing function: same parameter set as the public wrapper.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward_with_pool_parsed_inner(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    cands: Vec<WeightedLane>,
    mut body: Bytes,
    // The request body VALIDATED once by the caller for JSON-body operations, carried as a
    // `LazyBody` (head projection + on-demand DOM); `None` for an OPAQUE ingress body (multipart
    // transcription, binary) — those relay/translate at the BYTE level via the operation codecs and
    // skip every JSON-only read below. The top-level point reads below (`stream`, affinity `system`,
    // shim keys) go through the head `probe`; the full DOM is materialized ONLY when a consumer
    // needs the tree (rewrite hooks, taps, gates/policies, cross-protocol translation, failover).
    // `mut` so the global rewrite pass can materialize + mutate it before dispatch.
    mut v: Option<LazyBody>,
    // The ingress request Content-Type — the byte-level codec's parse hint (multipart boundary).
    req_content_type: &str,
    caller_token: Option<&str>,
    // The key the auth layer already resolved/synthesized for this caller (`GovCtx.key`) — used as
    // the routing-signal source when the token is not a virtual-key secret (group/SSO principals).
    resolved_gov_key: Option<&std::sync::Arc<busbar_api::VirtualKey>>,
    pool_name: &str,
    affinity_key: Option<&str>,
    ingress_protocol: &str,
    // A request's identity is (operation, protocol): `ingress_protocol` is the wire language,
    // `op` is the kind of work. Everything below is the engine carrying that pair through pool
    // selection, failover, the breaker, and billing. The engine reads only capabilities off the
    // spec, never its identity; core's `handlers::CHAT` reproduces today's behavior byte-for-byte.
    op: busbar_substrate::handlers::Op,
    // `mut`: borrowed by each attempt, consumed only by the one that delivers a body.
    mut usage_sink: Option<UsageSink>,
    // This request's correlation id, stamped ONCE by the wrapper (`forward_with_pool_parsed`)
    // before this fn was called — carried as a plain `Copy` scalar for the whole dispatch (stored on
    // `RequestCtx::request_id` below, and threaded into every hook projection built in here) rather
    // than re-derived per hop.
    request_id: u64,
    // The allowlisted client beta/version headers the caller ACTUALLY SENT, captured at ingress by the
    // neutral `busbar_substrate::proxy::collect_client_headers` against the plane's
    // `forwardable_client_header_names()` set. Stored on `RequestCtx` below so BOTH the hot path here
    // and the degraded exhaustion paths read the same set for the whole failover walk. Empty ⇒
    // nothing forwarded (byte-identical egress).
    client_fwd: Vec<(axum::http::HeaderName, axum::http::HeaderValue)>,
) -> Response {
    // Stage profiler: PREPARE spans all pre-dispatch bookkeeping (op-support filter, wants_stream +
    // affinity derivation, failover/breaker config) up to the failover loop. Zero cost when
    // `BUSBAR_PROFILE` is unset — `start` returns `None` and takes no `Instant`.
    let _prep = busbar_substrate::profile::start(busbar_substrate::profile::Stage::Prepare);
    // App-retype WEDGE 3: the failover loop's telemetry emits (upstream-attempt/failure, failover) and
    // every other host reach drive through the `host: &Arc<dyn EngineHost>` threaded in — no per-call
    // `engine_host_value` mint. The borrow is the stable payload Arc, so its borrowed returns outlive
    // the await loop.
    // EGRESS deletion switch: every candidate
    // lane's protocol must HOLD this operation's handler. A protocol whose handler was deleted is
    // not a valid egress for the operation — a clean no-handler 404 in the CALLER's dialect, never a
    // silent dispatch. Dormant while all six protocols serve chat; load-bearing the moment one is
    // removed (the deletion test).
    let mut cands: Vec<WeightedLane> = {
        let supports = |wl: &WeightedLane| {
            busbar_substrate::handlers::request_handler(
                EngineTables::new(rt).lanes()[wl.idx].protocol,
            )
            .and_then(|rh| rh.operation_handler(op.operation))
            .is_some()
        };
        // Fast path (the norm: every registered protocol serves every 1.x operation): all candidates
        // support the operation, so keep the caller's Vec as-is — no partition, no re-allocation.
        // Only when at least one lane lacks the handler do we pay the filter; semantics identical to
        // the previous `partition` (an all-dropped non-empty set is the same no-handler 404, and an
        // initially-empty set passes through to the pool-empty 503 below either way).
        if cands.iter().all(supports) {
            cands
        } else {
            let kept: Vec<WeightedLane> = cands.into_iter().filter(|wl| supports(wl)).collect();
            if kept.is_empty() {
                return ingress_error(
                    ingress_protocol,
                    StatusCode::NOT_FOUND,
                    KIND_NOT_FOUND,
                    DETAIL_MODEL_UNSUPPORTED_OPERATION,
                );
            }
            kept
        }
    };
    // `v` is the PRISTINE parsed request body (parsed once by the caller). Never mutated after this
    // point: each failover hop derives a fresh per-hop `hop_v` (the first hop consumes `v`; hops 2+
    // re-parse the retained `body` bytes) before translating/rewriting, so a cross-protocol hop never
    // re-translates a body already rewritten into a previous egress lane's shape (the bug: mutating a
    // shared `v` in place made hop N+1 read hop N's egress-shaped body with the ingress reader,
    // misparsing or skipping translation entirely on a mixed-protocol pool).

    // capture the caller's stream intent from the ingress body BEFORE any cross-protocol
    // translation rewrites `v` (Gemini routes streaming requests to a different upstream endpoint).
    // Delegated to the operation: chat reads the OpenAI-family `stream` boolean (byte-identical to
    // the previous inline read); a non-streaming op always returns false.
    // `probe()` answers this from the head projection (chat reads only the top-level `stream`
    // boolean — a captured head key) without materializing the DOM; once a DOM exists, `probe()` IS
    // the DOM, so the read is byte-identical either way.
    let wants_stream = v
        .as_ref()
        .map(|l| op.wants_stream(l.probe()))
        .unwrap_or(false);

    // Capture whether the ORIGINAL client opted into streaming token usage
    // (`stream_options.include_usage == true`) BEFORE any rewrite/translation touches `v`.
    // Meaningful only for an OpenAI-family ingress that speaks the `stream_options` convention;
    // any other ingress body simply lacks the key and reads `false`. Busbar ALWAYS injects
    // `include_usage` on the upstream request (so it can bill a streaming call), so this
    // flag alone decides whether the resulting trailing usage chunk is surfaced to THIS client
    // a client that did not opt in must not receive the unsolicited `{choices:[], usage}`
    // chunk. Read from the head projection where available (`probe()` is the head projection until a
    // DOM is materialized, then the DOM itself), so no DOM is forced for the common non-opt-in case.
    let client_include_usage = wants_stream
        && v.as_ref()
            .map(|l| {
                l.probe()
                    .pointer("/stream_options/include_usage")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false)
            })
            .unwrap_or(false);
    // Companion point-read (also free off the head projection): does the client body carry a
    // top-level `stream_options` key AT ALL? Drives the byte-level upstream include_usage injection
    // below - a body with NO `stream_options` can have the flag inserted with a single splice that
    // preserves the pristine same-proto re-emit (no DOM parse); a body that DOES carry one (but did
    // not opt in - e.g. `include_usage:false` or a sibling-only object) is the rare case that falls
    // to the DOM-materializing injector. Meaningful only for a streaming OpenAI-family body.
    let client_has_stream_options = wants_stream
        && v.as_ref()
            .map(|l| l.probe().get("stream_options").is_some())
            .unwrap_or(false);

    // ── GLOBAL REWRITE (transform) PASS ─────────────────────────────────────────────────────────
    // Fire the global `prompt: rw` gates (compression/redaction) BEFORE dispatch AND before the
    // routing decision, so the decision + upstream both see the rewritten body. Priority-ordered
    // transform chain; fail-safe throughout (a broken hook is skipped, a non-chat body is untouched).
    // ZERO COST when no rewrite hook is configured — the common case is a single always-false branch.
    // The pool's own rewrite chain (rw gates in its `hooks: [...]` list) fires AFTER the globals —
    // each chain internally priority-ordered, globals always first.
    // The pool's resolved rewrite chain, read through the core-side pool-hook facade (money-path
    // Phase 3-4 C): the resolved `Arc<dyn RoutingPolicy>` objects live core-side keyed by pool, not on
    // this plane's `PoolRuntime` (they cannot cross the `build_runtime` downcast). Byte-identical.
    let pool_rewrites: &[(
        std::time::Duration,
        std::sync::Arc<dyn busbar_api::RoutingPolicy>,
    )] = host.pool_rewrites(pool_name);
    if !host.rewrite_hooks().is_empty() || !pool_rewrites.is_empty() {
        if let Some(lazy) = v.as_mut() {
            // A rewrite hook's REJECT stops the request here — the same client shaping a decide-
            // path gate rejection gets (clamped status, sanitized message, native envelope).
            let reject = |status: u16, message: String| {
                diag_debug!(
                    REWRITE_GATE_REJECTED,
                    pool = pool_name,
                    status,
                    message = %message,
                    "rewrite gate rejected the request"
                );
                gate_rejected(ingress_error(
                    ingress_protocol,
                    StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
                    reject_kind_for_status(status),
                    &message,
                ))
            };
            // Rewrite hooks mutate the tree — materialize the DOM (rewrite paths always paid this
            // parse). The unreachable-in-practice parse failure (these bytes already validated)
            // fails CLOSED, matching the rewrite guarantee's serialize guard below.
            let Ok(parsed) = lazy.ensure_dom() else {
                diag_error!(
                    REWRITE_BODY_MATERIALIZE_FAILED,
                    "materializing the validated request body for the rewrite pass failed; \
                     rejecting rather than forwarding un-rewritten"
                );
                return reject(500, "request rewrite could not be applied".to_string());
            };
            let mut applied = match apply_global_rewrites(
                host.rewrite_hooks(),
                parsed,
                pool_name,
                ingress_protocol,
                op.operation,
                wants_stream,
                request_id,
            )
            .await
            {
                Ok(a) => a,
                Err((status, message)) => return reject(status, message),
            };
            applied |= match apply_global_rewrites(
                pool_rewrites,
                parsed,
                pool_name,
                ingress_protocol,
                op.operation,
                wants_stream,
                request_id,
            )
            .await
            {
                Ok(a) => a,
                Err((status, message)) => return reject(status, message),
            };
            // A committed rewrite makes the RETAINED bytes stale: the same-protocol pristine
            // short-circuit re-emits them verbatim, and failover hops 2+ re-parse them — either
            // path would silently discard the rewrite. Re-serialize the rewritten body as the new
            // retained bytes so every downstream reader of `body` sees the effective request.
            // Cost only on the rewrite path (a no-op request never reaches this serialize).
            if applied {
                match busbar_substrate::json::to_vec(parsed) {
                    Ok(bytes) => body = Bytes::from(bytes),
                    // A `prompt: rw` rewrite is a TRUSTED, possibly security-critical transform. If it
                    // cannot be serialized into the retained bytes, the first hop carries it but every
                    // FAILOVER hop (which re-parses `body`) would forward the ORIGINAL un-rewritten
                    // request — fail-OPEN on the rewrite guarantee. Fail CLOSED: reject rather than
                    // leak the un-rewritten body to a fallback lane. (Not realistically reachable;
                    // defense-in-depth for the rewrite invariant.)
                    Err(e) => {
                        diag_error!(REWRITE_RESERIALIZE_FAILED, error = %e, "re-serializing a committed rewrite failed; rejecting to avoid forwarding the un-rewritten request on failover");
                        return reject(500, "request rewrite could not be applied".to_string());
                    }
                }
            }
        }
    }

    // ── REQUEST IR ───────────────────────────────────────────────────────────────────────────────
    // Parse the EFFECTIVE request (post-rewrite) into the IR, once, here — before the taps, before
    // the gates, and before a lane (and therefore an egress protocol) has been chosen. That ordering
    // is the requirement, not an accident: a content hook may reroute the request across protocols,
    // so "is this hop same-protocol?" is not answerable at the point the hook's view must exist.
    //
    // GATED ON THE DEPLOYMENT, resolved at config apply: `any_content_hook` is true only when some
    // hook holds a `prompt: ro`/`rw` grant. A deployment that grants no hook access to content —
    // the default — takes a single predictable always-false branch and builds nothing.
    if host.any_content_hook() {
        if let Some(lazy) = v.as_mut() {
            let _ = lazy.ensure_ir(ingress_protocol, op);
        }
    }

    // ── GLOBAL TAP (observe) FIRE ────────────────────────────────────────────────────────────────
    // Fire the global request-stage `kind: tap` hooks FIRE-AND-FORGET: serialize the projection(s) to
    // owned bytes ONCE, then spawn one detached task per tap. A tap gets a write-only send with its
    // own deadline; its reply (if any) is ignored, its errors swallowed — a tap can NEVER delay,
    // reorder, or fail the request. Runs AFTER the rewrite pass so a tap observes the effective
    // (post-compression) body. Each tap receives the projection its GRANT allows: a `prompt: ro` tap
    // gets the prompt-content projection, a `prompt: no` (default) tap gets shape-only — so a tap
    // never over-shares. At most TWO projections are built (shape-only + with-prompt), regardless of
    // tap count. ZERO COST when no tap is configured (empty-list branch).
    // Hoisted empty check (mirrors `fire_global_taps`'s own first-line early return) so the DOM is
    // only materialized when a tap is actually configured — ZERO COST stays zero-parse.
    if !host.tap_hooks().is_empty() {
        if let Some(Ok(dom)) = v.as_mut().map(|l| l.ensure_dom()) {
            fire_global_taps(
                host,
                dom,
                &body,
                req_content_type,
                op.operation,
                pool_name,
                ingress_protocol,
                wants_stream,
                request_id,
                resolved_gov_key.and_then(|k| k.group.as_deref()),
            );
        }
    }

    // Gemini ingress streaming WITHOUT `?alt=sse`: the native client expects a JSON-array streamed
    // body, not SSE. The route layer signals this via a router shim key (read here; stripped from the
    // body unconditionally before forwarding). GATED on `uses_array_stream_shim()` (true only for
    // GeminiWriter): only a genuine Gemini client can want JSON-array response framing. Without the
    // gate a body-model client (openai/cohere/responses) that sent `{"__busbar_gemini_json_array":true}`
    // in its own fully-controlled body would have its SSE stream silently reframed as a JSON array
    // under `Content-Type: application/json` — undecodable by the official SDK and a router behavior
    // no native backend exhibits. False for every other protocol and for the `?alt=sse` gemini variant.
    // Additionally gated on `op.streaming()`: a non-streaming operation never frames a JSON-array
    // stream (chat streams, so this is a no-op for chat — `true && x == x`).
    let ingress_decl = busbar_substrate::proto::decl_for(ingress_protocol);
    let gemini_json_array = op.streaming()
        && ingress_decl.is_some_and(|d| d.uses_array_stream_shim)
        && ingress_decl
            .and_then(|d| d.dialect())
            .map(|di| {
                v.as_ref()
                    // The shim key is a captured head key — `probe()` answers without a DOM.
                    .map(|l| di.wants_array_stream(l.probe()))
                    .unwrap_or(false)
            })
            .unwrap_or(false);

    // Derive the affinity HASH early (before any mutations to v), from BORROWED bytes — the sticky
    // preference needs only `stable_hash(key)`, never the owned string, so hashing here avoids a
    // per-request `String` allocation. Prefer the supplied header key; else fall back to the
    // operation's body-derived key (chat: the top-level `system` string — byte-identical selection to
    // the previous owned-String read; other ops: no body affinity). `None` = no sticky preference.
    let affinity_key_hash: Option<u64> =
        affinity_key.map(crate::engine::stable_hash).or_else(|| {
            v.as_ref()
                // Chat's body affinity key is the top-level `system` string — a captured head key,
                // so `probe()` answers without materializing the DOM.
                .and_then(|l| op.body_affinity_key(l.probe()))
                .map(crate::engine::stable_hash)
        });

    // Before-first-byte failover boundary:
    // Failover is allowed ONLY until the first upstream byte reaches the client.
    // After that point, an upstream failure must NOT trigger failover because
    // the client already has a partial response. Instead:
    // - For SSE streams: emit an SSE `error` event and terminate the stream
    // - Record the breaker failure for that lane (the member tripped)
    // The client must restart the request itself after receiving the error event.

    // Failover config: prefer this pool's own settings, fall back to the global default.
    let pool_failover = EngineTables::new(rt)
        .pool_runtime()
        .get(pool_name)
        .and_then(|r| r.failover.as_ref())
        .or(EngineTables::new(rt).failover_cfg().as_ref());
    let (deadline_secs, max_cap) = match pool_failover {
        Some(f) => (f.timeout_secs, f.max_hops),
        None => (
            busbar_substrate::failover::DEFAULT_FAILOVER_DEADLINE_SECS,
            busbar_substrate::failover::DEFAULT_FAILOVER_CAP,
        ),
    };

    // Breaker config: prefer this pool's own settings, fall back to ADR-0002 defaults. Resolved
    // once and shared (Arc) so the streaming guard can record mid-stream failures with the same
    // thresholds the synchronous path used. The default (no per-pool breaker — the common case) is
    // a process-wide cached Arc, so the hot path pays no per-request allocation for it.
    let breaker_cfg: std::sync::Arc<busbar_substrate::store::BreakerCfg> =
        resolve_breaker_cfg(rt, pool_name);

    let mut request_ctx = RequestCtx::new(deadline_secs, request_id);
    // Carry the ingress-collected client beta/version allowlist across the whole failover walk so the
    // degraded exhaustion paths forward the same set the hot path does.
    request_ctx.forwarded_client_headers = client_fwd;

    // Apply configured failover exclusions: members named here are excluded from this pool's
    // candidate set (never selected, primary or failover) — a per-pool member blocklist.
    //
    // Removed from `cands` rather than seeded into `request_ctx.excluded`, mirroring how gate
    // restricts narrow the set. The two are different kinds of exclusion: `request_ctx.excluded`
    // accumulates already-tried lanes, so a consumer that reads it cannot tell a blocklisted member
    // from one this request has burned through. The exhaustion paths read `cands` directly —
    // `least_bad` and the `Retry-After` computation both did, and so reached blocklisted members.
    if let Some(excl) = pool_failover.and_then(|f| f.exclusions.as_ref()) {
        cands.retain(|wl| {
            !excl
                .iter()
                .any(|m| m == &EngineTables::new(rt).lanes()[wl.idx].model)
        });
    }

    // ── ROUTING-POLICY SEAM ───────────────────────────────────────────────────────────────────────
    // Resolve this pool's routing policy ONCE, here, before the failover loop. The policy (when
    // present) produces a ranked member preference that the loop's `pick_among` walks instead of the
    // blind SWRR pick — composing with the unchanged breaker filter + already-tried exclusion.
    //
    // ZERO-COST DEFAULT: a `route: weighted` (default / absent) pool has `policy == None`, so this is
    // a single predictable always-false branch — no `RoutingRequest`/`Candidate` projection is built,
    // no async policy is entered, and `policy_order` stays `None`, leaving the loop on today's exact
    // inline `select_weighted_in` path. The projection + async decision + ordered-walk only ever run
    // for a pool that resolved a non-default policy.
    //
    // `chosen_policy_name` is the policy that actually produced `policy_order` (for the
    // `x-busbar-route-policy` transparency header). It stays `None` on the default path AND when a
    // configured policy Abstains / errors-to-weighted (both fall through to SWRR, which is not a
    // "policy choice" worth advertising).
    // ── PHASE-2 DECISION GATES (concurrent at t0) ───────────────────────────────────────────────
    // Fire the GLOBAL decision gates and this pool's OWN gates for a verdict on this request,
    // BEFORE pool routing. All gates fire CONCURRENTLY against the same t0 candidate set — reject
    // and restrict COMMUTE (veto; intersect), and an order is re-validated against the FINAL
    // (post-restrict) set — then the outcomes reconcile deterministically over ONE chain, sorted by
    // ascending `priority` (stable: globals before pool gates on ties, then config order):
    //   1. any reject ⇒ reject wins. The FIRST rejecting gate in chain order (the priority
    //      tie-break) supplies the surfacing status/message; nothing is dispatched.
    //   2. else restricts INTERSECT, applied in chain order; a gate whose intersection empties the
    //      set applies ITS `on_empty` (weighted = advisory escape, that gate's restriction is
    //      skipped; the fail-closed default rejects with a 503).
    //   3. else the LAST ordering gate in the chain wins, filtered to the surviving candidate set
    //      (an order captured at t0 may name members a restrict excluded — the filter is what makes
    //      the concurrent firing sound). Empty after filtering = abstain (the pool's base ordering
    //      below applies).
    // The restriction persists across failover (hops select from the shrunk `cands`). ZERO COST
    // when no gate is configured (both sources empty ⇒ the pass is skipped).
    // The pool's resolved decision gates, read through the core-side pool-hook facade (see the rewrite
    // chain above for why these live core-side rather than on the plane's `PoolRuntime`).
    let pool_gates: &[(u16, busbar_substrate::hooks::ResolvedPolicy)] = host.pool_gates(pool_name);
    let mut gate_order: Option<(Vec<usize>, &'static str)> = None;
    if !host.global_gates().is_empty() || !pool_gates.is_empty() {
        // The chain: globals (pre-sorted ascending by priority) then pool gates (config order),
        // stable-sorted by priority — ties keep globals-first, then config order.
        let mut chain: Vec<&(u16, busbar_substrate::hooks::ResolvedPolicy)> = host
            .global_gates()
            .iter()
            .chain(pool_gates.iter())
            .collect();
        chain.sort_by_key(|(p, _)| *p);
        // Every concurrently-firing gate borrows the same parsed body; the shared Null stands in
        // for a non-JSON body (the same projection the sequential path used). Gates project
        // arbitrary body fields, so a configured gate materializes the DOM (as it always did).
        static NULL_BODY: Value = Value::Null;
        let gate_body: &Value = match v.as_mut() {
            Some(l) => match l.ensure_dom() {
                Ok(m) => &*m,
                Err(()) => &NULL_BODY,
            },
            None => &NULL_BODY,
        };
        let outcomes: Vec<PolicyOutcome> =
            futures::future::join_all(chain.iter().map(|(_, gate)| {
                decide_policy_order(
                    host,
                    rt,
                    gate,
                    &cands,
                    &request_ctx,
                    gate_body,
                    &body,
                    req_content_type,
                    pool_name,
                    ingress_protocol,
                    op.operation,
                    wants_stream,
                    caller_token,
                    resolved_gov_key,
                )
            }))
            .await;

        // Reconcile 1: REJECT WINS. The first rejecting gate in chain order surfaces — that is the
        // `priority` tie-break when several gates reject at once. A deliberate RejectRequest was
        // status-clamped 400..=499 + message-sanitized at the producing seam; a fail-closed errored
        // gate (`on_error: reject`) is a 503, never a silent proceed — it was declared load-bearing.
        for outcome in &outcomes {
            match outcome {
                PolicyOutcome::RejectRequest {
                    status,
                    message,
                    name,
                } => {
                    metrics::counter!(
                        busbar_substrate::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
                        "policy" => *name,
                        "pool" => pool_name.to_string(),
                        "status" => status.to_string(),
                    )
                    .increment(1);
                    diag_debug!(
                        DECISION_GATE_REJECTED,
                        policy = name,
                        pool = pool_name,
                        status,
                        message = %message,
                        "decision gate rejected the request"
                    );
                    return gate_rejected(ingress_error(
                        ingress_protocol,
                        StatusCode::from_u16(*status).unwrap_or(StatusCode::FORBIDDEN),
                        reject_kind_for_status(*status),
                        message,
                    ));
                }
                PolicyOutcome::Reject => {
                    return gate_rejected(ingress_error(
                        ingress_protocol,
                        StatusCode::SERVICE_UNAVAILABLE,
                        KIND_OVERLOADED,
                        "A required gate could not complete. Please retry shortly.",
                    ));
                }
                _ => {}
            }
        }

        // Reconcile 2: RESTRICTS INTERSECT, in chain order (intersection commutes — the final set
        // is order-independent; the chain order only decides WHOSE on_empty applies first when the
        // set empties). Shrinking `cands` makes the restriction persist across every failover hop
        // and keeps any ordering — gate or base — inside the eligible set.
        for outcome in &outcomes {
            if let PolicyOutcome::Restrict {
                tags_any,
                name,
                on_empty,
            } = outcome
            {
                // Capture this restrict so it PERSISTS across a `fallback_pool` hop (which rebuilds
                // candidates from an independent pool). Recorded for every restrict regardless of
                // whether it narrows here — the fail-closed reject case returns below before any
                // fallback, so a stray record is harmless.
                request_ctx.active_restricts.push(RestrictConstraint {
                    tags_any: tags_any.clone(),
                    on_empty: on_empty.clone(),
                    name,
                });
                let members = EngineTables::new(rt)
                    .pool_runtime()
                    .get(pool_name)
                    .map(|r| &r.members);
                let restricted: Vec<WeightedLane> = cands
                    .iter()
                    .filter(|wl| {
                        members.and_then(|m| m.get(&wl.idx)).is_some_and(|meta| {
                            meta.tags.iter().any(|t| tags_any.iter().any(|w| w == t))
                        })
                    })
                    .cloned()
                    .collect();
                if restricted.is_empty() {
                    if matches!(on_empty, busbar_substrate::config::PolicyOnError::Weighted) {
                        diag_debug!(
                            DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE,
                            policy = name,
                            pool = pool_name,
                            "decision gate restrict left no eligible lane; on_empty: weighted \
                             escape — this gate's restriction is skipped"
                        );
                        // leave `cands` unchanged and continue reconciling the next restrict.
                    } else {
                        metrics::counter!(
                            busbar_substrate::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
                            "policy" => *name,
                            "pool" => pool_name.to_string(),
                            "status" => "503".to_string(),
                        )
                        .increment(1);
                        diag_debug!(
                            DECISION_GATE_RESTRICT_REJECT,
                            policy = name,
                            pool = pool_name,
                            "decision gate restrict left no eligible lane (on_empty: reject)"
                        );
                        return gate_rejected(ingress_error(
                            ingress_protocol,
                            StatusCode::SERVICE_UNAVAILABLE,
                            KIND_OVERLOADED,
                            "No upstream satisfies a required gate's restriction. Please retry \
                             shortly.",
                        ));
                    }
                } else {
                    cands = restricted;
                    metrics::counter!(
                        busbar_substrate::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
                        "policy" => *name,
                        "pool" => pool_name.to_string(),
                    )
                    .increment(1);
                }
            }
        }

        // Reconcile 3: ORDER — LAST in the chain wins, re-validated against the FINAL candidate
        // set (the t0 order may name members a restrict excluded). An order that filters to empty
        // abstains — the pool's base ordering below applies.
        let surviving: std::collections::HashSet<usize> = cands.iter().map(|wl| wl.idx).collect();
        for outcome in outcomes {
            if let PolicyOutcome::Order { order, name } = outcome {
                let filtered: Vec<usize> = order
                    .into_iter()
                    .filter(|i| surviving.contains(i))
                    .collect();
                if !filtered.is_empty() {
                    gate_order = Some((filtered, name));
                } else {
                    // This gate outranks every earlier one in the chain, and it has abstained: the
                    // fall-through is the pool's BASE ordering, never a lower-priority gate's stale
                    // order left over from a previous loop iteration.
                    gate_order = None;
                }
            }
        }
        if let Some((_, name)) = &gate_order {
            metrics::counter!(
                busbar_substrate::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
                "policy" => *name,
                "pool" => pool_name.to_string(),
            )
            .increment(1);
        }
    }

    let mut chosen_policy_name: Option<&'static str> = None;
    let policy_order: Option<Vec<usize>> = if let Some((order, name)) = gate_order {
        // A phase-2 gate ORDERED: it overrides the pool's base ordering (a gate's abstain was the
        // reconciled fall-through to the base, handled above).
        chosen_policy_name = Some(name);
        Some(order)
    } else {
        // The pool's resolved routing policy, read through the core-side pool-hook facade.
        match host.pool_policy(pool_name) {
            // Default fast path: no policy ⇒ SWRR, byte-identical to pre-feature behavior. NOTHING below
            // this arm runs — no projection, no async, one predictable branch.
            None => None,
            // A non-default policy is configured: build the projection, run the decision (bounded by its
            // timeout), and coerce the outcome to a ranked order (or `None` ⇒ SWRR) per `on_error`.
            Some(resolved) => {
                // A configured routing policy projects the body — materialize the DOM (this pool
                // always paid the parse). `NULL_BODY_POLICY` stands in for non-JSON, as before.
                static NULL_BODY_POLICY: Value = Value::Null;
                let policy_body: &Value = match v.as_mut() {
                    Some(l) => match l.ensure_dom() {
                        Ok(m) => &*m,
                        Err(()) => &NULL_BODY_POLICY,
                    },
                    None => &NULL_BODY_POLICY,
                };
                // Box::pin: the policy-decision future (~1.6 KB, and its region set this fn's
                // coroutine union max) is COLD on the default path — it runs ONLY for a pool that
                // resolved a non-default `route:` policy, a path that already builds heap
                // projections (candidates Vec, budget chain, RoutingRequest) per decision. Awaited
                // inline it inflated the per-request future EVERY default-pool request carried;
                // boxed, the allocation lands only on policy-routed requests. (Same cold-arm
                // pattern as the exhaustion boxes below; the concurrent GATE firing above already
                // heap-allocates its futures via `join_all`.)
                let outcome = Box::pin(decide_policy_order(
                    host,
                    rt,
                    resolved,
                    &cands,
                    &request_ctx,
                    policy_body,
                    &body,
                    req_content_type,
                    pool_name,
                    ingress_protocol,
                    op.operation,
                    wants_stream,
                    caller_token,
                    resolved_gov_key,
                ))
                .await;
                match outcome {
                    // The policy returned a usable ranked order — record its name (for the
                    // `x-busbar-route-policy` header + the metric) and hand the order to the ordered walk.
                    PolicyOutcome::Order { order, name } => {
                        chosen_policy_name = Some(name);
                        metrics::counter!(
                            busbar_substrate::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
                            "policy" => name,
                            "pool" => pool_name.to_string(),
                        )
                        .increment(1);
                        Some(order)
                    }
                    // Abstain / error-coerced-to-weighted: fall through to today's exact SWRR.
                    PolicyOutcome::Weighted => None,
                    // on_error == reject (and the policy errored/timed out / saturated): fail closed with a
                    // 503 rather than silently degrading. Never strands as a hang — a clean rejection.
                    PolicyOutcome::Reject => {
                        return gate_rejected(ingress_error(
                            ingress_protocol,
                            StatusCode::SERVICE_UNAVAILABLE,
                            KIND_OVERLOADED,
                            "The routing policy could not select an upstream. Please retry \
                             shortly.",
                        ));
                    }
                    // The hook's REJECT verb: a deliberate, first-class policy decision (a guardrail /
                    // PII screen said no) — a 4xx to the caller, no upstream dispatched, and an
                    // operator-visible counter. `status` was clamped to 400..=499 and `message`
                    // sanitized at the seam that constructed the outcome (for every producer, wire or
                    // direct), so this arm can trust both.
                    PolicyOutcome::RejectRequest {
                        status,
                        message,
                        name,
                    } => {
                        // The `status` label is hook-influenced but BOUNDED: the seam that built this
                        // outcome clamps it to 400..=499 for every producer, so the worst-case series
                        // fan-out is 100 per (policy, pool).
                        metrics::counter!(
                            busbar_substrate::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
                            "policy" => name,
                            "pool" => pool_name.to_string(),
                            "status" => status.to_string(),
                        )
                        .increment(1);
                        // The message is safe to log: the seam that built this outcome sanitized it
                        // (control/invisible chars stripped, length capped — for EVERY producer, not
                        // just the wire transports), and it is the exact string the CLIENT receives.
                        diag_debug!(
                            ROUTING_POLICY_REJECTED,
                            policy = name,
                            pool = pool_name,
                            status,
                            message = %message,
                            "routing policy rejected the request"
                        );
                        return gate_rejected(ingress_error(
                            ingress_protocol,
                            StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
                            reject_kind_for_status(status),
                            &message,
                        ));
                    }
                    // The hook's RESTRICT verb: intersect the failover candidate set with members
                    // carrying one of `tags_any`, then let SWRR pick among the survivors. Shrinking
                    // `cands` here makes the restriction PERSIST across every failover hop (each hop
                    // selects from this set) — the compliance guarantee ("only these lanes, ever"). An
                    // EMPTY intersection is fail-closed (`on_empty` default reject), never allow-all;
                    // an empty `tags_any` (fail-closed-normalized malformed restrict) forces it.
                    PolicyOutcome::Restrict {
                        tags_any,
                        name,
                        on_empty,
                    } => {
                        // Capture this restrict so it PERSISTS across a `fallback_pool` hop, exactly
                        // as the GATE reconcile arm does. Shrinking `cands` below only covers in-pool
                        // failover; the fallback pool rebuilds candidates independently and consults
                        // `enforce_restricts`. The gate arm was fixed first; this BASE routing-policy
                        // arm (pool `route:` hook) is the sibling path that was still leaking a
                        // compliance restrict at the pool boundary.
                        request_ctx.active_restricts.push(RestrictConstraint {
                            tags_any: tags_any.clone(),
                            on_empty: on_empty.clone(),
                            name,
                        });
                        let members = EngineTables::new(rt)
                            .pool_runtime()
                            .get(pool_name)
                            .map(|r| &r.members);
                        // Filter into a temp so the ORIGINAL `cands` survives for a weighted on_empty
                        // escape; only commit the restriction when the intersection is non-empty.
                        let restricted: Vec<WeightedLane> = cands
                            .iter()
                            .filter(|wl| {
                                members.and_then(|m| m.get(&wl.idx)).is_some_and(|meta| {
                                    meta.tags.iter().any(|t| tags_any.iter().any(|w| w == t))
                                })
                            })
                            .cloned()
                            .collect();
                        if restricted.is_empty() {
                            // Empty intersection → the gate's `on_empty`. `Weighted` is the advisory escape
                            // (leave `cands` as the full pool → SWRR); default (and `First`, which has no
                            // eligible "first") is fail-closed reject.
                            if matches!(on_empty, busbar_substrate::config::PolicyOnError::Weighted)
                            {
                                diag_debug!(
                                ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
                                policy = name,
                                pool = pool_name,
                                "routing policy restrict left no eligible lane; on_empty: weighted \
                                 escape to full-pool SWRR"
                            );
                                None
                            } else {
                                metrics::counter!(
                                    busbar_substrate::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
                                    "policy" => name,
                                    "pool" => pool_name.to_string(),
                                    "status" => "503".to_string(),
                                )
                                .increment(1);
                                diag_debug!(
                                ROUTING_POLICY_RESTRICT_REJECT,
                                policy = name,
                                pool = pool_name,
                                "routing policy restrict left no eligible lane (on_empty: reject)"
                            );
                                return gate_rejected(ingress_error(
                                    ingress_protocol,
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    KIND_OVERLOADED,
                                    "No upstream satisfies the routing policy's restriction. \
                                     Please retry shortly.",
                                ));
                            }
                        } else {
                            // Commit the restriction: shrink `cands` to the survivors so it PERSISTS
                            // across every failover hop, then let SWRR pick among them.
                            cands = restricted;
                            chosen_policy_name = Some(name);
                            metrics::counter!(
                                busbar_substrate::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
                                "policy" => name,
                                "pool" => pool_name.to_string(),
                            )
                            .increment(1);
                            None
                        }
                    }
                }
            }
        }
    };

    // The pristine `v` is consumed by the FIRST hop (it is unmutated after the field reads above), so
    // the common no-failover path parses the body ONCE, not twice. Failover hops (2+) re-parse from
    // the retained `body` bytes — never from a previous hop's egress-shaped Value — preserving the
    // mixed-protocol-pool correctness the per-hop re-parse was introduced for.
    let body_is_json = v.is_some();
    // ── STAGE TAPS: candidate + routing shape ── captured ONCE (scalars only, so it survives `v`
    // moving into the first hop). Fire the `candidate` taps now: the decision reconcile + base ordering
    // above produced the FINAL candidate set for dispatch. ZERO COST when no stage tap is configured.
    let stage_shape =
        if host.tap_hooks_candidate().is_empty() && host.tap_hooks_routing().is_empty() {
            None
        } else {
            // Stage taps read arbitrary body fields for the shape — materialize the DOM (taps are
            // configured, so this request always paid the parse).
            let dom: Option<&Value> = match v.as_mut() {
                Some(l) => l.ensure_dom().ok().map(|m| &*m),
                None => None,
            };
            Some(capture_stage_shape(
                dom,
                &body,
                req_content_type,
                pool_name,
                ingress_protocol,
                Some(op.operation),
                wants_stream,
                request_ctx.request_id,
            ))
        };
    if let Some(shape) = &stage_shape {
        fire_stage_taps(
            host.tap_hooks_candidate(),
            shape,
            busbar_substrate::hooks::wire::HookStageProjection {
                at: "candidate",
                model: None,
                attempt_number: None,
                remaining_candidates: Some(cands.len()),
                previous_failure: None,
                outcome: None,
                status: None,
            },
            resolved_gov_key.and_then(|k| k.group.as_deref()),
            &**host,
        );
    }
    // Why the PREVIOUS attempt failed — feeds the routing-stage tap payload (the failover story).
    let mut last_failure: Option<&'static str> = None;

    // Upstream-credential mode for THIS pool, resolved ONCE (a String-keyed `pool_runtime` HashMap
    // lookup — a SipHash of the pool name) and carried as a `Copy` scalar for the whole dispatch. It
    // is invariant across every failover hop (the pool does not change mid-request), so hoisting it
    // out of the loop replaces a per-attempt (and per-error-classification) hash lookup with a single
    // register read on the always-on egress path — restoring the pre-1.5.3 `Copy` read that the
    // per-pool override turned into a per-call `App::pool_upstream_creds(pool_name)` map probe. Same
    // value the accessor returns (pool override else all-pools default), same passthrough-40x logic.
    let upstream_creds = EngineTables::new(rt).pool_upstream_creds(pool_name);

    // PREPARE ends here (dispatch loop begins). From here on, `v` IS the first-hop body: the loop
    // consumes it on hop 1 (`v.take()` / the pristine short-circuit) and failover hops 2+ re-parse
    // the retained `body` bytes. (This used to be a `first_hop_v = v` rebind for the name alone —
    // dropped because the extra binding cost the coroutine a second 80-byte `Option<LazyBody>` slot
    // held across every await of the attempt loop; wave-8a future-shrink.)
    drop(_prep);
    for attempt_no in 0..=max_cap {
        // Check deadline first (propagated across hops)
        if request_ctx.expired(now()) {
            return ingress_error(
                ingress_protocol,
                StatusCode::SERVICE_UNAVAILABLE,
                KIND_OVERLOADED,
                DETAIL_REQUEST_TIMEOUT,
            );
        }

        let _pick = busbar_substrate::profile::start(busbar_substrate::profile::Stage::LanePick);
        // `probe_epoch`: `Some(epoch)` when this pick WON a single-flight recovery probe (captured
        // synchronously by `pick_among` before any await), `None` for a Closed-ready no-op admit that
        // won none. The `probe_guard` built right below turns this into a RAII release that covers the
        // WHOLE dispatch window — including a dropped future — so this path no longer scatters explicit
        // (and formerly unowned) `release_probe_*` calls across its early-return arms.
        let (i, permit, probe_epoch) = match pick_among(
            host,
            rt,
            &cands,
            &mut request_ctx,
            affinity_key_hash,
            pool_name,
            policy_order.as_deref(),
        )
        .await
        {
            Some(x) => x,
            None => {
                if cands.is_empty() {
                    // Pool has no members at all — nothing to do.
                    return ingress_error(
                        ingress_protocol,
                        StatusCode::SERVICE_UNAVAILABLE,
                        KIND_OVERLOADED,
                        "The service is temporarily overloaded. Please retry shortly.",
                    );
                }
                // No usable lane — whether the members were tripped before this request
                // arrived or excluded during its failover attempts, apply the configured
                // exhaustion mode (Status503 / FallbackPool / LeastBad) with loop prevention.
                // Box::pin: the exhaustion future (~2.1 KB) is COLD (no usable lane), but awaited
                // inline it alone sets this fn's coroutine union max — boxing it shrinks the
                // per-request future every happy-path request carries; the alloc only happens on
                // the already-degraded path. (Same pattern as the fallback pool's recursive box.)
                return Box::pin(handle_exhaustion_for_pool(
                    host.clone(),
                    rt.clone(),
                    &cands,
                    now(),
                    pool_name,
                    body,
                    caller_token,
                    &mut request_ctx,
                    ingress_protocol,
                    op,
                    req_content_type,
                    usage_sink.clone(),
                ))
                .await;
            }
        };
        // LANE_PICK ends here (a lane + permit are in hand).
        drop(_pick);
        // ATTEMPT_SETUP: per-hop bookkeeping between lane_pick and the attempt — exclude, routing
        // taps (light path: none), metric-pool label, upstream-attempt telemetry.
        let _asetup =
            busbar_substrate::profile::start(busbar_substrate::profile::Stage::AttemptSetup);

        // Mark this lane as excluded for future attempts in this request
        request_ctx.exclude(i);

        // ── STAGE TAPS: routing ── the full failover story, per dispatch attempt: which lane,
        // which attempt number, how many candidates remain untried, and why the previous attempt
        // failed (None on the first).
        if let Some(shape) = &stage_shape {
            let remaining = cands
                .iter()
                .filter(|wl| !request_ctx.excluded.contains(&wl.idx))
                .count();
            fire_stage_taps(
                host.tap_hooks_routing(),
                shape,
                busbar_substrate::hooks::wire::HookStageProjection {
                    at: "routing",
                    model: Some(&EngineTables::new(rt).lanes()[i].model),
                    attempt_number: Some(
                        u32::try_from(attempt_no.saturating_add(1)).unwrap_or(u32::MAX),
                    ),
                    remaining_candidates: Some(remaining),
                    previous_failure: last_failure,
                    outcome: None,
                    status: None,
                },
                resolved_gov_key.and_then(|k| k.group.as_deref()),
                &**host,
            );
        }

        // The bounded `pool` LABEL for THIS hop's upstream/failover/breaker metrics.
        // Resolves to the routed lane's model name on the default (`""`) cell so these series
        // correlate with REQUESTS_TOTAL (which labels model-routed traffic by model, not `""`);
        // the breaker-cell key stays `pool_name` (`""`) — only the metric LABEL is decoupled.
        let metric_pool: &str = metric_pool_label(rt, pool_name, i);

        // count this upstream attempt (re-entrant across failover hops — each is a real attempt).
        host.telemetry_upstream_attempt(metric_pool, i);
        tracing::debug!(pool = %pool_name, lane = %EngineTables::new(rt).lanes()[i].model, "upstream attempt");

        let egress_name = EngineTables::new(rt).lanes()[i].protocol;
        drop(_asetup);
        // Derive a FRESH per-hop body for translation. Each failover hop must translate/rewrite
        // starting from the ORIGINAL request, never from a previous hop's egress-shaped body. Re-PARSE
        // from the pristine `Bytes` (Arc-backed, so cheap to retain) rather than deep-cloning the
        // parsed `Value` tree per hop: a single JSON parse is far cheaper in time and peak heap than
        // an O(n) `Value::clone` of a large request, which under sustained failover compounded to
        // O(n × max_cap) allocations.
        //
        // REQUEST SHORT-CIRCUIT WITHOUT A DOM: hop 1 of a SAME-protocol JSON dispatch whose head
        // projection PROVES no same-proto invalidator fires re-emits the retained bytes verbatim —
        // the exact bytes the translate seam's own pristine short-circuit would emit — without ever
        // materializing the `Value` tree. `head_provably_pristine` is one-sided (see its docs +
        // parity test): any doubt falls through to the unchanged materialize-and-translate path, so
        // the wire bytes are byte-identical on every branch. When the DOM was already materialized
        // (hooks/taps/gates/path-model ingress), `probe()` IS the (possibly hook-rewritten) DOM and
        // `body` was re-serialized in lockstep by the rewrite pass — the check stays sound.
        let head_pristine = ingress_protocol == egress_name
            && v.as_ref()
                .is_some_and(|l| head_provably_pristine(rt, i, l.probe()));
        let hop_v: Option<Value> = if head_pristine {
            // Consume the hop-1 body exactly as the translate path does; failover hops 2+ re-parse
            // from the retained pristine bytes, unchanged.
            v = None;
            None
        } else if !body_is_json {
            None // opaque ingress body: byte-level relay/translate; nothing to re-parse.
        } else {
            let parsed = match v.take() {
                // First hop: consume the carried body — the memoized DOM when one was
                // materialized (hooks/taps/gates/path-model), else ONE parse of the validated
                // bytes (the parse the old eager path performed at ingress).
                Some(l) => l.into_value(),
                // Failover hops: re-parse from the retained pristine bytes (SIMD parse).
                None => busbar_substrate::json::parse(&body).map_err(|_| ()),
            };
            match parsed {
                Ok(v) => Some(v),
                // `body` already validated/parsed once successfully above; this is infallible.
                Err(()) => {
                    // Pre-dispatch bail (no breaker outcome recorded): nothing was dispatched, so
                    // any single-flight probe this pick won is released here, owner-checked, and
                    // a recovering lane never wedges HalfOpen on this early exit.
                    if let Some(epoch) = probe_epoch {
                        host.lane_store()
                            .release_probe_owned_in(pool_name, i, epoch);
                    }
                    drop(permit);
                    return ingress_error(
                        ingress_protocol,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        KIND_API_ERROR,
                        DETAIL_INTERNAL_ERROR,
                    );
                }
            }
        };

        // THE ONE ATTEMPT: assemble, send, classify, deliver — the same function the degraded
        // exhaustion paths run. This loop only decides what a failed attempt means for the walk.
        let outcome = attempt(AttemptInput {
            hop: Hop {
                host,
                rt,
                lane: i,
                pool_cell: pool_name,
                cands: &cands,
                body: &body,
                pristine: head_pristine,
                body_is_json,
                req_content_type,
                ingress_protocol,
                egress_name,
                op,
                wants_stream,
                client_include_usage,
                client_has_stream_options,
                gemini_json_array,
                caller_token,
                upstream_creds,
                resolved_gov_key,
                remaining_secs: request_ctx.remaining(now()),
                breaker_cfg: &breaker_cfg,
                client_fwd: &request_ctx.forwarded_client_headers,
                chosen_policy_name,
                metric_pool,
                degraded: false,
            },
            permit,
            probe_epoch,
            hop_v,
            usage_sink: &mut usage_sink,
        })
        .await;
        match outcome {
            AttemptOutcome::Response(resp) | AttemptOutcome::Bail(resp) => return resp,
            AttemptOutcome::Failed {
                disposition,
                err_type,
                ..
            } => {
                if matches!(disposition, Disposition::ContextLength) {
                    // The request is too large for THIS model's context window: exclude every
                    // candidate whose known `context_max` is at or below the failed lane's (they
                    // share or undercut the limit that just failed), so failover lands on a
                    // larger-context or unknown-context member. An unknown limit on the failed lane
                    // excludes only the failed lane itself (already excluded above).
                    let failed_context_max = EngineTables::new(rt).lanes()[i].context_max;
                    for cand in &cands {
                        if let (Some(cand_context_max), Some(failed_limit)) = (
                            EngineTables::new(rt).lanes()[cand.idx].context_max,
                            failed_context_max,
                        ) {
                            if cand_context_max <= failed_limit {
                                request_ctx.exclude(cand.idx);
                            }
                        }
                    }
                }
                // Every failed attempt on this walk is a failover to the next candidate; the
                // routing-stage tap on the next hop tells the story of why.
                host.telemetry_failover(metric_pool, err_type);
                last_failure = Some(err_type);
                continue;
            }
        }
    }

    // Box::pin: cold path (candidates exhausted), boxed for the same coroutine-size reason as the
    // in-loop exhaustion return above — the happy path never allocates here.
    Box::pin(handle_exhaustion_for_pool(
        host.clone(),
        rt.clone(),
        &cands,
        now(),
        pool_name,
        body,
        caller_token,
        &mut request_ctx,
        ingress_protocol,
        op,
        req_content_type,
        usage_sink,
    ))
    .await
}

/// GLOBAL TAP (observe) stage of the forward pipeline. Fires the global request-stage `kind: tap`
/// hooks FIRE-AND-FORGET: serialize the projection(s) once, then spawn one detached task per tap. A tap gets
/// a write-only send with its own deadline; its reply is ignored, its errors swallowed — a tap can
/// NEVER delay, reorder, or fail the request. Each tap receives the projection its GRANT allows: a
/// `prompt: ro` tap gets the prompt-content projection, a `prompt: no` (default) tap gets shape-only.
/// At most TWO projections are built (shape-only + with-prompt) regardless of tap count. ZERO COST
/// when no tap is configured (the empty-list early return).
#[allow(clippy::too_many_arguments)]
fn fire_global_taps(
    host: &Arc<dyn EngineHost>,
    body: &Value,
    raw_body: &[u8],
    content_type: &str,
    operation: busbar_api::operation::Operation,
    pool_name: &str,
    ingress_protocol: &str,
    wants_stream: bool,
    request_id: u64,
    // The caller's `groups:` binding — the SELECTION axis (1.5.3). A tap fires only for a caller in
    // its `groups:` scope (empty scope = every caller). `None` (a groupless caller) matches only
    // unscoped taps. Walked against `app.groups_registry` (self + ancestors).
    caller_group: Option<&str>,
) {
    if host.tap_hooks().is_empty() {
        return;
    }
    // SELECTION: this tap fires for THIS caller iff its `groups:` scope admits the caller.
    let fires = |groups: &[String]| host.caller_in_hook_groups(caller_group, groups);
    let ctx = busbar_api::RoutingContext {
        pool: pool_name,
        budget_remaining: None,
        // Taps observe request shape; the budget-chain projection is a routing-policy signal
        // (decide_policy_order), not a tap payload.
        budget: &[],
    };
    // THE ONE READ for this seam, done once and shared by both projections. A body the reader
    // refuses yields the zeroed shape here rather than failing anything: request-stage taps are
    // fire-and-forget observation, and the gate/rewrite seams — which read the same IR — are where
    // an unreadable request is actually rejected.
    let facts = crate::engine::hooks::read_hook_facts(
        body,
        raw_body,
        content_type,
        ingress_protocol,
        Some(operation),
    )
    .unwrap_or(crate::engine::hooks::HookFacts::Absent);
    let build_proj = |with_prompt: bool| {
        let req = build_rewrite_request(
            &facts,
            body.get("model").and_then(serde_json::Value::as_str),
            pool_name,
            ingress_protocol,
            wants_stream,
            with_prompt,
            request_id,
        );
        busbar_substrate::json::to_vec(&busbar_substrate::hooks::wire::build(
            busbar_substrate::hooks::wire::OP_NOTIFY,
            &req,
            &[],
            &ctx,
        ))
        .ok()
        .map(std::sync::Arc::new)
    };
    // Shape-only is needed whenever any FIRING tap lacks the prompt grant; the prompt projection only
    // when at least one FIRING tap holds `prompt: ro`. Build each at most once. A tap filtered out by
    // its caller-group scope is not counted (it will not fire, so its projection need not be built).
    let any_prompt = host
        .tap_hooks()
        .iter()
        .any(|(_, send_prompt, _, groups)| *send_prompt && fires(groups));
    let any_shape = host
        .tap_hooks()
        .iter()
        .any(|(_, send_prompt, _, groups)| !*send_prompt && fires(groups));
    let shape_proj = if any_shape { build_proj(false) } else { None };
    let prompt_proj = if any_prompt { build_proj(true) } else { None };
    for (timeout, send_prompt, hook, groups) in host.tap_hooks() {
        // SELECTION: skip a tap whose `groups:` scope does not admit this caller.
        if !fires(groups) {
            continue;
        }
        // A granted tap prefers the prompt projection; fall back to shape-only if it failed to
        // serialize (never over-share, always safe).
        let proj = if *send_prompt {
            prompt_proj.clone().or_else(|| shape_proj.clone())
        } else {
            shape_proj.clone()
        };
        if let Some(proj) = proj {
            let policy = hook.clone();
            let budget = *timeout;
            crate::engine::hooks::spawn_bounded_tap(
                async move { policy.notify(&proj, budget).await },
            );
        }
    }
}

/// Resolve the effective `BreakerCfg` Arc for a pool: the pool's own settings when configured, else
/// a PROCESS-WIDE cached default Arc. The default is by far the common case, and the previous
/// per-request `Arc::new(clone().unwrap_or_default())` paid a heap allocation + struct clone on
/// EVERY forwarded request for a value that never changes; the cached Arc reduces that to a refcount
/// bump. Behavior is identical — the resolved thresholds are byte-for-byte the same.
pub(crate) fn resolve_breaker_cfg(
    rt: &Arc<NativeRuntime>,
    pool_name: &str,
) -> std::sync::Arc<busbar_substrate::store::BreakerCfg> {
    match EngineTables::new(rt)
        .pool_runtime()
        .get(pool_name)
        .and_then(|r| r.breaker.as_ref())
    {
        Some(cfg) => std::sync::Arc::new(cfg.clone()),
        None => {
            static DEFAULT: std::sync::OnceLock<
                std::sync::Arc<busbar_substrate::store::BreakerCfg>,
            > = std::sync::OnceLock::new();
            DEFAULT
                .get_or_init(|| std::sync::Arc::new(busbar_substrate::store::BreakerCfg::default()))
                .clone()
        }
    }
}

// The engine-level tests relocated with the engine ride `engine_tests/` (the money-path Phase 3-4 C
// relocation), not the `proxy/tests/` path core declared them at; `#[path]` is relative to `engine/`.
#[cfg(test)]
#[path = "engine_tests/inject_include_usage_tests.rs"]
mod inject_include_usage_tests;

#[cfg(test)]
#[path = "engine_tests/crossproto_delivery_billing_tests.rs"]
mod crossproto_delivery_billing_tests;

#[cfg(test)]
#[path = "engine_tests/send_envelope_tests.rs"]
mod send_envelope_tests;

#[cfg(test)]
#[path = "engine_tests/future_size_probe.rs"]
mod future_size_probe;
