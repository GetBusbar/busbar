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
    mut v: Option<LazyBody>,
    req_content_type: &str,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<busbar_api::VirtualKey>>,
    pool_name: &str,
    affinity_key: Option<&str>,
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
    usage_sink: Option<UsageSink>,
    request_id: u64,
    client_fwd: Vec<(axum::http::HeaderName, axum::http::HeaderValue)>,
) -> Response {
    let _prep = busbar_substrate::profile::start(busbar_substrate::profile::Stage::Prepare);
    let mut cands: Vec<WeightedLane> =
        match filter_cands_by_op_support(rt, cands, op, ingress_protocol) {
            Ok(kept) => kept,
            Err(resp) => return resp,
        };

    let (wants_stream, client_include_usage, client_has_stream_options) =
        capture_stream_intent(&v, op);

    if let Some(resp) = apply_request_rewrites(
        host,
        &mut v,
        &mut body,
        pool_name,
        ingress_protocol,
        op,
        wants_stream,
        request_id,
    )
    .await
    {
        return resp;
    }

    if host.any_content_hook() {
        if let Some(lazy) = v.as_mut() {
            let _ = lazy.ensure_ir(ingress_protocol, op);
        }
    }

    fire_request_taps(
        host,
        &mut v,
        &body,
        req_content_type,
        op,
        pool_name,
        ingress_protocol,
        wants_stream,
        request_id,
        resolved_gov_key,
    );

    let gemini_json_array = compute_gemini_json_array(ingress_protocol, op, &v);

    let affinity_key_hash: Option<u64> = compute_affinity_key_hash(affinity_key, &v, op);

    let (deadline_secs, max_cap) = resolve_failover_limits(rt, pool_name, &mut cands);

    let breaker_cfg: std::sync::Arc<busbar_substrate::store::BreakerCfg> =
        resolve_breaker_cfg(rt, pool_name);

    let mut request_ctx = RequestCtx::new(deadline_secs, request_id);
    request_ctx.forwarded_client_headers = client_fwd;

    let (cands, gate_order) = match reconcile_decision_gates(
        host,
        rt,
        cands,
        &mut request_ctx,
        &mut v,
        &body,
        req_content_type,
        pool_name,
        ingress_protocol,
        op,
        wants_stream,
        caller_token,
        resolved_gov_key,
    )
    .await
    {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let (policy_order, chosen_policy_name, cands) = match resolve_policy_order(
        host,
        rt,
        cands,
        &mut request_ctx,
        &mut v,
        gate_order,
        &body,
        req_content_type,
        pool_name,
        ingress_protocol,
        op,
        wants_stream,
        caller_token,
        resolved_gov_key,
    )
    .await
    {
        Ok(triple) => triple,
        Err(resp) => return resp,
    };

    let body_is_json = v.is_some();
    let stage_shape = capture_and_fire_candidate_taps(
        host,
        &mut v,
        &body,
        req_content_type,
        op,
        pool_name,
        ingress_protocol,
        wants_stream,
        request_ctx.request_id,
        cands.len(),
        resolved_gov_key,
    );

    let upstream_creds = EngineTables::new(rt).pool_upstream_creds(pool_name);

    drop(_prep);
    run_failover_dispatch(
        host,
        rt,
        cands,
        request_ctx,
        v,
        usage_sink,
        body,
        policy_order,
        stage_shape,
        affinity_key_hash,
        breaker_cfg,
        upstream_creds,
        chosen_policy_name,
        max_cap,
        pool_name,
        ingress_protocol,
        req_content_type,
        caller_token,
        resolved_gov_key,
        op,
        wants_stream,
        client_include_usage,
        client_has_stream_options,
        gemini_json_array,
        body_is_json,
    )
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

// ── forward_with_pool_parsed_inner sub-steps ─────────────────────────────────────────────────────
// The pipeline's request path was one function; these private helpers are its named sub-steps,
// lifted out verbatim so each stays readable and testable at its seam. Every one is a pure
// extract-and-split of the original inline block — same reads, same order, same envelopes — so the
// money path is byte-identical to the pre-split forward.

/// EGRESS deletion switch: every candidate lane's protocol must HOLD this operation's handler. A
/// protocol whose handler was deleted is not a valid egress for the operation — a clean no-handler
/// 404 in the CALLER's dialect, never a silent dispatch. The fast path (the norm: every registered
/// protocol serves every 1.x operation) keeps the caller's `Vec` as-is with no re-allocation; only
/// when a lane lacks the handler do we pay the filter (an all-dropped non-empty set is the same
/// no-handler 404; an initially-empty set passes through to the pool-empty 503 downstream).
fn filter_cands_by_op_support(
    rt: &Arc<NativeRuntime>,
    cands: Vec<WeightedLane>,
    op: busbar_substrate::handlers::Op,
    ingress_protocol: &str,
) -> Result<Vec<WeightedLane>, Response> {
    let supports = |wl: &WeightedLane| {
        busbar_substrate::handlers::request_handler(EngineTables::new(rt).lanes()[wl.idx].protocol)
            .and_then(|rh| rh.operation_handler(op.operation))
            .is_some()
    };
    if cands.iter().all(supports) {
        Ok(cands)
    } else {
        let kept: Vec<WeightedLane> = cands.into_iter().filter(|wl| supports(wl)).collect();
        if kept.is_empty() {
            return Err(ingress_error(
                ingress_protocol,
                StatusCode::NOT_FOUND,
                KIND_NOT_FOUND,
                DETAIL_MODEL_UNSUPPORTED_OPERATION,
            ));
        }
        Ok(kept)
    }
}

/// Capture the caller's stream intent from the ingress body BEFORE any cross-protocol translation
/// rewrites `v`. Returns `(wants_stream, client_include_usage, client_has_stream_options)`, all read
/// from the head projection where available (`probe()` is the head projection until a DOM is
/// materialized, then the DOM itself), so no DOM is forced for the common non-opt-in case. Delegated
/// to the operation: chat reads the OpenAI-family `stream` boolean + `stream_options` convention;
/// a non-streaming op (or a body lacking the keys) reads `false`. `client_include_usage` decides
/// whether the trailing usage chunk is surfaced to a client that did not opt in;
/// `client_has_stream_options` drives the byte-level upstream include_usage injection downstream.
fn capture_stream_intent(
    v: &Option<LazyBody>,
    op: busbar_substrate::handlers::Op,
) -> (bool, bool, bool) {
    let wants_stream = v
        .as_ref()
        .map(|l| op.wants_stream(l.probe()))
        .unwrap_or(false);
    let client_include_usage = wants_stream
        && v.as_ref()
            .map(|l| {
                l.probe()
                    .pointer("/stream_options/include_usage")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false)
            })
            .unwrap_or(false);
    let client_has_stream_options = wants_stream
        && v.as_ref()
            .map(|l| l.probe().get("stream_options").is_some())
            .unwrap_or(false);
    (
        wants_stream,
        client_include_usage,
        client_has_stream_options,
    )
}

/// GLOBAL REWRITE (transform) PASS. Fire the global `prompt: rw` gates (compression/redaction) then
/// the pool's own rewrite chain BEFORE dispatch AND before the routing decision, so the decision +
/// upstream both see the rewritten body. Priority-ordered, fail-safe (a broken hook is skipped, a
/// non-chat body is untouched). ZERO COST when no rewrite hook is configured. A hook's REJECT stops
/// the request here (returns the native reject envelope). A committed rewrite re-serializes `body`
/// so the same-protocol pristine short-circuit and failover hops re-parse the EFFECTIVE request;
/// a serialize failure fails CLOSED rather than leaking the un-rewritten body to a fallback lane.
/// Returns `Some(response)` on a reject/fail-closed exit, `None` to proceed.
#[allow(clippy::too_many_arguments)]
async fn apply_request_rewrites(
    host: &Arc<dyn EngineHost>,
    v: &mut Option<LazyBody>,
    body: &mut Bytes,
    pool_name: &str,
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
    wants_stream: bool,
    request_id: u64,
) -> Option<Response> {
    let pool_rewrites: &[(
        std::time::Duration,
        std::sync::Arc<dyn busbar_api::RoutingPolicy>,
    )] = host.pool_rewrites(pool_name);
    if !host.rewrite_hooks().is_empty() || !pool_rewrites.is_empty() {
        if let Some(lazy) = v.as_mut() {
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
            let Ok(parsed) = lazy.ensure_dom() else {
                diag_error!(
                    REWRITE_BODY_MATERIALIZE_FAILED,
                    "materializing the validated request body for the rewrite pass failed; \
                     rejecting rather than forwarding un-rewritten"
                );
                return Some(reject(
                    500,
                    "request rewrite could not be applied".to_string(),
                ));
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
                Err((status, message)) => return Some(reject(status, message)),
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
                Err((status, message)) => return Some(reject(status, message)),
            };
            if applied {
                match busbar_substrate::json::to_vec(parsed) {
                    Ok(bytes) => *body = Bytes::from(bytes),
                    Err(e) => {
                        diag_error!(REWRITE_RESERIALIZE_FAILED, error = %e, "re-serializing a committed rewrite failed; rejecting to avoid forwarding the un-rewritten request on failover");
                        return Some(reject(
                            500,
                            "request rewrite could not be applied".to_string(),
                        ));
                    }
                }
            }
        }
    }
    None
}

/// GLOBAL TAP (observe) FIRE. Fire the global request-stage `kind: tap` hooks FIRE-AND-FORGET after
/// the rewrite pass (so a tap observes the effective body). Each tap receives the projection its
/// GRANT allows (shape-only by default, prompt-content for a `prompt: ro` grant), so a tap never
/// over-shares; at most two projections are built regardless of tap count. A tap can NEVER delay,
/// reorder, or fail the request. ZERO COST (and zero DOM parse) when no tap is configured.
#[allow(clippy::too_many_arguments)]
fn fire_request_taps(
    host: &Arc<dyn EngineHost>,
    v: &mut Option<LazyBody>,
    body: &Bytes,
    req_content_type: &str,
    op: busbar_substrate::handlers::Op,
    pool_name: &str,
    ingress_protocol: &str,
    wants_stream: bool,
    request_id: u64,
    resolved_gov_key: Option<&std::sync::Arc<busbar_api::VirtualKey>>,
) {
    if !host.tap_hooks().is_empty() {
        if let Some(Ok(dom)) = v.as_mut().map(|l| l.ensure_dom()) {
            fire_global_taps(
                host,
                dom,
                body,
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
}

/// Gemini ingress streaming WITHOUT `?alt=sse`: the native client expects a JSON-array streamed
/// body, not SSE. Signalled via a router shim key (a captured head key — `probe()` answers without a
/// DOM). GATED on `uses_array_stream_shim` (true only for GeminiWriter) and `op.streaming()`: only a
/// genuine Gemini client can want JSON-array response framing, and a non-streaming op never frames a
/// stream. False for every other protocol and for the `?alt=sse` gemini variant.
fn compute_gemini_json_array(
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
    v: &Option<LazyBody>,
) -> bool {
    let ingress_decl = busbar_substrate::proto::decl_for(ingress_protocol);
    op.streaming()
        && ingress_decl.is_some_and(|d| d.uses_array_stream_shim)
        && ingress_decl
            .and_then(|d| d.dialect())
            .map(|di| {
                v.as_ref()
                    .map(|l| di.wants_array_stream(l.probe()))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
}

/// Derive the affinity HASH (before any mutations to `v`), from BORROWED bytes — the sticky
/// preference needs only `stable_hash(key)`, never the owned string. Prefer the supplied header key;
/// else fall back to the operation's body-derived key (chat: the top-level `system` string, a
/// captured head key — no DOM). `None` = no sticky preference.
fn compute_affinity_key_hash(
    affinity_key: Option<&str>,
    v: &Option<LazyBody>,
    op: busbar_substrate::handlers::Op,
) -> Option<u64> {
    affinity_key.map(crate::engine::stable_hash).or_else(|| {
        v.as_ref()
            .and_then(|l| op.body_affinity_key(l.probe()))
            .map(crate::engine::stable_hash)
    })
}

/// Failover config (deadline + hop cap) and the per-pool member blocklist. Prefer this pool's own
/// `failover` settings, fall back to the global default (then the ADR defaults). The blocklist is
/// removed from `cands` rather than seeded into `request_ctx.excluded`, mirroring how a gate
/// restrict narrows the set: the exhaustion paths read `cands` directly, so a blocklisted member
/// must never appear there. Returns `(deadline_secs, max_cap)`.
fn resolve_failover_limits(
    rt: &Arc<NativeRuntime>,
    pool_name: &str,
    cands: &mut Vec<WeightedLane>,
) -> (u64, usize) {
    let pool_failover = EngineTables::new(rt)
        .pool_runtime()
        .get(pool_name)
        .and_then(|r| r.failover.as_ref())
        .or(EngineTables::new(rt).failover_cfg().as_ref());
    let limits = match pool_failover {
        Some(f) => (f.timeout_secs, f.max_hops),
        None => (
            busbar_substrate::failover::DEFAULT_FAILOVER_DEADLINE_SECS,
            busbar_substrate::failover::DEFAULT_FAILOVER_CAP,
        ),
    };
    if let Some(excl) = pool_failover.and_then(|f| f.exclusions.as_ref()) {
        cands.retain(|wl| {
            !excl
                .iter()
                .any(|m| m == &EngineTables::new(rt).lanes()[wl.idx].model)
        });
    }
    limits
}

/// PHASE-2 DECISION GATES reconcile. Fire the global + pool decision gates concurrently at t0 and
/// reconcile deterministically (reject wins; else restricts intersect, persisted by shrinking
/// `cands`; else the last ordering gate wins, filtered to the surviving set). Returns the possibly
/// shrunk `cands` and the reconciled gate order, or `Err(response)` on a reject / fail-closed exit.
#[allow(clippy::too_many_arguments)]
async fn reconcile_decision_gates(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    mut cands: Vec<WeightedLane>,
    request_ctx: &mut RequestCtx,
    v: &mut Option<LazyBody>,
    body: &Bytes,
    req_content_type: &str,
    pool_name: &str,
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
    wants_stream: bool,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<busbar_api::VirtualKey>>,
) -> Result<(Vec<WeightedLane>, Option<(Vec<usize>, &'static str)>), Response> {
    let pool_gates: &[(u16, busbar_substrate::hooks::ResolvedPolicy)] = host.pool_gates(pool_name);
    let mut gate_order: Option<(Vec<usize>, &'static str)> = None;
    if !host.global_gates().is_empty() || !pool_gates.is_empty() {
        let mut chain: Vec<&(u16, busbar_substrate::hooks::ResolvedPolicy)> = host
            .global_gates()
            .iter()
            .chain(pool_gates.iter())
            .collect();
        chain.sort_by_key(|(p, _)| *p);
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
                    &*request_ctx,
                    gate_body,
                    body,
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
                    return Err(gate_rejected(ingress_error(
                        ingress_protocol,
                        StatusCode::from_u16(*status).unwrap_or(StatusCode::FORBIDDEN),
                        reject_kind_for_status(*status),
                        message,
                    )));
                }
                PolicyOutcome::Reject => {
                    return Err(gate_rejected(ingress_error(
                        ingress_protocol,
                        StatusCode::from_u16(
                            busbar_substrate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
                        )
                        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
                        KIND_OVERLOADED,
                        busbar_substrate::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
                    )));
                }
                _ => {}
            }
        }

        for outcome in &outcomes {
            if let PolicyOutcome::Restrict {
                tags_any,
                name,
                on_empty,
            } = outcome
            {
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
                        return Err(gate_rejected(ingress_error(
                            ingress_protocol,
                            StatusCode::SERVICE_UNAVAILABLE,
                            KIND_OVERLOADED,
                            "No upstream satisfies a required gate's restriction. Please retry \
                             shortly.",
                        )));
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
    Ok((cands, gate_order))
}

/// ROUTING-POLICY SEAM. When a phase-2 gate ordered, that order overrides the pool's base ordering;
/// otherwise resolve this pool's own routing policy (ZERO-COST default: no policy => SWRR, no
/// projection, no async). Coerces the policy outcome to a ranked order (`None` => SWRR) per
/// `on_error`, persisting a RESTRICT by shrinking `cands`. Returns `(policy_order,
/// chosen_policy_name, cands)`, or `Err(response)` on a reject / fail-closed exit.
#[allow(clippy::too_many_arguments)]
async fn resolve_policy_order(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    mut cands: Vec<WeightedLane>,
    request_ctx: &mut RequestCtx,
    v: &mut Option<LazyBody>,
    gate_order: Option<(Vec<usize>, &'static str)>,
    body: &Bytes,
    req_content_type: &str,
    pool_name: &str,
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
    wants_stream: bool,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<busbar_api::VirtualKey>>,
) -> Result<(Option<Vec<usize>>, Option<&'static str>, Vec<WeightedLane>), Response> {
    let mut chosen_policy_name: Option<&'static str> = None;
    let policy_order: Option<Vec<usize>> = if let Some((order, name)) = gate_order {
        chosen_policy_name = Some(name);
        Some(order)
    } else {
        match host.pool_policy(pool_name) {
            None => None,
            Some(resolved) => {
                static NULL_BODY_POLICY: Value = Value::Null;
                let policy_body: &Value = match v.as_mut() {
                    Some(l) => match l.ensure_dom() {
                        Ok(m) => &*m,
                        Err(()) => &NULL_BODY_POLICY,
                    },
                    None => &NULL_BODY_POLICY,
                };
                let outcome = Box::pin(decide_policy_order(
                    host,
                    rt,
                    resolved,
                    &cands,
                    &*request_ctx,
                    policy_body,
                    body,
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
                    PolicyOutcome::Weighted => None,
                    PolicyOutcome::Reject => {
                        return Err(gate_rejected(ingress_error(
                            ingress_protocol,
                            StatusCode::SERVICE_UNAVAILABLE,
                            KIND_OVERLOADED,
                            "The routing policy could not select an upstream. Please retry \
                             shortly.",
                        )));
                    }
                    PolicyOutcome::RejectRequest {
                        status,
                        message,
                        name,
                    } => {
                        metrics::counter!(
                            busbar_substrate::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
                            "policy" => name,
                            "pool" => pool_name.to_string(),
                            "status" => status.to_string(),
                        )
                        .increment(1);
                        diag_debug!(
                            ROUTING_POLICY_REJECTED,
                            policy = name,
                            pool = pool_name,
                            status,
                            message = %message,
                            "routing policy rejected the request"
                        );
                        return Err(gate_rejected(ingress_error(
                            ingress_protocol,
                            StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
                            reject_kind_for_status(status),
                            &message,
                        )));
                    }
                    PolicyOutcome::Restrict {
                        tags_any,
                        name,
                        on_empty,
                    } => {
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
                                return Err(gate_rejected(ingress_error(
                                    ingress_protocol,
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    KIND_OVERLOADED,
                                    "No upstream satisfies the routing policy's restriction. \
                                     Please retry shortly.",
                                )));
                            }
                        } else {
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
    Ok((policy_order, chosen_policy_name, cands))
}

/// Capture the stage-tap shape ONCE (scalars only, so it survives `v` moving into the first hop) and
/// fire the `candidate` taps: the decision reconcile + base ordering produced the FINAL candidate
/// set for dispatch. The returned `StageShape` is threaded into the dispatch loop so its per-hop
/// `routing` taps read the same captured shape. ZERO COST (and zero DOM parse) when no stage tap is
/// configured.
#[allow(clippy::too_many_arguments)]
fn capture_and_fire_candidate_taps<'a>(
    host: &Arc<dyn EngineHost>,
    v: &mut Option<LazyBody>,
    body: &Bytes,
    req_content_type: &str,
    op: busbar_substrate::handlers::Op,
    pool_name: &'a str,
    ingress_protocol: &'a str,
    wants_stream: bool,
    request_id: u64,
    remaining_candidates: usize,
    resolved_gov_key: Option<&std::sync::Arc<busbar_api::VirtualKey>>,
) -> Option<busbar_substrate::proxy::proxy_vocab::StageShape<'a>> {
    let stage_shape =
        if host.tap_hooks_candidate().is_empty() && host.tap_hooks_routing().is_empty() {
            None
        } else {
            let dom: Option<&Value> = match v.as_mut() {
                Some(l) => l.ensure_dom().ok().map(|m| &*m),
                None => None,
            };
            Some(capture_stage_shape(
                dom,
                body,
                req_content_type,
                pool_name,
                ingress_protocol,
                Some(op.operation),
                wants_stream,
                request_id,
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
                remaining_candidates: Some(remaining_candidates),
                previous_failure: None,
                outcome: None,
                status: None,
            },
            resolved_gov_key.and_then(|k| k.group.as_deref()),
            &**host,
        );
    }
    stage_shape
}

/// STAGE TAPS: routing — the full failover story per dispatch attempt (which lane, which attempt
/// number, how many candidates remain untried, and why the previous attempt failed). No-op when no
/// routing stage tap is configured (`stage_shape == None`).
#[allow(clippy::too_many_arguments)]
fn fire_routing_stage_tap(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    stage_shape: &Option<busbar_substrate::proxy::proxy_vocab::StageShape<'_>>,
    cands: &[WeightedLane],
    request_ctx: &RequestCtx,
    lane: usize,
    attempt_no: usize,
    last_failure: Option<&'static str>,
    resolved_gov_key: Option<&std::sync::Arc<busbar_api::VirtualKey>>,
) {
    if let Some(shape) = stage_shape {
        let remaining = cands
            .iter()
            .filter(|wl| !request_ctx.excluded.contains(&wl.idx))
            .count();
        fire_stage_taps(
            host.tap_hooks_routing(),
            shape,
            busbar_substrate::hooks::wire::HookStageProjection {
                at: "routing",
                model: Some(&EngineTables::new(rt).lanes()[lane].model),
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
}

/// Derive a FRESH per-hop request body for translation. Each failover hop must translate/rewrite
/// starting from the ORIGINAL request, never from a previous hop's egress-shaped body. `head_pristine`
/// hop 1 of a same-protocol JSON dispatch consumes the carried body (`*v = None`) and re-emits the
/// retained bytes verbatim; an opaque (non-JSON) body relays at the byte level (nothing to re-parse);
/// otherwise the first hop consumes the memoized DOM (or parses the validated bytes once) and failover
/// hops 2+ re-parse the retained pristine bytes. `Err(())` is the (infallible-in-practice) parse
/// failure — the caller releases any won single-flight probe, drops the permit, and returns a 500.
fn derive_hop_body(
    v: &mut Option<LazyBody>,
    head_pristine: bool,
    body_is_json: bool,
    body: &Bytes,
) -> Result<Option<Value>, ()> {
    if head_pristine {
        *v = None;
        Ok(None)
    } else if !body_is_json {
        Ok(None)
    } else {
        match v.take() {
            Some(l) => l.into_value(),
            None => busbar_substrate::json::parse(body).map_err(|_| ()),
        }
        .map(Some)
    }
}

/// On a context-length failure, the request is too large for THIS model's context window: exclude
/// every candidate whose known `context_max` is at or below the failed lane's (they share or
/// undercut the limit that just failed), so failover lands on a larger-context or unknown-context
/// member. An unknown limit on the failed lane excludes only the failed lane itself.
fn exclude_smaller_context_lanes(
    rt: &Arc<NativeRuntime>,
    request_ctx: &mut RequestCtx,
    cands: &[WeightedLane],
    failed_lane: usize,
) {
    let failed_context_max = EngineTables::new(rt).lanes()[failed_lane].context_max;
    for cand in cands {
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

/// Apply the pool's configured exhaustion mode (Status503 / FallbackPool / LeastBad) with loop
/// prevention. Called on the degraded paths (no usable lane, or candidates exhausted); the CALLER
/// `Box::pin`s this future so the cold exhaustion allocation never lands on a happy-path request.
#[allow(clippy::too_many_arguments)]
async fn run_exhaustion(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    cands: &[WeightedLane],
    pool_name: &str,
    body: Bytes,
    caller_token: Option<&str>,
    request_ctx: &mut RequestCtx,
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
    req_content_type: &str,
    usage_sink: Option<UsageSink>,
) -> Response {
    handle_exhaustion_for_pool(
        host.clone(),
        rt.clone(),
        cands,
        now(),
        pool_name,
        body,
        caller_token,
        request_ctx,
        ingress_protocol,
        op,
        req_content_type,
        usage_sink,
    )
    .await
}

/// The failover dispatch loop: pick a lane, run THE ONE attempt (assemble -> send -> classify ->
/// deliver), and decide what a failed attempt means for the walk -- until a hop delivers, the
/// deadline expires, or the candidates are exhausted (then the pool's configured exhaustion mode
/// runs). Lifted verbatim out of `forward_with_pool_parsed_inner`; every code path, order and
/// envelope is byte-identical. NOT boxed: this is the hot path, so its future stays inlined into the
/// caller exactly as the loop did (only the cold exhaustion + policy-decision arms box).
#[allow(clippy::too_many_arguments)]
async fn run_failover_dispatch<'a>(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    cands: Vec<WeightedLane>,
    mut request_ctx: RequestCtx,
    mut v: Option<LazyBody>,
    mut usage_sink: Option<UsageSink>,
    body: Bytes,
    policy_order: Option<Vec<usize>>,
    stage_shape: Option<StageShape<'a>>,
    affinity_key_hash: Option<u64>,
    breaker_cfg: std::sync::Arc<busbar_substrate::store::BreakerCfg>,
    upstream_creds: busbar_api::UpstreamCreds,
    chosen_policy_name: Option<&'static str>,
    max_cap: usize,
    pool_name: &'a str,
    ingress_protocol: &'a str,
    req_content_type: &str,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<busbar_api::VirtualKey>>,
    op: busbar_substrate::handlers::Op,
    wants_stream: bool,
    client_include_usage: bool,
    client_has_stream_options: bool,
    gemini_json_array: bool,
    body_is_json: bool,
) -> Response {
    let mut last_failure: Option<&'static str> = None;
    for attempt_no in 0..=max_cap {
        if request_ctx.expired(now()) {
            return ingress_error(
                ingress_protocol,
                StatusCode::SERVICE_UNAVAILABLE,
                KIND_OVERLOADED,
                DETAIL_REQUEST_TIMEOUT,
            );
        }

        let _pick = busbar_substrate::profile::start(busbar_substrate::profile::Stage::LanePick);
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
                    return ingress_error(
                        ingress_protocol,
                        StatusCode::SERVICE_UNAVAILABLE,
                        KIND_OVERLOADED,
                        "The service is temporarily overloaded. Please retry shortly.",
                    );
                }
                return Box::pin(run_exhaustion(
                    host,
                    rt,
                    &cands,
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
        drop(_pick);
        let _asetup =
            busbar_substrate::profile::start(busbar_substrate::profile::Stage::AttemptSetup);

        request_ctx.exclude(i);

        fire_routing_stage_tap(
            host,
            rt,
            &stage_shape,
            &cands,
            &request_ctx,
            i,
            attempt_no,
            last_failure,
            resolved_gov_key,
        );

        let metric_pool: &str = metric_pool_label(rt, pool_name, i);

        host.telemetry_upstream_attempt(metric_pool, i);
        tracing::debug!(pool = %pool_name, lane = %EngineTables::new(rt).lanes()[i].model, "upstream attempt");

        let egress_name = EngineTables::new(rt).lanes()[i].protocol;
        drop(_asetup);
        let head_pristine = ingress_protocol == egress_name
            && v.as_ref()
                .is_some_and(|l| head_provably_pristine(rt, i, l.probe()));
        let hop_v: Option<Value> = match derive_hop_body(&mut v, head_pristine, body_is_json, &body)
        {
            Ok(hv) => hv,
            Err(()) => {
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
        };

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
                    exclude_smaller_context_lanes(rt, &mut request_ctx, &cands, i);
                }
                host.telemetry_failover(metric_pool, err_type);
                last_failure = Some(err_type);
                continue;
            }
        }
    }

    Box::pin(run_exhaustion(
        host,
        rt,
        &cands,
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
#[path = "engine_tests/stream_deadline_tests.rs"]
mod stream_deadline_tests;

#[cfg(test)]
#[path = "engine_tests/future_size_probe.rs"]
mod future_size_probe;
