use super::*;
// The tracing seam: the ONE named level constant every hot-path `#[tracing::instrument]`
// in this file references, so a `#[tracing::instrument(level = "debug")]` hand-picked literal never
// re-forks the policy. `tracing::instrument`'s `level = <path>` form rejects a leading `crate`
// keyword segment (it parses a bare `Ident`/`Path`, and `crate` is not one), so the constant is
// imported here and referenced unqualified at each instrument site instead.
use axum::http::HeaderName;
use busbar_api::VirtualKey;
use busbar_kernel::observability::HOTPATH_LEVEL;
// The single neutral translate entrypoint (G6 step 4): the non-stream cross-protocol response arm
// routes its read→prepare_for_ingress→write core through `TranslateCodec::translate_response`.
use busbar_kernel::{diag_debug, diag_error};
use busbar_substrate_values::diagnostics::{
    DECISION_GATE_REJECTED, DECISION_GATE_RESTRICT_REJECT, DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE,
    REWRITE_BODY_MATERIALIZE_FAILED, REWRITE_GATE_REJECTED, REWRITE_RESERIALIZE_FAILED,
    ROUTING_POLICY_REJECTED, ROUTING_POLICY_RESTRICT_REJECT,
    ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
};

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
// (`busbar_kernel::testkit::BuiltAppSeam`, which core implements for its `App`) — so the ~81 test
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

    use busbar_kernel::testkit::BuiltAppSeam;

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn forward_with_pool<A: BuiltAppSeam + ?Sized>(
        app: &Arc<A>,
        cands: Vec<WeightedLane>,
        body: Bytes,
        caller_token: Option<&str>,
        pool_name: &str,
        affinity_key: Option<&str>,
        ingress_protocol: &str,
        op: busbar_substrate_values::handlers::Op,
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
        resolved_gov_key: Option<&std::sync::Arc<VirtualKey>>,
        pool_name: &str,
        affinity_key: Option<&str>,
        ingress_protocol: &str,
        op: busbar_substrate_values::handlers::Op,
        usage_sink: Option<UsageSink>,
        // The allowlisted client beta/version headers to forward (opt-in). A test entry that exercises
        // the forwarding path passes a collected set; every other test passes an empty Vec.
        client_fwd: Vec<(HeaderName, axum::http::HeaderValue)>,
    ) -> Response {
        // Mint the neutral host/rt the production path threads (see the module note).
        let host = busbar_kernel::testkit::engine_host(app);
        let rt = crate::engine::native_runtime_arc(host.as_ref());
        // Validate + head-project WITHOUT building a DOM (same malformed-body 400 contract as the
        // production entry — identical `LazyBody::parse` guard + parser).
        let v: LazyBody = match LazyBody::parse(&body) {
            Ok(v) => v,
            Err(_) => {
                tracing::debug!(detail = %busbar_substrate_values::json::parse_err_log(body.len()), "request body JSON parse failed");
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
    resolved_gov_key: Option<&'a std::sync::Arc<VirtualKey>>,
    pool_name: &'a str,
    affinity_key: Option<&'a str>,
    ingress_protocol: &'a str,
    op: busbar_substrate_values::handlers::Op,
    usage_sink: Option<UsageSink>,
    // The allowlisted client beta/version headers the caller ACTUALLY SENT (captured at ingress by the
    // neutral `busbar_kernel::proxy::collect_client_headers`), threaded to the egress assembly sites
    // where they are forwarded scoped to the matching egress dialect. Empty ⇒ byte-identical egress.
    client_fwd: Vec<(HeaderName, axum::http::HeaderValue)>,
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
        let _wrap = busbar_kernel::profile::start(busbar_kernel::profile::Stage::WrapSetup);
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
                busbar_kernel::hooks::wire::HookStageProjection {
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
    resolved_gov_key: Option<&std::sync::Arc<VirtualKey>>,
    pool_name: &str,
    affinity_key: Option<&str>,
    ingress_protocol: &str,
    // A request's identity is (operation, protocol): `ingress_protocol` is the wire language,
    // `op` is the kind of work. Everything below is the engine carrying that pair through pool
    // selection, failover, the breaker, and billing. The engine reads only capabilities off the
    // spec, never its identity; core's `handlers::CHAT` reproduces today's behavior byte-for-byte.
    op: busbar_substrate_values::handlers::Op,
    // Borrowed by each attempt, consumed only by the one that delivers a body (moved whole into the
    // failover loop, which owns the per-attempt borrow/take from there).
    usage_sink: Option<UsageSink>,
    // This request's correlation id, stamped ONCE by the wrapper (`forward_with_pool_parsed`)
    // before this fn was called — carried as a plain `Copy` scalar for the whole dispatch (stored on
    // `RequestCtx::request_id` below, and threaded into every hook projection built in here) rather
    // than re-derived per hop.
    request_id: u64,
    // The allowlisted client beta/version headers the caller ACTUALLY SENT, captured at ingress by the
    // neutral `busbar_kernel::proxy::collect_client_headers` against the plane's
    // `forwardable_client_header_names()` set. Stored on `RequestCtx` below so BOTH the hot path here
    // and the degraded exhaustion paths read the same set for the whole failover walk. Empty ⇒
    // nothing forwarded (byte-identical egress).
    client_fwd: Vec<(HeaderName, axum::http::HeaderValue)>,
) -> Response {
    // Stage profiler: PREPARE spans all pre-dispatch bookkeeping (op-support filter, wants_stream +
    // affinity derivation, failover/breaker config) up to the failover loop. Zero cost when
    // `BUSBAR_PROFILE` is unset — `start` returns `None` and takes no `Instant`.
    let _prep = busbar_kernel::profile::start(busbar_kernel::profile::Stage::Prepare);
    // App-retype WEDGE 3: the failover loop's telemetry emits (upstream-attempt/failure, failover) and
    // every other host reach drive through the `host: &Arc<dyn EngineHost>` threaded in — no per-call
    // `engine_host_value` mint. The borrow is the stable payload Arc, so its borrowed returns outlive
    // the await loop.
    // EGRESS deletion switch: every candidate
    // lane's protocol must HOLD this operation's handler. A protocol whose handler was deleted is
    // not a valid egress for the operation — a clean no-handler 404 in the CALLER's dialect, never a
    // silent dispatch. Dormant while all six protocols serve chat; load-bearing the moment one is
    // removed (the deletion test).
    let mut cands: Vec<WeightedLane> =
        match filter_candidates_for_op(rt, cands, op, ingress_protocol) {
            Ok(c) => c,
            Err(resp) => return resp,
        };
    // `v` is the PRISTINE parsed request body (parsed once by the caller), unmutated until the first
    // hop consumes it. Capture the caller's stream intent from the ingress body BEFORE any rewrite
    // or cross-protocol translation touches `v` (see `read_stream_intent`).
    let (wants_stream, client_include_usage, client_has_stream_options) =
        read_stream_intent(v.as_ref(), op);

    // ── GLOBAL REWRITE (transform) PASS ── fire the global + pool `prompt: rw` gates before dispatch
    // and before the routing decision, so both see the rewritten body (see `run_rewrite_pass`).
    if let Err(resp) = run_rewrite_pass(
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

    // ── REQUEST IR + GLOBAL TAP FIRE ── parse the effective (post-rewrite) request into the IR when a
    // content hook is granted, then fire the global request-stage taps fire-and-forget (see
    // `fire_request_ir_and_taps`). Both are ZERO COST when nothing is configured.
    fire_request_ir_and_taps(
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

    // Gemini JSON-array stream shim + the sticky-affinity hash, derived from the (possibly
    // DOM-materialized) body exactly where the inline reads sat (see `derive_route_signals`).
    let (gemini_json_array, affinity_key_hash) =
        derive_route_signals(v.as_ref(), op, ingress_protocol, affinity_key);

    // Failover + breaker config, the request context (carrying the client beta/version allowlist),
    // and this pool's configured member exclusions applied to `cands` (see `prepare_failover_ctx`).
    let (mut request_ctx, breaker_cfg, max_cap) =
        prepare_failover_ctx(rt, &mut cands, pool_name, request_id, client_fwd);

    // ── ROUTING-POLICY SEAM ── resolved ONCE before the loop; see `decide_routing` for the
    // phase-2 gate reconcile + base `route:` policy. ZERO COST default: `policy_order` stays None.
    let (policy_order, chosen_policy_name) = match decide_routing(
        host,
        rt,
        &mut cands,
        &mut v,
        &body,
        &mut request_ctx,
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

    // Boxed: the dispatch loop's future is the largest region of this state machine, and awaiting it
    // inline would union it into the outermost forward future (the size-probe tripwire). Boxing it
    // keeps the hot future small — the same coroutine-shrink rationale as the cold arms it contains.
    Box::pin(run_failover_loop(
        host,
        rt,
        cands,
        body,
        v,
        usage_sink,
        request_ctx,
        affinity_key_hash,
        pool_name,
        ingress_protocol,
        req_content_type,
        op,
        wants_stream,
        client_include_usage,
        client_has_stream_options,
        gemini_json_array,
        breaker_cfg,
        max_cap,
        policy_order,
        chosen_policy_name,
        caller_token,
        resolved_gov_key,
        _prep,
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
        busbar_substrate_values::json::to_vec(&busbar_kernel::hooks::wire::build(
            busbar_kernel::hooks::wire::OP_NOTIFY,
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
) -> std::sync::Arc<busbar_kernel::store::BreakerCfg> {
    match EngineTables::new(rt)
        .pool_runtime()
        .get(pool_name)
        .and_then(|r| r.breaker.as_ref())
    {
        Some(cfg) => std::sync::Arc::new(cfg.clone()),
        None => {
            static DEFAULT: std::sync::OnceLock<std::sync::Arc<busbar_kernel::store::BreakerCfg>> =
                std::sync::OnceLock::new();
            DEFAULT
                .get_or_init(|| std::sync::Arc::new(busbar_kernel::store::BreakerCfg::default()))
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
#[path = "engine_tests/stream_deadline_tests.rs"]
mod stream_deadline_tests;

#[cfg(test)]
#[path = "engine_tests/future_size_probe.rs"]
mod future_size_probe;

/// The routing-policy seam: the phase-2 decision-gate reconcile (reject/restrict/order over
/// one priority-sorted chain) then the pool's base `route:` policy, resolved ONCE before the
/// failover loop. Pure extraction of the routing block of [`forward_with_pool_parsed_inner`]:
/// mutates `cands` (restrict-intersect), `request_ctx` (active restricts) and `v` (DOM
/// materialization) exactly as the inline code did, returns `(policy_order, chosen_policy_name)`
/// on success and `Err(Response)` at each gate/policy reject. ZERO COST default path unchanged.
// `result_large_err`: `Err` is the plane's OWN finished ingress-native `Response`, handed straight
// back to the client (see the rationale on `attempt/assemble.rs::build`). Boxing it would only add
// an allocation on a gave-up path and ripple through every `?` site — behaviour-identical to leave.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
async fn decide_routing(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    cands: &mut Vec<WeightedLane>,
    v: &mut Option<LazyBody>,
    body: &Bytes,
    request_ctx: &mut RequestCtx,
    req_content_type: &str,
    pool_name: &str,
    ingress_protocol: &str,
    op: busbar_substrate_values::handlers::Op,
    wants_stream: bool,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<VirtualKey>>,
) -> Result<(Option<Vec<usize>>, Option<&'static str>), Response> {
    let gate_order = reconcile_phase2_gates(
        host,
        rt,
        cands,
        v,
        body,
        request_ctx,
        req_content_type,
        pool_name,
        ingress_protocol,
        op,
        wants_stream,
        caller_token,
        resolved_gov_key,
    )
    .await?;
    resolve_base_policy(
        host,
        rt,
        cands,
        v,
        request_ctx,
        body,
        req_content_type,
        pool_name,
        ingress_protocol,
        op,
        wants_stream,
        caller_token,
        resolved_gov_key,
        gate_order,
    )
    .await
}

/// The failover walk: pick a lane, dispatch one `attempt`, and on a failed attempt fail over
/// to the next candidate until one delivers, the candidates exhaust, or the deadline expires.
/// Pure extraction of the dispatch loop of [`forward_with_pool_parsed_inner`]; it owns the
/// mutable dispatch state (`cands`, `body`, `v`, `usage_sink`, `request_ctx`) the loop consumes
/// and drops `_prep` at the same point the inline code did (PREPARE ends, dispatch begins).
#[allow(clippy::too_many_arguments)]
async fn run_failover_loop(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    mut v: Option<LazyBody>,
    mut usage_sink: Option<UsageSink>,
    mut request_ctx: RequestCtx,
    affinity_key_hash: Option<u64>,
    pool_name: &str,
    ingress_protocol: &str,
    req_content_type: &str,
    op: busbar_substrate_values::handlers::Op,
    wants_stream: bool,
    client_include_usage: bool,
    client_has_stream_options: bool,
    gemini_json_array: bool,
    breaker_cfg: std::sync::Arc<busbar_kernel::store::BreakerCfg>,
    max_cap: usize,
    policy_order: Option<Vec<usize>>,
    chosen_policy_name: Option<&'static str>,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<VirtualKey>>,
    _prep: Option<busbar_kernel::profile::Timer>,
) -> Response {
    let body_is_json = v.is_some();
    // Candidate stage shape captured ONCE (scalars only, so it survives `v` moving into the first
    // hop) and the `candidate` taps fired now, over the FINAL candidate set (see
    // `capture_candidate_taps`). ZERO COST when no stage tap is configured.
    let stage_shape = capture_candidate_taps(
        host,
        &mut v,
        &body,
        req_content_type,
        pool_name,
        ingress_protocol,
        op,
        wants_stream,
        request_ctx.request_id,
        cands.len(),
        resolved_gov_key,
    );
    // Why the PREVIOUS attempt failed — feeds the routing-stage tap payload (the failover story).
    let mut last_failure: Option<&'static str> = None;

    // Upstream-credential mode for THIS pool, resolved ONCE and carried as a `Copy` scalar for the
    // whole dispatch (invariant across every failover hop), so the hot egress path pays a single
    // register read rather than a per-attempt `pool_upstream_creds` map probe.
    let upstream_creds = EngineTables::new(rt).pool_upstream_creds(pool_name);

    // PREPARE ends here (dispatch loop begins). From here on, `v` IS the first-hop body: the loop
    // consumes it on hop 1 (`v.take()` / the pristine short-circuit) and failover hops 2+ re-parse
    // the retained `body` bytes.
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

        let (i, permit, probe_epoch) = match pick_lane_or_exhaust(
            host,
            rt,
            &cands,
            &mut request_ctx,
            affinity_key_hash,
            pool_name,
            policy_order.as_deref(),
            &body,
            caller_token,
            ingress_protocol,
            op,
            req_content_type,
            &usage_sink,
        )
        .await
        {
            Ok(x) => x,
            Err(resp) => return resp,
        };
        // ATTEMPT_SETUP: per-hop bookkeeping between lane_pick and the attempt.
        let _asetup = busbar_kernel::profile::start(busbar_kernel::profile::Stage::AttemptSetup);
        let (metric_pool, egress_name) = prepare_attempt(
            host,
            rt,
            stage_shape.as_ref(),
            &cands,
            &mut request_ctx,
            i,
            attempt_no,
            last_failure,
            resolved_gov_key,
            pool_name,
        );
        drop(_asetup);
        if let Some(resp) = run_hop(
            host,
            rt,
            i,
            pool_name,
            &cands,
            &mut v,
            &body,
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
            &mut request_ctx,
            &breaker_cfg,
            chosen_policy_name,
            metric_pool,
            permit,
            probe_epoch,
            &mut usage_sink,
            &mut last_failure,
        )
        .await
        {
            return resp;
        }
    }

    // Candidates exhausted: apply the configured exhaustion mode.
    exhaust_pool(
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
    )
    .await
}

/// LANE_PICK for one failover hop, extracted straight out of [`run_failover_loop`]'s dispatch
/// loop (pure extraction — no behavior change; see its call site for why). Runs `pick_among` under
/// its own profiling span and turns a miss into the SAME terminal `Response` the inline code
/// returned: the plain "no members" 503 when the pool is empty, or the configured exhaustion mode
/// otherwise. `Ok` is a picked lane ready for [`prepare_attempt`]; `Err` is the response the loop
/// must return immediately, in place of the `return` the inline code used to make here.
#[allow(clippy::too_many_arguments)]
async fn pick_lane_or_exhaust(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    cands: &[WeightedLane],
    request_ctx: &mut RequestCtx,
    affinity_key_hash: Option<u64>,
    pool_name: &str,
    policy_order: Option<&[usize]>,
    body: &Bytes,
    caller_token: Option<&str>,
    ingress_protocol: &str,
    op: busbar_substrate_values::handlers::Op,
    req_content_type: &str,
    usage_sink: &Option<UsageSink>,
) -> Result<(usize, Permit, Option<u64>), Response> {
    let _pick = busbar_kernel::profile::start(busbar_kernel::profile::Stage::LanePick);
    // `probe_epoch`: `Some(epoch)` when this pick WON a single-flight recovery probe (captured
    // synchronously by `pick_among` before any await), `None` otherwise. The RAII release covers
    // the WHOLE dispatch window (built inside `attempt`), including a dropped future.
    match pick_among(
        host,
        rt,
        cands,
        request_ctx,
        affinity_key_hash,
        pool_name,
        policy_order,
    )
    .await
    {
        Some(x) => Ok(x),
        None => {
            if cands.is_empty() {
                // Pool has no members at all — nothing to do.
                return Err(ingress_error(
                    ingress_protocol,
                    StatusCode::SERVICE_UNAVAILABLE,
                    KIND_OVERLOADED,
                    "The service is temporarily overloaded. Please retry shortly.",
                ));
            }
            // No usable lane — apply the configured exhaustion mode with loop prevention. `body` is
            // cheap-cloned (a `Bytes` clone is a refcount bump, not a copy): the caller still owns
            // its `body` for the hop it dispatches once a lane IS picked, so this cannot take it.
            Err(exhaust_pool(
                host,
                rt,
                cands,
                pool_name,
                body.clone(),
                caller_token,
                request_ctx,
                ingress_protocol,
                op,
                req_content_type,
                usage_sink.clone(),
            )
            .await)
        }
    }
}

/// ATTEMPT_SETUP for one failover hop, extracted straight out of [`run_failover_loop`]'s dispatch
/// loop (pure extraction — no behavior change): mark the picked lane excluded, fire the routing
/// stage tap, and resolve this hop's metric `pool` label and egress protocol name — the bookkeeping
/// between [`pick_lane_or_exhaust`] and the attempt itself. Returns `(metric_pool, egress_name)` for
/// `run_hop`.
#[allow(clippy::too_many_arguments)]
fn prepare_attempt<'a>(
    host: &Arc<dyn EngineHost>,
    rt: &'a Arc<NativeRuntime>,
    stage_shape: Option<&StageShape<'_>>,
    cands: &[WeightedLane],
    request_ctx: &mut RequestCtx,
    i: usize,
    attempt_no: usize,
    last_failure: Option<&'static str>,
    resolved_gov_key: Option<&std::sync::Arc<VirtualKey>>,
    pool_name: &'a str,
) -> (&'a str, &'static str) {
    // Mark this lane as excluded for future attempts in this request
    request_ctx.exclude(i);

    // ── STAGE TAPS: routing ── the full failover story, per dispatch attempt (see
    // `fire_routing_tap`).
    fire_routing_tap(
        host,
        rt,
        stage_shape,
        cands,
        request_ctx,
        i,
        attempt_no,
        last_failure,
        resolved_gov_key,
    );

    // The bounded `pool` LABEL for THIS hop's upstream/failover/breaker metrics.
    let metric_pool: &str = metric_pool_label(rt, pool_name, i);

    // count this upstream attempt (re-entrant across failover hops — each is a real attempt).
    host.telemetry_upstream_attempt(metric_pool, i);
    tracing::debug!(pool = %pool_name, lane = %EngineTables::new(rt).lanes()[i].model, "upstream attempt");

    let egress_name = EngineTables::new(rt).lanes()[i].protocol;
    (metric_pool, egress_name)
}

/// The op-support candidate filter: every candidate lane's protocol must HOLD this operation's
/// handler (a deleted handler is not a valid egress — a clean no-handler 404). Fast path keeps
/// the caller's Vec as-is; `Err` is the ingress-native 404 when the filter empties a non-empty set.
// `result_large_err`: `Err` is the plane's own finished `Response`, returned as-is (see `assemble.rs`).
#[allow(clippy::result_large_err)]
fn filter_candidates_for_op(
    rt: &Arc<NativeRuntime>,
    cands: Vec<WeightedLane>,
    op: busbar_substrate_values::handlers::Op,
    ingress_protocol: &str,
) -> Result<Vec<WeightedLane>, Response> {
    let supports = |wl: &WeightedLane| {
        busbar_substrate_values::handlers::request_handler(
            EngineTables::new(rt).lanes()[wl.idx].protocol,
        )
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

/// The caller's stream intent, read off the ingress head projection BEFORE any rewrite touches
/// `v`: `(wants_stream, client_include_usage, client_has_stream_options)`. Byte-identical to the
/// inline reads; `probe()` answers without materializing the DOM in the common case.
fn read_stream_intent(
    v: Option<&LazyBody>,
    op: busbar_substrate_values::handlers::Op,
) -> (bool, bool, bool) {
    let wants_stream = v.map(|l| op.wants_stream(l.probe())).unwrap_or(false);
    let client_include_usage = wants_stream
        && v.map(|l| {
            l.probe()
                .pointer("/stream_options/include_usage")
                .and_then(|b| b.as_bool())
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let client_has_stream_options = wants_stream
        && v.map(|l| l.probe().get("stream_options").is_some())
            .unwrap_or(false);
    (
        wants_stream,
        client_include_usage,
        client_has_stream_options,
    )
}

/// The GLOBAL rewrite (transform) pass: fire the global then pool `prompt: rw` gates over the DOM,
/// re-serialize the retained `body` bytes when a rewrite commits (so the pristine short-circuit and
/// failover re-parse see the effective request), and reject fail-closed. Pure extraction; ZERO COST
/// when no rewrite hook is configured. `Err` is the ingress-native gate rejection.
// `result_large_err`: `Err` is the plane's own finished `Response`, returned as-is (see `assemble.rs`).
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
async fn run_rewrite_pass(
    host: &Arc<dyn EngineHost>,
    v: &mut Option<LazyBody>,
    body: &mut Bytes,
    pool_name: &str,
    ingress_protocol: &str,
    op: busbar_substrate_values::handlers::Op,
    wants_stream: bool,
    request_id: u64,
) -> Result<(), Response> {
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
                return Err(reject(
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
                Err((status, message)) => return Err(reject(status, message)),
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
                Err((status, message)) => return Err(reject(status, message)),
            };
            // A committed rewrite makes the RETAINED bytes stale: the same-protocol pristine
            // short-circuit re-emits them verbatim, and failover hops 2+ re-parse them — either
            // path would silently discard the rewrite. Re-serialize the rewritten body as the new
            // retained bytes so every downstream reader of `body` sees the effective request.
            // Cost only on the rewrite path (a no-op request never reaches this serialize).
            if applied {
                match busbar_substrate_values::json::to_vec(parsed) {
                    Ok(bytes) => *body = Bytes::from(bytes),
                    // A `prompt: rw` rewrite is a TRUSTED, possibly security-critical transform. If it
                    // cannot be serialized into the retained bytes, the first hop carries it but every
                    // FAILOVER hop (which re-parses `body`) would forward the ORIGINAL un-rewritten
                    // request — fail-OPEN on the rewrite guarantee. Fail CLOSED: reject rather than
                    // leak the un-rewritten body to a fallback lane. (Not realistically reachable;
                    // defense-in-depth for the rewrite invariant.)
                    Err(e) => {
                        diag_error!(REWRITE_RESERIALIZE_FAILED, error = %e, "re-serializing a committed rewrite failed; rejecting to avoid forwarding the un-rewritten request on failover");
                        return Err(reject(
                            500,
                            "request rewrite could not be applied".to_string(),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// REQUEST IR materialization (when a content hook is granted) then the GLOBAL request-stage tap
/// fire (fire-and-forget, after the rewrite pass so taps observe the effective body). Both branches
/// are ZERO COST when nothing is configured. Pure extraction of the inline IR + tap blocks.
#[allow(clippy::too_many_arguments)]
fn fire_request_ir_and_taps(
    host: &Arc<dyn EngineHost>,
    v: &mut Option<LazyBody>,
    body: &Bytes,
    req_content_type: &str,
    op: busbar_substrate_values::handlers::Op,
    pool_name: &str,
    ingress_protocol: &str,
    wants_stream: bool,
    request_id: u64,
    resolved_gov_key: Option<&std::sync::Arc<VirtualKey>>,
) {
    if host.any_content_hook() {
        if let Some(lazy) = v.as_mut() {
            let _ = lazy.ensure_ir(ingress_protocol, op);
        }
    }
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

/// The Gemini JSON-array stream shim flag and the sticky-affinity hash, derived from the ingress
/// body head projection. Byte-identical to the inline reads (gated on `uses_array_stream_shim` +
/// `op.streaming()`; affinity prefers the header key, else the op's body-derived key).
fn derive_route_signals(
    v: Option<&LazyBody>,
    op: busbar_substrate_values::handlers::Op,
    ingress_protocol: &str,
    affinity_key: Option<&str>,
) -> (bool, Option<u64>) {
    let ingress_decl = busbar_kernel::proto::decl_for(ingress_protocol);
    let gemini_json_array = op.streaming()
        && ingress_decl.is_some_and(|d| d.uses_array_stream_shim)
        && ingress_decl
            .and_then(|d| d.dialect())
            .map(|di| v.map(|l| di.wants_array_stream(l.probe())).unwrap_or(false))
            .unwrap_or(false);
    let affinity_key_hash: Option<u64> =
        affinity_key.map(crate::engine::stable_hash).or_else(|| {
            v.and_then(|l| op.body_affinity_key(l.probe()))
                .map(crate::engine::stable_hash)
        });
    (gemini_json_array, affinity_key_hash)
}

/// Failover + breaker config for this pool (own settings else defaults), the `RequestCtx` carrying
/// the ingress-collected client beta/version allowlist across the whole walk, and this pool's
/// configured member exclusions applied to `cands`. Returns `(request_ctx, breaker_cfg, max_cap)`.
fn prepare_failover_ctx(
    rt: &Arc<NativeRuntime>,
    cands: &mut Vec<WeightedLane>,
    pool_name: &str,
    request_id: u64,
    client_fwd: Vec<(HeaderName, axum::http::HeaderValue)>,
) -> (
    RequestCtx,
    std::sync::Arc<busbar_kernel::store::BreakerCfg>,
    usize,
) {
    let pool_failover = EngineTables::new(rt)
        .pool_runtime()
        .get(pool_name)
        .and_then(|r| r.failover.as_ref())
        .or(EngineTables::new(rt).failover_cfg().as_ref());
    let (deadline_secs, max_cap) = match pool_failover {
        Some(f) => (f.timeout_secs, f.max_hops),
        None => (
            busbar_kernel::failover::DEFAULT_FAILOVER_DEADLINE_SECS,
            busbar_kernel::failover::DEFAULT_FAILOVER_CAP,
        ),
    };
    let breaker_cfg: std::sync::Arc<busbar_kernel::store::BreakerCfg> =
        resolve_breaker_cfg(rt, pool_name);
    let mut request_ctx = RequestCtx::new(deadline_secs, request_id);
    request_ctx.forwarded_client_headers = client_fwd;
    if let Some(excl) = pool_failover.and_then(|f| f.exclusions.as_ref()) {
        cands.retain(|wl| {
            !excl
                .iter()
                .any(|m| m == &EngineTables::new(rt).lanes()[wl.idx].model)
        });
    }
    (request_ctx, breaker_cfg, max_cap)
}

/// PHASE-2 DECISION GATES: fire the global + pool decision gates CONCURRENTLY at t0, then reconcile
/// over one priority-sorted chain — reject wins (first in chain surfaces), else restricts intersect
/// (see `apply_gate_restricts`), else the last ordering gate wins re-validated against the surviving
/// set. Returns the winning gate order (`None` = abstain to the base policy). ZERO COST when no gate
/// is configured. `Err` is the ingress-native gate rejection.
// `result_large_err`: `Err` is the plane's own finished `Response`, returned as-is (see `assemble.rs`).
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
async fn reconcile_phase2_gates(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    cands: &mut Vec<WeightedLane>,
    v: &mut Option<LazyBody>,
    body: &Bytes,
    request_ctx: &mut RequestCtx,
    req_content_type: &str,
    pool_name: &str,
    ingress_protocol: &str,
    op: busbar_substrate_values::handlers::Op,
    wants_stream: bool,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<VirtualKey>>,
) -> Result<Option<(Vec<usize>, &'static str)>, Response> {
    let pool_gates: &[(u16, busbar_kernel::hooks::ResolvedPolicy)] = host.pool_gates(pool_name);
    let mut gate_order: Option<(Vec<usize>, &'static str)> = None;
    if !host.global_gates().is_empty() || !pool_gates.is_empty() {
        // The chain: globals (pre-sorted ascending by priority) then pool gates (config order),
        // stable-sorted by priority — ties keep globals-first, then config order.
        let mut chain: Vec<&(u16, busbar_kernel::hooks::ResolvedPolicy)> = host
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
                    cands.as_slice(),
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
                        busbar_kernel::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
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
                    // The refusal a load-bearing hook's FAILED call produces — the SAME status,
                    // kind and message the read-write (transform) seat renders for the same
                    // condition, from the same constants, so a caller cannot tell which seat's
                    // hook was down.
                    return Err(gate_rejected(ingress_error(
                        ingress_protocol,
                        StatusCode::from_u16(
                            busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
                        )
                        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
                        KIND_OVERLOADED,
                        busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
                    )));
                }
                _ => {}
            }
        }

        // Reconcile 2: RESTRICTS INTERSECT in chain order (see `apply_gate_restricts`).
        apply_gate_restricts(
            rt,
            cands,
            request_ctx,
            pool_name,
            ingress_protocol,
            &outcomes,
        )?;

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
                busbar_kernel::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
                "policy" => *name,
                "pool" => pool_name.to_string(),
            )
            .increment(1);
        }
    }

    Ok(gate_order)
}

/// Reconcile 2 of the phase-2 gates: RESTRICTS INTERSECT in chain order (intersection commutes; the
/// order only decides whose `on_empty` applies first when the set empties). Shrinks `cands` so the
/// restriction persists across failover, records each restrict on `request_ctx`, and fails closed
/// (`Err`) when a required restrict leaves no eligible lane.
// `result_large_err`: `Err` is the plane's own finished `Response`, returned as-is (see `assemble.rs`).
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
fn apply_gate_restricts(
    rt: &Arc<NativeRuntime>,
    cands: &mut Vec<WeightedLane>,
    request_ctx: &mut RequestCtx,
    pool_name: &str,
    ingress_protocol: &str,
    outcomes: &[PolicyOutcome],
) -> Result<(), Response> {
    for outcome in outcomes {
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
                if matches!(on_empty, busbar_kernel::config::PolicyOnError::Weighted) {
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
                        busbar_kernel::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
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
                *cands = restricted;
                metrics::counter!(
                    busbar_kernel::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
                    "policy" => *name,
                    "pool" => pool_name.to_string(),
                )
                .increment(1);
            }
        }
    }
    Ok(())
}

/// The pool's BASE routing policy, applied only when no phase-2 gate ordered: a phase-2 `gate_order`
/// overrides directly, else the resolved `route:` policy (default `None` ⇒ SWRR) produces a ranked
/// order / abstains / rejects / restricts. Returns `(policy_order, chosen_policy_name)`; `Err` is the
/// ingress-native policy rejection. ZERO COST default path unchanged (single always-false branch).
// `result_large_err`: `Err` is the plane's own finished `Response`, returned as-is (see `assemble.rs`).
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
async fn resolve_base_policy(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    cands: &mut Vec<WeightedLane>,
    v: &mut Option<LazyBody>,
    request_ctx: &mut RequestCtx,
    body: &Bytes,
    req_content_type: &str,
    pool_name: &str,
    ingress_protocol: &str,
    op: busbar_substrate_values::handlers::Op,
    wants_stream: bool,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<VirtualKey>>,
    gate_order: Option<(Vec<usize>, &'static str)>,
) -> Result<(Option<Vec<usize>>, Option<&'static str>), Response> {
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
                    cands.as_slice(),
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
                let (order, chosen) = apply_policy_outcome(
                    outcome,
                    rt,
                    cands,
                    request_ctx,
                    pool_name,
                    ingress_protocol,
                )?;
                if chosen.is_some() {
                    chosen_policy_name = chosen;
                }
                order
            }
        }
    };
    Ok((policy_order, chosen_policy_name))
}

/// The `PolicyOutcome` match, extracted straight out of [`resolve_base_policy`] (pure extraction —
/// no behavior change; see its call site). Turns a decided [`PolicyOutcome`] into the ranked order
/// (or `None` ⇒ SWRR) plus the policy name to advertise, exactly as the inline `match` did; `Err` is
/// the same ingress-native rejection the inline code returned early with.
fn apply_policy_outcome(
    outcome: PolicyOutcome,
    rt: &Arc<NativeRuntime>,
    cands: &mut Vec<WeightedLane>,
    request_ctx: &mut RequestCtx,
    pool_name: &str,
    ingress_protocol: &str,
) -> Result<(Option<Vec<usize>>, Option<&'static str>), Response> {
    match outcome {
        // The policy returned a usable ranked order — record its name (for the
        // `x-busbar-route-policy` header + the metric) and hand the order to the ordered walk.
        PolicyOutcome::Order { order, name } => {
            metrics::counter!(
                busbar_kernel::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
                "policy" => name,
                "pool" => pool_name.to_string(),
            )
            .increment(1);
            Ok((Some(order), Some(name)))
        }
        // Abstain / error-coerced-to-weighted: fall through to today's exact SWRR.
        PolicyOutcome::Weighted => Ok((None, None)),
        // on_error == reject (and the policy errored/timed out / saturated): fail closed with a
        // 503 rather than silently degrading. Never strands as a hang — a clean rejection.
        PolicyOutcome::Reject => Err(gate_rejected(ingress_error(
            ingress_protocol,
            StatusCode::SERVICE_UNAVAILABLE,
            KIND_OVERLOADED,
            "The routing policy could not select an upstream. Please retry \
             shortly.",
        ))),
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
                busbar_kernel::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
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
            Err(gate_rejected(ingress_error(
                ingress_protocol,
                StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
                reject_kind_for_status(status),
                &message,
            )))
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
            // The base routing-policy RESTRICT verb (see `apply_base_policy_restrict`):
            // it commits the survivor set on `cands`, records the restrict, and returns
            // the policy name to advertise (or `None` on a weighted escape). SWRR then
            // picks among the survivors, so the base order stays `None`.
            let chosen = apply_base_policy_restrict(
                rt,
                cands,
                request_ctx,
                pool_name,
                ingress_protocol,
                tags_any,
                name,
                on_empty,
            )?;
            Ok((None, chosen))
        }
    }
}

/// The base routing-policy RESTRICT verb: intersect `cands` with members carrying one of `tags_any`,
/// commit the survivors so the restriction PERSISTS across every failover hop, and record it on
/// `request_ctx` (so it survives a `fallback_pool` hop too). An EMPTY intersection is fail-closed
/// (`on_empty` default reject) unless `Weighted` (the advisory full-pool SWRR escape). Returns the
/// policy name to advertise on a commit, `None` on a weighted escape, and `Err` on a fail-closed 503.
// `result_large_err`: `Err` is the plane's own finished `Response`, returned as-is (see `assemble.rs`).
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
fn apply_base_policy_restrict(
    rt: &Arc<NativeRuntime>,
    cands: &mut Vec<WeightedLane>,
    request_ctx: &mut RequestCtx,
    pool_name: &str,
    ingress_protocol: &str,
    tags_any: Vec<String>,
    name: &'static str,
    on_empty: busbar_kernel::config::PolicyOnError,
) -> Result<Option<&'static str>, Response> {
    request_ctx.active_restricts.push(RestrictConstraint {
        tags_any: tags_any.clone(),
        on_empty: on_empty.clone(),
        name,
    });
    let members = EngineTables::new(rt)
        .pool_runtime()
        .get(pool_name)
        .map(|r| &r.members);
    // Filter into a temp so the ORIGINAL `cands` survives for a weighted on_empty escape; only
    // commit the restriction when the intersection is non-empty.
    let restricted: Vec<WeightedLane> = cands
        .iter()
        .filter(|wl| {
            members
                .and_then(|m| m.get(&wl.idx))
                .is_some_and(|meta| meta.tags.iter().any(|t| tags_any.iter().any(|w| w == t)))
        })
        .cloned()
        .collect();
    if restricted.is_empty() {
        // Empty intersection → the gate's `on_empty`. `Weighted` is the advisory escape (leave
        // `cands` as the full pool → SWRR); default (and `First`, which has no eligible "first") is
        // fail-closed reject.
        if matches!(on_empty, busbar_kernel::config::PolicyOnError::Weighted) {
            diag_debug!(
                ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
                policy = name,
                pool = pool_name,
                "routing policy restrict left no eligible lane; on_empty: weighted \
                 escape to full-pool SWRR"
            );
            Ok(None)
        } else {
            metrics::counter!(
                busbar_kernel::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
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
            Err(gate_rejected(ingress_error(
                ingress_protocol,
                StatusCode::SERVICE_UNAVAILABLE,
                KIND_OVERLOADED,
                "No upstream satisfies the routing policy's restriction. \
                 Please retry shortly.",
            )))
        }
    } else {
        // Commit the restriction: shrink `cands` to the survivors so it PERSISTS across every
        // failover hop, then let SWRR pick among them.
        *cands = restricted;
        metrics::counter!(
            busbar_kernel::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
            "policy" => name,
            "pool" => pool_name.to_string(),
        )
        .increment(1);
        Ok(Some(name))
    }
}

/// Capture the candidate stage shape ONCE (scalars, so it survives `v` moving into the first hop)
/// and fire the `candidate` stage taps over the final candidate set. Returns the shape (reused for
/// the per-hop routing taps). ZERO COST — and no DOM parse — when no stage tap is configured.
#[allow(clippy::too_many_arguments)]
fn capture_candidate_taps<'a>(
    host: &Arc<dyn EngineHost>,
    v: &mut Option<LazyBody>,
    body: &[u8],
    req_content_type: &str,
    pool_name: &'a str,
    ingress_protocol: &'a str,
    op: busbar_substrate_values::handlers::Op,
    wants_stream: bool,
    request_id: u64,
    cands_len: usize,
    resolved_gov_key: Option<&std::sync::Arc<VirtualKey>>,
) -> Option<StageShape<'a>> {
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
            busbar_kernel::hooks::wire::HookStageProjection {
                at: "candidate",
                model: None,
                attempt_number: None,
                remaining_candidates: Some(cands_len),
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

/// Fire the `routing` stage tap for one dispatch attempt: which lane, attempt number, how many
/// candidates remain untried, and why the previous attempt failed (`None` on the first). ZERO COST
/// when no routing tap is configured (`stage_shape` is `None`).
#[allow(clippy::too_many_arguments)]
fn fire_routing_tap(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    stage_shape: Option<&StageShape<'_>>,
    cands: &[WeightedLane],
    request_ctx: &RequestCtx,
    i: usize,
    attempt_no: usize,
    last_failure: Option<&'static str>,
    resolved_gov_key: Option<&std::sync::Arc<VirtualKey>>,
) {
    if let Some(shape) = stage_shape {
        let remaining = cands
            .iter()
            .filter(|wl| !request_ctx.excluded.contains(&wl.idx))
            .count();
        fire_stage_taps(
            host.tap_hooks_routing(),
            shape,
            busbar_kernel::hooks::wire::HookStageProjection {
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
}

/// Derive the FRESH per-hop request DOM. `head_pristine` consumes the hop-1 body (re-emit verbatim,
/// no DOM); an opaque (non-JSON) body has nothing to re-parse; otherwise consume the carried DOM on
/// hop 1 or re-parse the retained pristine bytes on failover hops. `Err(())` is the (infallible in
/// practice) parse failure the caller turns into a pre-dispatch 500.
fn derive_hop_body(
    v: &mut Option<LazyBody>,
    body: &Bytes,
    body_is_json: bool,
    head_pristine: bool,
) -> Result<Option<Value>, ()> {
    if head_pristine {
        *v = None;
        Ok(None)
    } else if !body_is_json {
        Ok(None)
    } else {
        let parsed = match v.take() {
            Some(l) => l.into_value(),
            None => busbar_substrate_values::json::parse(body).map_err(|_| ()),
        };
        match parsed {
            Ok(hv) => Ok(Some(hv)),
            Err(()) => Err(()),
        }
    }
}

/// On a ContextLength failure, exclude every candidate whose known `context_max` is at or below the
/// failed lane's (they share or undercut the limit that just failed), so failover lands on a
/// larger-context or unknown-context member. An unknown limit on the failed lane excludes nothing new.
fn exclude_smaller_context_lanes(
    rt: &Arc<NativeRuntime>,
    cands: &[WeightedLane],
    request_ctx: &mut RequestCtx,
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

/// THE ONE ATTEMPT for this hop: assemble the `Hop` view and run `attempt` (assemble, send, classify,
/// deliver). Pure extraction of the loop's per-hop dispatch — same `AttemptInput` the inline code
/// built, so the outcome is identical.
#[allow(clippy::too_many_arguments)]
async fn dispatch_hop(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    pool_name: &str,
    cands: &[WeightedLane],
    body: &Bytes,
    head_pristine: bool,
    body_is_json: bool,
    req_content_type: &str,
    ingress_protocol: &str,
    egress_name: &str,
    op: busbar_substrate_values::handlers::Op,
    wants_stream: bool,
    client_include_usage: bool,
    client_has_stream_options: bool,
    gemini_json_array: bool,
    caller_token: Option<&str>,
    upstream_creds: busbar_api::UpstreamCreds,
    resolved_gov_key: Option<&Arc<VirtualKey>>,
    request_ctx: &RequestCtx,
    breaker_cfg: &Arc<busbar_kernel::store::BreakerCfg>,
    chosen_policy_name: Option<&'static str>,
    metric_pool: &str,
    permit: Permit,
    probe_epoch: Option<u64>,
    hop_v: Option<Value>,
    usage_sink: &mut Option<UsageSink>,
) -> AttemptOutcome {
    attempt(AttemptInput {
        hop: Hop {
            host,
            rt,
            lane: i,
            pool_cell: pool_name,
            cands,
            body,
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
            breaker_cfg,
            client_fwd: &request_ctx.forwarded_client_headers,
            chosen_policy_name,
            metric_pool,
            degraded: false,
        },
        permit,
        probe_epoch,
        hop_v,
        usage_sink,
    })
    .await
}

/// Candidate exhaustion for this pool: apply the configured mode (Status503 / FallbackPool /
/// LeastBad) with loop prevention. Boxed for the coroutine-size reason the inline calls were — the
/// happy path never allocates here. Consumes `body`/`usage_sink` exactly as the inline calls did.
#[allow(clippy::too_many_arguments)]
async fn exhaust_pool(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    cands: &[WeightedLane],
    pool_name: &str,
    body: Bytes,
    caller_token: Option<&str>,
    request_ctx: &mut RequestCtx,
    ingress_protocol: &str,
    op: busbar_substrate_values::handlers::Op,
    req_content_type: &str,
    usage_sink: Option<UsageSink>,
) -> Response {
    Box::pin(handle_exhaustion_for_pool(
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
    ))
    .await
}

/// One hop of the failover walk after a lane is picked: derive the per-hop body, dispatch the
/// attempt, and classify the outcome. Returns `Some(response)` to return from the loop (a delivered
/// body, a bail, or the pre-dispatch parse-failure 500) and `None` to fail over to the next
/// candidate (recording the failover telemetry and, on ContextLength, excluding smaller-context
/// lanes). Pure extraction of the loop's per-hop tail.
#[allow(clippy::too_many_arguments)]
async fn run_hop(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    pool_name: &str,
    cands: &[WeightedLane],
    v: &mut Option<LazyBody>,
    body: &Bytes,
    body_is_json: bool,
    req_content_type: &str,
    ingress_protocol: &str,
    egress_name: &str,
    op: busbar_substrate_values::handlers::Op,
    wants_stream: bool,
    client_include_usage: bool,
    client_has_stream_options: bool,
    gemini_json_array: bool,
    caller_token: Option<&str>,
    upstream_creds: busbar_api::UpstreamCreds,
    resolved_gov_key: Option<&Arc<VirtualKey>>,
    request_ctx: &mut RequestCtx,
    breaker_cfg: &Arc<busbar_kernel::store::BreakerCfg>,
    chosen_policy_name: Option<&'static str>,
    metric_pool: &str,
    permit: Permit,
    probe_epoch: Option<u64>,
    usage_sink: &mut Option<UsageSink>,
    last_failure: &mut Option<&'static str>,
) -> Option<Response> {
    // REQUEST SHORT-CIRCUIT WITHOUT A DOM: hop 1 of a SAME-protocol JSON dispatch whose head
    // projection PROVES no same-proto invalidator fires re-emits the retained bytes verbatim —
    // byte-identical to the translate seam's own pristine short-circuit — without materializing
    // the `Value` tree. `head_provably_pristine` is one-sided; any doubt falls through.
    let head_pristine = ingress_protocol == egress_name
        && v.as_ref()
            .is_some_and(|l| head_provably_pristine(rt, i, l.probe()));
    // Derive a FRESH per-hop body (see `derive_hop_body`); each failover hop translates from the
    // ORIGINAL request, never a previous hop's egress-shaped body.
    let hop_v: Option<Value> = match derive_hop_body(v, body, body_is_json, head_pristine) {
        Ok(hv) => hv,
        // `body` already validated/parsed once successfully; this is infallible. Pre-dispatch bail
        // (no breaker outcome): release any probe this pick won, owner-checked, so a recovering lane
        // never wedges HalfOpen on this early exit.
        Err(()) => {
            if let Some(epoch) = probe_epoch {
                host.lane_store()
                    .release_probe_owned_in(pool_name, i, epoch);
            }
            drop(permit);
            return Some(ingress_error(
                ingress_protocol,
                StatusCode::INTERNAL_SERVER_ERROR,
                KIND_API_ERROR,
                DETAIL_INTERNAL_ERROR,
            ));
        }
    };

    // THE ONE ATTEMPT: assemble, send, classify, deliver (see `dispatch_hop`).
    let outcome = dispatch_hop(
        host,
        rt,
        i,
        pool_name,
        cands,
        body,
        head_pristine,
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
        request_ctx,
        breaker_cfg,
        chosen_policy_name,
        metric_pool,
        permit,
        probe_epoch,
        hop_v,
        usage_sink,
    )
    .await;
    match outcome {
        AttemptOutcome::Response(resp) | AttemptOutcome::Bail(resp) => Some(resp),
        AttemptOutcome::Failed {
            disposition,
            err_type,
            ..
        } => {
            if matches!(disposition, Disposition::ContextLength) {
                // Too large for THIS model's context window: exclude every candidate at or below the
                // failed lane's known limit so failover lands on a larger-context member.
                exclude_smaller_context_lanes(rt, cands, request_ctx, i);
            }
            // Every failed attempt on this walk is a failover to the next candidate.
            host.telemetry_failover(metric_pool, err_type);
            *last_failure = Some(err_type);
            None
        }
    }
}
