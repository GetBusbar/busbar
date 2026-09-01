use super::*;
// The tracing seam: the ONE named level constant every hot-path `#[tracing::instrument]`
// in this file references, so a `#[tracing::instrument(level = "debug")]` hand-picked literal never
// re-forks the policy. `tracing::instrument`'s `level = <path>` form rejects a leading `crate`
// keyword segment (it parses a bare `Ident`/`Path`, and `crate` is not one), so the constant is
// imported here and referenced unqualified at each instrument site instead.
use busbar_core::observability::HOTPATH_LEVEL;
// The single neutral translate entrypoint (G6 step 4): the non-stream cross-protocol response arm
// routes its read→prepare_for_ingress→write core through `TranslateCodec::translate_response`.
use busbar_core::diagnostics::{
    diag_debug, diag_error, diag_warn, ATTEMPT_TIMEOUT_FAILOVER, CROSSPROTO_BINARY_CODEC_FAILED,
    CROSSPROTO_JSON_CODEC_FAILED, CROSSPROTO_NONSTREAM_MIDTRANSFER_FAILED,
    CROSSPROTO_RESPONSE_NOT_TRANSLATABLE, CROSSPROTO_RESPONSE_NOT_TRANSLATABLE_DEGRADED,
    CROSSPROTO_TRANSLATION_CAP_EXCEEDED, DECISION_GATE_REJECTED, DECISION_GATE_RESTRICT_REJECT,
    DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE, LANE_HARD_DOWN, REWRITE_BODY_MATERIALIZE_FAILED,
    REWRITE_GATE_REJECTED, REWRITE_RESERIALIZE_FAILED, ROUTING_POLICY_REJECTED,
    ROUTING_POLICY_RESTRICT_REJECT, ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
};
use busbar_core::handlers::TranslateCodec;

/// Bodies at or above this size run the (pure, synchronous) cross-protocol translate on the
/// blocking pool instead of inline on the single-threaded worker — see the offload comment at the
/// call site. 128 KiB: the inline worst case at the boundary is ~1-2 ms (inside the p99 envelope),
/// and real chat bodies are two orders of magnitude smaller, so the offload branch is statically
/// dead on the happy path. A constant, not a knob.
const TRANSLATE_OFFLOAD_THRESHOLD: usize = 128 * 1024;

/// The send stage's three exits, so the attempt-cap and budget-deadline wrappers compose without
/// nesting error types: a response (or client error), the per-attempt hang cap firing, or the
/// non-streaming failover budget expiring.
enum SendOutcome {
    Sent(Result<http::Response<hyper::body::Incoming>, crate::engine::EgressError>),
    AttemptTimeout(u64),
    BudgetTimeout,
}

/// The unified send error the classification arm reads — the same two-way split the old
/// reqwest arm made (`is_timeout()` vs everything-else-is-connect), preserved exactly:
/// * the failover-budget deadline and a connect that exceeded its 10s bound are TIMEOUTS
///   (reqwest reported both via `is_timeout()`);
/// * every other client error (refused, TLS failure, reset before headers) is CONNECT class.
enum EgressSendError {
    Timeout,
    Client(crate::engine::EgressError),
}

impl EgressSendError {
    fn is_timeout(&self) -> bool {
        match self {
            EgressSendError::Timeout => true,
            // Walk the source chain for an io timeout: hyper surfaces our connector's 10s
            // connect bound as a connect error wrapping `io::ErrorKind::TimedOut`, which reqwest
            // classified as timeout — keep that split byte-identical for the breaker.
            EgressSendError::Client(e) => {
                let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
                while let Some(cur) = src {
                    if let Some(io) = cur.downcast_ref::<std::io::Error>() {
                        if io.kind() == std::io::ErrorKind::TimedOut {
                            return true;
                        }
                    }
                    src = cur.source();
                }
                false
            }
        }
    }
}

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
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward_with_pool(
    // BORROWED: the whole forward runs inline inside the request future, so nothing here needs an
    // owned Arc — ownership is taken ONLY at the escape points (streaming bodies, spawned
    // completions), each with its own explicit clone. Every by-value pass was a shared-refcount
    // RMW pair ping-ponging across workers (wave-6 profile).
    app: &Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    caller_token: Option<&str>,
    pool_name: &str,
    affinity_key: Option<&str>,
    ingress_protocol: &str,
    op: busbar_core::handlers::Op,
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
    )
    .await
}

/// [`forward_with_pool`] plus the caller's pre-resolved governance key (`GovCtx.key`). The named /
/// ad-hoc anthropic-dialect routes use this so a GROUP/SSO principal — whose bearer token is not a
/// virtual-key secret and so never resolves via the `lookup` fallback — still projects
/// `rate_headroom` / `identity` into a pool's routing policy, matching the universal dispatch path.
// A plain fn returning `Either<ready(400), forward_future>` rather than an async fn (wave-8a
// future-shrink): an async fn layer here stored its ten parameters in ITS coroutine and then moved
// them into `forward_with_pool_parsed`'s — double-stored per-request state (+280 bytes of
// await-boundary memcpy) for a wrapper whose only own work is one synchronous parse. The parse runs
// eagerly at call time — every caller `.await`s the returned future immediately, and `LazyBody::
// parse` is pure CPU with no I/O, so nothing observable moves — and the parameters land in exactly
// one coroutine. The malformed-body 400 contract is unchanged (`Either::Left` resolves to the same
// `ingress_error` on first poll).
#[allow(clippy::too_many_arguments)]
pub(crate) fn forward_with_pool_keyed<'a>(
    app: &'a Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    caller_token: Option<&'a str>,
    resolved_gov_key: Option<&'a std::sync::Arc<busbar_core::governance::VirtualKey>>,
    pool_name: &'a str,
    affinity_key: Option<&'a str>,
    ingress_protocol: &'a str,
    op: busbar_core::handlers::Op,
    usage_sink: Option<UsageSink>,
) -> impl std::future::Future<Output = Response> + 'a {
    // Validate + head-project WITHOUT building a DOM (same malformed-body 400 contract as the old
    // eager parse — `LazyBody::parse` goes through the identical `busbar_core::json` guard + parser).
    let _parse = busbar_core::profile::start(busbar_core::profile::Stage::InboundParse);
    let v: LazyBody = match LazyBody::parse(&body) {
        Ok(v) => v,
        Err(_) => {
            tracing::debug!(detail = %busbar_core::json::parse_err_log(body.len()), "request body JSON parse failed");
            return futures::future::Either::Left(std::future::ready(ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "We could not parse the JSON body of your request.",
            )));
        }
    };
    drop(_parse);
    futures::future::Either::Right(forward_with_pool_parsed(
        app,
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
    ))
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
    app: &'a Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    mut v: Option<LazyBody>,
    req_content_type: &'a str,
    caller_token: Option<&'a str>,
    resolved_gov_key: Option<&'a std::sync::Arc<busbar_core::governance::VirtualKey>>,
    pool_name: &'a str,
    affinity_key: Option<&'a str>,
    ingress_protocol: &'a str,
    op: busbar_core::handlers::Op,
    usage_sink: Option<UsageSink>,
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
        let _wrap = busbar_core::profile::start(busbar_core::profile::Stage::WrapSetup);
        let request_id = app.next_request_id();
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
        let completion_shape = if app.tap_hooks_response.is_empty() {
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
            app,
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
                &app.tap_hooks_response,
                &shape,
                busbar_core::hooks::wire::HookStageProjection {
                    at: "response",
                    model: None,
                    attempt_number: None,
                    remaining_candidates: None,
                    previous_failure: None,
                    outcome: Some(outcome),
                    status: Some(resp.status().as_u16()),
                },
                resolved_gov_key.and_then(|k| k.group.as_deref()),
                &app.groups_registry,
            );
        }
        resp
    }
    .instrument(span)
}

/// RAII refund for the headers-time `spend_budget` unit across the BUFFERED forward path's
/// spend→`read_capped(...).await` window (used by both `forward_with_pool_parsed_inner` here and
/// its `walk.rs` degraded-path twin). A client disconnect / LB reset parked at that await drops the
/// handler future without resuming it, so a plain local bool consulted only AFTER the await never
/// runs the refund (#21) — the streaming path has `FirstByteBody::drop` for this; the buffered path
/// has no such body wrapper, so it needs its own guard.
///
/// Mirrors `select::ProbeGuard`: armed by default, refunds on `Drop` unless disarmed first. Every
/// exit that must KEEP the charge (a delivered completion, or our own translation-cap truncation)
/// calls `disarm()` before returning; the exits that must refund (a pre-first-byte-equivalent
/// transport failure, or an untranslatable 2xx) simply leave it armed and let the `return` unwind
/// through it — replacing the old inline `if budget_spent { refund_budget(i) }` calls, not
/// supplementing them (calling both would double-refund).
struct BudgetSpendGuard<'a> {
    store: &'a dyn busbar_core::store::LaneRuntime,
    lane: usize,
    armed: bool,
}

impl BudgetSpendGuard<'_> {
    fn disarm(&mut self) {
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

/// The SINGLE source of truth for deciding what to do with a non-streaming CROSS-protocol 2xx
/// response, mirroring [`translate_request_cross_protocol`]'s role on the request side. Both the hot
/// path ([`forward_with_pool_parsed_inner`]) and the degraded last-resort path
/// ([`walk::forward_once`], FallbackPool/LeastBad) call THIS function so the two cannot drift apart on
/// any translation step — exactly the class of bug the request-side unification (see
/// `translate_request_cross_protocol`'s doc comment) already fixed once on the request side. Before
/// this extraction the response-side decision tree (TransportError / Truncated / binary-vs-JSON /
/// Bedrock-eventstream-synthesis / Gemini-array-wrap) was duplicated near-verbatim between the two
/// call sites, the same shape of risk the request side fixed but the response direction never inherited.
///
/// Called ONLY once the caller has already decided `ingress_protocol != egress` and the response is
/// NOT SSE — every exit from this function is a fully-built `Response`, so the caller's own call site
/// is always `return translate_response_cross_protocol(...).await;` (or `Ok(...)` around it on the
/// `Result`-returning degraded path).
///
/// Takes ownership of `r` (consumed by `read_capped`), `permit` (dropped once the whole body is in
/// hand — a buffered response holds no permit) and `usage_sink` (billed at most once, from whichever
/// exit actually delivers a completion) because every code path through this function returns.
///
/// `budget_guard` is borrowed, NOT owned: the caller's existing [`BudgetSpendGuard`] is reused (armed
/// or disarmed here) rather than a second instance constructed inside this function — a second
/// instance armed off the same `budget_spent` would refund/not-refund independently of the caller's
/// own guard and double-refund (or wrongly refund) on `Drop` when the caller's stack frame unwinds.
///
/// `chosen_policy_name` is `None` on the degraded path (which has no `chosen_policy_name` in scope —
/// there is no routing-policy decision on a FallbackPool/LeastBad hop) and threads straight into
/// [`maybe_attach_route_policy`], which is already a no-op on `None` — so passing `None` reproduces
/// the degraded path's prior behavior (no `x-busbar-route-*` headers) exactly, rather than needing a
/// separate branch.
///
/// `degraded` selects the few observably different log/warn strings the two call sites always had
/// (the degraded path's messages note "degraded path" / "degraded cross-protocol"). This extraction
/// changes no caller's observable HTTP behavior (status/headers/body/breaker/budget accounting are
/// byte-identical), but it DOES deliberately unify two pieces of tracing output that had drifted
/// independently and are not worth a THIRD parameter to keep apart:
///   - the degraded path's "untranslatable" warn previously lacked the `status` field the main path's
///     twin already carried — a real (if minor) drift this extraction closes rather than preserves;
///   - the codec-error warns previously spelled the degraded-path distinction into the message text
///     ("...(read_response, degraded path); ...") — replaced here with a structured `degraded` field
///     on both call sites (machine-filterable instead of embedded in a format string).
#[allow(clippy::too_many_arguments)]
async fn translate_response_cross_protocol(
    app: &Arc<App>,
    i: usize,
    ingress_protocol: &str,
    op: busbar_core::handlers::Op,
    pool: &str,
    breaker_cfg: &busbar_core::store::BreakerCfg,
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
) -> Response {
    let egress_name = app.engine_tables().lanes()[i].protocol;

    // Size-capped buffer under the COMPLETION cap (not the tight error-body cap): a legitimate 2xx
    // completion can far exceed 256 KiB and must be buffered WHOLE to parse+translate. `truncated`
    // distinguishes "too large to translate" from "genuinely unparseable" so a too-large success is
    // not mis-reported as a 500.
    // Bounded by the caller's `read_deadline` (the non-stream budget deadline, or the client-ceiling
    // re-provision) — reqwest's client-level timeout covered this whole-body buffer too. Expiry is a
    // failed transfer: the `TransportError` arm below refunds/compensates exactly as a mid-body cut.
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
    // Re-record the upstream RTT now that the WHOLE body has arrived — see the callers' doc comments:
    // on this buffered cross-protocol path Busbar awaits the entire upstream response before it can
    // parse+translate, so the body-download time is part of the upstream cost, not Busbar's.
    record_upstream_rtt(upstream_started.elapsed());
    drop(permit); // upstream call complete; a non-streamed response holds no permit
    if read_end == ReadEnd::TransportError {
        // The transfer failed mid-body. We optimistically recorded breaker success + spent the
        // budget on the 2xx HEADERS above (shared with the streaming path), but the BODY never
        // arrived intact: do NOT charge tokens for a corrupt fragment, record a compensating
        // transient failure so the breaker sees the transfer as failed, AND refund the request budget
        // unit spent on the headers — no usable response was delivered, so a failed body transfer
        // must not permanently drain the lane's `max_requests` budget.
        diag_debug!(
            CROSSPROTO_NONSTREAM_MIDTRANSFER_FAILED,
            ingress = %ingress_protocol,
            egress = %egress_name,
            "cross-protocol non-stream upstream body failed mid-transfer; \
             not recording success/usage, refunding budget, returning ingress-native error"
        );
        let tripped = app
            .store
            .record_transient_in(pool, i, ERR_NET_TRANSPORT, breaker_cfg, None);
        // A threshold-based Closed→Open trip here is a breaker trip too (#29).
        if tripped {
            emit_breaker_trip(app, pool, i);
        }
        // `budget_guard` is still armed here (nothing has disarmed it): dropping it on this `return`
        // refunds ONLY if the headers-spend actually decremented (#21).
        return ingress_error(
            ingress_protocol,
            StatusCode::BAD_GATEWAY,
            KIND_API_ERROR,
            GENERIC_RESPONSE_ERROR_DETAIL,
        );
    }
    if read_end == ReadEnd::Truncated {
        // The upstream body exceeded OUR translation cap, so we cannot translate it and the client
        // receives a 500 with NO completion. Token accounting is therefore deliberately NOT done here:
        // charging the key's TPM/spend budget for a completion the client never received is incorrect.
        // Unlike TransportError this is OUR cap, not an upstream fault, so the optimistic breaker
        // success recorded on the 2xx headers stands and the request budget unit is NOT refunded.
        diag_debug!(
            CROSSPROTO_TRANSLATION_CAP_EXCEEDED,
            ingress = %ingress_protocol,
            egress = %egress_name,
            cap = max_translated_body_bytes(),
            "cross-protocol non-stream success body exceeded the translation cap; \
             cannot translate, not charging tokens, returning ingress-native error"
        );
        budget_guard.disarm();
        return ingress_error(
            ingress_protocol,
            StatusCode::INTERNAL_SERVER_ERROR,
            KIND_API_ERROR,
            GENERIC_RESPONSE_ERROR_DETAIL,
        );
    }
    // Token accounting deferred to the delivery seam below (#2). A 2xx body whose usage block parses
    // but whose content shape is unmodeled does NOT reach a translate+return block below: it falls
    // through to the ingress-native 500 at the end, delivering NO completion. Charging here — before
    // translation is proven to succeed — would bill the key's TPM/spend for a completion the client
    // never receives, exactly the inconsistency the Truncated and TransportError branches above
    // deliberately avoid. So tap usage ONLY once we are inside the block that actually mints and
    // returns a translated response.
    let egress_op = busbar_core::handlers::request_handler(egress_name)
        .and_then(|rh| rh.operation_handler(op.operation));
    // The ingress operation handler that writes the client's dialect (chat delegates to the same
    // writer vtable — byte-identical). Resolved once, shared by both the opaque and JSON arms.
    let ingress_op = busbar_core::handlers::request_handler(ingress_protocol)
        .and_then(|rh| rh.operation_handler(op.operation));
    // OPAQUE (non-JSON) egress body — e.g. binary speech audio: bridge at the BYTE level through the
    // operation codecs and relay the ingress handler's WireBody (bytes + ITS content-type) verbatim.
    // JSON bodies take the Value path below. Parse the 2xx body ONCE, then branch on JSON vs opaque.
    // Every hop's read→prepare_for_ingress→write core routes through the single
    // `TranslateCodec::translate_response` entrypoint; the engine keeps telemetry, the
    // untranslatable-metadata warn, billing, budget accounting, native-metrics injection, the
    // gemini-array wrap, and all response building.
    let body_json = busbar_core::json::parse::<Value>(&bytes);
    if body_json.is_err() {
        if let Some(eh) = egress_op {
            match eh.translate_response(
                busbar_core::handlers::TranslateRespInput::Opaque(&bytes),
                ingress_op.is_some(),
                ingress_protocol,
                &app.engine_tables().lanes()[i].model,
                now(),
                false,
                None,
            ) {
                Err(ref e) => {
                    // A binary/opaque upstream body the egress codec cannot decode: log the CodecError
                    // so a repeated wall of 500s has a visible root cause instead of only the generic
                    // warn below.
                    diag_debug!(
                        CROSSPROTO_BINARY_CODEC_FAILED,
                        ingress = %ingress_protocol,
                        egress = %egress_name,
                        error = ?e,
                        degraded,
                        "cross-protocol binary response failed the egress codec (read_response); returning ingress-native 500",
                    );
                }
                Ok((usage, delivery)) => {
                    if let busbar_core::handlers::TranslatedResponse::Typed(wire) = delivery {
                        // Delivered: bill + disarm the spend guard here (tokens are now committed to
                        // this key; keep the lane unit too rather than refund it out from under an
                        // already-billed request).
                        record_resp_usage(usage, &usage_sink, app.engine_tables().lanes().get(i));
                        budget_guard.disarm();
                        let rb = Response::builder()
                            .status(status)
                            .header(CONTENT_TYPE, wire.content_type);
                        let rb = maybe_attach_response_request_id(rb, ingress_protocol, None);
                        let rb = maybe_attach_route_policy(
                            rb,
                            chosen_policy_name,
                            &app.engine_tables().lanes()[i].model,
                        );
                        return rb
                            .body(Body::from(wire.bytes))
                            .unwrap_or_else(|_| status.into_response());
                    }
                    // `Untranslatable` (ingress handler absent): NO client body could be written, so
                    // this falls through to the ingress-native 500 delivering no completion. Do NOT
                    // bill, and leave the guard ARMED so its `Drop` refunds the headers-time budget
                    // unit — a completion the client never receives is not charged, mirroring the
                    // streaming `FirstByteBody` refund-on-non-delivery.
                }
            }
        }
    }
    if let Ok(rv) = &body_json {
        if let Some(eh) = egress_op {
            // Gate translation on the ingress having a codec, exactly as the pre-cutover
            // `protocol_for(ingress_protocol)` guard did; the neutral `translate_response` now takes
            // the ingress protocol by NAME + a `serves-op` flag and reaches its writer through the
            // codec cell, so the concrete `ProtocolWriter` is no longer named at this call site.
            if busbar_core::proto::decl_for(ingress_protocol).is_some_and(|d| d.codec.is_some()) {
                // Read the wall-clock elapsed once for the wants-stream frame-synthesis fork (a
                // Bedrock ConverseStream client served a buffered Converse body); the JSON-body path
                // reads its own fresh elapsed for `inject_response_metrics` below, matching the two
                // independent clock reads the pre-cutover arm made.
                let stream_elapsed_ms = u64::try_from(upstream_started.elapsed().as_millis()).ok();
                match eh.translate_response(
                    busbar_core::handlers::TranslateRespInput::Json(rv),
                    ingress_op.is_some(),
                    ingress_protocol,
                    &app.engine_tables().lanes()[i].model,
                    now(),
                    wants_stream,
                    stream_elapsed_ms,
                ) {
                    Err(ref e) => {
                        // A JSON 2xx whose shape the egress codec rejects (e.g. a missing `embedding`
                        // array): log the CodecError before the generic 500 so the operator can tell a
                        // broken upstream from a new/renamed response field.
                        diag_debug!(
                            CROSSPROTO_JSON_CODEC_FAILED,
                            ingress = %ingress_protocol,
                            egress = %egress_name,
                            error = ?e,
                            degraded,
                            "cross-protocol JSON response failed the egress codec (read_response_value); returning ingress-native 500",
                        );
                    }
                    Ok((usage, delivery)) => {
                        // RESPONSE-side twin of `IrReq::prepare_for_egress`'s dropped-keys warn. The
                        // reader has just discarded any vendor-scoped response metadata the caller's
                        // protocol has no shape for (a Bedrock guardrail `trace`, a Gemini
                        // `safetyRatings`); this is the one place that still holds the upstream body
                        // AND knows the hop is cross-protocol, so it is where the drop gets named.
                        // Same-protocol routes never reach this function.
                        if let Ok(ref upstream_body) = body_json {
                            busbar_core::proto::warn_untranslatable_response_metadata(
                                egress_name,
                                ingress_protocol,
                                upstream_body,
                            );
                        }
                        // Token accounting: bill + disarm the spend guard ONLY when the resolved
                        // delivery variant actually hands bytes to the client. `IngressUnsupported`
                        // (renders a 404) and `Untranslatable` (falls through to the ingress-native
                        // 500) deliver NO completion — for those, leave the guard ARMED so its `Drop`
                        // refunds the headers-time budget unit, mirroring the streaming `FirstByteBody`
                        // refund-on-non-delivery. Billing a completion the client never receives is
                        // exactly the TPM/spend inconsistency the Truncated/TransportError branches
                        // above already avoid. No FirstByteBody on this buffered path, so a delivered
                        // response bills here — straight from the IR usage the egress reader decoded
                        // (captured before `prepare_for_ingress`).
                        if matches!(
                            delivery,
                            busbar_core::handlers::TranslatedResponse::StreamFrames(_)
                                | busbar_core::handlers::TranslatedResponse::Typed(_)
                                | busbar_core::handlers::TranslatedResponse::Json(_)
                        ) {
                            record_resp_usage(
                                usage,
                                &usage_sink,
                                app.engine_tables().lanes().get(i),
                            );
                            budget_guard.disarm();
                        }
                        match delivery {
                            // Bedrock ingress that requested ConverseStream but got a BUFFERED 2xx: a
                            // native AWS SDK decoder expects binary `eventstream` frames, delivered
                            // under `application/vnd.amazon.eventstream`.
                            busbar_core::handlers::TranslatedResponse::StreamFrames(frames) => {
                                let rb = Response::builder().status(status).header(
                                    CONTENT_TYPE,
                                    crate::engine::ingress_stream_content_type(ingress_protocol)
                                        .unwrap_or(crate::engine::TEXT_EVENT_STREAM),
                                );
                                let rb =
                                    maybe_attach_response_request_id(rb, ingress_protocol, None);
                                let rb = maybe_attach_route_policy(
                                    rb,
                                    chosen_policy_name,
                                    &app.engine_tables().lanes()[i].model,
                                );
                                return rb
                                    .body(Body::from(frames))
                                    .unwrap_or_else(|_| status.into_response());
                            }
                            busbar_core::handlers::TranslatedResponse::IngressUnsupported => {
                                return ingress_error(
                                    ingress_protocol,
                                    StatusCode::NOT_FOUND,
                                    KIND_NOT_FOUND,
                                    DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
                                );
                            }
                            // The ingress dialect's response is NOT JSON (binary speech): relay the
                            // WireBody — bytes + its content-type.
                            busbar_core::handlers::TranslatedResponse::Typed(wire) => {
                                let rb = Response::builder()
                                    .status(status)
                                    .header(CONTENT_TYPE, wire.content_type);
                                let rb =
                                    maybe_attach_response_request_id(rb, ingress_protocol, None);
                                let rb = maybe_attach_route_policy(
                                    rb,
                                    chosen_policy_name,
                                    &app.engine_tables().lanes()[i].model,
                                );
                                return rb
                                    .body(Body::from(wire.bytes))
                                    .unwrap_or_else(|_| status.into_response());
                            }
                            busbar_core::handlers::TranslatedResponse::Json(mut translated) => {
                                // A native AWS Bedrock Converse (non-stream) response ALWAYS populates
                                // `metrics.latencyMs`; the bedrock writer's `write_response` emits only
                                // output/stopReason/usage, so a bedrock-ingress non-stream client would
                                // read `metrics == None` — the proxy tell the streaming path already
                                // injects against. Inject the real request elapsed wall-clock, and OMIT
                                // `metrics` rather than fabricate a tell-tale `0` if timing is missing.
                                // Neutral seam: the native response-metrics injection is a per-dialect
                                // computed-codec method (`DialectCodec::inject_response_metrics`),
                                // reached by protocol NAME through `decl_for(name).dialect()`, so the
                                // concrete `ProtocolWriter` is no longer named here (G6 A4b).
                                if let Some(dialect) = busbar_core::proto::decl_for(ingress_protocol)
                                    .and_then(|d| d.dialect())
                                {
                                    dialect.inject_response_metrics(
                                        &mut translated,
                                        u64::try_from(upstream_started.elapsed().as_millis()).ok(),
                                    );
                                }
                                // Gemini JSON-array streaming (`:streamGenerateContent` WITHOUT
                                // `?alt=sse`) answered by a BUFFERED non-SSE 2xx: the native endpoint
                                // returns a JSON ARRAY of chunk objects, so a single bare `{...}` is
                                // undecodable by a Gemini SDK parsing the body as an array. Wrap the
                                // single translated object in a one-element array.
                                if gemini_json_array && wants_stream {
                                    let arr = Value::Array(vec![translated]);
                                    let rb = Response::builder()
                                        .status(status)
                                        .header(CONTENT_TYPE, APPLICATION_JSON);
                                    let rb = maybe_attach_route_policy(
                                        rb,
                                        chosen_policy_name,
                                        &app.engine_tables().lanes()[i].model,
                                    );
                                    return rb
                                        .body(Body::from(
                                            busbar_core::json::to_vec(&arr)
                                                .unwrap_or_else(|_| arr.to_string().into_bytes()),
                                        ))
                                        .unwrap_or_else(|_| status.into_response());
                                }
                                // Content-Type is the INGRESS JSON CT, not the upstream's — the body is
                                // now in the client's native non-stream shape.
                                let rb = Response::builder()
                                    .status(status)
                                    .header(CONTENT_TYPE, APPLICATION_JSON);
                                // The ingress writer's vtable attaches its native response request-id
                                // header. This is the CROSS-protocol translate path (ingress !=
                                // egress), so there is no upstream id to forward — `None` makes the
                                // writer synthesize one.
                                let rb =
                                    maybe_attach_response_request_id(rb, ingress_protocol, None);
                                let rb = maybe_attach_route_policy(
                                    rb,
                                    chosen_policy_name,
                                    &app.engine_tables().lanes()[i].model,
                                );
                                // sonic-rs: SIMD serialize of the translated client body (the
                                // response-path hot spot); fall back on the impossible serialize error.
                                let body_bytes = busbar_core::json::to_vec(&translated)
                                    .unwrap_or_else(|_| translated.to_string().into_bytes());
                                return rb
                                    .body(Body::from(body_bytes))
                                    .unwrap_or_else(|_| status.into_response());
                            }
                            // Opaque-only terminal; unreachable on the JSON path.
                            busbar_core::handlers::TranslatedResponse::Untranslatable => {}
                        }
                    }
                }
            }
        }
    }
    // Not translatable (non-JSON / unexpected-but-valid shape / unknown ingress). We reached this
    // block only because ingress != egress, so relaying the upstream body+Content-Type verbatim would
    // leak the EGRESS provider's native wire format to a different-protocol client — a foreign-format
    // response is an immediate proxy tell and a functional failure. Return an ingress-native 500
    // instead. (Same-protocol passthrough never enters this function.)
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
    // The 2xx headers optimistically recorded a breaker SUCCESS, but an undecodable body is exactly as
    // much a lane fault as a transport failure — without this, a lane returning undecodable 200s
    // forever never trips (unlike its TransportError sibling above, which already compensates).
    let tripped = app
        .store
        .record_transient_in(pool, i, "untranslatable-2xx", breaker_cfg, None);
    if tripped {
        emit_breaker_trip(app, pool, i);
    }
    // `budget_guard` is still armed here (nothing on this fallthrough disarmed it): dropping it on
    // this `return` refunds the headers-time unit, symmetric with the TransportError branch above.
    ingress_error(
        ingress_protocol,
        StatusCode::INTERNAL_SERVER_ERROR,
        KIND_API_ERROR,
        GENERIC_RESPONSE_ERROR_DETAIL,
    )
}

/// The dispatch core behind [`forward_with_pool_parsed`] (the thin wrapper exists only to fire the
/// response-stage taps around the whole request).
//
// Plumbing function: same parameter set as the public wrapper.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward_with_pool_parsed_inner(
    app: &Arc<App>,
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
    resolved_gov_key: Option<&std::sync::Arc<busbar_core::governance::VirtualKey>>,
    pool_name: &str,
    affinity_key: Option<&str>,
    ingress_protocol: &str,
    // A request's identity is (operation, protocol): `ingress_protocol` is the wire language,
    // `op` is the kind of work. Everything below is the engine carrying that pair through pool
    // selection, failover, the breaker, and billing. The engine reads only capabilities off the
    // spec, never its identity; `busbar_core::handlers::CHAT` reproduces today's behavior byte-for-byte.
    op: busbar_core::handlers::Op,
    usage_sink: Option<UsageSink>,
    // This request's correlation id, stamped ONCE by the wrapper (`forward_with_pool_parsed`)
    // before this fn was called — carried as a plain `Copy` scalar for the whole dispatch (stored on
    // `RequestCtx::request_id` below, and threaded into every hook projection built in here) rather
    // than re-derived per hop.
    request_id: u64,
) -> Response {
    // Stage profiler: PREPARE spans all pre-dispatch bookkeeping (op-support filter, wants_stream +
    // affinity derivation, failover/breaker config) up to the failover loop. Zero cost when
    // `BUSBAR_PROFILE` is unset — `start` returns `None` and takes no `Instant`.
    let _prep = busbar_core::profile::start(busbar_core::profile::Stage::Prepare);
    // EGRESS deletion switch: every candidate
    // lane's protocol must HOLD this operation's handler. A protocol whose handler was deleted is
    // not a valid egress for the operation — a clean no-handler 404 in the CALLER's dialect, never a
    // silent dispatch. Dormant while all six protocols serve chat; load-bearing the moment one is
    // removed (the deletion test).
    let mut cands: Vec<WeightedLane> = {
        let supports = |wl: &WeightedLane| {
            busbar_core::handlers::request_handler(app.engine_tables().lanes()[wl.idx].protocol)
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
    let pool_rewrites: &[(
        std::time::Duration,
        std::sync::Arc<dyn busbar_core::hooks::RoutingPolicy>,
    )] = app
        .engine_tables()
        .pool_runtime()
        .get(pool_name)
        .map(|r| r.rewrite_hooks.as_slice())
        .unwrap_or(&[]);
    if !app.rewrite_hooks.is_empty() || !pool_rewrites.is_empty() {
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
                &app.rewrite_hooks,
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
                match busbar_core::json::to_vec(parsed) {
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
    if app.any_content_hook {
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
    if !app.tap_hooks.is_empty() {
        if let Some(Ok(dom)) = v.as_mut().map(|l| l.ensure_dom()) {
            fire_global_taps(
                app,
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
    let ingress_decl = busbar_core::proto::decl_for(ingress_protocol);
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
    let pool_failover = app
        .engine_tables()
        .pool_runtime()
        .get(pool_name)
        .and_then(|r| r.failover.as_ref())
        .or(app.engine_tables().failover_cfg().as_ref());
    let (deadline_secs, max_cap) = match pool_failover {
        Some(f) => (f.timeout_secs, f.max_hops),
        None => (
            busbar_core::config::DEFAULT_FAILOVER_DEADLINE_SECS,
            busbar_core::config::DEFAULT_FAILOVER_CAP,
        ),
    };

    // Breaker config: prefer this pool's own settings, fall back to ADR-0002 defaults. Resolved
    // once and shared (Arc) so the streaming guard can record mid-stream failures with the same
    // thresholds the synchronous path used. The default (no per-pool breaker — the common case) is
    // a process-wide cached Arc, so the hot path pays no per-request allocation for it.
    let breaker_cfg: std::sync::Arc<busbar_core::store::BreakerCfg> = resolve_breaker_cfg(app, pool_name);

    let mut request_ctx = RequestCtx::new(deadline_secs, request_id);

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
                .any(|m| m == &app.engine_tables().lanes()[wl.idx].model)
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
    let pool_gates: &[(u16, busbar_core::hooks::ResolvedPolicy)] = app
        .engine_tables()
        .pool_runtime()
        .get(pool_name)
        .map(|r| r.gates.as_slice())
        .unwrap_or(&[]);
    let mut gate_order: Option<(Vec<usize>, &'static str)> = None;
    if !app.global_gates.is_empty() || !pool_gates.is_empty() {
        // The chain: globals (pre-sorted ascending by priority) then pool gates (config order),
        // stable-sorted by priority — ties keep globals-first, then config order.
        let mut chain: Vec<&(u16, busbar_core::hooks::ResolvedPolicy)> =
            app.global_gates.iter().chain(pool_gates.iter()).collect();
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
                    app,
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
                        busbar_core::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
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
                let members = app
                    .engine_tables()
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
                    if matches!(on_empty, busbar_core::config::PolicyOnError::Weighted) {
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
                            busbar_core::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
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
                        busbar_core::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
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
                busbar_core::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
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
        match app
            .engine_tables()
            .pool_runtime()
            .get(pool_name)
            .and_then(|r| r.policy.as_ref())
        {
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
                    app,
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
                            busbar_core::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
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
                            busbar_core::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
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
                        let members = app
                            .engine_tables()
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
                            if matches!(on_empty, busbar_core::config::PolicyOnError::Weighted) {
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
                                    busbar_core::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
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
                                busbar_core::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
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
    let stage_shape = if app.tap_hooks_candidate.is_empty() && app.tap_hooks_routing.is_empty() {
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
            &app.tap_hooks_candidate,
            shape,
            busbar_core::hooks::wire::HookStageProjection {
                at: "candidate",
                model: None,
                attempt_number: None,
                remaining_candidates: Some(cands.len()),
                previous_failure: None,
                outcome: None,
                status: None,
            },
            resolved_gov_key.and_then(|k| k.group.as_deref()),
            &app.groups_registry,
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
    let upstream_creds = app.engine_tables().pool_upstream_creds(pool_name);

    // PREPARE ends here (dispatch loop begins). From here on, `v` IS the first-hop body: the loop
    // consumes it on hop 1 (`v.take()` / the pristine short-circuit) and failover hops 2+ re-parse
    // the retained `body` bytes. (This used to be a `first_hop_v = v` rebind for the name alone —
    // dropped because the extra binding cost the coroutine a second 80-byte `Option<LazyBody>` slot
    // held across every await of the attempt loop; wave-8a future-shrink.)
    drop(_prep);
    for attempt in 0..=max_cap {
        // Check deadline first (propagated across hops)
        if request_ctx.expired(now()) {
            return ingress_error(
                ingress_protocol,
                StatusCode::SERVICE_UNAVAILABLE,
                KIND_OVERLOADED,
                DETAIL_REQUEST_TIMEOUT,
            );
        }

        let _pick = busbar_core::profile::start(busbar_core::profile::Stage::LanePick);
        // `probe_epoch`: `Some(epoch)` when this pick WON a single-flight recovery probe (captured
        // synchronously by `pick_among` before any await), `None` for a Closed-ready no-op admit that
        // won none. The `probe_guard` built right below turns this into a RAII release that covers the
        // WHOLE dispatch window — including a dropped future — so this path no longer scatters explicit
        // (and formerly unowned) `release_probe_*` calls across its early-return arms.
        let (i, permit, probe_epoch) = match pick_among(
            app,
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
                // the already-degraded path. (Same pattern as walk.rs's recursive box.)
                return Box::pin(handle_exhaustion_for_pool(
                    app.clone(),
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
        // RAII probe release covering the WHOLE dispatch window of THIS attempt, built ONLY when this
        // pick actually WON a single-flight recovery probe (`probe_epoch == Some`). Mirrors the
        // degraded `walk::forward_once` path (which already builds this guard): if this request future
        // is DROPPED mid-dispatch (a client disconnect while `req.send()` / `read_capped_body` is in
        // flight) NONE of the explicit early-return paths below run, so without a Drop guard the won
        // probe would strand the cell HalfOpen + `probe_in_flight` forever and single-flight would
        // bench the lane until the slow out-of-band prober reset it. `ProbeGuard::drop` releases it
        // OWNER-CHECKED (keyed on the captured epoch, so a stale drop never reverts a NEWER probe a
        // peer won). It stays ARMED across every early-return error path (each records a transient
        // first, which already transitions the cell, making the guard's release a safe owner-checked
        // no-op) and is DISARMED the moment the request records a legitimate SUCCESS
        // (`record_success_in` below) — from there the dispatched request/stream owns the probe
        // through its recorded outcome. A `None` pick (a Closed-ready no-op admit, which won no probe)
        // builds NO guard: it owns nothing to release. This supersedes the previous scattered
        // `release_probe_in`/`release_probe_owned_in` early-return calls and fixes their TWO bugs at
        // once: the pre-dispatch sites used the UNOWNED `release_probe_in` (which could revert a peer's
        // live probe), and NONE of the calls ran on a dropped future (the strand this closes).
        let mut probe_guard = probe_epoch.map(|epoch| crate::engine::select::ProbeGuard {
            store: app.store.as_ref(),
            pool: pool_name,
            lane: i,
            armed: true,
            probe_epoch: epoch,
        });
        // LANE_PICK ends here (a lane + permit are in hand).
        drop(_pick);
        // ATTEMPT_SETUP: per-hop bookkeeping between lane_pick and translate_req — exclude, routing
        // taps (light path: none), metric-pool label, upstream-attempt telemetry.
        let _asetup = busbar_core::profile::start(busbar_core::profile::Stage::AttemptSetup);

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
                &app.tap_hooks_routing,
                shape,
                busbar_core::hooks::wire::HookStageProjection {
                    at: "routing",
                    model: Some(&app.engine_tables().lanes()[i].model),
                    attempt_number: Some(
                        u32::try_from(attempt.saturating_add(1)).unwrap_or(u32::MAX),
                    ),
                    remaining_candidates: Some(remaining),
                    previous_failure: last_failure,
                    outcome: None,
                    status: None,
                },
                resolved_gov_key.and_then(|k| k.group.as_deref()),
                &app.groups_registry,
            );
        }

        // The bounded `pool` LABEL for THIS hop's upstream/failover/breaker metrics.
        // Resolves to the routed lane's model name on the default (`""`) cell so these series
        // correlate with REQUESTS_TOTAL (which labels model-routed traffic by model, not `""`);
        // the breaker-cell key below stays `pool_name` (`""`) — only the metric LABEL is decoupled.
        // Held as a borrow; every metric emit below goes through the TELEMETRY BANK (telemetry.rs),
        // which resolves `(metric_pool, i)` to this generation's pre-registered per-thread slots —
        // no label allocation and no shared-atomic contention on the walk.
        let metric_pool: &str = metric_pool_label(app, pool_name, i);

        // count this upstream attempt (re-entrant across failover hops — each is a real attempt).
        busbar_core::telemetry::upstream_attempt(app, metric_pool, i);
        tracing::debug!(pool = %pool_name, lane = %app.engine_tables().lanes()[i].model, "upstream attempt");

        let egress_name = app.engine_tables().lanes()[i].protocol;
        // Derive a FRESH per-hop body for translation. Each failover hop must translate/rewrite
        // starting from the ORIGINAL request, never from a previous hop's egress-shaped body. Re-PARSE
        // from the pristine `Bytes` (Arc-backed, so cheap to retain) rather than deep-cloning the
        // parsed `Value` tree per hop: a single JSON parse is far cheaper in time and peak heap than
        // an O(n) `Value::clone` of a large request (long histories / base64 images / big tool
        // schemas), which under sustained failover compounded to O(n × max_cap) allocations.
        drop(_asetup);
        let _xlate = busbar_core::profile::start(busbar_core::profile::Stage::TranslateReq);
        // REQUEST SHORT-CIRCUIT WITHOUT A DOM: hop 1 of a SAME-protocol
        // JSON dispatch whose head projection PROVES no same-proto invalidator (#1-#4, Vertex)
        // fires re-emits the retained bytes verbatim — the exact bytes the translate seam's own
        // pristine short-circuit would emit — without ever materializing the `Value` tree.
        // `head_provably_pristine` is one-sided (see its docs + parity test): any doubt falls
        // through to the unchanged materialize-and-translate path below, so the wire bytes are
        // byte-identical on every branch. When the DOM was already materialized (hooks/taps/gates/
        // path-model ingress), `probe()` IS the (possibly hook-rewritten) DOM and `body` was
        // re-serialized in lockstep by the rewrite pass — the check stays sound.
        let head_pristine = ingress_protocol == egress_name
            && v.as_ref()
                .is_some_and(|l| head_provably_pristine(app, i, l.probe()));
        let payload = if head_pristine {
            // Consume the hop-1 body exactly as the translate path does; failover hops 2+ re-parse
            // from the retained pristine bytes, unchanged. `Bytes::clone` = refcount bump.
            v = None;
            body.clone()
        } else {
            let hop_v: Option<Value> = if !body_is_json {
                None // opaque ingress body: byte-level relay/translate; nothing to re-parse.
            } else {
                let parsed = match v.take() {
                    // First hop: consume the carried body — the memoized DOM when one was
                    // materialized (hooks/taps/gates/path-model), else ONE parse of the validated
                    // bytes (the parse the old eager path performed at ingress).
                    Some(l) => l.into_value(),
                    // Failover hops: re-parse from the retained pristine bytes (sonic-rs: SIMD parse).
                    None => busbar_core::json::parse(&body).map_err(|_| ()),
                };
                match parsed {
                    Ok(v) => Some(v),
                    // `body` already validated/parsed once successfully above; this is infallible.
                    Err(()) => {
                        // Pre-dispatch bail (no breaker outcome recorded): the armed `probe_guard`
                        // above releases any single-flight probe this pick won on drop (owner-checked),
                        // so a recovering lane never wedges HalfOpen on this early exit.
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
            // SINGLE shared cross-protocol request-shaping seam (shared verbatim with `forward_once`'s
            // degraded path): read→clear-extra→write, shim-key strip, model rewrite, serialize. Both
            // paths route through `translate_request_cross_protocol` so neither can carry a translation
            // step the other lacks (the drift class that sharing one seam ends).
            //
            // HUGE-BODY OFFLOAD: the translate is a pure synchronous function over owned bytes — no
            // store, no client shard, no per-worker stripe — and on a single-threaded worker a
            // maximum-size body (`limits.request_body_max_bytes`, 32 MiB default) is hundreds of
            // milliseconds of CPU that would head-of-line-block every connection this worker owns.
            // At or above [`TRANSLATE_OFFLOAD_THRESHOLD`] the SAME call runs on the blocking pool
            // (the connection never moves; the worker keeps serving while this future waits); below
            // it, inline exactly as always. The common path pays one length compare — real chat
            // bodies sit two orders of magnitude under the threshold.
            let translated = if body.len() >= TRANSLATE_OFFLOAD_THRESHOLD {
                let app2 = app.clone();
                let body2 = body.clone();
                let ip: String = ingress_protocol.to_string();
                let ct: String = req_content_type.to_string();
                let key: String = resolved_gov_key
                    .map(|k| k.id.as_str())
                    .unwrap_or("anonymous")
                    .to_string();
                let reasoning =
                    effective_reasoning(&cands, i, app.engine_tables().lanes()[i].reasoning);
                match tokio::task::spawn_blocking(move || {
                    translate_request_cross_protocol(
                        &app2, i, &ip, op, hop_v, &ct, reasoning, &body2, &key,
                    )
                })
                .await
                {
                    Ok(r) => r,
                    // The blocking task itself failed (panic/cancel): internal error, same exit
                    // shape as a parse failure. Pre-dispatch bail — the armed `probe_guard` releases
                    // any won single-flight probe on drop (owner-checked).
                    Err(_) => {
                        drop(permit);
                        return ingress_error(
                            ingress_protocol,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            KIND_API_ERROR,
                            DETAIL_INTERNAL_ERROR,
                        );
                    }
                }
            } else {
                translate_request_cross_protocol(
                    app,
                    i,
                    ingress_protocol,
                    op,
                    hop_v,
                    req_content_type,
                    effective_reasoning(&cands, i, app.engine_tables().lanes()[i].reasoning),
                    &body,
                    resolved_gov_key
                        .map(|k| k.id.as_str())
                        .unwrap_or("anonymous"),
                )
            };
            match translated {
                Ok(p) => p,
                Err(resp) => {
                    // A translation failure also bails before dispatch — the armed `probe_guard`
                    // releases any won single-flight probe on drop (owner-checked), same
                    // wedged-HalfOpen leak avoided as the re-parse path above.
                    drop(permit);
                    return *resp;
                }
            }
        };
        // STREAMING-USAGE UPSTREAM INJECTION: busbar bills a
        // streaming chat call from the token usage it decodes off the upstream stream, but an OpenAI
        // Chat Completions upstream only emits that usage (in a trailing chunk) when the request
        // carried `stream_options.include_usage: true`. A client that did not opt in would otherwise
        // leave the upstream silent on tokens and busbar would bill ZERO. So force
        // `stream_options.include_usage` on a streaming request to an OpenAI Chat egress.
        //
        // PERF: an unconditional injector runs the DOM-parse+re-serialize
        // for every streaming OpenAI egress, including the same-protocol pristine
        // passthrough the head short-circuit exists to keep parse-free (the flagship lazy_body win).
        // Two gates avoid that:
        //   1. If the CLIENT already opted in (`client_include_usage`), the upstream body ALREADY
        //      carries `include_usage:true` - injection is a pure no-op re-serialize. Skip it entirely,
        //      preserving the pristine re-emit for the opted-in same-proto path.
        //   2. Otherwise inject via the HEAD-GATED byte-level path when the body carries no top-level
        //      `stream_options` (`!client_has_stream_options`): a single splice after the opening `{`
        //      that never materializes the DOM, so an opted-out pristine same-proto body stays
        //      parse-free too. Only the rare body that DOES carry a non-opted-in `stream_options`
        //      (e.g. `include_usage:false`, or sibling keys only) falls to the DOM injector.
        // Scoped to egresses that DECLARE `stream_usage_requires_opt_in` (Chat Completions) - every
        // other dialect's stream reports usage unconditionally, so there is nothing to inject and
        // this path never learns which dialect that was. The client-facing trailing
        // chunk is then gated on the CLIENT's own opt-in at the framing seam (both the cross-proto
        // `on_egress_chunk` un-fold/strip AND the same-proto verbatim strip), so this
        // injection never leaks an unsolicited usage chunk to an opted-out client.
        let payload = if wants_stream
            && body_is_json
            && busbar_core::proto::decl_for(egress_name).is_some_and(|d| d.stream_usage_requires_opt_in)
            && !client_include_usage
        {
            if client_has_stream_options {
                inject_openai_stream_include_usage(payload)
            } else {
                inject_openai_stream_include_usage_pristine(payload)
            }
        } else {
            payload
        };
        // TRANSLATE_REQ ends here (egress payload bytes in hand). CLIENT_BUILD spans the egress auth
        // + URL/path build + reqwest RequestBuilder construction that follows.
        drop(_xlate);
        let _cbuild = busbar_core::profile::start(busbar_core::profile::Stage::ClientBuild);
        let _t = busbar_timing::timeit!("egress_client_build");
        // MEASUREMENT ONLY (busbar-timing, additive): `egress_assemble` sub-scopes everything
        // below that is NOT the network send — credential select, path/URI build, auth-header
        // build (itself sub-timed as `egress_sigv4`), and reqwest `RequestBuilder` construction.
        // Dropped explicitly just before the send so its span never overlaps `egress_send`; the
        // outer `egress_client_build` (`_t` above) is untouched and should ~= assemble + send.
        let _asm = busbar_timing::timeit!("egress_assemble");

        // Mode-aware key selection: passthrough uses caller token, others use lane's api_key.
        // `upstream_creds` was resolved once before the loop (invariant per request).
        let key = match upstream_creds {
            // Passthrough forwards the CALLER's credential upstream. When the caller presents NO
            // credential, fall back to an EMPTY credential — NOT the lane operator's `api_key`
            // (a SECURITY boundary): borrowing the operator key would let an unauthenticated caller
            // silently spend on the operator's upstream account. An empty credential makes the
            // provider return its own 401/403, attributed to the caller (a client-auth fault, no
            // lane penalty), matching the documented passthrough contract. No-op in canonical
            // keyless passthrough (lane.api_key already empty); only changes the misconfigured
            // passthrough+configured-key case.
            busbar_core::auth::UpstreamCreds::Passthrough => caller_token.unwrap_or(""),
            busbar_core::auth::UpstreamCreds::Own => {
                app.engine_tables().lanes()[i].api_key.expose_secret()
            }
        };

        // per-request auth (SigV4 for Bedrock; static for others) needs the host/path/body.
        // The operation resolves its own upstream path from this lane: chat delegates to the
        // writer's stream-aware default (honoring any provider `path` override) — byte-identical to
        // the previous inline logic. `None` means this lane's protocol does not speak this
        // operation; unreachable for chat (every protocol speaks it), and impossible once the
        // router filters candidates by operation support, but the engine still bails safely rather
        // than dispatch to a wrong path — releasing any single-flight probe this lane won so it
        // cannot wedge HalfOpen (same contract as the re-parse/translate guards above).
        // The (operation × stream) egress target — wire URL and SigV4 canonical URI — was
        // precomputed at boot on the lane (pure functions of lane-constant config; see
        // `egress::build_egress_targets`, which also owns the sign-what-you-send encoding rule),
        // so this is a table read instead of a per-request path render + encode + URL parse. A
        // lookup miss is the exact condition the old `upstream_path` `None` arm caught: the
        // lane's protocol has no registered handler — bail safely, releasing any single-flight
        // probe this lane won so it cannot wedge HalfOpen.
        let Some(target) = app.engine_tables().lanes()[i].egress_target(op.operation, wants_stream)
        else {
            // Pre-dispatch bail (protocol has no handler for this op): the armed `probe_guard`
            // releases any won single-flight probe on drop (owner-checked).
            drop(permit);
            return ingress_error(
                ingress_protocol,
                StatusCode::INTERNAL_SERVER_ERROR,
                KIND_API_ERROR,
                DETAIL_INTERNAL_ERROR,
            );
        };
        let _cb_auth = busbar_core::profile::start(busbar_core::profile::Stage::CbAuth);
        // ONE wall-clock read for this attempt's assemble stage: the SigV4 timestamp here plus the
        // deadline-remaining reads at the timeout sites below. All three are second-granularity and
        // no await separates them (pick → translate → auth → build → send is one synchronous run),
        // so a shared read changes no observable value — the SigV4 timestamp is still taken INSIDE
        // the attempt loop, per attempt (the 5-minute-skew rule), never hoisted out of it.
        let attempt_wall = now();
        let signing_ctx = busbar_core::proto::SigningContext {
            host: &app.engine_tables().lanes()[i].signing_host,
            canonical_uri: &target.canonical_uri,
            body: &payload,
            timestamp_epoch: attempt_wall,
            upstream_creds: app.engine_tables().upstream_creds(),
        };
        // Own-mode dispatch on a lane-constant credential takes the boot-prebuilt header map (one
        // buffer copy, byte-identical to the live build — see `Lane::prebuilt_auth`). Passthrough
        // carries the CALLER's key and a non-constant credential (OAuth / SigV4) reads the request,
        // so both build live, exactly as before.
        // MEASUREMENT ONLY: `egress_sigv4` isolates the live auth-header build (SigV4 signing on
        // Bedrock; a cheap static/bearer build on other non-prebuilt arms, where this reads ~0).
        let egress_auth = match (
            &app.engine_tables().lanes()[i].prebuilt_auth,
            upstream_creds,
        ) {
            (Some(pre), busbar_core::auth::UpstreamCreds::Own) => pre.clone(),
            _ => convert_headers(busbar_timing::scope("egress_sigv4", || {
                lane_auth_headers(&app.engine_tables().lanes()[i], key, &signing_ctx)
            })),
        };
        drop(_cb_auth);

        // Egress request Content-Type: JSON bodies stay JSON (chat byte-identical). An OPAQUE body
        // relays the caller's own CT same-protocol (multipart boundary preserved verbatim) and uses
        // the EGRESS operation handler's declared wire CT cross-protocol (its write_request built
        // that wire — e.g. openai transcription's fixed-boundary multipart).
        let egress_ct: &str = if body_is_json {
            APPLICATION_JSON
        } else if ingress_protocol == egress_name {
            req_content_type
        } else {
            busbar_core::handlers::request_handler(egress_name)
                .and_then(|rh| rh.operation_handler(op.operation))
                .map(|h| h.egress_request_content_type())
                .unwrap_or(APPLICATION_JSON)
        };
        let _cb_reqwest = busbar_core::profile::start(busbar_core::profile::Stage::CbReqwest);
        // Assemble the egress request from PRECOMPUTED parts: the lane's boot-parsed
        // `http::Uri`, the prebuilt/live auth map extended in place with the three per-request
        // constants, and the body as one owned buffer. No builder machinery, no per-send URL
        // parse. Header ORDER matches the old builder exactly (auth, then CT/UA/Accept).
        let mut egress_headers = egress_auth;
        // Egress Content-Type: the JSON arm is a static constant; the two rare opaque-relay arms
        // carry bytes that arrived as a validated inbound header, so the parse cannot fail in
        // practice — a hostile impossibility maps to the same internal-error exit as a failed
        // translate rather than a panic.
        let ct_value = if body_is_json {
            axum::http::HeaderValue::from_static(APPLICATION_JSON)
        } else {
            match axum::http::HeaderValue::from_str(egress_ct) {
                Ok(v) => v,
                Err(_) => {
                    // Pre-dispatch bail: the armed `probe_guard` releases any won single-flight probe
                    // on drop (owner-checked).
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
        egress_headers.insert(CONTENT_TYPE, ct_value);
        // Native-SDK User-Agent for the egress protocol. The shared client sets none, so without
        // this the backend sees a UA-less request — a proxy fingerprint. `from_static`: a
        // protocol-declaration constant.
        egress_headers.insert(
            USER_AGENT,
            axum::http::HeaderValue::from_static(crate::engine::egress_user_agent(egress_name)),
        );
        // Native-SDK Accept for the egress protocol (eventstream/json/SSE by stream intent) — a
        // declaration constant, chosen by the operation; not part of SigV4 SignedHeaders.
        egress_headers.insert(
            ACCEPT,
            axum::http::HeaderValue::from_static(op.egress_accept(egress_name, wants_stream)),
        );
        let hreq = crate::engine::egress_request(target.uri.clone(), egress_headers, payload);
        drop(_cb_reqwest);
        // TIMEOUT RE-PROVISION (was reqwest's per-request/client-level `.timeout()`, which bounded
        // the ENTIRE lifecycle — connect, response headers, body). ONE deadline per attempt:
        //   * NON-streaming: the failover-budget remainder, on the send AND every buffered read —
        //     reqwest's per-request timeout, exactly.
        //   * STREAMING: the client-level ceiling (`limits.upstream_request_timeout_secs`),
        //     anchored HERE at send start and carried into the stream body's own ceiling below —
        //     reqwest's client-level envelope, exactly. Bounding a stream with the (much shorter)
        //     failover budget would truncate healthy long generations; bounding it with NOTHING
        //     let a black-holed upstream hold the send open forever with no breaker signal (audit
        //     finding F1: connect+TLS completed, headers never sent → indefinite hang). Expiry on
        //     either arm classifies as a transport timeout — what reqwest's is_timeout() reported.
        let send_deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(if wants_stream {
                app.client_settings.upstream_request_timeout_secs.max(1)
            } else {
                request_ctx.remaining(attempt_wall).max(1)
            });
        // CLIENT_BUILD ends here (the request is fully assembled). UPSTREAM_SEND spans the
        // client round-trip to response headers.
        drop(_cbuild);
        // MEASUREMENT ONLY: `egress_assemble` ends here — everything above this point was
        // assembly (credential select, path/header/request build); everything below is the send.
        // Only compiled under `timing`: with the feature off `_asm` is a zero-sized no-op guard
        // (`()`), and `drop`ping a `Copy` value does nothing — the `dropping_copy_types` lint.
        #[cfg(feature = "timing")]
        drop(_asm);
        let _send = busbar_core::profile::start(busbar_core::profile::Stage::UpstreamSend);
        // MEASUREMENT ONLY: `egress_send` spans ONLY the send round-trip below
        // (both the attempt-capped and uncapped arms), dropped right after the match resolves.
        let _snd = busbar_timing::timeit!("egress_send");
        // Wall-clock start of the upstream call, for the `metrics.latencyMs` a native bedrock
        // ConverseStream `metadata` frame carries on the buffered-synthesis path below.
        let upstream_started = std::time::Instant::now();
        // PER-ATTEMPT time-to-response-headers cap (`attempt_timeout_ms` — the hang detector). The
        // pool-member override wins over the model-level value; either is floored by the remaining
        // request budget. The send resolves when RESPONSE HEADERS arrive, so wrapping it bounds the
        // hang (connect + headers) without bounding a healthy long stream's BODY — the stream
        // rationale above is untouched. Expiry maps to the same transport-error arm as any
        // transport timeout: transient → breaker failure → fail over WITHIN this request.
        let attempt_ms = effective_attempt_timeout_ms(
            &cands,
            i,
            app.engine_tables().lanes()[i].attempt_timeout_ms,
        );
        // The non-stream budget deadline wraps BOTH send arms (reqwest applied it to the whole
        // request; the attempt cap, when smaller, still fires first inside). An expired budget
        // classifies as a transport timeout — exactly what reqwest's `is_timeout()` reported.
        let send_fut = async {
            let send = app.engine_tables().client().get().request(hreq);
            match attempt_ms {
                Some(ms) => {
                    let cap = attempt_cap(ms, request_ctx.remaining(attempt_wall));
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
                // Mirror the transport-timeout arm below EXACTLY (breaker record, trip emit,
                // failure + failover metrics, permit drop) — the only deltas are the distinct
                // `attempt_timeout` disposition/reason labels so operators can see hang-hops as
                // their own series, and the warn naming the cap.
                record_upstream_rtt(upstream_started.elapsed());
                let tripped = app.store.record_transient_in(
                    pool_name,
                    i,
                    ERR_NET_TIMEOUT,
                    &breaker_cfg,
                    None,
                );
                if tripped {
                    emit_breaker_trip(app, pool_name, i);
                }
                busbar_core::telemetry::upstream_failure(
                    app,
                    metric_pool,
                    i,
                    DISPOSITION_ATTEMPT_TIMEOUT,
                );
                busbar_core::telemetry::failover(app, metric_pool, DISPOSITION_ATTEMPT_TIMEOUT);
                diag_debug!(
                    ATTEMPT_TIMEOUT_FAILOVER,
                    pool = %pool_name,
                    lane = %app.engine_tables().lanes()[i].model,
                    attempt_timeout_ms = ms,
                    "no response headers within the attempt cap; failing over"
                );
                last_failure = Some(DISPOSITION_ATTEMPT_TIMEOUT);
                drop(permit);
                continue;
            }
        };
        // MEASUREMENT ONLY: `egress_send` ends here, matching `UPSTREAM_SEND` below exactly.
        // Only compiled under `timing` — see the `drop(_asm)` note above (feature-off `_snd` is `()`).
        #[cfg(feature = "timing")]
        drop(_snd);
        // UPSTREAM_SEND ends here (response headers received or transport error).
        drop(_send);
        record_upstream_rtt(upstream_started.elapsed());

        // Every BUFFERED read of this response below (error bodies, the cross-protocol translate
        // buffer) rides the SAME deadline as the send — the budget remainder (non-stream) or the
        // client-ceiling envelope anchored at send start (stream-intent responses read buffered
        // anyway, e.g. a non-2xx error body). One instant, one envelope, exactly reqwest's.
        let read_deadline = send_deadline;

        // POST_SEND: the last uncounted span inside `busbar;dur` — response status/StatusClass
        // classification + 2xx/failover branch selection, up to the RecordSuccess boundary on the
        // success arm (dropped there). On a failover `continue` it records that attempt's classify.
        let _postsend = busbar_core::profile::start(busbar_core::profile::Stage::PostSend);
        match res {
            Err(e) => {
                // Pre-response error: classify and potentially failover
                let err_type = if e.is_timeout() {
                    ERR_NET_TIMEOUT
                } else {
                    ERR_NET_CONNECT
                };
                let tripped =
                    app.store
                        .record_transient_in(pool_name, i, err_type, &breaker_cfg, None);
                // A threshold-based Closed→Open trip is a breaker trip for this (pool, lane) — emit
                // BREAKER_TRIPS_TOTAL once, mirroring the HardDown arm (#29). `record_transient_in`
                // returns `true` only on a logical trip (not a HalfOpen reopen or already-Open no-op),
                // so the counter is not multi-counted per cell or per cooldown bump.
                if tripped {
                    emit_breaker_trip(app, pool_name, i);
                }
                busbar_core::telemetry::upstream_failure(app, metric_pool, i, DISPOSITION_TRANSIENT);
                busbar_core::telemetry::failover(app, metric_pool, err_type);
                last_failure = Some(err_type);
                drop(permit);
                continue;
            }
            Ok(r) => {
                let status = r.status();

                // For non-2xx responses, read the body to classify (failover allowed)
                if !status.is_success() {
                    // caveat: passthrough 401/403 is caller's key failing, not busbar's
                    // Do NOT trip breaker / change member health; relay verbatim to caller
                    let is_passthrough_40x = upstream_creds
                        == busbar_core::auth::UpstreamCreds::Passthrough
                        && (status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN);

                    // Clone headers before consuming r with bytes(). The upstream `Retry-After`
                    // header (whole seconds) must be captured here — the per-protocol
                    // `extract_error` only sees the body, so the cooldown floor would otherwise be
                    // silently dropped on a 429 carrying an explicit retry hint.
                    let ct = r.headers().get(CONTENT_TYPE).cloned();
                    let retry_after_secs = busbar_core::breaker::parse_retry_after(r.headers());
                    // A real AWS Bedrock endpoint sends `x-amzn-requestid` and `x-amzn-errortype` on
                    // EVERY response, including 4xx. First-party AWS SDKs read `x-amzn-errortype`
                    // BEFORE the body `__type` for typed-exception dispatch; their absence on a
                    // same-protocol Bedrock→Bedrock error relay is a detectable indistinguishability
                    // tell. Capture them here (before `r` is consumed) so the same-protocol passthrough
                    // branches below can forward them verbatim on a bedrock-ingress relay.
                    let upstream_amzn_headers: Vec<(
                        axum::http::HeaderName,
                        axum::http::HeaderValue,
                    )> = if ingress_relays_amzn_headers(ingress_protocol) {
                        ingress_relayed_response_header_names(ingress_protocol)
                            .iter()
                            .filter_map(|name| {
                                let v = r.headers().get(*name)?.clone();
                                let n = axum::http::HeaderName::from_static(name);
                                Some((n, v))
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };
                    // For a NON-amzn same-protocol error relay (anthropic), capture the upstream's
                    // PRIMARY relayed id (`request-id`) so it can be forwarded verbatim — or synthesized
                    // if the upstream omitted it — mirroring `forward_once`'s same-proto error relay.
                    // Empty for protocols with no relayed header name.
                    let upstream_error_relay_id: Option<String> =
                        ingress_relayed_response_header_names(ingress_protocol)
                            .first()
                            .and_then(|name| r.headers().get(*name))
                            .and_then(|h| h.to_str().ok())
                            .map(|s| s.to_string());
                    // Size-capped read: a hostile/misconfigured upstream must not force an unbounded
                    // heap allocation for a non-2xx body before the breaker classification runs.
                    let bytes = read_capped_body(r, read_deadline).await;

                    if is_passthrough_40x {
                        // Verbatim relay of the upstream 401/403 body+CT is correct ONLY on the
                        // same-protocol path, where the upstream error is already in the client's
                        // native shape. On a CROSS-protocol boundary (e.g. an Anthropic-ingress client
                        // routed to an OpenAI backend that 401s) relaying the egress provider's native
                        // error envelope and Content-Type to a different-protocol SDK is a
                        // foreign-format leak — the SDK fails to decode it into its typed
                        // exception, an immediate proxy tell. Reshape into the ingress protocol's
                        // native envelope instead, deriving the kind from the status (the sibling
                        // ClientFault branch does the same). The passthrough breaker invariant is
                        // unchanged either way: no breaker penalty for a caller-key auth failure.
                        if ingress_protocol != egress_name {
                            // A passthrough 401/403 is the CALLER's own key failing — no breaker
                            // penalty — so no failure outcome is recorded to clear `probe_in_flight`.
                            // The still-armed `probe_guard` releases any won recovery probe on this
                            // return (owner-checked), so the lane never wedges HalfOpen.
                            // Reshape via the shared finalizer so the kind→native-envelope mapping
                            // (401→authentication_error, 403→permission_error, …) is identical on the
                            // main path, the degraded path, and the ClientFault branch below.
                            return shape_cross_protocol_error(ingress_protocol, status, &bytes);
                        }
                        // Same-protocol passthrough 401/403: caller-key auth failure carries no
                        // breaker penalty, so nothing clears `probe_in_flight`. The still-armed
                        // `probe_guard` releases any won probe on this return (owner-checked) before
                        // the verbatim relay, so the lane never wedges HalfOpen.
                        use axum::body::Body;
                        let mut rb = Response::builder().status(status);
                        if let Some(ct) = ct {
                            rb = rb.header(CONTENT_TYPE, ct);
                        }
                        // Forward the native response request-id header(s) on a same-protocol relay so
                        // the SDK's `request_id()` matches a real endpoint. Bedrock: both
                        // `x-amzn-requestid` + `x-amzn-errortype` VERBATIM. Anthropic: `request-id`
                        // upstream-or-synth (a native Anthropic 4xx always carries it). Mirrors forward_once.
                        if ingress_relays_amzn_headers(ingress_protocol) {
                            for (name, value) in &upstream_amzn_headers {
                                rb = rb.header(name, value);
                            }
                        } else {
                            rb = maybe_attach_response_request_id(
                                rb,
                                ingress_protocol,
                                upstream_error_relay_id.as_deref(),
                            );
                        }
                        // Re-create response from bytes for same-protocol passthrough relay
                        return rb
                            .body(Body::from(bytes))
                            .unwrap_or_else(|_| status.into_response());
                    }

                    // Two-stage pipeline: Stage 1a (the cell's `extract_error`) → RawUpstreamError
                    //                     Stage 1b (normalize_raw_error + error_map) → CanonicalSignal
                    //                     Stage 2 (breaker::classify_disposition) → Disposition
                    //
                    // Stage 1a asks the CELL that spoke to this upstream — the EGRESS protocol's
                    // codec for the operation being served, framed by the channel the attempt rode —
                    // rather than the lane's chat vtable. For the six LLM protocols the answer is
                    // identical (their cells all read the one envelope their protocol defines), and
                    // an operation whose upstream is not a lane at all is attributed the same way.
                    let mut raw = busbar_core::handlers::op_for(
                        egress_name,
                        op.operation,
                        busbar_core::transport::Transport::Http,
                    )
                    .map(|cell| cell.extract_error(status.as_u16(), &bytes))
                    .unwrap_or_else(|| {
                        busbar_core::breaker::RawUpstreamError::from_status(status.as_u16())
                    });
                    // Inject the Retry-After header (which the body-only extract_error can't see) so
                    // normalize_raw_error propagates it into CanonicalSignal.retry_after and the
                    // store honors it as a cooldown floor.
                    raw.retry_after_secs = retry_after_secs;
                    let sig = normalize_raw_error(&raw, &app.engine_tables().lanes()[i].error_map);
                    let disposition = classify_disposition(&sig);

                    // Exhaustive match on Disposition - no `_` arm, so a new disposition breaks the build
                    match disposition {
                        Disposition::ClientFault => {
                            // ADR-0002: Client fault (caller's bad input) → no breaker penalty.
                            // Track client_fault separately from upstream err.
                            app.store.record_client_fault(i);
                            // `record_client_fault` only bumps an observability counter — it does NOT
                            // clear `probe_in_flight`. Both ClientFault exits below (cross-protocol
                            // reshape and same-protocol verbatim relay) return without recording any
                            // breaker outcome, so the still-armed `probe_guard` is what releases any
                            // won recovery probe on those returns (owner-checked) — leaving the lane
                            // immediately re-probeable rather than wedged HalfOpen.
                            // Same-protocol passthrough relays the upstream 4xx body + CT verbatim
                            // (it is already in the client's native shape). Cross-protocol must
                            // RESHAPE the error into the ingress protocol's native envelope —
                            // relaying the EGRESS protocol's error body to a different-protocol
                            // client is an immediate proxy tell (e.g. an OpenAI-shaped 400 reaching
                            // an Anthropic SDK). The human message is lifted from the upstream body
                            // where available; the kind is derived from the classified StatusClass.
                            if ingress_protocol != egress_name {
                                let kind = client_fault_kind(sig.class);
                                let msg = extract_error_message(&bytes)
                                    .unwrap_or_else(|| GENERIC_REJECTED_DETAIL.to_string());
                                return ingress_error(ingress_protocol, status, kind, &msg);
                            }
                            use axum::body::Body;
                            let mut rb = Response::builder().status(status);
                            if let Some(ct) = ct {
                                rb = rb.header(CONTENT_TYPE, ct);
                            }
                            // Same as the passthrough-40x branch: preserve the native response
                            // request-id header on a same-protocol client-fault relay — bedrock's
                            // `x-amzn-*` verbatim, anthropic's `request-id` upstream-or-synth.
                            if ingress_relays_amzn_headers(ingress_protocol) {
                                for (name, value) in &upstream_amzn_headers {
                                    rb = rb.header(name, value);
                                }
                            } else {
                                rb = maybe_attach_response_request_id(
                                    rb,
                                    ingress_protocol,
                                    upstream_error_relay_id.as_deref(),
                                );
                            }
                            return rb
                                .body(Body::from(bytes))
                                .unwrap_or_else(|_| status.into_response());
                        }
                        Disposition::TransientUpstream => {
                            // Transient upstream failure → cooldown + err counter
                            // Record based on specific error type (exhaustive over remaining variants)
                            let tripped = if matches!(sig.class, StatusClass::RateLimit) {
                                app.store.record_rate_limit_in(
                                    pool_name,
                                    i,
                                    now(),
                                    &breaker_cfg,
                                    sig.retry_after,
                                )
                            } else {
                                let what = match sig.class {
                                    StatusClass::ServerError => "5xx",
                                    StatusClass::Timeout => ERR_NET_TIMEOUT,
                                    StatusClass::Network => "network",
                                    StatusClass::Overloaded => KIND_OVERLOADED,
                                    StatusClass::RateLimit => {
                                        // Should have been handled above but Rust needs exhaustive match
                                        "rate_limit"
                                    }
                                    // No-panic-on-request-path invariant: `breaker::classify` does not
                                    // currently map Auth/Billing/ClientError/ContextLength to
                                    // TransientUpstream, but encoding that as `unreachable!()` would
                                    // panic a Tokio worker (dropping every in-flight request on it) the
                                    // first time a future classifier change made one of them reachable.
                                    // Record a generic transient label instead — correct under today's
                                    // mapping and graceful if it ever changes.
                                    StatusClass::Auth
                                    | StatusClass::Billing
                                    | StatusClass::ClientError
                                    | StatusClass::ContextLength => "transient",
                                };
                                app.store.record_transient_in(
                                    pool_name,
                                    i,
                                    what,
                                    &breaker_cfg,
                                    sig.retry_after,
                                )
                            };
                            // A threshold-based Closed→Open trip is a breaker trip for this (pool,
                            // lane) — emit BREAKER_TRIPS_TOTAL once, mirroring the HardDown arm (#29).
                            if tripped {
                                emit_breaker_trip(app, pool_name, i);
                            }
                            busbar_core::telemetry::upstream_failure(
                                app,
                                metric_pool,
                                i,
                                DISPOSITION_TRANSIENT,
                            );
                            busbar_core::telemetry::failover(app, metric_pool, DISPOSITION_TRANSIENT);
                            last_failure = Some(DISPOSITION_TRANSIENT);
                            drop(permit);
                            continue;
                        }
                        Disposition::HardDown => {
                            // Hard down → permanent dead state (with probe recovery per)
                            // Only Billing and Auth reach this arm per breaker::classify
                            let reason = match sig.class {
                                StatusClass::Billing => {
                                    "billing / insufficient balance".to_string()
                                }
                                StatusClass::Auth => {
                                    format!("auth rejected (HTTP {})", status.as_u16())
                                }
                                // No-panic-on-request-path invariant: `breaker::classify` only maps
                                // Auth/Billing to HardDown today, but `unreachable!()` here would panic
                                // the worker the first time a classifier change routed another class to
                                // HardDown. Fall back to a generic reason (carrying the HTTP status for
                                // diagnostics) instead — graceful and robust to future mapping changes.
                                StatusClass::RateLimit
                                | StatusClass::Overloaded
                                | StatusClass::ServerError
                                | StatusClass::Timeout
                                | StatusClass::Network
                                | StatusClass::ClientError
                                | StatusClass::ContextLength => {
                                    format!("request rejected (HTTP {})", status.as_u16())
                                }
                            };
                            // A hard-down (auth rejection / billing exhaustion) is a property of the
                            // SHARED upstream, not of one routing pool: trip the lane in EVERY cell
                            // (default "" cell that `named`/`adhoc`/direct routes read AND every
                            // per-pool cell), mirroring `recover_lane`'s all-cells reach. Tripping
                            // only `pool_name`'s cell left the same dead upstream Closed in the other
                            // cells, so legacy/cross-protocol routes kept hammering it until the
                            // out-of-band prober caught it (the asymmetry this fixes).
                            let newly_tripped = app.store.record_hard_down_all_cells(i, &reason);
                            // A hard-down is a breaker trip for this lane — but only count a LOGICAL
                            // Closed→Open trip. A persistently-dead auth/billing lane re-enters this arm
                            // on every recovery-probe cycle (a HalfOpen reopen, not a fresh trip); gating
                            // on `newly_tripped` stops BREAKER_TRIPS_TOTAL inflating once per cooldown
                            // for a stuck lane (the metric's "once per logical trip" contract).
                            // Gate the warn on the LOGICAL Closed→Open trip, mirroring the
                            // BREAKER_TRIPS_TOTAL gating just above: a persistently-dead lane re-enters
                            // this arm on every recovery-probe cycle, so an ungated warn spams once per
                            // cooldown for a stuck lane. Warn on the fresh trip; the recurring
                            // still-down probe logs at `debug!`.
                            if newly_tripped {
                                busbar_core::telemetry::breaker_trip(app, metric_pool, i);
                                diag_warn!(LANE_HARD_DOWN, pool = %pool_name, lane = %app.engine_tables().lanes()[i].model, reason = %reason, "lane hard-down (breaker trip)");
                            } else {
                                diag_debug!(LANE_HARD_DOWN, pool = %pool_name, lane = %app.engine_tables().lanes()[i].model, reason = %reason, "lane still hard-down (recovery probe re-tripped)");
                            }
                            busbar_core::telemetry::upstream_failure(
                                app,
                                metric_pool,
                                i,
                                DISPOSITION_HARD_DOWN,
                            );
                            drop(permit);

                            // For auth failures: return error to caller. In NON-passthrough mode the
                            // rejected credential is busbar's OWN configured lane key, so the
                            // upstream's auth-rejection body is busbar-internal context (account
                            // ids, internal request ids, key hints) — do NOT leak it to an external
                            // caller. Return a normalized envelope instead. (Passthrough 401/403 is
                            // the caller's own key and is relayed verbatim earlier, before this.)
                            if matches!(sig.class, StatusClass::Auth) {
                                // Route through ingress_error so the body is the INGRESS protocol's
                                // NATIVE error envelope (Bedrock `{"__type":"AccessDeniedException",...}`,
                                // Gemini `{"error":{"status":"UNAUTHENTICATED",...}}`, etc.), not a
                                // hard-coded OpenAI-shaped body. The wire MESSAGE is the
                                // vendor-plausible auth-failure copy for the ingress protocol — NOT
                                // busbar-internal vocabulary. The previous "upstream rejected the lane
                                // credential" leaked the internal "lane" concept (no real vendor uses
                                // that word), a deterministic proxy tell; and in non-passthrough mode
                                // the rejected key is busbar's OWN, so the upstream's auth-rejection
                                // body must never be relayed either. The native error kind carries the
                                // auth signal; the message just reads like the real vendor's copy.
                                // Pass the INGRESS-protocol-native auth-failure status and kind, NOT
                                // the upstream's raw HTTP status. A real Bedrock auth failure is HTTP
                                // 403 AccessDeniedException and a real Gemini bad-key is HTTP 400
                                // INVALID_ARGUMENT — neither vendor ever returns 401 for auth. Echoing
                                // the egress backend's raw `status` (e.g. an Anthropic backend's 401)
                                // to a Bedrock/Gemini ingress client is a protocol-distinguishability
                                // tell and breaks SDK auth-retry/credential-refresh logic that keys off
                                // the native status. The canonical mapping lives in `auth.rs`
                                // (`auth_failure_status_and_kind`) so this path cannot drift from the
                                // pre-routing auth path.
                                let (auth_status, auth_kind) =
                                    busbar_core::auth::auth_failure_status_and_kind(ingress_protocol);
                                return ingress_error(
                                    ingress_protocol,
                                    auth_status,
                                    auth_kind,
                                    busbar_core::proto::vendor_auth_failure_message(ingress_protocol),
                                );
                            }

                            // For billing hard downs: continue to next lane (failover)
                            busbar_core::telemetry::failover(app, metric_pool, DISPOSITION_HARD_DOWN);
                            last_failure = Some(DISPOSITION_HARD_DOWN);
                            continue;
                        }
                        Disposition::ContextLength => {
                            // the request is too large for THIS model's context window.
                            // exclude from this request any candidate lane whose context_max
                            // is Some(c) with c <= failed_lane_context_max (and the failed lane itself).
                            // Rationale: those lanes share or undercut the limit that just failed,
                            // so don't waste attempts on them — failover lands on a larger-context
                            // (or unknown-context) member. If failed lane's context_max is None,
                            // exclude only the failed lane.
                            let failed_context_max = app.engine_tables().lanes()[i].context_max;

                            // Exclude candidates that cannot handle this request due to context limits.
                            for cand in &cands {
                                if let Some(cand_context_max) =
                                    app.engine_tables().lanes()[cand.idx].context_max
                                {
                                    // If this candidate has a known limit <= failed lane's limit, exclude it.
                                    if let Some(failed_limit) = failed_context_max {
                                        if cand_context_max <= failed_limit {
                                            request_ctx.exclude(cand.idx);
                                        }
                                    }
                                }
                            }

                            busbar_core::telemetry::upstream_failure(
                                app,
                                metric_pool,
                                i,
                                DISPOSITION_CONTEXT_LENGTH,
                            );
                            busbar_core::telemetry::failover(
                                app,
                                metric_pool,
                                DISPOSITION_CONTEXT_LENGTH,
                            );
                            // ContextLength is a client-fault variant (the request is too large for
                            // THIS lane's window) — no breaker penalty, so nothing records an outcome
                            // to clear `probe_in_flight`. The still-armed `probe_guard` releases any
                            // won recovery probe when it drops at this iteration's end (owner-checked),
                            // so this `continue` leaves the lane immediately probe-eligible again for
                            // normal-size requests rather than wedged HalfOpen.
                            last_failure = Some(DISPOSITION_CONTEXT_LENGTH);
                            drop(permit);
                            continue;
                        }
                    }
                }

                // POST_SEND ends here (success arm reached); RECORD_SUCCESS begins.
                drop(_postsend);
                // RECORD_SUCCESS: the post-2xx breaker/latency/budget bookkeeping (store lock ops).
                let _rec = busbar_core::profile::start(busbar_core::profile::Stage::RecordSuccess);
                // SUCCESS case: the upstream served a 2xx. Record the success for this lane (feeds
                // the per-lane `ok` counter and the breaker's success window) and consume one unit
                // of its lifetime request budget (the `max_requests` cost cap; `usable()` stops
                // admitting the lane once it reaches 0).
                app.store.record_success_in(pool_name, i);
                // DISARM the probe guard: `record_success_in` recorded this dispatch's legitimate
                // outcome (HalfOpen→Closed, probe cleared), so the request now owns the probe through
                // to that outcome. From here the streamed/buffered success body (or its own mid-stream
                // failure recording) is responsible for the cell, and the guard must NOT also release
                // it on drop (buffered return, cross-protocol translate handoff, or FirstByteBody
                // handoff below). No-op when no guard was built (a Closed-ready no-op admit).
                if let Some(g) = probe_guard.as_mut() {
                    g.armed = false;
                }
                // Fold this request's time-to-headers into the lane's latency EWMA (the routing
                // `fastest` signal). Measured to the upstream RESPONSE HEADERS (`req.send().await`
                // completion) — a cheap, bounded proxy that does NOT wait out an unbounded streaming
                // body. Lane-global + off the selection path; a no-op unless a `route: fastest` (or a
                // webhook/script policy reading `latency_ms`) consults it.
                app.store.record_latency_in(
                    pool_name,
                    i,
                    upstream_started.elapsed().as_secs_f64() * 1000.0,
                );
                // BIND the spend result (#21): the post-success spend is COST accounting, not the
                // admission gate (that was `lane_admissible`/`usable` before dispatch). It can no
                // longer over-spend; `false` means this lane was already at 0 (the next admission
                // check rejects it) OR that the spend was a no-op. The paired post-headers body
                // TransportError below refunds the budget, but `refund_budget` UNCONDITIONALLY
                // fetch_adds — so a refund of a no-op spend would push the budget ABOVE its cap. Guard
                // the refund on this bool. `budget_spent` is `true` for an unlimited lane (the spend
                // is a no-op success there) and `refund_budget` is likewise a no-op there, so an
                // unlimited lane neither over-counts nor under-counts.
                let budget_spent = app.store.spend_budget(i);
                // Guards the buffered path's spend→`read_capped(...).await` window (#21): armed
                // now, disarmed at every exit below that must KEEP the charge. Disarmed (without
                // refunding) just before the streaming builder, which hands the same `budget_spent`
                // value to `FirstByteBody` for its own cancellation-safe refund.
                let mut budget_guard = BudgetSpendGuard {
                    store: app.store.as_ref(),
                    lane: i,
                    armed: budget_spent,
                };
                // RECORD_SUCCESS ends; RESP_BUILD spans everything from here to the returned Response
                // (usage/CT capture, SSE-vs-buffered branch, FirstByteBody wiring, response builder).
                drop(_rec);
                let _resp = busbar_core::profile::start(busbar_core::profile::Stage::RespBuild);
                // RB_PRE sub-stage: header/CT/relay-id capture + SSE detection + translate resolution,
                // up to `FirstByteBody::new`. (The cross-protocol buffered branch returns before the
                // streaming builder, so on that path RB_PRE covers the pre-buffer work only.)
                let _rb_pre = busbar_core::profile::start(busbar_core::profile::Stage::RbPre);

                // stream the response body incrementally with first-byte boundary tracking
                let ct = r.headers().get(CONTENT_TYPE).cloned();
                // Capture the upstream PRIMARY relayed id (if any) BEFORE consuming `r` into the body
                // stream, keyed off the ingress writer's `ingress_relayed_response_header_names` (so
                // this names no protocol module). On a SAME-PROTOCOL streaming passthrough we forward
                // the real upstream id verbatim — `x-amzn-RequestId` for bedrock (a native
                // ConverseStream response carries it), `request-id` for anthropic; on a CROSS-PROTOCOL
                // stream the backend supplied none, so the attach helper synthesizes one below. Either
                // way a bedrock/anthropic-ingress stream must carry the header (matching a real
                // endpoint and the error path).
                let upstream_relay_id = ingress_relayed_response_header_names(ingress_protocol)
                    .first()
                    .and_then(|name| r.headers().get(*name))
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());
                let is_sse = ct
                    .as_ref()
                    .map(|h| is_streaming_content_type(h.to_str().unwrap_or("")))
                    .unwrap_or(false);

                // non-streaming cross-protocol response → buffer the whole JSON and
                // translate egress.read_response → IR → ingress.write_response. (Streaming
                // cross-protocol is handled in FirstByteBody below; same-protocol passes through.)
                if ingress_protocol != app.engine_tables().lanes()[i].protocol && !is_sse {
                    // Box::pin: the buffered cross-protocol translate future (~2.4 KB — the
                    // whole-body read + codec arms) is COLD relative to the pinned hot path (the
                    // same-protocol passthrough never enters, nor does any streaming response),
                    // and the path it serves already buffers the entire upstream body and
                    // materializes a DOM to translate — one boxed future is noise there. Awaited
                    // inline it set this fn's coroutine union max, so every same-proto request
                    // carried its bytes as await-boundary memcpy. (Same cold-arm pattern as the
                    // exhaustion boxes below and the boxed path-model ingress arms in
                    // `ingress::dispatch`.)
                    return Box::pin(translate_response_cross_protocol(
                        app,
                        i,
                        ingress_protocol,
                        op,
                        pool_name,
                        &breaker_cfg,
                        r,
                        read_deadline,
                        permit,
                        &mut budget_guard,
                        usage_sink,
                        status,
                        wants_stream,
                        gemini_json_array,
                        upstream_started,
                        chosen_policy_name,
                        false, // main hot path, not the degraded FallbackPool/LeastBad path
                    ))
                    .await;
                }

                // Use FirstByteBody wrapper to track first byte and emit SSE error events on mid-stream failures
                // on a cross-protocol SSE response, translate egress frames → ingress frames.
                let egress_name_for_translate = app.engine_tables().lanes()[i].protocol;
                // ONE registry-resolved factory, IDENTICAL to the degraded `walk.rs` path (extracted so
                // the two cannot drift): same-protocol SSE builds the verbatim same-proto translator
                // (byte-exact re-emit + IR usage A-tap; billing sources `translate.usage()`, no IR
                // bypass), cross-protocol builds the reframing translator, `!is_sse`/unknown-protocol
                // yields `None` → legacy raw-chunk passthrough.
                let translate = busbar_core::proto::new_stream_translator(
                    ingress_protocol,
                    egress_name_for_translate,
                    is_sse,
                );
                // Thread the client's streaming-usage opt-in to the framing. Busbar
                // always injected `include_usage` UPSTREAM, so the upstream stream carries a trailing
                // usage chunk; the OpenAI-ingress framing surfaces it to the client ONLY when the client
                // itself opted in, and STRIPS it otherwise so an opted-out client never sees the
                // unsolicited `{choices:[], usage}` chunk. No-op for every non-OpenAI ingress framing.
                let translate = translate.map(|mut t| {
                    t.set_client_include_usage(client_include_usage);
                    t
                });
                // Gemini non-`alt=sse` ingress: engage the JSON-array framer (only when this is in
                // fact a streamed SSE response — a same-protocol non-stream gemini response never
                // reaches the streaming builder).
                let json_array = (gemini_json_array && is_sse)
                    .then(|| {
                        busbar_core::proto::decl_for(ingress_protocol)
                            .and_then(|d| d.dialect())
                            .and_then(|dc| dc.make_array_stream_framer())
                    })
                    .flatten();
                // Handing the budget-refund decision to `FirstByteBody` (via `budget_spent` below,
                // which owns the cancellation case) — disarm the local guard so it does not ALSO refund
                // when this stack frame unwinds.
                budget_guard.disarm();
                // RB_PRE ends; RB_BODY spans the FirstByteBody wiring + response builder + return.
                drop(_rb_pre);
                let _rb_body = busbar_core::profile::start(busbar_core::profile::Stage::RbBody);
                let _rb_new = busbar_core::profile::start(busbar_core::profile::Stage::RbNew);
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
                    send_deadline,
                    app.clone(),
                    i,
                    breaker_cfg.clone(),
                    pool_name,
                    translate,
                    json_array,
                    usage_sink,
                    budget_spent,
                );
                let axum_body = guarded_body.into_body();
                drop(_rb_new);
                let _rb_finish = busbar_core::profile::start(busbar_core::profile::Stage::RbFinish);

                let _rbf_build = busbar_core::profile::start(busbar_core::profile::Stage::RbfBuild);
                let mut rb = Response::builder().status(status);
                // Cross-protocol streaming: the body is reframed to the client's format, so the CT
                // must be the ingress client's, not the upstream's. Same-protocol passthrough keeps
                // the upstream CT verbatim..
                let cross_protocol = ingress_protocol != app.engine_tables().lanes()[i].protocol;
                if gemini_json_array && is_sse {
                    // JSON-array streaming body: a `[ {...}, {...} ]` document, not SSE.
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
                drop(_rbf_build);
                let _rbf_attach = busbar_core::profile::start(busbar_core::profile::Stage::RbfAttach);
                // Bedrock-ingress streaming 2xx must carry `x-amzn-RequestId` (a real ConverseStream
                // always does, preferring the captured same-protocol upstream id else synthesizing);
                // anthropic-ingress streaming 2xx must carry `request-id` (the SDK reads it into
                // `Message._request_id`). The writer vtable selects the correct header+value per
                // protocol from the captured upstream id; non-relaying ingress: omit.
                rb = maybe_attach_response_request_id(
                    rb,
                    ingress_protocol,
                    upstream_relay_id.as_deref(),
                );
                // TRANSPARENCY: stamp which routing policy chose this target (no-op on the default
                // path / when the policy Abstained). Covers same-protocol passthrough + all streaming.
                rb = maybe_attach_route_policy(
                    rb,
                    chosen_policy_name,
                    &app.engine_tables().lanes()[i].model,
                );
                drop(_rbf_attach);
                let _rbf_body = busbar_core::profile::start(busbar_core::profile::Stage::RbfBody);
                return rb
                    .body(axum_body)
                    .unwrap_or_else(|_| status.into_response());
            }
        }
    }

    // Box::pin: cold path (candidates exhausted), boxed for the same coroutine-size reason as the
    // in-loop exhaustion return above — the happy path never allocates here.
    Box::pin(handle_exhaustion_for_pool(
        app.clone(),
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

/// Force `stream_options.include_usage: true` on an OpenAI Chat Completions streaming request body so
/// the upstream emits token usage busbar can bill. Parses `payload`, sets the nested flag
/// (creating `stream_options` if absent, overwriting a `false`), and re-serializes. On any parse/shape
/// failure the ORIGINAL bytes are returned unchanged — a malformed body is the upstream's to reject,
/// not busbar's to mangle, and the worst case is the pre-existing zero-usage billing gap rather than a
/// corrupted request. A body that already opted in re-serializes identically in effect.
fn inject_openai_stream_include_usage(payload: Bytes) -> Bytes {
    let mut v: Value = match busbar_core::json::parse(&payload) {
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
    match busbar_core::json::to_vec(&v) {
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
fn inject_openai_stream_include_usage_pristine(payload: Bytes) -> Bytes {
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

/// GLOBAL TAP (observe) stage of the forward pipeline. Fires the global request-stage `kind: tap`
/// hooks FIRE-AND-FORGET: serialize the projection(s) once, then spawn one detached task per tap. A tap gets
/// a write-only send with its own deadline; its reply is ignored, its errors swallowed — a tap can
/// NEVER delay, reorder, or fail the request. Each tap receives the projection its GRANT allows: a
/// `prompt: ro` tap gets the prompt-content projection, a `prompt: no` (default) tap gets shape-only.
/// At most TWO projections are built (shape-only + with-prompt) regardless of tap count. ZERO COST
/// when no tap is configured (the empty-list early return).
#[allow(clippy::too_many_arguments)]
fn fire_global_taps(
    app: &Arc<App>,
    body: &Value,
    raw_body: &[u8],
    content_type: &str,
    operation: busbar_core::operation::Operation,
    pool_name: &str,
    ingress_protocol: &str,
    wants_stream: bool,
    request_id: u64,
    // The caller's `groups:` binding — the SELECTION axis (1.5.3). A tap fires only for a caller in
    // its `groups:` scope (empty scope = every caller). `None` (a groupless caller) matches only
    // unscoped taps. Walked against `app.groups_registry` (self + ancestors).
    caller_group: Option<&str>,
) {
    if app.tap_hooks.is_empty() {
        return;
    }
    // SELECTION: this tap fires for THIS caller iff its `groups:` scope admits the caller.
    let fires = |groups: &[String]| {
        busbar_core::config::caller_in_hook_groups(caller_group, groups, &app.groups_registry)
    };
    let ctx = busbar_core::hooks::RoutingContext {
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
        busbar_core::json::to_vec(&busbar_core::hooks::wire::build(
            busbar_core::hooks::wire::OP_NOTIFY,
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
    let any_prompt = app
        .tap_hooks
        .iter()
        .any(|(_, send_prompt, _, groups)| *send_prompt && fires(groups));
    let any_shape = app
        .tap_hooks
        .iter()
        .any(|(_, send_prompt, _, groups)| !*send_prompt && fires(groups));
    let shape_proj = if any_shape { build_proj(false) } else { None };
    let prompt_proj = if any_prompt { build_proj(true) } else { None };
    for (timeout, send_prompt, hook, groups) in &app.tap_hooks {
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
    app: &Arc<App>,
    pool_name: &str,
) -> std::sync::Arc<busbar_core::store::BreakerCfg> {
    match app
        .engine_tables()
        .pool_runtime()
        .get(pool_name)
        .and_then(|r| r.breaker.as_ref())
    {
        Some(cfg) => std::sync::Arc::new(cfg.clone()),
        None => {
            static DEFAULT: std::sync::OnceLock<std::sync::Arc<busbar_core::store::BreakerCfg>> =
                std::sync::OnceLock::new();
            DEFAULT
                .get_or_init(|| std::sync::Arc::new(busbar_core::store::BreakerCfg::default()))
                .clone()
        }
    }
}

mod walk;
pub(crate) use walk::*;

#[cfg(test)]
#[path = "tests/inject_include_usage_tests.rs"]
mod inject_include_usage_tests;

#[cfg(test)]
#[path = "tests/crossproto_delivery_billing_tests.rs"]
mod crossproto_delivery_billing_tests;

#[cfg(test)]
#[path = "tests/send_envelope_tests.rs"]
mod send_envelope_tests;

#[cfg(test)]
#[path = "tests/future_size_probe.rs"]
mod future_size_probe;
