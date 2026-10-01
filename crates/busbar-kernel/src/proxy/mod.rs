// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// NOTE THE ABSENCE. This module used to import six `PROTO_*` constants for the hook seam's own
// content flattening. That second implementation is gone: the hook projection reads the IR the
// protocol's own reader produced, so nothing under `proxy/` names a dialect to decide what a
// request SAYS any more.
// The NEUTRAL proxy vocabulary that stays in core once a plane's engine moved out to its own crate.
// Core's own staying call sites name these at `crate::proxy::*` via the re-export below; the relocated
// engine names them across the crate boundary as `busbar_kernel::proxy::*`.
pub mod proxy_vocab;
pub use proxy_vocab::{
    gate_rejected, max_upstream_buffered_bytes, read_capped, GateRejected, ReadEnd, StageShape,
};

// NOTE: cross-protocol max-tokens defaulting lives in `IrReq::prepare_for_egress` — the IR owns its
// cross-protocol semantics; the engine is operation-blind. Precedence unit tests drive the IR method.

// The two `x-busbar-*` TRANSPARENCY response-header NAMES, the operator opt-in gate, and the opt-in
// setter now live in the neutral substrate (`busbar_kernel::proxy`) so the plane crates name them
// without reaching into busbar-core; re-exported here for core's own `crate::proxy::*` call sites
// (`router.rs`, `admin`, `main.rs`'s `configure_route_policy_headers`).

// APPLICATION_JSON, TEXT_EVENT_STREAM, DISPOSITION_TRANSIENT, POOL_LABEL_UNRESOLVED and
// PROVIDER_CODE_CONTEXT_LENGTH now live in the neutral substrate (busbar_kernel::proxy) so the
// plane crates name them without reaching into busbar-core; re-exported below for core's own
// `crate::proxy::*` call sites.

// Canonical error-KIND tokens: produced by `cross_protocol_error_kind` / passed to `ingress_error`
// as the `kind` argument. Each string is the protocol-agnostic discriminant that the per-protocol
// writer maps to its native error category. RELOCATED DOWN to the neutral `busbar_kernel::proxy`
// leaf (so the `busbar-llm` dialect writers name them without reaching into `busbar-core`) and
// re-exported here at their historical `crate::proxy::KIND_*` paths; the values are byte-identical
// (each aliases the ERR_TYPE_* bank at its substrate home).

// Network-transient `err_type` values passed to `record_transient_in` (the *category* of network
// failure recorded in the breaker store), and the failure-DISPOSITION metric-label values. RELOCATED
// DOWN to `busbar_kernel::proxy` so a relocated plane engine names them without reaching into
// `busbar-core`; re-exported here for core's own call sites.

// The per-request upstream-RTT task-local the `server_timing` middleware scopes and the forward path
// writes now lives in the neutral substrate (`busbar_kernel::proxy`) — single-compiled, so the
// router's `.scope()` and the plane's `.try_with()` read the ONE task-local. Re-exported here for
// core's own `proxy::UPSTREAM_RTT_US` call sites (`router.rs`).

// THE EGRESS ENGINE moved to the neutral substrate (`busbar_kernel::egress::engine`) — the
// one-egress-stack ruling's home for the owned outbound client every plane builds from. Core
// re-exports the engine names at their old `crate::proxy::` paths so every call site (state.rs's
// `EgressClient as Client`, appbuild's builder, the forward/health request assembly, the tests)
// keeps resolving unchanged. `pub` rather than `pub(crate)` deliberately: some of these names
// (`EgressConnector`) have no remaining in-core reader after the move, and an externally-visible
// re-export cannot rot into an unused-import warning while the path contract stands.
pub use busbar_kernel::egress::engine::{
    egress_request, install_proxy_tunnel_if_configured, EngineClient as EgressClient,
    EngineConnector as EgressConnector, EngineError as EgressError, EngineSpec as EgressClientSpec,
};

// The infallible per-lane egress-client shim now lives in the neutral substrate
// (`busbar_kernel::proxy::build_egress_client`) so a plane crate builds its egress client without
// reaching into `busbar-core`; re-exported here for core's own `crate::proxy::build_egress_client`
// call sites (`preflight`, `auth::token`, `egress_auth`, `engine_facade`).

// THE MONEY-PATH ENGINE TESTS (usage_tap / on_exhausted / egress_differential / forward_once_pool_cell
// / pool_upstream_creds / ordered_walk / reroute_pool / probe_* / hook_seam / signal_catalog /
// *_degrade / egress_dropped_controls_audit / alloc_gate / … ) RELOCATED to `busbar-llm`
// (`src/engine/tests/`, declared under `engine/mod.rs`) with the engine they drive
// (`forward_with_pool` et al.).

// THE EGRESS UNIT'S upstream-exchange vocabulary (#83a O1) — the capped body read, the operator
// body caps, the network-failure labels and the client-header transparency — at its historical
// `crate::proxy::…` paths; and the egress unit itself as `egress_unit`, the one path the kernel's
// plane driver reaches its walk through (the pick, the breaker ports, the exhaustion terminals).
pub use busbar_kernel_egress::{self as egress_unit, upstream::*};

// ── THE SHAPE VOCABULARY lives in `busbar_contract::protocol` (DECISIONS #83: contract = shapes;
//    SD-1 of the #83a split): the media-type and default user-agent literals a declaration defaults
//    to, the provider context-length code, the agnostic error-KIND tokens and the context-length
//    disposition label a dialect and the kernel both key on. Re-exported here under their historical
//    paths, so every caller compiles unchanged.
pub use busbar_contract::protocol::{
    APPLICATION_JSON, DISPOSITION_CONTEXT_LENGTH, EGRESS_UA_DEFAULT, KIND_API_ERROR,
    KIND_AUTHENTICATION, KIND_INSUFFICIENT_QUOTA, KIND_INVALID_REQUEST, KIND_NOT_FOUND,
    KIND_OVERLOADED, KIND_PERMISSION, KIND_RATE_LIMIT, KIND_REQUEST_TOO_LARGE, KIND_SERVER_ERROR,
    KIND_TIMEOUT, PROVIDER_CODE_CONTEXT_LENGTH, TEXT_EVENT_STREAM,
};

/// Metric-label values for the `disposition` dimension on `UPSTREAM_FAILURES_TOTAL` and the
/// `reason` dimension on `FAILOVERS_TOTAL`.
pub const DISPOSITION_TRANSIENT: &str =
    busbar_contract::upstream::Disposition::TransientUpstream.label();

/// Bounded `pool` metric-label sentinel used for every pre-routing failure (malformed body,
/// unresolved model, governance rejection) so the label space stays finite (metrics.rs).
pub const POOL_LABEL_UNRESOLVED: &str = "unresolved";

// ── Failure-DISPOSITION metric-label values (the `disposition` dimension on `UPSTREAM_FAILURES_TOTAL`
//    / the `reason` dimension on `FAILOVERS_TOTAL`). [`DISPOSITION_TRANSIENT`] already lives above;
//    these three are relocated DOWN from `busbar-core`'s `proxy` alongside it so the money-path
//    failure-classification names them without reaching into `busbar-core`.
/// A single attempt's budget-clamped transport timeout fired (retryable within the request).
pub const DISPOSITION_ATTEMPT_TIMEOUT: &str = "attempt_timeout";
pub const DISPOSITION_HARD_DOWN: &str = busbar_contract::upstream::Disposition::HardDown.label();

// ── The two `x-busbar-*` TRANSPARENCY response-header NAMES stamped when a non-default routing policy
//    chose the target lane, the operator opt-in gate, and the per-request upstream-RTT task-local the
//    router reads. Neutral vocabulary relocated DOWN from `busbar-core`'s `proxy` so the money-path
//    wire layer names them without reaching into `busbar-core`; core's `proxy` re-exports each at its
//    historical `crate::proxy::…` path (so `router.rs`/`main.rs`/`admin` call sites are untouched).
/// The `x-busbar-route-policy` TRANSPARENCY response header: the policy name that chose the lane.
pub const HDR_ROUTE_POLICY: &str = "x-busbar-route-policy";
/// The `x-busbar-route-target` TRANSPARENCY response header: the chosen lane's model.
pub const HDR_ROUTE_TARGET: &str = "x-busbar-route-target";

/// Whether the operator opted in to the `x-busbar-route-policy` / `-target` TRANSPARENCY headers
/// (`advanced.response_headers.route_policy`; default `false`). Set SYNCHRONOUSLY once at boot by
/// [`configure_route_policy_headers`]: a settled decision read at every emission site, never rebuilt
/// by a config apply (restart-to-apply). Unset ⇒ `false`.
static ROUTE_POLICY_HEADERS_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Apply the operator's `advanced.response_headers.route_policy` decision. Called exactly once, at
/// boot, before the router is built; `OnceLock::set` silently no-ops on any later call.
pub fn configure_route_policy_headers(enabled: bool) {
    let _ = ROUTE_POLICY_HEADERS_ENABLED.set(enabled);
}

/// Did the operator opt in to the `x-busbar-route-*` headers? Gates the route-policy header emit —
/// the header is a fingerprintable observable, so it defaults OFF.
pub fn route_policy_headers_enabled() -> bool {
    ROUTE_POLICY_HEADERS_ENABLED.get().copied().unwrap_or(false)
}

/// The DEFAULT ceiling, in bytes, on the content a hook is shown in one projection. `0` = UNLIMITED
/// (the default): the LLM prompt projection is sent UNCAPPED. A non-zero ceiling is an OPT-IN an
/// operator sets via `limits.hook_content_max_bytes`. Lives HERE so the plane's hook-projection
/// enforcer names the ceiling without reaching into `busbar-core`; core's `proxy` re-exports it.
pub const DEFAULT_HOOK_CONTENT_MAX_BYTES: usize = 0;

/// The effective content ceiling for this config generation, resolved once at config apply
/// (`limits.hook_content_max_bytes`) and read with a single relaxed load — never recomputed per
/// request.
static HOOK_CONTENT_MAX_BYTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_HOOK_CONTENT_MAX_BYTES);

/// Install the generation's content ceiling. Called at boot and on every config apply (by core's
/// `appbuild`).
pub fn set_hook_content_max_bytes(bytes: usize) {
    HOOK_CONTENT_MAX_BYTES.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

/// Read the generation's content ceiling. `0` = UNLIMITED. Named across the crate boundary by the
/// relocated hook-projection enforcer, which caps SERIALIZED BYTES against this value.
pub fn hook_content_max_bytes() -> usize {
    HOOK_CONTENT_MAX_BYTES.load(std::sync::atomic::Ordering::Relaxed)
}

/// THE NEUTRAL ERROR ENVELOPE — the body for an ingress name that resolves to no protocol. The
/// plainest `{"error": {"message", "type"}}` object, stated ONCE here so the spellings cannot drift,
/// and neutral so it survives every LLM dialect being dropped from the build.
pub fn agnostic_error_envelope(kind: &str, msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "message": msg, "type": kind } })
}

/// The canonical auth-failure `(HTTP status, error kind)` for an ingress protocol name — the agnostic
/// dispatch through the registry's `ProtocolDecl::auth_failure_status_and_kind` (which replaced the
/// `ProtocolWriter` vtable method). `BedrockWriter` resolves to (403, "auth"); `GeminiWriter` to (400,
/// "invalid_request_error"); every other dialect and an unknown/dropped protocol fall back to the
/// default (401, [`KIND_AUTHENTICATION`]) so the request path stays panic-free. Neutral: reads only the
/// protocol registry, so it survives every LLM dialect being dropped from the build.
pub fn auth_failure_status_and_kind(proto: &str) -> (http::StatusCode, &'static str) {
    crate::proto::decl_for(proto)
        .map(|d| d.auth_failure_status_and_kind)
        .unwrap_or((http::StatusCode::UNAUTHORIZED, KIND_AUTHENTICATION))
}

tokio::task_local! {
    /// Per-request slot the `server_timing` middleware reads to compute Busbar's INTERNAL
    /// processing time (= total request wall-clock − upstream round-trip), reported as a
    /// `Server-Timing: busbar;dur=<ms>` response header. Set via `.scope()` by the middleware;
    /// written by the forward path when an upstream call returns. Microseconds; the `u64::MAX`
    /// sentinel means "no upstream hop on this request" (admin/health/early error). Lives HERE in the
    /// neutral substrate (single-compiled) so the router's `.scope()` and the plane's `.try_with()`
    /// read the ONE task-local without the plane reaching into `busbar-core`.
    pub static UPSTREAM_RTT_US: std::sync::Arc<std::sync::atomic::AtomicU64>;
}

/// Build ONE egress client shard from a caller-supplied [`EngineSpec`](crate::egress::engine::EngineSpec).
/// An infallible shim over the engine's fallible builder ([`crate::egress::engine::build_client`],
/// where the parity ledger lives): every spec a resident plane actually passes here carries no extra
/// trust root and no client identity — the only arms a build can fail on — so the panic path here is
/// unreachable by construction. Lives HERE so a plane crate builds its egress client without reaching
/// into `busbar-core`; core's `proxy` re-exports it.
pub fn build_egress_client(
    spec: &crate::egress::engine::EngineSpec,
) -> crate::egress::engine::EngineClient {
    crate::egress::engine::build_client(spec)
        .expect("the base egress engine posture has no failing build arm")
}

// ── THE AGNOSTIC INGRESS-ERROR SHAPER — RELOCATED DOWN from `busbar_kernel::proxy::proxy_vocab` ──────
// The dialect-blind `(status, kind, msg)` → caller-dialect error `Response` projection, and core's own
// fallback envelope. Moved onto the neutral substrate so the extracted native-ingress path in
// `busbar-llm` shapes an ingress error through the neutral ABI rather than reaching BACK into
// `busbar-core`. It names no dialect literally: `crate::proto::decl_for` reads whatever registry the
// resident planes populated, and the fallback is the neutral envelope so it survives every LLM dialect
// being dropped with the `busbar-llm` plane. `busbar-core` re-exports both at their historical
// `busbar_kernel::proxy::{ingress_error, agnostic_error_envelope}` paths so every in-core caller is
// unchanged.

/// The agnostic ingress-error shaper: project a `(status, kind, msg)` into the caller-dialect error
/// response, attaching the protocol-appropriate headers via the resolved writer vtable. When `ingress`
/// resolves to no protocol the body is the neutral `agnostic_error_envelope` and no protocol headers
/// are attached — the shape that survives every LLM dialect being dropped with the `busbar-llm` plane.
pub fn ingress_error(
    ingress: &str,
    status: axum::http::StatusCode,
    kind: &str,
    msg: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let dialect = crate::proto::decl_for(ingress).and_then(|d| d.dialect());
    let envelope = match &dialect {
        Some(di) => di.write_error(status.as_u16(), kind, msg),
        None => agnostic_error_envelope(kind, msg),
    };
    let body = crate::json::to_string(&envelope)
        .unwrap_or_else(|_| agnostic_error_envelope(kind, msg).to_string());
    let mut resp = axum::response::Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, APPLICATION_JSON)
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| status.into_response());
    if let Some(di) = &dialect {
        di.attach_error_response_headers(resp.headers_mut(), kind, &envelope);
    }
    resp
}
