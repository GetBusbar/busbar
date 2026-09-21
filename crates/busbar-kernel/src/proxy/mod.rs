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
    agnostic_error_envelope, gate_rejected, hook_content_max_bytes,
    max_upstream_buffered_bytes, read_capped, set_hook_content_max_bytes, GateRejected, ReadEnd,
    StageShape, DEFAULT_HOOK_CONTENT_MAX_BYTES,
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

// A PLANE'S CONTRIBUTION TO THE ONE AUDIT CHAIN — a record type, nothing more. `pub(crate)`
// because the append happens at the plane's single terminal (`ingress::finish_inner`), which is
// where the plane's metrics and its refund decision are already made.
pub mod reqlog;
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
// call sites (`preflight`, `auth::token`, `egress_auth`, `export::webhook`, `engine_facade`).

// THE PLANE'S AUDIT CHAIN, DRIVEN THROUGH THE REAL ROUTER. Mounted from the plane rather than from
// `reqlog.rs` (which has its own record-level battery) for the reason the file's header gives: the
// claim is that a CUSTOMER'S REQUEST reaches the chain, and only a test that goes through
// `crate::build_router` and a real socket can see that. A record-level test would pass just as
// happily against a log with no production call site — which is the state this plane was in.

// THE MONEY-PATH ENGINE TESTS (usage_tap / on_exhausted / egress_differential / forward_once_pool_cell
// / pool_upstream_creds / ordered_walk / reroute_pool / probe_* / hook_seam / signal_catalog /
// *_degrade / egress_dropped_controls_audit / alloc_gate / … ) RELOCATED to `busbar-llm`
// (`src/engine/tests/`, declared under `engine/mod.rs`) with the engine they drive
// (`forward_with_pool` et al.). Only the record/dispatch audit tests that go
// through core's `build_router` (`reqlog_dispatch_tests`, above; `reqlog_tests`, in `reqlog.rs`) stay.

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====

// THE RE-EXPORT of the pure half, at the historical path. A glob so a value added there needs no
// edit here, and so `crate::proxy::sse`, `crate::proxy::KIND_*`, `crate::proxy::read_capped` and the
// rest resolve inside this crate exactly as when they were defined in this file.
pub use busbar_substrate_values::proxy::*;

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
