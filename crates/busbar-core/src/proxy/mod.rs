// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// NOTE THE ABSENCE. This module used to import six `PROTO_*` constants for the hook seam's own
// content flattening. That second implementation is gone: the hook projection reads the IR the
// protocol's own reader produced, so nothing under `proxy/` names a dialect to decide what a
// request SAYS any more.
use crate::proto::openai_family;

// The NEUTRAL proxy vocabulary that stays in core once the LLM engine moved to `busbar-llm`. Core's
// own staying call sites name these at `crate::proxy::*` via the re-export below; the relocated
// engine names them across the crate boundary as `busbar_core::proxy::*`.
pub mod proxy_vocab;
pub use proxy_vocab::{
    agnostic_error_envelope, fire_stage_taps, gate_rejected, hook_content_max_bytes, ingress_error,
    max_upstream_buffered_bytes, read_capped, set_hook_content_max_bytes, spawn_bounded_tap,
    GateRejected, ReadEnd, StageShape, DEFAULT_HOOK_CONTENT_MAX_BYTES,
};

// NOTE: cross-protocol max-tokens defaulting lives in `IrReq::prepare_for_egress` — the IR owns its
// cross-protocol semantics; the engine is operation-blind. Precedence unit tests drive the IR method.

/// The two `x-busbar-*` TRANSPARENCY response headers stamped when a non-default routing policy
/// chose the target lane: the policy name and the chosen lane's model. Hoisted to consts so the
/// emit site and any future readers cannot drift on spelling.
pub const HDR_ROUTE_POLICY: &str = "x-busbar-route-policy";
pub const HDR_ROUTE_TARGET: &str = "x-busbar-route-target";

/// Whether the operator opted in to the `x-busbar-route-policy` / `-target` TRANSPARENCY headers
/// (`advanced.response_headers.route_policy`; default `false`). Set SYNCHRONOUSLY once at
/// boot by [`configure_route_policy_headers`], mirroring `metrics::ENABLED` / `metrics::enabled()`:
/// a settled decision read at every emission site, never rebuilt by a config apply (restart-to-apply,
/// same as `advanced.response_headers.server_timing`). Unset ⇒ `false`: any test or build that never
/// calls `configure_route_policy_headers` has the headers off, matching the documented default.
static ROUTE_POLICY_HEADERS_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Apply the operator's `advanced.response_headers.route_policy` decision. Called exactly once, at
/// boot, before the router is built (see `main.rs::run`); `OnceLock::set` silently no-ops on any
/// later call, which is fine — the flag is documented restart-to-apply.
pub fn configure_route_policy_headers(enabled: bool) {
    let _ = ROUTE_POLICY_HEADERS_ENABLED.set(enabled);
}

/// Did the operator opt in to the `x-busbar-route-*` headers? Gates
/// [`wire::maybe_attach_route_policy`] — the header is a fingerprintable observable (same class as
/// `Server-Timing: busbar`), so it defaults OFF.
pub fn route_policy_headers_enabled() -> bool {
    ROUTE_POLICY_HEADERS_ENABLED.get().copied().unwrap_or(false)
}

// APPLICATION_JSON, TEXT_EVENT_STREAM, DISPOSITION_TRANSIENT, POOL_LABEL_UNRESOLVED and
// PROVIDER_CODE_CONTEXT_LENGTH now live in the neutral substrate (busbar_substrate::proxy) so the
// plane crates name them without reaching into busbar-core; re-exported below for core's own
// `crate::proxy::*` call sites.
pub use busbar_substrate::proxy::{
    APPLICATION_JSON, DISPOSITION_TRANSIENT, EGRESS_UA_DEFAULT, POOL_LABEL_UNRESOLVED,
    PROVIDER_CODE_CONTEXT_LENGTH, TEXT_EVENT_STREAM,
};

/// Canonical error-KIND tokens: produced by `cross_protocol_error_kind` / passed to
/// `ingress_error` as the `kind` argument. Each string is the protocol-agnostic discriminant that
/// the per-protocol writer maps to its native error category (e.g. Bedrock `__type`, Gemini
/// `error.status`). Values shared with the OpenAI-family/anthropic/admin vocabularies alias their
/// canonical home in `proto::openai_family`; only the two forward-specific tokens (`overloaded`,
/// `timeout`) are defined here.
pub const KIND_AUTHENTICATION: &str = openai_family::ERR_TYPE_AUTHENTICATION;
pub const KIND_PERMISSION: &str = openai_family::ERR_TYPE_PERMISSION;
pub const KIND_RATE_LIMIT: &str = openai_family::ERR_TYPE_RATE_LIMIT;
pub const KIND_INVALID_REQUEST: &str = openai_family::ERR_TYPE_INVALID_REQUEST;
pub const KIND_NOT_FOUND: &str = openai_family::ERR_TYPE_NOT_FOUND;
// The four PUBLIC forward-kind tokens the `busbar-llm` dialect writers name are RELOCATED DOWN to the
// neutral `busbar_substrate::proxy` leaf (so the plane names them without reaching into `busbar-core`)
// and re-exported here at their historical `crate::proxy::KIND_*` paths; the values are byte-identical
// (`KIND_API_ERROR`/`KIND_SERVER_ERROR` still alias the ERR_TYPE_* bank, now at its substrate home).
pub use busbar_substrate::proxy::{
    KIND_API_ERROR, KIND_OVERLOADED, KIND_SERVER_ERROR, KIND_TIMEOUT,
};
pub const KIND_INSUFFICIENT_QUOTA: &str = openai_family::ERR_TYPE_INSUFFICIENT_QUOTA;
pub const KIND_REQUEST_TOO_LARGE: &str = openai_family::ERR_TYPE_REQUEST_TOO_LARGE;

/// Network-transient `err_type` values passed to `record_transient_in`.  These are distinct from
/// the error-KIND tokens above: they label the *category* of network failure recorded in the
/// breaker store, not the protocol-level error kind surfaced to the caller.
// `pub` (was crate-internal): the relocated LLM engine (`busbar-llm`) names these at
// `busbar_core::proxy::ERR_NET_*` / `DISPOSITION_*` on its money-path failure-classification, the
// allowed plane→core edge.
pub const ERR_NET_CONNECT: &str = "connect";
pub const ERR_NET_TIMEOUT: &str = "timeout";
pub const ERR_NET_TRANSPORT: &str = "transport";
/// `err_type` recorded when a HalfOpen probe's degraded forward returns a non-2xx (bumps cooldown).
pub const ERR_DEGRADED_NON2XX: &str = "degraded-non2xx";

/// A single attempt's budget-clamped transport timeout fired (retryable within the request).
pub const DISPOSITION_ATTEMPT_TIMEOUT: &str = "attempt_timeout";
pub const DISPOSITION_HARD_DOWN: &str = "hard_down";
pub const DISPOSITION_CONTEXT_LENGTH: &str = "context_length";

tokio::task_local! {
    /// Per-request slot the `server_timing` middleware reads to compute Busbar's INTERNAL
    /// processing time (= total request wall-clock − upstream round-trip), reported as a
    /// `Server-Timing: busbar;dur=<ms>` response header. Set via `.scope()` by the middleware;
    /// written by `record_upstream_rtt` when an upstream call returns. Microseconds; the
    /// `u64::MAX` sentinel means "no upstream hop on this request" (admin/health/early error),
    /// in which case the middleware reports the full request time.
    pub static UPSTREAM_RTT_US: std::sync::Arc<std::sync::atomic::AtomicU64>;
}

// THE MODEL PLANE'S CONTRIBUTION TO THE ONE AUDIT CHAIN — a record type, nothing more. `pub(crate)`
// because the append happens at the plane's single terminal (`ingress::finish_inner`), which is
// where the plane's metrics and its refund decision are already made.
pub(crate) mod reqlog;
// THE EGRESS ENGINE moved to the neutral substrate (`busbar_substrate::egress::engine`) — the
// one-egress-stack ruling's home for the owned outbound client every plane builds from. Core
// re-exports the engine names at their old `crate::proxy::` paths so every call site (state.rs's
// `EgressClient as Client`, appbuild's builder, the forward/health request assembly, the tests)
// keeps resolving unchanged. `pub` rather than `pub(crate)` deliberately: some of these names
// (`EgressConnector`) have no remaining in-core reader after the move, and an externally-visible
// re-export cannot rot into an unused-import warning while the path contract stands.
pub use busbar_substrate::egress::engine::{
    egress_request, install_proxy_tunnel_if_configured, EngineClient as EgressClient,
    EngineConnector as EgressConnector, EngineError as EgressError, EngineSpec as EgressClientSpec,
};

/// Build ONE egress client shard on the LLM-lane posture. An infallible shim over the engine's
/// fallible builder (`busbar_substrate::egress::engine::build_client`, where the parity ledger
/// now lives): the LLM posture carries no extra trust root and no client identity — the only
/// arms a build can fail on — so the panic path here is unreachable by construction.
pub fn build_egress_client(spec: &EgressClientSpec) -> EgressClient {
    busbar_substrate::egress::engine::build_client(spec)
        .expect("the base egress engine posture has no failing build arm")
}

// THE PLANE'S AUDIT CHAIN, DRIVEN THROUGH THE REAL ROUTER. Mounted from the plane rather than from
// `reqlog.rs` (which has its own record-level battery) for the reason the file's header gives: the
// claim is that a CUSTOMER'S REQUEST reaches the chain, and only a test that goes through
// `crate::build_router` and a real socket can see that. A record-level test would pass just as
// happily against a log with no production call site — which is the state this plane was in.
#[cfg(test)]
#[path = "tests/reqlog_dispatch_tests.rs"]
mod reqlog_dispatch_tests;

// THE MONEY-PATH ENGINE TESTS (usage_tap / on_exhausted / egress_differential / forward_once_pool_cell
// / pool_upstream_creds / ordered_walk / reroute_pool / probe_* / hook_seam / signal_catalog /
// *_degrade / egress_dropped_controls_audit / alloc_gate / … ) RELOCATED to `busbar-llm`
// (`src/engine/proxy_tests/`, declared under `engine/mod.rs`) with the engine they drive
// (`forward_with_pool` et al.) — money-path Phase 3-4 C. Only the record/dispatch audit tests that go
// through core's `build_router` (`reqlog_dispatch_tests`, above; `reqlog_tests`, in `reqlog.rs`) stay.
