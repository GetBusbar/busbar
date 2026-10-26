// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral proxy vocabulary the kernel keeps: the stage-tap / gate-rejection primitives
//! ([`proxy_vocab`]), the failure-disposition metric labels, the per-request upstream-RTT task-local,
//! and the kernel's own error answer. Shapes live in `busbar_contract::protocol`, the upstream
//! exchange vocabulary in `busbar_kernel_egress::upstream`, the egress engine in `crate::egress::engine`.
pub mod proxy_vocab;

/// Metric-label values for the `disposition` dimension on `UPSTREAM_FAILURES_TOTAL` and the
/// `reason` dimension on `FAILOVERS_TOTAL`.
pub const DISPOSITION_TRANSIENT: &str =
    busbar_contract::upstream::Disposition::TransientUpstream.label();

/// Bounded `pool` metric-label sentinel used for every pre-routing failure (malformed body,
/// unresolved model, governance rejection) so the label space stays finite (metrics.rs).
pub const POOL_LABEL_UNRESOLVED: &str = "unresolved";

/// A single attempt's budget-clamped transport timeout fired (retryable within the request).
pub const DISPOSITION_ATTEMPT_TIMEOUT: &str = "attempt_timeout";
pub const DISPOSITION_HARD_DOWN: &str = busbar_contract::upstream::Disposition::HardDown.label();

/// THE NEUTRAL ERROR ENVELOPE — the body for an ingress name that resolves to no protocol. The
/// plainest `{"error": {"message", "type"}}` object, stated ONCE here so the spellings cannot drift,
/// and neutral so it survives every LLM dialect being dropped from the build.
pub fn agnostic_error_envelope(kind: &str, msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "message": msg, "type": kind } })
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
/// unreachable by construction.
pub fn build_egress_client(
    spec: &crate::egress::engine::EngineSpec,
) -> crate::egress::engine::EngineClient {
    crate::egress::engine::build_client(spec)
        .expect("the base egress engine posture has no failing build arm")
}

/// THE KERNEL'S OWN ERROR ANSWER: `(status, kind, msg)` as the neutral [`agnostic_error_envelope`],
/// `application/json`, at `status`, with no header of any dialect's. A plane that words a refusal in
/// its own dialect renders it through its door; this is the answer where none does.
pub fn ingress_error(
    status: axum::http::StatusCode,
    kind: &str,
    msg: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let envelope = agnostic_error_envelope(kind, msg);
    let body = crate::json::to_string(&envelope).unwrap_or_else(|_| envelope.to_string());
    axum::response::Response::builder()
        .status(status)
        .header(
            axum::http::header::CONTENT_TYPE,
            busbar_contract::protocol::APPLICATION_JSON,
        )
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| status.into_response())
}
