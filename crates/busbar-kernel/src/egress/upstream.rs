// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UPSTREAM-EXCHANGE VOCABULARY the kernel's egress speaks: the owned egress engine's names, the
//! egress unit (`busbar-kernel-egress`, Part 2 #36: "the upstream leg"), the capped body read and its
//! operator caps, the network-failure and failure-disposition labels, the provider context-length
//! code, and the per-request upstream round-trip slot the `server_timing` middleware reads.

pub use busbar_kernel::egress::engine::{
    egress_request, install_proxy_tunnel_if_configured, EngineClient as EgressClient,
    EngineConnector as EgressConnector, EngineError as EgressError, EngineSpec as EgressClientSpec,
};

// THE EGRESS UNIT'S upstream-exchange vocabulary (#83a O1) — the capped body read, the operator
// body caps, the network-failure labels and the client-header transparency — at its historical
// `crate::proxy::…` paths; and the egress unit itself as `egress_unit`, the one path the kernel's
// plane driver reaches its walk through (the pick, the breaker ports, the exhaustion terminals).
pub use busbar_kernel_egress::{self as egress_unit, upstream::*};

// The contract's shape vocabulary (DECISIONS #83): the default egress user-agent, the provider
// context-length code and the context-length disposition label.
pub use busbar_contract::protocol::{
    DISPOSITION_CONTEXT_LENGTH, EGRESS_UA_DEFAULT, PROVIDER_CODE_CONTEXT_LENGTH,
};

/// The upstream error-body buffering cap for this generation (`limits`), the ceiling the capped body
/// read holds an upstream's error answer to.
pub fn max_upstream_buffered_bytes() -> usize {
    crate::limits::upstream_error_body_max_bytes()
}

/// Metric-label values for the `disposition` dimension on `UPSTREAM_FAILURES_TOTAL` and the
/// `reason` dimension on `FAILOVERS_TOTAL`.
pub const DISPOSITION_TRANSIENT: &str =
    busbar_contract::upstream::Disposition::TransientUpstream.label();

/// A single attempt's budget-clamped transport timeout fired (retryable within the request).
pub const DISPOSITION_ATTEMPT_TIMEOUT: &str = "attempt_timeout";
pub const DISPOSITION_HARD_DOWN: &str = busbar_contract::upstream::Disposition::HardDown.label();

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
