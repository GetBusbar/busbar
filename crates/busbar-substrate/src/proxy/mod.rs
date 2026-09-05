// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `proxy` seam, in two halves.
//!
//! The PURE half — the two process-global body caps, the capped upstream-body read, the
//! content-type / error-kind / disposition / transparency-header vocabularies, the neutral error
//! envelope, the client-header capture/fold mechanics and the SSE frame reader — lives in
//! `busbar-substrate-values` and is re-exported below, so every historical
//! `busbar_substrate::proxy::…` path resolves unchanged.
//!
//! THIS file holds only the three items whose closure reaches I/O, and which therefore could not
//! cross into a crate that must resolve no hyper/reqwest/tokio edge:
//!
//!   * [`UPSTREAM_RTT_US`] — a `tokio::task_local!`, i.e. the runtime's own per-task storage.
//!   * [`build_egress_client`] — its whole signature is the engine's (`EngineSpec`/`EngineClient`).
//!   * [`ingress_error`] — it returns an `axum::response::Response`, a body backed by the server
//!     stack.
//!
//! Each keeps its name, its signature and its behaviour; only the file it sits in changed.

pub mod proxy_vocab;

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

/// Build ONE egress client shard on the LLM-lane posture. An infallible shim over the engine's
/// fallible builder ([`crate::egress::engine::build_client`], where the parity ledger lives): the
/// LLM posture carries no extra trust root and no client identity — the only arms a build can fail
/// on — so the panic path here is unreachable by construction. Lives HERE so a plane crate builds its
/// egress client without reaching into `busbar-core`; core's `proxy` re-exports it.
pub fn build_egress_client(
    spec: &crate::egress::engine::EngineSpec,
) -> crate::egress::engine::EngineClient {
    crate::egress::engine::build_client(spec)
        .expect("the base egress engine posture has no failing build arm")
}

// ── THE AGNOSTIC INGRESS-ERROR SHAPER — RELOCATED DOWN from `busbar_core::proxy::proxy_vocab` ──────
// The dialect-blind `(status, kind, msg)` → caller-dialect error `Response` projection, and core's own
// fallback envelope. Moved onto the neutral substrate so the extracted native-ingress path in
// `busbar-llm` shapes an ingress error through the neutral ABI rather than reaching BACK into
// `busbar-core`. It names no dialect literally: `crate::proto::decl_for` reads whatever registry the
// resident planes populated, and the fallback is the neutral envelope so it survives every LLM dialect
// being dropped with the `busbar-llm` plane. `busbar-core` re-exports both at their historical
// `busbar_core::proxy::{ingress_error, agnostic_error_envelope}` paths so every in-core caller is
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
