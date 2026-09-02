// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CORE'S IMPLEMENTATION of the neutral [`busbar_substrate::ingress::arrival::ArrivalHost`] — the
//! request-pipeline seam a path-model dialect (gemini/bedrock, extracted to `busbar-llm`) calls back
//! through. The dialect crate owns the URL parsing (its statement about its own URL space); core owns
//! the resolution + forward + error shaping, reached here.
//!
//! Mirrors `crate::plane_host::EngineHostImpl`: a stateless core object each method drives against the
//! live engine recovered from the opaque [`busbar_substrate::ingress::arrival::ArrivalCtx`] the dialect
//! threads back. App-retype WEDGE 3 (THE FLIP): the payload the dialect threads back is now the NEUTRAL
//! [`busbar_substrate::ingress::arrival::ArrivalPayload`] carrying an `Arc<dyn EngineHost>` (minted
//! core-side over the live `App`) rather than the `Arc<App>` it used to; each method reaches the engine
//! through that host seam, so the neutral payload names no core type and the extracted LLM plane can
//! downcast it without a backwards reach into `busbar-core`.

use std::time::Instant;

use axum::http::StatusCode;
use axum::response::Response;
use busbar_substrate::ingress::arrival::{ArrivalCtx, ArrivalHost};
// Re-exported at the historical `crate::ingress::arrival_host::ArrivalPayload` path so core's arrival
// construction sites keep naming it here after the type's pivot to the neutral substrate (WEDGE 3).
pub use busbar_substrate::ingress::arrival::ArrivalPayload;

fn payload(ctx: &ArrivalCtx) -> &ArrivalPayload {
    ctx.downcast_ref::<ArrivalPayload>()
        .expect("ArrivalCtx must carry the neutral ArrivalPayload — a wiring bug otherwise")
}

/// The one core arrival host. Stateless (all state arrives via [`ArrivalCtx`]); an `Arc` of it rides
/// every [`busbar_substrate::ingress::arrival::Arrival`] the catch-all mints.
pub(crate) struct CoreArrivalHost;

impl ArrivalHost for CoreArrivalHost {
    fn finish_rejected(
        &self,
        ctx: &ArrivalCtx,
        proto: &str,
        pool: &str,
        started: Instant,
        charged_at: u64,
        resp: Response,
    ) -> Response {
        let p = payload(ctx);
        p.host
            .finish_rejected(&p.gov, proto, pool, started, charged_at, resp)
    }

    fn ingress_error(
        &self,
        proto: &str,
        status: StatusCode,
        kind: &str,
        message: &str,
    ) -> Response {
        crate::proxy::ingress_error(proto, status, kind, message)
    }

    fn envelope_dialect(&self, ctx: &ArrivalCtx, path: &str) -> &'static str {
        payload(ctx).host.arrival_envelope_dialect(path)
    }

    fn fallback_not_found(
        &self,
        ctx: &ArrivalCtx,
        path: &str,
        status: StatusCode,
        err_type: &str,
        message: &str,
    ) -> Response {
        payload(ctx)
            .host
            .arrival_fallback_error(path, status, err_type, message)
    }

    fn percent_decode(&self, s: &str) -> String {
        crate::observability::percent_decode(s)
    }

    fn kind_not_found(&self) -> &'static str {
        crate::proxy::KIND_NOT_FOUND
    }

    fn kind_invalid_request(&self) -> &'static str {
        crate::proxy::KIND_INVALID_REQUEST
    }

    fn err_type_not_found(&self) -> &'static str {
        crate::admin::ERR_TYPE_NOT_FOUND
    }
}
