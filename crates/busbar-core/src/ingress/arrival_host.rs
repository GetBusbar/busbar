// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CORE'S IMPLEMENTATION of the neutral [`busbar_substrate::ingress::arrival::ArrivalHost`] — the
//! request-pipeline seam a path-model dialect (gemini/bedrock, extracted to `busbar-llm`) calls back
//! through. The dialect crate owns the URL parsing (its statement about its own URL space); core owns
//! the `App`/`GovCtx`/`CallerToken`-bound resolution + forward + error shaping, reached here.
//!
//! Mirrors `crate::plane_host::EngineHostImpl`: a stateless core object each method drives against the
//! live `App` recovered from the opaque [`busbar_substrate::ingress::arrival::ArrivalCtx`] the dialect
//! threads back. Every response-future method clones the cheap `Arc<App>`/`GovCtx`/`CallerToken` and
//! owns the moved `HeaderMap`/`Bytes`, so the future it hands back over the `fn`-pointer arrival
//! boundary borrows nothing.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use busbar_api::operation::Operation;
use busbar_substrate::ingress::arrival::{ArrivalCtx, ArrivalHost};

use crate::auth::CallerToken;
use crate::governance::GovCtx;
use crate::state::App;

/// The core payload core boxes into the opaque [`ArrivalCtx`] at the catch-all: the three
/// `busbar-core` handles a dialect must NOT name, threaded back into every host method opaquely.
pub(crate) struct ArrivalPayload {
    pub(crate) app: Arc<App>,
    pub(crate) gov: GovCtx,
    pub(crate) caller: CallerToken,
}

fn payload(ctx: &ArrivalCtx) -> &ArrivalPayload {
    ctx.downcast_ref::<ArrivalPayload>()
        .expect("ArrivalCtx must carry core's ArrivalPayload — a wiring bug otherwise")
}

/// The one core arrival host. Stateless (all state arrives via [`ArrivalCtx`]); an `Arc` of it rides
/// every [`busbar_substrate::ingress::arrival::Arrival`] the catch-all mints.
pub(crate) struct CoreArrivalHost;

impl ArrivalHost for CoreArrivalHost {
    fn ingress_path_model(
        &self,
        ctx: &ArrivalCtx,
        headers: HeaderMap,
        body: Bytes,
        model: String,
        operation: Operation,
        stream: bool,
        gemini_json_array: bool,
        proto: &'static str,
        gemini_api_version: Option<String>,
    ) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let p = payload(ctx);
        let app = p.app.clone();
        let gov = p.gov.clone();
        let caller = p.caller.clone();
        Box::pin(async move {
            super::ingress_path_model(
                &app,
                &gov,
                &caller,
                &headers,
                body,
                &model,
                operation,
                stream,
                gemini_json_array,
                proto,
                gemini_api_version.as_deref(),
            )
            .await
        })
    }

    fn operation_ingress(
        &self,
        ctx: &ArrivalCtx,
        headers: HeaderMap,
        body: Bytes,
        proto: &'static str,
        operation: Operation,
        model_hint: Option<String>,
    ) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let p = payload(ctx);
        let app = p.app.clone();
        let gov = p.gov.clone();
        let caller = p.caller.clone();
        Box::pin(async move {
            super::dispatch::operation_ingress(
                &app, &gov, &caller, &headers, body, proto, operation, model_hint,
            )
            .await
        })
    }

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
        super::finish_rejected(&p.app, &p.gov, proto, pool, started, charged_at, resp)
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
        let p = payload(ctx);
        crate::ingress::native::envelope_dialect(p.app.planes.ingress_of(path))
    }

    fn fallback_not_found(
        &self,
        ctx: &ArrivalCtx,
        path: &str,
        status: StatusCode,
        err_type: &str,
        message: &str,
    ) -> Response {
        let p = payload(ctx);
        crate::fallback_error_response(&p.app.planes, path, status, err_type, message)
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
