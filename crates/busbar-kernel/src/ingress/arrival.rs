// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral arrival values retained for historical in-process fixtures.
//!
//! Shipping arrivals are served exclusively through the owning plane's memory-ABI door; the
//! former path- and body-model callback registries are removed. These values keep the request
//! bytes and routing facts beside an opaque fixture context and typed host operations.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;

/// THE OPAQUE CORE CONTEXT of one arrival — core's `Arc<App>` + `GovCtx` + `CallerToken`, type-erased
/// so the dialect crate carries it back into the host methods without naming a core type. Core boxes
/// its own payload struct in here at the catch-all and downcasts it back inside each [`ArrivalHost`]
/// method; the dialect crate only ever holds and forwards it.
pub struct ArrivalCtx(Box<dyn std::any::Any + Send + Sync>);

impl ArrivalCtx {
    /// Box a core payload into the opaque context. Called only by core (the one crate that mints an
    /// arrival); the type parameter is core's own private payload struct.
    pub fn new<T: std::any::Any + Send + Sync>(payload: T) -> Self {
        ArrivalCtx(Box::new(payload))
    }

    /// Recover the core payload core boxed in [`ArrivalCtx::new`]. `None` only if a caller boxed a
    /// different type — a wiring bug, never a runtime input.
    pub fn downcast_ref<T: std::any::Any>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

/// THE NEUTRAL ARRIVAL PAYLOAD (App-retype WEDGE 3 — THE FLIP): the concrete value core boxes into the
/// opaque [`ArrivalCtx`] at the catch-all, and that both core's [`ArrivalHost`] impl and the LLM plane's
/// universal ingress downcast back out. It USED to be `busbar_kernel::ingress::arrival_host::ArrivalPayload`
/// (an `Arc<App>` + `GovCtx` + caller token), which forced the extracted LLM plane to name a core type to
/// downcast it — the last structural backwards reach on the request path. Pivoted here so the payload is
/// spelled in the NEUTRAL substrate: it carries the minted `Arc<dyn EngineHost>` (not the `Arc<App>` it
/// was minted over), the public [`busbar_contract::records::PlaneRequestCtx`] governance context, and the caller's
/// bearer token flattened to a neutral scalar. Core mints the host at each construction site
/// (`engine_host(&app)`); every downstream reader reaches the engine through the host seam, naming no
/// core type.
pub struct ArrivalPayload {
    /// The neutral engine host, minted core-side over the live `App` — the seam every reader (core's
    /// `ArrivalHost` impl and the LLM plane's ingress) drives instead of naming `Arc<App>`.
    pub host: Arc<dyn crate::plane_driver::EngineHost>,
    /// The resolved per-request governance context (public `busbar_contract` type).
    pub gov: busbar_contract::records::PlaneRequestCtx,
    /// The caller's verified credential, as a REF the host presents upstream for a `passthrough`
    /// pool (`crate::auth::present_caller`) — never plaintext a plane can read.
    pub caller_token: Option<crate::auth::CallerCredential>,
}

/// Core request helpers retained for historical in-process arrival fixtures.
///
/// The error-category accessors return core's neutral vocabulary, and the opaque context carries
/// the fixture's core-bound state without exposing it to its dialect handler.
pub trait ArrivalHost: Send + Sync {
    /// The NOT-CHARGED observability finish (`crate::ingress::finish_rejected`) a pre-routing rejection
    /// (malformed path, unsupported action, no handler) must flow through so it is counted + logged.
    #[allow(clippy::too_many_arguments)]
    fn finish_rejected(
        &self,
        ctx: &ArrivalCtx,
        proto: &str,
        pool: &str,
        started: Instant,
        charged_at: u64,
        resp: Response,
    ) -> Response;

    /// Render `status`/`kind`/`message` in `proto`'s native error envelope
    /// (`crate::proxy::ingress_error`).
    fn ingress_error(&self, proto: &str, status: StatusCode, kind: &str, message: &str)
        -> Response;

    /// The mount-aware dialect an answer to `path` is SHAPED in
    /// (`crate::ingress::native::envelope_dialect(app.planes.ingress_of(path))`).
    fn envelope_dialect(&self, ctx: &ArrivalCtx, path: &str) -> &'static str;

    /// The pre-collapse fallback 404 shape by path (`crate::fallback_error_response`).
    fn fallback_not_found(
        &self,
        ctx: &ArrivalCtx,
        path: &str,
        status: StatusCode,
        err_type: &str,
        message: &str,
    ) -> Response;

    /// Percent-decode one path segment through core's shared helper
    /// (`crate::observability::percent_decode`).
    fn percent_decode(&self, s: &str) -> String;

    /// `crate::proxy::KIND_NOT_FOUND` (the neutral "not found" error category).
    fn kind_not_found(&self) -> &'static str;
    /// `crate::proxy::KIND_INVALID_REQUEST`.
    fn kind_invalid_request(&self) -> &'static str;
    /// `crate::admin::ERR_TYPE_NOT_FOUND`.
    fn err_type_not_found(&self) -> &'static str;
}

/// ONE ARRIVAL, as a PATH-MODEL DIALECT RECEIVES IT — everything the catch-all already extracted, plus
/// the [`ArrivalHost`] it calls back through and the opaque [`ArrivalCtx`] it threads into every host
/// method. The neutral fields
/// (`path`/`uri`/`headers`/`body`) the dialect reads directly, the core-bound state only through `ctx`.
pub struct Arrival {
    /// The core pipeline the dialect calls back through.
    pub host: Arc<dyn ArrivalHost>,
    /// The opaque core context (`App`/`GovCtx`/`CallerToken`) the dialect forwards into host methods.
    pub ctx: ArrivalCtx,
    /// The request path, already `to_string`ed by the catch-all. The dialect parses ITS OWN model out.
    pub path: String,
    /// An OUT-OF-BAND routing name the catch-all resolved from the URL, for the busbar convenience
    /// surfaces whose model/pool lives in the PATH rather than the body: the `/{name}/v1/messages`
    /// (`named`) pool/model name, or the `/{provider}/{model}/v1/messages` (`adhoc`) model. `None` for
    /// a dialect-native arrival (anthropic `/v1/messages`, the generic body-model dispatch), where the
    /// model rides the body. A body-model arrival threads this straight into `operation_ingress`'s
    /// `model_hint`, the byte-identical successor to the pre-relocation `named`/`adhoc` name routing.
    pub model_hint: Option<String>,
    /// The original request URI (query intact — Gemini reads `?alt=sse`).
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
}
