// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL PATH-MODEL ARRIVAL SEAM — the ABI a URL-model dialect's ingress (gemini/bedrock) calls
//! to reach the core request pipeline WITHOUT naming a `busbar-core` type, and the protocol-name-keyed
//! side-table the composition root registers those arrivals through.
//!
//! ## Why this lives in the neutral substrate
//!
//! A path-model dialect (Gemini keeps the model in `/v1beta/models/{model}:generateContent`, Bedrock
//! in `/model/{id}/converse`) parses its OWN model out of the URL and then runs the SAME resolution +
//! forward every other dialect runs. That parsing is the dialect's statement about its own URL space,
//! so it belongs in the dialect's crate (`busbar-llm`), not in core. But the resolution + forward it
//! then calls (`ingress_path_model`, `operation_ingress`, the `finish_rejected`/`ingress_error`
//! error-shaping, the mount-aware `envelope_dialect`) is deeply `App`/`GovCtx`/`CallerToken`-bound and
//! stays in core. [`ArrivalHost`] is the seam between the two: core implements it over its live `App`;
//! the dialect crate holds an `Arc<dyn ArrivalHost>` (carried on the [`Arrival`]) and calls typed, safe
//! methods on it, crossing the core-only `App`/`GovCtx`/`CallerToken` as an OPAQUE [`ArrivalCtx`] and
//! the neutral `Operation`/`Response`/`HeaderMap`/`Bytes` directly. So the dialect names no
//! `busbar_core::` item and core names no dialect — exactly the plane ABI, mirroring `EngineHost`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use busbar_api::operation::Operation;

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

/// THE CORE REQUEST PIPELINE, as a path-model dialect's ingress reaches it. Every method that produces
/// a response future returns a BOXED, `'static` future: the core impl clones the cheap
/// `Arc<App>`/`GovCtx`/`CallerToken` out of the [`ArrivalCtx`] and owns the moved `HeaderMap`/`Bytes`,
/// so the future borrows nothing and is safe to hand back across the `fn`-pointer arrival boundary.
///
/// The `kind_*`/`err_type_*` accessors hand the dialect the core-owned neutral error-category vocabulary
/// (`KIND_NOT_FOUND`, …) by value, so the dialect names none of core's `proxy`/`admin` const modules.
pub trait ArrivalHost: Send + Sync {
    /// THE SHARED PATH-MODEL CORE (`crate::ingress::ingress_path_model`): inject the URL-derived
    /// `model` + route `stream` intent into the body and run the universal resolution + forward.
    /// `model_not_found_message` is the dialect's PRE-SHAPED model-not-found body in its own native
    /// vocabulary, used verbatim by core on a model miss — the dialect that owns the request builds it
    /// (so core names no dialect); `None` shares the neutral OpenAI-style copy.
    #[allow(clippy::too_many_arguments)]
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
        model_not_found_message: Option<String>,
    ) -> Pin<Box<dyn Future<Output = Response> + Send>>;

    /// THE UNIVERSAL BODY-MODEL/RESOLVED-OP INGRESS (`crate::ingress::dispatch::operation_ingress`) —
    /// the Bedrock `InvokeModel` arrival's tail, where the model is a path hint.
    fn operation_ingress(
        &self,
        ctx: &ArrivalCtx,
        headers: HeaderMap,
        body: Bytes,
        proto: &'static str,
        operation: Operation,
        model_hint: Option<String>,
    ) -> Pin<Box<dyn Future<Output = Response> + Send>>;

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
/// method. A struct because it crosses a `fn` pointer ([`PathIngress`]); the neutral fields
/// (`path`/`uri`/`headers`/`body`) the dialect reads directly, the core-bound state only through `ctx`.
pub struct Arrival {
    /// The core pipeline the dialect calls back through.
    pub host: Arc<dyn ArrivalHost>,
    /// The opaque core context (`App`/`GovCtx`/`CallerToken`) the dialect forwards into host methods.
    pub ctx: ArrivalCtx,
    /// The request path, already `to_string`ed by the catch-all. The dialect parses ITS OWN model out.
    pub path: String,
    /// The original request URI (query intact — Gemini reads `?alt=sse`).
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// A path-model dialect's own ingress: one arrival in, one boxed response future out. `pub` so the
/// composition root and the dialect crate (`busbar-llm`) name the registration-pair type. Boxed
/// deliberately: as a `match` arm every arrival's future inlined into the dispatch coroutine's union,
/// inflating the future every request carried regardless of dialect — a `fn` pointer to a boxed future
/// keeps that cost on the requests that take it.
pub type PathIngress = fn(Arrival) -> Pin<Box<dyn Future<Output = Response> + Send>>;

/// One protocol-name → arrival pairing, the element of an installed / test arrival table.
pub type PathIngressEntry = (&'static str, PathIngress);

/// A fn that yields a `&'static` arrival table — the shape the core-test/`test-support` hook seeds.
#[cfg(any(test, feature = "test-support"))]
pub type PathIngressFn = fn() -> &'static [PathIngressEntry];

/// The arrivals the COMPOSITION ROOT installed, protocol-name-keyed. Set once by
/// [`install_path_ingress`]; consulted by [`path_ingress_for`]. A `Vec`, not a `&'static [_]`, because
/// the composition root ASSEMBLES it from whichever protocol crates are linked.
static INSTALLED_PATH_INGRESS: std::sync::OnceLock<Vec<(&'static str, PathIngress)>> =
    std::sync::OnceLock::new();

/// INSTALL THE PATH-MODEL ARRIVALS — the composition root's one write, folded into
/// [`crate::proto::install_protocols_with_path_ingress`] beside the decl install so the two cannot
/// drift. Set-once, mirroring `install_protocols`.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
pub fn install_path_ingress(arrivals: Vec<(&'static str, PathIngress)>) {
    assert!(
        INSTALLED_PATH_INGRESS.set(arrivals).is_ok(),
        "install_path_ingress called twice: there is one composition root, and it registers once"
    );
}

/// THE CORE-TEST/`test-support` ARRIVAL HOOK — the analogue of [`crate::proto::set_test_builtins`]. A
/// build with no composition root (core's own test binary, a downstream `test-support` consumer) seeds
/// the dialect crate's `PATH_INGRESS` slice here from a `tests/` file / the LLM test-kit, so
/// [`path_ingress_for`] resolves the URL-model arrivals without a set-once `install_path_ingress`.
#[cfg(any(test, feature = "test-support"))]
static TEST_PATH_INGRESS_HOOK: std::sync::OnceLock<PathIngressFn> = std::sync::OnceLock::new();

/// SEED THE CORE-TEST/`test-support` ARRIVAL HOOK. Idempotent (first writer wins; the slice is the same
/// linked `PATH_INGRESS` either way), so several tests / the LLM test-kit may call it freely.
#[cfg(any(test, feature = "test-support"))]
pub fn set_test_path_ingress(f: PathIngressFn) {
    let _ = TEST_PATH_INGRESS_HOOK.set(f);
}

#[cfg(any(test, feature = "test-support"))]
fn test_path_ingress() -> &'static [PathIngressEntry] {
    TEST_PATH_INGRESS_HOOK.get().map(|f| f()).unwrap_or(&[])
}

/// RESOLVE A PATH-MODEL DIALECT'S ARRIVAL BY NAME — the by-name lookup the catch-all performs.
/// Consults the installed table first (the shipped path), then the test hook (test/`test-support`
/// only). `None` for a body-model protocol (its model is not in the URL): core then reaches the
/// universal ingress, exactly as before.
pub fn path_ingress_for(name: &str) -> Option<PathIngress> {
    if let Some(installed) = INSTALLED_PATH_INGRESS.get() {
        if let Some((_, f)) = installed.iter().find(|(n, _)| *n == name) {
            return Some(*f);
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    if let Some((_, f)) = test_path_ingress().iter().find(|(n, _)| *n == name) {
        return Some(*f);
    }
    None
}
