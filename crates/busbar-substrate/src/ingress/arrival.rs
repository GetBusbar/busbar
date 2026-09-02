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
/// universal ingress downcast back out. It USED to be `busbar_core::ingress::arrival_host::ArrivalPayload`
/// (an `Arc<App>` + `GovCtx` + caller token), which forced the extracted LLM plane to name a core type to
/// downcast it — the last structural backwards reach on the request path. Pivoted here so the payload is
/// spelled in the NEUTRAL substrate: it carries the minted `Arc<dyn EngineHost>` (not the `Arc<App>` it
/// was minted over), the public [`busbar_api::PlaneRequestCtx`] governance context, and the caller's
/// bearer token flattened to a neutral scalar. Core mints the host at each construction site
/// (`engine_host(&app)`); every downstream reader reaches the engine through the host seam, naming no
/// core type.
pub struct ArrivalPayload {
    /// The neutral engine host, minted core-side over the live `App` — the seam every reader (core's
    /// `ArrivalHost` impl and the LLM plane's ingress) drives instead of naming `Arc<App>`.
    pub host: Arc<dyn crate::plane_host::EngineHost>,
    /// The resolved per-request governance context (public `busbar_api` type).
    pub gov: busbar_api::PlaneRequestCtx,
    /// The caller's resolved bearer token (for passthrough forwarding), flattened to a neutral scalar.
    pub caller_token: Option<String>,
}

/// THE CORE REQUEST PIPELINE, as a path-model dialect's ingress reaches it. Every method that produces
/// a response future returns a BOXED, `'static` future: the core impl clones the cheap
/// `Arc<App>`/`GovCtx`/`CallerToken` out of the [`ArrivalCtx`] and owns the moved `HeaderMap`/`Bytes`,
/// so the future borrows nothing and is safe to hand back across the `fn`-pointer arrival boundary.
///
/// The `kind_*`/`err_type_*` accessors hand the dialect the core-owned neutral error-category vocabulary
/// (`KIND_NOT_FOUND`, …) by value, so the dialect names none of core's `proxy`/`admin` const modules.
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
/// method. A struct because it crosses a `fn` pointer ([`PathIngress`]); the neutral fields
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

// ============================================================================
// THE NEUTRAL BODY-MODEL ARRIVAL SEAM — the ABI a body-model dialect's universal ingress (the LLM
// plane's relocated `operation_ingress`) is registered through, mirroring the path-model seam above.
// A body-model protocol keeps the model IN THE BODY, so its arrival does no URL parsing; but the
// resolution + forward tail (`operation_ingress` → the one engine) reads the LLM routing tables and
// so RELOCATED into `busbar-llm`. Core's `protocol_dispatch` resolves the body-arrival by protocol
// name and calls it, naming no LLM type — exactly the plane ABI, reusing `Arrival`/`ArrivalHost`/
// `ArrivalCtx`.
// ============================================================================

/// A body-model dialect's own universal ingress: one arrival in, one boxed response future out.
/// Structurally identical to [`PathIngress` ] (it too takes an [`Arrival`] and returns a boxed
/// response future); a distinct alias names the DIFFERENT registration table it lands in (the
/// body-model side-table, not the path-model one).
pub type BodyIngress = fn(Arrival) -> Pin<Box<dyn Future<Output = Response> + Send>>;

/// One protocol-name → body-arrival pairing, the element of an installed / test body-arrival table.
pub type BodyIngressEntry = (&'static str, BodyIngress);

/// A fn that yields a `&'static` body-arrival table — the shape the core-test/`test-support` hook seeds.
#[cfg(any(test, feature = "test-support"))]
pub type BodyIngressFn = fn() -> &'static [BodyIngressEntry];

/// The body-arrivals the COMPOSITION ROOT installed, protocol-name-keyed. Set once by
/// [`install_body_ingress`]; consulted by [`body_ingress_for`]. A `Vec`, not a `&'static [_]`,
/// because the composition root ASSEMBLES it from whichever protocol crates are linked.
static INSTALLED_BODY_INGRESS: std::sync::OnceLock<Vec<(&'static str, BodyIngress)>> =
    std::sync::OnceLock::new();

/// INSTALL THE BODY-MODEL ARRIVALS — the composition root's one write, mirroring
/// [`install_path_ingress`]. Set-once.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
pub fn install_body_ingress(arrivals: Vec<(&'static str, BodyIngress)>) {
    assert!(
        INSTALLED_BODY_INGRESS.set(arrivals).is_ok(),
        "install_body_ingress called twice: there is one composition root, and it registers once"
    );
}

/// THE CORE-TEST/`test-support` BODY-ARRIVAL HOOK — the analogue of [`set_test_path_ingress`]. A
/// build with no composition root seeds the LLM plane's `BODY_INGRESS` slice here so
/// [`body_ingress_for`] resolves the universal ingress without a set-once `install_body_ingress`.
#[cfg(any(test, feature = "test-support"))]
static TEST_BODY_INGRESS_HOOK: std::sync::OnceLock<BodyIngressFn> = std::sync::OnceLock::new();

/// SEED THE CORE-TEST/`test-support` BODY-ARRIVAL HOOK. Idempotent (first writer wins).
#[cfg(any(test, feature = "test-support"))]
pub fn set_test_body_ingress(f: BodyIngressFn) {
    let _ = TEST_BODY_INGRESS_HOOK.set(f);
}

#[cfg(any(test, feature = "test-support"))]
fn test_body_ingress() -> &'static [BodyIngressEntry] {
    TEST_BODY_INGRESS_HOOK.get().map(|f| f()).unwrap_or(&[])
}

/// RESOLVE A BODY-MODEL DIALECT'S UNIVERSAL ARRIVAL BY NAME — the lookup `protocol_dispatch` performs
/// for a body-model protocol. Consults the installed table first, then the test hook. `None` when no
/// LLM plane is linked (core booted plane-agnostic): the caller then answers the honest no-handler
/// 404.
pub fn body_ingress_for(name: &str) -> Option<BodyIngress> {
    if let Some(installed) = INSTALLED_BODY_INGRESS.get() {
        if let Some((_, f)) = installed.iter().find(|(n, _)| *n == name) {
            return Some(*f);
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    if let Some((_, f)) = test_body_ingress().iter().find(|(n, _)| *n == name) {
        return Some(*f);
    }
    None
}

// ============================================================================
// THE NEUTRAL RESOLVED-COMPLETION SEAM — the ABI core's `EngineHost::synthesize_completion` (the MCP
// sampling re-entry) reaches the LLM plane's resolved-operation gauntlet through. The synthesizer
// drives ONE non-streaming chat completion (a known model + body) through the SAME resolved-op path
// (`operation_resolved` → the one engine) an arrival takes; that path reads the LLM routing tables
// and so RELOCATED into `busbar-llm`. Unlike the arrival seams there is exactly one synthesizer (the
// residual-default chat dialect's), so this is a single fn-pointer, not a protocol-keyed table.
// ============================================================================

/// One synthesize-completion request, as the LLM plane's relocated synthesizer receives it: the
/// opaque core context ([`ArrivalCtx`] carrying `App`/`GovCtx`/caller-token, downcast in-plane), the
/// resolved model, and the request headers + body. The plane resolves the residual-default chat
/// dialect + op itself and drives `operation_resolved` with `model` explicit — byte-identical to the
/// former core-resident `synthesize_completion_over`.
pub struct CompletionArrival {
    /// The opaque core context (`App`/`GovCtx`/caller-token) the plane downcasts in-plane.
    pub ctx: ArrivalCtx,
    /// The resolved model to route the synthesized completion through (passed explicitly, never read
    /// from the body).
    pub model: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// The LLM plane's resolved-completion synthesizer: one [`CompletionArrival`] in, one boxed response
/// future out (core reads its status + body into the neutral `HostCompletion`).
pub type CompletionIngress =
    fn(CompletionArrival) -> Pin<Box<dyn Future<Output = Response> + Send>>;

/// The synthesizer the COMPOSITION ROOT installed. Set once by [`install_completion_ingress`];
/// consulted by [`completion_ingress`]. Single, not a table (one residual-default chat synthesizer).
static INSTALLED_COMPLETION_INGRESS: std::sync::OnceLock<CompletionIngress> =
    std::sync::OnceLock::new();

/// INSTALL THE RESOLVED-COMPLETION SYNTHESIZER — the composition root's one write, mirroring
/// [`install_body_ingress`]. Set-once.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
pub fn install_completion_ingress(f: CompletionIngress) {
    assert!(
        INSTALLED_COMPLETION_INGRESS.set(f).is_ok(),
        "install_completion_ingress called twice: there is one composition root, and it registers once"
    );
}

/// THE CORE-TEST/`test-support` SYNTHESIZER HOOK — a build with no composition root seeds the LLM
/// plane's synthesizer here so [`completion_ingress`] resolves it without a set-once install.
#[cfg(any(test, feature = "test-support"))]
static TEST_COMPLETION_INGRESS_HOOK: std::sync::OnceLock<CompletionIngress> =
    std::sync::OnceLock::new();

/// SEED THE CORE-TEST/`test-support` SYNTHESIZER HOOK. Idempotent (first writer wins).
#[cfg(any(test, feature = "test-support"))]
pub fn set_test_completion_ingress(f: CompletionIngress) {
    let _ = TEST_COMPLETION_INGRESS_HOOK.set(f);
}

/// RESOLVE THE RESOLVED-COMPLETION SYNTHESIZER — the lookup `EngineHost::synthesize_completion`
/// performs. `None` when no LLM plane is linked (core booted plane-agnostic): the caller then returns
/// the honest "no chat dialect installed" error rather than a synthesized completion.
pub fn completion_ingress() -> Option<CompletionIngress> {
    if let Some(f) = INSTALLED_COMPLETION_INGRESS.get() {
        return Some(*f);
    }
    #[cfg(any(test, feature = "test-support"))]
    if let Some(f) = TEST_COMPLETION_INGRESS_HOOK.get() {
        return Some(*f);
    }
    None
}
