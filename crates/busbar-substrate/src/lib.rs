// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar NEUTRAL SUBSTRATE — the transport-agnostic value families and helpers a plane crate
//! (`busbar-mcp`, `busbar-a2a`) names without reaching into `busbar-core`.
//!
//! The Phase-B plane extraction inverts the old dependency direction: instead of the planes living
//! inside core and reaching for core-private types, the neutral pieces they share — trust value
//! families, egress-authorisation decisions, failover walk types, and the transport-neutral ingress
//! helpers — move DOWN into this crate. It depends only on the plugin contracts (`busbar-api`) and
//! the plugin ABI (`busbar-plugin`), both leaves, so a plane crate can depend on it with no path
//! back to core and no dependency cycle.
//!
//! B0-b relocates the Tier-0 leaves here (the guarded-fetch network primitives, the diagnostics
//! catalog, the audit vocabulary, the transport-neutral JSON-RPC envelope reader, the wire-format
//! names, and the capped upstream-body read); B1 the trust/egress/failover families. Core
//! re-exports each relocated item during the transition so the in-core call sites do not change in
//! the same commit.

// The neutral Admin API v1 DATA helpers (the path prefix + its absolute-path helper, the shared
// named-definition read view, and the OpenAPI response-schema attach helper) a plane crate names
// without reaching into core. Pure serde data + `serde_json` manipulation, no `App`/`Store`/audit/
// `Scope`. Core re-exports each from its old `admin::v1` path so its own call sites are unchanged.
pub mod api;
// The RFC 6750 `WWW-Authenticate` challenge render for OAuth 2.1 resource-server ingresses — pure
// `axum::http` + `serde_json`, no `App`/`Store`/auth-chain reach — so a plane crate names it without
// reaching into core. Core re-exports it from its old `auth::challenge` path.
pub mod auth {
    pub mod challenge;
}
pub mod detached;
pub mod diagnostics;
pub mod net_guard;
// A′ (ABI-purity P4): the ENV-guarded hot-path stage profiler (`Stage`/`start`/`record`/`dump`),
// relocated DOWN from `busbar-core` so the `busbar-llm` engine names it via the ABI instead of
// reaching back into `busbar_core::profile`. Pure std (atomics/Mutex/Instant), no `App`/`Store`
// reach, and — like the metrics registry — its accumulator buckets live SINGLE-COMPILED here so a
// dual-compiled plane test binary shares one profiler rather than splitting the sample set across
// two core instances. Core re-exports it from `busbar_core::profile` so its own call sites (the
// `auth`/`ingress` stage spans) are unchanged.
pub mod profile;
// A′ (ABI-purity P4): the neutral hot-path OBSERVABILITY floor a plane names via the ABI. Only the
// pure `HOTPATH_LEVEL` compile-time const lives here (the OTLP/stderr two-filter split's DEBUG
// floor); the App/webhook/net_guard-facing remainder of observability stays in busbar-core. Core
// re-exports this const from `busbar_core::observability::HOTPATH_LEVEL` so its call sites are
// unchanged.
pub mod observability {
    /// The tracing level at/above which the per-request hot-path spans (`forward`, lane-pick, egress)
    /// are emitted; the OTLP export floors here. A `const`, so both dual-compiled core instances in a
    /// plane test binary see one identical value — no registry, no split.
    pub const HOTPATH_LEVEL: tracing::Level = tracing::Level::DEBUG;
}
// wt2/neutral-utils: the five NEUTRAL transport/crypto utility leaves relocated down from
// busbar-core so a plane crate (busbar-llm) names them via the ABI instead of reaching back into
// `busbar_core::`. Each is pure (no plane/`App`/`Store` knowledge): JSON canonicalization + the
// depth-guarded parser seam (`sonic-rs`), the base64/media-type helper, the AWS EventStream (SSE)
// framing codec, the source-scoped lossless-extras namespace, and the hand-rolled SigV4 signer.
// Core re-exports each from its old `busbar_core::<mod>` path so its own call sites are unchanged.
pub mod eventstream;
pub mod json;
pub mod lossless;
pub mod media;
pub mod sigv4;
// A test-only tracing Layer that captures WARN/ERROR (and, lowered, DEBUG) events so the relocated
// `eventstream` framing tests can assert a `diag_*!` fired without a global subscriber. Copied with
// the module it serves; core keeps its own copy for its remaining test sites.
#[cfg(test)]
mod test_support {
    pub mod warn_capture;
}
pub mod audit {
    pub mod vocab;

    /// How many entries the in-memory ring retains. Bounds RAM, not history — a durable sink keeps the
    /// full log. `pub` (was `pub(crate)` in core) so the admin audit ring and the plane audit-log ring
    /// both name one cap across the core/substrate seam; core re-exports it at
    /// `crate::admin::audit::MAX_AUDIT_ENTRIES` so its own call sites are unchanged.
    pub const MAX_AUDIT_ENTRIES: usize = 1000;
}
pub mod ingress {
    /// THE NEUTRAL PATH-MODEL ARRIVAL SEAM — the `ArrivalHost` ABI a URL-model dialect (gemini/bedrock)
    /// calls to reach the core request pipeline, and the protocol-name-keyed side-table the composition
    /// root registers those arrivals through. Core implements `ArrivalHost` over its live `App`.
    pub mod arrival;
    /// THE NEUTRAL INBOUND BYTE-DUPLEX TRANSPORT — the byte half of a single full-duplex channel
    /// (framing, one write lock, a `CallRef`-keyed correlation table, EOF lifecycle), driven by a
    /// plane's two thin callbacks (`classify` + a frame handler). Names no protocol: frames cross as
    /// `Vec<u8>` and it parses none of them.
    pub mod byte_duplex;
    /// THE NEUTRAL FULL-DUPLEX WS INGRESS ACCEPTOR — accept an HTTP→WS upgrade (axum
    /// `WebSocketUpgrade`) and present the upgraded socket as the message `Stream`/`Sink<Vec<u8>>` pair
    /// [`byte_duplex::serve_messages`] consumes, keeping the handshake/routing at the boundary and out
    /// of the pump. The inbound half of the WS transport `Transport::WebSocket` selects; armed under
    /// `runtime`.
    #[cfg(feature = "runtime")]
    pub mod duplex_ws;
    pub mod jsonrpc;
    // B1: the transport-neutral JSON-RPC ingress SEQUENCE (`serve`), the core-refusal vocabulary and
    // the RFC 9728 metadata render. The `App`/`CurrentApp`-facing half (`ResourceMetadata`,
    // `metadata_handler`) stays in core and re-exports these.
    pub mod protocol;

    /// The NEUTRAL model-not-found copy shaper: the human string a router returns when a request
    /// names a model the deployment has no lane for. Pure text — the operator-shaped
    /// `model_not_found_message` override when present, else the historical default phrasing — with no
    /// `App` and no dialect. Relocated here (1.6.0 KEYSTONE) so the relocated engine names it without
    /// reaching into `busbar-core`; core re-exports it so its own call sites resolve unchanged.
    #[must_use]
    pub fn not_found_message(model: &str, model_not_found_message: Option<&str>) -> String {
        match model_not_found_message {
            Some(shaped) => shaped.to_string(),
            None => format!("The model '{model}' does not exist or you do not have access to it."),
        }
    }
}
pub mod billing;
pub mod breaker;
// The proleptic-Gregorian civil-date split shared by the plane crates that render an epoch timestamp
// (MCP task `iso8601_ms`, A2A push `status.timestamp`) without pulling a date-time crate into their
// closure. One copy here, in the substrate both planes depend on, rather than one per plane.
pub mod civil;
pub mod duration;
// The neutral protocol handler matrix — `OperationHandler`/`RequestHandler` and their codec-cell
// value families (`Cell`/`cell_of`/`IngressReject`/`CodecError`/`TranslateCodec`). Relocated from
// `busbar-core` so the dialect crates implement them here; core re-exports each from
// `busbar_core::handlers`. The engine dispatch handle and registry-resolved chat/op_for stay in core.
pub mod handlers;
// The neutral cross-plane IR leaves (`Invoke`/`Subscribe` request/response data) and the wire/egress
// value types (`WireBody`/`EgressCtx`). Pure value families a plane crate names directly; core keeps
// the `IrFacts` projection + the `IrHandle` wrappers and re-exports these types from their old paths.
pub mod egress;
pub mod ir;
pub mod plane;
pub mod wire;
// D1: the NEUTRAL HOST SEAM — the `EngineHost` trait a plane calls to reach engine host capabilities
// without naming a core type, plus the relocated lifecycle-scope arena (`DispatchScope` et al.) those
// capabilities register handles into. Core implements `EngineHost` over its live `App` and re-exports
// the scope types, so its own call sites are unchanged.
pub mod plane_host;
// S4a: the NEUTRAL ROUTE-MOUNT SEAM — the `PlaneRouteSpec` / `PlaneReqCtx` vocabulary a plane uses to
// declare its data routes without naming `CoreRouter` / `Arc<AppHandle>`, so `PlaneDecl`'s route
// field can be typed `fn(&dyn Any) -> Vec<PlaneRouteSpec>` and eventually travel to this crate.
pub mod plane_routes;
// ADMIN-2/3: the NEUTRAL PLANE TRUST-VERB SEAM — `PlaneTrust`/`PlaneVerbError`/`registered` (resolve +
// look) and `AdminRouteSpec`/`AdminReqCtx`/`AdminReply` (route mount), so a plane declares its admin
// trust verbs and resolves one registration without naming `AdminError`/`Scope`/`Arc<AppHandle>`/the
// core JSON envelope. Core re-exports the resolve/look half from `busbar_core::admin::planeverbs`.
pub mod admin_verbs;
pub mod admin_witness;
pub mod proto;
pub mod proxy;

// ── Phase-B B1: the trust value families + decision engines, the egress gate, the catalogue and the
// failover walk types + the lane-availability taxonomy. Each depends only on `busbar-api`
// (`VirtualKey`) and `busbar-plugin` (`hot::VerifyDecision`) — both leaves — plus this crate's own
// audit vocabulary. Core re-exports each relocated item so the in-core call sites do not change.
pub mod tls;
pub mod transport;
pub mod trust;
// THE EGRESS-AUTH SEAM: the outbound credential dispatch (`resolve`/`prebuild_auth`/
// `CredentialProvider`/`MetadataSsrfPolicy`), the two self-minting OAuth mechanisms (`jwt_bearer` /
// `oauth_client_credentials`, RFC 7523 / RFC 6749 §4.4) with their shared cached-token machinery,
// and the egress `gate` submodule. Relocated DOWN from `busbar_core::egress_auth` (the LLM plane
// named it as its last backwards reach); core re-exports every item at its historical
// `busbar_core::egress_auth::*` path so every in-core caller is unchanged. Secret material stays
// `busbar_api::Redacted` and the mint wire form is byte-identical — proven by the migrated mint
// suite (`jwt_bearer` / `oauth_client_credentials` / `helper` / `bearer_token` tests).
pub mod catalogue;
pub mod egress_auth;
pub mod failover;
pub mod store;
pub mod telemetry;
// The neutral METRIC-NAME facade: the `&'static str` Prometheus names a plane's engine emits. Pure
// data, no registry/`App`; core re-exports each from `crate::metrics`. The recorder + `render()` +
// scrape-time gauges stay in core (they flush the core-resident telemetry bank), so only the NAMES
// are neutral and the scrape stays ONE registry, byte-identical.
pub mod metrics;
// The neutral GOVERNANCE value families — the busbar-signed token crypto, the mint-parameter struct
// and the metering-bucket time base. Pure data + crypto with no `App`/`Store` reach; core re-exports
// each from its old `busbar_core::governance::…` path.
pub mod governance;
// ABI-purity CONFIG-ENUMS: the neutral LLM-runtime config VALUE enums (`PolicyOnError` /
// `ProviderAuth`) a plane names via the ABI. Fieldless serde enums moved DOWN with their derives +
// `#[serde(...)]` attrs VERBATIM (byte-identical wire form); core re-exports each from its historical
// `busbar_core::config::` path so the frozen config grammar + every deserialization are unchanged.
pub mod config;

// THE NEUTRAL hook value/wire layer (1.6.0 hooks seam): the plain-data resolved-policy carriers
// (`ResolvedPolicy`/`FallbackHook`) and the outbound hook-request `wire` projection, relocated off
// `busbar_core::hooks::` so the LLM model plane names the substrate ABI. Core re-exports these from its
// historical `busbar_core::hooks::` paths; the reply-side normalizers stay core-side.
pub mod hooks;

// THE TELLER: the one governed request loop every plane rides — the sealed step markers, the
// token-sealed capability types, the per-step plane trait and the single `run_unit` loop.
pub mod teller;

// THE NEUTRAL TEST-APP SEAM the plane test-kits drive the engine's test fixture through, so a plane
// crate builds/reaches the test App without naming `busbar_core::state::App`/`test_support::TestApp`.
// Revealed only under the test surface (core implements it for `TestApp`), like the sibling doubles.
#[cfg(any(test, feature = "test-support"))]
pub mod testkit;

// WEDGE 3-PREP: the neutral data-plane topology facts (worker count / per-thread worker id) + the
// per-worker-sharded upstream client they size, relocated DOWN from `busbar_core::state` so a plane
// crate names them without reaching into `busbar-core`. Core re-exports each at its historical
// `busbar_core::state::…` path.
pub mod topology;
