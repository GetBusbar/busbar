// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VOICE PLANE'S DATA-ROUTE MOUNT (behind the `runtime` feature) — the structural surface that
//! turns `PLANE_DECL`'s `routes` / `claims` / `admission` / `build` hooks from `None`/empty into the
//! plane's real ingress door.
//!
//! ## The two slots, and which one this is
//!
//! Voice contributes a DISPATCH slot ([`VoiceMount`]) through [`PlaneDecl::build`], carried in
//! `plane_slots` under the plane's decl key (`"voice"`). It is the object [`voice_claims`] /
//! [`voice_admission`] / [`voice_routes`] all read, and the SAME object the core route adapter hands a
//! handler as `PlaneReqCtx::slot`. It carries the plane's RFC 8707 audience (derived from the
//! deployment's `public_url`, the A2A precedent — one reading so the audience a caller is told to ask
//! for and the one busbar demands cannot drift apart) plus a live [`VoiceRuntime`] the route handlers
//! open governed sessions from. `None` when there is no `public_url` — a deployment with no receiving
//! origin fronts nothing, claims nothing and admits no one (the A2A delegation-only asymmetry).
//!
//! ## Five routes, two dialects, and what is live
//!
//! Every route MOUNTS, is AUDIENCE-CHECKED (`RouteAuth::Key`, under the plane's one audience) and, on
//! arrival, runs the governed session-open through [`crate::topology::begin_session`] /
//! [`crate::topology::telephony::begin_telephony`] — which go through `run_gauntlet_session`
//! (verify-strictly-before-charge). The two one-shot HTTP passes (`ek_` mint, SDP broker) reach the
//! provider once one is composed ([`install_provider`]); the browser-sideband WS accept is
//! control-only by design (media is peer-to-peer, see `crate::topology::webrtc`); the telephony and
//! Gemini Live WS accepts DIAL the composed provider through [`crate::topology::dial_provider`] and
//! proxy both sockets (see [`ws_accept`]) once one is composed. With no provider composed, every leg
//! still governs and mounts — it serves the client socket only, exactly as documented in
//! `docs/voice.md`.

use crate::ir::codec::gemini::GeminiLiveCodec;
use crate::ir::codec::{DuplexReader, DuplexWriter, OpenAiRealtimeCodec};
use crate::ir::config::SessionConfig;
use crate::runtime::carrier::Carrier;
use crate::runtime::scope::SessionHandle;
use crate::runtime::session::{UplinkForwarder, VoiceSession};
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use crate::topology::minter_https::HttpsTokenMinter;
use crate::topology::telephony::{begin_telephony, g711_config, open_admitted_telephony};
use crate::topology::webrtc::TokenMinter;
use crate::topology::{
    begin_session, dial_provider, open_admitted_session, stream_breaker_key, SessionBudget,
    SessionGauntlet, StartError,
};
use busbar_substrate::net_guard::GuardPolicy;
use busbar_substrate::egress::engine::{send_bounded, EngineClient};
use busbar_substrate::ingress::byte_duplex::serve_messages;
use busbar_substrate::ingress::duplex_ws::{
    accept_gauntlet, WsAcceptFuture, WsArrival, WsArrivalSpec,
};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane::observe::Counted;
use busbar_substrate::plane::registry::{BuildCtx, PlaneBootCtx};
use busbar_substrate::plane::PlaneAdmission;
use busbar_substrate::plane_host::{EngineHost, GateOutcome, TransformVerdict};
use busbar_substrate::plane_host::{GauntletPlane, GauntletRequest};
use busbar_substrate::plane_routes::PlaneRouteSpec;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::any::Any;
use std::sync::Arc;

/// The `busbar_plane_requests_total` family name (labels: plane, ingress_protocol, pool, outcome) —
/// the neutral per-mounted-plane request counter the core `/metrics` scrape exposes. Named by literal
/// so the voice plane emits into the SAME family without reaching into `busbar-core` (which owns the
/// constant); a `Counted` marker on the answer stands the core `plane::observe` middleware down so the
/// front-door series is never double-counted.
const PLANE_REQUESTS_TOTAL: &str = "busbar_plane_requests_total";

/// The bounded `pool` label the voice FRONT DOOR (the voice-server cell) emits under — a constant, not
/// a caller value, so the series count stays bounded. The outbound provider dial (the voice-client
/// cell) counts on its own `busbar_upstream_attempts_total` family in `topology::dial_provider`.
const FRONT_DOOR_POOL: &str = "voice-server";

/// The session-open method label the hook gate/tap projection carries — the single operation a voice
/// front-door request performs. Bounded (one value), so it is safe as the hook `tool` slot the
/// operator's gate reads.
const SESSION_OPEN_METHOD: &str = "session.open";

/// The coarse over-estimate (nanodollars) a session debits up front at reserve. It is an audit tap,
/// not a ceiling — the ceiling is the presenting key's own remaining budget, read per session.
const SESSION_ESTIMATE_NANOS: u64 = 1_000;

/// THE HOOK CONTAINER the voice plane's session-open gate/tap fire under — the plane's SINGULAR config
/// section noun (`streams`), since voice declares no per-registration container (its config is one
/// object, not a named-definition map). The operator attaches a session-open gate to this ONE
/// container, and `gate_attached(plane_key, container)` reads it here.
const GATE_CONTAINER: &str = "streams";

/// THE SCOPE KIND a key must hold to open a live session — the plane's one declared scope kind (see
/// `PLANE_DECL.scope_kinds`). Named once here, so the vocabulary an operator writes in
/// `allowed_scopes: [{ kind: session, value: … }]` and the vocabulary the door demands cannot drift.
const SESSION_SCOPE_KIND: &str = "session";

/// MAY THIS KEY OPEN A LIVE SESSION? The plane's authorization question, asked of the presenting key's
/// own grant and nothing else — the same shape MCP asks about a tool and A2A asks about an agent.
///
/// The value asked about is the voice front door's pool ([`FRONT_DOOR_POOL`]), which is the one pool a
/// voice session is ever served on, so an operator narrows a key to voice by granting
/// `{ kind: session, value: voice-server }` and nothing wider. A key with NO scope list at all is the
/// store's wildcard and is granted every kind, exactly as it is on every other plane; a key that
/// carries a list must have this entry in it.
#[must_use]
pub fn session_scope_allowed(key: &busbar_api::VirtualKey) -> bool {
    key.scope_allowed(SESSION_SCOPE_KIND, FRONT_DOOR_POOL)
}

/// The refusal a key without session scope gets: the plane's own fail-closed answer, in the same
/// plain-text shape every other voice refusal takes, and BEFORE any hook, lease, durable row or dial.
fn session_scope_refusal() -> axum::response::Response {
    refusal(
        axum::http::StatusCode::FORBIDDEN,
        "voice session-open refused: the presenting key holds no session scope for this voice pool \
         (fail closed)",
    )
}

/// A CONFIGURED PROVIDER ENDPOINT the one-shot mint / SDP-broker passes reach the realtime provider
/// through — the base origin plus the real server-side key. Composed by the composition root through
/// [`install_provider`]; a loopback test injects one directly into [`open_governed`] instead. The real
/// key stays server-side: it authenticates only the busbar↔provider hop and never reaches a browser
/// payload, and it is never rendered into any public accessor here.
pub(crate) struct ProviderEndpoint {
    /// The provider origin (scheme + authority, e.g. `https://api.openai.com`).
    pub base_url: String,
    /// The REAL provider key, held server-side.
    pub api_key: String,
}

/// THE COMPOSED REALTIME PROVIDER — the one endpoint the mint / SDP-broker passes dial, written once
/// by the composition root and read by every route thereafter.
///
/// SET-ONCE, first writer wins, exactly like the composition root's other process-wide installs (the
/// WS-accept arrivals, the hostless-egress driver). It is written after the deployment's config
/// resolves — which is later than the per-generation dispatch slot is built — so the routes read it
/// HERE rather than off the slot, and a config apply that rebuilds the slot cannot drop it.
static COMPOSED_PROVIDER: std::sync::OnceLock<ProviderEndpoint> = std::sync::OnceLock::new();

/// COMPOSE the realtime provider endpoint the mint / SDP-broker passes authenticate with — the
/// composition root's one write of the voice plane's egress credential.
///
/// `base_url` is the provider origin and `api_key` the credential the deployment already resolved
/// through its ordinary provider catalog and secret resolver — the plane's `streams:` grammar carries
/// no credential field and gains none. Returns `false` when an endpoint was already composed (the
/// first write stands), so a second caller is a no-op rather than a silent credential swap.
pub fn install_provider(base_url: impl Into<String>, api_key: impl Into<String>) -> bool {
    COMPOSED_PROVIDER
        .set(ProviderEndpoint {
            base_url: base_url.into(),
            api_key: api_key.into(),
        })
        .is_ok()
}

/// COMPOSE the realtime provider endpoint from a provider-catalog entry — the form the composition
/// root calls, so the plane resolves its own credential through the deployment's ordinary secret
/// resolver rather than the root handing plaintext across.
///
/// `base_url` and `api_key` are the origin and the secret REFERENCE the deployment already declared
/// for this provider in its provider catalog; `resolver` is the neutral secret-resolver seam (the
/// same one every other credential in the deployment is resolved through, built-in `env`/`file` plus
/// any `kind: secret` module). Fails closed with the resolver's own message: an unresolvable
/// reference composes nothing, so the mint / SDP routes keep answering "no provider composed" rather
/// than dialing with an empty credential. `Ok(false)` means an endpoint was already composed.
pub fn compose_provider(
    base_url: impl Into<String>,
    api_key: &busbar_api::SecretRef,
    resolver: &dyn busbar_api::SecretResolve,
) -> Result<bool, String> {
    let resolved = resolver.resolve_string(api_key)?;
    Ok(install_provider(base_url, resolved))
}

/// The composed provider endpoint, or `None` when the composition root composed none — in which case
/// the mint / SDP routes still answer "governed, but no provider credential composed".
pub(crate) fn composed_provider() -> Option<&'static ProviderEndpoint> {
    COMPOSED_PROVIDER.get()
}

/// Whether a realtime provider endpoint has been composed — i.e. whether the mint / SDP passes serve
/// rather than answering "no provider composed". The credential itself is never exposed.
#[must_use]
pub fn provider_composed() -> bool {
    COMPOSED_PROVIDER.get().is_some()
}

/// The composed provider's ORIGIN (never its key) — the non-secret half, for a boot log or a
/// conformance probe that needs to confirm which endpoint this deployment composed.
#[must_use]
pub fn composed_provider_base_url() -> Option<&'static str> {
    COMPOSED_PROVIDER.get().map(|p| p.base_url.as_str())
}

// ── THE SECOND DIALECT'S PROVIDER ENDPOINT (K4) ─────────────────────────────────────────────────────
//
// The K1 provider seam above is single-endpoint and OpenAI-shaped: one `OnceLock`, one credential, one
// `Authorization: Bearer` scheme. Gemini Live's provider hop authenticates with a DIFFERENT native
// scheme (`x-goog-api-key`, never `Authorization`), so it cannot share the OpenAI endpoint without
// silently reusing the wrong header shape. A second, independently-composed endpoint is the fix: same
// set-once discipline, same fail-closed resolve, keyed to its own dialect rather than folded into the
// first.

/// A COMPOSED REALTIME PROVIDER — the ONE endpoint the Gemini Live route dials, written once by the
/// composition root and read by [`ws_accept`] (via [`composed_gemini_provider`]) thereafter. SET-ONCE, first writer
/// wins, exactly like [`COMPOSED_PROVIDER`] — a second compose is a no-op, never a silent swap.
static COMPOSED_PROVIDER_GEMINI: std::sync::OnceLock<ProviderEndpoint> = std::sync::OnceLock::new();

/// COMPOSE the Gemini Live provider endpoint the plane's Gemini route dials — the Gemini twin of
/// [`install_provider`]. `api_key` is the RAW resolved credential (Gemini's native `x-goog-api-key`
/// value, never wrapped as a bearer token); the plane never renders it into a public accessor.
pub fn install_gemini_provider(base_url: impl Into<String>, api_key: impl Into<String>) -> bool {
    COMPOSED_PROVIDER_GEMINI
        .set(ProviderEndpoint {
            base_url: base_url.into(),
            api_key: api_key.into(),
        })
        .is_ok()
}

/// COMPOSE the Gemini Live provider endpoint from a provider-catalog entry — the Gemini twin of
/// [`compose_provider`]: resolves `api_key` through the deployment's neutral secret resolver and fails
/// closed (composes nothing) on an unresolvable reference.
pub fn compose_gemini_provider(
    base_url: impl Into<String>,
    api_key: &busbar_api::SecretRef,
    resolver: &dyn busbar_api::SecretResolve,
) -> Result<bool, String> {
    let resolved = resolver.resolve_string(api_key)?;
    Ok(install_gemini_provider(base_url, resolved))
}

/// The composed Gemini Live provider endpoint, or `None` when the composition root composed none.
pub(crate) fn composed_gemini_provider() -> Option<&'static ProviderEndpoint> {
    COMPOSED_PROVIDER_GEMINI.get()
}

/// Whether a Gemini Live provider endpoint has been composed.
#[must_use]
pub fn gemini_provider_composed() -> bool {
    COMPOSED_PROVIDER_GEMINI.get().is_some()
}

/// The composed Gemini provider's ORIGIN (never its key).
#[must_use]
pub fn composed_gemini_provider_base_url() -> Option<&'static str> {
    COMPOSED_PROVIDER_GEMINI.get().map(|p| p.base_url.as_str())
}

/// Gemini Live's native provider auth HEADER NAME — `x-goog-api-key`, never `Authorization`. Named
/// once, publicly, so a conformance probe and the live dial (once header-carrying WS dial lands; see
/// [`provider_ws_url`]'s doc for today's honest limit) name the SAME literal.
pub const GEMINI_API_KEY_HEADER: &str = "x-goog-api-key";

/// THE VOICE PLANE'S RFC 8707 RESOURCE PATH — the segment the plane's canonical audience carries and
/// the base every voice ingress route sits under. A token presented on any `/v1/realtime/*` path must
/// carry the audience `<public_url>/v1/realtime`; the claim of this ONE base covers all four routes by
/// segment-boundary match (the MCP `mount_path` / A2A `/a2a` precedent — one resource, one audience).
pub const MOUNT_PATH: &str = "/v1/realtime";

/// The browser-WebRTC ephemeral (`ek_`) client-secret MINT endpoint — a one-shot HTTP pass. The
/// concrete `TokenMinter` (the live `POST /v1/realtime/client_secrets` to the provider) is the port a
/// deployment binds; this route mounts + governs the session-open the mint is scoped to.
pub const MINT_PATH: &str = "/v1/realtime/client_secrets";

/// The SDP BROKER endpoint — a one-shot HTTP pass (`application/sdp` in, the provider's SDP answer
/// out). The upstream `POST /v1/realtime/calls` is the credential-gated tail behind the egress port.
pub const SDP_PATH: &str = "/v1/realtime/calls";

/// The BROWSER-WEBRTC SIDEBAND accept — the persistent control channel keyed by `{call_id}`. The
/// socket upgrade + provider dial is the credential-gated tail; the governed open runs here on arrival.
pub const SIDEBAND_PATH: &str = "/v1/realtime/sideband/{call_id}";

/// The TELEPHONY WS accept — the carrier media leg keyed by `{call_id}`, proxied `g711_ulaw`
/// end-to-end. The socket upgrade + provider WSS dial is the credential-gated tail.
pub const TELEPHONY_PATH: &str = "/v1/realtime/telephony/{call_id}";

/// THE GEMINI LIVE WS ACCEPT — the plane's SECOND dialect route (K4): a THIN DUPLEX PROXY between the
/// caller's WS and the Gemini `BidiGenerateContent` upstream, the same shape as the telephony leg
/// (client WS <-> busbar <-> provider WS) rather than the OpenAI browser-sideband's mint+SDP dance —
/// Gemini Live has no ephemeral-token-mint or SDP-broker concept; it is a native full-duplex socket on
/// both legs. Keyed by `{call_id}` exactly as the other WS legs are.
pub const GEMINI_PATH: &str = "/v1/realtime/gemini/{call_id}";

/// THE GEMINI DIALECT'S CLAIMED BASE — a path distinct from [`MOUNT_PATH`] so [`voice_claims`] can name
/// the Gemini route under its OWN wire format ([`crate::GEMINI_LIVE`]) rather than folding it into the
/// OpenAI claim, the A2A precedent of returning more than one `(path, wire)` pair per plane.
const GEMINI_MOUNT_PATH: &str = "/v1/realtime/gemini";

/// The RFC 9728 protected-resource metadata path for the voice resource (the `resource_metadata` a
/// refused caller is pointed at). Derived from `public_url` beside the audience; a deployment serves
/// the document itself (not one of the five mounted data routes).
const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/v1/realtime";

/// THE VOICE PLANE'S DISPATCH SLOT — the per-generation object `build` erases into `plane_slots` under
/// the decl key. Carries the plane's audience facts (derived from `public_url`) and a live runtime the
/// route handlers open governed sessions from.
pub struct VoiceMount {
    /// The RFC 8707 audience every inbound voice token must carry — `<public_url>/v1/realtime`.
    audience: String,
    /// The absolute RFC 9728 metadata URL quoted into a refused caller's `WWW-Authenticate` challenge.
    resource_metadata: String,
    /// The per-generation session runtime every route opens governed sessions from, carrying the
    /// operator's own `streams:` posture and ceilings. Its metering port is only the PRE-HOST default:
    /// each route rebinds the money hop onto the live host lease (`build_runtime_hosted`) once a
    /// request hands it an engine host, so a served session reserves against the caller's real grant.
    runtime: Arc<VoiceRuntime>,
    /// A per-slot provider endpoint override — `None` in every built slot, because the composition
    /// root composes the provider process-wide ([`install_provider`]) AFTER the slot is built. Kept as
    /// a field so a loopback test can inject one directly into [`open_governed`].
    ///
    /// The Gemini Live provider has NO per-slot override twin: unlike the OpenAI mint/SDP one-shot
    /// passes (which take a request-scoped `Option<&ProviderEndpoint>` a test can construct locally,
    /// see [`GovernedOpen::provider`]), the Gemini leg is a WS accept whose `on_socket` closure must be
    /// `'static` — so it reads the process-wide [`composed_gemini_provider`] directly rather than
    /// through the (non-`'static`) mount, and there is no request-scoped path to override on.
    provider: Option<ProviderEndpoint>,
}

impl VoiceMount {
    /// The realtime provider endpoint this mount's routes dial: the slot's own override when one was
    /// injected, else the one the composition root composed. `None` on a deployment that composed no
    /// provider, in which case the mint / SDP passes answer "governed, but no provider composed".
    fn provider(&self) -> Option<&ProviderEndpoint> {
        match self.provider.as_ref() {
            Some(p) => Some(p),
            None => composed_provider(),
        }
    }
}

impl VoiceMount {
    /// This plane's admission facts — the audience a token at the voice door must carry and where a
    /// refused caller is sent for one. Both strings are ONE reading of `public_url`, so the audience a
    /// caller is told to ask for and the one busbar demands cannot drift apart (the A2A precedent).
    fn admission(&self) -> PlaneAdmission {
        PlaneAdmission {
            audience: self.audience.clone(),
            resource_metadata: self.resource_metadata.clone(),
        }
    }
}

/// ONE READING of `public_url`: parse it, REPLACE the path wholesale, drop query and fragment — so a
/// `public_url` carrying a path of its own cannot produce a second spelling of the voice resource. The
/// A2A `serve::absolute` discipline, kept local so the plane names no core serve helper.
fn absolute(public_url: &str, path: &str) -> Option<String> {
    let mut u = url::Url::parse(public_url).ok()?;
    u.set_path(path);
    u.set_query(None);
    u.set_fragment(None);
    Some(u.to_string())
}

/// [`PlaneDecl::hydrate`] — BOOT-REHYDRATE the durable voice-session working-set BEFORE any listener is
/// bound, mirroring the A2A task-set restore. Under `store: memory` (the ephemeral posture this
/// in-process mount runs) there is no durable working-set, so it skips exactly as the A2A / MCP hydrate
/// hooks do — the plane's live carriers are per-connection and never survive a restart. When a durable
/// store IS configured, it restores the persisted `voice_session` rows through the neutral engine seam
/// ([`crate::runtime::scope::rehydrate_sessions`]): an active row is re-installed, a terminal one is
/// counted and left, and a row whose durable body cannot be decoded is counted and skipped — one bad
/// row never aborts the restore. Only a store-level list failure refuses boot (propagated as `Err`).
///
/// # Errors
/// Returns the store error's text when the durable list itself fails — a boot-refusing condition.
pub fn voice_hydrate(ctx: &dyn PlaneBootCtx) -> Result<(), String> {
    // Ephemeral by design (no configured store): no durable working-set to restore, so skip — the same
    // first move the A2A task-set restore makes.
    let Some(store) = ctx.plane_store() else {
        return Ok(());
    };
    // A configured store: restore the durable `voice_session` working-set into a fresh engine and
    // surface the outcome. A durable row a resumed session reattaches to via `SessionHandle::bind`.
    let engine = DurableHandleEngine::new();
    let counts = crate::runtime::scope::rehydrate_sessions(&engine, store.as_ref())
        .map_err(|e| format!("voice session rehydrate failed: {e}"))?;
    if counts.unreadable > 0 {
        tracing::warn!(
            unreadable = counts.unreadable,
            "voice: some durable session rows could not be decoded on boot; counted and skipped"
        );
    }
    // DEBUG, not INFO: a 1.5.5-shaped config with no `streams:` section still runs this hook (it is
    // gated on `has_store()`, not on the plane being configured) and must not gain a new boot line at
    // INFO — the neutrality binding (docs/design/ARCHITECTURE.md Appendix B). An operator who DID
    // configure `streams:` can still see this at DEBUG.
    tracing::debug!(
        active = counts.active,
        terminal = counts.terminal,
        unreadable = counts.unreadable,
        "voice: durable session working-set rehydrated"
    );
    Ok(())
}

/// [`PlaneDecl::start`] — the post-listener boot step. Voice opens no background boot task: a live
/// session is admitted and served per WS-accept ARRIVAL (through `run_gauntlet_session`, one governed
/// pass per connection), each running its own supervised pump that parks on the carrier's hard-close —
/// there is no process-wide sweep loop to spawn here (unlike the A2A start, which resolves outbound
/// client identities once). The live accept listener + provider dial are composed by the composition
/// root behind the plane's ports (the credential-gated tail). So this confirms readiness and returns
/// `Ok`, participating in the boot fold so the plane is an explicit member of it rather than silent.
///
/// # Errors
/// Never fails today; the signature is the boot-hook shape so future post-listener work refuses boot
/// through it rather than gaining a new seam.
pub fn voice_start(_ctx: &dyn PlaneBootCtx) -> Result<(), String> {
    tracing::debug!(
        "voice: started — sessions are admitted and served per WS-accept arrival (one \
         run_gauntlet_session pass each); no process-wide background task is spawned"
    );
    Ok(())
}

/// [`PlaneDecl::build`] — construct the voice DISPATCH slot for one config generation. Reads the
/// deployment's `public_url` (the receiving origin the plane fronts) and derives the plane's audience
/// from it. `None` when there is no `public_url`: a deployment with no receiving origin fronts nothing,
/// claims nothing and admits no one — the A2A delegation-only asymmetry, and what makes the plane bind
/// no audience rather than mount a door that could only ever refuse.
#[must_use]
pub fn voice_build(ctx: &BuildCtx) -> Option<Arc<dyn Any + Send + Sync>> {
    let public = ctx.public_url?;
    let audience = absolute(public, MOUNT_PATH)?;
    let resource_metadata = absolute(public, METADATA_PATH)?;
    let mount = VoiceMount {
        audience,
        resource_metadata,
        runtime: Arc::new(dispatch_runtime()),
        // No per-slot override: the composed provider is read process-wide at request time, because the
        // composition root composes it only after the deployment's config resolves (see the field doc).
        provider: None,
    };
    Some(Arc::new(mount))
}

/// The per-generation session runtime the dispatch slot carries. Seeded with the operator's own
/// `streams:` posture (the section the plane parsed — see `crate::config::configured`), so the locked
/// session config a mint carries and the ceilings the pump enforces are the ones the deployment wrote
/// rather than the plane's dev defaults. Its metering port is the pre-host default; every route
/// rebinds it onto the live host lease (see [`VoiceMount::runtime`]).
fn dispatch_runtime() -> VoiceRuntime {
    VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
    )
    .with_streams(&crate::config::configured())
}

/// [`PlaneDecl::claims`] — the ONE audience-checked region the voice plane answers on, spoken in its
/// first dialect. The base [`MOUNT_PATH`] covers all four routes by segment-boundary match, so every
/// `/v1/realtime/*` path a token is presented on is a path this plane claims (the R1 ratchet's
/// invariant: a path the plane answers on is a path it claims). Empty when the plane has no receiving
/// side (no dispatch slot), so it claims nothing exactly as it admits no one.
#[must_use]
pub fn voice_claims(slot: &dyn Any) -> Vec<(String, &'static str)> {
    match slot.downcast_ref::<VoiceMount>() {
        // TWO claims, one PER ROUTE DIALECT (K4): the OpenAI base (mint/SDP/sideband/telephony) and the
        // Gemini Live base (the thin duplex proxy) — the A2A precedent of naming more than one
        // `(path, wire)` pair so each dialect's own `ingress_protocol` is the one its own path answers
        // in, not a plane-wide constant that would mislabel the second dialect's traffic as the first.
        Some(_) => vec![
            (MOUNT_PATH.to_string(), crate::OPENAI_REALTIME),
            (GEMINI_MOUNT_PATH.to_string(), crate::GEMINI_LIVE),
        ],
        None => Vec::new(),
    }
}

/// [`PlaneDecl::admission`] — the audience a voice token must carry and where a refused caller is sent
/// for one, from the same dispatch slot. `Some` whenever the plane has a receiving side (a slot),
/// so `build_dispatch`'s R2 ratchet — a plane that CLAIMS a path must ADMIT (or boot refuses) — holds
/// by construction here: a slot ⇒ a claim AND an admission, never one without the other.
#[must_use]
pub fn voice_admission(slot: &dyn Any) -> Option<PlaneAdmission> {
    slot.downcast_ref::<VoiceMount>().map(VoiceMount::admission)
}

/// [`PlaneDecl::routes`] — the voice plane's TWO one-shot HTTP ingress routes, described NEUTRALLY
/// (S4a Option A): the `ek_` mint + SDP broker passes, each a thin neutral handler over `PlaneReqCtx`.
/// Both are `RouteAuth::Key` — behind the plane's one audience — so a token minted for another
/// resource is refused at the door. The browser-sideband + telephony WS-accept legs are NOT here: an
/// inbound WS upgrade cannot ride the buffered-body `PlaneReqCtx` adapter, so they are declared through
/// the neutral inbound WS-accept seam instead (see [`voice_ws_arrivals`]). Empty when the plane has no
/// receiving side (no dispatch slot), so a deployment that fronts nothing mounts nothing.
#[must_use]
pub fn voice_routes(slot: &dyn Any) -> Vec<PlaneRouteSpec> {
    use busbar_plugin::cold::http_endpoint::{RouteAuth, RouteMethod};
    use busbar_substrate::plane_routes::{PlaneReqCtx, PlaneRouteFuture};

    if slot.downcast_ref::<VoiceMount>().is_none() {
        return Vec::new();
    }
    vec![
        PlaneRouteSpec {
            path: MINT_PATH.to_string(),
            method: RouteMethod::Post,
            auth: RouteAuth::Key,
            handler: Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture { Box::pin(mint_route(ctx)) }),
        },
        PlaneRouteSpec {
            path: SDP_PATH.to_string(),
            method: RouteMethod::Post,
            auth: RouteAuth::Key,
            handler: Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture { Box::pin(sdp_route(ctx)) }),
        },
    ]
}

/// THE VOICE PLANE'S INBOUND WS-ACCEPT ARRIVALS — the browser-sideband + telephony media legs,
/// declared through the neutral substrate WS-accept seam (`WsArrivalSpec`) rather than `routes`,
/// because an inbound WS upgrade cannot ride the buffered-body `PlaneReqCtx` adapter (its body is
/// already consumed). Both are `RouteAuth::Key` under the plane's one audience — the SAME admission bar
/// the mint/SDP routes carry — so the auth middleware refuses a foreign-resource token BEFORE the
/// accept fn runs. The composition root installs these (`install_ws_arrivals`) and the core router
/// mounts one gauntlet-gated WS-accept route per spec, resolving the live runtime slot under the
/// plane's decl `key`. Empty when the plane has no receiving side, exactly as [`voice_routes`].
#[must_use]
pub fn voice_ws_arrivals() -> Vec<WsArrivalSpec> {
    use busbar_plugin::cold::http_endpoint::RouteAuth;
    let key = crate::PLANE_DECL.key;
    vec![
        WsArrivalSpec {
            path: SIDEBAND_PATH.to_string(),
            auth: RouteAuth::Key,
            slot_key: key,
            accept: Arc::new(|a: WsArrival| -> WsAcceptFuture {
                Box::pin(ws_accept(a, Ingress::Sideband, OpenAiRealtimeCodec))
            }),
        },
        WsArrivalSpec {
            path: TELEPHONY_PATH.to_string(),
            auth: RouteAuth::Key,
            slot_key: key,
            accept: Arc::new(|a: WsArrival| -> WsAcceptFuture {
                Box::pin(ws_accept(a, Ingress::Telephony, OpenAiRealtimeCodec))
            }),
        },
        // THE GEMINI LIVE THIN-DUPLEX ACCEPT (K4) — same admission bar (RouteAuth::Key under the
        // plane's one audience), the SAME `ws_accept` choke point, generic over the Gemini codec
        // instead of the OpenAI one.
        WsArrivalSpec {
            path: GEMINI_PATH.to_string(),
            auth: RouteAuth::Key,
            slot_key: key,
            accept: Arc::new(|a: WsArrival| -> WsAcceptFuture {
                Box::pin(ws_accept(a, Ingress::Gemini, GeminiLiveCodec))
            }),
        },
    ]
}

/// WHICH ingress a route drives — the topology-shaping fact a handler carries into the shared governed
/// open. Every arm funnels through [`crate::topology::begin_session`] (so through
/// `run_gauntlet_session`); they differ only in the locked config and carrier the topology binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ingress {
    /// The `ek_` mint (browser-WebRTC sideband): a sideband control session, no downlink media relay.
    Mint,
    /// The SDP broker: same sideband governed open; the SDP handshake is the credential-gated tail.
    Sdp,
    /// The browser-WebRTC sideband accept.
    Sideband,
    /// The telephony media leg — `g711_ulaw` end-to-end through the thin proxy.
    Telephony,
    /// THE GEMINI LIVE THIN-DUPLEX LEG (K4) — a native full-duplex socket both sides, proxied through
    /// the SAME [`crate::topology::telephony::TelephonyProxy`] shape the telephony leg uses (client WS
    /// <-> busbar <-> provider WS), just without the g711 lock and under the Gemini codec + the
    /// Gemini-keyed composed provider.
    Gemini,
}

/// The neutral inputs one governed session-open reads — bundled so the choke point takes ONE argument
/// and a test constructs the SAME shape the route handler does. `host` is the owned host seam (cloned
/// per blocking hook hop), `provider` the configured realtime endpoint (`None` ⇒ the mint / SDP passes
/// answer `501`), `key` the caller `(id, name)` the hook gate reads, `body`/`headers` the one-shot
/// pass's request payload (the SDP offer + its `Authorization: Bearer ek_`).
pub(crate) struct GovernedOpen<'a> {
    pub rt: &'a VoiceRuntime,
    pub host: Arc<dyn EngineHost>,
    pub provider: Option<&'a ProviderEndpoint>,
    pub ingress: Ingress,
    pub owner: String,
    pub call_id: String,
    /// The resolved presenting virtual key (audience-checked key chain), or `None` ungoverned. The
    /// hook gate reads its `(id, name)`; the Meter step lands each turn's usage on this key's ledger.
    pub vkey: Option<busbar_api::VirtualKey>,
    pub body: Bytes,
    pub headers: axum::http::HeaderMap,
    pub now: u64,
}

/// THE SHARED GOVERNED OPEN every voice route funnels through — the ONE choke point. In order:
///
/// 1. **hooks-gate** (`host.gate_decide`) — the operator's request-admission gate over the session-open
///    params. A `Reject` refuses BEFORE any lease/mint/dial. BYTE-IDENTICAL (nothing serialized, no
///    blocking hop) when no gate is attached — the `gate_attached` presence pre-filter.
/// 2. **hooks-tap** (`host.transform_over`) — a `prompt: rw` rewrite over the same params, AFTER the
///    gate and BEFORE the credential is leased. A committed rewrite REPLACES the locked session params
///    the mint/dial then carries; an abstaining chain (or no attached rewrite) leaves them
///    byte-identical.
/// 3. **the governed open** — [`crate::topology::begin_session`] /
///    [`crate::topology::telephony::begin_telephony`] runs `run_gauntlet_session`
///    (verify-strictly-before-charge): a denied destination refuses `403` before any lease/durable open.
/// 4. **the serving leg** — for `Mint`, the `ek_` is minted through [`HttpsTokenMinter`] over the
///    configured provider and returned as JSON; for `Sdp`, the offer is brokered upstream, the
///    `rtc_<call_id>` correlation key is stamped onto the durable row, and the answer + `Location`
///    header are returned. The `Sideband` / `Telephony` WS-accept legs answer `501` — the inbound
///    WS-accept seam lands separately.
///
/// The front-door request is COUNTED on `busbar_plane_requests_total` (plane = voice), and the answer
/// carries a [`Counted`] marker so the core `plane::observe` middleware stands down (no double count).
pub(crate) async fn open_governed(req: GovernedOpen<'_>) -> axum::response::Response {
    let GovernedOpen {
        rt,
        host,
        provider,
        ingress,
        owner,
        call_id,
        vkey,
        body,
        headers,
        now,
    } = req;
    // (0) AUTHORIZATION — may this key open a session here at all? Asked FIRST, of the caller's own
    // grant, so a key that is valid for this plane's audience but was never granted session scope is
    // refused before any hook fires, any lease is reserved, any durable row exists or any provider is
    // dialed. An ungoverned deployment resolves no key and has no grant to consult, so it proceeds
    // exactly as it did before — the refusal is a narrowing of governed callers only.
    if let Some(k) = vkey.as_ref() {
        if !session_scope_allowed(k) {
            return finish(session_scope_refusal());
        }
    }
    // The `(id, name)` the hook gate reads — derived from the resolved key (or `None` ungoverned).
    let key = vkey.as_ref().map(|k| (k.id.clone(), k.name.clone()));
    // THE METER STEP's attribution: land each turn's usage on the presenting key's ledger through the
    // core seam (the same seam every plane meters through). `None` ungoverned — nothing to attribute.
    let meter = vkey.as_ref().map(|k| {
        crate::runtime::metering::TurnMeter::new(
            Arc::clone(&host),
            k.clone(),
            FRONT_DOOR_POOL,
            crate::OPENAI_REALTIME,
        )
    });
    // THE MONEY HOP, bound to the LIVE host: a served session reserves and settles against the host's
    // own cost lease, not an in-process cell. The ceiling is the presenting key's REAL budget chain —
    // the tightest remaining bucket — so an exhausted caller is denied at the reserve and a live
    // session hard-closes the moment its settles reach that ceiling. An unbudgeted (or ungoverned)
    // caller has no ceiling to impose, and stays uncapped exactly as an unbudgeted model call is.
    let hosted = crate::runtime::build_runtime_hosted(rt, Arc::clone(&host));
    let rt = &hosted;
    let budget = SessionBudget {
        estimate_nanos: SESSION_ESTIMATE_NANOS,
        fee_nanos: 0,
        cap_nanos: crate::runtime::principal_cap_nanos(&host, vkey.as_ref(), now),
    };
    // The session-open params the hooks screen and (maybe) rewrite: the g711 lock for telephony, the
    // plane-default session posture otherwise. One projection both the gate and the tap read.
    let mut session_cfg = match ingress {
        Ingress::Telephony => g711_config(),
        Ingress::Mint | Ingress::Sdp | Ingress::Sideband | Ingress::Gemini => {
            rt.session_defaults.clone()
        }
    };

    // (1) HOOKS-GATE — refuse before any lease/mint/dial. Zero-cost / byte-identical when unattached.
    if let Err(refused) = hook_gate(&host, key.clone(), &call_id, now, &session_cfg).await {
        return finish(*refused);
    }
    // (2) HOOKS-TAP — rewrite the session-open params before the credential is leased. Byte-identical
    // (params untouched) when no rewrite hook is attached or the chain abstains.
    match hook_tap(&host, key, &call_id, now, &session_cfg).await {
        Ok(Some(rewritten)) => session_cfg = rewritten,
        Ok(None) => {}
        Err(refused) => return finish(*refused),
    }

    // (3) THE GOVERNED OPEN. Telephony has no durable handle to correlate; the sideband topologies keep
    // the handle so the SDP broker can stamp the `rtc_<call_id>` onto the row. `Gemini` never reaches
    // this fn today (no HTTP one-shot route dispatches it — only the WS-accept seam does, see
    // `ws_accept`); the arm exists only so this match stays exhaustive over `Ingress`.
    let resp = match ingress {
        Ingress::Telephony => match begin_telephony(
            rt,
            OpenAiRealtimeCodec,
            owner,
            call_id,
            session_cfg,
            budget,
            meter,
            now,
        ) {
            Ok(_proxy) => sideband_pending(),
            Err(e) => start_refusal(&e),
        },
        Ingress::Gemini => sideband_pending(),
        Ingress::Mint | Ingress::Sdp | Ingress::Sideband => match begin_session(
            rt,
            OpenAiRealtimeCodec,
            owner,
            call_id,
            Some(session_cfg.clone()),
            Carrier::sideband(),
            budget,
            meter,
            now,
        ) {
            // (4) THE SERVING LEG, past a clean governed open.
            Ok((_core, handle, _guard)) => match ingress {
                Ingress::Mint => serve_mint(provider, handle.owner(), &session_cfg).await,
                Ingress::Sdp => serve_sdp(provider, &headers, body, &handle, now).await,
                // The inbound WS-accept seam (browser sideband) lands separately — no bare on_upgrade.
                _ => sideband_pending(),
            },
            Err(e) => start_refusal(&e),
        },
    };
    finish(resp)
}

/// EMIT the front-door session-open count and MARK the answer counted. The plane-labelled counter
/// (`plane = voice`, the voice-server cell) lands on the neutral `busbar_plane_requests_total` family;
/// the [`Counted`] marker on the response tells the core `plane::observe` middleware this request was
/// already counted, so the front-door series is never double-counted at the boundary.
fn finish(mut resp: axum::response::Response) -> axum::response::Response {
    let outcome = busbar_substrate::telemetry::outcome_of(resp.status().as_u16());
    metrics::counter!(
        PLANE_REQUESTS_TOTAL,
        "plane" => "voice",
        "ingress_protocol" => crate::OPENAI_REALTIME,
        "pool" => FRONT_DOOR_POOL,
        "outcome" => outcome,
    )
    .increment(1);
    resp.extensions_mut().insert(Counted);
    resp
}

/// The hooks-GATE leg (`host.gate_decide`) over the session-open params. `Ok(())` proceeds; `Err` is a
/// finished refusal. ZERO-COST / BYTE-IDENTICAL when no gate is attached: the `gate_attached` presence
/// pre-filter short-circuits before any serialize or blocking hop.
async fn hook_gate(
    host: &Arc<dyn EngineHost>,
    key: Option<(String, String)>,
    session_id: &str,
    now: u64,
    cfg: &SessionConfig,
) -> Result<(), Box<axum::response::Response>> {
    if !host.gate_attached(crate::PLANE_DECL.key, GATE_CONTAINER) {
        return Ok(());
    }
    // Serialized ONCE for the seam (only past the presence check). The host re-selects the gate set by
    // `(plane_key, container)` and runs the same decision — the Seam-B inversion, so this plane body
    // names no core hook symbol. Driven on a blocking thread (the host runs the async gate on a fresh
    // runtime), so it MUST NOT run on a worker.
    let args_json = serde_json::to_vec(cfg).unwrap_or_default();
    let sid = session_id.to_string();
    let host = Arc::clone(host);
    let outcome = tokio::task::spawn_blocking(move || {
        host.gate_decide(
            crate::PLANE_DECL.key,
            GATE_CONTAINER,
            now,
            SESSION_OPEN_METHOD,
            &args_json,
            key.as_ref().map(|(id, name)| (id.as_str(), name.as_str())),
            (!sid.is_empty()).then_some(sid.as_str()),
        )
    })
    .await
    .unwrap_or(GateOutcome::Reject {
        status: 403,
        message: String::new(),
        hook: String::new(),
    });
    match outcome {
        GateOutcome::Proceed => Ok(()),
        GateOutcome::Reject {
            status, message, ..
        } => Err(Box::new(hook_refusal(status, &message))),
    }
}

/// The hooks-TAP leg (`host.transform_over`) over the session-open params. `Ok(Some(cfg))` is a
/// committed rewrite the caller substitutes for the locked params; `Ok(None)` is "no change" (no
/// attached rewrite, or an abstaining chain — BYTE-IDENTICAL); `Err` is a rewrite-gate rejection.
async fn hook_tap(
    host: &Arc<dyn EngineHost>,
    key: Option<(String, String)>,
    session_id: &str,
    now: u64,
    cfg: &SessionConfig,
) -> Result<Option<SessionConfig>, Box<axum::response::Response>> {
    if !host.tap_attached(crate::PLANE_DECL.key, GATE_CONTAINER) {
        return Ok(None);
    }
    let args_json = serde_json::to_vec(cfg).unwrap_or_default();
    let sid = session_id.to_string();
    let host = Arc::clone(host);
    let verdict = tokio::task::spawn_blocking(move || {
        host.transform_over(
            crate::PLANE_DECL.key,
            GATE_CONTAINER,
            now,
            SESSION_OPEN_METHOD,
            &args_json,
            key.as_ref().map(|(id, name)| (id.as_str(), name.as_str())),
            (!sid.is_empty()).then_some(sid.as_str()),
        )
    })
    .await
    // A join panic is FAIL-SAFE on the transform path (the gate already admitted): proceed unchanged.
    .unwrap_or(TransformVerdict::Proceed {
        applied: false,
        args_json: Vec::new(),
    });
    match verdict {
        TransformVerdict::Proceed { applied, args_json } => {
            if applied {
                // A committed rewrite REPLACES the locked session params the mint/dial carries.
                if let Ok(v) = serde_json::from_slice::<SessionConfig>(&args_json) {
                    return Ok(Some(v));
                }
            }
            Ok(None)
        }
        TransformVerdict::Reject {
            status, message, ..
        } => Err(Box::new(hook_refusal(status, &message))),
    }
}

/// THE `ek_` MINT one-shot pass, past the governed open: mint through [`HttpsTokenMinter`] over the
/// configured provider (the real key held server-side) and return the browser-facing `ek_` as JSON.
/// `None` provider ⇒ `501` (governed, but no provider credential composed).
async fn serve_mint(
    provider: Option<&ProviderEndpoint>,
    owner: &str,
    cfg: &SessionConfig,
) -> axum::response::Response {
    let Some(p) = provider else {
        return sideband_pending();
    };
    let minter = HttpsTokenMinter::new(egress_client(), &p.base_url, &p.api_key, owner, None);
    match minter.mint(cfg).await {
        Ok(token) => json_response(
            axum::http::StatusCode::OK,
            &serde_json::json!({
                "value": token.value,
                "expires_at_unix": token.expires_at_unix,
            }),
        ),
        Err(e) => text_response(
            axum::http::StatusCode::BAD_GATEWAY,
            format!("voice ephemeral-secret mint failed: {e}"),
        ),
    }
}

/// THE SDP BROKER one-shot pass, past the governed open: broker the browser's `application/sdp` offer
/// to the provider's `POST /v1/realtime/calls` under BUSBAR'S OWN provider credential (busbar brokers
/// the call server-side), PRESERVE the `Location: …/rtc_<call_id>` response header verbatim, STAMP that
/// `rtc_<call_id>` onto the durable session row (so busbar's governance and the brokered media call
/// name the SAME session), and return the SDP answer. `None` provider ⇒ `501`.
///
/// `_inbound` (the caller's request headers) is deliberately NOT read for egress: the inbound
/// `Authorization` is the caller's `RouteAuth::Key` GOVERNANCE bearer (the Auth plugin already consumed
/// it at the door), and forwarding it upstream would leak busbar's own authority to the provider. The
/// provider hop authenticates ONLY through [`crate::voice_provider_bearer`] — the same lane-constant
/// builder the `egress_auth_headers` decl and the `egress_tests` battery pin — never a caller token.
async fn serve_sdp(
    provider: Option<&ProviderEndpoint>,
    _inbound: &axum::http::HeaderMap,
    offer: Bytes,
    handle: &SessionHandle,
    now: u64,
) -> axum::response::Response {
    let Some(p) = provider else {
        return sideband_pending();
    };
    let uri = format!("{}/v1/realtime/calls", p.base_url.trim_end_matches('/'));
    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(&uri)
        .header(http::header::CONTENT_TYPE, "application/sdp");
    // Busbar's OWN provider credential — never the caller's inbound governance bearer.
    for (name, value) in crate::voice_provider_bearer(&p.api_key) {
        builder = builder.header(name, value);
    }
    let req = match builder.body(Full::new(offer)) {
        Ok(r) => r,
        Err(e) => {
            return text_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("voice SDP request did not build: {e}"),
            )
        }
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let resp = match send_bounded(&egress_client(), req, deadline).await {
        Ok(r) => r,
        Err(e) => {
            return text_response(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("voice SDP broker upstream failed: {}", e.into_cause()),
            )
        }
    };
    let status = resp.status();
    // PRESERVE the `Location` header verbatim, and derive the `rtc_<call_id>` correlation key from it.
    let location = resp.headers().get(http::header::LOCATION).cloned();
    let answer = match tokio::time::timeout_at(deadline, resp.into_body().collect()).await {
        Ok(Ok(b)) => b.to_bytes(),
        _ => {
            return text_response(
                axum::http::StatusCode::BAD_GATEWAY,
                "voice SDP answer was not read before the deadline".to_string(),
            )
        }
    };
    // STAMP the correlation key onto the durable row (owner-gated) — broker → row, the single key that
    // ties governance here to the media that flows there. A mismatch/absence is left unstamped.
    if let Some(rtc) = location
        .as_ref()
        .and_then(|v| v.to_str().ok())
        .and_then(rtc_call_id_of)
    {
        let _ = handle.set_rtc_call_id(&rtc, now);
    }
    let mut builder = axum::response::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/sdp");
    if let Some(loc) = location {
        builder = builder.header(http::header::LOCATION, loc);
    }
    builder
        .body(axum::body::Body::from(answer))
        .unwrap_or_else(|_| sideband_pending())
}

/// The last `rtc_<call_id>` path segment of a brokered call's `Location` header — the correlation key
/// the SDP broker stamps onto the durable row. `None` when no segment carries the `rtc_` prefix.
fn rtc_call_id_of(location: &str) -> Option<String> {
    location
        .rsplit('/')
        .find(|seg| seg.starts_with("rtc_"))
        .map(|seg| seg.split(['?', '#']).next().unwrap_or(seg).to_string())
}

/// The substrate egress client the one-shot HTTPS passes dial through (the same posture the concrete
/// minter uses). Built per pass; the composition root pools one once the provider config is threaded.
fn egress_client() -> EngineClient {
    busbar_substrate::proxy::build_egress_client(
        &busbar_substrate::egress::engine::EngineSpec::pooled_webpki(4, 300, false, false),
    )
}

/// A GOVERNED-BUT-UNCOMPOSED answer for a WS-accept leg (browser sideband / telephony media): the
/// session opened and was governed, but the inbound WS-accept seam that upgrades the socket lands
/// separately, so no bare `on_upgrade` is taken here.
fn sideband_pending() -> axum::response::Response {
    refusal(
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "voice session governed-open succeeded; the inbound WS-accept seam that upgrades the browser \
         sideband / telephony media socket lands separately",
    )
}

/// The finished refusal for a `begin_session` / `begin_telephony` [`StartError`] — verify-before-charge
/// at the route layer (a denied destination is `403` with zero charge).
fn start_refusal(e: &StartError) -> axum::response::Response {
    match e {
        StartError::DestinationRefused => refusal(
            axum::http::StatusCode::FORBIDDEN,
            "voice session destination refused at the open-pass gate (fail closed)",
        ),
        StartError::BudgetRefused => refusal(
            axum::http::StatusCode::PAYMENT_REQUIRED,
            "voice session budget refused (fail closed)",
        ),
        StartError::Durable(_) => refusal(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "voice session durable open failed",
        ),
    }
}

/// A finished plain-text response — the shape both a governed-but-uncomposed answer and a fail-closed
/// refusal are framed in, so a handler names no `IntoResponse` machinery.
fn refusal(status: axum::http::StatusCode, msg: &'static str) -> axum::response::Response {
    axum::response::Response::builder()
        .status(status)
        .body(axum::body::Body::from(msg))
        .expect("a static-body response always builds")
}

/// A finished plain-text response over an OWNED body (a hook's own message, an upstream failure cause).
fn text_response(status: axum::http::StatusCode, msg: String) -> axum::response::Response {
    axum::response::Response::builder()
        .status(status)
        .body(axum::body::Body::from(msg))
        .expect("a text-body response always builds")
}

/// A finished JSON response (the minted `ek_` payload).
fn json_response(
    status: axum::http::StatusCode,
    body: &serde_json::Value,
) -> axum::response::Response {
    axum::response::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(body).unwrap_or_default(),
        ))
        .expect("a json-body response always builds")
}

/// A hook's OWN refusal, framed with its status (clamped to a valid code) and message — the shape both
/// the gate and the rewrite-gate reject in.
fn hook_refusal(status: u16, message: &str) -> axum::response::Response {
    let status =
        axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::FORBIDDEN);
    text_response(
        status,
        if message.is_empty() {
            "voice session-open refused by a hook gate".to_string()
        } else {
            message.to_string()
        },
    )
}

/// Read the voice dispatch slot off the neutral `PlaneReqCtx::slot`, resolve the caller + a session id,
/// and drive the shared governed open. `slot` is the SAME `VoiceMount` `build` erased (the mount is
/// what creates the route), so the downcast never fails on a mounted route; the `Option` survives only
/// so a future refactor that mounted the route without the slot answers `500` rather than panicking.
async fn serve(
    ctx: busbar_substrate::plane_routes::PlaneReqCtx,
    ingress: Ingress,
) -> axum::response::Response {
    let Some(mount) = ctx.slot.downcast_ref::<VoiceMount>() else {
        return refusal(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "voice route reached without its dispatch slot",
        );
    };
    // The resolved caller the audience-checked key chain attached (the session owner), or the honest
    // constant on an ungoverned deployment — the SAME asymmetry the MCP notification principal reads.
    let owner = ctx
        .caller_principal
        .clone()
        .unwrap_or_else(|| "<ungoverned>".to_string());
    // The `{call_id}` capture for a WS accept, or a fresh id for a one-shot mint/SDP pass.
    let call_id = ctx
        .path_params
        .iter()
        .find(|(k, _)| k == "call_id")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| format!("voice-{}", unix_secs()));
    // The resolved presenting virtual key (the middleware-resolved, audience-checked key), or `None`
    // ungoverned. The hook gate reads its `(id, name)`; the Meter step lands usage on its ledger.
    let vkey = ctx.gov.as_ref().and_then(|g| g.key()).cloned();
    open_governed(GovernedOpen {
        rt: &mount.runtime,
        host: Arc::clone(&ctx.host),
        provider: mount.provider(),
        ingress,
        owner,
        call_id,
        vkey,
        body: ctx.body.clone(),
        headers: ctx.headers.clone(),
        now: unix_secs(),
    })
    .await
}

/// Wall-clock unix seconds for the session's `charged_at` / genesis stamp. The gauntlet clock the
/// production pump reads off the host is threaded once the composition root wires it; the structural
/// mount stamps the process clock.
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn mint_route(ctx: busbar_substrate::plane_routes::PlaneReqCtx) -> axum::response::Response {
    serve(ctx, Ingress::Mint).await
}
async fn sdp_route(ctx: busbar_substrate::plane_routes::PlaneReqCtx) -> axum::response::Response {
    serve(ctx, Ingress::Sdp).await
}
/// THE PROVIDER SIDE OF A WS DIAL — the origin, converted to `ws(s)://`, plus the fixed path the
/// dialect's realtime endpoint answers on. `api_key` rides in the URL for the ONE dialect whose native
/// scheme allows it (Gemini's documented `?key=` query form); OpenAI Realtime's native scheme is a
/// header (`Authorization: Bearer`) the neutral WS dialer (`busbar_substrate::egress::duplex_ws::dial`,
/// a `tokio_tungstenite::client_async` call with no custom-header hook) cannot carry today — a known,
/// stated limit of the shared dialer, not something this plane's dial call papers over. A loopback test
/// provider (this plane's own conformance harness) does not check either scheme, so the wiring proves
/// out end to end even though a real OpenAI dial would still need the dialer's header hook to land.
fn provider_ws_url(base_url: &str, dialect: &str, api_key: &str) -> String {
    let ws = base_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    let ws = ws.trim_end_matches('/');
    if dialect == crate::GEMINI_LIVE {
        format!(
            "{ws}/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent?key={api_key}"
        )
    } else {
        format!("{ws}/v1/realtime")
    }
}

/// THE INBOUND WS-ACCEPT FN for the browser-sideband / telephony / Gemini-Live media legs — what
/// replaces the `501` stub, moving the WS legs onto the neutral inbound WS-accept seam. Generic over
/// the dialect `codec` (K4): [`voice_ws_arrivals`] instantiates it once per dialect
/// ([`OpenAiRealtimeCodec`] for the sideband/telephony legs, [`GeminiLiveCodec`] for the Gemini leg) so
/// every leg runs the SAME choke point rather than a per-dialect copy. It builds the `GauntletRequest`
/// and [`SessionGauntlet`] EXACTLY as [`begin_session`] does (gov threaded from the audience-checked
/// auth layer, `destination` = the locked upstream model) and hands the upgrade to [`accept_gauntlet`]
/// — the ONLY path that consumes the upgrade into a live socket, and never a bare `on_upgrade`.
///
/// GAUNTLET-BEFORE-UPGRADE: `accept_gauntlet` runs `run_gauntlet_session` SYNCHRONOUSLY and, on a
/// refused destination, returns the gate's own `403` WITHOUT upgrading a socket, spawning a task, or
/// opening a durable row. Only on admit is the socket upgraded and `on_socket` spawned.
///
/// VERIFY-BEFORE-CHARGE, NO ORPHANED ROW: the D2 lease reserve + durable session open happen INSIDE
/// `on_socket` — AFTER the gauntlet admitted and BEFORE the pump reads a byte — through the gauntlet-
/// free [`open_admitted_session`] / [`open_admitted_telephony`] (the gauntlet already ran; re-running
/// it would double the gate). A refused accept opens nothing; a post-admit budget/durable refusal
/// commits no durable row and simply closes the just-upgraded socket. So no refused-or-aborted accept
/// ever leaves a live session row.
///
/// THE PROVIDER DIAL (K5): for `Telephony` and `Gemini`, when the ingress's dialect has a COMPOSED
/// provider, the leg opens a [`crate::topology::telephony::TelephonyProxy`] (the same thin-duplex
/// shape for both) and dials the provider through [`dial_provider`] — the net-guarded, breaker-admitted
/// path — before pumping either socket. A dial failure drops the just-admitted session (the proxy's
/// lease-close guard closes the reserve on drop) rather than serving a client socket with nowhere to
/// relay to. With NO provider composed, both legs fall back to serving the client socket only (the
/// documented "governed but not yet dialing" posture) exactly as before.
pub(crate) async fn ws_accept<C>(
    arrival: WsArrival,
    ingress: Ingress,
    codec: C,
) -> axum::response::Response
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
{
    let Some(mount) = arrival.slot.downcast_ref::<VoiceMount>() else {
        return refusal(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "voice WS-accept reached without its dispatch slot",
        );
    };
    // The dialect this leg speaks — the `ingress_protocol` label + the composed-provider table a
    // `Telephony`/`Gemini` dial reads from. Every other leg (Sideband) stays OpenAI-labelled: it has no
    // Gemini analogue today.
    let dialect = match ingress {
        Ingress::Gemini => crate::GEMINI_LIVE,
        _ => crate::OPENAI_REALTIME,
    };
    // The neutral host seam the operator hooks fire through — the SAME seam the one-shot passes read in
    // `open_governed`, so the WS-accept front door screens a session-open identically to mint/SDP.
    let host = Arc::clone(&arrival.host);
    // The presenting key, resolved once: the authorization gate, the hook projection, the budget
    // ceiling and the turn attribution all read it.
    let vkey = arrival.gov.as_ref().and_then(|g| g.key()).cloned();
    // (0) AUTHORIZATION, before the upgrade — a key that holds no session scope on this pool is refused
    // with the plane's own answer and no socket is bound, exactly as the one-shot passes refuse.
    if let Some(k) = vkey.as_ref() {
        if !session_scope_allowed(k) {
            return session_scope_refusal();
        }
    }
    // The per-generation runtime, its money hop rebound onto the live host lease so this session
    // reserves and settles against the caller's real grant rather than an in-process cell.
    let rt = Arc::new(crate::runtime::build_runtime_hosted(
        &mount.runtime,
        Arc::clone(&host),
    ));
    // The caller `(id, name)` the hook gate/tap read — the middleware-resolved key, or `None` ungoverned.
    let key = vkey.as_ref().map(|k| (k.id.clone(), k.name.clone()));
    // The resolved caller the audience-checked key chain attached (the session owner), or the honest
    // constant on an ungoverned deployment.
    let owner = arrival
        .caller_principal
        .clone()
        .unwrap_or_else(|| "<ungoverned>".to_string());
    // The `{call_id}` capture the accept route matched.
    let call_id = arrival
        .path_params
        .iter()
        .find(|(k, _)| k == "call_id")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| format!("voice-{}", unix_secs()));
    let now = unix_secs();
    // The locked session posture: g711 for telephony, the plane-default otherwise (including Gemini —
    // the Gemini leg carries no media-format lock of its own). The destination the gauntlet judges is
    // this config's model, exactly as `begin_session` derives it.
    let mut session_cfg = match ingress {
        Ingress::Telephony => g711_config(),
        _ => rt.session_defaults.clone(),
    };
    // (1) HOOKS-GATE — a rejecting operator gate refuses the session-open BEFORE the upgrade: a
    // pre-upgrade refusal Response, no socket bound, no lease/durable open. This closes the intra-plane
    // gap where telephony (which has no preceding `ek_` mint pass) reached the media leg screened by
    // nothing but the destination gauntlet; both WS legs now honor the operator gate exactly as the
    // one-shot mint/SDP passes do in `open_governed`.
    if let Err(refused) = hook_gate(&host, key.clone(), &call_id, now, &session_cfg).await {
        return *refused;
    }
    // (2) HOOKS-TAP — a committed rewrite replaces the locked session posture BEFORE the gauntlet judges
    // the destination and BEFORE the socket binds; byte-identical when no rewrite hook is attached.
    match hook_tap(&host, key, &call_id, now, &session_cfg).await {
        Ok(Some(rewritten)) => session_cfg = rewritten,
        Ok(None) => {}
        Err(refused) => return *refused,
    }
    let destination = session_cfg.model.clone().unwrap_or_default();
    let gov = arrival.gov.clone().unwrap_or_default();
    let gauntlet_req = GauntletRequest {
        gov: &gov,
        destination: &destination,
        correlation_id: 0,
        charged_at: now,
        started: std::time::Instant::now(),
    };
    let gate: Box<dyn GauntletPlane> = Box::new(SessionGauntlet {
        deny: rt.destination_denied(&destination),
    });
    // The session budget: the coarse over-estimate at reserve, no flat fee, and the presenting key's
    // REAL remaining budget as the ceiling — the SAME shape `open_governed` uses for the one-shot
    // passes, so both doors meter a session identically.
    let budget = SessionBudget {
        estimate_nanos: SESSION_ESTIMATE_NANOS,
        fee_nanos: 0,
        cap_nanos: crate::runtime::principal_cap_nanos(&host, vkey.as_ref(), now),
    };
    // THE METER STEP's attribution for this WS session — the presenting key each turn's usage is
    // landed on through the core seam, under THIS LEG'S OWN dialect label (K4: no longer a plane-wide
    // constant). Built from the resolved key (or `None` ungoverned) and moved into the post-upgrade
    // open below, exactly as `open_governed` does for the one-shot passes.
    let meter = vkey.clone().map(|k| {
        crate::runtime::metering::TurnMeter::new(Arc::clone(&host), k, FRONT_DOOR_POOL, dialect)
    });
    // The composed provider FOR THIS LEG'S DIALECT — read off the PROCESS-WIDE composed statics
    // directly (not `mount.provider()`/`mount.gemini_provider()`, whose per-slot override is borrowed
    // from `mount` and so cannot outlive it) so the `'static` `on_socket` closure below captures a
    // plain `Option<&'static ProviderEndpoint>` rather than a reference into the (non-'static) `arrival`
    // this fn is about to move out of.
    let provider = match ingress {
        Ingress::Gemini => composed_gemini_provider(),
        _ => composed_provider(),
    };
    accept_gauntlet(
        arrival.upgrade,
        gauntlet_req,
        gate,
        move |stream, sink| async move {
            match ingress {
                // TELEPHONY / GEMINI: a thin duplex proxy. With a composed provider, dial it and pump
                // both sockets through `TelephonyProxy::run` (K5); with none, fall back to serving the
                // client socket only (the documented "governed but not dialing" posture).
                Ingress::Telephony | Ingress::Gemini => match provider {
                    Some(p) => match open_admitted_telephony(
                        &rt,
                        codec,
                        owner,
                        call_id,
                        session_cfg,
                        budget,
                        meter,
                        now,
                    ) {
                        Ok(proxy) => {
                            let pool = stream_breaker_key(dialect);
                            let url = provider_ws_url(&p.base_url, dialect, &p.api_key);
                            match dial_provider(host.as_ref(), &pool, 0, &url, GuardPolicy::default())
                                .await
                            {
                                Ok((provider_in, provider_out)) => {
                                    proxy.run(provider_in, provider_out, stream, sink).await;
                                }
                                Err(e) => {
                                    // The dial failed: nothing to relay client frames to. Drop the
                                    // proxy (its lease-close guard closes the D2 reserve, and its
                                    // durable handle's own drop path applies) rather than serve a
                                    // client socket with no upstream — fail closed, no orphaned row.
                                    tracing::warn!(
                                        error = %e,
                                        dialect,
                                        "voice: provider dial failed; the just-admitted session is \
                                         dropped rather than served with no upstream"
                                    );
                                }
                            }
                        }
                        Err(_) => { /* budget/durable refusal: no durable row, socket closes */ }
                    },
                    // NO PROVIDER COMPOSED: serve the client socket only. The uplink plane forwards
                    // client→server frames to a channel whose receiver is DROPPED (bare `_`, not a
                    // named binding), so `unbounded_send` fails fast via `is_disconnected` and each
                    // frame is discarded with ZERO buffering — client uplink is decoded + metered with
                    // no upstream to funnel to, and no unbounded queue grows for the session's life.
                    None => {
                        if let Ok((core, _handle, _guard)) = open_admitted_session(
                            &rt,
                            codec,
                            owner,
                            call_id,
                            Some(session_cfg),
                            Carrier::sideband(),
                            budget,
                            meter,
                            now,
                        ) {
                            let (upstream_tx, _) = futures::channel::mpsc::unbounded::<Vec<u8>>();
                            serve_messages(
                                stream,
                                sink,
                                Arc::new(UplinkForwarder::new(core, upstream_tx)),
                            )
                            .await;
                        }
                    }
                },
                // BROWSER-WEBRTC SIDEBAND: media is peer-to-peer by design (see `crate::topology::webrtc`
                // docs) — this socket is control-only, so there is no provider leg to dial here.
                Ingress::Sideband => {
                    if let Ok((core, _handle, _guard)) = open_admitted_session(
                        &rt,
                        codec,
                        owner,
                        call_id,
                        Some(session_cfg),
                        Carrier::sideband(),
                        budget,
                        meter,
                        now,
                    ) {
                        serve_messages(stream, sink, Arc::new(VoiceSession::new(core))).await;
                    }
                }
                Ingress::Mint | Ingress::Sdp => {
                    // Never reached: the WS-accept seam mounts only Sideband/Telephony/Gemini (see
                    // `voice_ws_arrivals`); Mint/Sdp are the one-shot HTTP passes (`voice_routes`).
                }
            }
        },
    )
}

#[cfg(test)]
#[path = "tests/mount_tests.rs"]
mod mount_tests;

// The egress-credential cell reads only `DECLS` — no host, no live money hop.
#[cfg(test)]
#[path = "tests/egress_tests.rs"]
mod egress_tests;

// The remaining cells drive a real `EngineHost` double (breaker cell store / hook gate maps / the
// process-global metrics recorder) or a loopback provider, so they gate on `test-support`.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/breaker_tests.rs"]
mod breaker_tests;
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/hook_gate_tests.rs"]
mod hook_gate_tests;
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/hook_tap_tests.rs"]
mod hook_tap_tests;
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/metrics_tests.rs"]
mod metrics_tests;
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/sdp_tests.rs"]
mod sdp_tests;

// THE THREE COMPOSITION-ROOT CELLS: the provider credential the mint pass serves under, the real
// per-key metering lease a session reserves on, and the session-scope grant the door enforces. All
// three drive a real `EngineHost` double (and, for the mint, a loopback provider), so they gate on
// `test-support` exactly as the cells above do.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/metering_lease_tests.rs"]
mod metering_lease_tests;
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/mint_tests.rs"]
mod mint_tests;
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/scope_gate_tests.rs"]
mod scope_gate_tests;

// AUDIT-CHAIN + GOVERNANCE-BUDGET capability cells, re-homed to a gate-valid `/tests/` path (the
// equality gate rejects `runtime/tests.rs`). Runtime-gated so the durable engine / D2 lease compile;
// no `test-support` needed — they drive the durable session chain and the host metering lease only.
#[cfg(all(test, feature = "runtime"))]
#[path = "tests/audit_chain_tests.rs"]
mod audit_chain_tests;
#[cfg(all(test, feature = "runtime"))]
#[path = "tests/governance_budget_tests.rs"]
mod governance_budget_tests;

// BEHAVIORAL billing proof: drive a voice turn's usage through the SHIPPED Meter seam over a REAL
// governed `App` host and read the spend back off the one ledger (`GovState::usage_for`) — the
// ledger-level twin of the LLM plane's crossproto_delivery_billing oracle. Needs `test-support` for
// the real `App`/`engine_host` and `runtime` for the session metering types.
#[cfg(all(test, feature = "runtime", feature = "test-support"))]
#[path = "tests/billing_ledger_tests.rs"]
mod billing_ledger_tests;
