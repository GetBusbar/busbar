// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VOICE PLANE'S DATA-ROUTE MOUNT (behind the `runtime` feature) — the structural surface that
//! turns `PLANE_DECL`'s `routes` / `claims` / `admission` / `build` hooks from `None`/empty into the
//! plane's real ingress door, WITHOUT any live-provider network call.
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
//! ## Structural, NOT live
//!
//! The four routes MOUNT, are AUDIENCE-CHECKED (`RouteAuth::Key`, under the plane's one audience) and,
//! on arrival, run the governed session-open through [`crate::topology::begin_session`] /
//! [`crate::topology::telephony::begin_telephony`] — which go through `run_gauntlet_session`
//! (verify-strictly-before-charge). The LIVE provider legs — the `ek_` ephemeral-secret mint, the SDP
//! broker's upstream `POST`, the provider WSS dial and the client socket upgrade — stay BEHIND their
//! ports (`TokenMinter`, the guarded WS transport); a deployment supplies the concrete implementations.
//! This mount proves the door is real and governed; it opens no socket and calls no provider.

use crate::ir::codec::OpenAiRealtimeCodec;
use crate::ir::config::SessionConfig;
use crate::runtime::carrier::Carrier;
use crate::runtime::scope::SessionHandle;
use crate::runtime::session::{UplinkForwarder, VoiceSession};
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use crate::topology::minter_https::HttpsTokenMinter;
use crate::topology::telephony::{begin_telephony, g711_config};
use crate::topology::webrtc::TokenMinter;
use crate::topology::{
    begin_session, open_admitted_session, SessionBudget, SessionGauntlet, StartError,
};
use busbar_substrate::egress::engine::{send_bounded, EngineClient};
use busbar_substrate::ingress::byte_duplex::serve_messages;
use busbar_substrate::ingress::duplex_ws::{accept_gauntlet, WsArrival, WsArrivalSpec};
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

/// THE HOOK CONTAINER the voice plane's session-open gate/tap fire under — the plane's SINGULAR config
/// section noun (`streams`), since voice declares no per-registration container (its config is one
/// object, not a named-definition map). The operator attaches a session-open gate to this ONE
/// container, and `gate_attached(plane_key, container)` reads it here.
const GATE_CONTAINER: &str = "streams";

/// A CONFIGURED PROVIDER ENDPOINT the one-shot mint / SDP-broker passes reach the realtime provider
/// through — the base origin plus the real server-side key. `None` on the dispatch slot until the
/// composition root threads the provider-credential config (the SAME follow-on the runtime money hop
/// documents); a loopback test injects one directly into [`open_governed`]. The real key stays
/// server-side: it authenticates only the busbar↔provider hop and never reaches a browser payload.
pub(crate) struct ProviderEndpoint {
    /// The provider origin (scheme + authority, e.g. `https://api.openai.com`).
    pub base_url: String,
    /// The REAL provider key, held server-side.
    pub api_key: String,
}

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

/// The RFC 9728 protected-resource metadata path for the voice resource (the `resource_metadata` a
/// refused caller is pointed at). Derived from `public_url` beside the audience; a deployment serves
/// the document itself (not one of the four mounted data routes).
const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/v1/realtime";

/// THE VOICE PLANE'S DISPATCH SLOT — the per-generation object `build` erases into `plane_slots` under
/// the decl key. Carries the plane's audience facts (derived from `public_url`) and a live runtime the
/// route handlers open governed sessions from.
pub struct VoiceMount {
    /// The RFC 8707 audience every inbound voice token must carry — `<public_url>/v1/realtime`.
    audience: String,
    /// The absolute RFC 9728 metadata URL quoted into a refused caller's `WWW-Authenticate` challenge.
    resource_metadata: String,
    /// The per-generation session runtime the four routes open governed sessions from. Built with the
    /// in-process [`LocalMeteringPort`] and the plane-default session posture: the HOSTED money hop
    /// (`build_runtime_hosted`) and the operator's `streams:` posture overlay are threaded by the
    /// composition root as a follow-on — the SAME gap `build_runtime_hosted` documents — so this
    /// structural mount reserves against an in-process cell and never a real caller grant.
    runtime: Arc<VoiceRuntime>,
    /// The configured realtime provider endpoint the one-shot mint / SDP-broker passes reach — `None`
    /// until the composition root threads the provider-credential config (the same follow-on the
    /// runtime money hop documents). While `None`, the mint / SDP routes answer `501` (governed, but
    /// no provider credential composed); a loopback test injects one directly into [`open_governed`].
    provider: Option<ProviderEndpoint>,
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
    tracing::info!(
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
        // The provider-credential config is the composition root's follow-on (see the field doc); until
        // it is threaded, the mint / SDP routes answer `501` — governed, but no provider composed.
        provider: None,
    };
    Some(Arc::new(mount))
}

/// The per-generation session runtime the dispatch slot carries. Binds the in-process
/// [`LocalMeteringPort`] and the plane-default session posture (see [`VoiceMount::runtime`]); the live
/// host money hop + the operator's `streams:` overlay are the composition root's follow-on.
fn dispatch_runtime() -> VoiceRuntime {
    VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
    )
}

/// [`PlaneDecl::claims`] — the ONE audience-checked region the voice plane answers on, spoken in its
/// first dialect. The base [`MOUNT_PATH`] covers all four routes by segment-boundary match, so every
/// `/v1/realtime/*` path a token is presented on is a path this plane claims (the R1 ratchet's
/// invariant: a path the plane answers on is a path it claims). Empty when the plane has no receiving
/// side (no dispatch slot), so it claims nothing exactly as it admits no one.
#[must_use]
pub fn voice_claims(slot: &dyn Any) -> Vec<(String, &'static str)> {
    match slot.downcast_ref::<VoiceMount>() {
        Some(_) => vec![(MOUNT_PATH.to_string(), crate::OPENAI_REALTIME)],
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
            accept: Arc::new(|a: WsArrival| ws_accept(a, Ingress::Sideband)),
        },
        WsArrivalSpec {
            path: TELEPHONY_PATH.to_string(),
            auth: RouteAuth::Key,
            slot_key: key,
            accept: Arc::new(|a: WsArrival| ws_accept(a, Ingress::Telephony)),
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
    pub key: Option<(String, String)>,
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
        key,
        body,
        headers,
        now,
    } = req;
    // A coarse structural budget: an over-estimate the in-process lease reserves, no flat fee, uncapped.
    let budget = SessionBudget {
        estimate_nanos: 1_000,
        fee_nanos: 0,
        cap_nanos: None,
    };
    // The session-open params the hooks screen and (maybe) rewrite: the g711 lock for telephony, the
    // plane-default session posture otherwise. One projection both the gate and the tap read.
    let mut session_cfg = match ingress {
        Ingress::Telephony => g711_config(),
        Ingress::Mint | Ingress::Sdp | Ingress::Sideband => rt.session_defaults.clone(),
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
    // the handle so the SDP broker can stamp the `rtc_<call_id>` onto the row.
    let resp = match ingress {
        Ingress::Telephony => match begin_telephony(
            rt,
            OpenAiRealtimeCodec,
            owner,
            call_id,
            session_cfg,
            budget,
            now,
        ) {
            Ok(_proxy) => sideband_pending(),
            Err(e) => start_refusal(&e),
        },
        Ingress::Mint | Ingress::Sdp | Ingress::Sideband => match begin_session(
            rt,
            OpenAiRealtimeCodec,
            owner,
            call_id,
            Some(session_cfg.clone()),
            Carrier::sideband(),
            budget,
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
    // The caller `(id, name)` the hook gate reads — the middleware-resolved key, or `None` ungoverned.
    let key = ctx
        .gov
        .as_ref()
        .and_then(|g| g.key())
        .map(|k| (k.id.clone(), k.name.clone()));
    open_governed(GovernedOpen {
        rt: &mount.runtime,
        host: Arc::clone(&ctx.host),
        provider: mount.provider.as_ref(),
        ingress,
        owner,
        call_id,
        key,
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
/// THE INBOUND WS-ACCEPT FN for the browser-sideband / telephony media legs — what replaces the `501`
/// stub, moving the WS legs onto the neutral inbound WS-accept seam. It builds the `GauntletRequest` +
/// [`SessionGauntlet`] EXACTLY as [`begin_session`] does (gov threaded from the audience-checked auth
/// layer, `destination` = the locked upstream model) and hands the upgrade to
/// [`accept_gauntlet`] — the ONLY path that consumes the upgrade into a live socket, and never a bare
/// `on_upgrade`.
///
/// GAUNTLET-BEFORE-UPGRADE: `accept_gauntlet` runs `run_gauntlet_session` SYNCHRONOUSLY and, on a
/// refused destination, returns the gate's own `403` WITHOUT upgrading a socket, spawning a task, or
/// opening a durable row. Only on admit is the socket upgraded and `on_socket` spawned.
///
/// VERIFY-BEFORE-CHARGE, NO ORPHANED ROW: the D2 lease reserve + durable session open happen INSIDE
/// `on_socket` — AFTER the gauntlet admitted and BEFORE the pump reads a byte — through the gauntlet-
/// free [`open_admitted_session`] (the gauntlet already ran; re-running it would double the gate). A
/// refused accept opens nothing; a post-admit budget/durable refusal commits no durable row and simply
/// closes the just-upgraded socket. So no refused-or-aborted accept ever leaves a live session row.
fn ws_accept(arrival: WsArrival, ingress: Ingress) -> axum::response::Response {
    let Some(mount) = arrival.slot.downcast_ref::<VoiceMount>() else {
        return refusal(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "voice WS-accept reached without its dispatch slot",
        );
    };
    // Clone the per-generation runtime (Arc bump) so the post-admit `on_socket` closure owns it.
    let rt = Arc::clone(&mount.runtime);
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
    // The locked session posture: g711 for telephony, the plane-default otherwise. The destination the
    // gauntlet judges is this config's model, exactly as `begin_session` derives it.
    let session_cfg = match ingress {
        Ingress::Telephony => g711_config(),
        _ => rt.session_defaults.clone(),
    };
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
    // The coarse structural budget the in-process lease reserves (over-estimate, no fee, uncapped) —
    // the SAME shape `open_governed` uses for the one-shot passes.
    let budget = SessionBudget {
        estimate_nanos: 1_000,
        fee_nanos: 0,
        cap_nanos: None,
    };
    accept_gauntlet(
        arrival.upgrade,
        gauntlet_req,
        gate,
        move |stream, sink| async move {
            // POST-ADMIT: reserve the lease + open the durable session NOW, before a byte is pumped.
            // The gauntlet already admitted the destination inside `accept_gauntlet`, so this opens with no
            // second gate. A budget/durable refusal commits no durable row and closes the socket.
            // Without a composed provider both legs pump only the CLIENT socket — the provider dial (the
            // telephony downlink relay / the sideband upstream) is the credential-gated tail behind the
            // plane's port. A sideband carrier relays no downlink here; a real provider composition swaps in
            // the media relay. The governed lease/durable open below is identical either way.
            let carrier = Carrier::sideband();
            // A budget/durable refusal (the `Err`) commits no durable row and simply drops the just-
            // upgraded socket — fail closed, no orphaned live session. Only a clean open pumps a byte.
            if let Ok((core, _handle, _guard)) = open_admitted_session(
                &rt,
                OpenAiRealtimeCodec,
                owner,
                call_id,
                Some(session_cfg),
                carrier,
                budget,
                now,
            ) {
                // Serve the CLIENT socket over the neutral pump with the leg's client-facing plane;
                // `_handle`/`_guard` drop at pump-end, closing the durable row + the D2 lease.
                match ingress {
                    Ingress::Telephony => {
                        // The uplink plane forwards client→server frames to the shared upstream sink;
                        // absent a composed provider the sink is drained (the receiver is dropped), so
                        // client uplink is decoded + metered with no upstream to funnel to.
                        let (upstream_tx, _drain) = futures::channel::mpsc::unbounded::<Vec<u8>>();
                        serve_messages(
                            stream,
                            sink,
                            Arc::new(UplinkForwarder::new(core, upstream_tx)),
                        )
                        .await;
                    }
                    _ => {
                        serve_messages(stream, sink, Arc::new(VoiceSession::new(core))).await;
                    }
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
