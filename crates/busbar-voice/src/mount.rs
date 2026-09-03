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
use crate::runtime::carrier::Carrier;
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use crate::topology::telephony::{begin_telephony, g711_config};
use crate::topology::{begin_session, SessionBudget, StartError};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane::registry::{BuildCtx, PlaneBootCtx};
use busbar_substrate::plane::PlaneAdmission;
use busbar_substrate::plane_routes::PlaneRouteSpec;
use std::any::Any;
use std::sync::Arc;

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

/// [`PlaneDecl::routes`] — the voice plane's four ingress routes, described NEUTRALLY (S4a Option A):
/// the `ek_` mint + SDP broker one-shot passes and the browser-sideband + telephony WS accepts, each a
/// thin neutral handler over `PlaneReqCtx`. All four are `RouteAuth::Key` — behind the plane's one
/// audience — so a token minted for another resource is refused at the door. Empty when the plane has
/// no receiving side (no dispatch slot), so a deployment that fronts nothing mounts nothing.
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
        PlaneRouteSpec {
            path: SIDEBAND_PATH.to_string(),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
            handler: Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(sideband_route(ctx))
            }),
        },
        PlaneRouteSpec {
            path: TELEPHONY_PATH.to_string(),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
            handler: Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(telephony_route(ctx))
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
}

/// THE SHARED GOVERNED OPEN every voice route funnels through — the ONE choke point that runs
/// `run_gauntlet_session` (verify-strictly-before-charge) via [`crate::topology::begin_session`] /
/// [`crate::topology::telephony::begin_telephony`]. On a destination the runtime denies the gate
/// REFUSES before any lease/durable open (zero bytes, zero charge) and this answers `403`. On a clean
/// open it answers `501`: the session was GOVERNED, but the live provider/media leg (the `ek_` mint,
/// the SDP broker, the provider WSS dial, the socket upgrade) is composed by the deployment behind the
/// plane's ports, not by this in-process structural mount. Synchronous — the gate is `verify` (sync)
/// and the session opener is sync — so a route handler awaits nothing to reach it.
pub(crate) fn open_governed(
    rt: &VoiceRuntime,
    ingress: Ingress,
    owner: String,
    call_id: String,
    now: u64,
) -> axum::response::Response {
    // A coarse structural budget: an over-estimate the in-process lease reserves, no flat fee, uncapped.
    let budget = SessionBudget {
        estimate_nanos: 1_000,
        fee_nanos: 0,
        cap_nanos: None,
    };
    let opened = match ingress {
        Ingress::Telephony => begin_telephony(
            rt,
            OpenAiRealtimeCodec,
            owner,
            call_id,
            g711_config(),
            budget,
            now,
        )
        .map(|_proxy| ()),
        Ingress::Mint | Ingress::Sdp | Ingress::Sideband => begin_session(
            rt,
            OpenAiRealtimeCodec,
            owner,
            call_id,
            Some(rt.session_defaults.clone()),
            Carrier::sideband(),
            budget,
            now,
        )
        .map(|_open| ()),
    };
    match opened {
        // GOVERNED, but the live serving leg is the deployment's to compose behind the plane's ports.
        Ok(()) => refusal(
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "voice session governed-open succeeded; the live provider/media leg (ek_ mint / SDP \
             broker / provider WSS) is composed by the deployment behind the plane's ports, not by \
             this in-process structural mount",
        ),
        // The open-pass gate refused the destination BEFORE any charge (verify-before-charge).
        Err(StartError::DestinationRefused) => refusal(
            axum::http::StatusCode::FORBIDDEN,
            "voice session destination refused at the open-pass gate (fail closed)",
        ),
        Err(StartError::BudgetRefused) => refusal(
            axum::http::StatusCode::PAYMENT_REQUIRED,
            "voice session budget refused (fail closed)",
        ),
        Err(StartError::Durable(_)) => refusal(
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
    open_governed(&mount.runtime, ingress, owner, call_id, unix_secs())
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
async fn sideband_route(
    ctx: busbar_substrate::plane_routes::PlaneReqCtx,
) -> axum::response::Response {
    serve(ctx, Ingress::Sideband).await
}
async fn telephony_route(
    ctx: busbar_substrate::plane_routes::PlaneReqCtx,
) -> axum::response::Response {
    serve(ctx, Ingress::Telephony).await
}

#[cfg(test)]
#[path = "tests/mount_tests.rs"]
mod mount_tests;
