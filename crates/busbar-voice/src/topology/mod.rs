// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO TOPOLOGIES the voice runtime exposes (design `plane4-duplex-session.md` §5-6), behind the `runtime` feature.
//!
//! * [`webrtc`] — the BROWSER WebRTC sideband: busbar mints the ephemeral token and holds a persistent
//!   sideband control channel owning tools + instructions; the browser's MEDIA path is peer-to-peer, so
//!   busbar is mint/guard + control, NOT a media relay.
//! * [`telephony`] — a THIN WS PROXY: `g711_ulaw` end-to-end so 8 kHz passes straight through (no
//!   resample), with barge-in truncate driven from the codec's playback marks.
//!
//! Both are assembled from a [`crate::runtime::VoiceRuntime`] via [`begin_session`], which opens the D2
//! metering lease (fail-closed on a refused budget) and the durable [`SessionHandle`] before a frame
//! flows.

pub mod minter_https;
pub mod telephony;
pub mod twilio;
pub mod webrtc;

#[cfg(test)]
mod tests;

use crate::ir::codec::{DuplexReader, DuplexWriter};
use crate::ir::config::SessionConfig;
use crate::runtime::carrier::Carrier;
use crate::runtime::scope::SessionHandle;
use crate::runtime::session::SessionCore;
use crate::runtime::{LeaseCloseGuard, VoiceRuntime};
use busbar_substrate::egress::duplex_ws::{self, DialError};
use busbar_substrate::net_guard::GuardPolicy;
use busbar_substrate::plane::handle_engine::HandleEngineError;
use busbar_substrate::plane_host::{
    run_gauntlet_session, GauntletPlane, GauntletRequest, VerifyOutcome,
};
use busbar_substrate::transport::{Transport, UpstreamWireKind};
use futures::{Sink, Stream};
use std::sync::Arc;

/// DIAL THE PROVIDER SIDEBAND/UPSTREAM WSS through the neutral, net-guarded WS transport — the plane's
/// one door to an outbound duplex socket, and the close of the egress-audit finding that voice's
/// provider WSS never went through net-guard.
///
/// The plane SELECTS [`Transport::WebSocket`], resolves the axis to its neutral wire shape
/// ([`UpstreamWireKind::Duplex`]) and lets the SUBSTRATE open the socket: the dialer
/// resolves-then-pins-then-guards `url` and hands back the message `Stream`/`Sink<Vec<u8>>` pair the
/// session pump (`serve_messages`) consumes. The plane holds no socket, resolver or WS framing of its
/// own — it feeds the returned pair to a topology's provider leg
/// ([`telephony::TelephonyProxy::run`](crate::topology::telephony::TelephonyProxy::run) or the webrtc
/// sideband) and keeps ONLY data/session/media logic.
///
/// `policy` is the outbound trust posture (a public provider `wss://` takes the fail-closed
/// [`GuardPolicy::default`]); the guard NEVER opens a socket to a target it did not pin.
pub async fn dial_provider(
    url: &str,
    policy: GuardPolicy,
) -> Result<
    (
        impl Stream<Item = Vec<u8>> + Unpin,
        impl Sink<Vec<u8>> + Unpin + Send + 'static,
    ),
    DialError,
> {
    // The axis pins `WebSocket` to the full-duplex wire; the `else` is unreachable by construction (a
    // closed axis), expressed as a refusal rather than a panic so a mis-selection fails closed.
    let Some(UpstreamWireKind::Duplex) = Transport::WebSocket.upstream_wire() else {
        return Err(DialError::Url(url.to_string()));
    };
    duplex_ws::dial(url, policy).await
}

/// THE ALREADY-PRICED SESSION BUDGET handed across the D2 lease at session start (`plane4-duplex-session.md` §2.5): the coarse
/// over-`estimate` debited up front, the once-per-session flat `fee`, and the TRUE budget `cap`
/// exhaustion is judged against (`None` = uncapped, `Some(0)` = refuse-all). All nanodollars — the
/// plane priced them; core prices nothing.
#[derive(Debug, Clone, Copy)]
pub struct SessionBudget {
    /// The coarse over-estimate debited at reserve.
    pub estimate_nanos: u64,
    /// The once-per-session flat fee (`0` = none).
    pub fee_nanos: u64,
    /// The true budget ceiling (`None` = uncapped).
    pub cap_nanos: Option<u64>,
}

/// Why a session failed to start before any frame flowed.
#[derive(Debug)]
pub enum StartError {
    /// The OPEN-PASS gauntlet gate ([`run_gauntlet_session`]) REFUSED the session's destination BEFORE
    /// any lease/durable open — zero bytes, zero charge. The verify-strictly-before-charge invariant.
    DestinationRefused,
    /// The D2 metering lease REFUSED the reserve (a refuse-all / zero budget) — fail closed, never open.
    BudgetRefused,
    /// The durable [`SessionHandle`] could not be opened (the engine rejected the genesis).
    Durable(HandleEngineError),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::DestinationRefused => {
                write!(
                    f,
                    "voice session destination refused at the open-pass gate (fail closed)"
                )
            }
            StartError::BudgetRefused => write!(f, "voice session budget refused (fail closed)"),
            StartError::Durable(e) => write!(f, "voice session durable open failed: {e:?}"),
        }
    }
}

impl std::error::Error for StartError {}

/// THE VOICE PLANE's [`GauntletPlane`] for a SESSION open — its contribution to the shared open-pass
/// gauntlet gate. `verify_destination` (stage 2, the ONE shared pre-admission check) refuses a session
/// whose upstream `destination` (model) is on the plane's denial set, so the refusal lands BEFORE the
/// lease/durable open (zero bytes, zero charge). `drive` (the one-shot stages 4+5) is UNREACHABLE on the
/// session path — [`run_gauntlet_session`] only runs the gate, never `drive` — so it fails closed with a
/// neutral 500 if a future refactor ever mis-routed a session opener through the one-shot path.
struct SessionGauntlet {
    deny: bool,
}

#[async_trait::async_trait]
impl GauntletPlane for SessionGauntlet {
    fn verify_destination(&self, _req: &GauntletRequest<'_>) -> VerifyOutcome {
        if self.deny {
            VerifyOutcome::Refuse(
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .body(axum::body::Body::from("voice session destination denied"))
                    .expect("static refusal response builds"),
            )
        } else {
            VerifyOutcome::Proceed
        }
    }

    async fn drive(self: Box<Self>, _req: GauntletRequest<'_>) -> axum::response::Response {
        // Never reached on the session path (the opener runs only the admission gate). Fail closed.
        axum::response::Response::builder()
            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::from(
                "session gauntlet never drives a one-shot response",
            ))
            .expect("static fault response builds")
    }
}

/// BEGIN a governed session, common to both topologies: open the D2 metering lease (fail-closed on a
/// refused budget), open the durable [`SessionHandle`] at genesis, and assemble the [`SessionCore`]
/// with the plane's locked config, chosen `codec`, and `carrier`. The caller then serves the returned
/// core over the neutral pump.
///
/// Returns a BY-VALUE [`LeaseCloseGuard`] alongside the core: the topology's `run()` frame owns it so
/// the D2 lease is closed deterministically on any run() exit (incl. panic), independent of a parked
/// per-frame handler pinning `Arc<SessionCore>` (the hard-close-race leak the session-drop audit found).
#[allow(clippy::too_many_arguments)]
pub fn begin_session<C>(
    rt: &VoiceRuntime,
    codec: C,
    owner: impl Into<String>,
    call_id: impl Into<String>,
    locked_config: Option<SessionConfig>,
    carrier: Carrier,
    budget: SessionBudget,
    now: u64,
) -> Result<(Arc<SessionCore<C>>, SessionHandle, LeaseCloseGuard), StartError>
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
{
    // OPEN-PASS ADMISSION FIRST (verify STRICTLY before any charge): run the shared gauntlet gate at the
    // TOP through `run_gauntlet_session`. On refuse NOTHING is opened — no lease, no durable genesis, no
    // socket — so a refused session costs ZERO bytes and ZERO charge. The session's own charge
    // (`open_lease`, the cost_reserve leg) fires only AFTER the gate clears, matching the LLM plane's
    // real verify-before-admission-door order.
    let destination = locked_config
        .as_ref()
        .and_then(|c| c.model.clone())
        .unwrap_or_default();
    let gov = busbar_api::PlaneRequestCtx::default();
    let gauntlet_req = GauntletRequest {
        gov: &gov,
        destination: &destination,
        correlation_id: 0,
        charged_at: now,
        started: std::time::Instant::now(),
    };
    let plane: Box<dyn GauntletPlane> = Box::new(SessionGauntlet {
        deny: rt.destination_denied(&destination),
    });
    // The call-site the D3 witness pins: begin_session ACTUALLY calls run_gauntlet_session here.
    run_gauntlet_session(gauntlet_req, plane).map_err(|_refusal| StartError::DestinationRefused)?;

    // Only past the gate: the marquee guarantee's charge — no lease ⇒ no session (fail closed).
    let lease = rt
        .open_lease(budget.estimate_nanos, budget.fee_nanos, budget.cap_nanos)
        .ok_or(StartError::BudgetRefused)?;

    let handle = rt.bind_session(owner, call_id);
    handle.open(now).map_err(StartError::Durable)?;

    // Mint the by-value close guard from the lease BEFORE it moves into the core, so the topology owns a
    // handle that closes the reserve independent of the core's (possibly pinned) refcount.
    let guard = lease.close_guard();
    let core = Arc::new(SessionCore::new(
        codec,
        lease,
        Arc::clone(&rt.tools),
        carrier,
        locked_config,
    ));
    Ok((core, handle, guard))
}
