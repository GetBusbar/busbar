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
use busbar_substrate::breaker::{CanonicalSignal, StatusClass};
use busbar_substrate::egress::duplex_ws::{self, DialError};
use busbar_substrate::net_guard::GuardPolicy;
use busbar_substrate::plane::handle_engine::HandleEngineError;
use busbar_substrate::plane_host::{
    run_gauntlet_session, BreakerHost, DispatchScope, GauntletPlane, GauntletRequest, VerifyOutcome,
};
use busbar_substrate::transport::{Transport, UpstreamWireKind};
use futures::{Sink, Stream};
use std::sync::Arc;

/// THE VOICE PLANE'S BREAKER-CELL KEY for one provider dial target. The `stream:` prefix is the
/// plane-qualified keyspace rule (the `tool:` / `agent:` precedent — a voice cell can never collide
/// with an MCP tool cell, an A2A agent cell, or a bare LLM pool name), and the id is the operator's
/// provider/pool name that a refusal names. Formed HERE (not in the neutral substrate) so the voice
/// plane keys its own cell without a substrate helper and stays strong-form deletable.
#[must_use]
pub fn stream_breaker_key(provider: &str) -> String {
    format!("stream:{provider}")
}

/// Why a governed provider dial did not open a socket.
#[derive(Debug)]
pub enum DialProviderError {
    /// The `(pool, lane)` breaker cell was OPEN, so admission was refused BEFORE any socket — the
    /// fast-fail leg. Carries the honest `Retry-After` read off the cell's own cooldown.
    BreakerOpen {
        /// Seconds until the cell's cooldown expires (floored at 1).
        retry_after_secs: u64,
    },
    /// The dial itself failed (guard-refused / connect / TLS / handshake). The failure has already
    /// been recorded into the breaker cell.
    Dial(DialError),
}

impl std::fmt::Display for DialProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialProviderError::BreakerOpen { retry_after_secs } => write!(
                f,
                "voice provider dial refused: breaker open (retry after {retry_after_secs}s)"
            ),
            DialProviderError::Dial(e) => write!(f, "voice provider dial failed: {e:?}"),
        }
    }
}

impl std::error::Error for DialProviderError {}

/// The canonical breaker signal one [`DialError`] means. A target busbar's OWN net-guard or URL parse
/// refused is a DEFINITIVE (hard-down) failure — that configured/derived target can never be dialed
/// for this session, so its cell earns the sticky cooldown, exactly as an auth/billing hard-down does.
/// A connect / TLS / handshake failure to a pinned address is a TRANSIENT upstream signal (the cell
/// trips only once the error-rate window crosses its threshold), the same disposition the model
/// plane's own dispatch records a network blip under.
fn dial_signal(e: &DialError) -> CanonicalSignal {
    let class = match e {
        DialError::Guard(_) | DialError::Url(_) => StatusClass::Auth,
        DialError::Connect(_) | DialError::Tls(_) | DialError::Handshake(_) => StatusClass::Network,
    };
    CanonicalSignal {
        class,
        provider_signal: None,
        retry_after: None,
    }
}

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
///
/// THE BREAKER RIDES BENEATH THE DIAL (the voice-client cell): before any socket, the `(pool, lane)`
/// cell is probed through `host.breaker_admit` — an OPEN cell fast-fails in microseconds with the
/// cell's own `Retry-After` (never waiting out a dial timeout against a target already known down).
/// Past admission the attempt is counted on `busbar_upstream_attempts_total`, and the dial's outcome
/// is FOLDED back into the same cell: a clean open records a success (diluting the error window /
/// closing a recovery probe), a failure records its canonical signal (a guard/URL refusal opens the
/// cell hard-down; a connect/TLS/handshake blip is transient). `pool` is the plane's breaker-cell key
/// (see [`stream_breaker_key`]); `lane` is the member position (0 for a degenerate cell).
pub async fn dial_provider(
    host: &dyn BreakerHost,
    pool: &str,
    lane: usize,
    url: &str,
    policy: GuardPolicy,
) -> Result<
    (
        impl Stream<Item = Vec<u8>> + Unpin,
        impl Sink<Vec<u8>, Error = ()> + Unpin + Send + 'static,
    ),
    DialProviderError,
> {
    // FAST-FAIL ADMISSION FIRST: probe the cell through the host seam. An OPEN cell refuses here with
    // its own cooldown as `Retry-After` — no socket, no dial timeout. The probe is scoped so any
    // recovery probe it wins is released the instant this block ends; the in-place record below is the
    // authoritative fold, the documented `breaker_record_*` fallback disposition.
    {
        let scope = DispatchScope::new();
        if host
            .breaker_admit(&scope, pool.as_bytes(), lane as u32)
            .is_err()
        {
            return Err(DialProviderError::BreakerOpen {
                retry_after_secs: host.breaker_retry_after_secs(pool, lane),
            });
        }
    }

    // ADMITTED: count the dispatch attempt on the voice-client leg (both labels operator-configured
    // and bounded — a provider/pool name and a small lane integer — so the series count stays bounded).
    busbar_substrate::telemetry::upstream_attempt_on(pool, &lane.to_string());

    // The axis pins `WebSocket` to the full-duplex wire; the `else` is unreachable by construction (a
    // closed axis), expressed as a refusal rather than a panic so a mis-selection fails closed.
    let Some(UpstreamWireKind::Duplex) = Transport::WebSocket.upstream_wire() else {
        let e = DialError::Url(url.to_string());
        host.breaker_record_signal(pool, lane, &dial_signal(&e));
        return Err(DialProviderError::Dial(e));
    };

    match duplex_ws::dial(url, policy).await {
        Ok((stream, sink)) => {
            host.breaker_record_success(pool, lane);
            // `sink_map_err(|_| ())`: the substrate dialer's own Sink `Error` associated type is an
            // opaque `impl Trait` detail with no `Send` bound of its own (it happens to be `Send` today,
            // but nothing in its signature promises that) — and `TelephonyProxy::run` (the one consumer)
            // needs `POut::Error: Send` to spawn the drain task. Discarding the write-failure detail into
            // a bare `()` is a small, honest price: a write failure already means the socket is going
            // away (the pump's own EOF/close handling is what actually tears the session down), so no
            // caller of this fn reads the write error's content today.
            Ok((stream, futures::SinkExt::sink_map_err(sink, |_| ())))
        }
        Err(e) => {
            host.breaker_record_signal(pool, lane, &dial_signal(&e));
            Err(DialProviderError::Dial(e))
        }
    }
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
pub(crate) struct SessionGauntlet {
    pub(crate) deny: bool,
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
    meter: Option<crate::runtime::metering::TurnMeter>,
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

    // Only past the gate: reserve/bind/open the live carrier. Factored into [`open_admitted_session`]
    // so the inbound WS-accept seam — where the gauntlet has ALREADY run inside `accept_gauntlet`,
    // strictly before the socket upgrades — reuses the SAME post-admit open without re-running (or
    // duplicating) the gate. begin_session's own order is byte-identical: gauntlet, then this.
    open_admitted_session(
        rt,
        codec,
        owner,
        call_id,
        locked_config,
        carrier,
        budget,
        meter,
        now,
    )
}

/// THE POST-ADMIT OPEN of a governed session — the reserve/bind/open half of [`begin_session`],
/// called ONLY after the open-pass gauntlet has already admitted the destination (verify strictly
/// before any charge). Opens the D2 metering lease (fail-closed on a refused budget), opens the
/// durable [`SessionHandle`] at genesis, and assembles the [`SessionCore`]. NO gauntlet runs here: the
/// caller (`begin_session`, or the inbound WS-accept `accept_gauntlet` path) is responsible for having
/// run it first. A refused budget or a failed durable open returns before ANY durable row is committed
/// — so an aborted open, like a refused gauntlet, leaves no orphaned live session row.
#[allow(clippy::too_many_arguments)]
pub(crate) fn open_admitted_session<C>(
    rt: &VoiceRuntime,
    codec: C,
    owner: impl Into<String>,
    call_id: impl Into<String>,
    locked_config: Option<SessionConfig>,
    carrier: Carrier,
    budget: SessionBudget,
    meter: Option<crate::runtime::metering::TurnMeter>,
    now: u64,
) -> Result<(Arc<SessionCore<C>>, SessionHandle, LeaseCloseGuard), StartError>
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
{
    // The marquee guarantee's charge — no lease ⇒ no session (fail closed). Reserved AFTER admission.
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
        meter,
        Arc::clone(&rt.tools),
        carrier,
        locked_config,
    ));
    Ok((core, handle, guard))
}
