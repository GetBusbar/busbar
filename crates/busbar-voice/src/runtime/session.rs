// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIVE DUPLEX SESSION RUNTIME — the pump body, behind the `runtime` feature.
//!
//! Binds the neutral byte-duplex pump (`busbar_kernel::ingress::byte_duplex::serve_messages`), the
//! codec's `DuplexReader`/`DuplexWriter` pair, the durable `SessionScope`, and the kernel session
//! account (each closed turn's per-class counts, ledgered and budget-checked kernel-side) into one
//! governed carrier. The runtime is GENERIC over the codec traits (HARD RULE 3) so it does
//! not depend on WHICH dialect codec is present — the Gemini codec drops in unchanged.
//!
//! CONCURRENCY POSTURE. The neutral pump `tokio::spawn`s one `handle` per inbound frame, so the
//! decode+act logic lives in a SYNCHRONOUS, self-contained core ([`SessionCore::on_server_frame`] /
//! [`SessionCore::on_client_frame`]) that returns an [`Outbound`] plan; the `DuplexPlane` glue merely
//! drives that plan onto `out` (upstream) and the [`Carrier`] (downlink / hard-close). That keeps the
//! marquee behaviours — tool correlation, barge-in truncate, metered hard-close — deterministically
//! unit-testable without the async plumbing, while the pump integration is tested separately.

use crate::ir::codec::{DuplexReader, DuplexWriter, WireEvent};
use crate::ir::config::SessionConfig;
use crate::ir::usage::IrDuplexUsage;
use crate::runtime::carrier::Carrier;
use crate::runtime::metering::{SessionMetering, TurnVerdict};
use crate::runtime::tools::ToolExecutor;
use busbar_plane_streaming::governed::GovernedSession;
use busbar_plane_streaming::session::TurnCounters;
use busbar_plane_streaming::session_pump::{SessionPump, TurnSink};
use bytes::Bytes;
use std::sync::{Arc, Mutex};

use busbar_kernel::ingress::byte_duplex::{CallRef as WireCallRef, DuplexHandle, DuplexPlane};

/// THE FRAME PLAN one decoded inbound frame produces — what to write UPSTREAM (client→server events:
/// tool results, barge-in cancel/truncate, `response.create`), what to relay DOWNLINK to the client,
/// and whether the kernel's budget verdict tripped a HARD CLOSE this frame. The plane's own plan
/// (`busbar_plane_streaming::session_pump::Outbound`).
pub use busbar_plane_streaming::session_pump::Outbound;

/// The named reason a session closed at its configured wall-clock ceiling is told under.
pub use busbar_plane_streaming::session_pump::SESSION_CEILING_REASON;

/// A closed turn's way to the kernel account: the session's metering, when it has one. A turn the
/// account answers `MustClose` for cuts the session.
struct MeterSink<'m>(Option<&'m SessionMetering>);

impl TurnSink for MeterSink<'_> {
    fn turn_closed(&mut self, usage: Option<&IrDuplexUsage>, counters: TurnCounters) -> bool {
        match self.0 {
            Some(metering) => metering.report_turn(usage, counters) != TurnVerdict::MustClose,
            None => true,
        }
    }
}

/// THE GOVERNED SESSION CORE — the synchronous heart shared across the concurrent frame handlers. It
/// holds the plane's session pump (the codec, the locked config the browser cannot override, the
/// in-flight tool calls, the open turn's counters, the node's open-call binding) behind one lock,
/// and around it the session's metering (each closed turn's counts go to the kernel account), the
/// tool executor, the carrier and the session's wall-clock ceiling. Generic over the codec `C`
/// (HARD RULE 3); the tool executor is a dependency-inverted port.
pub struct SessionCore<C> {
    pump: Mutex<SessionPump<C>>,
    /// The session's metering: each closed turn's raw counts per class go to the kernel account,
    /// which ledgers them through the one metering path and answers whether the carrier stays open.
    /// `None` on an ungoverned deployment — nothing to attribute, nothing to close on.
    metering: Option<SessionMetering>,
    tools: Arc<dyn ToolExecutor>,
    carrier: Carrier,
    /// When this session opened — the start of the wall clock [`Self::ceiling`] bounds.
    opened: std::time::Instant,
    /// The hard session wall-clock ceiling (`streams.session_max_secs:`), `None` until a runtime
    /// binds one ([`Self::with_session_ceiling`]). Compared on the sweep tick beside the pump
    /// ([`Self::enforce_ceiling`]): a session past it is hard-closed exactly as a dry budget is.
    ceiling: Option<std::time::Duration>,
}

impl<C> SessionCore<C>
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
{
    /// Assemble a session core. `metering` is the session's OPEN kernel account (opened, and its
    /// budget checked, at session start); `locked_config` is the plane's authoritative
    /// tools+instructions.
    pub fn new(
        codec: C,
        metering: Option<SessionMetering>,
        tools: Arc<dyn ToolExecutor>,
        carrier: Carrier,
        locked_config: Option<SessionConfig>,
    ) -> Self {
        SessionCore {
            pump: Mutex::new(SessionPump::new(codec, locked_config)),
            metering,
            tools,
            carrier,
            opened: std::time::Instant::now(),
            ceiling: None,
        }
    }

    /// Bind the hard session wall-clock ceiling (`streams.session_max_secs:`).
    #[must_use]
    pub fn with_session_ceiling(mut self, secs: u32) -> Self {
        self.ceiling = Some(std::time::Duration::from_secs(u64::from(secs)));
        self
    }

    /// Close the session when it has run past its ceiling at `now`: the caller is told why, in its
    /// dialect, and the carrier hard-closes. `true` when it closed; a session with no ceiling never
    /// does.
    pub fn enforce_ceiling(&self, now: std::time::Instant) -> bool {
        let Some(ceiling) = self.ceiling else {
            return false;
        };
        if now.saturating_duration_since(self.opened) < ceiling {
            return false;
        }
        if !self.carrier.is_closed() {
            let told = self.lock().ceiling_error(ceiling.as_secs());
            if let Some(frame) = told {
                self.carrier.send_downlink(frame.0.to_vec());
            }
        }
        self.carrier.hard_close();
        true
    }

    /// Bind the node's open-call table for this session.
    #[must_use]
    pub fn with_governed(self, governed: GovernedSession) -> Self {
        self.lock().bind_governed(governed);
        self
    }

    /// The node's session id, when a table is bound.
    #[must_use]
    pub fn governed_session(&self) -> Option<u64> {
        self.lock().governed_session()
    }

    /// Sweep the table's unanswered calls past their deadline at `now_ms`; how many ended.
    pub fn sweep_expired(&self, now_ms: u64) -> usize {
        self.lock().sweep_expired(now_ms)
    }

    /// The session's carrier.
    pub fn carrier(&self) -> &Carrier {
        &self.carrier
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SessionPump<C>> {
        self.pump.lock().expect("session inner poisoned")
    }

    /// A FRAME FROM THE SERVED SOCKET's far side. Decoded and answered by the plane's pump; the
    /// calls this session serves itself run here, off the lock, in close order.
    pub async fn on_server_frame(&self, frame: WireEvent) -> Outbound {
        if self.carrier.is_closed() {
            return Outbound::default();
        }
        let tools = Arc::clone(&self.tools);
        let (mut out, to_exec) = self.lock().on_server_frame(
            frame,
            now_ms(),
            &mut MeterSink(self.metering.as_ref()),
            &|name: &str| tools.executes_here(name),
        );
        for run in to_exec {
            let output = self.tools.execute(&run.name, &run.args).await;
            self.lock().tool_executed(run, output, &mut out);
        }
        if out.close {
            self.carrier.hard_close();
        }
        out
    }

    /// A FRAME FROM THE CALLER, decoded and answered by the plane's pump.
    pub fn on_client_frame(&self, frame: WireEvent) -> Outbound {
        if self.carrier.is_closed() {
            return Outbound::default();
        }
        self.lock().on_client_frame(frame)
    }

    /// The session ends: the table forgets every call it had open.
    pub fn forget_governed_calls(&self) {
        self.lock().forget_governed_calls();
    }

    /// The session ends with a turn open: its counters settle, once.
    pub fn settle_open_turn(&self) {
        self.lock()
            .settle_open_turn(&mut MeterSink(self.metering.as_ref()));
    }
}

/// How often the tick beside a session's pump sweeps its governed calls.
///
/// One second, against a reply deadline the plane declares in tens of seconds: fine enough that a
/// call ends within a second of the deadline it was given, coarse enough that an idle session's tick
/// is not a cost. The deadline itself is not this crate's to name — the leg the root plans carries it,
/// and the sweep only asks the table which of them have passed.
const SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// **THE TICK BESIDE THE PUMP.** Run one session's frame loop with its governed-call sweep beside it,
/// and end when the pump does.
///
/// The wake has a frame to arrive on. The sweep does not: a client that simply never replies sends
/// nothing, so there is no frame on which anyone would notice, and a wait nobody sweeps is a hold
/// nobody settles. This is the only place in the session's life where time passing is itself an
/// event.
///
/// It rides each session's own pump rather than a process-wide loop, which is the shape this plane
/// already has — voice spawns no boot task, and a sweep that outlived the socket it was sweeping for
/// would be exactly the background loop the plane's start hook says it does not have. When the pump
/// returns, the tick is dropped with it.
pub async fn serve_with_sweep<C, F>(core: Arc<SessionCore<C>>, pump: F)
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
    F: std::future::Future<Output = ()>,
{
    let sweep = async {
        loop {
            tokio::time::sleep(SWEEP_EVERY).await;
            // A closed carrier is a conversation that is over; nothing left on it can be answered and
            // the pump is on its way out anyway.
            if core.carrier().is_closed() {
                return;
            }
            // The session wall-clock ceiling is time passing, too, and so is noticed here: a session
            // past it is hard-closed and the pump ends with the sweep.
            if core.enforce_ceiling(std::time::Instant::now()) {
                return;
            }
            core.sweep_expired(now_ms());
        }
    };
    futures::pin_mut!(pump);
    futures::pin_mut!(sweep);
    // The sweep never completes on its own, so this ends when — and only when — the pump does.
    futures::future::select(pump, sweep).await;
}

/// **SERVE A SESSION TO ITS TEARDOWN.** [`serve_with_sweep`], then settle the session's durable row
/// terminal and evict it, stamped at `now()` taken when the pump returns.
///
/// Every serving site used to drop its [`crate::runtime::SessionHandle`] unsettled once the pump
/// returned, so the row outlived the socket as an ACTIVE session. This is the one shape a serving
/// site takes instead, so none of them can forget the second half.
pub async fn serve_to_teardown<C, F, N>(
    core: Arc<SessionCore<C>>,
    handle: crate::runtime::SessionHandle,
    pump: F,
    now: N,
) where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
    F: std::future::Future<Output = ()>,
    N: FnOnce() -> u64,
{
    serve_with_sweep(Arc::clone(&core), pump).await;
    core.settle_open_turn();
    core.forget_governed_calls();
    handle.finish(now());
}

/// Wall-clock milliseconds, for the sweep's "which deadlines have passed" question.
///
/// The reading is handed to the node's table rather than compared here: which calls are past their
/// deadline is the table's judgement, and a clock read on this side that the table then re-derived
/// would be two clocks deciding one deadline.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// THE UPSTREAM-FACING PLANE — bound to the socket busbar holds to the provider (OpenAI Realtime). The
/// neutral pump reads server→client events off it; each `handle` decodes one and drives the plan onto
/// `out` (the client→server write side of the SAME socket) and the carrier (downlink to the client).
pub struct VoiceSession<C> {
    core: Arc<SessionCore<C>>,
}

impl<C> VoiceSession<C> {
    /// Bind the plane to a session core.
    pub fn new(core: Arc<SessionCore<C>>) -> Self {
        VoiceSession { core }
    }

    /// The shared session core.
    pub fn core(&self) -> &Arc<SessionCore<C>> {
        &self.core
    }
}

#[async_trait::async_trait]
impl<C> DuplexPlane for VoiceSession<C>
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
{
    fn classify(&self, _frame: &[u8]) -> Option<WireCallRef> {
        // OpenAI Realtime events are fire-and-forget notifications, never a reply to a transport-level
        // call busbar issued — correlation is done at the IR layer (voice `CallRef`), not here.
        None
    }

    async fn handle(self: Arc<Self>, frame: Vec<u8>, out: DuplexHandle) {
        let plan = self
            .core
            .on_server_frame(WireEvent(Bytes::from(frame)))
            .await;
        for up in plan.upstream {
            // THIS leg's policy for a write that fails: DIAGNOSE AND STOP SENDING. The upstream
            // socket is a session-long conversation, so a frame that never lands leaves the far end
            // holding a state busbar no longer shares — and every later frame of this plan would be
            // written into the same dead socket. Abandon the rest of the plan rather than emit
            // frames the peer will never see; the downlink and the close below still run, so the
            // client is still told.
            if let Err(e) = out.emit(up.0.to_vec()).await {
                tracing::warn!(
                    error = %e,
                    "streaming: an upstream frame could not be written; abandoning the rest of this plan's upstream"
                );
                break;
            }
        }
        for down in plan.downlink {
            self.core.carrier.send_downlink(down.0.to_vec());
        }
        if plan.close {
            self.core.carrier.hard_close();
        }
    }
}

/// THE UPLINK-FACING PLANE — bound to the socket busbar holds to the CLIENT (the telephony leg). The
/// neutral pump reads client→server frames off it; each `handle` decodes one, reconciles it against the
/// locked config, and forwards it to the UPSTREAM socket through the shared `upstream` sink (NOT this
/// socket's `out`, which is the downlink toward the client).
pub struct UplinkForwarder<C> {
    core: Arc<SessionCore<C>>,
    upstream: futures::channel::mpsc::UnboundedSender<Vec<u8>>,
}

impl<C> UplinkForwarder<C> {
    /// Bind the uplink plane to a session core and the shared upstream sink.
    pub fn new(
        core: Arc<SessionCore<C>>,
        upstream: futures::channel::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        UplinkForwarder { core, upstream }
    }
}

#[async_trait::async_trait]
impl<C> DuplexPlane for UplinkForwarder<C>
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
{
    fn classify(&self, _frame: &[u8]) -> Option<WireCallRef> {
        None
    }

    async fn handle(self: Arc<Self>, frame: Vec<u8>, _out: DuplexHandle) {
        let plan = self.core.on_client_frame(WireEvent(Bytes::from(frame)));
        for up in plan.upstream {
            // Funnel to the single upstream writer shared with the downlink-facing plane.
            let _ = self.upstream.unbounded_send(up.0.to_vec());
        }
    }
}
