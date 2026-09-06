// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIVE DUPLEX SESSION RUNTIME — the pump body, behind the `runtime` feature.
//!
//! Binds the neutral byte-duplex pump (`busbar_substrate::ingress::byte_duplex::serve_messages`), the
//! codec's `DuplexReader`/`DuplexWriter` pair, the durable `SessionScope`, and the D2 metering lease
//! into one governed carrier. The runtime is GENERIC over the codec traits (HARD RULE 3) so it does
//! not depend on WHICH dialect codec is present — the Gemini codec drops in unchanged.
//!
//! CONCURRENCY POSTURE. The neutral pump `tokio::spawn`s one `handle` per inbound frame, so the
//! decode+act logic lives in a SYNCHRONOUS, self-contained core ([`SessionCore::on_server_frame`] /
//! [`SessionCore::on_client_frame`]) that returns an [`Outbound`] plan; the `DuplexPlane` glue merely
//! drives that plan onto `out` (upstream) and the [`Carrier`] (downlink / hard-close). That keeps the
//! marquee behaviours — tool correlation, barge-in truncate, metered hard-close — deterministically
//! unit-testable without the async plumbing, while the pump integration is tested separately.

use crate::ir::codec::{DecodeState, DuplexReader, DuplexWriter, WireEvent};
use crate::ir::config::SessionConfig;
use crate::ir::control::IrDuplexControl;
use crate::ir::event::{IrClientEvent, IrServerEvent};
use crate::ir::tool::{CallRef, IrDuplexTool};
use crate::runtime::carrier::Carrier;
use crate::runtime::governed::GovernedSession;
use crate::runtime::metering::{MeteringLease, TurnMeter};
use crate::runtime::tools::ToolExecutor;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_substrate::ingress::byte_duplex::{CallRef as WireCallRef, DuplexHandle, DuplexPlane};

/// THE FRAME PLAN one decoded inbound frame produces — what to write UPSTREAM (client→server events:
/// tool results, barge-in cancel/truncate, `response.create`), what to relay DOWNLINK to the client,
/// and whether the metering lease tripped a HARD CLOSE this frame.
#[derive(Debug, Default)]
pub struct Outbound {
    /// Client→server wire frames to write up the served socket (via the handler's `out`).
    pub upstream: Vec<WireEvent>,
    /// Server→client wire frames to relay to the client (via the [`Carrier`] downlink).
    pub downlink: Vec<WireEvent>,
    /// The metering lease reported exhausted / refused this frame — the carrier must hard-close.
    pub close: bool,
    /// This frame carried a tool reply the node's table refused — nothing on this session was waiting
    /// on the identifier it named.
    ///
    /// A bit rather than silence, and the distinction is the point: a refused reply put nothing on
    /// the upstream wire, and a caller that could not tell that apart from a frame that was never
    /// sent would have no way to report a client answering calls it was never asked to make.
    pub refused_reply: bool,
}

impl Outbound {
    /// Queue one framed uplink event, honoring a DIALECT DROP: the writer answers `None` when the
    /// upstream dialect has no verb for the concept (a Gemini upstream has no `response.cancel`), and
    /// nothing is what a dropped concept must put on the wire.
    fn push_up(&mut self, framed: Option<WireEvent>) {
        if let Some(w) = framed {
            self.upstream.push(w);
        }
    }
}

/// ONE IN-FLIGHT SERVER-SIDE TOOL CALL, correlated by [`CallRef`] and accumulated across the
/// `CallOpen → CallArgs* → CallClose` frames the model streams (`plane4-duplex-session.md` §2.2). The raw `call_id` is kept so the
/// stateless writer can re-frame the `function_call_output` without consulting the map.
#[derive(Debug, Default, Clone)]
struct PendingCall {
    call_id: String,
    name: String,
    args: Vec<u8>,
    closed: bool,
    executed: bool,
}

/// The mutable per-session state guarded by one lock: the codec's decode state (seq, `CallRef` map,
/// barge-in playback position) and the in-flight tool-call table.
#[derive(Debug, Default)]
struct Inner {
    decode: DecodeState,
    calls: HashMap<CallRef, PendingCall>,
}

/// THE GOVERNED SESSION CORE — the synchronous heart shared across the concurrent frame handlers. It
/// owns the codec, the locked config (the plane's tools + instructions the browser cannot override),
/// the metering lease (which also prices each turn host-side), the tool executor, the priced model id,
/// and the carrier. Generic over the codec
/// `C` (HARD RULE 3); the lease and tool executor are dependency-inverted ports.
pub struct SessionCore<C> {
    codec: C,
    inner: Mutex<Inner>,
    /// The locked GA `session` config — the authoritative copy the plane holds server-side and
    /// re-applies; a client `session.update` is a HINT reconciled against this, never trusted blind.
    locked_config: Option<SessionConfig>,
    lease: Box<dyn MeteringLease>,
    /// The presenting-key attribution each turn's usage is landed on through the CORE Meter seam
    /// (`host.meter_ledger` + `host.meter_series`). `None` on an ungoverned deployment. Voice keeps
    /// NO meter of its own — this IS the metering step, the same one every plane traverses.
    meter: Option<TurnMeter>,
    tools: Arc<dyn ToolExecutor>,
    /// The upstream MODEL id this session prices against (from the locked `session` config; empty when
    /// the dialect carries it server-side and none was locked). Handed to the lease's `price_usage` so
    /// the host prices each turn against that model's rate-card lane.
    model: String,
    carrier: Carrier,
    /// The node's open-call table, when a composition root bound one. `None` is an ungoverned
    /// deployment: every call is served in-process and a client-authored result is carried upstream
    /// verbatim, which is exactly what this runtime did before the governed wait existed.
    governed: Option<GovernedSession>,
}

impl<C> SessionCore<C>
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
{
    /// Assemble a session core. `lease` is the OPEN D2 metering lease (already reserved at session
    /// start); `locked_config` is the plane's authoritative tools+instructions.
    pub fn new(
        codec: C,
        lease: Box<dyn MeteringLease>,
        meter: Option<TurnMeter>,
        tools: Arc<dyn ToolExecutor>,
        carrier: Carrier,
        locked_config: Option<SessionConfig>,
    ) -> Self {
        // The pricing model rides the locked config (the plane's authoritative `session` shape); a
        // dialect that carries the model server-side and locked none prices under the empty lane.
        let model = locked_config
            .as_ref()
            .and_then(|c| c.model.clone())
            .unwrap_or_default();
        SessionCore {
            codec,
            inner: Mutex::new(Inner::default()),
            locked_config,
            lease,
            meter,
            tools,
            model,
            carrier,
            governed: None,
        }
    }

    /// Bind this session to the node's open-call table.
    ///
    /// A builder step rather than a constructor argument because the table is not something every
    /// deployment has: the runtime and topology tests, the conformance rig's ungoverned legs and a
    /// `--validate` build all assemble a core with no root behind it, and each of them would
    /// otherwise have to name a table it has no use for.
    #[must_use]
    pub fn with_governed(mut self, governed: GovernedSession) -> Self {
        self.governed = Some(governed);
        self
    }

    /// **The tick's sweep.** End every governed call whose deadline has passed, and say how many.
    ///
    /// Driven from the node's tick beside the pump, because a wait that is never woken is a hold that
    /// is never settled and there is nothing on the frame path that will notice. An ungoverned
    /// session has no table and sweeps nothing.
    pub fn sweep_expired(&self, now_ms: u64) -> usize {
        match &self.governed {
            Some(g) => g.calls.expired(now_ms),
            None => 0,
        }
    }

    /// The session's carrier (downlink + hard-close latch).
    pub fn carrier(&self) -> &Carrier {
        &self.carrier
    }

    /// Total nanodollars the metering lease has settled so far — the audit tap the tests assert.
    pub fn settled_nanos(&self) -> u64 {
        self.lease.settled_nanos()
    }

    /// DECODE + ACT on ONE downlink (server→client) wire frame. Meters usage (hard-closing on
    /// exhaustion), correlates + executes tool calls server-side, drives barge-in truncate, and relays
    /// media/control downlink to the client. Returns the [`Outbound`] plan; a closed carrier yields an
    /// empty plan (the hard-close guarantee — nothing more is processed once dry).
    pub async fn on_server_frame(&self, frame: WireEvent) -> Outbound {
        if self.carrier.is_closed() {
            return Outbound::default();
        }

        let mut out = Outbound::default();
        // Tool calls whose arguments just completed — executed AFTER the lock is released (execute is
        // async and must not hold the std mutex across `.await`).
        let mut to_exec: Vec<(CallRef, String, String, Vec<u8>)> = Vec::new();

        {
            let mut g = self.inner.lock().expect("session inner poisoned");
            let inner = &mut *g;
            let events = self.codec.read_down(frame, &mut inner.decode);
            for ev in events {
                match ev {
                    // ── metering: the marquee guarantee ──────────────────────────────────────────
                    IrServerEvent::Usage(u) => {
                        // Fold the turn's five token classes onto the neutral reserved-key `Usage` (the
                        // 5→4 map), price it HOST-side against the model's rate-card lane, then settle the
                        // already-priced increment. A missing rate (`None`) fails CLOSED — the turn cannot
                        // meter as free — exactly as an exhaustion would.
                        let usage = u.to_billing_usage();
                        // METER THE TURN through the CORE seam — land this turn's usage on the ONE
                        // ledger, attributed to the presenting key (the voice twin of the LLM plane's
                        // `ledger_and_meter`). Voice keeps no meter of its own; THIS is the Meter step.
                        if let Some(meter) = &self.meter {
                            meter.record_turn(&self.model, &usage);
                        }
                        let close = match self.lease.price_usage(&self.model, &usage) {
                            Some(nanos) => self.lease.settle(nanos).must_close(),
                            None => true,
                        };
                        if close {
                            // Budget dry (or the lease refused / faulted / unpriced): cancel the in-flight
                            // response upstream and demand a hard close.
                            out.push_up(self.codec.write_up(
                                IrClientEvent::Control(IrDuplexControl::ResponseCancel),
                                &mut inner.decode,
                            ));
                            out.close = true;
                        }
                    }
                    // ── barge-in: cancel + truncate at the audio the user actually heard (`plane4-duplex-session.md` §2.3) ────
                    IrServerEvent::SpeechStarted { item_id, .. } => {
                        let heard_ms = inner.decode.flush_playback();
                        out.push_up(self.codec.write_up(
                            IrClientEvent::Control(IrDuplexControl::ResponseCancel),
                            &mut inner.decode,
                        ));
                        out.push_up(self.codec.write_up(
                            IrClientEvent::Control(IrDuplexControl::ItemTruncate {
                                item_ref: item_id.clone(),
                                content_index: 0,
                                audio_played_ms: heard_ms,
                            }),
                            &mut inner.decode,
                        ));
                        // The client still hears the barge-in acknowledgement.
                        out.downlink.extend(self.codec.write_down(
                            IrServerEvent::SpeechStarted {
                                item_id,
                                audio_start_ms: 0,
                            },
                            &mut inner.decode,
                        ));
                    }
                    // ── tool moat: correlate + accumulate, execute server-side on close (`plane4-duplex-session.md` §2.2) ─────
                    IrServerEvent::Tool(t) => {
                        let call_ref = t.call_ref();
                        match t {
                            IrDuplexTool::CallOpen { call_id, name, .. } => {
                                let e = inner.calls.entry(call_ref).or_default();
                                e.call_id = call_id;
                                e.name = name;
                            }
                            IrDuplexTool::CallArgs {
                                call_id,
                                json_delta,
                                ..
                            } => {
                                let e = inner.calls.entry(call_ref).or_default();
                                if e.call_id.is_empty() {
                                    e.call_id = call_id;
                                }
                                e.args.extend_from_slice(&json_delta);
                            }
                            IrDuplexTool::CallClose { call_id, .. } => {
                                let e = inner.calls.entry(call_ref).or_default();
                                if e.call_id.is_empty() {
                                    e.call_id = call_id;
                                }
                                e.closed = true;
                                if !e.executed {
                                    e.executed = true;
                                    // THE FORK. A tool this node serves is executed in-process below
                                    // and the client never authors its result — the moat, unchanged.
                                    // A tool it does not serve has only one possible answerer, so
                                    // nothing is executed here: the call's reply leg is the wait the
                                    // root entered when it planned the leg, and the answer comes back
                                    // up the client's own uplink.
                                    let client_serves =
                                        self.governed.is_some() && !self.tools.serves(&e.name);
                                    if !client_serves {
                                        to_exec.push((
                                            call_ref,
                                            e.call_id.clone(),
                                            e.name.clone(),
                                            e.args.clone(),
                                        ));
                                    }
                                }
                            }
                            // A server-side result echoed back to us is not something we act on.
                            IrDuplexTool::CallResult { .. } => {}
                        }
                    }
                    // ── media + control: relay downlink verbatim (identity IR) ────────────────────
                    ev @ (IrServerEvent::AudioFrame(_)
                    | IrServerEvent::AudioDone { .. }
                    | IrServerEvent::SpeechStopped { .. }
                    | IrServerEvent::SessionCreated { .. }
                    | IrServerEvent::Error { .. }) => {
                        // A downlink event that is not a frame on its own (a held tool-argument
                        // fragment) relays nothing — the same answer an unrepresentable uplink gives.
                        out.downlink
                            .extend(self.codec.write_down(ev, &mut inner.decode));
                    }
                    // Extraction-only — never client-translated (`plane4-duplex-session.md` §2.5).
                    IrServerEvent::RateLimits => {}
                }
            }
        }

        // Execute completed tool calls server-side, then feed the result back upstream and ask the
        // model to continue.
        for (call_ref, call_id, name, args) in to_exec {
            let output = self.tools.execute(&name, &args).await;
            // The write seam threads the session's decode state, so the lock is retaken AFTER the
            // await — never held across it.
            let mut g = self.inner.lock().expect("session inner poisoned");
            out.push_up(self.codec.write_up(
                IrClientEvent::Tool(IrDuplexTool::CallResult {
                    call_ref,
                    call_id,
                    // The tool the plane just ran — a dialect whose result frame requires a name
                    // (Gemini) gets the one the model actually called for.
                    name,
                    output: Bytes::from(output),
                }),
                &mut g.decode,
            ));
            out.push_up(self.codec.write_up(
                IrClientEvent::Control(IrDuplexControl::ResponseCreate { response: None }),
                &mut g.decode,
            ));
            drop(g);
        }

        if out.close {
            self.carrier.hard_close();
        }
        out
    }

    /// DECODE + ACT on ONE uplink (client→server) wire frame — the governed forward leg. Audio and
    /// control pass through to the upstream; a client `session.update` is RECONCILED against the locked
    /// config (the plane re-applies its own tools+instructions, never the browser's). Returns the
    /// upstream plan; downlink is unused on the uplink leg.
    pub fn on_client_frame(&self, frame: WireEvent) -> Outbound {
        if self.carrier.is_closed() {
            return Outbound::default();
        }
        let mut out = Outbound::default();
        let mut g = self.inner.lock().expect("session inner poisoned");
        let events = self.codec.read_up(frame, &mut g.decode);
        for ev in events {
            match ev {
                // The config-lock invariant: a client-originated configure is a hint. If the plane
                // holds a locked config, re-apply THAT; otherwise pass the client's through.
                IrClientEvent::Control(IrDuplexControl::SessionConfigure { config }) => {
                    let effective = self.locked_config.clone().unwrap_or(config);
                    out.push_up(self.codec.write_up(
                        IrClientEvent::Control(IrDuplexControl::SessionConfigure {
                            config: effective,
                        }),
                        &mut g.decode,
                    ));
                }
                // A CLIENT-AUTHORED TOOL REPLY. This is the answer a governed wait was entered for,
                // and it is the one client frame that is not simply carried: it names a call, and
                // which unit that call belongs to is the node's decision, not this pump's. So the
                // correlation goes to the node's table first and the wire second — a reply the table
                // refuses reaches the model on no wire at all, because paying it out against
                // whichever call happens to be standing is the exact failure the correlation exists
                // to prevent.
                IrClientEvent::Tool(IrDuplexTool::CallResult {
                    call_ref,
                    call_id,
                    name,
                    output,
                }) if self.governed.is_some() => {
                    let governed = self
                        .governed
                        .as_ref()
                        .expect("the arm's own guard read it as bound");
                    match governed.calls.replied(governed.session, &call_id) {
                        Ok(()) => {
                            // The wait was woken. The reply goes on to the model, and the model is
                            // asked to continue — the same two frames the in-process path authors,
                            // because a turn that stopped for a tool resumes the same way whoever
                            // answered it.
                            g.calls.remove(&call_ref);
                            out.push_up(self.codec.write_up(IrClientEvent::Tool(
                                IrDuplexTool::CallResult {
                                    call_ref,
                                    call_id,
                                    name,
                                    output,
                                },
                            )));
                            out.push_up(self.codec.write_up(IrClientEvent::Control(
                                IrDuplexControl::ResponseCreate { response: None },
                            )));
                        }
                        Err(_) => out.refused_reply = true,
                    }
                }
                // Everything else forwards verbatim (audio uplink, commits, item ops, tool results the
                // plane itself authored are not re-authored here).
                ev => {
                    out.push_up(self.codec.write_up(ev, &mut g.decode));
                }
            }
        }
        out
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
            core.sweep_expired(now_ms());
        }
    };
    futures::pin_mut!(pump);
    futures::pin_mut!(sweep);
    // The sweep never completes on its own, so this ends when — and only when — the pump does.
    futures::future::select(pump, sweep).await;
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
            out.emit(up.0.to_vec()).await;
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
