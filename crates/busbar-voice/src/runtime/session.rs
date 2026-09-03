// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIVE DUPLEX SESSION RUNTIME — the pump body the skeleton in `lib.rs` left `todo!()`.
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
use crate::runtime::metering::{MeteringLease, Pricing};
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
/// the metering lease, the tool executor, the pricing book, and the carrier. Generic over the codec
/// `C` (HARD RULE 3); the lease and tool executor are dependency-inverted ports.
pub struct SessionCore<C> {
    codec: C,
    inner: Mutex<Inner>,
    /// The locked GA `session` config — the authoritative copy the plane holds server-side and
    /// re-applies; a client `session.update` is a HINT reconciled against this, never trusted blind.
    locked_config: Option<SessionConfig>,
    lease: Box<dyn MeteringLease>,
    tools: Arc<dyn ToolExecutor>,
    pricing: Pricing,
    carrier: Carrier,
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
        tools: Arc<dyn ToolExecutor>,
        pricing: Pricing,
        carrier: Carrier,
        locked_config: Option<SessionConfig>,
    ) -> Self {
        SessionCore {
            codec,
            inner: Mutex::new(Inner::default()),
            locked_config,
            lease,
            tools,
            pricing,
            carrier,
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
                        let nanos = self.pricing.price(&u);
                        if self.lease.settle(nanos).must_close() {
                            // Budget dry (or the lease refused / faulted): cancel the in-flight
                            // response upstream and demand a hard close.
                            out.upstream.push(
                                self.codec.write_up(IrClientEvent::Control(
                                    IrDuplexControl::ResponseCancel,
                                )),
                            );
                            out.close = true;
                        }
                    }
                    // ── barge-in: cancel + truncate at the audio the user actually heard (`plane4-duplex-session.md` §2.3) ────
                    IrServerEvent::SpeechStarted { item_id, .. } => {
                        let heard_ms = inner.decode.flush_playback();
                        out.upstream.push(
                            self.codec
                                .write_up(IrClientEvent::Control(IrDuplexControl::ResponseCancel)),
                        );
                        out.upstream
                            .push(self.codec.write_up(IrClientEvent::Control(
                                IrDuplexControl::ItemTruncate {
                                    item_ref: item_id.clone(),
                                    content_index: 0,
                                    audio_played_ms: heard_ms,
                                },
                            )));
                        // The client still hears the barge-in acknowledgement.
                        out.downlink
                            .push(self.codec.write_down(IrServerEvent::SpeechStarted {
                                item_id,
                                audio_start_ms: 0,
                            }));
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
                                    to_exec.push((
                                        call_ref,
                                        e.call_id.clone(),
                                        e.name.clone(),
                                        e.args.clone(),
                                    ));
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
                        out.downlink.push(self.codec.write_down(ev));
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
            out.upstream.push(
                self.codec
                    .write_up(IrClientEvent::Tool(IrDuplexTool::CallResult {
                        call_ref,
                        call_id,
                        output: Bytes::from(output),
                    })),
            );
            out.upstream
                .push(self.codec.write_up(IrClientEvent::Control(
                    IrDuplexControl::ResponseCreate { response: None },
                )));
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
                    out.upstream
                        .push(self.codec.write_up(IrClientEvent::Control(
                            IrDuplexControl::SessionConfigure { config: effective },
                        )));
                }
                // Everything else forwards verbatim (audio uplink, commits, item ops, tool results the
                // plane itself authored are not re-authored here).
                ev => {
                    out.upstream.push(self.codec.write_up(ev));
                }
            }
        }
        out
    }
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
