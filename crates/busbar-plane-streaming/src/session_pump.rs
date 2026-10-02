// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SESSION PUMP: what one live session does with each frame, in both directions, sans I/O.
//!
//! A frame from the far end ([`SessionPump::on_server_frame`]) or from the caller
//! ([`SessionPump::on_client_frame`]) is decoded through the session's codec and answered with an
//! [`Outbound`] plan: the frames bound for the far end, the frames bound for the caller, and whether
//! the session must close. Nothing here sends, sleeps, reads a clock or holds a key; the caller
//! carries the plan, hands in the time where a rule needs one, and is told when a turn closes.
//!
//! What the pump holds for the session: the codec's decode state (sequence, call correlation,
//! barge-in playback position), the in-flight tool calls accumulated across their streamed
//! arguments, the open turn's own counters (the uplink audio admitted and the tool calls opened
//! since the last turn closed, the two quantities no usage report carries), the locked session
//! config the caller cannot override, and the node's open-call table binding when one is composed.
//!
//! What it asks of its caller, through [`TurnSink`]: when a turn closes (a usage report, an error,
//! or the session ending with a turn open), the turn's usage and counters, and whether the session
//! stays open.

use std::collections::HashMap;

use bytes::Bytes;

use crate::codec::ir::codec::{DecodeState, DuplexReader, DuplexWriter, WireEvent};
use crate::codec::ir::config::SessionConfig;
use crate::codec::ir::control::IrDuplexControl;
use crate::codec::ir::event::{IrClientEvent, IrServerEvent};
use crate::codec::ir::media::AudioFormat;
use crate::codec::ir::tool::{CallRef, IrDuplexTool};
use crate::codec::ir::usage::IrDuplexUsage;
use crate::governed::GovernedSession;
use crate::session::TurnCounters;

/// The reason code of the error frame a session past its configured ceiling is closed with.
pub const SESSION_CEILING_REASON: &str = "session_expired";

/// ONE FRAME'S PLAN: what the caller carries to each side, and whether the session ends.
#[derive(Debug, Default)]
pub struct Outbound {
    /// Frames bound for the far end.
    pub upstream: Vec<WireEvent>,
    /// Frames bound for the caller.
    pub downlink: Vec<WireEvent>,
    /// The session must close: its turn sink answered that it may not continue.
    pub close: bool,
    /// This frame carried a tool reply the node's table refused: nothing on this session was
    /// waiting on the identifier it named. A bit rather than silence, because a refused reply put
    /// nothing on the upstream wire, and a caller that could not tell that apart from a frame that
    /// was never sent could not report a client answering calls it was never asked to make.
    pub refused_reply: bool,
}

impl Outbound {
    /// Queue one framed uplink event, honouring a dialect drop: the writer answers `None` when the
    /// upstream dialect has no verb for the concept, and nothing is what a dropped concept puts on
    /// the wire.
    fn push_up(&mut self, framed: Option<WireEvent>) {
        if let Some(w) = framed {
            self.upstream.push(w);
        }
    }
}

/// Where a closed turn goes: its usage and its counters. The answer is whether the session may
/// continue; `false` cuts it (the far end is told to stop responding and the session closes).
pub trait TurnSink {
    /// One turn closed.
    fn turn_closed(&mut self, usage: Option<&IrDuplexUsage>, counters: TurnCounters) -> bool;
}

/// No turn sink: an ungoverned session. A closed turn attributes to nobody and never closes it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unmetered;

impl TurnSink for Unmetered {
    fn turn_closed(&mut self, _: Option<&IrDuplexUsage>, _: TurnCounters) -> bool {
        true
    }
}

/// A tool call the far end closed that this session serves itself: the call's correlation, its id,
/// its name and its accumulated arguments. The caller runs it and hands the output back through
/// [`SessionPump::tool_executed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRun {
    /// The call's correlation.
    pub call_ref: CallRef,
    /// The call id on the wire.
    pub call_id: String,
    /// The tool's name.
    pub name: String,
    /// The arguments, accumulated across the streamed deltas.
    pub args: Vec<u8>,
}

/// ONE IN-FLIGHT TOOL CALL, accumulated across the `CallOpen → CallArgs* → CallClose` frames the
/// model streams. The raw call id is kept so the stateless writer can frame the output without
/// consulting the map.
#[derive(Debug, Default, Clone)]
struct PendingCall {
    call_id: String,
    name: String,
    args: Vec<u8>,
    closed: bool,
    executed: bool,
}

/// THE SESSION PUMP over the session's codec `C`.
#[derive(Debug)]
pub struct SessionPump<C> {
    codec: C,
    decode: DecodeState,
    calls: HashMap<CallRef, PendingCall>,
    turn: TurnCounters,
    /// The locked `session` config: the authoritative copy the plane re-applies. A caller's
    /// `session.update` is a hint reconciled against it, never trusted blind.
    locked_config: Option<SessionConfig>,
    /// The format uplink audio is counted in: the locked config's input format, else PCM16.
    audio_in: AudioFormat,
    /// The node's open-call table, when one is composed. `None`: every call is served in-process and
    /// a caller-authored result is carried upstream verbatim.
    governed: Option<GovernedSession>,
}

impl<C> SessionPump<C>
where
    C: DuplexReader + DuplexWriter,
{
    /// A pump over `codec`, locked to `locked_config` when one is given.
    pub fn new(codec: C, locked_config: Option<SessionConfig>) -> Self {
        let audio_in = locked_config
            .as_ref()
            .and_then(|c| c.input_audio_format)
            .unwrap_or(AudioFormat::Pcm16);
        SessionPump {
            codec,
            decode: DecodeState::default(),
            calls: HashMap::new(),
            turn: TurnCounters::default(),
            locked_config,
            audio_in,
            governed: None,
        }
    }

    /// Bind the node's open-call table for this session.
    pub fn bind_governed(&mut self, governed: GovernedSession) {
        self.governed = Some(governed);
    }

    /// The node's session id, when a table is bound.
    #[must_use]
    pub fn governed_session(&self) -> Option<u64> {
        self.governed.as_ref().map(|g| g.session)
    }

    /// Sweep the table's unanswered calls past their deadline at `now_ms`; how many ended.
    pub fn sweep_expired(&self, now_ms: u64) -> usize {
        match &self.governed {
            Some(g) => g.calls.expired(now_ms),
            None => 0,
        }
    }

    /// The session ends: the table forgets every call it had open.
    pub fn forget_governed_calls(&self) {
        if let Some(g) = &self.governed {
            g.calls.closed(g.session);
        }
    }

    /// The error frame a session past its `ceiling_secs` ceiling is told before it closes, in its
    /// dialect; `None` when the dialect drops the concept.
    pub fn ceiling_error(&mut self, ceiling_secs: u64) -> Option<WireEvent> {
        self.codec.write_down(
            IrServerEvent::Error {
                code: SESSION_CEILING_REASON.to_string(),
                message: format!(
                    "the session reached its configured ceiling of {ceiling_secs} s (streams.session_max_secs)"
                ),
            },
            &mut self.decode,
        )
    }

    /// A FRAME FROM THE FAR END, at `now_ms`. `serves` answers whether this session runs a named tool
    /// itself; the calls it does are returned beside the plan, in close order, to be run and handed
    /// back through [`Self::tool_executed`].
    pub fn on_server_frame(
        &mut self,
        frame: WireEvent,
        now_ms: u64,
        sink: &mut dyn TurnSink,
        serves: &dyn Fn(&str) -> bool,
    ) -> (Outbound, Vec<ToolRun>) {
        let mut out = Outbound::default();
        let mut to_exec: Vec<ToolRun> = Vec::new();
        let events = self.codec.read_down(frame, &mut self.decode);
        for ev in events {
            if matches!(ev, IrServerEvent::Error { .. }) {
                self.settle_turn(sink, None, &mut out);
            }
            match ev {
                IrServerEvent::Usage(u) => self.settle_turn(sink, Some(&u), &mut out),
                IrServerEvent::SpeechStarted { item_id, .. } => {
                    let heard_ms = self.decode.flush_playback();
                    out.push_up(self.codec.write_up(
                        IrClientEvent::Control(IrDuplexControl::ResponseCancel),
                        &mut self.decode,
                    ));
                    out.push_up(self.codec.write_up(
                        IrClientEvent::Control(IrDuplexControl::ItemTruncate {
                            item_ref: item_id.clone(),
                            content_index: 0,
                            audio_played_ms: heard_ms,
                        }),
                        &mut self.decode,
                    ));
                    out.downlink.extend(self.codec.write_down(
                        IrServerEvent::SpeechStarted {
                            item_id,
                            audio_start_ms: 0,
                        },
                        &mut self.decode,
                    ));
                }
                IrServerEvent::Tool(t) => {
                    let call_ref = t.call_ref();
                    match t {
                        IrDuplexTool::CallOpen { call_id, name, .. } => {
                            self.turn.open_tool_call();
                            let e = self.calls.entry(call_ref).or_default();
                            e.call_id = call_id;
                            e.name = name;
                        }
                        IrDuplexTool::CallArgs {
                            call_id,
                            json_delta,
                            ..
                        } => {
                            let e = self.calls.entry(call_ref).or_default();
                            if e.call_id.is_empty() {
                                e.call_id = call_id;
                            }
                            e.args.extend_from_slice(&json_delta);
                        }
                        IrDuplexTool::CallClose { call_id, .. } => {
                            let e = self.calls.entry(call_ref).or_default();
                            if e.call_id.is_empty() {
                                e.call_id = call_id;
                            }
                            e.closed = true;
                            if !e.executed {
                                e.executed = true;
                                match &self.governed {
                                    Some(g) if !serves(&e.name) => {
                                        g.calls.planned(g.session, &e.call_id, now_ms);
                                    }
                                    _ => to_exec.push(ToolRun {
                                        call_ref,
                                        call_id: e.call_id.clone(),
                                        name: e.name.clone(),
                                        args: e.args.clone(),
                                    }),
                                }
                            }
                        }
                        IrDuplexTool::CallResult { .. } => {}
                    }
                }
                ev @ (IrServerEvent::AudioFrame(_)
                | IrServerEvent::AudioDone { .. }
                | IrServerEvent::SpeechStopped { .. }
                | IrServerEvent::SessionCreated { .. }
                | IrServerEvent::Error { .. }) => {
                    out.downlink
                        .extend(self.codec.write_down(ev, &mut self.decode));
                }
                IrServerEvent::RateLimits => {}
            }
        }
        (out, to_exec)
    }

    /// A tool this session ran answered `output`: the result goes to the far end, then a request for
    /// the model's next response.
    pub fn tool_executed(&mut self, run: ToolRun, output: Vec<u8>, out: &mut Outbound) {
        out.push_up(self.codec.write_up(
            IrClientEvent::Tool(IrDuplexTool::CallResult {
                call_ref: run.call_ref,
                call_id: run.call_id,
                name: run.name,
                output: Bytes::from(output),
            }),
            &mut self.decode,
        ));
        out.push_up(self.codec.write_up(
            IrClientEvent::Control(IrDuplexControl::ResponseCreate { response: None }),
            &mut self.decode,
        ));
    }

    /// A FRAME FROM THE CALLER. A `session.update` is replaced by the locked config; a tool reply is
    /// carried only when the node's table has the call open; uplink audio is counted; everything
    /// else is written through to the far end.
    pub fn on_client_frame(&mut self, frame: WireEvent) -> Outbound {
        let mut out = Outbound::default();
        let events = self.codec.read_up(frame, &mut self.decode);
        for ev in events {
            match ev {
                IrClientEvent::Control(IrDuplexControl::SessionConfigure { config }) => {
                    let effective = self.locked_config.clone().unwrap_or(config);
                    out.push_up(self.codec.write_up(
                        IrClientEvent::Control(IrDuplexControl::SessionConfigure {
                            config: effective,
                        }),
                        &mut self.decode,
                    ));
                }
                IrClientEvent::Tool(IrDuplexTool::CallResult {
                    call_ref,
                    call_id,
                    name,
                    output,
                }) if self.governed.is_some() => {
                    let replied = self
                        .governed
                        .as_ref()
                        .map(|g| g.calls.replied(g.session, &call_id));
                    match replied {
                        Some(Ok(())) => {
                            self.calls.remove(&call_ref);
                            out.push_up(self.codec.write_up(
                                IrClientEvent::Tool(IrDuplexTool::CallResult {
                                    call_ref,
                                    call_id,
                                    name,
                                    output,
                                }),
                                &mut self.decode,
                            ));
                            out.push_up(self.codec.write_up(
                                IrClientEvent::Control(IrDuplexControl::ResponseCreate {
                                    response: None,
                                }),
                                &mut self.decode,
                            ));
                        }
                        _ => out.refused_reply = true,
                    }
                }
                ev => {
                    if let IrClientEvent::AudioFrame(f) = &ev {
                        self.turn.admit_audio(self.audio_in, f.media.len());
                    }
                    out.push_up(self.codec.write_up(ev, &mut self.decode));
                }
            }
        }
        out
    }

    /// Close the open turn: its usage and counters go to `sink`; a sink that refuses to continue
    /// cuts the session (the far end is told to stop responding, and the plan closes).
    fn settle_turn(
        &mut self,
        sink: &mut dyn TurnSink,
        usage: Option<&IrDuplexUsage>,
        out: &mut Outbound,
    ) {
        let counters = self.turn.close();
        if !sink.turn_closed(usage, counters) {
            out.push_up(self.codec.write_up(
                IrClientEvent::Control(IrDuplexControl::ResponseCancel),
                &mut self.decode,
            ));
            out.close = true;
        }
    }

    /// The session ends with a turn open: the turn's counters settle, once. A turn with nothing
    /// counted settles nothing.
    pub fn settle_open_turn(&mut self, sink: &mut dyn TurnSink) {
        if self.turn.is_empty() {
            return;
        }
        let mut out = Outbound::default();
        self.settle_turn(sink, None, &mut out);
    }
}

#[cfg(test)]
#[path = "tests/session_pump_tests.rs"]
mod tests;
