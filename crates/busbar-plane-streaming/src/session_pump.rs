// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SESSION PUMP: what one live session does with each frame, in both directions, sans I/O.
//!
//! A session's caller and far end speak the same dialect, so the pump is a RELAY (Law 5: "A RELAY
//! (same dialect) runs the reader only as that read-only tap and sends the client's bytes with
//! governed byte-level splices; a WRITER runs only when translating"). A frame from the far end
//! ([`SessionPump::on_server_frame`]) reaches the caller as the far end sent it; a frame from the
//! caller ([`SessionPump::on_client_frame`]) reaches the far end as the caller sent it, except
//! that a frame configuring the session, or asking for one response under its own settings, takes
//! the session's locked keys ([`crate::splice`]). The reader reads each frame only to meter it.
//!
//! Nothing here answers for the caller (Law 11): a tool call, a barge-in, an error reach the caller
//! as they came, and the caller acts on them. Nothing here sends, sleeps, reads a clock or holds a
//! key; the caller carries the plan and is told when a turn closes.
//!
//! What the pump holds for the session: the codec's decode state, the open turn's own counters (the
//! uplink audio admitted and the tool calls opened since the last turn closed, the two quantities no
//! usage report carries), and the locked session config.
//!
//! What it asks of its caller, through [`TurnSink`]: when a turn closes (a usage report, an error,
//! or the session ending with a turn open), the turn's usage and counters, and whether the session
//! stays open.

use crate::codec::ir::codec::{DecodeState, DuplexReader, DuplexWriter, WireEvent, WireRef};
use crate::codec::ir::config::SessionConfig;
use crate::codec::ir::control::IrDuplexControl;
use crate::codec::ir::event::{IrClientEvent, IrServerEvent};
use crate::codec::ir::media::AudioFormat;
use crate::codec::ir::tool::IrDuplexTool;
use crate::codec::ir::usage::IrDuplexUsage;
use crate::session::TurnCounters;
use crate::splice::{splice, LockedKeys};

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
}

/// Where a closed turn goes: its usage and its counters. The answer is whether the session may
/// continue; `false` closes it.
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

/// THE SESSION PUMP over the session's codec `C`.
#[derive(Debug)]
pub struct SessionPump<C> {
    codec: C,
    decode: DecodeState,
    turn: TurnCounters,
    /// The locked `session` config: its keys are spliced over a caller's own.
    locked_config: Option<SessionConfig>,
    /// The format uplink audio is counted in when a frame's wire states none: the locked config's
    /// input format, else the one the caller's session update states, else PCM16.
    audio_in: AudioFormat,
}

impl<C> SessionPump<C>
where
    C: DuplexReader + DuplexWriter + LockedKeys,
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
            turn: TurnCounters::default(),
            locked_config,
            audio_in,
        }
    }

    /// The error frame a session past its `ceiling_secs` ceiling is told before it closes, in its
    /// dialect; `None` when the dialect has no place to say so.
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

    /// The locked session as a frame that configures the far end: what a caller-side envelope that
    /// configures nothing itself (the telephony carrier) is translated into. `None` with no lock.
    pub fn locked_update(&mut self) -> Option<WireEvent> {
        let config = self.locked_config.clone()?;
        self.codec.write_up(
            IrClientEvent::Control(IrDuplexControl::SessionConfigure { config }),
            &mut self.decode,
        )
    }

    /// A FRAME FROM THE FAR END. It reaches the caller as the far end sent it: a tool call is part
    /// of the model's response and the caller runs it, a barge-in is the caller's to act on (Law 11;
    /// QUESTIONS Q98). The reader reads it only to meter: a usage report or an error closes the open
    /// turn, and a tool call the far end opens is counted.
    pub fn on_server_frame(
        &mut self,
        frame: WireEvent,
        _now_ms: u64,
        sink: &mut dyn TurnSink,
    ) -> Outbound {
        let mut out = Outbound::default();
        if frame.0.is_empty() {
            return out;
        }
        for ev in self
            .codec
            .read_down_ref(WireRef(&frame.0), &mut self.decode)
        {
            match ev {
                IrServerEvent::Usage(u) => self.settle_turn(sink, Some(&u), &mut out),
                IrServerEvent::Error { .. } => self.settle_turn(sink, None, &mut out),
                IrServerEvent::Tool(IrDuplexTool::CallOpen { .. }) => self.turn.open_tool_call(),
                _ => {}
            }
        }
        out.downlink.push(frame);
        out
    }

    /// A FRAME FROM THE CALLER. It reaches the far end as the caller sent it; uplink audio is
    /// counted; a frame that configures the session or asks for a response under its own settings
    /// takes the locked keys. A frame that is not JSON goes nowhere: the lock is judged on what
    /// the reader reads, and bytes it cannot read are never handed to a far end whose own reader
    /// might read them differently.
    pub fn on_client_frame(&mut self, frame: WireEvent) -> Outbound {
        let mut out = Outbound::default();
        if serde_json::from_slice::<serde::de::IgnoredAny>(&frame.0).is_err() {
            return out;
        }
        let mut configures = false;
        let mut responds = false;
        for ev in self.codec.read_up_ref(WireRef(&frame.0), &mut self.decode) {
            match ev {
                IrClientEvent::AudioFrame(f) => {
                    self.turn
                        .admit_audio(f.format.unwrap_or(self.audio_in), f.media.len());
                }
                IrClientEvent::Control(IrDuplexControl::SessionConfigure { config }) => {
                    configures = true;
                    let locked = self
                        .locked_config
                        .as_ref()
                        .and_then(|c| c.input_audio_format);
                    if let Some(fmt) = locked.or(config.input_audio_format) {
                        self.audio_in = fmt;
                    }
                }
                IrClientEvent::Control(IrDuplexControl::ResponseCreate { .. }) => responds = true,
                _ => {}
            }
        }
        let rule = match (&self.locked_config, configures, responds) {
            (Some(locked), true, _) => Some(self.codec.configure_rule(locked)),
            (Some(_), false, true) => self.codec.response_rule(),
            _ => None,
        };
        match rule {
            None => out.upstream.push(frame),
            Some(rule) => {
                if let Some(spliced) = splice(&frame.0, &rule) {
                    out.upstream.push(WireEvent(spliced.into()));
                }
            }
        }
        out
    }

    /// Close the open turn: its usage and counters go to `sink`; a sink that refuses to continue
    /// closes the session.
    fn settle_turn(
        &mut self,
        sink: &mut dyn TurnSink,
        usage: Option<&IrDuplexUsage>,
        out: &mut Outbound,
    ) {
        let counters = self.turn.close();
        if !sink.turn_closed(usage, counters) {
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
