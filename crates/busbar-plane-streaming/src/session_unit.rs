// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE LIVE SESSION AS THE DRIVER SERVES IT, sans I/O: the session pump, the telephony carrier's
//! envelope where the session came in over the telephony door, the session's cumulative units and
//! its wall-clock ceiling.
//!
//! The driver pushes the caller's pieces ([`SessionUnit::from_caller`]) and the far end's
//! ([`SessionUnit::from_far_end`]); each answers a [`Plan`] of bytes for each side and whether the
//! session ends. Every closed turn adds to the session's cumulative units ([`SessionUnit::units`]),
//! which each answer reports; the kernel checkpoints them and decides a cut. The plane never cuts a
//! session on money: a cut is the kernel's, and it reaches the caller through the refusal render.

use bytes::Bytes;

use crate::codec::ir::codec::{DuplexReader, DuplexWriter, WireEvent};
use crate::codec::ir::config::SessionConfig;
use crate::codec::ir::usage::IrDuplexUsage;
use crate::codec::topology::twilio::{assert_g711_ulaw, TwilioEnvelope, TwilioError, TwilioEvent};
use crate::governed::GovernedSession;
use crate::meta;
use crate::session::{class_counts, TurnCounters};
use crate::session_pump::{SessionPump, TurnSink};
use crate::session_row::VoiceSessionRow;

/// The billable classes a session reports, in the tail's order (their index is the class a unit
/// count names).
pub const CLASSES: [busbar_contract::ids::MeterClassId; 6] = [
    meta::CLASS_AUDIO_TOKENS_IN,
    meta::CLASS_AUDIO_TOKENS_OUT,
    meta::CLASS_TEXT_TOKENS_IN,
    meta::CLASS_TEXT_TOKENS_OUT,
    meta::CLASS_AUDIO_SECONDS_IN,
    meta::CLASS_TOOL_CALLS,
];

/// The session's units so far, per class: every closed turn adds to them, and the session always
/// continues (the kernel owns the cut).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CumulativeUnits(pub [u64; 6]);

impl TurnSink for CumulativeUnits {
    fn turn_closed(&mut self, usage: Option<&IrDuplexUsage>, counters: TurnCounters) -> bool {
        for (class, n) in class_counts(usage, counters) {
            if let Some(i) = CLASSES.iter().position(|c| *c == class) {
                self.0[i] = self.0[i].saturating_add(n);
            }
        }
        true
    }
}

/// What one piece asks the driver to carry.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Frames bound for the far end, in order.
    pub to_far_end: Vec<Vec<u8>>,
    /// Frames bound for the caller, in order.
    pub to_caller: Vec<Vec<u8>>,
    /// The session ends after these frames.
    pub end: bool,
}

/// THE TELEPHONY CARRIER'S ENVELOPE around a session: the caller speaks Twilio Media Streams, the
/// far end the realtime dialect locked to `g711_ulaw` both ways, so the audio passes through
/// unchanged and only the envelope is rewritten.
#[derive(Debug, Default)]
pub struct TwilioBridge {
    stream_sid: Option<String>,
}

/// What one caller frame on the telephony door is.
#[derive(Debug, PartialEq, Eq)]
pub enum CallerStep {
    /// Caller audio, as the far end's dialect frames an uplink append.
    Audio(WireEvent),
    /// The call ended.
    Stop,
    /// The call is refused (no stream id, another media format, a frame not in Twilio's shape, a
    /// payload that is not clean base64): the session ends.
    Refused,
    /// Nothing for the far end (the handshake, a start, a mark, a keypress, an event this reader
    /// does not model, or media for another stream).
    Nothing,
}

impl TwilioBridge {
    /// Read one caller frame. A start with no stream id, or in another media format, is refused; so
    /// is a frame that is not Twilio's shape or carries a payload that is not clean base64 (data
    /// resuming after padding is never billed as a longer payload). An event this reader does not
    /// model is dropped.
    pub fn from_caller(&mut self, frame: &[u8]) -> CallerStep {
        match TwilioEnvelope::decode(frame) {
            Ok(TwilioEvent::Start(start)) => {
                if start.stream_sid.is_empty() || assert_g711_ulaw(&start.media_format).is_err() {
                    return CallerStep::Refused;
                }
                self.stream_sid = Some(start.stream_sid);
                CallerStep::Nothing
            }
            Ok(TwilioEvent::Media {
                stream_sid,
                payload,
            }) => {
                if stream_sid.is_empty() || self.stream_sid.as_deref() != Some(stream_sid.as_str())
                {
                    return CallerStep::Nothing;
                }
                let append = serde_json::json!({
                    "type": "input_audio_buffer.append",
                    "audio": busbar_contract::media::base64_encode(&payload),
                });
                CallerStep::Audio(WireEvent(Bytes::from(
                    serde_json::to_vec(&append).unwrap_or_default(),
                )))
            }
            Ok(TwilioEvent::Stop) => CallerStep::Stop,
            Ok(_) | Err(TwilioError::UnknownEvent(_)) => CallerStep::Nothing,
            Err(_) => CallerStep::Refused,
        }
    }

    /// Rewrite one frame bound for the caller into the carrier's envelope: model audio becomes a
    /// `media` frame on the call's stream, and a barge-in clears the audio the carrier has queued.
    /// `None` for a frame the carrier has no event for.
    #[must_use]
    pub fn to_caller(&self, frame: &[u8]) -> Option<Vec<u8>> {
        let sid = self.stream_sid.as_deref()?;
        let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
        match v.get("type").and_then(serde_json::Value::as_str)? {
            "response.output_audio.delta" | "response.audio.delta" => {
                let audio = busbar_contract::media::base64_decode(v.get("delta")?.as_str()?)?;
                Some(TwilioEnvelope::encode_media(sid, &audio))
            }
            "input_audio_buffer.speech_started" => serde_json::to_vec(&serde_json::json!({
                "event": "clear",
                "streamSid": sid,
            }))
            .ok(),
            _ => None,
        }
    }
}

/// ONE LIVE SESSION over the far end's codec `C`.
#[derive(Debug)]
pub struct SessionUnit<C> {
    pump: SessionPump<C>,
    /// The session's record: opened, its turn cursor, its provider call id, its end.
    row: VoiceSessionRow,
    /// Record writes not yet handed to the kernel, oldest first.
    writes: Vec<VoiceSessionRow>,
    units: CumulativeUnits,
    twilio: Option<TwilioBridge>,
    opened_ns: u64,
    ceiling_secs: Option<u64>,
    ended: bool,
}

impl<C> SessionUnit<C>
where
    C: DuplexReader + DuplexWriter,
{
    /// A session over `codec`, locked to `locked`, opened at `now_ns`, bounded by `ceiling_secs`.
    /// `telephony` puts the telephony carrier's envelope on the caller's side. `id` names the session
    /// and `owner` is the caller's reference (never the principal); the session's record is written
    /// at open.
    pub fn open(
        codec: C,
        locked: SessionConfig,
        telephony: bool,
        now_ns: u64,
        ceiling_secs: Option<u64>,
    ) -> Self {
        Self::open_as(codec, locked, telephony, now_ns, ceiling_secs, "", "")
    }

    /// [`Self::open`], naming the session `id` for `owner`.
    pub fn open_as(
        codec: C,
        locked: SessionConfig,
        telephony: bool,
        now_ns: u64,
        ceiling_secs: Option<u64>,
        id: &str,
        owner: &str,
    ) -> Self {
        let row = VoiceSessionRow {
            id: id.to_string(),
            owner: owner.to_string(),
            turns: 0,
            updated_at: now_ns / 1_000_000_000,
            terminal: false,
            rtc_call_id: None,
        };
        SessionUnit {
            writes: vec![row.clone()],
            row,
            pump: SessionPump::new(codec, Some(locked)),
            units: CumulativeUnits::default(),
            twilio: telephony.then(TwilioBridge::default),
            opened_ns: now_ns,
            ceiling_secs,
            ended: false,
        }
    }

    /// Bind the node's open-call table for this session.
    pub fn bind_governed(&mut self, governed: GovernedSession) {
        self.pump.bind_governed(governed);
    }

    /// The session's cumulative units, per class in [`CLASSES`] order.
    #[must_use]
    pub fn units(&self) -> CumulativeUnits {
        self.units
    }

    /// The record writes not yet handed to the kernel, oldest first; taking them clears them.
    pub fn take_writes(&mut self) -> Vec<VoiceSessionRow> {
        std::mem::take(&mut self.writes)
    }

    /// The provider named the session's call: it goes on the session's record.
    pub fn set_rtc_call_id(&mut self, rtc_call_id: &str, now_s: u64) {
        self.row.rtc_call_id = Some(rtc_call_id.to_string());
        self.row.updated_at = now_s;
        self.writes.push(self.row.clone());
    }

    /// `true` once the session has ended.
    #[must_use]
    pub fn ended(&self) -> bool {
        self.ended
    }

    fn caller_frames(&self, frames: Vec<WireEvent>) -> Vec<Vec<u8>> {
        frames
            .into_iter()
            .filter_map(|w| match &self.twilio {
                Some(bridge) => bridge.to_caller(&w.0),
                None => Some(w.0.to_vec()),
            })
            .collect()
    }

    /// A piece from the caller.
    pub fn from_caller(&mut self, bytes: &[u8]) -> Plan {
        if self.ended {
            return Plan::default();
        }
        let frame = match self.twilio.as_mut() {
            None => WireEvent(Bytes::copy_from_slice(bytes)),
            Some(bridge) => match bridge.from_caller(bytes) {
                CallerStep::Audio(w) => w,
                CallerStep::Stop | CallerStep::Refused => return self.end(),
                CallerStep::Nothing => return Plan::default(),
            },
        };
        let out = self.pump.on_client_frame(frame);
        Plan {
            to_far_end: out.upstream.into_iter().map(|w| w.0.to_vec()).collect(),
            to_caller: Vec::new(),
            end: false,
        }
    }

    /// A piece from the far end, at `now_ms`. No tool is served on this node: every call is relayed
    /// to the caller.
    pub fn from_far_end(&mut self, bytes: &[u8], now_ms: u64) -> Plan {
        if self.ended {
            return Plan::default();
        }
        let (out, _) = self.pump.on_server_frame(
            WireEvent(Bytes::copy_from_slice(bytes)),
            now_ms,
            &mut self.units,
            &|_: &str| false,
        );
        Plan {
            to_far_end: out.upstream.into_iter().map(|w| w.0.to_vec()).collect(),
            to_caller: self.caller_frames(out.downlink),
            end: false,
        }
    }

    /// The clock, at `now_ns` and `now_ms`: a session past its ceiling is told why and ends; the
    /// node's unanswered calls past their deadline are swept.
    pub fn tick(&mut self, now_ns: u64, now_ms: u64) -> Plan {
        if self.ended {
            return Plan::default();
        }
        self.pump.sweep_expired(now_ms);
        let Some(ceiling) = self.ceiling_secs else {
            return Plan::default();
        };
        if now_ns.saturating_sub(self.opened_ns) < ceiling.saturating_mul(1_000_000_000) {
            return Plan::default();
        }
        let told = self.pump.ceiling_error(ceiling);
        let mut plan = self.end();
        plan.to_caller = self.caller_frames(told.into_iter().collect());
        plan
    }

    /// The session ends: its open turn settles once, the node forgets its open calls, and the
    /// session's record is written terminal.
    pub fn end(&mut self) -> Plan {
        if !self.ended {
            self.ended = true;
            self.pump.settle_open_turn(&mut self.units);
            self.pump.forget_governed_calls();
            self.row.terminal = true;
            self.writes.push(self.row.clone());
        }
        Plan {
            end: true,
            ..Plan::default()
        }
    }
}

#[cfg(test)]
#[path = "tests/session_unit_tests.rs"]
mod tests;
