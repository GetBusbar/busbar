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
use crate::codec::topology::twilio::{CallerStep, TwilioBridge};
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

/// What one piece asks the driver to carry. Every frame a session emits, to either side, is one
/// TEXT message ([`FRAMES_ARE_TEXT`]): the realtime dialects and the telephony envelope are JSON
/// events. What arrives may be either: Gemini Live's server sends its JSON in binary frames, and a
/// frame is read by its bytes, not its opcode.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Frames bound for the far end, in order.
    pub to_far_end: Vec<Vec<u8>>,
    /// Frames bound for the caller, in order.
    pub to_caller: Vec<Vec<u8>>,
    /// The session ends after these frames.
    pub end: bool,
}

/// Every frame a session emits is one text message: the door sets the text bit on each.
pub const FRAMES_ARE_TEXT: bool = true;

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
