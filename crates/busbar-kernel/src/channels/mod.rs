// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared upstream channels: one long-lived stdio child or held HTTP request shared by many plane sessions, and the session signal registry (IF §12.19). The attachment side is real; the stdio/HTTP carrier driver (spawn, framing, demux) builds a `Link` per generation and calls `Attachment::linked` (W1-K8A).

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::records::Records;

use crate::plugin_records::RecordsDenied;
use crate::upstreams::UpstreamDef;
use link::Link;
use std::sync::Arc;
use tokio::sync::mpsc;

pub mod ask_line;
pub mod budget;
#[cfg(test)]
mod budget_tests;
pub mod carrier;
#[cfg(test)]
mod carrier_tests;
pub mod frame;
#[cfg(test)]
mod frame_tests;
pub mod line_carriers;
pub mod link;
pub mod protected;
#[cfg(test)]
mod protected_tests;
pub mod respawn;
pub mod signals;
pub mod stdio;
#[cfg(test)]
mod stdio_tests;
#[cfg(test)]
mod tests;

/// One long-lived upstream connection shared by many plane sessions: a stdio child (CARRIER_STDIO) or a held
/// HTTP request (CARRIER_HTTP, e.g. legacy MCP SSE). Key = (plane plugin, plane instance name, upstream name,
/// channel key, subject hash if CH_PER_CALLER). Core owns spawn/connect, framing (CH_FRAME_*), writes (in
/// arrival order; with CH_SERIAL one outstanding ask at a time), the generation counter (a dead child or
/// dropped request ends the generation: every attached session gets P_ERROR on its exchange), idle close
/// (`UpstreamDef.command.idle_s`, default 300 s) and the greet hand-off. Inbound messages are framed by core,
/// passed to the plane's sessionless `demux`, and delivered to the session holding that slot; slot 0 is dropped
/// (audited at debug) and DX_RESIGHT schedules a sighting probe.
/// **Round 18, routes by role (§8.6 DemuxRec, MSG_ASK).** Per channel generation core keeps the **ask line**: an
/// attachment enters it (in write order) with each EX_MSG carrying MSG_ASK and leaves on the DEMUX with DX_FINAL to
/// its slot, its detach, or the generation's end; under CH_SERIAL only the line's head is written and the rest wait,
/// and an EX_MSG without MSG_ASK (a reply to the member's own request, a notification) is written at once, so a
/// caller's answer to a member ask never queues behind the call that is waiting for it. DX_OUTSTANDING delivers to
/// the line's head as piece(FROM_UPSTREAM, its exchange, P_TEXT|P_FIN, message), leaving its ask open; on an empty
/// line core writes the DEMUX tail (the plane's protocol refusal) to the channel, or drops and counts
/// `plane_channel_unattributed_total` when there is none. DX_BROADCAST hands the message to `SessionSignals::signal`
/// with the instance, the key, the channel's subject (CH_PER_CALLER) and P_SIGNAL | P_TEXT. The reader task never
/// blocks on a session: every delivery is a `try_send` on the session's bounded channel.
/// **Respawn and trip (round 6; today's transport-stdio supervisor.rs, moved into core with the carrier):** a
/// child that exits or cannot be spawned ends its generation; the next attach respawns it no sooner than
/// 100 ms × 2^(n−1) after the n-th end counted inside a sliding 60 s window (100, 200, 400, 800 ms; schedule
/// from `backon::ExponentialBuilder`, no hand-rolled clock math); the 5th end inside 60 s **trips** the channel:
/// attaches fail at once with RecordsDenied::Unavailable (the session's exchange gets P_ERROR), audited
/// `upstream_child_tripped`, until the upstream is declared anew (config reload or admin reconfigure of that
/// upstream). Counters are per channel key and survive generations, not process restarts. The child starts in
/// `StdioCommand.cwd` with exactly `argv` and the resolved `env`; a `LocalProgram` pin is checked against the
/// spawned path before the first byte is written.
pub trait UpstreamChannels: Send + Sync + 'static {
    /// Attach `exchange` of the calling session. Returns the attachment (generation, slot, greet, ready tail)
    /// and the receiver of its demuxed inbound messages. Waits (bounded by the session deadline) while another
    /// session holds the greet of a fresh generation.
    fn attach<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        upstream: &'a UpstreamDef,
        req: ChannelReq<'a>,
    ) -> BoxFut<'a, Result<Attachment, RecordsDenied>>;
}
pub struct ChannelReq<'a> {
    pub exchange: u32,
    pub carrier: u32,
    pub flags: u32,
    pub framing: u32,
    pub key: &'a str,
    pub subject: Option<[u8; 32]>,
    pub head: Records<'a>,
}
/// Owned by the session's task. `send` = EX_MSG on the exchange; `ready` = CH_READY (greeting session only);
/// Drop detaches (and hands a pending greet to the next waiter).
pub struct Attachment {
    pub generation: u64,
    pub slot: u64,
    pub greet: bool,
    pub ready_tail: Box<[u8]>,
    rx: mpsc::Receiver<ChannelMsg>,
    link: Arc<Link>,
}
impl Attachment {
    /// Built by the carrier driver for each attach: `rx` carries the slot's demuxed inbound messages.
    #[must_use]
    pub fn linked(
        link: Arc<Link>,
        generation: u64,
        slot: u64,
        greet: bool,
        ready_tail: Box<[u8]>,
        rx: mpsc::Receiver<ChannelMsg>,
    ) -> Self {
        link.attach();
        Self {
            generation,
            slot,
            greet,
            ready_tail,
            rx,
            link,
        }
    }
    /// Round 18: `ask` = the EX_MSG carried MSG_ASK (enters the ask line; under CH_SERIAL waits its turn).
    pub fn send<'a>(
        &'a mut self,
        message: &'a [u8],
        ask: bool,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            self.link
                .send(self.slot, message, ask)
                .map_err(|()| RecordsDenied::Unavailable)
        })
    }
    pub fn ready(&mut self, tail: &[u8]) {
        if self.greet {
            self.link.ready(tail);
        }
    }
    pub fn recv(&mut self) -> BoxFut<'_, Option<ChannelMsg>> {
        Box::pin(async move { self.rx.recv().await.or(Some(ChannelMsg::Ended)) })
    }
}
pub enum ChannelMsg {
    Message(Box<[u8]>),
    Ended,
}
/// Round 18 (K8): the DETACH-key registry SIGNAL already uses, shared with `UpstreamChannels` for DX_BROADCAST.
pub trait SessionSignals: Send + Sync + 'static {
    /// Delivers `bytes` as piece(FROM_CORE, 0, flags, bytes) to every live session of plane instance `instance`
    /// registered under `key` by DETACH (only those of `subject` when it is Some), at most `plane::MAX_FANOUT`, each
    /// by `try_send` on its bounded session channel (full = dropped for that session, `plane_signal_dropped_total`).
    /// Returns how many accepted. Never blocks, never names a session to the plane. Round 20: the registry is
    /// in-process (one per gateway process); it is never replicated through the store, and no contract may
    /// rely on a SIGNAL or a DX_BROADCAST reaching another replica (§8.6 SignalRec, §16.159).
    fn signal(
        &self,
        instance: u64,
        key: &[u8],
        subject: Option<[u8; 32]>,
        flags: u32,
        bytes: &[u8],
    ) -> u32;
}

impl Drop for Attachment {
    fn drop(&mut self) {
        self.link.detach(self.slot, self.greet);
    }
}
