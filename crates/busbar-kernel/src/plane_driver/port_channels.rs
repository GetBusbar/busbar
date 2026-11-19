// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared upstream channels, `demux` and the tick over the plane port (IF §8.6, §12.19, §12.23; PLANE-DRIVER.md
//! slice 7).
//!
//! * CHANNEL and CH_READY intents are resolved by [`Resolver`](super::port_intents::Resolver) against a
//!   [`ChannelHost`]: an attached channel is delivered as `piece(FROM_CORE, exchange, P_CHANNEL, CH_ATTACH)` and
//!   held by the session's [`Task`] under its exchange (dropping the task detaches it); an attach that fails is
//!   `P_ERROR` with one REFUSAL on that exchange. [`UpstreamHost`] is the production host over
//!   [`UpstreamChannels`]; its calls are awaited on the session's task. A held channel is a trait object the
//!   session keeps by exchange, so its calls box their futures (CHANNEL routes only, never a plain request).
//! * [`demux`] is the sessionless `PlanePort::demux`: where one inbound channel message goes.
//! * [`decode_tick`] reads the `ADMIN_TICK` answer: PUSH and EMIT records only.
//!
//! The carrier driver that spawns the child, frames the stream and builds the generations is
//! [`crate::channels::carrier`]; the session loop that delivers what the channels receive is [`super::port_carrier`].
//! This file is the plane-facing half of both ([`PortDemuxer`] is the plane's `demux` for the carrier).

use std::collections::HashMap;
use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{tag as t, EmitRec, PushRec};
use busbar_plugin_abi::records::{RecErr, Records};
use busbar_ports::plane::{PlaneOut, PlanePort};
use busbar_ports::PortError;

use super::port_intents::Namespace;
use super::port_session::{Calls, Task};
use crate::channels::carrier::Demuxer;
use crate::channels::{Attachment, ChannelMsg, ChannelReq, UpstreamChannels};
use crate::plugin_records::RecordsDenied;
use crate::upstreams::UpstreamDef;

/// One channel a session holds. Dropping it detaches it (and hands a pending greet to the next waiter).
pub trait Held: Send {
    /// EX_MSG on the channel's exchange; `ask` = the message carried MSG_ASK (it enters the ask line).
    fn send<'a>(
        &'a mut self,
        message: &'a [u8],
        ask: bool,
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    /// CH_READY: `tail` is handed to later attachers (only the greeting session's takes effect).
    fn ready(&mut self, tail: &[u8]) -> Result<(), RecordsDenied>;
    /// RV_REMOTE: the far end's answer for a dialled media session (§12.13). Only a media bridge takes one; the
    /// default refuses.
    fn remote<'a>(&'a mut self, _description: &'a str) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(std::future::ready(Err(RecordsDenied::Invalid)))
    }
    /// Why the last `remote` was refused, in core's words (a mirror failure names the lines), if it says.
    fn refusal(&self) -> Option<String> {
        None
    }
    /// The next message from the far end, or the end of what this holds (`ChannelMsg::Ended`: a channel's generation
    /// ended, a media session closed). The default never resolves: a holder with nothing to say keeps its session
    /// alive and says nothing. Cancel safe: a dropped future loses nothing.
    fn recv(&mut self) -> BoxFut<'_, Option<ChannelMsg>> {
        Box::pin(std::future::pending())
    }
}

/// The channels of one session, by exchange.
pub type Channels = HashMap<u32, Box<dyn Held>>;

/// What a CHANNEL intent asks for (§8.6 ChanRec), as the host sees it.
pub struct ChannelAttach<'a> {
    pub exchange: u32,
    pub carrier: u32,
    pub flags: u32,
    pub framing: u32,
    pub key: &'a str,
    /// The request's verified subject scope, for `CH_PER_CALLER`.
    pub subject: Option<[u8; 32]>,
    /// The nested H_METHOD, H_PATH, PAIR* of a CARRIER_HTTP channel; empty otherwise.
    pub head: &'a [u8],
}

/// An attachment: the numbers `CH_ATTACH` carries, and the channel itself.
pub struct Attached {
    pub generation: u64,
    pub slot: u64,
    pub greet: bool,
    pub ready_tail: bytes::Bytes,
    pub held: Box<dyn Held>,
}

/// Attaches CHANNEL intents. `Sync`: the session's resolver borrows it across awaits.
pub trait ChannelHost: Sync {
    fn attach<'a>(
        &'a self,
        attach: &'a ChannelAttach<'a>,
    ) -> BoxFut<'a, Result<Attached, RecordsDenied>>;
}

impl<K: Calls + ?Sized> Task<'_, K> {
    /// Writes `message` to the channel held on `exchange`. `Ok(false)` = no channel is held there.
    pub async fn send_channel(
        &mut self,
        exchange: u32,
        message: &[u8],
        ask: bool,
    ) -> Result<bool, RecordsDenied> {
        match self.held.get_mut(&exchange) {
            Some(channel) => channel.send(message, ask).await.map(|()| true),
            None => Ok(false),
        }
    }
}

/// The attachment [`UpstreamHost`] hands a session.
struct Link {
    attachment: Attachment,
}

impl Held for Link {
    fn send<'a>(
        &'a mut self,
        message: &'a [u8],
        ask: bool,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(self.attachment.send(message, ask))
    }

    fn ready(&mut self, tail: &[u8]) -> Result<(), RecordsDenied> {
        self.attachment.ready(tail)
    }

    fn recv(&mut self) -> BoxFut<'_, Option<ChannelMsg>> {
        self.attachment.recv()
    }
}

/// The plane's `demux` as the carrier's [`Demuxer`]: a refused, failed or faulted call is logged and the message has
/// no slot (the port already handled the image).
pub struct PortDemuxer(Arc<dyn PlanePort>);

impl PortDemuxer {
    #[must_use]
    pub fn new(port: Arc<dyn PlanePort>) -> Self {
        Self(port)
    }
}

impl Demuxer for PortDemuxer {
    fn demux(&self, key: &str, message: &[u8]) -> Result<Option<Demuxed>, PortError> {
        demux(&*self.0, key, message)
    }
}

/// The production [`ChannelHost`]: [`UpstreamChannels`] under the plane instance's binding. `upstream_of` names
/// the configured upstream an exchange was sent to (the walk's choice); an exchange it does not know cannot attach.
pub struct UpstreamHost {
    pending: Option<Arc<super::port_admission::Pending>>,
    budget: Option<crate::channels::budget::UnitBudget>,
    channels: Arc<dyn UpstreamChannels>,
    who: Namespace,
    upstream_of: Box<dyn Fn(u32) -> Option<Arc<UpstreamDef>> + Send + Sync>,
}

impl UpstreamHost {
    #[must_use]
    pub fn new(
        channels: Arc<dyn UpstreamChannels>,
        who: Namespace,
        upstream_of: Box<dyn Fn(u32) -> Option<Arc<UpstreamDef>> + Send + Sync>,
    ) -> Self {
        Self {
            pending: None,
            budget: None,
            channels,
            who,
            upstream_of,
        }
    }
    pub fn with_budget(mut self, budget: Option<crate::channels::budget::UnitBudget>) -> Self {
        self.budget = budget;
        self
    }
    pub fn with_admission(mut self, pending: Option<Arc<super::port_admission::Pending>>) -> Self {
        self.pending = pending;
        self
    }

    pub(crate) fn command(
        &self,
    ) -> Result<Option<crate::channels::authority::ChannelAuthority>, RecordsDenied> {
        let Some(admitted) = self.pending.as_ref().and_then(|pending| pending.admitted()) else {
            return Ok(None);
        };
        if admitted.request.registered_command().is_none() {
            return Ok(None);
        }
        crate::channels::authority::ChannelAuthority::new(admitted.request.clone()).map(Some)
    }
}

impl ChannelHost for UpstreamHost {
    fn attach<'a>(
        &'a self,
        attach: &'a ChannelAttach<'a>,
    ) -> BoxFut<'a, Result<Attached, RecordsDenied>> {
        Box::pin(self.attached(attach))
    }
}

impl UpstreamHost {
    async fn attached(&self, attach: &ChannelAttach<'_>) -> Result<Attached, RecordsDenied> {
        let command = self.command()?;
        let upstream = if command.is_some() {
            self.pending
                .as_ref()
                .and_then(|pending| pending.admitted())
                .and_then(|admitted| admitted.request.registered_command())
                .cloned()
        } else {
            (self.upstream_of)(attach.exchange)
        }
        .ok_or(RecordsDenied::Invalid)?;
        let who = self.who.caller();
        let req = ChannelReq {
            command: command.as_ref(),
            budget: self.budget.as_ref().ok_or(RecordsDenied::Invalid)?,
            exchange: attach.exchange,
            carrier: attach.carrier,
            flags: attach.flags,
            framing: attach.framing,
            key: attach.key,
            subject: attach.subject,
            head: Records::new(attach.head),
        };
        let attachment = self.channels.attach(&who, &upstream, req).await?;
        Ok(Attached {
            generation: attachment.generation,
            slot: attachment.slot,
            greet: attachment.greet,
            ready_tail: attachment.ready_tail.clone(),
            held: Box::new(Link { attachment }),
        })
    }
}

/// Where one inbound channel message goes (§8.6 DemuxRec): `slot` ≠ 0 to that attachment, else by `flags`
/// (DX_OUTSTANDING with `tail` as its fallback, DX_BROADCAST with `tail` as the key, DX_FINAL, DX_RESIGHT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Demuxed {
    pub slot: u64,
    pub flags: u32,
    pub tail: Vec<u8>,
}

/// `PlanePort::demux`: the plane's answer for one framed inbound `message` on channel `key`. `None` = the plane
/// wrote no DEMUX, which is slot 0 (dropped and audited at debug). The adapter has already refused every
/// combination §8.6 forbids.
///
/// # Errors
/// The plane refused, failed or faulted; the port handled the image.
pub fn demux(
    port: &dyn PlanePort,
    key: &str,
    message: &[u8],
) -> Result<Option<Demuxed>, PortError> {
    let mut found = None;
    port.demux(key, message, &mut |out| {
        if let PlaneOut::Demux { slot, flags, tail } = out {
            found = Some(Demuxed {
                slot,
                flags,
                tail: tail.to_vec(),
            });
        }
    })?;
    Ok(found)
}

/// What an `ADMIN_TICK` answer asks core to do, in answer order within each list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickOut {
    /// (ttl_s, the nested push records) for the push queue.
    pub pushes: Vec<(u64, Vec<u8>)>,
    /// (carrier, bytes) for `LineCarriers::emit_from_plane`.
    pub emits: Vec<(u64, Vec<u8>)>,
}

/// Reads the answer of `admin(ADMIN_TICK)`. The adapter admits PUSH and EMIT only; anything else here is a core
/// bug and is skipped.
///
/// # Errors
/// The bytes do not frame as records.
pub fn decode_tick(answer: &[u8]) -> Result<TickOut, RecErr> {
    let mut out = TickOut::default();
    for rec in Records::new(answer) {
        let rec = rec?;
        match rec.tag {
            t::PUSH => {
                let (push, nested) = rec.pod_tail::<PushRec>()?;
                out.pushes.push((push.ttl_s, nested.to_vec()));
            }
            t::EMIT => {
                let (emit, bytes) = rec.pod_tail::<EmitRec>()?;
                out.emits.push((emit.carrier, bytes.to_vec()));
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "tests/port_channels_tests.rs"]
mod tests;
