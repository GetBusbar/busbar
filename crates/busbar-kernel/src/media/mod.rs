// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Media rendezvous: RV_ACCEPT, UP_NEW(CARRIER_RTC) and RV_REMOTE over the datagram transport (IF §12.13),
//! kernel side (W1-K11). Core decides here: what a dial offers ([`Lines`], and [`resolve`] for the UP_NEW
//! PAIR* the plane task reads), that a dial whose opening says nothing is never dialled, and that an answered
//! leg mirrors what was offered. The connector carries: it binds the listener, begins the datagram session and
//! implements [`MediaCarrier`] and [`MediaLeg`]; [`Media`] puts core's rules in front of it.

mod opening;

pub use opening::{resolve, DialOpening, Lines};

use busbar_plugin_abi::host_side::caller::BoxFut;

use crate::plugin_records::RecordsDenied;

/// RENDEZVOUS(RV_ACCEPT), UP_NEW(CARRIER_RTC) and RENDEZVOUS(RV_REMOTE). Core picks the datagram listener
/// (`routes.<id>.media`, moved out of the plane's own config: plane-streaming `streams.media` becomes core route
/// config, handed over once by the plane's own `migrate` as CORE_CFG(ROUTE_MEDIA), §12.10), the datagram transport (by protocol "webrtc"), and the
/// session; it never tells the plane which transport or listener served it, nor the transport which plane asked.
pub trait MediaRendezvous: Send + Sync + 'static {
    /// A client's offer: bind/choose the listener, `TransportPort::begin(ROLE_DATAGRAM, CONN_ACCEPT)`,
    /// `event(Rendezvous(offer))`, return the transport's RENDEZVOUS text and a bridge that carries the media
    /// session's streams to the plane session as exchange `exchange` (FROM_CLIENT pieces, EX_MSG back).
    fn accept<'a>(
        &'a self,
        route: u32,
        offer: &'a str,
    ) -> BoxFut<'a, Result<(Box<str>, MediaBridge), RecordsDenied>>;
    /// An upstream dial (round 27: with its opening): `begin(ROLE_DATAGRAM, CONN_DIAL)` with `ConnInfo.head` =
    /// `opening` (nested PAIR* records, `media` = <kind> lines then `channel` = <label> lines, ≥ 1; empty or any
    /// other name = `Invalid`, never dialled); returns the local offer and the bridge (FROM_UPSTREAM). The bridge
    /// keeps `opening` and refuses, in `remote`, an answered leg that does not mirror it.
    fn dial<'a>(
        &'a self,
        route: u32,
        opening: &'a [u8],
    ) -> BoxFut<'a, Result<(Box<str>, MediaBridge), RecordsDenied>>;
}

/// One media session's leg as the connector's session task holds it (today's `Pairing` and its `Bridge`).
/// Dropping it drops the TransportSession.
pub trait MediaLeg: Send + Sync + 'static {
    /// An accepted leg: wait until the caller's lines have settled (today's `Pairing::wait_opening`), then its
    /// media kinds in line order and its channel labels in the order the caller opened them. A closed leg =
    /// `Unavailable`.
    fn settled(&self) -> BoxFut<'_, Result<Lines, RecordsDenied>>;
    /// A dialled leg: hand the far end's answer to the transport (`event(Rendezvous(description))`) and, once
    /// it has taken it, the answered leg's media kinds and channel labels.
    fn answer<'a>(&'a self, description: &'a str) -> BoxFut<'a, Result<Lines, RecordsDenied>>;
    /// Close the session now (core refused it).
    fn close(&self);
}

/// The connector's datagram carriers. `accept` binds the route's media listener and begins
/// `ROLE_DATAGRAM, CONN_ACCEPT` with the offer; `dial` begins `ROLE_DATAGRAM, CONN_DIAL` with `ConnInfo.head` =
/// `opening`, which core has already checked. Each answers the transport's RENDEZVOUS text and the leg.
pub trait MediaCarrier: Send + Sync + 'static {
    fn accept<'a>(
        &'a self,
        route: u32,
        offer: &'a str,
    ) -> BoxFut<'a, Result<(Box<str>, Box<dyn MediaLeg>), RecordsDenied>>;
    fn dial<'a>(
        &'a self,
        route: u32,
        opening: &'a [u8],
    ) -> BoxFut<'a, Result<(Box<str>, Box<dyn MediaLeg>), RecordsDenied>>;
}

/// Core's rendezvous over a connector's carriers: the only way a [`MediaBridge`] is made.
pub struct Media<C> {
    carrier: C,
}

impl<C: MediaCarrier> Media<C> {
    pub fn new(carrier: C) -> Self {
        Media { carrier }
    }
}

impl<C: MediaCarrier> MediaRendezvous for Media<C> {
    fn accept<'a>(
        &'a self,
        route: u32,
        offer: &'a str,
    ) -> BoxFut<'a, Result<(Box<str>, MediaBridge), RecordsDenied>> {
        let _ = (&self.carrier, route, offer);
        todo!()
    }

    fn dial<'a>(
        &'a self,
        route: u32,
        opening: &'a [u8],
    ) -> BoxFut<'a, Result<(Box<str>, MediaBridge), RecordsDenied>> {
        let _ = (&self.carrier, route, opening);
        todo!()
    }
}

/// Owned by the plane session's task (one owner, §11.3); dropping it drops the TransportSession.
pub struct MediaBridge {
    leg: Box<dyn MediaLeg>,
    /// A dialled bridge's opening: the lines its answered leg must mirror. `None` = an accepted (caller) leg.
    dialled: Option<Lines>,
    /// `remote`'s refusal text once it closed the session for not mirroring the opening.
    refused: Option<Box<str>>,
}

impl MediaBridge {
    /// Round 27. The opening that mirrors this accepted (RV_ACCEPT) caller leg, as `dial`'s `opening`: one `media`
    /// = <kind> per caller line in order, then one `channel` = <label> per caller data channel in the order the
    /// caller opened them (today's connector `Bridge::opening` + `caller_channels`, datagram.rs:2567-2577, :2601, kept).
    /// Waits until the caller's lines have settled (today's `wait_opening`, datagram.rs:2815-2842); a closed leg
    /// or one with no line and no channel = `Unavailable`. A dialled bridge answers `Invalid`.
    pub fn opening(&self) -> BoxFut<'_, Result<Box<[u8]>, RecordsDenied>> {
        let _ = (&self.leg, &self.dialled);
        todo!()
    }
    /// RV_REMOTE: the far end's answer for a dialled session. Round 27: once the transport has taken the answer,
    /// the answered leg's media lines must mirror the opening's `media` lines (same count, same kind at every
    /// position; today's `Bridge::mirrored`, datagram.rs:2580-2597, kept) and carry every opening `channel`;
    /// otherwise the dialled session is closed and `remote` returns `Invalid` (the plane gets P_RV_FAILED with a
    /// REFUSAL whose text is `mirrored`'s, e.g. "line 0 is `audio` on the caller's leg and `video` upstream").
    pub fn remote<'a>(&'a mut self, description: &'a str) -> BoxFut<'a, Result<(), RecordsDenied>> {
        let _ = (&self.refused, description);
        todo!()
    }
    /// The text of `remote`'s refusal (the P_RV_FAILED REFUSAL text), once it closed the session.
    pub fn refusal(&self) -> Option<&str> {
        todo!()
    }
}

#[cfg(test)]
mod tests;
