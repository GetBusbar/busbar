// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Media rendezvous: RV_ACCEPT, UP_NEW(CARRIER_RTC) and RV_REMOTE over the datagram transport (IF §12.13). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K11 fills it.

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
/// Owned by the plane session's task (one owner, §11.3); dropping it drops the TransportSession.
pub struct MediaBridge {
    // W0-ABI: private fields (TransportSession owner channel, stream map) land with W1-K11.
    _stub: (),
}
impl MediaBridge {
    /// Round 27. The opening that mirrors this accepted (RV_ACCEPT) caller leg, as `dial`'s `opening`: one `media`
    /// = <kind> per caller line in order, then one `channel` = <label> per caller data channel in the order the
    /// caller opened them (today's connector `Bridge::opening` + `caller_channels`, datagram.rs:2567-2577, :2601, kept).
    /// Waits until the caller's lines have settled (today's `wait_opening`, datagram.rs:2815-2842); a closed leg
    /// or one with no line and no channel = `Unavailable`. A dialled bridge answers `Invalid`.
    pub fn opening(&self) -> BoxFut<'_, Result<Box<[u8]>, RecordsDenied>> {
        let _ = &self._stub;
        todo!()
    }
    /// RV_REMOTE: the far end's answer for a dialled session. Round 27: once the transport has taken the answer,
    /// the answered leg's media lines must mirror the opening's `media` lines (same count, same kind at every
    /// position; today's `Bridge::mirrored`, datagram.rs:2580-2597, kept) and carry every opening `channel`;
    /// otherwise the dialled session is closed and `remote` returns `Invalid` (the plane gets P_RV_FAILED with a
    /// REFUSAL whose text is `mirrored`'s, e.g. "line 0 is `audio` on the caller's leg and `video` upstream").
    pub fn remote<'a>(&'a mut self, description: &'a str) -> BoxFut<'a, Result<(), RecordsDenied>> {
        let _ = (&self._stub, description);
        todo!()
    }
}
