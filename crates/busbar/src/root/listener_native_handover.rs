// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hand-over of an admitted upgrade request (§12.27 steps 2 to 5): the one seam between
//! admission, which is the listener's, and the carrier that takes the stream, which is the
//! websocket transport's. Admission's part ends before this file: everything through money
//! happened on the HTTP head, through the data admission.

use std::sync::Arc;

use busbar_kernel::inbound::native::StreamOwner;

use super::InputError;
use crate::root::min3_boot::transports::ServedTransport;

// ---------------------------------------------------------------------------------------------
// THE HAND-OVER ITSELF (owner decision 18). What follows is the carrier side of an admitted
// upgrade: the caller's side of the plane session before and after the 101, and the adoption of
// the connection by the websocket transport. Nothing here admits anything: the request reached
// this file through the data admission (`listener_native_upgrade.rs`), unit and money included.
// ---------------------------------------------------------------------------------------------

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError, Weak};
use std::task::{Context, Poll};

use busbar_core_connector::framed_stream::session::{self, Feed, Inbound, TransportConn, Wiring};
use busbar_kernel::inbound::native::AcceptedConnection;
use busbar_kernel::inbound::request_snapshot::ChargedRequestSnapshot;
use busbar_kernel::plane_driver::port_duplex::{
    ClientEvent, ClientMessages, Ending, SWITCHING_PROTOCOLS,
};
use busbar_kernel::plane_driver::port_session::{ClientSink, ToClient};
use busbar_kernel::plane_driver::HeadFields;
use busbar_plugin_abi::records::{tag, U32Rec, Writer};
use busbar_plugin_abi::transport::{CONN_UPGRADED, ROLE_SERVER};
use busbar_ports::transport::ConnIn;
use tokio::sync::{mpsc, oneshot};

use super::NativeLimits;

/// The protocol an upgrade route's connection is handed to (§12.27).
pub(crate) const WEBSOCKET: &str = "websocket";

/// The stream a session begun with CONN_UPGRADED serves (transport kind, `ConnInfo.head`).
pub(crate) const ADOPTED_STREAM: u64 = 1;

/// The caller's messages the listener holds for the plane session at one time. One: the session
/// reads the caller no faster than its plane (and through it the far end) takes what was read.
const CALLER_QUEUE: usize = 1;

/// The largest head a CONN_UPGRADED `begin` is handed (the request's head and the plane's pairs).
const ADOPTED_HEAD_MAX: usize = 64 * 1024;

/// The message flags (`MSG_*`) of each data frame of a switched answer's body, in frame order.
/// The response body is HTTP's (`http_body::Frame` has data and trailers, nothing else), so what
/// a frame is of its message rides beside it: the sink states it as it hands the frame over and
/// the response's piece producer (`listener_native_response.rs`) takes it as it reads the frame.
#[derive(Default)]
pub(crate) struct MessageKinds(Mutex<VecDeque<u32>>);

impl MessageKinds {
    fn state(&self, flags: u32) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(flags);
    }

    /// The flags of the next data frame. `None` = a frame nobody stated: the producer is refused
    /// (a body frame of a switched answer that is not a message is never written).
    pub(crate) fn next(&self) -> Option<u32> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }
}

/// The latest end of the sessions of upgrade requests being prepared, by the stream owner of
/// their request ([`bound`]). An entry lives from the request's preparation to the making of its
/// caller's side (or to the next statement's sweep after its request ended). It is here for the
/// reason [`SWITCHING`] is: the path from the upgrade's preparation to the caller's side is the
/// data path's.
static BOUNDS: Mutex<Vec<(Weak<StreamOwner>, tokio::time::Instant)>> = Mutex::new(Vec::new());

/// THE LIMIT OF AN UPGRADED SESSION, stated once for the upgrade request `owner` carries, before
/// its data preparation: the session ends at `until` at the latest, whoever is still talking
/// (`listener_native_upgrade.rs` says how `until` is found). A second statement for one request
/// replaces the first only with an earlier time.
pub(crate) fn bound(owner: &Arc<StreamOwner>, until: tokio::time::Instant) {
    let mut bounds = BOUNDS.lock().unwrap_or_else(PoisonError::into_inner);
    // Requests that ended before their caller's side was made leave nothing behind.
    bounds.retain(|(held, _)| held.strong_count() > 0);
    let stated = bounds
        .iter_mut()
        .find(|(held, _)| held.upgrade().is_some_and(|live| Arc::ptr_eq(&live, owner)));
    match stated {
        Some((_, at)) => *at = (*at).min(until),
        None => bounds.push((Arc::downgrade(owner), until)),
    }
}

fn take_bound(owner: &Arc<StreamOwner>) -> Option<tokio::time::Instant> {
    let mut bounds = BOUNDS.lock().unwrap_or_else(PoisonError::into_inner);
    let at = bounds
        .iter()
        .position(|(held, _)| held.upgrade().is_some_and(|live| Arc::ptr_eq(&live, owner)))?;
    Some(bounds.swap_remove(at).1)
}

struct PipeState {
    /// The session reached its limit: the plane session is told the caller is gone, and nothing
    /// more is written for it.
    limited: bool,
    /// The plane committed with RESPOND(101).
    switched: bool,
    /// The plane wrote END for the caller.
    ended: bool,
    /// The item being offered to the HTTP side (at most one: its room is the body's one slot).
    offer: Vec<ToClient>,
    /// Where the caller's events are put, until the 101 hands it to the connection's supervisor (the pipe
    /// keeps no sender of its own after that: a supervisor that lets its sender go is a caller gone).
    to_plane: Option<mpsc::Sender<ClientEvent>>,
    /// Why the session ends, when the end is not the plane's own orderly one.
    cause: Option<Ending>,
}

/// THE CALLER'S SIDE OF AN UPGRADE REQUEST'S SESSION.
///
/// Before the plane commits it is the data path's own sink and nothing else: a head that is not
/// 101, its body and its end are an ordinary HTTP answer (the plane's refusal, the exhausted
/// walk's, a far end's error relayed), written before any 101. A head of 101 switches it: from
/// then on the session's MSG items are the answer's body, one data frame per message piece, each
/// with its flags stated beside it ([`MessageKinds`]); the caller's messages arrive through
/// [`ClientMessages`], fed by the connection's supervisor from the adopted transport session.
///
/// What it refuses (the session is then told the caller is gone, and its far end is let go): a
/// second 101; a message with no 101 before it; a body or trailers after a 101; anything after END.
///
/// THE SESSION'S LIMIT. An upgraded session whose plane states a ceiling is bounded by it
/// ([`bound`]); one whose plane states none has no limit here. At its limit the engine cuts
/// the caller's side, on whichever of its two faces the plane session is at: a session waiting
/// for the caller is woken and told the caller is gone ([`ClientEvent::Gone`]: "the engine cut
/// it"); a session writing to the caller has the item refused, which its relay reads the same
/// way. Either way the plane is told once, the far end is let go, and nothing more is written:
/// not a message, not the 101 of a session that would commit past its limit, and not the END (a
/// session cut at its limit did not end in order, so the adopted transport closes it as a
/// failure, never as a normal close). The answer's delivery then ends cut, and the unit settles
/// by the data path's own settlement on the usage the session last stated.
pub(crate) struct UpgradePipe {
    /// The session's latest end: its plane's stated ceiling. `None`: the plane states none (or no
    /// connection stands behind the pipe).
    until: Option<tokio::time::Instant>,
    /// The limit's timer, made the first time the plane session waits for the caller.
    alarm: Mutex<Option<std::pin::Pin<Box<tokio::time::Sleep>>>>,
    http: Arc<dyn ClientSink>,
    state: Mutex<PipeState>,
    kinds: Arc<MessageKinds>,
    from_caller: Mutex<mpsc::Receiver<ClientEvent>>,
    /// The plane's pairs on its RESPOND(101), kept for the adopting transport's `begin`.
    answered: Mutex<Option<HeadFields>>,
    /// Where the connection goes at the 101. `None` only for a pipe no connection stands behind.
    hand: Option<HandTo>,
}

/// What a committed upgrade's connection is handed over with.
pub(crate) struct HandTo {
    /// The websocket transport the connection is handed to.
    pub(crate) carrier: ServedTransport,
    /// The upgrade request's head, as the adopting transport is handed it.
    pub(crate) request: Arc<ChargedRequestSnapshot>,
    /// The carriers the route's chain read: never handed to the adopting transport either.
    pub(crate) withheld: Arc<[Box<str>]>,
    /// The stream owner of the upgrade request: what the connection's supervisor finds it by.
    pub(crate) owner: Arc<StreamOwner>,
}

/// The pairs of the upgrade request a second transport is handed: every pair but the carriers the
/// route's chain read and every client credential carrier (a credential is never handed on).
pub(crate) fn handed_on<'a>(
    pairs: impl Iterator<Item = (&'a str, &'a [u8])>,
    withheld: &'a [Box<str>],
) -> impl Iterator<Item = (&'a str, &'a [u8])> {
    pairs.filter(move |(name, _)| {
        !busbar_kernel::plane_driver::port::is_client_credential(name)
            && !withheld
                .iter()
                .any(|carrier| carrier.eq_ignore_ascii_case(name))
    })
}

impl UpgradePipe {
    /// The caller's side of an upgrade request's session, over the data path's sink `http`.
    ///
    /// Its session ends at the limit stated for the request ([`bound`]): its plane's stated
    /// ceiling. Where the plane states none, no borrowed number takes its place (owner decision):
    /// the session is bounded by the caller's budget and the connection's own liveness.
    pub(crate) fn new(http: Arc<dyn ClientSink>, hand: Option<HandTo>) -> Arc<Self> {
        let until = hand.as_ref().and_then(|hand| take_bound(&hand.owner));
        Self::bounded(http, hand, until)
    }

    /// As [`Self::new`], with the session's latest end given.
    pub(crate) fn bounded(
        http: Arc<dyn ClientSink>,
        hand: Option<HandTo>,
        until: Option<tokio::time::Instant>,
    ) -> Arc<Self> {
        let (to_plane, from_caller) = mpsc::channel(CALLER_QUEUE);
        Arc::new(Self {
            until,
            alarm: Mutex::new(None),
            http,
            state: Mutex::new(PipeState {
                limited: false,
                switched: false,
                ended: false,
                offer: Vec::new(),
                cause: None,
                to_plane: Some(to_plane),
            }),
            kinds: Arc::new(MessageKinds::default()),
            from_caller: Mutex::new(from_caller),
            answered: Mutex::new(None),
            hand,
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, PipeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the plane committed with RESPOND(101).
    pub(crate) fn switched(&self) -> bool {
        self.state().switched
    }

    /// Whether the session was cut at its limit.
    #[cfg(test)]
    pub(crate) fn limited(&self) -> bool {
        self.state().limited
    }

    /// Whether the session's limit has passed.
    fn past_limit(&self) -> bool {
        self.until
            .is_some_and(|until| tokio::time::Instant::now() >= until)
    }

    /// The flags of the switched answer's body frames, for the response's piece producer.
    pub(crate) fn kinds(&self) -> Arc<MessageKinds> {
        Arc::clone(&self.kinds)
    }

    /// Where the caller's events are put (the connection's supervisor holds it after the hand-over).
    #[cfg(test)]
    pub(crate) fn caller(&self) -> mpsc::Sender<ClientEvent> {
        self.state()
            .to_plane
            .take()
            .expect("the caller side is taken once")
    }

    /// The head the adopting transport's `begin` is handed (transport kind, `ConnInfo.head`): the
    /// upgrade request's H_METHOD, H_PATH, H_AUTHORITY and PAIR* (less the carriers the route's
    /// chain read), then H_STATUS(101) and the plane's RESPOND PAIR*.
    fn adopted_head(&self, hand: &HandTo) -> Result<Vec<u8>, InputError> {
        let answered = self
            .answered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(InputError::Invalid)?;
        let request = &hand.request;
        let mut head = busbar_plugin_abi::records::Reply::new();
        let full = |_| InputError::Capacity;
        head.put_text(tag::H_METHOD, request.method())
            .map_err(full)?;
        if request.query_present() {
            let mut target =
                String::with_capacity(request.path().len() + 1 + request.query().len());
            target.push_str(request.path());
            target.push('?');
            target.push_str(request.query());
            head.put_text(tag::H_PATH, &target).map_err(full)?;
        } else {
            head.put_text(tag::H_PATH, request.path()).map_err(full)?;
        }
        head.put_text(tag::H_AUTHORITY, request.authority())
            .map_err(full)?;
        for (name, value) in handed_on(request.headers(), &hand.withheld) {
            head.put_pair(tag::PAIR, name, value).map_err(full)?;
        }
        head.put_pod(
            tag::H_STATUS,
            &U32Rec {
                value: u32::from(SWITCHING_PROTOCOLS),
                _r: 0,
            },
        )
        .map_err(full)?;
        for (name, value) in &answered {
            let name = std::str::from_utf8(name).map_err(|_| InputError::Invalid)?;
            head.put_pair(tag::PAIR, name, value).map_err(full)?;
        }
        if head.as_bytes().len() > ADOPTED_HEAD_MAX {
            return Err(InputError::Capacity);
        }
        Ok(head.as_bytes().to_vec())
    }
}

impl ClientSink for UpgradePipe {
    fn poll_items(&self, cx: &mut Context<'_>, items: &mut Vec<ToClient>) -> Poll<bool> {
        let mut state = self.state();
        // A committed session past its limit is cut: what was offered and not taken, and
        // everything after it, is refused (the relay reads that as the caller gone).
        if state.switched && !state.limited && self.past_limit() {
            state.limited = true;
        }
        if state.limited {
            return Poll::Ready(false);
        }
        loop {
            if !state.offer.is_empty() {
                match self.http.poll_items(cx, &mut state.offer) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(false) => return Poll::Ready(false),
                    Poll::Ready(true) => state.offer.clear(),
                }
            }
            if items.is_empty() {
                return Poll::Ready(true);
            }
            if state.ended {
                // Nothing follows END.
                return Poll::Ready(false);
            }
            let offered = match items.remove(0) {
                ToClient::Head { status, fields } if status == SWITCHING_PROTOCOLS => {
                    if state.switched {
                        return Poll::Ready(false);
                    }
                    if self.past_limit() {
                        // A session is not committed past its limit: no 101 is written for it.
                        state.limited = true;
                        return Poll::Ready(false);
                    }
                    state.switched = true;
                    *self.answered.lock().unwrap_or_else(PoisonError::into_inner) =
                        Some(fields.clone());
                    // From here the connection's supervisor can find this session when the HTTP
                    // transport answers UPGRADE to the 101 it is about to be given.
                    if let Some(hand) = &self.hand {
                        if let Some(to_plane) = state.to_plane.take() {
                            announce(hand, to_plane, self.adopted_head(hand));
                        }
                    }
                    ToClient::Head { status, fields }
                }
                head @ ToClient::Head { .. } => {
                    if state.switched {
                        return Poll::Ready(false);
                    }
                    head
                }
                ToClient::Msg { flags, bytes } => {
                    if !state.switched {
                        // A message before any 101 has no wire to be written on.
                        return Poll::Ready(false);
                    }
                    self.kinds.state(flags);
                    ToClient::Body(bytes)
                }
                item @ (ToClient::Body(_) | ToClient::Trailers(_)) => {
                    if state.switched {
                        // After the 101 the answer is messages: a body is not one.
                        return Poll::Ready(false);
                    }
                    item
                }
                ToClient::End => {
                    state.ended = true;
                    if state.switched && state.cause.is_some() {
                        // Not the plane's orderly end (the far end failed): the answer is left
                        // without its END, which the adopted transport writes as its close for a
                        // failure (E_REFUSE: 1011), never as a normal close.
                        return Poll::Ready(false);
                    }
                    ToClient::End
                }
            };
            state.offer.push(offered);
        }
    }

    fn messages(&self) -> Option<&dyn ClientMessages> {
        Some(self)
    }
}

impl ClientMessages for UpgradePipe {
    fn poll_message(&self, cx: &mut Context<'_>) -> Poll<ClientEvent> {
        // The limit first: a caller that is still talking at the limit is cut all the same.
        if let Some(until) = self.until {
            if self.state().limited {
                return Poll::Ready(ClientEvent::Gone);
            }
            let reached = {
                let mut alarm = self.alarm.lock().unwrap_or_else(PoisonError::into_inner);
                let sleep = alarm.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(until)));
                std::future::Future::poll(sleep.as_mut(), cx).is_ready()
            };
            if reached {
                self.state().limited = true;
                return Poll::Ready(ClientEvent::Gone);
            }
        }
        let mut from_caller = self
            .from_caller
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match from_caller.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(event)) => Poll::Ready(event),
            // The supervisor let the session's sender go: the connection is over.
            Poll::Ready(None) => Poll::Ready(ClientEvent::Gone),
        }
    }

    fn ending(&self, cause: Ending) {
        self.state().cause = Some(cause);
    }
}

/// What the caller did, as the plane session is told it, from what the adopted transport session
/// handed up on its one stream.
pub(crate) fn event_of(inbound: Inbound) -> ClientEvent {
    match inbound {
        Inbound::Body {
            stream: ADOPTED_STREAM,
            flags,
            bytes,
        } => ClientEvent::Message {
            flags,
            bytes: bytes.as_slice().to_vec(),
        },
        // The caller's close frame, as the transport hands it up.
        Inbound::End(ADOPTED_STREAM) => ClientEvent::Closed,
        // A reset, a stall, or anything that is not this session's one stream: the caller's side
        // is over without an orderly close.
        Inbound::Body { .. }
        | Inbound::End(_)
        | Inbound::Head { .. }
        | Inbound::Trailers { .. }
        | Inbound::Reset { .. }
        | Inbound::Stalled(_) => ClientEvent::Gone,
    }
}

/// A committed upgrade waiting for its connection's hand-over.
struct Switching {
    owner: Weak<StreamOwner>,
    key: usize,
    to_plane: mpsc::Sender<ClientEvent>,
    carrier: ServedTransport,
    head: Result<Vec<u8>, ()>,
}

/// The committed upgrades whose connection has not been handed over yet, by the stream owner of
/// their request. An entry lives from the 101 item to the hand-over (or to the next commit's
/// sweep after its request ended): the connection's supervisor takes it when the HTTP transport
/// answers UPGRADE. It is here, and not passed along the response, because the response's path
/// from this request's preparation to the supervisor is the dispatch's and the delivery's.
static SWITCHING: Mutex<Vec<Switching>> = Mutex::new(Vec::new());

fn announce(hand: &HandTo, to_plane: mpsc::Sender<ClientEvent>, head: Result<Vec<u8>, InputError>) {
    let mut switching = SWITCHING.lock().unwrap_or_else(PoisonError::into_inner);
    // Requests that ended without a hand-over leave nothing behind.
    switching.retain(|entry| entry.owner.strong_count() > 0);
    switching.push(Switching {
        owner: Arc::downgrade(&hand.owner),
        key: Arc::as_ptr(&hand.owner) as usize,
        to_plane,
        carrier: hand.carrier.clone(),
        head: head.map_err(|_| ()),
    });
}

fn take_switching(owner: &Arc<StreamOwner>) -> Option<Switching> {
    let mut switching = SWITCHING.lock().unwrap_or_else(PoisonError::into_inner);
    let at = switching.iter().position(|entry| {
        entry.key == Arc::as_ptr(owner) as usize
            && entry
                .owner
                .upgrade()
                .is_some_and(|live| Arc::ptr_eq(&live, owner))
    })?;
    Some(switching.swap_remove(at))
}

/// The connection of `owner`'s request ended without a hand-over: a committed upgrade still
/// waiting for one is let go, so its plane session is told the caller is gone.
pub(crate) fn forget(owner: &Arc<StreamOwner>) {
    drop(take_switching(owner));
}

/// The connection after its hand-over: the websocket transport's session on the same socket,
/// begun and not yet driven. The supervisor drives it (`session::drive`) in place of the HTTP
/// session's task, with exactly these parts.
pub(crate) struct AdoptedConnection<S> {
    /// The websocket transport's session, begun with CONN_UPGRADED (its 101 is its begin answer).
    pub(crate) conn: TransportConn,
    /// The connection, unchanged.
    pub(crate) io: S,
    /// The operating-system progress reader, unchanged.
    pub(crate) progress: Arc<dyn busbar_contract::response_delivery::CarrierProgressReader>,
    /// The adopted session's wiring: the same delivery ledger (no counter reset), fresh queues.
    pub(crate) wiring: Wiring,
    /// What the adopted session hands up (the caller's messages, its close).
    pub(crate) inputs: mpsc::Receiver<Inbound>,
    /// Ends the adopted session by the engine's decision (`CR_*`).
    pub(crate) close: oneshot::Sender<u32>,
    /// Kept so the adopted session's queues stay open for its whole life: nothing is registered
    /// or fed on an adopted connection but its one upgraded answer.
    pub(crate) registrations: mpsc::Sender<session::RegisterResponse>,
    pub(crate) feeds: mpsc::Sender<Feed>,
    /// Where the caller's events go: the plane session's side.
    pub(crate) to_plane: mpsc::Sender<ClientEvent>,
}

/// THE ADOPT STEP (§12.27 step 3; delivery evidence E.5). The HTTP transport answered UPGRADE to
/// the 101 of the request one of `owners` carries: the connection, its byte counters, its
/// progress reader and the delivery entry of the upgraded answer go to the websocket transport,
/// which is begun with CONN_UPGRADED and the head, writes the 101 itself and serves the answer
/// as stream 1. The upgraded answer's feed goes with it: the pieces after the head are its
/// messages.
///
/// # Errors
/// No committed upgrade of this connection is waiting; the protocol named is not `websocket`; the
/// upgraded answer is not this connection's stream 1 (the delivery entry cannot be renamed yet);
/// the websocket transport refused `begin`. In every case nothing was written for the 101: the
/// connection is closed with its writer retired, the request is cancelled and its unit settles as
/// a cut answer.
pub(crate) fn adopt<S>(
    upgrade: Box<session::Upgrade<S>>,
    owners: &[Arc<StreamOwner>],
    facts: &AcceptedConnection,
    limits: &NativeLimits,
) -> Result<AdoptedConnection<S>, InputError> {
    fn refused<S>(
        upgrade: Box<session::Upgrade<S>>,
        error: InputError,
    ) -> Result<AdoptedConnection<S>, InputError> {
        // The exact writer is disposed before the failed delivery is frozen.
        session::Outcome::Upgraded(upgrade).retire();
        Err(error)
    }
    let Some(switching) = owners.iter().find_map(take_switching) else {
        return refused(upgrade, InputError::Invalid);
    };
    let Switching {
        to_plane,
        carrier,
        head,
        ..
    } = switching;
    let Ok(head) = head else {
        return refused(upgrade, InputError::Capacity);
    };
    if &*upgrade.protocol != WEBSOCKET
        || !carrier
            .port
            .protocols()
            .iter()
            .any(|protocol| protocol.as_ref() == WEBSOCKET)
        || !upgrade
            .feed
            .as_ref()
            .is_some_and(|(stream, _)| *stream == ADOPTED_STREAM)
    {
        return refused(upgrade, InputError::Invalid);
    }
    // `begin` first: the HTTP session still owns the answer until it returns OK.
    let begun = TransportConn::begin(
        carrier.port.clone(),
        &ConnIn {
            role: ROLE_SERVER,
            flags: CONN_UPGRADED,
            alpn: facts.alpn(),
            sni: facts.sni(),
            peer: facts.peer(),
            local: facts.local(),
            tls_peer_cert: facts.peer_certificate(),
            leftover: upgrade.leftover.as_slice(),
            head: &head,
            local_fingerprint: "",
            // The host clock the plugin's Host::mono_ns and WAKE_AT are stated on.
            mono_ns: busbar_plugin_abi::host_side::host_vt::vt::mono(),
        },
        limits.stall_ms,
        std::time::Instant::now(),
        upgrade.conn.storage().clone(),
    );
    let conn = match begun {
        Ok(conn) => conn,
        Err(ended) => return refused(upgrade, InputError::Transport(ended)),
    };
    let session::Upgrade {
        delivery,
        conn: http,
        io,
        feed,
        ..
    } = *upgrade;
    // The HTTP session is over: the adopting transport's `begin` returned OK.
    drop(http);
    let (mut ledger, progress) = delivery.into_parts();
    // The connection's delivery driver moves whole, counters and all, and is told so: the
    // upgraded answer is stream 1 of the adopting session, open from its `begin`, and the HTTP
    // session's SESSION statement ended with that session. Without this the adopting session's
    // own SESSION (stated in its `begin` answer, as every session's is) is `a second SESSION`
    // and the session faults on its first answer, after the 101 was decided.
    ledger.adopt(ADOPTED_STREAM);
    let (registrations, registered) = mpsc::channel(1);
    let (feeds, fed) = mpsc::channel(1);
    let (inbound, inputs) = mpsc::channel(1);
    let (close, closed) = oneshot::channel();
    let Some((_, pieces)) = feed else {
        return Err(InputError::Invalid);
    };
    // The upgraded answer's own pieces, on the stream the adopted session serves. The queue was
    // made just above with room for one: this cannot be refused.
    feeds
        .try_send(Feed {
            stream: ADOPTED_STREAM,
            pieces,
            opened: None,
        })
        .map_err(|_| InputError::Invalid)?;
    Ok(AdoptedConnection {
        conn,
        io,
        progress,
        wiring: Wiring {
            delivery: ledger,
            registrations: registered,
            feeds: fed,
            inbound,
            close: closed,
            write_timeout: limits.write_timeout,
            drain_grace: limits.drain_grace,
            counters: Arc::default(),
            read_holders: None,
        },
        inputs,
        close,
        registrations,
        feeds,
        to_plane,
    })
}

#[cfg(test)]
#[path = "tests/listener_native_handover.rs"]
mod tests;
