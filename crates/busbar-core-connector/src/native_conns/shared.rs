// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MANY REQUESTS ON ONE CONNECTION, OWNED BY ONE CORE.
//!
//! v1.5.5 shared one HTTP/2 connection among its requests; 1.6.0 lent a connection to one
//! exchange at a time, so every concurrent request paid a socket and a handshake. This is the
//! sharing, in two pieces:
//!
//! * [`Shared`]: one connection carried by several exchanges. There is no task and no channel per
//!   connection. Whichever exchange is polled drives it: it reads the socket, feeds the
//!   transport, takes its own pieces, and wakes the readers of the streams whose pieces it
//!   parked. Each stream keeps its reader's waker; when the driving exchange leaves, one waiting
//!   reader is woken to take over. Everything is on one core, so the lock is never contended and
//!   is never held across a wait.
//! * [`InUse`]: the core's connections in use, per key, with what is known of each key
//!   (`crate::outbound::lend`). An entry lives while its key has a connection or a dial, and is
//!   removed with the last of them: no table that grows.
//!
//! DECLARED by `native_conns.rs`: `State::Shared` is a stream on a shared connection, each core's
//! set (`CoreIdle::in_use`) holds the connections in use, `open_native` asks `lend_stream` before
//! the idle set, and the read wrapper calls `Exchange::share` once a session states that it
//! multiplexes.

use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use busbar_contract::conn::Piece;
use foldhash::{HashMap, HashMapExt as _};

use super::{Exchange, State};
use crate::conns::native_dial::{NativeConnection, NativeFailure, NativeHead};
use crate::conns::pool::PoolKey;
use crate::outbound::lend::{self, KeyEntry, Lend};
use crate::outbound::records::Session;

/// One connection carried by several exchanges on one core.
pub(crate) struct Shared {
    conn: Mutex<NativeConnection>,
    /// Since when the connection has carried no stream; `None` while it carries one. A shared connection
    /// with no stream is the kept connection of its key: it serves the next open, and is dropped from
    /// its core's set (and so closed) once it has idled past the deployment's idle timeout.
    idle_since: Mutex<Option<std::time::Instant>>,
    /// The waker of each stream's reader that found nothing, by stream.
    readers: Mutex<Vec<(u64, Waker)>>,
}

impl Shared {
    /// A connection, shared from now on.
    pub(crate) fn new(conn: NativeConnection) -> Arc<Self> {
        Arc::new(Self {
            conn: Mutex::new(conn),
            readers: Mutex::new(Vec::new()),
            idle_since: Mutex::new(None),
        })
    }

    /// Run `with` on the connection. Never held across a wait: every caller is a poll.
    pub(crate) fn with<T>(&self, with: impl FnOnce(&mut NativeConnection) -> T) -> T {
        let mut conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        with(&mut conn)
    }

    /// Whether the connection has carried no stream for `timeout` or longer at `now`.
    pub(crate) fn idle_past(&self, now: std::time::Instant, timeout: std::time::Duration) -> bool {
        self.idle_since
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some_and(|since| now.saturating_duration_since(since) >= timeout)
    }

    fn mark_idle(&self, idle: bool) {
        let mut since = self
            .idle_since
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match (idle, since.is_some()) {
            (true, false) => *since = Some(std::time::Instant::now()),
            (false, true) => *since = None,
            _ => {}
        }
    }

    /// What the connection has said about taking streams.
    pub(crate) fn in_use(&self) -> lend::InUse {
        self.with(|conn| conn.lending())
    }

    /// Wake the readers of the streams that now have a piece waiting (or everyone, when the
    /// connection failed or ended), other than `driver`. Called with no lock held by the caller.
    fn wake_others(&self, driver: u64) {
        let ready: Vec<Waker> = {
            let conn = self
                .conn
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let over = conn.cause().is_some() || !conn.live();
            let mut readers = self
                .readers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut woken = Vec::new();
            readers.retain(|(stream, waker)| {
                if *stream != driver && (over || conn.has_piece(*stream)) {
                    woken.push(waker.clone());
                    false
                } else {
                    true
                }
            });
            woken
        };
        for waker in ready {
            waker.wake();
        }
    }

    fn keep_reader(&self, stream: u64, waker: &Waker) {
        let mut readers = self
            .readers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match readers.iter_mut().find(|(id, _)| *id == stream) {
            Some((_, kept)) if kept.will_wake(waker) => {}
            Some((_, kept)) => kept.clone_from(waker),
            None => readers.push((stream, waker.clone())),
        }
    }

    fn forget_reader(&self, stream: u64) {
        self.readers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(id, _)| *id != stream);
    }

    /// Open one exchange on the connection (`NativeConnection::poll_send_head`). On a session
    /// that answered `STREAM_BUSY` the failure says so and the head's sealed values come back
    /// through `NativeConnection::take_handed_back`: the exchange offers them elsewhere.
    pub(crate) fn poll_send_head(
        &self,
        cx: &mut Context<'_>,
        head: &mut Option<NativeHead>,
        body_follows: bool,
    ) -> Poll<Result<u64, NativeFailure>> {
        let sent = self.with(|conn| conn.poll_send_head(cx, head, body_follows));
        if matches!(sent, Poll::Ready(Ok(_))) {
            self.mark_idle(false);
        }
        // The head's bytes moved the socket: streams that got pieces meanwhile are woken.
        self.wake_others(0);
        sent
    }

    /// One body piece of `stream`.
    pub(crate) fn poll_send_body(
        &self,
        cx: &mut Context<'_>,
        stream: u64,
        bytes: &[u8],
        end: bool,
    ) -> Poll<Result<usize, NativeFailure>> {
        let sent = self.with(|conn| conn.poll_send_body(cx, stream, bytes, end));
        self.wake_others(stream);
        sent
    }

    /// The next piece of `stream` into `buf`. The caller drives the connection for everyone: it
    /// reads the socket, takes its own piece, and the readers of the streams whose pieces it
    /// parked are woken. When nothing is ready the caller's waker is kept for its stream.
    pub(crate) fn poll_read(
        &self,
        cx: &mut Context<'_>,
        stream: u64,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, NativeFailure>> {
        let piece = self.with(|conn| conn.poll_read(cx, stream, buf));
        match &piece {
            Poll::Pending => self.keep_reader(stream, cx.waker()),
            Poll::Ready(_) => self.forget_reader(stream),
        }
        self.wake_others(stream);
        piece
    }

    /// The exchange on `stream` is over for its caller: ended and read to its end (`reset` =
    /// false), or left before that (`reset` = true: its stream is reset, the others finish).
    /// One waiting reader is woken to take over the driving, because the socket's wake may have
    /// been this caller's.
    pub(crate) fn leave(&self, stream: u64, reset: bool) {
        self.with(|conn| {
            if reset {
                conn.reset(stream);
            } else {
                conn.finish(stream);
            }
            let _ = conn.stream_over(stream, false);
        });
        self.forget_reader(stream);
        // The last stream left: the connection's idle time starts now.
        let empty = self.with(|conn| conn.lending().streams() == 0);
        self.mark_idle(empty);
        let next = self
            .readers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .first()
            .map(|(_, waker)| waker.clone());
        if let Some(waker) = next {
            waker.wake();
        }
    }

    /// The connection alone again (the last reference): back to its owner, to be kept idle or
    /// closed. `Err` while another exchange still holds it.
    pub(crate) fn into_alone(self: Arc<Self>) -> Result<NativeConnection, Arc<Self>> {
        Arc::try_unwrap(self).map(|shared| {
            shared
                .conn
                .into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
    }
}

/// Run `with` on the exchange's connection, owned alone or shared. `None` = it has none (still
/// judging, or gone).
pub(super) fn with_conn<T>(
    state: &mut State,
    with: impl FnOnce(&mut NativeConnection) -> T,
) -> Option<T> {
    match state {
        State::Dialled(conn) => Some(with(conn)),
        State::Shared(shared) => Some(shared.with(with)),
        State::Judging { .. } | State::Gone => None,
    }
}

/// THE EXCHANGE'S CONNECTION, owned alone or shared: the calls an exchange makes on it, with the
/// same names and answers either way. Shared, each call also wakes the other streams' readers
/// whose pieces it parked.
pub(super) enum Riding<'a> {
    /// The exchange owns the connection.
    Alone(&'a mut NativeConnection),
    /// The exchange has a stream on a connection others ride.
    Shared(&'a Shared),
}

/// The connection `state` rides, if it has one.
pub(super) fn riding(state: &mut State) -> Option<Riding<'_>> {
    match state {
        State::Dialled(conn) => Some(Riding::Alone(conn)),
        State::Shared(shared) => Some(Riding::Shared(shared)),
        State::Judging { .. } | State::Gone => None,
    }
}

impl Riding<'_> {
    /// `NativeConnection::offer_sealed`.
    pub(super) fn offer_sealed(&mut self, slots: crate::outbound::seal::Slots) {
        match self {
            Self::Alone(conn) => conn.offer_sealed(slots),
            Self::Shared(shared) => shared.with(|conn| conn.offer_sealed(slots)),
        }
    }

    /// `NativeConnection::poll_send_head`.
    pub(super) fn poll_send_head(
        &mut self,
        cx: &mut Context<'_>,
        head: &mut Option<NativeHead>,
        body_follows: bool,
    ) -> Poll<Result<u64, NativeFailure>> {
        match self {
            Self::Alone(conn) => conn.poll_send_head(cx, head, body_follows),
            Self::Shared(shared) => shared.poll_send_head(cx, head, body_follows),
        }
    }

    /// `NativeConnection::poll_send_body`.
    pub(super) fn poll_send_body(
        &mut self,
        cx: &mut Context<'_>,
        stream: u64,
        bytes: &[u8],
        end: bool,
    ) -> Poll<Result<usize, NativeFailure>> {
        match self {
            Self::Alone(conn) => conn.poll_send_body(cx, stream, bytes, end),
            Self::Shared(shared) => shared.poll_send_body(cx, stream, bytes, end),
        }
    }

    /// `NativeConnection::poll_read`.
    pub(super) fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        stream: u64,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, NativeFailure>> {
        match self {
            Self::Alone(conn) => conn.poll_read(cx, stream, buf),
            Self::Shared(shared) => shared.poll_read(cx, stream, buf),
        }
    }

    /// `NativeConnection::message_text`.
    pub(super) fn message_text(&self, stream: u64) -> Option<bool> {
        match self {
            Self::Alone(conn) => conn.message_text(stream),
            Self::Shared(shared) => shared.with(|conn| conn.message_text(stream)),
        }
    }

    /// `NativeConnection::close_code`.
    pub(super) fn close_code(&self, stream: u64) -> Option<u32> {
        match self {
            Self::Alone(conn) => conn.close_code(stream),
            Self::Shared(shared) => shared.with(|conn| conn.close_code(stream)),
        }
    }

    /// The exchange's answer was read to its end: its stream is forgotten. Shared, the connection
    /// stays for the others and one waiting reader takes over the driving.
    pub(super) fn finish(&mut self, stream: u64) {
        match self {
            Self::Alone(conn) => conn.finish(stream),
            Self::Shared(shared) => shared.leave(stream, false),
        }
    }
}

impl Exchange {
    /// CALLED by the connector's native wrappers after a poll (`read_native`, `landed_native`): an
    /// exchange that owns a connection whose session multiplexes shares it from now on, so later
    /// opens to the same key on this core ride it instead of dialling. A WebSocket connection, a
    /// connection that is never kept (no key) and one with no stream yet are not shared.
    pub(super) fn share(&mut self, set: &mut InUse<PoolKey, Arc<Shared>>) {
        let shares = self.ws.is_none()
            && self.key.is_some()
            && self.stream.is_some()
            && matches!(&self.state, State::Dialled(conn) if conn.multiplexes());
        if !shares {
            return;
        }
        let (State::Dialled(conn), Some(key)) = (
            std::mem::replace(&mut self.state, State::Gone),
            self.key.as_ref(),
        ) else {
            return;
        };
        let shared = Shared::new(conn);
        set.insert(key, &shared);
        self.state = State::Shared(shared);
    }
}

/// CALLED in `open_native` before the idle set is asked: a connection in use on this core to
/// `key` that takes another stream now. Connections of the key that can carry nothing more (failed,
/// or draining with no stream left) are dropped from the set first; a key left with none is
/// forgotten.
pub(super) fn lend_stream(
    set: &mut InUse<PoolKey, Arc<Shared>>,
    key: &PoolKey,
    pinned: bool,
    now: std::time::Instant,
    idle_timeout: std::time::Duration,
) -> Option<Arc<Shared>> {
    // Dropped from the set, a connection no exchange rides is closed by its drop (buffers wiped).
    set.retain(key, |conn| {
        !conn.in_use().finished() && !conn.idle_past(now, idle_timeout)
    });
    match set.lend(key, |conn| conn.in_use(), false, pinned) {
        Lent::Stream(conn) | Lent::Join(conn) => Some(conn),
        Lent::Idle | Lent::Dial => None,
    }
}

/// What a key has on one core.
struct Keyed<C> {
    entry: KeyEntry,
    /// Connections in use, in the order they were dialled.
    conns: Vec<C>,
    /// The connection of the dial in flight that later opens may join.
    joining: Option<C>,
}

impl<C> Default for Keyed<C> {
    fn default() -> Self {
        Self {
            entry: KeyEntry::default(),
            conns: Vec::new(),
            joining: None,
        }
    }
}

/// What an open is lent.
pub(crate) enum Lent<C> {
    /// A stream on this connection in use.
    Stream(C),
    /// Wait for this dial in flight and open a stream on its connection.
    Join(C),
    /// A kept idle connection: the caller takes it from the idle set.
    Idle,
    /// Nothing: dial.
    Dial,
}

/// THE CORE'S CONNECTIONS IN USE, per key. `K` is the idle set's own key (owner, need, trust,
/// seal, reach: a stream is never opened on a connection another registration's trust made); `C`
/// is the connection's handle (`Arc<Shared>`).
pub(crate) struct InUse<K, C> {
    keys: HashMap<K, Keyed<C>>,
}

impl<K: Eq + Hash + Clone, C: Clone> Default for InUse<K, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Eq + Hash + Clone, C: Clone> InUse<K, C> {
    /// Empty: nothing is made before the first dial.
    pub(crate) fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// What an open to `key` is lent. `view` reads a connection's own statements; `idle` = the
    /// key has a kept idle connection this open may take; `pinned` = the open pins its addresses.
    pub(crate) fn lend(
        &self,
        key: &K,
        view: impl Fn(&C) -> lend::InUse,
        idle: bool,
        pinned: bool,
    ) -> Lent<C> {
        let keyed = self.keys.get(key);
        let chosen = lend::choose(
            keyed.map(|keyed| &keyed.entry),
            keyed
                .into_iter()
                .flat_map(|keyed| keyed.conns.iter().map(&view)),
            idle,
            pinned,
        );
        match (chosen, keyed) {
            (Lend::Stream(at), Some(keyed)) => Lent::Stream(keyed.conns[at].clone()),
            (Lend::Join, Some(keyed)) => match &keyed.joining {
                Some(conn) => Lent::Join(conn.clone()),
                None => Lent::Dial,
            },
            (Lend::Idle, _) => Lent::Idle,
            _ => Lent::Dial,
        }
    }

    /// A dial to `key` began; `conn` is its connection, joinable once the key is known to
    /// multiplex.
    pub(crate) fn dial_began(&mut self, key: &K, conn: &C) {
        let keyed = self.keys.entry(key.clone()).or_default();
        keyed.entry.dial_began();
        if keyed.joining.is_none() {
            keyed.joining = Some(conn.clone());
        }
        keyed.conns.push(conn.clone());
    }

    /// The dial's session began and stated `session`.
    pub(crate) fn dial_opened(&mut self, key: &K, session: &Session) {
        if let Some(keyed) = self.keys.get_mut(key) {
            // `dial_opened` counts the connection; `dial_began` already holds its handle.
            keyed.entry.dial_opened(session);
            keyed.joining = None;
        }
    }

    /// A connection already open comes into shared use for `key` (its session stated that it
    /// multiplexes).
    pub(crate) fn insert(&mut self, key: &K, conn: &C) {
        let keyed = self.keys.entry(key.clone()).or_default();
        keyed.entry.dial_began();
        keyed.entry.dial_opened(&Session {
            flags: crate::outbound::records::S_MULTIPLEX,
            ..Session::default()
        });
        keyed.conns.push(conn.clone());
    }

    /// Keep only the connections of `key` that `keep` admits; a key left with none, and no dial in
    /// flight, is forgotten.
    pub(crate) fn retain(&mut self, key: &K, keep: impl Fn(&C) -> bool) {
        let Some(keyed) = self.keys.get_mut(key) else {
            return;
        };
        let before = keyed.conns.len();
        keyed.conns.retain(&keep);
        for _ in keyed.conns.len()..before {
            keyed.entry.conn_gone();
        }
        if keyed.conns.is_empty() && keyed.entry.empty() {
            self.keys.remove(key);
        }
    }

    /// A kept idle connection was taken into use for `key`.
    pub(crate) fn taken_into_use(&mut self, key: &K, conn: &C, session: &Session) {
        let keyed = self.keys.entry(key.clone()).or_default();
        keyed.entry.dial_began();
        keyed.entry.dial_opened(session);
        keyed.conns.push(conn.clone());
    }

    /// A connection of `key` left use (failed, closed, or went idle); `same` tells its handle
    /// from the others. `dialling` = it never opened a session. The key's entry is removed with
    /// its last connection, and with it what was known of the key.
    pub(crate) fn left(&mut self, key: &K, same: impl Fn(&C) -> bool, dialling: bool) {
        let Some(keyed) = self.keys.get_mut(key) else {
            return;
        };
        let before = keyed.conns.len();
        keyed.conns.retain(|conn| !same(conn));
        if keyed.conns.len() < before {
            if dialling {
                keyed.entry.dial_failed();
            } else {
                keyed.entry.conn_gone();
            }
        }
        if keyed.joining.as_ref().is_some_and(&same) {
            keyed.joining = None;
        }
        if keyed.conns.is_empty() && keyed.entry.empty() {
            self.keys.remove(key);
        }
    }

    /// Keep, over every key, only the connections `keep` admits; a key left with none, and no dial in
    /// flight, is forgotten. Run when a connection comes into shared use, so what a key holds never
    /// outlives its idle timeout by more than the time to the next promotion on its core.
    pub(crate) fn sweep(&mut self, keep: impl Fn(&C) -> bool) {
        self.keys.retain(|_, keyed| {
            let before = keyed.conns.len();
            keyed.conns.retain(&keep);
            for _ in keyed.conns.len()..before {
                keyed.entry.conn_gone();
            }
            !(keyed.conns.is_empty() && keyed.entry.empty())
        });
    }

    /// Keys with something in use.
    pub(crate) fn keys(&self) -> usize {
        self.keys.len()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::outbound::records::S_MULTIPLEX;

    /// A stand-in connection: what it says about taking streams.
    type Conn = Rc<Cell<lend::InUse>>;

    fn h2() -> Session {
        Session {
            flags: S_MULTIPLEX,
            stream_window: 1 << 20,
            conn_window: 4 << 20,
            _r: 0,
        }
    }

    fn conn(session: &Session) -> Conn {
        Rc::new(Cell::new(lend::InUse::begun(session)))
    }

    /// A connection whose dial is in flight: no session has begun, so it states nothing yet.
    fn dialling() -> Conn {
        Rc::new(Cell::new(lend::InUse::default()))
    }

    /// The dial's session began (`begin` answered): the connection states `session`.
    fn session_began(conn: &Conn, session: &Session) {
        conn.set(lend::InUse::begun(session));
    }

    fn view(conn: &Conn) -> lend::InUse {
        conn.get()
    }

    fn opened(conn: &Conn) {
        let mut state = conn.get();
        state.opened();
        conn.set(state);
    }

    #[test]
    fn n_opens_to_one_key_ride_the_first_connection_once_it_multiplexes() {
        let mut set: InUse<&str, Conn> = InUse::new();
        assert!(matches!(set.lend(&"k", view, false, false), Lent::Dial));
        let first = dialling();
        set.dial_began(&"k", &first);
        assert!(
            matches!(set.lend(&"k", view, false, false), Lent::Dial),
            "nothing is known of the key yet: a first burst dials"
        );
        set.dial_opened(&"k", &h2());
        session_began(&first, &h2());
        opened(&first);
        for _ in 0..50 {
            match set.lend(&"k", view, false, false) {
                Lent::Stream(lent) => {
                    assert!(Rc::ptr_eq(&lent, &first));
                    opened(&lent);
                }
                _ => panic!("the open rides the connection in use"),
            }
        }
        assert_eq!(first.get().streams(), 51);
        assert_eq!(set.keys(), 1);
    }

    #[test]
    fn once_the_key_multiplexes_a_later_open_joins_the_dial_in_flight() {
        let mut set: InUse<&str, Conn> = InUse::new();
        let first = dialling();
        set.dial_began(&"k", &first);
        set.dial_opened(&"k", &h2());
        session_began(&first, &h2());
        opened(&first);
        // The first connection drains (the far end is closing it); a new dial begins.
        let mut draining = first.get();
        draining.draining();
        first.set(draining);
        let second = dialling();
        set.dial_began(&"k", &second);
        match set.lend(&"k", view, false, false) {
            Lent::Join(joined) => assert!(Rc::ptr_eq(&joined, &second)),
            _ => panic!("the open waits for the dial in flight"),
        }
    }

    #[test]
    fn another_keys_connection_is_never_lent() {
        let mut set: InUse<&str, Conn> = InUse::new();
        let first = conn(&h2());
        set.dial_began(&"tenant-a", &first);
        set.dial_opened(&"tenant-a", &h2());
        opened(&first);
        assert!(matches!(
            set.lend(&"tenant-b", view, false, false),
            Lent::Dial
        ));
    }

    /// The in-use set under the idle set's own key: two needs of one instance to one authority, sealed by one
    /// `Pools` and forced onto one hash, so only the key's `Eq` tells them apart.
    #[test]
    fn two_needs_one_authority_never_share() {
        use busbar_contract::conn::{InstanceId, NeedId};
        let key = |need| PoolKey {
            owner: InstanceId(7),
            need: NeedId(need),
            door: 1,
            authority: "api.example:443".into(),
            secure: true,
            name: Some("api.example".into()),
            class: (0, 0),
            reach: false,
            anchored_as: None,
            trust: None,
            sealed: None,
            hash: 0,
        };
        let pools = crate::pool::Pools::new(crate::pool::PoolPosture::NONE);
        let first = pools.keyed(key(3));
        let mut second = pools.keyed(key(4));
        second.hash = first.hash;
        let mut set: InUse<PoolKey, Conn> = InUse::new();
        let riding = conn(&h2());
        set.dial_began(&first, &riding);
        set.dial_opened(&first, &h2());
        opened(&riding);
        assert!(matches!(
            set.lend(&first, view, false, false),
            Lent::Stream(_)
        ));
        assert!(
            matches!(set.lend(&second, view, false, false), Lent::Dial),
            "another need never rides the first need's connection"
        );
        // The first need's connection drains and its next dial is in flight: its own opens join it.
        let mut draining = riding.get();
        draining.draining();
        riding.set(draining);
        let in_flight = dialling();
        set.dial_began(&first, &in_flight);
        assert!(matches!(
            set.lend(&first, view, false, false),
            Lent::Join(_)
        ));
        assert!(
            matches!(set.lend(&second, view, false, false), Lent::Dial),
            "another need never joins the first need's dial"
        );
    }

    #[test]
    fn a_key_is_forgotten_with_its_last_connection() {
        let mut set: InUse<&str, Conn> = InUse::new();
        let first = conn(&h2());
        set.dial_began(&"k", &first);
        set.dial_opened(&"k", &h2());
        set.left(&"k", |one| Rc::ptr_eq(one, &first), false);
        assert_eq!(set.keys(), 0, "no table that grows");
        let failed = conn(&h2());
        set.dial_began(&"k", &failed);
        set.left(&"k", |one| Rc::ptr_eq(one, &failed), true);
        assert_eq!(set.keys(), 0);
    }

    #[test]
    fn a_pinned_open_and_an_idle_connection() {
        let mut set: InUse<&str, Conn> = InUse::new();
        let first = conn(&h2());
        set.dial_began(&"k", &first);
        set.dial_opened(&"k", &h2());
        opened(&first);
        assert!(matches!(set.lend(&"k", view, true, true), Lent::Dial));
        assert!(matches!(set.lend(&"other", view, true, false), Lent::Idle));
    }

    #[test]
    fn a_sweep_forgets_every_key_whose_connections_are_gone() {
        let mut set: InUse<&str, Conn> = InUse::new();
        let (live, dead) = (conn(&h2()), conn(&h2()));
        set.insert(&"a", &live);
        set.insert(&"b", &dead);
        let mut gone = dead.get();
        gone.gone();
        dead.set(gone);
        set.sweep(|conn| !conn.get().finished());
        assert_eq!(set.keys(), 1);
        assert!(matches!(
            set.lend(&"a", view, false, false),
            Lent::Stream(_)
        ));
        assert!(matches!(set.lend(&"b", view, false, false), Lent::Dial));
    }
}
