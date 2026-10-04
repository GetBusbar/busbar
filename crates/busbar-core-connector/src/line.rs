// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LINE: one composed connection as the exchanges riding it hold it.
//!
//! A dialled connection carries one exchange at a time, or, where it multiplexes (an `h2`
//! connection: [`Connection::multiplexes`]), many at once, one stream each (ARCHITECT ruling
//! Q-L18-MUX: concurrent requests to one origin share an h2 connection, as 1.5.5's pooled client
//! shared them). Every holder reads ITS stream: the pieces the framer answers are routed by stream,
//! a piece for another holder parked until that holder reads, and a piece for a stream nobody holds
//! any more dropped.
//!
//! THE WAKE FANS OUT. A socket registered on the reactor keeps ONE waker per direction, so two
//! holders polling one socket with their own wakers would each unseat the other's, and the one left
//! unseated would never be woken. Every drive of the connection therefore polls it with the line's
//! own waker, which wakes every holder still waiting; a holder that is woken for nothing polls,
//! finds nothing, and waits again.
//!
//! An ACCEPTED connection is a line with one holder that reads every stream.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use crate::compose::{Connection, Failure, HeadWords, Opening, EXCHANGE_STREAM};
use crate::framer::{Established, Got};

/// The key an accepted connection's one holder reads under: every stream.
pub(crate) const EVERY: u64 = u64::MAX;

/// The holders still waiting on a line, woken together.
#[derive(Default)]
struct FanOut {
    waiting: Mutex<HashMap<u64, Waker>>,
}

impl FanOut {
    fn wait(&self, stream: u64, waker: &Waker) {
        let mut w = self.waiting.lock().expect("waiters");
        match w.get_mut(&stream) {
            Some(held) if held.will_wake(waker) => {}
            _ => {
                w.insert(stream, waker.clone());
            }
        }
    }

    fn forget(&self, stream: u64) {
        self.waiting.lock().expect("waiters").remove(&stream);
    }

    fn wake_one(&self, stream: u64) {
        let w = self.waiting.lock().expect("waiters").get(&stream).cloned();
        if let Some(w) = w {
            w.wake();
        }
    }
}

impl Wake for FanOut {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let all: Vec<Waker> = self
            .waiting
            .lock()
            .expect("waiters")
            .values()
            .cloned()
            .collect();
        for w in all {
            w.wake();
        }
    }
}

struct State {
    conn: Option<Connection>,
    /// Pieces read off the connection for a holder that has not taken them, by stream.
    parked: HashMap<u64, VecDeque<Got>>,
    /// The streams a holder still reads.
    held: HashSet<u64>,
    /// The next stream an exchange opened on this line rides.
    next: u64,
}

/// One connection, held by the exchanges riding it.
pub(crate) struct Line {
    state: Mutex<State>,
    fan: Arc<FanOut>,
    /// How many exchanges hold the line (a pool counts a lent line as held from the moment it
    /// lends it).
    users: AtomicUsize,
    /// An exchange left it before its answer was whole: it is not lent again once idle.
    tainted: AtomicBool,
}

impl std::fmt::Debug for Line {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Line")
            .field("users", &self.users.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Line {
    /// A line over `conn`, held by its first exchange (a dialled connection's
    /// [`EXCHANGE_STREAM`], or an accepted connection's every stream).
    pub(crate) fn new(conn: Connection) -> Arc<Self> {
        let first = if conn.dialled() {
            EXCHANGE_STREAM
        } else {
            EVERY
        };
        Arc::new(Self {
            state: Mutex::new(State {
                conn: Some(conn),
                parked: HashMap::new(),
                held: HashSet::from([first]),
                next: EXCHANGE_STREAM + 1,
            }),
            fan: Arc::new(FanOut::default()),
            users: AtomicUsize::new(1),
            tainted: AtomicBool::new(false),
        })
    }

    fn fan_waker(&self) -> Waker {
        Waker::from(Arc::clone(&self.fan))
    }

    /// How many exchanges hold the line.
    pub(crate) fn users(&self) -> usize {
        self.users.load(Ordering::Acquire)
    }

    /// Count one more holder (the pool, lending the line).
    pub(crate) fn lend(&self) {
        self.users.fetch_add(1, Ordering::AcqRel);
    }

    /// Whether the line carries concurrent exchanges and is live.
    pub(crate) fn multiplexes(&self) -> bool {
        let s = self.state.lock().expect("line");
        s.conn.as_ref().is_some_and(Connection::multiplexes)
    }

    /// Every byte the line's socket has taken.
    pub(crate) fn flushed(&self) -> u64 {
        let s = self.state.lock().expect("line");
        s.conn.as_ref().map_or(0, Connection::flushed)
    }

    /// An idle line, read for what the far end sent while it sat: whether it can carry the next
    /// exchange (live, framed, nothing unread, never left mid-answer).
    pub(crate) fn fresh(&self) -> bool {
        if self.tainted.load(Ordering::Acquire) {
            return false;
        }
        let waker = self.fan_waker();
        let mut s = self.state.lock().expect("line");
        s.parked.values().all(VecDeque::is_empty)
            && s.conn
                .as_mut()
                .is_some_and(|c| c.fresh(&mut Context::from_waker(&waker)))
    }

    /// Whether an idle line may go back to the pool: never left mid-answer, and its connection can
    /// carry another exchange.
    pub(crate) fn reusable(&self) -> bool {
        let s = self.state.lock().expect("line");
        !self.tainted.load(Ordering::Acquire)
            && s.parked.values().all(VecDeque::is_empty)
            && s.conn.as_ref().is_some_and(Connection::reusable)
    }

    /// Open a new exchange on the line (the pool lent it, so its holder is already counted): its
    /// first message on the next stream. Answers the stream.
    ///
    /// # Errors
    ///
    /// The connection ended or failed, or the entry refused the message: the stream it would have
    /// ridden (its holder leaves with it) and why.
    pub(crate) fn attach(
        &self,
        opening: Option<Opening>,
        head_words: HeadWords,
    ) -> Result<u64, (u64, Failure)> {
        let waker = self.fan_waker();
        let mut s = self.state.lock().expect("line");
        let stream = s.next;
        s.next += 1;
        s.held.insert(stream);
        let Some(conn) = s.conn.as_mut() else {
            return Err((stream, Failure::Closed));
        };
        conn.open_exchange(
            stream,
            opening,
            head_words,
            &mut Context::from_waker(&waker),
        )
        .map_err(|f| (stream, f))?;
        Ok(stream)
    }

    /// Read what the connection answered into the parked pieces, waking each holder a piece came
    /// for. `Some` = the connection ended (`Ok`) or failed.
    fn route(&self, s: &mut State) -> Option<Result<(), Failure>> {
        let waker = self.fan_waker();
        let mut cx = Context::from_waker(&waker);
        let conn = s.conn.as_mut()?;
        let every = !conn.dialled();
        // A connection that does not multiplex has one holder at a time, who reads every piece (a
        // wire with one stream numbers its pieces `0`); only a multiplexing one is read by stream.
        let sole = (!every && !conn.multiplexes())
            .then(|| s.held.iter().next().copied())
            .flatten();
        loop {
            match conn.poll_piece(&mut cx) {
                Poll::Pending => return None,
                Poll::Ready(Ok(None)) => return Some(Ok(())),
                Poll::Ready(Err(f)) => return Some(Err(f)),
                Poll::Ready(Ok(Some(got))) => {
                    let key = if every {
                        EVERY
                    } else {
                        sole.unwrap_or(got.stream)
                    };
                    if s.held.contains(&key) {
                        s.parked.entry(key).or_default().push_back(got);
                        self.fan.wake_one(key);
                    }
                }
            }
        }
    }

    /// The next piece for `stream`: `Ready(Ok(Some))` a piece, `Ready(Ok(None))` the connection
    /// ended, `Pending` with `cx`'s waker among the line's waiting holders.
    pub(crate) fn poll_piece(
        &self,
        stream: u64,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Got>, Failure>> {
        self.fan.wait(stream, cx.waker());
        let mut s = self.state.lock().expect("line");
        if let Some(got) = s.parked.get_mut(&stream).and_then(VecDeque::pop_front) {
            return Poll::Ready(Ok(Some(got)));
        }
        let end = self.route(&mut s);
        if let Some(got) = s.parked.get_mut(&stream).and_then(VecDeque::pop_front) {
            return Poll::Ready(Ok(Some(got)));
        }
        match end {
            None if s.conn.is_some() => Poll::Pending,
            None | Some(Ok(())) => Poll::Ready(Ok(None)),
            Some(Err(f)) => Poll::Ready(Err(f)),
        }
    }

    /// Whether a piece (or the end) is ready for `stream`, without taking it.
    pub(crate) fn poll_ready(&self, stream: u64, cx: &mut Context<'_>) -> Poll<()> {
        self.fan.wait(stream, cx.waker());
        let mut s = self.state.lock().expect("line");
        let end = self.route(&mut s);
        if end.is_some() || s.conn.is_none() || s.parked.get(&stream).is_some_and(|q| !q.is_empty())
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Offer `bytes` on `stream` (`end` = its message is complete); answers how many were taken.
    ///
    /// # Errors
    ///
    /// The connection is closed or failed, or the framer refused the bytes.
    pub(crate) fn emit(
        &self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, Failure> {
        let waker = self.fan_waker();
        let mut s = self.state.lock().expect("line");
        let conn = s.conn.as_mut().ok_or(Failure::Closed)?;
        conn.emit(stream, bytes, end, text, &mut Context::from_waker(&waker))
    }

    /// What connection security established.
    pub(crate) fn established(&self) -> Option<Established> {
        let s = self.state.lock().expect("line");
        s.conn.as_ref().map(|c| c.established().clone())
    }

    /// Why the line's connection failed, once it has (see [`Connection::cause`]).
    pub(crate) fn cause(&self) -> Option<busbar_contract::conn::ConnCause> {
        let s = self.state.lock().expect("line");
        s.conn.as_ref().and_then(|c| c.cause().cloned())
    }

    /// The dial target the line's connection names, if it still holds one.
    pub(crate) fn target(&self) -> Option<String> {
        let s = self.state.lock().expect("line");
        s.conn.as_ref().map(|c| c.target().to_owned())
    }

    /// Upgrade this line's connection to connection security (a secure upgrade on an open dialled
    /// line), offering `name` (see [`Connection::upgrade_secure`]).
    pub(crate) fn upgrade_secure(
        &self,
        config: &Arc<rustls::ClientConfig>,
        name: &str,
        timeout: std::time::Duration,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Failure>> {
        let mut s = self.state.lock().expect("line");
        let Some(conn) = s.conn.as_mut() else {
            return Poll::Ready(Err(Failure::Closed));
        };
        conn.upgrade_secure(config, name, timeout, cx)
    }

    /// The SHA-256 of the far end's certificate, once a handshake completed (see
    /// [`Connection::peer_cert_hash`]).
    pub(crate) fn peer_cert_hash(&self) -> Option<String> {
        let s = self.state.lock().expect("line");
        s.conn.as_ref().and_then(Connection::peer_cert_hash)
    }

    /// `stream`'s holder leaves (`whole` = its answer was read to its end); answers how many
    /// holders are left.
    pub(crate) fn leave(&self, stream: u64, whole: bool) -> usize {
        {
            let mut s = self.state.lock().expect("line");
            s.held.remove(&stream);
            s.parked.remove(&stream);
        }
        self.fan.forget(stream);
        if !whole {
            self.tainted.store(true, Ordering::Release);
        }
        self.users.fetch_sub(1, Ordering::AcqRel) - 1
    }

    /// Close the connection (the last holder left and the line is not kept).
    pub(crate) fn close(&self) {
        let conn = self.state.lock().expect("line").conn.take();
        if let Some(c) = conn {
            c.close();
        }
    }
}
