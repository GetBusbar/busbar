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
//! THE CONNECTION HAS ONE OWNER AT A TIME, AND IS DRIVEN UNDER NO LOCK (`BUSBAR-1.6.0.md` §11, M1
//! DISPATCH RULINGS: "No plugin code runs under a host lock"). Driving a connection crosses into
//! its plugins (the carrier's reads and writes, the framer's ingest and emit), so the holder that
//! drives it first TAKES it out of the line, lets the line's lock go, drives it as its sole owner,
//! and brings it back. The lock only ever guards that hand-off and the parked pieces. A holder that
//! finds the connection out does not wait for it: a poll answers `Pending` and is woken when it is
//! back; a write takes nothing now (the caller re-offers it after its next read or wait); an
//! exchange opened meanwhile is handed to the owner, who opens it on the way back. A CLOSE never
//! waits either: a connection at home is taken and closed on the closer's thread with nothing held,
//! and one that is out is closed by the owner that has it, as it brings it back. So a crossing
//! that hangs (the dispatcher's watchdog reports it; nothing can preempt it) holds up only the one
//! task inside it, never a holder, a closer, or a worker dropping the line.
//!
//! An ACCEPTED connection is a line with one holder that reads every stream.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};

use busbar_contract::conn::ConnCause;

use crate::compose::{
    Connection, Failure, HeadWords, Opening, EXCHANGE_STREAM, RECEIVE_BUFFER_BYTES,
};
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

/// What the connection said of itself when it was last at home: what the line answers of it while
/// a holder has it out.
#[derive(Default)]
struct Seen {
    multiplexes: bool,
    flushed: u64,
    reusable: bool,
    established: Established,
    cause: Option<ConnCause>,
    target: String,
    /// Connection security's handshake had completed (what the far end's certificate hash is read
    /// off).
    secured: bool,
    peer_cert_hash: Option<String>,
}

impl Seen {
    /// Bring what is seen up to `conn`; what did not change is not copied again.
    fn refresh(&mut self, conn: &Connection) {
        self.multiplexes = conn.multiplexes();
        self.flushed = conn.flushed();
        self.reusable = conn.reusable();
        if self.established != *conn.established() {
            self.established.clone_from(conn.established());
        }
        if self.cause.as_ref() != conn.cause() {
            self.cause = conn.cause().cloned();
        }
        if self.target != conn.target() {
            conn.target().clone_into(&mut self.target);
        }
        if self.secured != conn.secured() {
            self.secured = conn.secured();
            self.peer_cert_hash = conn.peer_cert_hash();
        }
    }
}

struct State {
    /// The connection while it is at home: `None` while a holder has it out (and `closing` is not
    /// raised), and once it is closed.
    conn: Option<Connection>,
    /// The line is closed: a connection at home was taken and closed, and one that is out is
    /// closed by the holder that has it, as it brings it back.
    closing: bool,
    /// What the connection said of itself when it was last at home.
    seen: Seen,
    /// Exchanges opened while the connection was out, in order: its owner opens them on the way
    /// back, before anyone else can take it.
    opening: Vec<(u64, Option<Opening>, HeadWords)>,
    /// An exchange whose open was handed to the owner and failed: its holder's next read answers
    /// why.
    refused: HashMap<u64, Failure>,
    /// The holders that found the connection out, woken when it is back.
    missed: Vec<Waker>,
    /// Pieces read off the connection for a holder that has not taken them, by stream.
    parked: HashMap<u64, VecDeque<Got>>,
    /// The streams a holder still reads.
    held: HashSet<u64>,
    /// The next stream an exchange opened on this line rides.
    next: u64,
}

impl State {
    /// The bytes of every piece parked and not yet taken.
    fn parked_bytes(&self) -> usize {
        self.parked.values().flatten().map(|g| g.bytes.len()).sum()
    }

    /// Whether a piece (or why its open failed) waits for `stream`.
    fn waiting_for(&self, stream: u64) -> bool {
        self.refused.contains_key(&stream)
            || self.parked.get(&stream).is_some_and(|q| !q.is_empty())
    }

    /// `waker`'s holder found the connection out: it is woken when the connection is back.
    fn miss(&mut self, waker: &Waker) {
        if !self.missed.iter().any(|w| w.will_wake(waker)) {
            self.missed.push(waker.clone());
        }
    }
}

/// What asking for the connection came to.
enum Turn<R> {
    /// The holder had it, drove it with no lock held, and brought it back: what the drive answered.
    Ran(R),
    /// Another holder has it out.
    Out,
    /// The line is closed.
    Closed,
}

/// A connection a holder has out of its line. Only an unwind out of a drive drops it still holding
/// the connection: the line is then closed with the connection put back, to be closed (its
/// plugins' ends crossed) by whoever lets the line go.
struct Taken<'l> {
    line: &'l Line,
    conn: Option<Connection>,
}

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let mut s = self.line.state();
            s.closing = true;
            s.conn = Some(conn);
        }
    }
}

/// One connection, held by the exchanges riding it.
pub(crate) struct Line {
    state: Mutex<State>,
    fan: Arc<FanOut>,
    /// The connection was dialled (its holders read their own streams), not accepted.
    dialled: bool,
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
        let dialled = conn.dialled();
        let first = if dialled { EXCHANGE_STREAM } else { EVERY };
        let mut seen = Seen::default();
        seen.refresh(&conn);
        Arc::new(Self {
            state: Mutex::new(State {
                conn: Some(conn),
                closing: false,
                seen,
                opening: Vec::new(),
                refused: HashMap::new(),
                missed: Vec::new(),
                parked: HashMap::new(),
                held: HashSet::from([first]),
                next: EXCHANGE_STREAM + 1,
            }),
            fan: Arc::new(FanOut::default()),
            dialled,
            users: AtomicUsize::new(1),
            tainted: AtomicBool::new(false),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fan_waker(&self) -> Waker {
        Waker::from(Arc::clone(&self.fan))
    }

    /// THE HAND-OFF. Take the connection out of the line (`s` is the line's lock, let go here),
    /// `drive` it as its sole owner with no lock held, and bring it back: `settle` runs under the
    /// lock that puts it back, so what the drive read is parked before anyone else can drive it.
    /// `missed` (where given) is woken once the connection is back, when another holder has it out.
    fn turn<R>(
        &self,
        mut s: MutexGuard<'_, State>,
        missed: Option<&Waker>,
        drive: impl FnOnce(&mut Connection) -> R,
        settle: impl FnOnce(&mut State, &mut R),
    ) -> Turn<R> {
        if s.closing {
            return Turn::Closed;
        }
        let Some(conn) = s.conn.take() else {
            if let Some(w) = missed {
                s.miss(w);
            }
            return Turn::Out;
        };
        drop(s);
        let mut taken = Taken {
            line: self,
            conn: Some(conn),
        };
        let mut r = drive(taken.conn.as_mut().expect("the connection is out"));
        self.bring_back(&mut taken, |s| settle(s, &mut r));
        Turn::Ran(r)
    }

    /// Bring the connection `taken` back to the line: what was handed to its owner meanwhile is
    /// done first (each exchange opened, with no lock held), then it is put back (or, the line
    /// closed meanwhile, closed here, with no lock held), and the holders that found it out are
    /// woken.
    fn bring_back(&self, taken: &mut Taken<'_>, settle: impl FnOnce(&mut State)) {
        let mut s = self.state();
        settle(&mut s);
        loop {
            if s.closing {
                let missed = std::mem::take(&mut s.missed);
                drop(s);
                if let Some(conn) = taken.conn.take() {
                    conn.close();
                }
                wake(missed);
                return;
            }
            let opening = std::mem::take(&mut s.opening);
            if opening.is_empty() {
                let Some(conn) = taken.conn.take() else {
                    return;
                };
                s.seen.refresh(&conn);
                s.conn = Some(conn);
                let missed = std::mem::take(&mut s.missed);
                drop(s);
                wake(missed);
                return;
            }
            drop(s);
            let waker = self.fan_waker();
            let mut cx = Context::from_waker(&waker);
            let mut refused = Vec::new();
            if let Some(conn) = taken.conn.as_mut() {
                for (stream, opening, head_words) in opening {
                    if let Err(f) = conn.open_exchange(stream, opening, head_words, &mut cx) {
                        refused.push((stream, f));
                    }
                }
            }
            s = self.state();
            s.refused.extend(refused);
        }
    }

    /// How many exchanges hold the line.
    pub(crate) fn users(&self) -> usize {
        self.users.load(Ordering::Acquire)
    }

    /// Count one more holder (the pool, lending the line).
    pub(crate) fn lend(&self) {
        self.users.fetch_add(1, Ordering::AcqRel);
    }

    /// What the connection answers of itself (`home`), or, while a holder has it out, what it last
    /// said (`out`); `None` once the line is closed.
    fn fact<R>(
        &self,
        home: impl FnOnce(&Connection) -> R,
        out: impl FnOnce(&Seen) -> R,
    ) -> Option<R> {
        let s = self.state();
        if s.closing {
            return None;
        }
        Some(match s.conn.as_ref() {
            Some(conn) => home(conn),
            None => out(&s.seen),
        })
    }

    /// Whether the line carries concurrent exchanges and is live.
    pub(crate) fn multiplexes(&self) -> bool {
        self.fact(Connection::multiplexes, |s| s.multiplexes)
            .unwrap_or(false)
    }

    /// Every byte the line's socket has taken.
    pub(crate) fn flushed(&self) -> u64 {
        self.fact(Connection::flushed, |s| s.flushed).unwrap_or(0)
    }

    /// An idle line, read for what the far end sent while it sat: whether it can carry the next
    /// exchange (live, framed, nothing unread, never left mid-answer). A line a holder has out is
    /// not idle: not fresh.
    pub(crate) fn fresh(&self) -> bool {
        if self.tainted.load(Ordering::Acquire) {
            return false;
        }
        let waker = self.fan_waker();
        let s = self.state();
        if !s.parked.values().all(VecDeque::is_empty) {
            return false;
        }
        match self.turn(
            s,
            None,
            |c| c.fresh(&mut Context::from_waker(&waker)),
            |_, _| {},
        ) {
            Turn::Ran(fresh) => fresh,
            Turn::Out | Turn::Closed => false,
        }
    }

    /// Whether an idle line may go back to the pool: never left mid-answer, and its connection can
    /// carry another exchange.
    pub(crate) fn reusable(&self) -> bool {
        if self.tainted.load(Ordering::Acquire) {
            return false;
        }
        let unparked = self.state().parked.values().all(VecDeque::is_empty);
        unparked
            && self
                .fact(Connection::reusable, |s| s.reusable)
                .unwrap_or(false)
    }

    /// Open a new exchange on the line (the pool lent it, so its holder is already counted): its
    /// first message on the next stream. Answers the stream. While another holder has the
    /// connection out, the open is handed to it, and a failure is the stream's first read.
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
        let mut s = self.state();
        let stream = s.next;
        s.next += 1;
        s.held.insert(stream);
        if s.closing {
            return Err((stream, Failure::Closed));
        }
        if s.conn.is_none() {
            s.opening.push((stream, opening, head_words));
            return Ok(stream);
        }
        match self.turn(
            s,
            None,
            |conn| {
                conn.open_exchange(
                    stream,
                    opening,
                    head_words,
                    &mut Context::from_waker(&waker),
                )
            },
            |_, _| {},
        ) {
            Turn::Ran(opened) => opened.map(|()| stream).map_err(|f| (stream, f)),
            Turn::Out | Turn::Closed => Err((stream, Failure::Closed)),
        }
    }

    /// Read what the connection answered into the parked pieces, waking each holder a piece came
    /// for, until [`RECEIVE_BUFFER_BYTES`] are parked: past it the connection is not read until a
    /// holder takes some ([`Self::poll_piece`] wakes the others then). `Ran(Some)` = the connection
    /// ended (`Ok`) or failed. `missed` is woken once the connection is back, when another holder
    /// has it out.
    fn park_pieces(
        &self,
        s: MutexGuard<'_, State>,
        missed: &Waker,
    ) -> Turn<Option<Result<(), Failure>>> {
        let every = !self.dialled;
        // A connection that does not multiplex has one holder at a time, who reads every piece (a
        // wire with one stream numbers its pieces `0`); only a multiplexing one is read by stream,
        // and only the streams held now are counted against the cap.
        let multiplexes = s.conn.as_ref().is_some_and(Connection::multiplexes);
        let sole = (!every && !multiplexes)
            .then(|| s.held.iter().next().copied())
            .flatten();
        let held = (!every && multiplexes).then(|| s.held.clone());
        let key = move |got: &Got| {
            if every {
                EVERY
            } else {
                sole.unwrap_or(got.stream)
            }
        };
        let parked = s.parked_bytes();
        let waker = self.fan_waker();
        let turn = self.turn(
            s,
            Some(missed),
            |conn| {
                let mut cx = Context::from_waker(&waker);
                let mut parked = parked;
                let mut read = Vec::new();
                loop {
                    if parked >= RECEIVE_BUFFER_BYTES {
                        return (None, read);
                    }
                    let end = match conn.poll_piece(&mut cx) {
                        Poll::Pending => None,
                        Poll::Ready(Ok(None)) => Some(Ok(())),
                        Poll::Ready(Err(f)) => Some(Err(f)),
                        Poll::Ready(Ok(Some(got))) => {
                            if held.as_ref().is_none_or(|h| h.contains(&key(&got))) {
                                parked += got.bytes.len();
                                read.push(got);
                            }
                            continue;
                        }
                    };
                    return (end, read);
                }
            },
            // Parked under the lock that brings the connection back, in the order read: no other
            // drive can read a later piece first. A piece for a stream its holder left meanwhile
            // is dropped, and the others woken, as what a leaving holder left parked is.
            |s, (_, read)| {
                let mut dropped = false;
                for got in read.drain(..) {
                    let key = key(&got);
                    if s.held.contains(&key) {
                        s.parked.entry(key).or_default().push_back(got);
                        self.fan.wake_one(key);
                    } else {
                        dropped = true;
                    }
                }
                if dropped {
                    self.fan.wake_by_ref();
                }
            },
        );
        match turn {
            Turn::Ran((end, _)) => Turn::Ran(end),
            Turn::Out => Turn::Out,
            Turn::Closed => Turn::Closed,
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
        let mut s = self.state();
        if let Some(f) = s.refused.remove(&stream) {
            return Poll::Ready(Err(f));
        }
        let full = s.parked_bytes() >= RECEIVE_BUFFER_BYTES;
        if let Some(got) = s.parked.get_mut(&stream).and_then(VecDeque::pop_front) {
            if full && s.parked_bytes() < RECEIVE_BUFFER_BYTES {
                // Under the cap again: the connection is read again, for whoever waits on it.
                self.fan.wake_by_ref();
            }
            return Poll::Ready(Ok(Some(got)));
        }
        let end = self.park_pieces(s, cx.waker());
        let mut s = self.state();
        if let Some(got) = s.parked.get_mut(&stream).and_then(VecDeque::pop_front) {
            return Poll::Ready(Ok(Some(got)));
        }
        if let Some(f) = s.refused.remove(&stream) {
            return Poll::Ready(Err(f));
        }
        match end {
            Turn::Ran(Some(Err(f))) => Poll::Ready(Err(f)),
            Turn::Ran(Some(Ok(()))) | Turn::Closed => Poll::Ready(Ok(None)),
            Turn::Ran(None) | Turn::Out if s.closing => Poll::Ready(Ok(None)),
            Turn::Ran(None) | Turn::Out => Poll::Pending,
        }
    }

    /// Whether a piece (or the end) is ready for `stream`, without taking it.
    pub(crate) fn poll_ready(&self, stream: u64, cx: &mut Context<'_>) -> Poll<()> {
        self.fan.wait(stream, cx.waker());
        let s = self.state();
        let end = self.park_pieces(s, cx.waker());
        let s = self.state();
        if matches!(end, Turn::Ran(Some(_)) | Turn::Closed) || s.closing || s.waiting_for(stream) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Whether the line's dial has landed (see [`Connection::poll_landed`]): `Pending` with `cx`'s
    /// waker among `stream`'s waiting holders while it connects.
    pub(crate) fn poll_landed(
        &self,
        stream: u64,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Failure>> {
        self.fan.wait(stream, cx.waker());
        let waker = self.fan_waker();
        let s = self.state();
        match self.turn(
            s,
            Some(cx.waker()),
            |conn| conn.poll_landed(&mut Context::from_waker(&waker)),
            |_, _| {},
        ) {
            Turn::Ran(landed) => landed,
            Turn::Out => Poll::Pending,
            Turn::Closed => Poll::Ready(Err(Failure::Closed)),
        }
    }

    /// Offer `bytes` on `stream` (`end` = its message is complete); answers how many were taken:
    /// none while another holder has the connection out (the caller re-offers them after its next
    /// read or wait, as it does a full buffer).
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
        let s = self.state();
        match self.turn(
            s,
            None,
            |conn| conn.emit(stream, bytes, end, text, &mut Context::from_waker(&waker)),
            |_, _| {},
        ) {
            Turn::Ran(took) => took,
            Turn::Out => Ok(0),
            Turn::Closed => Err(Failure::Closed),
        }
    }

    /// What connection security established.
    pub(crate) fn established(&self) -> Option<Established> {
        self.fact(|c| c.established().clone(), |s| s.established.clone())
    }

    /// Why the line's connection failed, once it has (see [`Connection::cause`]).
    pub(crate) fn cause(&self) -> Option<ConnCause> {
        self.fact(|c| c.cause().cloned(), |s| s.cause.clone())
            .flatten()
    }

    /// The dial target the line's connection names, if it still holds one.
    pub(crate) fn target(&self) -> Option<String> {
        self.fact(|c| c.target().to_owned(), |s| s.target.clone())
    }

    /// Upgrade this line's connection to connection security (a secure upgrade on an open dialled
    /// line), offering `name` (see [`Connection::upgrade_secure`]). `unread_above` = the holder
    /// still keeps clear bytes it took off the line. Those, and a piece parked here unread, would
    /// be read after the upgrade as the verified far end's, so the upgrade is refused and the
    /// connection fails ([`crate::compose::UPGRADE_OVER_CLEAR_BYTES`]); what was parked is never
    /// read, the failure is.
    pub(crate) fn upgrade_secure(
        &self,
        config: &Arc<rustls::ClientConfig>,
        name: &str,
        timeout: std::time::Duration,
        unread_above: bool,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Failure>> {
        let missed = cx.waker().clone();
        let s = self.state();
        let parked = s.parked.values().any(|q| !q.is_empty());
        match self.turn(
            s,
            Some(&missed),
            |conn| {
                let answer =
                    conn.upgrade_secure_over(config, name, timeout, unread_above || parked, cx);
                let spent = matches!(&answer, Poll::Ready(Err(_))) && !conn.live();
                (answer, spent)
            },
            |s, (_, spent)| {
                if *spent {
                    s.parked.clear();
                }
            },
        ) {
            Turn::Ran((answer, _)) => answer,
            Turn::Out => Poll::Pending,
            Turn::Closed => Poll::Ready(Err(Failure::Closed)),
        }
    }

    /// The far end's certificate hash (the channel-binding input), once a handshake completed (see
    /// [`Connection::peer_cert_hash`]).
    pub(crate) fn peer_cert_hash(&self) -> Option<String> {
        self.fact(Connection::peer_cert_hash, |s| s.peer_cert_hash.clone())
            .flatten()
    }

    /// `stream`'s holder leaves (`whole` = its answer was read to its end); answers how many
    /// holders are left.
    pub(crate) fn leave(&self, stream: u64, whole: bool) -> usize {
        let unparked = {
            let mut s = self.state();
            s.held.remove(&stream);
            s.refused.remove(&stream);
            s.parked.remove(&stream).is_some_and(|q| !q.is_empty())
        };
        self.fan.forget(stream);
        if unparked {
            // What it left parked is dropped: under the cap, the connection is read again for
            // whoever waits on it.
            self.fan.wake_by_ref();
        }
        if !whole {
            self.tainted.store(true, Ordering::Release);
        }
        self.users.fetch_sub(1, Ordering::AcqRel) - 1
    }

    /// Close the connection (the last holder left and the line is not kept). Never waits: a
    /// connection at home is taken and closed here with no lock held; one a holder has out is
    /// closed by that holder as it brings it back.
    pub(crate) fn close(&self) {
        let conn = {
            let mut s = self.state();
            s.closing = true;
            s.conn.take()
        };
        if let Some(c) = conn {
            c.close();
        }
    }
}

/// Wake every holder in `missed`.
fn wake(missed: Vec<Waker>) {
    for w in missed {
        w.wake();
    }
}

#[cfg(test)]
#[path = "tests/line_tests.rs"]
mod tests;
