// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MEMBER PROGRAMS (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)): ONE long-lived program connection
//! per (instance, need, member), for a need whose `target_from` is the member-program path
//! (`busbar_contract::section::MEMBER_PROGRAM`). Each member's program is spawned on the first open
//! that names it ([`Member::lease`]) and kept: every later open on the member is a LEASE on the
//! same running program, so two exchanges with one member reach one process, and the plugin
//! correlates what it reads by its own ids.
//!
//! * A lease's first piece is its HEAD: one fields piece, a success, naming the program's
//!   GENERATION (`busbar_contract::conn::PROGRAM_GENERATION_FIELD`), which counts the member's
//!   spawns from `1`. Two leases reading one generation reach one running program; a plugin that
//!   must greet each program once (a handshake) greets each generation once.
//! * Every frame the program writes is handed to EVERY lease of its generation that is open when
//!   it is read, in order; a lease reads only what arrived after it opened. Whichever lease reads
//!   drives the program's pipes for all, and a frame read wakes every lease waiting on one.
//! * A write is ONE WHOLE MESSAGE ([`Connection::write_whole`]): leases sharing the program never
//!   interleave part of one message with another's.
//! * Closing a lease leaves the program running. A program that ends (its output closed, a failed
//!   pipe, or found exited when a lease opens) ends every lease of its generation, and the next
//!   open spawns it anew: the next generation. A program that keeps ending is restarted under
//!   backoff and stopped after a burst of ends ([`Supervisor`], the previous release's crash-loop
//!   policy), so a binary that always fails becomes a refusal, not a fork loop.
//! * A member RETIRED by a re-declaration (its registration gone, or its program changed) admits
//!   no new lease; its program is killed once its last lease closes (at once when it has none).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use busbar_contract::conn::{ConnError, Piece, PieceKind, Program, PROGRAM_GENERATION_FIELD};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::WireStatusClass;
use busbar_contract::transport::ConnFacts;

use crate::compose::{Connection, Dial, Failure, DEFAULT_OPEN_TIMEOUT};
use crate::framer::FramerDoor;

/// The first restart's backoff after a program ended (the previous release's crash-loop policy).
const BASE_BACKOFF: Duration = Duration::from_millis(100);
/// The ceiling the doubling backoff stops at.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// How many ends inside [`CRASH_WINDOW`] stop the restarts.
const CRASH_THRESHOLD: usize = 5;
/// The window the ends are counted over.
const CRASH_WINDOW: Duration = Duration::from_secs(60);

/// THE RESTART POLICY of one member's program: a circuit breaker, not a retry loop. Each end is
/// timed; the next spawn waits a backoff doubling from [`BASE_BACKOFF`] to [`MAX_BACKOFF`], and
/// [`CRASH_THRESHOLD`] ends inside [`CRASH_WINDOW`] stop the restarts until the member is declared
/// anew (an operator's changed program is a new member).
#[derive(Debug, Default)]
struct Supervisor {
    crashes: Vec<Instant>,
    restart_at: Option<Instant>,
    tripped: bool,
}

impl Supervisor {
    fn crashed(&mut self, now: Instant) {
        self.crashes
            .retain(|t| now.saturating_duration_since(*t) <= CRASH_WINDOW);
        self.crashes.push(now);
        if self.crashes.len() >= CRASH_THRESHOLD {
            self.tripped = true;
            return;
        }
        let shift = u32::try_from(self.crashes.len().saturating_sub(1))
            .unwrap_or(u32::MAX)
            .min(20);
        let backoff = BASE_BACKOFF.saturating_mul(1_u32 << shift).min(MAX_BACKOFF);
        self.restart_at = Some(now + backoff);
    }

    fn may_restart(&self, now: Instant) -> bool {
        !self.tripped && self.restart_at.is_none_or(|at| now >= at)
    }
}

/// The wakers of every lease waiting on a member's program, woken together: the program's pipes
/// are driven with this waker, so a frame read for one lease wakes them all.
#[derive(Default)]
struct Fan {
    wakers: Mutex<HashMap<u64, Waker>>,
}

impl Fan {
    fn register(&self, lease: u64, waker: &Waker) {
        self.wakers
            .lock()
            .expect("lease wakers")
            .insert(lease, waker.clone());
    }

    fn forget(&self, lease: u64) {
        self.wakers.lock().expect("lease wakers").remove(&lease);
    }

    fn wake_all(&self) {
        let woken: Vec<Waker> = self
            .wakers
            .lock()
            .expect("lease wakers")
            .drain()
            .map(|(_, w)| w)
            .collect();
        for w in woken {
            w.wake();
        }
    }
}

impl Wake for Fan {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

/// What one lease has to read.
struct Inbox {
    /// The generation it opened on.
    generation: u64,
    /// Its head's bytes, until read.
    head: Option<Vec<u8>>,
    /// The frames read since it opened, each with whether it ends its frame.
    pieces: VecDeque<(Vec<u8>, bool)>,
    /// The program ended: how (`None` = its output closed).
    ended: Option<Option<Failure>>,
    /// The end was read once; every read after it is closed.
    end_read: bool,
    /// The message its open carried, while the program's queue had no room for it.
    unsent: Option<Vec<u8>>,
}

/// The program as it runs.
struct Live {
    conn: Connection,
    generation: u64,
}

struct State {
    live: Option<Live>,
    generation: u64,
    retired: bool,
    next_lease: u64,
    leases: HashMap<u64, Inbox>,
    supervisor: Supervisor,
}

/// ONE MEMBER'S PROGRAM: its recipe, the entry framing its pipes, and the one connection every
/// lease on it shares.
pub(crate) struct Member {
    program: Program,
    door: Arc<dyn FramerDoor>,
    alpn: Vec<Vec<u8>>,
    state: Mutex<State>,
    fan: Arc<Fan>,
}

fn map(f: &Failure) -> ConnError {
    match f {
        Failure::Refused(_) => ConnError::Refused,
        Failure::Timeout => ConnError::Timeout,
        Failure::Closed => ConnError::Closed,
        Failure::Failed(_) => ConnError::Fault,
    }
}

/// A piece of `kind` that filled `len` bytes.
fn piece(kind: PieceKind, len: usize, end: bool) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end,
        status: (kind == PieceKind::Fields).then_some(WireStatusClass::Success),
        status_code: None,
        status_namespace: None,
        retry_after_secs: None,
        reason: None,
    }
}

impl State {
    /// The program of `generation` ended (`failure` = how, `None` = its output closed): it is
    /// killed, every lease of its generation ends, and an end the member did not ask for is a
    /// crash its supervisor counts.
    fn ended(&mut self, generation: u64, failure: Option<Failure>, fan: &Fan) {
        if self
            .live
            .as_ref()
            .is_some_and(|l| l.generation == generation)
        {
            if let Some(live) = self.live.take() {
                live.conn.close();
            }
            if !self.retired {
                self.supervisor.crashed(Instant::now());
            }
        }
        for inbox in self.leases.values_mut() {
            if inbox.generation == generation && inbox.ended.is_none() {
                inbox.ended = Some(failure.clone());
            }
        }
        fan.wake_all();
    }

    /// Queue what `lease`'s open carried, once the program's queue has room: `Ok(false)` while it
    /// has none.
    fn flush_unsent(&mut self, lease: u64, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let Some(inbox) = self.leases.get_mut(&lease) else {
            return Err(Failure::Closed);
        };
        let Some(unsent) = inbox.unsent.take() else {
            return Ok(true);
        };
        let generation = inbox.generation;
        let Some(live) = self.live.as_mut().filter(|l| l.generation == generation) else {
            return Err(Failure::Closed);
        };
        if live.conn.write_whole(&unsent, cx)? {
            return Ok(true);
        }
        if let Some(inbox) = self.leases.get_mut(&lease) {
            inbox.unsent = Some(unsent);
        }
        Ok(false)
    }
}

impl Member {
    /// The member running `program`, its pipes framed by `door`; nothing is spawned until the
    /// first lease.
    pub(crate) fn new(program: Program, door: Arc<dyn FramerDoor>, alpn: Vec<Vec<u8>>) -> Self {
        Self {
            program,
            door,
            alpn,
            state: Mutex::new(State {
                live: None,
                generation: 0,
                retired: false,
                next_lease: 1,
                leases: HashMap::new(),
                supervisor: Supervisor::default(),
            }),
            fan: Arc::new(Fan::default()),
        }
    }

    /// The program this member runs.
    pub(crate) fn program(&self) -> &Program {
        &self.program
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn fan_waker(&self) -> Waker {
        Waker::from(Arc::clone(&self.fan))
    }

    /// A LEASE on the member's program: spawned first when none runs (a new generation; one found
    /// exited is ended first), refused for a retired member and while the restart policy holds the
    /// program down. `first` (when not empty) is the lease's first message, written whole.
    pub(crate) fn lease(&self, first: &[u8]) -> Result<u64, ConnError> {
        let mut st = self.lock();
        if st.retired {
            return Err(ConnError::Refused);
        }
        // A program that already exited is never written to: its end is a crash, and this open
        // starts the next generation.
        let exited = st
            .live
            .as_mut()
            .and_then(|l| l.conn.program_exited().then_some(l.generation));
        if let Some(generation) = exited {
            st.ended(generation, None, &self.fan);
        }
        if st.live.is_none() {
            if !st.supervisor.may_restart(Instant::now()) {
                return Err(ConnError::Refused);
            }
            let dial = Dial {
                target: self.program.command.clone(),
                tls: None,
                alpn: self.alpn.clone(),
                open_timeout: DEFAULT_OPEN_TIMEOUT,
                opening: None,
                head_words: (Vec::new(), Vec::new()),
                anchors: None,
            };
            match Connection::spawn(Arc::clone(&self.door), &self.program, dial) {
                Ok(conn) => {
                    st.generation += 1;
                    let generation = st.generation;
                    st.live = Some(Live { conn, generation });
                }
                Err(f) => {
                    // A spawn that fails repeats on every attempt: it is counted like any end.
                    st.supervisor.crashed(Instant::now());
                    return Err(map(&f));
                }
            }
        }
        let generation = st.generation;
        let lease = st.next_lease;
        st.next_lease += 1;
        let mut head = Vec::new();
        head.extend_from_slice(PROGRAM_GENERATION_FIELD.as_bytes());
        head.extend_from_slice(busbar_contract::abi::transport::fields::SEPARATOR);
        head.extend_from_slice(generation.to_string().as_bytes());
        head.extend_from_slice(busbar_contract::abi::transport::fields::LINE_END);
        st.leases.insert(
            lease,
            Inbox {
                generation,
                head: Some(head),
                pieces: VecDeque::new(),
                ended: None,
                end_read: false,
                unsent: (!first.is_empty()).then(|| first.to_vec()),
            },
        );
        let waker = self.fan_waker();
        if let Err(f) = st.flush_unsent(lease, &mut Context::from_waker(&waker)) {
            st.ended(generation, Some(f.clone()), &self.fan);
            st.leases.remove(&lease);
            return Err(map(&f));
        }
        Ok(lease)
    }

    /// `lease`'s next piece into `buf`: its head, then each frame the program wrote since it
    /// opened, then the program's end; `Pending` (waking `waker`) while nothing has arrived.
    pub(crate) fn read(
        &self,
        lease: u64,
        waker: &Waker,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let fan_waker = self.fan_waker();
        let mut cx = Context::from_waker(&fan_waker);
        let mut st = self.lock();
        loop {
            let inbox = st.leases.get_mut(&lease).ok_or(ConnError::Closed)?;
            if let Some(head) = inbox.head.as_mut() {
                let n = head.len().min(buf.len());
                buf[..n].copy_from_slice(&head[..n]);
                head.drain(..n);
                let end = head.is_empty();
                if end {
                    inbox.head = None;
                }
                return Ok(piece(PieceKind::Fields, n, end));
            }
            if let Some((mut bytes, end)) = inbox.pieces.pop_front() {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                if n < bytes.len() {
                    bytes.drain(..n);
                    inbox.pieces.push_front((bytes, end));
                    return Ok(piece(PieceKind::Body, n, false));
                }
                return Ok(piece(PieceKind::Body, n, end));
            }
            if let Some(end) = inbox.ended.clone() {
                if inbox.end_read {
                    return Err(ConnError::Closed);
                }
                inbox.end_read = true;
                return match end {
                    None => Ok(piece(PieceKind::Completion, 0, true)),
                    Some(f) => Err(map(&f)),
                };
            }
            let generation = inbox.generation;
            match st.flush_unsent(lease, &mut cx) {
                Ok(_) => {}
                Err(f) => {
                    st.ended(generation, Some(f), &self.fan);
                    continue;
                }
            }
            let Some(live) = st.live.as_mut().filter(|l| l.generation == generation) else {
                st.ended(generation, None, &self.fan);
                continue;
            };
            self.fan.register(lease, waker);
            match live.conn.poll_piece(&mut cx) {
                Poll::Pending => return Err(ConnError::Pending),
                Poll::Ready(Ok(Some(got))) => {
                    if got.fields || (got.bytes.is_empty() && !got.end_of_frame) {
                        continue;
                    }
                    for inbox in st.leases.values_mut() {
                        if inbox.generation == generation && inbox.ended.is_none() {
                            inbox
                                .pieces
                                .push_back((got.bytes.clone(), got.end_of_frame));
                        }
                    }
                    self.fan.wake_all();
                }
                Poll::Ready(Ok(None)) => st.ended(generation, None, &self.fan),
                Poll::Ready(Err(f)) => st.ended(generation, Some(f), &self.fan),
            }
        }
    }

    /// Whether `lease` has a piece (or its end) ready, `waker` woken when one arrives.
    pub(crate) fn ready(&self, lease: u64, waker: &Waker) -> Result<bool, ConnError> {
        let fan_waker = self.fan_waker();
        let mut st = self.lock();
        let inbox = st.leases.get(&lease).ok_or(ConnError::Closed)?;
        if inbox.head.is_some() || !inbox.pieces.is_empty() || inbox.ended.is_some() {
            return Ok(true);
        }
        let generation = inbox.generation;
        let Some(live) = st.live.as_mut().filter(|l| l.generation == generation) else {
            return Ok(true);
        };
        self.fan.register(lease, waker);
        Ok(live
            .conn
            .poll_ready(&mut Context::from_waker(&fan_waker))
            .is_ready())
    }

    /// Write `bytes` on `lease` as ONE WHOLE MESSAGE: all taken, or `Pending` while the program's
    /// queue has no room for it.
    pub(crate) fn write(&self, lease: u64, bytes: &[u8]) -> Result<usize, ConnError> {
        let fan_waker = self.fan_waker();
        let mut cx = Context::from_waker(&fan_waker);
        let mut st = self.lock();
        let generation = st
            .leases
            .get(&lease)
            .filter(|i| i.ended.is_none())
            .map(|i| i.generation)
            .ok_or(ConnError::Closed)?;
        match st.flush_unsent(lease, &mut cx) {
            Ok(true) => {}
            Ok(false) => return Err(ConnError::Pending),
            Err(f) => {
                st.ended(generation, Some(f.clone()), &self.fan);
                return Err(map(&f));
            }
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let Some(live) = st.live.as_mut().filter(|l| l.generation == generation) else {
            return Err(ConnError::Closed);
        };
        match live.conn.write_whole(bytes, &mut cx) {
            Ok(true) => Ok(bytes.len()),
            Ok(false) => Err(ConnError::Pending),
            Err(f) => {
                st.ended(generation, Some(f.clone()), &self.fan);
                Err(map(&f))
            }
        }
    }

    /// What `lease`'s program established: no security, the entry's claim.
    pub(crate) fn facts(&self, lease: u64) -> Result<ConnFacts, ConnError> {
        let st = self.lock();
        st.leases.get(&lease).ok_or(ConnError::Closed)?;
        Ok(ConnFacts {
            sni: None,
            alpn: None,
            peer_cert: None,
            // A program is no network peer: no key is pinned, no client identity presented.
            peer_key_pin: None,
            client_identity: false,
            claim: self.door.facts().claims.first().map(|c| (*c).to_owned()),
        })
    }

    /// Close `lease`; the program runs on, unless the member is retired and this was its last
    /// lease.
    pub(crate) fn close(&self, lease: u64) {
        self.fan.forget(lease);
        let mut st = self.lock();
        st.leases.remove(&lease);
        if st.retired && st.leases.is_empty() {
            if let Some(live) = st.live.take() {
                live.conn.close();
            }
        }
    }

    /// RETIRE the member: no new lease; its program is killed now when no lease is open, else
    /// once the last one closes.
    pub(crate) fn retire(&self) {
        let mut st = self.lock();
        st.retired = true;
        if st.leases.is_empty() {
            if let Some(live) = st.live.take() {
                live.conn.close();
            }
        }
    }
}

/// EVERY MEMBER of one member-program need, by member name.
pub(crate) type Members = HashMap<String, Arc<Member>>;

/// The member an open's target names: its text up to the first `/` (a path the plugin spelled
/// after it is not the program's).
pub(crate) fn member_of(target: &str) -> &str {
    target.split('/').next().unwrap_or_default()
}

#[cfg(test)]
#[path = "tests/program_tests.rs"]
mod tests;
