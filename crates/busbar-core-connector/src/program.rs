// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MEMBER PROGRAMS: ONE long-lived program connection
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
//!   it is read, in order; a lease reads only what arrived after it opened, and only WHOLE frames:
//!   one opened while a frame is part way through skips that frame's rest (another lease's
//!   message, never the start of its own). Whichever lease reads drives the program's pipes for
//!   all, and a frame read wakes every lease waiting on one.
//! * A write is ONE WHOLE MESSAGE ([`Connection::write_whole`]): leases sharing the program never
//!   interleave part of one message with another's.
//! * Closing a lease leaves the program running. A program that ends (its output closed, a failed
//!   pipe, or found exited when a lease opens) ends every lease of its generation, and the next
//!   open spawns it anew: the next generation. WHETHER IT MAY BE SPAWNED AGAIN IS NOT DECIDED
//!   HERE: the supervisor of a spawned program is its carrier's (`BUSBAR-1.6.0.md` l.388). Every
//!   spawn is a `dial` carrying the member's supervision key (`DialIn::supervision_key`), and the
//!   carrier's verdict on it (spawned, or refused while it holds the program down) is the open's
//!   answer. The host keeps only the spawn's hygiene ([`Connection::spawn`], `hostio`).
//! * A member RETIRED by a re-declaration (its registration gone, or its program changed) admits
//!   no new lease; its program is killed once its last lease closes (at once when it has none).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use busbar_contract::conn::{ConnError, Piece, PieceKind, Program, PROGRAM_GENERATION_FIELD};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::WireStatusClass;
use busbar_contract::transport::ConnFacts;

use crate::compose::{Connection, Dial, Failure, Via, DEFAULT_OPEN_TIMEOUT, RECEIVE_BUFFER_BYTES};
use crate::map;

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
    /// The bytes of `pieces`: at [`RECEIVE_BUFFER_BYTES`] the program is not read again until this
    /// lease reads (the program held back, as a line's far end is by a holder that does not read).
    queued: usize,
    /// The program ended: how (`None` = its output closed).
    ended: Option<Option<Failure>>,
    /// The end was read once; every read after it is closed.
    end_read: bool,
    /// The message its open carried, while the program's queue had no room for it.
    unsent: Option<Vec<u8>>,
    /// It opened part way through a frame: that frame's rest is skipped.
    mid_frame: bool,
}

/// The program as it runs.
struct Live {
    conn: Connection,
    generation: u64,
}

struct State {
    live: Option<Live>,
    generation: u64,
    /// The last piece handed to the leases did not end its frame.
    mid_frame: bool,
    retired: bool,
    /// Its carrier was told its supervision key is retired ([`Member::end_retired`]).
    key_retired: bool,
    next_lease: u64,
    leases: HashMap<u64, Inbox>,
}

/// ONE MEMBER'S PROGRAM: its recipe, the entry framing its pipes, and the one connection every
/// lease on it shares.
pub(crate) struct Member {
    program: Program,
    /// Its environment references, resolved at config time and held for every spawn.
    env: crate::spawn_env::HeldEnv,
    /// The carrier the member's program rides.
    via: Via,
    alpn: Vec<Vec<u8>>,
    state: Mutex<State>,
    fan: Arc<Fan>,
    /// Its supervision key (`DialIn::supervision_key`): minted at [`Member::new`], never `0`, and
    /// kept for as long as this member is, so a re-declaration that keeps the member keeps it.
    supervision_key: u64,
}

/// The next member's supervision key: process-wide, from `1`.
static NEXT_SUPERVISION_KEY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

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
        fault: None,
        reason: None,
        declared_len: None,
    }
}

impl State {
    /// Whether a lease of `generation` still open holds [`RECEIVE_BUFFER_BYTES`] unread: the
    /// program is not read until it reads.
    fn backlogged(&self, generation: u64) -> bool {
        self.leases.values().any(|i| {
            i.generation == generation && i.ended.is_none() && i.queued >= RECEIVE_BUFFER_BYTES
        })
    }

    /// The program of `generation` ended (`failure` = how, `None` = its output closed): it is
    /// killed and every lease of its generation ends. The end is the carrier's to count (its
    /// supervisor saw the program's output close, or finds it ended at the `shut`).
    fn ended(&mut self, generation: u64, failure: Option<Failure>, fan: &Fan) {
        if self
            .live
            .as_ref()
            .is_some_and(|l| l.generation == generation)
        {
            if let Some(live) = self.live.take() {
                live.conn.close();
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
    /// The member running `program` over the carrier `via`, its environment references held as
    /// `env`; nothing is spawned until the first lease.
    pub(crate) fn new(
        program: Program,
        env: crate::spawn_env::HeldEnv,
        via: Via,
        alpn: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            program,
            env,
            via,
            alpn,
            state: Mutex::new(State {
                live: None,
                generation: 0,
                mid_frame: false,
                retired: false,
                key_retired: false,
                next_lease: 1,
                leases: HashMap::new(),
            }),
            fan: Arc::new(Fan::default()),
            supervision_key: NEXT_SUPERVISION_KEY
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// The program this member runs.
    pub(crate) fn program(&self) -> &Program {
        &self.program
    }

    /// Its environment references as config time resolved them.
    pub(crate) fn env(&self) -> &crate::spawn_env::HeldEnv {
        &self.env
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
    /// exited is ended first), refused for a retired member, and refused when the carrier refuses
    /// the spawn (its supervisor holding the program down is the carrier's verdict, not this
    /// host's). `first` (when not empty) is the lease's first message, written whole.
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
            let dial = Dial {
                target: self.program.command.clone(),
                tls: None,
                alpn: self.alpn.clone(),
                open_timeout: DEFAULT_OPEN_TIMEOUT,
                opening: None,
                head_words: (Vec::new(), Vec::new()),
                anchors: None,
            };
            match Connection::spawn(
                &self.via,
                &self.program,
                &self.env,
                dial,
                self.supervision_key,
            ) {
                Ok(conn) => {
                    st.generation += 1;
                    let generation = st.generation;
                    st.live = Some(Live { conn, generation });
                    st.mid_frame = false;
                }
                Err(f) => return Err(map(&f)),
            }
        }
        let generation = st.generation;
        let mid_frame = st.mid_frame;
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
                queued: 0,
                ended: None,
                end_read: false,
                unsent: (!first.is_empty()).then(|| first.to_vec()),
                mid_frame,
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
                let full = inbox.queued >= RECEIVE_BUFFER_BYTES;
                inbox.queued = inbox.queued.saturating_sub(n);
                if full && inbox.queued < RECEIVE_BUFFER_BYTES {
                    // Under the cap again: the program is read again, for whoever waits on it.
                    self.fan.wake_all();
                }
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
            if !st.live.as_ref().is_some_and(|l| l.generation == generation) {
                st.ended(generation, None, &self.fan);
                continue;
            }
            self.fan.register(lease, waker);
            if st.backlogged(generation) {
                return Err(ConnError::Pending);
            }
            let Some(live) = st.live.as_mut().filter(|l| l.generation == generation) else {
                continue;
            };
            match live.conn.poll_piece(&mut cx) {
                Poll::Pending => return Err(ConnError::Pending),
                Poll::Ready(Ok(Some(got))) => {
                    if got.fields || (got.bytes.is_empty() && !got.end_of_frame) {
                        continue;
                    }
                    for inbox in st.leases.values_mut() {
                        if inbox.generation != generation || inbox.ended.is_some() {
                            continue;
                        }
                        if inbox.mid_frame {
                            inbox.mid_frame = !got.end_of_frame;
                            continue;
                        }
                        inbox.queued += got.bytes.len();
                        inbox
                            .pieces
                            .push_back((got.bytes.clone(), got.end_of_frame));
                    }
                    st.mid_frame = !got.end_of_frame;
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
        if st.live.as_ref().is_some_and(|l| l.generation == generation) && st.backlogged(generation)
        {
            self.fan.register(lease, waker);
            return Ok(false);
        }
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
            claim: self
                .via
                .door
                .facts()
                .claims
                .first()
                .map(|c| (*c).to_owned()),
        })
    }

    /// Close `lease`; the program runs on, unless the member is retired and this was its last
    /// lease.
    pub(crate) fn close(&self, lease: u64) {
        self.fan.forget(lease);
        let mut st = self.lock();
        // A lease that held the program back lets it go: whoever waits on it reads it again.
        if st
            .leases
            .remove(&lease)
            .is_some_and(|i| i.queued >= RECEIVE_BUFFER_BYTES)
        {
            self.fan.wake_all();
        }
        let ending = st.retired && st.leases.is_empty();
        drop(st);
        if ending {
            self.end_retired();
        }
    }

    /// RETIRE the member: no new lease; its program is killed now when no lease is open, else
    /// once the last one closes.
    pub(crate) fn retire(&self) {
        let mut st = self.lock();
        st.retired = true;
        let ending = st.leases.is_empty();
        drop(st);
        if ending {
            self.end_retired();
        }
    }

    /// A RETIRED MEMBER WITH NO LEASE ENDS, once: its program is shut, then its carrier is told
    /// its supervision key is retired (`abi::transport::DEST_RETIRED`), so a supervising carrier
    /// forgets it. Both cross the carrier with no host lock held.
    fn end_retired(&self) {
        let (live, signal) = {
            let mut st = self.lock();
            let signal = !std::mem::replace(&mut st.key_retired, true);
            (st.live.take(), signal)
        };
        if let Some(live) = live {
            live.conn.close();
        }
        if signal {
            crate::carrier::Carried::retire_key(&self.via.door, &self.via.io, self.supervision_key);
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
