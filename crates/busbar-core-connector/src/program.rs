// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MEMBER PROGRAMS: ONE long-lived program connection

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};

use base64::Engine as _;
use busbar_contract::conn::{
    ConnError, Piece, PieceKind, Program, PROGRAM_EXPECT_GENERATION_FIELD,
    PROGRAM_EXPECT_INSTANCE_FIELD, PROGRAM_GENERATION_FIELD, PROGRAM_IDENTITY_FIELD,
    PROGRAM_INSTANCE_FIELD,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::WireStatusClass;
use busbar_contract::transport::ConnFacts;

use crate::compose::{Connection, Dial, Failure, Via, DEFAULT_OPEN_TIMEOUT, RECEIVE_BUFFER_BYTES};
use crate::map;

/// The wakers of every lease waiting on a member's program, woken together: the program's pipes
/// are driven with this waker, so a frame read for one lease wakes them all.
#[derive(Default)]
struct Fan {
    wakers: Mutex<HashMap<u64, Arc<Waker>>>,
}

impl Fan {
    /// The caller owns `waker` before taking any member lock. Return the displaced owner so its
    fn register(&self, lease: u64, waker: &Arc<Waker>) -> Option<Arc<Waker>> {
        self.wakers
            .lock()
            .expect("lease wakers")
            .insert(lease, Arc::clone(waker))
    }

    fn forget(&self, lease: u64) -> Option<Arc<Waker>> {
        self.wakers.lock().expect("lease wakers").remove(&lease)
    }

    fn wake_all(&self) {
        let woken: Vec<Arc<Waker>> = self
            .wakers
            .lock()
            .expect("lease wakers")
            .drain()
            .map(|(_, w)| w)
            .collect();
        for w in woken {
            w.wake_by_ref();
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
    /// Its connection while it is at home: `None` while a lease drives it with no lock held
    conn: Option<Connection>,
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
    /// A lease is spawning the next generation, with no lock held: another open waits for it.
    spawning: bool,
    /// Spawn attempts and connections whose close has not returned yet.
    programs_outstanding: usize,
    /// The callers that found the program's connection out with another lease, woken once it is
    missed: Vec<Arc<Waker>>,
    /// Notifications and displaced caller owners are retired only after the outer State guard.
    wake_missed: Vec<Arc<Waker>>,
    retired_wakers: Vec<Arc<Waker>>,
    wake_fan: bool,
    /// Connections taken out of the member to be closed, each once the lock is let go
    doomed: Vec<Connection>,
}

/// THE MEMBER'S LOCK, held. NO PLUGIN CODE RUNS UNDER IT (`BUSBAR-1.6.0.md` §11.13 M1): a
struct Locked<'m>(Option<MutexGuard<'m, State>>, &'m Member);

impl std::ops::Deref for Locked<'_> {
    type Target = State;

    fn deref(&self) -> &State {
        self.0.as_ref().expect("the member's lock")
    }
}

impl std::ops::DerefMut for Locked<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.0.as_mut().expect("the member's lock")
    }
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        let (doomed, missed, retired, wake_fan) = self
            .0
            .take()
            .map(|mut st| {
                (
                    std::mem::take(&mut st.doomed),
                    std::mem::take(&mut st.wake_missed),
                    std::mem::take(&mut st.retired_wakers),
                    std::mem::take(&mut st.wake_fan),
                )
            })
            .unwrap_or_default();

        drop(retired);
        for waker in missed {
            waker.wake_by_ref();
        }
        if wake_fan {
            self.1.fan.wake_all();
        }
        for conn in doomed {
            conn.close();

            self.1.lock().programs_outstanding -= 1;
            self.1.end_retired();
        }
    }
}

/// A connection a lease has out of its member. Only an unwind out of a drive drops it still
struct Out<'m> {
    member: &'m Member,
    generation: u64,
    conn: Option<Connection>,
}

impl Drop for Out<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let mut st = self.member.lock();
            st.ended(self.generation, Some(Failure::Closed));
            st.doomed.push(conn);
        }
    }
}

/// A spawn in flight with no lock held. Only an unwind out of the spawn drops it armed: the spawn
struct Spawning<'m> {
    member: &'m Member,
    armed: bool,
}

impl Drop for Spawning<'_> {
    fn drop(&mut self) {
        if self.armed {
            {
                let mut st = self.member.lock();
                st.spawning = false;
                st.programs_outstanding -= 1;
            }
            self.member.spawned.notify_all();
            self.member.end_retired();
        }
    }
}

/// ONE MEMBER'S PROGRAM: its recipe, the entry framing its pipes, and the one connection every
pub(crate) struct Member {
    program: Program,
    /// Its environment references, resolved at config time and held for every spawn.
    env: crate::spawn_env::HeldEnv,
    /// The carrier the member's program rides.
    via: Via,
    alpn: Vec<Vec<u8>>,
    state: Mutex<State>,
    /// Signalled as a spawn comes to its end.
    spawned: Condvar,
    fan: Arc<Fan>,
    /// Its supervision key (`DialIn::supervision_key`): minted at [`Member::new`], never `0`, and
    supervision_key: u64,
}

/// The next member's supervision key: process-wide, from `1`.
static NEXT_SUPERVISION_KEY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Expected {
    pub instance: u64,
    pub generation: u64,
}

pub(crate) fn is_expected_field(name: &str) -> bool {
    name.trim()
        .eq_ignore_ascii_case(PROGRAM_EXPECT_INSTANCE_FIELD)
        || name
            .trim()
            .eq_ignore_ascii_case(PROGRAM_EXPECT_GENERATION_FIELD)
}

impl Expected {
    pub(crate) fn of(fields: &[(&str, &[u8])]) -> Result<Option<Self>, ConnError> {
        let (mut instance, mut generation) = (None, None);
        for (name, value) in fields {
            let slot = if name.eq_ignore_ascii_case(PROGRAM_EXPECT_INSTANCE_FIELD) {
                &mut instance
            } else if name.eq_ignore_ascii_case(PROGRAM_EXPECT_GENERATION_FIELD) {
                &mut generation
            } else {
                return Err(ConnError::Refused);
            };
            if slot.is_some()
                || value.is_empty()
                || value[0] == b'0'
                || !value.iter().all(u8::is_ascii_digit)
            {
                return Err(ConnError::Refused);
            }
            *slot = Some(
                std::str::from_utf8(value)
                    .map_err(|_| ConnError::Refused)?
                    .parse::<u64>()
                    .map_err(|_| ConnError::Refused)?,
            );
        }
        match (instance, generation) {
            (None, None) => Ok(None),
            (Some(instance), Some(generation)) => Ok(Some(Self {
                instance,
                generation,
            })),
            _ => Err(ConnError::Refused),
        }
    }
}

fn next_supervision_key(counter: &std::sync::atomic::AtomicU64) -> Result<u64, ConnError> {
    counter
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |next| if next == 0 { None } else { next.checked_add(1) },
        )
        .map_err(|_| ConnError::Refused)
}

/// A piece of `kind` that filled `len` bytes.
fn piece(kind: PieceKind, len: usize, end: bool) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end,
        status: (kind == PieceKind::Fields).then_some(WireStatusClass::Success),
        status_code: (kind == PieceKind::Fields).then_some(200),
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

impl State {
    /// Whether a lease of `generation` still open holds [`RECEIVE_BUFFER_BYTES`] unread: the
    fn backlogged(&self, generation: u64) -> bool {
        self.leases.values().any(|i| {
            i.generation == generation && i.ended.is_none() && i.queued >= RECEIVE_BUFFER_BYTES
        })
    }

    /// The program of `generation` ended (`failure` = how, `None` = its output closed): it is
    fn ended(&mut self, generation: u64, failure: Option<Failure>) {
        if self
            .live
            .as_ref()
            .is_some_and(|l| l.generation == generation)
        {
            self.kill();
        }
        for inbox in self.leases.values_mut() {
            if inbox.generation == generation && inbox.ended.is_none() {
                inbox.ended = Some(failure.clone());
            }
        }
        let missed = std::mem::take(&mut self.missed);
        self.wake_missed.extend(missed);
        self.wake_fan = true;
    }

    /// The running program is let go: its connection (when at home) is closed once the lock is
    fn kill(&mut self) {
        if let Some(conn) = self.live.take().and_then(|l| l.conn) {
            self.doomed.push(conn);
        }
    }

    /// `waker`'s caller found the program's connection out: it is woken once it is back.
    fn miss(&mut self, waker: &Arc<Waker>) {
        if !self.missed.iter().any(|w| w.will_wake(waker)) {
            self.missed.push(Arc::clone(waker));
        }
    }
}

impl Member {
    /// The member running `program` over the carrier `via`, its environment references held as
    pub(crate) fn new(
        program: Program,
        env: crate::spawn_env::HeldEnv,
        via: Via,
        alpn: Vec<Vec<u8>>,
    ) -> Result<Self, ConnError> {
        let supervision_key = next_supervision_key(&NEXT_SUPERVISION_KEY)?;
        Ok(Self {
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
                spawning: false,
                programs_outstanding: 0,
                missed: Vec::new(),
                wake_missed: Vec::new(),
                retired_wakers: Vec::new(),
                wake_fan: false,
                doomed: Vec::new(),
            }),
            spawned: Condvar::new(),
            fan: Arc::new(Fan::default()),
            supervision_key,
        })
    }

    /// The program this member runs.
    pub(crate) fn program(&self) -> &Program {
        &self.program
    }

    /// Its environment references as config time resolved them.
    pub(crate) fn env(&self) -> &crate::spawn_env::HeldEnv {
        &self.env
    }

    fn lock(&self) -> Locked<'_> {
        Locked(
            Some(
                self.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            ),
            self,
        )
    }

    /// THE HAND-OFF (`BUSBAR-1.6.0.md` §11.13 M1). Take `generation`'s connection out of the
    fn crossing<'m, R>(
        &'m self,
        mut st: Locked<'m>,
        generation: u64,
        missed: &Arc<Waker>,
        drive: impl FnOnce(&mut Connection) -> R,
    ) -> (Locked<'m>, Option<R>) {
        let Some(live) = st.live.as_mut().filter(|l| l.generation == generation) else {
            return (st, None);
        };
        let Some(conn) = live.conn.take() else {
            st.miss(missed);
            return (st, None);
        };
        let mut out = Out {
            member: self,
            generation,
            conn: Some(conn),
        };
        drop(st);
        let r = drive(out.conn.as_mut().expect("the connection is out"));
        let conn = out.conn.take().expect("the connection is out");
        let mut st = self.lock();

        match st
            .live
            .as_mut()
            .filter(|l| l.generation == generation && l.conn.is_none())
        {
            Some(live) => live.conn = Some(conn),
            None => st.doomed.push(conn),
        }
        let missed = std::mem::take(&mut st.missed);
        st.wake_missed.extend(missed);
        (st, Some(r))
    }

    /// Queue what `lease`'s open carried, once the program's queue has room: `Ok(false)` while it
    fn flush_unsent<'m>(
        &'m self,
        mut st: Locked<'m>,
        lease: u64,
        cx: &mut Context<'_>,
        missed: &Arc<Waker>,
    ) -> (Locked<'m>, Result<bool, Failure>) {
        let Some(inbox) = st.leases.get_mut(&lease) else {
            return (st, Err(Failure::Closed));
        };
        let Some(unsent) = inbox.unsent.take() else {
            return (st, Ok(true));
        };
        let generation = inbox.generation;
        if !st.live.as_ref().is_some_and(|l| l.generation == generation) {
            return (st, Err(Failure::Closed));
        }
        let (mut st, wrote) =
            self.crossing(st, generation, missed, |conn| conn.write_whole(&unsent, cx));
        match wrote {
            Some(Ok(true)) => (st, Ok(true)),
            Some(Err(f)) => (st, Err(f)),
            Some(Ok(false)) | None => {
                if let Some(inbox) = st.leases.get_mut(&lease) {
                    inbox.unsent = Some(unsent);
                }
                (st, Ok(false))
            }
        }
    }

    fn fan_waker(&self) -> Waker {
        Waker::from(Arc::clone(&self.fan))
    }

    /// A LEASE on the member's program: spawned first when none runs (a new generation; one found
    pub(crate) fn lease(&self, first: &[u8], expected: Option<Expected>) -> Result<u64, ConnError> {
        let waker = Arc::new(self.fan_waker());
        let mut st = self.lock();
        loop {
            if st.retired {
                return Err(ConnError::Refused);
            }
            if !st.spawning {
                break;
            }

            let guard = st.0.take().expect("the member's lock");
            st.0 = Some(
                self.spawned
                    .wait(guard)
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
        }

        let exited = st.live.as_mut().and_then(|l| {
            l.conn
                .as_mut()
                .is_some_and(Connection::program_exited)
                .then_some(l.generation)
        });
        if let Some(generation) = exited {
            st.ended(generation, None);
        }
        if let Some(expected) = expected {
            if expected.instance != self.supervision_key
                || !st
                    .live
                    .as_ref()
                    .is_some_and(|live| live.generation == expected.generation)
            {
                return Err(ConnError::Refused);
            }
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

            st.spawning = true;
            st.programs_outstanding += 1;
            let mut spawning = Spawning {
                member: self,
                armed: true,
            };
            drop(st);
            let spawned = Connection::spawn(
                &self.via,
                &self.program,
                &self.env,
                dial,
                self.supervision_key,
            );
            spawning.armed = false;
            st = self.lock();
            st.spawning = false;
            self.spawned.notify_all();
            match spawned {
                Ok(conn) if st.retired => {
                    st.doomed.push(conn);
                    return Err(ConnError::Refused);
                }
                Ok(conn) => {
                    st.generation += 1;
                    let generation = st.generation;
                    st.live = Some(Live {
                        conn: Some(conn),
                        generation,
                    });
                    st.mid_frame = false;
                }
                Err(f) => {
                    st.programs_outstanding -= 1;
                    drop(st);
                    self.end_retired();
                    return Err(map(&f));
                }
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
        for (name, value) in [
            (PROGRAM_INSTANCE_FIELD, self.supervision_key.to_string()),
            (
                PROGRAM_IDENTITY_FIELD,
                base64::engine::general_purpose::STANDARD.encode(self.program.command.as_bytes()),
            ),
        ] {
            head.extend_from_slice(name.as_bytes());
            head.extend_from_slice(busbar_contract::abi::transport::fields::SEPARATOR);
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(busbar_contract::abi::transport::fields::LINE_END);
        }
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
        let (mut st, flushed) =
            self.flush_unsent(st, lease, &mut Context::from_waker(&waker), &waker);
        if let Err(f) = flushed {
            st.ended(generation, Some(f.clone()));
            st.leases.remove(&lease);
            return Err(map(&f));
        }
        Ok(lease)
    }

    /// `lease`'s next piece into `buf`: its head, then each frame the program wrote since it
    pub(crate) fn read(
        &self,
        lease: u64,
        waker: &Waker,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let incoming = Arc::new(waker.clone());
        let fan_waker = Arc::new(self.fan_waker());
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
                let unblocked = full && inbox.queued < RECEIVE_BUFFER_BYTES;
                let piece = if n < bytes.len() {
                    bytes.drain(..n);
                    inbox.pieces.push_front((bytes, end));
                    piece(PieceKind::Body, n, false)
                } else {
                    piece(PieceKind::Body, n, end)
                };
                if unblocked {
                    st.wake_fan = true;
                }
                return Ok(piece);
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
            let (back, flushed) = self.flush_unsent(st, lease, &mut cx, &fan_waker);
            st = back;
            match flushed {
                Ok(_) => {}
                Err(f) => {
                    st.ended(generation, Some(f));
                    continue;
                }
            }
            if !st.live.as_ref().is_some_and(|l| l.generation == generation) {
                st.ended(generation, None);
                continue;
            }
            st.retired_wakers
                .extend(self.fan.register(lease, &incoming));
            if st.backlogged(generation) {
                return Err(ConnError::Pending);
            }
            let (back, polled) =
                self.crossing(st, generation, &incoming, |conn| conn.poll_piece(&mut cx));
            st = back;

            let Some(polled) = polled else {
                return Err(ConnError::Pending);
            };
            match polled {
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
                    st.wake_fan = true;
                }
                Poll::Ready(Ok(None)) => st.ended(generation, None),
                Poll::Ready(Err(f)) => st.ended(generation, Some(f)),
            }
        }
    }

    /// Whether `lease` has a piece (or its end) ready, `waker` woken when one arrives.
    pub(crate) fn ready(&self, lease: u64, waker: &Waker) -> Result<bool, ConnError> {
        let incoming = Arc::new(waker.clone());
        let fan_waker = Arc::new(self.fan_waker());
        let mut st = self.lock();
        let inbox = st.leases.get(&lease).ok_or(ConnError::Closed)?;
        if inbox.head.is_some() || !inbox.pieces.is_empty() || inbox.ended.is_some() {
            return Ok(true);
        }
        let generation = inbox.generation;
        if st.live.as_ref().is_some_and(|l| l.generation == generation) && st.backlogged(generation)
        {
            st.retired_wakers
                .extend(self.fan.register(lease, &incoming));
            return Ok(false);
        }
        if !st.live.as_ref().is_some_and(|l| l.generation == generation) {
            return Ok(true);
        }
        st.retired_wakers
            .extend(self.fan.register(lease, &incoming));
        let (_st, polled) = self.crossing(st, generation, &incoming, |conn| {
            conn.poll_ready(&mut Context::from_waker(&fan_waker))
        });

        Ok(polled.is_some_and(|p| p.is_ready()))
    }

    /// Write `bytes` on `lease` as ONE WHOLE MESSAGE: all taken, or `Pending` while the program's
    pub(crate) fn write(&self, lease: u64, bytes: &[u8]) -> Result<usize, ConnError> {
        let fan_waker = Arc::new(self.fan_waker());
        let mut cx = Context::from_waker(&fan_waker);
        let st = self.lock();
        let generation = st
            .leases
            .get(&lease)
            .filter(|i| i.ended.is_none())
            .map(|i| i.generation)
            .ok_or(ConnError::Closed)?;
        let (mut st, flushed) = self.flush_unsent(st, lease, &mut cx, &fan_waker);
        match flushed {
            Ok(true) => {}
            Ok(false) => return Err(ConnError::Pending),
            Err(f) => {
                st.ended(generation, Some(f.clone()));
                return Err(map(&f));
            }
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        if !st.live.as_ref().is_some_and(|l| l.generation == generation) {
            return Err(ConnError::Closed);
        }
        let (mut st, wrote) = self.crossing(st, generation, &fan_waker, |conn| {
            conn.write_whole(bytes, &mut cx)
        });

        match wrote.unwrap_or(Ok(false)) {
            Ok(true) => Ok(bytes.len()),
            Ok(false) => Err(ConnError::Pending),
            Err(f) => {
                st.ended(generation, Some(f.clone()));
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
    pub(crate) fn close(&self, lease: u64) {
        let mut st = self.lock();

        st.retired_wakers.extend(self.fan.forget(lease));

        if st
            .leases
            .remove(&lease)
            .is_some_and(|i| i.queued >= RECEIVE_BUFFER_BYTES)
        {
            st.wake_fan = true;
        }
        let ending = st.retired && st.leases.is_empty();
        drop(st);
        if ending {
            self.end_retired();
        }
    }

    /// RETIRE the member: no new lease; its program is killed now when no lease is open, else
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
    fn end_retired(&self) {
        {
            let mut st = self.lock();
            if !st.retired || !st.leases.is_empty() {
                return;
            }
            st.kill();
        }
        let signal = {
            let mut st = self.lock();
            st.retired
                && st.leases.is_empty()
                && !st.spawning
                && st.programs_outstanding == 0
                && !std::mem::replace(&mut st.key_retired, true)
        };
        if signal {
            crate::carrier::Carried::retire_key(&self.via.door, &self.via.io, self.supervision_key);
        }
    }
}

/// EVERY MEMBER of one member-program need, by member name.
pub(crate) struct Declaration {
    member: Arc<Member>,
}

impl Declaration {
    pub(crate) fn new(member: Member) -> Self {
        Self {
            member: Arc::new(member),
        }
    }
    pub(crate) fn member(&self) -> Arc<Member> {
        Arc::clone(&self.member)
    }
}

impl std::ops::Deref for Declaration {
    type Target = Member;
    fn deref(&self) -> &Member {
        &self.member
    }
}

impl Drop for Declaration {
    fn drop(&mut self) {
        self.member.retire();
    }
}

/// Declaration custody is distinct from active leases: the last declaring record retires the
/// child even when a lease still holds its Member until the existing exchange finishes.
pub(crate) type Members = HashMap<String, Arc<Declaration>>;

/// The member an open's target names: its text up to the first `/` (a path the plugin spelled
pub(crate) fn member_of(target: &str) -> &str {
    target.split('/').next().unwrap_or_default()
}

#[cfg(test)]
#[path = "tests/program_tests.rs"]
mod tests;
