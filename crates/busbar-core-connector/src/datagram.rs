// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATAGRAM DRIVER: one association's datagram framer, driven host-side over the host's port
//! and secure layer (`BUSBAR-1.6.0.md` THE DESIGN §5, "Datagram media", l.758-766).
//!
//! The port is the host's ([`crate::udp`]) and so is the secure layer ([`crate::dtls`]); a framer
//! whose tail states `FRAMING_DATAGRAM` holds what is left. This driver stands between them for ONE
//! association and carries THE DATAGRAM LANE (`busbar_contract::abi::transport::datagram`) on every
//! call it makes:
//!
//! * PATHS ARE HOST NUMBERS. A far-end address gets a nonzero number the first time the driver
//!   hands up a datagram from it, and the framer is told it once, in the lane's `paths`. Only an
//!   address the secure layer knows (a verified check came from it, or core's own probe proved it)
//!   is ever handed up; anything else from the port stops here.
//! * THE RENDEZVOUS. The far end's description goes in on the rendezvous lane. The framer answers
//!   its own description as a piece and the terms; the terms build the secure layer's association
//!   (the handshake role, both ends' check credentials and the far end's certificate fingerprint).
//! * DATAGRAMS go through the secure layer's demultiplexer first ([`Association::ingest`]): what it
//!   hands up reaches the framer on the clear lane, and plaintext it opened on the secured lane.
//! * THE KEYING-MATERIAL ITEM. What the secure layer exported is presented ONCE, on the first call
//!   after the export, in host memory valid for that call, and then dropped, which zeroes it. It is
//!   never presented before the far end is verified: the secure layer exports nothing until the far
//!   end's certificate matched its description, and the lane's `verified` bit says so on the same
//!   call.
//! * ROUTES. A clear route leaves only where the secure layer allows it
//!   ([`Association::may_send_clear`]: the answer to a check to a path that sent one, anything else
//!   to the bound path); a secured route is sealed to the bound path. Any other route is dropped
//!   and counted ([`DatagramFraming::refused_routes`]).
//! * PATH REQUESTS go to the secure layer, which binds only a path it has proven by its own round
//!   trip; the lane's `bound` says where it stands on every call after.
//! * Every answer is judged (`check_datagram`) before any byte of it is used.
//! * THE DIALLING SIDE ([`DatagramFraming::dial`]) hears nothing before it sends: the far end's
//!   description advertised its candidates, and each is judged by the host's ONE destination judge
//!   ([`DialJudge`], under the dialling need's egress class) BEFORE any byte goes there. A candidate
//!   the judge refuses is never numbered, never told to the framer and never sent to; one it admits
//!   becomes an admitted candidate of the secure layer ([`Association::admit_candidate`]), which
//!   probes it and binds it only once that probe is answered from it. A verified check from a path
//!   no candidate named meets the SAME judge before the secure layer hears it: admitted, the path
//!   becomes an admitted candidate like any other; refused or pending, the check is dropped and the
//!   path is never probed, numbered, told to the framer or bound. The accepting side learns its
//!   paths from verified checks alone and admits no candidate.
//!
//! Sans-IO: the caller hands in what the port read and the clock, takes
//! [`DatagramFraming::poll_send`] out to the port, and calls [`DatagramFraming::timeout`] at
//! [`DatagramFraming::deadline`].

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use busbar_contract::abi::mechanism::call::{AbiStr, Field, Outcome};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::check::check_datagram;
use busbar_contract::abi::transport::{
    BeginIn, ConnFacts, DatagramLane, DatagramPath, DatagramRoute, EmitIn, FinishIn, FramerOut,
    FramingIn, IngestIn, KeyingMaterial, RendezvousTerms, CLOSE_NORMAL, EMIT_TEXT,
    FINGERPRINT_BYTES, HANDSHAKE_ANSWERS, HANDSHAKE_INITIATES, HANDSHAKE_NONE, LANE_CLEAR,
    LANE_RENDEZVOUS, LANE_SECURED, PATH_REQUEST_BIND, PATH_REQUEST_REBIND, SIDE_ACCEPT, SIDE_DIAL,
};

use crate::dtls::{Association, IceCredentials, Role, SessionCert, SrtpKeying, Up, Verdict};
use crate::framer::{instant_of, ready, Buffers, Call, Crossed, FramerDoor, Refused, Yielded};
use crate::publication::{Custody, Memory};
use crate::DialJudge;

/// The routes one framer answer may write.
pub(crate) const ROUTES_CAP: usize = 64;
/// The most far-end addresses one association numbers at once.
const MAX_PATHS: usize = 64;

const NO_TEXT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

fn text(b: &[u8]) -> AbiStr {
    if b.is_empty() {
        return NO_TEXT;
    }
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn fault(why: impl Into<String>) -> Refused {
    Refused {
        outcome: Outcome::Fault,
        error: why.into(),
    }
}

/// Explicit terminal reason when a configured pairing cannot retain its next checked batch.
pub const LINE_MEMORY_EXHAUSTED: &str = "the configured datagram LINE memory limit is exhausted";

fn needs_credit(error: &Refused) -> bool {
    error.error == LINE_MEMORY_EXHAUSTED
}

/// One incremental producer result. `Credit` has not crossed or accepted new input.
pub enum LineStep {
    /// The next ABI crossing needs storage credit; runnable publication must progress first.
    Credit,
    /// One checked batch. Fresh input was accepted only when `accepted` is true.
    Batch {
        /// The owned output.
        yielded: Yielded,
        /// This step crossed the supplied fresh input.
        accepted: bool,
    },
    /// The previous operation and its secure-layer settle have completed.
    Complete,
}

/// The host's numbers for the far-end addresses it has handed up.
#[derive(Debug, Default)]
struct PathBook {
    by_addr: HashMap<SocketAddr, u32>,
    by_path: HashMap<u32, SocketAddr>,
    /// Numbered, not yet told to the framer.
    untold: Vec<u32>,
    last: u32,
}

impl PathBook {
    fn path(&self, addr: SocketAddr) -> u32 {
        self.by_addr.get(&addr).copied().unwrap_or(0)
    }

    fn addr(&self, path: u32) -> Option<SocketAddr> {
        self.by_path.get(&path).copied()
    }

    /// `addr`'s number, numbering it now if it has none. At the cap the numbers of addresses the
    /// secure layer no longer knows make room (`keep` says which it still knows); a number is never
    /// reused.
    fn number(&mut self, addr: SocketAddr, keep: impl Fn(SocketAddr) -> bool) -> Option<u32> {
        if let Some(p) = self.by_addr.get(&addr) {
            return Some(*p);
        }
        if self.by_addr.len() >= MAX_PATHS {
            let gone: Vec<SocketAddr> =
                self.by_addr.keys().copied().filter(|a| !keep(*a)).collect();
            for a in gone {
                if let Some(p) = self.by_addr.remove(&a) {
                    self.by_path.remove(&p);
                    self.untold.retain(|u| *u != p);
                }
            }
            if self.by_addr.len() >= MAX_PATHS {
                return None;
            }
        }
        self.last = self.last.checked_add(1)?;
        self.by_addr.insert(addr, self.last);
        self.by_path.insert(self.last, addr);
        self.untold.push(self.last);
        Some(self.last)
    }
}

/// One framer op, as this driver makes it.
#[derive(Clone, Copy)]
enum Op<'a> {
    /// The opening fields a dialling framing offers.
    Begin(&'a [(String, Vec<u8>)]),
    /// Bytes on a lane (`0` = a call that only carries the host's state); `end` = the far end
    /// closed.
    Ingest {
        lane: u32,
        from: Option<SocketAddr>,
        bytes: &'a [u8],
        end: bool,
    },
    Emit {
        stream: u64,
        bytes: &'a [u8],
        end_of_frame: bool,
        text: bool,
    },
    Timer,
}

impl Op<'_> {
    /// The re-call a `YIELD_MORE` answer asks for: the same op, no new bytes.
    fn recall(self) -> Op<'static> {
        match self {
            Op::Begin(_) | Op::Timer => Op::Timer,
            Op::Ingest { .. } => Op::Ingest {
                lane: 0,
                from: None,
                bytes: &[],
                end: false,
            },
            Op::Emit { stream, .. } => Op::Emit {
                stream,
                bytes: &[],
                end_of_frame: false,
                text: false,
            },
        }
    }
}

/// One datagram operation, paused between checked host-output batches. The input is crossed
/// once before construction returns; a recall retains only the same op's empty-input form.
/// No later op may use the association until this turn is drained. Dropping an unfinished turn
/// finishes the association, so its already accepted bytes cannot be silently abandoned.
#[must_use = "drain the turn or drop it to finish its accepted operation"]
pub struct DatagramTurn<'f> {
    framing: &'f mut DatagramFraming,
    now: Instant,
    first: Option<Yielded>,
    recall: Option<Op<'static>>,
    recalls: crate::framer::Recalls,
    opened: VecDeque<Vec<u8>>,
    closed: bool,
    complete: bool,
    custody: Custody,
}

/// An owned same-op continuation. It holds no ABI loan and cannot accept fresh input.
struct Continuation {
    now: Instant,
    first: Option<Yielded>,
    recall: Option<Op<'static>>,
    recalls: crate::framer::Recalls,
    opened: VecDeque<Vec<u8>>,
    closed: bool,
    complete: bool,
    custody: Custody,
}

impl<'f> DatagramTurn<'f> {
    fn pause(mut self) -> Continuation {
        let continuation = Continuation {
            now: self.now,
            first: self.first.take(),
            recall: self.recall.take(),
            recalls: std::mem::take(&mut self.recalls),
            opened: std::mem::take(&mut self.opened),
            closed: self.closed,
            complete: self.complete,
            custody: std::mem::take(&mut self.custody),
        };
        self.complete = true;
        continuation
    }

    fn resume(framing: &'f mut DatagramFraming, continuation: Continuation) -> Self {
        Self {
            framing,
            now: continuation.now,
            first: continuation.first,
            recall: continuation.recall,
            recalls: continuation.recalls,
            opened: continuation.opened,
            closed: continuation.closed,
            complete: continuation.complete,
            custody: continuation.custody,
        }
    }
    fn settling(framing: &'f mut DatagramFraming, now: Instant) -> Self {
        Self {
            framing,
            now,
            first: None,
            recall: None,
            recalls: crate::framer::Recalls::default(),
            opened: VecDeque::new(),
            closed: false,
            complete: false,
            custody: Custody::default(),
        }
    }

    fn start(framing: &'f mut DatagramFraming, op: Op<'_>, now: Instant) -> Result<Self, Refused> {
        let mut turn = Self::settling(framing, now);
        match turn.cross(op) {
            Ok(batch) => turn.first = Some(batch),
            Err(error) => {
                // An explicit refusal keeps the existing operation's error contract; callers
                // decide whether it ends their session. Unwind and cancellation finish it.
                turn.complete = error.outcome == Outcome::Refused;
                return Err(error);
            }
        }
        Ok(turn)
    }

    fn cross(&mut self, op: Op<'_>) -> Result<Yielded, Refused> {
        let custody = self.framing.reserve_output()?;
        let producer = self
            .framing
            .memory
            .as_ref()
            .map(|memory| {
                memory
                    .producer()
                    .ok_or_else(|| fault("the pairing closed before the producer crossed"))
            })
            .transpose()?
            .unwrap_or_default();
        let answer = self.framing.cross_once(op)?;
        let mut batch = Yielded::default();
        batch.producer = producer;
        batch.custody = custody;
        let taken = self.framing.take(&answer, &mut batch, self.now);
        // take may copy wire before a later field fails validation. This owner wipes that
        // initialized copy on success and error; routes already leave through poll_send.
        zeroize::Zeroize::zeroize(&mut batch.wire);
        let done = taken?;
        batch.split_piece_custody();
        self.framing.metadata_custody = batch.custody.split(self.framing.bufs.field_storage());
        self.custody = batch.custody.split(
            std::mem::size_of::<Continuation>()
                + self.opened.capacity() * std::mem::size_of::<Vec<u8>>()
                + self.opened.iter().map(Vec::capacity).sum::<usize>(),
        );
        if !self.framing.send.is_empty() {
            self.framing.send_custody = batch.custody.split(
                self.framing.send.capacity() * std::mem::size_of::<(SocketAddr, Vec<u8>)>()
                    + self
                        .framing
                        .send
                        .iter()
                        .map(|(_, bytes)| bytes.capacity())
                        .sum::<usize>(),
            );
        }
        let retained = batch.retained_capacity();
        batch.custody.reduce(retained);
        if done {
            self.recall = None;
            self.recalls = crate::framer::Recalls::default();
        } else {
            self.recalls.owed(&answer)?;
            self.recall = Some(op.recall());
        }
        self.security_valid()?;
        Ok(batch)
    }

    fn security_valid(&self) -> Result<(), Refused> {
        if let Some(failure) = self.framing.secure.as_ref().and_then(Association::failure) {
            return Err(Refused {
                outcome: Outcome::Failed,
                error: format!("the secure layer failed the association: {failure:?}"),
            });
        }
        if self.framing.keying.is_some() && !self.framing.verified() {
            return Err(fault("keying material with the far end not verified"));
        }
        Ok(())
    }

    /// Take one checked output batch. Re-offer only after publishing the previous batch. `None`
    /// means the op, every same-op recall, and the secure-layer settle are all complete.
    ///
    /// # Errors
    ///
    /// The framer refused or produced an invalid answer, or the secure layer failed.
    pub fn next_batch(&mut self) -> Result<Option<Yielded>, Refused> {
        match self.advance() {
            Err(error) if needs_credit(&error) => Err(error),
            Err(error) => {
                // A previous READY crossing already took the operation's bytes. A failed
                // recall/settle cannot leave that accepted operation open for fresh input.
                self.framing.finish();
                self.complete = true;
                Err(error)
            }
            result => result,
        }
    }

    fn advance(&mut self) -> Result<Option<Yielded>, Refused> {
        if let Some(first) = self.first.take() {
            return Ok(Some(first));
        }
        if self.complete {
            return Ok(None);
        }
        loop {
            if let Some(op) = self.recall {
                return self.cross(op).map(Some);
            }
            if let Some(bytes) = self.opened.pop_front() {
                let from = self.framing.bound();
                let answer = self.cross(Op::Ingest {
                    lane: LANE_SECURED,
                    from,
                    bytes: &bytes,
                    end: false,
                });
                if answer.as_ref().is_err_and(needs_credit) {
                    self.opened.push_front(bytes);
                }
                return answer.map(Some);
            }
            if self.closed {
                let answer = self.cross(Op::Ingest {
                    lane: 0,
                    from: None,
                    bytes: &[],
                    end: true,
                });
                if answer.is_ok() {
                    self.closed = false;
                }
                return answer.map(Some);
            }
            if self
                .framing
                .secure
                .as_ref()
                .is_some_and(Association::has_host_output)
                && self.framing.credit.is_none()
            {
                self.framing.credit = Some(self.framing.reserve_output()?);
            }
            if let Some(secure) = self.framing.secure.as_mut() {
                while let Some(datagram) = secure.poll_wire() {
                    self.framing.send.push_back(datagram);
                }
                while let Some(up) = secure.poll_up() {
                    match up {
                        Up::Connected => {}
                        Up::Keyed(keying) => {
                            if self.framing.presented || self.framing.keying.is_some() {
                                return Err(fault("the secure layer exported keying twice"));
                            }
                            self.framing.keying = Some(keying);
                        }
                        Up::Plaintext(bytes) => self.opened.push_back(bytes),
                        Up::Closed => self.closed = true,
                    }
                }
            }
            if let Some(mut credit) = self.framing.credit.take() {
                if !self.framing.send.is_empty() {
                    self.framing.send_custody = credit.split(
                        self.framing.send.capacity() * std::mem::size_of::<(SocketAddr, Vec<u8>)>()
                            + self
                                .framing
                                .send
                                .iter()
                                .map(|(_, bytes)| bytes.capacity())
                                .sum::<usize>(),
                    );
                }
                self.custody = credit.split(
                    std::mem::size_of::<Continuation>()
                        + self.opened.capacity() * std::mem::size_of::<Vec<u8>>()
                        + self.opened.iter().map(Vec::capacity).sum::<usize>(),
                );
                // A later ABI crossing reserves its full bound independently of these
                // now-owned secure outputs; no credit is reused after it has been split.
            }
            self.security_valid()?;
            if !self.opened.is_empty() || self.closed {
                continue;
            }
            let state = (self.framing.bound_path(), self.framing.verified());
            if state != self.framing.told
                || self.framing.keying.is_some()
                || !self.framing.book.untold.is_empty()
            {
                return self
                    .cross(Op::Ingest {
                        lane: 0,
                        from: None,
                        bytes: &[],
                        end: false,
                    })
                    .map(Some);
            }
            self.complete = true;
            return Ok(None);
        }
    }

    /// Datagram output produced so far, available even while publication is paused.
    pub fn poll_send(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.framing.poll_send().or_else(|| {
            self.framing
                .secure
                .as_mut()
                .and_then(Association::poll_wire)
        })
    }
}

impl Drop for DatagramTurn<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.framing.finish();
        }
    }
}

fn append_batch(into: &mut Yielded, mut batch: Yielded) {
    batch.producer.prepend(std::mem::take(&mut into.producer));
    into.producer = batch.producer;
    batch.custody.prepend(std::mem::take(&mut into.custody));
    into.custody = batch.custody;
    into.heads.append(&mut batch.heads);
    into.pieces.append(&mut batch.pieces);
    into.piece_custody.append(&mut batch.piece_custody);
    into.flow.append(&mut batch.flow);
    into.interim.append(&mut batch.interim);
    into.ended |= batch.ended;
    into.deadline_ns = batch.deadline_ns;
    if batch.agreed != 0 {
        into.agreed = batch.agreed;
    }
}

/// What a framer answer asked of the host, copied out of its buffers.
#[derive(Default)]
struct Asked {
    routes: Vec<(u32, u32, Vec<u8>)>,
    request: (u32, u32, u32),
    terms: Option<Terms>,
}

/// Rendezvous terms, owned.
struct Terms {
    role: Role,
    local: IceCredentials,
    remote: IceCredentials,
    fingerprint: [u8; 32],
    /// The far end's advertised addresses, one per line, as the framer wrote them.
    candidates: Vec<String>,
}

/// ONE ASSOCIATION'S DATAGRAM FRAMER, driven over the host's port and secure layer (module docs).
pub struct DatagramFraming {
    door: Arc<dyn FramerDoor>,
    token: u64,
    bufs: Buffers,
    routes: Vec<DatagramRoute>,
    cert: Arc<SessionCert>,
    /// The host port's address, as text: the one candidate the framer advertises.
    local: String,
    secure: Option<Association>,
    book: PathBook,
    /// Exported by the secure layer, not yet presented.
    keying: Option<SrtpKeying>,
    /// The keying-material item has been presented.
    presented: bool,
    /// The host state the framer was last told: the bound path and the verified bit.
    told: (u32, bool),
    send: VecDeque<(SocketAddr, Vec<u8>)>,
    send_custody: Custody,
    retired_send: Custody,
    metadata_custody: Custody,
    refused_routes: u64,
    deadline_ns: Option<u64>,
    ended: bool,
    /// `SIDE_ACCEPT` or `SIDE_DIAL`.
    side: u32,
    /// The dialling side's destination judge and the need's egress class.
    judge: Option<(Arc<dyn DialJudge>, u32)>,
    refused_candidates: u64,
    /// The user name the far end's checks carry first, once the terms settled it: the key the
    /// port's demultiplexer finds this association by ([`Associations`]).
    user: Option<String>,
    memory: Option<Arc<Memory>>,
    credit: Option<Custody>,
    continuation: Option<Continuation>,
}

impl std::fmt::Debug for DatagramFraming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramFraming")
            .field("entry", &self.door.facts().name)
            .field("token", &self.token)
            .field("local", &self.local)
            .field("presented", &self.presented)
            .finish_non_exhaustive()
    }
}

impl DatagramFraming {
    /// Reserve the next checked batch before reading fresh input from the port. A failed
    /// reservation crosses no ABI and allocates no fallback output.
    pub fn prepare_output(&mut self) -> bool {
        if self.credit.is_some() {
            return true;
        }
        match self.reserve_output() {
            Ok(credit) => {
                self.credit = Some(credit);
                true
            }
            Err(_) => false,
        }
    }

    /// Return an unused pre-read reservation when the port did not relinquish input. Keeping
    /// idle credit would prevent the other leg from using the pairing's shared account.
    pub fn release_output_reservation(&mut self) {
        self.credit = None;
    }

    /// One fresh raw datagram, producing at most one checked output batch. Call only when the
    /// prior producer completed; subsequent batches resume through `line_step(None, ...)`.
    ///
    /// # Errors
    /// The association failed or a previous producer still owns it.
    pub fn datagram_step(
        &mut self,
        from: SocketAddr,
        bytes: &[u8],
        now: Instant,
    ) -> Result<LineStep, Refused> {
        if self.continuing() {
            return Err(fault("fresh datagram while a same-op continuation is owed"));
        }
        if !self.prepare_output() {
            return Ok(LineStep::Credit);
        }
        let unadmitted = self
            .secure
            .as_ref()
            .is_some_and(|secure| secure.unadmitted_check(from, bytes));
        if unadmitted && !self.admit_heard(from, now) {
            return self.settle_step(now);
        }
        let Some(secure) = self.secure.as_mut() else {
            self.credit = None;
            return Ok(LineStep::Complete);
        };
        let raw = secure.ingest(from, bytes, now) == Verdict::Raw && secure.knows(from);
        if !raw {
            return self.settle_step(now);
        }
        let known =
            |address: SocketAddr| secure.knows(address) || secure.bound_path() == Some(address);
        if self.book.number(from, known).is_none() {
            return self.settle_step(now);
        }
        self.start_step(
            Op::Ingest {
                lane: LANE_CLEAR,
                from: Some(from),
                bytes,
                end: false,
            },
            now,
        )
    }

    /// The clock, producing at most one checked output batch. Continuations retain same-op
    /// identity and are resumed without supplying fresh datagrams.
    ///
    /// # Errors
    /// The association failed or a previous producer still owns it.
    pub fn timeout_step(&mut self, now: Instant) -> Result<LineStep, Refused> {
        if self.continuing() {
            return Err(fault("fresh timer while a same-op continuation is owed"));
        }
        if !self.prepare_output() {
            return Ok(LineStep::Credit);
        }
        if let Some(secure) = self.secure.as_mut() {
            secure.handle_timeout(now);
        }
        if self.deadline_ns.is_some_and(|ns| instant_of(ns) <= now) {
            self.deadline_ns = None;
            self.start_step(Op::Timer, now)
        } else {
            self.settle_step(now)
        }
    }

    fn start_step(&mut self, op: Op<'_>, now: Instant) -> Result<LineStep, Refused> {
        let mut turn = DatagramTurn::start(self, op, now)?;
        let result = turn.next_batch();
        let continuation = turn.pause();
        self.keep_step(continuation, result, true)
    }

    fn settle_step(&mut self, now: Instant) -> Result<LineStep, Refused> {
        let mut turn = DatagramTurn::settling(self, now);
        let result = turn.next_batch();
        let continuation = turn.pause();
        self.keep_step(continuation, result, false)
    }

    fn keep_step(
        &mut self,
        continuation: Continuation,
        result: Result<Option<Yielded>, Refused>,
        accepted: bool,
    ) -> Result<LineStep, Refused> {
        match result {
            Ok(Some(mut yielded)) => {
                yielded.continuing = true;
                self.continuation = Some(continuation);
                Ok(LineStep::Batch { yielded, accepted })
            }
            Ok(None) => {
                self.credit = None;
                Ok(LineStep::Complete)
            }
            Err(error) if needs_credit(&error) => {
                self.continuation = Some(continuation);
                Ok(LineStep::Credit)
            }
            Err(error) => Err(error),
        }
    }
    /// Capture this pairing's storage account. Existing framings keep the account thereafter.
    pub fn memory(&mut self, memory: Arc<Memory>) {
        self.memory = Some(memory);
    }

    fn reserve_output(&mut self) -> Result<Custody, Refused> {
        if let Some(credit) = self.credit.take() {
            return Ok(credit);
        }
        let Some(memory) = &self.memory else {
            return Ok(Custody::default());
        };
        // Routes may independently overlap the entire wire buffer. Their copies coexist with
        // the checked output, and sealing may briefly retain plaintext and ciphertext together.
        let bound = self
            .bufs
            .retention_bound()
            .and_then(|n| {
                ROUTES_CAP
                    .checked_mul(crate::framer::WIRE_CAP)
                    .and_then(|routes| routes.checked_mul(3))
                    .and_then(|routes| n.checked_add(routes))
            })
            .and_then(|bound| {
                let queued = self.send.iter().try_fold(0_usize, |bytes, (_, datagram)| {
                    bytes.checked_add(datagram.capacity())
                })?;
                let slots = self
                    .send
                    .capacity()
                    .checked_mul(2)?
                    .checked_mul(std::mem::size_of::<(SocketAddr, Vec<u8>)>())?;
                bound.checked_add(queued)?.checked_add(slots)
            })
            .ok_or_else(|| fault(LINE_MEMORY_EXHAUSTED))?;
        memory
            .reserve(bound)
            .ok_or_else(|| fault(LINE_MEMORY_EXHAUSTED))
    }

    /// Whether a producer still owes a same-operation recall or secure-layer settle.
    #[must_use]
    pub fn continuing(&self) -> bool {
        self.continuation.is_some()
    }

    /// Cross at most one batch, resuming the old operation before any fresh Emit. A refused
    /// reservation leaves both the original bytes and continuation untouched.
    ///
    /// # Errors
    /// The framer or secure layer failed. Already accepted bytes must not be retried.
    pub fn line_step(
        &mut self,
        input: Option<&Across>,
        text: bool,
        now: Instant,
    ) -> Result<LineStep, Refused> {
        let continuation = self.continuation.take();
        let accepted = continuation.is_none() && input.is_some();
        let mut turn = if let Some(continuation) = continuation {
            DatagramTurn::resume(self, continuation)
        } else if let Some(input) = input {
            // Reserve before start, whose first crossing takes all the supplied bytes.
            match self.reserve_output() {
                Ok(credit) => self.credit = Some(credit),
                Err(error) if needs_credit(&error) => return Ok(LineStep::Credit),
                Err(error) => return Err(error),
            }
            DatagramTurn::start(
                self,
                Op::Emit {
                    stream: input.stream,
                    bytes: &input.bytes,
                    end_of_frame: input.end_of_frame,
                    text,
                },
                now,
            )?
        } else {
            return Ok(LineStep::Complete);
        };
        let result = turn.next_batch();
        let continuation = turn.pause();
        self.keep_step(continuation, result, accepted)
    }

    /// Begin an ACCEPTING association on `door`: the host's certificate `cert` (the framer gets its
    /// public DER, whose fingerprint its description states) and the host port's address `local`.
    /// The far end's description follows through [`Self::rendezvous`].
    ///
    /// # Errors
    ///
    /// The entry refused to frame it, or answered outside the lane's rules.
    pub fn accept(
        door: Arc<dyn FramerDoor>,
        cert: Arc<SessionCert>,
        local: SocketAddr,
    ) -> Result<(Self, Yielded), Refused> {
        Self::begin(door, cert, local, SIDE_ACCEPT, None, &[])
    }

    /// Begin an ACCEPTING association on `door` under a certificate minted for it alone: as
    /// [`Self::accept`], the session's certificate the connector's own, so the host that serves the
    /// association names no protocol of it.
    ///
    /// # Errors
    ///
    /// The certificate could not be minted, or the entry refused to frame it, or answered outside
    /// the lane's rules.
    pub fn accept_minted(
        door: Arc<dyn FramerDoor>,
        local: SocketAddr,
    ) -> Result<(Self, Yielded), Refused> {
        let cert = SessionCert::mint().map_err(|e| fault(format!("{e:?}")))?;
        Self::accept(door, Arc::new(cert), local)
    }

    /// Begin a DIALLING association on `door`: as [`Self::accept`], with the `opening` fields the
    /// framing offers (its own description comes back as a piece) and the destination `judge` every
    /// candidate the far end's answer advertises meets, under the dialling need's egress `class`,
    /// before any byte goes there.
    ///
    /// # Errors
    ///
    /// The entry refused to frame it, or answered outside the lane's rules.
    pub fn dial(
        door: Arc<dyn FramerDoor>,
        cert: Arc<SessionCert>,
        local: SocketAddr,
        opening: &[(String, Vec<u8>)],
        judge: Arc<dyn DialJudge>,
        class: u32,
    ) -> Result<(Self, Yielded), Refused> {
        Self::begin(door, cert, local, SIDE_DIAL, Some((judge, class)), opening)
    }

    fn begin(
        door: Arc<dyn FramerDoor>,
        cert: Arc<SessionCert>,
        local: SocketAddr,
        side: u32,
        judge: Option<(Arc<dyn DialJudge>, u32)>,
        opening: &[(String, Vec<u8>)],
    ) -> Result<(Self, Yielded), Refused> {
        if !door.facts().datagram {
            return Err(Refused {
                outcome: Outcome::Refused,
                error: format!(
                    "`{}` is no datagram framer: its calls carry no datagram lane",
                    door.facts().name
                ),
            });
        }
        let mut f = DatagramFraming {
            door,
            token: 0,
            bufs: Buffers::for_side(side),
            routes: vec![DatagramRoute::default(); ROUTES_CAP],
            cert,
            local: local.to_string(),
            secure: None,
            book: PathBook::default(),
            keying: None,
            presented: false,
            told: (0, false),
            send: VecDeque::new(),
            send_custody: Custody::default(),
            retired_send: Custody::default(),
            metadata_custody: Custody::default(),
            refused_routes: 0,
            deadline_ns: None,
            ended: false,
            side,
            judge,
            refused_candidates: 0,
            user: None,
            memory: None,
            credit: None,
            continuation: None,
        };
        let y = f.run(Op::Begin(opening), Instant::now())?;
        Ok((f, y))
    }

    /// The far end's description. The framer's own description comes back as a piece, and the
    /// terms it settled build the secure layer's association.
    ///
    /// # Errors
    ///
    /// The framer refused the description, or answered no terms for it.
    pub fn rendezvous(&mut self, description: &[u8], now: Instant) -> Result<Yielded, Refused> {
        let y = self.run(
            Op::Ingest {
                lane: LANE_RENDEZVOUS,
                from: None,
                bytes: description,
                end: false,
            },
            now,
        )?;
        if self.secure.is_none() {
            return Err(fault("the framer answered a rendezvous with no terms"));
        }
        Ok(y)
    }

    /// One datagram the port read from `from`. Before the rendezvous settled terms nothing on the
    /// port is this association's, and it is dropped.
    ///
    /// # Errors
    ///
    /// The framer failed the association, or the secure layer did.
    pub fn datagram(
        &mut self,
        from: SocketAddr,
        bytes: &[u8],
        now: Instant,
    ) -> Result<Yielded, Refused> {
        let unadmitted = self
            .secure
            .as_ref()
            .is_some_and(|s| s.unadmitted_check(from, bytes));
        if unadmitted && !self.admit_heard(from, now) {
            return self.settle(Yielded::default(), now);
        }
        let Some(secure) = self.secure.as_mut() else {
            return Ok(Yielded::default());
        };
        let up = secure.ingest(from, bytes, now) == Verdict::Raw && secure.knows(from);
        if !up {
            return self.settle(Yielded::default(), now);
        }
        let known = |a: SocketAddr| secure.knows(a) || secure.bound_path() == Some(a);
        if self.book.number(from, known).is_none() {
            return self.settle(Yielded::default(), now);
        }
        self.run(
            Op::Ingest {
                lane: LANE_CLEAR,
                from: Some(from),
                bytes,
                end: false,
            },
            now,
        )
    }

    /// One message's bytes for `stream` (`end_of_frame` sends it; `text` = a text message).
    ///
    /// # Errors
    ///
    /// The framer refused them.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        now: Instant,
    ) -> Result<Yielded, Refused> {
        self.run(
            Op::Emit {
                stream,
                bytes,
                end_of_frame,
                text,
            },
            now,
        )
    }

    /// Begin one emission, yielding its checked output a batch at a time. The caller retains
    /// publication custody between batches; the next recall carries no new application bytes.
    ///
    /// # Errors
    ///
    /// The framer refused the emission or answered outside the datagram contract.
    pub fn emit_turn(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        now: Instant,
    ) -> Result<DatagramTurn<'_>, Refused> {
        DatagramTurn::start(
            self,
            Op::Emit {
                stream,
                bytes,
                end_of_frame,
                text,
            },
            now,
        )
    }

    /// The clock: the secure layer's timers, and the framer's deadline when it has passed.
    ///
    /// # Errors
    ///
    /// The framer failed the association, or the secure layer did.
    pub fn timeout(&mut self, now: Instant) -> Result<Yielded, Refused> {
        if let Some(secure) = self.secure.as_mut() {
            secure.handle_timeout(now);
        }
        if self.deadline_ns.is_some_and(|ns| instant_of(ns) <= now) {
            self.deadline_ns = None;
            return self.run(Op::Timer, now);
        }
        self.settle(Yielded::default(), now)
    }

    /// When [`Self::timeout`] is next owed.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        let framer = self.deadline_ns.map(instant_of);
        let secure = self.secure.as_ref().and_then(Association::next_timeout);
        [framer, secure].into_iter().flatten().min()
    }

    /// The next datagram owed to the port, and where it goes.
    pub fn poll_send(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        // The previous returned datagram has retired before a caller requests the next one.
        self.retired_send = Custody::default();
        let next = self.send.pop_front();
        if next.is_some() {
            self.retired_send = self.send_custody.clone();
        }
        if self.send.is_empty() {
            self.send = VecDeque::new();
            self.send_custody = Custody::default();
        }
        next
    }

    /// How many routes the host refused to send (to a path the secure layer does not allow, or
    /// secured before there was a bound path to seal to).
    #[must_use]
    pub fn refused_routes(&self) -> u64 {
        self.refused_routes
    }

    /// The user name the far end's checks carry first, once the rendezvous settled it.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Whether a datagram from `path` is this association's: the secure layer knows it (a verified
    /// check, core's proof, an admitted candidate) or has it bound.
    #[must_use]
    pub fn owns(&self, path: SocketAddr) -> bool {
        self.secure
            .as_ref()
            .is_some_and(|s| s.knows(path) || s.bound_path() == Some(path))
    }

    /// Whether `path` is the one this association has bound (proven by core's round trip).
    #[must_use]
    pub fn binds(&self, path: SocketAddr) -> bool {
        self.secure
            .as_ref()
            .is_some_and(|s| s.bound_path() == Some(path))
    }

    /// The far-end addresses this association owns ([`Self::owns`]) that it has numbered: on the
    /// dialling side its admitted candidates, before any of them has sent a byte.
    pub fn addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.book.by_addr.keys().copied().filter(|a| self.owns(*a))
    }

    /// How many of the far end's advertised candidates the destination judge refused (dialling).
    #[must_use]
    pub fn refused_candidates(&self) -> u64 {
        self.refused_candidates
    }

    /// Whether the keying-material item has been presented to the framer.
    #[must_use]
    pub fn presented(&self) -> bool {
        self.presented
    }

    /// The path the secure layer has bound, as the far end's address.
    #[must_use]
    pub fn bound(&self) -> Option<SocketAddr> {
        self.secure.as_ref().and_then(Association::bound_path)
    }

    /// The framer said no frame follows.
    #[must_use]
    pub fn ended(&self) -> bool {
        self.ended
    }

    fn verified(&self) -> bool {
        self.secure.as_ref().is_some_and(Association::peer_verified)
    }

    fn bound_path(&self) -> u32 {
        self.bound().map_or(0, |a| self.book.path(a))
    }

    /// `first`, its `YIELD_MORE` re-calls, then whatever the secure layer owes the framer.
    fn run(&mut self, first: Op<'_>, now: Instant) -> Result<Yielded, Refused> {
        let mut y = Yielded::default();
        let mut turn = DatagramTurn::start(self, first, now)?;
        while let Some(batch) = turn.next_batch()? {
            append_batch(&mut y, batch);
        }
        Ok(y)
    }

    /// Drain the secure layer: its datagrams to the port, its plaintext to the framer, and the
    /// host state (bound path, verified bit, the keying-material item) the framer has not been
    /// told.
    fn settle(&mut self, mut y: Yielded, now: Instant) -> Result<Yielded, Refused> {
        let mut turn = DatagramTurn::settling(self, now);
        while let Some(batch) = turn.next_batch()? {
            append_batch(&mut y, batch);
        }
        y.wire.clear();
        Ok(y)
    }

    fn cross_once(&mut self, op: Op<'_>) -> Result<FramerOut, Refused> {
        if self.token == 0 && !matches!(op, Op::Begin(_)) {
            return Err(fault("the association's framing is closed"));
        }
        // The lane's host state at this call. Every pointer below is into memory that outlives
        // the crossing.
        let untold: Vec<(u32, String)> = self
            .book
            .untold
            .iter()
            .filter_map(|p| Some((*p, self.book.addr(*p)?.to_string())))
            .collect();
        let paths: Vec<DatagramPath> = untold
            .iter()
            .map(|(p, a)| DatagramPath {
                path: *p,
                _reserved: 0,
                addr: text(a.as_bytes()),
            })
            .collect();
        let verified = self.verified();
        let keying = self
            .keying
            .as_ref()
            .filter(|_| verified)
            .map(|k| KeyingMaterial {
                size: u32::try_from(std::mem::size_of::<KeyingMaterial>()).unwrap_or(u32::MAX),
                profile: k.profile.code(),
                bytes: k.material().as_ptr(),
                len: k.material().len(),
            });
        let (lane_code, from) = match op {
            Op::Ingest { lane, from, .. } => (lane, from),
            _ => (0, None),
        };
        let from_text = from.map(|a| a.to_string()).unwrap_or_default();
        let bound = self.bound_path();
        let lane = DatagramLane {
            size: u32::try_from(std::mem::size_of::<DatagramLane>()).unwrap_or(u32::MAX),
            lane: lane_code,
            path: from.map_or(0, |a| self.book.path(a)),
            bound,
            path_addr: text(from_text.as_bytes()),
            local_addr: text(self.local.as_bytes()),
            verified: u32::from(verified),
            _reserved: 0,
            keying: keying
                .as_ref()
                .map_or(std::ptr::null(), |k| k as *const KeyingMaterial),
            routes: self.routes.as_mut_ptr(),
            routes_cap: self.routes.len(),
            paths: if paths.is_empty() {
                std::ptr::null()
            } else {
                paths.as_ptr()
            },
            paths_len: paths.len(),
        };
        let mut o: FramerOut = blank_out();
        let c: Crossed = match op {
            Op::Begin(opening) => {
                let fields: Vec<Field> = opening
                    .iter()
                    .map(|(n, v)| Field {
                        name: text(n.as_bytes()),
                        value: text(v),
                    })
                    .collect();
                let facts = ConnFacts {
                    size: u32::try_from(std::mem::size_of::<ConnFacts>()).unwrap_or(u32::MAX),
                    _reserved: 0,
                    offered_name: NO_TEXT,
                    agreed_protocol: NO_TEXT,
                    peer_subject: NO_TEXT,
                    peer_issuer: NO_TEXT,
                    peer_fingerprint: NO_TEXT,
                    claim: NO_TEXT,
                    local_certificate: text(self.cert.public_der()),
                };
                let mut i: BeginIn = blank_in();
                i.side = self.side;
                // A datagram lane is always secured: its media rides the host's secure layer,
                // whose association the rendezvous terms build (no terms is the framer's fault).
                i.scheme = busbar_contract::abi::host::service::SCHEME_SECURE;
                i.facts = &facts;
                if !fields.is_empty() {
                    i.fields = fields.as_ptr();
                    i.fields_len = fields.len();
                }
                i.lane = &lane;
                i.sink = self.bufs.sink();
                self.door.cross(Call::Begin(&mut i, &mut o))
            }
            Op::Ingest { bytes, end, .. } => {
                let mut i: IngestIn = blank_in();
                i.framing = self.token;
                i.bytes = bytes.as_ptr();
                i.len = bytes.len();
                i.end = u32::from(end);
                i.lane = &lane;
                i.sink = self.bufs.sink();
                self.door.cross(Call::Ingest(&mut i, &mut o))
            }
            Op::Emit {
                stream,
                bytes,
                end_of_frame,
                text,
            } => {
                let mut i: EmitIn = blank_in();
                i.framing = self.token;
                i.stream = stream;
                i.bytes = bytes.as_ptr();
                i.len = bytes.len();
                i.end_of_frame = u32::from(end_of_frame);
                i.flags = if text { EMIT_TEXT } else { 0 };
                i.lane = &lane;
                i.sink = self.bufs.sink();
                self.door.cross(Call::Emit(&mut i, &mut o))
            }
            Op::Timer => {
                let mut i: FramingIn = blank_in();
                i.framing = self.token;
                i.lane = &lane;
                i.sink = self.bufs.sink();
                self.door.cross(Call::Timer(&mut i, &mut o))
            }
        };
        if let Err(f) = check_datagram(c.outcome, &o, &self.routes, self.routes.len() as u64) {
            return Err(fault(format!(
                "the framer's datagram answer breaks {:?} at {}",
                f.rule, f.field
            )));
        }
        ready(c)?;
        if matches!(op, Op::Begin(_)) {
            self.token = o.framing;
        }
        // What this call carried reached the framer: the paths are told, the host state is the
        // one it now holds, and the keying-material item is presented — dropped here, zeroed.
        self.book.untold.clear();
        self.told = (bound, verified);
        if keying.is_some() {
            self.keying = None;
            self.presented = true;
        }
        Ok(o)
    }

    /// Copy out and apply what one READY answer asked; `true` = it owes nothing more.
    fn take(&mut self, o: &FramerOut, y: &mut Yielded, now: Instant) -> Result<bool, Refused> {
        let d = &o.datagram;
        let mut asked = Asked {
            request: (d.request, d.request_from, d.request_to),
            ..Asked::default()
        };
        if d.routes_len != 0 {
            let wire = self
                .bufs
                .wire_written(o.yielded.wire_len)
                .ok_or_else(|| fault("the framer's routes are out of bounds"))?;
            for r in self.routes.iter().take(d.routes_len as usize) {
                let at = usize::try_from(r.offset).map_err(|_| fault("route offset"))?;
                let len = usize::try_from(r.len).map_err(|_| fault("route length"))?;
                let bytes = wire
                    .get(at..at.saturating_add(len))
                    .ok_or_else(|| fault("the framer's routes are out of bounds"))?;
                asked.routes.push((r.path, r.lane, bytes.to_vec()));
            }
        }
        if d.terms.role != HANDSHAKE_NONE {
            let frame = self
                .bufs
                .frame_written(o.yielded.frame_len)
                .ok_or_else(|| fault("the framer's terms are out of bounds"))?;
            asked.terms = Some(read_terms(&d.terms, frame)?);
        }
        let done = self.bufs.take(o, y)?;
        self.ended |= y.ended;
        self.deadline_ns = y.deadline_ns;
        if let Some(t) = asked.terms {
            if self.secure.is_some() {
                return Err(fault("the framer answered terms twice"));
            }
            self.user = Some(t.local.ufrag.clone());
            let mut secure = Association::new(
                Arc::clone(&self.cert),
                t.role,
                &t.local,
                &t.remote,
                t.fingerprint,
            );
            if self.side == SIDE_DIAL {
                secure.set_dialling();
            }
            self.secure = Some(secure);
            if self.side == SIDE_DIAL {
                self.admit(&t.candidates, now);
            }
        }
        for (path, lane, bytes) in asked.routes {
            self.send_answered(path, lane, bytes);
        }
        self.request(asked.request, now);
        Ok(done)
    }

    /// The dialling side's candidates: each judged by the destination judge first; an admitted one
    /// numbered (told to the framer on the next call) and handed to the secure layer, which probes
    /// it. A refused, unparsable or still-pending one is dropped and counted.
    fn admit(&mut self, candidates: &[String], now: Instant) {
        if self.judge.is_none() {
            return;
        }
        for c in candidates {
            let admitted = c
                .parse::<SocketAddr>()
                .ok()
                .filter(|addr| self.judged(*addr));
            let Some(addr) = admitted else {
                self.refused_candidates += 1;
                continue;
            };
            let Some(secure) = self.secure.as_mut() else {
                return;
            };
            if !secure.admit_candidate(addr, now) {
                self.refused_candidates += 1;
                continue;
            }
            let known = |a: SocketAddr| secure.knows(a) || secure.bound_path() == Some(a);
            if self.book.number(addr, known).is_none() {
                self.refused_candidates += 1;
            }
        }
    }

    /// THE dialling side's one admission test, for an advertised candidate and a heard path alike:
    /// `addr` meets the destination judge under the dialling need's egress class. A literal is
    /// judged at once; a refusal, a judgement that would pend, or one pinned elsewhere is no
    /// admission. No judge (the accepting side) admits nothing.
    fn judged(&self, addr: SocketAddr) -> bool {
        let Some((judge, class)) = self.judge.as_ref() else {
            return false;
        };
        matches!(
            judge.judge_dial(&addr.to_string(), *class, Box::new(|_| {})),
            Some(Ok(pinned)) if pinned == addr
        )
    }

    /// The dialling side: a verified check came from `addr`, a path no admitted candidate named.
    /// It is judged as a candidate is ([`Self::judged`]); admitted, it becomes an admitted candidate
    /// of the secure layer (probed now, bound only once proven) and the check is ingested. `false`
    /// = refused, pending or past the candidate cap: the check is dropped unheard.
    fn admit_heard(&mut self, addr: SocketAddr, now: Instant) -> bool {
        if !self.judged(addr) {
            return false;
        }
        self.secure
            .as_mut()
            .is_some_and(|s| s.admit_candidate(addr, now))
    }

    /// Send one route where the secure layer allows it, or drop it.
    fn send_answered(&mut self, path: u32, lane: u32, bytes: Vec<u8>) {
        let to = self.book.addr(path);
        let sent = match (self.secure.as_mut(), to) {
            (Some(secure), Some(to)) if lane == LANE_CLEAR => {
                let ok = secure.may_send_clear(to, &bytes);
                if ok {
                    self.send.push_back((to, bytes));
                }
                ok
            }
            (Some(secure), Some(to)) if lane == LANE_SECURED => {
                secure.bound_path() == Some(to) && secure.seal(&bytes).is_ok()
            }
            _ => false,
        };
        if !sent {
            self.refused_routes += 1;
        }
    }

    /// A path request, to the secure layer; a refused one leaves the bound path where it is.
    fn request(&mut self, (request, from, to): (u32, u32, u32), now: Instant) {
        let Some(secure) = self.secure.as_mut() else {
            return;
        };
        let Some(to) = self.book.addr(to) else {
            return;
        };
        match request {
            PATH_REQUEST_BIND => {
                let _ = secure.bind_path(to, now);
            }
            PATH_REQUEST_REBIND => {
                if let Some(from) = self.book.addr(from) {
                    let _ = secure.rebind_path(from, to, now);
                }
            }
            _ => {}
        }
    }
}

/// The rendezvous terms a framer answered, read out of its frame (already judged by
/// `check_terms`).
fn read_terms(t: &RendezvousTerms, frame: &[u8]) -> Result<Terms, Refused> {
    let span = |s: busbar_contract::abi::transport::FrameSpan| -> Result<&[u8], Refused> {
        let at = usize::try_from(s.offset).map_err(|_| fault("terms span"))?;
        let len = usize::try_from(s.len).map_err(|_| fault("terms span"))?;
        frame
            .get(at..at.saturating_add(len))
            .ok_or_else(|| fault("the framer's terms are out of bounds"))
    };
    let utf8 = |s| -> Result<String, Refused> {
        String::from_utf8(span(s)?.to_vec())
            .map_err(|_| fault("the framer's check credentials are not text"))
    };
    let role = match t.role {
        HANDSHAKE_INITIATES => Role::Client,
        HANDSHAKE_ANSWERS => Role::Server,
        _ => return Err(fault("the framer's terms name no handshake role")),
    };
    let candidates = String::from_utf8(span(t.candidates)?.to_vec())
        .map_err(|_| fault("the far end's candidates are not text"))?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    let mut fingerprint = [0_u8; FINGERPRINT_BYTES as usize];
    let stated = span(t.peer_fingerprint)?
        .get(..fingerprint.len())
        .ok_or_else(|| fault("the far end's fingerprint is short"))?;
    fingerprint.copy_from_slice(stated);
    Ok(Terms {
        role,
        local: IceCredentials {
            ufrag: utf8(t.local_user)?,
            pwd: utf8(t.local_secret)?,
        },
        remote: IceCredentials {
            ufrag: utf8(t.remote_user)?,
            pwd: utf8(t.remote_secret)?,
        },
        fingerprint,
        candidates,
    })
}

/// THE PORT'S ASSOCIATIONS: every association one host port carries, and the demultiplexer that
/// finds the one a datagram belongs to. A connectivity check names its association by the user
/// name its first USERNAME field carries (the association's own; the association still verifies
/// the check's integrity itself); any other datagram is found by the path it came from, which an
/// association claims only once its secure layer knows it. A datagram neither finds is dropped
/// here, before any association or framer sees it.
///
/// One port carries many ACCEPTED associations: each far end reaches it from its own address. A
/// DIALLED association takes a port of its own, because two calls to one far end would share
/// every address of the 5-tuple.
#[derive(Debug, Default)]
pub struct Associations {
    framings: HashMap<u64, DatagramFraming>,
    by_user: HashMap<String, u64>,
    by_path: HashMap<SocketAddr, u64>,
    last: u64,
    /// The associations a [`PortAssociations`] caller has out on a crossing: still carried (their
    /// user name and paths still find them), their framing with the caller.
    out: HashMap<u64, Out>,
    emissions: HashMap<u64, Arc<Emission>>,
}

#[derive(Debug)]
struct Emission {
    order: Arc<tokio::sync::Semaphore>,
    ready: tokio::sync::Notify,
    wake: futures::task::AtomicWaker,
}

impl Default for Emission {
    fn default() -> Self {
        Self {
            order: Arc::new(tokio::sync::Semaphore::new(1)),
            ready: tokio::sync::Notify::new(),
            wake: futures::task::AtomicWaker::new(),
        }
    }
}

#[derive(Clone, Copy)]
enum WhileBusy {
    Queue,
    Wait,
}

/// What a caller owes an association that is out on another caller's crossing: run, in order, by
/// that caller before it puts the association back.
#[derive(Debug)]
enum Owed<'a> {
    Datagram(SocketAddr, std::borrow::Cow<'a, [u8]>),
    Emit {
        stream: u64,
        bytes: std::borrow::Cow<'a, [u8]>,
        end_of_frame: bool,
        text: bool,
    },
    Timer,
}

impl Owed<'_> {
    fn owned(self) -> Owed<'static> {
        match self {
            Owed::Datagram(from, b) => Owed::Datagram(from, b.into_owned().into()),
            Owed::Emit {
                stream,
                bytes,
                end_of_frame,
                text,
            } => Owed::Emit {
                stream,
                bytes: bytes.into_owned().into(),
                end_of_frame,
                text,
            },
            Owed::Timer => Owed::Timer,
        }
    }
}

/// An association out on a crossing.
#[derive(Debug, Default)]
struct Out {
    /// An incremental producer between batches. It remains exclusively out until completion.
    continuing: Option<DatagramFraming>,
    /// The completed batch must reach publication before the next producer step.
    publishing: bool,
    owed: VecDeque<Owed<'static>>,
    /// Removed while out: its holder finishes it as it brings it back.
    closing: bool,
    /// Its deadline as it went out, until the clock owes it a [`Owed::Timer`].
    deadline: Option<Instant>,
}

/// Why an association was not added to a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAdded {
    /// Its rendezvous has not settled terms: nothing would find it.
    NoTerms,
    /// Another association on the port already answers to its user name.
    UserTaken,
}

impl Associations {
    /// An empty port.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Carry `framing` on this port; its number.
    ///
    /// # Errors
    ///
    /// [`NotAdded`]: no terms yet, or its user name is another association's.
    pub fn add(&mut self, framing: DatagramFraming) -> Result<u64, NotAdded> {
        let user = self.admits(&framing)?;
        Ok(self.carry(user, framing))
    }

    /// Whether `framing` may be carried: the user name it is found by.
    fn admits(&self, framing: &DatagramFraming) -> Result<String, NotAdded> {
        let user = framing.user().ok_or(NotAdded::NoTerms)?.to_owned();
        if self.by_user.contains_key(&user) {
            return Err(NotAdded::UserTaken);
        }
        Ok(user)
    }

    /// Carry `framing`, found by `user`; its number.
    fn carry(&mut self, user: String, framing: DatagramFraming) -> u64 {
        self.last += 1;
        let id = self.last;
        self.by_user.insert(user, id);
        // A dialled association hears nothing first: its admitted candidates' answers find it by
        // their path. A path another association already holds stays that association's (a
        // dialled association that shares a far end with another is given a port of its own).
        for addr in framing.addresses() {
            self.by_path.entry(addr).or_insert(id);
        }
        self.framings.insert(id, framing);
        self.emissions.insert(id, Arc::default());
        id
    }

    /// Stop carrying association `id`; the framing, for its owner to finish.
    pub fn remove(&mut self, id: u64) -> Option<DatagramFraming> {
        let f = self.framings.remove(&id)?;
        self.forget(id);
        Some(f)
    }

    /// Association `id` is no longer carried: its user name and paths let go.
    fn forget(&mut self, id: u64) {
        self.by_user.retain(|_, v| *v != id);
        self.by_path.retain(|_, v| *v != id);
        self.out.remove(&id);
        self.emissions.remove(&id);
    }

    /// The association `id`.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut DatagramFraming> {
        self.framings.get_mut(&id)
    }

    /// How many associations the port carries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.framings.len()
    }

    /// Whether the port carries none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.framings.is_empty()
    }

    /// One datagram the port read from `from`: the association it belongs to and what that
    /// association answered; `None` = it belongs to none and was dropped. An association that
    /// fails is removed (its framing dropped, which finishes it).
    pub fn datagram(
        &mut self,
        from: SocketAddr,
        bytes: &[u8],
        now: Instant,
    ) -> Option<(u64, Result<Yielded, Refused>)> {
        let id = self.find(from, bytes)?;
        let mut f = self.framings.remove(&id)?;
        let answer = f.datagram(from, bytes, now);
        if answer.is_ok() {
            self.route(id, from, &f);
        }
        if answer.is_err() {
            self.forget(id);
        } else {
            self.framings.insert(id, f);
        }
        Some((id, answer))
    }

    /// The association a datagram from `from` belongs to: a check's by its user name, anything
    /// else's by its path.
    fn find(&self, from: SocketAddr, bytes: &[u8]) -> Option<u64> {
        match check_user(bytes) {
            Some(user) => self.by_user.get(user).copied(),
            None => self.by_path.get(&from).copied(),
        }
    }

    /// Association `id` (its framing `f`, out of the map) took a datagram from `from`.
    fn route(&mut self, id: u64, from: SocketAddr, f: &DatagramFraming) {
        if !f.owns(from) {
            return;
        }
        let binds = f.binds(from);
        // A path another association holds stays its own while it still owns it, unless this one
        // has it BOUND (proven by core's round trip) and the holder does not: a heard check proves
        // only that its sender knows this association's password, never that it owns the source
        // address. A holder out on a crossing keeps what it holds.
        let take = match self.by_path.get(&from) {
            None => true,
            Some(holder) if *holder == id => false,
            Some(holder) => match self.framings.get(holder) {
                Some(h) => !h.owns(from) || (binds && !h.binds(from)),
                None => !self.out.contains_key(holder),
            },
        };
        if take {
            self.by_path.insert(from, id);
            // The paths it let go of (a heard path that made room for this one) are let go here
            // too, so the port routes an association no more paths than it owns.
            self.by_path
                .retain(|addr, holder| *holder != id || f.owns(*addr));
        }
    }

    /// The clock, for every association whose deadline has passed; a failed one is removed.
    pub fn timeout(&mut self, now: Instant) -> Vec<(u64, Result<Yielded, Refused>)> {
        let due: Vec<u64> = self
            .framings
            .iter()
            .filter(|(_, f)| f.deadline().is_some_and(|d| d <= now))
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::new();
        for id in due {
            if let Some(f) = self.framings.get_mut(&id) {
                let answer = f.timeout(now);
                if answer.is_err() {
                    self.remove(id);
                }
                out.push((id, answer));
            }
        }
        out
    }

    /// The earliest deadline of any association.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.framings
            .values()
            .filter_map(DatagramFraming::deadline)
            .chain(self.out.values().filter_map(|o| o.deadline))
            .min()
    }

    /// The next datagram any association owes the port, and where it goes.
    pub fn poll_send(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.framings
            .values_mut()
            .find_map(DatagramFraming::poll_send)
    }
}

/// What a port's associations answered: each association's number and what it yielded or why it
/// failed (a failed one is no longer carried).
pub type Answered = Vec<(u64, Result<Yielded, Refused>)>;

/// THE PORT'S ASSOCIATIONS, SHARED by every caller of one port: the port's task (datagrams, the
/// clock), the sessions' writers (emits), admissions and teardowns. `send` hands each datagram an
/// association owes the port to the port.
///
/// NO FRAMER IS CROSSED UNDER ITS LOCK (`BUSBAR-1.6.0.md` §11.13 M1): a caller takes the one
/// association out, crosses its framer with nothing held (a wedged framer holds only its own
/// association), and puts it back. A caller that finds it out does not wait: what it owes (a
/// datagram, an emit, the clock) is queued for the holder, who runs it, in order, before putting
/// the association back. A framing that finishes (removed, failed, or refused) is dropped with no
/// lock held; one removed while out is finished by its holder.
#[derive(Debug, Default)]
pub struct PortAssociations {
    assocs: std::sync::Mutex<Associations>,
    pub(crate) raw_busy_dropped: std::sync::atomic::AtomicU64,
}

#[derive(Debug)]
pub(crate) struct BusyIngress;

#[path = "raw_ingress.rs"]
mod raw_ingress;
pub use raw_ingress::RawIngress;

/// An association out of the map. Only an unwind drops it still holding the framing: the
/// association is then no longer carried, and its framing finished with no lock held.
struct Taken<'p> {
    port: &'p PortAssociations,
    id: u64,
    framing: Option<DatagramFraming>,
}

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        if let Some(f) = self.framing.take() {
            let emission = {
                let mut assocs = self.port.lock();
                let emission = assocs.emissions.get(&self.id).cloned();
                assocs.forget(self.id);
                emission
            };
            if let Some(emission) = emission {
                emission.order.close();
                emission.ready.notify_waiters();
                emission.wake.wake();
            }
            drop(f);
        }
    }
}

impl PortAssociations {
    /// Release a checked batch's publication barrier, waking its producer outside the lock.
    pub fn published(&self, id: u64) {
        let emission = {
            let mut assocs = self.lock();
            if let Some(out) = assocs.out.get_mut(&id) {
                out.publishing = false;
            }
            assocs.emissions.get(&id).cloned()
        };
        if let Some(emission) = emission {
            emission.ready.notify_waiters();
            emission.wake.wake();
        }
    }
    /// Wait before accepting/copying a busy application write. The returned permit keeps
    /// source writers ordered while the independent publication actor crosses its producer.
    pub async fn emission_ready(&self, id: u64) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let emission = self.lock().emissions.get(&id).cloned()?;
        let permit = Arc::clone(&emission.order).acquire_owned().await.ok()?;
        loop {
            let ready = emission.ready.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            {
                let assocs = self.lock();
                if assocs.framings.contains_key(&id) {
                    return Some(permit);
                }
                if assocs.out.get(&id).is_none_or(|out| out.closing) {
                    return None;
                }
            }
            ready.await;
        }
    }

    /// The trusted queued incremental path. Newly received network datagrams use
    /// [`Self::raw_datagram`]; already accepted/trusted operations keep queued custody.
    pub fn datagram_incremental(
        &self,
        from: SocketAddr,
        bytes: &[u8],
        now: Instant,
        send: &dyn Fn(SocketAddr, &[u8]),
    ) -> Answered {
        let Some(id) = self.lock().find(from, bytes) else {
            return Vec::new();
        };
        self.incremental(id, Owed::Datagram(from, bytes.into()), now, send)
    }

    /// The serving caller's incremental clock path. A busy producer retains its ordinary
    /// queued timer until its same-op continuation and older publication can progress.
    pub fn timeout_incremental(&self, now: Instant, send: &dyn Fn(SocketAddr, &[u8])) -> Answered {
        let due: Vec<_> = {
            let mut assocs = self.lock();
            for out in assocs.out.values_mut() {
                if out.deadline.is_some_and(|deadline| deadline <= now) {
                    out.deadline = None;
                    out.owed.push_back(Owed::Timer);
                }
            }
            assocs
                .framings
                .iter()
                .filter_map(|(id, f)| {
                    f.deadline()
                        .is_some_and(|deadline| deadline <= now)
                        .then_some(*id)
                })
                .collect()
        };
        due.into_iter()
            .flat_map(|id| self.incremental(id, Owed::Timer, now, send))
            .collect()
    }

    fn incremental(
        &self,
        id: u64,
        op: Owed<'_>,
        now: Instant,
        send: &dyn Fn(SocketAddr, &[u8]),
    ) -> Answered {
        self.incremental_admission(id, op, now, send, false)
            .expect("trusted queued operations do not use raw readiness refusal")
    }

    fn incremental_admission(
        &self,
        id: u64,
        op: Owed<'_>,
        now: Instant,
        send: &dyn Fn(SocketAddr, &[u8]),
        drop_busy: bool,
    ) -> Result<Answered, BusyIngress> {
        let f = {
            let mut assocs = self.lock();
            if let Some(out) = assocs.out.get_mut(&id) {
                if drop_busy && !out.closing {
                    return Err(BusyIngress);
                }
                if !out.closing {
                    out.owed.push_back(op.owned());
                }
                return Ok(Vec::new());
            }
            // A raw receive is ready only with its pre-crossing output credit. This host-only
            // preflight reuses existing credit or reserves into an empty slot: it cannot drop
            // an old lease, wake a callback, or cross the plugin under the association lock.
            if drop_busy
                && assocs
                    .framings
                    .get_mut(&id)
                    .is_some_and(|f| !f.prepare_output())
            {
                return Err(BusyIngress);
            }
            let Some(f) = assocs.framings.remove(&id) else {
                return Ok(Vec::new());
            };
            assocs.out.insert(
                id,
                Out {
                    deadline: f.deadline(),
                    ..Out::default()
                },
            );
            f
        };
        let mut taken = Taken {
            port: self,
            id,
            framing: Some(f),
        };
        let f = taken
            .framing
            .as_mut()
            .expect("the producer owns its framing");
        let from = match &op {
            Owed::Datagram(from, _) => Some(*from),
            _ => None,
        };
        let result = match &op {
            Owed::Datagram(from, bytes) => f.datagram_step(*from, bytes, now),
            Owed::Timer => f.timeout_step(now),
            Owed::Emit {
                stream,
                bytes,
                end_of_frame,
                text,
            } => {
                if f.prepare_output() {
                    f.start_step(
                        Op::Emit {
                            stream: *stream,
                            bytes,
                            end_of_frame: *end_of_frame,
                            text: *text,
                        },
                        now,
                    )
                } else {
                    Ok(LineStep::Credit)
                }
            }
        };
        while let Some((to, bytes)) = f.poll_send() {
            send(to, &bytes);
        }
        let mut assocs = self.lock();
        if let Some(from) = from {
            assocs.route(id, from, f);
        }
        if assocs.out.get(&id).is_none_or(|out| out.closing) || result.is_err() {
            // As `poll_line` and `Taken::drop` do: keep the emission before `forget` drops the
            // port's handle, so parked `emission_ready`/`poll_line` waiters are closed and woken.
            let emission = assocs.emissions.get(&id).cloned();
            assocs.forget(id);
            drop(assocs);
            drop(taken.framing.take());
            if let Some(emission) = emission {
                emission.order.close();
                emission.ready.notify_waiters();
                emission.wake.wake();
            }
            let answer = match result {
                Ok(LineStep::Batch { yielded, .. }) => Ok(yielded),
                Err(error) => Err(error),
                Ok(_) => Err(fault("the association closed during its producer")),
            };
            return Ok(vec![(id, answer)]);
        }
        let yielded = match result.expect("the producer result was checked") {
            LineStep::Batch { yielded, .. } => yielded,
            LineStep::Credit => {
                assocs
                    .out
                    .get_mut(&id)
                    .expect("the producer's routing record")
                    .owed
                    .push_front(op.owned());
                Yielded {
                    continuing: true,
                    ..Yielded::default()
                }
            }
            LineStep::Complete => Yielded::default(),
        };
        let pending = f.continuing() || assocs.out.get(&id).is_some_and(|out| !out.owed.is_empty());
        if pending {
            assocs
                .out
                .get_mut(&id)
                .expect("the producer's routing record")
                .publishing = true;
            assocs
                .out
                .get_mut(&id)
                .expect("the producer's routing record")
                .continuing = taken.framing.take();
        } else {
            assocs.out.remove(&id);
            assocs.framings.insert(
                id,
                taken.framing.take().expect("the producer owns its framing"),
            );
        }
        drop(assocs);
        Ok(vec![(
            id,
            Ok(Yielded {
                continuing: pending,
                ..yielded
            }),
        )])
    }

    /// Drive a single LINE producer batch without retaining exclusive association custody
    /// during publication. A busy association registers this scheduler's actual wake.
    pub fn poll_line(
        &self,
        id: u64,
        cx: &mut std::task::Context<'_>,
        input: Option<&Across>,
        text: bool,
        now: Instant,
        send: &dyn Fn(SocketAddr, &[u8]),
    ) -> std::task::Poll<Result<LineStep, Refused>> {
        let emission = self.lock().emissions.get(&id).cloned();
        let Some(emission) = emission else {
            return std::task::Poll::Ready(Err(fault("the association is closed")));
        };
        emission.wake.register(cx.waker());
        let (f, owed) = {
            let mut assocs = self.lock();
            if let Some(out) = assocs.out.get_mut(&id) {
                if out.closing {
                    return std::task::Poll::Ready(Err(fault("the association is closing")));
                }
                if out.publishing {
                    return std::task::Poll::Pending;
                }
                match out.continuing.take() {
                    Some(f) => {
                        let owed = (!f.continuing()).then(|| out.owed.pop_front()).flatten();
                        (f, owed)
                    }
                    None => return std::task::Poll::Pending,
                }
            } else {
                let Some(f) = assocs.framings.remove(&id) else {
                    return std::task::Poll::Ready(Err(fault("the association is closed")));
                };
                assocs.out.insert(
                    id,
                    Out {
                        deadline: f.deadline(),
                        ..Out::default()
                    },
                );
                (f, None)
            }
        };
        let mut taken = Taken {
            port: self,
            id,
            framing: Some(f),
        };
        let f = taken
            .framing
            .as_mut()
            .expect("the producer owns its framing");
        let mut result = match owed.as_ref() {
            Some(Owed::Datagram(from, bytes)) => f.datagram_step(*from, bytes, now),
            Some(Owed::Timer) => f.timeout_step(now),
            Some(Owed::Emit {
                stream,
                bytes,
                end_of_frame,
                text,
            }) => {
                if f.prepare_output() {
                    f.start_step(
                        Op::Emit {
                            stream: *stream,
                            bytes,
                            end_of_frame: *end_of_frame,
                            text: *text,
                        },
                        now,
                    )
                } else {
                    Ok(LineStep::Credit)
                }
            }
            None => f.line_step(input, text, now),
        };
        if owed.is_some() {
            if let Ok(LineStep::Batch { accepted, .. }) = &mut result {
                *accepted = false;
            }
        }
        while let Some((to, bytes)) = f.poll_send() {
            send(to, &bytes);
        }
        let mut assocs = self.lock();
        if let Some(Owed::Datagram(from, _)) = &owed {
            assocs.route(id, *from, f);
        }
        if matches!(result, Ok(LineStep::Credit)) {
            if let Some(owed) = owed {
                assocs
                    .out
                    .get_mut(&id)
                    .expect("the producer's routing record")
                    .owed
                    .push_front(owed);
            }
        }
        let closing = assocs.out.get(&id).is_none_or(|out| out.closing);
        if closing || result.is_err() {
            assocs.forget(id);
            drop(assocs);
            drop(taken.framing.take());
            emission.order.close();
            emission.ready.notify_waiters();
            emission.wake.wake();
            return std::task::Poll::Ready(match result {
                Ok(batch @ LineStep::Batch { .. }) => Ok(batch),
                Err(error) => Err(error),
                Ok(_) => Err(fault("the association closed during publication")),
            });
        }
        if matches!(result, Ok(LineStep::Complete)) {
            let out = assocs
                .out
                .get_mut(&id)
                .expect("the producer's routing record");
            if out.owed.is_empty() {
                assocs.out.remove(&id);
                assocs.framings.insert(
                    id,
                    taken.framing.take().expect("the producer owns its framing"),
                );
            } else {
                out.publishing = true;
                out.continuing = taken.framing.take();
                result = Ok(LineStep::Batch {
                    yielded: Yielded {
                        continuing: true,
                        ..Yielded::default()
                    },
                    accepted: false,
                });
            }
        } else {
            assocs
                .out
                .get_mut(&id)
                .expect("the producer's routing record")
                .publishing = matches!(result, Ok(LineStep::Batch { .. }));
            assocs
                .out
                .get_mut(&id)
                .expect("the producer's routing record")
                .continuing = taken.framing.take();
        }
        drop(assocs);
        emission.ready.notify_waiters();
        emission.wake.wake();
        std::task::Poll::Ready(result)
    }

    /// An empty port.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Associations> {
        self.assocs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Carry `framing` on this port; its number.
    ///
    /// # Errors
    ///
    /// [`NotAdded`]: no terms yet, or its user name is another association's. The refused
    /// framing finishes after the port's lock is let go.
    pub fn add(&self, framing: DatagramFraming) -> Result<u64, NotAdded> {
        self.add_with(framing, |_| {})
    }

    /// Carry `framing`, publishing its host routing record before any port crossing can see it.
    /// `publish` only records host state: it must not call the port, a plugin, or a user callback.
    /// The framing stays outside the map until publication returns, so refusal and publication
    /// unwind both finish it after the port guard is gone.
    ///
    /// # Errors
    ///
    /// [`NotAdded`]: as [`Self::add`]. A refused framing never calls `publish`.
    pub fn add_with(
        &self,
        framing: DatagramFraming,
        publish: impl FnOnce(u64),
    ) -> Result<u64, NotAdded> {
        let why = {
            let mut assocs = self.lock();
            match assocs.admits(&framing) {
                Ok(user) => {
                    publish(assocs.last + 1);
                    return Ok(assocs.carry(user, framing));
                }
                Err(why) => why,
            }
        };
        drop(framing);
        Err(why)
    }

    /// Stop carrying association `id`: its framing finishes, here with no lock held, or by its
    /// holder when it is out.
    pub fn remove(&self, id: u64) {
        let (gone, pending, emission) = {
            let mut assocs = self.lock();
            let emission = assocs.emissions.get(&id).cloned();
            let pending = assocs
                .out
                .get(&id)
                .is_some_and(|out| out.continuing.is_some())
                .then(|| assocs.out.remove(&id))
                .flatten();
            let gone = match assocs.out.get_mut(&id) {
                Some(out) => {
                    out.closing = true;
                    None
                }
                None => assocs.remove(id),
            };
            if pending.is_some() {
                assocs.forget(id);
            }
            (gone, pending, emission)
        };
        if let Some(emission) = emission {
            emission.order.close();
            emission.ready.notify_waiters();
            emission.wake.wake();
        }
        drop(gone);
        drop(pending);
    }

    /// How many associations the port carries.
    #[must_use]
    pub fn len(&self) -> usize {
        let assocs = self.lock();
        assocs.framings.len() + assocs.out.values().filter(|o| !o.closing).count()
    }

    /// Whether the port carries none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The earliest deadline of any association.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.lock().deadline()
    }

    /// One datagram the port read from `from`, to the association it belongs to: what the
    /// associations answered (nothing when it belongs to none, or is out and the datagram queued).
    pub fn datagram(
        &self,
        from: SocketAddr,
        bytes: &[u8],
        now: Instant,
        send: &dyn Fn(SocketAddr, &[u8]),
    ) -> Answered {
        let Some(id) = self.lock().find(from, bytes) else {
            return Vec::new();
        };
        self.turn(id, Owed::Datagram(from, bytes.into()), now, send)
            .1
    }

    /// The clock, for every association whose deadline has passed (one out is owed it).
    pub fn timeout(&self, now: Instant, send: &dyn Fn(SocketAddr, &[u8])) -> Answered {
        let due: Vec<u64> = {
            let mut assocs = self.lock();
            for out in assocs.out.values_mut() {
                if out.deadline.is_some_and(|d| d <= now) {
                    out.deadline = None;
                    out.owed.push_back(Owed::Timer);
                }
            }
            assocs
                .framings
                .iter()
                .filter(|(_, f)| f.deadline().is_some_and(|d| d <= now))
                .map(|(id, _)| *id)
                .collect()
        };
        due.into_iter()
            .flat_map(|id| self.turn(id, Owed::Timer, now, send).1)
            .collect()
    }

    /// One message's bytes for `stream` on association `id`: whether it was taken (`false` = no
    /// such association, or its framer refused them; queued behind another caller's crossing =
    /// taken), and what the associations answered for what this caller ran meanwhile.
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        &self,
        id: u64,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        now: Instant,
        send: &dyn Fn(SocketAddr, &[u8]),
    ) -> (bool, Answered) {
        let owed = Owed::Emit {
            stream,
            bytes: bytes.into(),
            end_of_frame,
            text,
        };
        let (ok, answered) = self.turn(id, owed, now, send);
        (ok.unwrap_or(false), answered)
    }

    /// Wait for this association's emission turn without accepting or copying a busy write.
    /// The caller retains `bytes` until the turn completes; cancellation before that turn
    /// removes its place in the writer order. `false` means absent, closing, or refused.
    #[allow(clippy::too_many_arguments)]
    pub async fn emit_ready(
        &self,
        id: u64,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        send: &(dyn Fn(SocketAddr, &[u8]) + Sync),
        answer: &(dyn Fn(Answered) + Sync),
    ) -> bool {
        let emission = self.lock().emissions.get(&id).cloned();
        let Some(emission) = emission else {
            return false;
        };
        let Ok(_order) = emission.order.acquire().await else {
            return false;
        };
        loop {
            let ready = emission.ready.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            let result = self.try_turn(
                id,
                Owed::Emit {
                    stream,
                    bytes: bytes.into(),
                    end_of_frame,
                    text,
                },
                Instant::now(),
                send,
                WhileBusy::Wait,
            );
            if let std::task::Poll::Ready((ok, answered)) = result {
                answer(answered);
                return ok.unwrap_or(false);
            }
            ready.await;
        }
    }

    /// THE HAND-OFF: take association `id` out, run `first` on it and then what was owed it
    /// meanwhile, each crossing with no lock held, and put it back (or, failed or removed, finish
    /// it with no lock held). Found out, `first` is queued for its holder. The first op's emit
    /// verdict (`None` = no such association), and what every operation the holder ran answered.
    fn turn(
        &self,
        id: u64,
        first: Owed<'_>,
        now: Instant,
        send: &dyn Fn(SocketAddr, &[u8]),
    ) -> (Option<bool>, Answered) {
        match self.try_turn(id, first, now, send, WhileBusy::Queue) {
            std::task::Poll::Ready(answer) => answer,
            std::task::Poll::Pending => unreachable!("queued turns never wait"),
        }
    }

    fn try_turn(
        &self,
        id: u64,
        first: Owed<'_>,
        now: Instant,
        send: &dyn Fn(SocketAddr, &[u8]),
        busy: WhileBusy,
    ) -> std::task::Poll<(Option<bool>, Answered)> {
        let (f, emission) = {
            let mut assocs = self.lock();
            if let Some(out) = assocs.out.get_mut(&id) {
                if out.closing {
                    return std::task::Poll::Ready((None, Vec::new()));
                }
                if matches!(busy, WhileBusy::Wait) {
                    return std::task::Poll::Pending;
                }
                out.owed.push_back(first.owned());
                return std::task::Poll::Ready((Some(true), Vec::new()));
            }
            let Some(f) = assocs.framings.remove(&id) else {
                return std::task::Poll::Ready((None, Vec::new()));
            };
            let deadline = f.deadline();
            assocs.out.insert(
                id,
                Out {
                    deadline,
                    ..Out::default()
                },
            );
            (f, assocs.emissions.get(&id).cloned())
        };
        let mut taken = Taken {
            port: self,
            id,
            framing: Some(f),
        };
        let mut op = first;
        let mut emitted = None;
        let mut answered = Vec::new();
        loop {
            let f = taken.framing.as_mut().expect("the association is out");
            let (failed, routed) = match op {
                Owed::Datagram(from, bytes) => {
                    let answer = f.datagram(from, &bytes, now);
                    let failed = answer.is_err();
                    answered.push((id, answer));
                    (failed, (!failed).then_some(from))
                }
                Owed::Timer => {
                    let answer = f.timeout(now);
                    let failed = answer.is_err();
                    answered.push((id, answer));
                    (failed, None)
                }
                Owed::Emit {
                    stream,
                    bytes,
                    end_of_frame,
                    text,
                } => {
                    let answer = f.emit(stream, &bytes, end_of_frame, text, now);
                    let ok = answer.is_ok();
                    if let Ok(yielded) = answer {
                        answered.push((id, Ok(yielded)));
                    }
                    emitted.get_or_insert(ok);
                    (false, None)
                }
            };
            while let Some((to, d)) = f.poll_send() {
                send(to, &d);
            }
            let mut assocs = self.lock();
            if let Some(from) = routed {
                assocs.route(id, from, f);
            }
            if failed || assocs.out.get(&id).is_none_or(|o| o.closing) {
                assocs.forget(id);
                drop(assocs);
                if let Some(emission) = &emission {
                    emission.order.close();
                    emission.ready.notify_waiters();
                    emission.wake.wake();
                }
                drop(taken.framing.take());
                break;
            }
            let next = assocs.out.get_mut(&id).and_then(|o| o.owed.pop_front());
            if let Some(next) = next {
                drop(assocs);
                op = next;
                continue;
            }
            assocs.out.remove(&id);
            if let Some(f) = taken.framing.take() {
                assocs.framings.insert(id, f);
            }
            break;
        }
        if let Some(emission) = emission {
            emission.ready.notify_waiters();
            emission.wake.wake();
        }
        std::task::Poll::Ready((emitted.or(Some(true)), answered))
    }
}

/// The user name a connectivity check names its receiver by: the part of its first USERNAME
/// field before the `:`. `None` for anything that is not a Binding request carrying one.
fn check_user(d: &[u8]) -> Option<&str> {
    const HEADER: usize = 20;
    if d.len() < HEADER || d[0..2] != [0x00, 0x01] || d[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return None;
    }
    let mut at = HEADER;
    while let Some(head) = d.get(at..at + 4) {
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let value = d.get(at + 4..at + 4 + len)?;
        if kind == 0x0006 {
            let name = std::str::from_utf8(value).ok()?;
            return name.split(':').next().filter(|u| !u.is_empty());
        }
        at += 4 + len.div_ceil(4) * 4;
    }
    None
}

/// Which leg of a bridged session an association is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// The association the caller opened (accepted on the claim door's port).
    Caller,
    /// The association the host dialled toward the far end for it.
    Upstream,
}

/// What a stream's head block says the stream is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamHead {
    /// A LINE: a stream of frames the host bridges and never reads (its `kind`).
    Line {
        /// The line's kind, as the framer named it.
        kind: String,
    },
    /// A CHANNEL: a stream of messages, the session's (its `label`).
    Channel {
        /// The channel's label, as the framer named it.
        label: String,
    },
}

/// Read a stream's head block (`name: value` lines): a `kind` field makes it a line, a `label`
/// field a channel; anything else is neither.
#[must_use]
pub fn stream_head(block: &[u8]) -> Option<StreamHead> {
    let text = std::str::from_utf8(block).ok()?;
    let mut label = None;
    for line in text.split("\r\n").filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':')?;
        let value = value.trim().to_owned();
        match name.trim() {
            "kind" => return Some(StreamHead::Line { kind: value }),
            "label" => label = Some(value),
            _ => {}
        }
    }
    label.map(|label| StreamHead::Channel { label })
}

/// One frame a leg yielded on a line, for the paired line of the other leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Across {
    /// The stream it goes to on the other leg.
    pub stream: u64,
    /// The frame, as the line carried it: never read.
    pub bytes: Vec<u8>,
    /// It ends its frame.
    pub end_of_frame: bool,
}

/// THE BRIDGE: one session's two associations, their LINES paired `i <-> i` by the order each leg
/// named them (the host pairs lines, the plane pairs channels). The upstream leg is dialled with
/// the caller's lines mirrored ([`Bridge::opening`]: same count, kind and order); a leg whose lines
/// do not mirror the other's is no bridge ([`Bridge::mirrored`]) and nothing crosses half-paired. A
/// line's frames are carried across unread; each leg seals with its own keys. Once
/// [`Bridge::stop`]ped nothing crosses again: the session's close stops both directions in one
/// step.
#[derive(Debug, Default)]
pub struct Bridge {
    caller: Vec<(u64, String)>,
    upstream: Vec<(u64, String)>,
    /// The caller's channels' labels, in the order it opened them.
    channels: Vec<String>,
    stopped: bool,
    custody: Vec<Custody>,
}

impl Bridge {
    /// A bridge with no line yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lines(&self, leg: Leg) -> &[(u64, String)] {
        match leg {
            Leg::Caller => &self.caller,
            Leg::Upstream => &self.upstream,
        }
    }

    /// The upstream dial's opening fields: one `media` field per caller line, its kind, in order,
    /// then one `channel` field per label the session names.
    #[must_use]
    pub fn opening(&self, channels: &[&str]) -> Vec<(String, Vec<u8>)> {
        self.caller
            .iter()
            .map(|(_, kind)| ("media".to_owned(), kind.clone().into_bytes()))
            .chain(
                channels
                    .iter()
                    .map(|l| ("channel".to_owned(), l.as_bytes().to_vec())),
            )
            .collect()
    }

    /// Whether the two legs' lines mirror: the same count, and the same kind at every position.
    ///
    /// # Errors
    ///
    /// The mismatch, named: the upstream dial is refused and the unit fails; nothing half-bridges.
    pub fn mirrored(&self) -> Result<(), String> {
        if self.caller.len() != self.upstream.len() {
            return Err(format!(
                "the upstream leg carries {} line(s), the caller's {}",
                self.upstream.len(),
                self.caller.len()
            ));
        }
        for (i, ((_, a), (_, b))) in self.caller.iter().zip(&self.upstream).enumerate() {
            if a != b {
                return Err(format!(
                    "line {i} is `{a}` on the caller's leg and `{b}` upstream"
                ));
            }
        }
        Ok(())
    }

    /// The caller's channels' labels, in the order it opened them: what the upstream dial names.
    #[must_use]
    pub fn caller_channels(&self) -> Vec<&str> {
        self.channels.iter().map(String::as_str).collect()
    }

    /// Stop the bridge: no frame crosses again, in either direction.
    pub fn stop(&mut self) {
        self.stopped = true;
    }

    /// The stream a frame on `leg`'s `stream` crosses to on the other leg; `None` = the stream is
    /// no line, the legs do not mirror, or the bridge is stopped.
    #[must_use]
    pub fn across(&self, leg: Leg, stream: u64) -> Option<u64> {
        if self.stopped || self.mirrored().is_err() {
            return None;
        }
        let i = self.lines(leg).iter().position(|(s, _)| *s == stream)?;
        let other = match leg {
            Leg::Caller => Leg::Upstream,
            Leg::Upstream => Leg::Caller,
        };
        self.lines(other).get(i).map(|(s, _)| *s)
    }

    /// Sort what `leg` yielded: a line's head is recorded, a line's frames go across (or are
    /// dropped when they cannot: never queued), and every other piece (a channel's head and
    /// messages, the leg's own description) is handed back for the session.
    pub fn sort(
        &mut self,
        leg: Leg,
        pieces: Vec<crate::framer::Got>,
    ) -> (Vec<crate::framer::Got>, Vec<Across>) {
        let mut session = Vec::new();
        let mut across = Vec::new();
        for g in pieces {
            let known = self.lines(leg).iter().any(|(s, _)| *s == g.stream);
            if g.fields && !known {
                match stream_head(&g.bytes) {
                    Some(StreamHead::Line { kind }) => {
                        match leg {
                            Leg::Caller => self.caller.push((g.stream, kind)),
                            Leg::Upstream => self.upstream.push((g.stream, kind)),
                        }
                        continue;
                    }
                    Some(StreamHead::Channel { label }) if leg == Leg::Caller => {
                        self.channels.push(label);
                    }
                    _ => {}
                }
            }
            if known {
                if let Some(stream) = self.across(leg, g.stream) {
                    if !g.ends_stream() {
                        across.push(Across {
                            stream,
                            bytes: g.bytes,
                            end_of_frame: g.end_of_frame,
                        });
                    }
                }
                continue;
            }
            session.push(g);
        }
        (session, across)
    }
}

/// A LEG'S DOOR for what crosses into it: the owner of the leg's association (the claim door's
/// port for the caller's, the connection table for the upstream's) emits there and closes it. Never
/// called with the caller's own lock held: a pairing hands a frame across only after the leg it
/// came from let its own association go.
pub trait LegSink: Send + Sync {
    /// Emit one line frame on this leg now.
    fn line(&self, across: Across, now: Instant);
    /// One producer batch, with no host lock held across its plugin crossing. `None` resumes
    /// the same op; a fresh frame waits until that op is complete.
    fn poll_line(
        &self,
        _cx: &mut std::task::Context<'_>,
        input: Option<&Across>,
        _text: bool,
        now: Instant,
    ) -> std::task::Poll<Result<LineStep, Refused>> {
        if let Some(input) = input {
            self.line(input.clone(), now);
            std::task::Poll::Ready(Ok(LineStep::Batch {
                yielded: Yielded::default(),
                accepted: true,
            }))
        } else {
            std::task::Poll::Ready(Ok(LineStep::Complete))
        }
    }
    /// The paired connection, without creating a strong ownership cycle.
    fn pairing(&self) -> Option<Arc<Pairing>> {
        None
    }
    /// Transfer channel storage to its real reader owner, or explicitly fail publication.
    fn channels(&self, _batch: SessionBatch, _now: Instant) -> Result<(), String> {
        Ok(())
    }
    /// Schedule on the leg's captured reactor and task tracker. A rejected task is dropped,
    /// preserving its pre-spawn cancellation guard.
    fn schedule(&self, task: PublicationTask) -> bool {
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(task);
                true
            }
            Err(_) => false,
        }
    }
    /// Close this leg's association. Called once, by the pairing's close.
    fn close(&self);
}

/// ONE HELD SESSION'S PAIRING: its caller leg, registered under the session's unit key before the
/// session runs ([`crate::Connector::pair`]); its upstream leg, the dial the session's walk opens
/// for that unit; and the [`Bridge`] between their lines. Closing it stops the bridge and closes
/// both legs, exactly once.
pub struct Pairing {
    state: std::sync::Mutex<PairState>,
    /// The caller leg's port address: the upstream leg binds a port of its own on the same host
    /// address.
    local: SocketAddr,
    memory: Arc<Memory>,
    published: tokio::sync::Notify,
}

struct PairState {
    bridge: Bridge,
    caller: Option<Arc<dyn LegSink>>,
    upstream: Option<Arc<dyn LegSink>>,
    closed: bool,
    publications: PublicationState,
}

#[path = "line_publication.rs"]
mod publication_scheduler;
use publication_scheduler::PublicationState;
pub use publication_scheduler::{PublicationOutcome, PublicationTask, SessionBatch, SubmitError};

impl std::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pairing")
            .field("local", &self.local)
            .field("closed", &self.closed())
            .finish_non_exhaustive()
    }
}

impl Pairing {
    /// A pairing for a session whose caller leg is `caller`, on the port at `local`.
    #[must_use]
    pub fn new(caller: Arc<dyn LegSink>, local: SocketAddr) -> Arc<Self> {
        Self::with_memory_limit(caller, local, None)
    }

    /// A pairing with an optional advanced shared live-storage limit. The default is unset;
    /// a configured limit can explicitly end a finite expanding feedback chain.
    #[must_use]
    pub fn with_memory_limit(
        caller: Arc<dyn LegSink>,
        local: SocketAddr,
        limit: Option<usize>,
    ) -> Arc<Self> {
        let pair = Arc::new(Pairing {
            state: std::sync::Mutex::new(PairState {
                bridge: Bridge::new(),
                caller: Some(caller),
                upstream: None,
                closed: false,
                publications: PublicationState::default(),
            }),
            local,
            memory: Memory::new(limit),
            published: tokio::sync::Notify::new(),
        });
        pair.memory.observe(Arc::downgrade(&pair));
        pair
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PairState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The caller leg's port address.
    #[must_use]
    pub fn local(&self) -> SocketAddr {
        self.local
    }

    /// Whether the pairing is closed.
    #[must_use]
    pub fn closed(&self) -> bool {
        self.lock().closed
    }

    /// The upstream dial's opening: the caller's lines mirrored, then its channels.
    #[must_use]
    pub fn opening(&self) -> Vec<(String, Vec<u8>)> {
        let st = self.lock();
        st.bridge.opening(&st.bridge.caller_channels())
    }

    /// What `leg` yielded: its line heads recorded, its line frames handed to the other leg (once
    /// that leg is attached and the lines mirror; dropped otherwise), and the session's pieces back.
    pub fn sort(
        &self,
        leg: Leg,
        pieces: Vec<crate::framer::Got>,
        now: Instant,
    ) -> Vec<crate::framer::Got> {
        let (session, across, to) = {
            let mut st = self.lock();
            let (session, across) = st.bridge.sort(leg, pieces);
            let to = match leg {
                Leg::Caller => st.upstream.clone(),
                Leg::Upstream => st.caller.clone(),
            };
            (session, across, to)
        };
        if let Some(to) = to {
            for a in across {
                to.line(a, now);
            }
        }
        session
    }

    /// Attach the upstream leg once its lines are known (sorted from its answer): refused, and
    /// nothing attached, unless they mirror the caller's or the pairing is closed.
    ///
    /// # Errors
    ///
    /// The mismatch, or the close: the upstream dial fails and nothing half-bridges.
    pub fn attach(&self, upstream: Arc<dyn LegSink>) -> Result<(), String> {
        let mut st = self.lock();
        if st.closed {
            return Err("the session closed before its upstream leg answered".into());
        }
        st.bridge.mirrored()?;
        if st.upstream.is_some() {
            return Err("the session already has an upstream leg".into());
        }
        st.upstream = Some(upstream);
        st.publications.waiting_attachment = false;
        drop(st);
        self.published.notify_waiters();
        Ok(())
    }

    /// CLOSE, exactly once: the bridge stops, then both legs close. A second close does nothing.
    pub fn close(&self) {
        let (legs, abandoned) = {
            let mut st = self.lock();
            if st.closed && st.caller.is_none() && st.upstream.is_none() {
                return;
            }
            st.closed = true;
            st.bridge.stop();
            let abandoned = st.publications.stop();
            ([st.caller.take(), st.upstream.take()], abandoned)
        };
        drop(abandoned);
        self.memory.close();
        self.retire_metadata_if_closed();
        self.published.notify_waiters();
        for leg in legs.into_iter().flatten() {
            leg.close();
        }
    }
}

impl DatagramFraming {
    fn finish(&mut self) {
        let token = std::mem::take(&mut self.token);
        if token == 0 {
            return;
        }
        let mut i: FinishIn = blank_in();
        i.framing = token;
        i.reason = CLOSE_NORMAL;
        i.sink = self.bufs.sink();
        let mut o: FramerOut = blank_out();
        let _ = self.door.cross(Call::Finish(&mut i, &mut o));
    }
}

impl Drop for DatagramFraming {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/datagram_tests.rs"]
mod tests;
