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
//!
//! Sans-IO: the caller hands in what the port read and the clock, takes
//! [`DatagramFraming::poll_send`] out to the port, and calls [`DatagramFraming::timeout`] at
//! [`DatagramFraming::deadline`].

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::check::check_datagram;
use busbar_contract::abi::transport::{
    BeginIn, ConnFacts, DatagramLane, DatagramPath, DatagramRoute, EmitIn, FinishIn, FramerOut,
    FramingIn, IngestIn, KeyingMaterial, RendezvousTerms, CLOSE_NORMAL, EMIT_TEXT,
    FINGERPRINT_BYTES, HANDSHAKE_ANSWERS, HANDSHAKE_INITIATES, HANDSHAKE_NONE, LANE_CLEAR,
    LANE_RENDEZVOUS, LANE_SECURED, PATH_REQUEST_BIND, PATH_REQUEST_REBIND, SIDE_ACCEPT,
};

use crate::dtls::{Association, IceCredentials, Role, SessionCert, SrtpKeying, Up, Verdict};
use crate::framer::{instant_of, ready, Buffers, Call, Crossed, FramerDoor, Refused, Yielded};

/// The routes one framer answer may write.
const ROUTES_CAP: usize = 64;
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
    Begin,
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
    fn again(self) -> Self {
        match self {
            Op::Begin | Op::Timer => Op::Timer,
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
    refused_routes: u64,
    deadline_ns: Option<u64>,
    ended: bool,
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
        let mut f = DatagramFraming {
            door,
            token: 0,
            bufs: Buffers::for_side(SIDE_ACCEPT),
            routes: vec![DatagramRoute::default(); ROUTES_CAP],
            cert,
            local: local.to_string(),
            secure: None,
            book: PathBook::default(),
            keying: None,
            presented: false,
            told: (0, false),
            send: VecDeque::new(),
            refused_routes: 0,
            deadline_ns: None,
            ended: false,
        };
        let y = f.run(Op::Begin, Instant::now())?;
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
        self.send.pop_front()
    }

    /// How many routes the host refused to send (to a path the secure layer does not allow, or
    /// secured before there was a bound path to seal to).
    #[must_use]
    pub fn refused_routes(&self) -> u64 {
        self.refused_routes
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
        self.cross(first, &mut y, now)?;
        self.settle(y, now)
    }

    /// Drain the secure layer: its datagrams to the port, its plaintext to the framer, and the
    /// host state (bound path, verified bit, the keying-material item) the framer has not been
    /// told.
    fn settle(&mut self, mut y: Yielded, now: Instant) -> Result<Yielded, Refused> {
        loop {
            let mut opened = Vec::new();
            let mut closed = false;
            if let Some(secure) = self.secure.as_mut() {
                while let Some(d) = secure.poll_wire() {
                    self.send.push_back(d);
                }
                while let Some(up) = secure.poll_up() {
                    match up {
                        Up::Connected => {}
                        Up::Keyed(k) => {
                            if self.presented || self.keying.is_some() {
                                return Err(fault("the secure layer exported keying twice"));
                            }
                            self.keying = Some(k);
                        }
                        Up::Plaintext(p) => opened.push(p),
                        Up::Closed => closed = true,
                    }
                }
                if let Some(f) = secure.failure() {
                    return Err(Refused {
                        outcome: Outcome::Failed,
                        error: format!("the secure layer failed the association: {f:?}"),
                    });
                }
            }
            if self.keying.is_some() && !self.verified() {
                return Err(fault("keying material with the far end not verified"));
            }
            let state = (self.bound_path(), self.verified());
            let owed = state != self.told || self.keying.is_some();
            if opened.is_empty() && !closed && !owed {
                y.wire.clear();
                return Ok(y);
            }
            for p in &opened {
                let from = self.bound();
                self.cross(
                    Op::Ingest {
                        lane: LANE_SECURED,
                        from,
                        bytes: p,
                        end: false,
                    },
                    &mut y,
                    now,
                )?;
            }
            if closed || (opened.is_empty() && owed) {
                self.cross(
                    Op::Ingest {
                        lane: 0,
                        from: None,
                        bytes: &[],
                        end: closed,
                    },
                    &mut y,
                    now,
                )?;
            }
        }
    }

    /// One op and its `YIELD_MORE` re-calls, each carrying the lane, each answer judged and
    /// applied.
    fn cross(&mut self, first: Op<'_>, y: &mut Yielded, now: Instant) -> Result<(), Refused> {
        let mut op = first;
        loop {
            let o = self.cross_once(op)?;
            let done = self.take(&o, y, now)?;
            if done {
                return Ok(());
            }
            op = op.again();
        }
    }

    fn cross_once(&mut self, op: Op<'_>) -> Result<FramerOut, Refused> {
        if self.token == 0 && !matches!(op, Op::Begin) {
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
            Op::Begin => {
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
                i.side = SIDE_ACCEPT;
                i.facts = &facts;
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
        if matches!(op, Op::Begin) {
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
            self.secure = Some(Association::new(
                Arc::clone(&self.cert),
                t.role,
                &t.local,
                &t.remote,
                t.fingerprint,
            ));
        }
        for (path, lane, bytes) in asked.routes {
            self.send_answered(path, lane, bytes);
        }
        self.request(asked.request, now);
        Ok(done)
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
    let mut fingerprint = [0_u8; FINGERPRINT_BYTES as usize];
    fingerprint.copy_from_slice(
        span(t.peer_fingerprint)?
            .get(..fingerprint.len())
            .ok_or_else(|| fault("the far end's fingerprint is short"))?,
    );
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
    })
}

impl Drop for DatagramFraming {
    fn drop(&mut self) {
        if self.token == 0 {
            return;
        }
        let mut i: FinishIn = blank_in();
        i.framing = self.token;
        i.reason = CLOSE_NORMAL;
        i.sink = self.bufs.sink();
        let mut o: FramerOut = blank_out();
        let _ = self.door.cross(Call::Finish(&mut i, &mut o));
        self.token = 0;
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/datagram_tests.rs"]
mod tests;
