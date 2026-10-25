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
use crate::DialJudge;

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
    fn again(self) -> Self {
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
            refused_routes: 0,
            deadline_ns: None,
            ended: false,
            side,
            judge,
            refused_candidates: 0,
            user: None,
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
            let owed = state != self.told || self.keying.is_some() || !self.book.untold.is_empty();
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
        let mut recalls = crate::framer::Recalls::default();
        loop {
            let o = self.cross_once(op)?;
            let done = self.take(&o, y, now)?;
            if done {
                return Ok(());
            }
            recalls.owed(&o)?;
            op = op.again();
        }
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
        let user = framing.user().ok_or(NotAdded::NoTerms)?.to_owned();
        if self.by_user.contains_key(&user) {
            return Err(NotAdded::UserTaken);
        }
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
        Ok(id)
    }

    /// Stop carrying association `id`; the framing, for its owner to finish.
    pub fn remove(&mut self, id: u64) -> Option<DatagramFraming> {
        let f = self.framings.remove(&id)?;
        self.by_user.retain(|_, v| *v != id);
        self.by_path.retain(|_, v| *v != id);
        Some(f)
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
        let id = match check_user(bytes) {
            Some(user) => self.by_user.get(user).copied(),
            None => self.by_path.get(&from).copied(),
        }?;
        let f = self.framings.get_mut(&id)?;
        let answer = f.datagram(from, bytes, now);
        let (owns, binds) = (f.owns(from), f.binds(from));
        if answer.is_ok() && owns {
            // A path another association holds stays its own while it still owns it, unless this
            // one has it BOUND (proven by core's round trip) and the holder does not: a heard check
            // proves only that its sender knows this association's password, never that it owns
            // the source address.
            let take = match self.by_path.get(&from) {
                None => true,
                Some(holder) if *holder == id => false,
                Some(holder) => self
                    .framings
                    .get(holder)
                    .is_none_or(|h| !h.owns(from) || (binds && !h.binds(from))),
            };
            if take {
                self.by_path.insert(from, id);
                // The paths it let go of (a heard path that made room for this one) are let go
                // here too, so the port routes an association no more paths than it owns.
                let framings = &self.framings;
                self.by_path.retain(|addr, holder| {
                    *holder != id || framings.get(holder).is_some_and(|h| h.owns(*addr))
                });
            }
        }
        if answer.is_err() {
            self.remove(id);
        }
        Some((id, answer))
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
            .min()
    }

    /// The next datagram any association owes the port, and where it goes.
    pub fn poll_send(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.framings
            .values_mut()
            .find_map(DatagramFraming::poll_send)
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
/// named them (ARCHITECT ruling, row 132: the host pairs lines, the plane pairs channels). The
/// upstream leg is dialled with the caller's lines mirrored ([`Bridge::opening`]: same count, kind
/// and order); a leg whose lines do not mirror the other's is no bridge ([`Bridge::mirrored`]) and
/// nothing crosses half-paired. A line's frames are carried across unread; each leg seals with
/// its own keys. Once [`Bridge::stop`]ped nothing crosses again: the session's close stops both
/// directions in one step.
#[derive(Debug, Default)]
pub struct Bridge {
    caller: Vec<(u64, String)>,
    upstream: Vec<(u64, String)>,
    /// The caller's channels' labels, in the order it opened them.
    channels: Vec<String>,
    stopped: bool,
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

    /// Whether the bridge is stopped.
    #[must_use]
    pub fn stopped(&self) -> bool {
        self.stopped
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
                    if !g.bytes.is_empty() {
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
    /// Close this leg's association. Called once, by the pairing's close.
    fn close(&self);
}

/// ONE HELD SESSION'S PAIRING (ARCHITECT rulings, row 132): its caller leg, registered under the
/// session's unit key before the session runs ([`crate::Connector::pair`]); its upstream leg, the
/// dial the session's walk opens for that unit; and the [`Bridge`] between their lines. Closing it
/// stops the bridge and closes both legs, exactly once.
pub struct Pairing {
    state: std::sync::Mutex<PairState>,
    /// The caller leg's port address: the upstream leg binds a port of its own on the same host
    /// address.
    local: SocketAddr,
}

struct PairState {
    bridge: Bridge,
    caller: Option<Arc<dyn LegSink>>,
    upstream: Option<Arc<dyn LegSink>>,
    closed: bool,
}

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
        Arc::new(Pairing {
            state: std::sync::Mutex::new(PairState {
                bridge: Bridge::new(),
                caller: Some(caller),
                upstream: None,
                closed: false,
            }),
            local,
        })
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
        st.upstream = Some(upstream);
        Ok(())
    }

    /// CLOSE, exactly once: the bridge stops, then both legs close. A second close does nothing.
    pub fn close(&self) {
        let legs = {
            let mut st = self.lock();
            if st.closed {
                return;
            }
            st.closed = true;
            st.bridge.stop();
            [st.caller.take(), st.upstream.take()]
        };
        for leg in legs.into_iter().flatten() {
            leg.close();
        }
    }
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
