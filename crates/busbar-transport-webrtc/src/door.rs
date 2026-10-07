// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `webrtc` DOOR: this transport as a DATAGRAM FRAMER on the transport kind's table
//! (`busbar_contract::abi::transport`, its datagram lane `abi::transport::datagram`). Every slot is
//! a [`SafeSlot`] over the SDK's generic lifecycle: no `unsafe` here.
//!
//! * `begin`: [`SIDE_ACCEPT`] (answers an offer) or [`SIDE_DIAL`] (yields its offer at once, on
//!   stream 0). The host's certificate comes in [`ConnFacts::local_certificate`] (public DER; its
//!   fingerprint is what the description states), the host port's address in the lane. A dialling
//!   framing's opening fields name what it offers: one `channel` field per data channel (its label,
//!   streams `1, 2, ...` in order) and `media: audio` for one Opus line (stream [`MEDIA_BASE`]).
//! * `ingest`: one datagram, or the far end's description, as the lane names it; the lane's host
//!   state (bound path, verified bit, keying-material item, new paths) is read first, on every call
//!   that carries a lane.
//! * `emit`: one message for a stream (a channel's message, an Opus frame for a media line),
//!   gathered until `end_of_frame`; [`EMIT_TEXT`] marks a channel message as text.
//! * `timer`: the clock; `finish`: the association closes.
//! * `locate`, `encode`, `refuse`, `detach`, `adopt`: REFUSED (no authority to dial, no envelope,
//!   no upgrade); every carrier op: REFUSED.
//!
//! A full host buffer is back-pressure: READY with [`YIELD_MORE`], and the re-call carries no new
//! bytes. No op pends.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::check::check_keying;
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnFacts, ConnIn,
    ConnOut, DatagramLane, DatagramRoute, DatagramYield, DialIn, EmitIn, EncodeIn, FinishIn,
    FramePiece, FrameSpan, FramerOut, FramerSink, FramingIn, IngestIn, IoOut, ListenIn, ListenOut,
    LocateIn, LocateOut, Ops, ReadIn, RefuseIn, RendezvousTerms, ShutIn, TransportTail, WriteIn,
    CANCEL_NOTHING_MOVED, EMIT_TEXT, FRAMING_DATAGRAM, HANDSHAKE_ANSWERS, HANDSHAKE_INITIATES,
    LANE_CLEAR, LANE_RENDEZVOUS, LANE_SECURED, PATH_REQUEST_BIND, PATH_REQUEST_REBIND,
    PIECE_CONTINUED, PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_TEXT, ROLE_FRAMER, SIDE_ACCEPT,
    SIDE_DIAL, UNIT0_FIRST_DATAGRAM, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE,
};

use crate::framing::{Framing, Lane, Opening, Piece, Request, Side, MEDIA_BASE};

// ── the statement ────────────────────────────────────────────────────────────────────────────────

/// The claim this entry answers for.
pub const KEY: &str = "webrtc";

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY)];

/// The claim's row: no selector forms (an association is reached through the rendezvous, never
/// selected on its datagrams), a session whose first unit opens on its first datagram.
const CLAIMS: &[Claim] = &[Claim {
    selector_forms: abi_str(""),
    egress_selector_forms: abi_str(""),
    facts: std::ptr::null(),
    facts_len: 0,
    status_namespace: NONE,
    session: 1,
    session_bound: 1,
    unit0_trigger: UNIT0_FIRST_DATAGRAM,
    status_at: 0,
    _reserved: 0,
}];

/// The transport kind's tail: a datagram framer, composing over nothing (the port is the host's).
const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<TransportTail>() as u32,
        _reserved: 0,
    },
    role: ROLE_FRAMER,
    framing: FRAMING_DATAGRAM,
    facts: 0,
    handshake_max_steps: 0,
    composes_over: std::ptr::null(),
    composes_over_len: 0,
    claim_rows: CLAIMS.as_ptr(),
    claim_rows_len: CLAIMS.len(),
    upgrades_to: std::ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: std::ptr::null(),
    status_rows_len: 0,
    settings: std::ptr::null(),
    settings_len: 0,
};

/// The door's Statement.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement(KEY, env!("CARGO_PKG_VERSION"), 64)
};

// ── the instance ─────────────────────────────────────────────────────────────────────────────────

/// One association's framing and the host clock it is read against.
struct Held1 {
    f: Framing,
    base_ns: u64,
    base: Instant,
    /// A message being gathered, per stream, and whether it is text.
    gathering: HashMap<u64, (Vec<u8>, bool)>,
    /// A piece split across calls: the bytes not yet written, and whether they continue a field
    /// line an earlier piece began.
    partial: Option<(Piece, bool)>,
}

impl Held1 {
    fn at(&self, ns: u64) -> Instant {
        self.base + Duration::from_nanos(ns.saturating_sub(self.base_ns))
    }

    fn ns(&self, t: Instant) -> u64 {
        let d = t.saturating_duration_since(self.base);
        self.base_ns
            .saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .max(1)
    }
}

/// The framings one instance holds.
pub struct Framings {
    framings: Mutex<HashMap<u64, Held1>>,
    next: AtomicU64,
}

type State = Held<Framings>;

impl Life for Framings {
    /// No framer op pends, so a cancel finds nothing in flight.
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    /// This framer reads no setting.
    fn validate(_: &[u8]) -> Result<(), Refusal> {
        Ok(())
    }

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            framings: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

impl Framings {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Held1>> {
        self.framings.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn framings<'a>(i: &Instance<'a, State>) -> Result<&'a Framings, Refusal> {
    i.get()
        .map(Held::life)
        .ok_or_else(|| Refusal::failed("no open instance"))
}

fn addr(s: Lent<'_, AbiStr>) -> Option<SocketAddr> {
    s.as_str().ok()?.parse().ok()
}

/// Read the lane's host state into the framing: new paths, the bound path, the verified bit and
/// the keying-material item.
fn host_state(h: &mut Held1, lane: Lent<'_, DatagramLane>, now: Instant) -> Result<(), String> {
    if let Some(a) = addr(lane.field(|l| &l.local_addr)) {
        h.f.local(a);
    }
    h.f.paths(
        lane.paths()
            .iter()
            .filter_map(|p| Some((p.path, addr(p.field(|x| &x.addr))?))),
    );
    let keying = match lane.keying() {
        Some(k) => {
            check_keying(&k)
                .map_err(|f| format!("the keying-material item is malformed: {}", f.field))?;
            Some((k.profile, k.bytes()))
        }
        None => None,
    };
    h.f.host(lane.bound, lane.verified == 1, keying, now)
}

/// Answer into the sink and the lane what the framing owes: routes (bytes in `wire`), pieces (bytes
/// in `frame`), the rendezvous terms, one path request, the deadline, and the flags.
fn answer(
    h: &mut Held1,
    sink: Lent<'_, FramerSink>,
    lane: Option<Lent<'_, DatagramLane>>,
    now_ns: u64,
    o: &mut Out<'_, FramerOut>,
) {
    let mut wire = sink.wire();
    let mut frame = sink.frame();
    let mut pieces = sink.pieces();
    let mut d = DatagramYield::default();
    let mut more = false;

    // Routes: only through a lane's buffer; a stream host gets none.
    if let Some(lane) = lane {
        let mut routes = lane.routes();
        while let Some(r) = h.f.next_route() {
            let room = wire.cap().saturating_sub(wire.asked());
            if routes.asked() >= routes.cap() || room < r.bytes.len() {
                h.f.unroute(r);
                more = true;
                break;
            }
            let at = wire.extend(&r.bytes);
            routes.push(DatagramRoute {
                offset: at as u64,
                len: r.bytes.len() as u64,
                path: r.path,
                lane: match r.lane {
                    Lane::Clear => LANE_CLEAR,
                    Lane::Secured => LANE_SECURED,
                },
            });
        }
        d.routes_len = u32::try_from(routes.asked()).unwrap_or(u32::MAX);
        if let Some(req) = h.f.take_request() {
            (d.request, d.request_from, d.request_to) = match req {
                Request::Bind(p) => (PATH_REQUEST_BIND, 0, p),
                Request::Rebind(a, b) => (PATH_REQUEST_REBIND, a, b),
            };
        }
    }

    // The terms first, whole, so their spans are in this answer's frame.
    if let Some(t) = h.f.take_terms() {
        let parts: [&[u8]; 6] = [
            t.local_user.as_bytes(),
            t.local_secret.as_bytes(),
            t.remote_user.as_bytes(),
            t.remote_secret.as_bytes(),
            &t.peer_fingerprint,
            &[],
        ];
        let candidates: String = t.candidates.iter().map(|c| format!("{c}\n")).collect();
        let total: usize = parts.iter().map(|p| p.len()).sum::<usize>() + candidates.len();
        if frame.cap().saturating_sub(frame.asked()) >= total {
            let mut span = |b: &[u8]| FrameSpan {
                offset: frame.extend(b) as u64,
                len: b.len() as u64,
            };
            d.terms = RendezvousTerms {
                role: if t.initiates {
                    HANDSHAKE_INITIATES
                } else {
                    HANDSHAKE_ANSWERS
                },
                _reserved: 0,
                local_user: span(parts[0]),
                local_secret: span(parts[1]),
                remote_user: span(parts[2]),
                remote_secret: span(parts[3]),
                peer_fingerprint: span(parts[4]),
                candidates: if candidates.is_empty() {
                    FrameSpan::default()
                } else {
                    span(candidates.as_bytes())
                },
            };
        } else {
            // Not room for them whole: the host drains and calls again.
            h.partial_terms(t);
            more = true;
        }
    }

    // Pieces.
    loop {
        let Some((mut p, continued)) = h
            .partial
            .take()
            .or_else(|| h.f.next_piece().map(|p| (p, false)))
        else {
            break;
        };
        let room = frame.cap().saturating_sub(frame.asked());
        if pieces.asked() >= pieces.cap() || (room == 0 && !p.bytes.is_empty()) {
            h.partial = Some((p, continued));
            more = true;
            break;
        }
        let whole = p.bytes.len() <= room;
        if !whole && p.fields && frame.asked() != 0 {
            // A field block starts a fresh answer rather than split mid-buffer.
            h.partial = Some((p, continued));
            more = true;
            break;
        }
        let n = p.bytes.len().min(room);
        let at = frame.extend(&p.bytes[..n]);
        let mut flags = 0_u16;
        if p.fields {
            flags |= PIECE_FIELDS;
            if continued {
                flags |= PIECE_CONTINUED;
            }
        }
        if p.text && n > 0 && !p.fields {
            flags |= PIECE_TEXT;
        }
        if whole {
            flags |= PIECE_END_OF_FRAME;
        }
        pieces.push(FramePiece {
            stream: p.stream,
            offset: at as u64,
            len: n as u64,
            code: 0,
            status_class: 0,
            _reserved: 0,
            flags,
            retry_after_secs: 0,
        });
        if !whole {
            p.bytes.drain(..n);
            // The rest of a field block continues the line this piece may have split.
            let continues = p.fields;
            h.partial = Some((p, continues));
            more = true;
            break;
        }
    }
    o.set(|o| &o.yielded.wire_len, wire.asked() as u64);
    o.set(|o| &o.yielded.frame_len, frame.asked() as u64);
    o.set(
        |o| &o.yielded.pieces_len,
        u32::try_from(pieces.asked()).unwrap_or(u32::MAX),
    );
    o.set(|o| &o.datagram, d);
    let mut flags = 0;
    more |= h.f.owes() || h.partial.is_some();
    if more {
        flags |= YIELD_MORE;
    } else if h.f.ended() {
        flags |= YIELD_ENDED;
    }
    if let Some(t) = h.f.next_timeout() {
        let ns = h.ns(t).max(now_ns.saturating_add(1));
        flags |= YIELD_HAS_DEADLINE;
        o.set(|o| &o.yielded.next_deadline_ns, ns);
    }
    o.set(|o| &o.yielded.flags, flags);
}

impl Held1 {
    fn partial_terms(&mut self, t: crate::framing::Terms) {
        self.f.restore_terms(t);
    }
}

/// Run `op` on the framing `token` names, then answer what it owes.
fn with(
    inst: &Instance<'_, State>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    lane: Option<Lent<'_, DatagramLane>>,
    o: &mut Out<'_, FramerOut>,
    op: impl FnOnce(&mut Held1, Instant) -> Result<(), String>,
) -> Outcome {
    let s = match framings(inst) {
        Ok(s) => s,
        Err(r) => return o.fail(r),
    };
    let mut held = s.lock();
    let Some(h) = held.get_mut(&token) else {
        return o.fail(Refusal::failed("no such framing"));
    };
    let now_ns = sink.now_monotonic_ns;
    let now = h.at(now_ns);
    let run = match lane {
        Some(l) => host_state(h, l, now).and_then(|()| op(h, now)),
        None => op(h, now),
    };
    if let Err(why) = run {
        held.remove(&token);
        return o.fail(Refusal::failed(why));
    }
    if let Some(why) = h.f.failure() {
        let why = why.to_owned();
        held.remove(&token);
        return o.fail(Refusal::failed(why));
    }
    answer(h, sink, lane, now_ns, o);
    Outcome::Ready
}

// ── the carrier ops: refused ─────────────────────────────────────────────────────────────────────

/// A carrier op: REFUSED. The port is the host's.
pub struct NotACarrier<I, O>(PhantomData<(I, O)>);

impl<I: AbiIn, O: AbiOut> SafeSlot for NotACarrier<I, O> {
    type In = I;
    type Out = O;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

/// A framer op this framer has no use for: FAILED with its reason.
pub struct Unused<I>(PhantomData<I>);

/// Why each unused op is refused.
pub trait Why {
    /// The reason.
    const WHY: &'static str;
}

impl Why for EncodeIn {
    const WHY: &'static str = "encode: an association carries no envelope";
}
impl Why for RefuseIn {
    const WHY: &'static str = "refuse: an association's refusal is the signalling unit's";
}
impl Why for AdoptIn {
    const WHY: &'static str = "adopt: an association is begun at its rendezvous, never adopted";
}

impl<I: AbiIn + Why> SafeSlot for Unused<I> {
    type In = I;
    type Out = FramerOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, I>, mut o: Out<'_, FramerOut>) -> Outcome {
        o.fail(Refusal::failed(I::WHY))
    }
}

// ── the framer ───────────────────────────────────────────────────────────────────────────────────

/// `locate`: REFUSED. An association's far end comes from its description, judged by the host.
pub struct Locate;
impl SafeSlot for Locate {
    type In = LocateIn;
    type Out = LocateOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, LocateIn>, mut o: Out<'_, LocateOut>) -> Outcome {
        o.fail(Refusal::failed(
            "locate: an association's far end comes from its description, not a target",
        ))
    }
}

/// What a dialling framing's opening fields offer.
fn opening(i: &Lent<'_, BeginIn>) -> Opening {
    let mut o = Opening::default();
    for f in i.fields().iter() {
        let (Ok(name), Ok(value)) = (
            f.field(|x| &x.name).as_str(),
            f.field(|x| &x.value).as_str(),
        ) else {
            continue;
        };
        match name {
            "channel" if !value.is_empty() => o.channels.push(value.to_owned()),
            "media" if value == "audio" => o.audio = true,
            _ => {}
        }
    }
    o
}

/// The host's public certificate, from the facts.
fn certificate<'a>(i: &Lent<'a, BeginIn>) -> Option<&'a [u8]> {
    let facts: Lent<'a, ConnFacts> = i.facts()?;
    if (facts.size as usize) < std::mem::size_of::<ConnFacts>() {
        return None;
    }
    let der = facts.field(|f| &f.local_certificate).bytes();
    (!der.is_empty()).then_some(der)
}

/// `begin`: an accepting framing waits for the offer; a dialling one yields its offer now.
pub struct Begin;
impl SafeSlot for Begin {
    type In = BeginIn;
    type Out = FramerOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, BeginIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        let side = match i.side {
            SIDE_ACCEPT => Side::Accept,
            SIDE_DIAL => Side::Dial,
            _ => {
                return o.fail(Refusal::failed(
                    "begin: an association is accepted or dialled, never one stream",
                ))
            }
        };
        let Some(lane) = i.lane() else {
            return o.fail(Refusal::failed("begin: a datagram framer reads its lane"));
        };
        let Some(cert) = certificate(&i) else {
            return o.fail(Refusal::failed("begin: the host presented no certificate"));
        };
        let sink = i.field(|x| &x.sink);
        let now_ns = sink.now_monotonic_ns;
        let base = Instant::now();
        let local = addr(lane.field(|l| &l.local_addr));
        let f = match Framing::begin(side, cert, local, &opening(&i), base) {
            Ok(f) => f,
            Err(why) => return o.fail(Refusal::failed(why)),
        };
        let mut h = Held1 {
            f,
            base_ns: now_ns,
            base,
            gathering: HashMap::new(),
            partial: None,
        };
        if let Err(why) = host_state(&mut h, lane, base) {
            return o.fail(Refusal::failed(why));
        }
        answer(&mut h, sink, Some(lane), now_ns, &mut o);
        let token = s.next.fetch_add(1, Ordering::Relaxed);
        s.lock().insert(token, h);
        o.set(|o| &o.framing, token);
        Outcome::Ready
    }
}

/// `ingest`: one datagram, or the far end's description.
pub struct Ingest;
impl SafeSlot for Ingest {
    type In = IngestIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, IngestIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(lane) = i.lane() else {
            return o.fail(Refusal::failed("ingest: a datagram framer reads its lane"));
        };
        let bytes = i.bytes();
        let ended = i.end != 0;
        with(
            &inst,
            i.framing,
            i.field(|x| &x.sink),
            Some(lane),
            &mut o,
            |h, now| {
                if bytes.is_empty() {
                    // The YIELD_MORE re-call (or a host-state-only call): nothing new.
                    if ended {
                        h.f.finish(now);
                    }
                    return Ok(());
                }
                match lane.lane {
                    LANE_RENDEZVOUS => h.f.rendezvous(bytes, now),
                    LANE_CLEAR | LANE_SECURED => {
                        let from = addr(lane.field(|l| &l.path_addr))
                            .ok_or("ingest: a datagram with no address")?;
                        let l = if lane.lane == LANE_CLEAR {
                            Lane::Clear
                        } else {
                            Lane::Secured
                        };
                        h.f.datagram(lane.path, from, l, bytes, now);
                        Ok(())
                    }
                    _ => Err("ingest: bytes on no lane".into()),
                }
            },
        )
    }
}

/// `emit`: a message's pieces, gathered; its last piece sends it.
pub struct Emit;
impl SafeSlot for Emit {
    type In = EmitIn;
    type Out = FramerOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, EmitIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        let bytes = i.bytes();
        let end = i.end_of_frame != 0;
        let text = i.flags & EMIT_TEXT != 0;
        let stream = i.stream;
        with(
            &inst,
            i.framing,
            i.field(|x| &x.sink),
            i.lane(),
            &mut o,
            |h, now| {
                if bytes.is_empty() && !end {
                    return Ok(());
                }
                let g = h.gathering.entry(stream).or_default();
                g.0.extend_from_slice(bytes);
                g.1 |= text;
                if !end {
                    return Ok(());
                }
                let (message, text) = h.gathering.remove(&stream).unwrap_or_default();
                if message.is_empty() {
                    return Ok(());
                }
                h.f.emit(stream, &message, text, now)
            },
        )
    }
}

/// `timer`: the deadline the framing asked for passed.
pub struct Timer;
impl SafeSlot for Timer {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        with(
            &inst,
            i.framing,
            i.field(|x| &x.sink),
            i.lane(),
            &mut o,
            |h, now| {
                h.f.timeout(now);
                Ok(())
            },
        )
    }
}

/// `detach`: REFUSED (an association is never handed to another framer).
pub struct Detach;
impl SafeSlot for Detach {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, FramingIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        o.fail(Refusal::failed(
            "detach: an association is never handed to another framer",
        ))
    }
}

/// `finish`: the association closes, its last datagrams answered; the framing is forgotten.
pub struct Finish;
impl SafeSlot for Finish {
    type In = FinishIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, FinishIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        let mut held = s.lock();
        let Some(mut h) = held.remove(&i.framing) else {
            return o.fail(Refusal::failed("finish: no such framing"));
        };
        drop(held);
        let sink = i.field(|x| &x.sink);
        let now_ns = sink.now_monotonic_ns;
        let now = h.at(now_ns);
        h.f.finish(now);
        // What the close owes is answered once; what does not fit is dropped with the framing.
        answer(&mut h, sink, i.lane(), now_ns, &mut o);
        let flags = o.get().yielded.flags & !(YIELD_MORE | YIELD_HAS_DEADLINE);
        o.set(|o| &o.yielded.next_deadline_ns, 0);
        o.set(|o| &o.yielded.flags, flags | YIELD_ENDED);
        Outcome::Ready
    }
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: life(Framings),
    kind_ops: {
        listen: Safe<NotACarrier<ListenIn, ListenOut>>,
        accept: Safe<NotACarrier<AcceptIn, AcceptOut>>,
        dial: Safe<NotACarrier<DialIn, ConnOut>>,
        read: Safe<NotACarrier<ReadIn, IoOut>>,
        write: Safe<NotACarrier<WriteIn, IoOut>>,
        flush: Safe<NotACarrier<ConnIn, OutHead>>,
        shut: Safe<NotACarrier<ShutIn, OutHead>>,
        arrival: Safe<NotACarrier<ArrivalIn, ArrivalOut>>,
        locate: Safe<Locate>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Emit>,
        encode: Safe<Unused<EncodeIn>>,
        refuse: Safe<Unused<RefuseIn>>,
        finish: Safe<Finish>,
        detach: Safe<Detach>,
        adopt: Safe<Unused<AdoptIn>>,
        timer: Safe<Timer>,
    },
}

/// The first media stream, for a host that names streams.
pub const FIRST_MEDIA_STREAM: u64 = MEDIA_BASE;
