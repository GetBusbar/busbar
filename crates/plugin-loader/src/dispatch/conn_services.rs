// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR SLOTS, HOST SIDE (`BUSBAR-1.6.0.md` §11.12, the connections section): the
//! [`ConnectorSlots`] table ([`CONN_SLOTS`]) an instance whose Statement declares a need is handed
//! at bind, each slot a thin frame over the host's ONE connection table
//! ([`busbar_contract::conn::Conns`]), called under the instance's own identity.
//!
//! * `ESTABLISH` opens the need (its Statement index) at the target the plugin names, landing only
//!   on an address of its `within` set when it states one (the addresses its `dest.judge` judged):
//!   the connector holds the pinned address to the set at the connect, before any byte is
//!   written, a framed need's included (its connect is at `WRITE_REQUEST`'s end).
//! * `READ` answers the next piece's bytes; nothing ready is PENDING on the caller's ticket (the
//!   table wakes it), and never PENDING without one. A closed stream reads as its end (`len` 0).
//! * `WRITE` offers bytes; `CLOSE` closes.
//! * `UPGRADE_SECURE` secures a raw stream from its next byte on (StartTLS after the plugin's own
//!   negotiation; TLS from the first byte, ldaps, when made before any byte), trusting the need's
//!   anchors (the public roots, and the operator CA its `trust_from` names on top); PENDING on the
//!   caller's ticket while the handshake runs. A framed stream refuses it.
//! * `FACTS` writes the stream's facts: whether it is secure, the protocol agreed and the hash of
//!   the far end's certificate (the channel-binding input), the strings held until it closes.
//! * `RANDOM` fills the buffer from the OS; `IDENTITY` names the process.
//! * `WRITE_REQUEST` sends a request on a FRAMED stream piece by piece (head, body, end): a framed
//!   need's `ESTABLISH` answers a stream the host holds unopened, the head and body are held here,
//!   and the end opens it with the whole request as its opening message, the head words included
//!   (`OpenDesc::method`, `OpenDesc::head_target`), so the framer writes its own wire head. A raw
//!   stream refuses it.
//! * `READ_REPLY` reads the reply piece by piece with its descriptor (`ReplyPiece`, spec Part 4
//!   Axis 3, "Every transport acks back to the sender"): the far end's head is `REPLY_HEAD` (its
//!   code, its reason as sent, its field block, `abi::transport::fields`), its body `REPLY_BODY`,
//!   and the end exactly ONE terminal piece, `REPLY_END` after a head or `REPLY_ACK` without one. A
//!   refused or failed stream (the egress class's refusal among them) is a failed ack: the read
//!   answers its refusal, with its text, and the reply has ended.
//! * A slot this host does not offer is NULL: a plugin that needs it refuses to open.
//!
//! THE REPLAY RULE (`abi::sdk::conn`): the host never runs a service twice. A ticketed service's
//! answer is kept under its completion handle, and a re-issued handle answers it again without a
//! second run; the worker forgets a ticket's answers when it recycles the ticket ([`forget`]).

use std::collections::HashMap;
use std::mem::size_of;
use std::net::IpAddr;
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use busbar_contract::abi::host::conn::connector::{
    service, ConnectorSlots, EstablishIn, FactsIn, IdentityIn, IoIn, ProcessIdentity, RandomIn,
    ReplyIn, ReplyPiece, RequestIn, RequestPiece, StreamFacts, StreamIn, UpgradeIn, REPLY_ACK,
    REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_BODY, REQUEST_END, REQUEST_HEAD, SERVICES,
    WITHIN_SEPARATOR,
};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket};
use busbar_contract::abi::transport::{fields, FrameSpan};
use busbar_contract::conn::{
    ConnError, ConnId, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind,
};

use super::ticket::InstanceWake;

/// The table an instance with a declared need is handed.
pub static CONN_SLOTS: ConnectorSlots = ConnectorSlots {
    size: size_of::<ConnectorSlots>() as u32,
    slots: SERVICES,
    establish: Some(establish),
    reject_endpoint: None,
    side_stream: None,
    read: Some(read),
    write: Some(write),
    upgrade_secure: Some(upgrade_secure),
    facts: Some(facts),
    checkout: None,
    checkin: None,
    close: Some(close),
    random: Some(random),
    identity: Some(identity),
    read_reply: Some(read_reply),
    write_request: Some(write_request),
};

/// A mechanism ticket as the connection table's wake number ([`busbar_contract::conn::Ticket`]):
/// [`Ticket::NONE`] is `0`, which registers nothing.
#[must_use]
pub const fn conn_ticket(t: Ticket) -> u64 {
    ((t.slot as u64) << 32) | t.generation as u64
}

/// The mechanism ticket a connection table's wake number names ([`conn_ticket`]'s inverse).
#[must_use]
pub const fn ticket_of(n: u64) -> Ticket {
    Ticket {
        slot: (n >> 32) as u32,
        generation: n as u32,
    }
}

/// One slot's answer, before it is written into the caller's `out`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Answer {
    outcome: Outcome,
    value: u64,
    len: u64,
    error: &'static str,
}

impl Answer {
    const fn ready(value: u64, len: u64) -> Self {
        Self {
            outcome: Outcome::Ready,
            value,
            len,
            error: "",
        }
    }

    const fn with(outcome: Outcome, error: &'static str) -> Self {
        Self {
            outcome,
            value: 0,
            len: 0,
            error,
        }
    }

    /// A connection table's refusal, as the plugin reads it.
    const fn of(e: ConnError) -> Self {
        let outcome = match e {
            ConnError::Pending => Outcome::Pending,
            ConnError::Timeout | ConnError::Closed | ConnError::Fault => Outcome::Failed,
            ConnError::NotOwner
            | ConnError::UndeclaredNeed
            | ConnError::Refused
            | ConnError::Unarmed => Outcome::Refused,
        };
        Self::with(outcome, e.text())
    }
}

/// The instance a context names, and its connection table.
pub(crate) fn armed(ctx: HostCtx) -> Option<&'static (InstanceId, Arc<dyn DeclaredConns>)> {
    if ctx.ptr.is_null() {
        return None;
    }
    // SAFETY: every `HostCtx` the host hands out points to a leaked `InstanceWake`.
    let wake: &'static InstanceWake = unsafe { &*ctx.ptr.cast_const().cast::<InstanceWake>() };
    wake.conn.get()
}

/// ONE SLOT'S FRAME: the `in` and `out` are there and the head is this service's and covers its
/// `in`, then `body` with the caller's identity and table. A panic answers FAULT; the whole `out`
/// is written.
fn slot(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    in_size: usize,
    body: impl FnOnce(InstanceId, &Arc<dyn DeclaredConns>, ServiceHead) -> Answer,
) -> RawOutcome {
    let a = catch_unwind(AssertUnwindSafe(|| {
        if input.is_null() || out.is_null() {
            return Answer::with(Outcome::Fault, "");
        }
        // SAFETY: a non-NULL `in` leads with its head (the call shape).
        let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
        if head.op != service || (head.size as usize) < in_size {
            return Answer::with(Outcome::Fault, "");
        }
        match armed(ctx) {
            Some((id, table)) => kept(*id, head.handle, || body(*id, table, head)),
            None => Answer::of(ConnError::Unarmed),
        }
    }))
    .unwrap_or_else(|_| Answer::with(Outcome::Fault, ""));
    if !out.is_null() {
        let o = ServiceOut {
            size: size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(a.outcome),
            _reserved: [0; 3],
            value: a.value,
            len: a.len,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: AbiStr {
                ptr: if a.error.is_empty() {
                    std::ptr::null()
                } else {
                    a.error.as_ptr()
                },
                len: a.error.len(),
            },
        };
        // SAFETY: the caller's `out`, checked non-NULL.
        unsafe { out.write_unaligned(o) };
    }
    RawOutcome::of(a.outcome)
}

/// The caller's bytes (`len` of them at `ptr`), or `None` for a length behind NULL.
///
/// # Safety
/// A non-NULL `ptr` names `len` live bytes for the call.
unsafe fn bytes<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    match (ptr.is_null(), len) {
        (_, 0) => Some(&mut []),
        (true, _) => None,
        // SAFETY: the caller's contract.
        (false, n) => Some(unsafe { std::slice::from_raw_parts_mut(ptr, n) }),
    }
}

extern "C" fn establish(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::ESTABLISH,
        size_of::<EstablishIn>(),
        |id, table, _| {
            // SAFETY: the head covered an `EstablishIn`.
            let i = unsafe { input.cast::<EstablishIn>().read_unaligned() };
            // SAFETY: a checked range of the caller's, live for the call.
            let Some(target) = (unsafe { bytes(i.target.ptr.cast_mut(), i.target.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            let target = String::from_utf8_lossy(target);
            // SAFETY: a checked range of the caller's, live for the call.
            let Some(within) = (unsafe { bytes(i.within.ptr.cast_mut(), i.within.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            let Some(within) = addresses(within) else {
                return Answer::with(
                    Outcome::Refused,
                    "an address the dial must land on is not an IP literal",
                );
            };
            if table.framed(id, NeedId(i.need)) {
                // A FRAMED need opens when its request is whole (`WRITE_REQUEST`'s end): its
                // request is the connection's opening message.
                let stream = held_id();
                held_conns().insert(
                    (id, stream),
                    Stream {
                        conn: Conn::Held {
                            need: NeedId(i.need),
                            target: target.into_owned(),
                            within,
                            head: None,
                            body: Vec::new(),
                        },
                        headed: false,
                        ended: false,
                    },
                );
                return Answer::ready(stream, 0);
            }
            let desc = OpenDesc {
                target: &target,
                within: &within,
                ..OpenDesc::default()
            };
            match table.open(id, NeedId(i.need), &desc) {
                Ok(ConnId(stream)) => Answer::ready(stream, 0),
                Err(e) => Answer::of(e),
            }
        },
    )
}

/// `EstablishIn::within`'s address set: IP literals joined by [`WITHIN_SEPARATOR`], empty = none;
/// `None` when an entry is not text or not an IP literal.
fn addresses(within: &[u8]) -> Option<Vec<IpAddr>> {
    let text = std::str::from_utf8(within).ok()?;
    if text.is_empty() {
        return Some(Vec::new());
    }
    text.split(WITHIN_SEPARATOR)
        .map(|a| a.trim().parse().ok())
        .collect()
}

extern "C" fn read(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::READ,
        size_of::<IoIn>(),
        |id, table, head| {
            // SAFETY: the head covered an `IoIn`.
            let i = unsafe { input.cast::<IoIn>().read_unaligned() };
            // SAFETY: the caller's buffer, live until the service completes.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            let ticket = conn_ticket(head.handle.ticket);
            let conn = match resolve(id, table, i.stream) {
                Ok(c) => c,
                Err(e) => return Answer::of(e),
            };
            match table.read(id, conn, ticket, buf) {
                Ok(piece) => Answer::ready(0, piece.len as u64),
                Err(ConnError::Closed) => Answer::ready(0, 0),
                Err(ConnError::Pending) if head.handle.ticket.is_none() => Answer::with(
                    Outcome::Refused,
                    "a read that would pend is callable only inside a ticketed op",
                ),
                Err(e) => Answer::of(e),
            }
        },
    )
}

extern "C" fn write(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::WRITE,
        size_of::<IoIn>(),
        |id, table, _| {
            // SAFETY: the head covered an `IoIn`.
            let i = unsafe { input.cast::<IoIn>().read_unaligned() };
            // SAFETY: the caller's bytes, live until the service completes.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            let conn = match resolve(id, table, i.stream) {
                Ok(c) => c,
                Err(e) => return Answer::of(e),
            };
            match table.write(id, conn, buf, false) {
                Ok(n) => Answer::ready(0, n as u64),
                Err(e) => Answer::of(e),
            }
        },
    )
}

extern "C" fn close(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::CLOSE,
        size_of::<StreamIn>(),
        |id, table, _| {
            // SAFETY: the head covered a `StreamIn`.
            let i = unsafe { input.cast::<StreamIn>().read_unaligned() };
            held_facts().remove(&(id, i.stream));
            let held = held_conns().remove(&(id, i.stream));
            let conn = match held.map(|s| s.conn) {
                // Never opened, or refused: nothing on the table to close.
                Some(Conn::Held { .. } | Conn::Failed(_)) => return Answer::ready(0, 0),
                Some(Conn::Open(c)) => c,
                None if i.stream & HELD != 0 => return Answer::of(ConnError::Closed),
                None => ConnId(i.stream),
            };
            match table.close(id, conn) {
                Ok(()) => Answer::ready(0, 0),
                Err(e) => Answer::of(e),
            }
        },
    )
}

/// An optional text the caller handed: `Ok(None)` when absent or empty, `Err` when it is not text.
///
/// # Safety
/// A non-NULL `s.ptr` names `s.len` live bytes for the call.
unsafe fn optional_text<'a>(s: AbiStr) -> Result<Option<&'a str>, ()> {
    if s.ptr.is_null() || s.len == 0 {
        return Ok(None);
    }
    // SAFETY: the caller's contract.
    let b = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
    std::str::from_utf8(b).map(Some).map_err(|_| ())
}

extern "C" fn upgrade_secure(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::UPGRADE_SECURE,
        size_of::<UpgradeIn>(),
        |id, table, head| {
            // SAFETY: the head covered an `UpgradeIn`.
            let i = unsafe { input.cast::<UpgradeIn>().read_unaligned() };
            // SAFETY: the caller's strings, live for the call.
            let (Ok(name), Ok(trust)) = (unsafe { optional_text(i.offered_name) }, unsafe {
                optional_text(i.trust)
            }) else {
                return Answer::with(Outcome::Fault, "");
            };
            if i.stream & HELD != 0 {
                return Answer::with(
                    Outcome::Refused,
                    "a framed stream is secured by its need, never upgraded",
                );
            }
            let ticket = conn_ticket(head.handle.ticket);
            match table.upgrade_secure(id, ConnId(i.stream), name, trust, ticket) {
                Ok(()) => Answer::ready(0, 0),
                Err(ConnError::Pending) if head.handle.ticket.is_none() => Answer::with(
                    Outcome::Refused,
                    "an upgrade that would pend is callable only inside a ticketed op",
                ),
                Err(e) => Answer::of(e),
            }
        },
    )
}

/// The facts strings each stream was answered, held until it closes (`FactsIn::facts`: "the
/// strings stay valid until the stream closes"): a later answer that differs is added, never put
/// in an earlier one's place.
type HeldFacts = HashMap<(InstanceId, u64), Vec<Box<str>>>;

fn held_facts() -> MutexGuard<'static, HeldFacts> {
    static HELD_FACTS: OnceLock<Mutex<HeldFacts>> = OnceLock::new();
    HELD_FACTS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `text`, held for `stream` until it closes, as the caller reads it.
fn held_text(all: &mut HeldFacts, key: (InstanceId, u64), text: Option<&str>) -> AbiStr {
    let Some(text) = text else {
        return AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        };
    };
    let kept = all.entry(key).or_default();
    if !kept.iter().any(|k| &**k == text) {
        kept.push(text.into());
    }
    let k = kept.iter().find(|k| &***k == text).expect("just kept");
    AbiStr {
        ptr: k.as_ptr(),
        len: k.len(),
    }
}

extern "C" fn facts(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::FACTS,
        size_of::<FactsIn>(),
        |id, table, _| {
            // SAFETY: the head covered a `FactsIn`.
            let i = unsafe { input.cast::<FactsIn>().read_unaligned() };
            if i.facts.is_null() {
                return Answer::with(Outcome::Fault, "");
            }
            let conn = match resolve(id, table, i.stream) {
                Ok(c) => c,
                Err(e) => return Answer::of(e),
            };
            let f = match table.facts(id, conn) {
                Ok(f) => f,
                Err(e) => return Answer::of(e),
            };
            let hash = f.peer_cert.as_ref().map(|c| c.fingerprint.as_str());
            let mut all = held_facts();
            let key = (id, i.stream);
            let written = StreamFacts {
                size: size_of::<StreamFacts>() as u32,
                secure: u32::from(hash.is_some()),
                endpoint: held_text(&mut all, key, None),
                agreed_protocol: held_text(&mut all, key, f.alpn.as_deref()),
                peer_cert_hash: held_text(&mut all, key, hash),
            };
            // SAFETY: the caller's `facts`, checked non-NULL, live for the call.
            unsafe { i.facts.write_unaligned(written) };
            Answer::ready(0, 0)
        },
    )
}

// ── THE REPLAY RULE ─────────────────────────────────────────────────────────────────────────────

/// Every ticketed service's answer, by instance and ticket, then by the handle's issue order.
type Kept = HashMap<(InstanceId, Ticket), HashMap<u32, Answer>>;

fn kept_answers() -> MutexGuard<'static, Kept> {
    static KEPT: OnceLock<Mutex<Kept>> = OnceLock::new();
    KEPT.get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `run` once per completion handle: a handle that already answered (anything but PENDING)
/// answers the same again, and `run` is not made a second time. A call on no ticket is never
/// kept: it may not pend, and every call is its own.
fn kept(id: InstanceId, h: CompletionHandle, run: impl FnOnce() -> Answer) -> Answer {
    if h.ticket.is_none() {
        return run();
    }
    if let Some(a) = kept_answers()
        .get(&(id, h.ticket))
        .and_then(|issued| issued.get(&h.seq))
    {
        return *a;
    }
    let a = run();
    if a.outcome != Outcome::Pending {
        kept_answers()
            .entry((id, h.ticket))
            .or_default()
            .insert(h.seq, a);
    }
    a
}

/// Forget every answer instance `id` kept under `ticket`: its worker recycled it. Keyed by the
/// instance as well as the ticket: tickets are minted per dispatcher, so another dispatcher's
/// instance may hold an identical ticket, and its kept answers are never its neighbour's to drop
/// (dropping them would make it run a stored establish or write a second time).
pub(crate) fn forget(id: InstanceId, ticket: Ticket) {
    kept_answers().remove(&(id, ticket));
}

/// Forget every answer the instances `ids` kept under worker `worker`'s tickets: it was replaced.
/// Another dispatcher's worker of the same index is not touched.
pub(crate) fn forget_worker(ids: &[InstanceId], worker: u32) {
    kept_answers()
        .retain(|(id, t), _| !(ids.contains(id) && super::ticket::decode(t.slot).0 == worker));
}

// ── FRAMED REQUESTS AND REPLIES ──────────────────────────────────────────────────────────────────

/// The bit a stream the host holds unopened carries (a connection table's ids never set it).
const HELD: u64 = 1 << 63;

/// The most a held request's body may reach before its write is refused.
pub const REQUEST_HELD_MAX: usize = 16 * 1024 * 1024;

/// A request's head, held until its end.
#[derive(Debug, Clone)]
struct Head {
    method: Vec<u8>,
    target: Vec<u8>,
    fields: Vec<(String, Vec<u8>)>,
    timeout_ms: u64,
}

/// Where a stream is.
#[derive(Debug)]
enum Conn {
    /// A framed stream ESTABLISH answered before its request is whole: the need, the target named
    /// at ESTABLISH (empty = the need's own), the address set its dial must land on, and the
    /// request so far.
    Held {
        need: NeedId,
        target: String,
        within: Vec<IpAddr>,
        head: Option<Head>,
        body: Vec<u8>,
    },
    /// Open on the connection table.
    Open(ConnId),
    /// Its open was refused or failed: the reply's failed ack.
    Failed(ConnError),
}

/// What the host keeps for one stream an instance holds.
#[derive(Debug)]
struct Stream {
    conn: Conn,
    /// The reply's head was read.
    headed: bool,
    /// The reply's terminal piece was read.
    ended: bool,
}

type HeldConns = HashMap<(InstanceId, u64), Stream>;

fn held_conns() -> MutexGuard<'static, HeldConns> {
    static HELD_CONNS: OnceLock<Mutex<HeldConns>> = OnceLock::new();
    HELD_CONNS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A new held stream's id.
fn held_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    HELD | NEXT.fetch_add(1, Ordering::Relaxed)
}

/// The connection `stream` names: a table id as it is, a held stream's once open. A held stream
/// whose request was never written is opened as it was named, raw (a WRITE or READ on a framed
/// stream).
fn resolve(
    id: InstanceId,
    table: &Arc<dyn DeclaredConns>,
    stream: u64,
) -> Result<ConnId, ConnError> {
    if stream & HELD == 0 {
        return Ok(ConnId(stream));
    }
    let mut all = held_conns();
    let s = all.get_mut(&(id, stream)).ok_or(ConnError::Closed)?;
    match &s.conn {
        Conn::Open(c) => Ok(*c),
        Conn::Failed(e) => Err(*e),
        Conn::Held { head: Some(_), .. } => Err(ConnError::Refused),
        Conn::Held {
            need,
            target,
            within,
            ..
        } => {
            let desc = OpenDesc {
                target,
                within,
                ..OpenDesc::default()
            };
            let opened = table.open(id, *need, &desc);
            s.conn = opened.map_or_else(Conn::Failed, Conn::Open);
            opened
        }
    }
}

/// A field block's fields, owned; a name that is not text, or a pseudo-field, refuses the block.
fn field_lines(block: &[u8]) -> Result<Vec<(String, Vec<u8>)>, Answer> {
    fields::lines(block)
        .map(|(name, value)| {
            if name.first() == Some(&b':') {
                return Err(Answer::with(
                    Outcome::Refused,
                    "a request field is a pseudo-field; the framer names its own head",
                ));
            }
            let name = std::str::from_utf8(name).map_err(|_| Answer::with(Outcome::Fault, ""))?;
            Ok((name.to_owned(), value.to_vec()))
        })
        .collect()
}

/// The bytes `span` names in `bytes`, or `None` past their end.
fn spanned(bytes: &[u8], span: FrameSpan) -> Option<&[u8]> {
    let at = usize::try_from(span.offset).ok()?;
    let len = usize::try_from(span.len).ok()?;
    bytes.get(at..at.checked_add(len)?)
}

extern "C" fn write_request(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::WRITE_REQUEST,
        size_of::<RequestIn>(),
        |id, table, _| {
            // SAFETY: the head covered a `RequestIn`.
            let i = unsafe { input.cast::<RequestIn>().read_unaligned() };
            if i.piece.is_null() {
                return Answer::with(Outcome::Fault, "");
            }
            // SAFETY: the caller's descriptor, checked non-NULL, live until the service completes.
            let piece: RequestPiece = unsafe { i.piece.read_unaligned() };
            // SAFETY: the caller's bytes, live until the service completes.
            let Some(bytes) = (unsafe { bytes(i.buf.cast_mut(), i.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            let mut all = held_conns();
            let Some(s) = all.get_mut(&(id, i.stream)) else {
                return Answer::with(
                    Outcome::Refused,
                    "the stream is not a framed request being written; write its bytes",
                );
            };
            let Conn::Held {
                need,
                target,
                within,
                head,
                body,
            } = &mut s.conn
            else {
                return Answer::with(
                    Outcome::Refused,
                    "the stream is not a framed request being written; write its bytes",
                );
            };
            match (piece.kind, head.is_some()) {
                (REQUEST_HEAD, false) => {
                    let (Some(method), Some(words), Some(block)) = (
                        spanned(bytes, piece.method),
                        spanned(bytes, piece.target),
                        spanned(bytes, piece.fields),
                    ) else {
                        return Answer::with(Outcome::Fault, "");
                    };
                    let lines = match field_lines(block) {
                        Ok(l) => l,
                        Err(refused) => return refused,
                    };
                    *head = Some(Head {
                        method: method.to_vec(),
                        target: words.to_vec(),
                        fields: lines,
                        timeout_ms: piece.timeout_ms,
                    });
                    Answer::ready(0, bytes.len() as u64)
                }
                (REQUEST_BODY, true) => {
                    if body.len() + bytes.len() > REQUEST_HELD_MAX {
                        return Answer::with(
                            Outcome::Refused,
                            "the request body passed the host's bound",
                        );
                    }
                    body.extend_from_slice(bytes);
                    Answer::ready(0, bytes.len() as u64)
                }
                (REQUEST_END, true) => {
                    let Some(h) = head.take() else {
                        return Answer::with(Outcome::Fault, "");
                    };
                    let fields: Vec<(&str, &[u8])> = h
                        .fields
                        .iter()
                        .map(|(n, v)| (n.as_str(), v.as_slice()))
                        .collect();
                    let desc = OpenDesc {
                        target: target.as_str(),
                        fields: &fields,
                        body: body.as_slice(),
                        timeout_ms: h.timeout_ms,
                        method: &h.method,
                        head_target: &h.target,
                        within,
                    };
                    // The request is handed over whole; what became of it is the reply's to say.
                    let opened = table.open(id, *need, &desc);
                    s.conn = opened.map_or_else(Conn::Failed, Conn::Open);
                    Answer::ready(0, 0)
                }
                (REQUEST_HEAD, true) => {
                    Answer::with(Outcome::Refused, "the request's head was already written")
                }
                (REQUEST_BODY | REQUEST_END, false) => Answer::with(
                    Outcome::Refused,
                    "a request's head is written before its body and its end",
                ),
                _ => Answer::with(Outcome::Fault, ""),
            }
        },
    )
}

extern "C" fn read_reply(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::READ_REPLY,
        size_of::<ReplyIn>(),
        |id, table, head| {
            // SAFETY: the head covered a `ReplyIn`.
            let i = unsafe { input.cast::<ReplyIn>().read_unaligned() };
            if i.piece.is_null() {
                return Answer::with(Outcome::Fault, "");
            }
            // SAFETY: the caller's buffer, live until the service completes.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            let (piece, answer) = reply(id, table, head, i.stream, buf);
            if let Some(p) = piece {
                // SAFETY: the caller's descriptor slot, checked non-NULL.
                unsafe { i.piece.write_unaligned(p) };
            }
            answer
        },
    )
}

/// The next piece of the reply on `stream`, read into `buf`: its descriptor (none for an answer
/// without one) and the answer.
fn reply(
    id: InstanceId,
    table: &Arc<dyn DeclaredConns>,
    head: ServiceHead,
    stream: u64,
    buf: &mut [u8],
) -> (Option<ReplyPiece>, Answer) {
    {
        let mut all = held_conns();
        let s = all.entry((id, stream)).or_insert(Stream {
            conn: Conn::Open(ConnId(stream)),
            headed: false,
            ended: false,
        });
        if s.ended {
            return (None, Answer::of(ConnError::Closed));
        }
        match &s.conn {
            Conn::Held { .. } => {
                return (
                    None,
                    Answer::with(Outcome::Refused, "the request is not whole: write its end"),
                )
            }
            Conn::Failed(e) => {
                // THE FAILED ACK: the stream's refusal, with its text, and the reply has ended.
                let e = *e;
                s.ended = true;
                return (None, Answer::of(e));
            }
            Conn::Open(_) => {}
        }
    }
    let conn = match resolve(id, table, stream) {
        Ok(c) => c,
        Err(e) => return (None, Answer::of(e)),
    };
    let ticket = conn_ticket(head.handle.ticket);
    loop {
        let got = table.read(id, conn, ticket, buf);
        let mut all = held_conns();
        let Some(s) = all.get_mut(&(id, stream)) else {
            return (None, Answer::of(ConnError::Closed));
        };
        let terminal = |s: &mut Stream| {
            s.ended = true;
            let kind = if s.headed { REPLY_END } else { REPLY_ACK };
            (
                Some(ReplyPiece {
                    kind,
                    ..ReplyPiece::default()
                }),
                Answer::ready(0, 0),
            )
        };
        return match got {
            Ok(p) => match p.kind {
                PieceKind::Fields if s.headed && p.len > 0 => {
                    // The far end's trailers: not handed up (1.5.5 dropped them); read on.
                    drop(all);
                    continue;
                }
                PieceKind::Fields => {
                    s.headed = true;
                    let reason = p.reason.clone().unwrap_or(p.len..p.len);
                    (
                        Some(ReplyPiece {
                            kind: REPLY_HEAD,
                            code: p.status_code.unwrap_or(0),
                            reason: FrameSpan {
                                offset: reason.start as u64,
                                len: (reason.end - reason.start) as u64,
                            },
                            fields: FrameSpan {
                                offset: 0,
                                len: p.len as u64,
                            },
                        }),
                        Answer::ready(0, reason.end.max(p.len) as u64),
                    )
                }
                PieceKind::Body | PieceKind::HookReply => (
                    Some(ReplyPiece {
                        kind: REPLY_BODY,
                        ..ReplyPiece::default()
                    }),
                    Answer::ready(0, p.len as u64),
                ),
                PieceKind::Completion => terminal(s),
            },
            Err(ConnError::Closed) => terminal(s),
            Err(ConnError::Pending) if head.handle.ticket.is_none() => (
                None,
                Answer::with(
                    Outcome::Refused,
                    "a read that would pend is callable only inside a ticketed op",
                ),
            ),
            Err(ConnError::Pending) => (None, Answer::of(ConnError::Pending)),
            Err(e) => {
                // A refusal or failure mid-reply is its failed ack.
                s.ended = true;
                (None, Answer::of(e))
            }
        };
    }
}

extern "C" fn random(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::RANDOM,
        size_of::<RandomIn>(),
        |_, _, _| {
            // SAFETY: the head covered a `RandomIn`.
            let i = unsafe { input.cast::<RandomIn>().read_unaligned() };
            // SAFETY: the caller's buffer, live for the call.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            match getrandom::fill(buf) {
                Ok(()) => Answer::ready(0, i.len as u64),
                Err(_) => Answer::with(Outcome::Failed, "the host has no randomness"),
            }
        },
    )
}

/// The process's OS user and program name, read once and held for the process's life.
fn process() -> &'static (String, String) {
    static ONE: OnceLock<(String, String)> = OnceLock::new();
    ONE.get_or_init(|| {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_default();
        let program = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();
        (user, program)
    })
}

fn abi(s: &'static str) -> AbiStr {
    AbiStr {
        ptr: if s.is_empty() {
            std::ptr::null()
        } else {
            s.as_ptr()
        },
        len: s.len(),
    }
}

extern "C" fn identity(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::IDENTITY,
        size_of::<IdentityIn>(),
        |_, _, _| {
            // SAFETY: the head covered an `IdentityIn`.
            let i = unsafe { input.cast::<IdentityIn>().read_unaligned() };
            if i.identity.is_null() {
                return Answer::with(Outcome::Fault, "");
            }
            let (user, program) = process();
            // SAFETY: the caller's identity slot, checked non-NULL.
            unsafe {
                i.identity.write_unaligned(ProcessIdentity {
                    size: size_of::<ProcessIdentity>() as u32,
                    _reserved: 0,
                    pid: u64::from(std::process::id()),
                    os_user: abi(user),
                    program: abi(program),
                });
            }
            Answer::ready(0, 0)
        },
    )
}

#[cfg(test)]
#[path = "../tests/conn_services_tests.rs"]
mod tests;
