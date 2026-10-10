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
//! * `IDENTITY` names the process, written afresh on every call (a replayed handle included: it
//!   writes the caller's memory, so its answer is never kept). `RANDOM` is RETIRED and served by
//!   no host: `random.fill`, a host service, is the one random service.
//! * `FACTS` answers what the stream's connection security established, as the connector observed
//!   it: the agreed protocol, the far end's key pin and whether busbar presented its client identity
//!   (the transport pin, ARCHITECT 2026-10-03) — a stream whose connection the connector refused for its
//!   trust anchors included, so a plugin reads the key the far end served. Its strings are held with
//!   the stream until it closes.
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
//! second run; the worker forgets a ticket's answers when it recycles the ticket, a driver
//! ticket's when its next tick starts, and any other ticket's when a new op (not a short answer's
//! re-call) starts on it ([`forget`]).

use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::net::IpAddr;
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use busbar_contract::abi::host::conn::connector::{
    service, ConnectorSlots, EstablishIn, FactsIn, IdentityIn, IoIn, ProcessIdentity, ReplyIn,
    ReplyPiece, RequestIn, RequestPiece, StreamFacts, StreamIn, UpgradeIn, REPLY_ACK, REPLY_BODY,
    REPLY_END, REPLY_HEAD, REQUEST_BODY, REQUEST_END, REQUEST_HEAD, SERVICES, UPGRADE_IN_V1_SIZE,
    UPGRADE_VERIFY_OFF, WITHIN_SEPARATOR,
};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket};
use busbar_contract::abi::transport::{fields, FrameSpan};
use busbar_contract::auth_calls::{Fields, FieldsRequest};
use busbar_contract::conn::{
    ConnError, ConnId, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind,
};
use std::future::Future as _;

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
    // RETIRED: `random.fill` (the host services' table) is the one random service.
    random: None,
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

    /// A connection table's refusal of `conn`, naming why the connection failed where the table
    /// names a cause: its `CAUSE_*` stage in `value`, the underlying error's own text in `error`.
    fn of_conn(e: ConnError, id: InstanceId, table: &Arc<dyn DeclaredConns>, conn: ConnId) -> Self {
        let plain = Self::of(e);
        if matches!(e, ConnError::Pending) {
            return plain;
        }
        match table.cause(id, conn) {
            Some(c) => Self {
                value: c.stage,
                error: match interned(&c.text) {
                    "" => plain.error,
                    text => text,
                },
                ..plain
            },
            None => plain,
        }
    }
}

/// The most distinct cause texts the slots keep (each lives for the process, as `ServiceOut::error`
/// must); past it a failure names its table's refusal text instead.
const CAUSE_TEXTS_MAX: usize = 1024;

/// `text`, kept for the process's life (one copy per distinct text, at most [`CAUSE_TEXTS_MAX`]);
/// `""` once that many are kept.
fn interned(text: &str) -> &'static str {
    static KEPT: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    if text.is_empty() {
        return "";
    }
    let mut kept = KEPT
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(t) = kept.get(text) {
        return t;
    }
    if kept.len() >= CAUSE_TEXTS_MAX {
        return "";
    }
    let t: &'static str = Box::leak(text.to_owned().into_boxed_str());
    kept.insert(t);
    t
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
            // A never-pend service that writes the caller's memory is run afresh on a replay: a
            // kept answer would say the bytes were written into memory this call never touched.
            Some((id, table)) if service == service::IDENTITY => body(*id, table, head),
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

/// How much of an [`EstablishIn`] a caller must state: everything before the appended
/// [`EstablishIn::member`], which a shorter one states as none.
const ESTABLISH_IN_MEMBERLESS: usize = std::mem::offset_of!(EstablishIn, member);

/// The caller's `EstablishIn`, as much of it as its head's `size` states: one that ends before the
/// appended `member` names none.
///
/// # Safety
/// `input` names an `EstablishIn` whose head was checked to state at least
/// [`ESTABLISH_IN_MEMBERLESS`] bytes, live for the call.
unsafe fn read_establish(input: *const c_void) -> EstablishIn {
    // SAFETY: the head is the struct's first field, covered by the checked size.
    let size = unsafe { input.cast::<ServiceHead>().read_unaligned() }.size as usize;
    // SAFETY: a plain repr(C) value of integers and pointer/length pairs: all-zero is every field
    // absent (a NULL string of length 0).
    let mut i: EstablishIn = unsafe { std::mem::zeroed() };
    let n = size.min(size_of::<EstablishIn>());
    // SAFETY: `n` bytes of the caller's, into a plain repr(C) value of at least `n` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            input.cast::<u8>(),
            std::ptr::from_mut(&mut i).cast::<u8>(),
            n,
        );
    }
    i
}

extern "C" fn establish(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::ESTABLISH,
        ESTABLISH_IN_MEMBERLESS,
        |id, table, _| {
            // SAFETY: the head covered an `EstablishIn` up to its appended `member`; one whose
            // `size` stops there names no registration.
            let i = unsafe { read_establish(input) };
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
            // SAFETY: a checked range of the caller's, live for the call.
            let Some(member) = (unsafe { bytes(i.member.ptr.cast_mut(), i.member.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            let member = String::from_utf8_lossy(member).into_owned();
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
                            member,
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
                timeout_ms: u64::from(i.timeout_ms),
                member: &member,
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
            // SAFETY: the caller's buffer, lent for this call only: the host keeps no hold on it
            // past the call, a PENDING answer included.
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
                Err(e) => Answer::of_conn(e, id, table, conn),
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
            // SAFETY: the caller's bytes, lent for this call only: the host keeps no hold on it
            // past the call, a PENDING answer included.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            let conn = match resolve(id, table, i.stream) {
                Ok(c) => c,
                Err(e) => return Answer::of(e),
            };
            match table.write(id, conn, buf, false, false) {
                Ok(n) => Answer::ready(0, n as u64),
                Err(e) => Answer::of_conn(e, id, table, conn),
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
                // (A request waiting on its auth call drops the call: a client drop.)
                // (A stream being opened outside the lock is closed by the call that opens it.)
                Some(Conn::Held { .. } | Conn::Failed(_) | Conn::Authing(_) | Conn::Opening) => {
                    return Answer::ready(0, 0)
                }
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
        UPGRADE_IN_V1_SIZE,
        |id, table, head| {
            // An `in` from before `flags` reads them as 0: only the bytes the head states are read.
            // SAFETY: an all-zero `UpgradeIn` is a valid value (NULL strings, no flags).
            let mut i: UpgradeIn = unsafe { std::mem::zeroed() };
            let given = (head.size as usize).min(size_of::<UpgradeIn>());
            // SAFETY: the head covered at least `UPGRADE_IN_V1_SIZE` bytes, and states `given`.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    input.cast::<u8>(),
                    std::ptr::from_mut(&mut i).cast::<u8>(),
                    given,
                );
            }
            let verify_off = i.flags & UPGRADE_VERIFY_OFF != 0;
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
            match table.upgrade_secure(id, ConnId(i.stream), name, trust, verify_off, ticket) {
                Ok(()) => {
                    if verify_off {
                        warn_unverified(ctx);
                    }
                    Answer::ready(0, 0)
                }
                Err(ConnError::Pending) if head.handle.ticket.is_none() => Answer::with(
                    Outcome::Refused,
                    "an upgrade that would pend is callable only inside a ticketed op",
                ),
                Err(e) => Answer::of(e),
            }
        },
    )
}

/// The first unverified handshake an instance's connection ran (the operator's opt-in, ARCHITECT
/// ruling 2026-10-03 on Q-L16-4) is logged at WARN, naming the instance: once per instance.
fn warn_unverified(ctx: HostCtx) {
    static WARNED: OnceLock<Mutex<std::collections::HashSet<usize>>> = OnceLock::new();
    if ctx.ptr.is_null() {
        return;
    }
    let first = WARNED
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(ctx.ptr as usize);
    if !first {
        return;
    }
    // SAFETY: every `HostCtx` the host hands out points to a leaked `InstanceWake`.
    let wake: &InstanceWake = unsafe { &*ctx.ptr.cast_const().cast::<InstanceWake>() };
    let instance = wake
        .caller
        .get()
        .map_or_else(|| "<unbound>".to_owned(), |c| c.instance.to_string());
    tracing::warn!(
        instance = %instance,
        "plugin instance '{instance}' secures a connection WITHOUT verifying the far end's certificate (operator opt-in, e.g. `#insecure`); its traffic can be intercepted"
    );
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
                peer_key_pin: held_text(&mut all, key, f.peer_key_pin.as_deref()),
                client_identity: u32::from(f.client_identity),
                _reserved: 0,
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

/// Forget every answer instance `id` kept under `ticket` (its worker recycled it, a driver
/// ticket's tick started, or a new op started on it); how many there were. Keyed by the instance as well as the ticket:
/// tickets are minted per dispatcher, so another dispatcher's instance may hold an identical
/// ticket, and its kept answers are never its neighbour's to drop (dropping them would make it run
/// a stored establish or write a second time).
pub(crate) fn forget(id: InstanceId, ticket: Ticket) -> usize {
    kept_answers()
        .remove(&(id, ticket))
        .map_or(0, |issued| issued.len())
}

/// Forget every answer the instances `ids` kept under worker `worker`'s tickets: it was replaced.
/// Another dispatcher's worker of the same index is not touched.
pub(crate) fn forget_worker(ids: &[InstanceId], worker: u32) {
    kept_answers()
        .retain(|(id, t), _| !(ids.contains(id) && super::ticket::decode(t.slot).0 == worker));
}

/// FORGET EVERYTHING instance `id` holds on the connector's process-wide maps — its held streams
/// and their facts, its kept answers — and close on `table` every connection a held stream had open.
/// Made when the instance can never cross again: the watchdog faulted it, or it is dropped (a
/// close, a reload). The maps are let go before anything is closed or dropped: a held stream's
/// pending auth call is the auth plugin's, and a close may cross into a transport door (THE DESIGN
/// §11.13 M1).
pub(crate) fn purge(id: InstanceId, table: &Arc<dyn DeclaredConns>) {
    held_facts().retain(|(i, _), _| *i != id);
    kept_answers().retain(|(i, _), _| *i != id);
    let gone: Vec<Stream> = {
        let mut all = held_conns();
        let keys: Vec<(InstanceId, u64)> = all.keys().filter(|(i, _)| *i == id).copied().collect();
        keys.iter().filter_map(|k| all.remove(k)).collect()
    };
    for s in gone {
        if let Conn::Open(c) = s.conn {
            let _ = table.close(id, c);
        }
    }
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
        /// The registration the stream names (`EstablishIn::member`); empty = none.
        member: String,
        head: Option<Head>,
        body: Vec<u8>,
    },
    /// Open on the connection table.
    Open(ConnId),
    /// Its open was refused or failed: the reply's failed ack.
    Failed(ConnError),
    /// The request is whole and its member's auth call is in flight: it opens when the fields
    /// answer (ARCHITECT round 5 Q-L3B-DOOR-EXCHANGE: the open calls the member binding's fields).
    Authing(Box<Authing>),
    /// One call has taken the stream out to open it, or to make or poll its member's auth call,
    /// OUTSIDE the connector's lock (THE DESIGN §11.13 M1: no plugin code runs under a host lock;
    /// the auth call is the auth plugin's, and an open may cross into a transport door). That call
    /// installs what it got ([`install`]); any other call on the stream meanwhile is refused.
    Opening,
}

/// A whole request waiting on its member binding's auth fields.
struct Authing {
    fielding: Box<dyn busbar_contract::auth_calls::Fielding>,
    need: NeedId,
    target: String,
    within: Vec<IpAddr>,
    member: String,
    head: Head,
    body: Vec<u8>,
}

impl std::fmt::Debug for Authing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authing")
            .field("need", &self.need)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
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

/// THE ONE LOCK over every instance's streams. Held only to read or swap a stream's state, never
/// across a call that can run plugin code: an auth plugin's `fields`, or a table open that may
/// cross into a transport door (THE DESIGN §11.13 M1). A wedged plugin would otherwise hold every
/// worker's connector I/O behind it, and a plugin that called back into the connector from inside
/// that call would relock it on its own thread.
fn held_conns_lock() -> &'static Mutex<HeldConns> {
    static HELD_CONNS: OnceLock<Mutex<HeldConns>> = OnceLock::new();
    HELD_CONNS.get_or_init(Mutex::default)
}

fn held_conns() -> MutexGuard<'static, HeldConns> {
    held_conns_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install `conn` on the stream a call took out to open ([`Conn::Opening`]), the lock re-taken
/// for the swap alone. A stream closed meanwhile is gone: what was opened for it is closed on the
/// table, and anything else it held (a pending auth call) is dropped, both after the lock is let
/// go.
fn install(id: InstanceId, stream: u64, table: &Arc<dyn DeclaredConns>, conn: Conn) {
    let orphan = {
        let mut all = held_conns();
        match all.get_mut(&(id, stream)) {
            Some(s) if matches!(s.conn, Conn::Opening) => {
                s.conn = conn;
                None
            }
            _ => Some(conn),
        }
    };
    if let Some(Conn::Open(c)) = orphan {
        let _ = table.close(id, c);
    }
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
    let (need, target, within, member) = {
        let mut all = held_conns();
        let s = all.get_mut(&(id, stream)).ok_or(ConnError::Closed)?;
        match &mut s.conn {
            Conn::Open(c) => return Ok(*c),
            Conn::Failed(e) => return Err(*e),
            Conn::Held { head: Some(_), .. } | Conn::Authing(_) | Conn::Opening => {
                return Err(ConnError::Refused)
            }
            Conn::Held {
                need,
                target,
                within,
                member,
                ..
            } => {
                let taken = (
                    *need,
                    std::mem::take(target),
                    std::mem::take(within),
                    std::mem::take(member),
                );
                s.conn = Conn::Opening;
                taken
            }
        }
    };
    // The open, outside the lock: it may cross into a transport door.
    let desc = OpenDesc {
        target: &target,
        within: &within,
        member: &member,
        ..OpenDesc::default()
    };
    let opened = table.open(id, need, &desc);
    install(
        id,
        stream,
        table,
        opened.map_or_else(Conn::Failed, Conn::Open),
    );
    opened
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
            // SAFETY: the caller's descriptor, checked non-NULL, lent for this call only: the host
            // keeps no hold on it past the call, a PENDING answer included.
            let piece: RequestPiece = unsafe { i.piece.read_unaligned() };
            // SAFETY: the caller's bytes, lent for this call only: the host keeps no hold on it
            // past the call, a PENDING answer included.
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
                member,
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
                    let Some(mut h) = head.take() else {
                        return Answer::with(Outcome::Fault, "");
                    };
                    // The request is whole: taken out of the map, so the member's auth call and
                    // the open run with the connector's lock let go (THE DESIGN §11.13 M1).
                    let need = *need;
                    let (target, within, member, body) = (
                        std::mem::take(target),
                        std::mem::take(within),
                        std::mem::take(member),
                        std::mem::take(body),
                    );
                    s.conn = Conn::Opening;
                    drop(all);
                    // THE PLUGIN'S STATED SCOPE is the host's own field
                    // (`abi::auth::SCOPE_REQUEST_FIELD`): out of the request before anything is
                    // encoded, lent to the member's auth call. No wire carries it.
                    let mut scope = None;
                    h.fields.retain(|(name, value)| {
                        if busbar_contract::abi::auth::is_scope_field(name.as_bytes()) {
                            scope.get_or_insert_with(|| value.clone());
                            false
                        } else {
                            true
                        }
                    });
                    let at = (target.as_str(), within.as_slice(), member.as_str());
                    // THE MEMBER'S BINDING (ARCHITECT round 5 Q-L3B-DOOR-EXCHANGE): a request to a
                    // member the connector holds a binding for carries that binding's auth fields,
                    // as the member's relayed calls do. The request is handed over whole; what
                    // became of it is the reply's to say.
                    let conn = match table.auth_of(id, need, &target) {
                        None => open_with(table, id, need, at, &h, &body, &[]),
                        Some(binding) => match auth_request(&binding, &h, &target, &body, scope) {
                            None => Conn::Failed(ConnError::Refused),
                            Some(request) => {
                                match binding.auth.fields_now(binding.handle, &request) {
                                    Some(Fields::Ready(auth)) => {
                                        open_with(table, id, need, at, &h, &body, &auth)
                                    }
                                    Some(Fields::Refused | Fields::Failed) => {
                                        Conn::Failed(ConnError::Refused)
                                    }
                                    None => Conn::Authing(Box::new(Authing {
                                        fielding: binding.auth.fields(binding.handle, request, 0),
                                        need,
                                        target,
                                        within,
                                        member,
                                        head: h,
                                        body,
                                    })),
                                }
                            }
                        },
                    };
                    install(id, i.stream, table, conn);
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

/// Open a whole request on the table: the member's `auth` fields first, then the plugin's (a
/// plugin field named like an auth field never doubles it: the binding's stands), 1.5.5's egress
/// order, as the relayed calls are opened.
#[allow(clippy::too_many_arguments)]
fn open_with(
    table: &Arc<dyn DeclaredConns>,
    id: InstanceId,
    need: NeedId,
    (target, within, member): (&str, &[IpAddr], &str),
    h: &Head,
    body: &[u8],
    auth: &[busbar_contract::auth_calls::AuthField],
) -> Conn {
    let mut fields: Vec<(&str, &[u8])> = Vec::with_capacity(auth.len() + h.fields.len());
    let names: Vec<String> = auth
        .iter()
        .map(|f| String::from_utf8_lossy(&f.name).into_owned())
        .collect();
    for (name, f) in names.iter().zip(auth) {
        fields.push((name.as_str(), f.value.expose_secret().as_slice()));
    }
    fields.extend(
        h.fields
            .iter()
            .filter(|(n, _)| !names.iter().any(|a| a.eq_ignore_ascii_case(n)))
            .map(|(n, v)| (n.as_str(), v.as_slice())),
    );
    let desc = OpenDesc {
        target,
        fields: &fields,
        body,
        timeout_ms: h.timeout_ms,
        method: &h.method,
        head_target: &h.target,
        within,
        member,
    };
    table
        .open(id, need, &desc)
        .map_or_else(Conn::Failed, Conn::Open)
}

/// The member binding's ONE auth call for a whole request to `target` (THE DESIGN, outbound auth: the facts at
/// the style's point; the request's head when the style reads it; its stated `scope` in the
/// extensions blob). A passthrough binding is lent the caller credential of the unit the crossing
/// serves (none presented: an empty one, so nothing is presented, never the operator's); a request
/// made inside no unit has no caller, and opens nothing (`None`): an operator's own fetch never
/// spends a caller's credential.
fn auth_request(
    binding: &busbar_contract::conn::ConnAuth,
    h: &Head,
    target: &str,
    body: &[u8],
    scope: Option<Vec<u8>>,
) -> Option<FieldsRequest> {
    use busbar_contract::abi::auth::{AuthPoint, STYLE_NEEDS_HEADERS};
    let caller_credential = if binding.passthrough {
        let unit = super::services::serving_unit()?;
        Some(
            binding
                .lender
                .as_ref()
                .and_then(|l| l.lent(unit))
                .unwrap_or_else(|| busbar_contract::redacted::Redacted::new(Vec::new())),
        )
    } else {
        None
    };
    let rest = target.split_once("://").map_or(target, |(_, r)| r);
    let (authority, path_query) = match rest.find(['/', '?']) {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (
            if p.is_empty() { "/" } else { p },
            Some(q.as_bytes().to_vec()),
        ),
        None => (path_query, None),
    };
    let point = if binding.points.has(AuthPoint::HeadBody) {
        AuthPoint::HeadBody
    } else {
        AuthPoint::Head
    };
    Some(FieldsRequest {
        point,
        unit: super::services::serving_unit().unwrap_or(0),
        body: (point == AuthPoint::HeadBody).then(|| body.to_vec()),
        method: h.method.clone(),
        authority: authority.to_string(),
        path: path.as_bytes().to_vec(),
        query,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        headers: if binding.style_flags & STYLE_NEEDS_HEADERS != 0 {
            h.fields
                .iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.clone()))
                .collect()
        } else {
            Vec::new()
        },
        caller_credential,
        extensions: busbar_contract::abi::auth::scope_extensions(scope.as_deref()),
        ..FieldsRequest::default()
    })
}

/// A waker that wakes `ticket` on the instance `ctx` names: a request waiting on its auth call is
/// read again when the call answers.
fn ticket_waker(ctx: HostCtx, ticket: Ticket) -> Option<std::task::Waker> {
    struct TicketWaker {
        route: std::sync::Weak<dyn super::ticket::WakeRoute>,
        ticket: Ticket,
    }
    impl std::task::Wake for TicketWaker {
        fn wake(self: Arc<Self>) {
            if let Some(route) = self.route.upgrade() {
                route.wake(self.ticket);
            }
        }
    }
    if ctx.ptr.is_null() || ticket.is_none() {
        return None;
    }
    // SAFETY: every `HostCtx` the host hands out points to a leaked `InstanceWake`.
    let wake: &'static InstanceWake = unsafe { &*ctx.ptr.cast_const().cast::<InstanceWake>() };
    let route = wake.route.get()?.clone();
    Some(std::task::Waker::from(Arc::new(TicketWaker {
        route,
        ticket,
    })))
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
            // SAFETY: the caller's buffer, lent for this call only: the host keeps no hold on it
            // past the call, a PENDING answer included.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            let (piece, answer) = reply(ctx, id, table, head, i.stream, buf);
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
    ctx: HostCtx,
    id: InstanceId,
    table: &Arc<dyn DeclaredConns>,
    head: ServiceHead,
    stream: u64,
    buf: &mut [u8],
) -> (Option<ReplyPiece>, Answer) {
    // A REQUEST WAITING ON ITS AUTH CALL opens when the call answers (its fields lead the head),
    // fails its ack when the call refuses or fails, and reads as nothing ready (on the caller's
    // ticket, woken when the call answers) until then. The call is taken out of the map to be
    // polled and opened with the connector's lock let go (THE DESIGN §11.13 M1).
    let waker = ticket_waker(ctx, head.handle.ticket);
    let authing = {
        let mut all = held_conns();
        match all.get_mut(&(id, stream)) {
            Some(s) if matches!(s.conn, Conn::Authing(_)) => {
                if waker.is_none() {
                    return (
                        None,
                        Answer::with(
                            Outcome::Refused,
                            "a read that would pend is callable only inside a ticketed op",
                        ),
                    );
                }
                match std::mem::replace(&mut s.conn, Conn::Opening) {
                    Conn::Authing(a) => Some(a),
                    _ => None,
                }
            }
            _ => None,
        }
    };
    if let (Some(mut a), Some(waker)) = (authing, waker) {
        let mut cx = std::task::Context::from_waker(&waker);
        let answered = match std::pin::Pin::new(&mut a.fielding).poll(&mut cx) {
            std::task::Poll::Pending => {
                install(id, stream, table, Conn::Authing(a));
                return (None, Answer::of(ConnError::Pending));
            }
            std::task::Poll::Ready(f) => f,
        };
        let opened = match answered {
            Fields::Ready(auth) => open_with(
                table,
                id,
                a.need,
                (&a.target, &a.within, &a.member),
                &a.head,
                &a.body,
                &auth,
            ),
            Fields::Refused | Fields::Failed => Conn::Failed(ConnError::Refused),
        };
        install(id, stream, table, opened);
    }
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
            Conn::Authing(_) => return (None, Answer::of(ConnError::Pending)),
            Conn::Opening => {
                return (
                    None,
                    Answer::with(
                        Outcome::Refused,
                        "another call on the stream is opening it; read when it answers",
                    ),
                )
            }
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
                // A refusal or failure mid-reply is its failed ack, naming why where it can.
                s.ended = true;
                drop(all);
                (None, Answer::of_conn(e, id, table, conn))
            }
        };
    }
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
