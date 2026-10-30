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
//!   written, a framed need's included (its connect is at `WRITE_REQUEST`'s end). A raw stream
//!   is answered once its dial has LANDED (PENDING on the caller's ticket while it connects): a
//!   refused connect is the establish's own answer, so a plugin's endpoint list moves on.
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
//! second run (a `READ_REPLY`'s with its piece and its bytes, written again into what the replay
//! lends); the worker forgets a ticket's answers when it recycles the ticket, a driver
//! ticket's when its next tick starts with nothing held on it (a held exchange keeps its
//! answers), and any other ticket's when a new op (not a short answer's
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
    ReplyPiece, RequestIn, RequestPiece, StreamFacts, StreamIn, UpgradeIn, CAUSE_AUTH_FAILED,
    CAUSE_AUTH_REFUSED, CAUSE_CREDENTIAL_UNAVAILABLE, CAUSE_NONE, REPLY_ACK, REPLY_BODY, REPLY_END,
    REPLY_HEAD, REQUEST_BODY, REQUEST_END, REQUEST_HEAD, SERVICES, UPGRADE_IN_V1_SIZE,
    UPGRADE_VERIFY_OFF, WITHIN_SEPARATOR,
};
use busbar_contract::abi::host::service::{lent_out, ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket};
use busbar_contract::abi::transport::{fields, FrameSpan};
use busbar_contract::auth_calls::{Fields, FieldsRequest};
use busbar_contract::conn::{
    ConnError, ConnId, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind,
};
use std::future::Future as _;

use super::services::{write_out, Answered};
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

/// A connection table's refusal, as the plugin reads it. An unavailable credential is a refusal
/// that names its own cause ([`CAUSE_CREDENTIAL_UNAVAILABLE`] in `value`), so the plugin can tell
/// it from the target's, the egress rules' or the far end's; an auth's refusal and an auth call's
/// failure name theirs ([`CAUSE_AUTH_REFUSED`], [`CAUSE_AUTH_FAILED`]).
const fn refusal(e: ConnError) -> Answered {
    let outcome = match e {
        ConnError::Pending => Outcome::Pending,
        ConnError::Timeout | ConnError::Closed | ConnError::Fault | ConnError::AuthFailed => {
            Outcome::Failed
        }
        ConnError::NotOwner
        | ConnError::UndeclaredNeed
        | ConnError::Refused
        | ConnError::Unarmed
        | ConnError::CredentialUnavailable
        | ConnError::AuthRefused => Outcome::Refused,
        // A cause this host does not name is the host failing the call.
        _ => Outcome::Fault,
    };
    let value = match e {
        ConnError::CredentialUnavailable => CAUSE_CREDENTIAL_UNAVAILABLE,
        ConnError::AuthRefused => CAUSE_AUTH_REFUSED,
        ConnError::AuthFailed => CAUSE_AUTH_FAILED,
        _ => CAUSE_NONE,
    };
    Answered {
        value,
        ..Answered::bare(outcome, e.text())
    }
}

/// A connection table's refusal of `conn`, naming why the connection failed where the table names
/// a cause: its `CAUSE_*` stage in `value`, the underlying error's own text in `error`.
fn refusal_of(
    e: ConnError,
    id: InstanceId,
    table: &Arc<dyn DeclaredConns>,
    conn: ConnId,
) -> Answered {
    let plain = refusal(e);
    if matches!(e, ConnError::Pending) {
        return plain;
    }
    match table.cause(id, conn) {
        Some(c) => Answered {
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
    super::handle::resolve(ctx)?.conn.get()
}

/// The seal the host lent the dispatcher a context's instance is adopted by (Part 2 #54): what the
/// member's auth fields are revealed under to join the request's head. `None` when none was lent.
fn lent_seal(ctx: HostCtx) -> Option<Arc<dyn busbar_contract::plugin::KernelSeal + Send + Sync>> {
    super::handle::resolve(ctx)?.route.get()?.upgrade()?.seal()
}

/// `run` under handle `h`, as the driver ticket's held exchanges see it (`super::held`): a tick
/// that reuses a handle another exchange issued in a kept cycle is answered FAULT and nothing runs
/// (a replay would hand it that exchange's kept answer); else `run`'s answer, PENDING or not,
/// noted against `h`.
fn held(wake: &InstanceWake, h: CompletionHandle, run: impl FnOnce() -> Answered) -> Answered {
    let store = wake
        .route
        .get()
        .and_then(std::sync::Weak::upgrade)
        .and_then(|r| r.store());
    if store.as_ref().is_some_and(|s| !s.held.call(h)) {
        return Answered::fault();
    }
    let a = run();
    if let Some(s) = store {
        s.held.answered(h, a.outcome == Outcome::Pending);
    }
    a
}

/// ONE SLOT'S FRAME: the `in` and `out` are there and the head is this service's and covers its
/// `in`, then `body` with the caller's identity, table and connector state. A panic answers FAULT;
/// the `out` is written as far as the caller stated it, and one stated below the first is REFUSED.
fn slot<R: Into<Kept>>(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    in_size: usize,
    body: impl FnOnce(InstanceId, &Arc<dyn DeclaredConns>, &ConnState, ServiceHead) -> R,
) -> RawOutcome {
    // THE CALLER'S `out`, as it states it: one below the first `ServiceOut` is REFUSED before the
    // service runs, and nothing of it is written (an `out` grows by appending, so an older caller's
    // smaller one is never overrun).
    let lent = if out.is_null() {
        0
    } else {
        // SAFETY: the caller's non-NULL `out`, its leading `size` readable.
        match unsafe { lent_out(out) } {
            Some(lent) => lent,
            None => return RawOutcome::of(Outcome::Refused),
        }
    };
    let a = catch_unwind(AssertUnwindSafe(|| {
        if input.is_null() || out.is_null() {
            return Answered::fault();
        }
        // SAFETY: a non-NULL `in` leads with its head (the call shape).
        let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
        if head.op != service || (head.size as usize) < in_size {
            return Answered::fault();
        }
        let Some((wake, (id, table))) =
            super::handle::resolve(ctx).and_then(|w| w.conn.get().map(|c| (w, c)))
        else {
            return refusal(ConnError::Unarmed);
        };
        let st = &wake.conn_state;
        let run = || -> Kept { body(*id, table, st, head).into() };
        // A never-pend service that writes the caller's memory is run afresh on a replay: a kept
        // answer would say the bytes were written into memory this call never touched.
        if service == service::IDENTITY {
            return run().answer;
        }
        // A replayed `READ_REPLY` writes what it read again into the memory the replay lends.
        let replay = (service == service::READ_REPLY).then_some(input);
        held(wake, head.handle, || st.kept(head.handle, replay, run))
    }))
    .unwrap_or_else(|_| Answered::fault());
    // SAFETY: the caller's `out`, as the call shape lends it, writable for the `lent` bytes it
    // stated.
    unsafe { write_out(out, &a, lent) }
}

/// The caller's bytes (`len` of them at `ptr`), or `None` for a length behind NULL or over the hard
/// byte maximum: capped before the slice is formed (THE DESIGN §11.13 M1).
///
/// # Safety
/// A non-NULL `ptr` names `len` live bytes for the call.
unsafe fn bytes<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    // SAFETY: the caller's contract.
    unsafe { super::validate::lent_mut(ptr, len) }
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
        |id, table, st, head| {
            // SAFETY: the head covered an `EstablishIn` up to its appended `member`; one whose
            // `size` stops there names no registration.
            let i = unsafe { read_establish(input) };
            // SAFETY: a checked range of the caller's, live for the call.
            let Some(target) = (unsafe { bytes(i.target.ptr.cast_mut(), i.target.len) }) else {
                return Answered::fault();
            };
            let target = String::from_utf8_lossy(target);
            // SAFETY: a checked range of the caller's, live for the call.
            let Some(within) = (unsafe { bytes(i.within.ptr.cast_mut(), i.within.len) }) else {
                return Answered::fault();
            };
            let Some(within) = addresses(within) else {
                return Answered::bare(
                    Outcome::Refused,
                    "an address the dial must land on is not an IP literal",
                );
            };
            // SAFETY: a checked range of the caller's, live for the call.
            let Some(member) = (unsafe { bytes(i.member.ptr.cast_mut(), i.member.len) }) else {
                return Answered::fault();
            };
            let member = String::from_utf8_lossy(member).into_owned();
            if table.framed(id, NeedId(i.need)) {
                // A FRAMED need opens when its request is whole (`WRITE_REQUEST`'s end): its
                // request is the connection's opening message.
                let stream = held_id();
                st.streams().insert(
                    stream,
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
                return Answered::ready(stream, 0);
            }
            // A RAW STREAM IS ANSWERED ONCE ITS DIAL HAS LANDED ("dial the need's endpoints ...
            // and answer the stream"): a far end that refuses the connect is the establish's own
            // answer, so a plugin trying an endpoint list in order (a libpq multi-host url: open;
            // on reject close and try the next) moves on to the next, as 1.5.5's driver did. While
            // it connects the call is PENDING on the caller's ticket, and its re-call (a new
            // handle, the same ticket) answers the same dial: nothing is dialled twice.
            let ticket = head.handle.ticket;
            let wanted = (NeedId(i.need), target.into_owned(), within, member);
            let conn = match st.dialling(id, table, ticket, &wanted) {
                Some(conn) => conn,
                None => {
                    let desc = OpenDesc {
                        target: &wanted.1,
                        within: &wanted.2,
                        timeout_ms: u64::from(i.timeout_ms),
                        member: &wanted.3,
                        ..OpenDesc::default()
                    };
                    match table.open(id, wanted.0, &desc) {
                        Ok(conn) => conn,
                        Err(e) => return refusal(e),
                    }
                }
            };
            // A call on no ticket may not pend: its stream is answered with the dial in flight.
            if ticket.is_none() {
                return Answered::ready(conn.0, 0);
            }
            match table.landed(id, conn, conn_ticket(ticket)) {
                Ok(()) => Answered::ready(conn.0, 0),
                Err(ConnError::Pending) => {
                    lock(&st.dialling).insert(ticket, (wanted, conn));
                    refusal(ConnError::Pending)
                }
                Err(e) => {
                    // The connect failed: its cause is read before the stream goes.
                    let a = refusal_of(e, id, table, conn);
                    let _ = table.close(id, conn);
                    a
                }
            }
        },
    )
}

/// What a pending `ESTABLISH` asked for: the need, the target, the `within` set and the
/// registration.
type Wanted = (NeedId, String, Vec<IpAddr>, String);

impl ConnState {
    /// The dial a pending `ESTABLISH` on `ticket` left in flight, taken, when the re-call asks for
    /// the same; one it no longer asks for is closed on `table`.
    fn dialling(
        &self,
        id: InstanceId,
        table: &Arc<dyn DeclaredConns>,
        ticket: Ticket,
        wanted: &Wanted,
    ) -> Option<ConnId> {
        if ticket.is_none() {
            return None;
        }
        let (asked, conn) = lock(&self.dialling).remove(&ticket)?;
        if &asked == wanted {
            return Some(conn);
        }
        let _ = table.close(id, conn);
        None
    }

    /// Close on `table` every dial a pending `ESTABLISH` left in flight on a ticket `gone` names:
    /// the op that asked for it ended without its re-call. The map is let go before anything is
    /// closed.
    fn drop_dialling(&self, table: Option<&ArmedConns>, gone: impl Fn(&Ticket) -> bool) {
        drop(self.take_dialling(table, gone));
    }

    /// [`ConnState::drop_dialling`]'s dials, taken out of the map and closed when the answer drops.
    fn take_dialling(&self, table: Option<&ArmedConns>, gone: impl Fn(&Ticket) -> bool) -> Closes {
        let left: Vec<ConnId> = {
            let mut all = lock(&self.dialling);
            let keys: Vec<Ticket> = all.keys().filter(|k| gone(k)).copied().collect();
            keys.iter()
                .filter_map(|k| all.remove(k).map(|(_, conn)| conn))
                .collect()
        };
        Closes(table.filter(|_| !left.is_empty()).cloned(), left)
    }
}

/// DIALS TO CLOSE ON A TABLE, closed when this drops. A close may cross into a transport door
/// (THE DESIGN §11.13 M1), so a caller under a lock keeps this until it has let the lock go.
#[must_use = "dropped, it closes its dials at once"]
pub(crate) struct Closes(Option<ArmedConns>, Vec<ConnId>);

impl Drop for Closes {
    fn drop(&mut self) {
        if let Some((id, table)) = &self.0 {
            for conn in self.1.drain(..) {
                let _ = table.close(*id, conn);
            }
        }
    }
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
        |id, table, st, head| {
            // SAFETY: the head covered an `IoIn`.
            let i = unsafe { input.cast::<IoIn>().read_unaligned() };
            // SAFETY: the caller's buffer, lent for this call only: the host keeps no hold on it
            // past the call, a PENDING answer included.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Answered::fault();
            };
            let ticket = conn_ticket(head.handle.ticket);
            let conn = match resolve(st, id, table, i.stream) {
                Ok(c) => c,
                Err(e) => return refusal(e),
            };
            match table.read(id, conn, ticket, buf) {
                Ok(piece) => Answered::ready(0, piece.len as u64),
                Err(ConnError::Closed) => Answered::ready(0, 0),
                Err(ConnError::Pending) if head.handle.ticket.is_none() => Answered::bare(
                    Outcome::Refused,
                    "a read that would pend is callable only inside a ticketed op",
                ),
                Err(e) => refusal_of(e, id, table, conn),
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
        |id, table, st, _| {
            // SAFETY: the head covered an `IoIn`.
            let i = unsafe { input.cast::<IoIn>().read_unaligned() };
            // SAFETY: the caller's bytes, lent for this call only: the host keeps no hold on it
            // past the call, a PENDING answer included.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Answered::fault();
            };
            let conn = match resolve(st, id, table, i.stream) {
                Ok(c) => c,
                Err(e) => return refusal(e),
            };
            match table.write(id, conn, buf, false, false) {
                Ok(n) => Answered::ready(0, n as u64),
                Err(e) => refusal_of(e, id, table, conn),
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
        |id, table, st, _| {
            // SAFETY: the head covered a `StreamIn`.
            let i = unsafe { input.cast::<StreamIn>().read_unaligned() };
            lock(&st.facts).remove(&i.stream);
            let held = st.streams().remove(&i.stream);
            let conn = match held.map(|s| s.conn) {
                // Never opened, or refused: nothing on the table to close.
                // (A request waiting on its auth call drops the call: a client drop.)
                // (A stream being opened outside the lock is closed by the call that opens it.)
                Some(Conn::Held { .. } | Conn::Failed(_) | Conn::Authing(_) | Conn::Opening) => {
                    return Answered::ready(0, 0)
                }
                Some(Conn::Open(c)) => c,
                None if i.stream & HELD != 0 => return refusal(ConnError::Closed),
                None => ConnId(i.stream),
            };
            match table.close(id, conn) {
                Ok(()) => Answered::ready(0, 0),
                Err(e) => refusal(e),
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
    // SAFETY: the caller's contract; the length is capped before the slice is formed.
    let b = unsafe { super::validate::lent_str(s) }.ok_or(())?;
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
        |id, table, _, head| {
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
                return Answered::fault();
            };
            if i.stream & HELD != 0 {
                return Answered::bare(
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
                    Answered::ready(0, 0)
                }
                Err(ConnError::Pending) if head.handle.ticket.is_none() => Answered::bare(
                    Outcome::Refused,
                    "an upgrade that would pend is callable only inside a ticketed op",
                ),
                Err(e) => refusal(e),
            }
        },
    )
}

/// The first unverified handshake an instance's connection ran (the operator's opt-in, ARCHITECT
/// ruling 2026-10-03 on Q-L16-4) is logged at WARN, naming the instance: once per instance.
fn warn_unverified(ctx: HostCtx) {
    static WARNED: OnceLock<Mutex<std::collections::HashSet<u64>>> = OnceLock::new();
    let Some(wake) = super::handle::resolve(ctx) else {
        return;
    };
    let first = WARNED
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(ctx.handle);
    if !first {
        return;
    }
    let instance = wake
        .caller
        .get()
        .map_or_else(|| "<unbound>".to_owned(), |c| c.instance.to_string());
    tracing::warn!(
        instance = %instance,
        "plugin instance '{instance}' secures a connection WITHOUT verifying the far end's certificate (operator opt-in, e.g. `#insecure`); its traffic can be intercepted"
    );
}

/// The facts strings each of an instance's streams was answered, held until it closes
/// (`FactsIn::facts`: "the strings stay valid until the stream closes"): a later answer that
/// differs is added, never put in an earlier one's place.
type HeldFacts = HashMap<u64, Vec<Box<str>>>;

/// `text`, held for `stream` until it closes, as the caller reads it.
fn held_text(all: &mut HeldFacts, key: u64, text: Option<&str>) -> AbiStr {
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
        |id, table, st, _| {
            // SAFETY: the head covered a `FactsIn`.
            let i = unsafe { input.cast::<FactsIn>().read_unaligned() };
            if i.facts.is_null() {
                return Answered::fault();
            }
            let conn = match resolve(st, id, table, i.stream) {
                Ok(c) => c,
                Err(e) => return refusal(e),
            };
            let f = match table.facts(id, conn) {
                Ok(f) => f,
                Err(e) => return refusal(e),
            };
            let hash = f.peer_cert.as_ref().map(|c| c.fingerprint.as_str());
            let mut all = lock(&st.facts);
            let key = i.stream;
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
            Answered::ready(0, 0)
        },
    )
}

// ── THE REPLAY RULE ─────────────────────────────────────────────────────────────────────────────

/// What an instance's [`InstanceWake::conn`] holds: its identity on the connection table, and the
/// table.
type ArmedConns = (InstanceId, Arc<dyn DeclaredConns>);

/// WHAT THE CONNECTOR HOLDS FOR ONE INSTANCE, on the instance's own [`InstanceWake`] (where every
/// slot call already resolves its context), so no instance's connector calls wait on another's
/// lock. Each lock is held only to read or swap an entry, never across a call that can run plugin
/// code: an auth plugin's `fields`, or a table open or close that may cross into a transport door
/// (THE DESIGN §11.13 M1). A wedged plugin would otherwise hold the instance's connector I/O behind
/// it, and a plugin that called back into the connector from inside that call would relock it on
/// its own thread.
#[derive(Default)]
pub(crate) struct ConnState {
    /// The instance's streams the host holds ([`Stream`]), by stream id.
    streams: Mutex<HashMap<u64, Stream>>,
    /// The facts strings its streams were answered ([`HeldFacts`]).
    facts: Mutex<HeldFacts>,
    /// THE DIALS IN FLIGHT: an `ESTABLISH` on a ticket that answered PENDING while its dial
    /// connects, by ticket, closed on the instance's table when the ticket moves on without it.
    dialling: Mutex<HashMap<Ticket, (Wanted, ConnId)>>,
    /// Every ticketed service's answer ([`Kept`]), by ticket, then by the handle's issue order.
    kept: Mutex<HashMap<Ticket, HashMap<u32, Kept>>>,
}

/// `m`, locked; a poisoned lock is still the state it guards.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One ticketed service's answer, stored once under its handle. A `READ_REPLY` keeps beside it its
/// piece and the bytes it wrote: the read wrote the caller's memory, so its replay writes them
/// again ([`replay_read`]), as a replayed `IDENTITY` does. A short answer's re-call starts the op
/// over with fresh buffers, and its kept reads are the far end's whole reply.
struct Kept {
    answer: Answered,
    read: Option<(ReplyPiece, Box<[u8]>)>,
}

impl From<Answered> for Kept {
    fn from(answer: Answered) -> Self {
        Self { answer, read: None }
    }
}

impl ConnState {
    /// The instance's held streams, locked.
    fn streams(&self) -> MutexGuard<'_, HashMap<u64, Stream>> {
        lock(&self.streams)
    }

    /// `run` once per completion handle: a handle that already answered (anything but PENDING)
    /// answers the same again, and `run` is not made a second time; a kept read is written again
    /// into what `replay` (a `READ_REPLY`'s `in`) lends. A call on no ticket is never kept: it may
    /// not pend, and every call is its own.
    fn kept(
        &self,
        h: CompletionHandle,
        replay: Option<*const c_void>,
        run: impl FnOnce() -> Kept,
    ) -> Answered {
        if h.ticket.is_none() {
            return run().answer;
        }
        if let Some(k) = lock(&self.kept)
            .get(&h.ticket)
            .and_then(|issued| issued.get(&h.seq))
        {
            if let (Some(input), Some(read)) = (replay, &k.read) {
                replay_read(input, read);
            }
            return k.answer;
        }
        let k = run();
        let a = k.answer;
        if a.outcome != Outcome::Pending {
            lock(&self.kept)
                .entry(h.ticket)
                .or_default()
                .insert(h.seq, k);
        }
        a
    }

    /// Forget every answer kept on `ticket`: how many there were, and every dial it left in flight,
    /// to be closed on `table` once the caller holds no lock ([`Closes`]).
    fn forget(&self, table: Option<&ArmedConns>, ticket: Ticket) -> (usize, Closes) {
        let closes = self.take_dialling(table, |t| *t == ticket);
        let kept = lock(&self.kept)
            .remove(&ticket)
            .map_or(0, |issued| issued.len());
        (kept, closes)
    }
}

/// A replayed read: what it wrote, written again into the piece slot and the buffer the replay's
/// `in` lends (as much of the bytes as the buffer holds).
fn replay_read(input: *const c_void, (piece, kept): &(ReplyPiece, Box<[u8]>)) {
    // SAFETY: `slot` checked the head covers a `ReplyIn`.
    let i = unsafe { input.cast::<ReplyIn>().read_unaligned() };
    // SAFETY: the caller's buffer, lent for this call only.
    let (false, Some(buf)) = (i.piece.is_null(), unsafe { bytes(i.buf, i.len) }) else {
        return;
    };
    let n = kept.len().min(buf.len());
    buf[..n].copy_from_slice(&kept[..n]);
    // SAFETY: the caller's descriptor slot, checked non-NULL.
    unsafe { i.piece.write_unaligned(*piece) };
}

/// Forget every answer instance `id` kept under `ticket` (its worker recycled it, a driver
/// ticket's tick started, or a new op started on it); how many there were. Held per instance as
/// well as by ticket: tickets are minted per dispatcher, so another dispatcher's instance may hold
/// an identical ticket, and its kept answers are never its neighbour's to drop (dropping them would
/// make it run a stored establish or write a second time).
pub(crate) fn forget(id: InstanceId, ticket: Ticket) -> (usize, Closes) {
    super::handle::supplier_of(id).map_or_else(
        || (0, Closes(None, Vec::new())),
        |w| w.conn_state.forget(w.conn.get(), ticket),
    )
}

/// Forget every answer the instances `ids` kept under worker `worker`'s tickets: it was replaced.
/// Another dispatcher's worker of the same index is not touched.
pub(crate) fn forget_worker(ids: &[InstanceId], worker: u32) {
    let gone = |t: &Ticket| super::ticket::decode(t.slot).0 == worker;
    for w in ids.iter().filter_map(|id| super::handle::supplier_of(*id)) {
        w.conn_state.drop_dialling(w.conn.get(), gone);
        lock(&w.conn_state.kept).retain(|t, _| !gone(t));
    }
}

/// FORGET EVERYTHING instance `id` holds on the connector — its held streams and their facts, its
/// kept answers, its dials in flight — and close on `table` every connection a held stream had
/// open. Made when the instance can never cross again: the watchdog faulted it, or it is dropped (a
/// close, a reload). The maps are let go before anything is closed or dropped: a held stream's
/// pending auth call is the auth plugin's, and a close may cross into a transport door (THE DESIGN
/// §11.13 M1). Last, the table forgets the instance ([`DeclaredConns::forget`]): its needs, every
/// connection still open on them, and its member programs, which a replaced instance would
/// otherwise leave running.
pub(crate) fn purge(id: InstanceId, table: &Arc<dyn DeclaredConns>) {
    if let Some(w) = super::handle::supplier_of(id) {
        let st = &w.conn_state;
        st.drop_dialling(w.conn.get(), |_| true);
        // Replaced whole, so the instance's entry (leaked for the process) keeps no capacity.
        *lock(&st.facts) = HashMap::new();
        *lock(&st.kept) = HashMap::new();
        let gone = std::mem::take(&mut *st.streams());
        for s in gone.into_values() {
            if let Conn::Open(c) = s.conn {
                let _ = table.close(id, c);
            }
        }
    }
    table.forget(id);
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
    /// answer (the open calls the member binding's fields).
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

/// Install `conn` on the stream a call took out to open ([`Conn::Opening`]), the instance's
/// streams lock ([`ConnState::streams`]: held only to read or swap a stream's state, never across
/// a call that can run plugin code, THE DESIGN §11.13 M1) re-taken for the swap alone. A stream
/// closed meanwhile is gone: what was opened for it is closed on the table, and anything else it
/// held (a pending auth call) is dropped, both after the lock is let go.
fn install(
    st: &ConnState,
    id: InstanceId,
    stream: u64,
    table: &Arc<dyn DeclaredConns>,
    conn: Conn,
) {
    let orphan = {
        let mut all = st.streams();
        match all.get_mut(&stream) {
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
    st: &ConnState,
    id: InstanceId,
    table: &Arc<dyn DeclaredConns>,
    stream: u64,
) -> Result<ConnId, ConnError> {
    if stream & HELD == 0 {
        return Ok(ConnId(stream));
    }
    let (need, target, within, member) = {
        let mut all = st.streams();
        let s = all.get_mut(&stream).ok_or(ConnError::Closed)?;
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
        st,
        id,
        stream,
        table,
        opened.map_or_else(Conn::Failed, Conn::Open),
    );
    opened
}

/// A field block's fields, owned; a name that is not text, or a pseudo-field, refuses the block.
fn field_lines(block: &[u8]) -> Result<Vec<(String, Vec<u8>)>, Answered> {
    fields::lines(block)
        .map(|(name, value)| {
            if name.first() == Some(&b':') {
                return Err(Answered::bare(
                    Outcome::Refused,
                    "a request field is a pseudo-field; the framer names its own head",
                ));
            }
            let name = std::str::from_utf8(name).map_err(|_| Answered::fault())?;
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
        |id, table, st, _| {
            // SAFETY: the head covered a `RequestIn`.
            let i = unsafe { input.cast::<RequestIn>().read_unaligned() };
            if i.piece.is_null() {
                return Answered::fault();
            }
            // SAFETY: the caller's descriptor, checked non-NULL, lent for this call only: the host
            // keeps no hold on it past the call, a PENDING answer included.
            let piece: RequestPiece = unsafe { i.piece.read_unaligned() };
            // SAFETY: the caller's bytes, lent for this call only: the host keeps no hold on it
            // past the call, a PENDING answer included.
            let Some(bytes) = (unsafe { bytes(i.buf.cast_mut(), i.len) }) else {
                return Answered::fault();
            };
            let mut all = st.streams();
            let Some(s) = all.get_mut(&i.stream) else {
                return Answered::bare(
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
                return Answered::bare(
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
                        return Answered::fault();
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
                    Answered::ready(0, bytes.len() as u64)
                }
                (REQUEST_BODY, true) => {
                    if body.len() + bytes.len() > REQUEST_HELD_MAX {
                        return Answered::bare(
                            Outcome::Refused,
                            "the request body passed the host's bound",
                        );
                    }
                    body.extend_from_slice(bytes);
                    Answered::ready(0, bytes.len() as u64)
                }
                (REQUEST_END, true) => {
                    let Some(mut h) = head.take() else {
                        return Answered::fault();
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
                    // THE PLUGIN'S WAIVER of the member's binding for this request
                    // (`abi::auth::NO_MEMBER_AUTH_FIELD`): the host's own field too, taken out here,
                    // and the request is opened with no member auth.
                    let mut waived = false;
                    h.fields.retain(|(name, value)| {
                        if busbar_contract::abi::auth::is_scope_field(name.as_bytes()) {
                            scope.get_or_insert_with(|| value.clone());
                            false
                        } else if busbar_contract::abi::auth::is_no_member_auth_field(
                            name.as_bytes(),
                        ) {
                            waived = true;
                            false
                        } else {
                            true
                        }
                    });
                    let at = (target.as_str(), within.as_slice(), member.as_str());
                    // THE MEMBER'S BINDING: a request to a member the connector holds a binding
                    // for carries that binding's auth fields, as the member's relayed calls do. The
                    // connector keys a binding by (instance, need, member, target origin); a
                    // request naming no member gets no binding. It is the binding of the member the
                    // stream NAMES (`EstablishIn::member`), never of another registration at the
                    // same origin. The request is handed over whole; what became of it is the
                    // reply's to say.
                    let bound = if waived {
                        None
                    } else {
                        table.auth_of(id, need, &member, &target)
                    };
                    // A refreshed binding answers this request's handle with a load (never a
                    // resolution inside this crossing); one whose credential its last refresh
                    // found unavailable refuses the request under its own cause, nothing
                    // presented.
                    let handle = bound.as_ref().and_then(|b| match &b.per_request {
                        Some(per) => per.handle_now(),
                        None => Some(b.handle),
                    });
                    let conn = match bound {
                        None => open_with(table, id, need, at, &h, body, &[], None),
                        Some(_) if handle.is_none() => {
                            Conn::Failed(ConnError::CredentialUnavailable)
                        }
                        Some(binding) => match auth_request(
                            &binding,
                            &h,
                            &target,
                            &body,
                            scope,
                            &completing(table, id, need, &target, &h, &body),
                        ) {
                            None => Conn::Failed(ConnError::Refused),
                            Some(request) => {
                                let handle = handle.unwrap_or(binding.handle);
                                match binding.auth.fields_now(handle, &request) {
                                    Some(Fields::Ready(auth)) => {
                                        let seal = lent_seal(ctx);
                                        open_with(
                                            table,
                                            id,
                                            need,
                                            at,
                                            &h,
                                            body,
                                            &auth,
                                            seal.as_deref(),
                                        )
                                    }
                                    Some(Fields::Refused | Fields::Failed) => {
                                        Conn::Failed(ConnError::Refused)
                                    }
                                    None => Conn::Authing(Box::new(Authing {
                                        fielding: binding.auth.fields(handle, request, 0),
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
                    install(st, id, i.stream, table, conn);
                    Answered::ready(0, 0)
                }
                (REQUEST_HEAD, true) => {
                    Answered::bare(Outcome::Refused, "the request's head was already written")
                }
                (REQUEST_BODY | REQUEST_END, false) => Answered::bare(
                    Outcome::Refused,
                    "a request's head is written before its body and its end",
                ),
                _ => Answered::fault(),
            }
        },
    )
}

/// Open a whole request on the table: the member's `auth` fields first, then the plugin's (a
/// plugin field named like an auth field never doubles it: the binding's stands), 1.5.5's egress
/// order, as the relayed calls are opened. The auth fields are revealed under `seal`, the one the
/// host lent the dispatcher; with auth fields and no seal the open is refused (fail closed).
#[allow(clippy::too_many_arguments)]
fn open_with(
    table: &Arc<dyn DeclaredConns>,
    id: InstanceId,
    need: NeedId,
    (target, within, member): (&str, &[IpAddr], &str),
    h: &Head,
    body: Vec<u8>,
    auth: &[busbar_contract::auth_calls::AuthField],
    seal: Option<&(dyn busbar_contract::plugin::KernelSeal + Send + Sync)>,
) -> Conn {
    let seal = match (auth.is_empty(), seal) {
        (true, _) => None,
        (false, Some(seal)) => Some(seal),
        (false, None) => return Conn::Failed(ConnError::Refused),
    };
    let mut fields: Vec<(&str, &[u8])> = Vec::with_capacity(auth.len() + h.fields.len());
    let names: Vec<String> = auth
        .iter()
        .map(|f| String::from_utf8_lossy(&f.name).into_owned())
        .collect();
    if let Some(seal) = seal {
        for (name, f) in names.iter().zip(auth) {
            fields.push((name.as_str(), f.value.expose(seal).as_slice()));
        }
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
        // The request the plugin wrote, frozen once: the connector keeps it without a copy.
        body: body.into(),
        timeout_ms: h.timeout_ms,
        method: &h.method,
        head_target: &h.target,
        within,
        member,
        unit: 0,
    };
    table
        .open(id, need, &desc)
        .map_or_else(Conn::Failed, Conn::Open)
}

/// THE LINES THE CONNECTOR COMPLETES the plugin's whole request with at its open (THE DESIGN
/// section 6, step 5; [`busbar_contract::conn::HeadDefaults::completing`]): the framer's own lines
/// its head does not carry, then the body's length where the framer leaves it to the host. They are
/// part of the head the member's auth call signs, so nothing is added after the auth runs.
fn completing(
    table: &Arc<dyn DeclaredConns>,
    id: InstanceId,
    need: NeedId,
    target: &str,
    h: &Head,
    body: &[u8],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    table.request_head(id, need, target).completing(
        |name| {
            h.fields
                .iter()
                .any(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
        },
        body.len(),
    )
}

/// The member binding's ONE auth call for a whole request to `target` (THE DESIGN, outbound auth: the facts at
/// the style's point; the request's head when the style reads it, completed with `added`, the lines
/// the connector adds at the open; its stated `scope` in the extensions blob). A passthrough binding is lent the caller credential of the unit the crossing
/// serves (none presented: an empty one, so nothing is presented, never the operator's); a request
/// made inside no unit has no caller, and opens nothing (`None`): an operator's own fetch never
/// spends a caller's credential.
fn auth_request(
    binding: &busbar_contract::conn::ConnAuth,
    h: &Head,
    target: &str,
    body: &[u8],
    scope: Option<Vec<u8>>,
    added: &[(Vec<u8>, Vec<u8>)],
) -> Option<FieldsRequest> {
    use busbar_contract::abi::auth::{AuthPoint, STYLE_NEEDS_HEADERS};
    let caller_credential = if binding.passthrough {
        let unit = super::services::serving_unit()?;
        Some(
            binding
                .lender
                .as_ref()
                .and_then(|l| l.lent(unit))
                .unwrap_or_else(|| busbar_contract::redacted::Secret::new(Vec::new())),
        )
    } else {
        None
    };
    // The authority the socket dials, read by the one split; the fragment is never sent, and a
    // web path's `\` is the `/` the dialling stack sends.
    let parts = busbar_contract::net::url_authority(target);
    let authority = parts.host_port;
    let path_query = parts.tail.split('#').next().unwrap_or("");
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, Some(q.as_bytes().to_vec())),
        None => (path_query, None),
    };
    let path = if path.is_empty() { "/" } else { path };
    let path: Vec<u8> = if parts.web {
        path.bytes()
            .map(|b| if b == b'\\' { b'/' } else { b })
            .collect()
    } else {
        path.as_bytes().to_vec()
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
        path,
        query,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        headers: if binding.style_flags & STYLE_NEEDS_HEADERS != 0 {
            h.fields
                .iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.clone()))
                .chain(added.iter().cloned())
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
    /// The route, and the instance `ctx` named as the ticket's supplier (#74).
    struct TicketWaker {
        waking: super::ticket::Waking,
        ticket: Ticket,
    }
    impl std::task::Wake for TicketWaker {
        fn wake(self: Arc<Self>) {
            self.waking.wake(self.ticket);
        }
    }
    if ticket.is_none() {
        return None;
    }
    let waking = super::ticket::Waking::of(super::handle::resolve(ctx)?)?;
    Some(std::task::Waker::from(Arc::new(TicketWaker {
        waking,
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
        |id, table, st, head| {
            // SAFETY: the head covered a `ReplyIn`.
            let i = unsafe { input.cast::<ReplyIn>().read_unaligned() };
            if i.piece.is_null() {
                return Kept::from(Answered::fault());
            }
            // SAFETY: the caller's buffer, lent for this call only: the host keeps no hold on it
            // past the call, a PENDING answer included.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Kept::from(Answered::fault());
            };
            let (piece, answer) = reply(ctx, st, id, table, head, i.stream, buf);
            let mut read = None;
            if let Some(p) = piece {
                // SAFETY: the caller's descriptor slot, checked non-NULL.
                unsafe { i.piece.write_unaligned(p) };
                // A ticketed read keeps what it wrote, stored with its answer.
                if answer.outcome != Outcome::Pending && !head.handle.ticket.is_none() {
                    let n = usize::try_from(answer.len).map_or(buf.len(), |n| n.min(buf.len()));
                    read = Some((p, buf[..n].into()));
                }
            }
            Kept { answer, read }
        },
    )
}

/// The next piece of the reply on `stream`, read into `buf`: its descriptor (none for an answer
/// without one) and the answer.
fn reply(
    ctx: HostCtx,
    st: &ConnState,
    id: InstanceId,
    table: &Arc<dyn DeclaredConns>,
    head: ServiceHead,
    stream: u64,
    buf: &mut [u8],
) -> (Option<ReplyPiece>, Answered) {
    // A REQUEST WAITING ON ITS AUTH CALL opens when the call answers (its fields lead the head),
    // fails its ack when the call refuses or fails, and reads as nothing ready (on the caller's
    // ticket, woken when the call answers) until then. The call is taken out of the map to be
    // polled and opened with the connector's lock let go (THE DESIGN §11.13 M1).
    let waker = ticket_waker(ctx, head.handle.ticket);
    let authing = {
        let mut all = st.streams();
        match all.get_mut(&stream) {
            Some(s) if matches!(s.conn, Conn::Authing(_)) => {
                if waker.is_none() {
                    return (
                        None,
                        Answered::bare(
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
                install(st, id, stream, table, Conn::Authing(a));
                return (None, refusal(ConnError::Pending));
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
                std::mem::take(&mut a.body),
                &auth,
                lent_seal(ctx).as_deref(),
            ),
            Fields::Refused | Fields::Failed => Conn::Failed(ConnError::Refused),
        };
        install(st, id, stream, table, opened);
    }
    {
        let mut all = st.streams();
        let s = all.entry(stream).or_insert(Stream {
            conn: Conn::Open(ConnId(stream)),
            headed: false,
            ended: false,
        });
        if s.ended {
            return (None, refusal(ConnError::Closed));
        }
        match &s.conn {
            Conn::Held { .. } => {
                return (
                    None,
                    Answered::bare(Outcome::Refused, "the request is not whole: write its end"),
                )
            }
            Conn::Failed(e) => {
                // THE FAILED ACK: the stream's refusal, with its text, and the reply has ended.
                let e = *e;
                s.ended = true;
                return (None, refusal(e));
            }
            Conn::Open(_) => {}
            Conn::Authing(_) => return (None, refusal(ConnError::Pending)),
            Conn::Opening => {
                return (
                    None,
                    Answered::bare(
                        Outcome::Refused,
                        "another call on the stream is opening it; read when it answers",
                    ),
                )
            }
        }
    }
    let conn = match resolve(st, id, table, stream) {
        Ok(c) => c,
        Err(e) => return (None, refusal(e)),
    };
    let ticket = conn_ticket(head.handle.ticket);
    loop {
        let got = table.read(id, conn, ticket, buf);
        let mut all = st.streams();
        let Some(s) = all.get_mut(&stream) else {
            return (None, refusal(ConnError::Closed));
        };
        let terminal = |s: &mut Stream| {
            s.ended = true;
            let kind = if s.headed { REPLY_END } else { REPLY_ACK };
            (
                Some(ReplyPiece {
                    kind,
                    ..ReplyPiece::default()
                }),
                Answered::ready(0, 0),
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
                        Answered::ready(0, reason.end.max(p.len) as u64),
                    )
                }
                PieceKind::Body | PieceKind::HookReply => (
                    Some(ReplyPiece {
                        kind: REPLY_BODY,
                        ..ReplyPiece::default()
                    }),
                    Answered::ready(0, p.len as u64),
                ),
                PieceKind::Completion => terminal(s),
            },
            Err(ConnError::Closed) => terminal(s),
            Err(ConnError::Pending) if head.handle.ticket.is_none() => (
                None,
                Answered::bare(
                    Outcome::Refused,
                    "a read that would pend is callable only inside a ticketed op",
                ),
            ),
            Err(ConnError::Pending) => (None, refusal(ConnError::Pending)),
            Err(e) => {
                // A refusal or failure mid-reply is its failed ack, naming why where it can.
                s.ended = true;
                drop(all);
                (None, refusal_of(e, id, table, conn))
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
        |_, _, _, _| {
            // SAFETY: the head covered an `IdentityIn`.
            let i = unsafe { input.cast::<IdentityIn>().read_unaligned() };
            if i.identity.is_null() {
                return Answered::fault();
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
            Answered::ready(0, 0)
        },
    )
}

#[cfg(test)]
#[path = "../tests/conn_services_tests.rs"]
mod tests;
