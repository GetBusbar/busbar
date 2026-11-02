// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::net::IpAddr;
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use futures::FutureExt as _;

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

use super::services::{service, write_out, Answered};
use super::ticket::InstanceWake;

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

    random: None,
    identity: Some(identity),
    read_reply: Some(read_reply),
    write_request: Some(write_request),
};

#[must_use]
pub const fn conn_ticket(t: Ticket) -> u64 {
    ((t.slot as u64) << 32) | t.generation as u64
}

#[must_use]
pub const fn ticket_of(n: u64) -> Ticket {
    Ticket {
        slot: (n >> 32) as u32,
        generation: n as u32,
    }
}

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

const CAUSE_TEXTS_MAX: usize = 1024;

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

pub(crate) fn armed(ctx: HostCtx) -> Option<&'static (InstanceId, Arc<dyn DeclaredConns>)> {
    super::handle::resolve(ctx)?.conn.get()
}

fn lent_seal(ctx: HostCtx) -> Option<Arc<dyn busbar_contract::plugin::KernelSeal + Send + Sync>> {
    super::handle::resolve(ctx)?.route.get()?.upgrade()?.seal()
}

fn held(wake: &InstanceWake, h: CompletionHandle, run: impl FnOnce() -> Answered) -> Answered {
    let store = wake
        .route
        .get()
        .and_then(std::sync::Weak::upgrade)
        .and_then(|r| r.store());
    let caller = std::ptr::from_ref(wake) as usize;
    let domain = busbar_contract::abi::sdk::completion_retirement::Domain::Connector;
    if store
        .as_ref()
        .is_some_and(|s| !s.held.call(caller, domain, h))
    {
        return Answered::fault();
    }
    let a = run();
    if let Some(s) = store {
        s.held
            .answered(caller, domain, h, a.outcome == Outcome::Pending);
    }
    a
}

fn slot<R: Into<Kept>>(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    in_size: usize,
    body: impl FnOnce(InstanceId, &Arc<dyn DeclaredConns>, &ConnState, ServiceHead) -> R,
) -> RawOutcome {
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
        let Some(wake) = super::handle::resolve(ctx) else {
            return refusal(ConnError::Unarmed);
        };
        let st = &wake.conn_state;
        let authority = if service == service::IDENTITY {
            wake.conn.get().map(|conn| Authority {
                conn: conn.clone(),
                binding: None,
            })
        } else {
            let creating = if service == service::ESTABLISH {
                st.dial_authority(head.handle.ticket)
            } else if matches!(
                service,
                service::READ
                    | service::WRITE
                    | service::UPGRADE_SECURE
                    | service::FACTS
                    | service::CLOSE
                    | service::READ_REPLY
                    | service::WRITE_REQUEST
            ) {
                // SAFETY: each checked service input has the same leading ServiceHead/stream
                // layout as StreamIn, and its required size covers that prefix.
                let stream = unsafe { input.cast::<StreamIn>().read_unaligned() }.stream;
                st.stream_authority(stream)
            } else {
                None
            };
            creating.or_else(|| {
                let binding = super::export_bindings::current();
                let conn = binding
                    .as_ref()
                    .map_or_else(|| wake.conn.get(), |binding| binding.conn.as_ref())?
                    .clone();
                Some(Authority { conn, binding })
            })
        };
        let Some(authority) = authority else {
            return refusal(ConnError::Unarmed);
        };
        let (id, table) = &authority.conn;
        let run = || -> Kept {
            super::export_bindings::crossing(authority.binding.clone(), || {
                body(*id, table, st, head).into()
            })
        };

        if service == service::IDENTITY {
            return run().answer;
        }

        let replay = matches!(
            service,
            service::READ_REPLY | service::READ | service::FACTS
        )
        .then_some(input);
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
            let need_timeout_ms = st.need_timeout(NeedId(i.need));
            let dial_timeout_ms = if i.timeout_ms == 0 {
                need_timeout_ms
            } else {
                u64::from(i.timeout_ms)
            };
            if table.framed(id, NeedId(i.need)) {
                let stream = held_id();
                st.streams().insert(
                    stream,
                    Stream {
                        authority: Authority::capture(id, table),
                        conn: Conn::Held {
                            need: NeedId(i.need),
                            target: target.into_owned(),
                            within,
                            member,
                            dial_timeout_ms,
                            head: None,
                            body: Vec::new(),
                        },
                        headed: false,
                        ended: false,
                        reply_timeout_ms: need_timeout_ms,
                    },
                );
                return Answered::ready(stream, 0);
            }

            let ticket = head.handle.ticket;
            let wanted = (
                NeedId(i.need),
                target.into_owned(),
                within,
                member,
                dial_timeout_ms,
            );
            let conn = match st.dialling(id, table, ticket, &wanted) {
                Some(conn) => conn,
                None => {
                    let desc = OpenDesc {
                        target: &wanted.1,
                        within: &wanted.2,
                        member: &wanted.3,
                        ..OpenDesc::default()
                    };
                    match table.open_request(id, wanted.0, &desc, false, dial_timeout_ms) {
                        Ok(conn) => conn,
                        Err(e) => return refusal(e),
                    }
                }
            };

            if ticket.is_none() {
                st.record_raw(id, table, conn, need_timeout_ms);
                return Answered::ready(conn.0, 0);
            }
            match table.landed(id, conn, conn_ticket(ticket)) {
                Ok(()) => {
                    st.record_raw(id, table, conn, need_timeout_ms);
                    Answered::ready(conn.0, 0)
                }
                Err(ConnError::Pending) => {
                    lock(&st.dialling).insert(
                        ticket,
                        Dial {
                            wanted,
                            conn,
                            authority: Authority::capture(id, table),
                        },
                    );
                    refusal(ConnError::Pending)
                }
                Err(e) => {
                    let a = refusal_of(e, id, table, conn);
                    let _ = table.close(id, conn);
                    a
                }
            }
        },
    )
}

type Wanted = (NeedId, String, Vec<IpAddr>, String, u64);

impl ConnState {
    fn dialling(
        &self,
        _id: InstanceId,
        _table: &Arc<dyn DeclaredConns>,
        ticket: Ticket,
        wanted: &Wanted,
    ) -> Option<ConnId> {
        if ticket.is_none() {
            return None;
        }
        let dial = lock(&self.dialling).remove(&ticket)?;
        if &dial.wanted == wanted {
            return Some(dial.conn);
        }
        let (owner, creating_table) = &dial.authority.conn;
        let _ = creating_table.close(*owner, dial.conn);
        // The dial's generation remains live through close, outside the state lock.
        drop(dial);
        None
    }

    fn drop_dialling(&self, table: Option<&ArmedConns>, gone: impl Fn(&Ticket) -> bool) {
        drop(self.take_dialling(table, gone));
    }

    fn take_dialling(&self, _table: Option<&ArmedConns>, gone: impl Fn(&Ticket) -> bool) -> Closes {
        let dials = {
            let mut all = lock(&self.dialling);
            let keys: Vec<Ticket> = all.keys().filter(|k| gone(k)).copied().collect();
            keys.iter().filter_map(|k| all.remove(k)).collect()
        };
        let waits = self.take_waits(|handle, _| gone(&handle.ticket));
        Closes {
            dials,
            streams: Vec::new(),
            waits,
        }
    }

    fn stream_authority(&self, stream: u64) -> Option<Authority> {
        self.streams().get(&stream).map(|s| s.authority.clone())
    }

    fn dial_authority(&self, ticket: Ticket) -> Option<Authority> {
        lock(&self.dialling)
            .get(&ticket)
            .map(|d| d.authority.clone())
    }

    /// Detach only the candidate's resources. Dropping the returned owner closes connections
    /// and auth calls without holding any ConnState lock, before releasing their generations.
    pub(crate) fn retire_binding(
        &self,
        binding: &Arc<super::export_bindings::Generation>,
    ) -> Closes {
        let streams: Vec<_> = {
            let mut all = self.streams();
            let keys: Vec<_> = all
                .iter()
                .filter(|(_, stream)| stream.authority.belongs_to(binding))
                .map(|(key, _)| *key)
                .collect();
            keys.into_iter()
                .filter_map(|key| all.remove(&key).map(|s| (key, s)))
                .collect()
        };
        let dials = {
            let mut all = lock(&self.dialling);
            let keys: Vec<_> = all
                .iter()
                .filter(|(_, dial)| dial.authority.belongs_to(binding))
                .map(|(key, _)| *key)
                .collect();
            keys.into_iter()
                .filter_map(|key| all.remove(&key))
                .collect()
        };
        {
            let mut facts = lock(&self.facts);
            for (key, _) in &streams {
                facts.remove(key);
            }
        }
        let waits = self.take_waits(|_, wait| {
            wait.binding
                .as_ref()
                .is_some_and(|creating| Arc::ptr_eq(creating, binding))
        });
        Closes {
            dials,
            streams: streams.into_iter().map(|(_, s)| s).collect(),
            waits,
        }
    }
}

#[must_use = "dropped, it closes its connections outside the state locks"]
#[derive(Default)]
pub(crate) struct Closes {
    dials: Vec<Dial>,
    streams: Vec<Stream>,
    waits: Vec<ReplyWait>,
}

impl Drop for Closes {
    fn drop(&mut self) {
        for dial in self.dials.drain(..) {
            let (owner, table) = &dial.authority.conn;
            let _ = table.close(*owner, dial.conn);
        }
        for stream in self.streams.drain(..) {
            if let Conn::Open(conn) = &stream.conn {
                let (owner, table) = &stream.authority.conn;
                let _ = table.close(*owner, *conn);
            }
            // In-flight auth is dropped here too; its generation outlives the fielding call.
        }
        self.waits.clear();
    }
}

fn addresses(within: &[u8]) -> Option<Vec<IpAddr>> {
    let text = std::str::from_utf8(within).ok()?;
    if text.is_empty() {
        return Some(Vec::new());
    }
    text.split(WITHIN_SEPARATOR)
        .map(|a| a.trim().parse().ok())
        .collect()
}

service!(read, slot, service::READ, IoIn, |id, table, st, head, i| {
    // SAFETY: the caller's buffer, lent for this call only: the host keeps no hold on it
    // past the call, a PENDING answer included.
    let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
        return Kept::from(Answered::fault());
    };
    let ticket = conn_ticket(head.handle.ticket);
    let conn = match resolve(st, id, table, i.stream) {
        Ok(c) => c,
        Err(e) => return refusal(e).into(),
    };
    if let Err(error) = st.wait_reply(head.handle, i.stream) {
        return refusal(error).into();
    }
    match table.read(id, conn, ticket, buf) {
        Ok(piece) => {
            let n = piece.len.min(buf.len());
            let answer = Answered::ready(0, n as u64);
            // A ticketed read keeps the bytes it wrote, stored with its answer.
            let read =
                (!head.handle.ticket.is_none() && n > 0).then(|| Wrote::Raw(buf[..n].into()));
            Kept {
                answer,
                read,
                delivered: false,
            }
        }
        Err(ConnError::Closed) => Answered::ready(0, 0).into(),
        Err(ConnError::Pending) if head.handle.ticket.is_none() => Answered::bare(
            Outcome::Refused,
            "a read that would pend is callable only inside a ticketed op",
        )
        .into(),
        Err(e) => refusal_of(e, id, table, conn).into(),
    }
});

service!(write, slot, service::WRITE, IoIn, |id, table, st, _, i| {
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
});

service!(
    close,
    slot,
    service::CLOSE,
    StreamIn,
    |id, table, st, _, i| {
        lock(&st.facts).remove(&i.stream);
        let held = st.streams().remove(&i.stream);
        let waits = st.take_waits(|_, wait| wait.stream == i.stream);
        drop(waits);
        let conn = match held.map(|s| s.conn) {
            // Never opened, or refused: nothing on the table to close.
            // (A request waiting on its auth call drops the call: a client drop.)
            // (A stream being opened outside the lock is closed by the call that opens it.)
            Some(Conn::Held { .. } | Conn::Failed(_) | Conn::Authing(_) | Conn::Opening) => {
                return Answered::ready(0, 0);
            }
            Some(Conn::Open(c)) => c,
            None if i.stream & HELD != 0 => return refusal(ConnError::Closed),
            None => ConnId(i.stream),
        };
        match table.close(id, conn) {
            Ok(()) => Answered::ready(0, 0),
            Err(e) => refusal(e),
        }
    }
);

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

type HeldFacts = HashMap<u64, Vec<Box<str>>>;

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

service!(
    facts,
    slot,
    service::FACTS,
    FactsIn,
    |id, table, st, head, i| {
        if i.facts.is_null() {
            return Kept::from(Answered::fault());
        }
        let conn = match resolve(st, id, table, i.stream) {
            Ok(c) => c,
            Err(e) => return refusal(e).into(),
        };
        let f = match table.facts(id, conn) {
            Ok(f) => f,
            Err(e) => return refusal(e).into(),
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
        // A ticketed call keeps the facts it wrote, stored with its answer.
        let read = (!head.handle.ticket.is_none()).then(|| {
            Wrote::Facts(KeptFacts {
                stream: key,
                secure: written.secure,
                client_identity: written.client_identity,
                agreed_protocol: f.alpn.as_deref().map(Into::into),
                peer_cert_hash: hash.map(Into::into),
                peer_key_pin: f.peer_key_pin.as_deref().map(Into::into),
            })
        });
        Kept {
            answer: Answered::ready(0, 0),
            read,
            delivered: false,
        }
    }
);

type ArmedConns = (InstanceId, Arc<dyn DeclaredConns>);

/// A connection retains the declarations and authority which created it, across publication.
#[derive(Clone)]
struct Authority {
    conn: ArmedConns,
    binding: Option<Arc<super::export_bindings::Generation>>,
}

impl Authority {
    fn capture(id: InstanceId, table: &Arc<dyn DeclaredConns>) -> Self {
        Self {
            conn: (id, table.clone()),
            binding: super::export_bindings::current(),
        }
    }

    fn belongs_to(&self, binding: &Arc<super::export_bindings::Generation>) -> bool {
        self.binding
            .as_ref()
            .is_some_and(|creating| Arc::ptr_eq(creating, binding))
    }
}

impl std::fmt::Debug for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authority")
            .field("owner", &self.conn.0)
            .finish_non_exhaustive()
    }
}

struct Dial {
    wanted: Wanted,
    conn: ConnId,
    authority: Authority,
}

/// WHAT THE CONNECTOR HOLDS FOR ONE INSTANCE, on the instance's own [`InstanceWake`] (where every
/// slot call already resolves its context), so no instance's connector calls wait on another's
/// lock. Each lock is held only to read or swap an entry, never across a call that can run plugin
/// code: an auth plugin's `fields`, or a table open or close that may cross into a transport door
/// (THE DESIGN §11.13 M1). A wedged plugin would otherwise hold the instance's connector I/O behind
/// it, and a plugin that called back into the connector from inside that call would relock it on
/// its own thread.
#[derive(Default)]
pub(crate) struct ConnState {
    /// The ticket supplier's context, even when a borrowed table binding names another owner.
    context: OnceLock<HostCtx>,
    /// Statement metadata, fixed at bind; open/refresh redeclare that same signed need.
    need_timeouts: OnceLock<Box<[u64]>>,
    /// The instance's streams the host holds ([`Stream`]), by stream id.
    streams: Mutex<HashMap<u64, Stream>>,
    /// The facts strings its streams were answered ([`HeldFacts`]).
    facts: Mutex<HeldFacts>,
    /// THE DIALS IN FLIGHT: an `ESTABLISH` on a ticket that answered PENDING while its dial
    /// connects, by ticket, closed on the instance's table when the ticket moves on without it.
    dialling: Mutex<HashMap<Ticket, Dial>>,
    /// Every ticketed service's answer ([`Kept`]), by ticket, then by the handle's issue order.
    kept: Mutex<HashMap<Ticket, HashMap<u32, Kept>>>,
    /// Each pending read's original bound, by full completion identity, never restarted by poll.
    waits: Mutex<HashMap<CompletionHandle, ReplyWait>>,
}

#[derive(Clone)]
struct ReplyWait {
    stream: u64,
    binding: Option<Arc<super::export_bindings::Generation>>,
    at: std::time::Instant,
    timer: Arc<OnceLock<ReplyTimer>>,
    /// Shared unregisters a clone's waker when that clone drops; retain the polled registration.
    registered: Arc<Mutex<Option<ReplyTimer>>>,
}

type ReplyTimer = futures::future::Shared<std::pin::Pin<Box<tokio::time::Sleep>>>;

impl ReplyWait {
    fn check(&self, waker: Option<&std::task::Waker>) -> Result<(), ConnError> {
        if std::time::Instant::now() >= self.at {
            return Err(ConnError::Timeout);
        }
        if let Some(waker) = waker.filter(|_| tokio::runtime::Handle::try_current().is_ok()) {
            let mut timer = self
                .timer
                .get_or_init(|| {
                    Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
                        self.at,
                    )))
                    .shared()
                })
                .clone();
            let ready = std::pin::Pin::new(&mut timer)
                .poll(&mut std::task::Context::from_waker(waker))
                .is_ready();
            let previous = lock(&self.registered).replace(timer);
            drop(previous);
            if ready {
                return Err(ConnError::Timeout);
            }
        }
        Ok(())
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) struct Kept {
    answer: Answered,
    read: Option<Wrote>,
    delivered: bool,
}

enum Wrote {
    Reply(ReplyPiece, Box<[u8]>),

    Raw(Box<[u8]>),

    Facts(KeptFacts),
}

struct KeptFacts {
    stream: u64,
    secure: u32,
    client_identity: u32,
    agreed_protocol: Option<Box<str>>,
    peer_cert_hash: Option<Box<str>>,
    peer_key_pin: Option<Box<str>>,
}

impl From<Answered> for Kept {
    fn from(answer: Answered) -> Self {
        Self {
            answer,
            read: None,
            delivered: false,
        }
    }
}

impl ConnState {
    pub(crate) fn declare_needs(
        &self,
        ctx: HostCtx,
        needs: &[busbar_contract::abi::mechanism::rendering::ReadNeed],
    ) {
        let _ = self.context.set(ctx);
        let _ = self
            .need_timeouts
            .set(needs.iter().map(|n| n.timeout_ms).collect());
    }

    fn need_timeout(&self, need: NeedId) -> u64 {
        self.need_timeouts
            .get()
            .and_then(|needs| needs.get(need.0 as usize))
            .copied()
            .unwrap_or(0)
    }

    fn record_raw(
        &self,
        id: InstanceId,
        table: &Arc<dyn DeclaredConns>,
        conn: ConnId,
        reply_timeout_ms: u64,
    ) {
        self.streams().entry(conn.0).or_insert(Stream {
            authority: Authority::capture(id, table),
            conn: Conn::Open(conn),
            headed: false,
            ended: false,
            reply_timeout_ms,
        });
    }

    fn wait_reply(&self, mut handle: CompletionHandle, stream: u64) -> Result<(), ConnError> {
        if handle.ticket.is_none() {
            return Ok(());
        }
        let streams = self.streams();
        let timeout_ms = streams.get(&stream).map_or(0, |s| s.reply_timeout_ms);
        if timeout_ms == 0 {
            return Ok(());
        }
        let Some(at) =
            std::time::Instant::now().checked_add(std::time::Duration::from_millis(timeout_ms))
        else {
            return Ok(());
        };
        handle._reserved = 0;
        let wait = lock(&self.waits)
            .entry(handle)
            .or_insert_with(|| ReplyWait {
                stream,
                binding: streams
                    .get(&stream)
                    .and_then(|s| s.authority.binding.clone()),
                at,
                timer: Arc::default(),
                registered: Arc::default(),
            })
            .clone();
        drop(streams);
        if wait.stream != stream {
            return Err(ConnError::Refused);
        }
        let waker = self
            .context
            .get()
            .and_then(|ctx| ticket_waker(*ctx, handle.ticket));
        wait.check(waker.as_ref())
    }

    fn take_waits(&self, gone: impl Fn(&CompletionHandle, &ReplyWait) -> bool) -> Vec<ReplyWait> {
        let mut all = lock(&self.waits);
        let keys: Vec<_> = all
            .iter()
            .filter(|(h, w)| gone(h, w))
            .map(|(h, _)| *h)
            .collect();
        keys.iter().filter_map(|h| all.remove(h)).collect()
    }

    fn streams(&self) -> MutexGuard<'_, HashMap<u64, Stream>> {
        lock(&self.streams)
    }

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
            .get_mut(&h.ticket)
            .and_then(|issued| issued.get_mut(&h.seq))
        {
            let answer = match (replay, &k.read) {
                (Some(input), Some(Wrote::Reply(piece, bytes))) => {
                    replay_read(input, k.answer, *piece, bytes)
                }
                (Some(input), Some(Wrote::Raw(bytes))) => replay_raw(input, k.answer, bytes),
                (Some(input), Some(Wrote::Facts(f))) => self.replay_facts(input, k.answer, f),
                _ => k.answer,
            };
            k.delivered = answer.outcome == k.answer.outcome
                && answer.needed_bytes == 0
                && answer.needed_items == 0;
            return answer;
        }
        let mut k = run();
        let a = k.answer;
        if a.outcome != Outcome::Pending {
            let waits =
                self.take_waits(|handle, _| handle.ticket == h.ticket && handle.seq == h.seq);
            drop(waits);
            k.delivered = a.needed_bytes == 0 && a.needed_items == 0;
            lock(&self.kept)
                .entry(h.ticket)
                .or_default()
                .insert(h.seq, k);
        }
        a
    }

    fn replay_facts(&self, input: *const c_void, answer: Answered, kept: &KeptFacts) -> Answered {
        // SAFETY: `slot` checked the head covers a `FactsIn`.
        let i = unsafe { input.cast::<FactsIn>().read_unaligned() };
        if i.facts.is_null() {
            return Answered::fault();
        }
        let mut all = lock(&self.facts);
        let open = all.contains_key(&kept.stream);
        let mut text = |t: &Option<Box<str>>| match t {
            Some(t) if open => held_text(&mut all, kept.stream, Some(t)),
            Some(t) => AbiStr {
                ptr: t.as_ptr(),
                len: t.len(),
            },
            None => held_text(&mut all, kept.stream, None),
        };
        let written = StreamFacts {
            size: size_of::<StreamFacts>() as u32,
            secure: kept.secure,
            endpoint: text(&None),
            agreed_protocol: text(&kept.agreed_protocol),
            peer_cert_hash: text(&kept.peer_cert_hash),
            peer_key_pin: text(&kept.peer_key_pin),
            client_identity: kept.client_identity,
            _reserved: 0,
        };
        // SAFETY: the caller's `facts`, checked non-NULL, live for the call.
        unsafe { i.facts.write_unaligned(written) };
        answer
    }

    fn forget(&self, table: Option<&ArmedConns>, ticket: Ticket) -> (usize, Closes) {
        let closes = self.take_dialling(table, |t| *t == ticket);
        let kept = lock(&self.kept)
            .remove(&ticket)
            .map_or(0, |issued| issued.len());
        (kept, closes)
    }

    pub(crate) fn retire(
        &self,
        ticket: Ticket,
        handles: &[busbar_contract::abi::sdk::completion_retirement::Handle],
        detach: impl FnOnce() -> Result<(), ()>,
    ) -> Result<Vec<Kept>, ()> {
        use busbar_contract::abi::sdk::completion_retirement::Domain;
        let mut all = lock(&self.kept);
        for handle in handles {
            let entry = all
                .get(&ticket)
                .and_then(|entries| entries.get(&handle.seq));
            match handle.domain {
                Domain::Connector if !entry.is_some_and(|kept| kept.delivered) => return Err(()),
                Domain::Host if entry.is_some() => return Err(()),
                _ => {}
            }
        }
        let mut removed = Vec::with_capacity(handles.len());
        detach()?;
        if let Some(entries) = all.get_mut(&ticket) {
            for handle in handles.iter().filter(|h| h.domain == Domain::Connector) {
                removed.push(
                    entries
                        .remove(&handle.seq)
                        .expect("validated connector result"),
                );
            }
            if entries.is_empty() {
                all.remove(&ticket);
            }
        }
        Ok(removed)
    }
}

fn replay_read(input: *const c_void, answer: Answered, piece: ReplyPiece, kept: &[u8]) -> Answered {
    // SAFETY: `slot` checked the head covers a `ReplyIn`.
    let i = unsafe { input.cast::<ReplyIn>().read_unaligned() };
    // SAFETY: the caller's buffer, lent for this call only.
    let (false, Some(buf)) = (i.piece.is_null(), unsafe { bytes(i.buf, i.len) }) else {
        return Answered::fault();
    };
    if kept.len() > buf.len() {
        return Answered {
            needed_bytes: kept.len() as u64,
            ..Answered::bare(Outcome::Failed, super::services::SHORT)
        };
    }
    buf[..kept.len()].copy_from_slice(kept);
    // SAFETY: the caller's descriptor slot, checked non-NULL.
    unsafe { i.piece.write_unaligned(piece) };
    answer
}

fn replay_raw(input: *const c_void, answer: Answered, kept: &[u8]) -> Answered {
    // SAFETY: `slot` checked the head covers an `IoIn`.
    let i = unsafe { input.cast::<IoIn>().read_unaligned() };
    // SAFETY: the caller's buffer, lent for this call only.
    let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
        return Answered::fault();
    };
    if kept.len() > buf.len() {
        return Answered {
            needed_bytes: kept.len() as u64,
            ..Answered::bare(Outcome::Failed, super::services::SHORT)
        };
    }
    buf[..kept.len()].copy_from_slice(kept);
    answer
}

pub(crate) struct Forgotten {
    _closes: Closes,
    _binding: Option<super::export_bindings::Forgotten>,
}

pub(crate) fn forget(id: InstanceId, ticket: Ticket) -> (usize, Forgotten) {
    super::handle::supplier_of(id).map_or_else(
        || {
            (
                0,
                Forgotten {
                    _closes: Closes::default(),
                    _binding: None,
                },
            )
        },
        |w| {
            let binding = w.exports.forget(w, ticket);
            let conn = binding
                .binding()
                .and_then(|b| b.conn.as_ref())
                .or_else(|| w.conn.get());
            let (kept, closes) = w.conn_state.forget(conn, ticket);
            (
                kept,
                Forgotten {
                    _closes: closes,
                    _binding: Some(binding),
                },
            )
        },
    )
}

pub(crate) fn forget_worker(ids: &[InstanceId], worker: u32) {
    let gone = |t: &Ticket| super::ticket::decode(t.slot).0 == worker;
    for w in ids.iter().filter_map(|id| super::handle::supplier_of(*id)) {
        for (ticket, binding) in w.exports.worker_pins(worker) {
            drop(w.conn_state.forget(binding.conn.as_ref(), ticket));
        }
        w.conn_state.drop_dialling(w.conn.get(), gone);
        lock(&w.conn_state.kept).retain(|t, _| !gone(t));
    }
}

pub(crate) fn purge(id: InstanceId, table: &Arc<dyn DeclaredConns>) {
    if let Some(w) = super::handle::supplier_of(id) {
        let st = &w.conn_state;
        st.drop_dialling(w.conn.get(), |_| true);

        *lock(&st.facts) = HashMap::new();
        *lock(&st.kept) = HashMap::new();
        let gone = std::mem::take(&mut *st.streams());
        drop(Closes {
            streams: gone.into_values().collect(),
            waits: st.take_waits(|_, _| true),
            ..Closes::default()
        });
    }
    forget_authority(id, table);
}

pub(crate) fn forget_authority(id: InstanceId, table: &Arc<dyn DeclaredConns>) {
    if let Some(wake) = super::handle::supplier_of(id) {
        if wake.conn.get().is_some_and(|(original, _)| *original == id)
            && wake
                .conn_forgotten
                .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
    }
    table.forget(id);
}

const HELD: u64 = 1 << 63;

pub const REQUEST_HELD_MAX: usize = 16 * 1024 * 1024;

/// A request's head, held until its end.
#[derive(Debug, Clone)]
struct Head {
    method: Vec<u8>,
    target: Vec<u8>,
    fields: Vec<(String, Vec<u8>)>,
    timeout_ms: u64,
    dial_timeout_ms: u64,
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
        dial_timeout_ms: u64,
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
    reply_timeout_ms: u64,
    /// The reply's head was read.
    headed: bool,
    /// The reply's terminal piece was read.
    ended: bool,
    // Drop auth/open state before releasing its creating generation.
    authority: Authority,
}

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

fn held_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    HELD | NEXT.fetch_add(1, Ordering::Relaxed)
}

fn resolve(
    st: &ConnState,
    id: InstanceId,
    table: &Arc<dyn DeclaredConns>,
    stream: u64,
) -> Result<ConnId, ConnError> {
    if stream & HELD == 0 {
        return Ok(ConnId(stream));
    }
    let (need, target, within, member, dial_timeout_ms) = {
        let mut all = st.streams();
        let s = all.get_mut(&stream).ok_or(ConnError::Closed)?;
        match &mut s.conn {
            Conn::Open(c) => return Ok(*c),
            Conn::Failed(e) => return Err(*e),
            Conn::Held { head: Some(_), .. } | Conn::Authing(_) | Conn::Opening => {
                return Err(ConnError::Refused);
            }
            Conn::Held {
                need,
                target,
                within,
                member,
                dial_timeout_ms,
                ..
            } => {
                let taken = (
                    *need,
                    std::mem::take(target),
                    std::mem::take(within),
                    std::mem::take(member),
                    *dial_timeout_ms,
                );
                s.conn = Conn::Opening;
                taken
            }
        }
    };

    let desc = OpenDesc {
        target: &target,
        within: &within,
        member: &member,
        ..OpenDesc::default()
    };
    let opened = table.open_request(id, need, &desc, false, dial_timeout_ms);
    install(
        st,
        id,
        stream,
        table,
        opened.map_or_else(Conn::Failed, Conn::Open),
    );
    opened
}

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
                dial_timeout_ms,
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
                        dial_timeout_ms: *dial_timeout_ms,
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

                    let need = *need;
                    let (target, within, member, body) = (
                        std::mem::take(target),
                        std::mem::take(within),
                        std::mem::take(member),
                        std::mem::take(body),
                    );
                    s.conn = Conn::Opening;
                    drop(all);

                    let mut scope = None;

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

                    let bound = if waived {
                        None
                    } else {
                        table.auth_of(id, need, &member, &target)
                    };

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
                                    Some(Fields::Refused) => Conn::Failed(ConnError::AuthRefused),
                                    Some(Fields::Failed) => Conn::Failed(ConnError::AuthFailed),
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
        .filter(|f| !f.query)
        .map(|f| String::from_utf8_lossy(&f.name).into_owned())
        .collect();
    let queries: Vec<_> = seal.map_or_else(Vec::new, |seal| {
        auth.iter()
            .filter(|f| f.query)
            .map(|f| f.query_pair(seal))
            .collect()
    });
    if let Some(seal) = seal {
        for (name, f) in names.iter().zip(auth.iter().filter(|f| !f.query)) {
            fields.push((name.as_str(), f.value.expose(seal).as_slice()));
        }
        fields.extend(queries.iter().map(|pair| {
            (
                busbar_contract::conn::SEALED_QUERY_FIELD,
                pair.expose(seal).as_slice(),
            )
        }));
    }
    fields.extend(
        h.fields
            .iter()
            .filter(|(n, _)| !busbar_contract::conn::is_sealed_query_field(n.as_bytes()))
            .filter(|(n, _)| !names.iter().any(|a| a.eq_ignore_ascii_case(n)))
            .map(|(n, v)| (n.as_str(), v.as_slice())),
    );
    let desc = OpenDesc {
        target,
        fields: &fields,

        body: body.into(),
        timeout_ms: h.timeout_ms,
        method: &h.method,
        head_target: &h.target,
        within,
        member,
        unit: 0,
    };
    table
        .open_request(
            id,
            need,
            &desc,
            auth.iter().any(|f| f.require_secure),
            h.dial_timeout_ms,
        )
        .map_or_else(Conn::Failed, Conn::Open)
}

fn completing(
    table: &Arc<dyn DeclaredConns>,
    id: InstanceId,
    need: NeedId,
    target: &str,
    h: &Head,
    body: &[u8],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    table
        .request_head(id, need, target)
        .completing(
            |name| {
                h.fields
                    .iter()
                    .any(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
            },
            body.len(),
        )
        .into_iter()
        .filter(|(name, _)| !busbar_contract::conn::is_sealed_query_field(name))
        .collect()
}

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
                .filter(|(name, _)| !busbar_contract::conn::is_sealed_query_field(name.as_bytes()))
                .map(|(n, v)| (n.as_bytes().to_vec(), v.clone()))
                .chain(
                    added
                        .iter()
                        .filter(|(name, _)| !busbar_contract::conn::is_sealed_query_field(name))
                        .cloned(),
                )
                .collect()
        } else {
            Vec::new()
        },
        caller_credential,
        extensions: busbar_contract::abi::auth::scope_extensions(scope.as_deref()),
        ..FieldsRequest::default()
    })
}

fn ticket_waker(ctx: HostCtx, ticket: Ticket) -> Option<std::task::Waker> {
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
            if let Err(error) = st.wait_reply(head.handle, i.stream) {
                if let Some(stream) = st.streams().get_mut(&i.stream) {
                    stream.ended = true;
                }
                return Kept::from(refusal(error));
            }
            let (piece, answer) = reply(ctx, st, id, table, head, i.stream, buf);
            let mut read = None;
            if let Some(p) = piece {
                // SAFETY: the caller's descriptor slot, checked non-NULL.
                unsafe { i.piece.write_unaligned(p) };

                if answer.outcome != Outcome::Pending && !head.handle.ticket.is_none() {
                    let n = usize::try_from(answer.len).map_or(buf.len(), |n| n.min(buf.len()));
                    read = Some(Wrote::Reply(p, buf[..n].into()));
                }
            }
            Kept {
                answer,
                read,
                delivered: false,
            }
        },
    )
}

fn reply(
    ctx: HostCtx,
    st: &ConnState,
    id: InstanceId,
    table: &Arc<dyn DeclaredConns>,
    head: ServiceHead,
    stream: u64,
    buf: &mut [u8],
) -> (Option<ReplyPiece>, Answered) {
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
            Fields::Refused => Conn::Failed(ConnError::AuthRefused),
            Fields::Failed => Conn::Failed(ConnError::AuthFailed),
        };
        install(st, id, stream, table, opened);
    }
    {
        let mut all = st.streams();
        let s = all.entry(stream).or_insert(Stream {
            authority: Authority::capture(id, table),
            conn: Conn::Open(ConnId(stream)),
            reply_timeout_ms: 0,
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
                );
            }
            Conn::Failed(e) => {
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
                );
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
                s.ended = true;
                drop(all);
                (None, refusal_of(e, id, table, conn))
            }
        };
    }
}

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

service!(
    identity,
    slot,
    service::IDENTITY,
    IdentityIn,
    |_, _, _, _, i| {
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
    }
);

#[cfg(test)]
#[path = "../tests/conn_services_tests.rs"]
mod tests;

#[cfg(test)]
mod retirement_tests {
    use super::*;
    use busbar_contract::abi::sdk::completion_retirement::{Acknowledgement, Domain, Handle};

    #[test]
    fn consumed_read_bytes_retire_while_another_operation_stays_pending() {
        let store = super::super::services::ServiceStore::default();
        let wake = Box::leak(Box::<InstanceWake>::default());
        let caller = std::ptr::from_ref(wake) as usize;
        let ticket = Ticket {
            slot: 1,
            generation: 2,
        };
        store.held.track(ticket);
        let owner = HostCtx { handle: 9 };
        let pending = CompletionHandle {
            ticket,
            seq: 3,
            ..CompletionHandle::ZERO
        };
        assert!(store.held.call(caller, Domain::Connector, pending));
        store
            .held
            .answered(caller, Domain::Connector, pending, true);
        let handle = CompletionHandle {
            ticket,
            seq: 4,
            ..CompletionHandle::ZERO
        };
        for byte in [1, 2, 3] {
            let capability = store.retirement_input(caller, owner, ticket).unwrap();
            assert!(store.held.call(caller, Domain::Connector, handle));
            let answer = wake.conn_state.kept(handle, None, || Kept {
                answer: Answered::ready(0, 4),
                read: Some(Wrote::Raw(vec![byte; 4].into())),
                delivered: false,
            });
            store.held.answered(
                caller,
                Domain::Connector,
                handle,
                answer.outcome == Outcome::Pending,
            );
            assert_eq!(lock(&wake.conn_state.kept).get(&ticket).unwrap().len(), 1);
            store
                .retire_results(
                    wake,
                    &Acknowledgement {
                        capability,
                        handles: vec![Handle {
                            domain: Domain::Connector,
                            seq: 4,
                        }],
                    },
                )
                .unwrap();
            assert!(lock(&wake.conn_state.kept).get(&ticket).is_none());
            assert_eq!(
                store.held.held(ticket),
                1,
                "the independent operation is still pending"
            );
        }
    }

    #[test]
    fn a_short_replay_cannot_retire_its_required_full_result() {
        let store = super::super::services::ServiceStore::default();
        let wake = Box::leak(Box::<InstanceWake>::default());
        let caller = std::ptr::from_ref(wake) as usize;
        let ticket = Ticket {
            slot: 1,
            generation: 2,
        };
        store.held.track(ticket);
        let capability = store
            .retirement_input(caller, HostCtx { handle: 9 }, ticket)
            .unwrap();
        let handle = CompletionHandle {
            ticket,
            seq: 4,
            ..CompletionHandle::ZERO
        };
        assert!(store.held.call(caller, Domain::Connector, handle));
        wake.conn_state.kept(handle, None, || Kept {
            answer: Answered::ready(0, 4),
            read: Some(Wrote::Raw(b"data".to_vec().into())),
            delivered: false,
        });
        let mut input = IoIn {
            head: ServiceHead::ZERO,
            stream: 1,
            buf: std::ptr::null_mut(),
            len: 0,
        };
        let answer = wake
            .conn_state
            .kept(handle, Some(std::ptr::from_ref(&input).cast()), || {
                panic!("a replay cannot read twice")
            });
        assert_eq!(answer.needed_bytes, 4);
        store
            .held
            .answered(caller, Domain::Connector, handle, false);
        let ack = Acknowledgement {
            capability,
            handles: vec![Handle {
                domain: Domain::Connector,
                seq: 4,
            }],
        };
        assert_eq!(store.retire_results(wake, &ack), Err(()));
        let mut bytes = [0; 4];
        input.buf = bytes.as_mut_ptr();
        input.len = bytes.len();
        let answer = wake
            .conn_state
            .kept(handle, Some(std::ptr::from_ref(&input).cast()), || {
                panic!("the full replay still reads once")
            });
        assert_eq!(answer.outcome, Outcome::Ready);
        assert_eq!(&bytes, b"data");
        store.retire_results(wake, &ack).unwrap();
    }
}

#[cfg(test)]
mod creating_authority_tests {
    use super::*;
    use busbar_contract::conn::{ConnSlab, Conns, Piece};
    use busbar_contract::transport::ConnFacts;

    #[derive(Default)]
    struct Table {
        slab: ConnSlab<()>,
        closed: Mutex<Vec<(InstanceId, ConnId)>>,
        forgotten: Mutex<Vec<InstanceId>>,
        state: OnceLock<&'static ConnState>,
    }

    impl Conns for Table {
        fn open(
            &self,
            owner: InstanceId,
            need: NeedId,
            _: &OpenDesc<'_>,
        ) -> Result<ConnId, ConnError> {
            self.slab.insert(owner, need, ())
        }
        fn write(
            &self,
            owner: InstanceId,
            conn: ConnId,
            bytes: &[u8],
            _: bool,
            _: bool,
        ) -> Result<usize, ConnError> {
            self.slab.get(owner, conn)?;
            Ok(bytes.len())
        }
        fn read(
            &self,
            owner: InstanceId,
            conn: ConnId,
            _: u64,
            _: &mut [u8],
        ) -> Result<Piece, ConnError> {
            self.slab.get(owner, conn)?;
            Err(ConnError::Closed)
        }
        fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
            Err(ConnError::Pending)
        }
        fn facts(&self, owner: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
            self.slab.get(owner, conn)?;
            Ok(ConnFacts::default())
        }
        fn close(&self, owner: InstanceId, conn: ConnId) -> Result<(), ConnError> {
            if let Some(state) = self.state.get() {
                assert!(state.streams.try_lock().is_ok());
                assert!(state.dialling.try_lock().is_ok());
                assert!(state.waits.try_lock().is_ok());
            }
            self.slab.remove(owner, conn)?;
            lock(&self.closed).push((owner, conn));
            Ok(())
        }
    }
    impl DeclaredConns for Table {
        fn declare(
            &self,
            owner: InstanceId,
            need: NeedId,
            _: &busbar_contract::abi::mechanism::rendering::ReadNeed,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(), ConnError> {
            self.slab.declare(owner, need);
            Ok(())
        }
        fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
            Some(self.slab.check_need(owner, need))
        }
        fn serves_scheme(&self, _: &str) -> bool {
            true
        }
        fn forget(&self, owner: InstanceId) {
            lock(&self.forgotten).push(owner);
        }
        fn upgrade_secure(
            &self,
            owner: InstanceId,
            conn: ConnId,
            _: Option<&str>,
            _: Option<&str>,
            _: bool,
            _: u64,
        ) -> Result<(), ConnError> {
            self.slab.get(owner, conn)?;
            Ok(())
        }
    }

    fn generation(
        owner: InstanceId,
        table: &Arc<dyn DeclaredConns>,
    ) -> Arc<super::super::export_bindings::Generation> {
        Arc::new(super::super::export_bindings::Generation {
            conn: Some((owner, table.clone())),
            destinations: Vec::new(),
        })
    }

    #[test]
    fn published_refresh_keeps_raw_held_and_pending_dials_on_their_creating_authority() {
        let wake = Box::leak(Box::<InstanceWake>::default());
        let ctx = super::super::handle::mint(wake).unwrap();
        let old_owner = super::super::handle::instance_id(ctx);
        let new_owner = InstanceId(u64::MAX - 1);
        let actual = Arc::new(Table::default());
        let table: Arc<dyn DeclaredConns> = actual.clone();
        assert!(wake.conn.set((old_owner, table.clone())).is_ok());
        assert!(actual.state.set(&wake.conn_state).is_ok());
        for owner in [old_owner, new_owner] {
            actual.slab.declare(owner, NeedId(0));
        }
        let old = generation(old_owner, &table);
        let new = generation(new_owner, &table);
        let raw = table
            .open(old_owner, NeedId(0), &OpenDesc::default())
            .unwrap();
        let pending = table
            .open(old_owner, NeedId(0), &OpenDesc::default())
            .unwrap();
        let held = held_id();
        let ticket = Ticket {
            slot: 6,
            generation: 2,
        };
        super::super::export_bindings::crossing(Some(old.clone()), || {
            wake.conn_state.record_raw(old_owner, &table, raw, 0);
            wake.conn_state.streams().insert(
                held,
                Stream {
                    conn: Conn::Held {
                        need: NeedId(0),
                        target: String::new(),
                        within: Vec::new(),
                        member: String::new(),
                        dial_timeout_ms: 0,
                        head: None,
                        body: Vec::new(),
                    },
                    headed: false,
                    ended: false,
                    reply_timeout_ms: 0,
                    authority: Authority::capture(old_owner, &table),
                },
            );
            lock(&wake.conn_state.dialling).insert(
                ticket,
                Dial {
                    wanted: (NeedId(0), String::new(), Vec::new(), String::new(), 0),
                    conn: pending,
                    authority: Authority::capture(old_owner, &table),
                },
            );
        });
        wake.exports.publish(new.clone());
        // The following services execute in the newly published operation context.
        super::super::export_bindings::crossing(Some(new), || {
            for stream in [raw.0, held] {
                let mut byte = [9];
                // SAFETY: these ABI inputs/outputs contain only plain zero-valid fields; all
                // heads and live payload loans are filled before the actual service call.
                let mut input: IoIn = unsafe { std::mem::zeroed() };
                input.head.size = size_of::<IoIn>() as u32;
                input.head.op = service::WRITE;
                input.stream = stream;
                input.buf = byte.as_mut_ptr();
                input.len = byte.len();
                let mut output: ServiceOut = unsafe { std::mem::zeroed() };
                output.size = size_of::<ServiceOut>() as u32;
                write(ctx, std::ptr::from_ref(&input).cast(), &mut output);
                assert_eq!(output.outcome, RawOutcome::of(Outcome::Ready));
                assert_eq!(output.len, 1);
            }
            let mut input: EstablishIn = unsafe { std::mem::zeroed() };
            input.head.size = size_of::<EstablishIn>() as u32;
            input.head.op = service::ESTABLISH;
            input.head.handle.ticket = ticket;
            let mut output: ServiceOut = unsafe { std::mem::zeroed() };
            output.size = size_of::<ServiceOut>() as u32;
            establish(ctx, std::ptr::from_ref(&input).cast(), &mut output);
            assert_eq!(output.outcome, RawOutcome::of(Outcome::Ready));
            assert_eq!(output.value, pending.0);
            assert_eq!(
                wake.conn_state.stream_authority(pending.0).unwrap().conn.0,
                old_owner
            );
        });
        assert!(!lock(&actual.forgotten).contains(&old_owner));
        assert_eq!(
            wake.conn_state.stream_authority(raw.0).unwrap().conn.0,
            old_owner
        );
        drop(wake.conn_state.retire_binding(&old));
        assert_eq!(lock(&actual.closed).len(), 3);
        assert!(lock(&actual.closed)
            .iter()
            .all(|(owner, _)| *owner == old_owner));
        wake.exports.clear();
    }

    #[test]
    fn candidate_retirement_closes_only_its_streams_dials_and_waits_outside_state_locks() {
        let state = Box::leak(Box::<ConnState>::default());
        let actual = Arc::new(Table::default());
        assert!(actual.state.set(state).is_ok());
        let table: Arc<dyn DeclaredConns> = actual.clone();
        let owners = [InstanceId(u64::MAX - 2), InstanceId(u64::MAX - 3)];
        let old = generation(owners[0], &table);
        let candidate = generation(owners[1], &table);
        let weak = Arc::downgrade(&candidate);
        let mut raw = Vec::new();
        for (owner, binding) in [(owners[0], &old), (owners[1], &candidate)] {
            actual.slab.declare(owner, NeedId(0));
            let conn = table.open(owner, NeedId(0), &OpenDesc::default()).unwrap();
            super::super::export_bindings::crossing(Some(binding.clone()), || {
                state.record_raw(owner, &table, conn, 1000);
            });
            let mut handle: CompletionHandle = unsafe { std::mem::zeroed() };
            handle.ticket = Ticket {
                slot: owner.0 as u32,
                generation: 1,
            };
            state.wait_reply(handle, conn.0).unwrap();
            raw.push(conn);
        }
        let dial = table
            .open(owners[1], NeedId(0), &OpenDesc::default())
            .unwrap();
        lock(&state.dialling).insert(
            Ticket {
                slot: 3,
                generation: 4,
            },
            Dial {
                wanted: (NeedId(0), String::new(), Vec::new(), String::new(), 0),
                conn: dial,
                authority: Authority {
                    conn: (owners[1], table.clone()),
                    binding: Some(candidate.clone()),
                },
            },
        );
        let closes = state.retire_binding(&candidate);
        assert!(
            lock(&actual.closed).is_empty(),
            "detaching does not run table code"
        );
        assert!(state.stream_authority(raw[0].0).is_some());
        assert!(state.stream_authority(raw[1].0).is_none());
        assert_eq!(lock(&state.waits).len(), 1);
        assert!(lock(&state.dialling).is_empty());
        drop(candidate);
        assert!(
            weak.upgrade().is_some(),
            "detached resources retain their authority until close"
        );
        drop(closes);
        assert!(weak.upgrade().is_none());
        assert_eq!(
            *lock(&actual.closed),
            vec![(owners[1], dial), (owners[1], raw[1])]
        );
        assert_eq!(*lock(&actual.forgotten), vec![owners[1]]);
        assert!(actual.slab.get(owners[0], raw[0]).is_ok());
        drop(state.retire_binding(&old));
    }
}
