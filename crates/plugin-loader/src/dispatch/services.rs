// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SERVICES, HOST SIDE (`BUSBAR-1.6.0.md` THE DESIGN, §11.12): the `HostSlots` table every
//! instance is handed ([`HOST_SLOTS`]), and the one mechanism every service runs through.
//!
//! * **Stored once, redeemed on the handle.** A ticketed call runs its service once under its
//!   [`CompletionHandle`] and stores the result. A re-issued handle (a resume, or the re-call a short
//!   answer earns) reads the stored result; nothing runs twice. The store forgets a ticket's results
//!   when the ticket is recycled, a driver ticket's when its next tick starts, and any other
//!   ticket's when a new op (not a short answer's re-call) starts on it.
//! * **The short-buffer rule.** A result that does not fit the caller's buffers answers FAILED with
//!   `needed_bytes`/`needed_items` at their full sizes and writes nothing. The one re-call on the same
//!   handle reads the stored result; a second short answer on that handle is FAULT.
//! * **May pend only on a ticket.** A service that may pend, called with no ticket, is REFUSED and
//!   never runs.
//! * **Served so far:** `clock.now`, `dest.judge`, `records.get`/`records.list`/`records.claim`,
//!   `sign`, `trust.sight`, `trust.due`, `trust.verify`, `records.secret` (to the credential
//!   kinds the caller's Statement declares, [`UNDECLARED_KIND`] otherwise), `work.open` /
//!   `work.find` / `work.settle` / `work.resume` and `unit.nest` (for the unit the crossing
//!   serves) and `disk.append` (to the destinations the caller was granted, [`NO_DESTINATION`]
//!   otherwise). Every other slot answers REFUSED ([`UNIMPLEMENTED`]).
//! * **Who called.** The instance's [`Caller`], stated at bind, is handed to every service that is
//!   scoped to its caller; an instance with none is REFUSED ([`NO_CALLER`]).
//!
//! THE SERVICES THEMSELVES ARE THE KERNEL'S. This file is the mechanism only: the kernel hands the
//! dispatcher its [`HostServices`] at construction, and every slot here dispatches into it. The
//! loader names no kernel crate.

use std::collections::HashMap;
use std::mem::size_of;
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, Weak};

use busbar_contract::abi::host::service::{
    self as svc, check_bufs, check_disk_append_in, check_head, check_random_fill_in,
    check_records_claim_in, check_work_record, may_pend, op, ClockNowIn, ClockReading, DestJudgeIn,
    DiskAppendIn, DiskWritten, EntitlementCheckIn, HostSlots, RandomFillIn, RecordsClaimIn,
    RecordsGetIn, RecordsListIn, RecordsSecretIn, ServiceBufs, ServiceHead, ServiceOut,
    SessionEmitIn, SignIn, TrustDueIn, TrustSightIn, TrustVerifyIn, UnitNestIn, WorkFindIn,
    WorkOpenIn, WorkResumeIn, WorkSettleIn, SERVICES,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::check;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket};

pub use busbar_contract::services::{
    Caller, DiskReport, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Stored,
};

use super::ticket::{decode, InstanceWake, WakeRoute};

/// The error text of a slot this host does not serve yet.
pub const UNIMPLEMENTED: &str = busbar_contract::services::UNSERVED;
/// The error text of a caller-scoped service called from an instance the host states no caller for.
pub const NO_CALLER: &str = "no caller is bound to this instance";
/// The error text of a claim with no time to live.
pub const NO_TTL: &str = "a claim states its time to live";
/// The error text of a may-pend service called with no ticket.
pub const UNTICKETED: &str = "a service that may pend is callable only inside a ticketed op";
/// The error text of a short answer.
pub const SHORT: &str = "the buffer is too small";
/// The refusal of a `random.fill` of no bytes or above `MAX_RANDOM_FILL`, before a byte is drawn.
pub const FILL_OUT_OF_RANGE: &str = "a fill asks for 1 to MAX_RANDOM_FILL bytes";
/// The refusal of a `records.secret` read of a credential kind the calling instance does not
/// declare, before anything is read.
pub const UNDECLARED_KIND: &str = "the caller does not declare that credential kind";
/// The refusal of a `disk.append` to a key the calling instance was not granted (its manifest
/// declares no such destination) or its settings leave unset, before anything is written.
pub const NO_DESTINATION: &str = "the caller was granted no such destination";
/// The error text of the second short answer on one handle.
pub const SECOND_SHORT: &str = "a second short answer on one handle";

// ── the stored results ─────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Entry {
    Running,
    Done { stored: Stored, shorts: u8 },
}

/// The results of one dispatcher's services, by ticket then issue order.
#[derive(Debug, Default)]
pub struct ServiceStore {
    inner: Mutex<HashMap<Ticket, HashMap<u32, Entry>>>,
}

impl ServiceStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Ticket, HashMap<u32, Entry>>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Store a pended service's result; `false` when the handle is not running.
    fn complete(&self, h: CompletionHandle, stored: Stored) -> bool {
        let mut map = self.lock();
        match map.get_mut(&h.ticket).and_then(|t| t.get_mut(&h.seq)) {
            Some(e @ Entry::Running) => {
                *e = Entry::Done { stored, shorts: 0 };
                true
            }
            _ => false,
        }
    }

    /// Forget every result under `ticket` (it was recycled, a driver ticket's tick started, or a
    /// new op started on it); how many there were.
    pub(crate) fn forget(&self, ticket: Ticket) -> usize {
        self.lock().remove(&ticket).map_or(0, |held| held.len())
    }

    /// Forget every result of worker `worker` (it was replaced).
    pub(crate) fn forget_worker(&self, worker: u32) {
        self.lock().retain(|t, _| decode(t.slot).0 != worker);
    }

    /// How many results the store holds.
    #[must_use]
    pub fn held(&self) -> usize {
        self.lock().values().map(HashMap::len).sum()
    }
}

/// The one answer a pended service gives: store the result under its handle, then wake its ticket.
pub struct Completer {
    store: Weak<ServiceStore>,
    route: Weak<dyn WakeRoute>,
    handle: CompletionHandle,
}

impl std::fmt::Debug for Completer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Completer")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl Completer {
    /// Store `stored` and wake the ticket. A handle whose ticket was recycled meanwhile is dropped.
    pub fn complete(self, stored: Stored) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        if store.complete(self.handle, stored) {
            if let Some(route) = self.route.upgrade() {
                route.wake(self.handle.ticket);
            }
        }
    }
}

/// What a dispatcher serves its instances from.
#[derive(Clone)]
pub(crate) struct Served {
    pub(crate) store: Arc<ServiceStore>,
    pub(crate) provider: Arc<dyn HostServices>,
}

// ── the answer ─────────────────────────────────────────────────────────────────────────────────

/// A service's answer, before it is written into the caller's `out`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answered {
    /// The outcome.
    pub outcome: Outcome,
    /// The scalar answer.
    pub value: u64,
    /// Bytes written.
    pub len: u64,
    /// Spans written.
    pub items: u64,
    /// On a short answer: the full byte size.
    pub needed_bytes: u64,
    /// On a short answer: the full span count.
    pub needed_items: u64,
    /// The reason, for FAILED/REFUSED.
    pub error: &'static str,
}

impl Answered {
    fn bare(outcome: Outcome, error: &'static str) -> Self {
        Self {
            outcome,
            value: 0,
            len: 0,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error,
        }
    }

    const fn fault() -> Self {
        Self {
            outcome: Outcome::Fault,
            value: 0,
            len: 0,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: "",
        }
    }
}

/// Write `stored` into the caller's buffers, or answer the short FAILED when it does not fit.
///
/// # Safety
/// `into`'s buffers are the caller's, live and writable for their capacities (checked non-NULL for a
/// capacity by [`check_bufs`]).
unsafe fn deliver(stored: &Stored, into: Option<&ServiceBufs>) -> Result<Answered, Answered> {
    let (cap, spans_cap) = into.map_or((0, 0), |b| (b.cap, b.spans_cap));
    if stored.bytes.len() > cap || stored.spans.len() > spans_cap {
        return Err(Answered {
            needed_bytes: stored.bytes.len() as u64,
            needed_items: stored.spans.len() as u64,
            ..Answered::bare(Outcome::Failed, SHORT)
        });
    }
    if let Some(b) = into {
        // SAFETY: both fit their capacities, checked above; the buffers are the caller's.
        unsafe {
            if !stored.bytes.is_empty() {
                std::ptr::copy_nonoverlapping(stored.bytes.as_ptr(), b.buf, stored.bytes.len());
            }
            for (i, s) in stored.spans.iter().enumerate() {
                b.spans.add(i).write_unaligned(*s);
            }
        }
    }
    Ok(Answered {
        outcome: stored.outcome,
        value: stored.value,
        len: stored.bytes.len() as u64,
        items: stored.spans.len() as u64,
        needed_bytes: 0,
        needed_items: 0,
        error: stored.error,
    })
}

/// THE MECHANISM every service runs through, kind-neutral: `body` is the service itself, run at
/// most once per handle.
///
/// # Safety
/// As [`deliver`].
pub(crate) unsafe fn serve(
    store: &Arc<ServiceStore>,
    route: &Weak<dyn WakeRoute>,
    head: &ServiceHead,
    into: Option<&ServiceBufs>,
    body: impl FnOnce(Option<Completer>) -> Ran,
) -> Answered {
    if head.handle.ticket.is_none() {
        if may_pend(head.op) {
            return Answered::bare(Outcome::Refused, UNTICKETED);
        }
        // A ticketless call is never stored: only a service that never pends gets here, and a
        // re-call re-reads it.
        return match body(None) {
            // SAFETY: the caller's contract.
            Ran::Now(stored) => unsafe { deliver(&stored, into) }.unwrap_or_else(|short| short),
            Ran::Later => Answered::fault(),
        };
    }
    let h = head.handle;
    let fresh = {
        let mut map = store.lock();
        match map.entry(h.ticket).or_default().entry(h.seq) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(Entry::Running);
                true
            }
        }
    };
    if fresh {
        let completer = Completer {
            store: Arc::downgrade(store),
            route: route.clone(),
            handle: h,
        };
        match body(Some(completer)) {
            Ran::Now(stored) => {
                store.complete(h, stored);
            }
            Ran::Later => {}
        }
    }
    let mut map = store.lock();
    match map.get_mut(&h.ticket).and_then(|t| t.get_mut(&h.seq)) {
        Some(Entry::Running) => Answered::bare(Outcome::Pending, ""),
        Some(Entry::Done { stored, shorts }) => {
            if *shorts >= 2 {
                return Answered::bare(Outcome::Fault, SECOND_SHORT);
            }
            // SAFETY: the caller's contract.
            match unsafe { deliver(stored, into) } {
                Ok(a) => a,
                Err(short) => {
                    *shorts += 1;
                    if *shorts >= 2 {
                        Answered::bare(Outcome::Fault, SECOND_SHORT)
                    } else {
                        short
                    }
                }
            }
        }
        // Forgotten under the call: its ticket was recycled.
        None => Answered::fault(),
    }
}

// ── the slots ──────────────────────────────────────────────────────────────────────────────────

/// The table a host hands every instance.
pub static HOST_SLOTS: HostSlots = HostSlots {
    size: size_of::<HostSlots>() as u32,
    slots: SERVICES,
    clock_now: Some(clock_now),
    records_get: Some(records_get),
    records_list: Some(records_list),
    records_claim: Some(records_claim),
    dest_judge: Some(dest_judge),
    sign: Some(sign),
    unit_nest: Some(unit_nest),
    work_open: Some(work_open),
    work_find: Some(work_find),
    work_settle: Some(work_settle),
    work_resume: Some(work_resume),
    trust_sight: Some(trust_sight),
    trust_due: Some(trust_due),
    verify_lookup: Some(verify_lookup),
    verify_store: Some(verify_store),
    entitlement_check: Some(entitlement_check),
    content_scan: Some(content_scan),
    hook_call: Some(hook_call),
    random_fill: Some(random_fill),
    need_admit: Some(need_admit),
    trust_verify: Some(trust_verify),
    records_secret: Some(records_secret),
    disk_append: Some(disk_append),
    session_emit: Some(session_emit),
};

/// The dispatcher an instance's context routes to, and what it serves.
fn served(ctx: HostCtx) -> Option<(Served, Weak<dyn WakeRoute>)> {
    if ctx.ptr.is_null() {
        return None;
    }
    // SAFETY: every `HostCtx` the host hands out points to a leaked `InstanceWake`.
    let wake = unsafe { &*ctx.ptr.cast_const().cast::<InstanceWake>() };
    let route = wake.route.get()?.clone();
    let served = route.upgrade()?.services()?;
    Some((served, route))
}

/// The caller an instance's context names; `None` before bind stated one.
fn caller(ctx: HostCtx) -> Option<Caller> {
    if ctx.ptr.is_null() {
        return None;
    }
    // SAFETY: every `HostCtx` the host hands out points to a leaked `InstanceWake`.
    let wake = unsafe { &*ctx.ptr.cast_const().cast::<InstanceWake>() };
    wake.caller.get().cloned()
}

/// A checked range of the caller's, copied: `None` for NULL with a length.
fn bytes_of(s: AbiStr, field: &'static str) -> Option<Vec<u8>> {
    check::text(s, field).ok()?;
    if s.len == 0 {
        return Some(Vec::new());
    }
    // SAFETY: a checked range of the caller's, live for the call; copied before any pend.
    Some(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }.to_vec())
}

/// A checked blob of the caller's, copied: `None` for NULL with a length.
fn blob_of(b: Blob, field: &'static str) -> Option<Vec<u8>> {
    check::listed(b.ptr, b.len, field).ok()?;
    if b.len == 0 {
        return Some(Vec::new());
    }
    // SAFETY: a checked range of the caller's, live for the call; copied before any pend.
    Some(unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec())
}

/// A checked UTF-8 string of the caller's, copied: `None` for NULL with a length or bad UTF-8.
fn text_of(s: AbiStr, field: &'static str) -> Option<String> {
    String::from_utf8(bytes_of(s, field)?).ok()
}

/// The [`Later`] a ticketed service's completer answers through.
fn later_of(completer: Option<Completer>) -> Option<Later> {
    completer.map(|c| -> Later { Box::new(move |s| c.complete(s)) })
}

/// ONE SLOT'S FRAME: the `in` and `out` are there, the head is this service's and covers its `in`,
/// a may-pend service has a ticket, then `body`. A panic answers FAULT; the whole `out` is written.
fn slot(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    in_size: usize,
    body: impl FnOnce(Served, Weak<dyn WakeRoute>, ServiceHead) -> Answered,
) -> RawOutcome {
    framed(input, out, service, in_size, |head| match served(ctx) {
        Some((served, route)) => body(served, route, head),
        None => Answered::bare(Outcome::Refused, "no host services are bound"),
    })
}

/// [`slot`]'s frame, for a service the kernel does not serve (the connection table answers it):
/// the `in` and `out` are there, the head is this service's and covers its `in`, a may-pend
/// service has a ticket, then `body`. A panic answers FAULT; the whole `out` is written.
fn framed(
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    in_size: usize,
    body: impl FnOnce(ServiceHead) -> Answered,
) -> RawOutcome {
    let a = catch_unwind(AssertUnwindSafe(|| {
        if input.is_null() || out.is_null() {
            return Answered::fault();
        }
        // SAFETY: a non-NULL `in` leads with its head (the call shape).
        let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
        if check_head(&head, service, in_size).is_err() {
            return Answered::fault();
        }
        if may_pend(service) && head.handle.ticket.is_none() {
            return Answered::bare(Outcome::Refused, UNTICKETED);
        }
        body(head)
    }))
    .unwrap_or_else(|_| Answered::fault());
    if !out.is_null() {
        let o = ServiceOut {
            size: size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(a.outcome),
            _reserved: [0; 3],
            value: a.value,
            len: a.len,
            items: a.items,
            needed_bytes: a.needed_bytes,
            needed_items: a.needed_items,
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

extern "C" fn clock_now(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        op::CLOCK_NOW,
        size_of::<ClockNowIn>(),
        |served, _, _| {
            // SAFETY: the head covered a `ClockNowIn`.
            let i = unsafe { input.cast::<ClockNowIn>().read_unaligned() };
            if i.reading.is_null() {
                return Answered::fault();
            }
            let r = served.provider.now();
            // SAFETY: the caller's reading slot, checked non-NULL.
            unsafe {
                i.reading.write_unaligned(ClockReading {
                    size: size_of::<ClockReading>() as u32,
                    _reserved: 0,
                    wall_ns: r.wall_ns,
                    mono_ns: r.mono_ns,
                });
            }
            Answered::bare(Outcome::Ready, "")
        },
    )
}

extern "C" fn dest_judge(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        op::DEST_JUDGE,
        size_of::<DestJudgeIn>(),
        |served, route, head| {
            // SAFETY: the head covered a `DestJudgeIn`.
            let i = unsafe { input.cast::<DestJudgeIn>().read_unaligned() };
            if check::text(i.dest, "dest_judge.dest").is_err()
                || check::bits(
                    u64::from(i.flags),
                    u64::from(svc::DEST_RESOLVE | svc::DEST_REFUSE_PRIVATE | svc::DEST_EXPLAIN),
                    "dest_judge.flags",
                )
                .is_err()
                || check_bufs(&i.into).is_err()
            {
                return Answered::fault();
            }
            // SAFETY: a checked range of the caller's, live for the call; copied before any pend.
            let dest = if i.dest.len == 0 {
                String::new()
            } else {
                String::from_utf8_lossy(unsafe {
                    std::slice::from_raw_parts(i.dest.ptr, i.dest.len)
                })
                .into_owned()
            };
            let provider = Arc::clone(&served.provider);
            // SAFETY: `into` checked above; the caller's buffers, where the judged addresses go.
            unsafe {
                serve(&served.store, &route, &head, Some(&i.into), |completer| {
                    let later = completer.map(|c| -> Later { Box::new(move |s| c.complete(s)) });
                    provider.dest_judge(&dest, i.egress_class, i.flags, later)
                })
            }
        },
    )
}

/// A caller-scoped slot's frame: [`slot`], then the instance's [`Caller`] or REFUSED.
fn scoped(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    in_size: usize,
    body: impl FnOnce(Served, Weak<dyn WakeRoute>, ServiceHead, Caller) -> Answered,
) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service,
        in_size,
        |served, route, head| match caller(ctx) {
            Some(c) => body(served, route, head, c),
            None => Answered::bare(Outcome::Refused, NO_CALLER),
        },
    )
}

/// Run a may-pend service under the mechanism: `run` gets the completer's [`Later`], which a
/// ticketed call always has.
///
/// # Safety
/// As [`deliver`].
unsafe fn pended(
    served: &Served,
    route: &Weak<dyn WakeRoute>,
    head: &ServiceHead,
    into: Option<&ServiceBufs>,
    run: impl FnOnce(Later) -> Ran,
) -> Answered {
    // SAFETY: the caller's contract.
    unsafe {
        serve(
            &served.store,
            route,
            head,
            into,
            |completer| match later_of(completer) {
                Some(later) => run(later),
                None => Ran::Now(Stored::refused(UNTICKETED)),
            },
        )
    }
}

extern "C" fn records_get(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::RECORDS_GET,
        size_of::<RecordsGetIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `RecordsGetIn`.
            let i = unsafe { input.cast::<RecordsGetIn>().read_unaligned() };
            let (Some(kind), Some(key)) = (
                text_of(i.kind, "records_get.kind"),
                bytes_of(i.key, "records_get.key"),
            ) else {
                return Answered::fault();
            };
            if check_bufs(&i.into).is_err() {
                return Answered::fault();
            }
            let provider = Arc::clone(&served.provider);
            // SAFETY: `into` checked above; the caller's buffers.
            unsafe {
                pended(&served, &route, &head, Some(&i.into), |later| {
                    provider.records_get(&caller, &kind, &key, later)
                })
            }
        },
    )
}

/// The credential kinds an instance's context declares it reads; none before bind stated them.
fn credential_kinds(ctx: HostCtx) -> &'static [String] {
    if ctx.ptr.is_null() {
        return &[];
    }
    // SAFETY: every `HostCtx` the host hands out points to a leaked (`'static`) `InstanceWake`.
    let wake: &'static InstanceWake = unsafe { &*ctx.ptr.cast_const().cast::<InstanceWake>() };
    wake.credential_kinds.get().map_or(&[], Vec::as_slice)
}

extern "C" fn records_secret(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        op::RECORDS_SECRET,
        size_of::<RecordsSecretIn>(),
        |served, route, head| {
            // SAFETY: the head covered a `RecordsSecretIn`.
            let i = unsafe { input.cast::<RecordsSecretIn>().read_unaligned() };
            let (Some(kind), Some(id)) = (
                text_of(i.kind, "records_secret.kind"),
                text_of(i.id, "records_secret.id"),
            ) else {
                return Answered::fault();
            };
            if check_bufs(&i.into).is_err() {
                return Answered::fault();
            }
            // THE DECLARED NEED: the caller's Statement names the kinds it reads; every other kind,
            // and every caller that names none (any non-auth instance), is refused before the
            // kernel reads anything.
            if !credential_kinds(ctx).contains(&kind) {
                return Answered::bare(Outcome::Refused, UNDECLARED_KIND);
            }
            let provider = Arc::clone(&served.provider);
            // SAFETY: `into` checked above; the caller's buffers.
            unsafe {
                pended(&served, &route, &head, Some(&i.into), |later| {
                    provider.records_secret(&kind, &id, later)
                })
            }
        },
    )
}

/// The destination the calling instance's `key` is bound to; `None` when it was granted no such
/// key, or its settings leave it unset.
fn destination(ctx: HostCtx, key: &str) -> Option<busbar_contract::services::DiskDest> {
    if ctx.ptr.is_null() {
        return None;
    }
    // SAFETY: every `HostCtx` the host hands out points to a leaked (`'static`) `InstanceWake`.
    let wake: &'static InstanceWake = unsafe { &*ctx.ptr.cast_const().cast::<InstanceWake>() };
    if !wake.destinations.get()?.iter().any(|k| k == key) {
        return None;
    }
    let bound = wake
        .bound
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    bound.iter().find(|d| d.key == key).cloned()
}

/// `disk.append` (THE DESIGN §11.11 R4, §11.12): the caller's destination KEY is mapped to the
/// file the host bound for it (granted from its manifest, bound from its settings at open), and
/// the bytes go to the kernel's bounded disk lane, which pends the call until the append is done.
/// On READY and FAILED the result slot gets what the lane reported: the rotation before the append,
/// and on READY the whole of the bytes. A key the caller was not granted is REFUSED
/// ([`NO_DESTINATION`]) before anything is written.
extern "C" fn disk_append(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        op::DISK_APPEND,
        size_of::<DiskAppendIn>(),
        |served, route, head| {
            // SAFETY: the head covered a `DiskAppendIn`.
            let i = unsafe { input.cast::<DiskAppendIn>().read_unaligned() };
            if check_disk_append_in(&i).is_err() {
                return Answered::fault();
            }
            let (Some(key), Some(bytes)) = (
                text_of(i.dest_key, "disk_append.dest_key"),
                blob_of(i.bytes, "disk_append.bytes"),
            ) else {
                return Answered::fault();
            };
            let Some(dest) = destination(ctx, &key) else {
                return Answered::bare(Outcome::Refused, NO_DESTINATION);
            };
            let whole = bytes.len() as u64;
            let provider = Arc::clone(&served.provider);
            // SAFETY: no buffer: the result is the `DiskWritten` slot, written below.
            let mut a = unsafe {
                pended(&served, &route, &head, None, |later| {
                    provider.disk_append(&dest, bytes, later)
                })
            };
            if matches!(a.outcome, Outcome::Ready | Outcome::Failed) {
                let report = DiskReport::of(&Stored {
                    outcome: a.outcome,
                    value: a.value,
                    bytes: Vec::new(),
                    spans: Vec::new(),
                    error: a.error,
                });
                let written = DiskWritten {
                    size: size_of::<DiskWritten>() as u32,
                    rotated: u8::from(report.rotated),
                    faults: report.faults,
                    _reserved: [0; 2],
                    written: if a.outcome == Outcome::Ready {
                        whole
                    } else {
                        0
                    },
                };
                // SAFETY: the caller's result slot, checked non-NULL by `check_disk_append_in`.
                unsafe { i.result.write_unaligned(written) };
                a.value = if a.outcome == Outcome::Ready {
                    0
                } else {
                    report.step
                };
            }
            a
        },
    )
}

extern "C" fn records_list(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::RECORDS_LIST,
        size_of::<RecordsListIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `RecordsListIn`.
            let i = unsafe { input.cast::<RecordsListIn>().read_unaligned() };
            let (Some(kind), Some(prefix), Some(after)) = (
                text_of(i.kind, "records_list.kind"),
                bytes_of(i.prefix, "records_list.prefix"),
                bytes_of(i.after, "records_list.after"),
            ) else {
                return Answered::fault();
            };
            if check_bufs(&i.into).is_err() {
                return Answered::fault();
            }
            let list = RecordsList {
                kind,
                prefix,
                after: (!i.after.ptr.is_null()).then_some(after),
                limit: i.limit,
            };
            let provider = Arc::clone(&served.provider);
            // SAFETY: `into` checked above; the caller's buffers.
            unsafe {
                pended(&served, &route, &head, Some(&i.into), |later| {
                    provider.records_list(&caller, list, later)
                })
            }
        },
    )
}

extern "C" fn records_claim(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::RECORDS_CLAIM,
        size_of::<RecordsClaimIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `RecordsClaimIn`.
            let i = unsafe { input.cast::<RecordsClaimIn>().read_unaligned() };
            let (Some(kind), Some(key)) = (
                text_of(i.kind, "records_claim.kind"),
                bytes_of(i.key, "records_claim.key"),
            ) else {
                return Answered::fault();
            };
            if check_records_claim_in(&i).is_err() {
                return Answered::bare(Outcome::Refused, NO_TTL);
            }
            let provider = Arc::clone(&served.provider);
            // SAFETY: no buffer is named.
            unsafe {
                pended(&served, &route, &head, None, |later| {
                    provider.records_claim(&caller, &kind, &key, i.ttl_ms, later)
                })
            }
        },
    )
}

extern "C" fn sign(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::SIGN,
        size_of::<SignIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `SignIn`.
            let i = unsafe { input.cast::<SignIn>().read_unaligned() };
            let Some(data) = blob_of(i.data, "sign.data") else {
                return Answered::fault();
            };
            if check_bufs(&i.into).is_err() {
                return Answered::fault();
            }
            let provider = Arc::clone(&served.provider);
            // SAFETY: `into` checked above; the caller's buffers.
            unsafe {
                serve(&served.store, &route, &head, Some(&i.into), |_| {
                    Ran::Now(provider.sign(&caller, &data))
                })
            }
        },
    )
}

extern "C" fn trust_sight(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::TRUST_SIGHT,
        size_of::<TrustSightIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `TrustSightIn`.
            let i = unsafe { input.cast::<TrustSightIn>().read_unaligned() };
            let (Some(counterparty), Some(hash)) = (
                text_of(i.counterparty, "trust_sight.counterparty"),
                text_of(i.catalogue_hash, "trust_sight.catalogue_hash"),
            ) else {
                return Answered::fault();
            };
            let provider = Arc::clone(&served.provider);
            // SAFETY: no buffer is named.
            unsafe {
                pended(&served, &route, &head, None, |later| {
                    provider.trust_sight(&caller, &counterparty, &hash, later)
                })
            }
        },
    )
}

extern "C" fn trust_due(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::TRUST_DUE,
        size_of::<TrustDueIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `TrustDueIn`.
            let i = unsafe { input.cast::<TrustDueIn>().read_unaligned() };
            if check_bufs(&i.into).is_err() {
                return Answered::fault();
            }
            let provider = Arc::clone(&served.provider);
            // SAFETY: `into` checked above; the caller's buffers.
            unsafe {
                serve(&served.store, &route, &head, Some(&i.into), |_| {
                    Ran::Now(provider.trust_due(&caller))
                })
            }
        },
    )
}

extern "C" fn trust_verify(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::TRUST_VERIFY,
        size_of::<TrustVerifyIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `TrustVerifyIn`.
            let i = unsafe { input.cast::<TrustVerifyIn>().read_unaligned() };
            let (Some(counterparty), Some(payload), Some(signatures)) = (
                text_of(i.counterparty, "trust_verify.counterparty"),
                blob_of(i.payload, "trust_verify.payload"),
                blob_of(i.signatures, "trust_verify.signatures"),
            ) else {
                return Answered::fault();
            };
            if check_bufs(&i.into).is_err() {
                return Answered::fault();
            }
            let provider = Arc::clone(&served.provider);
            // SAFETY: `into` checked above; the caller's buffers.
            unsafe {
                serve(&served.store, &route, &head, Some(&i.into), |_| {
                    Ran::Now(provider.trust_verify(&caller, &counterparty, &payload, &signatures))
                })
            }
        },
    )
}

thread_local! {
    /// The unit the crossing on this thread serves.
    static SERVING: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// The unit a crossing serves, stated for the host services it calls on its thread, and cleared
/// (to the unit of any crossing it is nested in) when the crossing returns.
pub(crate) struct Serving(Option<u64>);

impl Drop for Serving {
    fn drop(&mut self) {
        SERVING.with(|s| s.set(self.0));
    }
}

/// State that the crossing on this thread serves `unit` until the returned guard drops.
pub(crate) fn serving(unit: Option<u64>) -> Serving {
    Serving(SERVING.with(|s| s.replace(unit)))
}

/// The unit the crossing on this thread serves; `None` outside a crossing that serves one.
pub(crate) fn serving_unit() -> Option<u64> {
    SERVING.with(std::cell::Cell::get)
}

extern "C" fn entitlement_check(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::ENTITLEMENT_CHECK,
        size_of::<EntitlementCheckIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered an `EntitlementCheckIn`.
            let i = unsafe { input.cast::<EntitlementCheckIn>().read_unaligned() };
            let Some(target) = text_of(i.target, "entitlement_check.target") else {
                return Answered::fault();
            };
            let unit = serving_unit();
            let provider = Arc::clone(&served.provider);
            // SAFETY: no buffer is named.
            unsafe {
                serve(&served.store, &route, &head, None, |_| {
                    Ran::Now(provider.entitlement_check(&caller, unit, &target))
                })
            }
        },
    )
}

extern "C" fn session_emit(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::SESSION_EMIT,
        size_of::<SessionEmitIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `SessionEmitIn`.
            let i = unsafe { input.cast::<SessionEmitIn>().read_unaligned() };
            let Some(bytes) = blob_of(i.bytes, "session_emit.bytes") else {
                return Answered::fault();
            };
            if svc::check_session_emit_in(&i).is_err() {
                return Answered::bare(Outcome::Refused, EMIT_NOTHING);
            }
            let provider = Arc::clone(&served.provider);
            // SAFETY: no buffer is named.
            unsafe {
                serve(&served.store, &route, &head, None, |_| {
                    Ran::Now(provider.session_emit(&caller, i.session, &bytes))
                })
            }
        },
    )
}

/// `session.emit`'s refusal of a write that names no session or no bytes.
const EMIT_NOTHING: &str = "session.emit names an open session and something to write";

extern "C" fn random_fill(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        op::RANDOM_FILL,
        size_of::<RandomFillIn>(),
        |served, route, head| {
            // SAFETY: the head covered a `RandomFillIn`.
            let i = unsafe { input.cast::<RandomFillIn>().read_unaligned() };
            if check_bufs(&i.into).is_err() {
                return Answered::fault();
            }
            if check_random_fill_in(&i).is_err() {
                return Answered::bare(Outcome::Refused, FILL_OUT_OF_RANGE);
            }
            let provider = Arc::clone(&served.provider);
            // SAFETY: `into` checked above; the caller's buffers.
            unsafe {
                serve(&served.store, &route, &head, Some(&i.into), |_| {
                    Ran::Now(provider.random_fill(i.len))
                })
            }
        },
    )
}

extern "C" fn unit_nest(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::UNIT_NEST,
        size_of::<UnitNestIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `UnitNestIn`.
            let i = unsafe { input.cast::<UnitNestIn>().read_unaligned() };
            let (Some(verb), Some(target), Some(body)) = (
                text_of(i.verb, "unit_nest.verb"),
                text_of(i.target, "unit_nest.target"),
                blob_of(i.body, "unit_nest.body"),
            ) else {
                return Answered::fault();
            };
            if check_bufs(&i.into).is_err() {
                return Answered::fault();
            }
            let unit = serving_unit();
            let provider = Arc::clone(&served.provider);
            let ask = NestAsk { verb, target, body };
            // SAFETY: `into` checked above; the caller's buffers, where the whole reply goes.
            unsafe {
                pended(&served, &route, &head, Some(&i.into), |later| {
                    provider.unit_nest(&caller, unit, ask, later)
                })
            }
        },
    )
}

/// The refusal of a `work.open` or `work.settle` record past `MAX_WORK_RECORD`, before anything is
/// opened or settled.
pub const WORK_RECORD_TOO_LONG: &str = "the work record is longer than MAX_WORK_RECORD";

extern "C" fn work_open(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::WORK_OPEN,
        size_of::<WorkOpenIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `WorkOpenIn`.
            let i = unsafe { input.cast::<WorkOpenIn>().read_unaligned() };
            let (Some(kind), Some(record)) = (
                text_of(i.kind, "work_open.kind"),
                blob_of(i.record, "work_open.record"),
            ) else {
                return Answered::fault();
            };
            if check_bufs(&i.into).is_err() {
                return Answered::fault();
            }
            if check_work_record(&i.record).is_err() {
                return Answered::bare(Outcome::Refused, WORK_RECORD_TOO_LONG);
            }
            let unit = serving_unit();
            let provider = Arc::clone(&served.provider);
            // SAFETY: `into` checked above; the caller's buffers.
            unsafe {
                pended(&served, &route, &head, Some(&i.into), |later| {
                    provider.work_open(&caller, unit, &kind, &record, later)
                })
            }
        },
    )
}

extern "C" fn work_find(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::WORK_FIND,
        size_of::<WorkFindIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `WorkFindIn`.
            let i = unsafe { input.cast::<WorkFindIn>().read_unaligned() };
            let Some(reference) = bytes_of(i.reference, "work_find.reference") else {
                return Answered::fault();
            };
            if check_bufs(&i.into).is_err() {
                return Answered::fault();
            }
            let unit = serving_unit();
            let provider = Arc::clone(&served.provider);
            // SAFETY: `into` checked above; the caller's buffers.
            unsafe {
                pended(&served, &route, &head, Some(&i.into), |later| {
                    provider.work_find(&caller, unit, &reference, later)
                })
            }
        },
    )
}

extern "C" fn work_settle(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::WORK_SETTLE,
        size_of::<WorkSettleIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `WorkSettleIn`.
            let i = unsafe { input.cast::<WorkSettleIn>().read_unaligned() };
            let Some(record) = blob_of(i.record, "work_settle.record") else {
                return Answered::fault();
            };
            if check_work_record(&i.record).is_err() {
                return Answered::bare(Outcome::Refused, WORK_RECORD_TOO_LONG);
            }
            let provider = Arc::clone(&served.provider);
            // SAFETY: no buffer is named.
            unsafe {
                pended(&served, &route, &head, None, |later| {
                    provider.work_settle(&caller, i.handle, &record, later)
                })
            }
        },
    )
}

extern "C" fn work_resume(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    scoped(
        ctx,
        input,
        out,
        op::WORK_RESUME,
        size_of::<WorkResumeIn>(),
        |served, route, head, caller| {
            // SAFETY: the head covered a `WorkResumeIn`.
            let i = unsafe { input.cast::<WorkResumeIn>().read_unaligned() };
            if check_bufs(&i.into).is_err() {
                return Answered::fault();
            }
            let unit = serving_unit();
            let provider = Arc::clone(&served.provider);
            // SAFETY: `into` checked above; the caller's buffers.
            unsafe {
                pended(&served, &route, &head, Some(&i.into), |later| {
                    provider.work_resume(&caller, unit, i.handle, later)
                })
            }
        },
    )
}

/// `name = OP, In;`: a slot this host does not serve yet: its frame, then REFUSED.
macro_rules! unimplemented_slot {
    ($($name:ident = $op:ident, $in:ident;)*) => {$(
        extern "C" fn $name(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
            slot(ctx, input, out, op::$op, size_of::<svc::$in>(), |_, _, _| {
                Answered::bare(Outcome::Refused, UNIMPLEMENTED)
            })
        }
    )*};
}

unimplemented_slot! {
    verify_lookup = VERIFY_LOOKUP, VerifyLookupIn;
    verify_store = VERIFY_STORE, VerifyStoreIn;
    content_scan = CONTENT_SCAN, ContentScanIn;
    hook_call = HOOK_CALL, HookCallIn;
}

/// THE HOST'S VERDICT on the calling instance's declared need: what the host's one connection
/// table answered when the need was declared at bind (`DeclaredConns::declared`). READY when it was
/// admitted; REFUSED, in the table's words, when it was refused or never declared. Never pends. The
/// verdict binds fail-closed whether or not the plugin asks: every establish on a refused need is
/// refused by the table.
extern "C" fn need_admit(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    framed(
        input,
        out,
        op::NEED_ADMIT,
        size_of::<svc::NeedAdmitIn>(),
        |_| {
            // SAFETY: the head covered a `NeedAdmitIn`.
            let i = unsafe { input.cast::<svc::NeedAdmitIn>().read_unaligned() };
            let need = busbar_contract::conn::NeedId(i.need);
            let verdict = super::conn_services::armed(ctx)
                .and_then(|(instance, table)| table.declared(*instance, need))
                .unwrap_or(Err(busbar_contract::conn::ConnError::UndeclaredNeed));
            match verdict {
                Ok(()) => Answered::bare(Outcome::Ready, ""),
                Err(e) => Answered::bare(Outcome::Refused, e.text()),
            }
        },
    )
}

#[cfg(test)]
#[path = "../tests/host_services_tests.rs"]
mod tests;
